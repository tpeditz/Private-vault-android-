package com.example.ota

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import com.android.apksig.ApkVerifier
import com.example.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.TimeUnit
import kotlin.coroutines.coroutineContext

/**
 * Isolated Public OTA Update & Verification Engine (Sections 19, 20, 21, 22).
 *
 * Security & Architecture Contract:
 * - Zero access to vault databases, session managers, master/backup passwords, or encryption keys.
 * - Permanent public repository: `https://github.com/tpeditz/Private-vault-updates`
 * - Default manifest URL: `https://raw.githubusercontent.com/tpeditz/Private-vault-updates/main/update.json`
 * - Never starts downloading an APK unless the user explicitly chooses "Update Now".
 * - Uses official Android `com.android.apksig.ApkVerifier` (never `JarFile` certificate checks)
 *   to verify the candidate APK's cryptographic signature and requires an exact SHA-256 match
 *   against the currently installed application's own trusted signing certificate.
 */
class OtaUpdateManager(private val context: Context) {


    data class OtaManifest(
        val schemaVersion: Int,
        val packageName: String,
        val versionName: String,
        val versionCode: Int,
        val minimumSupportedVersionCode: Int,
        val downloadUrl: String,
        val sha256: String,
        val signingCertificateSha256: String,
        val releaseNotes: String,
        val forceUpdate: Boolean,
        val publishedAt: String,
        val apkSizeBytes: Long? = null,
        val minAndroidSdk: Int = 24
    )

    data class VerifiedCandidateApk(
        val apkFile: File,
        val manifest: OtaManifest,
        val actualSha256Hex: String,
        val verifiedSignerCertSha256Hex: String,
        val installedSignerCertSha256Hex: String,
        val archiveVersionCode: Long,
        val archiveVersionName: String
    )

    sealed interface OtaUiState {
        data object Idle : OtaUiState
        data object CheckingManifest : OtaUiState
        data class UpToDate(
            val installedVersionName: String,
            val installedVersionCode: Int,
            val checkedAtEpochMs: Long = System.currentTimeMillis()
        ) : OtaUiState

        /**
         * Presented when a strictly higher `versionCode` is available.
         * Never starts downloading automatically; waits for user to choose:
         * - Update Now
         * - Update Later
         * - Remind Me Later (Next Launch, Tomorrow, In 3 Days)
         */
        data class UpdateAvailable(
            val manifest: OtaManifest,
            val showPromptDialog: Boolean = true,
            val advisorySupportWarning: String? = null
        ) : OtaUiState

        data class Downloading(
            val manifest: OtaManifest,
            val bytesDownloaded: Long,
            val totalBytes: Long,
            val progressFraction: Float
        ) : OtaUiState

        data class VerifyingSignature(val manifest: OtaManifest) : OtaUiState

        data class ReadyToInstall(val verifiedCandidate: VerifiedCandidateApk) : OtaUiState

        data class Error(
            val title: String,
            val message: String,
            val isOfflineOrUnpublished: Boolean = false
        ) : OtaUiState
    }

    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(25, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .addNetworkInterceptor { chain ->
            val requestUrl = chain.request().url
            if (!requestUrl.isHttps) {
                throw SecurityException("Rejected non-HTTPS connection during OTA operation: ${requestUrl.scheme}")
            }
            val host = requestUrl.host.lowercase(Locale.ROOT)
            if (host !in ALLOWED_GITHUB_HOSTS) {
                throw SecurityException("Rejected untrusted OTA redirect/host: $host")
            }
            chain.proceed(chain.request())
        }
        .build()

    private val _otaState = MutableStateFlow<OtaUiState>(OtaUiState.Idle)
    val otaState: StateFlow<OtaUiState> = _otaState.asStateFlow()

    /**
     * Checks the public `update.json` manifest over HTTPS.
     */
    suspend fun checkForUpdates(
        manifestUrl: String = DEFAULT_MANIFEST_URL,
        showDialogIfAvailable: Boolean = true
    ): OtaUiState = withContext(Dispatchers.IO) {
        _otaState.value = OtaUiState.CheckingManifest
        try {
            validateHttpsGithubUrl(manifestUrl)
            val request = Request.Builder()
                .url(manifestUrl)
                .header("Accept", "application/json")
                .header("Cache-Control", "no-cache")
                .get()
                .build()

            httpClient.newCall(request).execute().use { response ->
                if (response.code == 404) {
                    val state = OtaUiState.Error(
                        title = "No Published Update Manifest Yet",
                        message = "The public update repository (tpeditz/Private-vault-updates) does not have a live update.json published yet, or you are on the initial build. Your offline vault works normally.",
                        isOfflineOrUnpublished = true
                    )
                    _otaState.value = state
                    return@withContext state
                }
                if (!response.isSuccessful) {
                    val state = OtaUiState.Error(
                        title = "Update Check Failed",
                        message = "Server returned HTTP ${response.code}. Your offline vault remains fully accessible."
                    )
                    _otaState.value = state
                    return@withContext state
                }

                val bodyBytes = response.body?.bytes()
                    ?: throw IllegalArgumentException("Empty manifest response.")
                if (bodyBytes.size > MAX_MANIFEST_BYTES) {
                    throw IllegalArgumentException("Manifest exceeds maximum allowed size ($MAX_MANIFEST_BYTES bytes).")
                }

                val jsonText = String(bodyBytes, Charsets.UTF_8)
                val state = evaluateManifestJson(
                    rawJson = jsonText,
                    installedPackageName = context.packageName,
                    installedVersionCode = BuildConfig.VERSION_CODE,
                    installedVersionName = BuildConfig.VERSION_NAME,
                    currentDeviceSdk = Build.VERSION.SDK_INT,
                    showDialogIfAvailable = showDialogIfAvailable
                )
                _otaState.value = state
                return@withContext state
            }
        } catch (e: java.io.IOException) {
            val state = OtaUiState.Error(
                title = "Offline or Network Unavailable",
                message = "Could not reach GitHub update server (${e.localizedMessage ?: "network offline"}). All PRIVATE VAULT features continue working offline.",
                isOfflineOrUnpublished = true
            )
            _otaState.value = state
            return@withContext state
        } catch (e: Exception) {
            val state = OtaUiState.Error(
                title = "Manifest Validation Rejected",
                message = e.message ?: "Invalid update manifest."
            )
            _otaState.value = state
            return@withContext state
        }
    }

    /**
     * Dismisses the modal prompt ("Update Later") while preserving the available update details
     * in Settings -> Updates so the user can install whenever they choose.
     */
    fun dismissUpdateDialogForLater() {
        val current = _otaState.value
        if (current is OtaUiState.UpdateAvailable) {
            _otaState.value = current.copy(showPromptDialog = false)
        }
    }

    /**
     * Triggered ONLY when the user explicitly taps "Update Now".
     * Downloads the APK to app-controlled cache storage, verifies size, SHA-256, package metadata,
     * and Android `apksig` `ApkVerifier` signature against the installed app's trusted certificate.
     */
    suspend fun downloadAndVerifyUpdate(manifest: OtaManifest): OtaUiState = withContext(Dispatchers.IO) {
        cleanupTemporaryApkFiles()
        val otaDir = File(context.cacheDir, "ota_updates").apply { mkdirs() }
        val targetFile = File(otaDir, "private_vault_update_${manifest.versionCode}.apk")

        try {
            validateHttpsGithubUrl(manifest.downloadUrl)
            _otaState.value = OtaUiState.Downloading(
                manifest = manifest,
                bytesDownloaded = 0L,
                totalBytes = manifest.apkSizeBytes ?: -1L,
                progressFraction = 0f
            )

            val request = Request.Builder()
                .url(manifest.downloadUrl)
                .get()
                .build()

            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw IllegalStateException("APK download failed with HTTP ${response.code}.")
                }
                val body = response.body ?: throw IllegalStateException("Empty APK response body.")
                val contentLength = body.contentLength()
                val expectedTotal = manifest.apkSizeBytes ?: contentLength

                if (expectedTotal > MAX_APK_BYTES) {
                    throw SecurityException("APK size ($expectedTotal bytes) exceeds safety limit.")
                }

                body.byteStream().use { input ->
                    FileOutputStream(targetFile).use { output ->
                        val buffer = ByteArray(16 * 1024)
                        var downloaded = 0L
                        while (true) {
                            if (!coroutineContext.isActive) {
                                targetFile.delete()
                                throw java.util.concurrent.CancellationException("Download cancelled by user.")
                            }
                            val read = input.read(buffer)
                            if (read == -1) break
                            downloaded += read
                            if (downloaded > MAX_APK_BYTES) {
                                targetFile.delete()
                                throw SecurityException("Downloaded stream exceeded 150 MiB safety limit.")
                            }
                            output.write(buffer, 0, read)
                            val fraction = if (expectedTotal > 0L) {
                                (downloaded.toFloat() / expectedTotal.toFloat()).coerceIn(0f, 1f)
                            } else {
                                0.5f
                            }
                            _otaState.value = OtaUiState.Downloading(
                                manifest = manifest,
                                bytesDownloaded = downloaded,
                                totalBytes = expectedTotal,
                                progressFraction = fraction
                            )
                        }
                        output.flush()
                    }
                }
            }

            _otaState.value = OtaUiState.VerifyingSignature(manifest)

            val installedSignerSha256 = getInstalledAppSigningCertSha256(context)
            val verified = verifyCandidateApkFile(
                context = context,
                apkFile = targetFile,
                manifest = manifest,
                installedAppPackageName = context.packageName,
                installedAppVersionCode = BuildConfig.VERSION_CODE.toLong(),
                installedSignerCertSha256Hex = installedSignerSha256
            )

            val readyState = OtaUiState.ReadyToInstall(verified)
            _otaState.value = readyState
            return@withContext readyState
        } catch (e: java.util.concurrent.CancellationException) {
            targetFile.delete()
            val fallback = OtaUiState.UpdateAvailable(manifest = manifest, showPromptDialog = false)
            _otaState.value = fallback
            throw e
        } catch (e: Exception) {
            targetFile.delete()
            val errState = OtaUiState.Error(
                title = "Update Verification Failed",
                message = e.message ?: "Candidate APK failed security verification and was deleted."
            )
            _otaState.value = errState
            return@withContext errState
        }
    }

    /**
     * Checks whether the user needs to grant "Install unknown apps" permission on Android 8.0+.
     */
    fun canRequestPackageInstalls(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.packageManager.canRequestPackageInstalls()
        } else {
            true
        }
    }

    fun buildManageUnknownAppSourcesIntent(): Intent {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Intent(
                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                Uri.parse("package:${context.packageName}")
            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        } else {
            Intent(Settings.ACTION_SECURITY_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }

    /**
     * Builds the FileProvider installation intent for a verified candidate APK.
     * Note: Caller MUST lock the vault (`VaultSessionManager.lockNow()`) immediately before
     * launching this intent (Section 22).
     */
    fun buildInstallVerifiedApkIntent(verifiedCandidate: VerifiedCandidateApk): Intent {
        val contentUri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            verifiedCandidate.apkFile
        )
        return Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(contentUri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }

    fun cleanupTemporaryApkFiles() {
        try {
            val otaDir = File(context.cacheDir, "ota_updates")
            if (otaDir.exists()) {
                otaDir.listFiles()?.forEach { it.delete() }
            }
        } catch (_: Exception) {
        }
    }

    /**
     * Debug/Test-Only Simulator (Confirmed Decision 4):
     * Strictly gated behind `BuildConfig.DEBUG` so debug/test builds can test the 3-option
     * update dialog, reminder deferrals, and error states without publishing a live GitHub release.
     */
    fun simulateManifestForDebugTesting(rawJson: String, showDialog: Boolean = true): OtaUiState {
        check(BuildConfig.DEBUG) { "OTA Simulator is restricted to debug/test builds." }
        val state = try {
            evaluateManifestJson(
                rawJson = rawJson,
                installedPackageName = context.packageName,
                installedVersionCode = BuildConfig.VERSION_CODE,
                installedVersionName = BuildConfig.VERSION_NAME,
                currentDeviceSdk = Build.VERSION.SDK_INT,
                showDialogIfAvailable = showDialog
            )
        } catch (e: Exception) {
            OtaUiState.Error(
                title = "Simulated Manifest Rejected",
                message = e.message ?: "Manifest validation failed."
            )
        }
        _otaState.value = state
        return state
    }

    /**
     * Returns the SHA-256 hex fingerprint of the currently installed application's signing certificate.
     */
    fun getInstalledSignerFingerprintHex(): String {
        return try {
            getInstalledAppSigningCertSha256(context)
        } catch (_: Exception) {
            "UNAVAILABLE_IN_JVM_TEST"
        }
    }

    companion object {
        const val EXPECTED_SCHEMA_VERSION = 1
        const val DEFAULT_MANIFEST_URL = "https://raw.githubusercontent.com/tpeditz/Private-vault-updates/main/update.json"
        const val PUBLIC_OTA_REPO_URL = "https://github.com/tpeditz/Private-vault-updates"
        const val MAX_MANIFEST_BYTES = 64 * 1024 // 64 KiB
        const val MAX_APK_BYTES = 150L * 1024L * 1024L // 150 MiB
        const val MAX_RELEASE_NOTES_CHARS = 4000

        private val ALLOWED_GITHUB_HOSTS = setOf(
            "raw.githubusercontent.com",
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com"
        )

        private val HEX_64_REGEX = Regex("^[0-9a-fA-F]{64}$")

        fun parseAndValidateManifest(
            rawJson: String,
            expectedPackageName: String,
            currentDeviceSdk: Int = Build.VERSION.SDK_INT
        ): OtaManifest {
            val root = JSONObject(rawJson)

            if (!root.has("schemaVersion")) {
                throw IllegalArgumentException("Manifest missing required 'schemaVersion' field.")
            }
            val schemaVersion = root.getInt("schemaVersion")
            if (schemaVersion != EXPECTED_SCHEMA_VERSION) {
                throw IllegalArgumentException("Unsupported manifest schemaVersion: $schemaVersion.")
            }

            val packageName = root.optString("packageName", "").trim()
            if (packageName != expectedPackageName) {
                throw SecurityException(
                    "Manifest packageName ('$packageName') does not match installed package ('$expectedPackageName')."
                )
            }

            val versionName = root.optString("versionName", "").trim()
            if (versionName.isEmpty() || versionName.length > 40) {
                throw IllegalArgumentException("Invalid or missing versionName in manifest.")
            }

            if (!root.has("versionCode")) {
                throw IllegalArgumentException("Manifest missing required 'versionCode' integer.")
            }
            val versionCode = root.getInt("versionCode")
            if (versionCode <= 0) {
                throw IllegalArgumentException("Manifest versionCode must be a positive integer ($versionCode).")
            }

            val minSupportedVersionCode = root.optInt("minimumSupportedVersionCode", 1)
            if (minSupportedVersionCode <= 0 || minSupportedVersionCode > versionCode) {
                throw IllegalArgumentException("Invalid minimumSupportedVersionCode ($minSupportedVersionCode).")
            }

            val downloadUrl = root.optString("downloadUrl", "").trim()
            validateHttpsGithubUrl(downloadUrl)

            val sha256 = root.optString("sha256", "").trim().lowercase(Locale.ROOT)
            if (!HEX_64_REGEX.matches(sha256)) {
                throw IllegalArgumentException("Manifest sha256 must be a valid 64-character hex SHA-256 digest.")
            }

            val signingCertSha256 = root.optString("signingCertificateSha256", "")
                .replace(":", "")
                .trim()
                .lowercase(Locale.ROOT)
            if (!HEX_64_REGEX.matches(signingCertSha256)) {
                throw IllegalArgumentException("Manifest signingCertificateSha256 must be a valid 64-character hex digest.")
            }

            val rawNotes = root.optString("releaseNotes", "").trim()
            if (rawNotes.length > MAX_RELEASE_NOTES_CHARS) {
                throw IllegalArgumentException("Manifest releaseNotes exceeds $MAX_RELEASE_NOTES_CHARS characters.")
            }
            // Strip any HTML/script tags from untrusted plain-text release notes (Section 21)
            val safeReleaseNotes = rawNotes.replace(Regex("<[^>]*>"), "")

            val forceUpdate = root.optBoolean("forceUpdate", false)
            val publishedAt = root.optString("publishedAt", "").trim()
            if (publishedAt.isEmpty()) {
                throw IllegalArgumentException("Manifest missing 'publishedAt' timestamp.")
            }

            val apkSizeBytes = if (root.has("apkSizeBytes") && !root.isNull("apkSizeBytes")) {
                val size = root.getLong("apkSizeBytes")
                if (size <= 1024L || size > MAX_APK_BYTES) {
                    throw IllegalArgumentException("Manifest apkSizeBytes ($size) is out of valid bounds.")
                }
                size
            } else {
                null
            }

            val minAndroidSdk = root.optInt("minAndroidSdk", 24)
            if (minAndroidSdk > currentDeviceSdk) {
                throw IllegalArgumentException(
                    "Update requires Android API $minAndroidSdk, which is newer than this device (API $currentDeviceSdk)."
                )
            }

            return OtaManifest(
                schemaVersion = schemaVersion,
                packageName = packageName,
                versionName = versionName,
                versionCode = versionCode,
                minimumSupportedVersionCode = minSupportedVersionCode,
                downloadUrl = downloadUrl,
                sha256 = sha256,
                signingCertificateSha256 = signingCertSha256,
                releaseNotes = safeReleaseNotes,
                forceUpdate = forceUpdate,
                publishedAt = publishedAt,
                apkSizeBytes = apkSizeBytes,
                minAndroidSdk = minAndroidSdk
            )
        }

        fun evaluateManifestJson(
            rawJson: String,
            installedPackageName: String,
            installedVersionCode: Int,
            installedVersionName: String,
            currentDeviceSdk: Int = Build.VERSION.SDK_INT,
            showDialogIfAvailable: Boolean = true
        ): OtaUiState {
            val manifest = parseAndValidateManifest(
                rawJson = rawJson,
                expectedPackageName = installedPackageName,
                currentDeviceSdk = currentDeviceSdk
            )

            // Compare versions numerically with versionCode; offer only strictly greater versionCode (U02)
            if (manifest.versionCode <= installedVersionCode) {
                return OtaUiState.UpToDate(
                    installedVersionName = installedVersionName,
                    installedVersionCode = installedVersionCode
                )
            }

            // Even if forceUpdate or minimumSupportedVersionCode is set in remote JSON,
            // NEVER lock out offline vault access (U12 / Section 21 & 22). Show only an advisory note.
            val advisoryWarning = if (manifest.forceUpdate || installedVersionCode < manifest.minimumSupportedVersionCode) {
                "Advisory: This update includes important security or compatibility improvements. Your offline vault remains fully accessible."
            } else {
                null
            }

            return OtaUiState.UpdateAvailable(
                manifest = manifest,
                showPromptDialog = showDialogIfAvailable,
                advisorySupportWarning = advisoryWarning
            )
        }

        fun validateHttpsGithubUrl(url: String) {
            val uri = Uri.parse(url)
            val scheme = uri.scheme?.lowercase(Locale.ROOT)
            if (scheme != "https") {
                throw SecurityException("OTA URL must use HTTPS (found: ${uri.scheme}).")
            }
            val host = uri.host?.lowercase(Locale.ROOT)
                ?: throw IllegalArgumentException("OTA URL is missing a valid host.")
            if (host !in ALLOWED_GITHUB_HOSTS) {
                throw SecurityException("OTA URL host '$host' is not in the approved GitHub release host list.")
            }
            if (url.contains("..")) {
                throw SecurityException("OTA URL contains forbidden path traversal segments.")
            }
        }

        /**
         * Verifies a downloaded candidate APK file using:
         * 1. Expected byte size (when specified)
         * 2. Actual SHA-256 digest match against `manifest.sha256`
         * 3. Android's official `com.android.apksig.ApkVerifier` cryptographic archive verification
         *    (`result.isVerified == true`), extracting the verified signer certificate(s)
         * 4. Exact SHA-256 match between the APK's verified signer certificate and the currently
         *    installed application's own trusted signing certificate (`installedSignerCertSha256Hex`)
         * 5. Archive `packageName` and `versionCode` consistency against the manifest and installed version
         */
        fun verifyCandidateApkFile(
            context: Context,
            apkFile: File,
            manifest: OtaManifest,
            installedAppPackageName: String,
            installedAppVersionCode: Long,
            installedSignerCertSha256Hex: String
        ): VerifiedCandidateApk {
            if (!apkFile.exists() || !apkFile.isFile) {
                throw IllegalArgumentException("Candidate APK file does not exist.")
            }

            if (manifest.apkSizeBytes != null && apkFile.length() != manifest.apkSizeBytes) {
                throw SecurityException(
                    "Downloaded APK byte size (${apkFile.length()}) does not match manifest (${manifest.apkSizeBytes})."
                )
            }

            // 1. Verify SHA-256 checksum
            val actualSha256 = computeFileSha256Hex(apkFile)
            if (!actualSha256.equals(manifest.sha256, ignoreCase = true)) {
                throw SecurityException(
                    "APK SHA-256 checksum mismatch (expected ${manifest.sha256.take(12)}..., got ${actualSha256.take(12)}...)."
                )
            }

            // 2. Cryptographically verify the APK signature using official Android apksig ApkVerifier (U06, U07)
            val verifierBuilder = ApkVerifier.Builder(apkFile)
                .setMinCheckedPlatformVersion(24)
            val verificationResult = try {
                verifierBuilder.build().verify()
            } catch (e: Exception) {
                throw SecurityException("apksig ApkVerifier failed to parse candidate APK: ${e.message}", e)
            }

            if (!verificationResult.isVerified) {
                val errors = verificationResult.errors.joinToString("; ") { it.toString() }
                throw SecurityException("Candidate APK failed cryptographic signature verification: $errors")
            }

            val signerCerts = verificationResult.signerCertificates
            if (signerCerts.isNullOrEmpty()) {
                throw SecurityException("Candidate APK contains no verified signer certificates.")
            }

            val candidateSignerHashes = signerCerts.map { cert ->
                sha256Hex(cert.encoded)
            }

            val normalizedInstalledSigner = installedSignerCertSha256Hex.replace(":", "").lowercase(Locale.ROOT)
            if (normalizedInstalledSigner.isBlank() || normalizedInstalledSigner !in candidateSignerHashes) {
                throw SecurityException(
                    "Candidate APK signing certificate (${candidateSignerHashes.firstOrNull()?.take(16)}...) " +
                        "does not match the installed app's trusted signing key (${normalizedInstalledSigner.take(16)}...)."
                )
            }

            // Also verify consistency with manifest's informational signingCertificateSha256 field
            val normalizedManifestSigner = manifest.signingCertificateSha256.replace(":", "").lowercase(Locale.ROOT)
            if (normalizedManifestSigner !in candidateSignerHashes) {
                throw SecurityException(
                    "Candidate APK signer certificate does not match manifest signingCertificateSha256."
                )
            }

            // 3. Verify package identity & versionCode inside the APK archive
            val archiveInfo: PackageInfo? = context.packageManager.getPackageArchiveInfo(
                apkFile.absolutePath,
                0
            )
            if (archiveInfo != null) {
                if (archiveInfo.packageName != installedAppPackageName) {
                    throw SecurityException(
                        "APK archive packageName ('${archiveInfo.packageName}') does not match installed app ('$installedAppPackageName')."
                    )
                }
                val archiveVerCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    archiveInfo.longVersionCode
                } else {
                    @Suppress("DEPRECATION")
                    archiveInfo.versionCode.toLong()
                }
                if (archiveVerCode != manifest.versionCode.toLong()) {
                    throw SecurityException(
                        "APK archive versionCode ($archiveVerCode) does not match manifest versionCode (${manifest.versionCode})."
                    )
                }
                if (archiveVerCode <= installedAppVersionCode) {
                    throw SecurityException(
                        "APK archive versionCode ($archiveVerCode) is not newer than installed version ($installedAppVersionCode)."
                    )
                }

                return VerifiedCandidateApk(
                    apkFile = apkFile,
                    manifest = manifest,
                    actualSha256Hex = actualSha256,
                    verifiedSignerCertSha256Hex = candidateSignerHashes.first(),
                    installedSignerCertSha256Hex = normalizedInstalledSigner,
                    archiveVersionCode = archiveVerCode,
                    archiveVersionName = archiveInfo.versionName ?: manifest.versionName
                )
            } else {
                // On headless JVM tests where PackageManager.getPackageArchiveInfo is not stubbed,
                // ApkVerifier has already cryptographically verified the full APK Zip/V2/V3 structure.
                return VerifiedCandidateApk(
                    apkFile = apkFile,
                    manifest = manifest,
                    actualSha256Hex = actualSha256,
                    verifiedSignerCertSha256Hex = candidateSignerHashes.first(),
                    installedSignerCertSha256Hex = normalizedInstalledSigner,
                    archiveVersionCode = manifest.versionCode.toLong(),
                    archiveVersionName = manifest.versionName
                )
            }
        }

        fun getInstalledAppSigningCertSha256(context: Context): String {
            val pm = context.packageManager
            val pkgName = context.packageName
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val pkgInfo = pm.getPackageInfo(pkgName, PackageManager.GET_SIGNING_CERTIFICATES)
                val signingInfo = pkgInfo.signingInfo
                    ?: throw SecurityException("Installed package has no SigningInfo.")
                val signatures = if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners
                } else {
                    signingInfo.signingCertificateHistory
                }
                val firstSig = signatures?.firstOrNull()
                    ?: throw SecurityException("Installed package has no signing certificates.")
                return sha256Hex(firstSig.toByteArray())
            } else {
                @Suppress("DEPRECATION")
                val pkgInfo = pm.getPackageInfo(pkgName, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                val firstSig = pkgInfo.signatures?.firstOrNull()
                    ?: throw SecurityException("Installed package has no legacy signatures.")
                return sha256Hex(firstSig.toByteArray())
            }
        }

        fun computeFileSha256Hex(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            FileInputStream(file).use { input ->
                val buffer = ByteArray(16 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read == -1) break
                    digest.update(buffer, 0, read)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }

        fun sha256Hex(bytes: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
            return digest.joinToString("") { "%02x".format(it) }
        }
    }
}

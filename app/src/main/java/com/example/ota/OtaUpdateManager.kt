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
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.URI
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * Self-contained HTTPS OTA Update Manager for PRIVATE VAULT.
 *
 * Security Invariants (B04 / N04 / R04 / R14 / R15):
 * 1. HTTPS-only transport with strict GitHub host and repository path allowlisting
 *    (`raw.githubusercontent.com/tpeditz/Private-vault-updates/...` and
 *    `github.com/tpeditz/Private-vault-updates/releases/download/...`), allowing custom repository
 *    overrides only in debug builds (`BuildConfig.DEBUG`).
 * 2. Never downloads an APK automatically—downloads ONLY when the user explicitly selects "Update Now".
 * 3. Verifies candidate APK using:
 *    - Exact SHA-256 file digest match against `update.json`
 *    - Official `com.android.apksig.ApkVerifier` cryptographic signature verification
 *    - Exact SHA-256 signing certificate match against the currently installed app's trusted signer(s)
 *    - Non-null parsed package archive metadata (`N04`: fails closed if `ArchiveInfoParser` returns null)
 *      confirming exact `packageName == context.packageName` and `versionCode > installedVersionCode`.
 */
class OtaUpdateManager(
    private val context: Context,
    private val installedSignerDigestsProvider: () -> Set<String> = {
        getInstalledSignerSha256Digests(context)
    },
    private val installedVersionCodeProvider: () -> Long = {
        getInstalledVersionCode(context)
    },
    private val archiveInfoParser: ArchiveInfoParser = ArchiveInfoParser { ctx, apkFile ->
        ctx.packageManager.getPackageArchiveInfo(
            apkFile.absolutePath,
            PackageManager.GET_META_DATA
        )
    }
) {

    fun interface ArchiveInfoParser {
        fun parseArchiveInfo(context: Context, apkFile: File): PackageInfo?
    }

    data class UpdateManifest(
        val versionCode: Int,
        val versionName: String,
        val apkDownloadUrl: String,
        val sha256Checksum: String,
        val releaseNotes: String,
        val publishedAt: String,
        val fileSizeBytes: Long
    )

    sealed interface OtaState {
        data object Idle : OtaState
        data object Checking : OtaState
        data class UpToDate(val currentVersionName: String, val currentVersionCode: Long) : OtaState
        data class UpdateAvailable(
            val manifest: UpdateManifest,
            val showPromptDialog: Boolean = true
        ) : OtaState
        data class Downloading(
            val manifest: UpdateManifest,
            val bytesDownloaded: Long,
            val totalBytes: Long
        ) : OtaState
        data class Verifying(val manifest: UpdateManifest) : OtaState
        data class ReadyToInstall(
            val manifest: UpdateManifest,
            val verifiedApkFile: File,
            val signerCertificateSha256: String
        ) : OtaState
        data class NeedsUnknownSourcesPermission(
            val manifest: UpdateManifest,
            val verifiedApkFile: File,
            val signerCertificateSha256: String
        ) : OtaState
        data class Error(
            val title: String,
            val detail: String,
            val recoverableManifest: UpdateManifest? = null
        ) : OtaState
    }

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .followRedirects(true)
        .followSslRedirects(true)
        .build()

    private val _otaState = MutableStateFlow<OtaState>(OtaState.Idle)
    val otaState: StateFlow<OtaState> = _otaState.asStateFlow()

    /**
     * Checks the HTTPS `update.json` manifest endpoint (or debug simulator override).
     */
    suspend fun checkForUpdates(
        manifestUrl: String,
        showDialogIfAvailable: Boolean = true
    ): OtaState = withContext(Dispatchers.IO) {
        _otaState.value = OtaState.Checking
        try {
            validateAllowedHttpsUrl(manifestUrl, isManifestEndpoint = true)
            val request = Request.Builder()
                .url(manifestUrl)
                .header("Accept", "application/json")
                .header("Cache-Control", "no-cache")
                .build()

            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val err = OtaState.Error(
                        title = "Update Check Failed",
                        detail = "Server returned HTTP ${response.code}. Your offline vaults remain unaffected."
                    )
                    _otaState.value = err
                    return@withContext err
                }

                val bodyStr = response.body?.string().orEmpty()
                if (bodyStr.isBlank()) {
                    val err = OtaState.Error(
                        title = "Invalid Update Manifest",
                        detail = "The update manifest response was empty."
                    )
                    _otaState.value = err
                    return@withContext err
                }

                val manifest = parseAndValidateManifestJson(bodyStr)
                val installedCode = installedVersionCodeProvider()
                val nextState = if (manifest.versionCode.toLong() > installedCode) {
                    OtaState.UpdateAvailable(
                        manifest = manifest,
                        showPromptDialog = showDialogIfAvailable
                    )
                } else {
                    OtaState.UpToDate(
                        currentVersionName = getInstalledVersionName(context),
                        currentVersionCode = installedCode
                    )
                }
                _otaState.value = nextState
                return@withContext nextState
            }
        } catch (e: Exception) {
            val err = OtaState.Error(
                title = "Unable to Check for Updates",
                detail = e.message ?: "Network error while checking update manifest."
            )
            _otaState.value = err
            return@withContext err
        }
    }

    /**
     * R15 Fix: Updates the prompt visibility of an already-fetched `UpdateAvailable` state without
     * issuing a duplicate network request.
     */
    fun setPromptDialogVisible(visible: Boolean) {
        val current = _otaState.value
        if (current is OtaState.UpdateAvailable) {
            _otaState.value = current.copy(showPromptDialog = visible)
        }
    }

    /**
     * Dismisses the modal prompt ("Update Later") without blocking any vault feature.
     */
    fun dismissUpdatePrompt() {
        setPromptDialogVisible(false)
    }

    /**
     * R14 Fix: Re-evaluates `NeedsUnknownSourcesPermission` when the user returns from Android's
     * "Install unknown apps" settings screen so they can immediately tap Install without re-downloading.
     */
    fun refreshInstallPermissionState(): Boolean {
        val current = _otaState.value
        if (current is OtaState.NeedsUnknownSourcesPermission) {
            if (canRequestPackageInstalls()) {
                _otaState.value = OtaState.ReadyToInstall(
                    manifest = current.manifest,
                    verifiedApkFile = current.verifiedApkFile,
                    signerCertificateSha256 = current.signerCertificateSha256
                )
                return true
            }
        }
        return false
    }

    /**
     * Downloads the candidate APK to private cache and runs full SHA-256 + `apksig` + archive verification.
     * Invoked ONLY when the user explicitly selects "Update Now".
     */
    suspend fun downloadAndVerifyUpdate(manifest: UpdateManifest): OtaState =
        withContext(Dispatchers.IO) {
            val otaDir = File(context.cacheDir, "ota_updates").apply { mkdirs() }
            val candidateFile = File(otaDir, "private_vault_update_v${manifest.versionCode}.apk")
            if (candidateFile.exists()) {
                candidateFile.delete()
            }

            try {
                validateAllowedHttpsUrl(manifest.apkDownloadUrl, isManifestEndpoint = false)
                _otaState.value = OtaState.Downloading(
                    manifest = manifest,
                    bytesDownloaded = 0L,
                    totalBytes = manifest.fileSizeBytes
                )

                val request = Request.Builder()
                    .url(manifest.apkDownloadUrl)
                    .build()

                httpClient.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        throw IllegalStateException("APK download failed with HTTP ${response.code}.")
                    }
                    // Validate final redirected URL host as well (R04)
                    val finalUrl = response.request.url.toString()
                    validateAllowedHttpsUrl(finalUrl, isManifestEndpoint = false)

                    val body = response.body ?: throw IllegalStateException("Empty APK response body.")
                    val total = if (body.contentLength() > 0) body.contentLength() else manifest.fileSizeBytes

                    body.byteStream().use { input ->
                        FileOutputStream(candidateFile).use { output ->
                            val buffer = ByteArray(16 * 1024)
                            var downloaded = 0L
                            var read: Int
                            while (input.read(buffer).also { read = it } != -1) {
                                output.write(buffer, 0, read)
                                downloaded += read
                                if ( downloaded > MAX_APK_BYTES) {
                                    throw IllegalStateException("Downloaded APK exceeds 150 MiB safety limit.")
                                }
                                _otaState.value = OtaState.Downloading(
                                    manifest = manifest,
                                    bytesDownloaded = downloaded,
                                    totalBytes = total
                                )
                            }
                            output.flush()
                        }
                    }
                }

                _otaState.value = OtaState.Verifying(manifest)
                val verifiedSignerSha256 = verifyCandidateApkFile(
                    apkFile = candidateFile,
                    expectedFileSha256 = manifest.sha256Checksum,
                    expectedVersionCode = manifest.versionCode.toLong()
                )

                val nextState = if (canRequestPackageInstalls()) {
                    OtaState.ReadyToInstall(
                        manifest = manifest,
                        verifiedApkFile = candidateFile,
                        signerCertificateSha256 = verifiedSignerSha256
                    )
                } else {
                    OtaState.NeedsUnknownSourcesPermission(
                        manifest = manifest,
                        verifiedApkFile = candidateFile,
                        signerCertificateSha256 = verifiedSignerSha256
                    )
                }
                _otaState.value = nextState
                return@withContext nextState
            } catch (e: Exception) {
                if (candidateFile.exists()) {
                    candidateFile.delete()
                }
                val err = OtaState.Error(
                    title = "Update Verification Failed",
                    detail = e.message ?: "Candidate APK failed security verification.",
                    recoverableManifest = manifest
                )
                _otaState.value = err
                return@withContext err
            }
        }

    /**
     * Verifies a candidate APK file on disk using:
     * 1. Exact SHA-256 digest match against `expectedFileSha256`
     * 2. Official Android `com.android.apksig.ApkVerifier` cryptographic signature verification
     * 3. Signer certificate SHA-256 match against the installed app's trusted signing certificate(s)
     * 4. Non-null package archive metadata (`N04` fail-closed!) confirming exact `packageName` match
     *    and strictly higher `versionCode`.
     *
     * Throws `SecurityException` or `IllegalArgumentException` on any mismatch and deletes the file.
     */
    fun verifyCandidateApkFile(
        apkFile: File,
        expectedFileSha256: String,
        expectedVersionCode: Long
    ): String {
        require(apkFile.exists() && apkFile.length() > 0L) {
            "Candidate APK file does not exist or is empty."
        }

        // 1. Verify exact SHA-256 checksum of the downloaded APK file
        val actualFileSha256 = computeFileSha256Hex(apkFile)
        val normalizedExpected = expectedFileSha256.trim().lowercase(Locale.US)
        if (!actualFileSha256.equals(normalizedExpected, ignoreCase = true)) {
            throw SecurityException(
                "APK SHA-256 checksum mismatch (expected $normalizedExpected, got $actualFileSha256)."
            )
        }

        // 2. Verify cryptographic APK signature schemes (v1/v2/v3) using official Android apksig
        val verifier = ApkVerifier.Builder(apkFile)
            .setMinCheckedPlatformVersion(Build.VERSION_CODES.N)
            .build()
        val result = verifier.verify()
        if (!result.isVerified) {
            val errorDetails = result.errors.joinToString("; ") { it.toString() }
            throw SecurityException("APK signature verification failed via apksig: $errorDetails")
        }

        val candidateCerts: List<X509Certificate> = result.signerCertificates
        if (candidateCerts.isEmpty()) {
            throw SecurityException("Candidate APK contains no verified signer certificates.")
        }

        val candidateSignerDigests = candidateCerts.map { cert ->
            sha256Hex(cert.encoded)
        }.toSet()

        // 3. Compare candidate signer certificate(s) against installed app's trusted signer(s)
        val trustedInstalledDigests = installedSignerDigestsProvider()
            .map { it.lowercase(Locale.US) }
            .toSet()
        if (trustedInstalledDigests.isEmpty()) {
            throw SecurityException("Unable to read installed app's trusted signing certificate.")
        }

        if (candidateSignerDigests != trustedInstalledDigests) {
            throw SecurityException(
                "APK signer certificate mismatch! Candidate signer (${candidateSignerDigests.first()}) " +
                    "does not match installed trusted signer (${trustedInstalledDigests.first()})."
            )
        }

        // 4. N04 Fix: Parse package archive metadata and FAIL CLOSED if null!
        val archiveInfo = archiveInfoParser.parseArchiveInfo(context, apkFile)
            ?: throw SecurityException(
                "Could not parse package archive metadata from candidate APK. Refusing unverified package."
            )

        val candidatePkg = archiveInfo.packageName
        if (candidatePkg != context.packageName) {
            throw SecurityException(
                "Candidate APK packageName ($candidatePkg) does not match installed package (${context.packageName})."
            )
        }
        val archiveVersionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            archiveInfo.longVersionCode
        } else {
            @Suppress("DEPRECATION")
            archiveInfo.versionCode.toLong()
        }
        if (archiveVersionCode != expectedVersionCode) {
            throw SecurityException(
                "Candidate APK versionCode ($archiveVersionCode) does not match manifest ($expectedVersionCode)."
            )
        }
        val installedCode = installedVersionCodeProvider()
        if (archiveVersionCode <= installedCode) {
            throw SecurityException(
                "Downgrade or replay rejected: candidate versionCode ($archiveVersionCode) <= installed ($installedCode)."
            )
        }

        return candidateSignerDigests.first()
    }

    /**
     * Debug/Test-only simulator allowing verification of the 3-choice OTA prompt
     * ("Update Now", "Update Later", "Remind Me Later") without requiring a live GitHub release.
     */
    fun simulateUpdateAvailableForDebug(
        simulatedVersionCode: Int = (installedVersionCodeProvider() + 1L).toInt(),
        simulatedVersionName: String = "1.1.0-sim"
    ) {
        if (!BuildConfig.DEBUG) return
        val manifest = UpdateManifest(
            versionCode = simulatedVersionCode,
            versionName = simulatedVersionName,
            apkDownloadUrl = "https://github.com/tpeditz/Private-vault-updates/releases/download/v$simulatedVersionName/PrivateVault-v$simulatedVersionName.apk",
            sha256Checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            releaseNotes = "• Verified Argon2id + AES-256-GCM dual-vault persistence\n" +
                "• Preserves both Real and Decoy vaults across in-place APK upgrades\n" +
                "• Signed with trusted release certificate",
            publishedAt = "2026-03-31",
            fileSizeBytes = 14_800_000L
        )
        _otaState.value = OtaState.UpdateAvailable(
            manifest = manifest,
            showPromptDialog = true
        )
    }

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

    fun buildInstallVerifiedApkIntent(verifiedApkFile: File): Intent {
        val authority = "${context.packageName}.fileprovider"
        val contentUri = FileProvider.getUriForFile(context, authority, verifiedApkFile)
        return Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(contentUri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }

    fun parseAndValidateManifestJson(jsonString: String): UpdateManifest {
        val root = JSONObject(jsonString)
        val versionCode = root.getInt("versionCode")
        val versionName = root.getString("versionName").trim()
        val apkUrl = root.getString("apkUrl").trim()
        val sha256 = root.getString("sha256").trim().lowercase(Locale.US)
        val releaseNotes = root.optString("releaseNotes", "Security and stability improvements.")
        val publishedAt = root.optString("publishedAt", "")
        val fileSizeBytes = root.optLong("fileSizeBytes", 0L)

        require(versionCode > 0) { "Manifest versionCode must be > 0." }
        require(versionName.isNotEmpty()) { "Manifest versionName cannot be empty." }
        validateAllowedHttpsUrl(apkUrl, isManifestEndpoint = false)
        require(sha256.matches(Regex("^[0-9a-f]{64}$"))) {
            "Manifest sha256 must be a valid 64-character hexadecimal SHA-256 digest."
        }

        return UpdateManifest(
            versionCode = versionCode,
            versionName = versionName,
            apkDownloadUrl = apkUrl,
            sha256Checksum = sha256,
            releaseNotes = releaseNotes,
            publishedAt = publishedAt,
            fileSizeBytes = fileSizeBytes
        )
    }

    /**
     * R04 Fix: Validates both HTTPS host AND canonical `tpeditz/Private-vault-updates` repository
     * path in production builds, allowing custom GitHub paths under the allowlisted hosts only
     * when `BuildConfig.DEBUG` is true.
     */
    fun validateAllowedHttpsUrl(
        url: String,
        isManifestEndpoint: Boolean = false,
        allowDebugCustomRepositoryPath: Boolean = BuildConfig.DEBUG
    ) {
        val parsed = try {
            URI(url.trim())
        } catch (e: Exception) {
            throw IllegalArgumentException("Malformed update URL: $url")
        }
        val scheme = parsed.scheme?.lowercase(Locale.US)
        require(scheme == "https") {
            "Insecure update URL rejected (HTTPS required): $url"
        }
        val host = parsed.host?.lowercase(Locale.US)
            ?: throw IllegalArgumentException("Update URL missing host: $url")
        require(host in ALLOWED_HOSTS) {
            "Untrusted update host rejected ($host). Only official GitHub release hosts are permitted."
        }

        if (!allowDebugCustomRepositoryPath) {
            val path = parsed.path ?: ""
            if (isManifestEndpoint) {
                require(
                    host == "raw.githubusercontent.com" &&
                        path.startsWith("/tpeditz/Private-vault-updates/")
                ) {
                    "Untrusted manifest repository path rejected ($host$path). Production updates must come from tpeditz/Private-vault-updates."
                }
            } else {
                val isOfficialReleasePath =
                    (host == "github.com" && path.startsWith("/tpeditz/Private-vault-updates/releases/download/")) ||
                        (host == "raw.githubusercontent.com" && path.startsWith("/tpeditz/Private-vault-updates/")) ||
                        (host == "objects.githubusercontent.com" || host == "release-assets.githubusercontent.com")
                require(isOfficialReleasePath) {
                    "Untrusted APK download path rejected ($host$path). Production updates must come from tpeditz/Private-vault-updates."
                }
            }
        }
    }

    companion object {
        private const val MAX_APK_BYTES = 150L * 1024L * 1024L

        val ALLOWED_HOSTS = setOf(
            "raw.githubusercontent.com",
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com"
        )

        fun getInstalledVersionCode(context: Context): Long {
            val pkgInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkgInfo.longVersionCode
            } else {
                @Suppress("DEPRECATION")
                pkgInfo.versionCode.toLong()
            }
        }

        fun getInstalledVersionName(context: Context): String {
            val pkgInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            return pkgInfo.versionName ?: "1.0.1"
        }

        @Suppress("DEPRECATION")
        fun getInstalledSignerSha256Digests(context: Context): Set<String> {
            val pm = context.packageManager
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val pkgInfo = pm.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
                val signingInfo = pkgInfo.signingInfo ?: return emptySet()
                val signatures = if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners
                } else {
                    signingInfo.signingCertificateHistory
                }
                signatures.orEmpty().map { sig -> sha256Hex(sig.toByteArray()) }.toSet()
            } else {
                val pkgInfo = pm.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
                pkgInfo.signatures.orEmpty().map { sig -> sha256Hex(sig.toByteArray()) }.toSet()
            }
        }

        fun computeFileSha256Hex(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            FileInputStream(file).use { input ->
                val buffer = ByteArray(16 * 1024)
                var read: Int
                while (input.read(buffer).also { read = it } != -1) {
                    digest.update(buffer, 0, read)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }

        fun sha256Hex(bytes: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256")
            return digest.digest(bytes).joinToString("") { "%02x".format(it) }
        }
    }
}

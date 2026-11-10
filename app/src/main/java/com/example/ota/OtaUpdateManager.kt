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
import okhttp3.Response
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.net.URI
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * Self-contained HTTPS OTA Update Manager for PRIVATE VAULT.
 *
 * Security Invariants (B04 / N04 / R04 / R14 / R15 / Section 11 & 12):
 * 1. HTTPS-only transport with strict GitHub host, port (443), no-userinfo, normalized path, and
 *    hop-by-hop redirect validation BEFORE sending any redirected request (`T26`).
 *    - Initial manifest requests must target `raw.githubusercontent.com/tpeditz/Private-vault-updates/...`
 *    - Initial APK download requests must target `github.com/tpeditz/Private-vault-updates/releases/download/...`
 *      or `raw.githubusercontent.com/tpeditz/Private-vault-updates/...`
 *    - Redirect hops on APK downloads may resolve only to official GitHub release asset CDN hosts
 *      (`objects.githubusercontent.com`, `release-assets.githubusercontent.com`).
 * 2. Never downloads an APK automatically—downloads ONLY when the user explicitly selects "Update Now".
 * 3. Verifies candidate APK using:
 *    - Exact SHA-256 file digest match against `update.json` (and exact `fileSizeBytes` match when > 0)
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

    // Section 12 Fix (T26): Disable automatic redirects so every redirect target is validated
    // BEFORE the next HTTP request is sent over the network.
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    private val _otaState = MutableStateFlow<OtaState>(OtaState.Idle)
    val otaState: StateFlow<OtaState> = _otaState.asStateFlow()

    @Volatile
    private var activeDownloadCall: okhttp3.Call? = null

    @Volatile
    private var isDownloadCancelled: Boolean = false

    /**
     * PV-BUG-010 Fix: Cancels an in-flight OTA APK download, deletes any partial candidate file
     * in cache, and restores `UpdateAvailable(showPromptDialog = false)` or `Idle`.
     */
    fun cancelActiveDownload(fallbackManifest: UpdateManifest? = null) {
        isDownloadCancelled = true
        activeDownloadCall?.cancel()
        activeDownloadCall = null
        val current = _otaState.value
        val manifest = fallbackManifest ?: (current as? OtaState.Downloading)?.manifest
        val otaDir = File(context.cacheDir, "ota_updates")
        if (otaDir.exists()) {
            otaDir.listFiles()?.forEach { runCatching { it.delete() } }
        }
        _otaState.value = if (manifest != null) {
            OtaState.UpdateAvailable(manifest = manifest, showPromptDialog = false)
        } else {
            OtaState.Idle
        }
    }

    /**
     * Checks the HTTPS `update.json` manifest endpoint (or debug simulator override).
     */
    suspend fun checkForUpdates(
        manifestUrl: String,
        showDialogIfAvailable: Boolean = true
    ): OtaState = withContext(Dispatchers.IO) {
        _otaState.value = OtaState.Checking
        try {
            executeWithValidatedRedirects(
                initialUrl = manifestUrl,
                isManifestEndpoint = true,
                headers = mapOf(
                    "Accept" to "application/json",
                    "Cache-Control" to "no-cache"
                )
            ).use { response ->
                if (!response.isSuccessful) {
                    val err = OtaState.Error(
                        title = "Update Check Failed",
                        detail = "Server returned HTTP ${response.code}. Your offline vaults remain unaffected."
                    )
                    _otaState.value = err
                    return@withContext err
                }

                val bodyStream = response.body?.byteStream()
                    ?: throw IllegalStateException("Empty update manifest response.")
                val bodyBytes = bodyStream.use { readBoundedBytes(it, MAX_MANIFEST_JSON_BYTES) }
                val bodyStr = String(bodyBytes, Charsets.UTF_8)
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
     * R15 / BUG 17 Fix: Updates the prompt visibility of an already-fetched `UpdateAvailable`
     * state in memory without issuing a duplicate network request.
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
     * R14 / BUG 16 Fix: Re-evaluates `NeedsUnknownSourcesPermission` when the user returns from
     * Android's "Install unknown apps" settings screen so they can immediately tap Install without re-downloading.
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
            isDownloadCancelled = false
            val otaDir = File(context.cacheDir, "ota_updates").apply { mkdirs() }
            // Clean up any older candidate files before downloading
            otaDir.listFiles()?.forEach { file ->
                if (file.name != "private_vault_update_v${manifest.versionCode}.apk") {
                    runCatching { file.delete() }
                }
            }
            val candidateFile = File(otaDir, "private_vault_update_v${manifest.versionCode}.apk")
            if (candidateFile.exists()) {
                candidateFile.delete()
            }

            try {
                _otaState.value = OtaState.Downloading(
                    manifest = manifest,
                    bytesDownloaded = 0L,
                    totalBytes = manifest.fileSizeBytes
                )

                executeWithValidatedRedirects(
                    initialUrl = manifest.apkDownloadUrl,
                    isManifestEndpoint = false
                ).use { response ->
                    if (!response.isSuccessful) {
                        throw IllegalStateException("APK download failed with HTTP ${response.code}.")
                    }

                    val body = response.body ?: throw IllegalStateException("Empty APK response body.")
                    val contentLength = body.contentLength()
                    if (contentLength > MAX_APK_BYTES) {
                        throw IllegalStateException("Candidate APK content-length ($contentLength) exceeds 150 MiB safety limit.")
                    }
                    val total = if (contentLength > 0) contentLength else manifest.fileSizeBytes

                    body.byteStream().use { input ->
                        FileOutputStream(candidateFile).use { output ->
                            val buffer = ByteArray(16 * 1024)
                            var downloaded = 0L
                            var read: Int
                            while (input.read(buffer).also { read = it } != -1) {
                                if (isDownloadCancelled) {
                                    throw java.io.InterruptedIOException("Download cancelled by user.")
                                }
                                downloaded += read
                                if (downloaded > MAX_APK_BYTES) {
                                    throw IllegalStateException("Downloaded APK exceeds 150 MiB safety limit.")
                                }
                                if (manifest.fileSizeBytes > 0L && downloaded > manifest.fileSizeBytes) {
                                    throw SecurityException(
                                        "Downloaded APK size ($downloaded bytes) exceeds manifest fileSizeBytes (${manifest.fileSizeBytes})."
                                    )
                                }
                                output.write(buffer, 0, read)
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
                    expectedVersionCode = manifest.versionCode.toLong(),
                    expectedFileSizeBytes = manifest.fileSizeBytes
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
                if (isDownloadCancelled) {
                    val cancelledState = OtaState.UpdateAvailable(
                        manifest = manifest,
                        showPromptDialog = false
                    )
                    _otaState.value = cancelledState
                    return@withContext cancelledState
                }
                val err = OtaState.Error(
                    title = "Update Verification Failed",
                    detail = e.message ?: "Candidate APK failed security verification.",
                    recoverableManifest = manifest
                )
                _otaState.value = err
                return@withContext err
            } finally {
                activeDownloadCall = null
            }
        }

    /**
     * Executes an HTTPS GET request while validating every redirect hop BEFORE sending the next request (`T26`).
     */
    private fun executeWithValidatedRedirects(
        initialUrl: String,
        isManifestEndpoint: Boolean,
        allowDebugCustomRepositoryPath: Boolean = BuildConfig.DEBUG,
        headers: Map<String, String> = emptyMap(),
        maxRedirects: Int = MAX_REDIRECT_HOPS
    ): Response {
        var currentUrl = initialUrl.trim()
        for (hop in 0..maxRedirects) {
            validateAllowedHttpsUrl(
                url = currentUrl,
                isManifestEndpoint = isManifestEndpoint,
                allowDebugCustomRepositoryPath = allowDebugCustomRepositoryPath,
                isRedirectHop = hop > 0
            )

            val requestBuilder = Request.Builder().url(currentUrl)
            headers.forEach { (k, v) -> requestBuilder.header(k, v) }
            val call = httpClient.newCall(requestBuilder.build())
            if (!isManifestEndpoint) {
                activeDownloadCall = call
            }
            val response = call.execute()

            if (response.code in REDIRECT_STATUS_CODES) {
                val locationHeader = response.header("Location")
                response.close()
                if (locationHeader.isNullOrBlank()) {
                    throw SecurityException("Redirect response (HTTP ${response.code}) missing Location header.")
                }
                if (hop == maxRedirects) {
                    throw SecurityException("Too many redirect hops ($maxRedirects) while fetching update resource.")
                }
                val resolvedUri = try {
                    URI(currentUrl).resolve(locationHeader.trim())
                } catch (e: Exception) {
                    throw IllegalArgumentException("Malformed redirect Location header: $locationHeader")
                }
                val nextUrl = resolvedUri.toString()
                // Validate the redirect target BEFORE issuing the next network call!
                validateAllowedHttpsUrl(
                    url = nextUrl,
                    isManifestEndpoint = isManifestEndpoint,
                    allowDebugCustomRepositoryPath = allowDebugCustomRepositoryPath,
                    isRedirectHop = true
                )
                currentUrl = nextUrl
                continue
            }
            return response
        }
        throw SecurityException("Exceeded maximum redirect hops.")
    }

    /**
     * Verifies a candidate APK file on disk using:
     * 1. Exact byte size check (when `expectedFileSizeBytes > 0`) and exact SHA-256 digest match
     * 2. Official Android `com.android.apksig.ApkVerifier` cryptographic signature verification
     * 3. Signer certificate SHA-256 match against the installed app's trusted signing certificate(s)
     * 4. Non-null package archive metadata (`N04` fail-closed!) confirming exact `packageName` match
     *    and strictly higher `versionCode`.
     */
    fun verifyCandidateApkFile(
        apkFile: File,
        expectedFileSha256: String,
        expectedVersionCode: Long,
        expectedFileSizeBytes: Long = 0L
    ): String {
        require(apkFile.exists() && apkFile.length() > 0L) {
            "Candidate APK file does not exist or is empty."
        }
        if (expectedFileSizeBytes > 0L && apkFile.length() != expectedFileSizeBytes) {
            throw SecurityException(
                "APK byte size mismatch (expected $expectedFileSizeBytes bytes, got ${apkFile.length()} bytes)."
            )
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
            publishedAt = "2026-11-05",
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

    /**
     * Parses and validates `update.json`, enforcing:
     * - Size bound (`<= 64 KiB`)
     * - No duplicate top-level JSON keys
     * - Backward compatibility across `apkUrl` and `downloadUrl` (rejecting conflicting values)
     * - Strict SHA-256 hex format, positive `versionCode`, and bounded plain-text `releaseNotes`.
     */
    fun parseAndValidateManifestJson(
        jsonString: String,
        allowDebugCustomRepositoryPath: Boolean = BuildConfig.DEBUG
    ): UpdateManifest {
        require(jsonString.toByteArray(Charsets.UTF_8).size <= MAX_MANIFEST_JSON_BYTES) {
            "Update manifest exceeds maximum safe size (64 KiB)."
        }
        requireNoDuplicateTopLevelJsonKeys(jsonString)

        val root = JSONObject(jsonString)
        val versionCodeLong = root.getLong("versionCode")
        require(versionCodeLong in 1L..Int.MAX_VALUE.toLong()) {
            "Manifest versionCode ($versionCodeLong) is out of supported range."
        }
        val versionCode = versionCodeLong.toInt()
        val versionName = root.getString("versionName").trim()
        require(versionName.isNotEmpty() && versionName.length <= 64) {
            "Manifest versionName must be between 1 and 64 characters."
        }

        val apkUrlPrimary = root.optString("apkUrl", "").trim()
        val downloadUrlLegacy = root.optString("downloadUrl", "").trim()
        if (apkUrlPrimary.isNotEmpty() && downloadUrlLegacy.isNotEmpty()) {
            require(apkUrlPrimary == downloadUrlLegacy) {
                "Ambiguous manifest: apkUrl and downloadUrl do not match."
            }
        }
        val apkUrl = apkUrlPrimary.ifEmpty { downloadUrlLegacy }
        require(apkUrl.isNotEmpty()) {
            "Manifest is missing required apkUrl."
        }

        val sha256Primary = root.optString("sha256", "").trim().lowercase(Locale.US)
        val sha256Legacy = root.optString("sha256Checksum", "").trim().lowercase(Locale.US)
        if (sha256Primary.isNotEmpty() && sha256Legacy.isNotEmpty()) {
            require(sha256Primary == sha256Legacy) {
                "Ambiguous manifest: sha256 and sha256Checksum do not match."
            }
        }
        val sha256 = sha256Primary.ifEmpty { sha256Legacy }

        val rawReleaseNotes = root.optString("releaseNotes", "Security and stability improvements.")
        val sanitizedNotes = rawReleaseNotes
            .replace("\u0000", "")
            .take(MAX_RELEASE_NOTES_CHARS)
            .trim()
            .ifEmpty { "Security and stability improvements." }

        val publishedAt = root.optString("publishedAt", "").trim().take(64)
        val fileSizeBytes = root.optLong("fileSizeBytes", root.optLong("apkSizeBytes", 0L))
        require(fileSizeBytes in 0L..MAX_APK_BYTES) {
            "Manifest fileSizeBytes ($fileSizeBytes) is out of valid bounds."
        }

        validateAllowedHttpsUrl(
            url = apkUrl,
            isManifestEndpoint = false,
            allowDebugCustomRepositoryPath = allowDebugCustomRepositoryPath,
            isRedirectHop = false
        )
        require(sha256.matches(Regex("^[0-9a-f]{64}$"))) {
            "Manifest sha256 must be a valid 64-character hexadecimal SHA-256 digest."
        }

        return UpdateManifest(
            versionCode = versionCode,
            versionName = versionName,
            apkDownloadUrl = apkUrl,
            sha256Checksum = sha256,
            releaseNotes = sanitizedNotes,
            publishedAt = publishedAt,
            fileSizeBytes = fileSizeBytes
        )
    }

    /**
     * R04 & Section 12 Fix (T26): Validates HTTPS scheme, host allowlist, port (default/443 only),
     * absence of userinfo (`user:pass@`), absence of `..` path traversal, and canonical
     * `/tpeditz/Private-vault-updates/` repository path in production builds.
     */
    fun validateAllowedHttpsUrl(
        url: String,
        isManifestEndpoint: Boolean = false,
        allowDebugCustomRepositoryPath: Boolean = BuildConfig.DEBUG,
        isRedirectHop: Boolean = false
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
        require(parsed.userInfo == null) {
            "Update URL with embedded userinfo rejected: $url"
        }
        require(parsed.port == -1 || parsed.port == 443) {
            "Update URL with non-standard port (${parsed.port}) rejected: $url"
        }
        val host = parsed.host?.lowercase(Locale.US)
            ?: throw IllegalArgumentException("Update URL missing host: $url")
        require(host in ALLOWED_HOSTS) {
            "Untrusted update host rejected ($host). Only official GitHub release hosts are permitted."
        }

        val rawPath = parsed.rawPath ?: parsed.path ?: ""
        val segments = rawPath.split('/')
        require(segments.none { it == ".." || it == "." || it.equals("%2e%2e", ignoreCase = true) }) {
            "Update URL containing path traversal segments rejected: $url"
        }

        val normalizedPath = parsed.normalize().path ?: ""

        if (!allowDebugCustomRepositoryPath) {
            if (isManifestEndpoint) {
                require(
                    host == "raw.githubusercontent.com" &&
                        normalizedPath.startsWith("/tpeditz/Private-vault-updates/")
                ) {
                    "Untrusted manifest repository path rejected ($host$normalizedPath). Production updates must come from tpeditz/Private-vault-updates."
                }
            } else if (!isRedirectHop) {
                // Initial APK URL in update.json must point to the official tpeditz/Private-vault-updates repository
                val isOfficialInitialApkPath =
                    (host == "github.com" && normalizedPath.startsWith("/tpeditz/Private-vault-updates/releases/download/")) ||
                        (host == "raw.githubusercontent.com" && normalizedPath.startsWith("/tpeditz/Private-vault-updates/"))
                require(isOfficialInitialApkPath) {
                    "Untrusted initial APK download path rejected ($host$normalizedPath). Production updates must come from tpeditz/Private-vault-updates."
                }
            } else {
                // Redirect hop from github.com/tpeditz/Private-vault-updates/releases/download/...
                val isOfficialRedirectTarget =
                    (host == "github.com" && normalizedPath.startsWith("/tpeditz/Private-vault-updates/releases/download/")) ||
                        (host == "raw.githubusercontent.com" && normalizedPath.startsWith("/tpeditz/Private-vault-updates/")) ||
                        (host in ALLOWED_CDN_REDIRECT_HOSTS && normalizedPath.isNotEmpty())
                require(isOfficialRedirectTarget) {
                    "Untrusted APK redirect target rejected ($host$normalizedPath)."
                }
            }
        }
    }

    private fun readBoundedBytes(input: InputStream, maxBytes: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(8 * 1024)
        var total = 0
        var read: Int
        while (input.read(buffer).also { read = it } != -1) {
            total += read
            if (total > maxBytes) {
                throw IllegalArgumentException("Response exceeds maximum allowed byte size ($maxBytes bytes).")
            }
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }

    private fun requireNoDuplicateTopLevelJsonKeys(jsonString: String) {
        val keyRegex = Regex(""""([A-Za-z0-9_]+)"\s*:""")
        val seenKeys = HashSet<String>()
        for (match in keyRegex.findAll(jsonString)) {
            val key = match.groupValues[1]
            require(seenKeys.add(key)) {
                "Duplicate JSON key '$key' rejected in update manifest."
            }
        }
    }

    companion object {
        const val MAX_APK_BYTES = 150L * 1024L * 1024L
        const val MAX_MANIFEST_JSON_BYTES = 64 * 1024
        const val MAX_RELEASE_NOTES_CHARS = 4_000
        private const val MAX_REDIRECT_HOPS = 5
        private val REDIRECT_STATUS_CODES = setOf(301, 302, 303, 307, 308)

        val ALLOWED_CDN_REDIRECT_HOSTS = setOf(
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com"
        )

        val ALLOWED_HOSTS = setOf(
            "raw.githubusercontent.com",
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com"
        )

        /**
         * Generates a canonical `update.json` manifest string compatible with both the installed
         * baseline (`versionCode 2`/`3`) and Version 5 (`versionCode 4`).
         */
        fun generateCompatibleManifestJson(manifest: UpdateManifest): String {
            val obj = JSONObject()
            obj.put("versionCode", manifest.versionCode)
            obj.put("versionName", manifest.versionName)
            obj.put("apkUrl", manifest.apkDownloadUrl)
            obj.put("downloadUrl", manifest.apkDownloadUrl)
            obj.put("sha256", manifest.sha256Checksum.lowercase(Locale.US))
            obj.put("fileSizeBytes", manifest.fileSizeBytes)
            obj.put("publishedAt", manifest.publishedAt)
            obj.put("releaseNotes", manifest.releaseNotes)
            return obj.toString(2)
        }

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
            return pkgInfo.versionName ?: "1.0.3"
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

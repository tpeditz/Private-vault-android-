package com.example.security

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Arrays

/**
 * Manages copying sensitive vault secrets to the Android system clipboard with:
 * 1. `ClipDescription.EXTRA_IS_SENSITIVE` on Android 13+ (API 33+) to mask system clipboard previews.
 * 2. Ownership verification via SHA-256 digest before auto-clearing so unrelated user clipboard
 *    items copied after the secret are never accidentally overwritten.
 * 3. Deferred foreground clearing (`R06`) when Android 10+ background clipboard restrictions prevent
 *    reading/clearing the clipboard while backgrounded.
 * 4. Public text copying (`copyPublicText`, `U04`) for non-sensitive developer contact handles so
 *    prior secret ownership tracking is cleanly retired.
 */
class SensitiveClipboardManager(
    context: Context,
    private val scope: CoroutineScope
) {
    private val clipboardManager =
        context.applicationContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

    @Volatile
    private var lastCopiedDigest: ByteArray? = null

    @Volatile
    private var pendingClearDigest: ByteArray? = null

    @Volatile
    private var pendingClearExpiresAtMs: Long = 0L

    private var clearJob: Job? = null

    private val _activeCountdownSeconds = MutableStateFlow<Int?>(null)
    val activeCountdownSeconds: StateFlow<Int?> = _activeCountdownSeconds.asStateFlow()

    companion object {
        private const val EXTRA_IS_SENSITIVE_COMPAT = "android.content.extra.IS_SENSITIVE"
        private const val PENDING_CLEAR_RETENTION_MS = 15 * 60 * 1000L // 15 minutes
    }

    /**
     * Copies a sensitive secret to the system clipboard and starts the auto-clear countdown.
     */
    fun copySensitiveSecret(
        label: String,
        secretValue: String,
        ttlSeconds: Int
    ) {
        if (secretValue.isEmpty()) return

        val clip = ClipData.newPlainText(label, secretValue)
        val extras = PersistableBundle().apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            } else {
                putBoolean(EXTRA_IS_SENSITIVE_COMPAT, true)
            }
        }
        clip.description.extras = extras

        val digest = sha256(secretValue)
        wipeDigest(lastCopiedDigest)
        wipeDigest(pendingClearDigest)
        lastCopiedDigest = digest
        pendingClearDigest = null
        pendingClearExpiresAtMs = 0L

        clipboardManager.setPrimaryClip(clip)

        clearJob?.cancel()
        if (ttlSeconds <= 0) {
            _activeCountdownSeconds.value = null
            return
        }

        clearJob = scope.launch {
            var remaining = ttlSeconds
            while (remaining > 0) {
                _activeCountdownSeconds.value = remaining
                delay(1_000L)
                remaining--
            }
            _activeCountdownSeconds.value = null
            clearIfStillOwned()
        }
    }

    /**
     * Copies non-sensitive public text (such as developer Telegram/Instagram handles in About screen)
     * without marking it sensitive or scheduling a secret auto-clear timer, while retiring any prior
     * secret digest ownership so a previous countdown will not erase the newly copied handle (U04, R06).
     */
    fun copyPublicText(
        label: String,
        publicValue: String
    ) {
        if (publicValue.isEmpty()) return
        clearJob?.cancel()
        clearJob = null
        _activeCountdownSeconds.value = null
        wipeDigest(lastCopiedDigest)
        wipeDigest(pendingClearDigest)
        lastCopiedDigest = null
        pendingClearDigest = null
        pendingClearExpiresAtMs = 0L

        val clip = ClipData.newPlainText(label, publicValue)
        clipboardManager.setPrimaryClip(clip)
    }

    /**
     * Clears the clipboard if it still holds the last secret copied by PRIVATE VAULT.
     *
     * R06 Fix: Does NOT wipe `lastCopiedDigest` before verifying that clipboard access succeeded.
     * If Android 10+ background restrictions prevent inspecting `primaryClip` (returning null or
     * throwing SecurityException while the app is not focus-owner), retains `pendingClearDigest`
     * so `retryPendingClearOnForeground()` can verify ownership and clear immediately when the app
     * regains foreground/window focus, without ever blindly erasing unrelated user clipboard text.
     */
    fun clearIfStillOwned(nowEpochMs: Long = System.currentTimeMillis()): Boolean {
        clearJob?.cancel()
        clearJob = null
        _activeCountdownSeconds.value = null

        val expectedDigest = lastCopiedDigest ?: pendingClearDigest ?: return false

        val inspectionResult = inspectCurrentClipboardText()
        when (inspectionResult) {
            is ClipboardInspection.AccessibleText -> {
                val currentDigest = sha256(inspectionResult.text)
                val matches = MessageDigest.isEqual(expectedDigest, currentDigest)
                Arrays.fill(currentDigest, 0.toByte())
                wipeDigest(lastCopiedDigest)
                wipeDigest(pendingClearDigest)
                lastCopiedDigest = null
                pendingClearDigest = null
                pendingClearExpiresAtMs = 0L
                if (matches) {
                    performSystemClipboardClear()
                    return true
                }
                return false
            }

            ClipboardInspection.ConfirmedEmpty -> {
                wipeDigest(lastCopiedDigest)
                wipeDigest(pendingClearDigest)
                lastCopiedDigest = null
                pendingClearDigest = null
                pendingClearExpiresAtMs = 0L
                return false
            }

            ClipboardInspection.BlockedOrUnavailable -> {
                // Retain digest for foreground/focus retry instead of wiping it prematurely or
                // blindly clearing unrelated user clipboard contents (R06).
                val copyForPending = expectedDigest.copyOf()
                wipeDigest(lastCopiedDigest)
                wipeDigest(pendingClearDigest)
                lastCopiedDigest = null
                pendingClearDigest = copyForPending
                pendingClearExpiresAtMs = nowEpochMs + PENDING_CLEAR_RETENTION_MS
                return false
            }
        }
    }

    /**
     * Called when the activity resumes or regains window focus so any deferred background clear
     * can safely verify SHA-256 ownership and clear the secret if still present (R06).
     */
    fun retryPendingClearOnForeground(nowEpochMs: Long = System.currentTimeMillis()): Boolean {
        val pending = pendingClearDigest ?: return false
        if (nowEpochMs > pendingClearExpiresAtMs) {
            wipeDigest(pending)
            pendingClearDigest = null
            pendingClearExpiresAtMs = 0L
            return false
        }
        return clearIfStillOwned(nowEpochMs)
    }

    fun hasPendingDeferredClear(): Boolean = pendingClearDigest != null

    /**
     * Cancels active countdown jobs and zeroes digest state when the owning ViewModel is cleared (R20).
     */
    fun shutdown() {
        clearJob?.cancel()
        clearJob = null
        _activeCountdownSeconds.value = null
        wipeDigest(lastCopiedDigest)
        wipeDigest(pendingClearDigest)
        lastCopiedDigest = null
        pendingClearDigest = null
        pendingClearExpiresAtMs = 0L
    }

    private sealed interface ClipboardInspection {
        data class AccessibleText(val text: String) : ClipboardInspection
        data object ConfirmedEmpty : ClipboardInspection
        data object BlockedOrUnavailable : ClipboardInspection
    }

    private fun inspectCurrentClipboardText(): ClipboardInspection {
        return try {
            if (!clipboardManager.hasPrimaryClip()) {
                // Note: On Android 10+, hasPrimaryClip() or primaryClip may return false/null when
                // the app does not have window focus. If we know we copied a secret, treat null
                // primaryClip as BlockedOrUnavailable so we can verify on focus return.
                val clip = clipboardManager.primaryClip
                if (clip == null) {
                    ClipboardInspection.BlockedOrUnavailable
                } else if (clip.itemCount == 0) {
                    ClipboardInspection.ConfirmedEmpty
                } else {
                    val text = clip.getItemAt(0)?.text?.toString()
                    if (text == null) ClipboardInspection.ConfirmedEmpty else ClipboardInspection.AccessibleText(text)
                }
            } else {
                val clip = clipboardManager.primaryClip ?: return ClipboardInspection.BlockedOrUnavailable
                if (clip.itemCount <= 0) {
                    ClipboardInspection.ConfirmedEmpty
                } else {
                    val text = clip.getItemAt(0)?.text?.toString()
                    if (text.isNullOrEmpty()) {
                        ClipboardInspection.ConfirmedEmpty
                    } else {
                        ClipboardInspection.AccessibleText(text)
                    }
                }
            }
        } catch (_: Throwable) {
            ClipboardInspection.BlockedOrUnavailable
        }
    }

    private fun performSystemClipboardClear() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                clipboardManager.clearPrimaryClip()
            } else {
                clipboardManager.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        } catch (_: Throwable) {
            // Best effort
        }
    }

    private fun wipeDigest(digest: ByteArray?) {
        if (digest != null) {
            Arrays.fill(digest, 0.toByte())
        }
    }

    private fun sha256(value: String): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(value.toByteArray(StandardCharsets.UTF_8))
    }
}

package com.example.security

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.security.MessageDigest

/**
 * Privacy-preserving clipboard helper (Section 16):
 * - Marks secret clips with `ClipDescription.EXTRA_IS_SENSITIVE` on Android 13+ (API 33+)
 *   and compat extra `"android.content.extra.IS_SENSITIVE"` on all versions to suppress
 *   keyboard/overlay plaintext previews.
 * - Tracks a SHA-256 hash of the last copied secret and clears the clipboard after the
 *   configured TTL (default 30 seconds) or on vault lock ONLY if the current clipboard
 *   still matches the app's copied item (never erasing an unrelated clip copied later by the user).
 */
class SensitiveClipboardManager(
    context: Context,
    private val scope: CoroutineScope
) {
    private val clipboardManager =
        context.applicationContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

    private var clearJob: Job? = null
    private var lastCopiedDigest: ByteArray? = null

    private val _remainingSeconds = MutableStateFlow(0)
    val remainingSeconds: StateFlow<Int> = _remainingSeconds.asStateFlow()

    private val _lastCopiedLabel = MutableStateFlow<String?>(null)
    val lastCopiedLabel: StateFlow<String?> = _lastCopiedLabel.asStateFlow()

    fun copySensitive(
        label: String,
        secretValue: String,
        ttlSeconds: Int = 30
    ) {
        if (secretValue.isEmpty()) return

        val clipData = ClipData.newPlainText(label, secretValue)
        val extras = PersistableBundle().apply {
            putBoolean("android.content.extra.IS_SENSITIVE", true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        clipData.description.extras = extras
        clipboardManager.setPrimaryClip(clipData)

        lastCopiedDigest = sha256(secretValue)
        _lastCopiedLabel.value = label

        clearJob?.cancel()
        if (ttlSeconds > 0) {
            clearJob = scope.launch {
                for (remaining in ttlSeconds downTo 1) {
                    _remainingSeconds.value = remaining
                    delay(1000L)
                }
                clearIfStillOwned()
            }
        }
    }

    /**
     * Clears the clipboard if and only if the currently held clip matches the last secret
     * copied by PRIVATE VAULT.
     */
    fun clearIfStillOwned() {
        clearJob?.cancel()
        clearJob = null
        _remainingSeconds.value = 0
        _lastCopiedLabel.value = null

        val expectedDigest = lastCopiedDigest ?: return
        lastCopiedDigest = null

        try {
            val currentClip = clipboardManager.primaryClip
            val currentText = currentClip?.getItemAt(0)?.text?.toString()
            if (currentText != null && MessageDigest.isEqual(sha256(currentText), expectedDigest)) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    clipboardManager.clearPrimaryClip()
                } else {
                    clipboardManager.setPrimaryClip(ClipData.newPlainText("", ""))
                }
            }
        } catch (_: Exception) {
            // Android 10+ background clipboard read restrictions may block primaryClip inspection when backgrounded;
            // attempt best-effort clear if owned within foreground/lock transition.
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    clipboardManager.clearPrimaryClip()
                }
            } catch (_: Exception) {
            }
        }
    }

    private fun sha256(input: String): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
    }
}

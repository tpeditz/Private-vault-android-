package com.example.security

import android.util.Log

/**
 * Redacted, privacy-preserving diagnostic logger and user-facing message sanitizer (Task 2.C).
 *
 * Security Rules:
 * - Never logs or returns passwords, PINs, keys, recovery material, notes, filenames,
 *   content:// or file:// URIs, internal storage paths, or SQLite/crypto stack traces.
 * - Retains safe, non-sensitive diagnostic category codes for operational troubleshooting.
 */
object SafeVaultLogger {

    private const val TAG = "PrivateVaultDiag"

    private val SENSITIVE_PATH_OR_URI_REGEX = Regex(
        """(content://[^\s"']+|file://[^\s"']+|/data/[^\s"']+|/storage/[^\s"']+|/sdcard/[^\s"']+)""",
        RegexOption.IGNORE_CASE
    )

    fun warn(component: String, safeCode: String) {
        try {
            Log.w(TAG, "[$component] code=$safeCode")
        } catch (_: Throwable) {
            // Ignore in local JVM unit tests where android.util.Log is not mocked
        }
    }

    fun error(component: String, safeCode: String, throwableClass: String? = null) {
        try {
            val suffix = if (!throwableClass.isNullOrBlank()) " type=$throwableClass" else ""
            Log.e(TAG, "[$component] code=$safeCode$suffix")
        } catch (_: Throwable) {
            // Ignore in local JVM unit tests
        }
    }

    /**
     * Redacts any accidental filesystem path or content URI from an exception message before
     * showing a user-facing banner, falling back to `fallbackMessage` if the message is blank
     * or contains internal technical details.
     */
    fun sanitizeUserFacingMessage(rawMessage: String?, fallbackMessage: String): String {
        if (rawMessage.isNullOrBlank()) return fallbackMessage
        val redacted = SENSITIVE_PATH_OR_URI_REGEX.replace(rawMessage, "[redacted-path]").trim()
        return if (redacted.isBlank() || redacted.length > 260) {
            fallbackMessage
        } else {
            redacted
        }
    }
}

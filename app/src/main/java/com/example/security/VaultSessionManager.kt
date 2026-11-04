package com.example.security

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.Arrays
import java.util.concurrent.atomic.AtomicLong

/**
 * Strongly typed session capability manager for PRIVATE VAULT.
 *
 * Isolation Rules:
 * - Slot 0 (REAL_SLOT = 0) and Slot 1 (DECOY_SLOT = 1) never share an unlocked DEK.
 * - Unlocking one slot destroys any previous session and increments the atomic sessionGenerationId.
 * - In-flight asynchronous work (search, autosave, export) must validate its captured
 *   sessionGenerationId before writing or updating state.
 * - Decoy sessions contain zero UI flags or labels indicating they are decoy; only Real Vault
 *   security configuration flows verify `session.canManageVaultSecurity` (true only for Slot 0).
 */
class VaultSessionManager {

    companion object {
        const val REAL_SLOT = 0
        const val DECOY_SLOT = 1
        const val FILE_PICKER_GRANT_WINDOW_MS = 90_000L
    }

    sealed interface SessionState {
        data object Locked : SessionState

        class Unlocked(
            val sessionId: Long,
            val slotId: Int,
            private val internalDekBytes: ByteArray,
            val unlockedAtEpochMs: Long = System.currentTimeMillis()
        ) : SessionState {

            /**
             * Returns a defensive copy of the 256-bit DEK for a single cryptographic operation.
             * Callers should wipe their copy in a finally block after use.
             */
            fun borrowDekCopy(): ByteArray {
                check(!isWiped) { "Session $sessionId has already been locked and wiped." }
                return internalDekBytes.copyOf()
            }

            /**
             * Only Slot 0 (Real Vault) can rotate the Real Master Password or configure Decoy Mode.
             */
            val canManageVaultSecurity: Boolean
                get() = slotId == REAL_SLOT

            @Volatile
            var isWiped: Boolean = false
                private set

            internal fun wipeKeyMaterial() {
                isWiped = true
                Arrays.fill(internalDekBytes, 0.toByte())
            }

            override fun toString(): String {
                // Never log key bytes or reveal slot role in generic toString()
                return "VaultSession.Unlocked(sessionId=$sessionId, active=${!isWiped})"
            }
        }
    }

    private val generationCounter = AtomicLong(1000L)

    private val _sessionState = MutableStateFlow<SessionState>(SessionState.Locked)
    val sessionState: StateFlow<SessionState> = _sessionState.asStateFlow()

    @Volatile
    private var lastBackgroundedAtEpochMs: Long? = null

    @Volatile
    private var filePickerGrantUntilEpochMs: Long = 0L

    /**
     * Establishes a new authenticated vault session after wiping any prior session.
     */
    @Synchronized
    fun openSession(slotId: Int, dekBytes: ByteArray): SessionState.Unlocked {
        lockNow()
        val newId = generationCounter.incrementAndGet()
        val session = SessionState.Unlocked(
            sessionId = newId,
            slotId = slotId,
            internalDekBytes = dekBytes.copyOf()
        )
        _sessionState.value = session
        return session
    }

    /**
     * Immediately locks the active vault, zeroes key material in memory, and advances the
     * generation counter so any in-flight coroutines from the old session fail validation.
     */
    @Synchronized
    fun lockNow() {
        val current = _sessionState.value
        if (current is SessionState.Unlocked) {
            current.wipeKeyMaterial()
        }
        generationCounter.incrementAndGet()
        lastBackgroundedAtEpochMs = null
        filePickerGrantUntilEpochMs = 0L
        _sessionState.value = SessionState.Locked
    }

    /**
     * Verifies whether a captured sessionId is still the active, unwiped session.
     */
    fun isSessionActive(sessionId: Long): Boolean {
        val current = _sessionState.value
        return current is SessionState.Unlocked && !current.isWiped && current.sessionId == sessionId
    }

    /**
     * Returns the current unlocked session if and only if it matches the expected sessionId.
     */
    fun requireActiveSession(sessionId: Long): SessionState.Unlocked {
        val current = _sessionState.value
        if (current is SessionState.Unlocked && !current.isWiped && current.sessionId == sessionId) {
            return current
        }
        throw IllegalStateException("Vault session is no longer active or has been locked.")
    }

    /**
     * Grants a bounded 90-second transition window for Android's Storage Access Framework
     * document picker so picking a backup location does not prematurely destroy the operation,
     * while still enforcing a hard 90-second ceiling if the user abandons the picker.
     */
    fun beginFilePickerTransitionWindow(nowEpochMs: Long = System.currentTimeMillis()) {
        if (_sessionState.value is SessionState.Unlocked) {
            filePickerGrantUntilEpochMs = nowEpochMs + FILE_PICKER_GRANT_WINDOW_MS
        }
    }

    fun endFilePickerTransitionWindow() {
        filePickerGrantUntilEpochMs = 0L
    }

    fun onAppBackgrounded(nowEpochMs: Long = System.currentTimeMillis()) {
        if (_sessionState.value is SessionState.Unlocked) {
            lastBackgroundedAtEpochMs = nowEpochMs
        }
    }

    /**
     * Evaluates whether the vault must lock upon returning to foreground.
     * - If `autoLockTimeoutMs == 0L` (Immediate lock on background), locks unless a bounded SAF
     *   file-picker transition is currently active and within its 90s ceiling.
     * - Otherwise locks if `elapsed >= autoLockTimeoutMs`.
     */
    fun onAppForegrounded(
        autoLockTimeoutMs: Long,
        nowEpochMs: Long = System.currentTimeMillis()
    ): Boolean {
        val bgTime = lastBackgroundedAtEpochMs ?: return false
        lastBackgroundedAtEpochMs = null

        val inValidPickerWindow = filePickerGrantUntilEpochMs > nowEpochMs
        filePickerGrantUntilEpochMs = 0L

        val elapsed = (nowEpochMs - bgTime).coerceAtLeast(0L)
        if (inValidPickerWindow && elapsed < FILE_PICKER_GRANT_WINDOW_MS) {
            return false
        }

        if (autoLockTimeoutMs <= 0L || elapsed >= autoLockTimeoutMs) {
            lockNow()
            return true
        }
        return false
    }
}

package com.example.security

import android.os.SystemClock
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
 * - Every lock event also increments `authRequestGeneration`, invalidating any in-flight KDF
 *   unlock or biometric unlock job so a late completion after screen-off/lock cannot reopen a vault (N03).
 * - Decoy sessions contain zero UI flags or labels indicating they are decoy; only Real Vault
 *   security configuration flows verify `session.canManageVaultSecurity` (true only for Slot 0).
 */
class VaultSessionManager(
    private val monotonicClockMs: () -> Long = {
        try {
            val elapsed = SystemClock.elapsedRealtime()
            if (elapsed > 0L) elapsed else System.currentTimeMillis()
        } catch (_: Throwable) {
            System.currentTimeMillis()
        }
    }
) {

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
            val isDecoyConfiguredInRealVault: Boolean = false,
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
             * Only Slot 0 (Real Vault) can manage Decoy Policy or enroll biometrics.
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
    private val authRequestGenerationCounter = AtomicLong(5000L)

    private val _sessionState = MutableStateFlow<SessionState>(SessionState.Locked)
    val sessionState: StateFlow<SessionState> = _sessionState.asStateFlow()

    @Volatile
    private var lastBackgroundedAtMonotonicMs: Long? = null

    @Volatile
    private var filePickerGrantUntilMonotonicMs: Long = 0L

    /**
     * Captures the current authentication generation before starting a KDF or biometric flow.
     * Any subsequent `lockNow()` call increments `authRequestGenerationCounter`, causing
     * `openSessionIfGenerationMatches` to reject late completions and wipe the derived DEK (N03).
     */
    fun currentAuthRequestGeneration(): Long = authRequestGenerationCounter.get()

    /**
     * Establishes a new authenticated vault session after wiping any prior session.
     */
    @Synchronized
    fun openSession(
        slotId: Int,
        dekBytes: ByteArray,
        isDecoyConfiguredInRealVault: Boolean = false
    ): SessionState.Unlocked {
        lockNow()
        val newId = generationCounter.incrementAndGet()
        val session = SessionState.Unlocked(
            sessionId = newId,
            slotId = slotId,
            internalDekBytes = dekBytes.copyOf(),
            isDecoyConfiguredInRealVault = if (slotId == REAL_SLOT) isDecoyConfiguredInRealVault else false
        )
        _sessionState.value = session
        return session
    }

    /**
     * Atomically opens a session ONLY if `expectedAuthGeneration` still matches the current
     * `authRequestGenerationCounter`. If a lock or screen-off event occurred while the KDF was
     * running, this returns null without opening the session (N03 / S02).
     */
    @Synchronized
    fun openSessionIfGenerationMatches(
        expectedAuthGeneration: Long,
        slotId: Int,
        dekBytes: ByteArray,
        isDecoyConfiguredInRealVault: Boolean = false
    ): SessionState.Unlocked? {
        if (authRequestGenerationCounter.get() != expectedAuthGeneration) {
            return null
        }
        val current = _sessionState.value
        if (current is SessionState.Unlocked) {
            current.wipeKeyMaterial()
        }
        authRequestGenerationCounter.incrementAndGet()
        val newId = generationCounter.incrementAndGet()
        val session = SessionState.Unlocked(
            sessionId = newId,
            slotId = slotId,
            internalDekBytes = dekBytes.copyOf(),
            isDecoyConfiguredInRealVault = if (slotId == REAL_SLOT) isDecoyConfiguredInRealVault else false
        )
        lastBackgroundedAtMonotonicMs = null
        filePickerGrantUntilMonotonicMs = 0L
        _sessionState.value = session
        return session
    }

    /**
     * Updates the Real Vault session's `isDecoyConfiguredInRealVault` state after Decoy Mode is
     * provisioned or disabled within the same unlocked Real session (R01).
     */
    @Synchronized
    fun updateRealVaultDecoyPolicyState(sessionId: Long, isDecoyConfigured: Boolean): SessionState.Unlocked? {
        val current = _sessionState.value
        if (current is SessionState.Unlocked && !current.isWiped && current.sessionId == sessionId && current.slotId == REAL_SLOT) {
            val dekCopy = current.borrowDekCopy()
            try {
                val updated = SessionState.Unlocked(
                    sessionId = current.sessionId,
                    slotId = current.slotId,
                    internalDekBytes = dekCopy,
                    isDecoyConfiguredInRealVault = isDecoyConfigured,
                    unlockedAtEpochMs = current.unlockedAtEpochMs
                )
                _sessionState.value = updated
                return updated
            } finally {
                Arrays.fill(dekCopy, 0.toByte())
            }
        }
        return null
    }

    /**
     * Immediately locks the active vault, zeroes key material in memory, and advances both
     * the session generation counter and the auth request generation counter so any in-flight
     * KDF or coroutine work from before the lock fails validation (N03).
     */
    @Synchronized
    fun lockNow() {
        val current = _sessionState.value
        if (current is SessionState.Unlocked) {
            current.wipeKeyMaterial()
        }
        generationCounter.incrementAndGet()
        authRequestGenerationCounter.incrementAndGet()
        lastBackgroundedAtMonotonicMs = null
        filePickerGrantUntilMonotonicMs = 0L
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
     * while still enforcing a hard 90-second ceiling if the user abandons the picker (U01).
     */
    fun beginFilePickerTransitionWindow(nowMonotonicMs: Long = monotonicClockMs()) {
        if (_sessionState.value is SessionState.Unlocked) {
            filePickerGrantUntilMonotonicMs = nowMonotonicMs + FILE_PICKER_GRANT_WINDOW_MS
        }
    }

    fun endFilePickerTransitionWindow() {
        filePickerGrantUntilMonotonicMs = 0L
    }

    fun isInFilePickerTransitionWindow(nowMonotonicMs: Long = monotonicClockMs()): Boolean {
        return filePickerGrantUntilMonotonicMs > nowMonotonicMs
    }

    fun onAppBackgrounded(nowMonotonicMs: Long = monotonicClockMs()) {
        if (_sessionState.value is SessionState.Unlocked) {
            lastBackgroundedAtMonotonicMs = nowMonotonicMs
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
        nowMonotonicMs: Long = monotonicClockMs()
    ): Boolean {
        val bgTime = lastBackgroundedAtMonotonicMs ?: return false
        lastBackgroundedAtMonotonicMs = null

        val inValidPickerWindow = filePickerGrantUntilMonotonicMs > nowMonotonicMs
        filePickerGrantUntilMonotonicMs = 0L

        val elapsed = (nowMonotonicMs - bgTime).coerceAtLeast(0L)
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

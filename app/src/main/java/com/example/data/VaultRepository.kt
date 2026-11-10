package com.example.data

import com.example.security.BiometricKeyEnvelopeHelper
import com.example.security.CryptoEngine
import com.example.security.VaultSessionManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.Arrays
import java.util.UUID
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher

/**
 * Primary repository coordinating encrypted SQLite persistence, two-slot (Real + Decoy) key
 * envelopes, authenticated record CRUD, folder lifecycle, and portable `.pvault` backups.
 *
 * Security Invariants:
 * - Both Slot 0 (Real) and Slot 1 (Decoy) envelopes are ALWAYS evaluated during `unlockWithPassword`
 *   so failed and successful unlocks execute two Argon2id derivations and two AES-GCM unwraps (`S02`).
 * - Single-flight `kdfMutex` (`N03`, `R03`) prevents concurrent Argon2id derivations from racing
 *   or exhausting heap memory.
 * - Every unlock attempt validates `expectedAuthGeneration` at the atomic session-open boundary so
 *   a lock/screen-off event while Argon2id is running cannot reopen the vault (`N03`).
 * - Decoy Mode policy state is stored inside Slot 0's authenticated inner envelope (`decoyPolicyFlag`)
 *   so an active empty decoy vault (0 records) remains recognized as active and continues to
 *   prohibit biometric enrollment (`R01`).
 * - Record decryption distinguishes valid records from corrupted/unreadable records (`N02`) so
 *   backup export and merge restore never silently drop or delete corrupted ciphertext.
 */
class VaultRepository(
    private val vaultDao: VaultDao,
    val sessionManager: VaultSessionManager = VaultSessionManager(),
    private val defaultKdfParamsProvider: () -> CryptoEngine.KdfParams = { CryptoEngine.KdfParams() }
) {

    private val kdfMutex = Mutex()

    sealed interface UnlockResult {
        data class Success(
            val session: VaultSessionManager.SessionState.Unlocked,
            val kdfDurationMs: Long
        ) : UnlockResult

        data class InvalidCredentials(
            val kdfDurationMs: Long
        ) : UnlockResult

        data object CancelledByLock : UnlockResult
    }

    data class DecryptedSlotSnapshot(
        val items: List<VaultItem>,
        val corruptedRecordIds: List<String>
    ) {
        val hasCorruptedRecords: Boolean get() = corruptedRecordIds.isNotEmpty()
    }

    class VaultRecordIntegrityException(
        val corruptedRecordIds: List<String>,
        message: String = "Detected ${corruptedRecordIds.size} unreadable or corrupted encrypted record(s) in the active vault."
    ) : IllegalStateException(message)

    /**
     * Checks whether the initial vault envelopes have been provisioned on disk.
     */
    suspend fun isVaultProvisioned(): Boolean = withContext(Dispatchers.IO) {
        val envelopes = vaultDao.getAllEnvelopes()
        envelopes.any { it.slotId == VaultSessionManager.REAL_SLOT } &&
            envelopes.any { it.slotId == VaultSessionManager.DECOY_SLOT }
    }

    /**
     * Checks whether biometric quick-unlock is currently enrolled on Slot 0 AND permitted.
     * Note: Biometric quick-unlock is automatically disabled whenever Decoy Mode is configured (`R01`).
     */
    suspend fun isBiometricUnlockEnrolled(): Boolean = withContext(Dispatchers.IO) {
        val slot0 = vaultDao.getEnvelopeForSlot(VaultSessionManager.REAL_SLOT) ?: return@withContext false
        slot0.biometricNonce != null &&
            slot0.biometricWrappedDek != null &&
            BiometricKeyEnvelopeHelper.hasKeystoreKey()
    }

    fun isBiometricKeyHardwareBacked(): Boolean {
        return BiometricKeyEnvelopeHelper.isHardwareBackedKey()
    }

    private fun deriveAndUnwrapWithLegacyFallback(
        passwordChars: CharArray,
        env: VaultEnvelopeEntity,
        slotId: Int,
        params: CryptoEngine.KdfParams
    ): CryptoEngine.UnwrappedEnvelopePayload? {
        val nfcKek = CryptoEngine.deriveKeyArgon2id(
            passwordChars = passwordChars,
            salt = env.kdfSalt,
            params = params,
            normalizeUnicodeNfc = true
        )
        try {
            val unwrapped = CryptoEngine.unwrapEnvelopePayloadOrNull(
                kekBytes = nfcKek,
                nonce = env.envelopeNonce,
                slotId = slotId,
                envelopeVersion = env.envelopeVersion,
                params = params,
                wrappedCiphertext = env.wrappedPayloadCiphertext
            )
            if (unwrapped != null || !CryptoEngine.hasDistinctLegacyNonNfcForm(passwordChars)) {
                return unwrapped
            }
        } finally {
            Arrays.fill(nfcKek, 0.toByte())
        }

        val rawKek = CryptoEngine.deriveKeyArgon2id(
            passwordChars = passwordChars,
            salt = env.kdfSalt,
            params = params,
            normalizeUnicodeNfc = false
        )
        return try {
            CryptoEngine.unwrapEnvelopePayloadOrNull(
                kekBytes = rawKek,
                nonce = env.envelopeNonce,
                slotId = slotId,
                envelopeVersion = env.envelopeVersion,
                params = params,
                wrappedCiphertext = env.wrappedPayloadCiphertext
            )
        } finally {
            Arrays.fill(rawKek, 0.toByte())
        }
    }

    /**
     * Evaluates whether Decoy Mode is currently active during an unlocked Real Vault session.
     * R01 Fix: Uses the authenticated `isDecoyConfiguredInRealVault` flag from Slot 0's inner
     * envelope rather than counting Slot 1 records, so an active empty Decoy Vault (0 records)
     * remains accurately recognized as active!
     */
    suspend fun isDecoyModeEnabledForRealSession(sessionId: Long): Boolean = withContext(Dispatchers.IO) {
        val session = sessionManager.requireActiveSession(sessionId)
        if (!session.canManageVaultSecurity) return@withContext false
        session.isDecoyConfiguredInRealVault
    }

    /**
     * Provisions a brand-new vault with:
     * - Slot 0 (Real Vault) encrypted under `realMasterPasswordChars`
     * - Slot 1 (Decoy Vault) either encrypted as an active Decoy Vault under `optionalDecoyPasswordChars`
     *   OR initialized with a structurally identical dummy envelope (`SLOT_ROLE_DUMMY`) wrapped with
     *   256-bit CSPRNG key material so no password can unwrap a dummy slot (`PV-SEC-006`).
     * - Built-in "General" folders are synthesized virtually in memory by `normalizeFoldersAndLinks`
     *   rather than persisted as initial SQLite rows (`PV-SEC-009`).
     * - Commits envelopes and initial records atomically inside a single `@Transaction` (`N06`).
     */
    suspend fun initializeNewVault(
        realMasterPasswordChars: CharArray,
        optionalDecoyPasswordChars: CharArray? = null,
        seedSampleDataInRealVault: Boolean = true,
        seedSampleDataInDecoyVault: Boolean = true
    ): VaultSessionManager.SessionState.Unlocked = withContext(Dispatchers.Default) {
        kdfMutex.withLock {
            require(realMasterPasswordChars.size >= 8) {
                "Master Password must be at least 8 characters."
            }
            if (optionalDecoyPasswordChars != null && optionalDecoyPasswordChars.isNotEmpty()) {
                require(optionalDecoyPasswordChars.size >= 8) {
                    "Decoy Password must be at least 8 characters."
                }
                require(!realMasterPasswordChars.contentEquals(optionalDecoyPasswordChars)) {
                    "Real Master Password and Decoy Password must be distinct."
                }
            }

            val params = defaultKdfParamsProvider()
            params.validateBounds()
            val now = System.currentTimeMillis()
            val hasDecoy = optionalDecoyPasswordChars != null && optionalDecoyPasswordChars.isNotEmpty()

            // 1. Build Slot 0 (Real Vault) envelope
            val salt0 = CryptoEngine.generateSalt()
            val nonce0 = CryptoEngine.generateNonce()
            val dek0 = CryptoEngine.generateDek()
            val kek0 = CryptoEngine.deriveKeyArgon2id(realMasterPasswordChars, salt0, params)

            // 2. Build Slot 1 (Decoy or Dummy) envelope
            val salt1 = CryptoEngine.generateSalt()
            val nonce1 = CryptoEngine.generateNonce()
            val dek1 = CryptoEngine.generateDek()
            var kek1: ByteArray? = null

            try {
                val payload0 = CryptoEngine.UnwrappedEnvelopePayload(
                    slotRoleFlag = CryptoEngine.SLOT_ROLE_ACTIVE,
                    decoyPolicyFlag = if (hasDecoy) CryptoEngine.DECOY_POLICY_ENABLED else CryptoEngine.DECOY_POLICY_DISABLED,
                    createdAtEpochMs = now,
                    rotatedAtEpochMs = now,
                    dekBytes = dek0
                )
                val wrapped0 = CryptoEngine.wrapEnvelopePayload(
                    kekBytes = kek0,
                    nonce = nonce0,
                    slotId = VaultSessionManager.REAL_SLOT,
                    envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                    params = params,
                    payload = payload0
                )

                val envelope0 = VaultEnvelopeEntity(
                    slotId = VaultSessionManager.REAL_SLOT,
                    envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                    kdfAlgorithm = params.algorithm,
                    kdfSalt = salt0,
                    kdfMemoryKb = params.memoryKb,
                    kdfIterations = params.iterations,
                    kdfParallelism = params.parallelism,
                    envelopeNonce = nonce0,
                    wrappedPayloadCiphertext = wrapped0,
                    biometricNonce = null,
                    biometricWrappedDek = null
                )

                // PV-SEC-006: Use 256-bit CSPRNG random key directly for dummy Slot 1 when Decoy Mode is disabled
                kek1 = if (hasDecoy) {
                    CryptoEngine.deriveKeyArgon2id(optionalDecoyPasswordChars!!, salt1, params)
                } else {
                    CryptoEngine.randomBytes(CryptoEngine.DEK_BYTES)
                }

                val payload1 = CryptoEngine.UnwrappedEnvelopePayload(
                    slotRoleFlag = if (hasDecoy) CryptoEngine.SLOT_ROLE_ACTIVE else CryptoEngine.SLOT_ROLE_DUMMY,
                    decoyPolicyFlag = CryptoEngine.DECOY_POLICY_DISABLED,
                    createdAtEpochMs = now,
                    rotatedAtEpochMs = now,
                    dekBytes = dek1
                )
                val wrapped1 = CryptoEngine.wrapEnvelopePayload(
                    kekBytes = kek1,
                    nonce = nonce1,
                    slotId = VaultSessionManager.DECOY_SLOT,
                    envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                    params = params,
                    payload = payload1
                )

                val envelope1 = VaultEnvelopeEntity(
                    slotId = VaultSessionManager.DECOY_SLOT,
                    envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                    kdfAlgorithm = params.algorithm,
                    kdfSalt = salt1,
                    kdfMemoryKb = params.memoryKb,
                    kdfIterations = params.iterations,
                    kdfParallelism = params.parallelism,
                    envelopeNonce = nonce1,
                    wrappedPayloadCiphertext = wrapped1,
                    biometricNonce = null,
                    biometricWrappedDek = null
                )

                val initialEntities = mutableListOf<EncryptedRecordEntity>()
                if (seedSampleDataInRealVault) {
                    buildStarterRealVaultRecords(now).forEach { item ->
                        initialEntities.add(encryptItemForSlot(VaultSessionManager.REAL_SLOT, dek0, item))
                    }
                }
                if (hasDecoy && seedSampleDataInDecoyVault) {
                    buildPlausibleDecoyVaultRecords(now).forEach { item ->
                        initialEntities.add(encryptItemForSlot(VaultSessionManager.DECOY_SLOT, dek1, item))
                    }
                }

                withContext(Dispatchers.IO) {
                    vaultDao.initializeVaultAtomically(
                        envelopes = listOf(envelope0, envelope1),
                        initialRecords = initialEntities
                    )
                }

                sessionManager.openSession(
                    slotId = VaultSessionManager.REAL_SLOT,
                    dekBytes = dek0,
                    isDecoyConfiguredInRealVault = hasDecoy
                )
            } finally {
                Arrays.fill(kek0, 0.toByte())
                kek1?.let { Arrays.fill(it, 0.toByte()) }
                Arrays.fill(dek0, 0.toByte())
                Arrays.fill(dek1, 0.toByte())
            }
        }
    }

    /**
     * Evaluates BOTH Slot 0 and Slot 1 key envelopes against `passwordChars`.
     *
     * Uniform Two-Slot Path (S02) + Lock-Race Prevention (N03) + Key Wiping (R05) + NFC Fallback (PV-SEC-011):
     * - Serialized via `kdfMutex` so concurrent unlock calls cannot overlap (`R03`).
     * - Always runs Argon2id + AES-GCM unwrap for Slot 0 AND Slot 1 before deciding the outcome.
     * - If `expectedAuthGeneration` no longer matches `sessionManager.currentAuthRequestGeneration()`
     *   (because a lock or screen-off event occurred while Argon2id was executing), the derived keys
     *   are wiped and `UnlockResult.CancelledByLock` is returned with the vault remaining `Locked` (`N03`).
     */
    suspend fun unlockWithPassword(
        passwordChars: CharArray,
        expectedAuthGeneration: Long = sessionManager.currentAuthRequestGeneration()
    ): UnlockResult = withContext(Dispatchers.Default) {
        kdfMutex.withLock {
            if (sessionManager.currentAuthRequestGeneration() != expectedAuthGeneration) {
                return@withLock UnlockResult.CancelledByLock
            }

            val envelopes = withContext(Dispatchers.IO) { vaultDao.getAllEnvelopes() }
            val env0 = envelopes.firstOrNull { it.slotId == VaultSessionManager.REAL_SLOT }
            val env1 = envelopes.firstOrNull { it.slotId == VaultSessionManager.DECOY_SLOT }

            if (env0 == null || env1 == null) {
                return@withLock UnlockResult.InvalidCredentials(0L)
            }

            val params0 = CryptoEngine.KdfParams(
                algorithm = env0.kdfAlgorithm,
                memoryKb = env0.kdfMemoryKb,
                iterations = env0.kdfIterations,
                parallelism = env0.kdfParallelism
            )
            val params1 = CryptoEngine.KdfParams(
                algorithm = env1.kdfAlgorithm,
                memoryKb = env1.kdfMemoryKb,
                iterations = env1.kdfIterations,
                parallelism = env1.kdfParallelism
            )
            params0.validateBounds()
            params1.validateBounds()

            val startNs = System.nanoTime()
            var unwrapped0: CryptoEngine.UnwrappedEnvelopePayload? = null
            var unwrapped1: CryptoEngine.UnwrappedEnvelopePayload? = null

            try {
                unwrapped0 = deriveAndUnwrapWithLegacyFallback(
                    passwordChars = passwordChars,
                    env = env0,
                    slotId = VaultSessionManager.REAL_SLOT,
                    params = params0
                )

                unwrapped1 = deriveAndUnwrapWithLegacyFallback(
                    passwordChars = passwordChars,
                    env = env1,
                    slotId = VaultSessionManager.DECOY_SLOT,
                    params = params1
                )

                val elapsedMs = ((System.nanoTime() - startNs) / 1_000_000L).coerceAtLeast(1L)

                return@withLock when {
                    unwrapped0 != null && unwrapped0.isActiveVault -> {
                        // Backward compatibility: if Slot 1 currently has records from a v1.0.0 DB
                        // created before decoyPolicyFlag was written, treat Decoy Mode as enabled too.
                        val legacyDecoyCount = if (!unwrapped0.isDecoyPolicyEnabled) {
                            withContext(Dispatchers.IO) {
                                vaultDao.countRecordsForSlot(VaultSessionManager.DECOY_SLOT)
                            }
                        } else {
                            0
                        }
                        val decoyActive = unwrapped0.isDecoyPolicyEnabled || legacyDecoyCount > 0
                        val opened = sessionManager.openSessionIfGenerationMatches(
                            expectedAuthGeneration = expectedAuthGeneration,
                            slotId = VaultSessionManager.REAL_SLOT,
                            dekBytes = unwrapped0.dekBytes,
                            isDecoyConfiguredInRealVault = decoyActive
                        )
                        if (opened != null) {
                            UnlockResult.Success(opened, elapsedMs)
                        } else {
                            UnlockResult.CancelledByLock
                        }
                    }
                    unwrapped1 != null && unwrapped1.isActiveVault -> {
                        val opened = sessionManager.openSessionIfGenerationMatches(
                            expectedAuthGeneration = expectedAuthGeneration,
                            slotId = VaultSessionManager.DECOY_SLOT,
                            dekBytes = unwrapped1.dekBytes,
                            isDecoyConfiguredInRealVault = false
                        )
                        if (opened != null) {
                            UnlockResult.Success(opened, elapsedMs)
                        } else {
                            UnlockResult.CancelledByLock
                        }
                    }
                    else -> {
                        UnlockResult.InvalidCredentials(elapsedMs)
                    }
                }
            } finally {
                unwrapped0?.wipe()
                unwrapped1?.wipe()
            }
        }
    }

    /**
     * Prepares an encryption cipher from Android Keystore for enrolling biometric quick-unlock.
     * Note: Biometric quick-unlock is only allowed for Slot 0 when Decoy Mode is disabled (`R01`).
     */
    suspend fun getCipherForBiometricEnrollment(sessionId: Long): Cipher? = withContext(Dispatchers.IO) {
        val session = sessionManager.requireActiveSession(sessionId)
        require(session.canManageVaultSecurity) {
            "Biometric settings are not available in this session."
        }
        require(!session.isDecoyConfiguredInRealVault) {
            "Biometric quick-unlock is disabled while Decoy Mode is active to protect plausible deniability."
        }
        BiometricKeyEnvelopeHelper.getEncryptCipherForEnrollment()
    }

    /**
     * Completes biometric enrollment after the user authenticates with `BiometricPrompt`.
     */
    suspend fun enrollBiometricWrapperWithAuthenticatedCipher(
        sessionId: Long,
        authenticatedCipher: Cipher
    ) = withContext(Dispatchers.IO) {
        val session = sessionManager.requireActiveSession(sessionId)
        require(session.canManageVaultSecurity) { "Unauthorized session." }
        require(!session.isDecoyConfiguredInRealVault) {
            "Biometric quick-unlock cannot be enabled while Decoy Mode is active."
        }
        val env0 = vaultDao.getEnvelopeForSlot(VaultSessionManager.REAL_SLOT)
            ?: throw IllegalStateException("Slot 0 envelope missing.")

        val dekCopy = session.borrowDekCopy()
        try {
            val wrapped = BiometricKeyEnvelopeHelper.wrapDekWithAuthenticatedCipher(
                authenticatedCipher = authenticatedCipher,
                dekBytes = dekCopy
            )
            vaultDao.upsertEnvelope(
                env0.copy(
                    biometricNonce = wrapped.iv,
                    biometricWrappedDek = wrapped.ciphertext
                )
            )
        } finally {
            Arrays.fill(dekCopy, 0.toByte())
        }
    }

    /**
     * Prepares the Android Keystore decryption cipher for biometric quick-unlock of Slot 0.
     */
    suspend fun getCipherForBiometricUnlock(): Cipher? = withContext(Dispatchers.IO) {
        val env0 = vaultDao.getEnvelopeForSlot(VaultSessionManager.REAL_SLOT) ?: return@withContext null
        val iv = env0.biometricNonce ?: return@withContext null
        if (env0.biometricWrappedDek == null) return@withContext null
        BiometricKeyEnvelopeHelper.getDecryptCipherForUnlock(iv)
    }

    /**
     * Unlocks Slot 0 using an authenticated `BiometricPrompt` cipher, checking `expectedAuthGeneration` (`N03`).
     */
    suspend fun unlockWithBiometricCipher(
        authenticatedCipher: Cipher,
        expectedAuthGeneration: Long = sessionManager.currentAuthRequestGeneration()
    ): VaultSessionManager.SessionState.Unlocked? = withContext(Dispatchers.IO) {
        val env0 = vaultDao.getEnvelopeForSlot(VaultSessionManager.REAL_SLOT) ?: return@withContext null
        val wrappedDek = env0.biometricWrappedDek ?: return@withContext null
        val dekBytes = try {
            BiometricKeyEnvelopeHelper.unwrapDekWithAuthenticatedCipher(
                authenticatedCipher = authenticatedCipher,
                ciphertext = wrappedDek
            )
        } catch (_: Exception) {
            return@withContext null
        }

        try {
            if (dekBytes.size != CryptoEngine.DEK_BYTES) return@withContext null
            sessionManager.openSessionIfGenerationMatches(
                expectedAuthGeneration = expectedAuthGeneration,
                slotId = VaultSessionManager.REAL_SLOT,
                dekBytes = dekBytes,
                isDecoyConfiguredInRealVault = false
            )
        } finally {
            Arrays.fill(dekBytes, 0.toByte())
        }
    }

    suspend fun disableBiometricUnlock() = withContext(Dispatchers.IO) {
        BiometricKeyEnvelopeHelper.deleteBiometricKey()
        val env0 = vaultDao.getEnvelopeForSlot(VaultSessionManager.REAL_SLOT) ?: return@withContext
        vaultDao.upsertEnvelope(
            env0.copy(
                biometricNonce = null,
                biometricWrappedDek = null
            )
        )
    }

    /**
     * R02 + PV-SEC-010 Fix: Rotates the password of the CURRENTLY ACTIVE vault slot (works in both
     * Slot 0 Real and Slot 1 Decoy).
     * - By default (`rekeyAllRecordsWithNewDek = false`), rotates the KEK and re-wraps the existing
     *   256-bit DEK for fast password updates.
     * - When `rekeyAllRecordsWithNewDek = true` (`PV-SEC-010`), generates a brand-new 256-bit DEK,
     *   decrypts and re-encrypts all records in the active slot under the new DEK, and commits the
     *   updated envelope + re-encrypted records atomically inside a single Room `@Transaction`.
     */
    suspend fun changeActiveVaultPassword(
        sessionId: Long,
        currentPasswordChars: CharArray,
        newPasswordChars: CharArray,
        rekeyAllRecordsWithNewDek: Boolean = false
    ) = withContext(Dispatchers.Default) {
        kdfMutex.withLock {
            val session = sessionManager.requireActiveSession(sessionId)
            require(newPasswordChars.size >= 8) {
                "New password must be at least 8 characters."
            }
            require(!currentPasswordChars.contentEquals(newPasswordChars)) {
                "New password must be different from the current password."
            }

            val activeSlotId = session.slotId
            val otherSlotId = if (activeSlotId == VaultSessionManager.REAL_SLOT) {
                VaultSessionManager.DECOY_SLOT
            } else {
                VaultSessionManager.REAL_SLOT
            }

            val activeEnv = withContext(Dispatchers.IO) {
                vaultDao.getEnvelopeForSlot(activeSlotId)
            } ?: throw IllegalStateException("Active vault envelope missing.")

            val otherEnv = withContext(Dispatchers.IO) {
                vaultDao.getEnvelopeForSlot(otherSlotId)
            }

            val currentParams = CryptoEngine.KdfParams(
                algorithm = activeEnv.kdfAlgorithm,
                memoryKb = activeEnv.kdfMemoryKb,
                iterations = activeEnv.kdfIterations,
                parallelism = activeEnv.kdfParallelism
            )
            val verifiedPayload = deriveAndUnwrapWithLegacyFallback(
                passwordChars = currentPasswordChars,
                env = activeEnv,
                slotId = activeSlotId,
                params = currentParams
            )

            if (verifiedPayload == null || !verifiedPayload.isActiveVault) {
                verifiedPayload?.wipe()
                throw IllegalArgumentException("Current password verification failed.")
            }

            // Ensure newPasswordChars does not collide with the other slot's password
            if (otherEnv != null) {
                val otherParams = CryptoEngine.KdfParams(
                    algorithm = otherEnv.kdfAlgorithm,
                    memoryKb = otherEnv.kdfMemoryKb,
                    iterations = otherEnv.kdfIterations,
                    parallelism = otherEnv.kdfParallelism
                )
                val otherUnwrapped = deriveAndUnwrapWithLegacyFallback(
                    passwordChars = newPasswordChars,
                    env = otherEnv,
                    slotId = otherSlotId,
                    params = otherParams
                )
                val collidesWithOtherSlot = otherUnwrapped != null && otherUnwrapped.isActiveVault
                otherUnwrapped?.wipe()
                require(!collidesWithOtherSlot) {
                    "This password is not available. Please choose a different password."
                }
            }

            val newSalt = CryptoEngine.generateSalt()
            val newNonce = CryptoEngine.generateNonce()
            val newKek = CryptoEngine.deriveKeyArgon2id(newPasswordChars, newSalt, currentParams)
            var newDek: ByteArray? = null
            try {
                if (!rekeyAllRecordsWithNewDek) {
                    val updatedPayload = verifiedPayload.copy(
                        rotatedAtEpochMs = System.currentTimeMillis()
                    )
                    val newWrapped = CryptoEngine.wrapEnvelopePayload(
                        kekBytes = newKek,
                        nonce = newNonce,
                        slotId = activeSlotId,
                        envelopeVersion = activeEnv.envelopeVersion,
                        params = currentParams,
                        payload = updatedPayload
                    )
                    withContext(Dispatchers.IO) {
                        vaultDao.upsertEnvelope(
                            activeEnv.copy(
                                kdfSalt = newSalt,
                                envelopeNonce = newNonce,
                                wrappedPayloadCiphertext = newWrapped
                            )
                        )
                    }
                } else {
                    val snapshot = loadDecryptedSlotSnapshotForSession(sessionId)
                    if (snapshot.hasCorruptedRecords) {
                        throw VaultRecordIntegrityException(
                            corruptedRecordIds = snapshot.corruptedRecordIds,
                            message = "Full DEK rotation aborted: ${snapshot.corruptedRecordIds.size} record(s) failed integrity verification."
                        )
                    }
                    newDek = CryptoEngine.generateDek()
                    val rotatedPayload = verifiedPayload.copy(
                        rotatedAtEpochMs = System.currentTimeMillis(),
                        dekBytes = newDek
                    )
                    val newWrapped = CryptoEngine.wrapEnvelopePayload(
                        kekBytes = newKek,
                        nonce = newNonce,
                        slotId = activeSlotId,
                        envelopeVersion = activeEnv.envelopeVersion,
                        params = currentParams,
                        payload = rotatedPayload
                    )
                    // Exclude unmodified virtual built-in default folders so SQLite row count stays clean (PV-SEC-009)
                    val itemsToPersist = snapshot.items.filterNot { item ->
                        item is VaultFolder &&
                            (item.id == VaultFolder.DEFAULT_NOTE_FOLDER_ID || item.id == VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID) &&
                            item.createdAtEpochMs == 0L
                    }
                    val reEncryptedEntities = itemsToPersist.map { item ->
                        encryptItemForSlot(activeSlotId, newDek, item)
                    }
                    if (activeSlotId == VaultSessionManager.REAL_SLOT) {
                        BiometricKeyEnvelopeHelper.deleteBiometricKey()
                    }
                    val updatedEnv = activeEnv.copy(
                        kdfSalt = newSalt,
                        envelopeNonce = newNonce,
                        wrappedPayloadCiphertext = newWrapped,
                        biometricNonce = if (activeSlotId == VaultSessionManager.REAL_SLOT) null else activeEnv.biometricNonce,
                        biometricWrappedDek = if (activeSlotId == VaultSessionManager.REAL_SLOT) null else activeEnv.biometricWrappedDek
                    )
                    withContext(Dispatchers.IO) {
                        vaultDao.rekeySlotAtomically(
                            slotId = activeSlotId,
                            updatedEnvelope = updatedEnv,
                            reEncryptedRecords = reEncryptedEntities
                        )
                    }
                    sessionManager.updateActiveSessionDek(sessionId, newDek)
                }
            } finally {
                Arrays.fill(newKek, 0.toByte())
                newDek?.let { Arrays.fill(it, 0.toByte()) }
                verifiedPayload.wipe()
            }
        }
    }

    /**
     * Backward-compatible alias for rotating the Real Master Password while Slot 0 is unlocked.
     */
    suspend fun rotateRealMasterPassword(
        sessionId: Long,
        currentPasswordChars: CharArray,
        newPasswordChars: CharArray,
        rekeyAllRecordsWithNewDek: Boolean = false
    ) {
        val session = sessionManager.requireActiveSession(sessionId)
        require(session.canManageVaultSecurity) {
            "Master Password rotation is only permitted in the primary vault."
        }
        changeActiveVaultPassword(sessionId, currentPasswordChars, newPasswordChars, rekeyAllRecordsWithNewDek)
    }

    /**
     * Verifies the Real Master Password without modifying state (used to gate the hidden Decoy
     * Policy Management sheet from Settings, `R02`).
     */
    suspend fun verifyRealMasterPasswordForSecurityGate(
        sessionId: Long,
        realMasterPasswordChars: CharArray
    ): Boolean = withContext(Dispatchers.Default) {
        kdfMutex.withLock {
            val session = sessionManager.requireActiveSession(sessionId)
            if (!session.canManageVaultSecurity) return@withLock false
            val env0 = withContext(Dispatchers.IO) {
                vaultDao.getEnvelopeForSlot(VaultSessionManager.REAL_SLOT)
            } ?: return@withLock false

            val params0 = CryptoEngine.KdfParams(
                algorithm = env0.kdfAlgorithm,
                memoryKb = env0.kdfMemoryKb,
                iterations = env0.kdfIterations,
                parallelism = env0.kdfParallelism
            )
            val unwrapped0 = deriveAndUnwrapWithLegacyFallback(
                passwordChars = realMasterPasswordChars,
                env = env0,
                slotId = VaultSessionManager.REAL_SLOT,
                params = params0
            )
            val valid = unwrapped0 != null && unwrapped0.isActiveVault
            unwrapped0?.wipe()
            valid
        }
    }

    /**
     * N05 Fix (Flow 1 — First-Time Provisioning OR Explicit Destructive Reset):
     * Provisions or resets Slot 1 (Decoy Vault) with a brand-new DEK, updates Slot 0's inner
     * envelope `decoyPolicyFlag = DECOY_POLICY_ENABLED`, clears biometric wrappers on Slot 0,
     * and commits everything atomically (`N06`, `R01`).
     *
     * If Decoy Mode is already enabled on this vault, requires `allowDestructiveReset = true`
     * so calling this method can never accidentally wipe existing decoy records (`N05`).
     */
    suspend fun configureDecoyVault(
        sessionId: Long,
        realMasterPasswordChars: CharArray,
        decoyPasswordChars: CharArray,
        seedSampleData: Boolean = true,
        allowDestructiveReset: Boolean = false
    ) = withContext(Dispatchers.Default) {
        kdfMutex.withLock {
            val session = sessionManager.requireActiveSession(sessionId)
            require(session.canManageVaultSecurity) {
                "Decoy Vault configuration is only available in the primary vault."
            }
            if (session.isDecoyConfiguredInRealVault && !allowDestructiveReset) {
                throw IllegalStateException(
                    "Decoy Vault is already provisioned. Use Change Decoy Password to keep existing decoy records, or confirm Reset & Wipe Decoy Vault."
                )
            }
            require(decoyPasswordChars.size >= 8) {
                "Decoy Password must be at least 8 characters."
            }
            require(!realMasterPasswordChars.contentEquals(decoyPasswordChars)) {
                "Decoy Password must be different from your Real Master Password."
            }

            val env0 = withContext(Dispatchers.IO) {
                vaultDao.getEnvelopeForSlot(VaultSessionManager.REAL_SLOT)
            } ?: throw IllegalStateException("Slot 0 envelope missing.")

            val params0 = CryptoEngine.KdfParams(
                algorithm = env0.kdfAlgorithm,
                memoryKb = env0.kdfMemoryKb,
                iterations = env0.kdfIterations,
                parallelism = env0.kdfParallelism
            )
            val kek0 = CryptoEngine.deriveKeyArgon2id(realMasterPasswordChars, env0.kdfSalt, params0)
            val unwrapped0 = deriveAndUnwrapWithLegacyFallback(
                passwordChars = realMasterPasswordChars,
                env = env0,
                slotId = VaultSessionManager.REAL_SLOT,
                params = params0
            )
            if (unwrapped0 == null || !unwrapped0.isActiveVault) {
                Arrays.fill(kek0, 0.toByte())
                unwrapped0?.wipe()
                throw IllegalArgumentException("Real Master Password verification failed.")
            }

            val now = System.currentTimeMillis()
            val salt1 = CryptoEngine.generateSalt()
            val nonce1 = CryptoEngine.generateNonce()
            val dek1 = CryptoEngine.generateDek()
            val kek1 = CryptoEngine.deriveKeyArgon2id(decoyPasswordChars, salt1, params0)

            try {
                // Re-wrap Slot 0 with decoyPolicyFlag = DECOY_POLICY_ENABLED and clear biometrics (R01)
                BiometricKeyEnvelopeHelper.deleteBiometricKey()
                val newNonce0 = CryptoEngine.generateNonce()
                val updatedPayload0 = unwrapped0.copy(
                    decoyPolicyFlag = CryptoEngine.DECOY_POLICY_ENABLED,
                    rotatedAtEpochMs = now
                )
                val rewrapped0 = CryptoEngine.wrapEnvelopePayload(
                    kekBytes = kek0,
                    nonce = newNonce0,
                    slotId = VaultSessionManager.REAL_SLOT,
                    envelopeVersion = env0.envelopeVersion,
                    params = params0,
                    payload = updatedPayload0
                )
                val updatedEnv0 = env0.copy(
                    envelopeNonce = newNonce0,
                    wrappedPayloadCiphertext = rewrapped0,
                    biometricNonce = null,
                    biometricWrappedDek = null
                )

                val payload1 = CryptoEngine.UnwrappedEnvelopePayload(
                    slotRoleFlag = CryptoEngine.SLOT_ROLE_ACTIVE,
                    decoyPolicyFlag = CryptoEngine.DECOY_POLICY_DISABLED,
                    createdAtEpochMs = now,
                    rotatedAtEpochMs = now,
                    dekBytes = dek1
                )
                val wrapped1 = CryptoEngine.wrapEnvelopePayload(
                    kekBytes = kek1,
                    nonce = nonce1,
                    slotId = VaultSessionManager.DECOY_SLOT,
                    envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                    params = params0,
                    payload = payload1
                )
                val updatedEnv1 = VaultEnvelopeEntity(
                    slotId = VaultSessionManager.DECOY_SLOT,
                    envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                    kdfAlgorithm = params0.algorithm,
                    kdfSalt = salt1,
                    kdfMemoryKb = params0.memoryKb,
                    kdfIterations = params0.iterations,
                    kdfParallelism = params0.parallelism,
                    envelopeNonce = nonce1,
                    wrappedPayloadCiphertext = wrapped1,
                    biometricNonce = null,
                    biometricWrappedDek = null
                )

                // PV-SEC-009: Do not write built-in default folders as SQLite rows; only write sample records if enabled
                val seedEntities = mutableListOf<EncryptedRecordEntity>()
                if (seedSampleData) {
                    buildPlausibleDecoyVaultRecords(now).forEach { item ->
                        seedEntities.add(encryptItemForSlot(VaultSessionManager.DECOY_SLOT, dek1, item))
                    }
                }

                withContext(Dispatchers.IO) {
                    vaultDao.provisionOrResetDecoyAtomically(
                        updatedRealEnvelope = updatedEnv0,
                        updatedDecoyEnvelope = updatedEnv1,
                        decoySlotId = VaultSessionManager.DECOY_SLOT,
                        seedRecords = seedEntities
                    )
                }
                sessionManager.updateRealVaultDecoyPolicyState(sessionId, isDecoyConfigured = true)
            } finally {
                Arrays.fill(kek0, 0.toByte())
                Arrays.fill(kek1, 0.toByte())
                Arrays.fill(dek1, 0.toByte())
                unwrapped0.wipe()
            }
        }
    }

    /**
     * N05 Fix (Flow 2 — Non-Destructive Decoy Password Rotation from Real Vault):
     * Verifies the current Decoy Password, unwraps the existing Slot 1 DEK, and re-wraps that
     * exact same Slot 1 DEK under `newDecoyPasswordChars` with a fresh salt and nonce so ALL
     * existing Slot 1 decoy notes, credentials, and folders remain 100% intact!
     */
    suspend fun rotateDecoyPasswordPreservingRecords(
        sessionId: Long,
        realMasterPasswordChars: CharArray,
        currentDecoyPasswordChars: CharArray,
        newDecoyPasswordChars: CharArray
    ) = withContext(Dispatchers.Default) {
        kdfMutex.withLock {
            val session = sessionManager.requireActiveSession(sessionId)
            require(session.canManageVaultSecurity) {
                "Decoy Vault management is only available in the primary vault."
            }
            require(newDecoyPasswordChars.size >= 8) {
                "New Decoy Password must be at least 8 characters."
            }
            require(!realMasterPasswordChars.contentEquals(newDecoyPasswordChars)) {
                "New Decoy Password must be different from your Real Master Password."
            }
            require(!currentDecoyPasswordChars.contentEquals(newDecoyPasswordChars)) {
                "New Decoy Password must be different from the current Decoy Password."
            }

            val env0 = withContext(Dispatchers.IO) {
                vaultDao.getEnvelopeForSlot(VaultSessionManager.REAL_SLOT)
            } ?: throw IllegalStateException("Slot 0 envelope missing.")
            val env1 = withContext(Dispatchers.IO) {
                vaultDao.getEnvelopeForSlot(VaultSessionManager.DECOY_SLOT)
            } ?: throw IllegalStateException("Slot 1 envelope missing.")

            val params0 = CryptoEngine.KdfParams(
                algorithm = env0.kdfAlgorithm,
                memoryKb = env0.kdfMemoryKb,
                iterations = env0.kdfIterations,
                parallelism = env0.kdfParallelism
            )
            val params1 = CryptoEngine.KdfParams(
                algorithm = env1.kdfAlgorithm,
                memoryKb = env1.kdfMemoryKb,
                iterations = env1.kdfIterations,
                parallelism = env1.kdfParallelism
            )

            var newKek1: ByteArray? = null
            var unwrapped0: CryptoEngine.UnwrappedEnvelopePayload? = null
            var unwrapped1: CryptoEngine.UnwrappedEnvelopePayload? = null

            try {
                unwrapped0 = deriveAndUnwrapWithLegacyFallback(
                    passwordChars = realMasterPasswordChars,
                    env = env0,
                    slotId = VaultSessionManager.REAL_SLOT,
                    params = params0
                )
                if (unwrapped0 == null || !unwrapped0.isActiveVault) {
                    throw IllegalArgumentException("Real Master Password verification failed.")
                }

                unwrapped1 = deriveAndUnwrapWithLegacyFallback(
                    passwordChars = currentDecoyPasswordChars,
                    env = env1,
                    slotId = VaultSessionManager.DECOY_SLOT,
                    params = params1
                )
                if (unwrapped1 == null || !unwrapped1.isActiveVault) {
                    throw IllegalArgumentException("Current Decoy Password verification failed.")
                }

                val newSalt1 = CryptoEngine.generateSalt()
                val newNonce1 = CryptoEngine.generateNonce()
                newKek1 = CryptoEngine.deriveKeyArgon2id(newDecoyPasswordChars, newSalt1, params1)
                val updatedPayload1 = unwrapped1.copy(
                    rotatedAtEpochMs = System.currentTimeMillis()
                )
                val rewrapped1 = CryptoEngine.wrapEnvelopePayload(
                    kekBytes = newKek1,
                    nonce = newNonce1,
                    slotId = VaultSessionManager.DECOY_SLOT,
                    envelopeVersion = env1.envelopeVersion,
                    params = params1,
                    payload = updatedPayload1
                )

                withContext(Dispatchers.IO) {
                    vaultDao.upsertEnvelope(
                        env1.copy(
                            kdfSalt = newSalt1,
                            envelopeNonce = newNonce1,
                            wrappedPayloadCiphertext = rewrapped1
                        )
                    )
                }
            } finally {
                newKek1?.let { Arrays.fill(it, 0.toByte()) }
                unwrapped0?.wipe()
                unwrapped1?.wipe()
            }
        }
    }

    /**
     * Disables Decoy Mode by replacing Slot 1 with a fresh unconfigured dummy envelope wrapped
     * with CSPRNG key material (`PV-SEC-006`), setting `decoyPolicyFlag = DECOY_POLICY_DISABLED`
     * in Slot 0, and deleting all Slot 1 records inside a single atomic `@Transaction` (`N06`, `R01`).
     */
    suspend fun disableDecoyVault(
        sessionId: Long,
        realMasterPasswordChars: CharArray
    ) = withContext(Dispatchers.Default) {
        kdfMutex.withLock {
            val session = sessionManager.requireActiveSession(sessionId)
            require(session.canManageVaultSecurity) { "Unauthorized session." }

            val env0 = withContext(Dispatchers.IO) {
                vaultDao.getEnvelopeForSlot(VaultSessionManager.REAL_SLOT)
            } ?: throw IllegalStateException("Slot 0 envelope missing.")

            val params0 = CryptoEngine.KdfParams(
                algorithm = env0.kdfAlgorithm,
                memoryKb = env0.kdfMemoryKb,
                iterations = env0.kdfIterations,
                parallelism = env0.kdfParallelism
            )
            val kek0 = CryptoEngine.deriveKeyArgon2id(realMasterPasswordChars, env0.kdfSalt, params0)
            val unwrapped0 = deriveAndUnwrapWithLegacyFallback(
                passwordChars = realMasterPasswordChars,
                env = env0,
                slotId = VaultSessionManager.REAL_SLOT,
                params = params0
            )
            if (unwrapped0 == null || !unwrapped0.isActiveVault) {
                Arrays.fill(kek0, 0.toByte())
                unwrapped0?.wipe()
                throw IllegalArgumentException("Real Master Password verification failed.")
            }

            val now = System.currentTimeMillis()
            val salt1 = CryptoEngine.generateSalt()
            val nonce1 = CryptoEngine.generateNonce()
            val dek1 = CryptoEngine.generateDek()
            // PV-SEC-006 Fix: Generate 256-bit random dummy KEK directly from SecureRandom
            val kek1 = CryptoEngine.randomBytes(CryptoEngine.DEK_BYTES)

            try {
                val newNonce0 = CryptoEngine.generateNonce()
                val updatedPayload0 = unwrapped0.copy(
                    decoyPolicyFlag = CryptoEngine.DECOY_POLICY_DISABLED,
                    rotatedAtEpochMs = now
                )
                val rewrapped0 = CryptoEngine.wrapEnvelopePayload(
                    kekBytes = kek0,
                    nonce = newNonce0,
                    slotId = VaultSessionManager.REAL_SLOT,
                    envelopeVersion = env0.envelopeVersion,
                    params = params0,
                    payload = updatedPayload0
                )
                val updatedEnv0 = env0.copy(
                    envelopeNonce = newNonce0,
                    wrappedPayloadCiphertext = rewrapped0
                )

                val payload1 = CryptoEngine.UnwrappedEnvelopePayload(
                    slotRoleFlag = CryptoEngine.SLOT_ROLE_DUMMY,
                    decoyPolicyFlag = CryptoEngine.DECOY_POLICY_DISABLED,
                    createdAtEpochMs = now,
                    rotatedAtEpochMs = now,
                    dekBytes = dek1
                )
                val wrapped1 = CryptoEngine.wrapEnvelopePayload(
                    kekBytes = kek1,
                    nonce = nonce1,
                    slotId = VaultSessionManager.DECOY_SLOT,
                    envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                    params = params0,
                    payload = payload1
                )

                val dummyEnv1 = VaultEnvelopeEntity(
                    slotId = VaultSessionManager.DECOY_SLOT,
                    envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                    kdfAlgorithm = params0.algorithm,
                    kdfSalt = salt1,
                    kdfMemoryKb = params0.memoryKb,
                    kdfIterations = params0.iterations,
                    kdfParallelism = params0.parallelism,
                    envelopeNonce = nonce1,
                    wrappedPayloadCiphertext = wrapped1
                )

                withContext(Dispatchers.IO) {
                    vaultDao.disableDecoyAtomically(
                        updatedRealEnvelope = updatedEnv0,
                        dummyDecoyEnvelope = dummyEnv1,
                        decoySlotId = VaultSessionManager.DECOY_SLOT
                    )
                }
                sessionManager.updateRealVaultDecoyPolicyState(sessionId, isDecoyConfigured = false)
            } finally {
                Arrays.fill(kek0, 0.toByte())
                Arrays.fill(kek1, 0.toByte())
                Arrays.fill(dek1, 0.toByte())
                unwrapped0.wipe()
            }
        }
    }

    /**
     * Loads and decrypts all records belonging to the currently active session slot, returning
     * both decrypted items and any corrupted record IDs (`N02`) while automatically canonicalizing
     * `folderId` links (`R12`).
     */
    suspend fun loadDecryptedSlotSnapshotForSession(sessionId: Long): DecryptedSlotSnapshot =
        withContext(Dispatchers.Default) {
            val session = sessionManager.requireActiveSession(sessionId)
            val dekCopy = session.borrowDekCopy()
            try {
                val entities = withContext(Dispatchers.IO) {
                    vaultDao.getRecordsForSlot(session.slotId)
                }
                val decodedItems = mutableListOf<VaultItem>()
                val corruptedIds = mutableListOf<String>()

                for (entity in entities) {
                    when (val res = decryptEntityStructured(session.slotId, dekCopy, entity)) {
                        is RecordDecryptResult.Success -> decodedItems.add(res.item)
                        is RecordDecryptResult.Corrupted -> corruptedIds.add(res.recordId)
                    }
                }

                // Ensure default "General" folders exist and canonicalize folderId links (R12)
                val normalizedItems = normalizeFoldersAndLinks(decodedItems)
                DecryptedSlotSnapshot(
                    items = normalizedItems,
                    corruptedRecordIds = corruptedIds
                )
            } finally {
                Arrays.fill(dekCopy, 0.toByte())
            }
        }

    /**
     * Loads and decrypts all valid records belonging to the currently active session slot.
     */
    suspend fun loadDecryptedRecordsForSession(sessionId: Long): List<VaultItem> {
        return loadDecryptedSlotSnapshotForSession(sessionId).items
    }

    /**
     * Encrypts and saves a `VaultItem` (`NoteRecord`, `CredentialRecord`, or `VaultFolder`)
     * into the active session's slot only after validating `sessionId`.
     */
    suspend fun saveVaultItem(sessionId: Long, item: VaultItem) = withContext(Dispatchers.Default) {
        val session = sessionManager.requireActiveSession(sessionId)
        val dekCopy = session.borrowDekCopy()
        try {
            val entity = encryptItemForSlot(session.slotId, dekCopy, item)
            if (!sessionManager.isSessionActive(sessionId)) {
                throw IllegalStateException("Vault locked before write could complete.")
            }
            withContext(Dispatchers.IO) {
                vaultDao.upsertRecord(entity)
            }
        } finally {
            Arrays.fill(dekCopy, 0.toByte())
        }
    }

    suspend fun deleteVaultItem(sessionId: Long, recordId: String) = withContext(Dispatchers.IO) {
        val session = sessionManager.requireActiveSession(sessionId)
        vaultDao.deleteRecord(session.slotId, recordId)
    }

    /**
     * R12 Fix: Renames an existing custom folder and updates all notes/credentials bound to that
     * folder's `folderId` (or legacy `folderName`) so no record is orphaned.
     */
    suspend fun renameVaultFolder(
        sessionId: Long,
        folderId: String,
        newNameRaw: String
    ) = withContext(Dispatchers.Default) {
        val newName = newNameRaw.trim()
        require(newName.isNotEmpty() && newName.length <= 60) {
            "Folder name must be between 1 and 60 characters."
        }
        require(!VaultFolder.isReservedAllName(newName)) {
            "\"All\" is reserved for the view filter."
        }
        require(!VaultFolder.isDefaultGeneralName(newName)) {
            "\"General\" is the built-in default folder."
        }

        val session = sessionManager.requireActiveSession(sessionId)
        val snapshot = loadDecryptedSlotSnapshotForSession(sessionId)
        val targetFolder = snapshot.items.filterIsInstance<VaultFolder>().firstOrNull { it.id == folderId }
            ?: throw IllegalArgumentException("Folder not found.")

        val duplicateExists = snapshot.items.filterIsInstance<VaultFolder>().any {
            it.scope == targetFolder.scope &&
                it.id != targetFolder.id &&
                it.name.trim().equals(newName, ignoreCase = true)
        }
        require(!duplicateExists) {
            "A folder named \"$newName\" already exists."
        }

        val now = System.currentTimeMillis()
        val updatedFolder = targetFolder.copy(name = newName, updatedAtEpochMs = now)
        val updatedRecords = mutableListOf<VaultItem>(updatedFolder)

        snapshot.items.forEach { item ->
            when (item) {
                is NoteRecord -> {
                    if (targetFolder.scope == FolderScope.NOTES &&
                        (item.folderId == targetFolder.id || item.folderName.equals(targetFolder.name, ignoreCase = true))
                    ) {
                        updatedRecords.add(
                            item.copy(
                                folderId = targetFolder.id,
                                folderName = newName,
                                updatedAtEpochMs = now
                            )
                        )
                    }
                }
                is CredentialRecord -> {
                    if (targetFolder.scope == FolderScope.CREDENTIALS &&
                        (item.folderId == targetFolder.id || item.folderName.equals(targetFolder.name, ignoreCase = true))
                    ) {
                        updatedRecords.add(
                            item.copy(
                                folderId = targetFolder.id,
                                folderName = newName,
                                updatedAtEpochMs = now
                            )
                        )
                    }
                }
                else -> {}
            }
        }

        val dekCopy = session.borrowDekCopy()
        try {
            val entities = updatedRecords.map { encryptItemForSlot(session.slotId, dekCopy, it) }
            if (!sessionManager.isSessionActive(sessionId)) {
                throw IllegalStateException("Vault locked before folder rename could complete.")
            }
            withContext(Dispatchers.IO) {
                vaultDao.upsertRecords(entities)
            }
        } finally {
            Arrays.fill(dekCopy, 0.toByte())
        }
    }

    /**
     * R12 Fix: Deletes a custom folder and reassigns all records inside it to the built-in
     * `"General"` folder (`DEFAULT_NOTE_FOLDER_ID` or `DEFAULT_CREDENTIAL_FOLDER_ID`) so deleting
     * a folder never deletes or orphans user notes or credentials.
     */
    suspend fun deleteVaultFolderAndReassignRecords(
        sessionId: Long,
        folderId: String
    ) = withContext(Dispatchers.Default) {
        require(
            folderId != VaultFolder.DEFAULT_NOTE_FOLDER_ID &&
                folderId != VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID
        ) {
            "The built-in General folder cannot be deleted."
        }

        val session = sessionManager.requireActiveSession(sessionId)
        val snapshot = loadDecryptedSlotSnapshotForSession(sessionId)
        val targetFolder = snapshot.items.filterIsInstance<VaultFolder>().firstOrNull { it.id == folderId }
            ?: return@withContext
        require(!VaultFolder.isDefaultGeneralName(targetFolder.name)) {
            "The built-in General folder cannot be deleted."
        }

        val now = System.currentTimeMillis()
        val reassignedItems = mutableListOf<VaultItem>()
        snapshot.items.forEach { item ->
            when (item) {
                is NoteRecord -> {
                    if (targetFolder.scope == FolderScope.NOTES &&
                        (item.folderId == targetFolder.id || item.folderName.equals(targetFolder.name, ignoreCase = true))
                    ) {
                        reassignedItems.add(
                            item.copy(
                                folderId = VaultFolder.DEFAULT_NOTE_FOLDER_ID,
                                folderName = VaultFolder.DEFAULT_FOLDER_NAME,
                                updatedAtEpochMs = now
                            )
                        )
                    }
                }
                is CredentialRecord -> {
                    if (targetFolder.scope == FolderScope.CREDENTIALS &&
                        (item.folderId == targetFolder.id || item.folderName.equals(targetFolder.name, ignoreCase = true))
                    ) {
                        reassignedItems.add(
                            item.copy(
                                folderId = VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID,
                                folderName = VaultFolder.DEFAULT_FOLDER_NAME,
                                updatedAtEpochMs = now
                            )
                        )
                    }
                }
                else -> {}
            }
        }

        val dekCopy = session.borrowDekCopy()
        try {
            val entities = reassignedItems.map { encryptItemForSlot(session.slotId, dekCopy, it) }
            if (!sessionManager.isSessionActive(sessionId)) {
                throw IllegalStateException("Vault locked before folder deletion could complete.")
            }
            withContext(Dispatchers.IO) {
                if (entities.isNotEmpty()) {
                    vaultDao.upsertRecords(entities)
                }
                vaultDao.deleteRecord(session.slotId, targetFolder.id)
            }
        } finally {
            Arrays.fill(dekCopy, 0.toByte())
        }
    }

    /**
     * Generates an encrypted `.pvault` byte array for the active session's slot.
     *
     * N02 Fix: If any record in the active slot fails AEAD authentication or decoding, aborts
     * the ordinary export with `VaultRecordIntegrityException` unless the caller explicitly sets
     * `allowSkipCorruptedRecords = true` (Recovery Export mode).
     * PV-BUG-009 Fix: Supports scoped export (`ALL_DATA`, `NOTES_ONLY`, `PASSWORDS_ONLY`).
     */
    suspend fun prepareEncryptedBackupBytes(
        sessionId: Long,
        backupPasswordChars: CharArray,
        appVersionName: String = "1.0.4",
        allowSkipCorruptedRecords: Boolean = false,
        exportScope: PortableBackupEngine.BackupExportScope = PortableBackupEngine.BackupExportScope.ALL_DATA
    ): ByteArray = withContext(Dispatchers.Default) {
        val snapshot = loadDecryptedSlotSnapshotForSession(sessionId)
        if (snapshot.hasCorruptedRecords && !allowSkipCorruptedRecords) {
            throw VaultRecordIntegrityException(
                corruptedRecordIds = snapshot.corruptedRecordIds,
                message = "Backup aborted: ${snapshot.corruptedRecordIds.size} encrypted record(s) failed integrity verification. Enable Recovery Export if you wish to export only intact records."
            )
        }
        val filteredItems = when (exportScope) {
            PortableBackupEngine.BackupExportScope.ALL_DATA -> snapshot.items
            PortableBackupEngine.BackupExportScope.NOTES_ONLY -> snapshot.items.filter { item ->
                item is NoteRecord || (item is VaultFolder && item.scope == FolderScope.NOTES)
            }
            PortableBackupEngine.BackupExportScope.PASSWORDS_ONLY -> snapshot.items.filter { item ->
                item is CredentialRecord || (item is VaultFolder && item.scope == FolderScope.CREDENTIALS)
            }
        }
        val params = defaultKdfParamsProvider()
        PortableBackupEngine.createEncryptedBackupBytes(
            items = filteredItems,
            backupPasswordChars = backupPasswordChars,
            appVersionName = appVersionName,
            kdfParams = params
        )
    }

    /**
     * Decrypts, verifies, and applies a `.pvault` backup into the currently unlocked vault slot.
     *
     * - Authenticates the entire `.pvault` file in memory before touching SQLite.
     * - Binds `originSlotId` at the start and verifies `sessionManager.requireActiveSession(sessionId)`
     *   matches `originSlotId` immediately before committing the Room transaction.
     * - N02 Fix: In `MERGE_KEEP_NEWEST` mode, if any existing record in the active slot is corrupted,
     *   aborts before modifying SQLite so corrupted ciphertext is never silently deleted! Also writes
     *   merged records via `upsertRecords` rather than `deleteAllRecordsForSlot`.
     */
    suspend fun applyVerifiedBackupRestore(
        sessionId: Long,
        backupBytes: ByteArray,
        backupPasswordChars: CharArray,
        restoreMode: PortableBackupEngine.RestoreMode
    ): PortableBackupEngine.BackupPayload = withContext(Dispatchers.Default) {
        val initialSession = sessionManager.requireActiveSession(sessionId)
        val originSlotId = initialSession.slotId

        // 1. Verify and decrypt backup completely in memory before touching database
        val verifiedPayload = PortableBackupEngine.decryptAndVerifyBackupBytes(
            backupBytes = backupBytes,
            backupPasswordChars = backupPasswordChars
        )

        // 2. Re-verify active session and slot binding
        val currentSession = sessionManager.requireActiveSession(sessionId)
        check(currentSession.slotId == originSlotId) {
            "Session slot changed during restore; aborting to prevent cross-vault write."
        }

        val snapshot = loadDecryptedSlotSnapshotForSession(sessionId)
        if (restoreMode == PortableBackupEngine.RestoreMode.MERGE_KEEP_NEWEST && snapshot.hasCorruptedRecords) {
            throw VaultRecordIntegrityException(
                corruptedRecordIds = snapshot.corruptedRecordIds,
                message = "Merge restore aborted to prevent data loss: ${snapshot.corruptedRecordIds.size} existing record(s) in this vault failed integrity verification."
            )
        }

        val finalItems = when (restoreMode) {
            PortableBackupEngine.RestoreMode.REPLACE_ACTIVE_VAULT ->
                normalizeFoldersAndLinks(verifiedPayload.items)
            PortableBackupEngine.RestoreMode.MERGE_KEEP_NEWEST -> {
                PortableBackupEngine.mergeItemsKeepNewest(snapshot.items, verifiedPayload.items)
            }
        }

        val dekCopy = currentSession.borrowDekCopy()
        try {
            val newEntities = finalItems.map { item ->
                encryptItemForSlot(originSlotId, dekCopy, item)
            }

            // Final atomic session check right before Room transaction
            val finalCheckSession = sessionManager.requireActiveSession(sessionId)
            check(finalCheckSession.slotId == originSlotId) {
                "Vault session expired before restore transaction commit."
            }

            withContext(Dispatchers.IO) {
                when (restoreMode) {
                    PortableBackupEngine.RestoreMode.REPLACE_ACTIVE_VAULT -> {
                        vaultDao.replaceAllRecordsForSlot(originSlotId, newEntities)
                    }
                    PortableBackupEngine.RestoreMode.MERGE_KEEP_NEWEST -> {
                        vaultDao.upsertRecords(newEntities)
                    }
                }
            }
            verifiedPayload
        } finally {
            Arrays.fill(dekCopy, 0.toByte())
        }
    }

    private fun normalizeFoldersAndLinks(rawItems: List<VaultItem>): List<VaultItem> {
        val folders = rawItems.filterIsInstance<VaultFolder>().toMutableList()
        val hasNotesGeneral = folders.any {
            it.scope == FolderScope.NOTES &&
                (it.id == VaultFolder.DEFAULT_NOTE_FOLDER_ID || VaultFolder.isDefaultGeneralName(it.name))
        }
        if (!hasNotesGeneral) {
            folders.add(
                0,
                VaultFolder(
                    id = VaultFolder.DEFAULT_NOTE_FOLDER_ID,
                    name = VaultFolder.DEFAULT_FOLDER_NAME,
                    scope = FolderScope.NOTES,
                    createdAtEpochMs = 0L,
                    updatedAtEpochMs = 0L
                )
            )
        }
        val hasCredsGeneral = folders.any {
            it.scope == FolderScope.CREDENTIALS &&
                (it.id == VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID || VaultFolder.isDefaultGeneralName(it.name))
        }
        if (!hasCredsGeneral) {
            folders.add(
                VaultFolder(
                    id = VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID,
                    name = VaultFolder.DEFAULT_FOLDER_NAME,
                    scope = FolderScope.CREDENTIALS,
                    createdAtEpochMs = 0L,
                    updatedAtEpochMs = 0L
                )
            )
        }

        val noteFolderById = folders.filter { it.scope == FolderScope.NOTES }.associateBy { it.id }
        val noteFolderByName = folders.filter { it.scope == FolderScope.NOTES }
            .associateBy { it.name.trim().lowercase() }

        val credFolderById = folders.filter { it.scope == FolderScope.CREDENTIALS }.associateBy { it.id }
        val credFolderByName = folders.filter { it.scope == FolderScope.CREDENTIALS }
            .associateBy { it.name.trim().lowercase() }

        val normalizedNonFolders = rawItems.filterNot { it is VaultFolder }.map { item ->
            when (item) {
                is NoteRecord -> {
                    val matched = noteFolderById[item.folderId]
                        ?: noteFolderByName[item.folderName.trim().lowercase()]
                    if (matched != null) {
                        item.copy(folderId = matched.id, folderName = matched.name)
                    } else {
                        item.copy(
                            folderId = VaultFolder.DEFAULT_NOTE_FOLDER_ID,
                            folderName = VaultFolder.DEFAULT_FOLDER_NAME
                        )
                    }
                }
                is CredentialRecord -> {
                    val matched = credFolderById[item.folderId]
                        ?: credFolderByName[item.folderName.trim().lowercase()]
                    if (matched != null) {
                        item.copy(folderId = matched.id, folderName = matched.name)
                    } else {
                        item.copy(
                            folderId = VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID,
                            folderName = VaultFolder.DEFAULT_FOLDER_NAME
                        )
                    }
                }
                else -> item
            }
        }

        return folders + normalizedNonFolders
    }

    private fun encryptItemForSlot(
        slotId: Int,
        dekBytes: ByteArray,
        item: VaultItem
    ): EncryptedRecordEntity {
        val nonce = CryptoEngine.generateNonce()
        val plaintext = VaultRecordCodec.encode(item)
        try {
            val aad = CryptoEngine.buildRecordAad(
                vaultSlot = slotId,
                recordId = item.id,
                schemaVersion = CryptoEngine.RECORD_SCHEMA_VERSION
            )
            val ciphertext = CryptoEngine.encryptAesGcm(
                keyBytes = dekBytes,
                nonce = nonce,
                plaintext = plaintext,
                aad = aad
            )
            return EncryptedRecordEntity(
                recordId = item.id,
                vaultSlot = slotId,
                schemaVersion = CryptoEngine.RECORD_SCHEMA_VERSION,
                nonce = nonce,
                ciphertext = ciphertext
            )
        } finally {
            Arrays.fill(plaintext, 0.toByte())
        }
    }

    private sealed interface RecordDecryptResult {
        data class Success(val item: VaultItem) : RecordDecryptResult
        data class Corrupted(val recordId: String) : RecordDecryptResult
    }

    private fun decryptEntityStructured(
        slotId: Int,
        dekBytes: ByteArray,
        entity: EncryptedRecordEntity
    ): RecordDecryptResult {
        if (entity.vaultSlot != slotId) return RecordDecryptResult.Corrupted(entity.recordId)
        val aad = CryptoEngine.buildRecordAad(
            vaultSlot = slotId,
            recordId = entity.recordId,
            schemaVersion = entity.schemaVersion
        )
        var plaintext = ByteArray(0)
        return try {
            plaintext = CryptoEngine.decryptAesGcm(
                keyBytes = dekBytes,
                nonce = entity.nonce,
                ciphertext = entity.ciphertext,
                aad = aad
            )
            val decoded = VaultRecordCodec.decode(plaintext)
            if (decoded.id != entity.recordId) {
                RecordDecryptResult.Corrupted(entity.recordId)
            } else {
                RecordDecryptResult.Success(decoded)
            }
        } catch (_: Exception) {
            RecordDecryptResult.Corrupted(entity.recordId)
        } finally {
            if (plaintext.isNotEmpty()) {
                Arrays.fill(plaintext, 0.toByte())
            }
        }
    }

    private fun buildDefaultStarterFolders(): List<VaultFolder> {
        return listOf(
            VaultFolder(
                id = VaultFolder.DEFAULT_NOTE_FOLDER_ID,
                name = VaultFolder.DEFAULT_FOLDER_NAME,
                scope = FolderScope.NOTES,
                createdAtEpochMs = 0L,
                updatedAtEpochMs = 0L
            ),
            VaultFolder(
                id = VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID,
                name = VaultFolder.DEFAULT_FOLDER_NAME,
                scope = FolderScope.CREDENTIALS,
                createdAtEpochMs = 0L,
                updatedAtEpochMs = 0L
            )
        )
    }

    private fun buildStarterRealVaultRecords(now: Long): List<VaultItem> {
        return listOf(
            NoteRecord(
                id = UUID.randomUUID().toString(),
                title = "Welcome to PRIVATE VAULT",
                body = "## Offline-First Security Architecture\n" +
                    "- **Key Derivation:** Argon2id v1.3 (`bcprov-jdk18on`)\n" +
                    "- **Authenticated Encryption:** AES-256-GCM with per-record 96-bit nonces and strict AAD slot binding\n" +
                    "- **Zero Cloud Sync:** All notes and credentials stay encrypted on your device.",
                format = NoteBodyFormat.MARKDOWN,
                category = "Security",
                folderName = VaultFolder.DEFAULT_FOLDER_NAME,
                folderId = VaultFolder.DEFAULT_NOTE_FOLDER_ID,
                tags = listOf("architecture", "security"),
                colorAccentIndex = 1,
                isPinned = true,
                isFavorite = true,
                createdAtEpochMs = now,
                updatedAtEpochMs = now
            ),
            NoteRecord(
                id = UUID.randomUUID().toString(),
                title = "Emergency Security Checklist",
                body = "Essential offline recovery steps:",
                format = NoteBodyFormat.CHECKLIST,
                checklistItems = listOf(
                    ChecklistEntry(text = "Verify Master Password is memorized", isChecked = true),
                    ChecklistEntry(text = "Export an encrypted .pvault backup file", isChecked = false),
                    ChecklistEntry(text = "Review password strength audit scores", isChecked = false)
                ),
                category = "Personal",
                folderName = VaultFolder.DEFAULT_FOLDER_NAME,
                folderId = VaultFolder.DEFAULT_NOTE_FOLDER_ID,
                tags = listOf("backup", "checklist"),
                colorAccentIndex = 2,
                isPinned = false,
                isFavorite = false,
                createdAtEpochMs = now - 60_000L,
                updatedAtEpochMs = now - 60_000L
            )
        )
    }

    private fun buildPlausibleDecoyVaultRecords(now: Long): List<VaultItem> {
        return listOf(
            NoteRecord(
                id = UUID.randomUUID().toString(),
                title = "Weekly Grocery & Household List",
                body = "Items to pick up this weekend:",
                format = NoteBodyFormat.CHECKLIST,
                checklistItems = listOf(
                    ChecklistEntry(text = "Fresh Arabica coffee beans", isChecked = true),
                    ChecklistEntry(text = "Almond milk & Greek yogurt", isChecked = false),
                    ChecklistEntry(text = "AA rechargeable batteries", isChecked = false)
                ),
                category = "Personal",
                folderName = VaultFolder.DEFAULT_FOLDER_NAME,
                folderId = VaultFolder.DEFAULT_NOTE_FOLDER_ID,
                tags = listOf("shopping", "home"),
                colorAccentIndex = 0,
                isPinned = true,
                isFavorite = false,
                createdAtEpochMs = now - 3_600_000L,
                updatedAtEpochMs = now - 3_600_000L
            ),
            CredentialRecord(
                id = UUID.randomUUID().toString(),
                serviceName = "Local Library Wi-Fi",
                username = "guest_reader",
                password = "ReadBooks2026!Library",
                websiteUrl = "https://library.example.org",
                notes = "Public reading room access",
                category = "Wi-Fi",
                folderName = VaultFolder.DEFAULT_FOLDER_NAME,
                folderId = VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID,
                tags = listOf("wifi"),
                isFavorite = false,
                createdAtEpochMs = now - 7_200_000L,
                updatedAtEpochMs = now - 7_200_000L
            )
        )
    }
}

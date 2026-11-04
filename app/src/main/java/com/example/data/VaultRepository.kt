package com.example.data

import com.example.security.BiometricKeystoreManager
import com.example.security.CryptoEngine
import com.example.security.VaultSessionManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.io.OutputStream
import java.util.Arrays
import java.util.UUID
import javax.crypto.Cipher

/**
 * Vault-scoped encrypted repository enforcing session capabilities, two-slot unlock evaluation,
 * atomic key re-wrapping, Decoy Vault provisioning, and portable encrypted backups.
 *
 * Security Rules:
 * - Every read/write of user records requires an active `VaultSessionManager.SessionState.Unlocked`
 *   token and verifies `sessionManager.requireActiveSession(sessionId)` before and after async work.
 * - Unlocking ALWAYS evaluates Argon2id on both `Slot 0` and `Slot 1` before returning, recording
 *   the measured two-slot latency in `KdfBenchmarkResult`.
 */
class VaultRepository(
    private val vaultDao: VaultDao,
    private val sessionManager: VaultSessionManager,
    private val biometricManager: BiometricKeystoreManager? = null,
    private val defaultKdfParamsProvider: () -> CryptoEngine.KdfParams = { CryptoEngine.KdfParams() }
) {

    sealed interface UnlockResult {
        data class Success(
            val session: VaultSessionManager.SessionState.Unlocked,
            val benchmark: CryptoEngine.KdfBenchmarkResult
        ) : UnlockResult

        data class InvalidCredentials(
            val failedAttempts: Int,
            val backoffDelayMs: Long,
            val benchmark: CryptoEngine.KdfBenchmarkResult? = null
        ) : UnlockResult

        data class Error(val message: String) : UnlockResult
    }

    @Volatile
    private var consecutiveFailedAttempts: Int = 0

    /**
     * Checks whether the initial Real + Decoy key envelopes have been created on disk.
     */
    suspend fun isVaultInitialized(): Boolean = withContext(Dispatchers.IO) {
        val envelopes = vaultDao.getAllEnvelopes()
        envelopes.any { it.slotId == VaultSessionManager.REAL_SLOT } &&
            envelopes.any { it.slotId == VaultSessionManager.DECOY_SLOT }
    }

    /**
     * Checks whether Biometric Unlock is currently configured on Slot 0.
     * Note: Biometric wrapper is automatically null whenever Decoy Mode is enabled.
     */
    suspend fun isBiometricWrapperPresent(): Boolean = withContext(Dispatchers.IO) {
        val realEnv = vaultDao.getEnvelopeBySlot(VaultSessionManager.REAL_SLOT)
        realEnv?.biometricNonce != null && realEnv.biometricWrappedDek != null
    }

    /**
     * First-time atomic initialization of Slot 0 (Real Vault) and Slot 1 (Decoy Vault or
     * indistinguishable dummy slot).
     */
    suspend fun initializeNewVault(
        realPasswordChars: CharArray,
        decoyPasswordChars: CharArray? = null,
        seedSampleDecoyData: Boolean = true
    ): UnlockResult = withContext(Dispatchers.Default) {
        require(realPasswordChars.size >= 8) {
            "Master password must be at least 8 characters."
        }
        if (decoyPasswordChars != null) {
            require(decoyPasswordChars.size >= 8) {
                "Decoy password must be at least 8 characters."
            }
            require(!realPasswordChars.contentEquals(decoyPasswordChars)) {
                "Real and Decoy passwords must be different."
            }
        }

        val now = System.currentTimeMillis()
        val kdfParams = defaultKdfParamsProvider()
        kdfParams.validateBounds()

        val realDek = CryptoEngine.generateDek()
        val decoyDek = CryptoEngine.generateDek()
        val realSalt = CryptoEngine.generateSalt()
        val decoySalt = CryptoEngine.generateSalt()
        val realNonce = CryptoEngine.generateNonce()
        val decoyNonce = CryptoEngine.generateNonce()

        // If decoy password is not provided, derive Slot 1's wrapping key from a random throwaway secret
        val dummyPasswordChars = UUID.randomUUID().toString().toCharArray()
        val slot1Password = decoyPasswordChars ?: dummyPasswordChars
        val slot1RoleFlag = if (decoyPasswordChars != null) {
            CryptoEngine.SLOT_ROLE_ACTIVE
        } else {
            CryptoEngine.SLOT_ROLE_DUMMY
        }

        val startSlot0 = System.nanoTime()
        val realKek = CryptoEngine.deriveKeyArgon2id(realPasswordChars, realSalt, kdfParams)
        val slot0Ms = ((System.nanoTime() - startSlot0) / 1_000_000L).coerceAtLeast(1L)

        val startSlot1 = System.nanoTime()
        val decoyKek = CryptoEngine.deriveKeyArgon2id(slot1Password, decoySalt, kdfParams)
        val slot1Ms = ((System.nanoTime() - startSlot1) / 1_000_000L).coerceAtLeast(1L)

        try {
            val realWrapped = CryptoEngine.wrapEnvelopePayload(
                kekBytes = realKek,
                nonce = realNonce,
                slotId = VaultSessionManager.REAL_SLOT,
                envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                params = kdfParams,
                payload = CryptoEngine.UnwrappedEnvelopePayload(
                    slotRoleFlag = CryptoEngine.SLOT_ROLE_ACTIVE,
                    createdAtEpochMs = now,
                    rotatedAtEpochMs = now,
                    dekBytes = realDek
                )
            )

            val decoyWrapped = CryptoEngine.wrapEnvelopePayload(
                kekBytes = decoyKek,
                nonce = decoyNonce,
                slotId = VaultSessionManager.DECOY_SLOT,
                envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                params = kdfParams,
                payload = CryptoEngine.UnwrappedEnvelopePayload(
                    slotRoleFlag = slot1RoleFlag,
                    createdAtEpochMs = now,
                    rotatedAtEpochMs = now,
                    dekBytes = decoyDek
                )
            )

            val slot0Entity = VaultEnvelopeEntity(
                slotId = VaultSessionManager.REAL_SLOT,
                envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                kdfAlgorithm = kdfParams.algorithm,
                kdfMemoryKb = kdfParams.memoryKb,
                kdfIterations = kdfParams.iterations,
                kdfParallelism = kdfParams.parallelism,
                kdfSalt = realSalt,
                wrapNonce = realNonce,
                wrappedPayloadCiphertext = realWrapped,
                biometricNonce = null,
                biometricWrappedDek = null
            )

            val slot1Entity = VaultEnvelopeEntity(
                slotId = VaultSessionManager.DECOY_SLOT,
                envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                kdfAlgorithm = kdfParams.algorithm,
                kdfMemoryKb = kdfParams.memoryKb,
                kdfIterations = kdfParams.iterations,
                kdfParallelism = kdfParams.parallelism,
                kdfSalt = decoySalt,
                wrapNonce = decoyNonce,
                wrappedPayloadCiphertext = decoyWrapped,
                biometricNonce = null,
                biometricWrappedDek = null
            )

            withContext(Dispatchers.IO) {
                vaultDao.upsertEnvelopes(listOf(slot0Entity, slot1Entity))
                // Seed default folders for Real Vault
                val defaultFolders = createDefaultFoldersForSlot(VaultSessionManager.REAL_SLOT, realDek, now)
                vaultDao.upsertEncryptedRecords(defaultFolders)

                if (decoyPasswordChars != null) {
                    val decoyFolders = createDefaultFoldersForSlot(VaultSessionManager.DECOY_SLOT, decoyDek, now)
                    vaultDao.upsertEncryptedRecords(decoyFolders)
                    if (seedSampleDecoyData) {
                        val sampleDecoyEntities = createFictitiousDecoyRecords(decoyDek, now)
                        vaultDao.upsertEncryptedRecords(sampleDecoyEntities)
                    }
                }
            }

            if (decoyPasswordChars != null) {
                biometricManager?.deleteBiometricKey()
            }

            consecutiveFailedAttempts = 0
            val session = sessionManager.openSession(VaultSessionManager.REAL_SLOT, realDek)
            val runtime = Runtime.getRuntime()
            val benchmark = CryptoEngine.KdfBenchmarkResult(
                deviceModel = "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}".trim(),
                androidSdkInt = android.os.Build.VERSION.SDK_INT,
                memoryKbPerSlot = kdfParams.memoryKb,
                iterations = kdfParams.iterations,
                parallelism = kdfParams.parallelism,
                singleSlotDurationMs = slot0Ms,
                twoSlotUnlockDurationMs = slot0Ms + slot1Ms,
                maxHeapMb = runtime.maxMemory() / (1024 * 1024),
                usedHeapMbAfterRun = (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024)
            )
            UnlockResult.Success(session, benchmark)
        } finally {
            Arrays.fill(realDek, 0.toByte())
            Arrays.fill(decoyDek, 0.toByte())
            Arrays.fill(realKek, 0.toByte())
            Arrays.fill(decoyKek, 0.toByte())
            Arrays.fill(dummyPasswordChars, '\u0000')
        }
    }

    /**
     * Unlocks either Slot 0 (Real) or Slot 1 (Decoy) by evaluating Argon2id on BOTH envelopes
     * before returning, ensuring comparable computational cost and recording two-slot benchmark telemetry.
     */
    suspend fun unlockWithPassword(passwordChars: CharArray): UnlockResult = withContext(Dispatchers.Default) {
        val envelopes = withContext(Dispatchers.IO) { vaultDao.getAllEnvelopes() }
        val env0 = envelopes.firstOrNull { it.slotId == VaultSessionManager.REAL_SLOT }
        val env1 = envelopes.firstOrNull { it.slotId == VaultSessionManager.DECOY_SLOT }

        if (env0 == null || env1 == null) {
            return@withContext UnlockResult.Error("Vault envelopes are missing or not initialized.")
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

        try {
            params0.validateBounds()
            params1.validateBounds()
        } catch (e: Exception) {
            return@withContext UnlockResult.Error("Envelope KDF parameters failed safety bounds: ${e.message}")
        }

        val start0 = System.nanoTime()
        val kek0 = CryptoEngine.deriveKeyArgon2id(passwordChars, env0.kdfSalt, params0)
        val unwrapped0 = CryptoEngine.unwrapEnvelopePayloadOrNull(
            kekBytes = kek0,
            nonce = env0.wrapNonce,
            slotId = env0.slotId,
            envelopeVersion = env0.envelopeVersion,
            params = params0,
            wrappedCiphertext = env0.wrappedPayloadCiphertext
        )
        val duration0Ms = ((System.nanoTime() - start0) / 1_000_000L).coerceAtLeast(1L)

        val start1 = System.nanoTime()
        val kek1 = CryptoEngine.deriveKeyArgon2id(passwordChars, env1.kdfSalt, params1)
        val unwrapped1 = CryptoEngine.unwrapEnvelopePayloadOrNull(
            kekBytes = kek1,
            nonce = env1.wrapNonce,
            slotId = env1.slotId,
            envelopeVersion = env1.envelopeVersion,
            params = params1,
            wrappedCiphertext = env1.wrappedPayloadCiphertext
        )
        val duration1Ms = ((System.nanoTime() - start1) / 1_000_000L).coerceAtLeast(1L)

        val runtime = Runtime.getRuntime()
        val benchmark = CryptoEngine.KdfBenchmarkResult(
            deviceModel = "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}".trim(),
            androidSdkInt = android.os.Build.VERSION.SDK_INT,
            memoryKbPerSlot = params0.memoryKb,
            iterations = params0.iterations,
            parallelism = params0.parallelism,
            singleSlotDurationMs = duration0Ms,
            twoSlotUnlockDurationMs = duration0Ms + duration1Ms,
            maxHeapMb = runtime.maxMemory() / (1024 * 1024),
            usedHeapMbAfterRun = (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024)
        )

        try {
            return@withContext when {
                unwrapped0 != null && unwrapped0.isActiveVault -> {
                    consecutiveFailedAttempts = 0
                    val session = sessionManager.openSession(VaultSessionManager.REAL_SLOT, unwrapped0.dekBytes)
                    UnlockResult.Success(session, benchmark)
                }

                unwrapped1 != null && unwrapped1.isActiveVault -> {
                    consecutiveFailedAttempts = 0
                    val session = sessionManager.openSession(VaultSessionManager.DECOY_SLOT, unwrapped1.dekBytes)
                    UnlockResult.Success(session, benchmark)
                }

                else -> {
                    consecutiveFailedAttempts += 1
                    val backoffMs = computeBackoffDelayMs(consecutiveFailedAttempts)
                    UnlockResult.InvalidCredentials(
                        failedAttempts = consecutiveFailedAttempts,
                        backoffDelayMs = backoffMs,
                        benchmark = benchmark
                    )
                }
            }
        } finally {
            Arrays.fill(kek0, 0.toByte())
            Arrays.fill(kek1, 0.toByte())
            unwrapped0?.wipe()
            unwrapped1?.wipe()
        }
    }

    /**
     * Checks whether Decoy Mode is currently configured as an active vault.
     * Callable ONLY from an authenticated Real Vault (Slot 0) session.
     */
    suspend fun isDecoyModeEnabled(
        sessionId: Long,
        decoyCheckPasswordChars: CharArray? = null
    ): Boolean = withContext(Dispatchers.IO) {
        val session = sessionManager.requireActiveSession(sessionId)
        require(session.canManageVaultSecurity) {
            "Decoy configuration status is restricted to the primary security context."
        }
        val realEnv = vaultDao.getEnvelopeBySlot(VaultSessionManager.REAL_SLOT)
        // Also inspect whether decoy slot has records or if biometric wrapper was disabled
        val decoyRecordsCount = vaultDao.getEncryptedRecordsForSlot(VaultSessionManager.DECOY_SLOT).size
        if (decoyCheckPasswordChars != null) {
            val env1 = vaultDao.getEnvelopeBySlot(VaultSessionManager.DECOY_SLOT) ?: return@withContext false
            val params1 = CryptoEngine.KdfParams(
                env1.kdfAlgorithm,
                env1.kdfMemoryKb,
                env1.kdfIterations,
                env1.kdfParallelism
            )
            val kek1 = CryptoEngine.deriveKeyArgon2id(decoyCheckPasswordChars, env1.kdfSalt, params1)
            val unwrapped = CryptoEngine.unwrapEnvelopePayloadOrNull(
                kek1, env1.wrapNonce, env1.slotId, env1.envelopeVersion, params1, env1.wrappedPayloadCiphertext
            )
            Arrays.fill(kek1, 0.toByte())
            val active = unwrapped?.isActiveVault == true
            unwrapped?.wipe()
            return@withContext active
        }
        return@withContext decoyRecordsCount > 0 && realEnv?.biometricWrappedDek == null
    }

    /**
     * Rotates the Real Master Password atomically by re-wrapping the existing Slot 0 DEK
     * without re-encrypting every record or touching Slot 1 (Section 12, S04).
     */
    suspend fun changeRealMasterPassword(
        sessionId: Long,
        currentRealPasswordChars: CharArray,
        newRealPasswordChars: CharArray
    ): Result<Unit> = withContext(Dispatchers.Default) {
        try {
            val session = sessionManager.requireActiveSession(sessionId)
            require(session.canManageVaultSecurity) {
                "Cannot modify master security envelope from this session."
            }
            require(newRealPasswordChars.size >= 8) {
                "New master password must be at least 8 characters."
            }

            val env0 = withContext(Dispatchers.IO) {
                vaultDao.getEnvelopeBySlot(VaultSessionManager.REAL_SLOT)
            } ?: return@withContext Result.failure(IllegalStateException("Slot 0 envelope missing."))

            val env1 = withContext(Dispatchers.IO) {
                vaultDao.getEnvelopeBySlot(VaultSessionManager.DECOY_SLOT)
            } ?: return@withContext Result.failure(IllegalStateException("Slot 1 envelope missing."))

            val params0 = CryptoEngine.KdfParams(
                env0.kdfAlgorithm,
                env0.kdfMemoryKb,
                env0.kdfIterations,
                env0.kdfParallelism
            )
            val currentKek = CryptoEngine.deriveKeyArgon2id(currentRealPasswordChars, env0.kdfSalt, params0)
            val unwrapped0 = CryptoEngine.unwrapEnvelopePayloadOrNull(
                currentKek,
                env0.wrapNonce,
                env0.slotId,
                env0.envelopeVersion,
                params0,
                env0.wrappedPayloadCiphertext
            )
            Arrays.fill(currentKek, 0.toByte())

            if (unwrapped0 == null || !unwrapped0.isActiveVault) {
                unwrapped0?.wipe()
                return@withContext Result.failure(SecurityException("Current master password is incorrect."))
            }

            // Ensure new Real password does not collide with active Decoy password
            val params1 = CryptoEngine.KdfParams(
                env1.kdfAlgorithm,
                env1.kdfMemoryKb,
                env1.kdfIterations,
                env1.kdfParallelism
            )
            val testDecoyKek = CryptoEngine.deriveKeyArgon2id(newRealPasswordChars, env1.kdfSalt, params1)
            val decoyUnwrapped = CryptoEngine.unwrapEnvelopePayloadOrNull(
                testDecoyKek,
                env1.wrapNonce,
                env1.slotId,
                env1.envelopeVersion,
                params1,
                env1.wrappedPayloadCiphertext
            )
            Arrays.fill(testDecoyKek, 0.toByte())
            if (decoyUnwrapped != null && decoyUnwrapped.isActiveVault) {
                decoyUnwrapped.wipe()
                unwrapped0.wipe()
                return@withContext Result.failure(
                    IllegalArgumentException("New master password must differ from the decoy password.")
                )
            }
            decoyUnwrapped?.wipe()

            val newSalt = CryptoEngine.generateSalt()
            val newNonce = CryptoEngine.generateNonce()
            val newParams = defaultKdfParamsProvider()
            val newKek = CryptoEngine.deriveKeyArgon2id(newRealPasswordChars, newSalt, newParams)

            try {
                val now = System.currentTimeMillis()
                val rewrappedCiphertext = CryptoEngine.wrapEnvelopePayload(
                    kekBytes = newKek,
                    nonce = newNonce,
                    slotId = VaultSessionManager.REAL_SLOT,
                    envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                    params = newParams,
                    payload = CryptoEngine.UnwrappedEnvelopePayload(
                        slotRoleFlag = CryptoEngine.SLOT_ROLE_ACTIVE,
                        createdAtEpochMs = unwrapped0.createdAtEpochMs,
                        rotatedAtEpochMs = now,
                        dekBytes = unwrapped0.dekBytes
                    )
                )

                val updatedEnv0 = env0.copy(
                    envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                    kdfAlgorithm = newParams.algorithm,
                    kdfMemoryKb = newParams.memoryKb,
                    kdfIterations = newParams.iterations,
                    kdfParallelism = newParams.parallelism,
                    kdfSalt = newSalt,
                    wrapNonce = newNonce,
                    wrappedPayloadCiphertext = rewrappedCiphertext
                )

                sessionManager.requireActiveSession(sessionId)
                withContext(Dispatchers.IO) {
                    vaultDao.upsertEnvelope(updatedEnv0)
                }
                Result.success(Unit)
            } finally {
                Arrays.fill(newKek, 0.toByte())
                unwrapped0.wipe()
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Configures or updates the Decoy Vault (Slot 1) from an authenticated Real Vault (Slot 0) session.
     * Automatically disables and wipes any Real Vault biometric wrapper per Section 14 & 15 (S11).
     */
    suspend fun configureDecoyVault(
        sessionId: Long,
        realMasterPasswordChars: CharArray,
        newDecoyPasswordChars: CharArray,
        seedSampleData: Boolean = true
    ): Result<Unit> = withContext(Dispatchers.Default) {
        try {
            val session = sessionManager.requireActiveSession(sessionId)
            require(session.canManageVaultSecurity) {
                "Decoy Vault configuration requires an authenticated Real Vault session."
            }
            require(newDecoyPasswordChars.size >= 8) {
                "Decoy password must be at least 8 characters."
            }
            require(!realMasterPasswordChars.contentEquals(newDecoyPasswordChars)) {
                "Decoy password must be different from the Real master password."
            }

            // Verify Real Master Password first
            val env0 = withContext(Dispatchers.IO) {
                vaultDao.getEnvelopeBySlot(VaultSessionManager.REAL_SLOT)
            } ?: return@withContext Result.failure(IllegalStateException("Slot 0 missing."))

            val params0 = CryptoEngine.KdfParams(
                env0.kdfAlgorithm,
                env0.kdfMemoryKb,
                env0.kdfIterations,
                env0.kdfParallelism
            )
            val realKek = CryptoEngine.deriveKeyArgon2id(realMasterPasswordChars, env0.kdfSalt, params0)
            val unwrapped0 = CryptoEngine.unwrapEnvelopePayloadOrNull(
                realKek,
                env0.wrapNonce,
                env0.slotId,
                env0.envelopeVersion,
                params0,
                env0.wrappedPayloadCiphertext
            )
            Arrays.fill(realKek, 0.toByte())
            if (unwrapped0 == null || !unwrapped0.isActiveVault) {
                unwrapped0?.wipe()
                return@withContext Result.failure(SecurityException("Real master password verification failed."))
            }
            unwrapped0.wipe()

            // Create fresh Decoy DEK and envelope for Slot 1
            val now = System.currentTimeMillis()
            val decoyParams = defaultKdfParamsProvider()
            val decoySalt = CryptoEngine.generateSalt()
            val decoyNonce = CryptoEngine.generateNonce()
            val decoyDek = CryptoEngine.generateDek()
            val decoyKek = CryptoEngine.deriveKeyArgon2id(newDecoyPasswordChars, decoySalt, decoyParams)

            try {
                val wrappedDecoy = CryptoEngine.wrapEnvelopePayload(
                    kekBytes = decoyKek,
                    nonce = decoyNonce,
                    slotId = VaultSessionManager.DECOY_SLOT,
                    envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                    params = decoyParams,
                    payload = CryptoEngine.UnwrappedEnvelopePayload(
                        slotRoleFlag = CryptoEngine.SLOT_ROLE_ACTIVE,
                        createdAtEpochMs = now,
                        rotatedAtEpochMs = now,
                        dekBytes = decoyDek
                    )
                )

                val newSlot1 = VaultEnvelopeEntity(
                    slotId = VaultSessionManager.DECOY_SLOT,
                    envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                    kdfAlgorithm = decoyParams.algorithm,
                    kdfMemoryKb = decoyParams.memoryKb,
                    kdfIterations = decoyParams.iterations,
                    kdfParallelism = decoyParams.parallelism,
                    kdfSalt = decoySalt,
                    wrapNonce = decoyNonce,
                    wrappedPayloadCiphertext = wrappedDecoy,
                    biometricNonce = null,
                    biometricWrappedDek = null
                )

                // Disable biometric wrapper on Slot 0 whenever Decoy is enabled (S11)
                val scrubbedSlot0 = env0.copy(
                    biometricNonce = null,
                    biometricWrappedDek = null
                )
                biometricManager?.deleteBiometricKey()

                withContext(Dispatchers.IO) {
                    vaultDao.upsertEnvelopes(listOf(scrubbedSlot0, newSlot1))
                    vaultDao.deleteAllRecordsForSlot(VaultSessionManager.DECOY_SLOT)
                    val decoyFolders = createDefaultFoldersForSlot(VaultSessionManager.DECOY_SLOT, decoyDek, now)
                    vaultDao.upsertEncryptedRecords(decoyFolders)
                    if (seedSampleData) {
                        val samples = createFictitiousDecoyRecords(decoyDek, now)
                        vaultDao.upsertEncryptedRecords(samples)
                    }
                }
                Result.success(Unit)
            } finally {
                Arrays.fill(decoyDek, 0.toByte())
                Arrays.fill(decoyKek, 0.toByte())
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Disables Decoy Mode from an authenticated Real Vault session by overwriting Slot 1 with a
     * fresh unconfigured dummy envelope (`slotRoleFlag = 0x00`) and deleting Slot 1 records.
     */
    suspend fun disableDecoyVault(
        sessionId: Long,
        realMasterPasswordChars: CharArray
    ): Result<Unit> = withContext(Dispatchers.Default) {
        try {
            val session = sessionManager.requireActiveSession(sessionId)
            require(session.canManageVaultSecurity) {
                "Disabling Decoy Mode requires an authenticated Real Vault session."
            }

            val env0 = withContext(Dispatchers.IO) {
                vaultDao.getEnvelopeBySlot(VaultSessionManager.REAL_SLOT)
            } ?: return@withContext Result.failure(IllegalStateException("Slot 0 missing."))

            val params0 = CryptoEngine.KdfParams(
                env0.kdfAlgorithm,
                env0.kdfMemoryKb,
                env0.kdfIterations,
                env0.kdfParallelism
            )
            val realKek = CryptoEngine.deriveKeyArgon2id(realMasterPasswordChars, env0.kdfSalt, params0)
            val unwrapped0 = CryptoEngine.unwrapEnvelopePayloadOrNull(
                realKek,
                env0.wrapNonce,
                env0.slotId,
                env0.envelopeVersion,
                params0,
                env0.wrappedPayloadCiphertext
            )
            Arrays.fill(realKek, 0.toByte())
            if (unwrapped0 == null || !unwrapped0.isActiveVault) {
                unwrapped0?.wipe()
                return@withContext Result.failure(SecurityException("Real master password verification failed."))
            }
            unwrapped0.wipe()

            val now = System.currentTimeMillis()
            val dummyParams = defaultKdfParamsProvider()
            val dummySalt = CryptoEngine.generateSalt()
            val dummyNonce = CryptoEngine.generateNonce()
            val dummyDek = CryptoEngine.generateDek()
            val dummyPass = UUID.randomUUID().toString().toCharArray()
            val dummyKek = CryptoEngine.deriveKeyArgon2id(dummyPass, dummySalt, dummyParams)

            try {
                val wrappedDummy = CryptoEngine.wrapEnvelopePayload(
                    kekBytes = dummyKek,
                    nonce = dummyNonce,
                    slotId = VaultSessionManager.DECOY_SLOT,
                    envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                    params = dummyParams,
                    payload = CryptoEngine.UnwrappedEnvelopePayload(
                        slotRoleFlag = CryptoEngine.SLOT_ROLE_DUMMY,
                        createdAtEpochMs = now,
                        rotatedAtEpochMs = now,
                        dekBytes = dummyDek
                    )
                )

                val dummySlot1 = VaultEnvelopeEntity(
                    slotId = VaultSessionManager.DECOY_SLOT,
                    envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                    kdfAlgorithm = dummyParams.algorithm,
                    kdfMemoryKb = dummyParams.memoryKb,
                    kdfIterations = dummyParams.iterations,
                    kdfParallelism = dummyParams.parallelism,
                    kdfSalt = dummySalt,
                    wrapNonce = dummyNonce,
                    wrappedPayloadCiphertext = wrappedDummy,
                    biometricNonce = null,
                    biometricWrappedDek = null
                )

                withContext(Dispatchers.IO) {
                    vaultDao.upsertEnvelope(dummySlot1)
                    vaultDao.deleteAllRecordsForSlot(VaultSessionManager.DECOY_SLOT)
                }
                Result.success(Unit)
            } finally {
                Arrays.fill(dummyDek, 0.toByte())
                Arrays.fill(dummyKek, 0.toByte())
                Arrays.fill(dummyPass, '\u0000')
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Completes Biometric Unlock enrollment using a Cipher authenticated by BiometricPrompt.
     * Permitted ONLY when Decoy Mode is disabled.
     */
    suspend fun enrollBiometricWrapperWithAuthenticatedCipher(
        sessionId: Long,
        authenticatedEncryptionCipher: Cipher
    ): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val session = sessionManager.requireActiveSession(sessionId)
            require(session.canManageVaultSecurity) {
                "Biometric enrollment is only allowed in the Real Vault."
            }
            val decoyRecords = vaultDao.getEncryptedRecordsForSlot(VaultSessionManager.DECOY_SLOT)
            require(decoyRecords.isEmpty()) {
                "Biometric unlock cannot be enabled while Decoy Mode is active."
            }

            val env0 = vaultDao.getEnvelopeBySlot(VaultSessionManager.REAL_SLOT)
                ?: return@withContext Result.failure(IllegalStateException("Slot 0 envelope missing."))

            val dekCopy = session.borrowDekCopy()
            try {
                val wrappedDek = authenticatedEncryptionCipher.doFinal(dekCopy)
                val iv = authenticatedEncryptionCipher.iv
                vaultDao.upsertEnvelope(
                    env0.copy(
                        biometricNonce = iv,
                        biometricWrappedDek = wrappedDek
                    )
                )
                Result.success(Unit)
            } finally {
                Arrays.fill(dekCopy, 0.toByte())
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Unlocks Slot 0 using a Decryption Cipher authenticated by AndroidX BiometricPrompt (S12).
     */
    suspend fun unlockWithAuthenticatedBiometricCipher(
        authenticatedDecryptionCipher: Cipher
    ): Result<VaultSessionManager.SessionState.Unlocked> = withContext(Dispatchers.IO) {
        try {
            val env0 = vaultDao.getEnvelopeBySlot(VaultSessionManager.REAL_SLOT)
                ?: return@withContext Result.failure(IllegalStateException("Slot 0 envelope missing."))
            val wrapped = env0.biometricWrappedDek
                ?: return@withContext Result.failure(IllegalStateException("Biometric wrapper not configured."))

            val dekBytes = authenticatedDecryptionCipher.doFinal(wrapped)
            try {
                val session = sessionManager.openSession(VaultSessionManager.REAL_SLOT, dekBytes)
                consecutiveFailedAttempts = 0
                Result.success(session)
            } finally {
                Arrays.fill(dekBytes, 0.toByte())
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun disableBiometricUnlock(sessionId: Long): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val session = sessionManager.requireActiveSession(sessionId)
            require(session.canManageVaultSecurity) { "Unauthorized session." }
            biometricManager?.deleteBiometricKey()
            val env0 = vaultDao.getEnvelopeBySlot(VaultSessionManager.REAL_SLOT)
            if (env0 != null) {
                vaultDao.upsertEnvelope(env0.copy(biometricNonce = null, biometricWrappedDek = null))
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Observes and decrypts all records for the given active session.
     * If the session is locked or replaced, immediately stops decrypting and returns empty.
     */
    fun observeDecryptedRecords(sessionId: Long): Flow<List<VaultRecordPayload>> {
        val initialSession = sessionManager.requireActiveSession(sessionId)
        val targetSlot = initialSession.slotId

        return vaultDao.observeEncryptedRecordsForSlot(targetSlot).map { entities ->
            if (!sessionManager.isSessionActive(sessionId)) {
                return@map emptyList()
            }
            val activeSession = try {
                sessionManager.requireActiveSession(sessionId)
            } catch (_: Exception) {
                return@map emptyList()
            }
            val dekCopy = activeSession.borrowDekCopy()
            try {
                entities.mapNotNull { entity ->
                    if (!sessionManager.isSessionActive(sessionId)) return@map emptyList()
                    decryptEntityOrNull(entity, dekCopy)
                }
            } finally {
                Arrays.fill(dekCopy, 0.toByte())
            }
        }
    }

    /**
     * Atomically encrypts and saves a Note, Credential, or Folder into the active session's slot.
     * Verifies session liveness both before encryption and immediately before committing to SQLite (S07).
     */
    suspend fun saveRecord(
        sessionId: Long,
        payload: VaultRecordPayload
    ): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val session = sessionManager.requireActiveSession(sessionId)
            val dekCopy = session.borrowDekCopy()
            try {
                val entity = encryptPayloadToEntity(payload, session.slotId, dekCopy)
                // Re-verify session is still active after encryption before writing to DB (S07)
                sessionManager.requireActiveSession(sessionId)
                vaultDao.upsertEncryptedRecord(entity)
                Result.success(Unit)
            } finally {
                Arrays.fill(dekCopy, 0.toByte())
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun deleteRecordPermanently(
        sessionId: Long,
        recordId: String
    ): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val session = sessionManager.requireActiveSession(sessionId)
            vaultDao.deleteEncryptedRecordById(recordId, session.slotId)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Builds an encrypted `.pvault` byte snapshot of the currently authenticated vault slot ONLY (S08, B06).
     */
    suspend fun prepareEncryptedBackupBytes(
        sessionId: Long,
        backupPasswordChars: CharArray,
        scope: PortableBackupEngine.ExportScope
    ): Result<ByteArray> = withContext(Dispatchers.Default) {
        try {
            val session = sessionManager.requireActiveSession(sessionId)
            val dekCopy = session.borrowDekCopy()
            val decryptedRecords = try {
                val entities = withContext(Dispatchers.IO) {
                    vaultDao.getEncryptedRecordsForSlot(session.slotId)
                }
                entities.mapNotNull { decryptEntityOrNull(it, dekCopy) }
            } finally {
                Arrays.fill(dekCopy, 0.toByte())
            }

            sessionManager.requireActiveSession(sessionId)
            val bytes = PortableBackupEngine.createEncryptedBackupBytes(
                backupPasswordChars = backupPasswordChars,
                records = decryptedRecords,
                scope = scope,
                kdfParams = defaultKdfParamsProvider()
            )
            Result.success(bytes)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Writes already-encrypted `.pvault` bytes to a user-selected SAF OutputStream and flushes/closes safely.
     */
    suspend fun writeEncryptedBackupToStream(
        encryptedBytes: ByteArray,
        outputStream: OutputStream
    ): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            outputStream.use { out ->
                out.write(encryptedBytes)
                out.flush()
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Verifies and previews a `.pvault` backup stream without modifying the database.
     */
    suspend fun previewBackupFromStream(
        sessionId: Long,
        inputStream: InputStream,
        backupPasswordChars: CharArray
    ): Result<PortableBackupEngine.VerifiedBackupPreview> = withContext(Dispatchers.Default) {
        try {
            sessionManager.requireActiveSession(sessionId)
            val preview = inputStream.use { stream ->
                PortableBackupEngine.verifyAndDecryptBackup(stream, backupPasswordChars)
            }
            sessionManager.requireActiveSession(sessionId)
            Result.success(preview)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Atomically applies a verified backup preview into the currently authenticated vault slot ONLY (S09, B05).
     */
    suspend fun applyVerifiedBackupRestore(
        sessionId: Long,
        preview: PortableBackupEngine.VerifiedBackupPreview,
        mode: PortableBackupEngine.RestoreMode
    ): Result<Int> = withContext(Dispatchers.IO) {
        try {
            val session = sessionManager.requireActiveSession(sessionId)
            val dekCopy = session.borrowDekCopy()
            try {
                when (mode) {
                    PortableBackupEngine.RestoreMode.REPLACE_ACTIVE_VAULT -> {
                        val newEntities = preview.records.map { record ->
                            encryptPayloadToEntity(record, session.slotId, dekCopy)
                        }
                        sessionManager.requireActiveSession(sessionId)
                        vaultDao.replaceAllRecordsForSlot(session.slotId, newEntities)
                        Result.success(newEntities.size)
                    }

                    PortableBackupEngine.RestoreMode.MERGE_KEEP_NEWEST -> {
                        val existingEntities = vaultDao.getEncryptedRecordsForSlot(session.slotId)
                        val existingMap = existingEntities
                            .mapNotNull { decryptEntityOrNull(it, dekCopy) }
                            .associateBy { it.id }
                            .toMutableMap()

                        for (incoming in preview.records) {
                            val current = existingMap[incoming.id]
                            if (current == null || incoming.updatedAtEpochMs >= current.updatedAtEpochMs) {
                                existingMap[incoming.id] = incoming
                            }
                        }

                        val mergedEntities = existingMap.values.map { record ->
                            encryptPayloadToEntity(record, session.slotId, dekCopy)
                        }
                        sessionManager.requireActiveSession(sessionId)
                        vaultDao.replaceAllRecordsForSlot(session.slotId, mergedEntities)
                        Result.success(preview.records.size)
                    }
                }
            } finally {
                Arrays.fill(dekCopy, 0.toByte())
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun encryptPayloadToEntity(
        payload: VaultRecordPayload,
        vaultSlot: Int,
        dekBytes: ByteArray
    ): EncryptedRecordEntity {
        val plaintextBytes = VaultPayloadSerializer.serialize(payload)
        val nonce = CryptoEngine.generateNonce()
        val aad = CryptoEngine.buildRecordAad(
            vaultSlot = vaultSlot,
            recordId = payload.id,
            schemaVersion = CryptoEngine.RECORD_SCHEMA_VERSION
        )
        try {
            val ciphertext = CryptoEngine.encryptAesGcm(
                keyBytes = dekBytes,
                nonce = nonce,
                plaintext = plaintextBytes,
                aad = aad
            )
            return EncryptedRecordEntity(
                recordId = payload.id,
                vaultSlot = vaultSlot,
                schemaVersion = CryptoEngine.RECORD_SCHEMA_VERSION,
                nonce = nonce,
                ciphertext = ciphertext
            )
        } finally {
            Arrays.fill(plaintextBytes, 0.toByte())
        }
    }

    private fun decryptEntityOrNull(
        entity: EncryptedRecordEntity,
        dekBytes: ByteArray
    ): VaultRecordPayload? {
        val aad = CryptoEngine.buildRecordAad(
            vaultSlot = entity.vaultSlot,
            recordId = entity.recordId,
            schemaVersion = entity.schemaVersion
        )
        val decryptedBytes = try {
            CryptoEngine.decryptAesGcm(
                keyBytes = dekBytes,
                nonce = entity.nonce,
                ciphertext = entity.ciphertext,
                aad = aad
            )
        } catch (_: Exception) {
            return null
        }

        return try {
            VaultPayloadSerializer.deserialize(decryptedBytes)
        } catch (_: Exception) {
            null
        } finally {
            Arrays.fill(decryptedBytes, 0.toByte())
        }
    }

    private fun createDefaultFoldersForSlot(
        slotId: Int,
        dekBytes: ByteArray,
        now: Long
    ): List<EncryptedRecordEntity> {
        val folders = listOf(
            VaultRecordPayload.FolderRecord(
                id = UUID.randomUUID().toString(),
                name = "General",
                colorHex = "#10B981",
                createdAtEpochMs = now,
                updatedAtEpochMs = now
            ),
            VaultRecordPayload.FolderRecord(
                id = UUID.randomUUID().toString(),
                name = "Personal",
                colorHex = "#14B8A6",
                createdAtEpochMs = now,
                updatedAtEpochMs = now
            ),
            VaultRecordPayload.FolderRecord(
                id = UUID.randomUUID().toString(),
                name = "Work",
                colorHex = "#38BDF8",
                createdAtEpochMs = now,
                updatedAtEpochMs = now
            )
        )
        return folders.map { encryptPayloadToEntity(it, slotId, dekBytes) }
    }

    /**
     * Generates ordinary-looking fictitious records using reserved example domains (`example.com`,
     * `example.org`) when the owner chooses to pre-populate the Decoy Vault during setup.
     */
    private fun createFictitiousDecoyRecords(
        decoyDek: ByteArray,
        now: Long
    ): List<EncryptedRecordEntity> {
        val samplePayloads = listOf(
            VaultRecordPayload.NoteRecord(
                id = UUID.randomUUID().toString(),
                title = "Weekly Grocery & Errands",
                body = "Milk, whole bean coffee, olive oil, oats, sparkling water, and dish soap.",
                formatStyle = NoteFormatStyle.CHECKLIST,
                checklistItems = listOf(
                    NoteChecklistItem("1", "Coffee beans (medium roast)", true),
                    NoteChecklistItem("2", "Olive oil & pasta", false),
                    NoteChecklistItem("3", "Pick up dry cleaning on Thursday", false)
                ),
                folderName = "Personal",
                tags = listOf("errands", "home"),
                isPinned = true,
                createdAtEpochMs = now - 86_400_000L * 3,
                updatedAtEpochMs = now - 3_600_000L * 5
            ),
            VaultRecordPayload.NoteRecord(
                id = UUID.randomUUID().toString(),
                title = "Reading List & Wi-Fi Guest Info",
                body = "Home Guest Network: LivingRoom_Guest\nPassphrase: WarmCoffee2026!\n\nBooks to check out:\n- The Pragmatic Programmer\n- Designing Data-Intensive Applications",
                formatStyle = NoteFormatStyle.PARAGRAPH,
                folderName = "General",
                tags = listOf("notes", "books"),
                isPinned = false,
                createdAtEpochMs = now - 86_400_000L * 7,
                updatedAtEpochMs = now - 86_400_000L * 2
            ),
            VaultRecordPayload.CredentialRecord(
                id = UUID.randomUUID().toString(),
                serviceName = "Public Library Portal",
                accountLabel = "Personal",
                username = "reader_card_4092",
                email = "reader@example.org",
                password = "LibraryBook#8492!Read",
                websiteUrl = "https://library.example.org",
                folderName = "Personal",
                tags = listOf("reading"),
                privateNotes = "City library e-book loan account (fictitious example domain)",
                isFavorite = true,
                createdAtEpochMs = now - 86_400_000L * 10,
                updatedAtEpochMs = now - 86_400_000L * 4
            ),
            VaultRecordPayload.CredentialRecord(
                id = UUID.randomUUID().toString(),
                serviceName = "Recipe Club Newsletter",
                accountLabel = "Personal",
                username = "homecook_weekly",
                email = "kitchen@example.com",
                password = "BasilTomato$2026*Soup",
                websiteUrl = "https://recipes.example.com",
                folderName = "General",
                tags = listOf("food"),
                privateNotes = "Weekend recipe archive login",
                isFavorite = false,
                createdAtEpochMs = now - 86_400_000L * 14,
                updatedAtEpochMs = now - 86_400_000L * 6
            )
        )
        return samplePayloads.map { encryptPayloadToEntity(it, VaultSessionManager.DECOY_SLOT, decoyDek) }
    }

    private fun computeBackoffDelayMs(failedCount: Int): Long {
        return when {
            failedCount <= 2 -> 0L
            failedCount == 3 -> 1_500L
            failedCount == 4 -> 3_000L
            failedCount == 5 -> 5_000L
            else -> 8_000L
        }
    }
}

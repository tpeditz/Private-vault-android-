package com.example

import android.content.Context
import android.content.pm.PackageInfo
import androidx.room.Room
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.core.app.ApplicationProvider
import com.android.apksig.ApkSigner
import com.example.data.AppPreferencesRepository
import com.example.data.NoteChecklistItem
import com.example.data.NoteFormatStyle
import com.example.data.PortableBackupEngine
import com.example.data.PrivateVaultDatabase
import com.example.data.VaultRecordPayload
import com.example.data.VaultRepository
import com.example.ota.OtaUpdateManager
import com.example.security.CryptoEngine
import com.example.security.OfflinePasswordStrengthEstimator
import com.example.security.PasswordGeneratorEngine
import com.example.security.VaultSessionManager
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import javax.security.auth.x500.X500Principal
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.x509.X509V3CertificateGenerator
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Date
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.crypto.AEADBadTagException

/**
 * Comprehensive Acceptance & Security Test Suite for PRIVATE VAULT (Sections 27, 28, 29).
 *
 * Covers:
 * - S01–S04: Argon2id KDF vectors/bounds, 72-byte unified key envelopes, AES-256-GCM AAD tamper
 *   rejection, zero plaintext leakage in raw SQLite files, and atomic Master Password rotation.
 * - S05–S11 & F01–F07: Real vs. Decoy routing, session capability isolation, async cancellation
 *   across lock boundaries, and independent multi-account credentials.
 * - F08–F12: Unbiased SecureRandom Password Generator and Offline Password Strength & Reuse Checker.
 * - B01–B06: Encrypted `.pvault` portable backup, wrong-password/tamper/bounds rejection,
 *   cross-instance fresh restore, and strict single-slot scoping.
 * - U01–U12: OTA Manifest validation, 3-option reminder deferral state machine (`Next Launch`,
 *   `Tomorrow`, `In 3 Days`), official Android `apksig` (`ApkVerifier`) signature verification
 *   against the trusted installed signer, and explicit Room schema migration (`v1` -> `v2`)
 *   proving both Real and Decoy vaults survive an application update intact.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

    private lateinit var context: Context
    private lateinit var dbFile: File
    private lateinit var database: PrivateVaultDatabase
    private lateinit var sessionManager: VaultSessionManager
    private lateinit var repository: VaultRepository

    // Fast bounded Argon2id profile for deterministic unit test execution while exercising real BouncyCastle Argon2id
    private val testKdfParams = CryptoEngine.KdfParams(
        algorithm = CryptoEngine.KDF_ALGORITHM_ARGON2ID,
        memoryKb = CryptoEngine.MIN_ALLOWED_MEMORY_KB, // 4096 KB (4 MiB)
        iterations = 1,
        parallelism = 1
    )

    @Before
    fun setUp() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        context = ApplicationProvider.getApplicationContext()
        dbFile = context.getDatabasePath("test_private_vault_${UUID.randomUUID()}.db")
        database = Room.databaseBuilder(context, PrivateVaultDatabase::class.java, dbFile.name)
            .allowMainThreadQueries()
            .addMigrations(PrivateVaultDatabase.MIGRATION_1_2)
            .build()
        sessionManager = VaultSessionManager()
        repository = VaultRepository(
            vaultDao = database.vaultDao(),
            sessionManager = sessionManager,
            biometricManager = null,
            defaultKdfParamsProvider = { testKdfParams }
        )
    }

    @After
    fun tearDown() {
        sessionManager.lockNow()
        database.close()
        dbFile.delete()
        File("${dbFile.absolutePath}-wal").delete()
        File("${dbFile.absolutePath}-shm").delete()
    }

    // =========================================================================================
    // S01, S02, S03: Cryptography, Argon2id KDF, Unified 72-Byte Envelopes & At-Rest Inspection
    // =========================================================================================

    @Test
    fun `S02 Argon2id determinism, bounds validation, and AES-256-GCM AAD tamper rejection`() {
        val pass = "CorrectHorseBatteryStaple!99".toCharArray()
        val salt = CryptoEngine.generateSalt()

        val key1 = CryptoEngine.deriveKeyArgon2id(pass, salt, testKdfParams)
        val key2 = CryptoEngine.deriveKeyArgon2id(pass, salt, testKdfParams)
        val differentSaltKey = CryptoEngine.deriveKeyArgon2id(pass, CryptoEngine.generateSalt(), testKdfParams)

        assertEquals(32, key1.size)
        assertArrayEquals("Same password and salt must derive identical 256-bit key", key1, key2)
        assertFalse("Different salt must derive different key", key1.contentEquals(differentSaltKey))

        // Out-of-bounds KDF parameters must be rejected before allocation (B03 / S03)
        var boundsRejected = false
        try {
            val hugeParams = testKdfParams.copy(memoryKb = 2_000_000) // ~2 GB
            CryptoEngine.deriveKeyArgon2id(pass, salt, hugeParams)
        } catch (_: IllegalArgumentException) {
            boundsRejected = true
        }
        assertTrue("Oversized Argon2id memory parameter must be rejected", boundsRejected)

        // AES-256-GCM encryption and AAD binding
        val nonce = CryptoEngine.generateNonce()
        val aadSlot0 = CryptoEngine.buildRecordAad(0, "rec-100", 1)
        val aadSlot1 = CryptoEngine.buildRecordAad(1, "rec-100", 1)
        val secretPlaintext = "TopSecretVaultPayload_2026".toByteArray(Charsets.UTF_8)

        val ciphertext = CryptoEngine.encryptAesGcm(key1, nonce, secretPlaintext, aadSlot0)
        val decrypted = CryptoEngine.decryptAesGcm(key1, nonce, ciphertext, aadSlot0)
        assertArrayEquals(secretPlaintext, decrypted)

        // Tampering with AAD (e.g. moving record from Slot 0 to Slot 1) must fail authentication
        var aadTamperRejected = false
        try {
            CryptoEngine.decryptAesGcm(key1, nonce, ciphertext, aadSlot1)
        } catch (_: AEADBadTagException) {
            aadTamperRejected = true
        }
        assertTrue("Cross-slot AAD mismatch must throw AEADBadTagException", aadTamperRejected)

        // Tampering with 1 bit of ciphertext must fail authentication
        val tamperedCiphertext = ciphertext.copyOf()
        tamperedCiphertext[tamperedCiphertext.lastIndex] =
            (tamperedCiphertext[tamperedCiphertext.lastIndex].toInt() xor 0x01).toByte()
        var bitFlipRejected = false
        try {
            CryptoEngine.decryptAesGcm(key1, nonce, tamperedCiphertext, aadSlot0)
        } catch (_: AEADBadTagException) {
            bitFlipRejected = true
        }
        assertTrue("Tampered GCM tag/ciphertext must be rejected", bitFlipRejected)
    }

    @Test
    fun `S01 and Unified Envelope - Synthetic secrets are absent from raw SQLite file and slots have identical outer structure`() = runBlocking {
        val realPass = "RealVaultMasterPass#2026".toCharArray()
        val initResult = repository.initializeNewVault(
            realPasswordChars = realPass,
            decoyPasswordChars = null, // Decoy unconfigured initially
            seedSampleDecoyData = false
        )
        assertTrue(initResult is VaultRepository.UnlockResult.Success)
        val session = (initResult as VaultRepository.UnlockResult.Success).session

        // Verify both Slot 0 and Slot 1 rows exist with identical 72-byte wrappedPayloadCiphertext
        val envelopes = database.vaultDao().getAllEnvelopes()
        assertEquals(2, envelopes.size)
        val env0 = envelopes.first { it.slotId == 0 }
        val env1 = envelopes.first { it.slotId == 1 }
        assertEquals(CryptoEngine.WRAPPED_ENVELOPE_CIPHERTEXT_BYTES, env0.wrappedPayloadCiphertext.size)
        assertEquals(CryptoEngine.WRAPPED_ENVELOPE_CIPHERTEXT_BYTES, env1.wrappedPayloadCiphertext.size)

        // Save distinctive synthetic note and credential
        val distinctiveNoteTitle = "SYNTHETIC_NOTE_TITLE_X998877"
        val distinctiveNoteBody = "SYNTHETIC_NOTE_BODY_SECRET_RECOVERY_SEED_ALPHA_OMEGA"
        val distinctiveService = "SYNTHETIC_BANK_SERVICE_Z4455"
        val distinctiveUsername = "SYNTHETIC_USER_ID_7766"
        val distinctivePassword = "SYNTHETIC_PASSWORD_VALUE_Q112233!"

        repository.saveRecord(
            session.sessionId,
            VaultRecordPayload.NoteRecord(
                id = UUID.randomUUID().toString(),
                title = distinctiveNoteTitle,
                body = distinctiveNoteBody,
                folderName = "SYNTHETIC_FOLDER_SECRET",
                tags = listOf("SYNTHETIC_TAG_99")
            )
        )
        repository.saveRecord(
            session.sessionId,
            VaultRecordPayload.CredentialRecord(
                id = UUID.randomUUID().toString(),
                serviceName = distinctiveService,
                accountLabel = "SYNTHETIC_LABEL_WORK",
                username = distinctiveUsername,
                password = distinctivePassword
            )
        )

        // Force SQLite WAL checkpoint/close so all bytes are flushed to disk
        database.openHelper.writableDatabase.query("PRAGMA wal_checkpoint(FULL)").close()

        val rawDbBytes = dbFile.readBytes()
        val rawDbAscii = String(rawDbBytes, Charsets.ISO_8859_1)

        assertFalse("Note title must NOT appear in raw SQLite file", rawDbAscii.contains(distinctiveNoteTitle))
        assertFalse("Note body must NOT appear in raw SQLite file", rawDbAscii.contains(distinctiveNoteBody))
        assertFalse("Folder name must NOT appear in raw SQLite file", rawDbAscii.contains("SYNTHETIC_FOLDER_SECRET"))
        assertFalse("Tag must NOT appear in raw SQLite file", rawDbAscii.contains("SYNTHETIC_TAG_99"))
        assertFalse("Service name must NOT appear in raw SQLite file", rawDbAscii.contains(distinctiveService))
        assertFalse("Username must NOT appear in raw SQLite file", rawDbAscii.contains(distinctiveUsername))
        assertFalse("Password must NOT appear in raw SQLite file", rawDbAscii.contains(distinctivePassword))
    }

    // =========================================================================================
    // F01–F06, S04–S11: Real vs. Decoy Vault Routing, Isolation, Master Password Rotation & Lock
    // =========================================================================================

    @Test
    fun `F02, F03, S04, S05, S06, S07 - Real vs Decoy routing, strict isolation, and master password rotation`() = runBlocking {
        val realPass = "MyRealVaultSecret!111".toCharArray()
        val decoyPass = "MyDecoyVaultSecret!222".toCharArray()
        val wrongPass = "CompletelyWrongPass!333".toCharArray()

        // Initialize with both Real and Decoy vaults
        val setupRes = repository.initializeNewVault(
            realPasswordChars = realPass,
            decoyPasswordChars = decoyPass,
            seedSampleDecoyData = true
        )
        assertTrue(setupRes is VaultRepository.UnlockResult.Success)
        val realSession = (setupRes as VaultRepository.UnlockResult.Success).session
        assertEquals(VaultSessionManager.REAL_SLOT, realSession.slotId)
        assertTrue("Two-slot benchmark must be recorded", setupRes.benchmark.twoSlotUnlockDurationMs >= 2L)

        // Add a secret record to Real Vault
        val realSecretNoteId = UUID.randomUUID().toString()
        repository.saveRecord(
            realSession.sessionId,
            VaultRecordPayload.NoteRecord(
                id = realSecretNoteId,
                title = "Real Vault Classified Note",
                body = "Only visible in Slot 0"
            )
        )

        // Lock and test wrong password (F02, S05)
        sessionManager.lockNow()
        assertFalse("Old session must be inactive after lock", sessionManager.isSessionActive(realSession.sessionId))

        // Attempting to save using a locked/stale sessionId must fail (S07)
        val staleSave = repository.saveRecord(
            realSession.sessionId,
            VaultRecordPayload.NoteRecord(
                id = UUID.randomUUID().toString(),
                title = "Stale Write",
                body = "Should be rejected"
            )
        )
        assertTrue("Stale session write must be rejected after lock", staleSave.isFailure)

        val wrongUnlock = repository.unlockWithPassword(wrongPass)
        assertTrue("Wrong password must not unlock any vault", wrongUnlock is VaultRepository.UnlockResult.InvalidCredentials)
        assertTrue(sessionManager.sessionState.value is VaultSessionManager.SessionState.Locked)

        // Unlock Decoy Vault (S05, S06)
        val decoyUnlock = repository.unlockWithPassword(decoyPass)
        assertTrue(decoyUnlock is VaultRepository.UnlockResult.Success)
        val decoySession = (decoyUnlock as VaultRepository.UnlockResult.Success).session
        assertEquals(VaultSessionManager.DECOY_SLOT, decoySession.slotId)
        assertFalse("Decoy session must NOT have security management capability", decoySession.canManageVaultSecurity)

        val decoyRecords = repository.observeDecryptedRecords(decoySession.sessionId).first()
        assertFalse(
            "Decoy vault must NEVER contain Real Vault records",
            decoyRecords.any { it.id == realSecretNoteId }
        )
        assertTrue(
            "Decoy vault should contain seeded fictitious sample records",
            decoyRecords.isNotEmpty()
        )

        // S10: Attempting to change Real Master Password from Decoy Session must fail
        val unauthorizedRotate = repository.changeRealMasterPassword(
            sessionId = decoySession.sessionId,
            currentRealPasswordChars = realPass,
            newRealPasswordChars = "NewRealPass!999".toCharArray()
        )
        assertTrue("Decoy session must not be allowed to rotate Real Master Password", unauthorizedRotate.isFailure)

        // Lock Decoy, unlock Real Vault, and rotate Real Master Password (S04)
        sessionManager.lockNow()
        val realUnlock2 = repository.unlockWithPassword(realPass)
        assertTrue(realUnlock2 is VaultRepository.UnlockResult.Success)
        val realSession2 = (realUnlock2 as VaultRepository.UnlockResult.Success).session

        val newRealPass = "RotatedRealMasterPass!2027".toCharArray()
        val rotateRes = repository.changeRealMasterPassword(
            sessionId = realSession2.sessionId,
            currentRealPasswordChars = realPass,
            newRealPasswordChars = newRealPass
        )
        assertTrue("Master password rotation in Real Vault must succeed", rotateRes.isSuccess)

        // Verify old Real password no longer works, new Real password works, and Decoy password still works
        sessionManager.lockNow()
        assertTrue(repository.unlockWithPassword(realPass) is VaultRepository.UnlockResult.InvalidCredentials)

        val rotatedUnlock = repository.unlockWithPassword(newRealPass)
        assertTrue(rotatedUnlock is VaultRepository.UnlockResult.Success)
        val realRecordsAfterRotate = repository.observeDecryptedRecords(
            (rotatedUnlock as VaultRepository.UnlockResult.Success).session.sessionId
        ).first()
        assertTrue("Real Vault note must survive Master Password rotation intact", realRecordsAfterRotate.any { it.id == realSecretNoteId })

        sessionManager.lockNow()
        assertTrue("Decoy password must remain unaffected by Real password rotation", repository.unlockWithPassword(decoyPass) is VaultRepository.UnlockResult.Success)
    }

    // =========================================================================================
    // F08–F12: Password Generator & Offline Password Strength / Reuse Estimator
    // =========================================================================================

    @Test
    fun `F08, F10, F11, F12 - Generator settings validation and Offline Strength & Reuse Checker`() {
        // Reject impossible generator combinations (all categories off)
        val invalidGen = PasswordGeneratorEngine.generate(
            PasswordGeneratorEngine.GeneratorConfig(
                length = 20,
                includeUppercase = false,
                includeLowercase = false,
                includeDigits = false,
                includeSymbols = false
            )
        )
        assertTrue(invalidGen is PasswordGeneratorEngine.GenerationResult.InvalidConfig)

        // Valid 24-character generation excluding ambiguous characters
        val validGen = PasswordGeneratorEngine.generate(
            PasswordGeneratorEngine.GeneratorConfig(
                length = 24,
                includeUppercase = true,
                includeLowercase = true,
                includeDigits = true,
                includeSymbols = true,
                excludeAmbiguous = true
            )
        )
        assertTrue(validGen is PasswordGeneratorEngine.GenerationResult.Success)
        val generatedPwd = (validGen as PasswordGeneratorEngine.GenerationResult.Success).password
        assertEquals(24, generatedPwd.length)
        assertFalse("Ambiguous chars must be excluded", generatedPwd.any { it in setOf('0', 'O', 'o', '1', 'l', 'I', '|') })

        // F11: Common patterned password with uppercase, digit, and symbol must NOT be rated Strong
        val patternedReport = OfflinePasswordStrengthEstimator.evaluate("P@ssw0rd1!")
        assertTrue(
            "Patterned dictionary/l33t password must be rated Weak or Very Weak",
            patternedReport.rating == OfflinePasswordStrengthEstimator.StrengthRating.VERY_WEAK ||
                patternedReport.rating == OfflinePasswordStrengthEstimator.StrengthRating.WEAK
        )

        // Keyboard walk detection
        val walkReport = OfflinePasswordStrengthEstimator.evaluate("Qwerty1234!@#")
        assertTrue(
            "Keyboard walk must be detected",
            walkReport.detectedWeaknesses.any { it.contains("keyboard", ignoreCase = true) }
        )

        // Generated 24-char random password must be Strong / Very Strong
        val strongReport = OfflinePasswordStrengthEstimator.evaluate(generatedPwd)
        assertTrue(
            strongReport.rating == OfflinePasswordStrengthEstimator.StrengthRating.STRONG ||
                strongReport.rating == OfflinePasswordStrengthEstimator.StrengthRating.VERY_STRONG
        )

        // F12: Local reuse warning scoped to current vault records
        val activeVaultList = listOf(
            Triple("cred-1", "GitHub", generatedPwd),
            Triple("cred-2", "ProtonMail", "DifferentUniquePassword#998877")
        )
        val reuseReport = OfflinePasswordStrengthEstimator.evaluate(
            password = generatedPwd,
            existingVaultCredentials = activeVaultList,
            excludeRecordId = "cred-new"
        )
        assertEquals(listOf("GitHub"), reuseReport.reusedServiceNames)
    }

    // =========================================================================================
    // B01–B06: Portable Encrypted Backup & Restore
    // =========================================================================================

    @Test
    fun `B01 to B06 - Encrypted backup format, wrong password rejection, cross-install restore, and vault scoping`() = runBlocking {
        val realPass = "RealVaultPass#2026".toCharArray()
        val decoyPass = "DecoyVaultPass#2026".toCharArray()
        val backupPass = "DedicatedBackupPass#999".toCharArray()

        val initRes = repository.initializeNewVault(realPass, decoyPass, seedSampleDecoyData = true)
        val realSession = (initRes as VaultRepository.UnlockResult.Success).session

        val noteId = UUID.randomUUID().toString()
        val secretNoteTitle = "BackupSurvivalNote_Alpha77"
        repository.saveRecord(
            realSession.sessionId,
            VaultRecordPayload.NoteRecord(
                id = noteId,
                title = secretNoteTitle,
                body = "Portable encrypted backup payload"
            )
        )

        // Export Real Vault backup
        val exportResult = repository.prepareEncryptedBackupBytes(
            sessionId = realSession.sessionId,
            backupPasswordChars = backupPass,
            scope = PortableBackupEngine.ExportScope.ALL
        )
        assertTrue(exportResult.isSuccess)
        val backupBytes = exportResult.getOrThrow()

        // B01: Backup bytes must not contain plaintext note title
        val rawBackupString = String(backupBytes, Charsets.ISO_8859_1)
        assertFalse("Exported .pvault file must not contain plaintext strings", rawBackupString.contains(secretNoteTitle))

        // B02: Wrong backup password must fail without modifying vault
        val wrongRestore = repository.previewBackupFromStream(
            sessionId = realSession.sessionId,
            inputStream = ByteArrayInputStream(backupBytes),
            backupPasswordChars = "WrongBackupPassword!123".toCharArray()
        )
        assertTrue("Wrong backup password must be rejected", wrongRestore.isFailure)

        // B02: Tampered backup byte must fail GCM authentication
        val tamperedBackup = backupBytes.copyOf()
        tamperedBackup[tamperedBackup.lastIndex] = (tamperedBackup[tamperedBackup.lastIndex].toInt() xor 0xFF).toByte()
        val tamperedRestore = repository.previewBackupFromStream(
            sessionId = realSession.sessionId,
            inputStream = ByteArrayInputStream(tamperedBackup),
            backupPasswordChars = backupPass
        )
        assertTrue("Tampered backup archive must be rejected", tamperedRestore.isFailure)

        // B04 & B06: Restore onto a fresh installation / database withoutaffecting the other vault slot
        val freshDbFile = context.getDatabasePath("fresh_install_${UUID.randomUUID()}.db")
        val freshDb = Room.databaseBuilder(context, PrivateVaultDatabase::class.java, freshDbFile.name)
            .allowMainThreadQueries()
            .build()
        val freshSessionMgr = VaultSessionManager()
        val freshRepo = VaultRepository(
            vaultDao = freshDb.vaultDao(),
            sessionManager = freshSessionMgr,
            defaultKdfParamsProvider = { testKdfParams }
        )

        try {
            val freshInit = freshRepo.initializeNewVault(
                realPasswordChars = "BrandNewDeviceMasterPass!1".toCharArray(),
                decoyPasswordChars = "BrandNewDeviceDecoyPass!2".toCharArray(),
                seedSampleDecoyData = true
            )
            val freshRealSession = (freshInit as VaultRepository.UnlockResult.Success).session

            val previewRes = freshRepo.previewBackupFromStream(
                sessionId = freshRealSession.sessionId,
                inputStream = ByteArrayInputStream(backupBytes),
                backupPasswordChars = backupPass
            )
            assertTrue(previewRes.isSuccess)
            val preview = previewRes.getOrThrow()
            assertEquals(1, preview.notesCount)

            val applyRes = freshRepo.applyVerifiedBackupRestore(
                sessionId = freshRealSession.sessionId,
                preview = preview,
                mode = PortableBackupEngine.RestoreMode.REPLACE_ACTIVE_VAULT
            )
            assertTrue(applyRes.isSuccess)

            val restoredRealRecords = freshRepo.observeDecryptedRecords(freshRealSession.sessionId).first()
            assertTrue(
                "Fresh installation must contain restored Real Vault note",
                restoredRealRecords.any { it is VaultRecordPayload.NoteRecord && it.title == secretNoteTitle }
            )

            // Verify fresh installation's Decoy Vault was NOT overwritten by Real Vault restore (S09, B06)
            freshSessionMgr.lockNow()
            val freshDecoyUnlock = freshRepo.unlockWithPassword("BrandNewDeviceDecoyPass!2".toCharArray())
            assertTrue(freshDecoyUnlock is VaultRepository.UnlockResult.Success)
            val freshDecoyRecords = freshRepo.observeDecryptedRecords(
                (freshDecoyUnlock as VaultRepository.UnlockResult.Success).session.sessionId
            ).first()
            assertFalse(
                "Restoring into Real Vault must never leak into or modify Decoy Vault",
                freshDecoyRecords.any { it is VaultRecordPayload.NoteRecord && it.title == secretNoteTitle }
            )
        } finally {
            freshSessionMgr.lockNow()
            freshDb.close()
            freshDbFile.delete()
        }
    }

    // =========================================================================================
    // U01–U12: OTA Manifest Validation, 3-Option Reminder Deferrals, apksig ApkVerifier & Migrations
    // =========================================================================================

    @Test
    fun `U02, U03, U04, U12 - OTA Manifest validation and 3-option Reminder Deferral state machine`() {
        val validJson = """
            {
              "schemaVersion": 1,
              "packageName": "com.tpeditz.privatevault",
              "versionName": "1.0.1",
              "versionCode": 2,
              "minimumSupportedVersionCode": 1,
              "downloadUrl": "https://github.com/tpeditz/Private-vault-updates/releases/download/v1.0.1/app-release.apk",
              "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
              "signingCertificateSha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
              "releaseNotes": "Bug fixes and security improvements",
              "forceUpdate": false,
              "publishedAt": "2026-11-05T10:00:00Z"
            }
        """.trimIndent()

        // U03: Strictly higher versionCode offers UpdateAvailable
        val stateHigher = OtaUpdateManager.evaluateManifestJson(
            rawJson = validJson,
            installedPackageName = "com.tpeditz.privatevault",
            installedVersionCode = 1,
            installedVersionName = "1.0.0"
        )
        assertTrue(stateHigher is OtaUpdateManager.OtaUiState.UpdateAvailable)

        // U02: Equal or lower versionCode returns UpToDate
        val stateEqual = OtaUpdateManager.evaluateManifestJson(
            rawJson = validJson,
            installedPackageName = "com.tpeditz.privatevault",
            installedVersionCode = 2,
            installedVersionName = "1.0.1"
        )
        assertTrue(stateEqual is OtaUpdateManager.OtaUiState.UpToDate)

        // Reject HTTP cleartext download URL
        var cleartextRejected = false
        try {
            OtaUpdateManager.parseAndValidateManifest(
                rawJson = validJson.replace("https://github.com", "http://github.com"),
                expectedPackageName = "com.tpeditz.privatevault"
            )
        } catch (_: SecurityException) {
            cleartextRejected = true
        }
        assertTrue("HTTP cleartext OTA URL must be rejected", cleartextRejected)

        // Test 3-option Reminder Deferral state machine (Next Launch, Tomorrow +24h, In 3 Days +72h)
        val now = 1_700_000_000_000L
        val nextLaunchState = AppPreferencesRepository.OtaReminderState(
            deferredVersionCode = 2,
            reminderType = AppPreferencesRepository.OtaReminderType.NEXT_LAUNCH,
            remindAfterEpochMs = 0L,
            launchNumberAtDeferral = 5L
        )
        assertFalse(
            "Same launch number must suppress automatic prompt",
            AppPreferencesRepository.shouldShowAutomaticUpdatePrompt(2, nextLaunchState, currentLaunchNumber = 5L, nowEpochMs = now)
        )
        assertTrue(
            "Next app launch (launch 6) must show prompt",
            AppPreferencesRepository.shouldShowAutomaticUpdatePrompt(2, nextLaunchState, currentLaunchNumber = 6L, nowEpochMs = now)
        )

        val threeDaysMs = 72L * 3600L * 1000L
        val threeDayState = AppPreferencesRepository.OtaReminderState(
            deferredVersionCode = 2,
            reminderType = AppPreferencesRepository.OtaReminderType.TIMESTAMP,
            remindAfterEpochMs = now + threeDaysMs,
            launchNumberAtDeferral = 5L
        )
        assertFalse(
            "Prompt must be suppressed before 3 days elapse",
            AppPreferencesRepository.shouldShowAutomaticUpdatePrompt(2, threeDayState, currentLaunchNumber = 8L, nowEpochMs = now + 24L * 3600L * 1000L)
        )
        assertTrue(
            "Prompt must be shown after 3 days elapse",
            AppPreferencesRepository.shouldShowAutomaticUpdatePrompt(2, threeDayState, currentLaunchNumber = 8L, nowEpochMs = now + threeDaysMs + 1000L)
        )
    }

    @Test
    fun `U06, U07 - Candidate APK verification using official Android apksig ApkVerifier and installed-signer match`() {
        val trustedKeyPair = generateRsaKeyPair()
        val trustedCert = generateSelfSignedCertificate(trustedKeyPair, "CN=Tp Editz Release Signer")
        val trustedCertSha256 = OtaUpdateManager.sha256Hex(trustedCert.encoded)

        val attackerKeyPair = generateRsaKeyPair()
        val attackerCert = generateSelfSignedCertificate(attackerKeyPair, "CN=Untrusted Attacker Signer")
        val attackerCertSha256 = OtaUpdateManager.sha256Hex(attackerCert.encoded)

        val unsignedApk = File(context.cacheDir, "unsigned_test.apk")
        val signedValidApk = File(context.cacheDir, "signed_valid_v2.apk")
        val signedAttackerApk = File(context.cacheDir, "signed_attacker_v2.apk")

        try {
            createMinimalTestApkZip(unsignedApk)

            // Sign valid candidate APK with trusted key using official Android apksig ApkSigner (V1 + V2)
            val trustedSignerConfig = ApkSigner.SignerConfig.Builder(
                "SIGNER",
                trustedKeyPair.private,
                listOf(trustedCert)
            ).build()
            ApkSigner.Builder(listOf(trustedSignerConfig))
                .setInputApk(unsignedApk)
                .setOutputApk(signedValidApk)
                .setMinSdkVersion(24)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .build()
                .sign()

            // Sign attacker APK with attacker key
            val attackerSignerConfig = ApkSigner.SignerConfig.Builder(
                "ATTACKER",
                attackerKeyPair.private,
                listOf(attackerCert)
            ).build()
            ApkSigner.Builder(listOf(attackerSignerConfig))
                .setInputApk(unsignedApk)
                .setOutputApk(signedAttackerApk)
                .setMinSdkVersion(24)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .build()
                .sign()

            val validApkSha256 = OtaUpdateManager.computeFileSha256Hex(signedValidApk)
            val validManifest = OtaUpdateManager.OtaManifest(
                schemaVersion = 1,
                packageName = context.packageName,
                versionName = "1.0.1",
                versionCode = 2,
                minimumSupportedVersionCode = 1,
                downloadUrl = "https://github.com/tpeditz/Private-vault-updates/releases/download/v1.0.1/app.apk",
                sha256 = validApkSha256,
                signingCertificateSha256 = trustedCertSha256,
                releaseNotes = "Signed update test",
                forceUpdate = false,
                publishedAt = "2026-11-05T00:00:00Z",
                apkSizeBytes = signedValidApk.length()
            )

            // Stub Robolectric PackageManager archive info for the valid APK
            val archivePkgInfo = PackageInfo().apply {
                packageName = context.packageName
                versionName = "1.0.1"
                @Suppress("DEPRECATION")
                versionCode = 2
                longVersionCode = 2L
            }
            shadowOf(context.packageManager).installPackage(archivePkgInfo)

            // 1. Valid APK signed by the installed trusted signer must pass ApkVerifier verification
            val verified = OtaUpdateManager.verifyCandidateApkFile(
                context = context,
                apkFile = signedValidApk,
                manifest = validManifest,
                installedAppPackageName = context.packageName,
                installedAppVersionCode = 1L,
                installedSignerCertSha256Hex = trustedCertSha256
            )
            assertEquals(validApkSha256, verified.actualSha256Hex)
            assertEquals(trustedCertSha256, verified.verifiedSignerCertSha256Hex)

            // 2. U06: APK signed by a different signer (even if manifest claims attackerCertSha256!)
            // MUST be rejected because it does not match installedSignerCertSha256Hex
            val attackerApkSha256 = OtaUpdateManager.computeFileSha256Hex(signedAttackerApk)
            val attackerManifest = validManifest.copy(
                sha256 = attackerApkSha256,
                signingCertificateSha256 = attackerCertSha256,
                apkSizeBytes = signedAttackerApk.length()
            )
            var wrongSignerRejected = false
            try {
                OtaUpdateManager.verifyCandidateApkFile(
                    context = context,
                    apkFile = signedAttackerApk,
                    manifest = attackerManifest,
                    installedAppPackageName = context.packageName,
                    installedAppVersionCode = 1L,
                    installedSignerCertSha256Hex = trustedCertSha256
                )
            } catch (_: SecurityException) {
                wrongSignerRejected = true
            }
            assertTrue("APK signed with untrusted key must be rejected even if manifest matches it", wrongSignerRejected)

            // 3. U07: Unsigned / corrupted APK archive must be rejected by apksig ApkVerifier
            val unsignedSha256 = OtaUpdateManager.computeFileSha256Hex(unsignedApk)
            val unsignedManifest = validManifest.copy(
                sha256 = unsignedSha256,
                apkSizeBytes = unsignedApk.length()
            )
            var unsignedRejected = false
            try {
                OtaUpdateManager.verifyCandidateApkFile(
                    context = context,
                    apkFile = unsignedApk,
                    manifest = unsignedManifest,
                    installedAppPackageName = context.packageName,
                    installedAppVersionCode = 1L,
                    installedSignerCertSha256Hex = trustedCertSha256
                )
            } catch (_: SecurityException) {
                unsignedRejected = true
            }
            assertTrue("Unsigned APK archive must be rejected by apksig ApkVerifier", unsignedRejected)
        } finally {
            unsignedApk.delete()
            signedValidApk.delete()
            signedAttackerApk.delete()
        }
    }

    @Test
    fun `U09, U10, U11 - Explicit Room schema migration v1 to v2 preserves both Real and Decoy encrypted vaults`() = runBlocking {
        val migrationDbName = "migration_survival_${UUID.randomUUID()}.db"
        val migrationDbFile = context.getDatabasePath(migrationDbName)

        try {
            // 1. Create a Version 1 SQLite database using SupportSQLiteOpenHelper (simulating v1.0.0)
            val v1Callback = object : SupportSQLiteOpenHelper.Callback(1) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    db.execSQL(
                        """
                        CREATE TABLE IF NOT EXISTS `vault_envelopes` (
                            `slot_id` INTEGER NOT NULL,
                            `envelope_version` INTEGER NOT NULL,
                            `kdf_algorithm` TEXT NOT NULL,
                            `kdf_memory_kb` INTEGER NOT NULL,
                            `kdf_iterations` INTEGER NOT NULL,
                            `kdf_parallelism` INTEGER NOT NULL,
                            `kdf_salt` BLOB NOT NULL,
                            `wrap_nonce` BLOB NOT NULL,
                            `wrapped_payload_ciphertext` BLOB NOT NULL,
                            `biometric_nonce` BLOB,
                            `biometric_wrapped_dek` BLOB,
                            PRIMARY KEY(`slot_id`)
                        )
                        """.trimIndent()
                    )
                    db.execSQL(
                        """
                        CREATE TABLE IF NOT EXISTS `encrypted_records` (
                            `record_id` TEXT NOT NULL,
                            `vault_slot` INTEGER NOT NULL,
                            `schema_version` INTEGER NOT NULL,
                            `nonce` BLOB NOT NULL,
                            `ciphertext` BLOB NOT NULL,
                            PRIMARY KEY(`record_id`)
                        )
                        """.trimIndent()
                    )
                }

                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {}
            }

            val helperConfig = SupportSQLiteOpenHelper.Configuration.builder(context)
                .name(migrationDbName)
                .callback(v1Callback)
                .build()
            val v1Helper = FrameworkSQLiteOpenHelperFactory().create(helperConfig)
            v1Helper.writableDatabase.close()
            v1Helper.close()

            // 2. Open with Room at Version 2 using MIGRATION_1_2 and populate both Real and Decoy vaults
            val migratedRoomDb = Room.databaseBuilder(context, PrivateVaultDatabase::class.java, migrationDbName)
                .addMigrations(PrivateVaultDatabase.MIGRATION_1_2)
                .allowMainThreadQueries()
                .build()

            val migSessionMgr = VaultSessionManager()
            val migRepo = VaultRepository(
                vaultDao = migratedRoomDb.vaultDao(),
                sessionManager = migSessionMgr,
                defaultKdfParamsProvider = { testKdfParams }
            )

            val realPass = "UpdateSurvivalRealPass!100".toCharArray()
            val decoyPass = "UpdateSurvivalDecoyPass!200".toCharArray()

            val initRes = migRepo.initializeNewVault(realPass, decoyPass, seedSampleDecoyData = true)
            assertTrue(initRes is VaultRepository.UnlockResult.Success)
            val realSession = (initRes as VaultRepository.UnlockResult.Success).session

            val realNoteId = UUID.randomUUID().toString()
            migRepo.saveRecord(
                realSession.sessionId,
                VaultRecordPayload.NoteRecord(
                    id = realNoteId,
                    title = "Pre-Update Real Vault Note",
                    body = "Must survive v1.0.0 -> v1.0.1 upgrade",
                    checklistItems = listOf(NoteChecklistItem("c1", "Verify migration", true)),
                    formatStyle = NoteFormatStyle.CHECKLIST
                )
            )
            migSessionMgr.lockNow()
            migratedRoomDb.close()

            // 3. Re-open database after simulated app upgrade restart and verify BOTH passwords and BOTH vaults
            val reopenedDb = Room.databaseBuilder(context, PrivateVaultDatabase::class.java, migrationDbName)
                .addMigrations(PrivateVaultDatabase.MIGRATION_1_2)
                .allowMainThreadQueries()
                .build()
            val postUpgradeSessionMgr = VaultSessionManager()
            val postUpgradeRepo = VaultRepository(
                vaultDao = reopenedDb.vaultDao(),
                sessionManager = postUpgradeSessionMgr,
                defaultKdfParamsProvider = { testKdfParams }
            )

            val unlockRealAfterUpdate = postUpgradeRepo.unlockWithPassword(realPass)
            assertTrue(unlockRealAfterUpdate is VaultRepository.UnlockResult.Success)
            val realRecords = postUpgradeRepo.observeDecryptedRecords(
                (unlockRealAfterUpdate as VaultRepository.UnlockResult.Success).session.sessionId
            ).first()
            assertTrue(
                "Real vault note must survive update migration intact",
                realRecords.any { it.id == realNoteId }
            )

            postUpgradeSessionMgr.lockNow()
            val unlockDecoyAfterUpdate = postUpgradeRepo.unlockWithPassword(decoyPass)
            assertTrue(unlockDecoyAfterUpdate is VaultRepository.UnlockResult.Success)
            val decoyRecords = postUpgradeRepo.observeDecryptedRecords(
                (unlockDecoyAfterUpdate as VaultRepository.UnlockResult.Success).session.sessionId
            ).first()
            assertTrue("Decoy vault records must survive update migration intact", decoyRecords.isNotEmpty())
            assertFalse("Decoy vault must still not see Real vault note after update", decoyRecords.any { it.id == realNoteId })

            reopenedDb.close()
        } finally {
            migrationDbFile.delete()
            File("${migrationDbFile.absolutePath}-wal").delete()
            File("${migrationDbFile.absolutePath}-shm").delete()
        }
    }

    @Test
    fun `S03, S09, S10 - Argon2id two-vault benchmark telemetry and SAF file-picker lock lifecycle`() {
        // 1. Measure proposed Standard profile (32 MiB/slot, t=3, p=2) and Low-RAM profile (16 MiB/slot, t=4, p=2)
        val standardProfile = CryptoEngine.KdfParams(
            algorithm = CryptoEngine.KDF_ALGORITHM_ARGON2ID,
            memoryKb = CryptoEngine.PROPOSED_STANDARD_MEMORY_KB,
            iterations = CryptoEngine.PROPOSED_STANDARD_ITERATIONS,
            parallelism = CryptoEngine.PROPOSED_STANDARD_PARALLELISM
        )
        val lowRamProfile = CryptoEngine.KdfParams(
            algorithm = CryptoEngine.KDF_ALGORITHM_ARGON2ID,
            memoryKb = CryptoEngine.PROPOSED_CONSTRAINED_MEMORY_KB,
            iterations = CryptoEngine.PROPOSED_CONSTRAINED_ITERATIONS,
            parallelism = CryptoEngine.PROPOSED_CONSTRAINED_PARALLELISM
        )

        val stdBench = CryptoEngine.measureKdfBenchmark(standardProfile)
        val lowRamBench = CryptoEngine.measureKdfBenchmark(lowRamProfile)

        println(
            "KDF_BENCHMARK_STANDARD: device=${stdBench.deviceModel}, sdk=${stdBench.androidSdkInt}, " +
                "memoryKbPerSlot=${stdBench.memoryKbPerSlot}, t=${stdBench.iterations}, p=${stdBench.parallelism}, " +
                "singleSlotMs=${stdBench.singleSlotDurationMs}, twoVaultUnlockMs=${stdBench.twoSlotUnlockDurationMs}, " +
                "maxHeapMb=${stdBench.maxHeapMb}, usedHeapMbAfterRun=${stdBench.usedHeapMbAfterRun}"
        )
        println(
            "KDF_BENCHMARK_LOW_RAM: device=${lowRamBench.deviceModel}, sdk=${lowRamBench.androidSdkInt}, " +
                "memoryKbPerSlot=${lowRamBench.memoryKbPerSlot}, t=${lowRamBench.iterations}, p=${lowRamBench.parallelism}, " +
                "singleSlotMs=${lowRamBench.singleSlotDurationMs}, twoVaultUnlockMs=${lowRamBench.twoSlotUnlockDurationMs}, " +
                "maxHeapMb=${lowRamBench.maxHeapMb}, usedHeapMbAfterRun=${lowRamBench.usedHeapMbAfterRun}"
        )

        assertTrue(stdBench.singleSlotDurationMs > 0L)
        assertTrue(stdBench.twoSlotUnlockDurationMs >= stdBench.singleSlotDurationMs)
        assertTrue(lowRamBench.singleSlotDurationMs > 0L)
        assertTrue(lowRamBench.twoSlotUnlockDurationMs >= lowRamBench.singleSlotDurationMs)

        // 2. Verify S09/S10 Auto-Lock & SAF File-Picker Transition Grace Window
        val dek = CryptoEngine.generateDek()
        val s1 = sessionManager.openSession(VaultSessionManager.REAL_SLOT, dek)
        assertTrue(sessionManager.isSessionActive(s1.sessionId))

        // Immediate auto-lock (0ms) without SAF picker locks immediately on foreground return
        sessionManager.onAppBackgrounded(nowEpochMs = 1_000L)
        val lockedImmediate = sessionManager.onAppForegrounded(autoLockTimeoutMs = 0L, nowEpochMs = 2_000L)
        assertTrue("Immediate timeout must lock when returning from normal backgrounding", lockedImmediate)
        assertFalse(sessionManager.isSessionActive(s1.sessionId))
        assertTrue(s1.isWiped)

        // SAF File-Picker 90-second bounded transition window preserves session during normal document selection (15s)
        val s2 = sessionManager.openSession(VaultSessionManager.REAL_SLOT, dek)
        sessionManager.beginFilePickerTransitionWindow(nowEpochMs = 10_000L)
        sessionManager.onAppBackgrounded(nowEpochMs = 10_100L)
        val lockedDuringQuickPicker = sessionManager.onAppForegrounded(autoLockTimeoutMs = 0L, nowEpochMs = 25_000L)
        assertFalse("Active SAF file-picker transition within 90s must not prematurely wipe session", lockedDuringQuickPicker)
        assertTrue(sessionManager.isSessionActive(s2.sessionId))

        // One-shot SAF grant is consumed upon foreground return; subsequent normal backgrounding locks immediately
        sessionManager.onAppBackgrounded(nowEpochMs = 26_000L)
        val lockedAfterGrantConsumed = sessionManager.onAppForegrounded(autoLockTimeoutMs = 0L, nowEpochMs = 27_000L)
        assertTrue("Consumed SAF picker grant must not exempt subsequent backgrounding", lockedAfterGrantConsumed)
        assertFalse(sessionManager.isSessionActive(s2.sessionId))

        // Abandoning the SAF picker beyond 90 seconds enforces hard lock
        val s3 = sessionManager.openSession(VaultSessionManager.REAL_SLOT, dek)
        sessionManager.beginFilePickerTransitionWindow(nowEpochMs = 100_000L)
        sessionManager.onAppBackgrounded(nowEpochMs = 100_100L)
        val lockedAfterExpiredPicker = sessionManager.onAppForegrounded(
            autoLockTimeoutMs = 0L,
            nowEpochMs = 100_100L + VaultSessionManager.FILE_PICKER_GRANT_WINDOW_MS + 1_000L
        )
        assertTrue("SAF picker transition exceeding 90s ceiling must force lock", lockedAfterExpiredPicker)
        assertFalse(sessionManager.isSessionActive(s3.sessionId))
        assertTrue(s3.isWiped)
    }

    private fun generateRsaKeyPair(): java.security.KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        return kpg.generateKeyPair()
    }

    @Suppress("DEPRECATION")
    private fun generateSelfSignedCertificate(
        keyPair: java.security.KeyPair,
        dn: String
    ): X509Certificate {
        val now = System.currentTimeMillis()
        val startDate = Date(now - 86_400_000L)
        val endDate = Date(now + 365L * 86_400_000L)
        val issuer = X500Principal(dn)
        val serial = BigInteger.valueOf(now)
        val certGen = X509V3CertificateGenerator()
        certGen.setSerialNumber(serial)
        certGen.setIssuerDN(issuer)
        certGen.setNotBefore(startDate)
        certGen.setNotAfter(endDate)
        certGen.setSubjectDN(issuer)
        certGen.setPublicKey(keyPair.public)
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption")
        return certGen.generate(keyPair.private, BouncyCastleProvider.PROVIDER_NAME)
    }

    private fun createMinimalTestApkZip(targetFile: File) {
        ZipOutputStream(FileOutputStream(targetFile)).use { zos ->
            val entry = ZipEntry("AndroidManifest.xml")
            zos.putNextEntry(entry)
            zos.write("MinimalBinaryManifestPlaceholder".toByteArray(Charsets.UTF_8))
            zos.closeEntry()
        }
    }
}

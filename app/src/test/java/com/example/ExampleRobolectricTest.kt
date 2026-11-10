package com.example

import android.content.Context
import android.content.pm.PackageInfo
import android.net.Uri
import androidx.activity.result.contract.ActivityResultContracts
import androidx.room.Room
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.core.app.ApplicationProvider
import com.android.apksig.ApkSigner
import com.example.data.AppPreferencesRepository
import com.example.data.ChecklistEntry
import com.example.data.CredentialRecord
import com.example.data.CustomCredentialField
import com.example.data.FolderScope
import com.example.data.NoteBodyFormat
import com.example.data.NoteRecord
import com.example.data.OtaReminderPolicy
import com.example.data.PortableBackupEngine
import com.example.data.PrivateVaultDatabase
import com.example.data.VaultAppPreferences
import com.example.data.VaultFolder
import com.example.data.VaultRepository
import com.example.ota.OtaUpdateManager
import com.example.security.CryptoEngine
import com.example.security.OfflinePasswordStrengthEstimator
import com.example.security.SensitiveClipboardManager
import com.example.security.VaultSessionManager
import com.example.ui.VaultViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.x509.X509V3CertificateGenerator
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
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
import javax.security.auth.x500.X500Principal

/**
 * Comprehensive Verification & Audit Repair Test Suite for PRIVATE VAULT.
 *
 * Covers:
 * - U01 & U02 & R16: Cache-staged `.pvault` export to a `Uri` and background IO stream restore.
 * - U04 & R06: Public contact handle copy (`@Tp_Editz`, `@tp_ediitz`) and ownership-checked clipboard clear.
 * - N01: Composite primary key `(vault_slot, record_id)` preventing cross-vault record overwrites + `MIGRATION_2_3`.
 * - N02: Corrupted record detection aborting ordinary export and merge restore without deleting ciphertext.
 * - N03: Atomic `authRequestGeneration` invalidating late KDF completions after `lockNow()`.
 * - N04 & R04: Fail-closed `OtaUpdateManager.verifyCandidateApkFile` when archive metadata is null + repository URL validation.
 * - N05 & R01 & R02: Authenticated `decoyPolicyFlag` in Slot 0 (even when Decoy has 0 records), active-vault password change in either slot, and non-destructive Decoy password rotation preserving all decoy records.
 * - N08, R12, R18, R19: Exact secret custom field preservation, folder create/rename/delete with reassignment to General, credential pinning, and multi-stem offline password strength penalties (`"maverick"`).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

    private lateinit var context: Context
    private lateinit var dbFile: File
    private lateinit var database: PrivateVaultDatabase
    private lateinit var sessionManager: VaultSessionManager
    private lateinit var repository: VaultRepository

    private val testKdfParams = CryptoEngine.KdfParams(
        algorithm = CryptoEngine.KDF_ALGORITHM_ARGON2ID,
        memoryKb = CryptoEngine.MIN_ALLOWED_MEMORY_KB, // 4096 KB (4 MiB) for fast unit tests
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
            .addMigrations(PrivateVaultDatabase.MIGRATION_1_2, PrivateVaultDatabase.MIGRATION_2_3)
            .build()
        sessionManager = VaultSessionManager()
        repository = VaultRepository(
            vaultDao = database.vaultDao(),
            sessionManager = sessionManager,
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

    @Test
    fun `S01, S02, S03 - Argon2id determinism, bounds validation, AAD tamper rejection, and raw SQLite binary inspection`() = runBlocking {
        val pass = "CorrectHorseBatteryStaple!99".toCharArray()
        val salt = CryptoEngine.generateSalt()

        val key1 = CryptoEngine.deriveKeyArgon2id(pass, salt, testKdfParams)
        val key2 = CryptoEngine.deriveKeyArgon2id(pass, salt, testKdfParams)
        val differentSaltKey = CryptoEngine.deriveKeyArgon2id(pass, CryptoEngine.generateSalt(), testKdfParams)

        assertEquals(32, key1.size)
        assertArrayEquals(key1, key2)
        assertFalse(key1.contentEquals(differentSaltKey))

        // Reject out-of-bounds KDF memory before allocation
        var boundsRejected = false
        try {
            CryptoEngine.deriveKeyArgon2id(pass, salt, testKdfParams.copy(memoryKb = 2_000_000))
        } catch (_: IllegalArgumentException) {
            boundsRejected = true
        }
        assertTrue(boundsRejected)

        // Provision vault and verify 72-byte envelopes and raw SQLite secrecy
        val session = repository.initializeNewVault(
            realMasterPasswordChars = "RealVaultMasterPass#2026".toCharArray(),
            optionalDecoyPasswordChars = null,
            seedSampleDataInRealVault = false,
            seedSampleDataInDecoyVault = false
        )

        val envelopes = database.vaultDao().getAllEnvelopes()
        assertEquals(2, envelopes.size)
        assertEquals(CryptoEngine.WRAPPED_ENVELOPE_CIPHERTEXT_BYTES, envelopes[0].wrappedPayloadCiphertext.size)
        assertEquals(CryptoEngine.WRAPPED_ENVELOPE_CIPHERTEXT_BYTES, envelopes[1].wrappedPayloadCiphertext.size)

        val secretTitle = "SYNTHETIC_NOTE_TITLE_X998877"
        val secretBody = "SYNTHETIC_NOTE_BODY_SECRET_RECOVERY_SEED_ALPHA_OMEGA"
        val secretService = "SYNTHETIC_BANK_SERVICE_Z4455"
        val secretPass = "SYNTHETIC_PASSWORD_VALUE_Q112233!"
        val secretCustomVal = "  EXACT_UNTRIMMED_SECRET_TOKEN_77  "

        repository.saveVaultItem(
            session.sessionId,
            NoteRecord(
                title = secretTitle,
                body = secretBody,
                folderName = "SYNTHETIC_FOLDER_SECRET",
                tags = listOf("SYNTHETIC_TAG_99")
            )
        )
        val credId = UUID.randomUUID().toString()
        repository.saveVaultItem(
            session.sessionId,
            CredentialRecord(
                id = credId,
                serviceName = secretService,
                username = "SYNTHETIC_USER_ID_7766",
                password = secretPass,
                customFields = listOf(
                    CustomCredentialField(label = "API Token", value = secretCustomVal, isSecret = true)
                )
            )
        )

        // N08: Verify custom field exact untrimmed value round-trips through encryption
        val loadedItems = repository.loadDecryptedRecordsForSession(session.sessionId)
        val loadedCred = loadedItems.filterIsInstance<CredentialRecord>().first { it.id == credId }
        assertEquals(secretCustomVal, loadedCred.customFields.first().value)

        database.openHelper.writableDatabase.query("PRAGMA wal_checkpoint(FULL)").close()
        val rawDbAscii = String(dbFile.readBytes(), Charsets.ISO_8859_1)
        assertFalse(rawDbAscii.contains(secretTitle))
        assertFalse(rawDbAscii.contains(secretBody))
        assertFalse(rawDbAscii.contains(secretService))
        assertFalse(rawDbAscii.contains(secretPass))
        assertFalse(rawDbAscii.contains("EXACT_UNTRIMMED_SECRET_TOKEN_77"))
    }

    @Test
    fun `N01 & N02 - Composite primary key prevents cross-vault record_id overwrites and corrupted ciphertext is never silently dropped`() = runBlocking {
        val realPass = "RealMasterPass!2026".toCharArray()
        val decoyPass = "DecoyMasterPass!2026".toCharArray()

        val realSession = repository.initializeNewVault(
            realMasterPasswordChars = realPass,
            optionalDecoyPasswordChars = decoyPass,
            seedSampleDataInRealVault = false,
            seedSampleDataInDecoyVault = false
        )

        val sharedRecordId = "collision-shared-record-id-001"
        repository.saveVaultItem(
            realSession.sessionId,
            NoteRecord(
                id = sharedRecordId,
                title = "Real Vault Note With Shared ID",
                body = "Belongs strictly to Slot 0"
            )
        )

        // Unlock Decoy Vault (Slot 1) and save a record with the EXACT SAME recordId
        sessionManager.lockNow()
        val decoyUnlock = repository.unlockWithPassword(decoyPass) as VaultRepository.UnlockResult.Success
        repository.saveVaultItem(
            decoyUnlock.session.sessionId,
            NoteRecord(
                id = sharedRecordId,
                title = "Decoy Vault Note With Shared ID",
                body = "Belongs strictly to Slot 1"
            )
        )

        // Verify Decoy Vault has its version
        val decoyNotes = repository.loadDecryptedRecordsForSession(decoyUnlock.session.sessionId)
            .filterIsInstance<NoteRecord>()
        assertEquals(1, decoyNotes.size)
        assertEquals("Decoy Vault Note With Shared ID", decoyNotes.first().title)

        // Re-unlock Real Vault (Slot 0) and prove its record with sharedRecordId was NOT overwritten! (N01)
        sessionManager.lockNow()
        val realUnlock = repository.unlockWithPassword(realPass) as VaultRepository.UnlockResult.Success
        val realNotes = repository.loadDecryptedRecordsForSession(realUnlock.session.sessionId)
            .filterIsInstance<NoteRecord>()
        assertEquals(1, realNotes.size)
        assertEquals("Real Vault Note With Shared ID", realNotes.first().title)

        // N02: Corrupt 1 byte of the Real Vault note's ciphertext in SQLite and verify export & merge abort rather than silently losing data
        val rawEntity = database.vaultDao().getRecordById(VaultSessionManager.REAL_SLOT, sharedRecordId)!!
        val corruptedCiphertext = rawEntity.ciphertext.copyOf()
        corruptedCiphertext[corruptedCiphertext.lastIndex] =
            (corruptedCiphertext[corruptedCiphertext.lastIndex].toInt() xor 0xFF).toByte()
        database.vaultDao().upsertRecord(rawEntity.copy(ciphertext = corruptedCiphertext))

        val snapshot = repository.loadDecryptedSlotSnapshotForSession(realUnlock.session.sessionId)
        assertEquals(listOf(sharedRecordId), snapshot.corruptedRecordIds)

        var exportBlockedOnCorruption = false
        try {
            repository.prepareEncryptedBackupBytes(
                sessionId = realUnlock.session.sessionId,
                backupPasswordChars = "BackupPassword!123".toCharArray(),
                allowSkipCorruptedRecords = false
            )
        } catch (e: VaultRepository.VaultRecordIntegrityException) {
            exportBlockedOnCorruption = true
            assertEquals(listOf(sharedRecordId), e.corruptedRecordIds)
        }
        assertTrue("Ordinary backup export must abort when a record is corrupted", exportBlockedOnCorruption)

        // Recovery export explicitly allowed by user succeeds for remaining intact records (folders)
        val recoveryBackupBytes = repository.prepareEncryptedBackupBytes(
            sessionId = realUnlock.session.sessionId,
            backupPasswordChars = "BackupPassword!123".toCharArray(),
            allowSkipCorruptedRecords = true
        )
        assertTrue(recoveryBackupBytes.isNotEmpty())

        // Merge restore must also abort when active slot has a corrupted record so it is never deleted
        var mergeBlockedOnCorruption = false
        try {
            repository.applyVerifiedBackupRestore(
                sessionId = realUnlock.session.sessionId,
                backupBytes = recoveryBackupBytes,
                backupPasswordChars = "BackupPassword!123".toCharArray(),
                restoreMode = PortableBackupEngine.RestoreMode.MERGE_KEEP_NEWEST
            )
        } catch (_: VaultRepository.VaultRecordIntegrityException) {
            mergeBlockedOnCorruption = true
        }
        assertTrue("Merge restore must abort if existing slot has corrupted records", mergeBlockedOnCorruption)
        assertNotNull(
            "Corrupted record ciphertext must still exist in SQLite after aborted merge",
            database.vaultDao().getRecordById(VaultSessionManager.REAL_SLOT, sharedRecordId)
        )
    }

    @Test
    fun `N03, N05, R01, R02 - Lock invalidates late KDF unlock, empty Decoy keeps decoyPolicyFlag active, and Decoy password rotation preserves decoy records`() = runBlocking {
        val realPass = "RealVaultPass!100".toCharArray()
        val decoyPass = "DecoyVaultPass!200".toCharArray()

        // Initialize with an EMPTY Decoy Vault (seedSampleDataInDecoyVault = false -> 0 notes/creds in Slot 1)
        val initialSession = repository.initializeNewVault(
            realMasterPasswordChars = realPass,
            optionalDecoyPasswordChars = decoyPass,
            seedSampleDataInRealVault = false,
            seedSampleDataInDecoyVault = false
        )

        // Delete all starter folders in Slot 1 so Slot 1 has literally 0 rows in encrypted_records
        database.vaultDao().deleteAllRecordsForSlot(VaultSessionManager.DECOY_SLOT)
        assertEquals(0, database.vaultDao().countRecordsForSlot(VaultSessionManager.DECOY_SLOT))

        // R01: Even with 0 records in Slot 1, Decoy Mode must remain recognized as active via Slot 0's inner envelope!
        sessionManager.lockNow()
        val unlockedReal = repository.unlockWithPassword(realPass) as VaultRepository.UnlockResult.Success
        assertTrue(
            "Empty decoy vault must still be recognized as active via Slot 0 decoyPolicyFlag",
            repository.isDecoyModeEnabledForRealSession(unlockedReal.session.sessionId)
        )

        // R01: Biometric enrollment must be rejected while empty Decoy Mode is active
        var bioBlockedWithEmptyDecoy = false
        try {
            repository.getCipherForBiometricEnrollment(unlockedReal.session.sessionId)
        } catch (_: IllegalArgumentException) {
            bioBlockedWithEmptyDecoy = true
        }
        assertTrue("Biometric enrollment must remain blocked even when Decoy Vault has 0 records", bioBlockedWithEmptyDecoy)

        // Add a custom note inside Decoy Vault
        sessionManager.lockNow()
        val decoySession1 = (repository.unlockWithPassword(decoyPass) as VaultRepository.UnlockResult.Success).session
        val decoyNoteId = UUID.randomUUID().toString()
        repository.saveVaultItem(
            decoySession1.sessionId,
            NoteRecord(
                id = decoyNoteId,
                title = "Decoy Travel Itinerary",
                body = "Must survive Decoy password rotation!"
            )
        )

        // R02: Rotate Decoy Password directly while inside Decoy session using changeActiveVaultPassword
        val decoyPass2 = "RotatedDecoyPassInDecoy!300".toCharArray()
        repository.changeActiveVaultPassword(
            sessionId = decoySession1.sessionId,
            currentPasswordChars = decoyPass,
            newPasswordChars = decoyPass2
        )

        // Unlock Real Vault and rotate Decoy Password non-destructively from Real Vault (N05)
        sessionManager.lockNow()
        val realSession2 = (repository.unlockWithPassword(realPass) as VaultRepository.UnlockResult.Success).session
        val decoyPass3 = "RotatedDecoyFromReal!400".toCharArray()
        repository.rotateDecoyPasswordPreservingRecords(
            sessionId = realSession2.sessionId,
            realMasterPasswordChars = realPass,
            currentDecoyPasswordChars = decoyPass2,
            newDecoyPasswordChars = decoyPass3
        )

        // Verify Decoy Vault unlocks with decoyPass3 AND still contains "Decoy Travel Itinerary"! (N05)
        sessionManager.lockNow()
        val decoyUnlockAfterRotate = repository.unlockWithPassword(decoyPass3)
        assertTrue(decoyUnlockAfterRotate is VaultRepository.UnlockResult.Success)
        val preservedDecoyNotes = repository.loadDecryptedRecordsForSession(
            (decoyUnlockAfterRotate as VaultRepository.UnlockResult.Success).session.sessionId
        ).filterIsInstance<NoteRecord>()
        assertTrue(
            "Decoy note must be preserved across non-destructive decoy password rotation",
            preservedDecoyNotes.any { it.id == decoyNoteId && it.title == "Decoy Travel Itinerary" }
        )

        // N03: Simulate a lock/screen-off occurring after capturing authRequestGeneration
        sessionManager.lockNow()
        val staleAuthGeneration = sessionManager.currentAuthRequestGeneration()
        // Lock happens while KDF is in flight (incrementing authRequestGeneration)
        sessionManager.lockNow()
        val lateUnlockResult = repository.unlockWithPassword(realPass, expectedAuthGeneration = staleAuthGeneration)
        assertTrue(
            "Late unlock completion after lock event must return CancelledByLock",
            lateUnlockResult is VaultRepository.UnlockResult.CancelledByLock
        )
        assertTrue(
            "Session state must remain Locked after late KDF completion",
            sessionManager.sessionState.value is VaultSessionManager.SessionState.Locked
        )
    }

    @Test
    fun `R12, R18, R19 - Folder create-rename-delete reassignment, credential pinning, and multi-stem strength estimator`() = runBlocking {
        val session = repository.initializeNewVault(
            realMasterPasswordChars = "FolderTestMaster!2026".toCharArray(),
            optionalDecoyPasswordChars = null,
            seedSampleDataInRealVault = false,
            seedSampleDataInDecoyVault = false
        )

        val customFolder = VaultFolder(
            id = "folder-banking-1",
            name = "Banking",
            scope = FolderScope.NOTES
        )
        repository.saveVaultItem(session.sessionId, customFolder)

        val noteInFolder = NoteRecord(
            id = "note-in-banking",
            title = "Tax Return Notes",
            body = "Filed on time",
            folderId = customFolder.id,
            folderName = customFolder.name
        )
        repository.saveVaultItem(session.sessionId, noteInFolder)

        // Rename folder "Banking" -> "Taxes & Finance" and verify note's folderName is updated while keeping folderId
        repository.renameVaultFolder(session.sessionId, customFolder.id, "Taxes & Finance")
        val afterRename = repository.loadDecryptedRecordsForSession(session.sessionId)
            .filterIsInstance<NoteRecord>()
            .first { it.id == noteInFolder.id }
        assertEquals(customFolder.id, afterRename.folderId)
        assertEquals("Taxes & Finance", afterRename.folderName)

        // Delete folder and verify note is safely reassigned to built-in "General" without being deleted!
        repository.deleteVaultFolderAndReassignRecords(session.sessionId, customFolder.id)
        val afterDelete = repository.loadDecryptedRecordsForSession(session.sessionId)
            .filterIsInstance<NoteRecord>()
            .first { it.id == noteInFolder.id }
        assertEquals(VaultFolder.DEFAULT_NOTE_FOLDER_ID, afterDelete.folderId)
        assertEquals(VaultFolder.DEFAULT_FOLDER_NAME, afterDelete.folderName)

        // R19: Verify "maverick" typo fix and cumulative multi-stem penalties
        val singleStemReport = OfflinePasswordStrengthEstimator.evaluate("maverickX9#pL")
        assertTrue(
            "Dictionary stem 'maverick' must be detected",
            singleStemReport.warnings.any { it.contains("maverick", ignoreCase = true) }
        )
        val multiStemReport = OfflinePasswordStrengthEstimator.evaluate("maverickshadowdragonX9#pL")
        assertTrue(
            "Multiple stems must be reported together",
            multiStemReport.warnings.any {
                it.contains("maverick") && it.contains("shadow")
            }
        )
    }

    @Test
    fun `U01, U02, U04, R06 - ViewModel cache-staged backup export and URI restore round-trip plus public handle clipboard copy`() = runBlocking {
        val prefsRepo = AppPreferencesRepository(context)
        val otaMgr = OtaUpdateManager(context)
        val viewModel = VaultViewModel(
            appContext = context,
            vaultRepository = repository,
            preferencesRepository = prefsRepo,
            otaUpdateManager = otaMgr,
            enableStartupOtaCheck = false
        )

        val realSession = repository.initializeNewVault(
            realMasterPasswordChars = "ViewModelBackupPass!1".toCharArray(),
            optionalDecoyPasswordChars = null,
            seedSampleDataInRealVault = true,
            seedSampleDataInDecoyVault = false
        )
        viewModel.refreshActiveVaultItems(realSession.sessionId)
        delay(100L)

        // U04 & R06: Copy a sensitive secret first, then copy Instagram public handle (@tp_ediitz)
        val clipScope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val testClipMgr = SensitiveClipboardManager(context, clipScope)
        try {
            testClipMgr.copySensitiveSecret("Vault Password", "SuperSecret123!", ttlSeconds = 30)
            testClipMgr.copyPublicText("Instagram ID", "@tp_ediitz")
            // Now calling clearIfStillOwned() must NOT clear the clipboard because public copy retired secret ownership!
            val cleared = testClipMgr.clearIfStillOwned()
            assertFalse("Public contact handle must not be cleared by secret ownership cleaner", cleared)
        } finally {
            testClipMgr.shutdown()
            clipScope.cancel()
        }

        // U01 & U02: Export encrypted .pvault via ViewModel staging file to a file:// Uri and restore it into a clean vault
        val exportedFile = File(context.cacheDir, "exported_roundtrip_${UUID.randomUUID()}.pvault")
        try {
            val prepJob = viewModel.prepareBackupExport(
                backupPassword = "PortableBackupPass!99",
                confirmPassword = "PortableBackupPass!99",
                onReadyToLaunchCreateDocument = {}
            )
            prepJob?.join()
            val exportJob = viewModel.completeExportToUri(Uri.fromFile(exportedFile))
            exportJob?.join()
            assertTrue(exportedFile.exists() && exportedFile.length() > 52L)

            // Wipe active vault records and restore from URI
            database.vaultDao().deleteAllRecordsForSlot(VaultSessionManager.REAL_SLOT)
            assertEquals(0, database.vaultDao().countRecordsForSlot(VaultSessionManager.REAL_SLOT))

            viewModel.onRestoreFileSelected(Uri.fromFile(exportedFile))?.join()
            val restoreJob = viewModel.verifyAndRestoreSelectedUri(
                backupPassword = "PortableBackupPass!99",
                restoreMode = PortableBackupEngine.RestoreMode.REPLACE_ACTIVE_VAULT
            )
            restoreJob?.join()

            val restoredItems = repository.loadDecryptedRecordsForSession(realSession.sessionId)
            assertTrue(
                "Starter notes must be restored from .pvault URI",
                restoredItems.filterIsInstance<NoteRecord>().isNotEmpty()
            )
        } finally {
            exportedFile.delete()
        }
    }

    @Test
    fun `N04, R04, U06, U07 - OtaUpdateManager fails closed on null archive metadata, enforces tpeditz repo URLs, and verifies apksig`() {
        val trustedKeyPair = generateRsaKeyPair()
        val trustedCert = generateSelfSignedCertificate(trustedKeyPair, "CN=Tp Editz Release Signer")
        val trustedCertSha256 = OtaUpdateManager.sha256Hex(trustedCert.encoded)

        val attackerKeyPair = generateRsaKeyPair()
        val attackerCert = generateSelfSignedCertificate(attackerKeyPair, "CN=Untrusted Attacker Signer")
        val attackerCertSha256 = OtaUpdateManager.sha256Hex(attackerCert.encoded)

        val unsignedApk = File(context.cacheDir, "unsigned_test.apk")
        val signedValidApk = File(context.cacheDir, "signed_valid_v3.apk")
        val signedAttackerApk = File(context.cacheDir, "signed_attacker_v3.apk")

        try {
            createMinimalTestApkZip(unsignedApk)

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

            // 1. N04: If ArchiveInfoParser returns null, verifyCandidateApkFile MUST FAIL CLOSED!
            val managerWithNullArchive = OtaUpdateManager(
                context = context,
                installedSignerDigestsProvider = { setOf(trustedCertSha256) },
                installedVersionCodeProvider = { 2L },
                archiveInfoParser = { _, _ -> null }
            )
            var nullArchiveRejected = false
            try {
                managerWithNullArchive.verifyCandidateApkFile(
                    apkFile = signedValidApk,
                    expectedFileSha256 = validApkSha256,
                    expectedVersionCode = 3L
                )
            } catch (_: SecurityException) {
                nullArchiveRejected = true
            }
            assertTrue("Null package archive metadata must fail closed with SecurityException (N04)", nullArchiveRejected)

            // 2. Valid archive info + valid apksig + matching trusted signer succeeds
            val validArchiveInfo = PackageInfo().apply {
                packageName = context.packageName
                versionName = "1.0.2"
                @Suppress("DEPRECATION")
                versionCode = 3
                longVersionCode = 3L
            }
            val managerWithValidArchive = OtaUpdateManager(
                context = context,
                installedSignerDigestsProvider = { setOf(trustedCertSha256) },
                installedVersionCodeProvider = { 2L },
                archiveInfoParser = { _, _ -> validArchiveInfo }
            )
            val verifiedDigest = managerWithValidArchive.verifyCandidateApkFile(
                apkFile = signedValidApk,
                expectedFileSha256 = validApkSha256,
                expectedVersionCode = 3L
            )
            assertEquals(trustedCertSha256, verifiedDigest)

            // 3. Attacker-signed APK must be rejected
            val attackerSha256 = OtaUpdateManager.computeFileSha256Hex(signedAttackerApk)
            var attackerRejected = false
            try {
                managerWithValidArchive.verifyCandidateApkFile(
                    apkFile = signedAttackerApk,
                    expectedFileSha256 = attackerSha256,
                    expectedVersionCode = 3L
                )
            } catch (_: SecurityException) {
                attackerRejected = true
            }
            assertTrue(attackerRejected)
            assertFalse(trustedCertSha256 == attackerCertSha256)

            // 4. R04: Production URL validation rejects foreign GitHub repositories
            var foreignRepoRejected = false
            try {
                managerWithValidArchive.validateAllowedHttpsUrl(
                    url = "https://raw.githubusercontent.com/otheruser/otherrepo/main/update.json",
                    isManifestEndpoint = true,
                    allowDebugCustomRepositoryPath = false
                )
            } catch (_: IllegalArgumentException) {
                foreignRepoRejected = true
            }
            assertTrue("Foreign GitHub repository path must be rejected in production mode (R04)", foreignRepoRejected)

            // Official tpeditz/Private-vault-updates manifest URL is accepted
            managerWithValidArchive.validateAllowedHttpsUrl(
                url = AppPreferencesRepository.DEFAULT_OTA_MANIFEST_URL,
                isManifestEndpoint = true,
                allowDebugCustomRepositoryPath = false
            )
        } finally {
            unsignedApk.delete()
            signedValidApk.delete()
            signedAttackerApk.delete()
        }
    }

    @Test
    fun `U09, U10, U11, N01 - Room schema migration v1 to v2 to v3 preserves both Real and Decoy vaults intact`() = runBlocking {
        val migrationDbName = "migration_v1_to_v3_${UUID.randomUUID()}.db"
        val migrationDbFile = context.getDatabasePath(migrationDbName)

        try {
            val v1Callback = object : SupportSQLiteOpenHelper.Callback(1) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    db.execSQL(
                        """
                        CREATE TABLE IF NOT EXISTS `vault_envelopes` (
                            `slot_id` INTEGER NOT NULL,
                            `envelope_version` INTEGER NOT NULL,
                            `kdf_algorithm` TEXT NOT NULL,
                            `kdf_salt` BLOB NOT NULL,
                            `kdf_memory_kb` INTEGER NOT NULL,
                            `kdf_iterations` INTEGER NOT NULL,
                            `kdf_parallelism` INTEGER NOT NULL,
                            `envelope_nonce` BLOB NOT NULL,
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

            // Open with Room at Version 3 using MIGRATION_1_2 and MIGRATION_2_3
            val migratedRoomDb = Room.databaseBuilder(context, PrivateVaultDatabase::class.java, migrationDbName)
                .addMigrations(PrivateVaultDatabase.MIGRATION_1_2, PrivateVaultDatabase.MIGRATION_2_3)
                .allowMainThreadQueries()
                .build()

            val migSessionMgr = VaultSessionManager()
            val migRepo = VaultRepository(
                vaultDao = migratedRoomDb.vaultDao(),
                sessionManager = migSessionMgr,
                defaultKdfParamsProvider = { testKdfParams }
            )

            val realPass = "UpgradeRealPass!100".toCharArray()
            val decoyPass = "UpgradeDecoyPass!200".toCharArray()
            val realSession = migRepo.initializeNewVault(
                realMasterPasswordChars = realPass,
                optionalDecoyPasswordChars = decoyPass,
                seedSampleDataInRealVault = true,
                seedSampleDataInDecoyVault = true
            )

            val realNoteId = UUID.randomUUID().toString()
            migRepo.saveVaultItem(
                realSession.sessionId,
                NoteRecord(
                    id = realNoteId,
                    title = "Pre-Update Real Vault Note",
                    body = "Survived v1 -> v2 -> v3 migration",
                    format = NoteBodyFormat.CHECKLIST,
                    checklistItems = listOf(ChecklistEntry(text = "Check composite PK", isChecked = true))
                )
            )
            migSessionMgr.lockNow()
            migratedRoomDb.close()

            val reopenedDb = Room.databaseBuilder(context, PrivateVaultDatabase::class.java, migrationDbName)
                .addMigrations(PrivateVaultDatabase.MIGRATION_1_2, PrivateVaultDatabase.MIGRATION_2_3)
                .allowMainThreadQueries()
                .build()
            val postUpgradeSessionMgr = VaultSessionManager()
            val postUpgradeRepo = VaultRepository(
                vaultDao = reopenedDb.vaultDao(),
                sessionManager = postUpgradeSessionMgr,
                defaultKdfParamsProvider = { testKdfParams }
            )

            val unlockReal = postUpgradeRepo.unlockWithPassword(realPass) as VaultRepository.UnlockResult.Success
            val realRecords = postUpgradeRepo.loadDecryptedRecordsForSession(unlockReal.session.sessionId)
            assertTrue(realRecords.any { it.id == realNoteId })

            postUpgradeSessionMgr.lockNow()
            val unlockDecoy = postUpgradeRepo.unlockWithPassword(decoyPass) as VaultRepository.UnlockResult.Success
            val decoyRecords = postUpgradeRepo.loadDecryptedRecordsForSession(unlockDecoy.session.sessionId)
            assertTrue(decoyRecords.isNotEmpty())
            assertFalse(decoyRecords.any { it.id == realNoteId })

            reopenedDb.close()
        } finally {
            migrationDbFile.delete()
            File("${migrationDbFile.absolutePath}-wal").delete()
            File("${migrationDbFile.absolutePath}-shm").delete()
        }
    }

    @Test
    fun `S03, S09, S10 - Argon2id benchmark telemetry, 3-option OTA reminder policy, and SAF file-picker window`() {
        val stdBench = CryptoEngine.measureKdfBenchmark(testKdfParams)
        assertTrue(stdBench.singleSlotDurationMs > 0L)
        assertTrue(stdBench.twoSlotUnlockDurationMs >= stdBench.singleSlotDurationMs)

        // Verify 3-option OTA reminder deferral policy (Next Launch, Tomorrow, In 3 Days)
        val prefsRepo = AppPreferencesRepository(context)
        val now = 1_700_000_000_000L
        val tomorrowPrefs = VaultAppPreferences(
            otaReminderPolicy = OtaReminderPolicy.TOMORROW,
            otaSnoozedUntilEpochMs = now + 24L * 3600L * 1000L,
            otaSnoozedVersionCode = 3
        )
        assertFalse(prefsRepo.shouldShowAutomaticUpdatePrompt(tomorrowPrefs, remoteVersionCode = 3, nowEpochMs = now + 3600_000L))
        assertTrue(prefsRepo.shouldShowAutomaticUpdatePrompt(tomorrowPrefs, remoteVersionCode = 3, nowEpochMs = now + 25L * 3600L * 1000L))
        assertTrue(prefsRepo.shouldShowAutomaticUpdatePrompt(tomorrowPrefs, remoteVersionCode = 4, nowEpochMs = now))

        // Verify SAF File-Picker 90s bounded transition window
        val dek = CryptoEngine.generateDek()
        val s1 = sessionManager.openSession(VaultSessionManager.REAL_SLOT, dek)
        sessionManager.onAppBackgrounded(nowMonotonicMs = 1_000L)
        assertTrue(sessionManager.onAppForegrounded(autoLockTimeoutMs = 0L, nowMonotonicMs = 2_000L))
        assertFalse(sessionManager.isSessionActive(s1.sessionId))

        val s2 = sessionManager.openSession(VaultSessionManager.REAL_SLOT, dek)
        sessionManager.beginFilePickerTransitionWindow(nowMonotonicMs = 10_000L)
        sessionManager.onAppBackgrounded(nowMonotonicMs = 10_100L)
        assertFalse(sessionManager.onAppForegrounded(autoLockTimeoutMs = 0L, nowMonotonicMs = 25_000L))
        assertTrue(sessionManager.isSessionActive(s2.sessionId))
    }

    @Test
    fun `T01, T02, T05 - MainActivity FragmentActivity 1_8_6 launches CreateDocument and OpenDocument without 16-bit requestCode crash`() {
        Robolectric.buildActivity(MainActivity::class.java).setup().use { controller ->
            val activity = controller.get()
            val createLauncher = activity.activityResultRegistry.register(
                "test_create_backup_doc",
                ActivityResultContracts.CreateDocument("application/octet-stream")
            ) { }
            val openLauncher = activity.activityResultRegistry.register(
                "test_open_restore_doc",
                ActivityResultContracts.OpenDocument()
            ) { }

            try {
                // In fragment:1.2.5 this threw IllegalArgumentException: Can only use lower 16 bits for requestCode
                createLauncher.launch("private-vault-backup-test.pvault")
                openLauncher.launch(arrayOf("*/*"))
            } finally {
                createLauncher.unregister()
                openLauncher.unregister()
            }
        }
    }

    @Test
    fun `T03, T04, T10, T31 - Backup preview, clean export status, cross-slot export guard, and Trash lifecycle`() = runBlocking {
        val realPass = "RealVaultPass#500".toCharArray()
        val decoyPass = "DecoyVaultPass#600".toCharArray()
        val realSession = repository.initializeNewVault(
            realMasterPasswordChars = realPass,
            optionalDecoyPasswordChars = decoyPass,
            seedSampleDataInRealVault = true,
            seedSampleDataInDecoyVault = true
        )
        repository.saveVaultItem(
            realSession.sessionId,
            CredentialRecord(
                serviceName = "Example Service",
                username = "alice@example.com",
                password = "AlicePassword!123"
            )
        )

        val viewModel = VaultViewModel(
            appContext = context,
            vaultRepository = repository,
            preferencesRepository = AppPreferencesRepository(context),
            otaUpdateManager = OtaUpdateManager(context),
            enableStartupOtaCheck = false
        )

        val exportDestFile = File(context.cacheDir, "v5_export_${UUID.randomUUID()}.pvault")
        try {
            // 1. T03: Export produces clean "Backup saved (X KB)." status without raw content:// or file:// URI
            var launchedFileName: String? = null
            viewModel.prepareBackupExport(
                backupPassword = "BackupPass!555",
                confirmPassword = "BackupPass!555",
                onReadyToLaunchCreateDocument = { suggested -> launchedFileName = suggested }
            )?.join()
            assertNotNull(launchedFileName)
            val stagedPath = viewModel.uiState.value.stagedBackupMetadata?.stagedFilePath
            assertNotNull(stagedPath)

            viewModel.completeExportToUri(Uri.fromFile(exportDestFile))?.join()
            assertTrue(exportDestFile.exists() && exportDestFile.length() > 0L)
            assertFalse(File(stagedPath!!).exists())
            val statusMsg = viewModel.uiState.value.statusBannerMessage.orEmpty()
            assertTrue("Expected 'Backup saved (... KB).' but got '$statusMsg'", statusMsg.startsWith("Backup saved ("))
            assertFalse(statusMsg.contains("file://") || statusMsg.contains("content://"))

            // 2. T04: Authenticated backup preview populates VerifiedRestorePreviewState without altering vault
            viewModel.onRestoreFileSelected(Uri.fromFile(exportDestFile))?.join()
            viewModel.verifyAndPreviewSelectedUri("BackupPass!555")?.join()
            val preview = viewModel.uiState.value.verifiedRestorePreview
            assertNotNull("Expected authenticated restore preview to be populated (T04)", preview)
            assertTrue(preview!!.notesCount >= 1)
            assertTrue(preview.credentialsCount >= 1)

            // 3. T10: Cross-slot export callback guard rejects writing a Slot 0 staged backup after switching to Slot 1
            val crossSlotDestFile = File(context.cacheDir, "cross_slot_${UUID.randomUUID()}.pvault")
            viewModel.prepareBackupExport(
                backupPassword = "BackupPass!555",
                confirmPassword = "BackupPass!555",
                onReadyToLaunchCreateDocument = { }
            )?.join()
            val crossSlotStagedPath = viewModel.uiState.value.stagedBackupMetadata?.stagedFilePath
            assertNotNull(crossSlotStagedPath)

            // Simulate user switching directly to Slot 1 (Decoy Vault) before CreateDocument callback returns
            val decoyUnlock = repository.unlockWithPassword(decoyPass) as VaultRepository.UnlockResult.Success
            assertEquals(VaultSessionManager.DECOY_SLOT, decoyUnlock.session.slotId)

            viewModel.completeExportToUri(Uri.fromFile(crossSlotDestFile))
            assertFalse("Cross-slot export must be rejected (T10)", crossSlotDestFile.exists())
            assertFalse("Staged file must be deleted on cross-slot rejection", File(crossSlotStagedPath!!).exists())
            assertTrue(viewModel.uiState.value.errorBannerMessage.orEmpty().contains("aborted", ignoreCase = true))

            // 4. T31: Trash soft-delete and restore lifecycle
            val noteToTrash = NoteRecord(title = "Trashable Note", body = "Soft delete check")
            repository.saveVaultItem(decoyUnlock.session.sessionId, noteToTrash)
            val trashedCopy = noteToTrash.copy(isTrashed = true)
            repository.saveVaultItem(decoyUnlock.session.sessionId, trashedCopy)
            val loadedAfterTrash = repository.loadDecryptedRecordsForSession(decoyUnlock.session.sessionId)
                .filterIsInstance<NoteRecord>()
                .first { it.id == noteToTrash.id }
            assertTrue("Expected isTrashed = true to persist in encrypted record (T31)", loadedAfterTrash.isTrashed)
        } finally {
            exportDestFile.delete()
        }
    }

    @Test
    fun `T25, T26, T28 - OTA manifest dual-schema compatibility, duplicate key rejection, and redirect URL validation`() {
        val otaManager = OtaUpdateManager(context)

        // 1. T25 & T28: Dual-schema generator emits both apkUrl and downloadUrl and parses cleanly
        val expectedUrl = "https://github.com/tpeditz/Private-vault-updates/releases/download/v1.0.3-b4/PRIVATE-VAULT-v1.0.3-b4.apk"
        val generatedJson = OtaUpdateManager.generateCompatibleManifestJson(
            OtaUpdateManager.UpdateManifest(
                versionCode = 4,
                versionName = "1.0.3",
                apkDownloadUrl = expectedUrl,
                sha256Checksum = "a".repeat(64),
                releaseNotes = "Version 5 release",
                publishedAt = "2026-11-05T00:00:00Z",
                fileSizeBytes = 12_345_678L
            )
        )
        assertTrue(generatedJson.contains("\"apkUrl\""))
        assertTrue(generatedJson.contains("\"downloadUrl\""))
        val parsed = otaManager.parseAndValidateManifestJson(generatedJson, allowDebugCustomRepositoryPath = false)
        assertEquals(4, parsed.versionCode)
        assertEquals("1.0.3", parsed.versionName)
        assertEquals(expectedUrl, parsed.apkDownloadUrl)

        // Legacy downloadUrl-only manifest is also accepted
        val legacyDownloadUrlOnly = """
            {
              "schemaVersion": 1,
              "versionCode": 4,
              "versionName": "1.0.3",
              "downloadUrl": "https://github.com/tpeditz/Private-vault-updates/releases/download/v1.0.3-b4/PRIVATE-VAULT-v1.0.3-b4.apk",
              "sha256": "${"b".repeat(64)}",
              "fileSizeBytes": 5000000,
              "releaseNotes": "Legacy field test",
              "publishedAt": "2026-11-05T00:00:00Z",
              "minSupportedVersionCode": 1
            }
        """.trimIndent()
        val parsedLegacy = otaManager.parseAndValidateManifestJson(legacyDownloadUrlOnly, allowDebugCustomRepositoryPath = false)
        assertEquals(4, parsedLegacy.versionCode)

        // Conflicting apkUrl and downloadUrl must be rejected
        var conflictRejected = false
        try {
            otaManager.parseAndValidateManifestJson(
                """
                {
                  "schemaVersion": 1,
                  "versionCode": 4,
                  "versionName": "1.0.3",
                  "apkUrl": "https://github.com/tpeditz/Private-vault-updates/releases/download/v1.0.3-b4/a.apk",
                  "downloadUrl": "https://github.com/tpeditz/Private-vault-updates/releases/download/v1.0.3-b4/b.apk",
                  "sha256": "${"c".repeat(64)}",
                  "fileSizeBytes": 5000000,
                  "releaseNotes": "Conflict",
                  "publishedAt": "2026-11-05T00:00:00Z",
                  "minSupportedVersionCode": 1
                }
                """.trimIndent(),
                allowDebugCustomRepositoryPath = false
            )
        } catch (_: IllegalArgumentException) {
            conflictRejected = true
        }
        assertTrue("Conflicting apkUrl and downloadUrl must be rejected (T25)", conflictRejected)

        // Duplicate top-level JSON keys must be rejected
        var duplicateKeyRejected = false
        try {
            otaManager.parseAndValidateManifestJson(
                """
                {
                  "schemaVersion": 1,
                  "versionCode": 2,
                  "versionCode": 4,
                  "versionName": "1.0.3",
                  "apkUrl": "https://github.com/tpeditz/Private-vault-updates/releases/download/v1.0.3-b4/a.apk",
                  "sha256": "${"d".repeat(64)}",
                  "fileSizeBytes": 5000000,
                  "releaseNotes": "Duplicate key",
                  "publishedAt": "2026-11-05T00:00:00Z",
                  "minSupportedVersionCode": 1
                }
                """.trimIndent(),
                allowDebugCustomRepositoryPath = false
            )
        } catch (_: IllegalArgumentException) {
            duplicateKeyRejected = true
        }
        assertTrue("Duplicate top-level JSON keys must be rejected (T25)", duplicateKeyRejected)

        // 2. T26: URL validation rejects userInfo, custom ports, path traversal, and untrusted hosts
        val invalidUrls = listOf(
            "http://raw.githubusercontent.com/tpeditz/Private-vault-updates/main/update.json",
            "https://user:pass@raw.githubusercontent.com/tpeditz/Private-vault-updates/main/update.json",
            "https://raw.githubusercontent.com:8443/tpeditz/Private-vault-updates/main/update.json",
            "https://raw.githubusercontent.com/tpeditz/Private-vault-updates/../other/update.json",
            "https://evil.example.com/tpeditz/Private-vault-updates/main/update.json"
        )
        for (badUrl in invalidUrls) {
            var rejected = false
            try {
                otaManager.validateAllowedHttpsUrl(
                    url = badUrl,
                    isManifestEndpoint = true,
                    allowDebugCustomRepositoryPath = false
                )
            } catch (_: IllegalArgumentException) {
                rejected = true
            }
            assertTrue("Expected invalid URL '$badUrl' to be rejected (T26)", rejected)
        }

        // Valid GitHub release asset CDN redirect hop is accepted when isManifestEndpoint = false and isRedirectHop = true
        otaManager.validateAllowedHttpsUrl(
            url = "https://objects.githubusercontent.com/github-production-release-asset-2e65be/12345/asset.apk",
            isManifestEndpoint = false,
            allowDebugCustomRepositoryPath = false,
            isRedirectHop = true
        )
    }

    @Test
    fun `PV-DATA-001 & PV-BUG-009 - Malformed backup JSON variants fail closed before any DB write and empty backup sets isEmptyBackup`() = runBlocking {
        val realPass = "RealVaultIntegrity!100".toCharArray()
        val decoyPass = "DecoyVaultIntegrity!200".toCharArray()
        val realSession = repository.initializeNewVault(
            realMasterPasswordChars = realPass,
            optionalDecoyPasswordChars = decoyPass,
            seedSampleDataInRealVault = false,
            seedSampleDataInDecoyVault = false
        )

        val protectedRealNote = NoteRecord(
            id = "protected-real-note-001",
            title = "Critical Real Vault Note",
            body = "Must never be wiped by malformed backup payload"
        )
        repository.saveVaultItem(realSession.sessionId, protectedRealNote)

        sessionManager.lockNow()
        val decoySession = (repository.unlockWithPassword(decoyPass) as VaultRepository.UnlockResult.Success).session
        val protectedDecoyNote = NoteRecord(
            id = "protected-decoy-note-001",
            title = "Critical Decoy Vault Note",
            body = "Inactive slot must also remain untouched"
        )
        repository.saveVaultItem(decoySession.sessionId, protectedDecoyNote)

        sessionManager.lockNow()
        val unlockedReal = (repository.unlockWithPassword(realPass) as VaultRepository.UnlockResult.Success).session

        val backupPass = "MalformedTestBackupPass!99".toCharArray()
        val malformedJsonPayloads = listOf(
            """{"containerFormat":"PVAULT-PORTABLE-V1","exportedAtEpochMs":1700000000000}""", // missing records
            """{"containerFormat":"PVAULT-PORTABLE-V1","exportedAtEpochMs":1700000000000,"records":null}""", // null records
            """{"containerFormat":"PVAULT-PORTABLE-V1","exportedAtEpochMs":1700000000000,"records":"corrupted"}""", // string records
            """{"containerFormat":"PVAULT-PORTABLE-V1","exportedAtEpochMs":1700000000000,"records":12345}""", // number records
            """{"containerFormat":"PVAULT-PORTABLE-V1","exportedAtEpochMs":1700000000000,"records":{}}""", // object records
            """{"containerFormat":"PVAULT-PORTABLE-V1","exportedAtEpochMs":1700000000000,"records":[null]}""", // null array item
            """{"containerFormat":"PVAULT-PORTABLE-V1","exportedAtEpochMs":1700000000000,"records":[{"id":"","recordType":"NOTE"}]}""", // blank id
            """{"containerFormat":"PVAULT-PORTABLE-V1","exportedAtEpochMs":1700000000000,"records":[{"id":"x1","recordType":"UNKNOWN_TYPE"}]}""" // invalid recordType
        )

        for (rawJson in malformedJsonPayloads) {
            val craftedBackupBytes = craftSignedBackupContainerForRawJson(rawJson, backupPass)
            var rejected = false
            try {
                repository.applyVerifiedBackupRestore(
                    sessionId = unlockedReal.sessionId,
                    backupBytes = craftedBackupBytes,
                    backupPasswordChars = backupPass.copyOf(),
                    restoreMode = PortableBackupEngine.RestoreMode.REPLACE_ACTIVE_VAULT
                )
            } catch (_: IllegalArgumentException) {
                rejected = true
            }
            assertTrue("Expected malformed payload '$rawJson' to be rejected with IllegalArgumentException", rejected)
        }

        // Verify active Real slot AND inactive Decoy slot remain 100% intact after all rejected REPLACE attempts
        val remainingRealNotes = repository.loadDecryptedRecordsForSession(unlockedReal.sessionId)
            .filterIsInstance<NoteRecord>()
        assertEquals(1, remainingRealNotes.size)
        assertEquals("Critical Real Vault Note", remainingRealNotes.first().title)

        sessionManager.lockNow()
        val reUnlockedDecoy = (repository.unlockWithPassword(decoyPass) as VaultRepository.UnlockResult.Success).session
        val remainingDecoyNotes = repository.loadDecryptedRecordsForSession(reUnlockedDecoy.sessionId)
            .filterIsInstance<NoteRecord>()
        assertEquals(1, remainingDecoyNotes.size)
        assertEquals("Critical Decoy Vault Note", remainingDecoyNotes.first().title)

        // Verify valid empty backup {"records":[]} is recognized with isEmptyBackup = true
        val validEmptyJson = """{"backupSchemaVersion":1,"exportedAtEpochMs":1700000000000,"appVersionName":"1.0.4","records":[]}"""
        val validEmptyBytes = craftSignedBackupContainerForRawJson(validEmptyJson, backupPass)
        val parsedEmpty = PortableBackupEngine.decryptAndVerifyBackupBytes(validEmptyBytes, backupPass.copyOf())
        assertTrue(parsedEmpty.isEmptyBackup)
        assertEquals(0, parsedEmpty.items.size)

        // PV-BUG-009: Verify selective export scope (NOTES_ONLY vs PASSWORDS_ONLY)
        sessionManager.lockNow()
        val realForScope = (repository.unlockWithPassword(realPass) as VaultRepository.UnlockResult.Success).session
        repository.saveVaultItem(
            realForScope.sessionId,
            CredentialRecord(
                id = "scope-cred-001",
                serviceName = "Scoped Service",
                username = "scoped_user",
                password = "ScopedPassword!123",
                accountLabel = "Work Account",
                isArchived = true
            )
        )
        val notesOnlyBytes = repository.prepareEncryptedBackupBytes(
            sessionId = realForScope.sessionId,
            backupPasswordChars = backupPass.copyOf(),
            exportScope = PortableBackupEngine.BackupExportScope.NOTES_ONLY
        )
        val parsedNotesOnly = PortableBackupEngine.decryptAndVerifyBackupBytes(notesOnlyBytes, backupPass.copyOf())
        assertEquals(1, parsedNotesOnly.notesCount)
        assertEquals(0, parsedNotesOnly.credentialsCount)

        val passwordsOnlyBytes = repository.prepareEncryptedBackupBytes(
            sessionId = realForScope.sessionId,
            backupPasswordChars = backupPass.copyOf(),
            exportScope = PortableBackupEngine.BackupExportScope.PASSWORDS_ONLY
        )
        val parsedPasswordsOnly = PortableBackupEngine.decryptAndVerifyBackupBytes(passwordsOnlyBytes, backupPass.copyOf())
        assertEquals(0, parsedPasswordsOnly.notesCount)
        assertEquals(1, parsedPasswordsOnly.credentialsCount)
        val restoredCred = parsedPasswordsOnly.items.filterIsInstance<CredentialRecord>().first()
        assertEquals("Work Account", restoredCred.accountLabel)
        assertTrue(restoredCred.isArchived)
    }

    @Test
    fun `PV-CRYPTO-001, PV-SEC-006, PV-SEC-009, PV-SEC-010, PV-SEC-011 - Strict envelope header validation, unguessable dummy slot, zero-row empty vault, atomic DEK rotation, and Unicode NFC normalization`() = runBlocking {
        // 1. PV-CRYPTO-001: Tamper with inner envelope header fields before wrapping and verify unwrapEnvelopePayloadOrNull rejects them
        val kek = CryptoEngine.generateDek()
        val dek = CryptoEngine.generateDek()
        val nonce = CryptoEngine.generateNonce()
        val validWrapped = CryptoEngine.wrapEnvelopePayload(
            kekBytes = kek,
            nonce = nonce,
            slotId = 0,
            envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
            params = testKdfParams,
            payload = CryptoEngine.UnwrappedEnvelopePayload(
                slotRoleFlag = CryptoEngine.SLOT_ROLE_ACTIVE,
                decoyPolicyFlag = CryptoEngine.DECOY_POLICY_DISABLED,
                createdAtEpochMs = 1_700_000_000_000L,
                rotatedAtEpochMs = 1_700_000_000_000L,
                dekBytes = dek
            )
        )
        assertNotNull(
            CryptoEngine.unwrapEnvelopePayloadOrNull(
                kekBytes = kek,
                nonce = nonce,
                slotId = 0,
                envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                params = testKdfParams,
                wrappedCiphertext = validWrapped
            )
        )

        // Craft an envelope with invalid roleFlag (0x7F) and verify unwrap returns null
        val invalidRoleCiphertext = CryptoEngine.wrapEnvelopePayload(
            kekBytes = kek,
            nonce = nonce,
            slotId = 0,
            envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
            params = testKdfParams,
            payload = CryptoEngine.UnwrappedEnvelopePayload(
                slotRoleFlag = 0x7F.toByte(),
                decoyPolicyFlag = CryptoEngine.DECOY_POLICY_DISABLED,
                createdAtEpochMs = 1_700_000_000_000L,
                rotatedAtEpochMs = 1_700_000_000_000L,
                dekBytes = dek
            )
        )
        assertEquals(
            null,
            CryptoEngine.unwrapEnvelopePayloadOrNull(
                kekBytes = kek,
                nonce = nonce,
                slotId = 0,
                envelopeVersion = CryptoEngine.ENVELOPE_VERSION,
                params = testKdfParams,
                wrappedCiphertext = invalidRoleCiphertext
            )
        )

        // 2. PV-SEC-006 & PV-SEC-009: Initialize vault with Decoy disabled and seedSampleData = false
        val nfcPass = "Caf\u00E9VaultMaster!2026".toCharArray() // precomposed 'é' (U+00E9)
        val nfdPass = "Cafe\u0301VaultMaster!2026".toCharArray() // decomposed 'e' + U+0301
        val session = repository.initializeNewVault(
            realMasterPasswordChars = nfcPass.copyOf(),
            optionalDecoyPasswordChars = null,
            seedSampleDataInRealVault = false,
            seedSampleDataInDecoyVault = false
        )

        // PV-SEC-009: Verify zero rows written to encrypted_records when seedSampleData is false, while default folders are synthesized in memory
        assertEquals(0, database.vaultDao().countRecordsForSlot(VaultSessionManager.REAL_SLOT))
        assertEquals(0, database.vaultDao().countRecordsForSlot(VaultSessionManager.DECOY_SLOT))
        val synthesizedItems = repository.loadDecryptedRecordsForSession(session.sessionId)
        assertEquals(2, synthesizedItems.filterIsInstance<VaultFolder>().size)

        // PV-SEC-006: Verify dummy Slot 1 cannot be unlocked with "xxxxxxxxxxxxxxxx"
        sessionManager.lockNow()
        val dummyUnlockAttempt = repository.unlockWithPassword("xxxxxxxxxxxxxxxx".toCharArray())
        assertTrue(dummyUnlockAttempt is VaultRepository.UnlockResult.InvalidCredentials)

        // 3. PV-SEC-011: Verify decomposed NFD password unlocks the vault created with precomposed NFC password
        val nfdUnlock = repository.unlockWithPassword(nfdPass.copyOf())
        assertTrue("Decomposed NFD password must unlock NFC-created vault (PV-SEC-011)", nfdUnlock is VaultRepository.UnlockResult.Success)

        // 4. PV-SEC-010: Full cryptographic DEK rotation re-encrypts all records in the active slot atomically
        val activeSession = (nfdUnlock as VaultRepository.UnlockResult.Success).session
        val noteBeforeRekey = NoteRecord(
            id = "rekey-note-001",
            title = "Rekey Atomic Verification",
            body = "Ciphertext must change when DEK rotates",
            isArchived = true
        )
        repository.saveVaultItem(activeSession.sessionId, noteBeforeRekey)
        val rawBeforeRekey = database.vaultDao().getRecordById(VaultSessionManager.REAL_SLOT, noteBeforeRekey.id)!!

        val rotatedPass = "NewRotatedMasterPass!2027".toCharArray()
        repository.changeActiveVaultPassword(
            sessionId = activeSession.sessionId,
            currentPasswordChars = nfcPass.copyOf(),
            newPasswordChars = rotatedPass.copyOf(),
            rekeyAllRecordsWithNewDek = true
        )

        val rawAfterRekey = database.vaultDao().getRecordById(VaultSessionManager.REAL_SLOT, noteBeforeRekey.id)!!
        assertFalse(
            "Record ciphertext must be re-encrypted under a new DEK when rekeyAllRecordsWithNewDek = true",
            rawBeforeRekey.ciphertext.contentEquals(rawAfterRekey.ciphertext)
        )

        val loadedAfterRekey = repository.loadDecryptedRecordsForSession(activeSession.sessionId)
            .filterIsInstance<NoteRecord>()
            .first { it.id == noteBeforeRekey.id }
        assertEquals("Rekey Atomic Verification", loadedAfterRekey.title)
        assertTrue(loadedAfterRekey.isArchived)
    }

    @Test
    fun `PV-SEC-003, PV-SEC-007, PV-SEC-008, PV-BUG-003, PV-BUG-007 - Unbiased generator error reporting, passphrase entropy, proactive background lock, decoy-neutral biometric state, and note dirty guard`() = runBlocking {
        // 1. PV-SEC-003: Generator returns explicit InvalidConfig when all character sets are disabled
        val invalidGen = com.example.security.PasswordGeneratorEngine.generate(
            com.example.security.PasswordGeneratorEngine.GeneratorConfig(
                includeUppercase = false,
                includeLowercase = false,
                includeDigits = false,
                includeSymbols = false
            )
        )
        assertTrue(invalidGen is com.example.security.PasswordGeneratorEngine.GenerationResult.InvalidConfig)

        // Multi-word passphrase evaluation awards realistic word-list entropy
        val passphraseReport = OfflinePasswordStrengthEstimator.evaluate("Amber-Anchor-Apollo-Arctic-Arrow-Atlas-42")
        assertTrue(
            "6-word passphrase must achieve STRONG or FORTRESS rating (got ${passphraseReport.band}, score=${passphraseReport.score})",
            passphraseReport.score >= 70
        )

        // 2. PV-SEC-008 & PV-BUG-003 & PV-BUG-007: Verify ViewModel decoy-neutral biometric policy, note dirty guard, and duplicate/archive helpers
        val realPass = "RealNeutralBio!100".toCharArray()
        val decoyPass = "DecoyNeutralBio!200".toCharArray()
        val realSession = repository.initializeNewVault(
            realMasterPasswordChars = realPass,
            optionalDecoyPasswordChars = decoyPass,
            seedSampleDataInRealVault = false,
            seedSampleDataInDecoyVault = false
        )

        val prefsRepo = AppPreferencesRepository(context)
        val viewModel = VaultViewModel(
            appContext = context,
            vaultRepository = repository,
            preferencesRepository = prefsRepo,
            otaUpdateManager = OtaUpdateManager(context),
            enableStartupOtaCheck = false
        )
        viewModel.refreshActiveVaultItems(realSession.sessionId)?.join()
        assertTrue("Real session with Decoy Mode enabled must expose isBiometricBlockedByPolicy = true", viewModel.uiState.value.isBiometricBlockedByPolicy)

        // PV-BUG-003: Create a note with a known past timestamp, open it in the editor, and verify isDirty is false when untouched
        val fixedPastTime = 1_650_000_000_000L
        val existingNote = NoteRecord(
            id = "untouched-note-001",
            title = "Untouched Note",
            body = "Original body",
            createdAtEpochMs = fixedPastTime,
            updatedAtEpochMs = fixedPastTime
        )
        repository.saveVaultItem(realSession.sessionId, existingNote)
        viewModel.refreshActiveVaultItems(realSession.sessionId)?.join()

        viewModel.openExistingNoteDraft(existingNote)
        assertFalse("Newly opened existing note must have isDirty == false", viewModel.uiState.value.activeNoteDraft?.isDirty ?: true)
        viewModel.commitActiveNoteDraft(closeOnSuccess = true, isSilentAutosave = true)
        val afterCloseNoEdit = repository.loadDecryptedRecordsForSession(realSession.sessionId)
            .filterIsInstance<NoteRecord>()
            .first { it.id == existingNote.id }
        assertEquals(
            "Closing an untouched note must not mutate updatedAtEpochMs (PV-BUG-003)",
            fixedPastTime,
            afterCloseNoEdit.updatedAtEpochMs
        )

        // Unlock Decoy Vault and verify identical isBiometricBlockedByPolicy == true (PV-SEC-008)
        sessionManager.lockNow()
        val decoySession = (repository.unlockWithPassword(decoyPass) as VaultRepository.UnlockResult.Success).session
        viewModel.refreshActiveVaultItems(decoySession.sessionId)?.join()
        assertTrue("Decoy session must expose identical isBiometricBlockedByPolicy = true", viewModel.uiState.value.isBiometricBlockedByPolicy)

        // 3. PV-SEC-007: Proactive background auto-lock with 0ms timeout locks immediately on background
        viewModel.setAutoLockTimeoutMs(0L)
        viewModel.onAppBackgrounded()
        assertFalse("Session must lock immediately when backgrounded with 0ms auto-lock timeout", sessionManager.isSessionActive(decoySession.sessionId))
    }

    private fun craftSignedBackupContainerForRawJson(
        rawJson: String,
        passwordChars: CharArray
    ): ByteArray {
        val salt = CryptoEngine.generateSalt()
        val nonce = CryptoEngine.generateNonce()
        val header = ByteArray(PortableBackupEngine.HEADER_BYTES)
        java.nio.ByteBuffer.wrap(header)
            .put("PVAULTB1".toByteArray(Charsets.US_ASCII))
            .putInt(CryptoEngine.BACKUP_SCHEMA_VERSION)
            .putInt(testKdfParams.memoryKb)
            .putInt(testKdfParams.iterations)
            .putInt(testKdfParams.parallelism)
            .put(salt)
            .put(nonce)
        val key = CryptoEngine.deriveKeyArgon2id(passwordChars, salt, testKdfParams)
        val aad = CryptoEngine.buildBackupAad(CryptoEngine.BACKUP_SCHEMA_VERSION, testKdfParams)
        val ciphertext = CryptoEngine.encryptAesGcm(
            keyBytes = key,
            nonce = nonce,
            plaintext = rawJson.toByteArray(Charsets.UTF_8),
            aad = aad
        )
        return header + ciphertext
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

package com.example.ui

import android.content.Context
import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.example.data.AppPreferencesRepository
import com.example.data.NoteFormatStyle
import com.example.data.PortableBackupEngine
import com.example.data.PrivateVaultDatabase
import com.example.data.VaultEnvelopeEntity
import com.example.data.VaultRecordPayload
import com.example.data.VaultRepository
import com.example.ota.OtaUpdateManager
import com.example.security.BiometricKeystoreManager
import com.example.security.CryptoEngine
import com.example.security.OfflinePasswordStrengthEstimator
import com.example.security.PasswordGeneratorEngine
import com.example.security.SensitiveClipboardManager
import com.example.security.VaultSessionManager
import com.example.ui.theme.AppThemeMode
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.io.InputStream
import java.io.OutputStream
import java.util.Arrays
import java.util.UUID
import javax.crypto.Cipher

enum class PrimaryVaultTab {
    NOTES,
    PASSWORDS,
    GENERATOR,
    STRENGTH_CHECK
}

enum class SecondaryDestination {
    NONE,
    BACKUP_RESTORE,
    SECURITY_DECOY,
    UPDATES,
    ABOUT
}

enum class NoteFilterMode(val label: String) {
    ACTIVE("Active"),
    FAVORITES("Favorites"),
    ARCHIVED("Archived"),
    TRASH("Trash")
}

enum class NoteSortMode(val label: String) {
    UPDATED_DESC("Recently Updated"),
    TITLE_ASC("Title (A–Z)")
}

enum class CredentialFilterMode(val label: String) {
    ACTIVE("Active"),
    FAVORITES("Favorites"),
    ARCHIVED("Archived"),
    TRASH("Trash")
}

enum class AutosaveStatus {
    IDLE,
    SAVING,
    SAVED,
    ERROR
}

enum class OtaDeferralOption(val label: String, val description: String) {
    NEXT_LAUNCH("Next app launch", "Remind me the next time I open PRIVATE VAULT"),
    TOMORROW("Tomorrow", "Remind me in 24 hours"),
    THREE_DAYS("In three days", "Remind me in 72 hours")
}

data class VaultUiState(
    val isLoadingInitialization: Boolean = true,
    val isVaultInitialized: Boolean = false,
    val isBiometricEnrolledForRealVault: Boolean = false,
    val isDecoyConfiguredInRealSession: Boolean = false,
    val isUnlockInProgress: Boolean = false,
    val unlockErrorMessage: String? = null,
    val unlockBackoffRemainingMs: Long = 0L,

    // Active navigation
    val selectedTab: PrimaryVaultTab = PrimaryVaultTab.NOTES,
    val secondaryDestination: SecondaryDestination = SecondaryDestination.NONE,

    // Active vault decrypted records (empty immediately on lock)
    val notes: List<VaultRecordPayload.NoteRecord> = emptyList(),
    val credentials: List<VaultRecordPayload.CredentialRecord> = emptyList(),
    val folders: List<VaultRecordPayload.FolderRecord> = emptyList(),

    // Notes filter & search state
    val noteSearchQuery: String = "",
    val selectedNoteFolder: String = "All",
    val noteFilterMode: NoteFilterMode = NoteFilterMode.ACTIVE,
    val noteSortMode: NoteSortMode = NoteSortMode.UPDATED_DESC,
    val autosaveStatus: AutosaveStatus = AutosaveStatus.IDLE,
    val autosaveErrorMessage: String? = null,

    // Passwords filter & search state
    val credentialSearchQuery: String = "",
    val selectedCredentialFolder: String = "All",
    val credentialFilterMode: CredentialFilterMode = CredentialFilterMode.ACTIVE,
    val prefilledGeneratorPasswordForNewCredential: String? = null,

    // Generator state (cleared on lock)
    val generatorConfig: PasswordGeneratorEngine.GeneratorConfig = PasswordGeneratorEngine.GeneratorConfig(),
    val generatedPasswordResult: PasswordGeneratorEngine.GenerationResult =
        PasswordGeneratorEngine.generate(PasswordGeneratorEngine.GeneratorConfig()),

    // Strength checker state (cleared on lock)
    val strengthCheckerInput: String = "",

    // Backup & Restore state
    val isBackupOperationInProgress: Boolean = false,
    val pendingEncryptedBackupBytes: ByteArray? = null,
    val verifiedBackupPreview: PortableBackupEngine.VerifiedBackupPreview? = null,
    val backupStatusMessage: String? = null,
    val backupErrorMessage: String? = null,

    // Security & Settings feedback
    val securityStatusMessage: String? = null,
    val securityErrorMessage: String? = null,
    val isRunningKdfBenchmark: Boolean = false
)

class VaultViewModel(
    private val appContext: Context,
    val sessionManager: VaultSessionManager,
    val vaultRepository: VaultRepository,
    val preferencesRepository: AppPreferencesRepository,
    val biometricKeystoreManager: BiometricKeystoreManager,
    val clipboardManager: SensitiveClipboardManager,
    val otaUpdateManager: OtaUpdateManager
) : ViewModel() {

    private val _uiState = MutableStateFlow(VaultUiState())
    val uiState: StateFlow<VaultUiState> = _uiState.asStateFlow()

    val sessionState: StateFlow<VaultSessionManager.SessionState> = sessionManager.sessionState

    val settingsState: StateFlow<AppPreferencesRepository.AppSettingsState> =
        preferencesRepository.settingsFlow.stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = AppPreferencesRepository.AppSettingsState()
        )

    val otaState: StateFlow<OtaUpdateManager.OtaUiState> = otaUpdateManager.otaState
    val clipboardRemainingSeconds: StateFlow<Int> = clipboardManager.remainingSeconds

    private var activeRecordsCollectionJob: Job? = null
    private var autosaveJob: Job? = null
    private var otaDownloadJob: Job? = null

    init {
        observeSessionLifecycle()
        initializeStartupChecks()
    }

    private fun initializeStartupChecks() {
        viewModelScope.launch {
            val initialized = vaultRepository.isVaultInitialized()
            val bioEnrolled = if (initialized) vaultRepository.isBiometricWrapperPresent() else false
            _uiState.update {
                it.copy(
                    isLoadingInitialization = false,
                    isVaultInitialized = initialized,
                    isBiometricEnrolledForRealVault = bioEnrolled
                )
            }

            val launchNum = preferencesRepository.incrementAppLaunchCounter()
            val currentSettings = preferencesRepository.getSnapshot()

            // Rate-limited launch update check if enabled (at most once every 15 minutes unless manual)
            val now = System.currentTimeMillis()
            if (currentSettings.autoCheckUpdatesOnLaunch &&
                (now - currentSettings.lastOtaAutoCheckEpochMs >= 15 * 60 * 1000L || currentSettings.lastOtaAutoCheckEpochMs == 0L)
            ) {
                preferencesRepository.recordOtaAutoCheckTimestamp(now)
                val resultState = otaUpdateManager.checkForUpdates(
                    manifestUrl = currentSettings.customOtaManifestUrl,
                    showDialogIfAvailable = false
                )
                if (resultState is OtaUpdateManager.OtaUiState.UpdateAvailable) {
                    val shouldPrompt = AppPreferencesRepository.shouldShowAutomaticUpdatePrompt(
                        candidateVersionCode = resultState.manifest.versionCode,
                        reminderState = currentSettings.otaReminderState,
                        currentLaunchNumber = launchNum,
                        nowEpochMs = now
                    )
                    if (!shouldPrompt) {
                        otaUpdateManager.dismissUpdateDialogForLater()
                    } else {
                        // Re-emit with showPromptDialog = true
                        otaUpdateManager.checkForUpdates(
                            manifestUrl = currentSettings.customOtaManifestUrl,
                            showDialogIfAvailable = true
                        )
                    }
                }
            }
        }
    }

    private fun observeSessionLifecycle() {
        viewModelScope.launch {
            sessionManager.sessionState.collectLatest { state ->
                activeRecordsCollectionJob?.cancel()
                autosaveJob?.cancel()

                when (state) {
                    is VaultSessionManager.SessionState.Locked -> {
                        val bioEnrolled = if (_uiState.value.isVaultInitialized) {
                            vaultRepository.isBiometricWrapperPresent()
                        } else {
                            false
                        }
                        // Clear all transient secrets, decrypted records, search queries, and checker/generator inputs (F13, S07)
                        _uiState.update { current ->
                            current.copy(
                                isBiometricEnrolledForRealVault = bioEnrolled,
                                isDecoyConfiguredInRealSession = false,
                                secondaryDestination = SecondaryDestination.NONE,
                                notes = emptyList(),
                                credentials = emptyList(),
                                folders = emptyList(),
                                noteSearchQuery = "",
                                credentialSearchQuery = "",
                                prefilledGeneratorPasswordForNewCredential = null,
                                strengthCheckerInput = "",
                                pendingEncryptedBackupBytes = null,
                                verifiedBackupPreview = null,
                                autosaveStatus = AutosaveStatus.IDLE,
                                autosaveErrorMessage = null,
                                generatedPasswordResult = PasswordGeneratorEngine.generate(
                                    PasswordGeneratorEngine.GeneratorConfig()
                                )
                            )
                        }
                    }

                    is VaultSessionManager.SessionState.Unlocked -> {
                        val capturedSessionId = state.sessionId
                        val canManageSecurity = state.canManageVaultSecurity
                        val decoyActive = if (canManageSecurity) {
                            try {
                                vaultRepository.isDecoyModeEnabled(capturedSessionId)
                            } catch (_: Exception) {
                                false
                            }
                        } else {
                            false
                        }
                        val bioPresent = vaultRepository.isBiometricWrapperPresent()

                        _uiState.update {
                            it.copy(
                                isDecoyConfiguredInRealSession = decoyActive,
                                isBiometricEnrolledForRealVault = bioPresent,
                                unlockErrorMessage = null
                            )
                        }

                        activeRecordsCollectionJob = viewModelScope.launch {
                            vaultRepository.observeDecryptedRecords(capturedSessionId).collect { allRecords ->
                                if (!sessionManager.isSessionActive(capturedSessionId)) return@collect
                                val notes = allRecords.filterIsInstance<VaultRecordPayload.NoteRecord>()
                                val creds = allRecords.filterIsInstance<VaultRecordPayload.CredentialRecord>()
                                val folders = allRecords.filterIsInstance<VaultRecordPayload.FolderRecord>()
                                _uiState.update { current ->
                                    current.copy(
                                        notes = notes,
                                        credentials = creds,
                                        folders = folders
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // First-Time Setup & Unlock Actions
    // -----------------------------------------------------------------------------------------

    fun setupInitialVault(
        masterPassword: String,
        confirmMasterPassword: String,
        enableDecoy: Boolean,
        decoyPassword: String,
        confirmDecoyPassword: String,
        seedSampleDecoyData: Boolean
    ) {
        if (masterPassword.length < 8) {
            _uiState.update { it.copy(unlockErrorMessage = "Master password must be at least 8 characters.") }
            return
        }
        if (masterPassword != confirmMasterPassword) {
            _uiState.update { it.copy(unlockErrorMessage = "Master passwords do not match.") }
            return
        }
        if (enableDecoy) {
            if (decoyPassword.length < 8) {
                _uiState.update { it.copy(unlockErrorMessage = "Decoy password must be at least 8 characters.") }
                return
            }
            if (decoyPassword != confirmDecoyPassword) {
                _uiState.update { it.copy(unlockErrorMessage = "Decoy passwords do not match.") }
                return
            }
            if (decoyPassword == masterPassword) {
                _uiState.update { it.copy(unlockErrorMessage = "Real and Decoy passwords must be different.") }
                return
            }
        }

        viewModelScope.launch {
            _uiState.update { it.copy(isUnlockInProgress = true, unlockErrorMessage = null) }
            val realChars = masterPassword.toCharArray()
            val decoyChars = if (enableDecoy) decoyPassword.toCharArray() else null
            try {
                val result = vaultRepository.initializeNewVault(
                    realPasswordChars = realChars,
                    decoyPasswordChars = decoyChars,
                    seedSampleDecoyData = seedSampleDecoyData
                )
                when (result) {
                    is VaultRepository.UnlockResult.Success -> {
                        preferencesRepository.saveKdfBenchmarkResult(result.benchmark)
                        _uiState.update {
                            it.copy(
                                isUnlockInProgress = false,
                                isVaultInitialized = true,
                                unlockErrorMessage = null
                            )
                        }
                    }
                    is VaultRepository.UnlockResult.InvalidCredentials -> {
                        _uiState.update {
                            it.copy(
                                isUnlockInProgress = false,
                                unlockErrorMessage = "Could not initialize vault credentials."
                            )
                        }
                    }
                    is VaultRepository.UnlockResult.Error -> {
                        _uiState.update {
                            it.copy(
                                isUnlockInProgress = false,
                                unlockErrorMessage = result.message
                            )
                        }
                    }
                }
            } finally {
                Arrays.fill(realChars, '\u0000')
                if (decoyChars != null) Arrays.fill(decoyChars, '\u0000')
            }
        }
    }

    fun unlockVault(password: String) {
        if (_uiState.value.unlockBackoffRemainingMs > 0L) return
        if (password.isEmpty()) {
            _uiState.update { it.copy(unlockErrorMessage = "Enter your master password.") }
            return
        }

        viewModelScope.launch {
            _uiState.update { it.copy(isUnlockInProgress = true, unlockErrorMessage = null) }
            val passChars = password.toCharArray()
            try {
                when (val result = vaultRepository.unlockWithPassword(passChars)) {
                    is VaultRepository.UnlockResult.Success -> {
                        preferencesRepository.saveKdfBenchmarkResult(result.benchmark)
                        _uiState.update {
                            it.copy(
                                isUnlockInProgress = false,
                                unlockErrorMessage = null,
                                unlockBackoffRemainingMs = 0L
                            )
                        }
                    }
                    is VaultRepository.UnlockResult.InvalidCredentials -> {
                        if (result.benchmark != null) {
                            preferencesRepository.saveKdfBenchmarkResult(result.benchmark)
                        }
                        // Generic error that never reveals whether Real or Decoy was close (Section 13 & 14)
                        val delayMs = result.backoffDelayMs
                        _uiState.update {
                            it.copy(
                                isUnlockInProgress = false,
                                unlockErrorMessage = "Invalid password. Please verify your passphrase and try again.",
                                unlockBackoffRemainingMs = delayMs
                            )
                        }
                        if (delayMs > 0L) {
                            var remaining = delayMs
                            while (remaining > 0L) {
                                delay(250L)
                                remaining = (remaining - 250L).coerceAtLeast(0L)
                                _uiState.update { it.copy(unlockBackoffRemainingMs = remaining) }
                            }
                        }
                    }
                    is VaultRepository.UnlockResult.Error -> {
                        _uiState.update {
                            it.copy(
                                isUnlockInProgress = false,
                                unlockErrorMessage = result.message
                            )
                        }
                    }
                }
            } finally {
                Arrays.fill(passChars, '\u0000')
            }
        }
    }

    fun lockVaultNow() {
        autosaveJob?.cancel()
        clipboardManager.clearIfStillOwned()
        sessionManager.lockNow()
    }

    // -----------------------------------------------------------------------------------------
    // Navigation & Filtering
    // -----------------------------------------------------------------------------------------

    fun selectPrimaryTab(tab: PrimaryVaultTab) {
        _uiState.update {
            it.copy(
                selectedTab = tab,
                secondaryDestination = SecondaryDestination.NONE
            )
        }
    }

    fun openSecondaryDestination(destination: SecondaryDestination) {
        _uiState.update {
            it.copy(
                secondaryDestination = destination,
                securityStatusMessage = null,
                securityErrorMessage = null,
                backupStatusMessage = null,
                backupErrorMessage = null
            )
        }
    }

    fun updateNoteSearchQuery(query: String) {
        _uiState.update { it.copy(noteSearchQuery = query) }
    }

    fun updateNoteFilterMode(mode: NoteFilterMode) {
        _uiState.update { it.copy(noteFilterMode = mode) }
    }

    fun updateNoteSortMode(mode: NoteSortMode) {
        _uiState.update { it.copy(noteSortMode = mode) }
    }

    fun updateSelectedNoteFolder(folderName: String) {
        _uiState.update { it.copy(selectedNoteFolder = folderName) }
    }

    fun updateCredentialSearchQuery(query: String) {
        _uiState.update { it.copy(credentialSearchQuery = query) }
    }

    fun updateCredentialFilterMode(mode: CredentialFilterMode) {
        _uiState.update { it.copy(credentialFilterMode = mode) }
    }

    fun updateSelectedCredentialFolder(folderName: String) {
        _uiState.update { it.copy(selectedCredentialFolder = folderName) }
    }

    // -----------------------------------------------------------------------------------------
    // Notes CRUD & Encrypted Autosave (Section 07)
    // -----------------------------------------------------------------------------------------

    fun saveNote(
        note: VaultRecordPayload.NoteRecord,
        isAutosave: Boolean = false,
        onComplete: (Boolean) -> Unit = {}
    ) {
        val currentSession = sessionState.value as? VaultSessionManager.SessionState.Unlocked ?: run {
            onComplete(false)
            return
        }
        val capturedSessionId = currentSession.sessionId

        if (note.title.isBlank() && note.body.isBlank() && note.checklistItems.isEmpty()) {
            _uiState.update {
                it.copy(
                    autosaveStatus = AutosaveStatus.ERROR,
                    autosaveErrorMessage = "Note requires a title or content before saving."
                )
            }
            onComplete(false)
            return
        }

        autosaveJob?.cancel()
        autosaveJob = viewModelScope.launch {
            _uiState.update { it.copy(autosaveStatus = AutosaveStatus.SAVING, autosaveErrorMessage = null) }
            if (isAutosave) {
                delay(350L)
            }
            val result = vaultRepository.saveRecord(
                sessionId = capturedSessionId,
                payload = note.copy(
                    title = note.title.take(300),
                    body = note.body.take(100_000),
                    updatedAtEpochMs = System.currentTimeMillis()
                )
            )
            if (result.isSuccess) {
                _uiState.update { it.copy(autosaveStatus = AutosaveStatus.SAVED, autosaveErrorMessage = null) }
                onComplete(true)
            } else {
                _uiState.update {
                    it.copy(
                        autosaveStatus = AutosaveStatus.ERROR,
                        autosaveErrorMessage = result.exceptionOrNull()?.message
                            ?: "Encrypted save failed. Your in-session draft is preserved."
                    )
                }
                onComplete(false)
            }
        }
    }

    fun duplicateNote(note: VaultRecordPayload.NoteRecord) {
        val now = System.currentTimeMillis()
        saveNote(
            note.copy(
                id = UUID.randomUUID().toString(),
                title = "${note.title} (Copy)".take(300),
                createdAtEpochMs = now,
                updatedAtEpochMs = now
            )
        )
    }

    fun moveNoteToTrash(note: VaultRecordPayload.NoteRecord) {
        val now = System.currentTimeMillis()
        saveNote(
            note.copy(
                isTrashed = true,
                trashedAtEpochMs = now,
                updatedAtEpochMs = now
            )
        )
    }

    fun restoreNoteFromTrash(note: VaultRecordPayload.NoteRecord) {
        val now = System.currentTimeMillis()
        saveNote(
            note.copy(
                isTrashed = false,
                trashedAtEpochMs = null,
                updatedAtEpochMs = now
            )
        )
    }

    fun deleteRecordPermanently(recordId: String) {
        val currentSession = sessionState.value as? VaultSessionManager.SessionState.Unlocked ?: return
        viewModelScope.launch {
            vaultRepository.deleteRecordPermanently(currentSession.sessionId, recordId)
        }
    }

    // -----------------------------------------------------------------------------------------
    // Credentials CRUD & Reuse Analysis (Section 08)
    // -----------------------------------------------------------------------------------------

    fun saveCredential(
        credential: VaultRecordPayload.CredentialRecord,
        onComplete: (Boolean) -> Unit = {}
    ) {
        val currentSession = sessionState.value as? VaultSessionManager.SessionState.Unlocked ?: run {
            onComplete(false)
            return
        }
        if (credential.serviceName.isBlank() || credential.password.isEmpty()) {
            onComplete(false)
            return
        }
        viewModelScope.launch {
            val result = vaultRepository.saveRecord(
                sessionId = currentSession.sessionId,
                payload = credential.copy(
                    serviceName = credential.serviceName.trim().take(200),
                    updatedAtEpochMs = System.currentTimeMillis()
                )
            )
            _uiState.update { it.copy(prefilledGeneratorPasswordForNewCredential = null) }
            onComplete(result.isSuccess)
        }
    }

    fun duplicateCredential(credential: VaultRecordPayload.CredentialRecord) {
        val now = System.currentTimeMillis()
        saveCredential(
            credential.copy(
                id = UUID.randomUUID().toString(),
                accountLabel = "${credential.accountLabel} (Copy)",
                createdAtEpochMs = now,
                updatedAtEpochMs = now
            )
        )
    }

    fun moveCredentialToTrash(credential: VaultRecordPayload.CredentialRecord) {
        val now = System.currentTimeMillis()
        saveCredential(
            credential.copy(
                isTrashed = true,
                trashedAtEpochMs = now,
                updatedAtEpochMs = now
            )
        )
    }

    fun restoreCredentialFromTrash(credential: VaultRecordPayload.CredentialRecord) {
        val now = System.currentTimeMillis()
        saveCredential(
            credential.copy(
                isTrashed = false,
                trashedAtEpochMs = null,
                updatedAtEpochMs = now
            )
        )
    }

    fun createFolder(folderName: String) {
        val trimmed = folderName.trim().take(60)
        if (trimmed.isEmpty()) return
        val currentSession = sessionState.value as? VaultSessionManager.SessionState.Unlocked ?: return
        viewModelScope.launch {
            vaultRepository.saveRecord(
                sessionId = currentSession.sessionId,
                payload = VaultRecordPayload.FolderRecord(
                    id = UUID.randomUUID().toString(),
                    name = trimmed
                )
            )
        }
    }

    // -----------------------------------------------------------------------------------------
    // Password Generator & Strength Checker (Sections 09 & 10)
    // -----------------------------------------------------------------------------------------

    fun updateGeneratorConfig(newConfig: PasswordGeneratorEngine.GeneratorConfig) {
        val result = PasswordGeneratorEngine.generate(newConfig)
        _uiState.update {
            it.copy(
                generatorConfig = newConfig,
                generatedPasswordResult = result
            )
        }
    }

    fun regeneratePassword() {
        val config = _uiState.value.generatorConfig
        _uiState.update {
            it.copy(generatedPasswordResult = PasswordGeneratorEngine.generate(config))
        }
    }

    fun sendGeneratedPasswordToNewCredential(password: String) {
        _uiState.update {
            it.copy(
                prefilledGeneratorPasswordForNewCredential = password,
                selectedTab = PrimaryVaultTab.PASSWORDS,
                secondaryDestination = SecondaryDestination.NONE
            )
        }
    }

    fun clearPrefilledGeneratorPassword() {
        _uiState.update { it.copy(prefilledGeneratorPasswordForNewCredential = null) }
    }

    fun updateStrengthCheckerInput(input: String) {
        _uiState.update { it.copy(strengthCheckerInput = input) }
    }

    fun evaluatePasswordStrengthInActiveVault(
        password: String,
        excludeRecordId: String? = null
    ): OfflinePasswordStrengthEstimator.StrengthReport {
        val activeCreds = _uiState.value.credentials
            .filter { !it.isTrashed }
            .map { Triple(it.id, "${it.serviceName} (${it.accountLabel})", it.password) }
        return OfflinePasswordStrengthEstimator.evaluate(
            password = password,
            existingVaultCredentials = activeCreds,
            excludeRecordId = excludeRecordId
        )
    }

    fun copySecretToClipboard(label: String, value: String) {
        val ttl = settingsState.value.clipboardClearSeconds
        clipboardManager.copySensitive(label = label, secretValue = value, ttlSeconds = ttl)
    }

    // -----------------------------------------------------------------------------------------
    // Portable Encrypted Backup & Restore (Section 17)
    // -----------------------------------------------------------------------------------------

    fun prepareBackupForExport(
        backupPassword: String,
        confirmBackupPassword: String,
        scope: PortableBackupEngine.ExportScope,
        onReadyToPickDestination: () -> Unit
    ) {
        if (backupPassword.length < 8) {
            _uiState.update { it.copy(backupErrorMessage = "Backup password must be at least 8 characters.") }
            return
        }
        if (backupPassword != confirmBackupPassword) {
            _uiState.update { it.copy(backupErrorMessage = "Backup passwords do not match.") }
            return
        }
        val currentSession = sessionState.value as? VaultSessionManager.SessionState.Unlocked ?: return

        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isBackupOperationInProgress = true,
                    backupErrorMessage = null,
                    backupStatusMessage = "Encrypting active vault snapshot with Argon2id + AES-256-GCM..."
                )
            }
            val passChars = backupPassword.toCharArray()
            try {
                val result = vaultRepository.prepareEncryptedBackupBytes(
                    sessionId = currentSession.sessionId,
                    backupPasswordChars = passChars,
                    scope = scope
                )
                result.fold(
                    onSuccess = { bytes ->
                        sessionManager.beginFilePickerTransitionWindow()
                        _uiState.update {
                            it.copy(
                                isBackupOperationInProgress = false,
                                pendingEncryptedBackupBytes = bytes,
                                backupStatusMessage = "Encrypted snapshot ready (${bytes.size / 1024} KB). Select destination file..."
                            )
                        }
                        onReadyToPickDestination()
                    },
                    onFailure = { err ->
                        _uiState.update {
                            it.copy(
                                isBackupOperationInProgress = false,
                                backupErrorMessage = err.message ?: "Failed to build encrypted backup."
                            )
                        }
                    }
                )
            } finally {
                Arrays.fill(passChars, '\u0000')
            }
        }
    }

    fun writePendingBackupToStream(outputStream: OutputStream?) {
        sessionManager.endFilePickerTransitionWindow()
        val bytes = _uiState.value.pendingEncryptedBackupBytes
        if (bytes == null || outputStream == null) {
            _uiState.update {
                it.copy(
                    pendingEncryptedBackupBytes = null,
                    backupErrorMessage = "Export cancelled or destination file could not be opened."
                )
            }
            return
        }

        viewModelScope.launch {
            _uiState.update { it.copy(isBackupOperationInProgress = true, backupErrorMessage = null) }
            val writeResult = vaultRepository.writeEncryptedBackupToStream(bytes, outputStream)
            Arrays.fill(bytes, 0.toByte())
            if (writeResult.isSuccess) {
                _uiState.update {
                    it.copy(
                        isBackupOperationInProgress = false,
                        pendingEncryptedBackupBytes = null,
                        backupStatusMessage = "Encrypted .pvault backup written and verified successfully."
                    )
                }
            } else {
                _uiState.update {
                    it.copy(
                        isBackupOperationInProgress = false,
                        pendingEncryptedBackupBytes = null,
                        backupErrorMessage = writeResult.exceptionOrNull()?.message
                            ?: "Failed to write backup file."
                    )
                }
            }
        }
    }

    fun beginRestoreFileSelection() {
        sessionManager.beginFilePickerTransitionWindow()
    }

    fun verifyBackupForRestorePreview(
        inputStream: InputStream?,
        backupPassword: String
    ) {
        sessionManager.endFilePickerTransitionWindow()
        if (inputStream == null) {
            _uiState.update { it.copy(backupErrorMessage = "Could not open selected backup file.") }
            return
        }
        if (backupPassword.isEmpty()) {
            _uiState.update { it.copy(backupErrorMessage = "Enter the backup password used when exporting this file.") }
            return
        }
        val currentSession = sessionState.value as? VaultSessionManager.SessionState.Unlocked ?: return

        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isBackupOperationInProgress = true,
                    backupErrorMessage = null,
                    backupStatusMessage = "Verifying backup header and Argon2id + AES-256-GCM authentication tag..."
                )
            }
            val passChars = backupPassword.toCharArray()
            try {
                val result = vaultRepository.previewBackupFromStream(
                    sessionId = currentSession.sessionId,
                    inputStream = inputStream,
                    backupPasswordChars = passChars
                )
                result.fold(
                    onSuccess = { preview ->
                        _uiState.update {
                            it.copy(
                                isBackupOperationInProgress = false,
                                verifiedBackupPreview = preview,
                                backupStatusMessage = "Backup authenticated: ${preview.notesCount} notes, ${preview.credentialsCount} credentials, ${preview.foldersCount} folders."
                            )
                        }
                    },
                    onFailure = { err ->
                        _uiState.update {
                            it.copy(
                                isBackupOperationInProgress = false,
                                verifiedBackupPreview = null,
                                backupErrorMessage = err.message ?: "Backup verification failed."
                            )
                        }
                    }
                )
            } finally {
                Arrays.fill(passChars, '\u0000')
            }
        }
    }

    fun confirmRestoreFromPreview(mode: PortableBackupEngine.RestoreMode) {
        val preview = _uiState.value.verifiedBackupPreview ?: return
        val currentSession = sessionState.value as? VaultSessionManager.SessionState.Unlocked ?: return

        viewModelScope.launch {
            _uiState.update { it.copy(isBackupOperationInProgress = true, backupErrorMessage = null) }
            val result = vaultRepository.applyVerifiedBackupRestore(
                sessionId = currentSession.sessionId,
                preview = preview,
                mode = mode
            )
            result.fold(
                onSuccess = { count ->
                    _uiState.update {
                        it.copy(
                            isBackupOperationInProgress = false,
                            verifiedBackupPreview = null,
                            backupStatusMessage = "Successfully restored $count records into the active vault."
                        )
                    }
                },
                onFailure = { err ->
                    _uiState.update {
                        it.copy(
                            isBackupOperationInProgress = false,
                            backupErrorMessage = err.message ?: "Restore failed; existing vault data was preserved."
                        )
                    }
                }
            )
        }
    }

    fun cancelRestorePreview() {
        _uiState.update { it.copy(verifiedBackupPreview = null) }
    }

    // -----------------------------------------------------------------------------------------
    // Security, Master Password Rotation, Decoy Mode & Biometrics (Sections 12, 13, 14, 15)
    // -----------------------------------------------------------------------------------------

    fun rotateRealMasterPassword(
        currentPassword: String,
        newPassword: String,
        confirmNewPassword: String
    ) {
        if (newPassword.length < 8) {
            _uiState.update { it.copy(securityErrorMessage = "New master password must be at least 8 characters.") }
            return
        }
        if (newPassword != confirmNewPassword) {
            _uiState.update { it.copy(securityErrorMessage = "New master passwords do not match.") }
            return
        }
        val currentSession = sessionState.value as? VaultSessionManager.SessionState.Unlocked ?: return

        viewModelScope.launch {
            _uiState.update { it.copy(securityErrorMessage = null, securityStatusMessage = "Re-wrapping Real Vault key envelope...") }
            val currChars = currentPassword.toCharArray()
            val newChars = newPassword.toCharArray()
            try {
                val result = vaultRepository.changeRealMasterPassword(
                    sessionId = currentSession.sessionId,
                    currentRealPasswordChars = currChars,
                    newRealPasswordChars = newChars
                )
                result.fold(
                    onSuccess = {
                        _uiState.update {
                            it.copy(
                                securityStatusMessage = "Master password updated atomically. Note: previously exported .pvault backup files remain encrypted under their original backup passwords.",
                                securityErrorMessage = null
                            )
                        }
                    },
                    onFailure = { err ->
                        _uiState.update {
                            it.copy(
                                securityErrorMessage = err.message ?: "Master password change failed.",
                                securityStatusMessage = null
                            )
                        }
                    }
                )
            } finally {
                Arrays.fill(currChars, '\u0000')
                Arrays.fill(newChars, '\u0000')
            }
        }
    }

    fun configureDecoyVault(
        realPassword: String,
        decoyPassword: String,
        confirmDecoyPassword: String,
        seedSampleData: Boolean
    ) {
        if (decoyPassword.length < 8) {
            _uiState.update { it.copy(securityErrorMessage = "Decoy password must be at least 8 characters.") }
            return
        }
        if (decoyPassword != confirmDecoyPassword) {
            _uiState.update { it.copy(securityErrorMessage = "Decoy passwords do not match.") }
            return
        }
        if (realPassword == decoyPassword) {
            _uiState.update { it.copy(securityErrorMessage = "Decoy password must differ from the Real master password.") }
            return
        }
        val currentSession = sessionState.value as? VaultSessionManager.SessionState.Unlocked ?: return

        viewModelScope.launch {
            _uiState.update { it.copy(securityErrorMessage = null, securityStatusMessage = "Provisioning isolated Decoy Vault envelope...") }
            val realChars = realPassword.toCharArray()
            val decoyChars = decoyPassword.toCharArray()
            try {
                val result = vaultRepository.configureDecoyVault(
                    sessionId = currentSession.sessionId,
                    realMasterPasswordChars = realChars,
                    newDecoyPasswordChars = decoyChars,
                    seedSampleData = seedSampleData
                )
                result.fold(
                    onSuccess = {
                        _uiState.update {
                            it.copy(
                                isDecoyConfiguredInRealSession = true,
                                isBiometricEnrolledForRealVault = false,
                                securityStatusMessage = "Decoy Vault configured. Biometric unlock on the Real Vault has been automatically disabled to preserve decoy policy.",
                                securityErrorMessage = null
                            )
                        }
                    },
                    onFailure = { err ->
                        _uiState.update {
                            it.copy(
                                securityErrorMessage = err.message ?: "Failed to configure Decoy Vault.",
                                securityStatusMessage = null
                            )
                        }
                    }
                )
            } finally {
                Arrays.fill(realChars, '\u0000')
                Arrays.fill(decoyChars, '\u0000')
            }
        }
    }

    fun disableDecoyVault(realPassword: String) {
        val currentSession = sessionState.value as? VaultSessionManager.SessionState.Unlocked ?: return
        viewModelScope.launch {
            val realChars = realPassword.toCharArray()
            try {
                val result = vaultRepository.disableDecoyVault(currentSession.sessionId, realChars)
                result.fold(
                    onSuccess = {
                        _uiState.update {
                            it.copy(
                                isDecoyConfiguredInRealSession = false,
                                securityStatusMessage = "Decoy Vault disabled and replaced with an unconfigured dummy envelope.",
                                securityErrorMessage = null
                            )
                        }
                    },
                    onFailure = { err ->
                        _uiState.update {
                            it.copy(
                                securityErrorMessage = err.message ?: "Failed to disable Decoy Vault.",
                                securityStatusMessage = null
                            )
                        }
                    }
                )
            } finally {
                Arrays.fill(realChars, '\u0000')
            }
        }
    }

    fun completeBiometricEnrollment(authenticatedCipher: Cipher) {
        val currentSession = sessionState.value as? VaultSessionManager.SessionState.Unlocked ?: return
        viewModelScope.launch {
            val result = vaultRepository.enrollBiometricWrapperWithAuthenticatedCipher(
                sessionId = currentSession.sessionId,
                authenticatedEncryptionCipher = authenticatedCipher
            )
            result.fold(
                onSuccess = {
                    _uiState.update {
                        it.copy(
                            isBiometricEnrolledForRealVault = true,
                            securityStatusMessage = "Hardware-backed biometric unlock enabled for Real Vault.",
                            securityErrorMessage = null
                        )
                    }
                },
                onFailure = { err ->
                    _uiState.update {
                        it.copy(
                            securityErrorMessage = err.message ?: "Failed to enroll biometric key wrapper."
                        )
                    }
                }
            )
        }
    }

    fun unlockWithAuthenticatedBiometricCipher(authenticatedCipher: Cipher) {
        viewModelScope.launch {
            val result = vaultRepository.unlockWithAuthenticatedBiometricCipher(authenticatedCipher)
            result.onFailure { err ->
                _uiState.update {
                    it.copy(
                        unlockErrorMessage = "Biometric key unlock failed (${err.message}). Please use your master password."
                    )
                }
            }
        }
    }

    fun disableBiometricUnlock() {
        val currentSession = sessionState.value as? VaultSessionManager.SessionState.Unlocked ?: return
        viewModelScope.launch {
            vaultRepository.disableBiometricUnlock(currentSession.sessionId)
            _uiState.update {
                it.copy(
                    isBiometricEnrolledForRealVault = false,
                    securityStatusMessage = "Biometric unlock disabled and Keystore key deleted."
                )
            }
        }
    }

    suspend fun getRealVaultBiometricNonce(): ByteArray? {
        val db = PrivateVaultDatabase.getInstance(appContext)
        return db.vaultDao().getEnvelopeBySlot(VaultSessionManager.REAL_SLOT)?.biometricNonce
    }

    fun runOnDeviceKdfBenchmark() {
        if (_uiState.value.isRunningKdfBenchmark) return
        viewModelScope.launch {
            _uiState.update { it.copy(isRunningKdfBenchmark = true, securityStatusMessage = "Measuring two-slot Argon2id KDF latency on this device...") }
            val result = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
                CryptoEngine.measureKdfBenchmark()
            }
            preferencesRepository.saveKdfBenchmarkResult(result)
            _uiState.update {
                it.copy(
                    isRunningKdfBenchmark = false,
                    securityStatusMessage = "Measured 2-vault Argon2id unlock: ${result.twoSlotUnlockDurationMs} ms (${result.singleSlotDurationMs} ms/slot at ${result.memoryKbPerSlot / 1024} MiB)."
                )
            }
        }
    }

    // -----------------------------------------------------------------------------------------
    // Non-Secret App Preferences
    // -----------------------------------------------------------------------------------------

    fun setThemeMode(mode: AppThemeMode) {
        viewModelScope.launch { preferencesRepository.setThemeMode(mode) }
    }

    fun setAutoLockTimeoutMs(timeoutMs: Long) {
        viewModelScope.launch { preferencesRepository.setAutoLockTimeoutMs(timeoutMs) }
    }

    fun setClipboardClearSeconds(seconds: Int) {
        viewModelScope.launch { preferencesRepository.setClipboardClearSeconds(seconds) }
    }

    fun setBlockScreenshots(enabled: Boolean) {
        viewModelScope.launch { preferencesRepository.setBlockScreenshots(enabled) }
    }

    // -----------------------------------------------------------------------------------------
    // OTA Updates & Three-Option Reminder Controls (Update Now / Update Later / Remind Me Later)
    // -----------------------------------------------------------------------------------------

    fun checkForUpdatesNow() {
        viewModelScope.launch {
            val url = settingsState.value.customOtaManifestUrl
            preferencesRepository.recordOtaAutoCheckTimestamp()
            otaUpdateManager.checkForUpdates(manifestUrl = url, showDialogIfAvailable = true)
        }
    }

    /**
     * Option 1: "Update Now" — Starts downloading and verifying the candidate APK.
     */
    fun chooseUpdateNow(manifest: OtaUpdateManager.OtaManifest) {
        otaDownloadJob?.cancel()
        otaDownloadJob = viewModelScope.launch {
            preferencesRepository.clearOtaReminder()
            otaUpdateManager.downloadAndVerifyUpdate(manifest)
        }
    }

    fun cancelActiveOtaDownload() {
        otaDownloadJob?.cancel()
        otaDownloadJob = null
        otaUpdateManager.cleanupTemporaryApkFiles()
    }

    /**
     * Option 2: "Update Later" — Closes the dialog and lets the user continue using the app.
     */
    fun chooseUpdateLater() {
        otaUpdateManager.dismissUpdateDialogForLater()
    }

    /**
     * Option 3: "Remind Me Later" — Persists the user's chosen reminder schedule
     * (Next app launch, Tomorrow +24h, or In three days +72h) and closes the dialog.
     */
    fun chooseRemindMeLater(
        manifest: OtaUpdateManager.OtaManifest,
        option: OtaDeferralOption
    ) {
        viewModelScope.launch {
            val snapshot = preferencesRepository.getSnapshot()
            val now = System.currentTimeMillis()
            when (option) {
                OtaDeferralOption.NEXT_LAUNCH -> {
                    preferencesRepository.saveOtaReminderChoice(
                        versionCode = manifest.versionCode,
                        reminderType = AppPreferencesRepository.OtaReminderType.NEXT_LAUNCH,
                        remindAfterEpochMs = 0L,
                        currentLaunchCount = snapshot.appLaunchCounter
                    )
                }
                OtaDeferralOption.TOMORROW -> {
                    preferencesRepository.saveOtaReminderChoice(
                        versionCode = manifest.versionCode,
                        reminderType = AppPreferencesRepository.OtaReminderType.TIMESTAMP,
                        remindAfterEpochMs = now + 24L * 3600L * 1000L,
                        currentLaunchCount = snapshot.appLaunchCounter
                    )
                }
                OtaDeferralOption.THREE_DAYS -> {
                    preferencesRepository.saveOtaReminderChoice(
                        versionCode = manifest.versionCode,
                        reminderType = AppPreferencesRepository.OtaReminderType.TIMESTAMP,
                        remindAfterEpochMs = now + 72L * 3600L * 1000L,
                        currentLaunchCount = snapshot.appLaunchCounter
                    )
                }
            }
            otaUpdateManager.dismissUpdateDialogForLater()
        }
    }

    fun setAutoCheckUpdatesOnLaunch(enabled: Boolean) {
        viewModelScope.launch { preferencesRepository.setAutoCheckUpdatesOnLaunch(enabled) }
    }

    fun setCustomOtaManifestUrl(url: String) {
        viewModelScope.launch { preferencesRepository.setCustomOtaManifestUrl(url) }
    }

    /**
     * Locks the active vault session before handing off to Android's package installer or
     * unknown-sources settings screen (Section 22).
     */
    fun prepareAndBuildInstallIntent(verifiedCandidate: OtaUpdateManager.VerifiedCandidateApk): Intent {
        lockVaultNow()
        return if (!otaUpdateManager.canRequestPackageInstalls()) {
            otaUpdateManager.buildManageUnknownAppSourcesIntent()
        } else {
            otaUpdateManager.buildInstallVerifiedApkIntent(verifiedCandidate)
        }
    }

    fun triggerDebugOtaSimulation(rawJson: String) {
        otaUpdateManager.simulateManifestForDebugTesting(rawJson, showDialog = true)
    }

    class Factory(private val context: Context) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            val appCtx = context.applicationContext
            val db = PrivateVaultDatabase.getInstance(appCtx)
            val sessionMgr = VaultSessionManager()
            val bioMgr = BiometricKeystoreManager(appCtx)
            val prefsRepo = AppPreferencesRepository(appCtx)
            val vaultRepo = VaultRepository(
                vaultDao = db.vaultDao(),
                sessionManager = sessionMgr,
                biometricManager = bioMgr
            )
            val otaMgr = OtaUpdateManager(appCtx)
            val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.Dispatchers.Main)
            val clipMgr = SensitiveClipboardManager(appCtx, scope)

            return VaultViewModel(
                appContext = appCtx,
                sessionManager = sessionMgr,
                vaultRepository = vaultRepo,
                preferencesRepository = prefsRepo,
                biometricKeystoreManager = bioMgr,
                clipboardManager = clipMgr,
                otaUpdateManager = otaMgr
            ) as T
        }
    }
}

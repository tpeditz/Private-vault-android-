package com.example.ui

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
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
import com.example.data.ThemePreference
import com.example.data.VaultAppPreferences
import com.example.data.VaultFolder
import com.example.data.VaultItem
import com.example.data.VaultRepository
import com.example.ota.OtaUpdateManager
import com.example.security.CryptoEngine
import com.example.security.OfflinePasswordStrengthEstimator
import com.example.security.PasswordGeneratorEngine
import com.example.security.SensitiveClipboardManager
import com.example.security.VaultSessionManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.util.Arrays
import java.util.UUID
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher

enum class PrimaryTab {
    NOTES,
    PASSWORDS,
    TOOLS,
    SETTINGS,
    GENERATOR,
    STRENGTH_AUDIT
}

enum class ToolsSegment {
    GENERATOR,
    STRENGTH_CHECKER
}

enum class AutosaveIndicator {
    IDLE,
    UNSAVED,
    SAVING,
    SAVED,
    ERROR
}

enum class SecondaryDestination {
    NONE,
    BACKUP_RESTORE,
    SECURITY_SETTINGS,
    OTA_UPDATES,
    ABOUT_CREDITS
}

enum class SortOrder(val label: String) {
    UPDATED_DESC("Recently Updated"),
    CREATED_DESC("Newest Created"),
    ALPHABETICAL("Alphabetical (A–Z)")
}

data class NoteEditorDraftState(
    val noteId: String = UUID.randomUUID().toString(),
    val isEditingExisting: Boolean = false,
    val isDirty: Boolean = false,
    val autosaveIndicator: AutosaveIndicator = AutosaveIndicator.IDLE,
    val createdAtEpochMs: Long = System.currentTimeMillis(),
    val title: String = "",
    val body: String = "",
    val format: NoteBodyFormat = NoteBodyFormat.PLAIN_TEXT,
    val category: String = "Personal",
    val folderId: String = VaultFolder.DEFAULT_NOTE_FOLDER_ID,
    val folderName: String = VaultFolder.DEFAULT_FOLDER_NAME,
    val tagsText: String = "",
    val colorAccentIndex: Int = 0,
    val isPinned: Boolean = false,
    val isFavorite: Boolean = false,
    val isArchived: Boolean = false,
    val checklistItems: List<ChecklistEntry> = emptyList(),
    val pendingNewChecklistText: String = "",
    val showMarkdownPreview: Boolean = false,
    val editorError: String? = null
)

data class CredentialEditorDraftState(
    val credentialId: String = UUID.randomUUID().toString(),
    val isEditingExisting: Boolean = false,
    val createdAtEpochMs: Long = System.currentTimeMillis(),
    val serviceName: String = "",
    val accountLabel: String = "",
    val username: String = "",
    val password: String = "",
    val websiteUrl: String = "",
    val notes: String = "",
    val category: String = "Logins",
    val folderId: String = VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID,
    val folderName: String = VaultFolder.DEFAULT_FOLDER_NAME,
    val tagsText: String = "",
    val isFavorite: Boolean = false,
    val isPinned: Boolean = false,
    val isArchived: Boolean = false,
    val customFields: List<CustomCredentialField> = emptyList(),
    val pendingCustomLabel: String = "",
    val pendingCustomValue: String = "",
    val pendingCustomIsSecret: Boolean = true,
    val editorError: String? = null
)

data class StagedBackupMetadata(
    val operationId: String,
    val originSlotId: Int,
    val sessionGenerationId: Long,
    val stagedFilePath: String,
    val sizeBytes: Long,
    val suggestedFileName: String
)

enum class BackupOperationStage(val label: String) {
    IDLE("Idle"),
    PREPARING_EXPORT("Preparing encrypted .pvault…"),
    WAITING_FOR_EXPORT_DESTINATION("Waiting for Save As location…"),
    WRITING_EXPORT("Writing encrypted .pvault…"),
    WAITING_FOR_RESTORE_FILE("Waiting for .pvault file selection…"),
    VERIFYING_RESTORE("Verifying Argon2id + AES-256-GCM backup…"),
    APPLYING_RESTORE("Applying authenticated restore…")
}

data class VerifiedRestorePreviewState(
    val operationId: String = UUID.randomUUID().toString(),
    val targetSessionId: Long = 0L,
    val targetSlotId: Int = 0,
    val sourceUriString: String = "",
    val fileName: String,
    val exportedAtEpochMs: Long,
    val appVersionName: String,
    val notesCount: Int,
    val credentialsCount: Int,
    val foldersCount: Int,
    val isEmptyBackup: Boolean = false
)

data class VaultUiState(
    val isLoading: Boolean = true,
    val isVaultProvisioned: Boolean = false,
    val isBiometricEnrolled: Boolean = false,
    val isBiometricHardwareBacked: Boolean = false,
    val isDecoyModeEnabled: Boolean = false,
    val isBiometricBlockedByPolicy: Boolean = false,
    val isDecoyPolicySheetUnlocked: Boolean = false,
    val sessionState: VaultSessionManager.SessionState = VaultSessionManager.SessionState.Locked,
    val primaryTab: PrimaryTab = PrimaryTab.NOTES,
    val activeToolsSegment: ToolsSegment = ToolsSegment.GENERATOR,
    val secondaryDestination: SecondaryDestination = SecondaryDestination.NONE,

    // Active unlocked vault data
    val notes: List<NoteRecord> = emptyList(),
    val credentials: List<CredentialRecord> = emptyList(),
    val folders: List<VaultFolder> = emptyList(),
    val corruptedRecordCount: Int = 0,

    // Search & filter state ("All" is represented by null selected folder ID — R12)
    val notesSearchQuery: String = "",
    val selectedNoteCategory: String = "All",
    val selectedNoteFolderId: String? = null,
    val notesSortOrder: SortOrder = SortOrder.UPDATED_DESC,
    val notesFavoritesOnly: Boolean = false,
    val notesArchiveOnly: Boolean = false,
    val notesTrashOnly: Boolean = false,

    val credentialsSearchQuery: String = "",
    val selectedCredentialCategory: String = "All",
    val selectedCredentialFolderId: String? = null,
    val credentialsSortOrder: SortOrder = SortOrder.UPDATED_DESC,
    val credentialsFavoritesOnly: Boolean = false,
    val credentialsArchiveOnly: Boolean = false,
    val credentialsTrashOnly: Boolean = false,

    // Session-scoped active drafts surviving rotation & keyboard resize (R10)
    val activeNoteDraft: NoteEditorDraftState? = null,
    val activeCredentialDraft: CredentialEditorDraftState? = null,

    // Backup & Restore state (U01, U02, R10, R16, Section 05, PV-BUG-009)
    val backupOperationStage: BackupOperationStage = BackupOperationStage.IDLE,
    val backupExportScope: PortableBackupEngine.BackupExportScope =
        PortableBackupEngine.BackupExportScope.ALL_DATA,
    val stagedBackupMetadata: StagedBackupMetadata? = null,
    val selectedRestoreUriString: String? = null,
    val selectedRestoreFileName: String? = null,
    val verifiedRestorePreview: VerifiedRestorePreviewState? = null,
    val allowRecoveryExportSkippingCorrupted: Boolean = false,

    // Generator & Strength Audit state
    val generatorConfig: OfflinePasswordStrengthEstimator.GeneratorConfig =
        OfflinePasswordStrengthEstimator.GeneratorConfig(),
    val generatedCandidate: String = "",
    val generatorError: String? = null,
    val generatorExplanation: String = "",
    val passphraseWordCount: Int = 5,
    val strengthCheckerInput: String = "",

    // Rate limiting & status banners
    val failedUnlockAttempts: Int = 0,
    val unlockCooldownRemainingMs: Long = 0L,
    val lastUnlockKdfDurationMs: Long = 0L,
    val isBusy: Boolean = false,
    val statusBannerMessage: String? = null,
    val errorBannerMessage: String? = null
)

class VaultViewModel(
    private val appContext: Context,
    val vaultRepository: VaultRepository,
    val preferencesRepository: AppPreferencesRepository,
    val otaUpdateManager: OtaUpdateManager,
    private val enableStartupOtaCheck: Boolean = true
) : ViewModel() {

    // R20 Fix: Bound to viewModelScope and shut down cleanly in onCleared()
    val clipboardManager: SensitiveClipboardManager =
        SensitiveClipboardManager(appContext, viewModelScope)

    private val _uiState = MutableStateFlow(VaultUiState())
    val uiState: StateFlow<VaultUiState> = _uiState.asStateFlow()

    private val _preferences = MutableStateFlow(VaultAppPreferences())
    val preferences: StateFlow<VaultAppPreferences> = _preferences.asStateFlow()

    val otaState: StateFlow<OtaUpdateManager.OtaState> = otaUpdateManager.otaState
    val clipboardCountdownSeconds: StateFlow<Int?> = clipboardManager.activeCountdownSeconds

    private var unlockJob: Job? = null
    private var backgroundAutoLockJob: Job? = null
    private val backupMutex = kotlinx.coroutines.sync.Mutex()

    init {
        cleanupStaleBackupStagingFiles()
        observePreferences()
        observeSessionLifecycle()
        initializeStartupChecks()
    }

    override fun onCleared() {
        super.onCleared()
        backgroundAutoLockJob?.cancel()
        clipboardManager.shutdown()
        cleanupStaleBackupStagingFiles()
    }

    private fun observePreferences() {
        viewModelScope.launch {
            preferencesRepository.preferencesFlow.collect { prefs ->
                _preferences.value = prefs
                val now = System.currentTimeMillis()
                val rawRemaining = (prefs.unlockCooldownUntilEpochMs - now)
                val clampedRemaining = if (rawRemaining > 0L) {
                    rawRemaining.coerceAtMost(AppPreferencesRepository.MAX_COOLDOWN_MS)
                } else {
                    0L
                }
                _uiState.update {
                    it.copy(
                        failedUnlockAttempts = prefs.consecutiveFailedUnlocks,
                        unlockCooldownRemainingMs = clampedRemaining
                    )
                }
            }
        }
    }

    private fun observeSessionLifecycle() {
        viewModelScope.launch {
            vaultRepository.sessionManager.sessionState.collect { session ->
                when (session) {
                    is VaultSessionManager.SessionState.Locked -> {
                        backgroundAutoLockJob?.cancel()
                        backgroundAutoLockJob = null
                        // Note: If the user is in the middle of the Android system Save As picker (U01),
                        // we keep stagedBackupMetadata (which points only to an already-encrypted
                        // .pvault file on disk) so the CreateDocument callback can finish copying it!
                        val inPickerWindow = vaultRepository.sessionManager.isInFilePickerTransitionWindow()
                        if (!inPickerWindow) {
                            deleteStagedBackupFile(_uiState.value.stagedBackupMetadata)
                        }
                        _uiState.update { state ->
                            state.copy(
                                sessionState = VaultSessionManager.SessionState.Locked,
                                notes = emptyList(),
                                credentials = emptyList(),
                                folders = emptyList(),
                                corruptedRecordCount = 0,
                                isDecoyModeEnabled = false,
                                isBiometricBlockedByPolicy = false,
                                isDecoyPolicySheetUnlocked = false,
                                activeNoteDraft = null,
                                activeCredentialDraft = null,
                                backupOperationStage = if (inPickerWindow) state.backupOperationStage else BackupOperationStage.IDLE,
                                stagedBackupMetadata = if (inPickerWindow) state.stagedBackupMetadata else null,
                                selectedRestoreUriString = null,
                                selectedRestoreFileName = null,
                                verifiedRestorePreview = null,
                                strengthCheckerInput = "",
                                notesSearchQuery = "",
                                credentialsSearchQuery = ""
                            )
                        }
                    }

                    is VaultSessionManager.SessionState.Unlocked -> {
                        val blockedByPolicy = session.slotId == VaultSessionManager.DECOY_SLOT ||
                            session.isDecoyConfiguredInRealVault
                        _uiState.update { state ->
                            state.copy(
                                sessionState = session,
                                isBiometricBlockedByPolicy = blockedByPolicy
                            )
                        }
                        refreshActiveVaultItems(session.sessionId)
                    }
                }
            }
        }
    }

    private fun initializeStartupChecks() {
        viewModelScope.launch {
            val provisioned = vaultRepository.isVaultProvisioned()
            val bioEnrolled = vaultRepository.isBiometricUnlockEnrolled()
            val bioHardwareBacked = vaultRepository.isBiometricKeyHardwareBacked()
            val defaultCfg = OfflinePasswordStrengthEstimator.GeneratorConfig()
            val genResult = PasswordGeneratorEngine.generate(
                length = defaultCfg.length,
                includeUppercase = defaultCfg.includeUppercase,
                includeLowercase = defaultCfg.includeLowercase,
                includeDigits = defaultCfg.includeDigits,
                includeSymbols = defaultCfg.includeSymbols,
                excludeAmbiguous = defaultCfg.excludeAmbiguous
            )
            val initialPass = (genResult as? PasswordGeneratorEngine.GenerationResult.Success)?.password
                ?: OfflinePasswordStrengthEstimator.generatePassword(defaultCfg)
            val initialExplanation = (genResult as? PasswordGeneratorEngine.GenerationResult.Success)?.explanation
                ?: ""

            _uiState.update {
                it.copy(
                    isLoading = false,
                    isVaultProvisioned = provisioned,
                    isBiometricEnrolled = bioEnrolled,
                    isBiometricHardwareBacked = bioHardwareBacked,
                    generatedCandidate = initialPass,
                    generatorError = null,
                    generatorExplanation = initialExplanation
                )
            }

            if (enableStartupOtaCheck) {
                val currentPrefs = preferencesRepository.preferencesFlow.first()
                if (currentPrefs.autoCheckOtaOnStartup) {
                    val result = otaUpdateManager.checkForUpdates(
                        manifestUrl = currentPrefs.otaManifestUrl,
                        showDialogIfAvailable = false
                    )
                    if (result is OtaUpdateManager.OtaState.UpdateAvailable) {
                        val shouldPrompt = preferencesRepository.shouldShowAutomaticUpdatePrompt(
                            prefs = currentPrefs,
                            remoteVersionCode = result.manifest.versionCode
                        )
                        if (shouldPrompt) {
                            otaUpdateManager.setPromptDialogVisible(true)
                        }
                    }
                }
            }
        }
    }

    fun refreshActiveVaultItems(sessionId: Long? = currentSessionIdOrNull()): Job? {
        val activeId = sessionId ?: return null
        return viewModelScope.launch(Dispatchers.Default) {
            try {
                val snapshot = vaultRepository.loadDecryptedSlotSnapshotForSession(activeId)
                val decoyEnabled = vaultRepository.isDecoyModeEnabledForRealSession(activeId)
                val bioEnrolled = vaultRepository.isBiometricUnlockEnrolled()
                val bioHardwareBacked = vaultRepository.isBiometricKeyHardwareBacked()
                val activeSession = vaultRepository.sessionManager.sessionState.value as? VaultSessionManager.SessionState.Unlocked
                    ?: return@launch
                if (activeSession.sessionId != activeId) return@launch

                // PV-SEC-008 Fix: Both Real (when Decoy is enabled) and Decoy sessions set
                // isBiometricBlockedByPolicy = true so Settings renders the exact same Biometric UI.
                val blockedByPolicy = activeSession.slotId == VaultSessionManager.DECOY_SLOT || decoyEnabled

                val notes = snapshot.items.filterIsInstance<NoteRecord>()
                val creds = snapshot.items.filterIsInstance<CredentialRecord>()
                val folders = snapshot.items.filterIsInstance<VaultFolder>()

                _uiState.update { state ->
                    state.copy(
                        notes = notes,
                        credentials = creds,
                        folders = folders,
                        corruptedRecordCount = snapshot.corruptedRecordIds.size,
                        isDecoyModeEnabled = decoyEnabled,
                        isBiometricBlockedByPolicy = blockedByPolicy,
                        isBiometricEnrolled = bioEnrolled,
                        isBiometricHardwareBacked = bioHardwareBacked
                    )
                }
            } catch (_: Exception) {
                // Session locked during load
            }
        }
    }

    // ============================================================================================
    // Vault Setup, Unlock & Lock Lifecycle
    // ============================================================================================

    fun setupNewVault(
        realPassword: String,
        confirmRealPassword: String,
        enableDecoy: Boolean,
        decoyPassword: String,
        confirmDecoyPassword: String,
        seedStarterSamples: Boolean
    ) {
        if (realPassword.length < 8) {
            setErrorBanner("Master Password must be at least 8 characters.")
            return
        }
        if (realPassword != confirmRealPassword) {
            setErrorBanner("Master Passwords do not match.")
            return
        }
        if (enableDecoy) {
            if (decoyPassword.length < 8) {
                setErrorBanner("Decoy Password must be at least 8 characters.")
                return
            }
            if (decoyPassword != confirmDecoyPassword) {
                setErrorBanner("Decoy Passwords do not match.")
                return
            }
            if (realPassword == decoyPassword) {
                setErrorBanner("Real Master Password and Decoy Password must be distinct.")
                return
            }
        }

        val realChars = realPassword.toCharArray()
        val decoyChars = if (enableDecoy) decoyPassword.toCharArray() else null

        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, errorBannerMessage = null) }
            try {
                val session = vaultRepository.initializeNewVault(
                    realMasterPasswordChars = realChars,
                    optionalDecoyPasswordChars = decoyChars,
                    seedSampleDataInRealVault = seedStarterSamples,
                    seedSampleDataInDecoyVault = seedStarterSamples
                )
                val provisioned = vaultRepository.isVaultProvisioned()
                val bioEnrolled = vaultRepository.isBiometricUnlockEnrolled()
                preferencesRepository.clearUnlockFailures()
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        isVaultProvisioned = provisioned,
                        isBiometricEnrolled = bioEnrolled,
                        isBiometricBlockedByPolicy = enableDecoy,
                        sessionState = session,
                        statusBannerMessage = "Encrypted vault provisioned."
                    )
                }
                refreshActiveVaultItems(session.sessionId)
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        errorBannerMessage = e.message ?: "Failed to initialize vault."
                    )
                }
            } finally {
                Arrays.fill(realChars, '\u0000')
                if (decoyChars != null) Arrays.fill(decoyChars, '\u0000')
            }
        }
    }

    fun unlockWithPassword(password: String) {
        if (password.isBlank()) {
            setErrorBanner("Enter your vault password.")
            return
        }

        val now = System.currentTimeMillis()
        val cooldownUntil = _preferences.value.unlockCooldownUntilEpochMs
        val remainingCooldownMs = (cooldownUntil - now).coerceAtMost(AppPreferencesRepository.MAX_COOLDOWN_MS)
        if (remainingCooldownMs > 0L) {
            val remainingSec = ((remainingCooldownMs + 999L) / 1000L).coerceAtLeast(1L)
            setErrorBanner("Please wait ${remainingSec}s before trying again.")
            return
        }

        val passwordChars = password.toCharArray()
        val capturedAuthGen = vaultRepository.sessionManager.currentAuthRequestGeneration()

        unlockJob?.cancel()
        unlockJob = viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, errorBannerMessage = null) }
            try {
                when (val result = vaultRepository.unlockWithPassword(passwordChars, capturedAuthGen)) {
                    is VaultRepository.UnlockResult.Success -> {
                        preferencesRepository.clearUnlockFailures()
                        val blockedByPolicy = result.session.slotId == VaultSessionManager.DECOY_SLOT ||
                            result.session.isDecoyConfiguredInRealVault
                        _uiState.update {
                            it.copy(
                                isBusy = false,
                                failedUnlockAttempts = 0,
                                unlockCooldownRemainingMs = 0L,
                                lastUnlockKdfDurationMs = result.kdfDurationMs,
                                sessionState = result.session,
                                isBiometricBlockedByPolicy = blockedByPolicy,
                                errorBannerMessage = null
                            )
                        }
                        refreshActiveVaultItems(result.session.sessionId)
                    }

                    is VaultRepository.UnlockResult.InvalidCredentials -> {
                        val (newFailures, cooldownMs) = preferencesRepository.recordUnlockFailure()
                        _uiState.update {
                            it.copy(
                                isBusy = false,
                                failedUnlockAttempts = newFailures,
                                unlockCooldownRemainingMs = cooldownMs,
                                lastUnlockKdfDurationMs = result.kdfDurationMs,
                                errorBannerMessage = if (cooldownMs > 0L) {
                                    "Invalid password ($newFailures failed attempts). Cooldown: ${cooldownMs / 1000}s."
                                } else {
                                    "Invalid password. Could not unwrap vault key envelope."
                                }
                            )
                        }
                    }

                    VaultRepository.UnlockResult.CancelledByLock -> {
                        _uiState.update {
                            it.copy(
                                isBusy = false,
                                sessionState = VaultSessionManager.SessionState.Locked
                            )
                        }
                    }
                }
            } catch (_: CancellationException) {
                _uiState.update { it.copy(isBusy = false) }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        errorBannerMessage = e.message ?: "Unlock error."
                    )
                }
            } finally {
                Arrays.fill(passwordChars, '\u0000')
            }
        }
    }

    fun completeBiometricUnlock(authenticatedCipher: Cipher) {
        val capturedAuthGen = vaultRepository.sessionManager.currentAuthRequestGeneration()
        viewModelScope.launch {
            val session = vaultRepository.unlockWithBiometricCipher(authenticatedCipher, capturedAuthGen)
            if (session != null) {
                preferencesRepository.clearUnlockFailures()
                _uiState.update {
                    it.copy(
                        failedUnlockAttempts = 0,
                        unlockCooldownRemainingMs = 0L,
                        sessionState = session,
                        errorBannerMessage = null
                    )
                }
                refreshActiveVaultItems(session.sessionId)
            } else {
                setErrorBanner("Biometric key envelope could not be unwrapped. Please unlock with your password.")
            }
        }
    }

    /**
     * R08 Fix: Handles permanently invalidated Android Keystore biometric keys by retiring only
     * the invalid biometric wrapper and displaying a clear user message while preserving password unlock.
     */
    fun handleInvalidatedBiometricKey() {
        viewModelScope.launch {
            vaultRepository.disableBiometricUnlock()
            _uiState.update {
                it.copy(
                    isBiometricEnrolled = false,
                    isBiometricHardwareBacked = false,
                    errorBannerMessage = "Device biometrics changed. Please unlock with your password and re-enable biometric quick-unlock in Settings."
                )
            }
        }
    }

    fun completeBiometricEnrollment(authenticatedCipher: Cipher) {
        val sessionId = currentSessionIdOrNull() ?: return
        viewModelScope.launch {
            try {
                vaultRepository.enrollBiometricWrapperWithAuthenticatedCipher(
                    sessionId = sessionId,
                    authenticatedCipher = authenticatedCipher
                )
                val enrolled = vaultRepository.isBiometricUnlockEnrolled()
                val hwBacked = vaultRepository.isBiometricKeyHardwareBacked()
                _uiState.update {
                    it.copy(
                        isBiometricEnrolled = enrolled,
                        isBiometricHardwareBacked = hwBacked,
                        statusBannerMessage = "Biometric quick-unlock enabled."
                    )
                }
            } catch (e: Exception) {
                setErrorBanner(e.message ?: "Could not enroll biometric unlock.")
            }
        }
    }

    fun disableBiometricUnlock() {
        viewModelScope.launch {
            vaultRepository.disableBiometricUnlock()
            _uiState.update {
                it.copy(
                    isBiometricEnrolled = false,
                    isBiometricHardwareBacked = false,
                    statusBannerMessage = "Biometric quick-unlock disabled."
                )
            }
        }
    }

    /**
     * N03 Fix: Immediately cancels any in-flight KDF unlock job and increments both session and
     * auth request generations so a late KDF completion can never reopen the vault after locking.
     */
    fun lockVaultNow(reasonBanner: String? = null) {
        unlockJob?.cancel()
        unlockJob = null
        backgroundAutoLockJob?.cancel()
        backgroundAutoLockJob = null
        vaultRepository.sessionManager.lockNow()
        clipboardManager.clearIfStillOwned()
        _uiState.update {
            it.copy(
                isBusy = false,
                secondaryDestination = SecondaryDestination.NONE,
                statusBannerMessage = reasonBanner
            )
        }
    }

    /**
     * PV-SEC-007 Fix: Proactively locks the vault in the background (or schedules a coroutine timer
     * for `autoLockTimeoutMs`) so the decrypted DEK does not remain in memory indefinitely while
     * the app is backgrounded.
     */
    fun onAppBackgrounded() {
        vaultRepository.sessionManager.onAppBackgrounded()
        backgroundAutoLockJob?.cancel()
        backgroundAutoLockJob = null

        val isUnlocked = vaultRepository.sessionManager.sessionState.value is VaultSessionManager.SessionState.Unlocked
        if (!isUnlocked) return

        val inPickerWindow = vaultRepository.sessionManager.isInFilePickerTransitionWindow()
        val timeoutMs = _preferences.value.autoLockTimeoutMs

        if (!inPickerWindow && timeoutMs <= 0L) {
            lockVaultNow("Vault automatically locked.")
            return
        }

        val delayMs = if (inPickerWindow) {
            VaultSessionManager.FILE_PICKER_GRANT_WINDOW_MS
        } else {
            timeoutMs
        }

        backgroundAutoLockJob = viewModelScope.launch {
            delay(delayMs)
            if (vaultRepository.sessionManager.sessionState.value is VaultSessionManager.SessionState.Unlocked) {
                lockVaultNow("Vault automatically locked.")
            }
        }
    }

    fun onAppForegrounded() {
        backgroundAutoLockJob?.cancel()
        backgroundAutoLockJob = null
        val timeout = _preferences.value.autoLockTimeoutMs
        val locked = vaultRepository.sessionManager.onAppForegrounded(timeout)
        clipboardManager.retryPendingClearOnForeground()
        otaUpdateManager.refreshInstallPermissionState()
        if (locked) {
            clipboardManager.clearIfStillOwned()
            _uiState.update {
                it.copy(
                    isBusy = false,
                    secondaryDestination = SecondaryDestination.NONE,
                    statusBannerMessage = "Vault automatically locked."
                )
            }
        }
    }

    fun onWindowFocusRegained() {
        clipboardManager.retryPendingClearOnForeground()
        otaUpdateManager.refreshInstallPermissionState()
    }

    fun onScreenTurnedOff() {
        if (_preferences.value.lockOnScreenOff) {
            lockVaultNow("Vault locked on screen off.")
        }
    }

    // ============================================================================================
    // Navigation & Draft Editors (R10, R11, R12, R13, R18, Friendly 4-Tab Nav)
    // ============================================================================================

    fun selectPrimaryTab(tab: PrimaryTab) {
        _uiState.update { state ->
            when (tab) {
                PrimaryTab.GENERATOR -> state.copy(
                    primaryTab = PrimaryTab.TOOLS,
                    activeToolsSegment = ToolsSegment.GENERATOR,
                    secondaryDestination = SecondaryDestination.NONE
                )
                PrimaryTab.STRENGTH_AUDIT -> state.copy(
                    primaryTab = PrimaryTab.TOOLS,
                    activeToolsSegment = ToolsSegment.STRENGTH_CHECKER,
                    secondaryDestination = SecondaryDestination.NONE
                )
                else -> state.copy(
                    primaryTab = tab,
                    secondaryDestination = SecondaryDestination.NONE
                )
            }
        }
    }

    fun selectToolsSegment(segment: ToolsSegment) {
        _uiState.update {
            it.copy(
                primaryTab = PrimaryTab.TOOLS,
                activeToolsSegment = segment,
                secondaryDestination = SecondaryDestination.NONE
            )
        }
    }

    fun openSecondaryDestination(destination: SecondaryDestination) {
        _uiState.update {
            it.copy(
                secondaryDestination = destination,
                isDecoyPolicySheetUnlocked = if (destination != SecondaryDestination.SECURITY_SETTINGS) false else it.isDecoyPolicySheetUnlocked
            )
        }
    }

    // --- Session-scoped Note Editor Draft (R10, R11, R13, PV-BUG-003, PV-BUG-004, PV-BUG-007) ---

    fun openNewNoteDraft() {
        val defaultFolderId = _uiState.value.selectedNoteFolderId ?: VaultFolder.DEFAULT_NOTE_FOLDER_ID
        val folderObj = _uiState.value.folders.firstOrNull {
            it.scope == FolderScope.NOTES && it.id == defaultFolderId
        }
        _uiState.update {
            it.copy(
                activeNoteDraft = NoteEditorDraftState(
                    isDirty = false,
                    autosaveIndicator = AutosaveIndicator.IDLE,
                    folderId = folderObj?.id ?: VaultFolder.DEFAULT_NOTE_FOLDER_ID,
                    folderName = folderObj?.name ?: VaultFolder.DEFAULT_FOLDER_NAME
                )
            )
        }
    }

    fun openExistingNoteDraft(note: NoteRecord) {
        _uiState.update {
            it.copy(
                activeNoteDraft = NoteEditorDraftState(
                    noteId = note.id,
                    isEditingExisting = true,
                    isDirty = false,
                    autosaveIndicator = AutosaveIndicator.SAVED,
                    createdAtEpochMs = note.createdAtEpochMs,
                    title = note.title,
                    body = note.body,
                    format = note.format,
                    category = note.category,
                    folderId = note.folderId.ifBlank { VaultFolder.DEFAULT_NOTE_FOLDER_ID },
                    folderName = note.folderName.ifBlank { VaultFolder.DEFAULT_FOLDER_NAME },
                    tagsText = note.tags.joinToString(", "),
                    colorAccentIndex = note.colorAccentIndex,
                    isPinned = note.isPinned,
                    isFavorite = note.isFavorite,
                    isArchived = note.isArchived,
                    checklistItems = note.checklistItems
                )
            )
        }
    }

    fun updateActiveNoteDraft(transform: (NoteEditorDraftState) -> NoteEditorDraftState) {
        _uiState.update { state ->
            val current = state.activeNoteDraft ?: return@update state
            val next = transform(current)
            val contentChanged = next.title != current.title ||
                next.body != current.body ||
                next.format != current.format ||
                next.category != current.category ||
                next.folderId != current.folderId ||
                next.tagsText != current.tagsText ||
                next.colorAccentIndex != current.colorAccentIndex ||
                next.isPinned != current.isPinned ||
                next.isFavorite != current.isFavorite ||
                next.isArchived != current.isArchived ||
                next.checklistItems != current.checklistItems ||
                next.pendingNewChecklistText != current.pendingNewChecklistText
            val finalDraft = if (contentChanged) {
                next.copy(
                    isDirty = true,
                    autosaveIndicator = AutosaveIndicator.UNSAVED
                )
            } else {
                next
            }
            state.copy(activeNoteDraft = finalDraft)
        }
    }

    fun closeNoteDraft() {
        _uiState.update { it.copy(activeNoteDraft = null) }
    }

    /**
     * R11, R13, PV-BUG-003 & PV-BUG-004 Fix:
     * - Saves the active Note draft, automatically committing any non-empty pending checklist text.
     * - In silent autosave mode (`isSilentAutosave == true`), skips saving if `!draft.isDirty` so
     *   merely viewing a note never overwrites `updatedAtEpochMs` (`PV-BUG-003`).
     * - Updates `autosaveIndicator` (`SAVING` -> `SAVED` / `ERROR`) (`PV-BUG-004`).
     */
    fun commitActiveNoteDraft(
        closeOnSuccess: Boolean,
        isSilentAutosave: Boolean = false
    ) {
        val sessionId = currentSessionIdOrNull() ?: return
        val draft = _uiState.value.activeNoteDraft ?: return

        if (isSilentAutosave && !draft.isDirty) {
            if (closeOnSuccess) {
                closeNoteDraft()
            }
            return
        }

        val finalChecklist = if (draft.pendingNewChecklistText.isNotBlank()) {
            draft.checklistItems + ChecklistEntry(text = draft.pendingNewChecklistText.trim())
        } else {
            draft.checklistItems
        }

        if (draft.title.isBlank() && draft.body.isBlank() && finalChecklist.isEmpty()) {
            if (!isSilentAutosave) {
                updateActiveNoteDraft {
                    it.copy(
                        autosaveIndicator = AutosaveIndicator.ERROR,
                        editorError = "Please enter a note title, body text, or checklist item before saving."
                    )
                }
            }
            return
        }

        _uiState.update { state ->
            state.copy(
                activeNoteDraft = state.activeNoteDraft?.copy(
                    autosaveIndicator = AutosaveIndicator.SAVING
                )
            )
        }

        val resolvedNote = NoteRecord(
            id = draft.noteId,
            title = draft.title.trim().ifEmpty { "Untitled Note" },
            body = draft.body,
            format = draft.format,
            checklistItems = finalChecklist,
            category = draft.category.trim().ifEmpty { "Personal" },
            folderId = draft.folderId.ifBlank { VaultFolder.DEFAULT_NOTE_FOLDER_ID },
            folderName = draft.folderName.trim().ifEmpty { VaultFolder.DEFAULT_FOLDER_NAME },
            tags = draft.tagsText.split(",").map { it.trim() }.filter { it.isNotEmpty() },
            colorAccentIndex = draft.colorAccentIndex,
            isPinned = draft.isPinned,
            isFavorite = draft.isFavorite,
            isArchived = draft.isArchived,
            createdAtEpochMs = draft.createdAtEpochMs,
            updatedAtEpochMs = System.currentTimeMillis()
        )

        viewModelScope.launch {
            try {
                vaultRepository.saveVaultItem(sessionId, resolvedNote)
                refreshActiveVaultItems(sessionId)
                _uiState.update { state ->
                    state.copy(
                        activeNoteDraft = if (closeOnSuccess) {
                            null
                        } else {
                            state.activeNoteDraft?.copy(
                                isEditingExisting = true,
                                isDirty = false,
                                autosaveIndicator = AutosaveIndicator.SAVED,
                                checklistItems = finalChecklist,
                                pendingNewChecklistText = "",
                                editorError = null
                            )
                        },
                        statusBannerMessage = if (!isSilentAutosave) "Encrypted note saved." else state.statusBannerMessage
                    )
                }
            } catch (e: Exception) {
                val msg = e.message ?: "Failed to save note."
                _uiState.update { state ->
                    state.copy(
                        activeNoteDraft = state.activeNoteDraft?.copy(
                            autosaveIndicator = AutosaveIndicator.ERROR,
                            editorError = msg
                        )
                    )
                }
                if (!isSilentAutosave) {
                    setErrorBanner(msg)
                }
            }
        }
    }

    fun saveNote(note: NoteRecord, onComplete: () -> Unit = {}) {
        val sessionId = currentSessionIdOrNull() ?: return
        viewModelScope.launch {
            try {
                vaultRepository.saveVaultItem(
                    sessionId,
                    note.copy(updatedAtEpochMs = System.currentTimeMillis())
                )
                refreshActiveVaultItems(sessionId)
                onComplete()
            } catch (e: Exception) {
                setErrorBanner(e.message ?: "Failed to save note.")
            }
        }
    }

    fun deleteNote(noteId: String) {
        val sessionId = currentSessionIdOrNull() ?: return
        viewModelScope.launch {
            try {
                vaultRepository.deleteVaultItem(sessionId, noteId)
                refreshActiveVaultItems(sessionId)
                _uiState.update { state ->
                    state.copy(
                        activeNoteDraft = if (state.activeNoteDraft?.noteId == noteId) null else state.activeNoteDraft,
                        statusBannerMessage = "Note deleted."
                    )
                }
            } catch (e: Exception) {
                setErrorBanner(e.message ?: "Failed to delete note.")
            }
        }
    }

    fun toggleNotePin(note: NoteRecord) {
        saveNote(note.copy(isPinned = !note.isPinned))
    }

    fun toggleNoteFavorite(note: NoteRecord) {
        saveNote(note.copy(isFavorite = !note.isFavorite))
    }

    fun toggleNoteArchive(note: NoteRecord) {
        val nextArchived = !note.isArchived
        saveNote(note.copy(isArchived = nextArchived, isTrashed = false)) {
            setStatusBanner(if (nextArchived) "Note archived." else "Note unarchived.")
        }
    }

    fun duplicateNote(note: NoteRecord) {
        val now = System.currentTimeMillis()
        val copy = note.copy(
            id = UUID.randomUUID().toString(),
            title = "${note.title.ifBlank { "Untitled Note" }} (Copy)",
            isTrashed = false,
            createdAtEpochMs = now,
            updatedAtEpochMs = now
        )
        saveNote(copy) {
            setStatusBanner("Note duplicated.")
        }
    }

    fun toggleNoteTrash(note: NoteRecord) {
        val nextTrashed = !note.isTrashed
        saveNote(note.copy(isTrashed = nextTrashed)) {
            setStatusBanner(if (nextTrashed) "Note moved to Trash." else "Note restored from Trash.")
        }
    }

    // --- Session-scoped Credential Editor Draft (R10, R13, R18, N08, PV-BUG-007) ---

    fun openNewCredentialDraft(initialPassword: String = "") {
        val defaultFolderId = _uiState.value.selectedCredentialFolderId ?: VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID
        val folderObj = _uiState.value.folders.firstOrNull {
            it.scope == FolderScope.CREDENTIALS && it.id == defaultFolderId
        }
        _uiState.update {
            it.copy(
                activeCredentialDraft = CredentialEditorDraftState(
                    password = initialPassword,
                    folderId = folderObj?.id ?: VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID,
                    folderName = folderObj?.name ?: VaultFolder.DEFAULT_FOLDER_NAME
                )
            )
        }
    }

    fun useGeneratedPasswordInNewCredential() {
        val candidate = _uiState.value.generatedCandidate
        if (candidate.isBlank()) return
        val defaultFolderId = _uiState.value.selectedCredentialFolderId ?: VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID
        val folderObj = _uiState.value.folders.firstOrNull {
            it.scope == FolderScope.CREDENTIALS && it.id == defaultFolderId
        }
        _uiState.update {
            it.copy(
                primaryTab = PrimaryTab.PASSWORDS,
                secondaryDestination = SecondaryDestination.NONE,
                activeCredentialDraft = CredentialEditorDraftState(
                    password = candidate,
                    folderId = folderObj?.id ?: VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID,
                    folderName = folderObj?.name ?: VaultFolder.DEFAULT_FOLDER_NAME
                ),
                statusBannerMessage = "Generated password loaded into new credential."
            )
        }
    }

    fun openExistingCredentialDraft(credential: CredentialRecord) {
        _uiState.update {
            it.copy(
                activeCredentialDraft = CredentialEditorDraftState(
                    credentialId = credential.id,
                    isEditingExisting = true,
                    createdAtEpochMs = credential.createdAtEpochMs,
                    serviceName = credential.serviceName,
                    accountLabel = credential.accountLabel,
                    username = credential.username,
                    password = credential.password,
                    websiteUrl = credential.websiteUrl,
                    notes = credential.notes,
                    category = credential.category,
                    folderId = credential.folderId.ifBlank { VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID },
                    folderName = credential.folderName.ifBlank { VaultFolder.DEFAULT_FOLDER_NAME },
                    tagsText = credential.tags.joinToString(", "),
                    isFavorite = credential.isFavorite,
                    isPinned = credential.isPinned,
                    isArchived = credential.isArchived,
                    customFields = credential.customFields
                )
            )
        }
    }

    fun updateActiveCredentialDraft(transform: (CredentialEditorDraftState) -> CredentialEditorDraftState) {
        _uiState.update { state ->
            val current = state.activeCredentialDraft ?: return@update state
            state.copy(activeCredentialDraft = transform(current))
        }
    }

    fun closeCredentialDraft() {
        _uiState.update { it.copy(activeCredentialDraft = null) }
    }

    /**
     * N08 & R13 Fix: Saves the active Credential draft, preserving exact secret custom field values
     * without calling `.trim()` on values, and auto-committing or validating any non-empty pending
     * custom field inputs (`pendingCustomLabel` / `pendingCustomValue`) so typed user data is never
     * silently dropped.
     */
    fun commitActiveCredentialDraft() {
        val sessionId = currentSessionIdOrNull() ?: return
        val draft = _uiState.value.activeCredentialDraft ?: return

        if (draft.serviceName.isBlank()) {
            updateActiveCredentialDraft {
                it.copy(editorError = "Service or Title is required.")
            }
            return
        }

        val hasPendingLabel = draft.pendingCustomLabel.isNotBlank()
        val hasPendingValue = draft.pendingCustomValue.isNotEmpty()
        if (hasPendingLabel xor hasPendingValue) {
            updateActiveCredentialDraft {
                it.copy(
                    editorError = "You have an unfinished custom field. Please enter both Label and Value (or clear the field) before saving."
                )
            }
            return
        }

        val finalCustomFields = if (hasPendingLabel && hasPendingValue) {
            draft.customFields + CustomCredentialField(
                label = draft.pendingCustomLabel.trim(),
                // N08 Fix: Preserve exact custom field value without trimming
                value = draft.pendingCustomValue,
                isSecret = draft.pendingCustomIsSecret
            )
        } else {
            draft.customFields
        }

        val resolvedCredential = CredentialRecord(
            id = draft.credentialId,
            serviceName = draft.serviceName.trim(),
            accountLabel = draft.accountLabel.trim(),
            username = draft.username.trim(),
            // Preserve exact password characters
            password = draft.password,
            websiteUrl = draft.websiteUrl.trim(),
            notes = draft.notes,
            category = draft.category.trim().ifEmpty { "Logins" },
            folderId = draft.folderId.ifBlank { VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID },
            folderName = draft.folderName.trim().ifEmpty { VaultFolder.DEFAULT_FOLDER_NAME },
            tags = draft.tagsText.split(",").map { it.trim() }.filter { it.isNotEmpty() },
            customFields = finalCustomFields,
            isFavorite = draft.isFavorite,
            isPinned = draft.isPinned,
            isArchived = draft.isArchived,
            createdAtEpochMs = draft.createdAtEpochMs,
            updatedAtEpochMs = System.currentTimeMillis()
        )

        viewModelScope.launch {
            try {
                vaultRepository.saveVaultItem(sessionId, resolvedCredential)
                refreshActiveVaultItems(sessionId)
                _uiState.update {
                    it.copy(
                        activeCredentialDraft = null,
                        statusBannerMessage = "Encrypted credential saved."
                    )
                }
            } catch (e: Exception) {
                val msg = e.message ?: "Failed to save credential."
                updateActiveCredentialDraft { it.copy(editorError = msg) }
                setErrorBanner(msg)
            }
        }
    }

    fun saveCredential(credential: CredentialRecord, onComplete: () -> Unit = {}) {
        val sessionId = currentSessionIdOrNull() ?: return
        viewModelScope.launch {
            try {
                vaultRepository.saveVaultItem(
                    sessionId,
                    credential.copy(updatedAtEpochMs = System.currentTimeMillis())
                )
                refreshActiveVaultItems(sessionId)
                onComplete()
            } catch (e: Exception) {
                setErrorBanner(e.message ?: "Failed to save credential.")
            }
        }
    }

    fun deleteCredential(credentialId: String) {
        val sessionId = currentSessionIdOrNull() ?: return
        viewModelScope.launch {
            try {
                vaultRepository.deleteVaultItem(sessionId, credentialId)
                refreshActiveVaultItems(sessionId)
                _uiState.update { state ->
                    state.copy(
                        activeCredentialDraft = if (state.activeCredentialDraft?.credentialId == credentialId) null else state.activeCredentialDraft,
                        statusBannerMessage = "Credential deleted."
                    )
                }
            } catch (e: Exception) {
                setErrorBanner(e.message ?: "Failed to delete credential.")
            }
        }
    }

    fun toggleCredentialFavorite(credential: CredentialRecord) {
        saveCredential(credential.copy(isFavorite = !credential.isFavorite))
    }

    /**
     * R18 Fix: Toggles `CredentialRecord.isPinned` so pinned credentials sort first.
     */
    fun toggleCredentialPin(credential: CredentialRecord) {
        saveCredential(credential.copy(isPinned = !credential.isPinned))
    }

    fun toggleCredentialArchive(credential: CredentialRecord) {
        val nextArchived = !credential.isArchived
        saveCredential(credential.copy(isArchived = nextArchived, isTrashed = false)) {
            setStatusBanner(if (nextArchived) "Credential archived." else "Credential unarchived.")
        }
    }

    fun duplicateCredential(credential: CredentialRecord) {
        val now = System.currentTimeMillis()
        val copy = credential.copy(
            id = UUID.randomUUID().toString(),
            serviceName = "${credential.serviceName} (Copy)",
            isTrashed = false,
            createdAtEpochMs = now,
            updatedAtEpochMs = now
        )
        saveCredential(copy) {
            setStatusBanner("Credential duplicated.")
        }
    }

    fun toggleCredentialTrash(credential: CredentialRecord) {
        val nextTrashed = !credential.isTrashed
        saveCredential(credential.copy(isTrashed = nextTrashed)) {
            setStatusBanner(if (nextTrashed) "Credential moved to Trash." else "Credential restored from Trash.")
        }
    }

    // --- Folder Lifecycle (Create, Rename, Delete with Reassignment — R12) ---

    fun createFolder(name: String, scope: FolderScope) {
        val cleaned = name.trim()
        if (cleaned.isEmpty()) {
            setErrorBanner("Folder name cannot be empty.")
            return
        }
        if (VaultFolder.isReservedAllName(cleaned)) {
            setErrorBanner("\"All\" is reserved for the view filter. Choose a different folder name.")
            return
        }
        val duplicate = _uiState.value.folders.any {
            it.scope == scope && it.name.trim().equals(cleaned, ignoreCase = true)
        }
        if (duplicate) {
            setErrorBanner("A folder named \"$cleaned\" already exists.")
            return
        }
        val sessionId = currentSessionIdOrNull() ?: return
        viewModelScope.launch {
            try {
                val folder = VaultFolder(
                    name = cleaned,
                    scope = scope
                )
                vaultRepository.saveVaultItem(sessionId, folder)
                refreshActiveVaultItems(sessionId)
                setStatusBanner("Folder \"$cleaned\" created.")
            } catch (e: Exception) {
                setErrorBanner(e.message ?: "Failed to create folder.")
            }
        }
    }

    fun renameFolder(folderId: String, newName: String) {
        val sessionId = currentSessionIdOrNull() ?: return
        viewModelScope.launch {
            try {
                vaultRepository.renameVaultFolder(sessionId, folderId, newName)
                refreshActiveVaultItems(sessionId)
                setStatusBanner("Folder renamed to \"${newName.trim()}\".")
            } catch (e: Exception) {
                setErrorBanner(e.message ?: "Failed to rename folder.")
            }
        }
    }

    fun deleteFolder(folderId: String) {
        val sessionId = currentSessionIdOrNull() ?: return
        viewModelScope.launch {
            try {
                vaultRepository.deleteVaultFolderAndReassignRecords(sessionId, folderId)
                _uiState.update { state ->
                    state.copy(
                        selectedNoteFolderId = if (state.selectedNoteFolderId == folderId) null else state.selectedNoteFolderId,
                        selectedCredentialFolderId = if (state.selectedCredentialFolderId == folderId) null else state.selectedCredentialFolderId
                    )
                }
                refreshActiveVaultItems(sessionId)
                setStatusBanner("Folder deleted. Items were moved to General.")
            } catch (e: Exception) {
                setErrorBanner(e.message ?: "Failed to delete folder.")
            }
        }
    }

    // ============================================================================================
    // Search & Filter Controls (R12, PV-BUG-007)
    // ============================================================================================

    fun setNotesSearchQuery(query: String) {
        _uiState.update { it.copy(notesSearchQuery = query) }
    }

    fun setSelectedNoteCategory(category: String) {
        _uiState.update { it.copy(selectedNoteCategory = category) }
    }

    fun setSelectedNoteFolderId(folderId: String?) {
        _uiState.update { it.copy(selectedNoteFolderId = folderId) }
    }

    fun setNotesSortOrder(order: SortOrder) {
        _uiState.update { it.copy(notesSortOrder = order) }
    }

    fun setNotesFavoritesOnly(favOnly: Boolean) {
        _uiState.update {
            it.copy(
                notesFavoritesOnly = favOnly,
                notesArchiveOnly = if (favOnly) false else it.notesArchiveOnly,
                notesTrashOnly = if (favOnly) false else it.notesTrashOnly
            )
        }
    }

    fun setNotesArchiveOnly(archiveOnly: Boolean) {
        _uiState.update {
            it.copy(
                notesArchiveOnly = archiveOnly,
                notesFavoritesOnly = if (archiveOnly) false else it.notesFavoritesOnly,
                notesTrashOnly = if (archiveOnly) false else it.notesTrashOnly
            )
        }
    }

    fun setNotesTrashOnly(trashOnly: Boolean) {
        _uiState.update {
            it.copy(
                notesTrashOnly = trashOnly,
                notesFavoritesOnly = if (trashOnly) false else it.notesFavoritesOnly,
                notesArchiveOnly = if (trashOnly) false else it.notesArchiveOnly
            )
        }
    }

    fun setCredentialsSearchQuery(query: String) {
        _uiState.update { it.copy(credentialsSearchQuery = query) }
    }

    fun setSelectedCredentialCategory(category: String) {
        _uiState.update { it.copy(selectedCredentialCategory = category) }
    }

    fun setSelectedCredentialFolderId(folderId: String?) {
        _uiState.update { it.copy(selectedCredentialFolderId = folderId) }
    }

    fun setCredentialsSortOrder(order: SortOrder) {
        _uiState.update { it.copy(credentialsSortOrder = order) }
    }

    fun setCredentialsFavoritesOnly(favOnly: Boolean) {
        _uiState.update {
            it.copy(
                credentialsFavoritesOnly = favOnly,
                credentialsArchiveOnly = if (favOnly) false else it.credentialsArchiveOnly,
                credentialsTrashOnly = if (favOnly) false else it.credentialsTrashOnly
            )
        }
    }

    fun setCredentialsArchiveOnly(archiveOnly: Boolean) {
        _uiState.update {
            it.copy(
                credentialsArchiveOnly = archiveOnly,
                credentialsFavoritesOnly = if (archiveOnly) false else it.credentialsFavoritesOnly,
                credentialsTrashOnly = if (archiveOnly) false else it.credentialsTrashOnly
            )
        }
    }

    fun setCredentialsTrashOnly(trashOnly: Boolean) {
        _uiState.update {
            it.copy(
                credentialsTrashOnly = trashOnly,
                credentialsFavoritesOnly = if (trashOnly) false else it.credentialsFavoritesOnly,
                credentialsArchiveOnly = if (trashOnly) false else it.credentialsArchiveOnly
            )
        }
    }

    // ============================================================================================
    // Password Generator & Offline Strength Checker (PV-SEC-003)
    // ============================================================================================

    fun updateGeneratorConfig(config: OfflinePasswordStrengthEstimator.GeneratorConfig) {
        val result = PasswordGeneratorEngine.generate(
            length = config.length,
            includeUppercase = config.includeUppercase,
            includeLowercase = config.includeLowercase,
            includeDigits = config.includeDigits,
            includeSymbols = config.includeSymbols,
            excludeAmbiguous = config.excludeAmbiguous
        )
        when (result) {
            is PasswordGeneratorEngine.GenerationResult.Success -> {
                _uiState.update {
                    it.copy(
                        generatorConfig = config,
                        generatedCandidate = result.password,
                        generatorError = null,
                        generatorExplanation = result.explanation
                    )
                }
            }
            is PasswordGeneratorEngine.GenerationResult.InvalidConfig -> {
                _uiState.update {
                    it.copy(
                        generatorConfig = config,
                        generatorError = result.message
                    )
                }
            }
        }
    }

    fun regeneratePasswordCandidate() {
        val config = _uiState.value.generatorConfig
        val result = PasswordGeneratorEngine.generate(
            length = config.length,
            includeUppercase = config.includeUppercase,
            includeLowercase = config.includeLowercase,
            includeDigits = config.includeDigits,
            includeSymbols = config.includeSymbols,
            excludeAmbiguous = config.excludeAmbiguous
        )
        when (result) {
            is PasswordGeneratorEngine.GenerationResult.Success -> {
                _uiState.update {
                    it.copy(
                        generatedCandidate = result.password,
                        generatorError = null,
                        generatorExplanation = result.explanation
                    )
                }
            }
            is PasswordGeneratorEngine.GenerationResult.InvalidConfig -> {
                _uiState.update {
                    it.copy(generatorError = result.message)
                }
            }
        }
    }

    fun generatePassphraseCandidate(words: Int = _uiState.value.passphraseWordCount) {
        val clamped = words.coerceIn(4, 8)
        val phrase = OfflinePasswordStrengthEstimator.generatePassphrase(wordCount = clamped)
        val report = OfflinePasswordStrengthEstimator.evaluate(phrase)
        _uiState.update {
            it.copy(
                passphraseWordCount = clamped,
                generatedCandidate = phrase,
                generatorError = null,
                generatorExplanation = "$clamped-word offline passphrase • ~${report.estimatedEntropyBits} bits word-list entropy"
            )
        }
    }

    fun setStrengthCheckerInput(input: String) {
        _uiState.update { it.copy(strengthCheckerInput = input) }
    }

    fun copySecretToClipboard(label: String, secret: String) {
        val ttl = _preferences.value.clipboardClearTtlSeconds
        clipboardManager.copySensitiveSecret(label, secret, ttl)
        setStatusBanner("$label copied. Clipboard will auto-clear in ${ttl}s.")
    }

    /**
     * U04 Fix: Copies public developer contact IDs (Telegram / Instagram handles) without marking
     * them as vault secrets or scheduling auto-clear, while retiring any prior secret tracking.
     */
    fun copyPublicContactHandle(label: String, handle: String) {
        clipboardManager.copyPublicText(label, handle)
        setStatusBanner("$label ($handle) copied to clipboard.")
    }

    // ============================================================================================
    // Portable Encrypted Backup & Restore (U01, U02, N02, R10, R16, PV-BACKUP-001, PV-BUG-009)
    // ============================================================================================

    fun setAllowRecoveryExportSkippingCorrupted(allowed: Boolean) {
        _uiState.update { it.copy(allowRecoveryExportSkippingCorrupted = allowed) }
    }

    fun setBackupExportScope(scope: PortableBackupEngine.BackupExportScope) {
        _uiState.update { it.copy(backupExportScope = scope) }
    }

    /**
     * U01 & R16 Fix: Encrypts the active vault slot into a temporary `.pvault` staging file inside
     * `context.cacheDir/backup_staging/` on `Dispatchers.Default`/`IO`, opens the 90s SAF picker
     * transition window, and invokes `onReadyToLaunchCreateDocument(suggestedFileName)` on the
     * main thread so `MainActivity`'s top-level `CreateDocument` launcher opens the Save As dialog!
     */
    fun prepareBackupExport(
        backupPassword: String,
        confirmPassword: String,
        onReadyToLaunchCreateDocument: (String) -> Unit
    ): Job? {
        if (backupPassword.length < 8) {
            setErrorBanner("Backup encryption password must be at least 8 characters.")
            return null
        }
        if (backupPassword != confirmPassword) {
            setErrorBanner("Backup passwords do not match.")
            return null
        }
        val session = (vaultRepository.sessionManager.sessionState.value as? VaultSessionManager.SessionState.Unlocked)
            ?: (_uiState.value.sessionState as? VaultSessionManager.SessionState.Unlocked)
            ?: run {
                setErrorBanner("Vault must be unlocked to export a backup.")
                return null
            }
        val sessionId = session.sessionId
        val originSlotId = session.slotId
        val passChars = backupPassword.toCharArray()
        val allowSkipCorrupted = _uiState.value.allowRecoveryExportSkippingCorrupted
        val exportScope = _uiState.value.backupExportScope

        return viewModelScope.launch(Dispatchers.Default) {
            if (!backupMutex.tryLock()) {
                Arrays.fill(passChars, '\u0000')
                setErrorBanner("A backup or restore operation is already in progress.")
                return@launch
            }
            _uiState.update {
                it.copy(
                    isBusy = true,
                    backupOperationStage = BackupOperationStage.PREPARING_EXPORT,
                    errorBannerMessage = null
                )
            }
            var encryptedBytes: ByteArray? = null
            try {
                encryptedBytes = vaultRepository.prepareEncryptedBackupBytes(
                    sessionId = sessionId,
                    backupPasswordChars = passChars,
                    appVersionName = OtaUpdateManager.getInstalledVersionName(appContext),
                    allowSkipCorruptedRecords = allowSkipCorrupted,
                    exportScope = exportScope
                )
                val opId = UUID.randomUUID().toString()
                val stagingDir = File(appContext.cacheDir, "backup_staging").apply { mkdirs() }
                val stagedFile = File(stagingDir, "pending_export_$opId.pvault")
                withContext(Dispatchers.IO) {
                    stagedFile.outputStream().use { out ->
                        out.write(encryptedBytes)
                        out.flush()
                    }
                }

                val suggestedName = "private-vault-backup-${System.currentTimeMillis() / 1000}.pvault"
                val metadata = StagedBackupMetadata(
                    operationId = opId,
                    originSlotId = originSlotId,
                    sessionGenerationId = sessionId,
                    stagedFilePath = stagedFile.absolutePath,
                    sizeBytes = stagedFile.length(),
                    suggestedFileName = suggestedName
                )

                deleteStagedBackupFile(_uiState.value.stagedBackupMetadata)
                vaultRepository.sessionManager.beginFilePickerTransitionWindow()
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        backupOperationStage = BackupOperationStage.WAITING_FOR_EXPORT_DESTINATION,
                        stagedBackupMetadata = metadata,
                        statusBannerMessage = "Encrypted backup prepared. Choose where to save $suggestedName."
                    )
                }
                onReadyToLaunchCreateDocument(suggestedName)
            } catch (e: VaultRepository.VaultRecordIntegrityException) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        backupOperationStage = BackupOperationStage.IDLE,
                        errorBannerMessage = e.message
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        backupOperationStage = BackupOperationStage.IDLE,
                        errorBannerMessage = e.message ?: "Failed to prepare encrypted backup."
                    )
                }
            } finally {
                Arrays.fill(passChars, '\u0000')
                encryptedBytes?.let { Arrays.fill(it, 0.toByte()) }
                backupMutex.unlock()
            }
        }
    }

    /**
     * U01, R16, T03 & T10 Fix: Called from `MainActivity`'s top-level `CreateDocument` result callback.
     * Verifies no cross-slot switch occurred, opens `contentResolver.openOutputStream(uri)` on `Dispatchers.IO`
     * inside `use {}`, copies the staged encrypted `.pvault` file, deletes the staging file in `finally`,
     * and reports `"Backup saved ($sizeKb KB)."` without exposing raw content URIs.
     */
    fun completeExportToUri(destinationUri: Uri?): Job? {
        vaultRepository.sessionManager.endFilePickerTransitionWindow()
        val metadata = _uiState.value.stagedBackupMetadata
        if (destinationUri == null) {
            deleteStagedBackupFile(metadata)
            _uiState.update {
                it.copy(
                    backupOperationStage = BackupOperationStage.IDLE,
                    stagedBackupMetadata = null,
                    statusBannerMessage = "Backup export cancelled."
                )
            }
            return null
        }

        if (metadata == null) {
            setErrorBanner("No staged backup found to write. Please prepare the backup again.")
            return null
        }

        // T10 Guard: If the vault was re-unlocked to a different slot while the picker was open,
        // reject the stale staged backup so Slot 0 and Slot 1 exports can never cross!
        val currentSession = vaultRepository.sessionManager.sessionState.value
        if (currentSession is VaultSessionManager.SessionState.Unlocked &&
            currentSession.slotId != metadata.originSlotId
        ) {
            deleteStagedBackupFile(metadata)
            _uiState.update {
                it.copy(
                    backupOperationStage = BackupOperationStage.IDLE,
                    stagedBackupMetadata = null,
                    errorBannerMessage = "Backup export aborted because active vault session changed."
                )
            }
            return null
        }

        return viewModelScope.launch(Dispatchers.Default) {
            if (!backupMutex.tryLock()) {
                setErrorBanner("A backup or restore operation is already in progress.")
                return@launch
            }
            _uiState.update {
                it.copy(
                    isBusy = true,
                    backupOperationStage = BackupOperationStage.WRITING_EXPORT,
                    errorBannerMessage = null
                )
            }
            try {
                val bytesWritten = withContext(Dispatchers.IO) {
                    val stagedFile = File(metadata.stagedFilePath)
                    if (!stagedFile.exists() || stagedFile.length() <= 0L) {
                        throw FileNotFoundException("Staged encrypted backup file is no longer available.")
                    }
                    val outStream = openOutputStreamForUri(destinationUri)
                        ?: throw IllegalStateException("Android storage provider could not open the selected file for writing.")
                    outStream.use { output ->
                        FileInputStream(stagedFile).use { input ->
                            val copied = input.copyTo(output)
                            output.flush()
                            copied
                        }
                    }
                }
                if (bytesWritten <= 0L) {
                    throw IllegalStateException("Zero bytes were written to the selected backup file.")
                }
                val sizeKb = (bytesWritten / 1024L).coerceAtLeast(1L)
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        backupOperationStage = BackupOperationStage.IDLE,
                        stagedBackupMetadata = null,
                        statusBannerMessage = "Backup saved ($sizeKb KB)."
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        backupOperationStage = BackupOperationStage.IDLE,
                        stagedBackupMetadata = null,
                        errorBannerMessage = "Backup export failed: ${e.message ?: "Unable to write to selected location."}"
                    )
                }
            } finally {
                deleteStagedBackupFile(metadata)
                backupMutex.unlock()
            }
        }
    }

    /**
     * U02 & R10 Fix: Called when the user initiates choosing a `.pvault` file to restore.
     */
    fun beginRestoreFileSelection(onReadyToLaunchOpenDocument: () -> Unit) {
        vaultRepository.sessionManager.beginFilePickerTransitionWindow()
        _uiState.update {
            it.copy(backupOperationStage = BackupOperationStage.WAITING_FOR_RESTORE_FILE)
        }
        onReadyToLaunchOpenDocument()
    }

    /**
     * U02 & R10 Fix: Called from `MainActivity`'s top-level `OpenDocument` result callback.
     * Stores the selected `Uri` immediately in `VaultUiState` and resolves its display name on IO.
     */
    fun onRestoreFileSelected(sourceUri: Uri?): Job? {
        vaultRepository.sessionManager.endFilePickerTransitionWindow()
        if (sourceUri == null) {
            _uiState.update {
                it.copy(
                    backupOperationStage = BackupOperationStage.IDLE,
                    statusBannerMessage = "Restore file selection cancelled."
                )
            }
            return null
        }
        val fallbackName = sourceUri.lastPathSegment ?: "backup.pvault"
        _uiState.update {
            it.copy(
                backupOperationStage = BackupOperationStage.IDLE,
                selectedRestoreUriString = sourceUri.toString(),
                selectedRestoreFileName = fallbackName,
                verifiedRestorePreview = null,
                statusBannerMessage = "Selected backup file: $fallbackName. Enter backup password to verify and restore."
            )
        }
        return viewModelScope.launch(Dispatchers.Default) {
            val displayName = withContext(Dispatchers.IO) {
                resolveDisplayNameForUri(sourceUri)
            }
            _uiState.update {
                it.copy(
                    selectedRestoreFileName = displayName,
                    statusBannerMessage = "Selected backup file: $displayName. Enter backup password to verify and restore."
                )
            }
        }
    }

    /**
     * Section 05, BUG 05 & T04 Fix: Decrypts and authenticates the selected `.pvault` file in memory
     * without modifying the database, populating `verifiedRestorePreview` with the verified record counts,
     * export timestamp, and app version so the user can inspect the backup before applying it.
     */
    fun verifyAndPreviewSelectedUri(backupPassword: String): Job? {
        val uriString = _uiState.value.selectedRestoreUriString
        if (uriString.isNullOrBlank()) {
            setErrorBanner("Please select a .pvault backup file first.")
            return null
        }
        val uri = try {
            Uri.parse(uriString)
        } catch (_: Exception) {
            setErrorBanner("Selected backup file URI is invalid.")
            return null
        }
        return verifyAndPreviewFromUri(uri, backupPassword)
    }

    fun verifyAndPreviewFromUri(sourceUri: Uri, backupPassword: String): Job? {
        if (backupPassword.isBlank()) {
            setErrorBanner("Enter the password for this .pvault backup file.")
            return null
        }
        val passChars = backupPassword.toCharArray()
        val fileName = _uiState.value.selectedRestoreFileName ?: sourceUri.lastPathSegment ?: "backup.pvault"

        return viewModelScope.launch(Dispatchers.Default) {
            if (!backupMutex.tryLock()) {
                Arrays.fill(passChars, '\u0000')
                setErrorBanner("A backup or restore operation is already in progress.")
                return@launch
            }
            _uiState.update {
                it.copy(
                    isBusy = true,
                    backupOperationStage = BackupOperationStage.VERIFYING_RESTORE,
                    errorBannerMessage = null
                )
            }
            try {
                val backupBytes = withContext(Dispatchers.IO) {
                    val inputStream = openInputStreamForUri(sourceUri)
                        ?: throw FileNotFoundException("Android storage provider could not open the selected backup file.")
                    inputStream.use { input ->
                        readBoundedBytes(input, PortableBackupEngine.MAX_BACKUP_FILE_BYTES)
                    }
                }
                val verifiedPayload = PortableBackupEngine.decryptAndVerifyBackupBytes(
                    backupBytes = backupBytes,
                    backupPasswordChars = passChars
                )
                val preview = VerifiedRestorePreviewState(
                    fileName = fileName,
                    exportedAtEpochMs = verifiedPayload.exportedAtEpochMs,
                    appVersionName = verifiedPayload.appVersionName,
                    notesCount = verifiedPayload.notesCount,
                    credentialsCount = verifiedPayload.credentialsCount,
                    foldersCount = verifiedPayload.foldersCount,
                    isEmptyBackup = verifiedPayload.isEmptyBackup
                )
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        backupOperationStage = BackupOperationStage.IDLE,
                        verifiedRestorePreview = preview,
                        statusBannerMessage = if (preview.isEmptyBackup) {
                            "Backup verified: This .pvault file contains 0 records (empty backup)."
                        } else {
                            "Backup verified: ${preview.notesCount} notes, ${preview.credentialsCount} credentials, ${preview.foldersCount} folders."
                        }
                    )
                }
            } catch (_: AEADBadTagException) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        backupOperationStage = BackupOperationStage.IDLE,
                        verifiedRestorePreview = null,
                        errorBannerMessage = "Backup verification failed: wrong backup password or tampered .pvault file."
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        backupOperationStage = BackupOperationStage.IDLE,
                        verifiedRestorePreview = null,
                        errorBannerMessage = "Backup verification failed: ${e.message ?: "Invalid .pvault file."}"
                    )
                }
            } finally {
                Arrays.fill(passChars, '\u0000')
                backupMutex.unlock()
            }
        }
    }

    /**
     * U02 & R16 Fix: Reads the selected `.pvault` `Uri` on `Dispatchers.IO` inside `use {}` with
     * strict 32 MiB size bounds, verifies the Argon2id + AES-256-GCM tag in memory, and commits
     * the restore to the active vault slot without ever crashing on bad passwords or malformed files.
     */
    fun verifyAndRestoreSelectedUri(
        backupPassword: String,
        restoreMode: PortableBackupEngine.RestoreMode
    ): Job? {
        val uriString = _uiState.value.selectedRestoreUriString
        if (uriString.isNullOrBlank()) {
            setErrorBanner("Please select a .pvault backup file first.")
            return null
        }
        val uri = try {
            Uri.parse(uriString)
        } catch (_: Exception) {
            setErrorBanner("Selected backup file URI is invalid.")
            return null
        }
        return verifyAndRestoreFromUri(uri, backupPassword, restoreMode)
    }

    fun verifyAndRestoreFromUri(
        sourceUri: Uri,
        backupPassword: String,
        restoreMode: PortableBackupEngine.RestoreMode
    ): Job? {
        if (backupPassword.isBlank()) {
            setErrorBanner("Enter the password for this .pvault backup file.")
            return null
        }
        val sessionId = currentSessionIdOrNull() ?: run {
            setErrorBanner("Vault must be unlocked before restoring a backup.")
            return null
        }
        val passChars = backupPassword.toCharArray()
        val fileName = _uiState.value.selectedRestoreFileName ?: sourceUri.lastPathSegment ?: "backup.pvault"

        return viewModelScope.launch(Dispatchers.Default) {
            if (!backupMutex.tryLock()) {
                Arrays.fill(passChars, '\u0000')
                setErrorBanner("A backup or restore operation is already in progress.")
                return@launch
            }
            _uiState.update {
                it.copy(
                    isBusy = true,
                    backupOperationStage = BackupOperationStage.VERIFYING_RESTORE,
                    errorBannerMessage = null
                )
            }
            try {
                val backupBytes = withContext(Dispatchers.IO) {
                    val inputStream = openInputStreamForUri(sourceUri)
                        ?: throw FileNotFoundException("Android storage provider could not open the selected backup file.")
                    inputStream.use { input ->
                        readBoundedBytes(input, PortableBackupEngine.MAX_BACKUP_FILE_BYTES)
                    }
                }

                _uiState.update {
                    it.copy(backupOperationStage = BackupOperationStage.APPLYING_RESTORE)
                }

                val payload = vaultRepository.applyVerifiedBackupRestore(
                    sessionId = sessionId,
                    backupBytes = backupBytes,
                    backupPasswordChars = passChars,
                    restoreMode = restoreMode
                )
                val preview = VerifiedRestorePreviewState(
                    fileName = fileName,
                    exportedAtEpochMs = payload.exportedAtEpochMs,
                    appVersionName = payload.appVersionName,
                    notesCount = payload.notesCount,
                    credentialsCount = payload.credentialsCount,
                    foldersCount = payload.foldersCount,
                    isEmptyBackup = payload.isEmptyBackup
                )
                refreshActiveVaultItems(sessionId)
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        backupOperationStage = BackupOperationStage.IDLE,
                        selectedRestoreUriString = null,
                        selectedRestoreFileName = null,
                        verifiedRestorePreview = preview,
                        statusBannerMessage = "Restored ${payload.notesCount} notes & ${payload.credentialsCount} credentials."
                    )
                }
            } catch (_: AEADBadTagException) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        backupOperationStage = BackupOperationStage.IDLE,
                        errorBannerMessage = "Restore rejected: wrong backup password or tampered .pvault file. Existing vault data is untouched."
                    )
                }
            } catch (e: VaultRepository.VaultRecordIntegrityException) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        backupOperationStage = BackupOperationStage.IDLE,
                        errorBannerMessage = e.message
                    )
                }
            } catch (e: SecurityException) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        backupOperationStage = BackupOperationStage.IDLE,
                        errorBannerMessage = "Storage permission expired for selected file. Please choose the .pvault file again."
                    )
                }
            } catch (e: FileNotFoundException) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        backupOperationStage = BackupOperationStage.IDLE,
                        errorBannerMessage = "The selected backup file could not be found. Please choose a valid .pvault file."
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        backupOperationStage = BackupOperationStage.IDLE,
                        errorBannerMessage = "Restore rejected: ${e.message ?: "Invalid .pvault file."}"
                    )
                }
            } finally {
                Arrays.fill(passChars, '\u0000')
                backupMutex.unlock()
            }
        }
    }

    private fun openInputStreamForUri(uri: Uri): java.io.InputStream? {
        if (uri.scheme.equals("file", ignoreCase = true)) {
            val path = uri.path ?: return null
            val file = File(path)
            if (!file.exists()) throw FileNotFoundException("File not found: $path")
            return file.inputStream()
        }
        return appContext.contentResolver.openInputStream(uri)
    }

    private fun openOutputStreamForUri(uri: Uri): java.io.OutputStream? {
        if (uri.scheme.equals("file", ignoreCase = true)) {
            val path = uri.path ?: return null
            val file = File(path)
            file.parentFile?.mkdirs()
            return file.outputStream()
        }
        return appContext.contentResolver.openOutputStream(uri)
    }

    private fun readBoundedBytes(input: java.io.InputStream, maxBytes: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(16 * 1024)
        var total = 0
        var read: Int
        while (input.read(buffer).also { read = it } != -1) {
            total += read
            if (total > maxBytes) {
                throw IllegalArgumentException("Selected file exceeds the 32 MiB maximum .pvault backup size.")
            }
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }

    private fun resolveDisplayNameForUri(uri: Uri): String {
        return try {
            appContext.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                ?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if (idx >= 0) cursor.getString(idx) else null
                    } else {
                        null
                    }
                } ?: uri.lastPathSegment ?: "backup.pvault"
        } catch (_: Exception) {
            uri.lastPathSegment ?: "backup.pvault"
        }
    }

    private fun deleteStagedBackupFile(metadata: StagedBackupMetadata?) {
        if (metadata == null) return
        try {
            val file = File(metadata.stagedFilePath)
            if (file.exists()) {
                file.delete()
            }
        } catch (_: Exception) {
        }
    }

    private fun cleanupStaleBackupStagingFiles() {
        try {
            val dir = File(appContext.cacheDir, "backup_staging")
            if (dir.exists()) {
                dir.listFiles()?.forEach { it.delete() }
            }
        } catch (_: Exception) {
        }
    }

    // ============================================================================================
    // Security Settings, Active-Vault Password Change & Decoy Policy Management (N05, R02, R07, R09)
    // ============================================================================================

    /**
     * R02 & PV-SEC-010 Fix: Rotates the password of the currently active vault (works identically in both
     * Real and Decoy sessions using generic active-vault terminology!), with optional full DEK rotation
     * and atomic re-encryption of every vault record.
     */
    fun changeActiveVaultPassword(
        currentPassword: String,
        newPassword: String,
        confirmNewPassword: String,
        rekeyAllRecordsWithNewDek: Boolean = false
    ) {
        if (newPassword.length < 8) {
            setErrorBanner("New Vault Password must be at least 8 characters.")
            return
        }
        if (newPassword != confirmNewPassword) {
            setErrorBanner("New Vault Passwords do not match.")
            return
        }
        val sessionId = currentSessionIdOrNull() ?: return
        val currentChars = currentPassword.toCharArray()
        val newChars = newPassword.toCharArray()

        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, errorBannerMessage = null) }
            try {
                vaultRepository.changeActiveVaultPassword(
                    sessionId = sessionId,
                    currentPasswordChars = currentChars,
                    newPasswordChars = newChars,
                    rekeyAllRecordsWithNewDek = rekeyAllRecordsWithNewDek
                )
                if (rekeyAllRecordsWithNewDek) {
                    refreshActiveVaultItems(sessionId)
                }
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        statusBannerMessage = if (rekeyAllRecordsWithNewDek) {
                            "Vault password updated and all records re-encrypted with a new 256-bit DEK."
                        } else {
                            "Vault password updated and key envelope re-wrapped."
                        }
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        errorBannerMessage = e.message ?: "Failed to update vault password."
                    )
                }
            } finally {
                Arrays.fill(currentChars, '\u0000')
                Arrays.fill(newChars, '\u0000')
            }
        }
    }

    fun rotateRealMasterPassword(
        currentPassword: String,
        newPassword: String,
        confirmNewPassword: String,
        rekeyAllRecordsWithNewDek: Boolean = false
    ) {
        changeActiveVaultPassword(currentPassword, newPassword, confirmNewPassword, rekeyAllRecordsWithNewDek)
    }

    /**
     * R02 Fix: Verifies the Real Master Password before opening the Decoy Policy Management sheet.
     * In a Decoy session, this always returns an authentication error without revealing that the
     * user is currently in a Decoy session.
     */
    fun unlockDecoyPolicySheet(realMasterPassword: String) {
        if (realMasterPassword.isBlank()) {
            setErrorBanner("Enter your Master Password to open Advanced Security Policy.")
            return
        }
        val sessionId = currentSessionIdOrNull() ?: return
        val realChars = realMasterPassword.toCharArray()

        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, errorBannerMessage = null) }
            try {
                val verified = vaultRepository.verifyRealMasterPasswordForSecurityGate(sessionId, realChars)
                if (verified) {
                    val decoyActive = vaultRepository.isDecoyModeEnabledForRealSession(sessionId)
                    _uiState.update {
                        it.copy(
                            isBusy = false,
                            isDecoyModeEnabled = decoyActive,
                            isDecoyPolicySheetUnlocked = true,
                            errorBannerMessage = null
                        )
                    }
                } else {
                    _uiState.update {
                        it.copy(
                            isBusy = false,
                            isDecoyPolicySheetUnlocked = false,
                            errorBannerMessage = "Master Password verification failed."
                        )
                    }
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        errorBannerMessage = e.message ?: "Verification failed."
                    )
                }
            } finally {
                Arrays.fill(realChars, '\u0000')
            }
        }
    }

    fun closeDecoyPolicySheet() {
        _uiState.update { it.copy(isDecoyPolicySheetUnlocked = false) }
    }

    /**
     * N05 Fix (Flow 1 — First-Time Provisioning OR Confirmed Destructive Reset):
     * Provisions Decoy Mode (or resets & wipes the Decoy Vault when `allowDestructiveReset == true`).
     */
    fun configureDecoyVault(
        realMasterPassword: String,
        decoyPassword: String,
        confirmDecoyPassword: String,
        seedPlausibleData: Boolean,
        allowDestructiveReset: Boolean = false
    ) {
        if (decoyPassword.length < 8) {
            setErrorBanner("Decoy Password must be at least 8 characters.")
            return
        }
        if (decoyPassword != confirmDecoyPassword) {
            setErrorBanner("Decoy Passwords do not match.")
            return
        }
        val sessionId = currentSessionIdOrNull() ?: return
        val realChars = realMasterPassword.toCharArray()
        val decoyChars = decoyPassword.toCharArray()

        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, errorBannerMessage = null) }
            try {
                vaultRepository.configureDecoyVault(
                    sessionId = sessionId,
                    realMasterPasswordChars = realChars,
                    decoyPasswordChars = decoyChars,
                    seedSampleData = seedPlausibleData,
                    allowDestructiveReset = allowDestructiveReset
                )
                refreshActiveVaultItems(sessionId)
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        isDecoyModeEnabled = true,
                        isBiometricEnrolled = false,
                        isBiometricHardwareBacked = false,
                        isBiometricBlockedByPolicy = true,
                        statusBannerMessage = if (allowDestructiveReset) {
                            "Decoy Vault reset with a new key envelope."
                        } else {
                            "Decoy Vault provisioned. Biometric quick-unlock disabled for plausible deniability."
                        }
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        errorBannerMessage = e.message ?: "Failed to configure Decoy Vault."
                    )
                }
            } finally {
                Arrays.fill(realChars, '\u0000')
                Arrays.fill(decoyChars, '\u0000')
            }
        }
    }

    /**
     * N05 Fix (Flow 2 — Non-Destructive Decoy Password Rotation):
     * Changes the Decoy Password while preserving all existing Slot 1 decoy notes and credentials.
     */
    fun rotateDecoyPasswordPreservingData(
        realMasterPassword: String,
        currentDecoyPassword: String,
        newDecoyPassword: String,
        confirmNewDecoyPassword: String
    ) {
        if (newDecoyPassword.length < 8) {
            setErrorBanner("New Decoy Password must be at least 8 characters.")
            return
        }
        if (newDecoyPassword != confirmNewDecoyPassword) {
            setErrorBanner("New Decoy Passwords do not match.")
            return
        }
        val sessionId = currentSessionIdOrNull() ?: return
        val realChars = realMasterPassword.toCharArray()
        val currentDecoyChars = currentDecoyPassword.toCharArray()
        val newDecoyChars = newDecoyPassword.toCharArray()

        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, errorBannerMessage = null) }
            try {
                vaultRepository.rotateDecoyPasswordPreservingRecords(
                    sessionId = sessionId,
                    realMasterPasswordChars = realChars,
                    currentDecoyPasswordChars = currentDecoyChars,
                    newDecoyPasswordChars = newDecoyChars
                )
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        statusBannerMessage = "Decoy password rotated. All existing decoy records were preserved."
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        errorBannerMessage = e.message ?: "Failed to rotate Decoy Password."
                    )
                }
            } finally {
                Arrays.fill(realChars, '\u0000')
                Arrays.fill(currentDecoyChars, '\u0000')
                Arrays.fill(newDecoyChars, '\u0000')
            }
        }
    }

    fun disableDecoyVault(realMasterPassword: String) {
        val sessionId = currentSessionIdOrNull() ?: return
        val realChars = realMasterPassword.toCharArray()
        viewModelScope.launch {
            _uiState.update { it.copy(isBusy = true, errorBannerMessage = null) }
            try {
                vaultRepository.disableDecoyVault(sessionId, realChars)
                refreshActiveVaultItems(sessionId)
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        isDecoyModeEnabled = false,
                        isBiometricBlockedByPolicy = false,
                        statusBannerMessage = "Decoy Vault disabled and replaced with an unconfigured dummy envelope."
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        errorBannerMessage = e.message ?: "Failed to disable Decoy Vault."
                    )
                }
            } finally {
                Arrays.fill(realChars, '\u0000')
            }
        }
    }

    fun runDeviceKdfBenchmark() {
        viewModelScope.launch(Dispatchers.Default) {
            _uiState.update { it.copy(isBusy = true, errorBannerMessage = null) }
            try {
                val bench = CryptoEngine.measureKdfBenchmark()
                preferencesRepository.saveManualKdfBenchmark(bench)
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        statusBannerMessage = "Measured Argon2id: ${bench.singleSlotDurationMs}ms/slot (${bench.twoSlotUnlockDurationMs}ms 2-slot) on ${bench.deviceModel}."
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isBusy = false,
                        errorBannerMessage = e.message ?: "Benchmark failed."
                    )
                }
            }
        }
    }

    fun setThemePreference(theme: ThemePreference) {
        _preferences.update { it.copy(themePreference = theme) }
        viewModelScope.launch { preferencesRepository.setThemePreference(theme) }
    }

    fun setAutoLockTimeoutMs(timeoutMs: Long) {
        _preferences.update { it.copy(autoLockTimeoutMs = timeoutMs) }
        viewModelScope.launch { preferencesRepository.setAutoLockTimeoutMs(timeoutMs) }
    }

    fun setLockOnScreenOff(enabled: Boolean) {
        _preferences.update { it.copy(lockOnScreenOff = enabled) }
        viewModelScope.launch { preferencesRepository.setLockOnScreenOff(enabled) }
    }

    /**
     * R09 Fix: Prevents a Decoy session from weakening the Real Vault's `blockScreenshots` policy.
     */
    fun setBlockScreenshots(enabled: Boolean) {
        val currentSession = _uiState.value.sessionState as? VaultSessionManager.SessionState.Unlocked ?: return
        if (!enabled && !currentSession.canManageVaultSecurity) {
            setErrorBanner("Screenshot protection cannot be disabled in this session.")
            return
        }
        _preferences.update { it.copy(blockScreenshots = enabled) }
        viewModelScope.launch { preferencesRepository.setBlockScreenshots(enabled) }
    }

    fun setClipboardClearTtlSeconds(seconds: Int) {
        _preferences.update { it.copy(clipboardClearTtlSeconds = seconds) }
        viewModelScope.launch { preferencesRepository.setClipboardClearTtlSeconds(seconds) }
    }

    fun setAutoCheckOtaOnStartup(enabled: Boolean) {
        _preferences.update { it.copy(autoCheckOtaOnStartup = enabled) }
        viewModelScope.launch { preferencesRepository.setAutoCheckOtaOnStartup(enabled) }
    }

    // ============================================================================================
    // OTA Update Actions ("Update Now", "Update Later", "Remind Me Later", "Cancel Download")
    // ============================================================================================

    fun checkForOtaUpdatesManual() {
        viewModelScope.launch {
            otaUpdateManager.checkForUpdates(
                manifestUrl = _preferences.value.otaManifestUrl,
                showDialogIfAvailable = true
            )
        }
    }

    fun updateOtaManifestUrl(url: String) {
        viewModelScope.launch {
            try {
                otaUpdateManager.validateAllowedHttpsUrl(url, isManifestEndpoint = true)
                preferencesRepository.setOtaManifestUrl(url)
                setStatusBanner("OTA manifest URL updated.")
            } catch (e: Exception) {
                setErrorBanner(e.message ?: "Invalid HTTPS GitHub manifest URL.")
            }
        }
    }

    fun onOtaUpdateNowSelected(manifest: OtaUpdateManager.UpdateManifest) {
        viewModelScope.launch {
            preferencesRepository.clearOtaReminder()
            otaUpdateManager.downloadAndVerifyUpdate(manifest)
        }
    }

    fun cancelOtaDownload() {
        otaUpdateManager.cancelActiveDownload()
        setStatusBanner("OTA update download cancelled.")
    }

    fun onOtaUpdateLaterSelected() {
        otaUpdateManager.dismissUpdatePrompt()
    }

    fun onOtaRemindMeLaterSelected(
        policy: OtaReminderPolicy,
        versionCode: Int
    ) {
        viewModelScope.launch {
            preferencesRepository.saveOtaReminderChoice(policy, versionCode)
            otaUpdateManager.dismissUpdatePrompt()
            val label = when (policy) {
                OtaReminderPolicy.NEXT_APP_LAUNCH -> "on next app launch"
                OtaReminderPolicy.TOMORROW -> "tomorrow"
                OtaReminderPolicy.IN_THREE_DAYS -> "in 3 days"
                OtaReminderPolicy.NONE -> "later"
            }
            setStatusBanner("Update reminder saved ($label).")
        }
    }

    fun triggerDebugOtaSimulation() {
        otaUpdateManager.simulateUpdateAvailableForDebug()
    }

    // ============================================================================================
    // Banner Helpers
    // ============================================================================================

    fun clearBanners() {
        _uiState.update { it.copy(statusBannerMessage = null, errorBannerMessage = null) }
    }

    fun setStatusBanner(message: String?) {
        _uiState.update { it.copy(statusBannerMessage = message, errorBannerMessage = null) }
    }

    fun setErrorBanner(message: String?) {
        _uiState.update { it.copy(errorBannerMessage = message, statusBannerMessage = null) }
    }

    private fun currentSessionIdOrNull(): Long? {
        return (vaultRepository.sessionManager.sessionState.value as? VaultSessionManager.SessionState.Unlocked)?.sessionId
            ?: (_uiState.value.sessionState as? VaultSessionManager.SessionState.Unlocked)?.sessionId
    }

    class Factory(private val context: Context) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            val appContext = context.applicationContext
            val db = PrivateVaultDatabase.getInstance(appContext)
            val repo = VaultRepository(db.vaultDao())
            val prefs = AppPreferencesRepository(appContext)
            val ota = OtaUpdateManager(appContext)
            return VaultViewModel(
                appContext = appContext,
                vaultRepository = repo,
                preferencesRepository = prefs,
                otaUpdateManager = ota
            ) as T
        }
    }
}

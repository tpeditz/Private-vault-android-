package com.example

import android.content.ActivityNotFoundException
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.data.ThemePreference
import com.example.ota.OtaUpdateManager
import com.example.security.VaultSessionManager
import com.example.ui.AboutVaultScreen
import com.example.ui.BackupAndRestoreScreen
import com.example.ui.NotesTabScreen
import com.example.ui.OtaThreeOptionUpdateDialog
import com.example.ui.OtaUpdatesScreen
import com.example.ui.PasswordsTabScreen
import com.example.ui.PrimaryTab
import com.example.ui.SecondaryDestination
import com.example.ui.SecurityAndDecoySettingsScreen
import com.example.ui.SettingsHubScreen
import com.example.ui.SetupVaultScreen
import com.example.ui.ToolsTabScreen
import com.example.ui.UnlockVaultScreen
import com.example.ui.VaultUiState
import com.example.ui.VaultViewModel
import com.example.ui.theme.PrivateVaultTheme
import kotlinx.coroutines.launch
import javax.crypto.Cipher

class MainActivity : FragmentActivity() {

    private val viewModel: VaultViewModel by viewModels {
        VaultViewModel.Factory(applicationContext)
    }

    private val screenOffReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == Intent.ACTION_SCREEN_OFF) {
                viewModel.onScreenTurnedOff()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // Default to FLAG_SECURE immediately at window creation before first frame (R09)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        val filter = IntentFilter(Intent.ACTION_SCREEN_OFF)
        ContextCompat.registerReceiver(
            this,
            screenOffReceiver,
            filter,
            ContextCompat.RECEIVER_NOT_EXPORTED
        )

        setContent {
            val uiState by viewModel.uiState.collectAsStateWithLifecycle()
            val preferences by viewModel.preferences.collectAsStateWithLifecycle()
            val otaState by viewModel.otaState.collectAsStateWithLifecycle()
            val clipboardCountdown by viewModel.clipboardCountdownSeconds.collectAsStateWithLifecycle()

            val useDarkTheme = when (preferences.themePreference) {
                ThemePreference.DARK_OBSIDIAN -> true
                ThemePreference.LIGHT_CLEAN -> false
                ThemePreference.SYSTEM -> isSystemInDarkTheme()
            }

            // R09 Fix: Enforce FLAG_SECURE unconditionally while locked/setup, and whenever
            // preferences.blockScreenshots is true.
            val isUnlocked = uiState.sessionState is VaultSessionManager.SessionState.Unlocked
            val shouldEnforceFlagSecure = !isUnlocked || preferences.blockScreenshots
            LaunchedEffect(shouldEnforceFlagSecure) {
                if (shouldEnforceFlagSecure) {
                    window.setFlags(
                        WindowManager.LayoutParams.FLAG_SECURE,
                        WindowManager.LayoutParams.FLAG_SECURE
                    )
                } else {
                    window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                }
            }

            // Observe ON_STOP / ON_START for immediate or timed auto-lock
            val lifecycleOwner = LocalLifecycleOwner.current
            DisposableEffect(lifecycleOwner) {
                val observer = LifecycleEventObserver { _, event ->
                    when (event) {
                        Lifecycle.Event.ON_STOP -> {
                            if (!isChangingConfigurations) {
                                viewModel.onAppBackgrounded()
                            }
                        }
                        Lifecycle.Event.ON_START -> {
                            viewModel.onAppForegrounded()
                        }
                        else -> {}
                    }
                }
                lifecycleOwner.lifecycle.addObserver(observer)
                onDispose {
                    lifecycleOwner.lifecycle.removeObserver(observer)
                }
            }

            PrivateVaultTheme(darkTheme = useDarkTheme) {
                // U03 Fix: Full-bleed root Surface matching theme background so keyboard transitions
                // never expose a raw black or white window backdrop.
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    PrivateVaultRootApp(
                        activity = this@MainActivity,
                        viewModel = viewModel,
                        uiState = uiState,
                        preferences = preferences,
                        otaState = otaState,
                        clipboardCountdown = clipboardCountdown
                    )
                }
            }
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) {
            viewModel.onWindowFocusRegained()
        }
    }

    override fun onDestroy() {
        try {
            unregisterReceiver(screenOffReceiver)
        } catch (_: Exception) {
        }
        super.onDestroy()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PrivateVaultRootApp(
    activity: FragmentActivity,
    viewModel: VaultViewModel,
    uiState: VaultUiState,
    preferences: com.example.data.VaultAppPreferences,
    otaState: OtaUpdateManager.OtaState,
    clipboardCountdown: Int?
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // U01 & U02 Fix: Register SAF document launchers at the top-level root composable so they
    // survive screen navigation, configuration changes, and file-picker lifecycle transitions!
    val createBackupDocumentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { destinationUri: Uri? ->
        viewModel.completeExportToUri(destinationUri)
    }

    val openRestoreDocumentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { sourceUri: Uri? ->
        viewModel.onRestoreFileSelected(sourceUri)
    }

    val launchCreateBackupPicker: (String) -> Unit = { suggestedFileName ->
        try {
            createBackupDocumentLauncher.launch(suggestedFileName)
        } catch (e: ActivityNotFoundException) {
            viewModel.setErrorBanner("No document picker app found on this device to save the backup file.")
        } catch (e: Exception) {
            viewModel.setErrorBanner("Could not open Save As dialog: ${e.message}")
        }
    }

    val launchOpenRestorePicker: () -> Unit = {
        try {
            openRestoreDocumentLauncher.launch(arrayOf("*/*"))
        } catch (e: ActivityNotFoundException) {
            viewModel.setErrorBanner("No file manager app found on this device to select a .pvault file.")
        } catch (e: Exception) {
            viewModel.setErrorBanner("Could not open file selector: ${e.message}")
        }
    }

    // Global 3-option OTA Update Available dialog ("Update Now", "Update Later", "Remind Me Later")
    val availableUpdateState = otaState as? OtaUpdateManager.OtaState.UpdateAvailable
    if (availableUpdateState != null && availableUpdateState.showPromptDialog) {
        OtaThreeOptionUpdateDialog(
            manifest = availableUpdateState.manifest,
            onUpdateNow = {
                viewModel.onOtaUpdateNowSelected(availableUpdateState.manifest)
            },
            onUpdateLater = {
                viewModel.onOtaUpdateLaterSelected()
            },
            onRemindMeLater = { reminderPolicy ->
                viewModel.onOtaRemindMeLaterSelected(
                    policy = reminderPolicy,
                    versionCode = availableUpdateState.manifest.versionCode
                )
            }
        )
    }

    // R14 Fix: If the user tapped "Update Now" while the vault is locked, show a locked-safe
    // progress/verification/install dialog so they can see progress and launch the installer
    // without unlocking!
    val isLocked = uiState.sessionState !is VaultSessionManager.SessionState.Unlocked
    if (isLocked) {
        LockedOtaStatusDialogIfActive(
            otaState = otaState,
            onInstallVerifiedApk = { apkFile ->
                try {
                    context.startActivity(viewModel.otaUpdateManager.buildInstallVerifiedApkIntent(apkFile))
                } catch (e: Exception) {
                    viewModel.setErrorBanner("Could not launch package installer: ${e.message}")
                }
            },
            onOpenUnknownSourcesSettings = {
                try {
                    context.startActivity(viewModel.otaUpdateManager.buildManageUnknownAppSourcesIntent())
                } catch (e: Exception) {
                    viewModel.setErrorBanner("Could not open Unknown App Sources settings: ${e.message}")
                }
            },
            onRetryDownload = { manifest ->
                viewModel.onOtaUpdateNowSelected(manifest)
            },
            onCancelDownload = {
                viewModel.cancelOtaDownload()
            },
            onDismissError = {
                viewModel.otaUpdateManager.dismissUpdatePrompt()
            }
        )
    }

    if (uiState.isLoading) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background),
            contentAlignment = Alignment.Center
        ) {
            CircularProgressIndicator()
        }
        return
    }

    if (!uiState.isVaultProvisioned) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background)
                .systemBarsPadding()
                .consumeWindowInsets(WindowInsets.systemBars)
        ) {
            StatusBannerStrip(
                statusMessage = uiState.statusBannerMessage,
                errorMessage = uiState.errorBannerMessage,
                clipboardCountdown = clipboardCountdown,
                onDismiss = viewModel::clearBanners
            )
            SetupVaultScreen(
                isBusy = uiState.isBusy,
                onCreateVault = { realPass, confirmReal, enableDecoy, decoyPass, confirmDecoy, seedSamples ->
                    viewModel.setupNewVault(
                        realPassword = realPass,
                        confirmRealPassword = confirmReal,
                        enableDecoy = enableDecoy,
                        decoyPassword = decoyPass,
                        confirmDecoyPassword = confirmDecoy,
                        seedStarterSamples = seedSamples
                    )
                }
            )
        }
        return
    }

    val unlockedSession = uiState.sessionState as? VaultSessionManager.SessionState.Unlocked
    if (unlockedSession == null) {
        val biometricHardwareAvailable = remember(context) {
            BiometricManager.from(context).canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG
            ) == BiometricManager.BIOMETRIC_SUCCESS
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background)
                .systemBarsPadding()
                .consumeWindowInsets(WindowInsets.systemBars)
        ) {
            StatusBannerStrip(
                statusMessage = uiState.statusBannerMessage,
                errorMessage = uiState.errorBannerMessage,
                clipboardCountdown = clipboardCountdown,
                onDismiss = viewModel::clearBanners
            )
            UnlockVaultScreen(
                isBusy = uiState.isBusy,
                isBiometricAvailable = uiState.isBiometricEnrolled && biometricHardwareAvailable,
                failedAttempts = uiState.failedUnlockAttempts,
                cooldownRemainingMs = uiState.unlockCooldownRemainingMs,
                lastKdfDurationMs = uiState.lastUnlockKdfDurationMs,
                onUnlockWithPassword = viewModel::unlockWithPassword,
                onRequestBiometricUnlock = {
                    scope.launch {
                        val cipher = viewModel.vaultRepository.getCipherForBiometricUnlock()
                        if (cipher != null) {
                            launchBiometricPrompt(
                                activity = activity,
                                title = "Unlock PRIVATE VAULT",
                                subtitle = "Verify your biometric credential to unwrap the vault key",
                                cipher = cipher,
                                onAuthenticated = { authCipher ->
                                    viewModel.completeBiometricUnlock(authCipher)
                                },
                                onError = { errMsg ->
                                    viewModel.setErrorBanner(errMsg)
                                }
                            )
                        } else {
                            viewModel.handleInvalidatedBiometricKey()
                        }
                    }
                }
            )
        }
        return
    }

    // Active Unlocked Vault Shell
    var topMenuExpanded by remember { mutableStateOf(false) }
    val isEditorOpen = uiState.activeNoteDraft != null || uiState.activeCredentialDraft != null
    val isToolsSelected = uiState.primaryTab == PrimaryTab.TOOLS ||
        uiState.primaryTab == PrimaryTab.GENERATOR ||
        uiState.primaryTab == PrimaryTab.STRENGTH_AUDIT

    BoxWithConstraints(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
    ) {
        val isWideLayout = maxWidth >= 640.dp

        Scaffold(
            modifier = Modifier.fillMaxSize(),
            containerColor = MaterialTheme.colorScheme.background,
            contentWindowInsets = WindowInsets.systemBars,
            topBar = {
                Column {
                    TopAppBar(
                        title = {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Shield,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary
                                )
                                Column {
                                    Text(
                                        text = "PRIVATE VAULT",
                                        style = MaterialTheme.typography.titleMedium,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Text(
                                        text = "Encrypted on this device • Offline",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        },
                        actions = {
                            // Immediate One-Tap Lock Button
                            IconButton(
                                onClick = { viewModel.lockVaultNow("Vault locked.") },
                                modifier = Modifier.testTag("top_lock_vault_button")
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Lock,
                                    contentDescription = "Lock Vault Immediately",
                                    tint = MaterialTheme.colorScheme.primary
                                )
                            }

                            Box {
                                IconButton(
                                    onClick = { topMenuExpanded = true },
                                    modifier = Modifier.testTag("top_overflow_menu_button")
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.MoreVert,
                                        contentDescription = "Vault Menu"
                                    )
                                }

                                DropdownMenu(
                                    expanded = topMenuExpanded,
                                    onDismissRequest = { topMenuExpanded = false }
                                ) {
                                    DropdownMenuItem(
                                        text = { Text("Backup & Restore (.pvault)") },
                                        leadingIcon = {
                                            Icon(Icons.Filled.SaveAlt, contentDescription = null)
                                        },
                                        onClick = {
                                            topMenuExpanded = false
                                            viewModel.openSecondaryDestination(SecondaryDestination.BACKUP_RESTORE)
                                        },
                                        modifier = Modifier.testTag("menu_backup_restore")
                                    )
                                    DropdownMenuItem(
                                        text = { Text("Security & Vault Settings") },
                                        leadingIcon = {
                                            Icon(Icons.Filled.Settings, contentDescription = null)
                                        },
                                        onClick = {
                                            topMenuExpanded = false
                                            viewModel.openSecondaryDestination(SecondaryDestination.SECURITY_SETTINGS)
                                        },
                                        modifier = Modifier.testTag("menu_security_settings")
                                    )
                                    DropdownMenuItem(
                                        text = { Text("Updates (OTA)") },
                                        leadingIcon = {
                                            Icon(Icons.Filled.SystemUpdate, contentDescription = null)
                                        },
                                        onClick = {
                                            topMenuExpanded = false
                                            viewModel.openSecondaryDestination(SecondaryDestination.OTA_UPDATES)
                                        },
                                        modifier = Modifier.testTag("menu_ota_updates")
                                    )
                                    DropdownMenuItem(
                                        text = { Text("About & Credits") },
                                        leadingIcon = {
                                            Icon(Icons.Filled.Info, contentDescription = null)
                                        },
                                        onClick = {
                                            topMenuExpanded = false
                                            viewModel.openSecondaryDestination(SecondaryDestination.ABOUT_CREDITS)
                                        },
                                        modifier = Modifier.testTag("menu_about_credits")
                                    )
                                }
                            }
                        },
                        colors = TopAppBarDefaults.topAppBarColors(
                            containerColor = MaterialTheme.colorScheme.surface
                        )
                    )

                    StatusBannerStrip(
                        statusMessage = uiState.statusBannerMessage,
                        errorMessage = uiState.errorBannerMessage,
                        clipboardCountdown = clipboardCountdown,
                        onDismiss = viewModel::clearBanners
                    )
                }
            },
            bottomBar = {
                // Section 06 / T15 Fix: Hide bottom NavigationBar when a full-screen Note or Credential
                // editor is open so the software keyboard does not stack 80.dp of navigation chrome above IME.
                if (!isWideLayout && uiState.secondaryDestination == SecondaryDestination.NONE && !isEditorOpen) {
                    NavigationBar {
                        NavigationBarItem(
                            selected = uiState.primaryTab == PrimaryTab.NOTES,
                            onClick = { viewModel.selectPrimaryTab(PrimaryTab.NOTES) },
                            icon = { Icon(Icons.Filled.Description, contentDescription = "Notes") },
                            label = { Text("Notes") },
                            modifier = Modifier.testTag("nav_tab_notes")
                        )
                        NavigationBarItem(
                            selected = uiState.primaryTab == PrimaryTab.PASSWORDS,
                            onClick = { viewModel.selectPrimaryTab(PrimaryTab.PASSWORDS) },
                            icon = { Icon(Icons.Filled.Key, contentDescription = "Passwords") },
                            label = { Text("Passwords") },
                            modifier = Modifier.testTag("nav_tab_passwords")
                        )
                        NavigationBarItem(
                            selected = isToolsSelected,
                            onClick = { viewModel.selectPrimaryTab(PrimaryTab.TOOLS) },
                            icon = { Icon(Icons.Filled.Refresh, contentDescription = "Tools") },
                            label = { Text("Tools") },
                            modifier = Modifier.testTag("nav_tab_tools")
                        )
                        NavigationBarItem(
                            selected = uiState.primaryTab == PrimaryTab.SETTINGS,
                            onClick = { viewModel.selectPrimaryTab(PrimaryTab.SETTINGS) },
                            icon = { Icon(Icons.Filled.Settings, contentDescription = "Settings") },
                            label = { Text("Settings") },
                            modifier = Modifier.testTag("nav_tab_settings")
                        )
                    }
                }
            }
        ) { innerPadding ->
            // U03 Fix: Consume outer Scaffold's innerPadding so nested screens and IME padding
            // never double-count system bar or keyboard insets!
            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.background)
                    .padding(innerPadding)
                    .consumeWindowInsets(innerPadding)
            ) {
                if (isWideLayout) {
                    NavigationRail(
                        modifier = Modifier.fillMaxHeight()
                    ) {
                        NavigationRailItem(
                            selected = uiState.secondaryDestination == SecondaryDestination.NONE &&
                                uiState.primaryTab == PrimaryTab.NOTES,
                            onClick = { viewModel.selectPrimaryTab(PrimaryTab.NOTES) },
                            icon = { Icon(Icons.Filled.Description, contentDescription = "Notes") },
                            label = { Text("Notes") }
                        )
                        NavigationRailItem(
                            selected = uiState.secondaryDestination == SecondaryDestination.NONE &&
                                uiState.primaryTab == PrimaryTab.PASSWORDS,
                            onClick = { viewModel.selectPrimaryTab(PrimaryTab.PASSWORDS) },
                            icon = { Icon(Icons.Filled.Key, contentDescription = "Passwords") },
                            label = { Text("Passwords") }
                        )
                        NavigationRailItem(
                            selected = uiState.secondaryDestination == SecondaryDestination.NONE &&
                                isToolsSelected,
                            onClick = { viewModel.selectPrimaryTab(PrimaryTab.TOOLS) },
                            icon = { Icon(Icons.Filled.Refresh, contentDescription = "Tools") },
                            label = { Text("Tools") }
                        )
                        NavigationRailItem(
                            selected = uiState.secondaryDestination == SecondaryDestination.NONE &&
                                uiState.primaryTab == PrimaryTab.SETTINGS,
                            onClick = { viewModel.selectPrimaryTab(PrimaryTab.SETTINGS) },
                            icon = { Icon(Icons.Filled.Settings, contentDescription = "Settings") },
                            label = { Text("Settings") }
                        )
                    }
                }

                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxHeight()
                        .background(MaterialTheme.colorScheme.background)
                ) {
                    when (uiState.secondaryDestination) {
                        SecondaryDestination.BACKUP_RESTORE -> {
                            BackupAndRestoreScreen(
                                uiState = uiState,
                                viewModel = viewModel,
                                onLaunchCreateBackupDocument = launchCreateBackupPicker,
                                onLaunchOpenRestoreDocument = launchOpenRestorePicker,
                                onBack = { viewModel.openSecondaryDestination(SecondaryDestination.NONE) }
                            )
                        }

                        SecondaryDestination.SECURITY_SETTINGS -> {
                            SecurityAndDecoySettingsScreen(
                                uiState = uiState,
                                preferences = preferences,
                                viewModel = viewModel,
                                onRequestBiometricEnrollment = {
                                    scope.launch {
                                        try {
                                            val cipher = viewModel.vaultRepository.getCipherForBiometricEnrollment(
                                                unlockedSession.sessionId
                                            )
                                            if (cipher != null) {
                                                launchBiometricPrompt(
                                                    activity = activity,
                                                    title = "Enable Biometric Quick-Unlock",
                                                    subtitle = "Confirm biometrics to wrap your vault key inside Android Keystore",
                                                    cipher = cipher,
                                                    onAuthenticated = { authCipher ->
                                                        viewModel.completeBiometricEnrollment(authCipher)
                                                    },
                                                    onError = { errMsg ->
                                                        viewModel.setErrorBanner(errMsg)
                                                    }
                                                )
                                            } else {
                                                viewModel.setErrorBanner(
                                                    "Biometric quick-unlock is not available on this device or configuration."
                                                )
                                            }
                                        } catch (e: Exception) {
                                            viewModel.setErrorBanner(e.message ?: "Biometric enrollment unavailable.")
                                        }
                                    }
                                },
                                onBack = { viewModel.openSecondaryDestination(SecondaryDestination.NONE) }
                            )
                        }

                        SecondaryDestination.OTA_UPDATES -> {
                            OtaUpdatesScreen(
                                otaState = otaState,
                                preferences = preferences,
                                viewModel = viewModel,
                                onBack = { viewModel.openSecondaryDestination(SecondaryDestination.NONE) }
                            )
                        }

                        SecondaryDestination.ABOUT_CREDITS -> {
                            AboutVaultScreen(
                                viewModel = viewModel,
                                onBack = { viewModel.openSecondaryDestination(SecondaryDestination.NONE) }
                            )
                        }

                        SecondaryDestination.NONE -> {
                            when (uiState.primaryTab) {
                                PrimaryTab.NOTES -> NotesTabScreen(
                                    uiState = uiState,
                                    viewModel = viewModel
                                )

                                PrimaryTab.PASSWORDS -> PasswordsTabScreen(
                                    uiState = uiState,
                                    viewModel = viewModel
                                )

                                PrimaryTab.TOOLS,
                                PrimaryTab.GENERATOR,
                                PrimaryTab.STRENGTH_AUDIT -> ToolsTabScreen(
                                    uiState = uiState,
                                    viewModel = viewModel
                                )

                                PrimaryTab.SETTINGS -> SettingsHubScreen(
                                    uiState = uiState,
                                    preferences = preferences,
                                    otaState = otaState,
                                    viewModel = viewModel
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LockedOtaStatusDialogIfActive(
    otaState: OtaUpdateManager.OtaState,
    onInstallVerifiedApk: (java.io.File) -> Unit,
    onOpenUnknownSourcesSettings: () -> Unit,
    onRetryDownload: (OtaUpdateManager.UpdateManifest) -> Unit,
    onCancelDownload: () -> Unit,
    onDismissError: () -> Unit
) {
    when (otaState) {
        is OtaUpdateManager.OtaState.Downloading -> {
            val fraction = if (otaState.totalBytes > 0L) {
                (otaState.bytesDownloaded.toFloat() / otaState.totalBytes.toFloat()).coerceIn(0f, 1f)
            } else {
                0f
            }
            AlertDialog(
                onDismissRequest = {},
                icon = { Icon(Icons.Filled.SystemUpdate, contentDescription = null) },
                title = { Text("Downloading v${otaState.manifest.versionName}…") },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        LinearProgressIndicator(
                            progress = { fraction },
                            modifier = Modifier.fillMaxWidth()
                        )
                        Text(
                            text = "${otaState.bytesDownloaded / 1024} KB / ${otaState.totalBytes / 1024} KB",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                },
                confirmButton = {},
                dismissButton = {
                    TextButton(
                        onClick = onCancelDownload,
                        modifier = Modifier.testTag("locked_ota_cancel_download_button")
                    ) {
                        Text("Cancel Download")
                    }
                }
            )
        }

        is OtaUpdateManager.OtaState.Verifying -> {
            AlertDialog(
                onDismissRequest = {},
                icon = { CircularProgressIndicator(modifier = Modifier.size(28.dp)) },
                title = { Text("Verifying APK Signature…") },
                text = {
                    Text(
                        "Checking SHA-256 checksum, Android apksig signature scheme, and trusted signer match."
                    )
                },
                confirmButton = {}
            )
        }

        is OtaUpdateManager.OtaState.ReadyToInstall -> {
            AlertDialog(
                onDismissRequest = onDismissError,
                icon = {
                    Icon(
                        Icons.Filled.CheckCircle,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.secondary
                    )
                },
                title = { Text("Verified Update Ready") },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(
                            "Version ${otaState.manifest.versionName} passed SHA-256 and trusted signer verification."
                        )
                        Text(
                            "Signer SHA-256: ${otaState.signerCertificateSha256.take(24)}…",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                confirmButton = {
                    Button(
                        onClick = { onInstallVerifiedApk(otaState.verifiedApkFile) },
                        modifier = Modifier.testTag("locked_ota_install_button")
                    ) {
                        Text("Confirm Installation")
                    }
                },
                dismissButton = {
                    TextButton(onClick = onDismissError) {
                        Text("Later")
                    }
                }
            )
        }

        is OtaUpdateManager.OtaState.NeedsUnknownSourcesPermission -> {
            AlertDialog(
                onDismissRequest = onDismissError,
                icon = { Icon(Icons.Filled.Build, contentDescription = null) },
                title = { Text("Allow Update Installation") },
                text = {
                    Text(
                        "The update APK is verified and ready. Enable 'Install unknown apps' for PRIVATE VAULT in Android Settings, then return here to install."
                    )
                },
                confirmButton = {
                    Button(onClick = onOpenUnknownSourcesSettings) {
                        Text("Open Android Settings")
                    }
                },
                dismissButton = {
                    TextButton(onClick = onDismissError) {
                        Text("Later")
                    }
                }
            )
        }

        is OtaUpdateManager.OtaState.Error -> {
            if (otaState.recoverableManifest != null) {
                AlertDialog(
                    onDismissRequest = onDismissError,
                    icon = {
                        Icon(
                            Icons.Filled.Warning,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.error
                        )
                    },
                    title = { Text(otaState.title) },
                    text = { Text(otaState.detail) },
                    confirmButton = {
                        OutlinedButton(onClick = { onRetryDownload(otaState.recoverableManifest) }) {
                            Text("Retry Update")
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = onDismissError) {
                            Text("Close")
                        }
                    }
                )
            }
        }

        else -> {}
    }
}

@Composable
private fun StatusBannerStrip(
    statusMessage: String?,
    errorMessage: String?,
    clipboardCountdown: Int?,
    onDismiss: () -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        AnimatedVisibility(visible = clipboardCountdown != null) {
            Surface(
                color = MaterialTheme.colorScheme.secondaryContainer,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Sensitive clipboard active • Auto-clearing in ${clipboardCountdown ?: 0}s",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                }
            }
        }

        AnimatedVisibility(visible = errorMessage != null || statusMessage != null) {
            val isError = errorMessage != null
            val containerColor = if (isError) {
                MaterialTheme.colorScheme.errorContainer
            } else {
                MaterialTheme.colorScheme.primaryContainer
            }
            val contentColor = if (isError) {
                MaterialTheme.colorScheme.onErrorContainer
            } else {
                MaterialTheme.colorScheme.onPrimaryContainer
            }

            Surface(
                color = containerColor,
                shape = RoundedCornerShape(0.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(if (isError) "error_banner" else "status_banner")
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = errorMessage ?: statusMessage.orEmpty(),
                        style = MaterialTheme.typography.bodySmall,
                        color = contentColor,
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    IconButton(
                        onClick = onDismiss,
                        modifier = Modifier.size(32.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Close,
                            contentDescription = "Dismiss Banner",
                            tint = contentColor,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
            }
        }
    }
}

private fun launchBiometricPrompt(
    activity: FragmentActivity,
    title: String,
    subtitle: String,
    cipher: Cipher,
    onAuthenticated: (Cipher) -> Unit,
    onError: (String) -> Unit
) {
    val executor = ContextCompat.getMainExecutor(activity)
    val prompt = BiometricPrompt(
        activity,
        executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                val authenticatedCipher = result.cryptoObject?.cipher
                if (authenticatedCipher != null) {
                    onAuthenticated(authenticatedCipher)
                } else {
                    onError("Biometric cipher was not returned. Please unlock with your password.")
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                if (errorCode != BiometricPrompt.ERROR_USER_CANCELED &&
                    errorCode != BiometricPrompt.ERROR_NEGATIVE_BUTTON &&
                    errorCode != BiometricPrompt.ERROR_CANCELED
                ) {
                    onError("Biometric authentication unavailable: $errString")
                }
            }
        }
    )

    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setSubtitle(subtitle)
        .setNegativeButtonText("Use Password")
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .build()

    prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
}

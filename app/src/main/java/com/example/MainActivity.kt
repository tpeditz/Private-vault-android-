package com.example

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.Backup
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.outlined.AutoFixHigh
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import com.example.ota.OtaUpdateManager
import com.example.security.VaultSessionManager
import com.example.ui.AboutVaultScreen
import com.example.ui.BackupAndRestoreScreen
import com.example.ui.GeneratorTabScreen
import com.example.ui.NotesTabScreen
import com.example.ui.OtaThreeOptionUpdateDialog
import com.example.ui.OtaUpdatesScreen
import com.example.ui.PasswordsTabScreen
import com.example.ui.PrimaryVaultTab
import com.example.ui.SecondaryDestination
import com.example.ui.SecurityAndDecoySettingsScreen
import com.example.ui.SetupVaultScreen
import com.example.ui.StrengthCheckTabScreen
import com.example.ui.UnlockVaultScreen
import com.example.ui.VaultUiState
import com.example.ui.VaultViewModel
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.PrivateVaultTheme
import kotlinx.coroutines.launch

class MainActivity : FragmentActivity() {

    private val viewModel: VaultViewModel by viewModels {
        VaultViewModel.Factory(applicationContext)
    }

    private val screenOffReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == Intent.ACTION_SCREEN_OFF) {
                viewModel.lockVaultNow()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Enforce FLAG_SECURE by default before rendering any secret UI (Section 16)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        enableEdgeToEdge()

        val filter = IntentFilter(Intent.ACTION_SCREEN_OFF)
        ContextCompat.registerReceiver(
            this,
            screenOffReceiver,
            filter,
            ContextCompat.RECEIVER_NOT_EXPORTED
        )

        setContent {
            val uiState by viewModel.uiState.collectAsStateWithLifecycle()
            val sessionState by viewModel.sessionState.collectAsStateWithLifecycle()
            val settingsState by viewModel.settingsState.collectAsStateWithLifecycle()
            val otaState by viewModel.otaState.collectAsStateWithLifecycle()
            val clipboardSeconds by viewModel.clipboardRemainingSeconds.collectAsStateWithLifecycle()

            LaunchedEffect(settingsState.blockScreenshots) {
                if (settingsState.blockScreenshots) {
                    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                } else {
                    window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                }
            }

            PrivateVaultTheme(themeMode = settingsState.themeMode) {
                // Global 3-Option OTA Update Prompt Dialog (Update Now | Update Later | Remind Me Later)
                val availableUpdate = otaState as? OtaUpdateManager.OtaUiState.UpdateAvailable
                if (availableUpdate != null && availableUpdate.showPromptDialog) {
                    OtaThreeOptionUpdateDialog(
                        manifest = availableUpdate.manifest,
                        advisoryWarning = availableUpdate.advisorySupportWarning,
                        onUpdateNow = {
                            viewModel.chooseUpdateNow(availableUpdate.manifest)
                            if (sessionState is VaultSessionManager.SessionState.Unlocked) {
                                viewModel.openSecondaryDestination(SecondaryDestination.UPDATES)
                            }
                        },
                        onUpdateLater = {
                            viewModel.chooseUpdateLater()
                        },
                        onRemindMeLater = { deferralOption ->
                            viewModel.chooseRemindMeLater(availableUpdate.manifest, deferralOption)
                        }
                    )
                }

                when {
                    uiState.isLoadingInitialization -> {
                        Box(
                            modifier = Modifier.fillMaxSize(),
                            contentAlignment = Alignment.Center
                        ) {
                            CircularProgressIndicator()
                        }
                    }

                    !uiState.isVaultInitialized -> {
                        SetupVaultScreen(
                            uiState = uiState,
                            onCompleteSetup = viewModel::setupInitialVault
                        )
                    }

                    sessionState is VaultSessionManager.SessionState.Locked -> {
                        UnlockVaultScreen(
                            uiState = uiState,
                            onUnlockWithPassword = viewModel::unlockVault,
                            onTriggerBiometricUnlock = {
                                launchBiometricUnlockPrompt()
                            }
                        )
                    }

                    sessionState is VaultSessionManager.SessionState.Unlocked -> {
                        AuthenticatedVaultShell(
                            uiState = uiState,
                            sessionState = sessionState,
                            settingsState = settingsState,
                            otaState = otaState,
                            clipboardRemainingSeconds = clipboardSeconds,
                            viewModel = viewModel,
                            onRequestBiometricEnrollment = {
                                launchBiometricEnrollmentPrompt()
                            },
                            onLaunchExternalIntent = { intent ->
                                try {
                                    startActivity(intent)
                                } catch (_: Exception) {
                                }
                            }
                        )
                    }
                }
            }
        }
    }

    override fun onStop() {
        super.onStop()
        viewModel.sessionManager.onAppBackgrounded()
    }

    override fun onStart() {
        super.onStart()
        val timeoutMs = viewModel.settingsState.value.autoLockTimeoutMs
        val locked = viewModel.sessionManager.onAppForegrounded(timeoutMs)
        if (locked) {
            viewModel.clipboardManager.clearIfStillOwned()
        }
    }

    override fun onDestroy() {
        try {
            unregisterReceiver(screenOffReceiver)
        } catch (_: Exception) {
        }
        super.onDestroy()
    }

    private fun launchBiometricEnrollmentPrompt() {
        try {
            val cipher = viewModel.biometricKeystoreManager.createEncryptionCipherForBiometricEnrollment()
            val executor = ContextCompat.getMainExecutor(this)
            val prompt = BiometricPrompt(
                this,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val authedCipher = result.cryptoObject?.cipher ?: return
                        viewModel.completeBiometricEnrollment(authedCipher)
                    }
                }
            )
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Enable Biometric Vault Unlock")
                .setSubtitle("Bind hardware-backed Keystore encryption key to your biometric credential")
                .setNegativeButtonText("Cancel")
                .build()
            prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        } catch (_: Exception) {
        }
    }

    private fun launchBiometricUnlockPrompt() {
        lifecycleScope.launch {
            try {
                val iv = viewModel.getRealVaultBiometricNonce() ?: return@launch
                val cipher = viewModel.biometricKeystoreManager.createDecryptionCipher(iv)
                val executor = ContextCompat.getMainExecutor(this@MainActivity)
                val prompt = BiometricPrompt(
                    this@MainActivity,
                    executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            val authedCipher = result.cryptoObject?.cipher ?: return
                            viewModel.unlockWithAuthenticatedBiometricCipher(authedCipher)
                        }
                    }
                )
                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Unlock PRIVATE VAULT")
                    .setSubtitle("Authenticate to unwrap your encrypted vault key")
                    .setNegativeButtonText("Use Master Password")
                    .build()
                prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
            } catch (_: Exception) {
                // If biometric key was invalidated (e.g. new fingerprint enrolled), fall back safely to master password
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuthenticatedVaultShell(
    uiState: VaultUiState,
    sessionState: VaultSessionManager.SessionState,
    settingsState: com.example.data.AppPreferencesRepository.AppSettingsState,
    otaState: OtaUpdateManager.OtaUiState,
    clipboardRemainingSeconds: Int,
    viewModel: VaultViewModel,
    onRequestBiometricEnrollment: () -> Unit,
    onLaunchExternalIntent: (Intent) -> Unit
) {
    var showOverflowMenu by remember { mutableStateOf(false) }

    BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
        val isWideScreen = maxWidth >= 600.dp

        Scaffold(
            contentWindowInsets = WindowInsets.safeDrawing,
            topBar = {
                Column {
                    TopAppBar(
                        colors = TopAppBarDefaults.topAppBarColors(
                            containerColor = MaterialTheme.colorScheme.surface
                        ),
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
                                Text(
                                    text = "PRIVATE VAULT",
                                    style = MaterialTheme.typography.titleLarge
                                )
                            }
                        },
                        actions = {
                            // Visible Instant Lock Action (Section 05 & 13)
                            IconButton(
                                onClick = viewModel::lockVaultNow,
                                modifier = Modifier.testTag("top_bar_lock_button")
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Lock,
                                    contentDescription = "Lock Vault Immediately",
                                    tint = MaterialTheme.colorScheme.primary
                                )
                            }

                            Box {
                                IconButton(
                                    onClick = { showOverflowMenu = true },
                                    modifier = Modifier.testTag("top_bar_overflow_menu_button")
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.MoreVert,
                                        contentDescription = "More tools & settings"
                                    )
                                }

                                DropdownMenu(
                                    expanded = showOverflowMenu,
                                    onDismissRequest = { showOverflowMenu = false }
                                ) {
                                    DropdownMenuItem(
                                        text = { Text("Backup & Restore") },
                                        leadingIcon = {
                                            Icon(imageVector = Icons.Filled.Backup, contentDescription = null)
                                        },
                                        onClick = {
                                            showOverflowMenu = false
                                            viewModel.openSecondaryDestination(SecondaryDestination.BACKUP_RESTORE)
                                        },
                                        modifier = Modifier.testTag("menu_backup_restore")
                                    )
                                    DropdownMenuItem(
                                        text = { Text("Security & Settings") },
                                        leadingIcon = {
                                            Icon(imageVector = Icons.Filled.Security, contentDescription = null)
                                        },
                                        onClick = {
                                            showOverflowMenu = false
                                            viewModel.openSecondaryDestination(SecondaryDestination.SECURITY_DECOY)
                                        },
                                        modifier = Modifier.testTag("menu_security_settings")
                                    )
                                    DropdownMenuItem(
                                        text = { Text("Updates (OTA)") },
                                        leadingIcon = {
                                            Icon(imageVector = Icons.Filled.SystemUpdate, contentDescription = null)
                                        },
                                        onClick = {
                                            showOverflowMenu = false
                                            viewModel.openSecondaryDestination(SecondaryDestination.UPDATES)
                                        },
                                        modifier = Modifier.testTag("menu_ota_updates")
                                    )
                                    DropdownMenuItem(
                                        text = { Text("About PRIVATE VAULT") },
                                        leadingIcon = {
                                            Icon(imageVector = Icons.Filled.Info, contentDescription = null)
                                        },
                                        onClick = {
                                            showOverflowMenu = false
                                            viewModel.openSecondaryDestination(SecondaryDestination.ABOUT)
                                        },
                                        modifier = Modifier.testTag("menu_about")
                                    )
                                }
                            }
                        }
                    )

                    // Sensitive Clipboard Countdown Banner (never displays the secret itself - Section 16)
                    if (clipboardRemainingSeconds > 0) {
                        Surface(
                            color = MaterialTheme.colorScheme.secondaryContainer,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp, vertical = 6.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "Secret copied (marked sensitive) • Auto-clearing in ${clipboardRemainingSeconds}s",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = JetBrainsMonoFontFamily,
                                    color = MaterialTheme.colorScheme.onSecondaryContainer
                                )
                            }
                        }
                    }
                }
            },
            bottomBar = {
                if (!isWideScreen && uiState.secondaryDestination == SecondaryDestination.NONE) {
                    NavigationBar {
                        NavigationBarItem(
                            selected = uiState.selectedTab == PrimaryVaultTab.NOTES,
                            onClick = { viewModel.selectPrimaryTab(PrimaryVaultTab.NOTES) },
                            icon = {
                                Icon(
                                    imageVector = if (uiState.selectedTab == PrimaryVaultTab.NOTES) {
                                        Icons.Filled.Description
                                    } else {
                                        Icons.Outlined.Description
                                    },
                                    contentDescription = "Notes"
                                )
                            },
                            label = { Text("Notes") },
                            modifier = Modifier.testTag("nav_tab_notes")
                        )

                        NavigationBarItem(
                            selected = uiState.selectedTab == PrimaryVaultTab.PASSWORDS,
                            onClick = { viewModel.selectPrimaryTab(PrimaryVaultTab.PASSWORDS) },
                            icon = {
                                Icon(
                                    imageVector = if (uiState.selectedTab == PrimaryVaultTab.PASSWORDS) {
                                        Icons.Filled.Key
                                    } else {
                                        Icons.Outlined.Key
                                    },
                                    contentDescription = "Passwords"
                                )
                            },
                            label = { Text("Passwords") },
                            modifier = Modifier.testTag("nav_tab_passwords")
                        )

                        NavigationBarItem(
                            selected = uiState.selectedTab == PrimaryVaultTab.GENERATOR,
                            onClick = { viewModel.selectPrimaryTab(PrimaryVaultTab.GENERATOR) },
                            icon = {
                                Icon(
                                    imageVector = if (uiState.selectedTab == PrimaryVaultTab.GENERATOR) {
                                        Icons.Filled.AutoFixHigh
                                    } else {
                                        Icons.Outlined.AutoFixHigh
                                    },
                                    contentDescription = "Generator"
                                )
                            },
                            label = { Text("Generator") },
                            modifier = Modifier.testTag("nav_tab_generator")
                        )

                        NavigationBarItem(
                            selected = uiState.selectedTab == PrimaryVaultTab.STRENGTH_CHECK,
                            onClick = { viewModel.selectPrimaryTab(PrimaryVaultTab.STRENGTH_CHECK) },
                            icon = {
                                Icon(
                                    imageVector = if (uiState.selectedTab == PrimaryVaultTab.STRENGTH_CHECK) {
                                        Icons.Filled.Security
                                    } else {
                                        Icons.Outlined.Security
                                    },
                                    contentDescription = "Strength Check"
                                )
                            },
                            label = { Text("Strength Check") },
                            modifier = Modifier.testTag("nav_tab_strength")
                        )
                    }
                }
            }
        ) { innerPadding ->
            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) {
                if (isWideScreen && uiState.secondaryDestination == SecondaryDestination.NONE) {
                    NavigationRail {
                        NavigationRailItem(
                            selected = uiState.selectedTab == PrimaryVaultTab.NOTES,
                            onClick = { viewModel.selectPrimaryTab(PrimaryVaultTab.NOTES) },
                            icon = { Icon(Icons.Filled.Description, contentDescription = "Notes") },
                            label = { Text("Notes") }
                        )
                        NavigationRailItem(
                            selected = uiState.selectedTab == PrimaryVaultTab.PASSWORDS,
                            onClick = { viewModel.selectPrimaryTab(PrimaryVaultTab.PASSWORDS) },
                            icon = { Icon(Icons.Filled.Key, contentDescription = "Passwords") },
                            label = { Text("Passwords") }
                        )
                        NavigationRailItem(
                            selected = uiState.selectedTab == PrimaryVaultTab.GENERATOR,
                            onClick = { viewModel.selectPrimaryTab(PrimaryVaultTab.GENERATOR) },
                            icon = { Icon(Icons.Filled.AutoFixHigh, contentDescription = "Generator") },
                            label = { Text("Generator") }
                        )
                        NavigationRailItem(
                            selected = uiState.selectedTab == PrimaryVaultTab.STRENGTH_CHECK,
                            onClick = { viewModel.selectPrimaryTab(PrimaryVaultTab.STRENGTH_CHECK) },
                            icon = { Icon(Icons.Filled.Security, contentDescription = "Strength Check") },
                            label = { Text("Strength Check") }
                        )
                    }
                }

                Box(modifier = Modifier.fillMaxSize()) {
                    when (uiState.secondaryDestination) {
                        SecondaryDestination.BACKUP_RESTORE -> {
                            BackupAndRestoreScreen(
                                uiState = uiState,
                                viewModel = viewModel,
                                onBack = { viewModel.openSecondaryDestination(SecondaryDestination.NONE) }
                            )
                        }

                        SecondaryDestination.SECURITY_DECOY -> {
                            SecurityAndDecoySettingsScreen(
                                uiState = uiState,
                                settingsState = settingsState,
                                sessionState = sessionState,
                                viewModel = viewModel,
                                onRequestBiometricEnrollmentPrompt = onRequestBiometricEnrollment,
                                onBack = { viewModel.openSecondaryDestination(SecondaryDestination.NONE) }
                            )
                        }

                        SecondaryDestination.UPDATES -> {
                            OtaUpdatesScreen(
                                settingsState = settingsState,
                                otaState = otaState,
                                viewModel = viewModel,
                                onLaunchInstallerIntent = onLaunchExternalIntent,
                                onBack = { viewModel.openSecondaryDestination(SecondaryDestination.NONE) }
                            )
                        }

                        SecondaryDestination.ABOUT -> {
                            AboutVaultScreen(
                                viewModel = viewModel,
                                onNavigateToUpdates = {
                                    viewModel.openSecondaryDestination(SecondaryDestination.UPDATES)
                                },
                                onBack = { viewModel.openSecondaryDestination(SecondaryDestination.NONE) }
                            )
                        }

                        SecondaryDestination.NONE -> {
                            when (uiState.selectedTab) {
                                PrimaryVaultTab.NOTES -> NotesTabScreen(uiState = uiState, viewModel = viewModel)
                                PrimaryVaultTab.PASSWORDS -> PasswordsTabScreen(uiState = uiState, viewModel = viewModel)
                                PrimaryVaultTab.GENERATOR -> GeneratorTabScreen(uiState = uiState, viewModel = viewModel)
                                PrimaryVaultTab.STRENGTH_CHECK -> StrengthCheckTabScreen(uiState = uiState, viewModel = viewModel)
                            }
                        }
                    }
                }
            }
        }
    }
}

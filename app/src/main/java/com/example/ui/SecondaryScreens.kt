package com.example.ui

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.Backup
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.LockReset
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.example.BuildConfig
import com.example.data.AppPreferencesRepository
import com.example.data.PortableBackupEngine
import com.example.ota.OtaUpdateManager
import com.example.security.BiometricKeystoreManager
import com.example.security.CryptoEngine
import com.example.security.VaultSessionManager
import com.example.ui.theme.AppThemeMode
import com.example.ui.theme.JetBrainsMonoFontFamily
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// =============================================================================================
// 1. THREE-OPTION OTA UPDATE PROMPT DIALOG (Update Now | Update Later | Remind Me Later)
// =============================================================================================

@Composable
fun OtaThreeOptionUpdateDialog(
    manifest: OtaUpdateManager.OtaManifest,
    advisoryWarning: String?,
    onUpdateNow: () -> Unit,
    onUpdateLater: () -> Unit,
    onRemindMeLater: (OtaDeferralOption) -> Unit
) {
    var showReminderPicker by remember { mutableStateOf(false) }
    var selectedDeferral by remember { mutableStateOf(OtaDeferralOption.TOMORROW) }

    AlertDialog(
        onDismissRequest = onUpdateLater,
        icon = {
            Icon(
                imageVector = Icons.Filled.SystemUpdate,
                contentDescription = "Update Available",
                tint = MaterialTheme.colorScheme.primary
            )
        },
        title = {
            Text(
                text = if (!showReminderPicker) {
                    "Update Available: v${manifest.versionName}"
                } else {
                    "Remind Me Later"
                },
                modifier = Modifier.testTag("ota_dialog_title")
            )
        },
        text = {
            if (!showReminderPicker) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "Installed: v${BuildConfig.VERSION_NAME} (code ${BuildConfig.VERSION_CODE}) → Latest: v${manifest.versionName} (code ${manifest.versionCode})",
                        style = MaterialTheme.typography.labelMedium,
                        fontFamily = JetBrainsMonoFontFamily,
                        color = MaterialTheme.colorScheme.primary
                    )

                    if (advisoryWarning != null) {
                        Surface(
                            color = MaterialTheme.colorScheme.secondaryContainer,
                            shape = MaterialTheme.shapes.extraSmall
                        ) {
                            Text(
                                text = advisoryWarning,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSecondaryContainer,
                                modifier = Modifier.padding(8.dp)
                            )
                        }
                    }

                    Text(
                        text = "Release Notes:",
                        style = MaterialTheme.typography.labelLarge
                    )
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        shape = MaterialTheme.shapes.small,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = manifest.releaseNotes.ifBlank { "Security and stability improvements." },
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(10.dp)
                        )
                    }

                    Text(
                        text = "No download starts unless you choose Update Now. Your Real and Decoy vaults remain intact and accessible offline.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "When should PRIVATE VAULT remind you about v${manifest.versionName}?",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    OtaDeferralOption.entries.forEach { option ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp)
                        ) {
                            RadioButton(
                                selected = selectedDeferral == option,
                                onClick = { selectedDeferral = option },
                                modifier = Modifier.testTag("ota_remind_radio_${option.name.lowercase()}")
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Column {
                                Text(
                                    text = option.label,
                                    style = MaterialTheme.typography.titleSmall
                                )
                                Text(
                                    text = option.description,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            if (!showReminderPicker) {
                Button(
                    onClick = onUpdateNow,
                    modifier = Modifier.testTag("ota_update_now_button")
                ) {
                    Icon(imageVector = Icons.Filled.CloudDownload, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Update Now")
                }
            } else {
                Button(
                    onClick = { onRemindMeLater(selectedDeferral) },
                    modifier = Modifier.testTag("ota_confirm_reminder_button")
                ) {
                    Icon(imageVector = Icons.Filled.Schedule, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Save Reminder")
                }
            }
        },
        dismissButton = {
            if (!showReminderPicker) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    TextButton(
                        onClick = { showReminderPicker = true },
                        modifier = Modifier.testTag("ota_remind_me_later_button")
                    ) {
                        Text("Remind Me Later")
                    }
                    OutlinedButton(
                        onClick = onUpdateLater,
                        modifier = Modifier.testTag("ota_update_later_button")
                    ) {
                        Text("Update Later")
                    }
                }
            } else {
                TextButton(onClick = { showReminderPicker = false }) {
                    Text("Back")
                }
            }
        }
    )
}

// =============================================================================================
// 2. ENCRYPTED PORTABLE BACKUP & RESTORE SCREEN (Section 17)
// =============================================================================================

@Composable
fun BackupAndRestoreScreen(
    uiState: VaultUiState,
    viewModel: VaultViewModel,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    var exportPassword by remember { mutableStateOf("") }
    var confirmExportPassword by remember { mutableStateOf("") }
    var selectedScope by remember { mutableStateOf(PortableBackupEngine.ExportScope.ALL) }

    var restorePassword by remember { mutableStateOf("") }
    var selectedRestoreUri by remember { mutableStateOf<Uri?>(null) }
    var selectedRestoreMode by remember { mutableStateOf(PortableBackupEngine.RestoreMode.MERGE_KEEP_NEWEST) }

    val createDocumentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri: Uri? ->
        val outStream = uri?.let { context.contentResolver.openOutputStream(it) }
        viewModel.writePendingBackupToStream(outStream)
    }

    val openDocumentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        selectedRestoreUri = uri
    }

    BackHandler(onBack = onBack)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            IconButton(onClick = onBack) {
                Icon(imageVector = Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
            }
            Text(
                text = "Encrypted Manual Backup & Restore",
                style = MaterialTheme.typography.headlineMedium
            )
        }

        Surface(
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.65f),
            shape = MaterialTheme.shapes.small,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = "Vault-Scoped Portable Format (.pvault): Exports only the currently unlocked vault session using a fresh 128-bit salt, Argon2id key derivation, and AES-256-GCM authenticated encryption. Backup passwords can differ from your live master password. Changing your master password later does not alter previously exported backup files.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(12.dp)
            )
        }

        if (uiState.backupStatusMessage != null) {
            Surface(
                color = MaterialTheme.colorScheme.primaryContainer,
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = uiState.backupStatusMessage,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }

        if (uiState.backupErrorMessage != null) {
            Surface(
                color = MaterialTheme.colorScheme.errorContainer,
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = uiState.backupErrorMessage,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }

        // Export Card
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(imageVector = Icons.Filled.Backup, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Text(text = "Export Encrypted Backup (.pvault)", style = MaterialTheme.typography.titleMedium)
                }

                PortableBackupEngine.ExportScope.entries.forEach { scope ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        RadioButton(
                            selected = selectedScope == scope,
                            onClick = { selectedScope = scope }
                        )
                        Text(text = scope.label, style = MaterialTheme.typography.bodyMedium)
                    }
                }

                OutlinedTextField(
                    value = exportPassword,
                    onValueChange = { exportPassword = it },
                    label = { Text("Dedicated Backup Password (min 8 chars)") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.None,
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.Password
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("backup_export_password_input")
                )

                OutlinedTextField(
                    value = confirmExportPassword,
                    onValueChange = { confirmExportPassword = it },
                    label = { Text("Confirm Backup Password") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.None,
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.Password
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("backup_confirm_export_password_input")
                )

                Button(
                    onClick = {
                        val stamp = SimpleDateFormat("yyyyMMdd_HHmm", Locale.US).format(Date())
                        viewModel.prepareBackupForExport(
                            backupPassword = exportPassword,
                            confirmBackupPassword = confirmExportPassword,
                            scope = selectedScope,
                            onReadyToPickDestination = {
                                exportPassword = ""
                                confirmExportPassword = ""
                                createDocumentLauncher.launch("private_vault_backup_$stamp.pvault")
                            }
                        )
                    },
                    enabled = !uiState.isBackupOperationInProgress && exportPassword.length >= 8,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("backup_export_button")
                ) {
                    Text("Encrypt & Choose Export Location")
                }
            }
        }

        // Restore Card
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(imageVector = Icons.Filled.Restore, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Text(text = "Restore Encrypted Backup", style = MaterialTheme.typography.titleMedium)
                }

                OutlinedButton(
                    onClick = {
                        viewModel.beginRestoreFileSelection()
                        openDocumentLauncher.launch(arrayOf("*/*"))
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("backup_select_restore_file_button")
                ) {
                    Text(
                        if (selectedRestoreUri != null) {
                            "Selected File: ${selectedRestoreUri?.lastPathSegment ?: "backup.pvault"}"
                        } else {
                            "1. Select .pvault Backup File"
                        }
                    )
                }

                OutlinedTextField(
                    value = restorePassword,
                    onValueChange = { restorePassword = it },
                    label = { Text("2. Enter Backup File Password") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.None,
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.Password
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("backup_restore_password_input")
                )

                Button(
                    onClick = {
                        val uri = selectedRestoreUri ?: return@Button
                        val stream = context.contentResolver.openInputStream(uri)
                        viewModel.verifyBackupForRestorePreview(stream, restorePassword)
                        restorePassword = ""
                    },
                    enabled = selectedRestoreUri != null && restorePassword.isNotEmpty() && !uiState.isBackupOperationInProgress,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("backup_verify_preview_button")
                ) {
                    Text("Verify & Preview Backup Contents")
                }

                // Verified Restore Preview Box
                val preview = uiState.verifiedBackupPreview
                if (preview != null) {
                    HorizontalDivider()
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        shape = MaterialTheme.shapes.medium,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Text(
                                text = "Authenticated Backup Preview",
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.primary
                            )
                            Text(
                                text = "• Private Notes: ${preview.notesCount}\n" +
                                    "• Saved Credentials: ${preview.credentialsCount}\n" +
                                    "• Folders: ${preview.foldersCount}\n" +
                                    "• Scope: ${preview.exportScope.label}",
                                style = MaterialTheme.typography.bodySmall
                            )

                            PortableBackupEngine.RestoreMode.entries.forEach { mode ->
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    RadioButton(
                                        selected = selectedRestoreMode == mode,
                                        onClick = { selectedRestoreMode = mode }
                                    )
                                    Column {
                                        Text(text = mode.label, style = MaterialTheme.typography.titleSmall)
                                        Text(
                                            text = mode.description,
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                OutlinedButton(
                                    onClick = viewModel::cancelRestorePreview,
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text("Cancel")
                                }
                                Button(
                                    onClick = {
                                        viewModel.confirmRestoreFromPreview(selectedRestoreMode)
                                    },
                                    modifier = Modifier
                                        .weight(1f)
                                        .testTag("backup_confirm_restore_button")
                                ) {
                                    Text("Confirm Restore")
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// =============================================================================================
// 3. SECURITY, DECOY VAULT, BIOMETRICS & KDF BENCHMARK SCREEN (Sections 11–16)
// =============================================================================================

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SecurityAndDecoySettingsScreen(
    uiState: VaultUiState,
    settingsState: AppPreferencesRepository.AppSettingsState,
    sessionState: VaultSessionManager.SessionState,
    viewModel: VaultViewModel,
    onRequestBiometricEnrollmentPrompt: () -> Unit,
    onBack: () -> Unit
) {
    val isRealVaultSession = (sessionState as? VaultSessionManager.SessionState.Unlocked)?.canManageVaultSecurity == true
    val bioHardwareStatus = remember { viewModel.biometricKeystoreManager.checkBiometricAvailability() }

    var currMasterPass by remember { mutableStateOf("") }
    var newMasterPass by remember { mutableStateOf("") }
    var confirmNewMasterPass by remember { mutableStateOf("") }

    var realPassForDecoy by remember { mutableStateOf("") }
    var newDecoyPass by remember { mutableStateOf("") }
    var confirmNewDecoyPass by remember { mutableStateOf("") }
    var seedSampleDecoy by remember { mutableStateOf(true) }

    BackHandler(onBack = onBack)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            IconButton(onClick = onBack) {
                Icon(imageVector = Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
            }
            Text(
                text = "Security, Privacy & Preferences",
                style = MaterialTheme.typography.headlineMedium
            )
        }

        if (uiState.securityStatusMessage != null) {
            Surface(
                color = MaterialTheme.colorScheme.primaryContainer,
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = uiState.securityStatusMessage,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }

        if (uiState.securityErrorMessage != null) {
            Surface(
                color = MaterialTheme.colorScheme.errorContainer,
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = uiState.securityErrorMessage,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }

        // Theme, Auto-Lock, Clipboard & Screenshot Policy
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(text = "App Appearance & Session Locking", style = MaterialTheme.typography.titleMedium)

                Text(text = "Theme Mode", style = MaterialTheme.typography.labelLarge)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    AppThemeMode.entries.forEach { mode ->
                        FilterChip(
                            selected = settingsState.themeMode == mode,
                            onClick = { viewModel.setThemeMode(mode) },
                            label = { Text(mode.name) }
                        )
                    }
                }

                HorizontalDivider()

                Text(text = "Auto-Lock Timeout on Background", style = MaterialTheme.typography.labelLarge)
                val timeoutOptions = listOf(
                    0L to "Immediate",
                    30_000L to "30 sec",
                    60_000L to "1 min",
                    300_000L to "5 min"
                )
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    timeoutOptions.forEach { (ms, label) ->
                        FilterChip(
                            selected = settingsState.autoLockTimeoutMs == ms,
                            onClick = { viewModel.setAutoLockTimeoutMs(ms) },
                            label = { Text(label) }
                        )
                    }
                }

                HorizontalDivider()

                Text(text = "Sensitive Clipboard Auto-Clear Timer", style = MaterialTheme.typography.labelLarge)
                val clipOptions = listOf(15, 30, 60)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    clipOptions.forEach { sec ->
                        FilterChip(
                            selected = settingsState.clipboardClearSeconds == sec,
                            onClick = { viewModel.setClipboardClearSeconds(sec) },
                            label = { Text("${sec}s") }
                        )
                    }
                }

                HorizontalDivider()

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(text = "Block Screenshots & Screen Recording (FLAG_SECURE)", style = MaterialTheme.typography.titleSmall)
                        Text(
                            text = "Prevents screenshots and hides vault previews in Android Recents.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = settingsState.blockScreenshots,
                        onCheckedChange = viewModel::setBlockScreenshots
                    )
                }
            }
        }

        // Argon2id KDF Telemetry & On-Device Benchmark Card (Refinement #2)
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(imageVector = Icons.Filled.Speed, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Text(
                        text = "Argon2id KDF Parameters & 2-Slot Benchmark",
                        style = MaterialTheme.typography.titleMedium
                    )
                }

                val bench = settingsState.lastKdfBenchmark
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    shape = MaterialTheme.shapes.small,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        if (bench != null) {
                            Text(
                                text = "STATUS: MEASURED ON DEVICE",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = JetBrainsMonoFontFamily,
                                color = MaterialTheme.colorScheme.primary
                            )
                            Text(
                                text = "Device: ${bench.deviceModel} (API ${bench.androidSdkInt})\n" +
                                    "KDF: Argon2id v1.3 (BouncyCastle 1.80)\n" +
                                    "Parameters: ${bench.memoryKbPerSlot / 1024} MiB/slot, ${bench.iterations} iterations, ${bench.parallelism} lanes\n" +
                                    "Single-Slot Time: ${bench.singleSlotDurationMs} ms\n" +
                                    "Two-Slot Unlock Time (Slot 0 + Slot 1): ${bench.twoSlotUnlockDurationMs} ms\n" +
                                    "JVM Heap: ${bench.usedHeapMbAfterRun} MiB used / ${bench.maxHeapMb} MiB max",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = JetBrainsMonoFontFamily
                            )
                        } else {
                            Text(
                                text = "STATUS: PROPOSED DEFAULT (Until Measured)\n" +
                                    "Proposed Profile: ${CryptoEngine.selectDefaultMemoryKb() / 1024} MiB/slot, ${CryptoEngine.selectDefaultIterations()} iterations, 2 lanes",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = JetBrainsMonoFontFamily
                            )
                        }
                    }
                }

                OutlinedButton(
                    onClick = viewModel::runOnDeviceKdfBenchmark,
                    enabled = !uiState.isRunningKdfBenchmark,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("run_kdf_benchmark_button")
                ) {
                    if (uiState.isRunningKdfBenchmark) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Measuring 2-Slot Argon2id...")
                    } else {
                        Text("Measure Two-Vault Argon2id Benchmark Now")
                    }
                }
            }
        }

        // Real-Vault-Only Security Controls (Master Password Rotation, Biometric Policy, Decoy Config)
        // Decoy sessions do not allow changing Real credentials (S10)
        if (isRealVaultSession) {
            // Biometric Convenience (When Decoy is Disabled - Section 15)
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(imageVector = Icons.Filled.Fingerprint, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Text(text = "Hardware Biometric Unlock Policy", style = MaterialTheme.typography.titleMedium)
                    }

                    if (uiState.isDecoyConfiguredInRealSession) {
                        Surface(
                            color = MaterialTheme.colorScheme.surfaceVariant,
                            shape = MaterialTheme.shapes.small,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = "Decoy Policy Active: Because Decoy Mode is enabled, biometric unlock for the Real Vault is automatically disabled so a fingerprint prompt cannot reveal or jump into the Real Vault.",
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.padding(10.dp)
                            )
                        }
                    } else {
                        Text(
                            text = "Hardware Status: ${bioHardwareStatus.name}. When enabled, Android Keystore binds an AES-256-GCM wrapping key to strong biometric authentication.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        if (uiState.isBiometricEnrolledForRealVault) {
                            OutlinedButton(
                                onClick = viewModel::disableBiometricUnlock,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Disable Biometric Unlock & Delete Keystore Wrapper")
                            }
                        } else {
                            Button(
                                onClick = onRequestBiometricEnrollmentPrompt,
                                enabled = bioHardwareStatus == BiometricKeystoreManager.BiometricHardwareStatus.AVAILABLE,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Enable Hardware Biometric Unlock")
                            }
                        }
                    }
                }
            }

            // Master Password Change (Section 12, S04)
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(imageVector = Icons.Filled.LockReset, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Text(text = "Change Real Master Password", style = MaterialTheme.typography.titleMedium)
                    }

                    OutlinedTextField(
                        value = currMasterPass,
                        onValueChange = { currMasterPass = it },
                        label = { Text("Current Master Password") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = newMasterPass,
                        onValueChange = { newMasterPass = it },
                        label = { Text("New Master Password (min 8 chars)") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = confirmNewMasterPass,
                        onValueChange = { confirmNewMasterPass = it },
                        label = { Text("Confirm New Master Password") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )

                    Button(
                        onClick = {
                            viewModel.rotateRealMasterPassword(currMasterPass, newMasterPass, confirmNewMasterPass)
                            currMasterPass = ""
                            newMasterPass = ""
                            confirmNewMasterPass = ""
                        },
                        enabled = currMasterPass.isNotEmpty() && newMasterPass.length >= 8,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Atomically Re-Wrap Real Vault Key")
                    }
                }
            }

            // Decoy Vault Configuration (Section 14)
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(imageVector = Icons.Filled.Shield, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Text(
                            text = if (uiState.isDecoyConfiguredInRealSession) {
                                "Decoy Vault Configuration (Active)"
                            } else {
                                "Configure Isolated Decoy Vault"
                            },
                            style = MaterialTheme.typography.titleMedium
                        )
                    }

                    Text(
                        text = "Configure or update a separate decoy password that opens an isolated secondary vault (Slot 1). Note: Enabling Decoy Mode automatically disables biometric unlock on the Real Vault.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    OutlinedTextField(
                        value = realPassForDecoy,
                        onValueChange = { realPassForDecoy = it },
                        label = { Text("Authorize with Current Real Master Password") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = newDecoyPass,
                        onValueChange = { newDecoyPass = it },
                        label = { Text("Decoy Vault Password (min 8 chars)") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = confirmNewDecoyPass,
                        onValueChange = { confirmNewDecoyPass = it },
                        label = { Text("Confirm Decoy Vault Password") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = seedSampleDecoy,
                            onCheckedChange = { seedSampleDecoy = it }
                        )
                        Text(
                            text = "Seed harmless fictitious notes & accounts (example.org)",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        if (uiState.isDecoyConfiguredInRealSession) {
                            OutlinedButton(
                                onClick = {
                                    viewModel.disableDecoyVault(realPassForDecoy)
                                    realPassForDecoy = ""
                                },
                                enabled = realPassForDecoy.isNotEmpty(),
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Disable Decoy")
                            }
                        }
                        Button(
                            onClick = {
                                viewModel.configureDecoyVault(
                                    realPassword = realPassForDecoy,
                                    decoyPassword = newDecoyPass,
                                    confirmDecoyPassword = confirmNewDecoyPass,
                                    seedSampleData = seedSampleDecoy
                                )
                                realPassForDecoy = ""
                                newDecoyPass = ""
                                confirmNewDecoyPass = ""
                            },
                            enabled = realPassForDecoy.isNotEmpty() && newDecoyPass.length >= 8,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Save Decoy Vault")
                        }
                    }
                }
            }
        }
    }
}

// =============================================================================================
// 4. OTA UPDATES SCREEN & DEBUG SIMULATOR (Sections 20, 21, 22)
// =============================================================================================

@Composable
fun OtaUpdatesScreen(
    settingsState: AppPreferencesRepository.AppSettingsState,
    otaState: OtaUpdateManager.OtaUiState,
    viewModel: VaultViewModel,
    onLaunchInstallerIntent: (Intent) -> Unit,
    onBack: () -> Unit
) {
    var manifestUrlInput by remember(settingsState.customOtaManifestUrl) {
        mutableStateOf(settingsState.customOtaManifestUrl)
    }
    val installedSignerHex = remember { viewModel.otaUpdateManager.getInstalledSignerFingerprintHex() }

    BackHandler(onBack = onBack)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            IconButton(onClick = onBack) {
                Icon(imageVector = Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
            }
            Text(
                text = "OTA Application Updates",
                style = MaterialTheme.typography.headlineMedium
            )
        }

        // Installed Identity Card
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(text = "Installed Build & Trust Anchor", style = MaterialTheme.typography.titleMedium)
                Text(
                    text = "Package ID: ${BuildConfig.APPLICATION_ID}\n" +
                        "Installed Version: ${BuildConfig.VERSION_NAME} (versionCode ${BuildConfig.VERSION_CODE})\n" +
                        "Public OTA Repo: https://github.com/tpeditz/Private-vault-updates\n" +
                        "Trusted Installed Signer SHA-256:\n${installedSignerHex.take(32)}...",
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = JetBrainsMonoFontFamily,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(text = "Automatic Launch Update Checks", style = MaterialTheme.typography.titleSmall)
                        Text(
                            text = "Checks GitHub update.json over HTTPS on launch. Never sends vault data.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = settingsState.autoCheckUpdatesOnLaunch,
                        onCheckedChange = viewModel::setAutoCheckUpdatesOnLaunch
                    )
                }

                val rem = settingsState.otaReminderState
                if (rem.deferredVersionCode > BuildConfig.VERSION_CODE && rem.reminderType != AppPreferencesRepository.OtaReminderType.NONE) {
                    Surface(
                        color = MaterialTheme.colorScheme.secondaryContainer,
                        shape = MaterialTheme.shapes.extraSmall,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = "Active Reminder Deferral for vCode ${rem.deferredVersionCode}: ${rem.reminderType.name}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSecondaryContainer,
                            modifier = Modifier.padding(8.dp)
                        )
                    }
                }

                Button(
                    onClick = viewModel::checkForUpdatesNow,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("ota_manual_check_button")
                ) {
                    Icon(imageVector = Icons.Filled.SystemUpdate, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Check for Updates Now")
                }
            }
        }

        // Current OTA Status Card
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(text = "Update Status", style = MaterialTheme.typography.titleMedium)

                when (otaState) {
                    is OtaUpdateManager.OtaUiState.Idle -> {
                        Text(
                            text = "Tap 'Check for Updates Now' to query the public update manifest.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    is OtaUpdateManager.OtaUiState.CheckingManifest -> {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                            Text("Fetching https://raw.githubusercontent.com/tpeditz/Private-vault-updates/main/update.json...")
                        }
                    }
                    is OtaUpdateManager.OtaUiState.UpToDate -> {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(imageVector = Icons.Filled.CheckCircle, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            Text(
                                text = "You are on the latest version (${otaState.installedVersionName}, code ${otaState.installedVersionCode}).",
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    }
                    is OtaUpdateManager.OtaUiState.UpdateAvailable -> {
                        val m = otaState.manifest
                        Text(
                            text = "New Version Available: v${m.versionName} (code ${m.versionCode})",
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = m.releaseNotes,
                            style = MaterialTheme.typography.bodySmall
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = { viewModel.chooseUpdateNow(m) },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Update Now")
                            }
                            OutlinedButton(
                                onClick = {
                                    viewModel.chooseRemindMeLater(m, OtaDeferralOption.TOMORROW)
                                },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Remind Tomorrow")
                            }
                        }
                    }
                    is OtaUpdateManager.OtaUiState.Downloading -> {
                        Text(
                            text = "Downloading v${otaState.manifest.versionName} (${(otaState.progressFraction * 100).toInt()}%)...",
                            style = MaterialTheme.typography.bodyMedium
                        )
                        LinearProgressIndicator(
                            progress = { otaState.progressFraction },
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedButton(
                            onClick = viewModel::cancelActiveOtaDownload,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Cancel Download")
                        }
                    }
                    is OtaUpdateManager.OtaUiState.VerifyingSignature -> {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                            Text("Verifying SHA-256 & Android apksig ApkVerifier Signer Certificate...")
                        }
                    }
                    is OtaUpdateManager.OtaUiState.ReadyToInstall -> {
                        val c = otaState.verifiedCandidate
                        Surface(
                            color = MaterialTheme.colorScheme.primaryContainer,
                            shape = MaterialTheme.shapes.small,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(
                                modifier = Modifier.padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Text(
                                    text = "APK Verified with Android apksig ApkVerifier",
                                    style = MaterialTheme.typography.titleSmall,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer
                                )
                                Text(
                                    text = "SHA-256: ${c.actualSha256Hex.take(24)}...\n" +
                                        "Verified Signer Matches Installed Key: YES",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = JetBrainsMonoFontFamily,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer
                                )
                            }
                        }
                        if (!viewModel.otaUpdateManager.canRequestPackageInstalls()) {
                            Text(
                                text = "Android requires 'Install unknown apps' permission for PRIVATE VAULT to hand off the verified update APK to the system installer.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Button(
                            onClick = {
                                val intent = viewModel.prepareAndBuildInstallIntent(c)
                                onLaunchInstallerIntent(intent)
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Lock Vault & Confirm Android Installation")
                        }
                    }
                    is OtaUpdateManager.OtaUiState.Error -> {
                        Surface(
                            color = if (otaState.isOfflineOrUnpublished) {
                                MaterialTheme.colorScheme.surfaceVariant
                            } else {
                                MaterialTheme.colorScheme.errorContainer
                            },
                            shape = MaterialTheme.shapes.small,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(
                                modifier = Modifier.padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Text(
                                    text = otaState.title,
                                    style = MaterialTheme.typography.titleSmall,
                                    color = if (otaState.isOfflineOrUnpublished) {
                                        MaterialTheme.colorScheme.onSurfaceVariant
                                    } else {
                                        MaterialTheme.colorScheme.onErrorContainer
                                    }
                                )
                                Text(
                                    text = otaState.message,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = if (otaState.isOfflineOrUnpublished) {
                                        MaterialTheme.colorScheme.onSurfaceVariant
                                    } else {
                                        MaterialTheme.colorScheme.onErrorContainer
                                    }
                                )
                            }
                        }
                    }
                }
            }
        }

        // Manifest Endpoint Configuration
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(text = "Public Manifest Endpoint", style = MaterialTheme.typography.titleMedium)
                OutlinedTextField(
                    value = manifestUrlInput,
                    onValueChange = { manifestUrlInput = it },
                    label = { Text("GitHub HTTPS update.json URL") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            manifestUrlInput = OtaUpdateManager.DEFAULT_MANIFEST_URL
                            viewModel.setCustomOtaManifestUrl(OtaUpdateManager.DEFAULT_MANIFEST_URL)
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Reset to Default")
                    }
                    Button(
                        onClick = { viewModel.setCustomOtaManifestUrl(manifestUrlInput) },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Save Endpoint")
                    }
                }
            }
        }

        // Debug-Only OTA Test Simulator (Strictly gated behind BuildConfig.DEBUG per Confirmed Decision 4)
        if (BuildConfig.DEBUG) {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text(
                        text = "Debug / Test Build Only: OTA Manifest Simulator",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = "This panel is compiled ONLY in debug/test builds (BuildConfig.DEBUG == true) to test the 3-option Update Dialog (Update Now / Update Later / Remind Me Later) before publishing to GitHub.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(
                            onClick = {
                                val sampleJson = """
                                    {
                                      "schemaVersion": 1,
                                      "packageName": "${BuildConfig.APPLICATION_ID}",
                                      "versionName": "1.0.1",
                                      "versionCode": 2,
                                      "minimumSupportedVersionCode": 1,
                                      "downloadUrl": "https://github.com/tpeditz/Private-vault-updates/releases/download/v1.0.1/private-vault-v1.0.1.apk",
                                      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                      "signingCertificateSha256": "${installedSignerHex.ifBlank { "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }}",
                                      "releaseNotes": "• Verified preservation of both Real and Decoy encrypted vaults\n• Improved Argon2id benchmark reporting",
                                      "forceUpdate": false,
                                      "publishedAt": "2026-11-05T12:00:00Z"
                                    }
                                """.trimIndent()
                                viewModel.triggerDebugOtaSimulation(sampleJson)
                            },
                            modifier = Modifier
                                .weight(1f)
                                .testTag("debug_simulate_update_available_button")
                        ) {
                            Text("Simulate v1.0.1 Dialog")
                        }

                        OutlinedButton(
                            onClick = {
                                val downgradeJson = """
                                    {
                                      "schemaVersion": 1,
                                      "packageName": "${BuildConfig.APPLICATION_ID}",
                                      "versionName": "1.0.0",
                                      "versionCode": 1,
                                      "minimumSupportedVersionCode": 1,
                                      "downloadUrl": "https://github.com/tpeditz/Private-vault-updates/releases/download/v1.0.0/private-vault-v1.0.0.apk",
                                      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                      "signingCertificateSha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                      "releaseNotes": "Same version test",
                                      "forceUpdate": false,
                                      "publishedAt": "2026-11-04T12:00:00Z"
                                    }
                                """.trimIndent()
                                viewModel.triggerDebugOtaSimulation(downgradeJson)
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Simulate Equal v1.0.0")
                        }
                    }
                }
            }
        }
    }
}

// =============================================================================================
// 5. ABOUT & DEVELOPER CREDITS SCREEN (Section 24 - Exact Tp Editz Credits)
// =============================================================================================

@Composable
fun AboutVaultScreen(
    viewModel: VaultViewModel,
    onNavigateToUpdates: () -> Unit,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    var showOpenTelegramDialog by remember { mutableStateOf(false) }

    BackHandler(onBack = onBack)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            IconButton(onClick = onBack) {
                Icon(imageVector = Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
            }
            Text(
                text = "About PRIVATE VAULT",
                style = MaterialTheme.typography.headlineMedium
            )
        }

        // Exact Required Developer Credits Card (Section 24, F16)
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier
                .fillMaxWidth()
                .testTag("about_credits_card")
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(
                        imageVector = Icons.Filled.Shield,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(36.dp)
                    )
                    Column {
                        Text(
                            text = "PRIVATE VAULT",
                            style = MaterialTheme.typography.headlineLarge,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.testTag("about_app_title")
                        )
                        Text(
                            text = "Developed by Tp Editz",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.testTag("about_developer_name")
                        )
                    }
                }

                HorizontalDivider()

                Text(
                    text = "Telegram: @Tp_Editz",
                    style = MaterialTheme.typography.bodyLarge,
                    fontFamily = JetBrainsMonoFontFamily,
                    modifier = Modifier.testTag("about_telegram_handle")
                )

                Text(
                    text = "Version: ${BuildConfig.VERSION_NAME} (versionCode ${BuildConfig.VERSION_CODE})",
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = JetBrainsMonoFontFamily,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.testTag("about_version_text")
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            viewModel.copySecretToClipboard("Developer Telegram", "@Tp_Editz")
                        },
                        modifier = Modifier
                            .weight(1f)
                            .testTag("about_copy_telegram_button")
                    ) {
                        Icon(imageVector = Icons.Filled.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Copy @Tp_Editz")
                    }

                    Button(
                        onClick = { showOpenTelegramDialog = true },
                        modifier = Modifier
                            .weight(1f)
                            .testTag("about_open_telegram_button")
                    ) {
                        Icon(imageVector = Icons.AutoMirrored.Filled.OpenInNew, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Open Telegram")
                    }
                }

                OutlinedButton(
                    onClick = onNavigateToUpdates,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(imageVector = Icons.Filled.SystemUpdate, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Check for Updates")
                }
            }
        }

        // Concise Privacy & Threat Model Statement (Section 11, 14, 19, 24)
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(imageVector = Icons.Outlined.VerifiedUser, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Text(text = "Privacy Statement & Security Boundary", style = MaterialTheme.typography.titleMedium)
                }
                Text(
                    text = "• 100% Offline Vault Operations: All notes, saved passwords, folders, tags, timestamps, password generation, and strength evaluations run locally on your device without analytics, cloud sync, or external API calls.\n" +
                        "• Cryptographic Architecture: Master and backup passwords derive 256-bit keys via Argon2id (RFC 9106). Vault envelopes and records are encrypted with AES-256-GCM using fresh 96-bit nonces and Associated Authenticated Data (AAD).\n" +
                        "• Residual Metadata & Threat Limits: While record titles, bodies, credentials, timestamps, and flags are encrypted inside AES-256-GCM blobs, an attacker with raw filesystem access can still observe record counts per slot, approximate ciphertext sizes, and SQLite file modification times. An unlocked compromised/rooted OS, untrusted keyboard, or physical observation can bypass app-layer controls.\n" +
                        "• Network Boundary: Internet access is used exclusively to fetch public update metadata and signed release APKs from https://github.com/tpeditz/Private-vault-updates over HTTPS. Connecting to GitHub exposes standard HTTPS connection metadata (IP address and request timing) to GitHub.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        // Open-Source Third-Party Licenses Summary
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(imageVector = Icons.Outlined.Info, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Text(text = "Third-Party Open Source Libraries", style = MaterialTheme.typography.titleMedium)
                }
                Text(
                    text = "• BouncyCastle Crypto APIs (bcprov-jdk18on 1.80) — MIT-style License (Argon2id RFC 9106)\n" +
                        "• Android Open Source Project Jetpack (Compose, Room, Biometric, DataStore) — Apache License 2.0\n" +
                        "• Android Tools APK Signer / Verifier (com.android.tools.build:apksig) — Apache License 2.0\n" +
                        "• Square OkHttp — Apache License 2.0\n" +
                        "• Bundled Fonts: Space Grotesk, Plus Jakarta Sans, JetBrains Mono — SIL Open Font License 1.1",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }

    if (showOpenTelegramDialog) {
        AlertDialog(
            onDismissRequest = { showOpenTelegramDialog = false },
            title = { Text("Open External Link?") },
            text = {
                Text("Open https://t.me/Tp_Editz in your external browser or Telegram app? No vault data is ever transmitted.")
            },
            confirmButton = {
                Button(
                    onClick = {
                        showOpenTelegramDialog = false
                        try {
                            val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://t.me/Tp_Editz")).apply {
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            }
                            context.startActivity(intent)
                        } catch (_: Exception) {
                        }
                    }
                ) {
                    Text("Open Link")
                }
            },
            dismissButton = {
                TextButton(onClick = { showOpenTelegramDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}

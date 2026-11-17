package com.example.ui

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.OpenInBrowser
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Warning
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
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.example.BuildConfig
import com.example.data.AppPreferencesRepository
import com.example.data.OtaReminderPolicy
import com.example.data.PortableBackupEngine
import com.example.data.ThemePreference
import com.example.data.VaultAppPreferences
import com.example.ota.OtaUpdateManager
import com.example.security.CryptoEngine

// ============================================================================================
// 0. Settings Hub Screen (PrimaryTab.SETTINGS — Friendly 4-Tab Consolidation)
// ============================================================================================

@Composable
fun SettingsHubScreen(
    uiState: VaultUiState,
    preferences: VaultAppPreferences,
    otaState: OtaUpdateManager.OtaState,
    viewModel: VaultViewModel
) {
    val context = LocalContext.current
    val installedVersionName = remember(context) { OtaUpdateManager.getInstalledVersionName(context) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(
            text = "Vault Settings & Tools",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = "Manage encrypted backups, appearance, auto-lock preferences, and verified app updates.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        // Quick Appearance Switcher Card (Friendly Light Default + Dark Obsidian + System)
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "Appearance & Theme",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = "Choose a clean light palette, deep dark obsidian, or follow your Android system setting.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilterChip(
                        selected = preferences.themePreference == ThemePreference.LIGHT_CLEAN,
                        onClick = { viewModel.setThemePreference(ThemePreference.LIGHT_CLEAN) },
                        label = { Text("Light (Clean)") },
                        modifier = Modifier.testTag("theme_chip_light_clean")
                    )
                    FilterChip(
                        selected = preferences.themePreference == ThemePreference.DARK_OBSIDIAN,
                        onClick = { viewModel.setThemePreference(ThemePreference.DARK_OBSIDIAN) },
                        label = { Text("Dark (Obsidian)") },
                        modifier = Modifier.testTag("theme_chip_dark_obsidian")
                    )
                    FilterChip(
                        selected = preferences.themePreference == ThemePreference.SYSTEM,
                        onClick = { viewModel.setThemePreference(ThemePreference.SYSTEM) },
                        label = { Text("Match System") },
                        modifier = Modifier.testTag("theme_chip_system")
                    )
                }
            }
        }

        // Hub Navigation Cards
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { viewModel.openSecondaryDestination(SecondaryDestination.BACKUP_RESTORE) }
                .testTag("settings_open_backup_card"),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(18.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Icon(
                    imageVector = Icons.Filled.SaveAlt,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(28.dp)
                )
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Backup & Restore (.pvault)",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Export or restore encrypted backups (${uiState.notes.size} notes, ${uiState.credentials.size} passwords, ${uiState.mediaItems.size} media)",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { viewModel.openSecondaryDestination(SecondaryDestination.SECURITY_SETTINGS) }
                .testTag("settings_open_security_card"),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(18.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Icon(
                    imageVector = Icons.Filled.Security,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(28.dp)
                )
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Security, Passwords & Auto-Lock",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Change vault password, configure biometric quick-unlock, auto-lock timeout, and advanced security policy",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { viewModel.openSecondaryDestination(SecondaryDestination.OTA_UPDATES) }
                .testTag("settings_open_ota_card"),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(18.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Icon(
                    imageVector = Icons.Filled.SystemUpdate,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(28.dp)
                )
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "App Updates (OTA)",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    val otaSubtitle = when (otaState) {
                        is OtaUpdateManager.OtaState.UpdateAvailable -> "Update available: v${otaState.manifest.versionName}"
                        else -> "Installed v$installedVersionName • Check for verified updates"
                    }
                    Text(
                        text = otaSubtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { viewModel.openSecondaryDestination(SecondaryDestination.ABOUT_CREDITS) }
                .testTag("settings_open_about_card"),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(18.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Icon(
                    imageVector = Icons.Filled.Info,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(28.dp)
                )
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "About & Developer Credits",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Developed by Tp Editz • Security specifications & contact links",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

// ============================================================================================
// 1. Encrypted Backup & Restore Screen (.pvault) — Fixes U01, U02, N02, R10, R16, PV-DATA-001, PV-BUG-009
// ============================================================================================

@Composable
fun BackupAndRestoreScreen(
    uiState: VaultUiState,
    viewModel: VaultViewModel,
    onLaunchCreateBackupDocument: (String) -> Unit,
    onLaunchOpenRestoreDocument: () -> Unit,
    onBack: () -> Unit
) {
    BackHandler { onBack() }

    // Section 05, BUG 02, BUG 12 & T09 Fix: Keep backup/restore passwords in non-saveable memory.
    var exportPassword by remember { mutableStateOf("") }
    var confirmExportPassword by remember { mutableStateOf("") }
    var showExportPassword by remember { mutableStateOf(false) }

    var restorePassword by remember { mutableStateOf("") }
    var showRestorePassword by remember { mutableStateOf(false) }
    var restoreMode by rememberSaveable {
        mutableStateOf(PortableBackupEngine.RestoreMode.MERGE_KEEP_NEWEST)
    }
    var showConfirmEmptyReplaceDialog by remember { mutableStateOf(false) }

    if (showConfirmEmptyReplaceDialog) {
        AlertDialog(
            onDismissRequest = { showConfirmEmptyReplaceDialog = false },
            icon = {
                Icon(
                    Icons.Filled.Warning,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error
                )
            },
            title = { Text("Replace Vault with Empty Backup?") },
            text = {
                Text(
                    "The selected .pvault backup contains 0 records. Proceeding with 'Replace all records in active vault slot' will delete all ${uiState.notes.size} notes and ${uiState.credentials.size} credentials in this vault."
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showConfirmEmptyReplaceDialog = false
                        val submittedPass = restorePassword
                        restorePassword = ""
                        viewModel.verifyAndRestoreSelectedUri(
                            backupPassword = submittedPass,
                            restoreMode = restoreMode
                        )
                    },
                    modifier = Modifier.testTag("confirm_empty_backup_replace_button")
                ) {
                    Text("Replace & Wipe Active Vault")
                }
            },
            dismissButton = {
                TextButton(onClick = { showConfirmEmptyReplaceDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        SecondaryHeader(
            title = "Encrypted Backup & Restore (.pvault)",
            onBack = onBack
        )

        Text(
            text = "Backups export ONLY the currently unlocked vault slot. Every .pvault file is independently encrypted with Argon2id + AES-256-GCM and authenticated in memory before any restore touches SQLite.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        if (uiState.backupOperationStage != BackupOperationStage.IDLE) {
            Surface(
                color = MaterialTheme.colorScheme.secondaryContainer,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("backup_operation_stage_banner")
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    if (uiState.isBusy) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp
                        )
                    }
                    Text(
                        text = uiState.backupOperationStage.label,
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                }
            }
        }

        // N02 Fix: Explicit Integrity Warning if any corrupted record exists in the active slot
        if (uiState.corruptedRecordCount > 0) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            Icons.Filled.Warning,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onErrorContainer
                        )
                        Text(
                            text = "Integrity Alert: ${uiState.corruptedRecordCount} Unreadable Record(s)",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                    Text(
                        text = "One or more encrypted records in this vault failed AES-256-GCM authentication. To prevent silent data loss, normal export and merge restore are blocked unless you explicitly enable Recovery Export below.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = uiState.allowRecoveryExportSkippingCorrupted,
                            onCheckedChange = viewModel::setAllowRecoveryExportSkippingCorrupted
                        )
                        Text(
                            text = "Enable Recovery Export (export intact records only)",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
            }
        }

        // Export Card (U01 & PV-BUG-009 Fix)
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        Icons.Filled.SaveAlt,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = "Export Active Vault (${uiState.notes.size} notes, ${uiState.credentials.size} credentials, ${uiState.mediaItems.size} media)",
                        style = MaterialTheme.typography.titleMedium
                    )
                }

                // PV-BUG-009 & Correction 2 Fix: Selective Backup Export Scope with explicit 22 MiB raw media ceiling notice
                Text(
                    text = "Export Scope:",
                    style = MaterialTheme.typography.labelMedium
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    PortableBackupEngine.BackupExportScope.entries.forEach { scope ->
                        FilterChip(
                            selected = uiState.backupExportScope == scope,
                            onClick = { viewModel.setBackupExportScope(scope) },
                            label = { Text(scope.label) },
                            modifier = Modifier.testTag("backup_scope_${scope.name.lowercase()}")
                        )
                    }
                }
                Text(
                    text = "Capacity Notice: A portable .pvault container has a 32 MiB maximum file limit (~22 MiB raw encrypted media after Base64 encoding). Selecting \"All Data + Media (≤22 MiB)\" verifies every encrypted chunk before export and fails closed if active-slot media exceeds 22 MiB—never silently skipping files.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                OutlinedTextField(
                    value = exportPassword,
                    onValueChange = { exportPassword = it },
                    label = { Text("Backup Encryption Password (min 8 chars)") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        autoCorrectEnabled = false
                    ),
                    visualTransformation = if (showExportPassword) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                    trailingIcon = {
                        IconButton(onClick = { showExportPassword = !showExportPassword }) {
                            Icon(
                                imageVector = if (showExportPassword) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = if (showExportPassword) "Hide backup password" else "Show backup password"
                            )
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("backup_export_password_input")
                )

                OutlinedTextField(
                    value = confirmExportPassword,
                    onValueChange = { confirmExportPassword = it },
                    label = { Text("Confirm Backup Password") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        autoCorrectEnabled = false
                    ),
                    visualTransformation = if (showExportPassword) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("backup_export_confirm_password_input")
                )

                Button(
                    onClick = {
                        viewModel.prepareBackupExport(
                            backupPassword = exportPassword,
                            confirmPassword = confirmExportPassword,
                            onReadyToLaunchCreateDocument = { suggestedName ->
                                exportPassword = ""
                                confirmExportPassword = ""
                                onLaunchCreateBackupDocument(suggestedName)
                            }
                        )
                    },
                    enabled = !uiState.isBusy && exportPassword.length >= 8 && confirmExportPassword.length >= 8,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("backup_export_button")
                ) {
                    if (uiState.isBusy) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onPrimary
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Encrypting .pvault Backup…")
                    } else {
                        Icon(Icons.Filled.SaveAlt, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Export Encrypted .pvault")
                    }
                }

                if (uiState.stagedBackupMetadata != null) {
                    OutlinedButton(
                        onClick = {
                            onLaunchCreateBackupDocument(uiState.stagedBackupMetadata.suggestedFileName)
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Re-open Save As Dialog (${uiState.stagedBackupMetadata.suggestedFileName})")
                    }
                }
            }
        }

        // Restore Card (U02 & PV-DATA-001 Fix)
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        Icons.Filled.Restore,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.secondary
                    )
                    Text(
                        text = "Restore from .pvault Backup",
                        style = MaterialTheme.typography.titleMedium
                    )
                }

                OutlinedTextField(
                    value = restorePassword,
                    onValueChange = { restorePassword = it },
                    label = { Text("Backup Decryption Password") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        autoCorrectEnabled = false
                    ),
                    visualTransformation = if (showRestorePassword) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                    trailingIcon = {
                        IconButton(onClick = { showRestorePassword = !showRestorePassword }) {
                            Icon(
                                imageVector = if (showRestorePassword) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = if (showRestorePassword) "Hide restore password" else "Show restore password"
                            )
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("backup_restore_password_input")
                )

                Text(
                    text = "Conflict Resolution Policy:",
                    style = MaterialTheme.typography.labelMedium
                )

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    RadioButton(
                        selected = restoreMode == PortableBackupEngine.RestoreMode.MERGE_KEEP_NEWEST,
                        onClick = {
                            restoreMode = PortableBackupEngine.RestoreMode.MERGE_KEEP_NEWEST
                        }
                    )
                    Text(
                        text = "Merge with active vault (keep newest updated record)",
                        style = MaterialTheme.typography.bodySmall
                    )
                }

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    RadioButton(
                        selected = restoreMode == PortableBackupEngine.RestoreMode.REPLACE_ACTIVE_VAULT,
                        onClick = {
                            restoreMode = PortableBackupEngine.RestoreMode.REPLACE_ACTIVE_VAULT
                        }
                    )
                    Text(
                        text = "Replace all records in active vault slot",
                        style = MaterialTheme.typography.bodySmall
                    )
                }

                OutlinedButton(
                    onClick = {
                        viewModel.beginRestoreFileSelection {
                            onLaunchOpenRestoreDocument()
                        }
                    },
                    enabled = !uiState.isBusy,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("backup_select_file_button")
                ) {
                    Icon(Icons.Filled.FolderOpen, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (uiState.selectedRestoreFileName != null) {
                            "Selected: ${uiState.selectedRestoreFileName}"
                        } else {
                            "Choose .pvault File"
                        }
                    )
                }

                if (uiState.selectedRestoreUriString != null) {
                    OutlinedButton(
                        onClick = {
                            viewModel.verifyAndPreviewSelectedUri(backupPassword = restorePassword)
                        },
                        enabled = !uiState.isBusy && restorePassword.isNotBlank(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("backup_preview_submit_button")
                    ) {
                        Icon(Icons.Filled.CheckCircle, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Preview Backup Contents")
                    }

                    Button(
                        onClick = {
                            val isReplacingNonEmptyWithEmpty =
                                restoreMode == PortableBackupEngine.RestoreMode.REPLACE_ACTIVE_VAULT &&
                                    uiState.verifiedRestorePreview?.isEmptyBackup == true &&
                                    (uiState.notes.isNotEmpty() || uiState.credentials.isNotEmpty())
                            if (isReplacingNonEmptyWithEmpty) {
                                showConfirmEmptyReplaceDialog = true
                            } else {
                                val submittedPass = restorePassword
                                restorePassword = ""
                                viewModel.verifyAndRestoreSelectedUri(
                                    backupPassword = submittedPass,
                                    restoreMode = restoreMode
                                )
                            }
                        },
                        enabled = !uiState.isBusy && restorePassword.isNotBlank(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("backup_restore_button")
                    ) {
                        if (uiState.isBusy) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp,
                                color = MaterialTheme.colorScheme.onPrimary
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Verifying & Restoring .pvault…")
                        } else {
                            Icon(Icons.Filled.Restore, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Verify & Restore Now")
                        }
                    }
                }

                val preview = uiState.verifiedRestorePreview
                if (preview != null) {
                    Surface(
                        color = if (preview.isEmptyBackup) {
                            MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.65f)
                        } else {
                            MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.55f)
                        },
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("verified_restore_preview_card")
                    ) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = "Authenticated Backup Preview (${preview.fileName})",
                                style = MaterialTheme.typography.titleSmall,
                                color = if (preview.isEmptyBackup) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.primary,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = "Records: ${preview.notesCount} notes • ${preview.credentialsCount} credentials • ${preview.foldersCount} folders",
                                style = MaterialTheme.typography.bodySmall
                            )
                            if (preview.isEmptyBackup) {
                                Text(
                                    text = "Warning: This backup contains 0 records. Restoring in Replace mode will empty the active vault.",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.error,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                            Text(
                                text = "Created by PRIVATE VAULT v${preview.appVersionName}",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================================
// 2. Security, Active-Vault Password & Plausible Deniability Policy Screen (N05, R02, R07, PV-SEC-008, PV-SEC-010)
// ============================================================================================

@Composable
fun SecurityAndDecoySettingsScreen(
    uiState: VaultUiState,
    preferences: VaultAppPreferences,
    viewModel: VaultViewModel,
    onRequestBiometricEnrollment: () -> Unit,
    onBack: () -> Unit
) {
    BackHandler { onBack() }

    // R02, BUG 02, BUG 12 & T09 Fix: Keep all password inputs in non-saveable memory.
    var currentVaultPass by remember { mutableStateOf("") }
    var newVaultPass by remember { mutableStateOf("") }
    var confirmNewVaultPass by remember { mutableStateOf("") }
    var showChangePasswords by remember { mutableStateOf(false) }
    var rekeyAllRecordsWithNewDek by rememberSaveable { mutableStateOf(false) }

    // R02 & N05 Fix: Password-gated Plausible Deniability Policy Sheet state
    var showPolicyGateDialog by rememberSaveable { mutableStateOf(false) }
    var gatePasswordInput by remember { mutableStateOf("") }

    // Decoy Provisioning / Rotation / Destructive Reset state
    var realPassForDecoy by remember { mutableStateOf("") }
    var currentDecoyPass by remember { mutableStateOf("") }
    var decoyPass by remember { mutableStateOf("") }
    var confirmDecoyPass by remember { mutableStateOf("") }
    var seedDecoyData by rememberSaveable { mutableStateOf(true) }
    var confirmDestructiveReset by rememberSaveable { mutableStateOf(false) }

    if (showPolicyGateDialog && !uiState.isDecoyPolicySheetUnlocked) {
        AlertDialog(
            onDismissRequest = {
                showPolicyGateDialog = false
                gatePasswordInput = ""
            },
            icon = { Icon(Icons.Filled.Security, contentDescription = null) },
            title = { Text("Verify Master Password") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "Enter your primary Master Password to access dual-envelope Plausible Deniability Policy settings.",
                        style = MaterialTheme.typography.bodySmall
                    )
                    OutlinedTextField(
                        value = gatePasswordInput,
                        onValueChange = { gatePasswordInput = it },
                        label = { Text("Master Password") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            autoCorrectEnabled = false
                        ),
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("decoy_gate_password_input")
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val submitted = gatePasswordInput
                        gatePasswordInput = ""
                        showPolicyGateDialog = false
                        viewModel.unlockDecoyPolicySheet(submitted)
                    },
                    enabled = gatePasswordInput.isNotBlank() && !uiState.isBusy,
                    modifier = Modifier.testTag("decoy_gate_confirm_button")
                ) {
                    Text("Verify")
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        showPolicyGateDialog = false
                        gatePasswordInput = ""
                    }
                ) {
                    Text("Cancel")
                }
            }
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        SecondaryHeader(
            title = "Security & Vault Settings",
            onBack = onBack
        )

        // Auto-Lock, Screenshot Protection & Theme Preferences
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = "Locking, Screen Security & Clipboard",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary
                )

                Text(
                    text = "Auto-Lock Timeout on Background:",
                    style = MaterialTheme.typography.labelMedium
                )

                val timeoutOptions = listOf(
                    0L to "Immediate",
                    30_000L to "30s",
                    60_000L to "1m",
                    300_000L to "5m"
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    timeoutOptions.forEach { (ms, label) ->
                        FilterChip(
                            selected = preferences.autoLockTimeoutMs == ms,
                            onClick = { viewModel.setAutoLockTimeoutMs(ms) },
                            label = { Text(label) }
                        )
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Lock Immediately When Screen Turns Off")
                        Text(
                            text = "Wipes in-memory DEK as soon as the display powers down.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = preferences.lockOnScreenOff,
                        onCheckedChange = viewModel::setLockOnScreenOff
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Block Screenshots & Recents Preview (FLAG_SECURE)")
                        Text(
                            text = "Prevents screenshots, screen recording, and task-switcher snapshots.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = preferences.blockScreenshots,
                        onCheckedChange = viewModel::setBlockScreenshots
                    )
                }

                Text(
                    text = "Sensitive Clipboard Auto-Clear Timer:",
                    style = MaterialTheme.typography.labelMedium
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    listOf(15, 30, 60).forEach { sec ->
                        FilterChip(
                            selected = preferences.clipboardClearTtlSeconds == sec,
                            onClick = { viewModel.setClipboardClearTtlSeconds(sec) },
                            label = { Text("${sec}s") }
                        )
                    }
                }

                Text(
                    text = "Theme Appearance:",
                    style = MaterialTheme.typography.labelMedium
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    ThemePreference.entries.forEach { theme ->
                        FilterChip(
                            selected = preferences.themePreference == theme,
                            onClick = { viewModel.setThemePreference(theme) },
                            label = { Text(theme.name.replace('_', ' ')) }
                        )
                    }
                }
            }
        }

        // R02 & PV-SEC-010 Fix: Generic Active-Vault Password Rotation Card + Optional Full DEK Re-encryption
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        Icons.Filled.Lock,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = "Change Vault Password",
                        style = MaterialTheme.typography.titleMedium
                    )
                }
                Text(
                    text = "Re-wraps the active vault's 256-bit Data Encryption Key (DEK) with a fresh 16-byte Argon2id salt and 12-byte GCM nonce, or optionally rotates the DEK and re-encrypts every record.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                OutlinedTextField(
                    value = currentVaultPass,
                    onValueChange = { currentVaultPass = it },
                    label = { Text("Current Vault Password") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        autoCorrectEnabled = false
                    ),
                    visualTransformation = if (showChangePasswords) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                    trailingIcon = {
                        IconButton(onClick = { showChangePasswords = !showChangePasswords }) {
                            Icon(
                                imageVector = if (showChangePasswords) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = if (showChangePasswords) "Hide passwords" else "Show passwords"
                            )
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("change_vault_current_password_input")
                )
                OutlinedTextField(
                    value = newVaultPass,
                    onValueChange = { newVaultPass = it },
                    label = { Text("New Vault Password (min 8 chars)") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        autoCorrectEnabled = false
                    ),
                    visualTransformation = if (showChangePasswords) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("change_vault_new_password_input")
                )
                OutlinedTextField(
                    value = confirmNewVaultPass,
                    onValueChange = { confirmNewVaultPass = it },
                    label = { Text("Confirm New Vault Password") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        autoCorrectEnabled = false
                    ),
                    visualTransformation = if (showChangePasswords) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("change_vault_confirm_password_input")
                )

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = rekeyAllRecordsWithNewDek,
                        onCheckedChange = { rekeyAllRecordsWithNewDek = it },
                        modifier = Modifier.testTag("change_vault_rekey_dek_checkbox")
                    )
                    Text(
                        text = "Also generate a brand-new 256-bit DEK and re-encrypt all vault records atomically",
                        style = MaterialTheme.typography.bodySmall
                    )
                }

                Button(
                    onClick = {
                        viewModel.changeActiveVaultPassword(
                            currentPassword = currentVaultPass,
                            newPassword = newVaultPass,
                            confirmNewPassword = confirmNewVaultPass,
                            rekeyAllRecordsWithNewDek = rekeyAllRecordsWithNewDek
                        )
                        currentVaultPass = ""
                        newVaultPass = ""
                        confirmNewVaultPass = ""
                    },
                    enabled = !uiState.isBusy && currentVaultPass.isNotBlank() && newVaultPass.length >= 8,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("change_vault_password_button")
                ) {
                    Text("Update Vault Password")
                }
            }
        }

        // Biometric Quick-Unlock Card (PV-SEC-008 & PV-SEC-001 Fix: Identical copy in Real+Decoy and Decoy sessions)
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        Icons.Filled.Fingerprint,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = "Biometric Quick-Unlock",
                        style = MaterialTheme.typography.titleMedium
                    )
                }

                if (uiState.isBiometricBlockedByPolicy) {
                    Text(
                        text = "Biometric quick-unlock is disabled by active security policy for this vault configuration.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.tertiary,
                        modifier = Modifier.testTag("biometric_policy_disabled_text")
                    )
                } else {
                    val keyBackingDescription = if (uiState.isBiometricEnrolled) {
                        if (uiState.isBiometricHardwareBacked) {
                            "Enrolled • Hardware-backed Android Keystore (TEE / StrongBox)"
                        } else {
                            "Enrolled • Android Keystore (software-backed on this device)"
                        }
                    } else {
                        "Wraps the vault DEK using a biometric-authenticated AES-256-GCM key in Android Keystore."
                    }
                    Text(
                        text = keyBackingDescription,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Button(
                            onClick = onRequestBiometricEnrollment,
                            enabled = !uiState.isBiometricEnrolled && !uiState.isBusy,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(if (uiState.isBiometricEnrolled) "Biometrics Enabled" else "Enable Biometrics")
                        }
                        if (uiState.isBiometricEnrolled) {
                            OutlinedButton(
                                onClick = viewModel::disableBiometricUnlock,
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Disable")
                            }
                        }
                    }
                }
            }
        }

        // R02 & N05 Fix: Password-Gated Plausible Deniability Policy Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(
                            Icons.Filled.Security,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.secondary
                        )
                        Text(
                            text = "Advanced Multi-Envelope Policy",
                            style = MaterialTheme.typography.titleMedium
                        )
                    }
                    if (uiState.isDecoyPolicySheetUnlocked) {
                        TextButton(onClick = viewModel::closeDecoyPolicySheet) {
                            Text("Lock Panel")
                        }
                    }
                }

                if (!uiState.isDecoyPolicySheetUnlocked) {
                    Text(
                        text = "Configure or rotate secondary key envelope policies. Requires Master Password verification.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    OutlinedButton(
                        onClick = { showPolicyGateDialog = true },
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("open_decoy_policy_gate_button")
                    ) {
                        Icon(Icons.Filled.Lock, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Verify Master Password to Configure")
                    }
                } else {
                    // Unlocked Decoy Policy Management Sheet (only reachable in Real Vault)
                    Text(
                        text = if (uiState.isDecoyModeEnabled) {
                            "Status: Decoy Vault is ACTIVE (Slot 1 configured). You can rotate the Decoy Password while preserving all decoy records, or perform a destructive reset."
                        } else {
                            "Status: Decoy Vault is NOT configured (Slot 1 holds an unconfigured dummy envelope)."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.secondary,
                        fontWeight = FontWeight.SemiBold
                    )

                    OutlinedTextField(
                        value = realPassForDecoy,
                        onValueChange = { realPassForDecoy = it },
                        label = { Text("Confirm Primary Master Password") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            autoCorrectEnabled = false
                        ),
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("decoy_real_master_password_input")
                    )

                    if (!uiState.isDecoyModeEnabled) {
                        // Flow 1: First-Time Decoy Provisioning
                        HorizontalDivider()
                        Text(
                            text = "Provision New Decoy Vault",
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.primary
                        )

                        OutlinedTextField(
                            value = decoyPass,
                            onValueChange = { decoyPass = it },
                            label = { Text("Decoy Password (min 8 chars)") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(
                                keyboardType = KeyboardType.Password,
                                autoCorrectEnabled = false
                            ),
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("decoy_new_password_input")
                        )

                        OutlinedTextField(
                            value = confirmDecoyPass,
                            onValueChange = { confirmDecoyPass = it },
                            label = { Text("Confirm Decoy Password") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(
                                keyboardType = KeyboardType.Password,
                                autoCorrectEnabled = false
                            ),
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("decoy_confirm_password_input")
                        )

                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(
                                checked = seedDecoyData,
                                onCheckedChange = { seedDecoyData = it }
                            )
                            Text(
                                text = "Seed plausible sample notes & credentials in Decoy Vault",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }

                        Button(
                            onClick = {
                                viewModel.configureDecoyVault(
                                    realMasterPassword = realPassForDecoy,
                                    decoyPassword = decoyPass,
                                    confirmDecoyPassword = confirmDecoyPass,
                                    seedPlausibleData = seedDecoyData,
                                    allowDestructiveReset = false
                                )
                                realPassForDecoy = ""
                                decoyPass = ""
                                confirmDecoyPass = ""
                            },
                            enabled = !uiState.isBusy && realPassForDecoy.isNotBlank() && decoyPass.length >= 8,
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("provision_decoy_button")
                        ) {
                            Text("Enable Decoy Vault")
                        }
                    } else {
                        // Flow 2 (N05 Fix): Non-Destructive Decoy Password Rotation
                        HorizontalDivider()
                        Text(
                            text = "Change Decoy Password (Preserves Existing Decoy Records)",
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "Re-wraps the existing Decoy DEK so all notes, passwords, and folders inside the Decoy Vault remain intact.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )

                        OutlinedTextField(
                            value = currentDecoyPass,
                            onValueChange = { currentDecoyPass = it },
                            label = { Text("Current Decoy Password") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(
                                keyboardType = KeyboardType.Password,
                                autoCorrectEnabled = false
                            ),
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("decoy_current_password_input")
                        )
                        OutlinedTextField(
                            value = decoyPass,
                            onValueChange = { decoyPass = it },
                            label = { Text("New Decoy Password (min 8 chars)") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(
                                keyboardType = KeyboardType.Password,
                                autoCorrectEnabled = false
                            ),
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("decoy_new_password_input")
                        )
                        OutlinedTextField(
                            value = confirmDecoyPass,
                            onValueChange = { confirmDecoyPass = it },
                            label = { Text("Confirm New Decoy Password") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(
                                keyboardType = KeyboardType.Password,
                                autoCorrectEnabled = false
                            ),
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("decoy_confirm_password_input")
                        )

                        Button(
                            onClick = {
                                viewModel.rotateDecoyPasswordPreservingData(
                                    realMasterPassword = realPassForDecoy,
                                    currentDecoyPassword = currentDecoyPass,
                                    newDecoyPassword = decoyPass,
                                    confirmNewDecoyPassword = confirmDecoyPass
                                )
                                realPassForDecoy = ""
                                currentDecoyPass = ""
                                decoyPass = ""
                                confirmDecoyPass = ""
                            },
                            enabled = !uiState.isBusy &&
                                realPassForDecoy.isNotBlank() &&
                                currentDecoyPass.isNotBlank() &&
                                decoyPass.length >= 8,
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("rotate_decoy_password_button")
                        ) {
                            Text("Rotate Decoy Password (Keep Data)")
                        }

                        // Flow 3 (N05 Fix): Explicit Destructive Reset & Wipe Decoy Vault
                        HorizontalDivider()
                        Text(
                            text = "Destructive Reset or Disable Decoy Vault",
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.error
                        )

                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(
                                checked = confirmDestructiveReset,
                                onCheckedChange = { confirmDestructiveReset = it },
                                modifier = Modifier.testTag("decoy_destructive_reset_checkbox")
                            )
                            Text(
                                text = "I understand that resetting or disabling the Decoy Vault permanently deletes all existing Decoy Vault records.",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }

                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(
                                checked = seedDecoyData,
                                onCheckedChange = { seedDecoyData = it }
                            )
                            Text(
                                text = "Seed fresh sample records on reset",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedButton(
                                onClick = {
                                    viewModel.configureDecoyVault(
                                        realMasterPassword = realPassForDecoy,
                                        decoyPassword = decoyPass,
                                        confirmDecoyPassword = confirmDecoyPass,
                                        seedPlausibleData = seedDecoyData,
                                        allowDestructiveReset = true
                                    )
                                    realPassForDecoy = ""
                                    currentDecoyPass = ""
                                    decoyPass = ""
                                    confirmDecoyPass = ""
                                    confirmDestructiveReset = false
                                },
                                enabled = !uiState.isBusy &&
                                    confirmDestructiveReset &&
                                    realPassForDecoy.isNotBlank() &&
                                    decoyPass.length >= 8,
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("reset_wipe_decoy_button")
                            ) {
                                Text("Reset & Wipe Decoy")
                            }

                            OutlinedButton(
                                onClick = {
                                    viewModel.disableDecoyVault(realPassForDecoy)
                                    realPassForDecoy = ""
                                    confirmDestructiveReset = false
                                },
                                enabled = !uiState.isBusy &&
                                    confirmDestructiveReset &&
                                    realPassForDecoy.isNotBlank(),
                                colors = ButtonDefaults.outlinedButtonColors(
                                    contentColor = MaterialTheme.colorScheme.error
                                ),
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("disable_decoy_button")
                            ) {
                                Text("Disable Decoy")
                            }
                        }
                    }
                }
            }
        }

        // Device Argon2id KDF Benchmark & Telemetry Card (R07: manual-only, no exact timestamp)
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        Icons.Filled.Speed,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = "Argon2id v1.3 KDF Parameters & Device Benchmark",
                        style = MaterialTheme.typography.titleMedium
                    )
                }

                val defaultMem = CryptoEngine.selectDefaultMemoryKb()
                val defaultIter = CryptoEngine.selectDefaultIterations()
                val statusLabel = if (preferences.lastBenchmarkSingleSlotMs > 0L) {
                    "MEASURED ON DEVICE (${preferences.lastBenchmarkDevice})"
                } else {
                    "PROPOSED DEFAULT (Run Benchmark Below to Measure on Device)"
                }

                Text(
                    text = "Parameter Status: $statusLabel",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.secondary
                )
                Text(
                    text = "• Algorithm: Argon2id v1.3 (org.bouncycastle:bcprov-jdk18on:1.80)\n" +
                        "• Memory per Slot: ${defaultMem / 1024} MiB ($defaultMem KB)\n" +
                        "• Iterations (t): $defaultIter • Parallelism (p): ${CryptoEngine.PROPOSED_STANDARD_PARALLELISM}",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )

                if (preferences.lastBenchmarkSingleSlotMs > 0L) {
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = "Recorded Device Telemetry:",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.primary
                            )
                            Text(
                                text = "Device: ${preferences.lastBenchmarkDevice}\n" +
                                    "Single-Slot Derivation: ${preferences.lastBenchmarkSingleSlotMs} ms\n" +
                                    "Two-Slot Unlock Path (Slot 0 + Slot 1): ${preferences.lastBenchmarkTwoSlotMs} ms\n" +
                                    "Heap Usage: ${preferences.lastBenchmarkUsedHeapMb} MB / ${preferences.lastBenchmarkMaxHeapMb} MB max",
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }
                }

                OutlinedButton(
                    onClick = viewModel::runDeviceKdfBenchmark,
                    enabled = !uiState.isBusy,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("run_kdf_benchmark_button")
                ) {
                    Text("Run 2-Slot Argon2id Benchmark Now")
                }
            }
        }
    }
}

// ============================================================================================
// 3. OTA Updates Screen & 3-Option Update Prompt Dialog (PV-BUG-010)
// ============================================================================================

@Composable
fun OtaUpdatesScreen(
    otaState: OtaUpdateManager.OtaState,
    preferences: VaultAppPreferences,
    viewModel: VaultViewModel,
    onBack: () -> Unit
) {
    BackHandler { onBack() }
    val context = LocalContext.current
    var manifestUrlInput by remember(preferences.otaManifestUrl) {
        mutableStateOf(preferences.otaManifestUrl)
    }

    val installedVersionName = remember(context) { OtaUpdateManager.getInstalledVersionName(context) }
    val installedVersionCode = remember(context) { OtaUpdateManager.getInstalledVersionCode(context) }
    val installedSignerDigests = remember(context) {
        OtaUpdateManager.getInstalledSignerSha256Digests(context)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        SecondaryHeader(
            title = "Updates (OTA)",
            onBack = onBack
        )

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "Installed Build & Trusted Signer",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = "Version: $installedVersionName (versionCode $installedVersionCode)",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "Trusted Signer SHA-256:\n${installedSignerDigests.firstOrNull() ?: "Unavailable"}",
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "Every OTA candidate APK is verified with SHA-256 + Android apksig ApkVerifier + installed signer certificate match + package archive metadata inspection before installation.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                // PV-BUG-010 Fix: User-configurable startup OTA check toggle
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Check for Updates Automatically on Launch")
                        Text(
                            text = "Queries the public GitHub update manifest once on startup.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(
                        checked = preferences.autoCheckOtaOnStartup,
                        onCheckedChange = viewModel::setAutoCheckOtaOnStartup,
                        modifier = Modifier.testTag("ota_auto_check_switch")
                    )
                }

                Button(
                    onClick = viewModel::checkForOtaUpdatesManual,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("ota_check_now_button")
                ) {
                    Icon(Icons.Filled.SystemUpdate, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Check for Updates Now")
                }

                if (BuildConfig.DEBUG) {
                    OutlinedButton(
                        onClick = viewModel::triggerDebugOtaSimulation,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("ota_simulate_debug_button")
                    ) {
                        Text("Debug Simulator: Preview 3-Option Update Prompt")
                    }
                }
            }
        }

        // Current OTA Status Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "Update Status",
                    style = MaterialTheme.typography.titleMedium
                )

                when (otaState) {
                    is OtaUpdateManager.OtaState.Idle -> {
                        Text(
                            text = "Idle. Tap 'Check for Updates Now' to query the public release manifest.",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }

                    is OtaUpdateManager.OtaState.Checking -> {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp))
                            Text("Checking HTTPS update manifest…")
                        }
                    }

                    is OtaUpdateManager.OtaState.UpToDate -> {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(
                                Icons.Filled.CheckCircle,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.secondary
                            )
                            Text(
                                "You are running the latest version (${otaState.currentVersionName})."
                            )
                        }
                    }

                    is OtaUpdateManager.OtaState.UpdateAvailable -> {
                        Text(
                            text = "Update Available: v${otaState.manifest.versionName} (code ${otaState.manifest.versionCode})",
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = otaState.manifest.releaseNotes,
                            style = MaterialTheme.typography.bodySmall
                        )
                        Button(
                            onClick = { viewModel.onOtaUpdateNowSelected(otaState.manifest) },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Filled.CloudDownload, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Update Now (Download & Verify)")
                        }
                    }

                    is OtaUpdateManager.OtaState.Downloading -> {
                        val fraction = if (otaState.totalBytes > 0L) {
                            (otaState.bytesDownloaded.toFloat() / otaState.totalBytes.toFloat()).coerceIn(0f, 1f)
                        } else {
                            0f
                        }
                        Text("Downloading v${otaState.manifest.versionName}…")
                        LinearProgressIndicator(
                            progress = { fraction },
                            modifier = Modifier.fillMaxWidth()
                        )
                        Text(
                            text = "${otaState.bytesDownloaded / 1024} KB / ${otaState.totalBytes / 1024} KB",
                            style = MaterialTheme.typography.labelSmall
                        )
                        OutlinedButton(
                            onClick = viewModel::cancelOtaDownload,
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("ota_cancel_download_button")
                        ) {
                            Text("Cancel Download")
                        }
                    }

                    is OtaUpdateManager.OtaState.Verifying -> {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            CircularProgressIndicator(modifier = Modifier.size(20.dp))
                            Text("Verifying SHA-256 & apksig signer certificate…")
                        }
                    }

                    is OtaUpdateManager.OtaState.ReadyToInstall -> {
                        Text(
                            text = "Verified v${otaState.manifest.versionName} Ready to Install",
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.secondary
                        )
                        Text(
                            text = "Verified Signer SHA-256:\n${otaState.signerCertificateSha256}",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace
                        )
                        Button(
                            onClick = {
                                val installIntent = viewModel.otaUpdateManager.buildInstallVerifiedApkIntent(
                                    otaState.verifiedApkFile
                                )
                                viewModel.lockVaultNow("Vault locked before launching system package installer.")
                                try {
                                    context.startActivity(installIntent)
                                } catch (e: Exception) {
                                    viewModel.setErrorBanner("Could not launch package installer: ${e.message}")
                                }
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("ota_confirm_install_button")
                        ) {
                            Text("Confirm Installation in Android")
                        }
                    }

                    is OtaUpdateManager.OtaState.NeedsUnknownSourcesPermission -> {
                        Text(
                            text = "APK Verified! Android requires 'Install unknown apps' permission for PRIVATE VAULT to launch the package installer.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.tertiary
                        )
                        Button(
                            onClick = {
                                val settingsIntent = viewModel.otaUpdateManager.buildManageUnknownAppSourcesIntent()
                                viewModel.lockVaultNow("Vault locked before opening Android Unknown App Sources settings.")
                                try {
                                    context.startActivity(settingsIntent)
                                } catch (e: Exception) {
                                    viewModel.setErrorBanner("Could not open Unknown App Sources settings: ${e.message}")
                                }
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("ota_open_unknown_sources_button")
                        ) {
                            Icon(Icons.Filled.Build, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Grant Install Permission in Settings")
                        }
                        OutlinedButton(
                            onClick = {
                                if (viewModel.otaUpdateManager.canRequestPackageInstalls()) {
                                    val installIntent = viewModel.otaUpdateManager.buildInstallVerifiedApkIntent(
                                        otaState.verifiedApkFile
                                    )
                                    viewModel.lockVaultNow("Vault locked before launching system package installer.")
                                    try {
                                        context.startActivity(installIntent)
                                    } catch (e: Exception) {
                                        viewModel.setErrorBanner("Could not launch package installer: ${e.message}")
                                    }
                                }
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Proceed to Install Verified APK")
                        }
                    }

                    is OtaUpdateManager.OtaState.Error -> {
                        Text(
                            text = otaState.title,
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.error
                        )
                        Text(
                            text = otaState.detail,
                            style = MaterialTheme.typography.bodySmall
                        )
                        if (otaState.recoverableManifest != null) {
                            OutlinedButton(
                                onClick = {
                                    viewModel.onOtaUpdateNowSelected(otaState.recoverableManifest)
                                }
                            ) {
                                Text("Retry Download & Verification")
                            }
                        }
                    }
                }
            }
        }

        // Public Manifest Endpoint Configuration (Editable only in Debug builds — R04)
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "Public Release Endpoint",
                    style = MaterialTheme.typography.titleMedium
                )
                Text(
                    text = "Public Update Repository: ${AppPreferencesRepository.PUBLIC_OTA_REPO_URL}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                if (BuildConfig.DEBUG) {
                    OutlinedTextField(
                        value = manifestUrlInput,
                        onValueChange = { manifestUrlInput = it },
                        label = { Text("HTTPS update.json Manifest URL (Debug Override)") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedButton(
                        onClick = { viewModel.updateOtaManifestUrl(manifestUrlInput) },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Save Manifest Endpoint")
                    }
                } else {
                    Text(
                        text = "Manifest Endpoint:\n${AppPreferencesRepository.DEFAULT_OTA_MANIFEST_URL}",
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

/**
 * Mandatory 3-option OTA Update Dialog:
 * - **Update Now:** Downloads and verifies the update, then asks the user to confirm installation.
 * - **Update Later:** Closes the dialog and continues using the app.
 * - **Remind Me Later:** Lets the user choose Next app launch, Tomorrow, or In 3 days.
 */
@Composable
fun OtaThreeOptionUpdateDialog(
    manifest: OtaUpdateManager.UpdateManifest,
    onUpdateNow: () -> Unit,
    onUpdateLater: () -> Unit,
    onRemindMeLater: (OtaReminderPolicy) -> Unit
) {
    var showReminderSubChoices by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onUpdateLater,
        icon = {
            Icon(
                Icons.Filled.SystemUpdate,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary
            )
        },
        title = {
            Text(
                text = "Update Available: v${manifest.versionName}",
                style = MaterialTheme.typography.titleLarge
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = "A new signed release of PRIVATE VAULT is available. Your encrypted Real and Decoy vaults are preserved across updates.",
                    style = MaterialTheme.typography.bodySmall
                )
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(
                            text = "Release Notes:",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = manifest.releaseNotes,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }

                if (!showReminderSubChoices) {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = onUpdateNow,
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("ota_dialog_update_now_button")
                        ) {
                            Icon(Icons.Filled.CloudDownload, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Update Now")
                        }

                        OutlinedButton(
                            onClick = onUpdateLater,
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("ota_dialog_update_later_button")
                        ) {
                            Text("Update Later")
                        }

                        TextButton(
                            onClick = { showReminderSubChoices = true },
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("ota_dialog_remind_me_later_button")
                        ) {
                            Text("Remind Me Later…")
                        }
                    }
                } else {
                    Text(
                        text = "When should PRIVATE VAULT remind you?",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        OutlinedButton(
                            onClick = { onRemindMeLater(OtaReminderPolicy.NEXT_APP_LAUNCH) },
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("ota_remind_next_launch_button")
                        ) {
                            Text("Next App Launch")
                        }
                        OutlinedButton(
                            onClick = { onRemindMeLater(OtaReminderPolicy.TOMORROW) },
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("ota_remind_tomorrow_button")
                        ) {
                            Text("Tomorrow (24 Hours)")
                        }
                        OutlinedButton(
                            onClick = { onRemindMeLater(OtaReminderPolicy.IN_THREE_DAYS) },
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("ota_remind_three_days_button")
                        ) {
                            Text("In 3 Days")
                        }
                    }
                }
            }
        },
        confirmButton = {}
    )
}

// ============================================================================================
// 4. About & Developer Credits Screen (Tp Editz — Telegram + Instagram U04)
// ============================================================================================

@Composable
fun AboutVaultScreen(
    viewModel: VaultViewModel,
    onBack: () -> Unit
) {
    BackHandler { onBack() }
    val context = LocalContext.current
    var pendingExternalDestination by remember { mutableStateOf<Pair<String, String>?>(null) }

    val openDestinationPair = pendingExternalDestination
    if (openDestinationPair != null) {
        val (platformName, targetUrl) = openDestinationPair
        AlertDialog(
            onDismissRequest = { pendingExternalDestination = null },
            icon = { Icon(Icons.Filled.OpenInBrowser, contentDescription = null) },
            title = { Text("Open External $platformName Profile?") },
            text = {
                Text(
                    "For your security, PRIVATE VAULT will lock your active vault session before opening $targetUrl in an external app."
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        pendingExternalDestination = null
                        viewModel.lockVaultNow("Vault locked before opening external link.")
                        try {
                            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(targetUrl)).apply {
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            }
                            context.startActivity(intent)
                        } catch (_: ActivityNotFoundException) {
                            viewModel.setErrorBanner("No browser or app installed to open $targetUrl.")
                        } catch (e: Exception) {
                            viewModel.setErrorBanner("Unable to open link: ${e.message}")
                        }
                    },
                    modifier = Modifier.testTag("confirm_external_open_button")
                ) {
                    Text("Lock Vault & Open")
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingExternalDestination = null }) {
                    Text("Cancel")
                }
            }
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        SecondaryHeader(
            title = "About & Credits",
            onBack = onBack
        )

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
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
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Version ${OtaUpdateManager.getInstalledVersionName(context)} (Code ${OtaUpdateManager.getInstalledVersionCode(context)}) • Offline Encrypted Security Suite",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.testTag("about_installed_version_text")
                        )
                    }
                }

                HorizontalDivider()

                // Developer Credits Block (Telegram + Instagram U04, Section 09, T22)
                Text(
                    text = "Developed by Tp Editz",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Telegram: @Tp_Editz",
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace
                )

                BoxWithConstraints(modifier = Modifier.fillMaxWidth()) {
                    val isNarrow = maxWidth < 360.dp
                    if (isNarrow) {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedButton(
                                onClick = {
                                    viewModel.copyPublicContactHandle("Telegram ID", "@Tp_Editz")
                                },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("copy_telegram_id_button")
                            ) {
                                Icon(Icons.Filled.ContentCopy, contentDescription = null)
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Copy Telegram ID")
                            }
                            Button(
                                onClick = {
                                    pendingExternalDestination = "Telegram" to "https://t.me/Tp_Editz"
                                },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("open_telegram_button")
                            ) {
                                Icon(Icons.Filled.OpenInBrowser, contentDescription = null)
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Open Telegram")
                            }
                        }
                    } else {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            OutlinedButton(
                                onClick = {
                                    viewModel.copyPublicContactHandle("Telegram ID", "@Tp_Editz")
                                },
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("copy_telegram_id_button")
                            ) {
                                Icon(Icons.Filled.ContentCopy, contentDescription = null)
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Copy Telegram ID")
                            }

                            Button(
                                onClick = {
                                    pendingExternalDestination = "Telegram" to "https://t.me/Tp_Editz"
                                },
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("open_telegram_button")
                            ) {
                                Icon(Icons.Filled.OpenInBrowser, contentDescription = null)
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Open Telegram")
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(4.dp))

                // U04 Fix: Instagram Developer Credit Row
                Text(
                    text = "Instagram: @tp_ediitz",
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace
                )

                BoxWithConstraints(modifier = Modifier.fillMaxWidth()) {
                    val isNarrow = maxWidth < 360.dp
                    if (isNarrow) {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedButton(
                                onClick = {
                                    viewModel.copyPublicContactHandle("Instagram ID", "@tp_ediitz")
                                },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("copy_instagram_id_button")
                            ) {
                                Icon(Icons.Filled.ContentCopy, contentDescription = null)
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Copy Instagram ID")
                            }
                            Button(
                                onClick = {
                                    pendingExternalDestination = "Instagram" to "https://www.instagram.com/tp_ediitz/"
                                },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("open_instagram_button")
                            ) {
                                Icon(Icons.Filled.OpenInBrowser, contentDescription = null)
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Open Instagram")
                            }
                        }
                    } else {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            OutlinedButton(
                                onClick = {
                                    viewModel.copyPublicContactHandle("Instagram ID", "@tp_ediitz")
                                },
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("copy_instagram_id_button")
                            ) {
                                Icon(Icons.Filled.ContentCopy, contentDescription = null)
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Copy Instagram ID")
                            }

                            Button(
                                onClick = {
                                    pendingExternalDestination = "Instagram" to "https://www.instagram.com/tp_ediitz/"
                                },
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("open_instagram_button")
                            ) {
                                Icon(Icons.Filled.OpenInBrowser, contentDescription = null)
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Open Instagram")
                            }
                        }
                    }
                }
            }
        }

        // Security Architecture & Honest Plausible Deniability Limitations Disclosure
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        Icons.Filled.Info,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.secondary
                    )
                    Text(
                        text = "Cryptographic Specification & Decoy Limitations",
                        style = MaterialTheme.typography.titleMedium
                    )
                }

                Text(
                    text = "• Key Derivation: Argon2id v1.3 (RFC 9106) via BouncyCastle (bcprov-jdk18on:1.80)\n" +
                        "• Encryption: AES-256-GCM with 96-bit CSPRNG nonces and 128-bit authentication tags\n" +
                        "• Unified Key Envelopes: Both Slot 0 and Slot 1 rows always exist in vault_envelopes (72-byte wrapped payload) and are evaluated on every password unlock attempt\n" +
                        "• Composite SQLite Primary Key: encrypted_records enforces PRIMARY KEY(vault_slot, record_id) with strict AAD slot binding",
                    style = MaterialTheme.typography.bodySmall
                )

                HorizontalDivider()

                Text(
                    text = "Plausible Deniability Scope & Forensic Limitations:",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.tertiary
                )
                Text(
                    text = "1. Casual Coercion Resistance: Entering your Decoy Password unlocks an isolated second vault with zero UI indicators of a primary vault.\n" +
                        "2. Root / Raw SQLite Inspection: While both key envelopes are always present and structurally identical, a forensic examiner with root access to `/data/data/com.tpeditz.privatevault/databases/` can observe the count and ciphertext byte lengths of rows in `encrypted_records` per `vault_slot`.\n" +
                        "3. Biometric Trade-Off: Enrolling Android Keystore biometrics binds a hardware key to Slot 0; therefore, PRIVATE VAULT automatically disables biometric quick-unlock whenever Decoy Mode is active.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun SecondaryHeader(
    title: String,
    onBack: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        IconButton(
            onClick = onBack,
            modifier = Modifier.testTag("secondary_back_button")
        ) {
            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
        }
        Text(
            text = title,
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold
        )
    }
}

package com.example.ui

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Archive
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.RestoreFromTrash
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.StarOutline
import androidx.compose.material.icons.outlined.Unarchive
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.CustomCredentialField
import com.example.data.VaultRecordPayload
import com.example.security.OfflinePasswordStrengthEstimator
import com.example.security.PasswordGeneratorEngine
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.StatusFair
import com.example.ui.theme.StatusStrong
import com.example.ui.theme.StatusVeryStrong
import com.example.ui.theme.StatusVeryWeak
import com.example.ui.theme.StatusWeak
import java.util.Locale
import java.util.UUID

@Composable
fun PasswordsTabScreen(
    uiState: VaultUiState,
    viewModel: VaultViewModel
) {
    var editingCredential by remember { mutableStateOf<VaultRecordPayload.CredentialRecord?>(null) }
    var credentialPendingPermanentDelete by remember { mutableStateOf<VaultRecordPayload.CredentialRecord?>(null) }

    // If the user tapped "Save to Passwords" in the Generator tab, open the new credential editor
    LaunchedEffect(uiState.prefilledGeneratorPasswordForNewCredential) {
        val prefilled = uiState.prefilledGeneratorPasswordForNewCredential
        if (!prefilled.isNullOrEmpty()) {
            val now = System.currentTimeMillis()
            editingCredential = VaultRecordPayload.CredentialRecord(
                id = UUID.randomUUID().toString(),
                serviceName = "",
                accountLabel = "Personal",
                password = prefilled,
                folderName = if (uiState.selectedCredentialFolder == "All") "General" else uiState.selectedCredentialFolder,
                createdAtEpochMs = now,
                updatedAtEpochMs = now
            )
            viewModel.clearPrefilledGeneratorPassword()
        }
    }

    if (editingCredential != null) {
        CredentialEditorView(
            initialCredential = editingCredential!!,
            availableFolders = uiState.folders.map { it.name }.ifEmpty { listOf("General", "Personal", "Work") },
            evaluateStrength = { pwd, id ->
                viewModel.evaluatePasswordStrengthInActiveVault(pwd, id)
            },
            onSave = { updated ->
                viewModel.saveCredential(updated) {
                    editingCredential = null
                }
            },
            onDuplicate = { cred ->
                viewModel.duplicateCredential(cred)
                editingCredential = null
            },
            onMoveToTrash = { cred ->
                viewModel.moveCredentialToTrash(cred)
                editingCredential = null
            },
            onClose = { editingCredential = null }
        )
        return
    }

    val folderNames = remember(uiState.folders) {
        listOf("All") + uiState.folders.map { it.name }.distinct()
    }

    // Active-vault password reuse map: password -> count of non-trashed credentials in THIS vault
    val reuseCountByPassword = remember(uiState.credentials) {
        uiState.credentials
            .filter { !it.isTrashed && it.password.isNotEmpty() }
            .groupingBy { it.password }
            .eachCount()
    }

    val filteredCredentials = remember(
        uiState.credentials,
        uiState.credentialSearchQuery,
        uiState.selectedCredentialFolder,
        uiState.credentialFilterMode
    ) {
        val q = uiState.credentialSearchQuery.trim().lowercase(Locale.ROOT)
        uiState.credentials
            .filter { cred ->
                when (uiState.credentialFilterMode) {
                    CredentialFilterMode.ACTIVE -> !cred.isTrashed && !cred.isArchived
                    CredentialFilterMode.FAVORITES -> !cred.isTrashed && cred.isFavorite
                    CredentialFilterMode.ARCHIVED -> !cred.isTrashed && cred.isArchived
                    CredentialFilterMode.TRASH -> cred.isTrashed
                }
            }
            .filter { cred ->
                uiState.selectedCredentialFolder == "All" ||
                    cred.folderName.equals(uiState.selectedCredentialFolder, ignoreCase = true)
            }
            .filter { cred ->
                // Search service name, account label, username, email, and folder/tags WITHOUT exposing password values (Section 08)
                if (q.isEmpty()) true
                else {
                    cred.serviceName.lowercase(Locale.ROOT).contains(q) ||
                        cred.accountLabel.lowercase(Locale.ROOT).contains(q) ||
                        cred.username.lowercase(Locale.ROOT).contains(q) ||
                        cred.email.lowercase(Locale.ROOT).contains(q) ||
                        cred.folderName.lowercase(Locale.ROOT).contains(q) ||
                        cred.tags.any { it.lowercase(Locale.ROOT).contains(q) }
                }
            }
            .sortedWith(
                compareByDescending<VaultRecordPayload.CredentialRecord> { it.isFavorite }
                    .thenBy { it.serviceName.lowercase(Locale.ROOT) }
                    .thenBy { it.accountLabel.lowercase(Locale.ROOT) }
            )
    }

    Scaffold(
        floatingActionButton = {
            FloatingActionButton(
                onClick = {
                    val now = System.currentTimeMillis()
                    editingCredential = VaultRecordPayload.CredentialRecord(
                        id = UUID.randomUUID().toString(),
                        serviceName = "",
                        accountLabel = "Personal",
                        password = "",
                        folderName = if (uiState.selectedCredentialFolder == "All") "General" else uiState.selectedCredentialFolder,
                        createdAtEpochMs = now,
                        updatedAtEpochMs = now
                    )
                },
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
                modifier = Modifier.testTag("create_credential_fab")
            ) {
                Icon(imageVector = Icons.Filled.Add, contentDescription = "Add Saved Password")
            }
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            OutlinedTextField(
                value = uiState.credentialSearchQuery,
                onValueChange = viewModel::updateCredentialSearchQuery,
                placeholder = { Text("Search service, label, username, or email...") },
                singleLine = true,
                leadingIcon = {
                    Icon(imageVector = Icons.Filled.Search, contentDescription = "Search credentials")
                },
                trailingIcon = {
                    if (uiState.credentialSearchQuery.isNotEmpty()) {
                        IconButton(onClick = { viewModel.updateCredentialSearchQuery("") }) {
                            Icon(imageVector = Icons.Filled.Close, contentDescription = "Clear search")
                        }
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp)
                    .testTag("passwords_search_input")
            )

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                CredentialFilterMode.entries.forEach { mode ->
                    FilterChip(
                        selected = uiState.credentialFilterMode == mode,
                        onClick = { viewModel.updateCredentialFilterMode(mode) },
                        label = { Text(mode.label) }
                    )
                }
            }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                folderNames.forEach { folder ->
                    AssistChip(
                        onClick = { viewModel.updateSelectedCredentialFolder(folder) },
                        label = {
                            Text(
                                text = folder,
                                fontWeight = if (uiState.selectedCredentialFolder == folder) FontWeight.Bold else FontWeight.Normal
                            )
                        }
                    )
                }
            }

            if (filteredCredentials.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Key,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(48.dp)
                        )
                        Text(
                            text = "No saved passwords in ${uiState.credentialFilterMode.label}",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            text = "Tap + to store an encrypted credential or multiple accounts per service.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .weight(1f),
                    contentPadding = PaddingValues(bottom = 88.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(filteredCredentials, key = { it.id }) { cred ->
                        val isReused = (reuseCountByPassword[cred.password] ?: 0) > 1
                        val strength = remember(cred.password, isReused) {
                            viewModel.evaluatePasswordStrengthInActiveVault(cred.password, cred.id)
                        }
                        CredentialListCard(
                            credential = cred,
                            strengthReport = strength,
                            isReusedInActiveVault = isReused,
                            onEdit = { editingCredential = cred },
                            onCopyUsername = {
                                val userOrEmail = cred.username.ifBlank { cred.email }
                                viewModel.copySecretToClipboard("Username", userOrEmail)
                            },
                            onCopyPassword = {
                                viewModel.copySecretToClipboard("Password", cred.password)
                            },
                            onToggleFavorite = {
                                viewModel.saveCredential(cred.copy(isFavorite = !cred.isFavorite))
                            },
                            onToggleArchive = {
                                viewModel.saveCredential(cred.copy(isArchived = !cred.isArchived))
                            },
                            onRestoreFromTrash = {
                                viewModel.restoreCredentialFromTrash(cred)
                            },
                            onDeletePermanently = {
                                credentialPendingPermanentDelete = cred
                            }
                        )
                    }
                }
            }
        }
    }

    if (credentialPendingPermanentDelete != null) {
        val target = credentialPendingPermanentDelete!!
        AlertDialog(
            onDismissRequest = { credentialPendingPermanentDelete = null },
            title = { Text("Permanently Delete Credential?") },
            text = {
                Text(
                    "Permanently delete \"${target.serviceName} (${target.accountLabel})\" from this encrypted vault? This cannot be undone."
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.deleteRecordPermanently(target.id)
                        credentialPendingPermanentDelete = null
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                ) {
                    Text("Delete Permanently")
                }
            },
            dismissButton = {
                TextButton(onClick = { credentialPendingPermanentDelete = null }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun CredentialListCard(
    credential: VaultRecordPayload.CredentialRecord,
    strengthReport: OfflinePasswordStrengthEstimator.StrengthReport,
    isReusedInActiveVault: Boolean,
    onEdit: () -> Unit,
    onCopyUsername: () -> Unit,
    onCopyPassword: () -> Unit,
    onToggleFavorite: () -> Unit,
    onToggleArchive: () -> Unit,
    onRestoreFromTrash: () -> Unit,
    onDeletePermanently: () -> Unit
) {
    var isPasswordRevealed by remember(credential.id) { mutableStateOf(false) }
    var showExternalBrowserConfirm by remember { mutableStateOf(false) }
    val context = LocalContext.current

    val initials = remember(credential.serviceName) {
        credential.serviceName
            .trim()
            .split(" ")
            .filter { it.isNotEmpty() }
            .take(2)
            .joinToString("") { it.first().uppercase() }
            .ifEmpty { "PV" }
    }

    val badgeColor = when (strengthReport.rating) {
        OfflinePasswordStrengthEstimator.StrengthRating.VERY_WEAK -> StatusVeryWeak
        OfflinePasswordStrengthEstimator.StrengthRating.WEAK -> StatusWeak
        OfflinePasswordStrengthEstimator.StrengthRating.FAIR -> StatusFair
        OfflinePasswordStrengthEstimator.StrengthRating.STRONG -> StatusStrong
        OfflinePasswordStrengthEstimator.StrengthRating.VERY_STRONG -> StatusVeryStrong
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onEdit)
            .testTag("credential_card_${credential.id}")
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Local monogram icon (never fetches online favicons per Section 08)
                Box(
                    modifier = Modifier
                        .size(44.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primaryContainer),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = initials,
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        fontWeight = FontWeight.Bold
                    )
                }

                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = credential.serviceName,
                            style = MaterialTheme.typography.titleMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Surface(
                            color = MaterialTheme.colorScheme.secondaryContainer,
                            shape = MaterialTheme.shapes.extraSmall
                        ) {
                            Text(
                                text = credential.accountLabel,
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSecondaryContainer,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                    }

                    val primaryIdentity = credential.username.ifBlank { credential.email }
                    if (primaryIdentity.isNotBlank()) {
                        Text(
                            text = primaryIdentity,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }

                if (!credential.isTrashed) {
                    Row {
                        IconButton(onClick = onToggleFavorite, modifier = Modifier.size(36.dp)) {
                            Icon(
                                imageVector = if (credential.isFavorite) Icons.Filled.Star else Icons.Outlined.StarOutline,
                                contentDescription = if (credential.isFavorite) "Remove favorite" else "Mark favorite",
                                tint = if (credential.isFavorite) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        IconButton(onClick = onToggleArchive, modifier = Modifier.size(36.dp)) {
                            Icon(
                                imageVector = if (credential.isArchived) Icons.Outlined.Unarchive else Icons.Filled.Archive,
                                contentDescription = if (credential.isArchived) "Unarchive" else "Archive",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                } else {
                    Row {
                        IconButton(onClick = onRestoreFromTrash) {
                            Icon(
                                imageVector = Icons.Filled.RestoreFromTrash,
                                contentDescription = "Restore credential",
                                tint = MaterialTheme.colorScheme.primary
                            )
                        }
                        IconButton(onClick = onDeletePermanently) {
                            Icon(
                                imageVector = Icons.Filled.DeleteForever,
                                contentDescription = "Delete credential permanently",
                                tint = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                }
            }

            // Masked / Revealed Password Row with Accessible Announcements (Section 06 & 08)
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f),
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = if (isPasswordRevealed) credential.password else "••••••••••••••••",
                        style = MaterialTheme.typography.bodyMedium,
                        fontFamily = JetBrainsMonoFontFamily,
                        modifier = Modifier
                            .weight(1f)
                            .semantics {
                                // Do not read secret value automatically unless user deliberately revealed it
                                contentDescription = if (isPasswordRevealed) {
                                    "Password revealed"
                                } else {
                                    "Password masked"
                                }
                            }
                            .testTag("credential_password_display_${credential.id}")
                    )

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        IconButton(
                            onClick = { isPasswordRevealed = !isPasswordRevealed },
                            modifier = Modifier
                                .semantics {
                                    contentDescription = if (isPasswordRevealed) {
                                        "Password currently revealed. Tap to mask password."
                                    } else {
                                        "Password currently masked. Tap to reveal password."
                                    }
                                }
                                .testTag("credential_reveal_button_${credential.id}")
                        ) {
                            Icon(
                                imageVector = if (isPasswordRevealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = null
                            )
                        }

                        if (credential.username.isNotBlank() || credential.email.isNotBlank()) {
                            TextButton(
                                onClick = onCopyUsername,
                                modifier = Modifier.testTag("copy_username_button_${credential.id}")
                            ) {
                                Text("Copy ID")
                            }
                        }

                        TextButton(
                            onClick = onCopyPassword,
                            modifier = Modifier.testTag("copy_password_button_${credential.id}")
                        ) {
                            Icon(
                                imageVector = Icons.Filled.ContentCopy,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Copy Pass")
                        }
                    }
                }
            }

            // Strength & Local Reuse Badges
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Surface(
                    color = badgeColor.copy(alpha = 0.18f),
                    shape = MaterialTheme.shapes.extraSmall
                ) {
                    Text(
                        text = "Strength: ${strengthReport.rating.label}",
                        style = MaterialTheme.typography.labelSmall,
                        color = badgeColor,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }

                if (isReusedInActiveVault) {
                    Surface(
                        color = StatusWeak.copy(alpha = 0.2f),
                        shape = MaterialTheme.shapes.extraSmall
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp),
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Warning,
                                contentDescription = "Reused password warning",
                                tint = StatusWeak,
                                modifier = Modifier.size(13.dp)
                            )
                            Text(
                                text = "Reused in this vault",
                                style = MaterialTheme.typography.labelSmall,
                                color = StatusWeak
                            )
                        }
                    }
                }

                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    shape = MaterialTheme.shapes.extraSmall
                ) {
                    Text(
                        text = credential.folderName,
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }

                if (credential.websiteUrl.isNotBlank()) {
                    AssistChip(
                        onClick = { showExternalBrowserConfirm = true },
                        leadingIcon = {
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.OpenInNew,
                                contentDescription = null,
                                modifier = Modifier.size(14.dp)
                            )
                        },
                        label = { Text("Open URL") },
                        modifier = Modifier.height(26.dp)
                    )
                }
            }
        }
    }

    if (showExternalBrowserConfirm) {
        AlertDialog(
            onDismissRequest = { showExternalBrowserConfirm = false },
            title = { Text("Open Website in External Browser?") },
            text = {
                Text(
                    "Open \"${credential.websiteUrl}\" in your device's external web browser? PRIVATE VAULT never attaches your username or password to the URL."
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showExternalBrowserConfirm = false
                        val rawUrl = credential.websiteUrl.trim()
                        val safeUrl = if (rawUrl.startsWith("https://") || rawUrl.startsWith("http://")) {
                            rawUrl
                        } else {
                            "https://$rawUrl"
                        }
                        try {
                            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(safeUrl)).apply {
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            }
                            context.startActivity(intent)
                        } catch (_: Exception) {
                        }
                    }
                ) {
                    Text("Open Externally")
                }
            },
            dismissButton = {
                TextButton(onClick = { showExternalBrowserConfirm = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun CredentialEditorView(
    initialCredential: VaultRecordPayload.CredentialRecord,
    availableFolders: List<String>,
    evaluateStrength: (String, String) -> OfflinePasswordStrengthEstimator.StrengthReport,
    onSave: (VaultRecordPayload.CredentialRecord) -> Unit,
    onDuplicate: (VaultRecordPayload.CredentialRecord) -> Unit,
    onMoveToTrash: (VaultRecordPayload.CredentialRecord) -> Unit,
    onClose: () -> Unit
) {
    var serviceName by remember(initialCredential.id) { mutableStateOf(initialCredential.serviceName) }
    var accountLabel by remember(initialCredential.id) { mutableStateOf(initialCredential.accountLabel) }
    var username by remember(initialCredential.id) { mutableStateOf(initialCredential.username) }
    var email by remember(initialCredential.id) { mutableStateOf(initialCredential.email) }
    var password by remember(initialCredential.id) { mutableStateOf(initialCredential.password) }
    var showPassword by remember { mutableStateOf(false) }
    var websiteUrl by remember(initialCredential.id) { mutableStateOf(initialCredential.websiteUrl) }
    var folderName by remember(initialCredential.id) { mutableStateOf(initialCredential.folderName) }
    var tagsText by remember(initialCredential.id) { mutableStateOf(initialCredential.tags.joinToString(", ")) }
    var privateNotes by remember(initialCredential.id) { mutableStateOf(initialCredential.privateNotes) }
    var customFields by remember(initialCredential.id) { mutableStateOf(initialCredential.customFields) }
    var newCustomLabel by remember { mutableStateOf("") }
    var newCustomValue by remember { mutableStateOf("") }
    var validationError by remember { mutableStateOf<String?>(null) }

    val strengthReport = remember(password) {
        evaluateStrength(password, initialCredential.id)
    }

    fun buildCurrentRecord(): VaultRecordPayload.CredentialRecord {
        val parsedTags = tagsText.split(",")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()
        return initialCredential.copy(
            serviceName = serviceName.trim(),
            accountLabel = accountLabel.trim().ifBlank { "Personal" },
            username = username.trim(),
            email = email.trim(),
            password = password,
            websiteUrl = websiteUrl.trim(),
            folderName = folderName,
            tags = parsedTags,
            privateNotes = privateNotes,
            customFields = customFields
        )
    }

    BackHandler(onBack = onClose)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = onClose) {
                Icon(imageVector = Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back to passwords")
            }
            Text(
                text = if (initialCredential.serviceName.isBlank()) "New Saved Credential" else "Edit Credential",
                style = MaterialTheme.typography.titleLarge
            )
            Row {
                if (initialCredential.serviceName.isNotBlank()) {
                    IconButton(onClick = { onDuplicate(buildCurrentRecord()) }) {
                        Icon(imageVector = Icons.Filled.ContentCopy, contentDescription = "Duplicate credential")
                    }
                    IconButton(onClick = { onMoveToTrash(buildCurrentRecord()) }) {
                        Icon(
                            imageVector = Icons.Filled.Delete,
                            contentDescription = "Move credential to trash",
                            tint = MaterialTheme.colorScheme.error
                        )
                    }
                }
            }
        }

        // Important Local-Only Distinction Banner (Section 08 & 10)
        Surface(
            color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.7f),
            shape = MaterialTheme.shapes.small,
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier.padding(12.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    imageVector = Icons.Outlined.Info,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp)
                )
                Text(
                    text = "Local Vault Record: Saving or replacing a password here updates your encrypted vault on this device only. Remember to also update the password on the actual service's website or app.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        OutlinedTextField(
            value = serviceName,
            onValueChange = { serviceName = it },
            label = { Text("Service or App Name (e.g. GitHub, ProtonMail)") },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .testTag("credential_service_input")
        )

        OutlinedTextField(
            value = accountLabel,
            onValueChange = { accountLabel = it },
            label = { Text("Account Label (e.g. Personal, Work, Secondary)") },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .testTag("credential_label_input")
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            OutlinedTextField(
                value = username,
                onValueChange = { username = it },
                label = { Text("Username") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.None,
                    autoCorrectEnabled = false
                ),
                modifier = Modifier
                    .weight(1f)
                    .testTag("credential_username_input")
            )
            OutlinedTextField(
                value = email,
                onValueChange = { email = it },
                label = { Text("Email") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.None,
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Email
                ),
                modifier = Modifier
                    .weight(1f)
                    .testTag("credential_email_input")
            )
        }

        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password *") },
            singleLine = true,
            visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                capitalization = KeyboardCapitalization.None,
                autoCorrectEnabled = false,
                keyboardType = KeyboardType.Password
            ),
            trailingIcon = {
                Row {
                    IconButton(
                        onClick = { showPassword = !showPassword },
                        modifier = Modifier.semantics {
                            contentDescription = if (showPassword) "Hide password" else "Reveal password"
                        }
                    ) {
                        Icon(
                            imageVector = if (showPassword) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                            contentDescription = null
                        )
                    }
                    IconButton(
                        onClick = {
                            val generated = PasswordGeneratorEngine.generate(
                                PasswordGeneratorEngine.GeneratorConfig(length = 20)
                            )
                            if (generated is PasswordGeneratorEngine.GenerationResult.Success) {
                                password = generated.password
                                showPassword = true
                            }
                        },
                        modifier = Modifier.testTag("credential_inline_generate_button")
                    ) {
                        Icon(
                            imageVector = Icons.Filled.AutoFixHigh,
                            contentDescription = "Generate strong 20-character random password"
                        )
                    }
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .testTag("credential_password_input")
        )

        if (password.isNotEmpty()) {
            val barColor = when (strengthReport.rating) {
                OfflinePasswordStrengthEstimator.StrengthRating.VERY_WEAK -> StatusVeryWeak
                OfflinePasswordStrengthEstimator.StrengthRating.WEAK -> StatusWeak
                OfflinePasswordStrengthEstimator.StrengthRating.FAIR -> StatusFair
                OfflinePasswordStrengthEstimator.StrengthRating.STRONG -> StatusStrong
                OfflinePasswordStrengthEstimator.StrengthRating.VERY_STRONG -> StatusVeryStrong
            }
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = "Local Strength: ${strengthReport.rating.label}",
                            style = MaterialTheme.typography.labelMedium,
                            color = barColor
                        )
                        Text(
                            text = "~${strengthReport.effectiveEntropyBits.toInt()} bits",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = JetBrainsMonoFontFamily
                        )
                    }
                    LinearProgressIndicator(
                        progress = { (strengthReport.scoreOutOf100 / 100f).coerceIn(0.05f, 1f) },
                        color = barColor,
                        modifier = Modifier.fillMaxWidth()
                    )
                    if (strengthReport.reusedServiceNames.isNotEmpty()) {
                        Text(
                            text = "Reuse Warning: Also used by ${strengthReport.reusedServiceNames.joinToString(", ")} in this vault.",
                            style = MaterialTheme.typography.bodySmall,
                            color = StatusWeak
                        )
                    }
                }
            }
        }

        OutlinedTextField(
            value = websiteUrl,
            onValueChange = { websiteUrl = it },
            label = { Text("Website or App URL (optional)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(
                capitalization = KeyboardCapitalization.None,
                autoCorrectEnabled = false,
                keyboardType = KeyboardType.Uri
            ),
            modifier = Modifier.fillMaxWidth()
        )

        Text(text = "Folder", style = MaterialTheme.typography.labelLarge)
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            availableFolders.forEach { folder ->
                FilterChip(
                    selected = folderName == folder,
                    onClick = { folderName = folder },
                    label = { Text(folder) }
                )
            }
        }

        OutlinedTextField(
            value = tagsText,
            onValueChange = { tagsText = it },
            label = { Text("Tags (comma separated)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )

        OutlinedTextField(
            value = privateNotes,
            onValueChange = { privateNotes = it },
            label = { Text("Private Notes (encrypted)") },
            minLines = 3,
            modifier = Modifier.fillMaxWidth()
        )

        // Custom Text Fields Section
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(text = "Custom Text Fields", style = MaterialTheme.typography.titleSmall)
                customFields.forEachIndexed { idx, field ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = "${field.label}: ${field.value}",
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.weight(1f)
                        )
                        IconButton(
                            onClick = {
                                customFields = customFields.toMutableList().also { it.removeAt(idx) }
                            }
                        ) {
                            Icon(imageVector = Icons.Filled.Close, contentDescription = "Remove custom field")
                        }
                    }
                }
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = newCustomLabel,
                        onValueChange = { newCustomLabel = it },
                        placeholder = { Text("Field Label") },
                        singleLine = true,
                        modifier = Modifier.weight(1f)
                    )
                    OutlinedTextField(
                        value = newCustomValue,
                        onValueChange = { newCustomValue = it },
                        placeholder = { Text("Value") },
                        singleLine = true,
                        modifier = Modifier.weight(1f)
                    )
                    Button(
                        onClick = {
                            if (newCustomLabel.isNotBlank() && newCustomValue.isNotBlank()) {
                                customFields = customFields + CustomCredentialField(
                                    id = UUID.randomUUID().toString(),
                                    label = newCustomLabel.trim(),
                                    value = newCustomValue.trim()
                                )
                                newCustomLabel = ""
                                newCustomValue = ""
                            }
                        }
                    ) {
                        Text("Add")
                    }
                }
            }
        }

        if (validationError != null) {
            Text(
                text = validationError!!,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall
            )
        }

        HorizontalDivider()

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedButton(
                onClick = onClose,
                modifier = Modifier.weight(1f)
            ) {
                Text("Cancel")
            }
            Button(
                onClick = {
                    if (serviceName.isBlank()) {
                        validationError = "Please enter a service or app name."
                    } else if (password.isEmpty()) {
                        validationError = "Please enter or generate a password."
                    } else {
                        onSave(buildCurrentRecord())
                    }
                },
                modifier = Modifier
                    .weight(1f)
                    .testTag("credential_editor_save_button")
            ) {
                Icon(imageVector = Icons.Filled.Key, contentDescription = null)
                Spacer(modifier = Modifier.width(6.dp))
                Text("Save Encrypted")
            }
        }
    }
}

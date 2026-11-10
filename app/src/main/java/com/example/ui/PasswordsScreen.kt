package com.example.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Archive
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.CreateNewFolder
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Unarchive
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.outlined.PushPin
import androidx.compose.material.icons.outlined.StarBorder
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.CredentialRecord
import com.example.data.CustomCredentialField
import com.example.data.FolderScope
import com.example.data.VaultFolder
import com.example.security.OfflinePasswordStrengthEstimator
import java.util.Locale

private val CREDENTIAL_CATEGORIES = listOf("All", "Logins", "Banking", "Email", "Social", "Work", "Wi-Fi", "Crypto")

@Composable
fun PasswordsTabScreen(
    uiState: VaultUiState,
    viewModel: VaultViewModel
) {
    var showManageFoldersDialog by remember { mutableStateOf(false) }
    var pendingPermanentDeleteCredentialId by remember { mutableStateOf<String?>(null) }

    val activeDraft = uiState.activeCredentialDraft
    if (activeDraft != null) {
        val credFolders = remember(uiState.folders) {
            uiState.folders.filter { it.scope == FolderScope.CREDENTIALS }
                .ifEmpty {
                    listOf(
                        VaultFolder(
                            id = VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID,
                            name = VaultFolder.DEFAULT_FOLDER_NAME,
                            scope = FolderScope.CREDENTIALS
                        )
                    )
                }
        }
        val otherVaultPasswords = remember(uiState.credentials, activeDraft.credentialId) {
            uiState.credentials.filter { it.id != activeDraft.credentialId }.map { it.password }
        }
        CredentialEditorView(
            draft = activeDraft,
            availableFolders = credFolders,
            existingVaultPasswords = otherVaultPasswords,
            onUpdateDraft = viewModel::updateActiveCredentialDraft,
            onSave = viewModel::commitActiveCredentialDraft,
            onDelete = if (activeDraft.isEditingExisting) {
                { viewModel.deleteCredential(activeDraft.credentialId) }
            } else {
                null
            },
            onCopySecret = viewModel::copySecretToClipboard,
            onClose = viewModel::closeCredentialDraft
        )
        return
    }

    if (pendingPermanentDeleteCredentialId != null) {
        AlertDialog(
            onDismissRequest = { pendingPermanentDeleteCredentialId = null },
            title = { Text("Delete Credential Permanently?") },
            text = {
                Text(
                    "This saved credential will be permanently removed from your vault and cannot be recovered unless you have an external .pvault backup."
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        val id = pendingPermanentDeleteCredentialId
                        pendingPermanentDeleteCredentialId = null
                        if (id != null) {
                            viewModel.deleteCredential(id)
                        }
                    },
                    modifier = Modifier.testTag("confirm_perm_delete_credential_button")
                ) {
                    Text("Delete Permanently")
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingPermanentDeleteCredentialId = null }) {
                    Text("Cancel")
                }
            }
        )
    }

    val credFolders = remember(uiState.folders) {
        uiState.folders.filter { it.scope == FolderScope.CREDENTIALS }
            .sortedWith(compareBy<VaultFolder> { !VaultFolder.isDefaultGeneralName(it.name) }.thenBy { it.name.lowercase() })
    }

    val filteredCredentials = remember(
        uiState.credentials,
        uiState.credentialsSearchQuery,
        uiState.selectedCredentialCategory,
        uiState.selectedCredentialFolderId,
        uiState.credentialsSortOrder,
        uiState.credentialsFavoritesOnly,
        uiState.credentialsArchiveOnly,
        uiState.credentialsTrashOnly
    ) {
        val q = uiState.credentialsSearchQuery.trim().lowercase(Locale.US)
        val filtered = uiState.credentials.filter { cred ->
            val matchesLifecycle = when {
                uiState.credentialsTrashOnly -> cred.isTrashed
                uiState.credentialsArchiveOnly -> !cred.isTrashed && cred.isArchived
                else -> !cred.isTrashed && !cred.isArchived
            }
            val matchesQuery = if (q.isEmpty()) {
                true
            } else {
                cred.serviceName.lowercase(Locale.US).contains(q) ||
                    cred.accountLabel.lowercase(Locale.US).contains(q) ||
                    cred.username.lowercase(Locale.US).contains(q) ||
                    cred.websiteUrl.lowercase(Locale.US).contains(q) ||
                    cred.notes.lowercase(Locale.US).contains(q) ||
                    cred.category.lowercase(Locale.US).contains(q) ||
                    cred.folderName.lowercase(Locale.US).contains(q) ||
                    cred.tags.any { it.lowercase(Locale.US).contains(q) }
            }
            val matchesCat = uiState.selectedCredentialCategory == "All" ||
                cred.category.equals(uiState.selectedCredentialCategory, ignoreCase = true)
            val matchesFolder = uiState.selectedCredentialFolderId == null ||
                cred.folderId == uiState.selectedCredentialFolderId
            val matchesFav = !uiState.credentialsFavoritesOnly || cred.isFavorite
            matchesLifecycle && matchesQuery && matchesCat && matchesFolder && matchesFav
        }

        // R18 Fix: Sort pinned credentials first, then by selected sort order
        val comparator = when (uiState.credentialsSortOrder) {
            SortOrder.UPDATED_DESC -> compareByDescending<CredentialRecord> { it.isPinned }
                .thenByDescending { it.isFavorite }
                .thenByDescending { it.updatedAtEpochMs }
            SortOrder.CREATED_DESC -> compareByDescending<CredentialRecord> { it.isPinned }
                .thenByDescending { it.isFavorite }
                .thenByDescending { it.createdAtEpochMs }
            SortOrder.ALPHABETICAL -> compareByDescending<CredentialRecord> { it.isPinned }
                .thenByDescending { it.isFavorite }
                .thenBy { it.serviceName.lowercase(Locale.US) }
        }
        filtered.sortedWith(comparator)
    }

    if (showManageFoldersDialog) {
        FolderManagementDialog(
            scopeLabel = "Credential",
            folders = credFolders,
            onCreateFolder = { name -> viewModel.createFolder(name, FolderScope.CREDENTIALS) },
            onRenameFolder = { folderId, newName -> viewModel.renameFolder(folderId, newName) },
            onDeleteFolder = { folderId -> viewModel.deleteFolder(folderId) },
            onDismiss = { showManageFoldersDialog = false }
        )
    }

    // U03 Fix: Nested Scaffold uses zero contentWindowInsets so outer Scaffold's consumed insets
    // are not applied twice when the keyboard opens!
    Scaffold(
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        containerColor = MaterialTheme.colorScheme.background,
        floatingActionButton = {
            FloatingActionButton(
                onClick = { viewModel.openNewCredentialDraft() },
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
                modifier = Modifier.testTag("add_credential_fab")
            ) {
                Icon(Icons.Filled.Add, contentDescription = "Add Encrypted Credential")
            }
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background)
                .padding(innerPadding)
                .imePadding()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            OutlinedTextField(
                value = uiState.credentialsSearchQuery,
                onValueChange = viewModel::setCredentialsSearchQuery,
                placeholder = { Text("Search services, usernames, labels, notes…") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                trailingIcon = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        IconButton(
                            onClick = {
                                viewModel.setCredentialsFavoritesOnly(!uiState.credentialsFavoritesOnly)
                            }
                        ) {
                            Icon(
                                imageVector = if (uiState.credentialsFavoritesOnly) Icons.Filled.Star else Icons.Outlined.StarBorder,
                                contentDescription = "Toggle Favorites Filter",
                                tint = if (uiState.credentialsFavoritesOnly) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        IconButton(
                            onClick = { showManageFoldersDialog = true },
                            modifier = Modifier.testTag("manage_credential_folders_button")
                        ) {
                            Icon(
                                imageVector = Icons.Filled.CreateNewFolder,
                                contentDescription = "Manage Credential Folders"
                            )
                        }
                    }
                },
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("credentials_search_input")
            )

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                CREDENTIAL_CATEGORIES.forEach { category ->
                    FilterChip(
                        selected = uiState.selectedCredentialCategory == category,
                        onClick = { viewModel.setSelectedCredentialCategory(category) },
                        label = { Text(category) }
                    )
                }
            }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                FilterChip(
                    selected = uiState.selectedCredentialFolderId == null,
                    onClick = { viewModel.setSelectedCredentialFolderId(null) },
                    label = { Text("Folder: All") },
                    leadingIcon = {
                        Icon(
                            Icons.Filled.Folder,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                )
                credFolders.forEach { folder ->
                    FilterChip(
                        selected = uiState.selectedCredentialFolderId == folder.id,
                        onClick = { viewModel.setSelectedCredentialFolderId(folder.id) },
                        label = { Text(folder.name) }
                    )
                }
                AssistChip(
                    onClick = {
                        val nextOrder = when (uiState.credentialsSortOrder) {
                            SortOrder.UPDATED_DESC -> SortOrder.CREATED_DESC
                            SortOrder.CREATED_DESC -> SortOrder.ALPHABETICAL
                            SortOrder.ALPHABETICAL -> SortOrder.UPDATED_DESC
                        }
                        viewModel.setCredentialsSortOrder(nextOrder)
                    },
                    label = { Text("Sort: ${uiState.credentialsSortOrder.label}") }
                )

                val archivedCount = uiState.credentials.count { !it.isTrashed && it.isArchived }
                FilterChip(
                    selected = uiState.credentialsArchiveOnly,
                    onClick = { viewModel.setCredentialsArchiveOnly(!uiState.credentialsArchiveOnly) },
                    label = { Text(if (archivedCount > 0) "Archive ($archivedCount)" else "Archive") },
                    leadingIcon = {
                        Icon(
                            Icons.Filled.Archive,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    },
                    modifier = Modifier.testTag("credentials_archive_chip")
                )

                val trashedCount = uiState.credentials.count { it.isTrashed }
                FilterChip(
                    selected = uiState.credentialsTrashOnly,
                    onClick = { viewModel.setCredentialsTrashOnly(!uiState.credentialsTrashOnly) },
                    label = { Text(if (trashedCount > 0) "Trash ($trashedCount)" else "Trash") },
                    leadingIcon = {
                        Icon(
                            Icons.Filled.Delete,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    },
                    modifier = Modifier.testTag("credentials_trash_chip")
                )
            }

            if (filteredCredentials.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = "No matching credentials",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            text = "Tap the + button to add an encrypted login, banking credential, or API key.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .testTag("credentials_list"),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(filteredCredentials, key = { it.id }) { cred ->
                        CredentialItemCard(
                            credential = cred,
                            onClick = { viewModel.openExistingCredentialDraft(cred) },
                            onCopyUsername = {
                                viewModel.copySecretToClipboard(
                                    "${cred.serviceName} Username",
                                    cred.username
                                )
                            },
                            onCopyPassword = {
                                viewModel.copySecretToClipboard(
                                    "${cred.serviceName} Password",
                                    cred.password
                                )
                            },
                            onTogglePin = { viewModel.toggleCredentialPin(cred) },
                            onToggleFavorite = { viewModel.toggleCredentialFavorite(cred) },
                            onDuplicate = { viewModel.duplicateCredential(cred) },
                            onToggleArchive = { viewModel.toggleCredentialArchive(cred) },
                            onToggleTrash = { viewModel.toggleCredentialTrash(cred) },
                            onPermanentDelete = { pendingPermanentDeleteCredentialId = cred.id }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun CredentialItemCard(
    credential: CredentialRecord,
    onClick: () -> Unit,
    onCopyUsername: () -> Unit,
    onCopyPassword: () -> Unit,
    onTogglePin: () -> Unit,
    onToggleFavorite: () -> Unit,
    onDuplicate: () -> Unit,
    onToggleArchive: () -> Unit,
    onToggleTrash: () -> Unit,
    onPermanentDelete: () -> Unit
) {
    var revealPassword by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag("credential_card_${credential.id}"),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Surface(
                        color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.size(38.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(
                                imageVector = Icons.Filled.Key,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(20.dp)
                            )
                        }
                    }

                    Column(modifier = Modifier.weight(1f)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Text(
                                text = credential.serviceName,
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            if (credential.accountLabel.isNotBlank()) {
                                Surface(
                                    color = MaterialTheme.colorScheme.secondaryContainer,
                                    shape = RoundedCornerShape(6.dp)
                                ) {
                                    Text(
                                        text = credential.accountLabel,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                    )
                                }
                            }
                        }
                        if (credential.username.isNotBlank()) {
                            Text(
                                text = credential.username,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (!credential.isTrashed) {
                        IconButton(
                            onClick = onTogglePin,
                            modifier = Modifier.size(36.dp)
                        ) {
                            Icon(
                                imageVector = if (credential.isPinned) Icons.Filled.PushPin else Icons.Outlined.PushPin,
                                contentDescription = if (credential.isPinned) "Unpin Credential" else "Pin Credential",
                                tint = if (credential.isPinned) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        IconButton(
                            onClick = onToggleFavorite,
                            modifier = Modifier.size(36.dp)
                        ) {
                            Icon(
                                imageVector = if (credential.isFavorite) Icons.Filled.Star else Icons.Outlined.StarBorder,
                                contentDescription = "Favorite Credential",
                                tint = if (credential.isFavorite) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        IconButton(
                            onClick = onDuplicate,
                            modifier = Modifier
                                .size(36.dp)
                                .testTag("duplicate_credential_${credential.id}")
                        ) {
                            Icon(
                                imageVector = Icons.Filled.ContentCopy,
                                contentDescription = "Duplicate Credential",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        IconButton(
                            onClick = onToggleArchive,
                            modifier = Modifier
                                .size(36.dp)
                                .testTag("archive_credential_${credential.id}")
                        ) {
                            Icon(
                                imageVector = if (credential.isArchived) Icons.Filled.Unarchive else Icons.Filled.Archive,
                                contentDescription = if (credential.isArchived) "Unarchive Credential" else "Archive Credential",
                                tint = if (credential.isArchived) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        IconButton(
                            onClick = onToggleTrash,
                            modifier = Modifier
                                .size(36.dp)
                                .testTag("trash_credential_${credential.id}")
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Delete,
                                contentDescription = "Move Credential to Trash",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    } else {
                        TextButton(
                            onClick = onToggleTrash,
                            modifier = Modifier.testTag("restore_credential_${credential.id}")
                        ) {
                            Text("Restore")
                        }
                        IconButton(
                            onClick = onPermanentDelete,
                            modifier = Modifier
                                .size(36.dp)
                                .testTag("perm_delete_credential_${credential.id}")
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Delete,
                                contentDescription = "Delete Permanently",
                                tint = MaterialTheme.colorScheme.error,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                }
            }

            // Masked/Revealed Password Row with quick copy actions
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f),
                shape = RoundedCornerShape(10.dp),
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
                        text = if (revealPassword) credential.password else "••••••••••••",
                        style = MaterialTheme.typography.bodyMedium,
                        fontFamily = FontFamily.Monospace,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        IconButton(
                            onClick = { revealPassword = !revealPassword },
                            modifier = Modifier.size(36.dp)
                        ) {
                            Icon(
                                imageVector = if (revealPassword) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = if (revealPassword) "Hide password" else "Reveal password",
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        if (credential.username.isNotBlank()) {
                            IconButton(
                                onClick = onCopyUsername,
                                modifier = Modifier.size(36.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.ContentCopy,
                                    contentDescription = "Copy Username",
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        }
                        IconButton(
                            onClick = onCopyPassword,
                            modifier = Modifier
                                .size(36.dp)
                                .testTag("copy_password_${credential.id}")
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Key,
                                contentDescription = "Copy Password",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        shape = RoundedCornerShape(6.dp)
                    ) {
                        Text(
                            text = credential.category,
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                        )
                    }
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        shape = RoundedCornerShape(6.dp)
                    ) {
                        Text(
                            text = credential.folderName,
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                        )
                    }
                }

                if (credential.websiteUrl.isNotBlank()) {
                    Text(
                        text = credential.websiteUrl,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}

@Composable
private fun CredentialEditorView(
    draft: CredentialEditorDraftState,
    availableFolders: List<VaultFolder>,
    existingVaultPasswords: Collection<String>,
    onUpdateDraft: ((CredentialEditorDraftState) -> CredentialEditorDraftState) -> Unit,
    onSave: () -> Unit,
    onDelete: (() -> Unit)?,
    onCopySecret: (String, String) -> Unit,
    onClose: () -> Unit
) {
    var showConfirmDeleteDialog by remember { mutableStateOf(false) }

    BackHandler {
        onClose()
    }

    if (showConfirmDeleteDialog && onDelete != null) {
        AlertDialog(
            onDismissRequest = { showConfirmDeleteDialog = false },
            title = { Text("Delete Credential Permanently?") },
            text = {
                Text("This saved credential will be permanently deleted from your vault.")
            },
            confirmButton = {
                Button(
                    onClick = {
                        showConfirmDeleteDialog = false
                        onDelete()
                    },
                    modifier = Modifier.testTag("confirm_editor_delete_credential_button")
                ) {
                    Text("Delete Permanently")
                }
            },
            dismissButton = {
                TextButton(onClick = { showConfirmDeleteDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    var showPassword by remember { mutableStateOf(false) }
    val revealedCustomFieldIds = remember { mutableStateMapOf<String, Boolean>() }

    // R19 Fix: Include existingVaultPasswords in remember keys so reuse warnings update live
    val strengthReport = remember(draft.password, existingVaultPasswords) {
        OfflinePasswordStrengthEstimator.evaluate(draft.password, existingVaultPasswords)
    }

    // U03 Fix: Single scrollable Column with single imePadding()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            IconButton(
                onClick = onClose,
                modifier = Modifier.testTag("credential_editor_back_button")
            ) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
            }

            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                IconButton(onClick = { onUpdateDraft { it.copy(isPinned = !it.isPinned) } }) {
                    Icon(
                        imageVector = if (draft.isPinned) Icons.Filled.PushPin else Icons.Outlined.PushPin,
                        contentDescription = "Pin Credential",
                        tint = if (draft.isPinned) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                IconButton(onClick = { onUpdateDraft { it.copy(isFavorite = !it.isFavorite) } }) {
                    Icon(
                        imageVector = if (draft.isFavorite) Icons.Filled.Star else Icons.Outlined.StarBorder,
                        contentDescription = "Favorite Credential",
                        tint = if (draft.isFavorite) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (onDelete != null) {
                    IconButton(
                        onClick = { showConfirmDeleteDialog = true },
                        modifier = Modifier.testTag("credential_editor_delete_button")
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Delete,
                            contentDescription = "Delete Credential",
                            tint = MaterialTheme.colorScheme.error
                        )
                    }
                }
                Button(
                    onClick = onSave,
                    enabled = draft.serviceName.isNotBlank(),
                    modifier = Modifier.testTag("credential_editor_save_button")
                ) {
                    Icon(Icons.Filled.Check, contentDescription = null)
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Save")
                }
            }
        }

        if (draft.editorError != null) {
            Surface(
                color = MaterialTheme.colorScheme.errorContainer,
                shape = RoundedCornerShape(10.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = draft.editorError,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }

        OutlinedTextField(
            value = draft.serviceName,
            onValueChange = { text -> onUpdateDraft { it.copy(serviceName = text, editorError = null) } },
            label = { Text("Service / Title *") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
            modifier = Modifier
                .fillMaxWidth()
                .testTag("credential_service_input")
        )

        OutlinedTextField(
            value = draft.accountLabel,
            onValueChange = { text -> onUpdateDraft { it.copy(accountLabel = text) } },
            label = { Text("Account Label (e.g., Personal, Work)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
            modifier = Modifier
                .fillMaxWidth()
                .testTag("credential_account_label_input")
        )

        OutlinedTextField(
            value = draft.username,
            onValueChange = { text -> onUpdateDraft { it.copy(username = text) } },
            label = { Text("Username / Email / Account ID") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
            trailingIcon = {
                if (draft.username.isNotEmpty()) {
                    IconButton(onClick = { onCopySecret("Username", draft.username) }) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = "Copy Username")
                    }
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .testTag("credential_username_input")
        )

        OutlinedTextField(
            value = draft.password,
            onValueChange = { text -> onUpdateDraft { it.copy(password = text) } },
            label = { Text("Password / Secret Key") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                autoCorrectEnabled = false
            ),
            visualTransformation = if (showPassword) {
                VisualTransformation.None
            } else {
                PasswordVisualTransformation()
            },
            trailingIcon = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = { showPassword = !showPassword }) {
                        Icon(
                            imageVector = if (showPassword) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                            contentDescription = if (showPassword) "Hide password" else "Show password"
                        )
                    }
                    IconButton(
                        onClick = {
                            val generated = OfflinePasswordStrengthEstimator.generatePassword(
                                OfflinePasswordStrengthEstimator.GeneratorConfig(length = 20)
                            )
                            onUpdateDraft { it.copy(password = generated) }
                        },
                        modifier = Modifier.testTag("credential_generate_password_button")
                    ) {
                        Icon(Icons.Filled.Refresh, contentDescription = "Generate Strong Password")
                    }
                    if (draft.password.isNotEmpty()) {
                        IconButton(onClick = { onCopySecret("Password", draft.password) }) {
                            Icon(Icons.Filled.ContentCopy, contentDescription = "Copy Password")
                        }
                    }
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .testTag("credential_password_input")
        )

        // PV-BUG-011 Fix: Clarify that updating a saved password here only updates your offline vault record
        Text(
            text = "Note: Updating a password here only updates your encrypted record in Private Vault. Remember to also update it on the website or service itself.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        if (draft.password.isNotEmpty()) {
            PasswordStrengthInlineBar(report = strengthReport)
        }

        OutlinedTextField(
            value = draft.websiteUrl,
            onValueChange = { text -> onUpdateDraft { it.copy(websiteUrl = text) } },
            label = { Text("Website / URI (optional)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
            modifier = Modifier
                .fillMaxWidth()
                .testTag("credential_url_input")
        )

        // Category Selector
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            CREDENTIAL_CATEGORIES.filter { it != "All" }.forEach { cat ->
                FilterChip(
                    selected = draft.category.equals(cat, ignoreCase = true),
                    onClick = { onUpdateDraft { it.copy(category = cat) } },
                    label = { Text(cat) }
                )
            }
        }

        if (availableFolders.isNotEmpty()) {
            Text(
                text = "Folder",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                availableFolders.forEach { folder ->
                    FilterChip(
                        selected = draft.folderId == folder.id,
                        onClick = {
                            onUpdateDraft {
                                it.copy(folderId = folder.id, folderName = folder.name)
                            }
                        },
                        label = { Text(folder.name) }
                    )
                }
            }
        }

        OutlinedTextField(
            value = draft.tagsText,
            onValueChange = { text -> onUpdateDraft { it.copy(tagsText = text) } },
            label = { Text("Tags (comma separated)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
            modifier = Modifier.fillMaxWidth()
        )

        OutlinedTextField(
            value = draft.notes,
            onValueChange = { text -> onUpdateDraft { it.copy(notes = text) } },
            label = { Text("Encrypted Notes / Recovery Codes") },
            minLines = 3,
            keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
            modifier = Modifier
                .fillMaxWidth()
                .testTag("credential_notes_input")
        )

        // N08 Fix: Custom Fields Section with exact value preservation and secret masking
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "Custom Fields (PINs, Security Questions, API Tokens)",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.primary
                )

                draft.customFields.forEach { field ->
                    val isRevealed = revealedCustomFieldIds[field.id] == true
                    val displayValue = if (field.isSecret && !isRevealed) {
                        "••••••••••••"
                    } else {
                        field.value
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = if (field.isSecret) "${field.label} (Secret)" else field.label,
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                text = displayValue,
                                style = MaterialTheme.typography.bodyMedium,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            if (field.isSecret) {
                                IconButton(
                                    onClick = {
                                        revealedCustomFieldIds[field.id] = !isRevealed
                                    }
                                ) {
                                    Icon(
                                        imageVector = if (isRevealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                        contentDescription = if (isRevealed) "Hide ${field.label}" else "Reveal ${field.label}"
                                    )
                                }
                            }
                            IconButton(onClick = { onCopySecret(field.label, field.value) }) {
                                Icon(Icons.Filled.ContentCopy, contentDescription = "Copy ${field.label}")
                            }
                            IconButton(
                                onClick = {
                                    onUpdateDraft { state ->
                                        state.copy(
                                            customFields = state.customFields.filterNot { it.id == field.id }
                                        )
                                    }
                                }
                            ) {
                                Icon(Icons.Filled.Delete, contentDescription = "Delete Custom Field")
                            }
                        }
                    }
                }

                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = draft.pendingCustomLabel,
                            onValueChange = { text ->
                                onUpdateDraft { it.copy(pendingCustomLabel = text, editorError = null) }
                            },
                            label = { Text("Label") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                            modifier = Modifier
                                .weight(1f)
                                .testTag("custom_field_label_input")
                        )
                        OutlinedTextField(
                            value = draft.pendingCustomValue,
                            onValueChange = { text ->
                                // N08 Fix: Preserve exact custom field value without trimming
                                onUpdateDraft { it.copy(pendingCustomValue = text, editorError = null) }
                            },
                            label = { Text("Exact Value") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(
                                keyboardType = if (draft.pendingCustomIsSecret) KeyboardType.Password else KeyboardType.Text,
                                autoCorrectEnabled = false
                            ),
                            visualTransformation = if (draft.pendingCustomIsSecret) {
                                PasswordVisualTransformation()
                            } else {
                                VisualTransformation.None
                            },
                            modifier = Modifier
                                .weight(1f)
                                .testTag("custom_field_value_input")
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(
                                checked = draft.pendingCustomIsSecret,
                                onCheckedChange = { checked ->
                                    onUpdateDraft { it.copy(pendingCustomIsSecret = checked) }
                                },
                                modifier = Modifier.testTag("custom_field_secret_checkbox")
                            )
                            Text(
                                text = "Secret field (mask value by default)",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }

                        OutlinedButton(
                            onClick = {
                                if (draft.pendingCustomLabel.isNotBlank() && draft.pendingCustomValue.isNotEmpty()) {
                                    onUpdateDraft { state ->
                                        state.copy(
                                            customFields = state.customFields + CustomCredentialField(
                                                label = state.pendingCustomLabel.trim(),
                                                // N08 Fix: Do NOT call .trim() on secret custom value!
                                                value = state.pendingCustomValue,
                                                isSecret = state.pendingCustomIsSecret
                                            ),
                                            pendingCustomLabel = "",
                                            pendingCustomValue = "",
                                            editorError = null
                                        )
                                    }
                                }
                            },
                            enabled = draft.pendingCustomLabel.isNotBlank() && draft.pendingCustomValue.isNotEmpty(),
                            modifier = Modifier.testTag("custom_field_add_button")
                        ) {
                            Text("Add Field")
                        }
                    }
                }
            }
        }
    }
}

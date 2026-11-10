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
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Unarchive
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
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.ChecklistEntry
import com.example.data.FolderScope
import com.example.data.NoteBodyFormat
import com.example.data.NoteRecord
import com.example.data.VaultFolder
import com.example.ui.theme.NoteCardAccents
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val NOTE_CATEGORIES = listOf("All", "Personal", "Work", "Finance", "Security", "Ideas")
private val NUMBERED_LIST_REGEX = Regex("""^\d+\.\s+.*""")

@Composable
fun NotesTabScreen(
    uiState: VaultUiState,
    viewModel: VaultViewModel
) {
    var showManageFoldersDialog by remember { mutableStateOf(false) }
    var pendingPermanentDeleteNoteId by remember { mutableStateOf<String?>(null) }

    val activeDraft = uiState.activeNoteDraft
    if (activeDraft != null) {
        val noteFolders = remember(uiState.folders) {
            uiState.folders.filter { it.scope == FolderScope.NOTES }
                .ifEmpty {
                    listOf(
                        VaultFolder(
                            id = VaultFolder.DEFAULT_NOTE_FOLDER_ID,
                            name = VaultFolder.DEFAULT_FOLDER_NAME,
                            scope = FolderScope.NOTES
                        )
                    )
                }
        }
        NoteEditorView(
            draft = activeDraft,
            availableFolders = noteFolders,
            onUpdateDraft = viewModel::updateActiveNoteDraft,
            onSaveAndClose = {
                viewModel.commitActiveNoteDraft(closeOnSuccess = true, isSilentAutosave = false)
            },
            onSilentAutosave = {
                viewModel.commitActiveNoteDraft(closeOnSuccess = false, isSilentAutosave = true)
            },
            onDelete = if (activeDraft.isEditingExisting) {
                { viewModel.deleteNote(activeDraft.noteId) }
            } else {
                null
            },
            onCloseWithoutDiscard = {
                // PV-BUG-003 Fix: Only commit on close if the user actually modified the draft (`isDirty`),
                // so merely viewing an existing note never overwrites `updatedAtEpochMs`!
                if (activeDraft.isDirty && (
                        activeDraft.title.isNotBlank() || activeDraft.body.isNotBlank() ||
                            activeDraft.checklistItems.isNotEmpty() || activeDraft.pendingNewChecklistText.isNotBlank()
                        )
                ) {
                    viewModel.commitActiveNoteDraft(closeOnSuccess = true, isSilentAutosave = true)
                } else {
                    viewModel.closeNoteDraft()
                }
            }
        )
        return
    }

    if (pendingPermanentDeleteNoteId != null) {
        AlertDialog(
            onDismissRequest = { pendingPermanentDeleteNoteId = null },
            title = { Text("Delete Note Permanently?") },
            text = {
                Text(
                    "This encrypted note will be permanently removed from this vault and cannot be recovered unless you have an external .pvault backup."
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        val id = pendingPermanentDeleteNoteId
                        pendingPermanentDeleteNoteId = null
                        if (id != null) {
                            viewModel.deleteNote(id)
                        }
                    },
                    modifier = Modifier.testTag("confirm_perm_delete_note_button")
                ) {
                    Text("Delete Permanently")
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingPermanentDeleteNoteId = null }) {
                    Text("Cancel")
                }
            }
        )
    }

    val noteFolders = remember(uiState.folders) {
        uiState.folders.filter { it.scope == FolderScope.NOTES }
            .sortedWith(compareBy<VaultFolder> { !VaultFolder.isDefaultGeneralName(it.name) }.thenBy { it.name.lowercase() })
    }

    val filteredNotes = remember(
        uiState.notes,
        uiState.notesSearchQuery,
        uiState.selectedNoteCategory,
        uiState.selectedNoteFolderId,
        uiState.notesSortOrder,
        uiState.notesFavoritesOnly,
        uiState.notesArchiveOnly,
        uiState.notesTrashOnly
    ) {
        val q = uiState.notesSearchQuery.trim().lowercase(Locale.US)
        val filtered = uiState.notes.filter { note ->
            val matchesLifecycle = when {
                uiState.notesTrashOnly -> note.isTrashed
                uiState.notesArchiveOnly -> !note.isTrashed && note.isArchived
                else -> !note.isTrashed && !note.isArchived
            }
            val matchesQuery = if (q.isEmpty()) {
                true
            } else {
                note.title.lowercase(Locale.US).contains(q) ||
                    note.body.lowercase(Locale.US).contains(q) ||
                    note.category.lowercase(Locale.US).contains(q) ||
                    note.folderName.lowercase(Locale.US).contains(q) ||
                    note.tags.any { it.lowercase(Locale.US).contains(q) } ||
                    note.checklistItems.any { it.text.lowercase(Locale.US).contains(q) }
            }
            val matchesCat = uiState.selectedNoteCategory == "All" ||
                note.category.equals(uiState.selectedNoteCategory, ignoreCase = true)
            val matchesFolder = uiState.selectedNoteFolderId == null ||
                note.folderId == uiState.selectedNoteFolderId
            val matchesFav = !uiState.notesFavoritesOnly || note.isFavorite
            matchesLifecycle && matchesQuery && matchesCat && matchesFolder && matchesFav
        }

        val comparator = when (uiState.notesSortOrder) {
            SortOrder.UPDATED_DESC -> compareByDescending<NoteRecord> { it.isPinned }
                .thenByDescending { it.updatedAtEpochMs }
            SortOrder.CREATED_DESC -> compareByDescending<NoteRecord> { it.isPinned }
                .thenByDescending { it.createdAtEpochMs }
            SortOrder.ALPHABETICAL -> compareByDescending<NoteRecord> { it.isPinned }
                .thenBy { it.title.lowercase(Locale.US) }
        }
        filtered.sortedWith(comparator)
    }

    if (showManageFoldersDialog) {
        FolderManagementDialog(
            scopeLabel = "Note",
            folders = noteFolders,
            onCreateFolder = { name -> viewModel.createFolder(name, FolderScope.NOTES) },
            onRenameFolder = { folderId, newName -> viewModel.renameFolder(folderId, newName) },
            onDeleteFolder = { folderId -> viewModel.deleteFolder(folderId) },
            onDismiss = { showManageFoldersDialog = false }
        )
    }

    // U03 Fix: Nested Scaffold uses zero contentWindowInsets so outer Scaffold's consumed insets
    // are not applied a second time when the keyboard opens!
    Scaffold(
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        containerColor = MaterialTheme.colorScheme.background,
        floatingActionButton = {
            FloatingActionButton(
                onClick = { viewModel.openNewNoteDraft() },
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
                modifier = Modifier.testTag("add_note_fab")
            ) {
                Icon(Icons.Filled.Add, contentDescription = "Create Encrypted Note")
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
            // Search Bar
            OutlinedTextField(
                value = uiState.notesSearchQuery,
                onValueChange = viewModel::setNotesSearchQuery,
                placeholder = { Text("Search encrypted notes, tags, checklists…") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                trailingIcon = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        IconButton(onClick = { viewModel.setNotesFavoritesOnly(!uiState.notesFavoritesOnly) }) {
                            Icon(
                                imageVector = if (uiState.notesFavoritesOnly) Icons.Filled.Star else Icons.Outlined.StarBorder,
                                contentDescription = "Toggle Favorites Filter",
                                tint = if (uiState.notesFavoritesOnly) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        IconButton(
                            onClick = { showManageFoldersDialog = true },
                            modifier = Modifier.testTag("manage_note_folders_button")
                        ) {
                            Icon(
                                imageVector = Icons.Filled.CreateNewFolder,
                                contentDescription = "Manage Note Folders"
                            )
                        }
                    }
                },
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("notes_search_input")
            )

            // Category Filter Chips
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                NOTE_CATEGORIES.forEach { category ->
                    FilterChip(
                        selected = uiState.selectedNoteCategory == category,
                        onClick = { viewModel.setSelectedNoteCategory(category) },
                        label = { Text(category) }
                    )
                }
            }

            // Folder, Sort, Archive & Trash Bar (R12 & PV-BUG-007)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                FilterChip(
                    selected = uiState.selectedNoteFolderId == null,
                    onClick = { viewModel.setSelectedNoteFolderId(null) },
                    label = { Text("Folder: All") },
                    leadingIcon = {
                        Icon(
                            Icons.Filled.Folder,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                )
                noteFolders.forEach { folder ->
                    FilterChip(
                        selected = uiState.selectedNoteFolderId == folder.id,
                        onClick = { viewModel.setSelectedNoteFolderId(folder.id) },
                        label = { Text(folder.name) }
                    )
                }

                AssistChip(
                    onClick = {
                        val nextOrder = when (uiState.notesSortOrder) {
                            SortOrder.UPDATED_DESC -> SortOrder.CREATED_DESC
                            SortOrder.CREATED_DESC -> SortOrder.ALPHABETICAL
                            SortOrder.ALPHABETICAL -> SortOrder.UPDATED_DESC
                        }
                        viewModel.setNotesSortOrder(nextOrder)
                    },
                    label = { Text("Sort: ${uiState.notesSortOrder.label}") }
                )

                val archivedCount = uiState.notes.count { !it.isTrashed && it.isArchived }
                FilterChip(
                    selected = uiState.notesArchiveOnly,
                    onClick = { viewModel.setNotesArchiveOnly(!uiState.notesArchiveOnly) },
                    label = { Text(if (archivedCount > 0) "Archive ($archivedCount)" else "Archive") },
                    leadingIcon = {
                        Icon(
                            Icons.Filled.Archive,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    },
                    modifier = Modifier.testTag("notes_archive_chip")
                )

                val trashedCount = uiState.notes.count { it.isTrashed }
                FilterChip(
                    selected = uiState.notesTrashOnly,
                    onClick = { viewModel.setNotesTrashOnly(!uiState.notesTrashOnly) },
                    label = { Text(if (trashedCount > 0) "Trash ($trashedCount)" else "Trash") },
                    leadingIcon = {
                        Icon(
                            Icons.Filled.Delete,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                    },
                    modifier = Modifier.testTag("notes_trash_chip")
                )
            }

            if (filteredNotes.isEmpty()) {
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
                            text = "No matching encrypted notes",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            text = "Tap the + button to create a rich Markdown, checklist, or plain-text note encrypted on this device.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .testTag("notes_list"),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(filteredNotes, key = { it.id }) { note ->
                        NoteItemCard(
                            note = note,
                            onClick = { viewModel.openExistingNoteDraft(note) },
                            onTogglePin = { viewModel.toggleNotePin(note) },
                            onToggleFavorite = { viewModel.toggleNoteFavorite(note) },
                            onDuplicate = { viewModel.duplicateNote(note) },
                            onToggleArchive = { viewModel.toggleNoteArchive(note) },
                            onToggleTrash = { viewModel.toggleNoteTrash(note) },
                            onPermanentDelete = { pendingPermanentDeleteNoteId = note.id }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun NoteItemCard(
    note: NoteRecord,
    onClick: () -> Unit,
    onTogglePin: () -> Unit,
    onToggleFavorite: () -> Unit,
    onDuplicate: () -> Unit,
    onToggleArchive: () -> Unit,
    onToggleTrash: () -> Unit,
    onPermanentDelete: () -> Unit
) {
    val dateFormat = remember { SimpleDateFormat("dd MMM yyyy, HH:mm", Locale.US) }
    val accentBg = NoteCardAccents.getOrElse(note.colorAccentIndex) { MaterialTheme.colorScheme.surface }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag("note_card_${note.id}"),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (note.colorAccentIndex == 0) {
                MaterialTheme.colorScheme.surface
            } else {
                accentBg
            }
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
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Text(
                        text = note.title.ifBlank { "Untitled Note" },
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (!note.isTrashed) {
                        IconButton(
                            onClick = onTogglePin,
                            modifier = Modifier.size(36.dp)
                        ) {
                            Icon(
                                imageVector = if (note.isPinned) Icons.Filled.PushPin else Icons.Outlined.PushPin,
                                contentDescription = if (note.isPinned) "Unpin Note" else "Pin Note",
                                tint = if (note.isPinned) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        IconButton(
                            onClick = onToggleFavorite,
                            modifier = Modifier.size(36.dp)
                        ) {
                            Icon(
                                imageVector = if (note.isFavorite) Icons.Filled.Star else Icons.Outlined.StarBorder,
                                contentDescription = if (note.isFavorite) "Remove Favorite" else "Mark Favorite",
                                tint = if (note.isFavorite) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        IconButton(
                            onClick = onDuplicate,
                            modifier = Modifier
                                .size(36.dp)
                                .testTag("duplicate_note_${note.id}")
                        ) {
                            Icon(
                                imageVector = Icons.Filled.ContentCopy,
                                contentDescription = "Duplicate Note",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        IconButton(
                            onClick = onToggleArchive,
                            modifier = Modifier
                                .size(36.dp)
                                .testTag("archive_note_${note.id}")
                        ) {
                            Icon(
                                imageVector = if (note.isArchived) Icons.Filled.Unarchive else Icons.Filled.Archive,
                                contentDescription = if (note.isArchived) "Unarchive Note" else "Archive Note",
                                tint = if (note.isArchived) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        IconButton(
                            onClick = onToggleTrash,
                            modifier = Modifier
                                .size(36.dp)
                                .testTag("trash_note_${note.id}")
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Delete,
                                contentDescription = "Move Note to Trash",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    } else {
                        TextButton(
                            onClick = onToggleTrash,
                            modifier = Modifier.testTag("restore_note_${note.id}")
                        ) {
                            Text("Restore")
                        }
                        IconButton(
                            onClick = onPermanentDelete,
                            modifier = Modifier
                                .size(36.dp)
                                .testTag("perm_delete_note_${note.id}")
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

            if (note.format == NoteBodyFormat.CHECKLIST && note.checklistItems.isNotEmpty()) {
                val doneCount = note.checklistItems.count { it.isChecked }
                Text(
                    text = "Checklist ($doneCount/${note.checklistItems.size} completed)",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.secondary
                )
                note.checklistItems.take(3).forEach { entry ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            text = if (entry.isChecked) "☑" else "☐",
                            style = MaterialTheme.typography.bodySmall
                        )
                        Text(
                            text = entry.text,
                            style = MaterialTheme.typography.bodySmall,
                            textDecoration = if (entry.isChecked) TextDecoration.LineThrough else TextDecoration.None,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            } else if (note.body.isNotBlank()) {
                Text(
                    text = note.body,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis
                )
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
                            text = note.category,
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                        )
                    }
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        shape = RoundedCornerShape(6.dp)
                    ) {
                        Text(
                            text = note.folderName,
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                        )
                    }
                    note.tags.take(2).forEach { tag ->
                        Surface(
                            color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.4f),
                            shape = RoundedCornerShape(6.dp)
                        ) {
                            Text(
                                text = "#$tag",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                            )
                        }
                    }
                }

                Text(
                    text = dateFormat.format(Date(note.updatedAtEpochMs)),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun NoteEditorView(
    draft: NoteEditorDraftState,
    availableFolders: List<VaultFolder>,
    onUpdateDraft: ((NoteEditorDraftState) -> NoteEditorDraftState) -> Unit,
    onSaveAndClose: () -> Unit,
    onSilentAutosave: () -> Unit,
    onDelete: (() -> Unit)?,
    onCloseWithoutDiscard: () -> Unit
) {
    var showConfirmDeleteDialog by remember { mutableStateOf(false) }

    BackHandler {
        onCloseWithoutDiscard()
    }

    if (showConfirmDeleteDialog && onDelete != null) {
        AlertDialog(
            onDismissRequest = { showConfirmDeleteDialog = false },
            title = { Text("Delete Note Permanently?") },
            text = {
                Text("This encrypted note will be permanently deleted from your vault.")
            },
            confirmButton = {
                Button(
                    onClick = {
                        showConfirmDeleteDialog = false
                        onDelete()
                    },
                    modifier = Modifier.testTag("confirm_editor_delete_note_button")
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

    // PV-BUG-003 Fix: Only run debounced encrypted autosave when `draft.isDirty` is true!
    LaunchedEffect(
        draft.isDirty,
        draft.title,
        draft.body,
        draft.format,
        draft.category,
        draft.folderId,
        draft.tagsText,
        draft.colorAccentIndex,
        draft.isPinned,
        draft.isFavorite,
        draft.isArchived,
        draft.checklistItems
    ) {
        if (draft.isDirty && (draft.title.isNotBlank() || draft.body.isNotBlank() || draft.checklistItems.isNotEmpty())) {
            delay(850L)
            onSilentAutosave()
        }
    }

    // U03 Fix: Single scrollable Column with a single imePadding()
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
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                IconButton(
                    onClick = onCloseWithoutDiscard,
                    modifier = Modifier.testTag("note_editor_back_button")
                ) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back to Notes")
                }

                // PV-BUG-004 Fix: Live Autosave Status Badge
                val statusLabel = when (draft.autosaveIndicator) {
                    AutosaveIndicator.IDLE, AutosaveIndicator.SAVED -> "Saved"
                    AutosaveIndicator.SAVING -> "Saving…"
                    AutosaveIndicator.UNSAVED -> "Unsaved changes"
                    AutosaveIndicator.ERROR -> "Save failed"
                }
                val statusBg = when (draft.autosaveIndicator) {
                    AutosaveIndicator.IDLE, AutosaveIndicator.SAVED -> MaterialTheme.colorScheme.secondaryContainer
                    AutosaveIndicator.SAVING -> MaterialTheme.colorScheme.primaryContainer
                    AutosaveIndicator.UNSAVED -> MaterialTheme.colorScheme.surfaceVariant
                    AutosaveIndicator.ERROR -> MaterialTheme.colorScheme.errorContainer
                }
                val statusFg = when (draft.autosaveIndicator) {
                    AutosaveIndicator.IDLE, AutosaveIndicator.SAVED -> MaterialTheme.colorScheme.onSecondaryContainer
                    AutosaveIndicator.SAVING -> MaterialTheme.colorScheme.onPrimaryContainer
                    AutosaveIndicator.UNSAVED -> MaterialTheme.colorScheme.onSurfaceVariant
                    AutosaveIndicator.ERROR -> MaterialTheme.colorScheme.onErrorContainer
                }
                Surface(
                    color = statusBg,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.testTag("note_autosave_status")
                ) {
                    Text(
                        text = statusLabel,
                        style = MaterialTheme.typography.labelSmall,
                        color = statusFg,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }
            }

            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                IconButton(onClick = { onUpdateDraft { it.copy(isPinned = !it.isPinned) } }) {
                    Icon(
                        imageVector = if (draft.isPinned) Icons.Filled.PushPin else Icons.Outlined.PushPin,
                        contentDescription = "Pin Note",
                        tint = if (draft.isPinned) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                IconButton(onClick = { onUpdateDraft { it.copy(isFavorite = !it.isFavorite) } }) {
                    Icon(
                        imageVector = if (draft.isFavorite) Icons.Filled.Star else Icons.Outlined.StarBorder,
                        contentDescription = "Favorite Note",
                        tint = if (draft.isFavorite) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (onDelete != null) {
                    IconButton(
                        onClick = { showConfirmDeleteDialog = true },
                        modifier = Modifier.testTag("note_editor_delete_button")
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Delete,
                            contentDescription = "Delete Note",
                            tint = MaterialTheme.colorScheme.error
                        )
                    }
                }
                Button(
                    onClick = onSaveAndClose,
                    modifier = Modifier.testTag("note_editor_save_button")
                ) {
                    Icon(Icons.Filled.Check, contentDescription = null)
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Save & Done")
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
            value = draft.title,
            onValueChange = { text -> onUpdateDraft { it.copy(title = text, editorError = null) } },
            label = { Text("Note Title") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
            modifier = Modifier
                .fillMaxWidth()
                .testTag("note_editor_title_input")
        )

        // Format switcher: Plain Text / Markdown / Checklist
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            NoteBodyFormat.entries.forEach { fmt ->
                FilterChip(
                    selected = draft.format == fmt,
                    onClick = { onUpdateDraft { it.copy(format = fmt) } },
                    label = { Text(fmt.name.replace('_', ' ')) }
                )
            }
            if (draft.format == NoteBodyFormat.MARKDOWN) {
                FilterChip(
                    selected = draft.showMarkdownPreview,
                    onClick = { onUpdateDraft { it.copy(showMarkdownPreview = !it.showMarkdownPreview) } },
                    label = { Text(if (draft.showMarkdownPreview) "Edit Markdown" else "Preview Markdown") }
                )
            }
        }

        // PV-BUG-008 Fix: Markdown Quick-Formatting Toolbar
        if (draft.format == NoteBodyFormat.MARKDOWN && !draft.showMarkdownPreview) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                AssistChip(
                    onClick = {
                        onUpdateDraft { state ->
                            val prefix = if (state.body.isEmpty() || state.body.endsWith("\n")) "# " else "\n# "
                            state.copy(body = state.body + prefix)
                        }
                    },
                    label = { Text("# Heading") },
                    modifier = Modifier.testTag("md_btn_heading")
                )
                AssistChip(
                    onClick = {
                        onUpdateDraft { state ->
                            state.copy(body = state.body + "**bold**")
                        }
                    },
                    label = { Text("**Bold**") },
                    modifier = Modifier.testTag("md_btn_bold")
                )
                AssistChip(
                    onClick = {
                        onUpdateDraft { state ->
                            val prefix = if (state.body.isEmpty() || state.body.endsWith("\n")) "- " else "\n- "
                            state.copy(body = state.body + prefix)
                        }
                    },
                    label = { Text("• Bullet") },
                    modifier = Modifier.testTag("md_btn_bullet")
                )
                AssistChip(
                    onClick = {
                        onUpdateDraft { state ->
                            val prefix = if (state.body.isEmpty() || state.body.endsWith("\n")) "1. " else "\n1. "
                            state.copy(body = state.body + prefix)
                        }
                    },
                    label = { Text("1. Numbered") },
                    modifier = Modifier.testTag("md_btn_numbered")
                )
                AssistChip(
                    onClick = {
                        onUpdateDraft { state ->
                            state.copy(body = state.body + "`code`")
                        }
                    },
                    label = { Text("`Code`") },
                    modifier = Modifier.testTag("md_btn_code")
                )
            }
        }

        // Category & Folder selection
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            NOTE_CATEGORIES.filter { it != "All" }.forEach { cat ->
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

        // Color Accent Picker
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text("Card Accent:", style = MaterialTheme.typography.labelMedium)
            NoteCardAccents.forEachIndexed { idx, color ->
                Box(
                    modifier = Modifier
                        .size(28.dp)
                        .clip(CircleShape)
                        .background(color)
                        .clickable { onUpdateDraft { it.copy(colorAccentIndex = idx) } },
                    contentAlignment = Alignment.Center
                ) {
                    if (draft.colorAccentIndex == idx) {
                        Icon(
                            imageVector = Icons.Filled.Check,
                            contentDescription = "Selected Accent",
                            tint = Color.White,
                            modifier = Modifier.size(16.dp)
                        )
                    }
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

        if (draft.format == NoteBodyFormat.CHECKLIST) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Interactive Checklist",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.primary
                    )

                    draft.checklistItems.forEach { entry ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(
                                checked = entry.isChecked,
                                onCheckedChange = { checked ->
                                    onUpdateDraft { state ->
                                        state.copy(
                                            checklistItems = state.checklistItems.map {
                                                if (it.id == entry.id) it.copy(isChecked = checked) else it
                                            }
                                        )
                                    }
                                }
                            )
                            Text(
                                text = entry.text,
                                modifier = Modifier.weight(1f),
                                textDecoration = if (entry.isChecked) TextDecoration.LineThrough else TextDecoration.None
                            )
                            IconButton(
                                onClick = {
                                    onUpdateDraft { state ->
                                        state.copy(
                                            checklistItems = state.checklistItems.filterNot { it.id == entry.id }
                                        )
                                    }
                                }
                            ) {
                                Icon(Icons.Filled.Delete, contentDescription = "Remove Item")
                            }
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = draft.pendingNewChecklistText,
                            onValueChange = { text ->
                                onUpdateDraft { it.copy(pendingNewChecklistText = text, editorError = null) }
                            },
                            placeholder = { Text("Add checklist item…") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                            modifier = Modifier
                                .weight(1f)
                                .testTag("note_checklist_new_input")
                        )
                        Button(
                            onClick = {
                                if (draft.pendingNewChecklistText.isNotBlank()) {
                                    onUpdateDraft { state ->
                                        state.copy(
                                            checklistItems = state.checklistItems +
                                                ChecklistEntry(text = state.pendingNewChecklistText.trim()),
                                            pendingNewChecklistText = "",
                                            editorError = null
                                        )
                                    }
                                }
                            },
                            modifier = Modifier.testTag("note_checklist_add_button")
                        ) {
                            Text("Add")
                        }
                    }
                }
            }
        }

        if (draft.format == NoteBodyFormat.MARKDOWN && draft.showMarkdownPreview) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text(
                        text = "Markdown Preview",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    HorizontalDivider()
                    MarkdownPreviewBlock(markdown = draft.body)
                }
            }
        } else {
            OutlinedTextField(
                value = draft.body,
                onValueChange = { text -> onUpdateDraft { it.copy(body = text, editorError = null) } },
                label = { Text("Encrypted Note Content") },
                minLines = 8,
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("note_editor_body_input")
            )
        }
    }
}

@Composable
fun FolderManagementDialog(
    scopeLabel: String,
    folders: List<VaultFolder>,
    onCreateFolder: (String) -> Unit,
    onRenameFolder: (String, String) -> Unit,
    onDeleteFolder: (String) -> Unit,
    onDismiss: () -> Unit
) {
    var newFolderName by remember { mutableStateOf("") }
    var editingFolderId by remember { mutableStateOf<String?>(null) }
    var editingFolderName by remember { mutableStateOf("") }
    var pendingDeleteFolder by remember { mutableStateOf<VaultFolder?>(null) }

    if (pendingDeleteFolder != null) {
        val folderToDelete = pendingDeleteFolder!!
        AlertDialog(
            onDismissRequest = { pendingDeleteFolder = null },
            title = { Text("Delete Folder '${folderToDelete.name}'?") },
            text = {
                Text(
                    "Any items currently inside '${folderToDelete.name}' will be safely moved to the default General folder."
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        pendingDeleteFolder = null
                        onDeleteFolder(folderToDelete.id)
                    },
                    modifier = Modifier.testTag("confirm_delete_folder_button")
                ) {
                    Text("Delete Folder")
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingDeleteFolder = null }) {
                    Text("Cancel")
                }
            }
        )
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Manage $scopeLabel Folders") },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "Create custom folders or rename/delete existing ones. Deleting a folder safely moves its items to General.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = newFolderName,
                        onValueChange = { newFolderName = it },
                        label = { Text("New folder name") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                        modifier = Modifier
                            .weight(1f)
                            .testTag("new_folder_name_input")
                    )
                    Button(
                        onClick = {
                            if (newFolderName.isNotBlank()) {
                                onCreateFolder(newFolderName.trim())
                                newFolderName = ""
                            }
                        },
                        enabled = newFolderName.isNotBlank(),
                        modifier = Modifier.testTag("create_folder_confirm_button")
                    ) {
                        Text("Create")
                    }
                }

                HorizontalDivider()

                folders.forEach { folder ->
                    val isBuiltInGeneral = VaultFolder.isDefaultGeneralName(folder.name) ||
                        folder.id == VaultFolder.DEFAULT_NOTE_FOLDER_ID ||
                        folder.id == VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID

                    if (editingFolderId == folder.id) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            OutlinedTextField(
                                value = editingFolderName,
                                onValueChange = { editingFolderName = it },
                                singleLine = true,
                                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                                modifier = Modifier.weight(1f)
                            )
                            TextButton(
                                onClick = {
                                    if (editingFolderName.isNotBlank()) {
                                        onRenameFolder(folder.id, editingFolderName.trim())
                                        editingFolderId = null
                                    }
                                }
                            ) {
                                Text("Save")
                            }
                            TextButton(onClick = { editingFolderId = null }) {
                                Text("Cancel")
                            }
                        }
                    } else {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(
                                    Icons.Filled.Folder,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(18.dp)
                                )
                                Text(
                                    text = if (isBuiltInGeneral) "${folder.name} (Default)" else folder.name,
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Medium
                                )
                            }
                            if (!isBuiltInGeneral) {
                                Row {
                                    IconButton(
                                        onClick = {
                                            editingFolderId = folder.id
                                            editingFolderName = folder.name
                                        },
                                        modifier = Modifier.size(32.dp)
                                    ) {
                                        Icon(
                                            Icons.Filled.Edit,
                                            contentDescription = "Rename ${folder.name}",
                                            modifier = Modifier.size(18.dp)
                                        )
                                    }
                                    IconButton(
                                        onClick = { pendingDeleteFolder = folder },
                                        modifier = Modifier.size(32.dp)
                                    ) {
                                        Icon(
                                            Icons.Filled.Delete,
                                            contentDescription = "Delete ${folder.name}",
                                            tint = MaterialTheme.colorScheme.error,
                                            modifier = Modifier.size(18.dp)
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            OutlinedButton(onClick = onDismiss) {
                Text("Done")
            }
        }
    )
}

@Composable
private fun MarkdownPreviewBlock(markdown: String) {
    val lines = remember(markdown) { markdown.lines() }
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        lines.forEach { line ->
            val trimmed = line.trim()
            when {
                trimmed.startsWith("### ") -> Text(
                    text = trimmed.removePrefix("### "),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.primary
                )
                trimmed.startsWith("## ") -> Text(
                    text = trimmed.removePrefix("## "),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary
                )
                trimmed.startsWith("# ") -> Text(
                    text = trimmed.removePrefix("# "),
                    style = MaterialTheme.typography.headlineSmall,
                    color = MaterialTheme.colorScheme.primary
                )
                trimmed.startsWith("- ") || trimmed.startsWith("* ") -> Text(
                    text = "• " + trimmed.drop(2),
                    style = MaterialTheme.typography.bodyMedium
                )
                NUMBERED_LIST_REGEX.matches(trimmed) -> Text(
                    text = trimmed,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
                trimmed.startsWith("> ") -> Text(
                    text = trimmed.removePrefix("> "),
                    style = MaterialTheme.typography.bodyMedium,
                    fontStyle = FontStyle.Italic,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                trimmed.startsWith("```") -> HorizontalDivider()
                else -> Text(
                    text = line,
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = if (line.startsWith("    ")) FontFamily.Monospace else FontFamily.Default
                )
            }
        }
    }
}

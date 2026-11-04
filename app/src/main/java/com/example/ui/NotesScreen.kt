package com.example.ui

import androidx.activity.compose.BackHandler
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Archive
import androidx.compose.material.icons.filled.CheckBox
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.CreateNewFolder
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.FormatListBulleted
import androidx.compose.material.icons.filled.FormatListNumbered
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.RestoreFromTrash
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.SortByAlpha
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Title
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.PushPin
import androidx.compose.material.icons.outlined.StarOutline
import androidx.compose.material.icons.outlined.Unarchive
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.NoteChecklistItem
import com.example.data.NoteFormatStyle
import com.example.data.VaultRecordPayload
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun NotesTabScreen(
    uiState: VaultUiState,
    viewModel: VaultViewModel
) {
    var editingNote by remember { mutableStateOf<VaultRecordPayload.NoteRecord?>(null) }
    var showCreateFolderDialog by remember { mutableStateOf(false) }
    var newFolderName by remember { mutableStateOf("") }
    var notePendingPermanentDelete by remember { mutableStateOf<VaultRecordPayload.NoteRecord?>(null) }

    if (editingNote != null) {
        NoteEditorView(
            initialNote = editingNote!!,
            availableFolders = uiState.folders.map { it.name }.ifEmpty { listOf("General", "Personal", "Work") },
            autosaveStatus = uiState.autosaveStatus,
            autosaveErrorMessage = uiState.autosaveErrorMessage,
            onSaveNote = { updatedNote, isAuto ->
                editingNote = updatedNote
                viewModel.saveNote(updatedNote, isAutosave = isAuto)
            },
            onDuplicate = { note ->
                viewModel.duplicateNote(note)
                editingNote = null
            },
            onMoveToTrash = { note ->
                viewModel.moveNoteToTrash(note)
                editingNote = null
            },
            onClose = { editingNote = null }
        )
        return
    }

    val folderNames = remember(uiState.folders) {
        listOf("All") + uiState.folders.map { it.name }.distinct()
    }

    val filteredNotes = remember(
        uiState.notes,
        uiState.noteSearchQuery,
        uiState.selectedNoteFolder,
        uiState.noteFilterMode,
        uiState.noteSortMode
    ) {
        val q = uiState.noteSearchQuery.trim().lowercase(Locale.ROOT)
        uiState.notes
            .filter { note ->
                when (uiState.noteFilterMode) {
                    NoteFilterMode.ACTIVE -> !note.isTrashed && !note.isArchived
                    NoteFilterMode.FAVORITES -> !note.isTrashed && note.isFavorite
                    NoteFilterMode.ARCHIVED -> !note.isTrashed && note.isArchived
                    NoteFilterMode.TRASH -> note.isTrashed
                }
            }
            .filter { note ->
                uiState.selectedNoteFolder == "All" || note.folderName.equals(uiState.selectedNoteFolder, ignoreCase = true)
            }
            .filter { note ->
                if (q.isEmpty()) true
                else {
                    note.title.lowercase(Locale.ROOT).contains(q) ||
                        note.body.lowercase(Locale.ROOT).contains(q) ||
                        note.tags.any { it.lowercase(Locale.ROOT).contains(q) } ||
                        note.checklistItems.any { it.text.lowercase(Locale.ROOT).contains(q) }
                }
            }
            .sortedWith(
                Comparator { a, b ->
                    if (a.isPinned != b.isPinned) {
                        if (a.isPinned) -1 else 1
                    } else {
                        when (uiState.noteSortMode) {
                            NoteSortMode.UPDATED_DESC -> b.updatedAtEpochMs.compareTo(a.updatedAtEpochMs)
                            NoteSortMode.TITLE_ASC -> a.title.lowercase(Locale.ROOT).compareTo(b.title.lowercase(Locale.ROOT))
                        }
                    }
                }
            )
    }

    Scaffold(
        floatingActionButton = {
            FloatingActionButton(
                onClick = {
                    val now = System.currentTimeMillis()
                    editingNote = VaultRecordPayload.NoteRecord(
                        id = UUID.randomUUID().toString(),
                        title = "",
                        body = "",
                        folderName = if (uiState.selectedNoteFolder == "All") "General" else uiState.selectedNoteFolder,
                        createdAtEpochMs = now,
                        updatedAtEpochMs = now
                    )
                },
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
                modifier = Modifier.testTag("create_note_fab")
            ) {
                Icon(imageVector = Icons.Filled.Add, contentDescription = "Create Private Note")
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
            // Search & Sort Row
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedTextField(
                    value = uiState.noteSearchQuery,
                    onValueChange = viewModel::updateNoteSearchQuery,
                    placeholder = { Text("Search encrypted notes...") },
                    singleLine = true,
                    leadingIcon = {
                        Icon(imageVector = Icons.Filled.Search, contentDescription = "Search notes")
                    },
                    trailingIcon = {
                        if (uiState.noteSearchQuery.isNotEmpty()) {
                            IconButton(onClick = { viewModel.updateNoteSearchQuery("") }) {
                                Icon(imageVector = Icons.Filled.Close, contentDescription = "Clear search")
                            }
                        }
                    },
                    modifier = Modifier
                        .weight(1f)
                        .testTag("notes_search_input")
                )

                IconButton(
                    onClick = {
                        val nextSort = if (uiState.noteSortMode == NoteSortMode.UPDATED_DESC) {
                            NoteSortMode.TITLE_ASC
                        } else {
                            NoteSortMode.UPDATED_DESC
                        }
                        viewModel.updateNoteSortMode(nextSort)
                    },
                    modifier = Modifier.testTag("notes_sort_button")
                ) {
                    Icon(
                        imageVector = Icons.Filled.SortByAlpha,
                        contentDescription = "Sort notes (${uiState.noteSortMode.label})"
                    )
                }

                IconButton(
                    onClick = { showCreateFolderDialog = true },
                    modifier = Modifier.testTag("notes_add_folder_button")
                ) {
                    Icon(
                        imageVector = Icons.Filled.CreateNewFolder,
                        contentDescription = "Create new folder"
                    )
                }
            }

            // Filter Mode Chips (Active / Favorites / Archived / Trash)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                NoteFilterMode.entries.forEach { mode ->
                    FilterChip(
                        selected = uiState.noteFilterMode == mode,
                        onClick = { viewModel.updateNoteFilterMode(mode) },
                        label = { Text(mode.label) }
                    )
                }
            }

            // Folder Chips
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                folderNames.forEach { folder ->
                    AssistChip(
                        onClick = { viewModel.updateSelectedNoteFolder(folder) },
                        label = {
                            Text(
                                text = folder,
                                fontWeight = if (uiState.selectedNoteFolder == folder) FontWeight.Bold else FontWeight.Normal
                            )
                        }
                    )
                }
            }

            if (uiState.noteFilterMode == NoteFilterMode.TRASH) {
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    shape = MaterialTheme.shapes.small,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = "Recoverable Trash: Notes in Trash remain encrypted inside this vault until you restore them or permanently delete them. Note: on flash storage, permanent deletion removes database records but cannot guarantee physical erasure of all prior flash wear-leveling blocks or exported backups.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(10.dp)
                    )
                }
            }

            if (filteredNotes.isEmpty()) {
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
                            imageVector = Icons.Outlined.Description,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(48.dp)
                        )
                        Text(
                            text = "No notes in ${uiState.noteFilterMode.label}",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Text(
                            text = "Tap + to create an AES-256-GCM encrypted private note.",
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
                    items(filteredNotes, key = { it.id }) { note ->
                        NoteListCard(
                            note = note,
                            onClick = { editingNote = note },
                            onTogglePin = {
                                viewModel.saveNote(note.copy(isPinned = !note.isPinned))
                            },
                            onToggleFavorite = {
                                viewModel.saveNote(note.copy(isFavorite = !note.isFavorite))
                            },
                            onToggleArchive = {
                                viewModel.saveNote(note.copy(isArchived = !note.isArchived))
                            },
                            onRestoreFromTrash = {
                                viewModel.restoreNoteFromTrash(note)
                            },
                            onDeletePermanently = {
                                notePendingPermanentDelete = note
                            }
                        )
                    }
                }
            }
        }
    }

    if (showCreateFolderDialog) {
        AlertDialog(
            onDismissRequest = { showCreateFolderDialog = false },
            title = { Text("Create Encrypted Folder") },
            text = {
                OutlinedTextField(
                    value = newFolderName,
                    onValueChange = { newFolderName = it },
                    label = { Text("Folder Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.createFolder(newFolderName)
                        newFolderName = ""
                        showCreateFolderDialog = false
                    }
                ) {
                    Text("Create")
                }
            },
            dismissButton = {
                TextButton(onClick = { showCreateFolderDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    if (notePendingPermanentDelete != null) {
        val target = notePendingPermanentDelete!!
        AlertDialog(
            onDismissRequest = { notePendingPermanentDelete = null },
            title = { Text("Permanently Delete Note?") },
            text = {
                Text(
                    "This will permanently remove \"${target.title.ifBlank { "Untitled Note" }}\" from your active encrypted database. This action cannot be undone unless you have a separate .pvault backup."
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.deleteRecordPermanently(target.id)
                        notePendingPermanentDelete = null
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                ) {
                    Text("Delete Permanently")
                }
            },
            dismissButton = {
                TextButton(onClick = { notePendingPermanentDelete = null }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun NoteListCard(
    note: VaultRecordPayload.NoteRecord,
    onClick: () -> Unit,
    onTogglePin: () -> Unit,
    onToggleFavorite: () -> Unit,
    onToggleArchive: () -> Unit,
    onRestoreFromTrash: () -> Unit,
    onDeletePermanently: () -> Unit
) {
    val dateFormat = remember { SimpleDateFormat("dd MMM yyyy, HH:mm", Locale.getDefault()) }

    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag("note_card_${note.id}")
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    if (note.isPinned) {
                        Icon(
                            imageVector = Icons.Filled.PushPin,
                            contentDescription = "Pinned",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                    Text(
                        text = note.title.ifBlank { "Untitled Private Note" },
                        style = when (note.formatStyle) {
                            NoteFormatStyle.HEADING -> MaterialTheme.typography.titleLarge
                            else -> MaterialTheme.typography.titleMedium
                        },
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                if (!note.isTrashed) {
                    Row {
                        IconButton(onClick = onTogglePin, modifier = Modifier.size(36.dp)) {
                            Icon(
                                imageVector = if (note.isPinned) Icons.Filled.PushPin else Icons.Outlined.PushPin,
                                contentDescription = if (note.isPinned) "Unpin note" else "Pin note",
                                tint = if (note.isPinned) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        IconButton(onClick = onToggleFavorite, modifier = Modifier.size(36.dp)) {
                            Icon(
                                imageVector = if (note.isFavorite) Icons.Filled.Star else Icons.Outlined.StarOutline,
                                contentDescription = if (note.isFavorite) "Remove favorite" else "Mark favorite",
                                tint = if (note.isFavorite) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        IconButton(onClick = onToggleArchive, modifier = Modifier.size(36.dp)) {
                            Icon(
                                imageVector = if (note.isArchived) Icons.Outlined.Unarchive else Icons.Filled.Archive,
                                contentDescription = if (note.isArchived) "Unarchive note" else "Archive note",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                } else {
                    Row {
                        IconButton(onClick = onRestoreFromTrash) {
                            Icon(
                                imageVector = Icons.Filled.RestoreFromTrash,
                                contentDescription = "Restore note from trash",
                                tint = MaterialTheme.colorScheme.primary
                            )
                        }
                        IconButton(onClick = onDeletePermanently) {
                            Icon(
                                imageVector = Icons.Filled.DeleteForever,
                                contentDescription = "Permanently delete note",
                                tint = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                }
            }

            if (note.formatStyle == NoteFormatStyle.CHECKLIST && note.checklistItems.isNotEmpty()) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    note.checklistItems.take(3).forEach { item ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Filled.CheckBox,
                                contentDescription = null,
                                modifier = Modifier.size(14.dp),
                                tint = if (item.isChecked) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                text = item.text,
                                style = MaterialTheme.typography.bodySmall,
                                textDecoration = if (item.isChecked) TextDecoration.LineThrough else TextDecoration.None,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }
            } else if (note.body.isNotBlank()) {
                val formattedPreview = when (note.formatStyle) {
                    NoteFormatStyle.BULLET_LIST -> note.body.lines().take(3).joinToString("\n") { "• $it" }
                    NoteFormatStyle.NUMBERED_LIST -> note.body.lines().take(3).mapIndexed { i, line -> "${i + 1}. $line" }.joinToString("\n")
                    else -> note.body
                }
                Text(
                    text = formattedPreview,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis
                )
            }

            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Surface(
                    color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.6f),
                    shape = MaterialTheme.shapes.extraSmall
                ) {
                    Text(
                        text = note.folderName,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
                note.tags.forEach { tag ->
                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        shape = MaterialTheme.shapes.extraSmall
                    ) {
                        Text(
                            text = "#$tag",
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.weight(1f))
                Text(
                    text = dateFormat.format(Date(note.updatedAtEpochMs)),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun NoteEditorView(
    initialNote: VaultRecordPayload.NoteRecord,
    availableFolders: List<String>,
    autosaveStatus: AutosaveStatus,
    autosaveErrorMessage: String?,
    onSaveNote: (VaultRecordPayload.NoteRecord, Boolean) -> Unit,
    onDuplicate: (VaultRecordPayload.NoteRecord) -> Unit,
    onMoveToTrash: (VaultRecordPayload.NoteRecord) -> Unit,
    onClose: () -> Unit
) {
    var title by remember(initialNote.id) { mutableStateOf(initialNote.title) }
    var body by remember(initialNote.id) { mutableStateOf(initialNote.body) }
    var formatStyle by remember(initialNote.id) { mutableStateOf(initialNote.formatStyle) }
    var folderName by remember(initialNote.id) { mutableStateOf(initialNote.folderName) }
    var tagsText by remember(initialNote.id) { mutableStateOf(initialNote.tags.joinToString(", ")) }
    var checklistItems by remember(initialNote.id) { mutableStateOf(initialNote.checklistItems) }
    var newChecklistText by remember { mutableStateOf("") }

    fun currentDraft(): VaultRecordPayload.NoteRecord {
        val parsedTags = tagsText.split(",")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()
        return initialNote.copy(
            title = title,
            body = body,
            formatStyle = formatStyle,
            folderName = folderName,
            tags = parsedTags,
            checklistItems = checklistItems
        )
    }

    BackHandler {
        val draft = currentDraft()
        if (draft.title.isNotBlank() || draft.body.isNotBlank() || draft.checklistItems.isNotEmpty()) {
            onSaveNote(draft, false)
        }
        onClose()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Editor Header with Autosave Status & Actions
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(
                onClick = {
                    val draft = currentDraft()
                    if (draft.title.isNotBlank() || draft.body.isNotBlank() || draft.checklistItems.isNotEmpty()) {
                        onSaveNote(draft, false)
                    }
                    onClose()
                }
            ) {
                Icon(imageVector = Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back to notes")
            }

            // Encrypted Autosave Status Badge
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                when (autosaveStatus) {
                    AutosaveStatus.SAVING -> {
                        Text(
                            text = "Encrypting & saving...",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.secondary
                        )
                    }
                    AutosaveStatus.SAVED -> {
                        Icon(
                            imageVector = Icons.Filled.CheckCircle,
                            contentDescription = "Saved",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(16.dp)
                        )
                        Text(
                            text = "Saved (Encrypted)",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                    AutosaveStatus.ERROR -> {
                        Icon(
                            imageVector = Icons.Filled.ErrorOutline,
                            contentDescription = "Save error",
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(16.dp)
                        )
                        Text(
                            text = "Save failed (Draft kept)",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                    AutosaveStatus.IDLE -> {
                        Text(
                            text = "Encrypted Editor",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            Row {
                IconButton(onClick = { onDuplicate(currentDraft()) }) {
                    Icon(imageVector = Icons.Filled.ContentCopy, contentDescription = "Duplicate note")
                }
                IconButton(onClick = { onMoveToTrash(currentDraft()) }) {
                    Icon(
                        imageVector = Icons.Filled.Delete,
                        contentDescription = "Move note to trash",
                        tint = MaterialTheme.colorScheme.error
                    )
                }
            }
        }

        if (autosaveErrorMessage != null) {
            Surface(
                color = MaterialTheme.colorScheme.errorContainer,
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = autosaveErrorMessage,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(10.dp)
                )
            }
        }

        // Lightweight Formatting Toolbar (Paragraph, Heading, Bullets, Numbered, Checklist)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            NoteFormatStyle.entries.forEach { style ->
                FilterChip(
                    selected = formatStyle == style,
                    onClick = {
                        formatStyle = style
                        onSaveNote(currentDraft(), true)
                    },
                    leadingIcon = {
                        val icon = when (style) {
                            NoteFormatStyle.HEADING -> Icons.Filled.Title
                            NoteFormatStyle.BULLET_LIST -> Icons.Filled.FormatListBulleted
                            NoteFormatStyle.NUMBERED_LIST -> Icons.Filled.FormatListNumbered
                            NoteFormatStyle.CHECKLIST -> Icons.Filled.CheckBox
                            NoteFormatStyle.PARAGRAPH -> Icons.Outlined.Description
                        }
                        Icon(imageVector = icon, contentDescription = null, modifier = Modifier.size(16.dp))
                    },
                    label = { Text(style.label) }
                )
            }
        }

        OutlinedTextField(
            value = title,
            onValueChange = {
                title = it
                onSaveNote(currentDraft(), true)
            },
            label = { Text("Note Title") },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .testTag("note_editor_title_input")
        )

        if (formatStyle == NoteFormatStyle.CHECKLIST) {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Checklist Items",
                        style = MaterialTheme.typography.titleSmall
                    )
                    checklistItems.forEachIndexed { idx, item ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Checkbox(
                                checked = item.isChecked,
                                onCheckedChange = { checked ->
                                    checklistItems = checklistItems.toMutableList().also {
                                        it[idx] = item.copy(isChecked = checked)
                                    }
                                    onSaveNote(currentDraft(), true)
                                }
                            )
                            Text(
                                text = item.text,
                                modifier = Modifier.weight(1f),
                                textDecoration = if (item.isChecked) TextDecoration.LineThrough else TextDecoration.None
                            )
                            IconButton(
                                onClick = {
                                    checklistItems = checklistItems.toMutableList().also { it.removeAt(idx) }
                                    onSaveNote(currentDraft(), true)
                                }
                            ) {
                                Icon(imageVector = Icons.Filled.Close, contentDescription = "Remove checklist item")
                            }
                        }
                    }

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = newChecklistText,
                            onValueChange = { newChecklistText = it },
                            placeholder = { Text("Add checklist item...") },
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
                        Button(
                            onClick = {
                                if (newChecklistText.isNotBlank()) {
                                    checklistItems = checklistItems + NoteChecklistItem(
                                        id = UUID.randomUUID().toString(),
                                        text = newChecklistText.trim(),
                                        isChecked = false
                                    )
                                    newChecklistText = ""
                                    onSaveNote(currentDraft(), true)
                                }
                            }
                        ) {
                            Text("Add")
                        }
                    }
                }
            }
        }

        OutlinedTextField(
            value = body,
            onValueChange = {
                body = it
                onSaveNote(currentDraft(), true)
            },
            label = {
                Text(
                    when (formatStyle) {
                        NoteFormatStyle.BULLET_LIST -> "Bullet List Content (one bullet per line)"
                        NoteFormatStyle.NUMBERED_LIST -> "Numbered List Content (one item per line)"
                        else -> "Private Note Body"
                    }
                )
            },
            minLines = 8,
            modifier = Modifier
                .fillMaxWidth()
                .testTag("note_editor_body_input")
        )

        // Folder Selector & Tags
        Text(
            text = "Folder",
            style = MaterialTheme.typography.labelLarge
        )
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            availableFolders.forEach { folder ->
                FilterChip(
                    selected = folderName == folder,
                    onClick = {
                        folderName = folder
                        onSaveNote(currentDraft(), true)
                    },
                    label = { Text(folder) }
                )
            }
        }

        OutlinedTextField(
            value = tagsText,
            onValueChange = {
                tagsText = it
                onSaveNote(currentDraft(), true)
            },
            label = { Text("Tags (comma separated, e.g. personal, finance, ideas)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )

        HorizontalDivider()

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedButton(
                onClick = onClose,
                modifier = Modifier.weight(1f)
            ) {
                Text("Close")
            }
            Button(
                onClick = {
                    onSaveNote(currentDraft(), false)
                    onClose()
                },
                modifier = Modifier
                    .weight(1f)
                    .testTag("note_editor_save_button")
            ) {
                Text("Save & Done")
            }
        }
    }
}

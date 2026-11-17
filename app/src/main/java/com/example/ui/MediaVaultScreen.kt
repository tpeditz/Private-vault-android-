package com.example.ui

import android.graphics.BitmapFactory
import android.media.MediaPlayer
import android.view.SurfaceHolder
import android.view.SurfaceView
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AddPhotoAlternate
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.filled.FavoriteBorder
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.RestoreFromTrash
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.data.MediaKind
import com.example.data.MediaRecord
import com.example.security.StreamingMediaCryptoEngine
import kotlinx.coroutines.delay
import java.util.Arrays
import java.util.Locale

enum class MediaFilterMode(val label: String) {
    ALL("All"),
    PHOTOS("Photos"),
    VIDEOS("Videos"),
    FAVORITES("Favorites"),
    TRASH("Trash")
}

@Composable
fun MediaTabScreen(
    uiState: VaultUiState,
    viewModel: VaultViewModel,
    onLaunchPhotoVideoPicker: () -> Unit,
    onLaunchDocumentMediaPicker: () -> Unit
) {
    var activeViewerItem by remember { mutableStateOf<MediaRecord?>(null) }
    var pendingPermanentDeleteItem by remember { mutableStateOf<MediaRecord?>(null) }

    val filteredItems = remember(
        uiState.mediaItems,
        uiState.mediaSearchQuery,
        uiState.mediaFilterMode
    ) {
        val query = uiState.mediaSearchQuery.trim().lowercase(Locale.ROOT)
        uiState.mediaItems
            .filter { item ->
                when (uiState.mediaFilterMode) {
                    MediaFilterMode.ALL -> !item.isTrashed
                    MediaFilterMode.PHOTOS -> !item.isTrashed && item.mediaKind == MediaKind.PHOTO
                    MediaFilterMode.VIDEOS -> !item.isTrashed && item.mediaKind == MediaKind.VIDEO
                    MediaFilterMode.FAVORITES -> !item.isTrashed && item.isFavorite
                    MediaFilterMode.TRASH -> item.isTrashed
                }
            }
            .filter { item ->
                if (query.isEmpty()) {
                    true
                } else {
                    item.title.lowercase(Locale.ROOT).contains(query) ||
                        item.mimeType.lowercase(Locale.ROOT).contains(query) ||
                        item.tags.any { it.lowercase(Locale.ROOT).contains(query) }
                }
            }
            .sortedWith(
                compareByDescending<MediaRecord> { it.isFavorite }
                    .thenByDescending { it.updatedAtEpochMs }
            )
    }

    // Permanent Cryptographic Deletion Confirmation Dialog (Correction 3)
    val itemToDelete = pendingPermanentDeleteItem
    if (itemToDelete != null) {
        AlertDialog(
            onDismissRequest = { pendingPermanentDeleteItem = null },
            icon = {
                Icon(
                    imageVector = Icons.Filled.DeleteForever,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error
                )
            },
            title = { Text("Cryptographically Delete Media?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "Delete \"${itemToDelete.title}\" permanently from this vault?",
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "This action permanently destroys the item's unique 256-bit AES-GCM media and thumbnail keys inside the encrypted database and unlinks the .pvmedia and .pvthumb ciphertext files.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "Flash Storage Note: Because mobile flash storage uses wear-leveling, in-place file overwriting cannot guarantee physical block erasure. Destroying the per-file 256-bit keys renders any residual ciphertext blocks computationally unrecoverable.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val target = itemToDelete
                        pendingPermanentDeleteItem = null
                        if (activeViewerItem?.id == target.id) {
                            activeViewerItem = null
                        }
                        viewModel.deleteMediaPermanently(target.id)
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error
                    ),
                    modifier = Modifier.testTag("confirm_crypto_delete_media_button")
                ) {
                    Text("Destroy Keys & Delete")
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingPermanentDeleteItem = null }) {
                    Text("Cancel")
                }
            }
        )
    }

    // Active Full-Screen Encrypted Photo or Video Viewer
    val currentViewer = activeViewerItem
    if (currentViewer != null) {
        if (currentViewer.mediaKind == MediaKind.PHOTO) {
            EncryptedPhotoViewerDialog(
                mediaRecord = currentViewer,
                viewModel = viewModel,
                onDismiss = { activeViewerItem = null }
            )
        } else {
            EncryptedVideoPlayerDialog(
                mediaRecord = currentViewer,
                viewModel = viewModel,
                onDismiss = { activeViewerItem = null }
            )
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Header & Zero-Permission Import Actions
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Encrypted Media Vault",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "256 KiB chunked AES-256-GCM • Full-chunk verified • Zero plaintext on disk",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Button(
                onClick = {
                    viewModel.vaultRepository.sessionManager.beginFilePickerTransitionWindow()
                    onLaunchPhotoVideoPicker()
                },
                enabled = !uiState.isImportingMedia && !uiState.isBusy,
                modifier = Modifier
                    .weight(1f)
                    .testTag("media_import_picker_button")
            ) {
                Icon(Icons.Filled.AddPhotoAlternate, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Add Photos / Videos")
            }

            OutlinedButton(
                onClick = {
                    viewModel.vaultRepository.sessionManager.beginFilePickerTransitionWindow()
                    onLaunchDocumentMediaPicker()
                },
                enabled = !uiState.isImportingMedia && !uiState.isBusy,
                modifier = Modifier.testTag("media_import_files_button")
            ) {
                Icon(Icons.Filled.FolderOpen, contentDescription = null)
                Spacer(modifier = Modifier.width(6.dp))
                Text("Files")
            }
        }

        // Live Streaming Encryption & Every-Chunk Verification Progress Banner
        if (uiState.isImportingMedia) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("media_import_progress_banner"),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.secondaryContainer
                )
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp
                        )
                        Text(
                            text = uiState.mediaImportStatusText.ifBlank {
                                "Encrypting and verifying media chunks…"
                            },
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.onSecondaryContainer
                        )
                    }
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                }
            }
        }

        // Search & Filter Bar
        OutlinedTextField(
            value = uiState.mediaSearchQuery,
            onValueChange = viewModel::setMediaSearchQuery,
            placeholder = { Text("Search encrypted photos & videos…") },
            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
            trailingIcon = {
                if (uiState.mediaSearchQuery.isNotEmpty()) {
                    IconButton(onClick = { viewModel.setMediaSearchQuery("") }) {
                        Icon(Icons.Filled.Close, contentDescription = "Clear search")
                    }
                }
            },
            singleLine = true,
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier
                .fillMaxWidth()
                .testTag("media_search_input")
        )

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            MediaFilterMode.entries.forEach { mode ->
                FilterChip(
                    selected = uiState.mediaFilterMode == mode,
                    onClick = { viewModel.setMediaFilterMode(mode) },
                    label = { Text(mode.label) },
                    modifier = Modifier.testTag("media_filter_${mode.name.lowercase()}")
                )
            }
        }

        if (filteredItems.isEmpty()) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                shape = RoundedCornerShape(18.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(24.dp),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        imageVector = Icons.Filled.Lock,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(44.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = if (uiState.mediaFilterMode == MediaFilterMode.TRASH) {
                            "Media Trash is Empty"
                        } else {
                            "No Encrypted Photos or Videos Yet"
                        },
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "Imported photos and videos are encrypted into 256 KiB AES-256-GCM chunks with per-file keys and full-stream verification before commit. Your original gallery files are never modified unless you delete them yourself.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            LazyVerticalGrid(
                columns = GridCells.Adaptive(minSize = 156.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .testTag("media_vault_grid"),
                contentPadding = PaddingValues(bottom = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(
                    items = filteredItems,
                    key = { it.id }
                ) { item ->
                    EncryptedMediaGridCard(
                        item = item,
                        thumbnailBytes = uiState.decryptedThumbnailsById[item.id],
                        onRequestThumbnailLoad = { viewModel.ensureMediaThumbnailLoaded(item) },
                        onOpenViewer = { activeViewerItem = item },
                        onToggleFavorite = { viewModel.toggleMediaFavorite(item) },
                        onToggleTrash = { viewModel.toggleMediaTrash(item) },
                        onRequestPermanentDelete = { pendingPermanentDeleteItem = item }
                    )
                }
            }
        }
    }
}

@Composable
private fun EncryptedMediaGridCard(
    item: MediaRecord,
    thumbnailBytes: ByteArray?,
    onRequestThumbnailLoad: () -> Unit,
    onOpenViewer: () -> Unit,
    onToggleFavorite: () -> Unit,
    onToggleTrash: () -> Unit,
    onRequestPermanentDelete: () -> Unit
) {
    LaunchedEffect(item.id, thumbnailBytes == null) {
        if (thumbnailBytes == null) {
            onRequestThumbnailLoad()
        }
    }

    val decodedBitmap = remember(item.id, thumbnailBytes) {
        if (thumbnailBytes != null && thumbnailBytes.isNotEmpty()) {
            runCatching {
                BitmapFactory.decodeByteArray(thumbnailBytes, 0, thumbnailBytes.size)?.asImageBitmap()
            }.getOrNull()
        } else {
            null
        }
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onOpenViewer() }
            .testTag("media_item_card_${item.id}"),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .aspectRatio(1.15f)
                    .background(MaterialTheme.colorScheme.surfaceVariant),
                contentAlignment = Alignment.Center
            ) {
                if (decodedBitmap != null) {
                    Image(
                        bitmap = decodedBitmap,
                        contentDescription = item.title,
                        contentScale = ContentScale.Crop,
                        modifier = Modifier.fillMaxSize()
                    )
                } else {
                    Icon(
                        imageVector = if (item.mediaKind == MediaKind.VIDEO) {
                            Icons.Filled.Videocam
                        } else {
                            Icons.Filled.Image
                        },
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(36.dp)
                    )
                }

                // Top-left media kind + duration badge
                Surface(
                    color = Color.Black.copy(alpha = 0.68f),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier
                        .align(Alignment.TopStart)
                        .padding(8.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Icon(
                            imageVector = if (item.mediaKind == MediaKind.VIDEO) {
                                Icons.Filled.Videocam
                            } else {
                                Icons.Filled.Image
                            },
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(14.dp)
                        )
                        Text(
                            text = if (item.mediaKind == MediaKind.VIDEO && item.durationMs > 0L) {
                                formatDurationMs(item.durationMs)
                            } else if (item.mediaKind == MediaKind.VIDEO) {
                                "VIDEO"
                            } else {
                                "PHOTO"
                            },
                            style = MaterialTheme.typography.labelSmall,
                            color = Color.White
                        )
                    }
                }

                if (item.mediaKind == MediaKind.VIDEO) {
                    Surface(
                        color = Color.Black.copy(alpha = 0.6f),
                        shape = CircleShape,
                        modifier = Modifier.size(44.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(
                                imageVector = Icons.Filled.PlayArrow,
                                contentDescription = "Play encrypted video",
                                tint = Color.White,
                                modifier = Modifier.size(26.dp)
                            )
                        }
                    }
                }
            }

            Column(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = item.title,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "${formatByteSize(item.originalSizeBytes)} • ${item.chunkCount} chunk(s)",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (!item.isTrashed) {
                        IconButton(
                            onClick = onToggleFavorite,
                            modifier = Modifier.size(36.dp)
                        ) {
                            Icon(
                                imageVector = if (item.isFavorite) Icons.Filled.Favorite else Icons.Filled.FavoriteBorder,
                                contentDescription = "Toggle Favorite",
                                tint = if (item.isFavorite) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        IconButton(
                            onClick = onToggleTrash,
                            modifier = Modifier.size(36.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Delete,
                                contentDescription = "Move to Trash",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    } else {
                        IconButton(
                            onClick = onToggleTrash,
                            modifier = Modifier.size(36.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Filled.RestoreFromTrash,
                                contentDescription = "Restore from Trash",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }

                    IconButton(
                        onClick = onRequestPermanentDelete,
                        modifier = Modifier
                            .size(36.dp)
                            .testTag("media_crypto_delete_${item.id}")
                    ) {
                        Icon(
                            imageVector = Icons.Filled.DeleteForever,
                            contentDescription = "Cryptographically Delete Permanently",
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun EncryptedPhotoViewerDialog(
    mediaRecord: MediaRecord,
    viewModel: VaultViewModel,
    onDismiss: () -> Unit
) {
    var photoBytes by remember(mediaRecord.id) { mutableStateOf<ByteArray?>(null) }
    var loadError by remember(mediaRecord.id) { mutableStateOf<String?>(null) }

    LaunchedEffect(mediaRecord.id) {
        try {
            photoBytes = viewModel.loadDecryptedPhotoBytes(mediaRecord)
        } catch (e: Exception) {
            loadError = "Could not authenticate or decrypt photo."
        }
    }

    DisposableEffect(mediaRecord.id) {
        onDispose {
            photoBytes?.let { Arrays.fill(it, 0.toByte()) }
            photoBytes = null
        }
    }

    val imageBitmap = remember(photoBytes) {
        val bytes = photoBytes ?: return@remember null
        runCatching {
            val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts)
            var sampleSize = 1
            while (opts.outWidth / sampleSize > 2048 || opts.outHeight / sampleSize > 2048) {
                sampleSize *= 2
            }
            val decodeOpts = BitmapFactory.Options().apply { inSampleSize = sampleSize }
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, decodeOpts)?.asImageBitmap()
        }.getOrNull()
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = Color.Black
        ) {
            Column(modifier = Modifier.fillMaxSize()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = mediaRecord.title,
                            style = MaterialTheme.typography.titleMedium,
                            color = Color.White,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = "${formatByteSize(mediaRecord.originalSizeBytes)} • ${mediaRecord.chunkCount} verified chunk(s) • SHA-256 ${mediaRecord.ciphertextSha256Hex.take(12)}…",
                            style = MaterialTheme.typography.labelSmall,
                            color = Color.White.copy(alpha = 0.75f)
                        )
                    }
                    IconButton(onClick = onDismiss) {
                        Icon(
                            imageVector = Icons.Filled.Close,
                            contentDescription = "Close photo viewer",
                            tint = Color.White
                        )
                    }
                }

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .padding(12.dp),
                    contentAlignment = Alignment.Center
                ) {
                    when {
                        loadError != null -> {
                            Text(
                                text = loadError.orEmpty(),
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                        imageBitmap != null -> {
                            Image(
                                bitmap = imageBitmap,
                                contentDescription = mediaRecord.title,
                                contentScale = ContentScale.Fit,
                                modifier = Modifier.fillMaxSize()
                            )
                        }
                        else -> {
                            CircularProgressIndicator(color = Color.White)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun EncryptedVideoPlayerDialog(
    mediaRecord: MediaRecord,
    viewModel: VaultViewModel,
    onDismiss: () -> Unit
) {
    var dataSource by remember(mediaRecord.id) {
        mutableStateOf<StreamingMediaCryptoEngine.EncryptedChunkMediaDataSource?>(null)
    }
    var mediaPlayer by remember(mediaRecord.id) { mutableStateOf<MediaPlayer?>(null) }
    var isPrepared by remember(mediaRecord.id) { mutableStateOf(false) }
    var isPlaying by remember(mediaRecord.id) { mutableStateOf(false) }
    var currentPosMs by remember(mediaRecord.id) { mutableIntStateOf(0) }
    var totalDurationMs by remember(mediaRecord.id) {
        mutableIntStateOf(mediaRecord.durationMs.toInt().coerceAtLeast(1))
    }
    var playerError by remember(mediaRecord.id) { mutableStateOf<String?>(null) }

    LaunchedEffect(mediaRecord.id) {
        try {
            dataSource = viewModel.openEncryptedVideoDataSource(mediaRecord)
        } catch (_: Exception) {
            playerError = "Could not open encrypted video stream."
        }
    }

    LaunchedEffect(isPrepared, isPlaying) {
        while (isPrepared && isPlaying) {
            val mp = mediaPlayer
            if (mp != null) {
                runCatching {
                    currentPosMs = mp.currentPosition
                }
            }
            delay(250L)
        }
    }

    DisposableEffect(mediaRecord.id) {
        onDispose {
            runCatching {
                mediaPlayer?.stop()
            }
            runCatching {
                mediaPlayer?.release()
            }
            mediaPlayer = null
            runCatching {
                dataSource?.close()
            }
            dataSource = null
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = Color.Black
        ) {
            Column(modifier = Modifier.fillMaxSize()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = mediaRecord.title,
                            style = MaterialTheme.typography.titleMedium,
                            color = Color.White,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = "In-memory EncryptedChunkMediaDataSource • Zero temp video files on disk",
                            style = MaterialTheme.typography.labelSmall,
                            color = Color.White.copy(alpha = 0.75f)
                        )
                    }
                    IconButton(onClick = onDismiss) {
                        Icon(
                            imageVector = Icons.Filled.Close,
                            contentDescription = "Close video player",
                            tint = Color.White
                        )
                    }
                }

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f)
                        .padding(12.dp),
                    contentAlignment = Alignment.Center
                ) {
                    val activeDataSource = dataSource
                    when {
                        playerError != null -> {
                            Text(
                                text = playerError.orEmpty(),
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                        activeDataSource != null -> {
                            AndroidView(
                                factory = { ctx ->
                                    SurfaceView(ctx).apply {
                                        holder.addCallback(object : SurfaceHolder.Callback {
                                            override fun surfaceCreated(holder: SurfaceHolder) {
                                                try {
                                                    val mp = MediaPlayer()
                                                    mediaPlayer = mp
                                                    mp.setDisplay(holder)
                                                    mp.setDataSource(activeDataSource)
                                                    mp.setOnPreparedListener { preparedMp ->
                                                        isPrepared = true
                                                        totalDurationMs = preparedMp.duration.coerceAtLeast(1)
                                                        preparedMp.start()
                                                        isPlaying = true
                                                    }
                                                    mp.setOnCompletionListener {
                                                        isPlaying = false
                                                        currentPosMs = totalDurationMs
                                                    }
                                                    mp.setOnErrorListener { _, _, _ ->
                                                        playerError = "Encrypted video playback encountered a codec or integrity error."
                                                        isPlaying = false
                                                        true
                                                    }
                                                    mp.prepareAsync()
                                                } catch (_: Exception) {
                                                    playerError = "Failed to initialize encrypted video playback."
                                                }
                                            }

                                            override fun surfaceChanged(
                                                holder: SurfaceHolder,
                                                format: Int,
                                                width: Int,
                                                height: Int
                                            ) = Unit

                                            override fun surfaceDestroyed(holder: SurfaceHolder) {
                                                runCatching { mediaPlayer?.setDisplay(null) }
                                            }
                                        })
                                    }
                                },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .aspectRatio(16f / 9f)
                                    .clip(RoundedCornerShape(12.dp))
                            )
                        }
                        else -> {
                            CircularProgressIndicator(color = Color.White)
                        }
                    }
                }

                // Playback controls bar
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp, vertical = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Slider(
                        value = currentPosMs.toFloat().coerceIn(0f, totalDurationMs.toFloat()),
                        onValueChange = { newPos ->
                            currentPosMs = newPos.toInt()
                            runCatching { mediaPlayer?.seekTo(currentPosMs) }
                        },
                        valueRange = 0f..totalDurationMs.toFloat().coerceAtLeast(1f),
                        enabled = isPrepared
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = "${formatDurationMs(currentPosMs.toLong())} / ${formatDurationMs(totalDurationMs.toLong())}",
                            style = MaterialTheme.typography.labelMedium,
                            color = Color.White
                        )
                        Button(
                            onClick = {
                                val mp = mediaPlayer ?: return@Button
                                if (mp.isPlaying) {
                                    mp.pause()
                                    isPlaying = false
                                } else {
                                    mp.start()
                                    isPlaying = true
                                }
                            },
                            enabled = isPrepared
                        ) {
                            Icon(
                                imageVector = if (isPlaying) Icons.Filled.Pause else Icons.Filled.PlayArrow,
                                contentDescription = if (isPlaying) "Pause" else "Play"
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(if (isPlaying) "Pause" else "Play")
                        }
                    }
                }
            }
        }
    }
}

private fun formatByteSize(bytes: Long): String {
    return when {
        bytes >= 1024L * 1024L -> String.format(Locale.US, "%.1f MB", bytes.toDouble() / (1024.0 * 1024.0))
        bytes >= 1024L -> String.format(Locale.US, "%.1f KB", bytes.toDouble() / 1024.0)
        else -> "$bytes B"
    }
}

private fun formatDurationMs(durationMs: Long): String {
    val totalSec = (durationMs / 1000L).coerceAtLeast(0L)
    val min = totalSec / 60L
    val sec = totalSec % 60L
    return String.format(Locale.US, "%d:%02d", min, sec)
}

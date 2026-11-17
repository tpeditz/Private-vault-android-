package com.example.data

import com.example.security.CryptoEngine
import com.example.security.StreamingMediaCryptoEngine
import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.Arrays
import java.util.Base64
import javax.crypto.AEADBadTagException

/**
 * Self-contained encrypted portable `.pvault` backup engine.
 *
 * Binary Header Layout:
 * - `[0..7]`   8B Magic `"PVAULTB1"`
 * - `[8..11]`  4B `backupSchemaVersion` (`1`)
 * - `[12..15]` 4B `kdfMemoryKb`
 * - `[16..19]` 4B `kdfIterations`
 * - `[20..23]` 4B `kdfParallelism`
 * - `[24..39]` 16B `backupKdfSalt`
 * - `[40..51]` 12B `backupGcmNonce`
 * - `[52..N]`  AES-256-GCM ciphertext + 16B tag of UTF-8 JSON payload
 *
 * Scope, Capacity & Privacy Guarantee:
 * - Exports ONLY the currently unlocked vault slot's records.
 * - Never embeds SQLite `vault_slot` integers or reveals whether another slot exists.
 * - Portable `.pvault` files have a hard `32 MiB` (`MAX_BACKUP_FILE_BYTES`) container ceiling to
 *   prevent out-of-memory errors during authenticated in-memory verification. Because embedded
 *   `.pvmedia` and `.pvthumb` blobs are Base64-encoded inside the JSON payload (~33% size overhead),
 *   `ALL_DATA_WITH_MEDIA` enforces a strict `22 MiB` (`MAX_RAW_MEDIA_BYTES_FOR_PORTABLE_BACKUP`)
 *   raw media ciphertext limit and fails closed before export if active-slot media exceeds this
 *   capacity—never silently skipping files or claiming a partial backup is complete.
 */
object PortableBackupEngine {

    private val MAGIC_BYTES = "PVAULTB1".toByteArray(StandardCharsets.US_ASCII)
    const val HEADER_BYTES = 52
    const val MAX_BACKUP_FILE_BYTES = 32 * 1024 * 1024 // 32 MiB portable container ceiling
    const val MAX_RAW_MEDIA_BYTES_FOR_PORTABLE_BACKUP = 22 * 1024 * 1024 // 22 MiB raw media ciphertext ceiling (~29.3 MiB Base64)
    const val MAX_RECORDS_PER_BACKUP = 10_000
    const val MAX_FIELD_CHARS = 256_000

    enum class RestoreMode {
        MERGE_KEEP_NEWEST,
        REPLACE_ACTIVE_VAULT
    }

    enum class BackupExportScope(val label: String) {
        ALL_DATA("Notes & Passwords"),
        ALL_DATA_WITH_MEDIA("All Data + Media (≤22 MiB)"),
        NOTES_ONLY("Notes Only"),
        PASSWORDS_ONLY("Passwords Only")
    }

    data class EmbeddedMediaBlob(
        val mediaId: String,
        val formatVersion: Int,
        val chunkCount: Int,
        val ciphertextSha256: String,
        val mediaCiphertextBytes: ByteArray,
        val thumbCiphertextBytes: ByteArray
    )

    data class BackupPayload(
        val exportedAtEpochMs: Long,
        val appVersionName: String,
        val items: List<VaultItem>,
        val mediaBlobs: Map<String, EmbeddedMediaBlob> = emptyMap()
    ) {
        val notesCount: Int get() = items.count { it is NoteRecord }
        val credentialsCount: Int get() = items.count { it is CredentialRecord }
        val foldersCount: Int get() = items.count { it is VaultFolder }
        val mediaCount: Int get() = items.count { it is MediaRecord }
        val isEmptyBackup: Boolean
            get() = items.none { it is NoteRecord || it is CredentialRecord || it is MediaRecord }
    }

    /**
     * Encrypts a list of active-slot `VaultItem`s (and optional verified `EmbeddedMediaBlob`s)
     * into a portable `.pvault` byte array.
     */
    fun createEncryptedBackupBytes(
        items: List<VaultItem>,
        backupPasswordChars: CharArray,
        appVersionName: String = "1.0.5",
        kdfParams: CryptoEngine.KdfParams = CryptoEngine.KdfParams(),
        exportedAtEpochMs: Long = System.currentTimeMillis(),
        mediaBlobs: Map<String, EmbeddedMediaBlob> = emptyMap()
    ): ByteArray {
        require(backupPasswordChars.isNotEmpty()) { "Backup password cannot be empty." }
        require(items.size <= MAX_RECORDS_PER_BACKUP) {
            "Backup exceeds maximum supported record count ($MAX_RECORDS_PER_BACKUP)."
        }
        kdfParams.validateBounds()

        val mediaRecords = items.filterIsInstance<MediaRecord>()
        if (mediaRecords.isNotEmpty()) {
            var totalRawCiphertextBytes = 0L
            for (record in mediaRecords) {
                val blob = mediaBlobs[record.id]
                    ?: throw IllegalArgumentException(
                        "Backup aborted: missing encrypted media content for item ${record.id}. Portable media backups never silently skip files."
                    )
                require(blob.mediaCiphertextBytes.isNotEmpty() && blob.thumbCiphertextBytes.isNotEmpty()) {
                    "Backup aborted: empty encrypted media or thumbnail payload for item ${record.id}."
                }
                require(blob.ciphertextSha256.equals(record.ciphertextSha256Hex, ignoreCase = true)) {
                    "Backup aborted: media SHA-256 mismatch for item ${record.id}."
                }
                totalRawCiphertextBytes += blob.mediaCiphertextBytes.size.toLong() + blob.thumbCiphertextBytes.size.toLong()
            }
            require(totalRawCiphertextBytes <= MAX_RAW_MEDIA_BYTES_FOR_PORTABLE_BACKUP.toLong()) {
                val totalMiB = String.format(java.util.Locale.US, "%.1f", totalRawCiphertextBytes.toDouble() / (1024.0 * 1024.0))
                "Active vault media ($totalMiB MiB) exceeds the 22.0 MiB raw media capacity of a single 32 MiB portable .pvault container. Export using \"Notes & Passwords\" scope so no media files are silently skipped."
            }
        }

        val salt = CryptoEngine.generateSalt()
        val nonce = CryptoEngine.generateNonce()
        val backupKek = CryptoEngine.deriveKeyArgon2id(
            passwordChars = backupPasswordChars,
            salt = salt,
            params = kdfParams,
            normalizeUnicodeNfc = true
        )

        var plaintextBytes = ByteArray(0)
        try {
            val root = JSONObject()
            root.put("backupSchemaVersion", CryptoEngine.BACKUP_SCHEMA_VERSION)
            root.put("exportedAtEpochMs", exportedAtEpochMs)
            root.put("appVersionName", appVersionName)

            val recordsArray = JSONArray()
            val seenIds = HashSet<String>(items.size)
            items.forEach { item ->
                require(item.id.isNotBlank()) { "Cannot export a record with a blank ID." }
                require(seenIds.add(item.id)) { "Duplicate record ID detected during backup export: ${item.id}" }
                val encodedBytes = VaultRecordCodec.encode(item)
                try {
                    val itemJson = JSONObject(String(encodedBytes, StandardCharsets.UTF_8))
                    recordsArray.put(itemJson)
                } finally {
                    Arrays.fill(encodedBytes, 0.toByte())
                }
            }
            root.put("records", recordsArray)

            if (mediaRecords.isNotEmpty()) {
                val blobsArray = JSONArray()
                val encoder = Base64.getEncoder()
                for (record in mediaRecords) {
                    val blob = mediaBlobs.getValue(record.id)
                    val blobObj = JSONObject()
                    blobObj.put("mediaId", blob.mediaId)
                    blobObj.put("formatVersion", blob.formatVersion)
                    blobObj.put("chunkCount", blob.chunkCount)
                    blobObj.put("ciphertextSha256", blob.ciphertextSha256)
                    blobObj.put("mediaCiphertextBase64", encoder.encodeToString(blob.mediaCiphertextBytes))
                    blobObj.put("thumbCiphertextBase64", encoder.encodeToString(blob.thumbCiphertextBytes))
                    blobsArray.put(blobObj)
                }
                root.put("mediaBlobs", blobsArray)
            }

            plaintextBytes = root.toString().toByteArray(StandardCharsets.UTF_8)
            require(plaintextBytes.size <= MAX_BACKUP_FILE_BYTES - HEADER_BYTES - CryptoEngine.GCM_TAG_BYTES) {
                "Serialized backup exceeds the 32 MiB portable .pvault container limit. Use \"Notes & Passwords\" export scope if your vault contains large media."
            }
            val aad = CryptoEngine.buildBackupAad(CryptoEngine.BACKUP_SCHEMA_VERSION, kdfParams)
            val ciphertext = CryptoEngine.encryptAesGcm(
                keyBytes = backupKek,
                nonce = nonce,
                plaintext = plaintextBytes,
                aad = aad
            )

            val output = ByteArray(HEADER_BYTES + ciphertext.size)
            val buffer = ByteBuffer.wrap(output)
            buffer.put(MAGIC_BYTES)
            buffer.putInt(CryptoEngine.BACKUP_SCHEMA_VERSION)
            buffer.putInt(kdfParams.memoryKb)
            buffer.putInt(kdfParams.iterations)
            buffer.putInt(kdfParams.parallelism)
            buffer.put(salt)
            buffer.put(nonce)
            buffer.put(ciphertext)
            return output
        } finally {
            Arrays.fill(backupKek, 0.toByte())
            if (plaintextBytes.isNotEmpty()) {
                Arrays.fill(plaintextBytes, 0.toByte())
            }
        }
    }

    /**
     * Validates the `.pvault` header, enforces KDF bounds, derives the backup key, verifies the
     * AES-256-GCM authentication tag in memory, and strictly validates the `records` array and all
     * record fields (plus any embedded media blobs) BEFORE any database or disk write.
     */
    @Throws(
        IllegalArgumentException::class,
        AEADBadTagException::class
    )
    fun decryptAndVerifyBackupBytes(
        backupBytes: ByteArray,
        backupPasswordChars: CharArray
    ): BackupPayload {
        require(backupPasswordChars.isNotEmpty()) { "Backup password is required." }
        require(backupBytes.size >= HEADER_BYTES + CryptoEngine.GCM_TAG_BYTES) {
            "Invalid or truncated .pvault backup file."
        }
        require(backupBytes.size <= MAX_BACKUP_FILE_BYTES) {
            "Backup file exceeds maximum safe size (32 MiB)."
        }

        val buffer = ByteBuffer.wrap(backupBytes)
        val fileMagic = ByteArray(MAGIC_BYTES.size)
        buffer.get(fileMagic)
        require(fileMagic.contentEquals(MAGIC_BYTES)) {
            "Unrecognized file header. Please select a valid .pvault encrypted backup."
        }

        val schemaVersion = buffer.int
        require(schemaVersion == CryptoEngine.BACKUP_SCHEMA_VERSION) {
            "Unsupported backup schema version: $schemaVersion"
        }

        val memoryKb = buffer.int
        val iterations = buffer.int
        val parallelism = buffer.int

        val kdfParams = CryptoEngine.KdfParams(
            algorithm = CryptoEngine.KDF_ALGORITHM_ARGON2ID,
            memoryKb = memoryKb,
            iterations = iterations,
            parallelism = parallelism
        )
        // Strict KDF bounds enforcement before allocating Argon2 memory (B03 / S03)
        kdfParams.validateBounds()

        val salt = ByteArray(CryptoEngine.SALT_BYTES)
        buffer.get(salt)

        val nonce = ByteArray(CryptoEngine.NONCE_BYTES)
        buffer.get(nonce)

        val ciphertextLength = backupBytes.size - HEADER_BYTES
        val ciphertext = ByteArray(ciphertextLength)
        buffer.get(ciphertext)

        val aad = CryptoEngine.buildBackupAad(schemaVersion, kdfParams)
        var backupKek = CryptoEngine.deriveKeyArgon2id(
            passwordChars = backupPasswordChars,
            salt = salt,
            params = kdfParams,
            normalizeUnicodeNfc = true
        )
        var decryptedBytes = ByteArray(0)
        try {
            decryptedBytes = try {
                CryptoEngine.decryptAesGcm(
                    keyBytes = backupKek,
                    nonce = nonce,
                    ciphertext = ciphertext,
                    aad = aad
                )
            } catch (tagEx: AEADBadTagException) {
                if (CryptoEngine.hasDistinctLegacyNonNfcForm(backupPasswordChars)) {
                    Arrays.fill(backupKek, 0.toByte())
                    backupKek = CryptoEngine.deriveKeyArgon2id(
                        passwordChars = backupPasswordChars,
                        salt = salt,
                        params = kdfParams,
                        normalizeUnicodeNfc = false
                    )
                    CryptoEngine.decryptAesGcm(
                        keyBytes = backupKek,
                        nonce = nonce,
                        ciphertext = ciphertext,
                        aad = aad
                    )
                } else {
                    throw tagEx
                }
            }

            val root = try {
                JSONObject(String(decryptedBytes, StandardCharsets.UTF_8))
            } catch (_: Exception) {
                throw IllegalArgumentException("Malformed backup payload: invalid JSON structure.")
            }

            if (root.has("backupSchemaVersion")) {
                val innerVersion = root.optInt("backupSchemaVersion", -1)
                require(innerVersion == CryptoEngine.BACKUP_SCHEMA_VERSION) {
                    "Unsupported inner backup schema version: $innerVersion"
                }
            }

            if (!root.has("records") || root.isNull("records")) {
                throw IllegalArgumentException("Malformed backup payload: missing required 'records' array.")
            }
            val rawRecordsValue = root.get("records")
            if (rawRecordsValue !is JSONArray) {
                throw IllegalArgumentException("Malformed backup payload: 'records' must be a JSON array.")
            }
            val recordsArray = rawRecordsValue

            require(recordsArray.length() <= MAX_RECORDS_PER_BACKUP) {
                "Backup contains too many records (${recordsArray.length()} > $MAX_RECORDS_PER_BACKUP)."
            }

            val exportedAt = root.optLong("exportedAtEpochMs", 0L)
            require(exportedAt >= 0L) {
                "Malformed backup payload: invalid exportedAtEpochMs timestamp."
            }
            val appVersion = root.optString("appVersionName", "unknown")
            require(appVersion.length <= 64) {
                "Malformed backup payload: invalid appVersionName length."
            }

            val items = mutableListOf<VaultItem>()
            val seenIds = HashSet<String>(recordsArray.length())
            for (i in 0 until recordsArray.length()) {
                if (recordsArray.isNull(i)) {
                    throw IllegalArgumentException("Malformed record at index $i in backup: null element.")
                }
                val elem = recordsArray.get(i)
                val obj = elem as? JSONObject
                    ?: throw IllegalArgumentException("Malformed record at index $i in backup: expected JSON object.")
                if (!obj.has("id") || obj.isNull("id") || obj.optString("id", "").isBlank()) {
                    throw IllegalArgumentException("Malformed record at index $i in backup: missing or blank record ID.")
                }
                if (!obj.has("recordType") || obj.isNull("recordType")) {
                    throw IllegalArgumentException("Malformed record at index $i in backup: missing recordType.")
                }

                val decoded = try {
                    VaultRecordCodec.decodeFromJsonObject(obj)
                } catch (e: Exception) {
                    throw IllegalArgumentException("Malformed record at index $i in backup: ${e.message}")
                }
                validateDecodedRecordLimits(decoded)
                require(seenIds.add(decoded.id)) {
                    "Backup contains duplicate record ID: ${decoded.id}"
                }
                items.add(decoded)
            }

            validateFolderReferences(items)

            val parsedBlobs = LinkedHashMap<String, EmbeddedMediaBlob>()
            if (root.has("mediaBlobs") && !root.isNull("mediaBlobs")) {
                val rawBlobs = root.get("mediaBlobs")
                if (rawBlobs !is JSONArray) {
                    throw IllegalArgumentException("Malformed backup payload: 'mediaBlobs' must be a JSON array.")
                }
                val decoder = Base64.getDecoder()
                for (i in 0 until rawBlobs.length()) {
                    val blobObj = rawBlobs.optJSONObject(i)
                        ?: throw IllegalArgumentException("Malformed mediaBlob at index $i in backup.")
                    val mediaId = blobObj.optString("mediaId", "").trim()
                    val formatVersion = blobObj.optInt("formatVersion", StreamingMediaCryptoEngine.FORMAT_VERSION_V1)
                    val chunkCount = blobObj.optInt("chunkCount", 0)
                    val sha256 = blobObj.optString("ciphertextSha256", "").trim().lowercase()
                    val mediaB64 = blobObj.optString("mediaCiphertextBase64", "")
                    val thumbB64 = blobObj.optString("thumbCiphertextBase64", "")

                    require(mediaId.isNotBlank() && chunkCount > 0 && sha256.length == 64) {
                        "Malformed mediaBlob metadata at index $i in backup."
                    }
                    val mediaBytes = try {
                        decoder.decode(mediaB64)
                    } catch (_: Exception) {
                        throw IllegalArgumentException("Malformed Base64 media ciphertext for item $mediaId.")
                    }
                    val thumbBytes = try {
                        decoder.decode(thumbB64)
                    } catch (_: Exception) {
                        throw IllegalArgumentException("Malformed Base64 thumbnail ciphertext for item $mediaId.")
                    }
                    require(mediaBytes.isNotEmpty() && thumbBytes.isNotEmpty()) {
                        "Empty media or thumbnail payload in backup for item $mediaId."
                    }
                    val actualSha256 = StreamingMediaCryptoEngine.sha256Hex(mediaBytes)
                    require(actualSha256.equals(sha256, ignoreCase = true)) {
                        "Media blob SHA-256 integrity check failed for item $mediaId in backup."
                    }
                    parsedBlobs[mediaId] = EmbeddedMediaBlob(
                        mediaId = mediaId,
                        formatVersion = formatVersion,
                        chunkCount = chunkCount,
                        ciphertextSha256 = actualSha256,
                        mediaCiphertextBytes = mediaBytes,
                        thumbCiphertextBytes = thumbBytes
                    )
                }
            }

            // Ensure every MediaRecord in items has a verified EmbeddedMediaBlob in parsedBlobs
            for (item in items) {
                if (item is MediaRecord) {
                    val blob = parsedBlobs[item.id]
                        ?: throw IllegalArgumentException(
                            "Malformed backup payload: MediaRecord ${item.id} is missing its encrypted media blob."
                        )
                    require(blob.ciphertextSha256.equals(item.ciphertextSha256Hex, ignoreCase = true)) {
                        "Malformed backup payload: MediaRecord ${item.id} SHA-256 does not match its media blob."
                    }
                    require(blob.chunkCount == item.chunkCount) {
                        "Malformed backup payload: MediaRecord ${item.id} chunk count mismatch."
                    }
                }
            }

            return BackupPayload(
                exportedAtEpochMs = exportedAt,
                appVersionName = appVersion,
                items = items,
                mediaBlobs = parsedBlobs
            )
        } finally {
            Arrays.fill(backupKek, 0.toByte())
            if (decryptedBytes.isNotEmpty()) {
                Arrays.fill(decryptedBytes, 0.toByte())
            }
        }
    }

    private fun validateDecodedRecordLimits(item: VaultItem) {
        require(item.id.isNotBlank() && item.id.length <= 128) {
            "Invalid record ID length in backup."
        }
        require(item.createdAtEpochMs >= 0L && item.updatedAtEpochMs >= 0L) {
            "Invalid negative timestamp in backup record."
        }
        when (item) {
            is NoteRecord -> {
                require(
                    item.title.length <= MAX_FIELD_CHARS &&
                        item.body.length <= MAX_FIELD_CHARS &&
                        item.category.length <= 120 &&
                        item.folderName.isNotBlank() &&
                        item.folderName.length <= 120 &&
                        item.folderId.isNotBlank() &&
                        item.folderId.length <= 128 &&
                        !VaultFolder.isReservedAllName(item.folderName)
                ) {
                    "Note record in backup has invalid field lengths or folder metadata."
                }
                require(item.checklistItems.size <= 1_000) {
                    "Note record in backup exceeds maximum checklist item count."
                }
            }
            is CredentialRecord -> {
                require(
                    item.serviceName.isNotBlank() &&
                        item.serviceName.length <= MAX_FIELD_CHARS &&
                        item.accountLabel.length <= 120 &&
                        item.username.length <= MAX_FIELD_CHARS &&
                        item.password.length <= MAX_FIELD_CHARS &&
                        item.websiteUrl.length <= MAX_FIELD_CHARS &&
                        item.notes.length <= MAX_FIELD_CHARS &&
                        item.category.length <= 120 &&
                        item.folderName.isNotBlank() &&
                        item.folderName.length <= 120 &&
                        item.folderId.isNotBlank() &&
                        item.folderId.length <= 128 &&
                        !VaultFolder.isReservedAllName(item.folderName)
                ) {
                    "Credential record in backup has invalid field lengths or folder metadata."
                }
                require(item.customFields.size <= 200) {
                    "Credential record in backup exceeds maximum custom field count."
                }
            }
            is VaultFolder -> {
                require(item.name.isNotBlank() && item.name.length <= 120) {
                    "Folder record in backup has an invalid name."
                }
                require(!VaultFolder.isReservedAllName(item.name)) {
                    "Folder record in backup uses reserved filter name 'All'."
                }
            }
            is MediaRecord -> {
                require(
                    item.title.isNotBlank() &&
                        item.title.length <= 255 &&
                        item.originalFileName.length <= 255 &&
                        item.mimeType.isNotBlank() &&
                        item.mimeType.length <= 120 &&
                        item.originalSizeBytes > 0L &&
                        item.encryptedSizeBytes > 0L &&
                        item.chunkCount > 0 &&
                        item.fileMediaKeyBase64.isNotBlank() &&
                        item.thumbnailKeyBase64.isNotBlank() &&
                        item.ciphertextSha256Hex.length == 64
                ) {
                    "Media record in backup has invalid metadata or key lengths."
                }
            }
        }
    }

    /**
     * Ensures no note or credential references a folder defined for the wrong scope (e.g., a Note
     * pointing to a CREDENTIALS folder ID).
     */
    private fun validateFolderReferences(items: List<VaultItem>) {
        val folders = items.filterIsInstance<VaultFolder>()
        val foldersById = folders.associateBy { it.id }

        items.forEach { item ->
            when (item) {
                is NoteRecord -> {
                    val referencedFolder = foldersById[item.folderId]
                    if (referencedFolder != null && referencedFolder.scope != FolderScope.NOTES) {
                        throw IllegalArgumentException(
                            "Malformed backup: note references a folder from the ${referencedFolder.scope} scope."
                        )
                    }
                    if (item.folderId == VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID) {
                        throw IllegalArgumentException(
                            "Malformed backup: note references the default credentials folder ID."
                        )
                    }
                }
                is CredentialRecord -> {
                    val referencedFolder = foldersById[item.folderId]
                    if (referencedFolder != null && referencedFolder.scope != FolderScope.CREDENTIALS) {
                        throw IllegalArgumentException(
                            "Malformed backup: credential references a folder from the ${referencedFolder.scope} scope."
                        )
                    }
                    if (item.folderId == VaultFolder.DEFAULT_NOTE_FOLDER_ID) {
                        throw IllegalArgumentException(
                            "Malformed backup: credential references the default notes folder ID."
                        )
                    }
                }
                else -> {}
            }
        }
    }

    /**
     * Computes a deterministic merge between existing active-vault records and imported backup records.
     * - Matching `id`: keeps the item with the newer `updatedAtEpochMs`.
     * - Folders with matching `(scope, normalized name)`: deduplicates and canonicalizes `folderId`
     *   across imported records so folder links stay consistent after merge (`R12`).
     */
    fun mergeItemsKeepNewest(
        existingItems: List<VaultItem>,
        importedItems: List<VaultItem>
    ): List<VaultItem> {
        val mergedById = LinkedHashMap<String, VaultItem>()
        existingItems.forEach { mergedById[it.id] = it }

        importedItems.forEach { imported ->
            val current = mergedById[imported.id]
            if (current == null || imported.updatedAtEpochMs >= current.updatedAtEpochMs) {
                mergedById[imported.id] = imported
            }
        }

        val canonicalFoldersByKey = LinkedHashMap<String, VaultFolder>()
        val folderIdRemap = HashMap<String, VaultFolder>()
        val nonFolderItems = mutableListOf<VaultItem>()

        mergedById.values.forEach { item ->
            if (item is VaultFolder) {
                val key = "${item.scope.name}:${item.name.trim().lowercase()}"
                val existingFolder = canonicalFoldersByKey[key]
                if (existingFolder == null) {
                    canonicalFoldersByKey[key] = item
                    folderIdRemap[item.id] = item
                } else {
                    val winner = if (item.updatedAtEpochMs > existingFolder.updatedAtEpochMs) {
                        existingFolder.copy(
                            name = item.name.trim(),
                            updatedAtEpochMs = item.updatedAtEpochMs
                        )
                    } else {
                        existingFolder
                    }
                    canonicalFoldersByKey[key] = winner
                    folderIdRemap[existingFolder.id] = winner
                    folderIdRemap[item.id] = winner
                }
            } else {
                nonFolderItems.add(item)
            }
        }

        val normalizedItems = nonFolderItems.map { item ->
            when (item) {
                is NoteRecord -> {
                    val mappedFolder = folderIdRemap[item.folderId]
                        ?: canonicalFoldersByKey["${FolderScope.NOTES.name}:${item.folderName.trim().lowercase()}"]
                    if (mappedFolder != null) {
                        item.copy(folderId = mappedFolder.id, folderName = mappedFolder.name)
                    } else if (VaultFolder.isDefaultGeneralName(item.folderName)) {
                        item.copy(
                            folderId = VaultFolder.DEFAULT_NOTE_FOLDER_ID,
                            folderName = VaultFolder.DEFAULT_FOLDER_NAME
                        )
                    } else {
                        item
                    }
                }
                is CredentialRecord -> {
                    val mappedFolder = folderIdRemap[item.folderId]
                        ?: canonicalFoldersByKey["${FolderScope.CREDENTIALS.name}:${item.folderName.trim().lowercase()}"]
                    if (mappedFolder != null) {
                        item.copy(folderId = mappedFolder.id, folderName = mappedFolder.name)
                    } else if (VaultFolder.isDefaultGeneralName(item.folderName)) {
                        item.copy(
                            folderId = VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID,
                            folderName = VaultFolder.DEFAULT_FOLDER_NAME
                        )
                    } else {
                        item
                    }
                }
                else -> item
            }
        }

        return canonicalFoldersByKey.values.toList() + normalizedItems
    }
}

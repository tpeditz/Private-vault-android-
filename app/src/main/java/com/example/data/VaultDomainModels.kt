package com.example.data

import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.util.UUID

/**
 * Decrypted domain models held only in volatile memory during an active, unlocked vault session.
 * All models serialize to a single versioned UTF-8 JSON envelope before AES-256-GCM encryption.
 */
sealed interface VaultItem {
    val id: String
    val createdAtEpochMs: Long
    val updatedAtEpochMs: Long
}

data class ChecklistEntry(
    val id: String = UUID.randomUUID().toString(),
    val text: String,
    val isChecked: Boolean = false
)

enum class NoteBodyFormat {
    PLAIN_TEXT,
    MARKDOWN,
    CHECKLIST
}

data class NoteRecord(
    override val id: String = UUID.randomUUID().toString(),
    val title: String,
    val body: String,
    val format: NoteBodyFormat = NoteBodyFormat.PLAIN_TEXT,
    val checklistItems: List<ChecklistEntry> = emptyList(),
    val category: String = "Personal",
    val folderName: String = VaultFolder.DEFAULT_FOLDER_NAME,
    val folderId: String = VaultFolder.DEFAULT_NOTE_FOLDER_ID,
    val tags: List<String> = emptyList(),
    val colorAccentIndex: Int = 0,
    val isPinned: Boolean = false,
    val isFavorite: Boolean = false,
    val isArchived: Boolean = false,
    val isTrashed: Boolean = false,
    override val createdAtEpochMs: Long = System.currentTimeMillis(),
    override val updatedAtEpochMs: Long = System.currentTimeMillis()
) : VaultItem

data class CustomCredentialField(
    val id: String = UUID.randomUUID().toString(),
    val label: String,
    val value: String,
    val isSecret: Boolean = true
)

data class CredentialRecord(
    override val id: String = UUID.randomUUID().toString(),
    val serviceName: String,
    val accountLabel: String = "",
    val username: String,
    val password: String,
    val websiteUrl: String = "",
    val notes: String = "",
    val category: String = "Logins",
    val folderName: String = VaultFolder.DEFAULT_FOLDER_NAME,
    val folderId: String = VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID,
    val tags: List<String> = emptyList(),
    val customFields: List<CustomCredentialField> = emptyList(),
    val isFavorite: Boolean = false,
    val isPinned: Boolean = false,
    val isArchived: Boolean = false,
    val isTrashed: Boolean = false,
    override val createdAtEpochMs: Long = System.currentTimeMillis(),
    override val updatedAtEpochMs: Long = System.currentTimeMillis()
) : VaultItem

enum class MediaKind {
    PHOTO,
    VIDEO
}

/**
 * Decrypted domain metadata for an encrypted Photo or Video item in the vault (Task 1).
 *
 * Security Design:
 * - Stored inside `encrypted_records` encrypted with AES-256-GCM under the active slot's DEK.
 * - Holds the unique per-file 256-bit `fileMediaKeyBase64` (used to encrypt/decrypt the streaming
 *   `PVM1` chunks in `<id>.pvmedia`) and `thumbnailKeyBase64` (used to encrypt/decrypt `<id>.pvthumb`).
 * - Permanently deleting this record from `encrypted_records` cryptographically destroys the per-file keys.
 */
data class MediaRecord(
    override val id: String = UUID.randomUUID().toString(),
    val title: String,
    val originalFileName: String,
    val mimeType: String,
    val mediaKind: MediaKind,
    val originalSizeBytes: Long,
    val encryptedSizeBytes: Long,
    val chunkCount: Int,
    val formatVersion: Int = 1,
    val widthPx: Int = 0,
    val heightPx: Int = 0,
    val durationMs: Long = 0L,
    val fileMediaKeyBase64: String,
    val thumbnailKeyBase64: String,
    val ciphertextSha256Hex: String,
    val tags: List<String> = emptyList(),
    val notes: String = "",
    val isFavorite: Boolean = false,
    val isTrashed: Boolean = false,
    override val createdAtEpochMs: Long = System.currentTimeMillis(),
    override val updatedAtEpochMs: Long = System.currentTimeMillis()
) : VaultItem

enum class FolderScope {
    NOTES,
    CREDENTIALS
}

data class VaultFolder(
    override val id: String = UUID.randomUUID().toString(),
    val name: String,
    val scope: FolderScope,
    override val createdAtEpochMs: Long = System.currentTimeMillis(),
    override val updatedAtEpochMs: Long = System.currentTimeMillis()
) : VaultItem {
    companion object {
        const val DEFAULT_FOLDER_NAME = "General"
        const val RESERVED_ALL_FILTER_NAME = "All"
        const val DEFAULT_NOTE_FOLDER_ID = "builtin-folder-notes-general"
        const val DEFAULT_CREDENTIAL_FOLDER_ID = "builtin-folder-credentials-general"

        fun isReservedAllName(candidate: String): Boolean {
            return candidate.trim().equals(RESERVED_ALL_FILTER_NAME, ignoreCase = true)
        }

        fun isDefaultGeneralName(candidate: String): Boolean {
            return candidate.trim().equals(DEFAULT_FOLDER_NAME, ignoreCase = true)
        }
    }
}

/**
 * Deterministic JSON serializer/deserializer for encrypted record payloads.
 */
object VaultRecordCodec {

    private const val TYPE_NOTE = "NOTE"
    private const val TYPE_CREDENTIAL = "CREDENTIAL"
    private const val TYPE_FOLDER = "FOLDER"
    private const val TYPE_MEDIA = "MEDIA"

    fun encode(item: VaultItem): ByteArray {
        val root = JSONObject()
        when (item) {
            is NoteRecord -> {
                root.put("recordType", TYPE_NOTE)
                root.put("id", item.id)
                root.put("title", item.title)
                root.put("body", item.body)
                root.put("format", item.format.name)
                root.put("category", item.category)
                root.put("folderName", item.folderName)
                root.put("folderId", item.folderId)
                root.put("colorAccentIndex", item.colorAccentIndex)
                root.put("isPinned", item.isPinned)
                root.put("isFavorite", item.isFavorite)
                root.put("isArchived", item.isArchived)
                root.put("isTrashed", item.isTrashed)
                root.put("createdAtEpochMs", item.createdAtEpochMs)
                root.put("updatedAtEpochMs", item.updatedAtEpochMs)

                val tagsArray = JSONArray()
                item.tags.forEach { tagsArray.put(it) }
                root.put("tags", tagsArray)

                val checklistArray = JSONArray()
                item.checklistItems.forEach { entry ->
                    val obj = JSONObject()
                    obj.put("id", entry.id)
                    obj.put("text", entry.text)
                    obj.put("isChecked", entry.isChecked)
                    checklistArray.put(obj)
                }
                root.put("checklistItems", checklistArray)
            }

            is CredentialRecord -> {
                root.put("recordType", TYPE_CREDENTIAL)
                root.put("id", item.id)
                root.put("serviceName", item.serviceName)
                root.put("accountLabel", item.accountLabel)
                root.put("username", item.username)
                root.put("password", item.password)
                root.put("websiteUrl", item.websiteUrl)
                root.put("notes", item.notes)
                root.put("category", item.category)
                root.put("folderName", item.folderName)
                root.put("folderId", item.folderId)
                root.put("isFavorite", item.isFavorite)
                root.put("isPinned", item.isPinned)
                root.put("isArchived", item.isArchived)
                root.put("isTrashed", item.isTrashed)
                root.put("createdAtEpochMs", item.createdAtEpochMs)
                root.put("updatedAtEpochMs", item.updatedAtEpochMs)

                val tagsArray = JSONArray()
                item.tags.forEach { tagsArray.put(it) }
                root.put("tags", tagsArray)

                val customArray = JSONArray()
                item.customFields.forEach { field ->
                    val obj = JSONObject()
                    obj.put("id", field.id)
                    obj.put("label", field.label)
                    obj.put("value", field.value)
                    obj.put("isSecret", field.isSecret)
                    customArray.put(obj)
                }
                root.put("customFields", customArray)
            }

            is VaultFolder -> {
                root.put("recordType", TYPE_FOLDER)
                root.put("id", item.id)
                root.put("name", item.name)
                root.put("scope", item.scope.name)
                root.put("createdAtEpochMs", item.createdAtEpochMs)
                root.put("updatedAtEpochMs", item.updatedAtEpochMs)
            }

            is MediaRecord -> {
                root.put("recordType", TYPE_MEDIA)
                root.put("id", item.id)
                root.put("title", item.title)
                root.put("originalFileName", item.originalFileName)
                root.put("mimeType", item.mimeType)
                root.put("mediaKind", item.mediaKind.name)
                root.put("originalSizeBytes", item.originalSizeBytes)
                root.put("encryptedSizeBytes", item.encryptedSizeBytes)
                root.put("chunkCount", item.chunkCount)
                root.put("formatVersion", item.formatVersion)
                root.put("widthPx", item.widthPx)
                root.put("heightPx", item.heightPx)
                root.put("durationMs", item.durationMs)
                root.put("fileMediaKeyBase64", item.fileMediaKeyBase64)
                root.put("thumbnailKeyBase64", item.thumbnailKeyBase64)
                root.put("ciphertextSha256Hex", item.ciphertextSha256Hex)
                root.put("notes", item.notes)
                root.put("isFavorite", item.isFavorite)
                root.put("isTrashed", item.isTrashed)
                root.put("createdAtEpochMs", item.createdAtEpochMs)
                root.put("updatedAtEpochMs", item.updatedAtEpochMs)

                val tagsArray = JSONArray()
                item.tags.forEach { tagsArray.put(it) }
                root.put("tags", tagsArray)
            }
        }
        return root.toString().toByteArray(StandardCharsets.UTF_8)
    }

    fun decode(bytes: ByteArray): VaultItem {
        val jsonString = String(bytes, StandardCharsets.UTF_8)
        val root = JSONObject(jsonString)
        return decodeFromJsonObject(root)
    }

    fun decodeFromJsonObject(root: JSONObject): VaultItem {
        return when (val type = root.optString("recordType")) {
            TYPE_NOTE -> {
                val tags = mutableListOf<String>()
                val tagsArray = root.optJSONArray("tags")
                if (tagsArray != null) {
                    for (i in 0 until tagsArray.length()) {
                        tags.add(tagsArray.optString(i))
                    }
                }

                val checklist = mutableListOf<ChecklistEntry>()
                val checklistArray = root.optJSONArray("checklistItems")
                if (checklistArray != null) {
                    for (i in 0 until checklistArray.length()) {
                        val obj = checklistArray.optJSONObject(i) ?: continue
                        checklist.add(
                            ChecklistEntry(
                                id = obj.optString("id", UUID.randomUUID().toString()),
                                text = obj.optString("text", ""),
                                isChecked = obj.optBoolean("isChecked", false)
                            )
                        )
                    }
                }

                val formatStr = root.optString("format", NoteBodyFormat.PLAIN_TEXT.name)
                val format = runCatching { NoteBodyFormat.valueOf(formatStr) }
                    .getOrDefault(NoteBodyFormat.PLAIN_TEXT)

                val rawFolderName = root.optString("folderName", VaultFolder.DEFAULT_FOLDER_NAME)
                    .ifBlank { VaultFolder.DEFAULT_FOLDER_NAME }
                val rawFolderId = root.optString("folderId", "").ifBlank {
                    if (VaultFolder.isDefaultGeneralName(rawFolderName)) {
                        VaultFolder.DEFAULT_NOTE_FOLDER_ID
                    } else {
                        ""
                    }
                }

                NoteRecord(
                    id = root.getString("id"),
                    title = root.optString("title", ""),
                    body = root.optString("body", ""),
                    format = format,
                    checklistItems = checklist,
                    category = root.optString("category", "Personal"),
                    folderName = rawFolderName,
                    folderId = rawFolderId,
                    tags = tags,
                    colorAccentIndex = root.optInt("colorAccentIndex", 0),
                    isPinned = root.optBoolean("isPinned", false),
                    isFavorite = root.optBoolean("isFavorite", false),
                    isArchived = root.optBoolean("isArchived", false),
                    isTrashed = root.optBoolean("isTrashed", false),
                    createdAtEpochMs = root.optLong("createdAtEpochMs", 0L),
                    updatedAtEpochMs = root.optLong("updatedAtEpochMs", 0L)
                )
            }

            TYPE_CREDENTIAL -> {
                val tags = mutableListOf<String>()
                val tagsArray = root.optJSONArray("tags")
                if (tagsArray != null) {
                    for (i in 0 until tagsArray.length()) {
                        tags.add(tagsArray.optString(i))
                    }
                }

                val customFields = mutableListOf<CustomCredentialField>()
                val customArray = root.optJSONArray("customFields")
                if (customArray != null) {
                    for (i in 0 until customArray.length()) {
                        val obj = customArray.optJSONObject(i) ?: continue
                        customFields.add(
                            CustomCredentialField(
                                id = obj.optString("id", UUID.randomUUID().toString()),
                                label = obj.optString("label", ""),
                                // N08 Fix: Preserve exact custom field value without trimming
                                value = obj.optString("value", ""),
                                isSecret = obj.optBoolean("isSecret", true)
                            )
                        )
                    }
                }

                val rawFolderName = root.optString("folderName", VaultFolder.DEFAULT_FOLDER_NAME)
                    .ifBlank { VaultFolder.DEFAULT_FOLDER_NAME }
                val rawFolderId = root.optString("folderId", "").ifBlank {
                    if (VaultFolder.isDefaultGeneralName(rawFolderName)) {
                        VaultFolder.DEFAULT_CREDENTIAL_FOLDER_ID
                    } else {
                        ""
                    }
                }

                CredentialRecord(
                    id = root.getString("id"),
                    serviceName = root.optString("serviceName", ""),
                    accountLabel = root.optString("accountLabel", ""),
                    username = root.optString("username", ""),
                    password = root.optString("password", ""),
                    websiteUrl = root.optString("websiteUrl", ""),
                    notes = root.optString("notes", ""),
                    category = root.optString("category", "Logins"),
                    folderName = rawFolderName,
                    folderId = rawFolderId,
                    tags = tags,
                    customFields = customFields,
                    isFavorite = root.optBoolean("isFavorite", false),
                    isPinned = root.optBoolean("isPinned", false),
                    isArchived = root.optBoolean("isArchived", false),
                    isTrashed = root.optBoolean("isTrashed", false),
                    createdAtEpochMs = root.optLong("createdAtEpochMs", 0L),
                    updatedAtEpochMs = root.optLong("updatedAtEpochMs", 0L)
                )
            }

            TYPE_FOLDER -> {
                val scopeStr = root.optString("scope", FolderScope.NOTES.name)
                val scope = runCatching { FolderScope.valueOf(scopeStr) }
                    .getOrDefault(FolderScope.NOTES)
                VaultFolder(
                    id = root.getString("id"),
                    name = root.optString("name", VaultFolder.DEFAULT_FOLDER_NAME),
                    scope = scope,
                    createdAtEpochMs = root.optLong("createdAtEpochMs", 0L),
                    updatedAtEpochMs = root.optLong("updatedAtEpochMs", 0L)
                )
            }

            TYPE_MEDIA -> {
                val tags = mutableListOf<String>()
                val tagsArray = root.optJSONArray("tags")
                if (tagsArray != null) {
                    for (i in 0 until tagsArray.length()) {
                        tags.add(tagsArray.optString(i))
                    }
                }
                val kindStr = root.optString("mediaKind", MediaKind.PHOTO.name)
                val kind = runCatching { MediaKind.valueOf(kindStr) }
                    .getOrDefault(MediaKind.PHOTO)

                val fileMediaKeyB64 = root.optString("fileMediaKeyBase64", "")
                val thumbKeyB64 = root.optString("thumbnailKeyBase64", "")
                val sha256Hex = root.optString("ciphertextSha256Hex", "")
                require(fileMediaKeyB64.isNotBlank() && thumbKeyB64.isNotBlank() && sha256Hex.length == 64) {
                    "Encrypted MediaRecord is missing required cryptographic key or SHA-256 metadata."
                }

                MediaRecord(
                    id = root.getString("id"),
                    title = root.optString("title", "Encrypted Media"),
                    originalFileName = root.optString("originalFileName", ""),
                    mimeType = root.optString("mimeType", "application/octet-stream"),
                    mediaKind = kind,
                    originalSizeBytes = root.optLong("originalSizeBytes", 0L),
                    encryptedSizeBytes = root.optLong("encryptedSizeBytes", 0L),
                    chunkCount = root.optInt("chunkCount", 1),
                    formatVersion = root.optInt("formatVersion", 1),
                    widthPx = root.optInt("widthPx", 0),
                    heightPx = root.optInt("heightPx", 0),
                    durationMs = root.optLong("durationMs", 0L),
                    fileMediaKeyBase64 = fileMediaKeyB64,
                    thumbnailKeyBase64 = thumbKeyB64,
                    ciphertextSha256Hex = sha256Hex,
                    tags = tags,
                    notes = root.optString("notes", ""),
                    isFavorite = root.optBoolean("isFavorite", false),
                    isTrashed = root.optBoolean("isTrashed", false),
                    createdAtEpochMs = root.optLong("createdAtEpochMs", 0L),
                    updatedAtEpochMs = root.optLong("updatedAtEpochMs", 0L)
                )
            }

            else -> throw IllegalArgumentException("Unsupported vault recordType: $type")
        }
    }
}

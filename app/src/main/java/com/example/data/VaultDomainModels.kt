package com.example.data

import org.json.JSONArray
import org.json.JSONObject

/**
 * Decrypted in-memory domain models for PRIVATE VAULT.
 *
 * Security Rules (Section 25):
 * - `toString()` is explicitly overridden on all secret-bearing models to redact note bodies,
 *   titles, usernames, and passwords so accidental logging or crash traces never dump secrets.
 * - Serialized to JSON ONLY immediately prior to AES-256-GCM encryption into `EncryptedRecordEntity`.
 */

enum class NoteFormatStyle(val label: String) {
    PARAGRAPH("Paragraph"),
    HEADING("Heading"),
    BULLET_LIST("Bullet List"),
    NUMBERED_LIST("Numbered List"),
    CHECKLIST("Checklist")
}

data class NoteChecklistItem(
    val id: String,
    val text: String,
    val isChecked: Boolean
) {
    override fun toString(): String = "NoteChecklistItem(id=$id, checked=$isChecked)"
}

data class CustomCredentialField(
    val id: String,
    val label: String,
    val value: String,
    val isSecret: Boolean = false
) {
    override fun toString(): String = "CustomCredentialField(id=$id)"
}

sealed interface VaultRecordPayload {
    val id: String
    val createdAtEpochMs: Long
    val updatedAtEpochMs: Long

    data class NoteRecord(
        override val id: String,
        val title: String,
        val body: String,
        val formatStyle: NoteFormatStyle = NoteFormatStyle.PARAGRAPH,
        val checklistItems: List<NoteChecklistItem> = emptyList(),
        val folderId: String? = null,
        val folderName: String = "General",
        val tags: List<String> = emptyList(),
        val isPinned: Boolean = false,
        val isFavorite: Boolean = false,
        val isArchived: Boolean = false,
        val isTrashed: Boolean = false,
        val trashedAtEpochMs: Long? = null,
        override val createdAtEpochMs: Long = System.currentTimeMillis(),
        override val updatedAtEpochMs: Long = System.currentTimeMillis()
    ) : VaultRecordPayload {
        override fun toString(): String = "NoteRecord(id=$id, redacted=true)"
    }

    data class CredentialRecord(
        override val id: String,
        val serviceName: String,
        val accountLabel: String = "Personal",
        val username: String = "",
        val email: String = "",
        val password: String,
        val websiteUrl: String = "",
        val folderId: String? = null,
        val folderName: String = "General",
        val tags: List<String> = emptyList(),
        val privateNotes: String = "",
        val customFields: List<CustomCredentialField> = emptyList(),
        val isFavorite: Boolean = false,
        val isPinned: Boolean = false,
        val isArchived: Boolean = false,
        val isTrashed: Boolean = false,
        val trashedAtEpochMs: Long? = null,
        override val createdAtEpochMs: Long = System.currentTimeMillis(),
        override val updatedAtEpochMs: Long = System.currentTimeMillis()
    ) : VaultRecordPayload {
        override fun toString(): String = "CredentialRecord(id=$id, redacted=true)"
    }

    data class FolderRecord(
        override val id: String,
        val name: String,
        val colorHex: String = "#10B981",
        override val createdAtEpochMs: Long = System.currentTimeMillis(),
        override val updatedAtEpochMs: Long = System.currentTimeMillis()
    ) : VaultRecordPayload {
        override fun toString(): String = "FolderRecord(id=$id, redacted=true)"
    }
}

object VaultPayloadSerializer {

    private const val TYPE_NOTE = "NOTE"
    private const val TYPE_CREDENTIAL = "CREDENTIAL"
    private const val TYPE_FOLDER = "FOLDER"

    fun serialize(payload: VaultRecordPayload): ByteArray {
        val root = JSONObject()
        root.put("id", payload.id)
        root.put("createdAtEpochMs", payload.createdAtEpochMs)
        root.put("updatedAtEpochMs", payload.updatedAtEpochMs)

        when (payload) {
            is VaultRecordPayload.NoteRecord -> {
                root.put("recordType", TYPE_NOTE)
                root.put("title", payload.title)
                root.put("body", payload.body)
                root.put("formatStyle", payload.formatStyle.name)
                root.put("folderId", payload.folderId ?: "")
                root.put("folderName", payload.folderName)
                root.put("isPinned", payload.isPinned)
                root.put("isFavorite", payload.isFavorite)
                root.put("isArchived", payload.isArchived)
                root.put("isTrashed", payload.isTrashed)
                if (payload.trashedAtEpochMs != null) {
                    root.put("trashedAtEpochMs", payload.trashedAtEpochMs)
                }
                val tagsArr = JSONArray()
                payload.tags.forEach { tagsArr.put(it) }
                root.put("tags", tagsArr)

                val checkArr = JSONArray()
                payload.checklistItems.forEach { item ->
                    val obj = JSONObject()
                    obj.put("id", item.id)
                    obj.put("text", item.text)
                    obj.put("isChecked", item.isChecked)
                    checkArr.put(obj)
                }
                root.put("checklistItems", checkArr)
            }

            is VaultRecordPayload.CredentialRecord -> {
                root.put("recordType", TYPE_CREDENTIAL)
                root.put("serviceName", payload.serviceName)
                root.put("accountLabel", payload.accountLabel)
                root.put("username", payload.username)
                root.put("email", payload.email)
                root.put("password", payload.password)
                root.put("websiteUrl", payload.websiteUrl)
                root.put("folderId", payload.folderId ?: "")
                root.put("folderName", payload.folderName)
                root.put("privateNotes", payload.privateNotes)
                root.put("isFavorite", payload.isFavorite)
                root.put("isPinned", payload.isPinned)
                root.put("isArchived", payload.isArchived)
                root.put("isTrashed", payload.isTrashed)
                if (payload.trashedAtEpochMs != null) {
                    root.put("trashedAtEpochMs", payload.trashedAtEpochMs)
                }
                val tagsArr = JSONArray()
                payload.tags.forEach { tagsArr.put(it) }
                root.put("tags", tagsArr)

                val customArr = JSONArray()
                payload.customFields.forEach { field ->
                    val obj = JSONObject()
                    obj.put("id", field.id)
                    obj.put("label", field.label)
                    obj.put("value", field.value)
                    obj.put("isSecret", field.isSecret)
                    customArr.put(obj)
                }
                root.put("customFields", customArr)
            }

            is VaultRecordPayload.FolderRecord -> {
                root.put("recordType", TYPE_FOLDER)
                root.put("name", payload.name)
                root.put("colorHex", payload.colorHex)
            }
        }

        return root.toString().toByteArray(Charsets.UTF_8)
    }

    fun deserialize(bytes: ByteArray): VaultRecordPayload {
        val jsonString = String(bytes, Charsets.UTF_8)
        val root = JSONObject(jsonString)
        val id = root.getString("id")
        val createdAt = root.optLong("createdAtEpochMs", System.currentTimeMillis())
        val updatedAt = root.optLong("updatedAtEpochMs", createdAt)

        return when (val type = root.getString("recordType")) {
            TYPE_NOTE -> {
                val tags = mutableListOf<String>()
                val tagsArr = root.optJSONArray("tags")
                if (tagsArr != null) {
                    for (i in 0 until tagsArr.length()) {
                        tags.add(tagsArr.getString(i))
                    }
                }
                val checklist = mutableListOf<NoteChecklistItem>()
                val checkArr = root.optJSONArray("checklistItems")
                if (checkArr != null) {
                    for (i in 0 until checkArr.length()) {
                        val obj = checkArr.getJSONObject(i)
                        checklist.add(
                            NoteChecklistItem(
                                id = obj.optString("id", "$i"),
                                text = obj.optString("text", ""),
                                isChecked = obj.optBoolean("isChecked", false)
                            )
                        )
                    }
                }
                val styleName = root.optString("formatStyle", NoteFormatStyle.PARAGRAPH.name)
                val style = try {
                    NoteFormatStyle.valueOf(styleName)
                } catch (_: Exception) {
                    NoteFormatStyle.PARAGRAPH
                }
                val folderIdRaw = root.optString("folderId", "")
                val trashedAt = if (root.has("trashedAtEpochMs")) root.optLong("trashedAtEpochMs") else null

                VaultRecordPayload.NoteRecord(
                    id = id,
                    title = root.optString("title", ""),
                    body = root.optString("body", ""),
                    formatStyle = style,
                    checklistItems = checklist,
                    folderId = folderIdRaw.ifBlank { null },
                    folderName = root.optString("folderName", "General"),
                    tags = tags,
                    isPinned = root.optBoolean("isPinned", false),
                    isFavorite = root.optBoolean("isFavorite", false),
                    isArchived = root.optBoolean("isArchived", false),
                    isTrashed = root.optBoolean("isTrashed", false),
                    trashedAtEpochMs = trashedAt,
                    createdAtEpochMs = createdAt,
                    updatedAtEpochMs = updatedAt
                )
            }

            TYPE_CREDENTIAL -> {
                val tags = mutableListOf<String>()
                val tagsArr = root.optJSONArray("tags")
                if (tagsArr != null) {
                    for (i in 0 until tagsArr.length()) {
                        tags.add(tagsArr.getString(i))
                    }
                }
                val customFields = mutableListOf<CustomCredentialField>()
                val customArr = root.optJSONArray("customFields")
                if (customArr != null) {
                    for (i in 0 until customArr.length()) {
                        val obj = customArr.getJSONObject(i)
                        customFields.add(
                            CustomCredentialField(
                                id = obj.optString("id", "$i"),
                                label = obj.optString("label", ""),
                                value = obj.optString("value", ""),
                                isSecret = obj.optBoolean("isSecret", false)
                            )
                        )
                    }
                }
                val folderIdRaw = root.optString("folderId", "")
                val trashedAt = if (root.has("trashedAtEpochMs")) root.optLong("trashedAtEpochMs") else null

                VaultRecordPayload.CredentialRecord(
                    id = id,
                    serviceName = root.optString("serviceName", ""),
                    accountLabel = root.optString("accountLabel", "Personal"),
                    username = root.optString("username", ""),
                    email = root.optString("email", ""),
                    password = root.optString("password", ""),
                    websiteUrl = root.optString("websiteUrl", ""),
                    folderId = folderIdRaw.ifBlank { null },
                    folderName = root.optString("folderName", "General"),
                    tags = tags,
                    privateNotes = root.optString("privateNotes", ""),
                    customFields = customFields,
                    isFavorite = root.optBoolean("isFavorite", false),
                    isPinned = root.optBoolean("isPinned", false),
                    isArchived = root.optBoolean("isArchived", false),
                    isTrashed = root.optBoolean("isTrashed", false),
                    trashedAtEpochMs = trashedAt,
                    createdAtEpochMs = createdAt,
                    updatedAtEpochMs = updatedAt
                )
            }

            TYPE_FOLDER -> {
                VaultRecordPayload.FolderRecord(
                    id = id,
                    name = root.optString("name", "General"),
                    colorHex = root.optString("colorHex", "#10B981"),
                    createdAtEpochMs = createdAt,
                    updatedAtEpochMs = updatedAt
                )
            }

            else -> throw IllegalArgumentException("Unsupported VaultRecordPayload type: $type")
        }
    }
}

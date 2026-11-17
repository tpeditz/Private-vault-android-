package com.example.data

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Unified versioned key envelope row stored in SQLite.
 *
 * Exactly two rows exist at all times after initial vault creation:
 * - `slotId = 0`: Primary (Real) Vault key envelope
 * - `slotId = 1`: Secondary (Decoy) Vault key envelope (contains a random unconfigured dummy DEK
 *   until the user configures a Decoy password, making both rows structurally identical on disk).
 */
@Entity(tableName = "vault_envelopes")
data class VaultEnvelopeEntity(
    @PrimaryKey
    @ColumnInfo(name = "slot_id")
    val slotId: Int,

    @ColumnInfo(name = "envelope_version")
    val envelopeVersion: Int,

    @ColumnInfo(name = "kdf_algorithm")
    val kdfAlgorithm: String,

    @ColumnInfo(name = "kdf_salt", typeAffinity = ColumnInfo.BLOB)
    val kdfSalt: ByteArray,

    @ColumnInfo(name = "kdf_memory_kb")
    val kdfMemoryKb: Int,

    @ColumnInfo(name = "kdf_iterations")
    val kdfIterations: Int,

    @ColumnInfo(name = "kdf_parallelism")
    val kdfParallelism: Int,

    @ColumnInfo(name = "envelope_nonce", typeAffinity = ColumnInfo.BLOB)
    val envelopeNonce: ByteArray,

    @ColumnInfo(name = "wrapped_payload_ciphertext", typeAffinity = ColumnInfo.BLOB)
    val wrappedPayloadCiphertext: ByteArray,

    @ColumnInfo(name = "biometric_nonce", typeAffinity = ColumnInfo.BLOB)
    val biometricNonce: ByteArray? = null,

    @ColumnInfo(name = "biometric_wrapped_dek", typeAffinity = ColumnInfo.BLOB)
    val biometricWrappedDek: ByteArray? = null
)

/**
 * Unified encrypted record row stored in SQLite (`encrypted_records`).
 *
 * Security & Metadata Minimization (B02 / N01):
 * - Composite primary key `(vault_slot, record_id)` guarantees that an identical `record_id`
 *   imported or created in Slot 0 and Slot 1 can NEVER collide or overwrite the other slot's record (`N01`).
 * - Notes, Credentials, Vault Folders, and MediaRecords are stored in this single table.
 * - No plaintext titles, usernames, URLs, filenames, MIME types, categories, record types, or
 *   per-file media keys exist in SQLite columns.
 * - Every record's entire metadata and payload is serialized and encrypted inside `ciphertext`
 *   with AES-256-GCM bound to `AAD = "PV1-REC|slot=$vaultSlot|id=$recordId|ver=$schemaVersion"`.
 */
@Entity(
    tableName = "encrypted_records",
    primaryKeys = ["vault_slot", "record_id"],
    indices = [Index(value = ["vault_slot"])]
)
data class EncryptedRecordEntity(
    @ColumnInfo(name = "record_id")
    val recordId: String,

    @ColumnInfo(name = "vault_slot")
    val vaultSlot: Int,

    @ColumnInfo(name = "schema_version")
    val schemaVersion: Int,

    @ColumnInfo(name = "nonce", typeAffinity = ColumnInfo.BLOB)
    val nonce: ByteArray,

    @ColumnInfo(name = "ciphertext", typeAffinity = ColumnInfo.BLOB)
    val ciphertext: ByteArray
)

/**
 * Encrypted media file lifecycle and integrity tracking row (`encrypted_media_files`, added in Room v4).
 *
 * Purpose:
 * - Tracks app-private encrypted media files (`.pvmedia`) and encrypted thumbnails (`.pvthumb`)
 *   without storing any sensitive filenames, MIME types, or keys in plaintext columns.
 * - `importStatus`: `0` (`IMPORT_STATUS_STAGING`) while streaming encryption & every-chunk verification
 *   are in flight; `1` (`IMPORT_STATUS_COMMITTED`) only after all chunks pass AEAD verification and
 *   the corresponding encrypted `MediaRecord` is committed in `encrypted_records`.
 * - Enables deterministic cleanup of interrupted imports and orphan files across app restarts.
 */
@Entity(
    tableName = "encrypted_media_files",
    primaryKeys = ["vault_slot", "media_id"],
    indices = [Index(value = ["vault_slot"])]
)
data class EncryptedMediaFileEntity(
    @ColumnInfo(name = "vault_slot")
    val vaultSlot: Int,

    @ColumnInfo(name = "media_id")
    val mediaId: String,

    @ColumnInfo(name = "format_version")
    val formatVersion: Int,

    @ColumnInfo(name = "relative_media_path")
    val relativeMediaPath: String,

    @ColumnInfo(name = "relative_thumb_path")
    val relativeThumbPath: String,

    @ColumnInfo(name = "encrypted_size_bytes")
    val encryptedSizeBytes: Long,

    @ColumnInfo(name = "chunk_count")
    val chunkCount: Int,

    @ColumnInfo(name = "ciphertext_sha256")
    val ciphertextSha256: String,

    @ColumnInfo(name = "import_status")
    val importStatus: Int,

    @ColumnInfo(name = "created_at_epoch_ms")
    val createdAtEpochMs: Long
) {
    companion object {
        const val IMPORT_STATUS_STAGING: Int = 0
        const val IMPORT_STATUS_COMMITTED: Int = 1
    }
}

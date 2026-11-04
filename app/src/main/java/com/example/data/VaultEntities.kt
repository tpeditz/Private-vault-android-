package com.example.data

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Unified versioned key-envelope table (`vault_envelopes`).
 *
 * Security Invariants (Confirmed Decision 3):
 * - Both `slotId = 0` (Real Vault) and `slotId = 1` (Decoy Vault) rows ALWAYS exist after setup.
 * - There is NO plaintext `isConfigured` column in SQLite.
 * - `wrappedPayloadCiphertext` is always exactly 72 bytes (56-byte inner struct + 16-byte GCM tag)
 *   containing `magic ("PVE1")`, `slotRoleFlag (0x01 active / 0x00 dummy)`, `reservedFlags`,
 *   `createdAtEpochMs`, `rotatedAtEpochMs`, and the 32-byte `dekBytes`.
 * - `biometricNonce` and `biometricWrappedDek` are null whenever Decoy Mode is enabled or
 *   Biometrics are disabled.
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

    @ColumnInfo(name = "kdf_memory_kb")
    val kdfMemoryKb: Int,

    @ColumnInfo(name = "kdf_iterations")
    val kdfIterations: Int,

    @ColumnInfo(name = "kdf_parallelism")
    val kdfParallelism: Int,

    @ColumnInfo(name = "kdf_salt", typeAffinity = ColumnInfo.BLOB)
    val kdfSalt: ByteArray,

    @ColumnInfo(name = "wrap_nonce", typeAffinity = ColumnInfo.BLOB)
    val wrapNonce: ByteArray,

    @ColumnInfo(name = "wrapped_payload_ciphertext", typeAffinity = ColumnInfo.BLOB)
    val wrappedPayloadCiphertext: ByteArray,

    @ColumnInfo(name = "biometric_nonce", typeAffinity = ColumnInfo.BLOB)
    val biometricNonce: ByteArray? = null,

    @ColumnInfo(name = "biometric_wrapped_dek", typeAffinity = ColumnInfo.BLOB)
    val biometricWrappedDek: ByteArray? = null
) {
    override fun toString(): String {
        return "VaultEnvelopeEntity(slotId=$slotId, version=$envelopeVersion, kdf=$kdfAlgorithm)"
    }
}

/**
 * Encrypted vault records table (`encrypted_records`).
 *
 * Security Invariants:
 * - Exposes ZERO plaintext titles, bodies, service names, usernames, URLs, folders, tags,
 *   timestamps, or boolean flags (`isPinned`, `isFavorite`, `isArchived`, `isTrashed`).
 * - All record content and metadata live inside `ciphertext` (AES-256-GCM authenticated with AAD
 *   binding `vaultSlot`, `recordId`, and `schemaVersion`).
 * - Added `migrationTag` nullable column in Schema v2 to test and prove non-destructive explicit
 *   Room migrations (`MIGRATION_1_2`) across app updates while preserving both Real and Decoy slots.
 */
@Entity(
    tableName = "encrypted_records",
    indices = [Index(value = ["vault_slot"])]
)
data class EncryptedRecordEntity(
    @PrimaryKey
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
) {
    override fun toString(): String {
        return "EncryptedRecordEntity(id=$recordId, slot=$vaultSlot, bytes=${ciphertext.size})"
    }
}

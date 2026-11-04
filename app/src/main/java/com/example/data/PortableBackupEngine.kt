package com.example.data

import com.example.security.CryptoEngine
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.util.Arrays
import javax.crypto.AEADBadTagException

/**
 * Portable Encrypted Backup & Restore Engine (Section 17).
 *
 * Binary `.pvault` Format v1:
 * - [0..3]    4B Magic: `"PVBK"`
 * - [4..7]    4B Schema Version: `1` (Big-Endian Int)
 * - [8..11]   4B Argon2id Memory KB: e.g. `32768` (bounded `[4096..131072]` before allocation)
 * - [12..15]  4B Argon2id Iterations: e.g. `3` (bounded `[1..12]`)
 * - [16..19]  4B Argon2id Parallelism: e.g. `2` (bounded `[1..4]`)
 * - [20..35]  16B Argon2id Salt
 * - [36..47]  12B AES-256-GCM Nonce
 * - [48..N]   AES-256-GCM Ciphertext + 16B Auth Tag (bound with AAD `"PV1-BACKUP|ver=1|..."`)
 *
 * Security Rules:
 * - Header contains ONLY minimal non-secret framing; all record counts, timestamps, notes,
 *   credentials, and folders live inside the authenticated encrypted payload.
 * - Never embeds the backup password, raw master password, or live vault DEK.
 * - Exports ONLY the currently authenticated vault slot (`Real` OR `Decoy`), never both.
 */
object PortableBackupEngine {

    private val MAGIC_BYTES = byteArrayOf('P'.code.toByte(), 'V'.code.toByte(), 'B'.code.toByte(), 'K'.code.toByte())
    const val HEADER_BYTES = 48
    const val MAX_BACKUP_FILE_BYTES = 50 * 1024 * 1024 // 50 MiB upper bound (B03)

    enum class ExportScope(val label: String) {
        ALL("All Active Vault Data (Notes, Passwords & Folders)"),
        NOTES_ONLY("Private Notes & Folders Only"),
        PASSWORDS_ONLY("Saved Passwords & Folders Only")
    }

    enum class RestoreMode(val label: String, val description: String) {
        MERGE_KEEP_NEWEST(
            "Merge with Current Vault",
            "Keeps existing records and imports new or newer records from the backup."
        ),
        REPLACE_ACTIVE_VAULT(
            "Replace Active Vault Only",
            "Replaces all records in the currently unlocked vault with the backup contents. Never touches the other vault."
        )
    }

    data class VerifiedBackupPreview(
        val schemaVersion: Int,
        val exportedAtEpochMs: Long,
        val exportScope: ExportScope,
        val notesCount: Int,
        val credentialsCount: Int,
        val foldersCount: Int,
        val records: List<VaultRecordPayload>
    )

    /**
     * Builds and encrypts a portable `.pvault` byte array in memory from the active vault's records.
     */
    fun createEncryptedBackupBytes(
        backupPasswordChars: CharArray,
        records: List<VaultRecordPayload>,
        scope: ExportScope = ExportScope.ALL,
        kdfParams: CryptoEngine.KdfParams = CryptoEngine.KdfParams(),
        exportedAtEpochMs: Long = System.currentTimeMillis()
    ): ByteArray {
        require(backupPasswordChars.size >= 8) {
            "Backup password must be at least 8 characters."
        }
        kdfParams.validateBounds()

        val filteredRecords = records.filter { record ->
            when (scope) {
                ExportScope.ALL -> true
                ExportScope.NOTES_ONLY -> record is VaultRecordPayload.NoteRecord || record is VaultRecordPayload.FolderRecord
                ExportScope.PASSWORDS_ONLY -> record is VaultRecordPayload.CredentialRecord || record is VaultRecordPayload.FolderRecord
            }
        }

        val rootJson = JSONObject()
        rootJson.put("schemaVersion", CryptoEngine.BACKUP_SCHEMA_VERSION)
        rootJson.put("exportedAtEpochMs", exportedAtEpochMs)
        rootJson.put("exportScope", scope.name)

        val recordsJsonArray = JSONArray()
        for (record in filteredRecords) {
            val serializedRecordJson = String(VaultPayloadSerializer.serialize(record), Charsets.UTF_8)
            recordsJsonArray.put(JSONObject(serializedRecordJson))
        }
        rootJson.put("records", recordsJsonArray)

        val plaintextBytes = rootJson.toString().toByteArray(Charsets.UTF_8)
        val salt = CryptoEngine.generateSalt()
        val nonce = CryptoEngine.generateNonce()
        val backupKey = CryptoEngine.deriveKeyArgon2id(backupPasswordChars, salt, kdfParams)

        try {
            val aad = CryptoEngine.buildBackupAad(CryptoEngine.BACKUP_SCHEMA_VERSION, kdfParams)
            val ciphertext = CryptoEngine.encryptAesGcm(
                keyBytes = backupKey,
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
            Arrays.fill(backupKey, 0.toByte())
            Arrays.fill(plaintextBytes, 0.toByte())
        }
    }

    /**
     * Reads, validates bounds, authenticates, and decrypts a `.pvault` stream for restore preview.
     * Rejects oversized files, malformed headers, out-of-bounds KDF parameters, wrong passwords,
     * and tampered ciphertexts before touching any database state.
     */
    @Throws(IllegalArgumentException::class, SecurityException::class)
    fun verifyAndDecryptBackup(
        inputStream: InputStream,
        backupPasswordChars: CharArray
    ): VerifiedBackupPreview {
        val rawBytes = readBoundedBytes(inputStream, MAX_BACKUP_FILE_BYTES)
        return verifyAndDecryptBackupBytes(rawBytes, backupPasswordChars)
    }

    @Throws(IllegalArgumentException::class, SecurityException::class)
    fun verifyAndDecryptBackupBytes(
        rawBytes: ByteArray,
        backupPasswordChars: CharArray
    ): VerifiedBackupPreview {
        if (rawBytes.size < HEADER_BYTES + CryptoEngine.GCM_TAG_BYTES) {
            throw IllegalArgumentException("Backup file is truncated or too small to be a valid .pvault archive.")
        }
        if (rawBytes.size > MAX_BACKUP_FILE_BYTES) {
            throw IllegalArgumentException("Backup file exceeds the 50 MiB safety limit.")
        }

        val buffer = ByteBuffer.wrap(rawBytes)
        val magic = ByteArray(4)
        buffer.get(magic)
        if (!magic.contentEquals(MAGIC_BYTES)) {
            throw IllegalArgumentException("Unrecognized file format (missing PVBK header).")
        }

        val schemaVersion = buffer.int
        if (schemaVersion != CryptoEngine.BACKUP_SCHEMA_VERSION) {
            throw IllegalArgumentException("Unsupported backup format version: $schemaVersion.")
        }

        val memoryKb = buffer.int
        val iterations = buffer.int
        val parallelism = buffer.int

        // Validate KDF bounds BEFORE allocating Argon2 memory (B03)
        val kdfParams = CryptoEngine.KdfParams(
            algorithm = CryptoEngine.KDF_ALGORITHM_ARGON2ID,
            memoryKb = memoryKb,
            iterations = iterations,
            parallelism = parallelism
        )
        kdfParams.validateBounds()

        val salt = ByteArray(CryptoEngine.SALT_BYTES)
        buffer.get(salt)
        val nonce = ByteArray(CryptoEngine.NONCE_BYTES)
        buffer.get(nonce)

        val ciphertextLength = rawBytes.size - HEADER_BYTES
        val ciphertext = ByteArray(ciphertextLength)
        buffer.get(ciphertext)

        val backupKey = CryptoEngine.deriveKeyArgon2id(backupPasswordChars, salt, kdfParams)
        val decryptedBytes = try {
            val aad = CryptoEngine.buildBackupAad(schemaVersion, kdfParams)
            CryptoEngine.decryptAesGcm(
                keyBytes = backupKey,
                nonce = nonce,
                ciphertext = ciphertext,
                aad = aad
            )
        } catch (e: AEADBadTagException) {
            throw SecurityException("Incorrect backup password or tampered backup archive.", e)
        } catch (e: Exception) {
            throw SecurityException("Failed to authenticate backup archive: ${e.message}", e)
        } finally {
            Arrays.fill(backupKey, 0.toByte())
        }

        try {
            val rootJson = JSONObject(String(decryptedBytes, Charsets.UTF_8))
            val innerVersion = rootJson.optInt("schemaVersion", -1)
            if (innerVersion != schemaVersion) {
                throw SecurityException("Backup inner version mismatch.")
            }
            val exportedAt = rootJson.optLong("exportedAtEpochMs", 0L)
            val scopeStr = rootJson.optString("exportScope", ExportScope.ALL.name)
            val scope = try {
                ExportScope.valueOf(scopeStr)
            } catch (_: Exception) {
                ExportScope.ALL
            }

            val recordsArray = rootJson.getJSONArray("records")
            val parsedRecords = mutableListOf<VaultRecordPayload>()
            for (i in 0 until recordsArray.length()) {
                val itemObj = recordsArray.getJSONObject(i)
                val record = VaultPayloadSerializer.deserialize(itemObj.toString().toByteArray(Charsets.UTF_8))
                parsedRecords.add(record)
            }

            val notesCount = parsedRecords.count { it is VaultRecordPayload.NoteRecord }
            val credentialsCount = parsedRecords.count { it is VaultRecordPayload.CredentialRecord }
            val foldersCount = parsedRecords.count { it is VaultRecordPayload.FolderRecord }

            return VerifiedBackupPreview(
                schemaVersion = schemaVersion,
                exportedAtEpochMs = exportedAt,
                exportScope = scope,
                notesCount = notesCount,
                credentialsCount = credentialsCount,
                foldersCount = foldersCount,
                records = parsedRecords
            )
        } finally {
            Arrays.fill(decryptedBytes, 0.toByte())
        }
    }

    private fun readBoundedBytes(inputStream: InputStream, maxBytes: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var total = 0
        while (true) {
            val read = inputStream.read(buf)
            if (read == -1) break
            total += read
            if (total > maxBytes) {
                throw IllegalArgumentException("Input stream exceeds maximum allowed backup size ($maxBytes bytes).")
            }
            out.write(buf, 0, read)
        }
        return out.toByteArray()
    }
}

package com.example.data

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Transaction
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Dao
interface VaultDao {

    @Query("SELECT * FROM vault_envelopes ORDER BY slot_id ASC")
    suspend fun getAllEnvelopes(): List<VaultEnvelopeEntity>

    @Query("SELECT * FROM vault_envelopes WHERE slot_id = :slotId LIMIT 1")
    suspend fun getEnvelopeForSlot(slotId: Int): VaultEnvelopeEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertEnvelope(envelope: VaultEnvelopeEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertEnvelopes(envelopes: List<VaultEnvelopeEntity>)

    @Query("SELECT * FROM encrypted_records WHERE vault_slot = :vaultSlot")
    suspend fun getRecordsForSlot(vaultSlot: Int): List<EncryptedRecordEntity>

    @Query("SELECT * FROM encrypted_records WHERE vault_slot = :vaultSlot AND record_id = :recordId LIMIT 1")
    suspend fun getRecordById(vaultSlot: Int, recordId: String): EncryptedRecordEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertRecord(record: EncryptedRecordEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertRecords(records: List<EncryptedRecordEntity>)

    @Query("DELETE FROM encrypted_records WHERE vault_slot = :vaultSlot AND record_id = :recordId")
    suspend fun deleteRecord(vaultSlot: Int, recordId: String)

    @Query("DELETE FROM encrypted_records WHERE vault_slot = :vaultSlot")
    suspend fun deleteAllRecordsForSlot(vaultSlot: Int)

    @Query("DELETE FROM encrypted_records")
    suspend fun deleteAllRecords()

    @Query("SELECT COUNT(*) FROM encrypted_records WHERE vault_slot = :vaultSlot")
    suspend fun countRecordsForSlot(vaultSlot: Int): Int

    // ============================================================================================
    // Encrypted Media Files (`encrypted_media_files` — Room Schema v4)
    // ============================================================================================

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertMediaFileEntity(entity: EncryptedMediaFileEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertMediaFileEntities(entities: List<EncryptedMediaFileEntity>)

    @Query("SELECT * FROM encrypted_media_files WHERE vault_slot = :vaultSlot AND media_id = :mediaId LIMIT 1")
    suspend fun getMediaFileEntity(vaultSlot: Int, mediaId: String): EncryptedMediaFileEntity?

    @Query("SELECT * FROM encrypted_media_files WHERE vault_slot = :vaultSlot")
    suspend fun getAllMediaFileEntitiesForSlot(vaultSlot: Int): List<EncryptedMediaFileEntity>

    @Query("SELECT * FROM encrypted_media_files")
    suspend fun getAllMediaFileEntities(): List<EncryptedMediaFileEntity>

    @Query("DELETE FROM encrypted_media_files WHERE vault_slot = :vaultSlot AND media_id = :mediaId")
    suspend fun deleteMediaFileEntity(vaultSlot: Int, mediaId: String)

    @Query("DELETE FROM encrypted_media_files WHERE vault_slot = :vaultSlot")
    suspend fun deleteAllMediaFilesForSlot(vaultSlot: Int)

    @Query("DELETE FROM encrypted_media_files")
    suspend fun deleteAllMediaFiles()

    /**
     * Atomically commits a verified media item into both `encrypted_records` (which holds the
     * per-file 256-bit keys and metadata encrypted under the slot DEK) and `encrypted_media_files`
     * (`import_status = COMMITTED`).
     */
    @Transaction
    suspend fun commitVerifiedMediaAtomically(
        encryptedRecord: EncryptedRecordEntity,
        committedMediaEntity: EncryptedMediaFileEntity
    ) {
        upsertRecord(encryptedRecord)
        upsertMediaFileEntity(committedMediaEntity)
    }

    /**
     * Atomically deletes both the encrypted `MediaRecord` (destroying its wrapped per-file keys)
     * and the `EncryptedMediaFileEntity` tracking row.
     */
    @Transaction
    suspend fun deleteMediaRecordAndEntityAtomically(vaultSlot: Int, mediaId: String) {
        deleteRecord(vaultSlot, mediaId)
        deleteMediaFileEntity(vaultSlot, mediaId)
    }

    @Transaction
    suspend fun replaceAllRecordsForSlot(vaultSlot: Int, newRecords: List<EncryptedRecordEntity>) {
        deleteAllRecordsForSlot(vaultSlot)
        if (newRecords.isNotEmpty()) {
            upsertRecords(newRecords)
        }
    }

    @Transaction
    suspend fun replaceAllRecordsAndMediaForSlot(
        vaultSlot: Int,
        newRecords: List<EncryptedRecordEntity>,
        newMediaEntities: List<EncryptedMediaFileEntity>
    ) {
        deleteAllRecordsForSlot(vaultSlot)
        deleteAllMediaFilesForSlot(vaultSlot)
        if (newRecords.isNotEmpty()) {
            upsertRecords(newRecords)
        }
        if (newMediaEntities.isNotEmpty()) {
            upsertMediaFileEntities(newMediaEntities)
        }
    }

    /**
     * N06 Fix: Atomic initial vault provisioning transaction.
     * Clears any stale records and writes both Slot 0 and Slot 1 envelopes + optional seed records
     * inside a single SQLite transaction so a crash can never leave a half-initialized database.
     */
    @Transaction
    suspend fun initializeVaultAtomically(
        envelopes: List<VaultEnvelopeEntity>,
        initialRecords: List<EncryptedRecordEntity>
    ) {
        deleteAllRecords()
        deleteAllMediaFiles()
        upsertEnvelopes(envelopes)
        if (initialRecords.isNotEmpty()) {
            upsertRecords(initialRecords)
        }
    }

    /**
     * N06 Fix: Atomic decoy provisioning / destructive reset transaction.
     * Updates both Slot 0 (biometric wrapper cleared + decoyPolicyFlag = 1) and Slot 1 envelopes
     * and replaces Slot 1 records in a single SQLite transaction.
     */
    @Transaction
    suspend fun provisionOrResetDecoyAtomically(
        updatedRealEnvelope: VaultEnvelopeEntity,
        updatedDecoyEnvelope: VaultEnvelopeEntity,
        decoySlotId: Int,
        seedRecords: List<EncryptedRecordEntity>
    ) {
        upsertEnvelopes(listOf(updatedRealEnvelope, updatedDecoyEnvelope))
        deleteAllRecordsForSlot(decoySlotId)
        deleteAllMediaFilesForSlot(decoySlotId)
        if (seedRecords.isNotEmpty()) {
            upsertRecords(seedRecords)
        }
    }

    /**
     * N06 Fix: Atomic decoy disable transaction.
     * Updates Slot 0 (decoyPolicyFlag = 0) and Slot 1 (dummy envelope) and wipes Slot 1 records
     * atomically.
     */
    @Transaction
    suspend fun disableDecoyAtomically(
        updatedRealEnvelope: VaultEnvelopeEntity,
        dummyDecoyEnvelope: VaultEnvelopeEntity,
        decoySlotId: Int
    ) {
        upsertEnvelopes(listOf(updatedRealEnvelope, dummyDecoyEnvelope))
        deleteAllRecordsForSlot(decoySlotId)
        deleteAllMediaFilesForSlot(decoySlotId)
    }

    /**
     * PV-SEC-010 Fix: Atomic full-DEK rotation transaction for an active vault slot.
     * Replaces the slot's key envelope and all re-encrypted records inside a single SQLite transaction.
     */
    @Transaction
    suspend fun rekeySlotAtomically(
        slotId: Int,
        updatedEnvelope: VaultEnvelopeEntity,
        reEncryptedRecords: List<EncryptedRecordEntity>
    ) {
        upsertEnvelope(updatedEnvelope)
        replaceAllRecordsForSlot(slotId, reEncryptedRecords)
    }
}

@Database(
    entities = [
        VaultEnvelopeEntity::class,
        EncryptedRecordEntity::class,
        EncryptedMediaFileEntity::class
    ],
    version = 4,
    exportSchema = false
)
abstract class PrivateVaultDatabase : RoomDatabase() {

    abstract fun vaultDao(): VaultDao

    companion object {
        private const val DATABASE_NAME = "private_vault_encrypted.db"

        /**
         * Explicit forward migration v1 -> v2 preserving both Slot 0 (Real) and Slot 1 (Decoy)
         * key envelopes and all encrypted record rows across APK updates.
         */
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_encrypted_records_vault_slot` ON `encrypted_records` (`vault_slot`)"
                )
            }
        }

        /**
         * N01 Fix: Explicit non-destructive migration v2 -> v3 converting `encrypted_records`
         * from single-column PRIMARY KEY(`record_id`) to composite PRIMARY KEY(`vault_slot`, `record_id`)
         * while preserving every existing row in both Slot 0 (Real) and Slot 1 (Decoy).
         */
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `encrypted_records_new` (
                        `record_id` TEXT NOT NULL,
                        `vault_slot` INTEGER NOT NULL,
                        `schema_version` INTEGER NOT NULL,
                        `nonce` BLOB NOT NULL,
                        `ciphertext` BLOB NOT NULL,
                        PRIMARY KEY(`vault_slot`, `record_id`)
                    )
                    """.trimIndent()
                )
                db.execSQL(
                    """
                    INSERT OR REPLACE INTO `encrypted_records_new` (`record_id`, `vault_slot`, `schema_version`, `nonce`, `ciphertext`)
                    SELECT `record_id`, `vault_slot`, `schema_version`, `nonce`, `ciphertext` FROM `encrypted_records`
                    """.trimIndent()
                )
                db.execSQL("DROP TABLE `encrypted_records`")
                db.execSQL("ALTER TABLE `encrypted_records_new` RENAME TO `encrypted_records`")
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_encrypted_records_vault_slot` ON `encrypted_records` (`vault_slot`)"
                )
            }
        }

        /**
         * Task 1.F: Explicit non-destructive migration v3 -> v4 adding `encrypted_media_files`
         * while preserving all existing `vault_envelopes` and `encrypted_records` rows intact.
         */
        val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    """
                    CREATE TABLE IF NOT EXISTS `encrypted_media_files` (
                        `vault_slot` INTEGER NOT NULL,
                        `media_id` TEXT NOT NULL,
                        `format_version` INTEGER NOT NULL,
                        `relative_media_path` TEXT NOT NULL,
                        `relative_thumb_path` TEXT NOT NULL,
                        `encrypted_size_bytes` INTEGER NOT NULL,
                        `chunk_count` INTEGER NOT NULL,
                        `ciphertext_sha256` TEXT NOT NULL,
                        `import_status` INTEGER NOT NULL,
                        `created_at_epoch_ms` INTEGER NOT NULL,
                        PRIMARY KEY(`vault_slot`, `media_id`)
                    )
                    """.trimIndent()
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_encrypted_media_files_vault_slot` ON `encrypted_media_files` (`vault_slot`)"
                )
            }
        }

        @Volatile
        private var INSTANCE: PrivateVaultDatabase? = null

        fun getInstance(context: Context): PrivateVaultDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    PrivateVaultDatabase::class.java,
                    DATABASE_NAME
                )
                    .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4)
                    // Never enable fallbackToDestructiveMigration() so an update can never wipe vaults
                    .build()
                INSTANCE = instance
                instance
            }
        }

        fun createInMemoryForTest(context: Context): PrivateVaultDatabase {
            return Room.inMemoryDatabaseBuilder(
                context.applicationContext,
                PrivateVaultDatabase::class.java
            )
                .allowMainThreadQueries()
                .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4)
                .build()
        }
    }
}

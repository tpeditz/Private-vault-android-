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

    @Transaction
    suspend fun replaceAllRecordsForSlot(vaultSlot: Int, newRecords: List<EncryptedRecordEntity>) {
        deleteAllRecordsForSlot(vaultSlot)
        if (newRecords.isNotEmpty()) {
            upsertRecords(newRecords)
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
    }
}

@Database(
    entities = [VaultEnvelopeEntity::class, EncryptedRecordEntity::class],
    version = 3,
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

        @Volatile
        private var INSTANCE: PrivateVaultDatabase? = null

        fun getInstance(context: Context): PrivateVaultDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    PrivateVaultDatabase::class.java,
                    DATABASE_NAME
                )
                    .addMigrations(MIGRATION_1_2, MIGRATION_2_3)
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
                .addMigrations(MIGRATION_1_2, MIGRATION_2_3)
                .build()
        }
    }
}

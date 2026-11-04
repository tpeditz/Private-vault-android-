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
import kotlinx.coroutines.flow.Flow

@Dao
interface VaultDao {

    @Query("SELECT * FROM vault_envelopes ORDER BY slot_id ASC")
    suspend fun getAllEnvelopes(): List<VaultEnvelopeEntity>

    @Query("SELECT * FROM vault_envelopes WHERE slot_id = :slotId LIMIT 1")
    suspend fun getEnvelopeBySlot(slotId: Int): VaultEnvelopeEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertEnvelope(envelope: VaultEnvelopeEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertEnvelopes(envelopes: List<VaultEnvelopeEntity>)

    @Query("SELECT * FROM encrypted_records WHERE vault_slot = :vaultSlot")
    fun observeEncryptedRecordsForSlot(vaultSlot: Int): Flow<List<EncryptedRecordEntity>>

    @Query("SELECT * FROM encrypted_records WHERE vault_slot = :vaultSlot")
    suspend fun getEncryptedRecordsForSlot(vaultSlot: Int): List<EncryptedRecordEntity>

    @Query("SELECT * FROM encrypted_records WHERE record_id = :recordId AND vault_slot = :vaultSlot LIMIT 1")
    suspend fun getEncryptedRecordById(recordId: String, vaultSlot: Int): EncryptedRecordEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertEncryptedRecord(record: EncryptedRecordEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertEncryptedRecords(records: List<EncryptedRecordEntity>)

    @Query("DELETE FROM encrypted_records WHERE record_id = :recordId AND vault_slot = :vaultSlot")
    suspend fun deleteEncryptedRecordById(recordId: String, vaultSlot: Int)

    @Query("DELETE FROM encrypted_records WHERE vault_slot = :vaultSlot")
    suspend fun deleteAllRecordsForSlot(vaultSlot: Int)

    @Transaction
    suspend fun replaceAllRecordsForSlot(vaultSlot: Int, newRecords: List<EncryptedRecordEntity>) {
        deleteAllRecordsForSlot(vaultSlot)
        if (newRecords.isNotEmpty()) {
            upsertEncryptedRecords(newRecords)
        }
    }
}

@Database(
    entities = [
        VaultEnvelopeEntity::class,
        EncryptedRecordEntity::class
    ],
    version = 2,
    exportSchema = false
)
abstract class PrivateVaultDatabase : RoomDatabase() {

    abstract fun vaultDao(): VaultDao

    companion object {
        const val DATABASE_NAME = "private_vault_encrypted.db"

        /**
         * Explicit non-destructive migration from version 1 to version 2 (Section 18, U11).
         * Preserves all `vault_envelopes` and `encrypted_records` across both Real and Decoy vaults
         * and ensures the `vault_slot` index exists.
         *
         * NOTE: `fallbackToDestructiveMigration()` is strictly prohibited and never called.
         */
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
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
                    .addMigrations(MIGRATION_1_2)
                    // Never enable fallbackToDestructiveMigration()
                    .build()
                INSTANCE = instance
                instance
            }
        }
    }
}

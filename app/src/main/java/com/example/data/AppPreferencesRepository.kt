package com.example.data

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.example.security.CryptoEngine
import com.example.ui.theme.AppThemeMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

private val Context.vaultPrefsDataStore by preferencesDataStore(name = "private_vault_nonsecret_settings")

/**
 * Stores strictly non-sensitive app preferences and OTA reminder deferral state.
 *
 * Security Invariants (Section 13 & 14):
 * - NEVER stores an `isUnlocked` flag, master password, backup password, or decoy status flag.
 * - Stores theme preference, auto-lock timeout, clipboard TTL, screenshot protection toggle,
 *   OTA auto-check setting, OTA 3-option reminder deferral state, and latest measured KDF benchmark.
 */
class AppPreferencesRepository(private val context: Context) {

    enum class OtaReminderType {
        NONE,
        NEXT_LAUNCH,
        TIMESTAMP
    }

    data class OtaReminderState(
        val deferredVersionCode: Int = 0,
        val reminderType: OtaReminderType = OtaReminderType.NONE,
        val remindAfterEpochMs: Long = 0L,
        val launchNumberAtDeferral: Long = 0L
    )

    data class AppSettingsState(
        val themeMode: AppThemeMode = AppThemeMode.DARK,
        val autoLockTimeoutMs: Long = 60_000L, // Default 1 minute
        val clipboardClearSeconds: Int = 30,   // Default 30 seconds
        val blockScreenshots: Boolean = true,  // Default enabled (FLAG_SECURE)
        val autoCheckUpdatesOnLaunch: Boolean = true,
        val customOtaManifestUrl: String = "https://raw.githubusercontent.com/tpeditz/Private-vault-updates/main/update.json",
        val appLaunchCounter: Long = 0L,
        val lastOtaAutoCheckEpochMs: Long = 0L,
        val otaReminderState: OtaReminderState = OtaReminderState(),
        val lastKdfBenchmark: CryptoEngine.KdfBenchmarkResult? = null
    )

    private object Keys {
        val THEME_MODE = stringPreferencesKey("theme_mode")
        val AUTO_LOCK_MS = longPreferencesKey("auto_lock_ms")
        val CLIPBOARD_TTL_SEC = intPreferencesKey("clipboard_ttl_sec")
        val BLOCK_SCREENSHOTS = booleanPreferencesKey("block_screenshots")
        val AUTO_CHECK_OTA = booleanPreferencesKey("auto_check_ota")
        val CUSTOM_OTA_URL = stringPreferencesKey("custom_ota_url")
        val APP_LAUNCH_COUNTER = longPreferencesKey("app_launch_counter")
        val LAST_OTA_CHECK_MS = longPreferencesKey("last_ota_check_ms")

        // OTA 3-option Reminder Me Later state
        val OTA_DEFERRED_VERSION = intPreferencesKey("ota_deferred_version")
        val OTA_REMINDER_TYPE = stringPreferencesKey("ota_reminder_type")
        val OTA_REMIND_AFTER_MS = longPreferencesKey("ota_remind_after_ms")
        val OTA_LAUNCH_AT_DEFERRAL = longPreferencesKey("ota_launch_at_deferral")

        // KDF Benchmark Telemetry
        val KDF_BENCH_DEVICE = stringPreferencesKey("kdf_bench_device")
        val KDF_BENCH_SDK = intPreferencesKey("kdf_bench_sdk")
        val KDF_BENCH_MEM_KB = intPreferencesKey("kdf_bench_mem_kb")
        val KDF_BENCH_ITER = intPreferencesKey("kdf_bench_iter")
        val KDF_BENCH_PAR = intPreferencesKey("kdf_bench_par")
        val KDF_BENCH_SINGLE_MS = longPreferencesKey("kdf_bench_single_ms")
        val KDF_BENCH_TWO_SLOT_MS = longPreferencesKey("kdf_bench_two_slot_ms")
        val KDF_BENCH_MAX_HEAP_MB = longPreferencesKey("kdf_bench_max_heap_mb")
        val KDF_BENCH_USED_HEAP_MB = longPreferencesKey("kdf_bench_used_heap_mb")
        val KDF_BENCH_MEASURED_AT = longPreferencesKey("kdf_bench_measured_at")
    }

    val settingsFlow: Flow<AppSettingsState> = context.vaultPrefsDataStore.data.map { prefs ->
        val themeStr = prefs[Keys.THEME_MODE] ?: AppThemeMode.DARK.name
        val theme = try {
            AppThemeMode.valueOf(themeStr)
        } catch (_: Exception) {
            AppThemeMode.DARK
        }

        val remTypeStr = prefs[Keys.OTA_REMINDER_TYPE] ?: OtaReminderType.NONE.name
        val remType = try {
            OtaReminderType.valueOf(remTypeStr)
        } catch (_: Exception) {
            OtaReminderType.NONE
        }

        val benchSingleMs = prefs[Keys.KDF_BENCH_SINGLE_MS]
        val benchmark = if (benchSingleMs != null) {
            CryptoEngine.KdfBenchmarkResult(
                deviceModel = prefs[Keys.KDF_BENCH_DEVICE] ?: "Android Device",
                androidSdkInt = prefs[Keys.KDF_BENCH_SDK] ?: 0,
                memoryKbPerSlot = prefs[Keys.KDF_BENCH_MEM_KB] ?: CryptoEngine.PROPOSED_STANDARD_MEMORY_KB,
                iterations = prefs[Keys.KDF_BENCH_ITER] ?: CryptoEngine.PROPOSED_STANDARD_ITERATIONS,
                parallelism = prefs[Keys.KDF_BENCH_PAR] ?: CryptoEngine.PROPOSED_STANDARD_PARALLELISM,
                singleSlotDurationMs = benchSingleMs,
                twoSlotUnlockDurationMs = prefs[Keys.KDF_BENCH_TWO_SLOT_MS] ?: (benchSingleMs * 2),
                maxHeapMb = prefs[Keys.KDF_BENCH_MAX_HEAP_MB] ?: 0L,
                usedHeapMbAfterRun = prefs[Keys.KDF_BENCH_USED_HEAP_MB] ?: 0L,
                measuredAtEpochMs = prefs[Keys.KDF_BENCH_MEASURED_AT] ?: 0L
            )
        } else {
            null
        }

        AppSettingsState(
            themeMode = theme,
            autoLockTimeoutMs = prefs[Keys.AUTO_LOCK_MS] ?: 60_000L,
            clipboardClearSeconds = prefs[Keys.CLIPBOARD_TTL_SEC] ?: 30,
            blockScreenshots = prefs[Keys.BLOCK_SCREENSHOTS] ?: true,
            autoCheckUpdatesOnLaunch = prefs[Keys.AUTO_CHECK_OTA] ?: true,
            customOtaManifestUrl = prefs[Keys.CUSTOM_OTA_URL]
                ?: "https://raw.githubusercontent.com/tpeditz/Private-vault-updates/main/update.json",
            appLaunchCounter = prefs[Keys.APP_LAUNCH_COUNTER] ?: 0L,
            lastOtaAutoCheckEpochMs = prefs[Keys.LAST_OTA_CHECK_MS] ?: 0L,
            otaReminderState = OtaReminderState(
                deferredVersionCode = prefs[Keys.OTA_DEFERRED_VERSION] ?: 0,
                reminderType = remType,
                remindAfterEpochMs = prefs[Keys.OTA_REMIND_AFTER_MS] ?: 0L,
                launchNumberAtDeferral = prefs[Keys.OTA_LAUNCH_AT_DEFERRAL] ?: 0L
            ),
            lastKdfBenchmark = benchmark
        )
    }

    suspend fun getSnapshot(): AppSettingsState = settingsFlow.first()

    suspend fun incrementAppLaunchCounter(): Long {
        var updated = 0L
        context.vaultPrefsDataStore.edit { prefs ->
            updated = (prefs[Keys.APP_LAUNCH_COUNTER] ?: 0L) + 1L
            prefs[Keys.APP_LAUNCH_COUNTER] = updated
        }
        return updated
    }

    suspend fun setThemeMode(mode: AppThemeMode) {
        context.vaultPrefsDataStore.edit { it[Keys.THEME_MODE] = mode.name }
    }

    suspend fun setAutoLockTimeoutMs(timeoutMs: Long) {
        context.vaultPrefsDataStore.edit { it[Keys.AUTO_LOCK_MS] = timeoutMs }
    }

    suspend fun setClipboardClearSeconds(seconds: Int) {
        context.vaultPrefsDataStore.edit { it[Keys.CLIPBOARD_TTL_SEC] = seconds.coerceIn(10, 300) }
    }

    suspend fun setBlockScreenshots(enabled: Boolean) {
        context.vaultPrefsDataStore.edit { it[Keys.BLOCK_SCREENSHOTS] = enabled }
    }

    suspend fun setAutoCheckUpdatesOnLaunch(enabled: Boolean) {
        context.vaultPrefsDataStore.edit { it[Keys.AUTO_CHECK_OTA] = enabled }
    }

    suspend fun setCustomOtaManifestUrl(url: String) {
        context.vaultPrefsDataStore.edit { it[Keys.CUSTOM_OTA_URL] = url.trim() }
    }

    suspend fun recordOtaAutoCheckTimestamp(nowEpochMs: Long = System.currentTimeMillis()) {
        context.vaultPrefsDataStore.edit { it[Keys.LAST_OTA_CHECK_MS] = nowEpochMs }
    }

    /**
     * Persists the user's "Remind Me Later" choice (Next Launch, Tomorrow +24h, or In 3 Days +72h).
     */
    suspend fun saveOtaReminderChoice(
        versionCode: Int,
        reminderType: OtaReminderType,
        remindAfterEpochMs: Long,
        currentLaunchCount: Long
    ) {
        context.vaultPrefsDataStore.edit { prefs ->
            prefs[Keys.OTA_DEFERRED_VERSION] = versionCode
            prefs[Keys.OTA_REMINDER_TYPE] = reminderType.name
            prefs[Keys.OTA_REMIND_AFTER_MS] = remindAfterEpochMs
            prefs[Keys.OTA_LAUNCH_AT_DEFERRAL] = currentLaunchCount
        }
    }

    suspend fun clearOtaReminder() {
        context.vaultPrefsDataStore.edit { prefs ->
            prefs[Keys.OTA_DEFERRED_VERSION] = 0
            prefs[Keys.OTA_REMINDER_TYPE] = OtaReminderType.NONE.name
            prefs[Keys.OTA_REMIND_AFTER_MS] = 0L
        }
    }

    suspend fun saveKdfBenchmarkResult(result: CryptoEngine.KdfBenchmarkResult) {
        context.vaultPrefsDataStore.edit { prefs ->
            prefs[Keys.KDF_BENCH_DEVICE] = result.deviceModel
            prefs[Keys.KDF_BENCH_SDK] = result.androidSdkInt
            prefs[Keys.KDF_BENCH_MEM_KB] = result.memoryKbPerSlot
            prefs[Keys.KDF_BENCH_ITER] = result.iterations
            prefs[Keys.KDF_BENCH_PAR] = result.parallelism
            prefs[Keys.KDF_BENCH_SINGLE_MS] = result.singleSlotDurationMs
            prefs[Keys.KDF_BENCH_TWO_SLOT_MS] = result.twoSlotUnlockDurationMs
            prefs[Keys.KDF_BENCH_MAX_HEAP_MB] = result.maxHeapMb
            prefs[Keys.KDF_BENCH_USED_HEAP_MB] = result.usedHeapMbAfterRun
            prefs[Keys.KDF_BENCH_MEASURED_AT] = result.measuredAtEpochMs
        }
    }

    companion object {
        /**
         * Pure function to evaluate whether an automatic update prompt should be shown for
         * a candidate `versionCode` given the saved `OtaReminderState`.
         *
         * Manual "Check for Updates" in Settings -> Updates always bypasses deferral.
         */
        fun shouldShowAutomaticUpdatePrompt(
            candidateVersionCode: Int,
            reminderState: OtaReminderState,
            currentLaunchNumber: Long,
            nowEpochMs: Long = System.currentTimeMillis()
        ): Boolean {
            if (candidateVersionCode <= 0) return false
            // If a newer version than the deferred one was published, show prompt
            if (reminderState.deferredVersionCode != candidateVersionCode) return true

            return when (reminderState.reminderType) {
                OtaReminderType.NONE -> true
                OtaReminderType.NEXT_LAUNCH -> currentLaunchNumber > reminderState.launchNumberAtDeferral
                OtaReminderType.TIMESTAMP -> nowEpochMs >= reminderState.remindAfterEpochMs
            }
        }
    }
}

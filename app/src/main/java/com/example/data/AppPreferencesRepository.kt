package com.example.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.example.security.CryptoEngine
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.vaultDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "private_vault_preferences"
)

enum class ThemePreference {
    DARK_OBSIDIAN,
    LIGHT_CLEAN,
    SYSTEM
}

enum class OtaReminderPolicy {
    NONE,
    NEXT_APP_LAUNCH,
    TOMORROW,
    IN_THREE_DAYS
}

data class VaultAppPreferences(
    val themePreference: ThemePreference = ThemePreference.DARK_OBSIDIAN,
    val autoLockTimeoutMs: Long = 60_000L, // Default: 1 minute
    val lockOnScreenOff: Boolean = true,
    val blockScreenshots: Boolean = true,
    val clipboardClearTtlSeconds: Int = 30,
    val otaManifestUrl: String = AppPreferencesRepository.DEFAULT_OTA_MANIFEST_URL,
    val otaReminderPolicy: OtaReminderPolicy = OtaReminderPolicy.NONE,
    val otaSnoozedUntilEpochMs: Long = 0L,
    val otaSnoozedVersionCode: Int = 0,
    // R03: Coarse unlock cooldown state persisted across process restarts (without revealing decoy/real state)
    val consecutiveFailedUnlocks: Int = 0,
    val unlockCooldownUntilEpochMs: Long = 0L,
    // R07: Only manual benchmark runs are persisted, without exact unlock timestamps
    val lastBenchmarkDevice: String = "",
    val lastBenchmarkSingleSlotMs: Long = 0L,
    val lastBenchmarkTwoSlotMs: Long = 0L,
    val lastBenchmarkMemoryKb: Int = 0,
    val lastBenchmarkIterations: Int = 0,
    val lastBenchmarkParallelism: Int = 0,
    val lastBenchmarkMaxHeapMb: Long = 0L,
    val lastBenchmarkUsedHeapMb: Long = 0L
)

class AppPreferencesRepository(private val context: Context) {

    companion object {
        const val DEFAULT_OTA_MANIFEST_URL =
            "https://raw.githubusercontent.com/tpeditz/Private-vault-updates/main/update.json"
        const val PUBLIC_OTA_REPO_URL =
            "https://github.com/tpeditz/Private-vault-updates"
        const val MAX_COOLDOWN_MS = 30_000L

        private val KEY_THEME = stringPreferencesKey("theme_preference")
        private val KEY_AUTO_LOCK_MS = longPreferencesKey("auto_lock_timeout_ms")
        private val KEY_LOCK_SCREEN_OFF = booleanPreferencesKey("lock_on_screen_off")
        private val KEY_BLOCK_SCREENSHOTS = booleanPreferencesKey("block_screenshots")
        private val KEY_CLIPBOARD_TTL_SEC = intPreferencesKey("clipboard_clear_ttl_sec")

        private val KEY_OTA_MANIFEST_URL = stringPreferencesKey("ota_manifest_url")
        private val KEY_OTA_REMINDER_POLICY = stringPreferencesKey("ota_reminder_policy")
        private val KEY_OTA_SNOOZE_UNTIL_MS = longPreferencesKey("ota_snooze_until_ms")
        private val KEY_OTA_SNOOZED_VERSION = intPreferencesKey("ota_snoozed_version")

        private val KEY_FAILED_UNLOCK_COUNT = intPreferencesKey("failed_unlock_count")
        private val KEY_UNLOCK_COOLDOWN_UNTIL_MS = longPreferencesKey("unlock_cooldown_until_ms")

        private val KEY_KDF_BENCH_DEVICE = stringPreferencesKey("kdf_bench_device")
        private val KEY_KDF_BENCH_SINGLE_MS = longPreferencesKey("kdf_bench_single_ms")
        private val KEY_KDF_BENCH_TWO_SLOT_MS = longPreferencesKey("kdf_bench_two_slot_ms")
        private val KEY_KDF_BENCH_MEM_KB = intPreferencesKey("kdf_bench_mem_kb")
        private val KEY_KDF_BENCH_ITER = intPreferencesKey("kdf_bench_iter")
        private val KEY_KDF_BENCH_PAR = intPreferencesKey("kdf_bench_par")
        private val KEY_KDF_BENCH_MAX_HEAP_MB = longPreferencesKey("kdf_bench_max_heap_mb")
        private val KEY_KDF_BENCH_USED_HEAP_MB = longPreferencesKey("kdf_bench_used_heap_mb")
        // Legacy key to clean up if present (R07)
        private val KEY_LEGACY_KDF_BENCH_MEASURED_AT = longPreferencesKey("kdf_bench_measured_at")
    }

    val preferencesFlow: Flow<VaultAppPreferences> = context.vaultDataStore.data.map { prefs ->
        val themeStr = prefs[KEY_THEME] ?: ThemePreference.DARK_OBSIDIAN.name
        val theme = runCatching { ThemePreference.valueOf(themeStr) }
            .getOrDefault(ThemePreference.DARK_OBSIDIAN)

        val reminderStr = prefs[KEY_OTA_REMINDER_POLICY] ?: OtaReminderPolicy.NONE.name
        val reminder = runCatching { OtaReminderPolicy.valueOf(reminderStr) }
            .getOrDefault(OtaReminderPolicy.NONE)

        VaultAppPreferences(
            themePreference = theme,
            autoLockTimeoutMs = prefs[KEY_AUTO_LOCK_MS] ?: 60_000L,
            lockOnScreenOff = prefs[KEY_LOCK_SCREEN_OFF] ?: true,
            blockScreenshots = prefs[KEY_BLOCK_SCREENSHOTS] ?: true,
            clipboardClearTtlSeconds = (prefs[KEY_CLIPBOARD_TTL_SEC] ?: 30).coerceIn(10, 300),
            otaManifestUrl = prefs[KEY_OTA_MANIFEST_URL] ?: DEFAULT_OTA_MANIFEST_URL,
            otaReminderPolicy = reminder,
            otaSnoozedUntilEpochMs = prefs[KEY_OTA_SNOOZE_UNTIL_MS] ?: 0L,
            otaSnoozedVersionCode = prefs[KEY_OTA_SNOOZED_VERSION] ?: 0,
            consecutiveFailedUnlocks = (prefs[KEY_FAILED_UNLOCK_COUNT] ?: 0).coerceAtLeast(0),
            unlockCooldownUntilEpochMs = prefs[KEY_UNLOCK_COOLDOWN_UNTIL_MS] ?: 0L,
            lastBenchmarkDevice = prefs[KEY_KDF_BENCH_DEVICE] ?: "",
            lastBenchmarkSingleSlotMs = prefs[KEY_KDF_BENCH_SINGLE_MS] ?: 0L,
            lastBenchmarkTwoSlotMs = prefs[KEY_KDF_BENCH_TWO_SLOT_MS] ?: 0L,
            lastBenchmarkMemoryKb = prefs[KEY_KDF_BENCH_MEM_KB] ?: 0,
            lastBenchmarkIterations = prefs[KEY_KDF_BENCH_ITER] ?: 0,
            lastBenchmarkParallelism = prefs[KEY_KDF_BENCH_PAR] ?: 0,
            lastBenchmarkMaxHeapMb = prefs[KEY_KDF_BENCH_MAX_HEAP_MB] ?: 0L,
            lastBenchmarkUsedHeapMb = prefs[KEY_KDF_BENCH_USED_HEAP_MB] ?: 0L
        )
    }

    suspend fun setThemePreference(theme: ThemePreference) {
        context.vaultDataStore.edit { it[KEY_THEME] = theme.name }
    }

    suspend fun setAutoLockTimeoutMs(timeoutMs: Long) {
        context.vaultDataStore.edit { it[KEY_AUTO_LOCK_MS] = timeoutMs.coerceAtLeast(0L) }
    }

    suspend fun setLockOnScreenOff(enabled: Boolean) {
        context.vaultDataStore.edit { it[KEY_LOCK_SCREEN_OFF] = enabled }
    }

    suspend fun setBlockScreenshots(enabled: Boolean) {
        context.vaultDataStore.edit { it[KEY_BLOCK_SCREENSHOTS] = enabled }
    }

    suspend fun setClipboardClearTtlSeconds(seconds: Int) {
        context.vaultDataStore.edit { it[KEY_CLIPBOARD_TTL_SEC] = seconds.coerceIn(10, 300) }
    }

    suspend fun setOtaManifestUrl(url: String) {
        val cleaned = url.trim().ifBlank { DEFAULT_OTA_MANIFEST_URL }
        context.vaultDataStore.edit { it[KEY_OTA_MANIFEST_URL] = cleaned }
    }

    /**
     * Persists the user's "Remind Me Later" choice (`NEXT_APP_LAUNCH`, `TOMORROW`, `IN_THREE_DAYS`)
     * so PRIVATE VAULT never nags repeatedly before the chosen window expires.
     */
    suspend fun saveOtaReminderChoice(
        policy: OtaReminderPolicy,
        versionCode: Int,
        nowEpochMs: Long = System.currentTimeMillis()
    ) {
        val snoozeUntil = when (policy) {
            OtaReminderPolicy.NONE -> 0L
            OtaReminderPolicy.NEXT_APP_LAUNCH -> 0L
            OtaReminderPolicy.TOMORROW -> nowEpochMs + 24L * 60L * 60L * 1000L
            OtaReminderPolicy.IN_THREE_DAYS -> nowEpochMs + 3L * 24L * 60L * 60L * 1000L
        }
        context.vaultDataStore.edit { prefs ->
            prefs[KEY_OTA_REMINDER_POLICY] = policy.name
            prefs[KEY_OTA_SNOOZE_UNTIL_MS] = snoozeUntil
            prefs[KEY_OTA_SNOOZED_VERSION] = versionCode
        }
    }

    suspend fun clearOtaReminder() {
        context.vaultDataStore.edit { prefs ->
            prefs[KEY_OTA_REMINDER_POLICY] = OtaReminderPolicy.NONE.name
            prefs[KEY_OTA_SNOOZE_UNTIL_MS] = 0L
            prefs[KEY_OTA_SNOOZED_VERSION] = 0
        }
    }

    /**
     * R03 Fix: Persists coarse unlock failure backoff across process death with clock-skew clamping
     * so killing and restarting the app cannot bypass rate limiting and wall-clock changes cannot
     * permanently lock the user out beyond MAX_COOLDOWN_MS (30s).
     */
    suspend fun recordUnlockFailure(nowEpochMs: Long = System.currentTimeMillis()): Pair<Int, Long> {
        var newFailures = 1
        var cooldownMs = 0L
        context.vaultDataStore.edit { prefs ->
            val current = (prefs[KEY_FAILED_UNLOCK_COUNT] ?: 0).coerceAtLeast(0)
            newFailures = current + 1
            cooldownMs = when {
                newFailures < 3 -> 0L
                newFailures == 3 -> 2_000L
                newFailures == 4 -> 5_000L
                newFailures == 5 -> 10_000L
                newFailures == 6 -> 20_000L
                else -> MAX_COOLDOWN_MS
            }
            prefs[KEY_FAILED_UNLOCK_COUNT] = newFailures
            prefs[KEY_UNLOCK_COOLDOWN_UNTIL_MS] = if (cooldownMs > 0L) nowEpochMs + cooldownMs else 0L
        }
        return newFailures to cooldownMs
    }

    suspend fun clearUnlockFailures() {
        context.vaultDataStore.edit { prefs ->
            prefs[KEY_FAILED_UNLOCK_COUNT] = 0
            prefs[KEY_UNLOCK_COOLDOWN_UNTIL_MS] = 0L
        }
    }

    /**
     * R07 Fix: Saves manual KDF benchmark results without storing exact timestamps or running on
     * routine unlocks.
     */
    suspend fun saveManualKdfBenchmark(result: CryptoEngine.KdfBenchmarkResult) {
        context.vaultDataStore.edit { prefs ->
            prefs[KEY_KDF_BENCH_DEVICE] = result.deviceModel
            prefs[KEY_KDF_BENCH_SINGLE_MS] = result.singleSlotDurationMs
            prefs[KEY_KDF_BENCH_TWO_SLOT_MS] = result.twoSlotUnlockDurationMs
            prefs[KEY_KDF_BENCH_MEM_KB] = result.memoryKbPerSlot
            prefs[KEY_KDF_BENCH_ITER] = result.iterations
            prefs[KEY_KDF_BENCH_PAR] = result.parallelism
            prefs[KEY_KDF_BENCH_MAX_HEAP_MB] = result.maxHeapMb
            prefs[KEY_KDF_BENCH_USED_HEAP_MB] = result.usedHeapMbAfterRun
            prefs.remove(KEY_LEGACY_KDF_BENCH_MEASURED_AT)
        }
    }

    /**
     * Evaluates whether an automatic startup update prompt should be displayed for `remoteVersionCode`.
     */
    fun shouldShowAutomaticUpdatePrompt(
        prefs: VaultAppPreferences,
        remoteVersionCode: Int,
        nowEpochMs: Long = System.currentTimeMillis()
    ): Boolean {
        if (prefs.otaSnoozedVersionCode != remoteVersionCode) {
            return true
        }
        return when (prefs.otaReminderPolicy) {
            OtaReminderPolicy.NONE -> true
            OtaReminderPolicy.NEXT_APP_LAUNCH -> true
            OtaReminderPolicy.TOMORROW,
            OtaReminderPolicy.IN_THREE_DAYS -> nowEpochMs >= prefs.otaSnoozedUntilEpochMs
        }
    }
}

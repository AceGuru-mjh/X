package com.unknown.security.core.persistence

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.unknown.security.core.model.EnginePolicy
import com.unknown.security.core.model.GuardTier
import com.unknown.security.core.model.ThemeMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.json.Json

private val Context.unknownDataStore: DataStore<Preferences> by preferencesDataStore(name = "unknown_settings")

/**
 * persisted settings:
 * - selected guard tier
 * - guard on/off
 * - engine policy (serialized JSON)
 * - onboarding completion flag
 * - appearance (theme mode)
 */
class SettingsStore(
    private val context: Context,
) {
    private object Keys {
        val TIER = stringPreferencesKey("guard_tier")
        val GUARD_ENABLED = booleanPreferencesKey("guard_enabled")
        val ONBOARDING_COMPLETED = booleanPreferencesKey("onboarding_completed")
        val THEME_MODE = stringPreferencesKey("theme_mode")
        val POLICY_JSON = stringPreferencesKey("engine_policy_json")
    }

    private val json =
        Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

    val tierFlow: Flow<GuardTier> =
        context.unknownDataStore.data.map { prefs ->
            val key = prefs[Keys.TIER] ?: GuardTier.STANDARD.key
            GuardTier.fromKey(key) ?: GuardTier.STANDARD
        }

    val guardEnabledFlow: Flow<Boolean> =
        context.unknownDataStore.data.map { prefs ->
            prefs[Keys.GUARD_ENABLED] ?: true
        }

    val onboardingCompletedFlow: Flow<Boolean> =
        context.unknownDataStore.data.map { prefs ->
            prefs[Keys.ONBOARDING_COMPLETED] ?: false
        }

    val themeModeFlow: Flow<ThemeMode> =
        context.unknownDataStore.data.map { prefs ->
            ThemeMode.fromKey(prefs[Keys.THEME_MODE])
        }

    val policyFlow: Flow<EnginePolicy> =
        context.unknownDataStore.data.map { prefs ->
            val raw = prefs[Keys.POLICY_JSON]
            if (raw.isNullOrBlank()) {
                EnginePolicy()
            } else {
                runCatching { json.decodeFromString(EnginePolicy.serializer(), raw) }
                    .getOrDefault(EnginePolicy())
            }
        }

    suspend fun setTier(tier: GuardTier) {
        context.unknownDataStore.edit { it[Keys.TIER] = tier.key }
    }

    suspend fun setGuardEnabled(enabled: Boolean) {
        context.unknownDataStore.edit { it[Keys.GUARD_ENABLED] = enabled }
    }

    suspend fun setOnboardingCompleted(completed: Boolean) {
        context.unknownDataStore.edit { it[Keys.ONBOARDING_COMPLETED] = completed }
    }

    suspend fun setThemeMode(mode: ThemeMode) {
        context.unknownDataStore.edit { it[Keys.THEME_MODE] = mode.key }
    }

    suspend fun setPolicy(policy: EnginePolicy) {
        context.unknownDataStore.edit { it[Keys.POLICY_JSON] = json.encodeToString(EnginePolicy.serializer(), policy) }
    }

    suspend fun currentTier(): GuardTier = tierFlow.first()

    suspend fun currentPolicy(): EnginePolicy = policyFlow.first()
}

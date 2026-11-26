package com.nava.app.reminders

import com.nava.app.di.PreferencesStorageGateway
import com.nava.domain.automation.MorningBriefingConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Persists non-sensitive Morning Briefing schedule preferences in `MODE_PRIVATE` SharedPreferences.
 *
 * Security invariant: Stores ONLY boolean toggles and HH:MM schedule numbers; zero user notes,
 * utterances, or notification contents are ever written here.
 */
class MorningBriefingPreferencesStore(
    private val storage: PreferencesStorageGateway
) {
    private val lock = Any()
    private val _stateFlow = MutableStateFlow(readConfig())
    val stateFlow: StateFlow<MorningBriefingConfig> = _stateFlow.asStateFlow()

    fun currentConfig(): MorningBriefingConfig = _stateFlow.value

    fun updateConfig(transform: (MorningBriefingConfig) -> MorningBriefingConfig): MorningBriefingConfig {
        return synchronized(lock) {
            val updated = transform(_stateFlow.value)
            storage.putBoolean(KEY_ENABLED, updated.enabled)
            storage.putString(KEY_HOUR, updated.hour.toString())
            storage.putString(KEY_MINUTE, updated.minute.toString())
            storage.putBoolean(KEY_INCLUDE_CALENDAR, updated.includeCalendar)
            storage.putBoolean(KEY_INCLUDE_NOTIFICATIONS, updated.includeNotifications)
            storage.putBoolean(KEY_INCLUDE_REMINDERS, updated.includeReminders)
            storage.putBoolean(KEY_AI_SUMMARY_ENABLED, updated.aiSummaryEnabled)
            _stateFlow.value = updated
            updated
        }
    }

    private fun readConfig(): MorningBriefingConfig {
        val enabled = storage.getBoolean(KEY_ENABLED, false)
        val hour = storage.getString(KEY_HOUR, "8")?.toIntOrNull()?.coerceIn(0, 23) ?: 8
        val minute = storage.getString(KEY_MINUTE, "0")?.toIntOrNull()?.coerceIn(0, 59) ?: 0
        val includeCalendar = storage.getBoolean(KEY_INCLUDE_CALENDAR, true)
        val includeNotifications = storage.getBoolean(KEY_INCLUDE_NOTIFICATIONS, true)
        val includeReminders = storage.getBoolean(KEY_INCLUDE_REMINDERS, true)
        val aiSummaryEnabled = storage.getBoolean(KEY_AI_SUMMARY_ENABLED, false)
        return MorningBriefingConfig(
            enabled = enabled,
            hour = hour,
            minute = minute,
            includeCalendar = includeCalendar,
            includeNotifications = includeNotifications,
            includeReminders = includeReminders,
            aiSummaryEnabled = aiSummaryEnabled
        )
    }

    companion object {
        private const val KEY_ENABLED: String = "morning_briefing_enabled"
        private const val KEY_HOUR: String = "morning_briefing_hour"
        private const val KEY_MINUTE: String = "morning_briefing_minute"
        private const val KEY_INCLUDE_CALENDAR: String = "morning_briefing_include_calendar"
        private const val KEY_INCLUDE_NOTIFICATIONS: String = "morning_briefing_include_notifications"
        private const val KEY_INCLUDE_REMINDERS: String = "morning_briefing_include_reminders"
        private const val KEY_AI_SUMMARY_ENABLED: String = "morning_briefing_ai_summary_enabled"
    }
}

package com.nava.domain.automation

/**
 * Recurrence cadence for a zero-battery scheduled reminder backed by Android `AlarmManager`.
 */
enum class ReminderRecurrence {
    ONCE,
    DAILY,
    WEEKLY
}

/**
 * Lifecycle state of a persisted [ScheduledReminder].
 */
enum class ReminderStatus {
    ACTIVE,
    COMPLETED,
    CANCELLED
}

/**
 * Immutable domain representation of a user-scheduled offline reminder.
 *
 * Plaintext title and message are persisted strictly inside the AES-256-GCM encrypted payload
 * column of `EncryptedSqliteStore` (`scheduled_reminders` table).
 */
data class ScheduledReminder(
    val reminderId: String,
    val title: String,
    val message: String = "",
    val triggerAtEpochMs: Long,
    val recurrence: ReminderRecurrence = ReminderRecurrence.ONCE,
    val status: ReminderStatus = ReminderStatus.ACTIVE,
    val createdAtEpochMs: Long = 0L,
    val updatedAtEpochMs: Long = 0L
) {
    init {
        require(reminderId.isNotBlank()) { "reminderId must not be blank" }
        require(title.isNotBlank()) { "title must not be blank" }
        require(triggerAtEpochMs > 0L) { "triggerAtEpochMs must be positive" }
    }

    /**
     * Computes the next trigger timestamp strictly after [nowEpochMs] for recurring reminders,
     * or returns `null` for [ReminderRecurrence.ONCE].
     */
    fun nextOccurrenceEpochMs(nowEpochMs: Long): Long? {
        val intervalMs = when (recurrence) {
            ReminderRecurrence.ONCE -> return null
            ReminderRecurrence.DAILY -> MILLIS_PER_DAY
            ReminderRecurrence.WEEKLY -> MILLIS_PER_WEEK
        }
        var candidate = triggerAtEpochMs + intervalMs
        while (candidate <= nowEpochMs) {
            candidate += intervalMs
        }
        return candidate
    }

    companion object {
        const val MILLIS_PER_MINUTE: Long = 60_000L
        const val MILLIS_PER_DAY: Long = 86_400_000L
        const val MILLIS_PER_WEEK: Long = 7L * MILLIS_PER_DAY
        const val DEFAULT_SNOOZE_MINUTES: Long = 15L
    }
}

/**
 * Non-sensitive configuration for the zero-idle-battery Morning Briefing.
 */
data class MorningBriefingConfig(
    val enabled: Boolean = false,
    val hour: Int = 8,
    val minute: Int = 0,
    val includeCalendar: Boolean = true,
    val includeNotifications: Boolean = true,
    val includeReminders: Boolean = true,
    val aiSummaryEnabled: Boolean = false
) {
    init {
        require(hour in 0..23) { "hour must be in 0..23" }
        require(minute in 0..59) { "minute must be in 0..59" }
    }
}

/**
 * Port for encrypted persistence of [ScheduledReminder] records.
 */
interface ScheduledReminderPort {
    suspend fun saveReminder(reminder: ScheduledReminder)

    suspend fun findReminder(reminderId: String): ScheduledReminder?

    suspend fun listActiveReminders(): List<ScheduledReminder>

    suspend fun listAllReminders(): List<ScheduledReminder>

    suspend fun updateStatus(
        reminderId: String,
        status: ReminderStatus,
        updatedAtEpochMs: Long
    ): Boolean

    suspend fun deleteReminder(reminderId: String): Boolean
}

/**
 * Platform port for scheduling and cancelling zero-battery OS alarms for [ScheduledReminder]
 * and Morning Briefing triggers.
 */
interface ReminderSchedulerPort {
    /**
     * Registers an OS alarm for [reminder]. Returns `true` if scheduled (exact or inexact fallback).
     */
    fun scheduleReminder(reminder: ScheduledReminder): Boolean

    /** Cancels any pending OS alarm associated with [reminderId]. */
    fun cancelReminder(reminderId: String)

    /**
     * Schedules the next Morning Briefing alarm at [hour]:[minute] local time.
     * Returns the scheduled epoch milliseconds, or `null` if scheduling failed.
     */
    fun scheduleMorningBriefing(hour: Int, minute: Int, nowEpochMs: Long): Long?

    /** Cancels any pending Morning Briefing alarm. */
    fun cancelMorningBriefing()
}

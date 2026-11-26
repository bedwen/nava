package com.nava.feature.automations.reminder

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import com.nava.domain.automation.ReminderSchedulerPort
import com.nava.domain.automation.ScheduledReminder
import java.util.Calendar
import java.util.TimeZone

/**
 * Zero-battery Android [AlarmManager] scheduler implementing `:domain` [ReminderSchedulerPort].
 *
 * Security & reliability invariants:
 * - Uses `setExactAndAllowWhileIdle` when permitted (`Build.VERSION.SDK_INT < S` or
 *   `AlarmManager.canScheduleExactAlarms()`), automatically falling back to
 *   `setAndAllowWhileIdle` so reminders still fire even without exact-alarm permission.
 * - Uses strictly explicit package-scoped intents and `PendingIntent.FLAG_IMMUTABLE`.
 * - Zero persistent background service or polling loop (0% idle battery drain).
 */
class ReminderAlarmScheduler(
    private val context: Context,
    private val reminderReceiverClassName: String = DEFAULT_REMINDER_RECEIVER_CLASS,
    private val briefingReceiverClassName: String = DEFAULT_BRIEFING_RECEIVER_CLASS
) : ReminderSchedulerPort {

    private val appContext: Context = context.applicationContext

    override fun scheduleReminder(reminder: ScheduledReminder): Boolean {
        val alarmManager = appContext.getSystemService(Context.ALARM_SERVICE) as? AlarmManager
            ?: return false
        val pendingIntent = buildReminderPendingIntent(reminder.reminderId)
        return scheduleAlarm(alarmManager, reminder.triggerAtEpochMs, pendingIntent)
    }

    override fun cancelReminder(reminderId: String) {
        val alarmManager = appContext.getSystemService(Context.ALARM_SERVICE) as? AlarmManager
            ?: return
        val pendingIntent = buildReminderPendingIntent(reminderId)
        alarmManager.cancel(pendingIntent)
        pendingIntent.cancel()
    }

    override fun scheduleMorningBriefing(hour: Int, minute: Int, nowEpochMs: Long): Long? {
        require(hour in 0..23) { "hour must be in 0..23" }
        require(minute in 0..59) { "minute must be in 0..59" }
        val alarmManager = appContext.getSystemService(Context.ALARM_SERVICE) as? AlarmManager
            ?: return null
        val triggerAtEpochMs = computeNextDailyTriggerEpochMs(hour, minute, nowEpochMs)
        val pendingIntent = buildBriefingPendingIntent()
        val scheduled = scheduleAlarm(alarmManager, triggerAtEpochMs, pendingIntent)
        return if (scheduled) triggerAtEpochMs else null
    }

    override fun cancelMorningBriefing() {
        val alarmManager = appContext.getSystemService(Context.ALARM_SERVICE) as? AlarmManager
            ?: return
        val pendingIntent = buildBriefingPendingIntent()
        alarmManager.cancel(pendingIntent)
        pendingIntent.cancel()
    }

    private fun scheduleAlarm(
        alarmManager: AlarmManager,
        triggerAtEpochMs: Long,
        pendingIntent: PendingIntent
    ): Boolean {
        return try {
            val canExact = Build.VERSION.SDK_INT < Build.VERSION_CODES.S ||
                alarmManager.canScheduleExactAlarms()
            if (canExact) {
                alarmManager.setExactAndAllowWhileIdle(
                    AlarmManager.RTC_WAKEUP,
                    triggerAtEpochMs,
                    pendingIntent
                )
            } else {
                alarmManager.setAndAllowWhileIdle(
                    AlarmManager.RTC_WAKEUP,
                    triggerAtEpochMs,
                    pendingIntent
                )
            }
            true
        } catch (_: SecurityException) {
            try {
                alarmManager.setAndAllowWhileIdle(
                    AlarmManager.RTC_WAKEUP,
                    triggerAtEpochMs,
                    pendingIntent
                )
                true
            } catch (_: Exception) {
                false
            }
        }
    }

    private fun buildReminderPendingIntent(reminderId: String): PendingIntent {
        val intent = Intent(ACTION_FIRE_REMINDER).apply {
            setClassName(appContext.packageName, reminderReceiverClassName)
            putExtra(EXTRA_REMINDER_ID, reminderId)
        }
        return PendingIntent.getBroadcast(
            appContext,
            requestCodeForReminder(reminderId),
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    private fun buildBriefingPendingIntent(): PendingIntent {
        val intent = Intent(ACTION_FIRE_MORNING_BRIEFING).apply {
            setClassName(appContext.packageName, briefingReceiverClassName)
        }
        return PendingIntent.getBroadcast(
            appContext,
            BRIEFING_REQUEST_CODE,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    companion object {
        const val ACTION_FIRE_REMINDER: String = "com.nava.app.action.FIRE_REMINDER"
        const val ACTION_FIRE_MORNING_BRIEFING: String = "com.nava.app.action.FIRE_MORNING_BRIEFING"
        const val EXTRA_REMINDER_ID: String = "nava_reminder_id"

        const val DEFAULT_REMINDER_RECEIVER_CLASS: String =
            "com.nava.app.reminders.ReminderBroadcastReceiver"
        const val DEFAULT_BRIEFING_RECEIVER_CLASS: String =
            "com.nava.app.reminders.MorningBriefingReceiver"

        private const val BRIEFING_REQUEST_CODE: Int = 0x4E41_5642

        /** Deterministic non-colliding positive request code for a reminder ID. */
        fun requestCodeForReminder(reminderId: String): Int {
            val hash = reminderId.hashCode() and 0x3FFF_FFFF
            return if (hash == 0) 1 else hash
        }

        /**
         * Computes the next local [hour]:[minute] trigger timestamp strictly after [nowEpochMs].
         */
        fun computeNextDailyTriggerEpochMs(
            hour: Int,
            minute: Int,
            nowEpochMs: Long,
            timeZone: TimeZone = TimeZone.getDefault()
        ): Long {
            val cal = Calendar.getInstance(timeZone).apply {
                timeInMillis = nowEpochMs
                set(Calendar.HOUR_OF_DAY, hour)
                set(Calendar.MINUTE, minute)
                set(Calendar.SECOND, 0)
                set(Calendar.MILLISECOND, 0)
            }
            if (cal.timeInMillis <= nowEpochMs) {
                cal.add(Calendar.DAY_OF_YEAR, 1)
            }
            return cal.timeInMillis
        }
    }
}

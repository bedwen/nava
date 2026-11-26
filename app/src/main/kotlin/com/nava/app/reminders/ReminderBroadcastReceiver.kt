package com.nava.app.reminders

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.nava.app.di.NavaApplication
import com.nava.domain.automation.ReminderRecurrence
import com.nava.domain.automation.ReminderStatus
import com.nava.feature.automations.reminder.ReminderAlarmScheduler
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Zero-battery [BroadcastReceiver] invoked by `AlarmManager` when a scheduled reminder fires.
 *
 * Wakes for milliseconds, decrypts the target reminder from `ScheduledReminderDao`, posts a local
 * notification with inline **Done** & **Snooze 15m** actions, advances recurring reminders to their
 * next occurrence, and exits without ever loading the LLM.
 *
 * Lockscreen resilience: if Android Keystore (`setUnlockedDeviceRequired(true)`) is locked when
 * the alarm fires, degrades gracefully to a privacy-preserving generic notification without crashing.
 */
class ReminderBroadcastReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ReminderAlarmScheduler.ACTION_FIRE_REMINDER) return
        val reminderId = intent.getStringExtra(ReminderAlarmScheduler.EXTRA_REMINDER_ID)
            ?.takeIf { it.isNotBlank() } ?: return
        val app = context.applicationContext as? NavaApplication ?: return
        val pendingResult = goAsync()
        val exceptionHandler = CoroutineExceptionHandler { _, _ -> }
        val receiverScope = CoroutineScope(SupervisorJob() + Dispatchers.IO + exceptionHandler)

        receiverScope.launch {
            try {
                val container = app.appContainer
                val reminder = try {
                    container.scheduledReminderDao.findReminder(reminderId)
                } catch (_: Throwable) {
                    ReminderNotificationPoster.postLockedReminderNotification(app, reminderId)
                    return@launch
                } ?: return@launch

                if (reminder.status != ReminderStatus.ACTIVE) {
                    return@launch
                }

                ReminderNotificationPoster.postReminderNotification(app, reminder)

                val nowMs = System.currentTimeMillis()
                if (reminder.recurrence != ReminderRecurrence.ONCE) {
                    val nextMs = reminder.nextOccurrenceEpochMs(nowMs)
                    if (nextMs != null) {
                        val updated = reminder.copy(
                            triggerAtEpochMs = nextMs,
                            updatedAtEpochMs = nowMs
                        )
                        runCatching {
                            container.scheduledReminderDao.saveReminder(updated)
                            container.reminderAlarmScheduler.scheduleReminder(updated)
                        }
                    }
                }
            } catch (_: Throwable) {
                // Never crash the broadcast process on unexpected storage or Keystore errors.
            } finally {
                receiverScope.cancel()
                pendingResult.finish()
            }
        }
    }
}

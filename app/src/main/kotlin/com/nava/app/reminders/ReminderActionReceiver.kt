package com.nava.app.reminders

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.nava.app.di.NavaApplication
import com.nava.domain.automation.ReminderRecurrence
import com.nava.domain.automation.ReminderStatus
import com.nava.domain.automation.ScheduledReminder
import com.nava.feature.automations.reminder.ReminderAlarmScheduler
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Handles inline notification action buttons (**Done** and **Snooze 15m**) on reminder
 * notifications without waking the UI or loading the LLM.
 */
class ReminderActionReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != ReminderNotificationPoster.ACTION_REMINDER_DONE &&
            action != ReminderNotificationPoster.ACTION_REMINDER_SNOOZE
        ) {
            return
        }
        val reminderId = intent.getStringExtra(ReminderAlarmScheduler.EXTRA_REMINDER_ID)
            ?.takeIf { it.isNotBlank() } ?: return
        val notificationId = intent.getIntExtra(
            ReminderNotificationPoster.EXTRA_NOTIFICATION_ID,
            ReminderNotificationPoster.notificationIdForReminder(reminderId)
        )
        val app = context.applicationContext as? NavaApplication ?: return
        val pendingResult = goAsync()
        val exceptionHandler = CoroutineExceptionHandler { _, _ -> }
        val receiverScope = CoroutineScope(SupervisorJob() + Dispatchers.IO + exceptionHandler)

        receiverScope.launch {
            try {
                val container = app.appContainer
                val nowMs = System.currentTimeMillis()
                val existing = runCatching {
                    container.scheduledReminderDao.findReminder(reminderId)
                }.getOrNull()
                if (existing != null) {
                    when (action) {
                        ReminderNotificationPoster.ACTION_REMINDER_DONE -> {
                            if (existing.recurrence == ReminderRecurrence.ONCE) {
                                runCatching {
                                    container.scheduledReminderDao.updateStatus(
                                        reminderId = reminderId,
                                        status = ReminderStatus.COMPLETED,
                                        updatedAtEpochMs = nowMs
                                    )
                                    container.reminderAlarmScheduler.cancelReminder(reminderId)
                                }
                            }
                        }

                        ReminderNotificationPoster.ACTION_REMINDER_SNOOZE -> {
                            val snoozeTriggerMs = nowMs +
                                (ScheduledReminder.DEFAULT_SNOOZE_MINUTES * ScheduledReminder.MILLIS_PER_MINUTE)
                            val snoozed = existing.copy(
                                triggerAtEpochMs = snoozeTriggerMs,
                                status = ReminderStatus.ACTIVE,
                                updatedAtEpochMs = nowMs
                            )
                            runCatching {
                                container.scheduledReminderDao.saveReminder(snoozed)
                                container.reminderAlarmScheduler.scheduleReminder(snoozed)
                            }
                        }
                    }
                }
                ReminderNotificationPoster.cancelNotification(app, notificationId)
            } catch (_: Throwable) {
                // Gracefully absorb locked-Keystore or storage errors without crashing.
            } finally {
                receiverScope.cancel()
                pendingResult.finish()
            }
        }
    }
}

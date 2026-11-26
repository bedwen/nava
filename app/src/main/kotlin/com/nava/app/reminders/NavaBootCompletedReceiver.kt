package com.nava.app.reminders

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.nava.app.di.NavaApplication
import com.nava.domain.automation.ReminderRecurrence
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Re-registers all active encrypted reminders and the scheduled Morning Briefing with
 * Android `AlarmManager` after device reboot (`ACTION_BOOT_COMPLETED`).
 *
 * Security & battery invariants:
 * - Zero LLM loading on boot.
 * - Strictly reacts to `Intent.ACTION_BOOT_COMPLETED`.
 * - Gracefully handles locked-Keystore errors on direct-boot / pre-unlock environments.
 */
class NavaBootCompletedReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) {
            return
        }
        val app = context.applicationContext as? NavaApplication ?: return
        val pendingResult = goAsync()
        val exceptionHandler = CoroutineExceptionHandler { _, _ -> }
        val receiverScope = CoroutineScope(SupervisorJob() + Dispatchers.IO + exceptionHandler)

        receiverScope.launch {
            try {
                val container = app.appContainer
                val nowMs = System.currentTimeMillis()
                val activeReminders = runCatching {
                    container.scheduledReminderDao.listActiveReminders()
                }.getOrDefault(emptyList())
                for (reminder in activeReminders) {
                    if (reminder.triggerAtEpochMs > nowMs) {
                        container.reminderAlarmScheduler.scheduleReminder(reminder)
                    } else if (reminder.recurrence != ReminderRecurrence.ONCE) {
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
                }

                val briefingConfig = container.morningBriefingPreferencesStore.currentConfig()
                if (briefingConfig.enabled) {
                    container.reminderAlarmScheduler.scheduleMorningBriefing(
                        hour = briefingConfig.hour,
                        minute = briefingConfig.minute,
                        nowEpochMs = nowMs
                    )
                }
            } catch (_: Throwable) {
                // Gracefully absorb locked-Keystore or storage errors on boot.
            } finally {
                receiverScope.cancel()
                pendingResult.finish()
            }
        }
    }
}

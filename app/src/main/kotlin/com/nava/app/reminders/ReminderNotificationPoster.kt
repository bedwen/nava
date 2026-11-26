package com.nava.app.reminders

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.nava.app.MainActivity
import com.nava.app.R
import com.nava.domain.automation.ScheduledReminder
import com.nava.feature.automations.reminder.ReminderAlarmScheduler

/**
 * Local notification poster for zero-battery Scheduled Reminders and Morning Briefings.
 *
 * Security invariants:
 * - Strictly checks `POST_NOTIFICATIONS` on Android 13+ before posting.
 * - Uses `PendingIntent.FLAG_IMMUTABLE` on all content and action intents.
 * - All intents are explicitly scoped to Nava's own package and receiver classes.
 */
object ReminderNotificationPoster {
    const val CHANNEL_REMINDERS: String = "nava_reminders"
    const val CHANNEL_MORNING_BRIEFING: String = "nava_morning_briefing"
    const val CHANNEL_WATCHER_ALERTS: String = "nava_watcher_alerts"

    const val ACTION_REMINDER_DONE: String = "com.nava.app.action.REMINDER_DONE"
    const val ACTION_REMINDER_SNOOZE: String = "com.nava.app.action.REMINDER_SNOOZE"

    const val EXTRA_NOTIFICATION_ID: String = "nava_notification_id"
    const val EXTRA_OPEN_BRIEFING_SUMMARY: String = "nava_open_briefing_summary"

    private const val BRIEFING_NOTIFICATION_ID: Int = 0x4E41_5643
    private const val TEST_NOTIFICATION_ID: Int = 0x4E41_5654

    fun postTestNotification(context: Context): Boolean {
        val appContext = context.applicationContext
        if (!canPostNotifications(appContext)) return false
        val manager = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return false
        ensureChannels(appContext, manager)

        val openIntent = Intent(appContext, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentPendingIntent = PendingIntent.getActivity(
            appContext,
            TEST_NOTIFICATION_ID,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val title = appContext.getString(R.string.test_notification_title)
        val body = appContext.getString(R.string.test_notification_body)

        val notification = NotificationCompat.Builder(appContext, CHANNEL_REMINDERS)
            .setSmallIcon(R.drawable.ic_stat_nava)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_REMINDER)
            .setAutoCancel(true)
            .setContentIntent(contentPendingIntent)
            .build()

        manager.notify(TEST_NOTIFICATION_ID, notification)
        return true
    }

    fun postReminderNotification(context: Context, reminder: ScheduledReminder) {
        val appContext = context.applicationContext
        if (!canPostNotifications(appContext)) return
        val manager = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return
        ensureChannels(appContext, manager)

        val notificationId = notificationIdForReminder(reminder.reminderId)
        val openIntent = Intent(appContext, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentPendingIntent = PendingIntent.getActivity(
            appContext,
            notificationId,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val doneIntent = Intent(appContext, ReminderActionReceiver::class.java).apply {
            action = ACTION_REMINDER_DONE
            putExtra(ReminderAlarmScheduler.EXTRA_REMINDER_ID, reminder.reminderId)
            putExtra(EXTRA_NOTIFICATION_ID, notificationId)
        }
        val donePendingIntent = PendingIntent.getBroadcast(
            appContext,
            notificationId * 2 + 1,
            doneIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val snoozeIntent = Intent(appContext, ReminderActionReceiver::class.java).apply {
            action = ACTION_REMINDER_SNOOZE
            putExtra(ReminderAlarmScheduler.EXTRA_REMINDER_ID, reminder.reminderId)
            putExtra(EXTRA_NOTIFICATION_ID, notificationId)
        }
        val snoozePendingIntent = PendingIntent.getBroadcast(
            appContext,
            notificationId * 2 + 2,
            snoozeIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val bodyText = reminder.message.takeIf { it.isNotBlank() }
            ?: appContext.getString(R.string.reminder_notification_default_body)

        val notification = NotificationCompat.Builder(appContext, CHANNEL_REMINDERS)
            .setSmallIcon(R.drawable.ic_stat_nava)
            .setContentTitle(reminder.title)
            .setContentText(bodyText)
            .setStyle(NotificationCompat.BigTextStyle().bigText(bodyText))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_REMINDER)
            .setAutoCancel(true)
            .setContentIntent(contentPendingIntent)
            .addAction(
                0,
                appContext.getString(R.string.reminder_action_done),
                donePendingIntent
            )
            .addAction(
                0,
                appContext.getString(R.string.reminder_action_snooze_15m),
                snoozePendingIntent
            )
            .build()

        manager.notify(notificationId, notification)
    }

    /**
     * Posts a privacy-preserving generic notification when a scheduled reminder fires while
     * Android Keystore (`setUnlockedDeviceRequired(true)`) is locked and cannot decrypt the title.
     */
    fun postLockedReminderNotification(context: Context, reminderId: String) {
        val appContext = context.applicationContext
        if (!canPostNotifications(appContext)) return
        val manager = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return
        ensureChannels(appContext, manager)

        val notificationId = notificationIdForReminder(reminderId)
        val openIntent = Intent(appContext, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentPendingIntent = PendingIntent.getActivity(
            appContext,
            notificationId,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(appContext, CHANNEL_REMINDERS)
            .setSmallIcon(R.drawable.ic_stat_nava)
            .setContentTitle(appContext.getString(R.string.reminder_channel_name))
            .setContentText(appContext.getString(R.string.reminder_notification_default_body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_REMINDER)
            .setAutoCancel(true)
            .setContentIntent(contentPendingIntent)
            .build()

        manager.notify(notificationId, notification)
    }

    fun postMorningBriefingNotification(
        context: Context,
        title: String,
        body: String
    ) {
        val appContext = context.applicationContext
        if (!canPostNotifications(appContext)) return
        val manager = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return
        ensureChannels(appContext, manager)

        val openIntent = Intent(appContext, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(EXTRA_OPEN_BRIEFING_SUMMARY, true)
        }
        val contentPendingIntent = PendingIntent.getActivity(
            appContext,
            BRIEFING_NOTIFICATION_ID,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val safeBody = body.takeIf { it.isNotBlank() }
            ?: appContext.getString(R.string.briefing_empty_body)

        val notification = NotificationCompat.Builder(appContext, CHANNEL_MORNING_BRIEFING)
            .setSmallIcon(R.drawable.ic_stat_nava)
            .setContentTitle(title)
            .setContentText(safeBody.lineSequence().firstOrNull().orEmpty())
            .setStyle(NotificationCompat.BigTextStyle().bigText(safeBody))
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setContentIntent(contentPendingIntent)
            .addAction(
                0,
                appContext.getString(R.string.briefing_action_summarize_nava),
                contentPendingIntent
            )
            .build()

        manager.notify(BRIEFING_NOTIFICATION_ID, notification)
    }

    fun postWatcherAlertNotification(
        context: Context,
        watcher: com.nava.domain.automation.NotificationWatcher,
        sourcePackageName: String,
        title: String,
        snippet: String
    ) {
        val appContext = context.applicationContext
        if (!canPostNotifications(appContext)) return
        val manager = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return
        ensureChannels(appContext, manager)

        val notificationId = notificationIdForReminder("watch_${watcher.watcherId}_${title.hashCode()}")
        val openIntent = Intent(appContext, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentPendingIntent = PendingIntent.getActivity(
            appContext,
            notificationId,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val alertTitle = appContext.getString(R.string.watcher_alert_notif_title, watcher.label)
        val alertBody = if (title.isNotBlank() && snippet.isNotBlank() && title != snippet) {
            "$title: $snippet"
        } else {
            snippet.ifBlank { title.ifBlank { sourcePackageName } }
        }

        val notification = NotificationCompat.Builder(appContext, CHANNEL_WATCHER_ALERTS)
            .setSmallIcon(R.drawable.ic_stat_nava)
            .setContentTitle(alertTitle)
            .setContentText(alertBody)
            .setStyle(NotificationCompat.BigTextStyle().bigText(alertBody))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setAutoCancel(true)
            .setContentIntent(contentPendingIntent)
            .build()

        manager.notify(notificationId, notification)
    }

    fun cancelNotification(context: Context, notificationId: Int) {
        val manager = context.applicationContext
            .getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return
        manager.cancel(notificationId)
    }

    fun notificationIdForReminder(reminderId: String): Int {
        val hash = reminderId.hashCode() and 0x1FFF_FFFF
        return if (hash < 1000) hash + 1000 else hash
    }

    private fun canPostNotifications(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED
    }

    private fun ensureChannels(context: Context, manager: NotificationManager) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val reminderChannel = NotificationChannel(
            CHANNEL_REMINDERS,
            context.getString(R.string.reminder_channel_name),
            NotificationManager.IMPORTANCE_HIGH
        )
        val briefingChannel = NotificationChannel(
            CHANNEL_MORNING_BRIEFING,
            context.getString(R.string.briefing_channel_name),
            NotificationManager.IMPORTANCE_DEFAULT
        )
        val watcherChannel = NotificationChannel(
            CHANNEL_WATCHER_ALERTS,
            context.getString(R.string.watcher_channel_name),
            NotificationManager.IMPORTANCE_HIGH
        )
        manager.createNotificationChannel(reminderChannel)
        manager.createNotificationChannel(briefingChannel)
        manager.createNotificationChannel(watcherChannel)
    }
}

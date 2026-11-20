package com.nava.feature.automations.common

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.nava.domain.ui.UserMessage

/**
 * Standard completion notification payload emitted after an unattended routine or background
 * continuation finishes `Auto`-permitted safe actions.
 */
data class CompletionNotificationRequest(
    val notificationId: Int,
    val requestId: String,
    val message: UserMessage,
    val ruleId: String? = null,
    val taskId: String? = null
) {
    init {
        require(requestId.isNotBlank()) { "CompletionNotificationRequest requestId must not be blank" }
    }
}

/**
 * High-priority interactive notification payload emitted whenever a background routine or
 * background continuation encounters an action requiring an Action Confirmation Card or
 * Biometric verification (PLAN.md Sections 5.6 & 9).
 */
data class InteractiveNotificationRequest(
    val notificationId: Int,
    val requestId: String,
    val pendingToolNames: List<String>,
    val targetId: String,
    val message: UserMessage,
    val requiresBiometric: Boolean = false,
    val hasUntrustedHighRiskSlot: Boolean = false,
    val canonicalArguments: Map<String, String> = emptyMap(),
    val ruleId: String? = null,
    val taskId: String? = null
) {
    init {
        require(requestId.isNotBlank()) { "InteractiveNotificationRequest requestId must not be blank" }
        require(pendingToolNames.isNotEmpty()) { "InteractiveNotificationRequest must name at least one pending tool" }
        require(targetId.isNotBlank()) { "InteractiveNotificationRequest targetId must not be blank" }
    }
}

/**
 * Pure descriptor for a foreground `WorkManager` notification while a long-running user-initiated
 * task continues in the background.
 */
data class ForegroundNotificationSpec(
    val notificationId: Int,
    val channelId: String,
    val taskId: String,
    val message: UserMessage
) {
    init {
        require(channelId.isNotBlank()) { "ForegroundNotificationSpec channelId must not be blank" }
        require(taskId.isNotBlank()) { "ForegroundNotificationSpec taskId must not be blank" }
    }
}

/**
 * Thin, JVM-testable bridge for posting automation completion notifications, high-priority
 * interactive Action Confirmation Card notifications, and foreground worker descriptors.
 */
interface AutomationNotificationBridge {
    fun postCompletionNotification(request: CompletionNotificationRequest)

    fun postInteractiveConfirmationNotification(request: InteractiveNotificationRequest)

    fun cancelNotification(notificationId: Int)

    fun createForegroundNotificationSpec(
        taskId: String,
        message: UserMessage
    ): ForegroundNotificationSpec

    companion object {
        const val CHANNEL_COMPLETION: String = "nava_automation_completion"
        const val CHANNEL_INTERACTIVE_CONFIRMATION: String = "nava_automation_confirmation"
        const val CHANNEL_FOREGROUND_TASK: String = "nava_automation_foreground"

        const val EXTRA_REQUEST_ID: String = "com.nava.extra.REQUEST_ID"
        const val EXTRA_RULE_ID: String = "com.nava.extra.RULE_ID"
        const val EXTRA_TASK_ID: String = "com.nava.extra.TASK_ID"
        const val EXTRA_REQUIRES_BIOMETRIC: String = "com.nava.extra.REQUIRES_BIOMETRIC"
        const val EXTRA_UNTRUSTED_HIGH_RISK: String = "com.nava.extra.UNTRUSTED_HIGH_RISK"
    }
}

/**
 * Production Android `NotificationCompat` implementation of [AutomationNotificationBridge].
 *
 * The presentation layer (`:app`) supplies [messageRenderer] (backed by localized `strings.xml`)
 * and [interactiveContentIntentFactory] (opening Nava's Action Confirmation Card) so
 * `:feature-automations` stays strictly decoupled from `:app`.
 */
class AndroidAutomationNotificationBridge(
    private val context: Context,
    private val messageRenderer: (UserMessage) -> Pair<String, String> = ::defaultRenderMessage,
    private val interactiveContentIntentFactory: (InteractiveNotificationRequest) -> PendingIntent? = { null },
    private val smallIconResId: Int = android.R.drawable.ic_dialog_info
) : AutomationNotificationBridge {

    init {
        ensureChannels()
    }

    override fun postCompletionNotification(request: CompletionNotificationRequest) {
        if (!canPostNotifications()) return
        val (title, text) = messageRenderer(request.message)
        val notification = NotificationCompat.Builder(context, AutomationNotificationBridge.CHANNEL_COMPLETION)
            .setSmallIcon(smallIconResId)
            .setContentTitle(title)
            .setContentText(text)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()
        notifySafely(request.notificationId, notification)
    }

    override fun postInteractiveConfirmationNotification(request: InteractiveNotificationRequest) {
        if (!canPostNotifications()) return
        val (title, text) = messageRenderer(request.message)
        val builder = NotificationCompat.Builder(
            context,
            AutomationNotificationBridge.CHANNEL_INTERACTIVE_CONFIRMATION
        )
            .setSmallIcon(smallIconResId)
            .setContentTitle(title)
            .setContentText(text)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_REMINDER)
            .setAutoCancel(true)

        interactiveContentIntentFactory(request)?.let { pendingIntent ->
            builder.setContentIntent(pendingIntent)
        }
        notifySafely(request.notificationId, builder.build())
    }

    override fun cancelNotification(notificationId: Int) {
        NotificationManagerCompat.from(context).cancel(notificationId)
    }

    override fun createForegroundNotificationSpec(
        taskId: String,
        message: UserMessage
    ): ForegroundNotificationSpec {
        return ForegroundNotificationSpec(
            notificationId = stableNotificationId("fg:$taskId"),
            channelId = AutomationNotificationBridge.CHANNEL_FOREGROUND_TASK,
            taskId = taskId,
            message = message
        )
    }

    /**
     * Builds an Android [Notification] suitable for `WorkManager`'s `ForegroundInfo`.
     */
    fun buildForegroundNotification(spec: ForegroundNotificationSpec): Notification {
        val (title, text) = messageRenderer(spec.message)
        return NotificationCompat.Builder(context, spec.channelId)
            .setSmallIcon(smallIconResId)
            .setContentTitle(title)
            .setContentText(text)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .build()
    }

    private fun ensureChannels() {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return
        val channels = listOf(
            NotificationChannel(
                AutomationNotificationBridge.CHANNEL_COMPLETION,
                "Automation Completions",
                NotificationManager.IMPORTANCE_DEFAULT
            ),
            NotificationChannel(
                AutomationNotificationBridge.CHANNEL_INTERACTIVE_CONFIRMATION,
                "Action Confirmations",
                NotificationManager.IMPORTANCE_HIGH
            ),
            NotificationChannel(
                AutomationNotificationBridge.CHANNEL_FOREGROUND_TASK,
                "Background Tasks",
                NotificationManager.IMPORTANCE_LOW
            )
        )
        for (channel in channels) {
            manager.createNotificationChannel(channel)
        }
    }

    private fun canPostNotifications(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) return false
        }
        return NotificationManagerCompat.from(context).areNotificationsEnabled()
    }

    private fun notifySafely(notificationId: Int, notification: Notification) {
        try {
            NotificationManagerCompat.from(context).notify(notificationId, notification)
        } catch (_: SecurityException) {
            // Permission revoked concurrently; fail safely without crashing background worker.
        }
    }

    companion object {
        fun stableNotificationId(key: String): Int {
            val hash = key.hashCode() and 0x7FFFFFFF
            return if (hash == 0) 1 else hash
        }

        private fun defaultRenderMessage(message: UserMessage): Pair<String, String> {
            return "Nava" to message.key.name
        }
    }
}

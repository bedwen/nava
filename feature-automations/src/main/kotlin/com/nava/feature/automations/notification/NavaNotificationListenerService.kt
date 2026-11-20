package com.nava.feature.automations.notification

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import com.nava.domain.automation.CapturedNotification
import com.nava.domain.automation.NotificationInboxPort
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.PermissionEvaluatorPort
import com.nava.domain.security.SensitiveSlotKind
import com.nava.feature.automations.common.ToolTargetIds
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Pure Kotlin coordinator implementing the in-memory Default-Deny notification filtering invariant.
 */
class NotificationIngestionFilter(
    private val permissionEvaluator: PermissionEvaluatorPort,
    private val inbox: NotificationInboxPort
) {
    /**
     * Filters and conditionally ingests an incoming notification.
     *
     * CRITICAL IN-MEMORY DEFAULT-DENY INVARIANT (PLAN.md 5.7 & Gate 2):
     * [lazyContentExtractor] is evaluated strictly AFTER confirming that [packageName]
     * has been granted [AtomicCapability.NOTIFICATION_READ] with an allowed confirmation level.
     * If the capability is disabled, unconfigured, or denied, this function returns false
     * immediately in memory without invoking [lazyContentExtractor], reading extras, or caching.
     */
    suspend fun onPosted(
        notificationKey: String,
        packageName: String,
        postedAtEpochMs: Long,
        channelId: String? = null,
        lazyContentExtractor: () -> Pair<String, String>
    ): Boolean {
        if (notificationKey.isBlank() || packageName.isBlank()) {
            return false
        }

        val targetId = ToolTargetIds.forPackage(packageName)
        val level = try {
            permissionEvaluator.evaluateCapability(targetId, AtomicCapability.NOTIFICATION_READ)
        } catch (_: Exception) {
            ConfirmationLevel.DISABLED
        }

        if (!level.isAllowed || level == ConfirmationLevel.DISABLED) {
            // Default-Deny drop: lazyContentExtractor is NEVER called.
            return false
        }

        // Only permitted packages proceed to content extraction and sanitization.
        val (rawTitle, rawBody) = lazyContentExtractor()
        val titleTainted = Gemma4InputSanitizer.sanitizeExternal(
            rawExternalInput = rawTitle,
            slotKind = SensitiveSlotKind.TEXT_BODY,
            sourceLabel = packageName
        )
        val bodyTainted = Gemma4InputSanitizer.sanitizeExternal(
            rawExternalInput = rawBody,
            slotKind = SensitiveSlotKind.TEXT_BODY,
            sourceLabel = packageName
        )

        val captured = CapturedNotification(
            notificationKey = notificationKey,
            packageName = packageName,
            title = titleTainted,
            body = bodyTainted,
            postedAtEpochMs = postedAtEpochMs,
            channelId = channelId
        )

        inbox.ingest(captured)
        return true
    }

    suspend fun onRemoved(notificationKey: String): Boolean {
        if (notificationKey.isBlank()) return false
        return inbox.removeByKey(notificationKey)
    }
}

/**
 * Clean static service-locator hook allowing `:app`'s `AppContainer` to bind dependencies
 * into the Android-instantiated [NavaNotificationListenerService] without Hilt or Dagger.
 *
 * Security invariant: fails closed (Default-Deny) whenever unbound.
 */
object NotificationServiceBinding {
    @Volatile
    private var filter: NotificationIngestionFilter? = null

    @Volatile
    private var evaluator: PermissionEvaluatorPort? = null

    @Volatile
    private var inbox: NotificationInboxPort? = null

    fun bind(evaluatorPort: PermissionEvaluatorPort, inboxPort: NotificationInboxPort) {
        evaluator = evaluatorPort
        inbox = inboxPort
        filter = NotificationIngestionFilter(evaluatorPort, inboxPort)
    }

    fun bindCustomFilter(customFilter: NotificationIngestionFilter) {
        filter = customFilter
    }

    fun unbind() {
        filter = null
        evaluator = null
        inbox = null
    }

    fun getFilter(): NotificationIngestionFilter? = filter
    fun getEvaluator(): PermissionEvaluatorPort? = evaluator
    fun getInbox(): NotificationInboxPort? = inbox
}

/**
 * Android [NotificationListenerService] subclass forwarding lifecycle events to [NotificationIngestionFilter].
 */
class NavaNotificationListenerService : NotificationListenerService() {
    private val serviceScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null) return
        val key = sbn.key ?: return
        val pkg = sbn.packageName ?: return
        val postTime = sbn.postTime
        val channelId = sbn.notification?.channelId

        val activeFilter = NotificationServiceBinding.getFilter() ?: return // Fail-closed when unbound

        serviceScope.launch {
            activeFilter.onPosted(
                notificationKey = key,
                packageName = pkg,
                postedAtEpochMs = postTime,
                channelId = channelId,
                lazyContentExtractor = {
                    val extras = sbn.notification?.extras
                    val title = extras?.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
                    val text = extras?.getCharSequence(Notification.EXTRA_TEXT)?.toString().orEmpty()
                    title to text
                }
            )
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        if (sbn == null) return
        val key = sbn.key ?: return
        val activeFilter = NotificationServiceBinding.getFilter() ?: return

        serviceScope.launch {
            activeFilter.onRemoved(key)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }
}

package com.nava.feature.automations.notification

import android.app.Notification
import android.content.ComponentName
import android.content.Context
import android.os.Build
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
import kotlinx.coroutines.CancellationException
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
    private val inbox: NotificationInboxPort,
    private val onLiveIngested: (suspend (CapturedNotification) -> Unit)? = null
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
    ): Boolean = ingest(
        notificationKey = notificationKey,
        packageName = packageName,
        postedAtEpochMs = postedAtEpochMs,
        channelId = channelId,
        isLiveEvent = true,
        lazySenderExtractor = null,
        lazyContentExtractor = lazyContentExtractor
    )

    /**
     * Like [onPosted], additionally capturing sender identity from structured notification
     * metadata via [lazySenderExtractor] (invoked only for permitted packages).
     */
    suspend fun onPostedWithSender(
        notificationKey: String,
        packageName: String,
        postedAtEpochMs: Long,
        channelId: String?,
        isLiveEvent: Boolean,
        lazySenderExtractor: () -> String,
        lazyContentExtractor: () -> Pair<String, String>
    ): Boolean = ingest(
        notificationKey = notificationKey,
        packageName = packageName,
        postedAtEpochMs = postedAtEpochMs,
        channelId = channelId,
        isLiveEvent = isLiveEvent,
        lazySenderExtractor = lazySenderExtractor,
        lazyContentExtractor = lazyContentExtractor
    )

    internal suspend fun onPostedInternal(
        notificationKey: String,
        packageName: String,
        postedAtEpochMs: Long,
        channelId: String? = null,
        isLiveEvent: Boolean = true,
        lazyContentExtractor: () -> Pair<String, String>
    ): Boolean = ingest(
        notificationKey = notificationKey,
        packageName = packageName,
        postedAtEpochMs = postedAtEpochMs,
        channelId = channelId,
        isLiveEvent = isLiveEvent,
        lazySenderExtractor = null,
        lazyContentExtractor = lazyContentExtractor
    )

    private suspend fun ingest(
        notificationKey: String,
        packageName: String,
        postedAtEpochMs: Long,
        channelId: String?,
        isLiveEvent: Boolean,
        lazySenderExtractor: (() -> String)?,
        lazyContentExtractor: () -> Pair<String, String>
    ): Boolean {
        if (notificationKey.isBlank() || packageName.isBlank() || packageName == SELF_PACKAGE_NAME) {
            return false
        }

        val targetId = ToolTargetIds.forPackage(packageName)
        val level = try {
            permissionEvaluator.evaluateCapability(targetId, AtomicCapability.NOTIFICATION_READ)
        } catch (e: CancellationException) {
            throw e
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

        // Sender identities (names, email addresses, phone numbers) are destination-grade data:
        // tag them RECIPIENT_ADDRESS so any use as a tool target forces explicit confirmation.
        val senderHintsTainted = lazySenderExtractor?.invoke()
            ?.takeIf { it.isNotBlank() }
            ?.let { rawSender ->
                Gemma4InputSanitizer.sanitizeExternal(
                    rawExternalInput = rawSender,
                    slotKind = SensitiveSlotKind.RECIPIENT_ADDRESS,
                    sourceLabel = packageName
                )
            }

        val captured = CapturedNotification(
            notificationKey = notificationKey,
            packageName = packageName,
            title = titleTainted,
            body = bodyTainted,
            postedAtEpochMs = postedAtEpochMs,
            channelId = channelId,
            senderHints = senderHintsTainted
        )

        inbox.ingest(captured)
        if (isLiveEvent) {
            onLiveIngested?.invoke(captured)
        }
        return true
    }

    suspend fun onRemoved(notificationKey: String): Boolean {
        if (notificationKey.isBlank()) return false
        return inbox.removeByKey(notificationKey)
    }

    companion object {
        private const val SELF_PACKAGE_NAME: String = "com.nava.app"
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

    @Volatile
    private var resyncActiveNotificationsHandler: (suspend () -> Unit)? = null

    fun bind(
        evaluatorPort: PermissionEvaluatorPort,
        inboxPort: NotificationInboxPort,
        onLiveIngested: (suspend (CapturedNotification) -> Unit)? = null
    ) {
        evaluator = evaluatorPort
        inbox = inboxPort
        filter = NotificationIngestionFilter(evaluatorPort, inboxPort, onLiveIngested)
    }

    fun bindCustomFilter(customFilter: NotificationIngestionFilter) {
        filter = customFilter
    }

    fun registerResyncHandler(handler: suspend () -> Unit) {
        resyncActiveNotificationsHandler = handler
    }

    fun unregisterResyncHandler() {
        resyncActiveNotificationsHandler = null
    }

    /**
     * Triggers an on-demand re-scan of active status-bar notifications through
     * [NotificationIngestionFilter] so notifications posted before an app was granted
     * `NOTIFICATION_READ` become available immediately without relaxing Default-Deny.
     */
    suspend fun requestActiveNotificationsResync() {
        val handler = resyncActiveNotificationsHandler ?: return
        try {
            handler()
        } catch (ce: CancellationException) {
            throw ce
        } catch (_: Exception) {
            // Fail-closed: never propagate platform binder errors to callers.
        }
    }

    /**
     * Requests Android to rebind [NavaNotificationListenerService] when the app restarts or updates
     * and the system has not yet re-invoked `onListenerConnected()`, ensuring active notifications
     * from all permitted apps stay synchronized universally.
     */
    fun requestRebindIfUnbound(context: Context) {
        if (resyncActiveNotificationsHandler != null) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            runCatching {
                NotificationListenerService.requestRebind(
                    ComponentName(context.applicationContext, NavaNotificationListenerService::class.java)
                )
            }
        }
    }

    fun unbind() {
        filter = null
        evaluator = null
        inbox = null
        resyncActiveNotificationsHandler = null
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

    override fun onCreate() {
        super.onCreate()
        NotificationServiceBinding.registerResyncHandler {
            syncActiveNotificationsNow()
        }
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        NotificationServiceBinding.registerResyncHandler {
            syncActiveNotificationsNow()
        }
        serviceScope.launch {
            syncActiveNotificationsNow()
        }
    }

    override fun onListenerDisconnected() {
        NotificationServiceBinding.unregisterResyncHandler()
        super.onListenerDisconnected()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null) return
        val key = sbn.key ?: return
        val pkg = sbn.packageName ?: return
        val postTime = sbn.postTime
        val channelId = sbn.notification?.channelId

        val activeFilter = NotificationServiceBinding.getFilter() ?: return // Fail-closed when unbound

        serviceScope.launch {
            activeFilter.onPostedWithSender(
                notificationKey = key,
                packageName = pkg,
                postedAtEpochMs = postTime,
                channelId = channelId,
                isLiveEvent = true,
                lazySenderExtractor = { extractSenderHints(sbn) },
                lazyContentExtractor = { extractNotificationContent(sbn) }
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
        NotificationServiceBinding.unregisterResyncHandler()
        super.onDestroy()
        serviceScope.cancel()
    }

    private suspend fun syncActiveNotificationsNow() {
        val activeFilter = NotificationServiceBinding.getFilter() ?: return
        val active = runCatching { activeNotifications }.getOrNull() ?: emptyArray()
        for (sbn in active) {
            val key = sbn?.key ?: continue
            val pkg = sbn.packageName ?: continue
            activeFilter.onPostedWithSender(
                notificationKey = key,
                packageName = pkg,
                postedAtEpochMs = sbn.postTime,
                channelId = sbn.notification?.channelId,
                isLiveEvent = false,
                lazySenderExtractor = { extractSenderHints(sbn) },
                lazyContentExtractor = { extractNotificationContent(sbn) }
            )
        }
    }

    private fun extractNotificationContent(sbn: StatusBarNotification): Pair<String, String> {
        val extras = sbn.notification?.extras
        val title = extras?.getCharSequence(Notification.EXTRA_TITLE)?.toString()
            ?.takeIf { it.isNotBlank() }
            ?: extras?.getCharSequence(Notification.EXTRA_TITLE_BIG)?.toString().orEmpty()
        val bigText = extras?.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()?.trim()
        val plainText = extras?.getCharSequence(Notification.EXTRA_TEXT)?.toString()?.trim()
        val textLines = extras?.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)
            ?.mapNotNull { it?.toString()?.trim()?.takeIf(String::isNotEmpty) }
            ?.takeLast(5)
            ?.joinToString(" | ")
        val summaryText = extras?.getCharSequence(Notification.EXTRA_SUMMARY_TEXT)?.toString()?.trim()
            ?: extras?.getCharSequence(Notification.EXTRA_SUB_TEXT)?.toString()?.trim()
        val text = when {
            !bigText.isNullOrBlank() && !plainText.isNullOrBlank() && !bigText.contains(plainText) ->
                "$plainText - $bigText"
            !bigText.isNullOrBlank() -> bigText
            !textLines.isNullOrBlank() -> textLines
            !plainText.isNullOrBlank() -> plainText
            !summaryText.isNullOrBlank() -> summaryText
            else -> ""
        }
        return title to text
    }

    /**
     * Sender identity from structured metadata only (`EXTRA_PEOPLE_LIST`), never from free text.
     * Keeps display names plus `mailto:`/`tel:` addresses; other URIs (e.g. `content://` contact
     * lookups) are dropped. Bounded to [MAX_SENDER_PEOPLE] people and [MAX_SENDER_HINT_CHARS].
     */
    @Suppress("DEPRECATION")
    private fun extractSenderHints(sbn: StatusBarNotification): String {
        val extras = sbn.notification?.extras ?: return ""
        val people = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                extras.getParcelableArrayList(Notification.EXTRA_PEOPLE_LIST, android.app.Person::class.java)
            } else {
                extras.getParcelableArrayList<android.app.Person>(Notification.EXTRA_PEOPLE_LIST)
            }
        }.getOrNull().orEmpty()
        if (people.isEmpty()) return ""
        return people.asSequence()
            .mapNotNull { person ->
                val name = person.name?.toString()?.trim()?.takeIf { it.isNotEmpty() }
                val address = person.uri?.trim()?.let { uri ->
                    when {
                        uri.startsWith(MAILTO_PREFIX, ignoreCase = true) -> uri.substring(MAILTO_PREFIX.length)
                        uri.startsWith(TEL_PREFIX, ignoreCase = true) -> uri.substring(TEL_PREFIX.length)
                        else -> null
                    }
                }?.trim()?.takeIf { it.isNotEmpty() }
                listOfNotNull(name, address).joinToString(" ").takeIf { it.isNotEmpty() }
            }
            .distinct()
            .take(MAX_SENDER_PEOPLE)
            .joinToString(", ")
            .take(MAX_SENDER_HINT_CHARS)
    }

    private companion object {
        const val MAILTO_PREFIX: String = "mailto:"
        const val TEL_PREFIX: String = "tel:"
        const val MAX_SENDER_PEOPLE: Int = 3
        const val MAX_SENDER_HINT_CHARS: Int = 160
    }
}

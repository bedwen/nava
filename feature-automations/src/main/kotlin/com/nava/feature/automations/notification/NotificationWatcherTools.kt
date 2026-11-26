package com.nava.feature.automations.notification

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.automation.CapturedNotification
import com.nava.domain.automation.NotificationWatcher
import com.nava.domain.automation.NotificationWatcherAlertPort
import com.nava.domain.automation.NotificationWatcherPort
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.NavaTool
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolCategory
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolResult
import com.nava.domain.tool.ToolSchemaField
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.ToolArgumentReader
import com.nava.feature.automations.common.ToolTargetIds
import java.text.Normalizer
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Pure Kotlin zero-battery notification watcher matcher.
 *
 * Security & privacy invariants (Iron Laws 5 & 6):
 * - Invoked strictly AFTER [NotificationIngestionFilter] confirms the source package has
 *   `NOTIFICATION_READ` allowed.
 * - 100% passive: matching can only trigger a local read-only alert notification to the user;
 *   it never invokes tools, sends messages, or mutates device data.
 */
object NotificationWatcherMatcher {
    private val DIACRITICS_REGEX = Regex("\\p{InCombiningDiacriticalMarks}+")

    private val APP_ALIAS_PREFIXES: Map<String, Set<String>> = mapOf(
        "gmail" to setOf("com.google.android.gm"),
        "mail" to setOf("com.google.android.gm", "com.microsoft.office.outlook", "com.samsung.android.email.provider", "com.yahoo.mobile.client.android.mail"),
        "email" to setOf("com.google.android.gm", "com.microsoft.office.outlook", "com.samsung.android.email.provider"),
        "eposta" to setOf("com.google.android.gm", "com.microsoft.office.outlook", "com.samsung.android.email.provider"),
        "whatsapp" to setOf("com.whatsapp", "com.whatsapp.w4b"),
        "wp" to setOf("com.whatsapp", "com.whatsapp.w4b"),
        "telegram" to setOf("org.telegram.messenger", "org.telegram.messenger.web"),
        "sms" to setOf("com.google.android.apps.messaging", "com.samsung.android.messaging", "com.android.mms"),
        "mesaj" to setOf("com.google.android.apps.messaging", "com.samsung.android.messaging", "com.android.mms"),
        "mesajlar" to setOf("com.google.android.apps.messaging", "com.samsung.android.messaging", "com.android.mms"),
        "messages" to setOf("com.google.android.apps.messaging", "com.samsung.android.messaging", "com.android.mms"),
        "instagram" to setOf("com.instagram.android"),
        "slack" to setOf("com.Slack"),
        "discord" to setOf("com.discord")
    )

    internal fun fold(raw: String): String {
        val nfd = Normalizer.normalize(raw, Normalizer.Form.NFD)
        return DIACRITICS_REGEX.replace(nfd, "")
            .replace('\u0131', 'i')
            .replace('\u0130', 'i')
            .lowercase(Locale.ROOT)
            .trim()
    }

    fun matches(watcher: NotificationWatcher, notification: CapturedNotification): Boolean {
        if (!watcher.enabled) return false
        if (watcher.keywords.isEmpty() && watcher.senderFilter.isNullOrBlank()) return false

        val pkgFilter = watcher.packageFilter?.trim()?.takeIf { it.isNotEmpty() }
        if (pkgFilter != null && !matchesPackage(pkgFilter, notification.packageName)) {
            return false
        }

        val foldedTitle = fold(notification.title.value)
        val foldedBody = fold(notification.body.value)
        val combined = "$foldedTitle $foldedBody"
        val combinedNoSpaces = combined.replace(" ", "")

        val sender = watcher.senderFilter?.trim()?.takeIf { it.isNotEmpty() }
        if (sender != null && !matchesTerm(sender, combined, combinedNoSpaces)) {
            return false
        }

        if (watcher.keywords.isNotEmpty()) {
            val anyKeywordMatched = watcher.keywords.any { kw ->
                matchesTerm(kw, combined, combinedNoSpaces)
            }
            if (!anyKeywordMatched) {
                return false
            }
        }

        return true
    }

    /**
     * Matches a single user-provided term (keyword, sender name, or email address) against the
     * folded notification text.
     *
     * Gmail and many email clients display only the sender's display name (e.g. "Nezih Erbay" or
     * "Halit Buluthan Cetintas") in Android notifications rather than the raw email address.
     * When [rawTerm] is an email address (`local@domain`), this method matches either the full
     * address OR all meaningful tokens of the local part against both spaced and whitespace-stripped
     * notification text.
     */
    private fun matchesTerm(rawTerm: String, combined: String, combinedNoSpaces: String): Boolean {
        val foldedTerm = fold(rawTerm)
        if (foldedTerm.isEmpty()) return false
        if (combined.contains(foldedTerm)) return true

        val termNoSpaces = foldedTerm.replace(" ", "")
        if (termNoSpaces.length >= 3 && combinedNoSpaces.contains(termNoSpaces)) return true

        val atIndex = foldedTerm.indexOf('@')
        if (atIndex > 0) {
            val localPart = foldedTerm.substring(0, atIndex)
            val tokens = localPart
                .split('.', '_', '-', '+')
                .map { it.trim() }
                .filter { it.length >= 2 }
            if (tokens.isNotEmpty() && tokens.all { token ->
                    combined.contains(token) || combinedNoSpaces.contains(token)
                }
            ) {
                return true
            }
        }
        return false
    }

    private fun matchesPackage(rawFilter: String, packageName: String): Boolean {
        val foldedFilter = fold(rawFilter)
        val lowerPkg = packageName.lowercase(Locale.ROOT)
        if (lowerPkg == foldedFilter || lowerPkg.contains(foldedFilter)) {
            return true
        }
        val mappedPackages = APP_ALIAS_PREFIXES[foldedFilter]
        if (mappedPackages != null && lowerPkg in mappedPackages) {
            return true
        }
        for ((alias, pkgs) in APP_ALIAS_PREFIXES) {
            if (foldedFilter.contains(alias) && lowerPkg in pkgs) {
                return true
            }
        }
        return false
    }
}

/**
 * Evaluates live permitted incoming [CapturedNotification]s against enabled [NotificationWatcher]s
 * with in-memory cooldown deduplication so repeated Android notification updates never spam alerts.
 */
class NotificationWatcherEngine(
    private val watcherPort: NotificationWatcherPort,
    private val alertPort: NotificationWatcherAlertPort,
    private val clockMs: () -> Long = System::currentTimeMillis
) {
    private val recentAlertTimestamps = ConcurrentHashMap<String, Long>()

    @Volatile
    private var cachedEnabledWatchers: List<NotificationWatcher> = emptyList()

    /**
     * Refreshes the in-memory enabled watcher snapshot from [watcherPort] while the device is
     * unlocked so lock-screen notifications can still be evaluated without failing on Keystore
     * `setUnlockedDeviceRequired(true)`.
     */
    suspend fun refreshCache() {
        val loaded = runCatching { watcherPort.listEnabledWatchers() }.getOrNull() ?: return
        cachedEnabledWatchers = loaded
    }

    suspend fun onLiveNotificationIngested(notification: CapturedNotification) {
        val fresh = runCatching { watcherPort.listEnabledWatchers() }.getOrNull()
        val enabledWatchers = if (fresh != null) {
            cachedEnabledWatchers = fresh
            fresh
        } else {
            cachedEnabledWatchers
        }
        if (enabledWatchers.isEmpty()) return

        val now = clockMs()
        pruneOldCooldowns(now)

        for (watcher in enabledWatchers) {
            if (!NotificationWatcherMatcher.matches(watcher, notification)) continue
            val dedupKey = "${watcher.watcherId}|${notification.notificationKey}"
            val lastFired = recentAlertTimestamps[dedupKey]
            if (lastFired != null && (now - lastFired) < DEDUP_COOLDOWN_MS) {
                continue
            }
            recentAlertTimestamps[dedupKey] = now
            runCatching { watcherPort.recordTrigger(watcher.watcherId, now) }

            val cleanTitle = Gemma4InputSanitizer.sanitize(notification.title.value).trim()
            val cleanBody = Gemma4InputSanitizer.sanitize(notification.body.value).trim()
            val snippet = cleanBody.ifBlank { cleanTitle }.take(MAX_SNIPPET_CHARS)

            runCatching {
                alertPort.postWatcherAlert(
                    watcher = watcher,
                    sourcePackageName = notification.packageName,
                    title = cleanTitle.ifBlank { notification.packageName },
                    snippet = snippet
                )
            }
        }
    }

    private fun pruneOldCooldowns(nowMs: Long) {
        if (recentAlertTimestamps.size < 64) return
        val iterator = recentAlertTimestamps.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if ((nowMs - entry.value) >= DEDUP_COOLDOWN_MS) {
                iterator.remove()
            }
        }
    }

    companion object {
        const val DEDUP_COOLDOWN_MS: Long = 30_000L
        private const val MAX_SNIPPET_CHARS: Int = 220
    }
}

/**
 * Factory creating the two orthogonal proactive watcher tools:
 * - [CreateNotificationWatcherTool] (`create_notification_watcher`, `CREATE_DRAFT`)
 * - [ManageNotificationWatchersTool] (`manage_notification_watchers`, `DATA_READ`)
 */
object NotificationWatcherTools {
    fun createAll(
        watcherPort: NotificationWatcherPort,
        auditLog: AuditLogPort,
        clockMs: () -> Long = System::currentTimeMillis
    ): List<NavaTool> = listOf(
        CreateNotificationWatcherTool(watcherPort, auditLog, clockMs),
        ManageNotificationWatchersTool(watcherPort, auditLog, clockMs)
    )
}

/**
 * [NavaTool] creating a passive zero-battery [NotificationWatcher] rule from natural language
 * (e.g. "Alert me when an email about invoice or package arrives").
 */
class CreateNotificationWatcherTool(
    private val watcherPort: NotificationWatcherPort,
    private val auditLog: AuditLogPort,
    private val clockMs: () -> Long = System::currentTimeMillis
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.CREATE_NOTIFICATION_WATCHER,
        displayNameKey = "tool_create_notification_watcher",
        description = "Creates a proactive offline notification watcher that alerts the user whenever a permitted incoming email, SMS, or app notification matches specified keywords or sender.",
        category = ToolCategory.COMMUNICATION,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "label",
                description = "Short friendly name for the watcher alert rule",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "keywords",
                description = "Comma-separated keywords to watch for in incoming notifications (e.g. 'invoice, package')",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "sender",
                description = "Optional sender name or address substring to match",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "app_name",
                description = "Optional app filter such as gmail, whatsapp, sms, or telegram (omit to watch all permitted apps)",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            )
        ),
        supportsUnattendedRule = false
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        if (ToolArgumentReader.hasUntrustedArgument(arguments) && !context.isUserConfirmed) {
            return ToolArgumentReader.securityFailure("UNTRUSTED_WATCHER_CONFIRMATION_REQUIRED")
        }

        val rawKeywords = ToolArgumentReader.getString(arguments, "keywords")?.value.orEmpty()
        val keywords = rawKeywords
            .split(',', ';', '|')
            .map { Gemma4InputSanitizer.sanitize(it).trim() }
            .filter { it.isNotEmpty() }
            .distinct()
            .take(10)

        val sender = ToolArgumentReader.getString(arguments, "sender")?.value
            ?.let { Gemma4InputSanitizer.sanitize(it).trim() }
            ?.takeIf { it.isNotEmpty() }

        val appName = ToolArgumentReader.getString(arguments, "app_name")?.value
            ?.let { Gemma4InputSanitizer.sanitize(it).trim() }
            ?.takeIf { it.isNotEmpty() && !it.equals("all", ignoreCase = true) && it != "*" }

        if (keywords.isEmpty() && sender == null) {
            return ToolArgumentReader.invalidArgumentsFailure(
                "At least one keyword or sender is required to create a notification watcher"
            )
        }

        val rawLabel = ToolArgumentReader.getString(arguments, "label")?.value
            ?.let { Gemma4InputSanitizer.sanitize(it).trim() }
            ?.takeIf { it.isNotEmpty() }

        val label = rawLabel ?: buildString {
            if (sender != null) append(sender)
            if (keywords.isNotEmpty()) {
                if (isNotEmpty()) append(" - ")
                append(keywords.take(3).joinToString(", "))
            }
        }.take(60)

        val now = clockMs()
        val watcherId = "watch_${UUID.randomUUID().toString().replace("-", "").take(12)}"
        val watcher = NotificationWatcher(
            watcherId = watcherId,
            label = label,
            keywords = keywords,
            senderFilter = sender,
            packageFilter = appName,
            enabled = true,
            createdAtEpochMs = now
        )
        watcherPort.saveWatcher(watcher)

        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = now,
                toolName = metadata.name,
                targetId = ToolTargetIds.NOTIFICATIONS,
                actionSummary = "Created notification watcher $watcherId ($label)",
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "SUCCESS"
            )
        )

        val details = buildList {
            if (keywords.isNotEmpty()) add("Keywords: ${keywords.joinToString(", ")}")
            if (sender != null) add("Sender: $sender")
            if (appName != null) add("App: $appName")
        }.joinToString("\n")

        return ToolResult.Success(
            message = UserMessage(
                key = MessageKey.ACTION_WATCHER_CREATED,
                args = listOf(MessageArg.Text(label))
            ),
            outputValues = mapOf(
                "watcher_id" to watcherId,
                "label" to label,
                "summary" to details
            ),
            outputProvenance = DataProvenance.SYSTEM
        )
    }
}

/**
 * [NavaTool] listing, pausing, resuming, or deleting saved [NotificationWatcher] rules.
 */
class ManageNotificationWatchersTool(
    private val watcherPort: NotificationWatcherPort,
    private val auditLog: AuditLogPort,
    private val clockMs: () -> Long = System::currentTimeMillis
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.MANAGE_NOTIFICATION_WATCHERS,
        displayNameKey = "tool_manage_notification_watchers",
        description = "Lists, pauses, resumes, or deletes proactive notification watchers.",
        category = ToolCategory.COMMUNICATION,
        requiredCapability = AtomicCapability.DATA_READ,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "operation",
                description = "Operation to perform: LIST, DELETE, PAUSE, or RESUME",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "watcher_id",
                description = "Optional watcher ID or label to delete, pause, or resume",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            )
        ),
        supportsUnattendedRule = false
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        val now = clockMs()
        val op = ToolArgumentReader.getString(arguments, "operation")?.value
            ?.trim()?.uppercase(Locale.US) ?: "LIST"
        val query = ToolArgumentReader.getString(arguments, "watcher_id")?.value?.trim()

        if (op == "LIST" || query.isNullOrBlank()) {
            val all = watcherPort.listWatchers()
            val summary = all.joinToString("\n") { w ->
                val stateTag = if (w.enabled) "ON" else "OFF"
                val criteria = buildList {
                    if (w.senderFilter != null) add(w.senderFilter!!)
                    if (w.keywords.isNotEmpty()) add(w.keywords.joinToString(", "))
                    if (w.packageFilter != null) add(w.packageFilter!!)
                }.joinToString(" / ")
                "- [$stateTag] ${w.label}" + if (criteria.isNotEmpty()) " ($criteria)" else ""
            }
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = now,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.NOTIFICATIONS,
                    actionSummary = "Listed ${all.size} notification watchers",
                    provenance = DataProvenance.USER_UTTERANCE,
                    decision = "SUCCESS"
                )
            )
            return ToolResult.Success(
                message = UserMessage(
                    key = MessageKey.ACTION_WATCHERS_LISTED,
                    args = listOf(MessageArg.Number(all.size.toLong()))
                ),
                outputValues = mapOf(
                    "count" to all.size.toString(),
                    "summary" to summary
                ),
                outputProvenance = DataProvenance.SYSTEM
            )
        }

        val all = watcherPort.listWatchers()
        val foldedQuery = NotificationWatcherMatcher.fold(query)
        val matched = all.firstOrNull { it.watcherId == query }
            ?: all.firstOrNull { NotificationWatcherMatcher.fold(it.label).contains(foldedQuery) }
            ?: return ToolArgumentReader.notFoundFailure(query)

        return when (op) {
            "DELETE", "REMOVE", "CANCEL" -> {
                watcherPort.deleteWatcher(matched.watcherId)
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = now,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.NOTIFICATIONS,
                        actionSummary = "Deleted notification watcher ${matched.watcherId}",
                        provenance = DataProvenance.USER_UTTERANCE,
                        decision = "SUCCESS"
                    )
                )
                ToolResult.Success(
                    message = UserMessage(
                        key = MessageKey.ACTION_WATCHER_DELETED,
                        args = listOf(MessageArg.Text(matched.label))
                    ),
                    outputValues = mapOf("watcher_id" to matched.watcherId),
                    outputProvenance = DataProvenance.SYSTEM
                )
            }

            "PAUSE", "DISABLE" -> {
                watcherPort.setWatcherEnabled(matched.watcherId, false)
                ToolResult.Success(
                    message = UserMessage(
                        key = MessageKey.ACTION_WATCHERS_LISTED,
                        args = listOf(MessageArg.Number(1L))
                    ),
                    outputValues = mapOf("watcher_id" to matched.watcherId, "enabled" to "false"),
                    outputProvenance = DataProvenance.SYSTEM
                )
            }

            "RESUME", "ENABLE" -> {
                watcherPort.setWatcherEnabled(matched.watcherId, true)
                ToolResult.Success(
                    message = UserMessage(
                        key = MessageKey.ACTION_WATCHERS_LISTED,
                        args = listOf(MessageArg.Number(1L))
                    ),
                    outputValues = mapOf("watcher_id" to matched.watcherId, "enabled" to "true"),
                    outputProvenance = DataProvenance.SYSTEM
                )
            }

            else -> ToolArgumentReader.invalidArgumentsFailure("Unsupported watcher operation: $op")
        }
    }
}

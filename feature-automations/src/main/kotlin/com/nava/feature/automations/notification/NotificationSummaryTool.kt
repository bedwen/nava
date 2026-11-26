package com.nava.feature.automations.notification

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.automation.NotificationInboxPort
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.PermissionEvaluatorPort
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
import com.nava.feature.automations.common.AutomationIntentGateway
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.ToolArgumentReader
import com.nava.feature.automations.common.ToolTargetIds
import java.text.Normalizer
import java.util.Locale

/**
 * Deterministic, locale-agnostic urgency bucket for captured notifications.
 *
 * Security invariant: Urgency classification is strictly a display grouping heuristic and
 * NEVER elevates provenance above [DataProvenance.UNTRUSTED_EXTERNAL] or triggers tools.
 */
enum class NotificationUrgency {
    URGENT,
    INFO,
    NOISE
}

/**
 * Lightweight, zero-LLM notification urgency classifier used by [NotificationSummaryTool] and
 * `DailyBriefingBuilder`.
 */
object NotificationUrgencyClassifier {
    private val OTP_REGEX = Regex("\\b\\d{4,8}\\b")

    private val URGENT_KEYWORDS = setOf(
        "otp", "code", "verify", "verification", "security", "alert", "urgent",
        "bank", "payment", "delivery", "missed call", "calendar", "meeting"
    )

    private val NOISE_KEYWORDS = setOf(
        "sale", "discount", "offer", "promo", "coupon", "newsletter", "deal"
    )

    fun classify(packageName: String, title: String, body: String): NotificationUrgency {
        val combined = "$title $body".lowercase(Locale.ROOT)
        if (OTP_REGEX.containsMatchIn(combined) || URGENT_KEYWORDS.any { combined.contains(it) }) {
            return NotificationUrgency.URGENT
        }
        if (NOISE_KEYWORDS.any { combined.contains(it) }) {
            return NotificationUrgency.NOISE
        }
        val pkgLower = packageName.lowercase(Locale.ROOT)
        if (pkgLower.contains("messaging") || pkgLower.contains("whatsapp") ||
            pkgLower.contains("signal") || pkgLower.contains("telegram") ||
            pkgLower.contains("dialer") || pkgLower.contains("calendar")
        ) {
            return NotificationUrgency.URGENT
        }
        return NotificationUrgency.INFO
    }
}

/**
 * [NavaTool] adapter for summarizing recent notifications captured from permitted applications.
 *
 * Invariants:
 * - Atomic capability: strictly bound to [AtomicCapability.NOTIFICATION_READ].
 * - Supports unattended background routines when registered.
 * - Always tags output with [DataProvenance.UNTRUSTED_EXTERNAL] so downstream components never
 *   treat notification summaries as trusted user commands.
 * - Double-checks [PermissionEvaluatorPort] per package to enforce immediate revocation.
 * - Records every execution in [AuditLogPort].
 */
class NotificationSummaryTool(
    private val inbox: NotificationInboxPort,
    private val permissionEvaluator: PermissionEvaluatorPort,
    private val auditLog: AuditLogPort,
    private val intentGateway: AutomationIntentGateway? = null
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.SUMMARIZE_NOTIFICATIONS,
        displayNameKey = "tool_summarize_notifications_name",
        description = "Summarizes recent notifications captured from permitted applications",
        category = ToolCategory.COMMUNICATION,
        requiredCapability = AtomicCapability.NOTIFICATION_READ,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "package_name",
                description = "Optional application name or package filter (omit to read all permitted apps)",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "limit",
                description = "Maximum number of notifications to summarize",
                required = false,
                slotKind = SensitiveSlotKind.DURATION,
                valueType = SlotValueType.INTEGER
            ),
            ToolSchemaField(
                name = "since_epoch_ms",
                description = "Optional timestamp filter in epoch milliseconds",
                required = false,
                slotKind = SensitiveSlotKind.DURATION,
                valueType = SlotValueType.INTEGER
            )
        ),
        supportsUnattendedRule = true
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        val rawPackageArg = ToolArgumentReader.getString(arguments, "package_name")?.value?.trim()?.takeIf { it.isNotEmpty() }
        val limit = (ToolArgumentReader.getInt(arguments, "limit")?.value
            ?: NotificationInboxPort.DEFAULT_LIMIT)
            .coerceIn(1, MAX_SUMMARY_LIMIT)
        val sinceEpochMs = ToolArgumentReader.getLong(arguments, "since_epoch_ms")?.value

        NotificationServiceBinding.requestActiveNotificationsResync()

        val resolvedPackages: Set<String>? = if (rawPackageArg != null) {
            resolvePackageFilter(rawPackageArg)
        } else {
            null
        }

        if (resolvedPackages != null && resolvedPackages.isNotEmpty()) {
            val anyAllowed = resolvedPackages.any { pkg ->
                permissionEvaluator.evaluateCapability(
                    ToolTargetIds.forPackage(pkg),
                    AtomicCapability.NOTIFICATION_READ
                ).isAllowed
            }
            if (!anyAllowed) {
                val primaryTarget = ToolTargetIds.forPackage(resolvedPackages.first())
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = context.issuedAtEpochMs,
                        toolName = metadata.name,
                        targetId = primaryTarget,
                        actionSummary = "Notification summary access denied for package ${resolvedPackages.first()}",
                        provenance = DataProvenance.SYSTEM,
                        decision = "PERMISSION_DENIED"
                    )
                )
                return ToolResult.Failure(
                    message = UserMessage(
                        key = MessageKey.ERROR_PERMISSION_DENIED,
                        args = listOf(MessageArg.Text(resolvedPackages.first()))
                    ),
                    errorCode = "PERMISSION_DENIED",
                    isSecurityViolation = true
                )
            }
        }

        val packageFilter = resolvedPackages?.takeIf { it.isNotEmpty() }
        val candidates = inbox.listRecent(
            packageFilter = packageFilter,
            sinceEpochMs = sinceEpochMs,
            limit = limit
        )

        // Double check permission evaluator per package
        val permitted = candidates.filter { item ->
            val itemTarget = ToolTargetIds.forPackage(item.packageName)
            permissionEvaluator.evaluateCapability(itemTarget, AtomicCapability.NOTIFICATION_READ).isAllowed
        }

        if (permitted.isEmpty()) {
            val hasAnyPermittedNotificationTarget = if (packageFilter != null) {
                true
            } else {
                permissionEvaluator.listProfiles().any { profile ->
                    profile.levelFor(AtomicCapability.NOTIFICATION_READ).isAllowed &&
                        profile.assignedTargets.any { isAppPackageTarget(it) }
                }
            }
            val emptyMessageKey = if (hasAnyPermittedNotificationTarget) {
                MessageKey.ACTION_NOTIFICATIONS_EMPTY
            } else {
                MessageKey.INFO_NO_PERMITTED_NOTIFICATION_APPS
            }
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = context.issuedAtEpochMs,
                    toolName = metadata.name,
                    targetId = context.targetId,
                    actionSummary = if (hasAnyPermittedNotificationTarget) {
                        "Summarized 0 notifications"
                    } else {
                        "No apps have NOTIFICATION_READ permission"
                    },
                    provenance = DataProvenance.UNTRUSTED_EXTERNAL,
                    decision = "SUCCESS"
                )
            )
            return ToolResult.Success(
                message = UserMessage(emptyMessageKey),
                outputValues = mapOf(
                    "count" to "0",
                    "summary" to "",
                    "has_permitted_apps" to hasAnyPermittedNotificationTarget.toString()
                ),
                outputProvenance = DataProvenance.UNTRUSTED_EXTERNAL
            )
        }

        val grouped = LinkedHashMap<NotificationUrgency, MutableList<String>>(3)
        for (item in permitted) {
            val cleanTitle = Gemma4InputSanitizer.sanitize(item.title.value)
                .replace('\r', ' ')
                .replace('\n', ' ')
                .trim()
            val cleanBody = Gemma4InputSanitizer.sanitize(item.body.value)
                .replace('\r', ' ')
                .replace('\n', ' ')
                .trim()
            val urgency = NotificationUrgencyClassifier.classify(item.packageName, cleanTitle, cleanBody)
            val line = "[${item.packageName}] $cleanTitle: $cleanBody"
            grouped.getOrPut(urgency) { ArrayList() }.add(line)
        }

        val summaryBuilder = StringBuilder()
        val orderedBuckets = listOf(
            NotificationUrgency.URGENT to "[URGENT]",
            NotificationUrgency.INFO to "[INFO]",
            NotificationUrgency.NOISE to "[NOISE]"
        )
        for ((bucket, header) in orderedBuckets) {
            val lines = grouped[bucket].orEmpty()
            if (lines.isEmpty()) continue
            if (summaryBuilder.isNotEmpty()) {
                summaryBuilder.append("\n")
            }
            summaryBuilder.append(header)
            for (line in lines) {
                summaryBuilder.append("\n").append(line)
            }
        }
        val summaryText = summaryBuilder.toString()

        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = context.issuedAtEpochMs,
                toolName = metadata.name,
                targetId = context.targetId,
                actionSummary = "Summarized ${permitted.size} notifications",
                provenance = DataProvenance.UNTRUSTED_EXTERNAL,
                decision = "SUCCESS"
            )
        )

        return ToolResult.Success(
            message = UserMessage(
                key = MessageKey.ACTION_NOTIFICATIONS_SUMMARIZED,
                args = listOf(MessageArg.Number(permitted.size.toLong()))
            ),
            outputValues = mapOf(
                "count" to permitted.size.toString(),
                "summary" to summaryText
            ),
            outputProvenance = DataProvenance.UNTRUSTED_EXTERNAL
        )
    }

    private fun resolvePackageFilter(rawArg: String): Set<String>? {
        if ('.' in rawArg) {
            return setOf(rawArg)
        }
        val exactResolved = intentGateway?.resolveLaunchablePackage(rawArg)
        if (!exactResolved.isNullOrBlank()) {
            return setOf(exactResolved)
        }
        val foldedQuery = foldLabelForMatch(rawArg)
        if (foldedQuery.isEmpty()) return null
        val matched = LinkedHashSet<String>()
        val installed = intentGateway?.listLaunchableApps().orEmpty()
        for (app in installed) {
            val foldedLabel = foldLabelForMatch(app.displayLabel)
            val foldedPkg = app.packageName.lowercase(Locale.ROOT)
            if (foldedLabel.contains(foldedQuery) || foldedPkg.contains(foldedQuery)) {
                matched.add(app.packageName)
            }
        }
        return if (matched.isNotEmpty()) matched else null
    }

    private fun foldLabelForMatch(raw: String): String {
        val replaced = raw.replace('\u0131', 'i').replace('\u0130', 'I')
        val decomposed = Normalizer.normalize(replaced, Normalizer.Form.NFKD)
        val sb = StringBuilder(decomposed.length)
        for (ch in decomposed) {
            if (Character.getType(ch) != Character.NON_SPACING_MARK.toInt()) {
                sb.append(ch.lowercaseChar())
            }
        }
        return sb.toString().trim()
    }

    private fun isAppPackageTarget(targetId: String): Boolean {
        val trimmed = targetId.trim()
        if (trimmed.isEmpty()) return false
        return !trimmed.startsWith("system.") &&
            !trimmed.startsWith("nava.") &&
            !trimmed.startsWith("saf:")
    }

    companion object {
        const val MAX_SUMMARY_LIMIT: Int = 50
    }
}

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
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.ToolArgumentReader
import com.nava.feature.automations.common.ToolTargetIds

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
    private val auditLog: AuditLogPort
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
                description = "Optional package name filter",
                required = false,
                slotKind = SensitiveSlotKind.PACKAGE_NAME,
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
        val packageName = ToolArgumentReader.getString(arguments, "package_name")?.value
        val limit = ToolArgumentReader.getInt(arguments, "limit")?.value
            ?: NotificationInboxPort.DEFAULT_LIMIT
        val sinceEpochMs = ToolArgumentReader.getLong(arguments, "since_epoch_ms")?.value

        if (packageName != null) {
            val targetId = ToolTargetIds.forPackage(packageName)
            val level = permissionEvaluator.evaluateCapability(targetId, AtomicCapability.NOTIFICATION_READ)
            if (!level.isAllowed) {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = context.issuedAtEpochMs,
                        toolName = metadata.name,
                        targetId = targetId,
                        actionSummary = "Notification summary access denied for package $packageName",
                        provenance = DataProvenance.SYSTEM,
                        decision = "PERMISSION_DENIED"
                    )
                )
                return ToolResult.Failure(
                    message = UserMessage(
                        key = MessageKey.ERROR_PERMISSION_DENIED,
                        args = listOf(MessageArg.Text(packageName))
                    ),
                    errorCode = "PERMISSION_DENIED",
                    isSecurityViolation = true
                )
            }
        }

        val packageFilter = if (packageName != null) setOf(packageName) else null
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
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = context.issuedAtEpochMs,
                    toolName = metadata.name,
                    targetId = context.targetId,
                    actionSummary = "Summarized 0 notifications",
                    provenance = DataProvenance.UNTRUSTED_EXTERNAL,
                    decision = "SUCCESS"
                )
            )
            return ToolResult.Success(
                message = UserMessage(MessageKey.ACTION_NOTIFICATIONS_EMPTY),
                outputValues = mapOf(
                    "count" to "0",
                    "summary" to ""
                ),
                outputProvenance = DataProvenance.UNTRUSTED_EXTERNAL
            )
        }

        val summaryBuilder = StringBuilder()
        for (item in permitted) {
            val cleanTitle = Gemma4InputSanitizer.sanitize(item.title.value)
            val cleanBody = Gemma4InputSanitizer.sanitize(item.body.value)
            if (summaryBuilder.isNotEmpty()) {
                summaryBuilder.append("\n")
            }
            summaryBuilder.append("[").append(item.packageName).append("] ")
            summaryBuilder.append(cleanTitle).append(": ").append(cleanBody)
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
}

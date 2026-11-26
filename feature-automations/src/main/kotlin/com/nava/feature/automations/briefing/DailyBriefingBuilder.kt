package com.nava.feature.automations.briefing

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.automation.MorningBriefingConfig
import com.nava.domain.automation.NotificationInboxPort
import com.nava.domain.automation.ScheduledReminder
import com.nava.domain.automation.ScheduledReminderPort
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.PermissionEvaluatorPort
import com.nava.domain.security.Tainted
import com.nava.domain.tool.NavaTool
import com.nava.domain.tool.ToolCategory
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.CalendarGatewayResult
import com.nava.feature.automations.common.CalendarPlatformGateway
import com.nava.feature.automations.common.ToolTargetIds
import com.nava.feature.automations.notification.NotificationUrgency
import com.nava.feature.automations.notification.NotificationUrgencyClassifier
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Structured zero-AI Morning Briefing payload assembled deterministically in <200ms with 0% LLM cost.
 */
data class DailyBriefingResult(
    val calendarLines: List<String>,
    val reminderLines: List<String>,
    val urgentNotificationLines: List<String>,
    val infoNotificationLines: List<String>,
    val renderedText: String,
    val hasUntrustedExternalContent: Boolean,
    val totalItemCount: Int
)

/**
 * Deterministic, zero-LLM daily briefing assembler combining:
 * 1. Today's calendar events (only when `CalendarPlatformGateway` is permitted and enabled)
 * 2. Active scheduled reminders due within the next 24 hours
 * 3. Permitted recent notifications grouped into Urgent / Info (always sanitized and tagged
 *    `UNTRUSTED_EXTERNAL` - never trusted as commands)
 */
class DailyBriefingBuilder(
    private val reminderPort: ScheduledReminderPort,
    private val notificationInbox: NotificationInboxPort,
    private val permissionEvaluator: PermissionEvaluatorPort,
    private val calendarGateway: CalendarPlatformGateway? = null,
    private val timeZone: TimeZone = TimeZone.getDefault()
) {

    suspend fun buildBriefing(
        nowEpochMs: Long,
        config: MorningBriefingConfig = MorningBriefingConfig(enabled = true)
    ): DailyBriefingResult {
        val endOfWindowMs = nowEpochMs + ScheduledReminder.MILLIS_PER_DAY
        val timeFmt = SimpleDateFormat("HH:mm", Locale.US).apply { this.timeZone = this@DailyBriefingBuilder.timeZone }

        val calendarLines = ArrayList<String>()
        var hasUntrusted = false
        if (config.includeCalendar && calendarGateway != null) {
            val calAllowed = permissionEvaluator.evaluateCapability(
                ToolTargetIds.CALENDAR,
                AtomicCapability.DATA_READ
            ).isAllowed
            if (calAllowed) {
                val startOfDayMs = startOfLocalDayEpochMs(nowEpochMs)
                val endOfDayMs = startOfDayMs + ScheduledReminder.MILLIS_PER_DAY
                val calResult = calendarGateway.queryEvents(startOfDayMs, endOfDayMs)
                if (calResult is CalendarGatewayResult.Success) {
                    for (ev in calResult.value.sortedBy { it.startEpochMs }.take(MAX_ITEMS_PER_SECTION)) {
                        val timeStr = timeFmt.format(Date(ev.startEpochMs))
                        val cleanTitle = flattenSingleLine(Gemma4InputSanitizer.sanitize(ev.title))
                        if (cleanTitle.isNotEmpty()) {
                            calendarLines.add("$timeStr - $cleanTitle")
                            hasUntrusted = true
                        }
                    }
                }
            }
        }

        val reminderLines = ArrayList<String>()
        if (config.includeReminders) {
            val remindersAllowed = permissionEvaluator.evaluateCapability(
                ToolTargetIds.REMINDERS,
                AtomicCapability.DATA_READ
            ).isAllowed || permissionEvaluator.evaluateCapability(
                ToolTargetIds.CLOCK,
                AtomicCapability.DATA_READ
            ).isAllowed
            if (remindersAllowed) {
                val startOfDayMs = startOfLocalDayEpochMs(nowEpochMs)
                val active = runCatching { reminderPort.listActiveReminders() }
                    .getOrDefault(emptyList())
                    .filter { it.triggerAtEpochMs in startOfDayMs..endOfWindowMs }
                    .take(MAX_ITEMS_PER_SECTION)
                for (rem in active) {
                    val timeStr = timeFmt.format(Date(rem.triggerAtEpochMs))
                    val cleanTitle = flattenSingleLine(Gemma4InputSanitizer.sanitize(rem.title))
                    if (cleanTitle.isNotEmpty()) {
                        reminderLines.add("$timeStr - $cleanTitle")
                    }
                }
            }
        }

        val urgentLines = ArrayList<String>()
        val infoLines = ArrayList<String>()
        if (config.includeNotifications) {
            val sinceMs = nowEpochMs - BRIEFING_NOTIFICATION_LOOKBACK_MS
            val recent = notificationInbox.listRecent(
                packageFilter = null,
                sinceEpochMs = sinceMs,
                limit = MAX_NOTIFICATION_SCAN
            )
            for (item in recent) {
                val itemTarget = ToolTargetIds.forPackage(item.packageName)
                if (!permissionEvaluator.evaluateCapability(itemTarget, AtomicCapability.NOTIFICATION_READ).isAllowed) {
                    continue
                }
                hasUntrusted = true
                val cleanTitle = flattenSingleLine(Gemma4InputSanitizer.sanitize(item.title.value))
                val cleanBody = flattenSingleLine(Gemma4InputSanitizer.sanitize(item.body.value))
                val urgency = NotificationUrgencyClassifier.classify(item.packageName, cleanTitle, cleanBody)
                val line = "[${item.packageName}] $cleanTitle: $cleanBody".take(MAX_LINE_CHARS)
                when (urgency) {
                    NotificationUrgency.URGENT -> if (urgentLines.size < MAX_ITEMS_PER_SECTION) urgentLines.add(line)
                    NotificationUrgency.INFO -> if (infoLines.size < MAX_ITEMS_PER_SECTION) infoLines.add(line)
                    NotificationUrgency.NOISE -> Unit
                }
            }
        }

        val sb = StringBuilder()
        if (calendarLines.isNotEmpty()) {
            sb.append("[CALENDAR]\n")
            calendarLines.forEach { sb.append("- ").append(it).append("\n") }
        }
        if (reminderLines.isNotEmpty()) {
            if (sb.isNotEmpty()) sb.append("\n")
            sb.append("[REMINDERS]\n")
            reminderLines.forEach { sb.append("- ").append(it).append("\n") }
        }
        if (urgentLines.isNotEmpty()) {
            if (sb.isNotEmpty()) sb.append("\n")
            sb.append("[URGENT]\n")
            urgentLines.forEach { sb.append("- ").append(it).append("\n") }
        }
        if (infoLines.isNotEmpty()) {
            if (sb.isNotEmpty()) sb.append("\n")
            sb.append("[INFO]\n")
            infoLines.forEach { sb.append("- ").append(it).append("\n") }
        }

        val totalCount = calendarLines.size + reminderLines.size + urgentLines.size + infoLines.size
        return DailyBriefingResult(
            calendarLines = calendarLines,
            reminderLines = reminderLines,
            urgentNotificationLines = urgentLines,
            infoNotificationLines = infoLines,
            renderedText = sb.toString().trim(),
            hasUntrustedExternalContent = hasUntrusted,
            totalItemCount = totalCount
        )
    }

    private fun flattenSingleLine(input: String): String {
        return input.replace('\r', ' ').replace('\n', ' ').trim()
    }

    private fun startOfLocalDayEpochMs(nowEpochMs: Long): Long {
        val cal = Calendar.getInstance(timeZone).apply {
            timeInMillis = nowEpochMs
            set(Calendar.HOUR_OF_DAY, 0)
            set(Calendar.MINUTE, 0)
            set(Calendar.SECOND, 0)
            set(Calendar.MILLISECOND, 0)
        }
        return cal.timeInMillis
    }

    companion object {
        private const val MAX_ITEMS_PER_SECTION: Int = 6
        private const val MAX_NOTIFICATION_SCAN: Int = 24
        private const val MAX_LINE_CHARS: Int = 140
        private const val BRIEFING_NOTIFICATION_LOOKBACK_MS: Long = 12L * 3_600_000L
    }
}

/**
 * [NavaTool] adapter exposing the zero-AI Morning Briefing on demand from the Hub or routines.
 *
 * Whenever notifications are included, output provenance is strictly [DataProvenance.UNTRUSTED_EXTERNAL].
 */
class DailyBriefingTool(
    private val builder: DailyBriefingBuilder,
    private val auditLog: AuditLogPort,
    private val configProvider: () -> MorningBriefingConfig = { MorningBriefingConfig(enabled = true) },
    private val clock: () -> Long = System::currentTimeMillis
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.DAILY_BRIEFING,
        displayNameKey = "tool_daily_briefing_name",
        description = "Generates the morning or daily briefing schedule overview (use only when user asks for a daily briefing, not to read a specific notification)",
        category = ToolCategory.COMMUNICATION,
        requiredCapability = AtomicCapability.NOTIFICATION_READ,
        schemaVersion = 1,
        fields = emptyList(),
        supportsUnattendedRule = true
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        val now = clock()
        val result = builder.buildBriefing(nowEpochMs = now, config = configProvider())
        val outputProvenance = if (result.hasUntrustedExternalContent) {
            DataProvenance.UNTRUSTED_EXTERNAL
        } else {
            DataProvenance.SYSTEM
        }

        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = now,
                toolName = metadata.name,
                targetId = ToolTargetIds.NOTIFICATIONS,
                actionSummary = "Assembled daily briefing (${result.totalItemCount} items)",
                provenance = outputProvenance,
                decision = "SUCCESS"
            )
        )

        return ToolResult.Success(
            message = UserMessage(
                key = MessageKey.ACTION_BRIEFING_READY,
                args = listOf(MessageArg.Number(result.totalItemCount.toLong()))
            ),
            outputValues = mapOf(
                "count" to result.totalItemCount.toString(),
                "summary" to result.renderedText
            ),
            outputProvenance = outputProvenance
        )
    }
}

package com.nava.feature.automations.reminder

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.automation.ReminderRecurrence
import com.nava.domain.automation.ReminderSchedulerPort
import com.nava.domain.automation.ReminderStatus
import com.nava.domain.automation.ScheduledReminder
import com.nava.domain.automation.ScheduledReminderPort
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
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID

/**
 * Factory creating the two orthogonal zero-battery reminder [NavaTool] adapters:
 * - [ScheduleReminderTool] (`schedule_reminder`, [AtomicCapability.CREATE_DRAFT], unattended-safe)
 * - [CancelReminderTool] (`cancel_reminder`, [AtomicCapability.MODIFY_DELETE_SEND], interactive)
 */
object ReminderTools {
    fun createAll(
        reminderPort: ScheduledReminderPort,
        schedulerPort: ReminderSchedulerPort,
        auditLog: AuditLogPort,
        clock: () -> Long = System::currentTimeMillis
    ): List<NavaTool> = listOf(
        ScheduleReminderTool(reminderPort, schedulerPort, auditLog, clock),
        CancelReminderTool(reminderPort, schedulerPort, auditLog, clock)
    )
}

/**
 * [NavaTool] adapter scheduling a zero-battery local reminder persisted in AES-256-GCM storage
 * and backed by Android `AlarmManager` (via [ReminderSchedulerPort]).
 */
class ScheduleReminderTool(
    private val reminderPort: ScheduledReminderPort,
    private val schedulerPort: ReminderSchedulerPort,
    private val auditLog: AuditLogPort,
    private val clock: () -> Long = System::currentTimeMillis
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.SCHEDULE_REMINDER,
        displayNameKey = "tool_schedule_reminder_name",
        description = "Schedules an offline reminder notification in seconds, minutes, or at a specific time (prefer this over set_timer whenever the user asks for a reminder).",
        category = ToolCategory.TIME_CALENDAR,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "title",
                description = "Reminder title or text to display",
                required = true,
                slotKind = SensitiveSlotKind.EVENT_TITLE,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "trigger_at_iso",
                description = "ISO-8601 local date-time (YYYY-MM-DDTHH:MM:SS) when the reminder should fire",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.ISO_DATETIME
            ),
            ToolSchemaField(
                name = "delay_minutes",
                description = "Relative delay in minutes from now (e.g. 15); use delay_seconds for seconds",
                required = false,
                slotKind = SensitiveSlotKind.DURATION,
                valueType = SlotValueType.INTEGER
            ),
            ToolSchemaField(
                name = "delay_seconds",
                description = "Relative delay in seconds from now (e.g. 10 or 30)",
                required = false,
                slotKind = SensitiveSlotKind.DURATION,
                valueType = SlotValueType.INTEGER
            ),
            ToolSchemaField(
                name = "recurrence",
                description = "Recurrence cadence: ONCE, DAILY, or WEEKLY",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "message",
                description = "Optional extra note body for the reminder",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            )
        ),
        supportsUnattendedRule = true
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        if (ToolArgumentReader.hasVaultSourceArgument(arguments) && !context.isUserConfirmed) {
            return ToolArgumentReader.securityFailure("VAULT_TAINT_CONFIRMATION_REQUIRED")
        }
        if (ToolArgumentReader.hasUntrustedArgument(arguments) && !context.isUserConfirmed) {
            return ToolArgumentReader.securityFailure("UNTRUSTED_REMINDER_CONFIRMATION_REQUIRED")
        }
        val rawTitle = ToolArgumentReader.getString(arguments, "title")?.value
            ?: return ToolArgumentReader.invalidArgumentsFailure("title is required")
        val title = Gemma4InputSanitizer.sanitize(rawTitle).trim()
        if (title.isEmpty()) {
            return ToolArgumentReader.invalidArgumentsFailure("title must not be blank")
        }
        val rawMessage = ToolArgumentReader.getString(arguments, "message")?.value.orEmpty()
        val message = Gemma4InputSanitizer.sanitize(rawMessage).trim()

        val now = clock()
        val triggerIso = ToolArgumentReader.getString(arguments, "trigger_at_iso")?.value
        val delayMinutes = ToolArgumentReader.getLong(arguments, "delay_minutes")?.value
        val delaySeconds = ToolArgumentReader.getLong(arguments, "delay_seconds")?.value

        val totalDelayMs = ((delayMinutes ?: 0L).coerceAtLeast(0L) * ScheduledReminder.MILLIS_PER_MINUTE) +
            ((delaySeconds ?: 0L).coerceAtLeast(0L) * 1_000L)

        val triggerAtEpochMs = when {
            triggerIso != null -> parseLocalIsoDateTime(triggerIso)
                ?: return ToolArgumentReader.invalidArgumentsFailure("Invalid trigger_at_iso format")
            totalDelayMs > 0L -> now + totalDelayMs
            else -> return ToolArgumentReader.invalidArgumentsFailure(
                "Either trigger_at_iso, positive delay_minutes, or positive delay_seconds is required"
            )
        }

        val effectiveTriggerMs = if (triggerAtEpochMs <= now) {
            now + ScheduledReminder.MILLIS_PER_MINUTE
        } else {
            triggerAtEpochMs
        }

        val recurrenceRaw = ToolArgumentReader.getString(arguments, "recurrence")?.value
            ?.trim()?.uppercase(Locale.US)
        val recurrence = when (recurrenceRaw) {
            null, "", "ONCE", "NONE" -> ReminderRecurrence.ONCE
            "DAILY", "EVERY_DAY" -> ReminderRecurrence.DAILY
            "WEEKLY", "EVERY_WEEK" -> ReminderRecurrence.WEEKLY
            else -> return ToolArgumentReader.invalidArgumentsFailure("Unsupported recurrence: $recurrenceRaw")
        }

        val reminderId = "rem_${UUID.randomUUID().toString().replace("-", "").take(12)}"
        val reminder = ScheduledReminder(
            reminderId = reminderId,
            title = title,
            message = message,
            triggerAtEpochMs = effectiveTriggerMs,
            recurrence = recurrence,
            status = ReminderStatus.ACTIVE,
            createdAtEpochMs = now,
            updatedAtEpochMs = now
        )

        val provenance = if (context.isUnattendedBackground) DataProvenance.SYSTEM else DataProvenance.USER_UTTERANCE
        reminderPort.saveReminder(reminder)
        val scheduled = schedulerPort.scheduleReminder(reminder)
        if (!scheduled) {
            reminderPort.deleteReminder(reminderId)
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = now,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.REMINDERS,
                    actionSummary = "Failed to schedule reminder alarm for $reminderId",
                    provenance = provenance,
                    decision = "PLATFORM_UNAVAILABLE"
                )
            )
            return ToolArgumentReader.platformUnavailableFailure("AlarmManager unavailable")
        }

        val formattedIso = formatLocalIsoDateTime(effectiveTriggerMs)
        val timePart = formattedIso.substringAfter('T')
        val displayTime = if (delaySeconds != null && delaySeconds > 0L) {
            timePart.take(8)
        } else {
            timePart.take(5)
        }
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = now,
                toolName = metadata.name,
                targetId = ToolTargetIds.REMINDERS,
                actionSummary = "Scheduled reminder $reminderId (${recurrence.name})",
                provenance = provenance,
                decision = "SUCCESS"
            )
        )

        return ToolResult.Success(
            message = UserMessage(
                key = MessageKey.ACTION_REMINDER_SCHEDULED,
                args = listOf(
                    MessageArg.Text(title),
                    MessageArg.IsoTime(displayTime)
                )
            ),
            outputValues = mapOf(
                "reminder_id" to reminderId,
                "title" to title,
                "trigger_at_epoch_ms" to effectiveTriggerMs.toString(),
                "trigger_at_iso" to formattedIso,
                "recurrence" to recurrence.name
            ),
            outputProvenance = DataProvenance.SYSTEM
        )
    }

    companion object {
        private val ISO_PATTERNS = listOf(
            "yyyy-MM-dd'T'HH:mm:ss",
            "yyyy-MM-dd'T'HH:mm",
            "yyyy-MM-dd HH:mm:ss",
            "yyyy-MM-dd HH:mm"
        )

        internal fun parseLocalIsoDateTime(
            iso: String,
            timeZone: TimeZone = TimeZone.getDefault()
        ): Long? {
            val cleaned = iso.trim().removeSuffix("Z")
            for (pattern in ISO_PATTERNS) {
                val sdf = SimpleDateFormat(pattern, Locale.US).apply {
                    this.timeZone = timeZone
                    isLenient = false
                }
                val parsed = runCatching { sdf.parse(cleaned)?.time }.getOrNull()
                if (parsed != null) return parsed
            }
            return null
        }

        internal fun formatLocalIsoDateTime(
            epochMs: Long,
            timeZone: TimeZone = TimeZone.getDefault()
        ): String {
            val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US).apply {
                this.timeZone = timeZone
            }
            return sdf.format(Date(epochMs))
        }
    }
}

/**
 * [NavaTool] adapter cancelling an active [ScheduledReminder] by ID or title match.
 */
class CancelReminderTool(
    private val reminderPort: ScheduledReminderPort,
    private val schedulerPort: ReminderSchedulerPort,
    private val auditLog: AuditLogPort,
    private val clock: () -> Long = System::currentTimeMillis
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.CANCEL_REMINDER,
        displayNameKey = "tool_cancel_reminder_name",
        description = "Cancels a scheduled offline reminder by ID or title",
        category = ToolCategory.TIME_CALENDAR,
        requiredCapability = AtomicCapability.MODIFY_DELETE_SEND,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "reminder_id",
                description = "Exact reminder ID to cancel",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "title",
                description = "Title or keyword of the reminder to cancel",
                required = false,
                slotKind = SensitiveSlotKind.EVENT_TITLE,
                valueType = SlotValueType.STRING
            )
        ),
        supportsUnattendedRule = false
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        val reminderIdArg = ToolArgumentReader.getString(arguments, "reminder_id")?.value
        val titleArg = ToolArgumentReader.getString(arguments, "title")?.value

        val target: ScheduledReminder? = when {
            reminderIdArg != null -> reminderPort.findReminder(reminderIdArg)
            titleArg != null -> {
                val needle = titleArg.lowercase(Locale.ROOT)
                reminderPort.listActiveReminders().firstOrNull { rem ->
                    rem.title.lowercase(Locale.ROOT).contains(needle)
                }
            }
            else -> return ToolArgumentReader.invalidArgumentsFailure("reminder_id or title is required")
        }

        if (target == null) {
            return ToolResult.Failure(
                message = UserMessage(
                    key = MessageKey.ERROR_NOT_FOUND,
                    args = listOf(MessageArg.Text(reminderIdArg ?: titleArg.orEmpty()))
                ),
                errorCode = ToolArgumentReader.ERROR_NOT_FOUND
            )
        }

        val now = clock()
        reminderPort.updateStatus(target.reminderId, ReminderStatus.CANCELLED, now)
        schedulerPort.cancelReminder(target.reminderId)

        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = now,
                toolName = metadata.name,
                targetId = ToolTargetIds.REMINDERS,
                actionSummary = "Cancelled reminder ${target.reminderId}",
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "SUCCESS"
            )
        )

        return ToolResult.Success(
            message = UserMessage(
                key = MessageKey.ACTION_REMINDER_CANCELLED,
                args = listOf(MessageArg.Text(target.title))
            ),
            outputValues = mapOf(
                "reminder_id" to target.reminderId,
                "title" to target.title
            ),
            outputProvenance = DataProvenance.SYSTEM
        )
    }
}

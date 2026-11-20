package com.nava.feature.automations.alarm

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.SecurityFirewallPort
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
import com.nava.feature.automations.common.AutomationOutboundActions
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.PlatformDispatchResult
import com.nava.feature.automations.common.ToolArgumentReader
import com.nava.feature.automations.common.ToolTargetIds
import java.util.Locale

/**
 * Composite adapter exposing orthogonal [NavaTool] implementations for clock automation:
 * [SetAlarmTool] and [SetTimerTool].
 */
class AlarmTimerTool(
    private val intentGateway: AutomationIntentGateway,
    private val firewall: SecurityFirewallPort,
    private val auditLog: AuditLogPort,
    private val clock: () -> Long = System::currentTimeMillis
) : Iterable<NavaTool> {

    val setAlarmTool: NavaTool = SetAlarmTool(intentGateway, firewall, auditLog, clock)
    val setTimerTool: NavaTool = SetTimerTool(intentGateway, firewall, auditLog, clock)

    fun allTools(): List<NavaTool> = listOf(setAlarmTool, setTimerTool)

    override fun iterator(): Iterator<NavaTool> = allTools().iterator()
}

/**
 * Atomic tool for creating clock alarms ([AutomationToolNames.SET_ALARM]).
 * Supports Tier 1 rule arguments (hour, minute, meridiem, period_keyword, label)
 * as well as canonical ISO/HH:mm time arguments.
 */
class SetAlarmTool(
    private val intentGateway: AutomationIntentGateway,
    private val firewall: SecurityFirewallPort,
    private val auditLog: AuditLogPort,
    private val clock: () -> Long = System::currentTimeMillis
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.SET_ALARM,
        displayNameKey = "tool_set_alarm",
        description = "Sets a system clock alarm for a specified hour and minute.",
        category = ToolCategory.TIME_CALENDAR,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "hour",
                description = "Hour of day (0-23 or 1-12 with meridiem)",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.INTEGER
            ),
            ToolSchemaField(
                name = "minute",
                description = "Minute of hour (0-59)",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.INTEGER
            ),
            ToolSchemaField(
                name = "time",
                description = "Time string in HH:mm format",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.ISO_TIME
            ),
            ToolSchemaField(
                name = "meridiem",
                description = "AM or PM indicator",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "period_keyword",
                description = "Day period (morning, evening, night)",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "label",
                description = "Optional alarm label",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "skip_ui",
                description = "Whether to set the alarm silently without foregrounding clock UI",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.BOOLEAN
            )
        ),
        supportsUnattendedRule = true
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        val nowMs = clock()
        val worstProvenance = ToolArgumentReader.worstProvenance(arguments)

        if (ToolArgumentReader.hasVaultSourceArgument(arguments)) {
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.CLOCK,
                    actionSummary = "Blocked alarm with vault taint",
                    provenance = worstProvenance,
                    decision = "VAULT_EXFILTRATION_BLOCKED"
                )
            )
            return ToolArgumentReader.securityFailure("VAULT_DATA_EXFILTRATION_BLOCKED")
        }

        val parsedTime = parseTime(arguments)
        if (parsedTime == null) {
            val failure = ToolArgumentReader.invalidArgumentsFailure("Invalid or missing alarm time")
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.CLOCK,
                    actionSummary = "Invalid alarm arguments",
                    provenance = worstProvenance,
                    decision = failure.errorCode
                )
            )
            return failure
        }

        val (hour, minute) = parsedTime
        val label = ToolArgumentReader.getString(arguments, "label")?.value
        val skipUi = ToolArgumentReader.getBoolean(arguments, "skip_ui")?.value ?: false

        val firewallDecision = firewall.validateOutboundTarget(
            toolName = metadata.name,
            action = AutomationOutboundActions.ACTION_SET_ALARM,
            uriOrTarget = Tainted.fromSystem("")
        )

        when (firewallDecision) {
            is FirewallDecision.Denied -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CLOCK,
                        actionSummary = "Firewall denied alarm: ${firewallDecision.reasonCode}",
                        provenance = worstProvenance,
                        decision = firewallDecision.reasonCode
                    )
                )
                return ToolResult.Failure(
                    message = firewallDecision.message,
                    errorCode = firewallDecision.reasonCode,
                    isSecurityViolation = true
                )
            }
            is FirewallDecision.RequiresConfirmation -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CLOCK,
                        actionSummary = "Alarm requires interactive confirmation",
                        provenance = worstProvenance,
                        decision = "CONFIRMATION_REQUIRED"
                    )
                )
                return ToolResult.ConfirmationRequired(
                    message = firewallDecision.message,
                    pendingToolName = metadata.name,
                    targetId = ToolTargetIds.CLOCK,
                    canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                    requiresBiometric = false,
                    hasUntrustedHighRiskSlot = false
                )
            }
            is FirewallDecision.RequiresBiometric -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CLOCK,
                        actionSummary = "Alarm requires biometric confirmation",
                        provenance = worstProvenance,
                        decision = "BIOMETRIC_REQUIRED"
                    )
                )
                return ToolResult.ConfirmationRequired(
                    message = firewallDecision.message,
                    pendingToolName = metadata.name,
                    targetId = ToolTargetIds.CLOCK,
                    canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                    requiresBiometric = true,
                    hasUntrustedHighRiskSlot = false
                )
            }
            FirewallDecision.Authorized -> Unit
        }

        return when (val dispatch = intentGateway.dispatchSetAlarm(hour, minute, label, skipUi)) {
            is PlatformDispatchResult.Dispatched -> {
                val timeString = "${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}"
                val summary = if (label.isNullOrBlank()) {
                    "Set alarm for $timeString"
                } else {
                    "Set alarm for $timeString labeled '$label'"
                }
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CLOCK,
                        actionSummary = summary,
                        provenance = worstProvenance,
                        decision = "SUCCESS"
                    )
                )
                ToolResult.Success(
                    message = UserMessage(
                        key = MessageKey.ACTION_ALARM_SET,
                        args = listOf(MessageArg.IsoTime(timeString))
                    ),
                    outputValues = mapOf(
                        "hour" to hour.toString(),
                        "minute" to minute.toString(),
                        "time" to timeString
                    )
                )
            }
            is PlatformDispatchResult.MissingPermission -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CLOCK,
                        actionSummary = "Missing permission for alarm: ${dispatch.permission}",
                        provenance = worstProvenance,
                        decision = ToolArgumentReader.ERROR_SYSTEM_PERMISSION_MISSING
                    )
                )
                ToolArgumentReader.missingPermissionFailure(dispatch.permission)
            }
            is PlatformDispatchResult.Unavailable -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CLOCK,
                        actionSummary = "Clock platform unavailable: ${dispatch.reason}",
                        provenance = worstProvenance,
                        decision = ToolArgumentReader.ERROR_PLATFORM_UNAVAILABLE
                    )
                )
                ToolArgumentReader.platformUnavailableFailure(dispatch.reason)
            }
        }
    }

    private fun parseTime(arguments: Map<String, Tainted<SlotValueAst>>): Pair<Int, Int>? {
        val timeStr = ToolArgumentReader.getString(arguments, "time")?.value
        if (timeStr != null) {
            val fromTimeString = parseTimeString(timeStr)
            if (fromTimeString != null) return fromTimeString
        }

        val rawHour = ToolArgumentReader.getInt(arguments, "hour")?.value ?: return null
        val rawMinute = ToolArgumentReader.getInt(arguments, "minute")?.value ?: 0

        val meridiem = ToolArgumentReader.getString(arguments, "meridiem")?.value?.lowercase(Locale.ROOT)
        val period = ToolArgumentReader.getString(arguments, "period_keyword")?.value?.lowercase(Locale.ROOT)

        var hour = rawHour
        val minute = rawMinute

        val isPm = meridiem == "pm" || period == "evening" || period == "night"
        val isAm = meridiem == "am" || period == "morning"

        if (isPm && hour in 1..11) {
            hour += 12
        } else if (isAm && hour == 12) {
            hour = 0
        }

        return if (hour in 0..23 && minute in 0..59) {
            Pair(hour, minute)
        } else {
            null
        }
    }

    private fun parseTimeString(raw: String): Pair<Int, Int>? {
        val trimmed = raw.trim().lowercase(Locale.ROOT)
        val isPm = trimmed.contains("pm")
        val isAm = trimmed.contains("am")

        val cleanTime = trimmed
            .replace("am", "")
            .replace("pm", "")
            .trim()

        val parts = cleanTime.split(":")
        if (parts.size < 2) {
            val singleHour = cleanTime.toIntOrNull() ?: return null
            var h = singleHour
            if (isPm && h in 1..11) h += 12
            if (isAm && h == 12) h = 0
            return if (h in 0..23) Pair(h, 0) else null
        }

        val h = parts[0].trim().toIntOrNull() ?: return null
        val m = parts[1].trim().toIntOrNull() ?: return null

        var adjustedHour = h
        if (isPm && adjustedHour in 1..11) {
            adjustedHour += 12
        } else if (isAm && adjustedHour == 12) {
            adjustedHour = 0
        }

        return if (adjustedHour in 0..23 && m in 0..59) {
            Pair(adjustedHour, m)
        } else {
            null
        }
    }
}

/**
 * Atomic tool for starting countdown timers ([AutomationToolNames.SET_TIMER]).
 * Supports duration_seconds directly or duration_value with duration_unit (seconds, minutes, hours).
 */
class SetTimerTool(
    private val intentGateway: AutomationIntentGateway,
    private val firewall: SecurityFirewallPort,
    private val auditLog: AuditLogPort,
    private val clock: () -> Long = System::currentTimeMillis
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.SET_TIMER,
        displayNameKey = "tool_set_timer",
        description = "Sets a countdown timer for a specified duration in seconds.",
        category = ToolCategory.TIME_CALENDAR,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "duration_seconds",
                description = "Timer duration in seconds",
                required = false,
                slotKind = SensitiveSlotKind.DURATION,
                valueType = SlotValueType.DURATION_SECONDS
            ),
            ToolSchemaField(
                name = "duration_value",
                description = "Timer duration value",
                required = false,
                slotKind = SensitiveSlotKind.DURATION,
                valueType = SlotValueType.INTEGER
            ),
            ToolSchemaField(
                name = "duration_unit",
                description = "Unit of duration (second, minute, hour)",
                required = false,
                slotKind = SensitiveSlotKind.DURATION,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "label",
                description = "Optional timer label",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "skip_ui",
                description = "Whether to start timer silently without foregrounding clock UI",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.BOOLEAN
            )
        ),
        supportsUnattendedRule = true
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        val nowMs = clock()
        val worstProvenance = ToolArgumentReader.worstProvenance(arguments)

        if (ToolArgumentReader.hasVaultSourceArgument(arguments)) {
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.CLOCK,
                    actionSummary = "Blocked timer with vault taint",
                    provenance = worstProvenance,
                    decision = "VAULT_EXFILTRATION_BLOCKED"
                )
            )
            return ToolArgumentReader.securityFailure("VAULT_DATA_EXFILTRATION_BLOCKED")
        }

        val totalSeconds = parseDurationSeconds(arguments)
        if (totalSeconds == null || totalSeconds <= 0) {
            val failure = ToolArgumentReader.invalidArgumentsFailure("Duration must be a positive integer")
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.CLOCK,
                    actionSummary = "Invalid timer duration arguments",
                    provenance = worstProvenance,
                    decision = failure.errorCode
                )
            )
            return failure
        }

        val label = ToolArgumentReader.getString(arguments, "label")?.value
        val skipUi = ToolArgumentReader.getBoolean(arguments, "skip_ui")?.value ?: false

        val firewallDecision = firewall.validateOutboundTarget(
            toolName = metadata.name,
            action = AutomationOutboundActions.ACTION_SET_TIMER,
            uriOrTarget = Tainted.fromSystem("")
        )

        when (firewallDecision) {
            is FirewallDecision.Denied -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CLOCK,
                        actionSummary = "Firewall denied timer: ${firewallDecision.reasonCode}",
                        provenance = worstProvenance,
                        decision = firewallDecision.reasonCode
                    )
                )
                return ToolResult.Failure(
                    message = firewallDecision.message,
                    errorCode = firewallDecision.reasonCode,
                    isSecurityViolation = true
                )
            }
            is FirewallDecision.RequiresConfirmation -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CLOCK,
                        actionSummary = "Timer requires interactive confirmation",
                        provenance = worstProvenance,
                        decision = "CONFIRMATION_REQUIRED"
                    )
                )
                return ToolResult.ConfirmationRequired(
                    message = firewallDecision.message,
                    pendingToolName = metadata.name,
                    targetId = ToolTargetIds.CLOCK,
                    canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                    requiresBiometric = false,
                    hasUntrustedHighRiskSlot = false
                )
            }
            is FirewallDecision.RequiresBiometric -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CLOCK,
                        actionSummary = "Timer requires biometric confirmation",
                        provenance = worstProvenance,
                        decision = "BIOMETRIC_REQUIRED"
                    )
                )
                return ToolResult.ConfirmationRequired(
                    message = firewallDecision.message,
                    pendingToolName = metadata.name,
                    targetId = ToolTargetIds.CLOCK,
                    canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                    requiresBiometric = true,
                    hasUntrustedHighRiskSlot = false
                )
            }
            FirewallDecision.Authorized -> Unit
        }

        return when (val dispatch = intentGateway.dispatchSetTimer(totalSeconds, label, skipUi)) {
            is PlatformDispatchResult.Dispatched -> {
                val summary = if (label.isNullOrBlank()) {
                    "Set timer for ${totalSeconds}s"
                } else {
                    "Set timer for ${totalSeconds}s labeled '$label'"
                }
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CLOCK,
                        actionSummary = summary,
                        provenance = worstProvenance,
                        decision = "SUCCESS"
                    )
                )
                ToolResult.Success(
                    message = UserMessage(
                        key = MessageKey.ACTION_TIMER_SET,
                        args = listOf(MessageArg.Number(totalSeconds.toLong()))
                    ),
                    outputValues = mapOf("duration_seconds" to totalSeconds.toString())
                )
            }
            is PlatformDispatchResult.MissingPermission -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CLOCK,
                        actionSummary = "Missing permission for timer: ${dispatch.permission}",
                        provenance = worstProvenance,
                        decision = ToolArgumentReader.ERROR_SYSTEM_PERMISSION_MISSING
                    )
                )
                ToolArgumentReader.missingPermissionFailure(dispatch.permission)
            }
            is PlatformDispatchResult.Unavailable -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CLOCK,
                        actionSummary = "Clock platform unavailable: ${dispatch.reason}",
                        provenance = worstProvenance,
                        decision = ToolArgumentReader.ERROR_PLATFORM_UNAVAILABLE
                    )
                )
                ToolArgumentReader.platformUnavailableFailure(dispatch.reason)
            }
        }
    }

    private fun parseDurationSeconds(arguments: Map<String, Tainted<SlotValueAst>>): Int? {
        val durationDirect = ToolArgumentReader.getInt(arguments, "duration_seconds")?.value
        if (durationDirect != null && durationDirect > 0) {
            return durationDirect
        }

        val value = ToolArgumentReader.getInt(arguments, "duration_value")?.value ?: return null
        if (value <= 0) return null

        val unit = ToolArgumentReader.getString(arguments, "duration_unit")?.value?.lowercase(Locale.ROOT)
            ?: "seconds"

        val multiplier = when (unit) {
            "second", "seconds", "sec", "s" -> 1
            "minute", "minutes", "min", "m" -> 60
            "hour", "hours", "hr", "h" -> 3600
            else -> return null
        }

        val product = value.toLong() * multiplier.toLong()
        return if (product in 1..Int.MAX_VALUE) product.toInt() else null
    }
}

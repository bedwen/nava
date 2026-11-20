package com.nava.feature.automations.calendar

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.Gemma4InputSanitizer
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
import com.nava.feature.automations.common.AutomationOutboundActions
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.CalendarEventDraft
import com.nava.feature.automations.common.CalendarEventPatch
import com.nava.feature.automations.common.CalendarGatewayResult
import com.nava.feature.automations.common.CalendarPlatformGateway
import com.nava.feature.automations.common.ToolArgumentReader
import com.nava.feature.automations.common.ToolTargetIds
import java.util.Locale

/**
 * Composite adapter exposing orthogonal [NavaTool] implementations for calendar automation:
 * [CalendarQueryTool], [CalendarCreateTool], and [CalendarModifyTool].
 */
class CalendarTool(
    private val calendarGateway: CalendarPlatformGateway,
    private val firewall: SecurityFirewallPort,
    private val auditLog: AuditLogPort,
    private val clock: () -> Long = System::currentTimeMillis
) : Iterable<NavaTool> {

    val queryTool: NavaTool = CalendarQueryTool(calendarGateway, firewall, auditLog, clock)
    val createTool: NavaTool = CalendarCreateTool(calendarGateway, firewall, auditLog, clock)
    val modifyTool: NavaTool = CalendarModifyTool(calendarGateway, firewall, auditLog, clock)

    fun allTools(): List<NavaTool> = listOf(queryTool, createTool, modifyTool)

    override fun iterator(): Iterator<NavaTool> = allTools().iterator()
}

/**
 * Read-only tool querying system calendar events ([AutomationToolNames.CALENDAR_QUERY]).
 * Marks output with [DataProvenance.UNTRUSTED_EXTERNAL] and sanitizes event text fields.
 */
class CalendarQueryTool(
    private val calendarGateway: CalendarPlatformGateway,
    private val firewall: SecurityFirewallPort,
    private val auditLog: AuditLogPort,
    private val clock: () -> Long = System::currentTimeMillis
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.CALENDAR_QUERY,
        displayNameKey = "tool_calendar_query",
        description = "Queries calendar events within a specified epoch time window.",
        category = ToolCategory.TIME_CALENDAR,
        requiredCapability = AtomicCapability.DATA_READ,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "start_epoch_ms",
                description = "Query window start epoch in milliseconds",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.INTEGER
            ),
            ToolSchemaField(
                name = "end_epoch_ms",
                description = "Query window end epoch in milliseconds",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.INTEGER
            ),
            ToolSchemaField(
                name = "start_time",
                description = "Query window start timestamp",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.ISO_DATETIME
            ),
            ToolSchemaField(
                name = "end_time",
                description = "Query window end timestamp",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.ISO_DATETIME
            ),
            ToolSchemaField(
                name = "limit",
                description = "Maximum number of events to return (default 50)",
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
        val nowMs = clock()
        val worstProvenance = ToolArgumentReader.worstProvenance(arguments)

        val startEpoch = ToolArgumentReader.getLong(arguments, "start_epoch_ms")?.value
            ?: ToolArgumentReader.getLong(arguments, "start_time")?.value
            ?: nowMs

        val endEpoch = ToolArgumentReader.getLong(arguments, "end_epoch_ms")?.value
            ?: ToolArgumentReader.getLong(arguments, "end_time")?.value
            ?: (startEpoch + ONE_DAY_MS)

        if (endEpoch < startEpoch) {
            val failure = ToolArgumentReader.invalidArgumentsFailure("end_epoch_ms must be >= start_epoch_ms")
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.CALENDAR,
                    actionSummary = "Invalid calendar query time range",
                    provenance = worstProvenance,
                    decision = failure.errorCode
                )
            )
            return failure
        }

        val limit = ToolArgumentReader.getInt(arguments, "limit")?.value
            ?: CalendarPlatformGateway.DEFAULT_QUERY_LIMIT

        val firewallDecision = firewall.validateOutboundTarget(
            toolName = metadata.name,
            action = AutomationOutboundActions.ACTION_CALENDAR_PROVIDER,
            uriOrTarget = Tainted.fromSystem(CalendarPlatformGateway.CALENDAR_PROVIDER_BASE_URI)
        )

        when (firewallDecision) {
            is FirewallDecision.Denied -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Firewall denied calendar query: ${firewallDecision.reasonCode}",
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
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Calendar query requires confirmation",
                        provenance = worstProvenance,
                        decision = "CONFIRMATION_REQUIRED"
                    )
                )
                return ToolResult.ConfirmationRequired(
                    message = firewallDecision.message,
                    pendingToolName = metadata.name,
                    targetId = ToolTargetIds.CALENDAR,
                    canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments)
                )
            }
            is FirewallDecision.RequiresBiometric -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Calendar query requires biometric",
                        provenance = worstProvenance,
                        decision = "BIOMETRIC_REQUIRED"
                    )
                )
                return ToolResult.ConfirmationRequired(
                    message = firewallDecision.message,
                    pendingToolName = metadata.name,
                    targetId = ToolTargetIds.CALENDAR,
                    canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                    requiresBiometric = true
                )
            }
            FirewallDecision.Authorized -> Unit
        }

        return when (val queryResult = calendarGateway.queryEvents(startEpoch, endEpoch, limit)) {
            is CalendarGatewayResult.Success -> {
                val sanitizedEvents = queryResult.value.map { event ->
                    "${event.eventId}:${Gemma4InputSanitizer.sanitize(event.title)}@${event.startEpochMs}"
                }
                val count = queryResult.value.size
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Queried $count calendar events",
                        provenance = DataProvenance.UNTRUSTED_EXTERNAL,
                        decision = "SUCCESS"
                    )
                )
                ToolResult.Success(
                    message = UserMessage(
                        key = MessageKey.ACTION_CALENDAR_EVENTS_QUERIED,
                        args = listOf(MessageArg.Number(count.toLong()))
                    ),
                    outputValues = mapOf(
                        "count" to count.toString(),
                        "events_summary" to sanitizedEvents.joinToString(";")
                    ),
                    outputProvenance = DataProvenance.UNTRUSTED_EXTERNAL
                )
            }
            is CalendarGatewayResult.MissingPermission -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Missing permission for calendar query: ${queryResult.permission}",
                        provenance = worstProvenance,
                        decision = ToolArgumentReader.ERROR_SYSTEM_PERMISSION_MISSING
                    )
                )
                ToolArgumentReader.missingPermissionFailure(queryResult.permission)
            }
            is CalendarGatewayResult.NotFound -> {
                ToolArgumentReader.notFoundFailure(queryResult.eventId.toString())
            }
            is CalendarGatewayResult.Unavailable -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Calendar query unavailable: ${queryResult.reason}",
                        provenance = worstProvenance,
                        decision = ToolArgumentReader.ERROR_PLATFORM_UNAVAILABLE
                    )
                )
                ToolArgumentReader.platformUnavailableFailure(queryResult.reason)
            }
        }
    }

    companion object {
        private const val ONE_DAY_MS: Long = 86_400_000L
    }
}

/**
 * Draft creation tool for calendar events ([AutomationToolNames.CALENDAR_CREATE]).
 */
class CalendarCreateTool(
    private val calendarGateway: CalendarPlatformGateway,
    private val firewall: SecurityFirewallPort,
    private val auditLog: AuditLogPort,
    private val clock: () -> Long = System::currentTimeMillis
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.CALENDAR_CREATE,
        displayNameKey = "tool_calendar_create",
        description = "Creates a new calendar event entry.",
        category = ToolCategory.TIME_CALENDAR,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "title",
                description = "Title of the calendar event",
                required = true,
                slotKind = SensitiveSlotKind.EVENT_TITLE,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "start_epoch_ms",
                description = "Event start epoch in milliseconds",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.INTEGER
            ),
            ToolSchemaField(
                name = "end_epoch_ms",
                description = "Event end epoch in milliseconds",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.INTEGER
            ),
            ToolSchemaField(
                name = "start_time",
                description = "Event start timestamp",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.ISO_DATETIME
            ),
            ToolSchemaField(
                name = "end_time",
                description = "Event end timestamp",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.ISO_DATETIME
            ),
            ToolSchemaField(
                name = "description",
                description = "Optional event description",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "location",
                description = "Optional event location",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "all_day",
                description = "Whether the event lasts all day",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.BOOLEAN
            ),
            ToolSchemaField(
                name = "calendar_id",
                description = "Optional local calendar ID",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.INTEGER
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
                    targetId = ToolTargetIds.CALENDAR,
                    actionSummary = "Blocked calendar create with vault taint",
                    provenance = worstProvenance,
                    decision = "VAULT_EXFILTRATION_BLOCKED"
                )
            )
            return ToolArgumentReader.securityFailure("VAULT_DATA_EXFILTRATION_BLOCKED")
        }

        val rawTitle = ToolArgumentReader.getString(arguments, "title")?.value
        if (rawTitle.isNullOrBlank()) {
            val failure = ToolArgumentReader.invalidArgumentsFailure("Missing or blank event title")
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.CALENDAR,
                    actionSummary = "Invalid calendar create arguments: title missing",
                    provenance = worstProvenance,
                    decision = failure.errorCode
                )
            )
            return failure
        }
        val title = Gemma4InputSanitizer.sanitize(rawTitle)

        val startEpoch = ToolArgumentReader.getLong(arguments, "start_epoch_ms")?.value
            ?: ToolArgumentReader.getLong(arguments, "start_time")?.value
            ?: (nowMs + ONE_HOUR_MS)

        val endEpoch = ToolArgumentReader.getLong(arguments, "end_epoch_ms")?.value
            ?: ToolArgumentReader.getLong(arguments, "end_time")?.value
            ?: (startEpoch + ONE_HOUR_MS)

        if (endEpoch < startEpoch) {
            val failure = ToolArgumentReader.invalidArgumentsFailure("end_epoch_ms must be >= start_epoch_ms")
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.CALENDAR,
                    actionSummary = "Invalid calendar create time range",
                    provenance = worstProvenance,
                    decision = failure.errorCode
                )
            )
            return failure
        }

        val description = ToolArgumentReader.getString(arguments, "description")?.value?.let {
            Gemma4InputSanitizer.sanitize(it)
        }.orEmpty()

        val location = ToolArgumentReader.getString(arguments, "location")?.value?.let {
            Gemma4InputSanitizer.sanitize(it)
        }.orEmpty()

        val allDay = ToolArgumentReader.getBoolean(arguments, "all_day")?.value ?: false
        val calendarId = ToolArgumentReader.getLong(arguments, "calendar_id")?.value

        val draft = CalendarEventDraft(
            title = title,
            startEpochMs = startEpoch,
            endEpochMs = endEpoch,
            description = description,
            location = location,
            allDay = allDay,
            calendarId = calendarId
        )

        val firewallDecision = firewall.validateOutboundTarget(
            toolName = metadata.name,
            action = AutomationOutboundActions.ACTION_CALENDAR_PROVIDER,
            uriOrTarget = Tainted.fromSystem(CalendarPlatformGateway.CALENDAR_PROVIDER_BASE_URI)
        )

        when (firewallDecision) {
            is FirewallDecision.Denied -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Firewall denied calendar create: ${firewallDecision.reasonCode}",
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
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Calendar create requires confirmation",
                        provenance = worstProvenance,
                        decision = "CONFIRMATION_REQUIRED"
                    )
                )
                return ToolResult.ConfirmationRequired(
                    message = firewallDecision.message,
                    pendingToolName = metadata.name,
                    targetId = ToolTargetIds.CALENDAR,
                    canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments)
                )
            }
            is FirewallDecision.RequiresBiometric -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Calendar create requires biometric",
                        provenance = worstProvenance,
                        decision = "BIOMETRIC_REQUIRED"
                    )
                )
                return ToolResult.ConfirmationRequired(
                    message = firewallDecision.message,
                    pendingToolName = metadata.name,
                    targetId = ToolTargetIds.CALENDAR,
                    canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                    requiresBiometric = true
                )
            }
            FirewallDecision.Authorized -> Unit
        }

        return when (val result = calendarGateway.createEvent(draft)) {
            is CalendarGatewayResult.Success -> {
                val eventId = result.value
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Created calendar event '$title' (id=$eventId)",
                        provenance = worstProvenance,
                        decision = "SUCCESS"
                    )
                )
                ToolResult.Success(
                    message = UserMessage(
                        key = MessageKey.ACTION_CALENDAR_EVENT_CREATED,
                        args = listOf(MessageArg.Text(title))
                    ),
                    outputValues = mapOf("event_id" to eventId.toString())
                )
            }
            is CalendarGatewayResult.MissingPermission -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Missing permission for calendar create: ${result.permission}",
                        provenance = worstProvenance,
                        decision = ToolArgumentReader.ERROR_SYSTEM_PERMISSION_MISSING
                    )
                )
                ToolArgumentReader.missingPermissionFailure(result.permission)
            }
            is CalendarGatewayResult.NotFound -> {
                ToolArgumentReader.notFoundFailure(result.eventId.toString())
            }
            is CalendarGatewayResult.Unavailable -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Calendar create unavailable: ${result.reason}",
                        provenance = worstProvenance,
                        decision = ToolArgumentReader.ERROR_PLATFORM_UNAVAILABLE
                    )
                )
                ToolArgumentReader.platformUnavailableFailure(result.reason)
            }
        }
    }

    companion object {
        private const val ONE_HOUR_MS: Long = 3_600_000L
    }
}

/**
 * Modification tool for updating or deleting calendar events ([AutomationToolNames.CALENDAR_MODIFY]).
 * Enforces [AtomicCapability.MODIFY_DELETE_SEND] and never runs in unattended background mode.
 */
class CalendarModifyTool(
    private val calendarGateway: CalendarPlatformGateway,
    private val firewall: SecurityFirewallPort,
    private val auditLog: AuditLogPort,
    private val clock: () -> Long = System::currentTimeMillis
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.CALENDAR_MODIFY,
        displayNameKey = "tool_calendar_modify",
        description = "Updates or deletes an existing calendar event entry.",
        category = ToolCategory.TIME_CALENDAR,
        requiredCapability = AtomicCapability.MODIFY_DELETE_SEND,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "operation",
                description = "Modification operation ('update' or 'delete')",
                required = true,
                slotKind = SensitiveSlotKind.INTENT_ACTION,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "event_id",
                description = "Calendar event identifier to modify",
                required = true,
                slotKind = SensitiveSlotKind.EVENT_TITLE,
                valueType = SlotValueType.INTEGER
            ),
            ToolSchemaField(
                name = "title",
                description = "Updated title",
                required = false,
                slotKind = SensitiveSlotKind.EVENT_TITLE,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "description",
                description = "Updated description",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "location",
                description = "Updated location",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "start_epoch_ms",
                description = "Updated start epoch in milliseconds",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.INTEGER
            ),
            ToolSchemaField(
                name = "end_epoch_ms",
                description = "Updated end epoch in milliseconds",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.INTEGER
            ),
            ToolSchemaField(
                name = "all_day",
                description = "Updated all day flag",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.BOOLEAN
            )
        ),
        supportsUnattendedRule = false
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        val nowMs = clock()
        val worstProvenance = ToolArgumentReader.worstProvenance(arguments)

        if (context.isUnattendedBackground) {
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.CALENDAR,
                    actionSummary = "Blocked unattended execution of calendar modify",
                    provenance = worstProvenance,
                    decision = "UNATTENDED_FORBIDDEN"
                )
            )
            return ToolArgumentReader.securityFailure("UNATTENDED_EXECUTION_FORBIDDEN")
        }

        if (ToolArgumentReader.hasVaultSourceArgument(arguments)) {
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.CALENDAR,
                    actionSummary = "Blocked calendar modify with vault taint",
                    provenance = worstProvenance,
                    decision = "VAULT_EXFILTRATION_BLOCKED"
                )
            )
            return ToolArgumentReader.securityFailure("VAULT_DATA_EXFILTRATION_BLOCKED")
        }

        val eventId = ToolArgumentReader.getLong(arguments, "event_id")?.value
        if (eventId == null || eventId <= 0L) {
            val failure = ToolArgumentReader.invalidArgumentsFailure("Invalid or missing event_id")
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.CALENDAR,
                    actionSummary = "Invalid calendar modify arguments: bad event_id",
                    provenance = worstProvenance,
                    decision = failure.errorCode
                )
            )
            return failure
        }

        val operation = ToolArgumentReader.getString(arguments, "operation")?.value?.lowercase(Locale.ROOT)
        if (operation != "update" && operation != "delete") {
            val failure = ToolArgumentReader.invalidArgumentsFailure("operation must be 'update' or 'delete'")
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.CALENDAR,
                    actionSummary = "Invalid calendar modify operation: $operation",
                    provenance = worstProvenance,
                    decision = failure.errorCode
                )
            )
            return failure
        }

        val firewallDecision = firewall.validateOutboundTarget(
            toolName = metadata.name,
            action = AutomationOutboundActions.ACTION_CALENDAR_PROVIDER,
            uriOrTarget = Tainted.fromSystem(CalendarPlatformGateway.CALENDAR_PROVIDER_BASE_URI)
        )

        when (firewallDecision) {
            is FirewallDecision.Denied -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Firewall denied calendar modify: ${firewallDecision.reasonCode}",
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
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Calendar modify requires confirmation",
                        provenance = worstProvenance,
                        decision = "CONFIRMATION_REQUIRED"
                    )
                )
                return ToolResult.ConfirmationRequired(
                    message = firewallDecision.message,
                    pendingToolName = metadata.name,
                    targetId = ToolTargetIds.CALENDAR,
                    canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments)
                )
            }
            is FirewallDecision.RequiresBiometric -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Calendar modify requires biometric",
                        provenance = worstProvenance,
                        decision = "BIOMETRIC_REQUIRED"
                    )
                )
                return ToolResult.ConfirmationRequired(
                    message = firewallDecision.message,
                    pendingToolName = metadata.name,
                    targetId = ToolTargetIds.CALENDAR,
                    canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                    requiresBiometric = true
                )
            }
            FirewallDecision.Authorized -> Unit
        }

        return if (operation == "delete") {
            when (val deleteResult = calendarGateway.deleteEvent(eventId)) {
                is CalendarGatewayResult.Success -> {
                    auditLog.record(
                        AuditLogEntry(
                            timestampEpochMs = nowMs,
                            toolName = metadata.name,
                            targetId = ToolTargetIds.CALENDAR,
                            actionSummary = "Deleted calendar event id=$eventId",
                            provenance = worstProvenance,
                            decision = "SUCCESS"
                        )
                    )
                    ToolResult.Success(
                        message = UserMessage(
                            key = MessageKey.ACTION_CALENDAR_EVENT_DELETED,
                            args = listOf(MessageArg.Number(eventId))
                        ),
                        outputValues = mapOf("event_id" to eventId.toString())
                    )
                }
                is CalendarGatewayResult.NotFound -> {
                    auditLog.record(
                        AuditLogEntry(
                            timestampEpochMs = nowMs,
                            toolName = metadata.name,
                            targetId = ToolTargetIds.CALENDAR,
                            actionSummary = "Calendar event not found for deletion: id=$eventId",
                            provenance = worstProvenance,
                            decision = ToolArgumentReader.ERROR_NOT_FOUND
                        )
                    )
                    ToolArgumentReader.notFoundFailure(eventId.toString())
                }
                is CalendarGatewayResult.MissingPermission -> {
                    auditLog.record(
                        AuditLogEntry(
                            timestampEpochMs = nowMs,
                            toolName = metadata.name,
                            targetId = ToolTargetIds.CALENDAR,
                            actionSummary = "Missing permission for calendar delete: ${deleteResult.permission}",
                            provenance = worstProvenance,
                            decision = ToolArgumentReader.ERROR_SYSTEM_PERMISSION_MISSING
                        )
                    )
                    ToolArgumentReader.missingPermissionFailure(deleteResult.permission)
                }
                is CalendarGatewayResult.Unavailable -> {
                    auditLog.record(
                        AuditLogEntry(
                            timestampEpochMs = nowMs,
                            toolName = metadata.name,
                            targetId = ToolTargetIds.CALENDAR,
                            actionSummary = "Calendar delete unavailable: ${deleteResult.reason}",
                            provenance = worstProvenance,
                            decision = ToolArgumentReader.ERROR_PLATFORM_UNAVAILABLE
                        )
                    )
                    ToolArgumentReader.platformUnavailableFailure(deleteResult.reason)
                }
            }
        } else {
            val title = ToolArgumentReader.getString(arguments, "title")?.value?.let {
                Gemma4InputSanitizer.sanitize(it)
            }
            val description = ToolArgumentReader.getString(arguments, "description")?.value?.let {
                Gemma4InputSanitizer.sanitize(it)
            }
            val location = ToolArgumentReader.getString(arguments, "location")?.value?.let {
                Gemma4InputSanitizer.sanitize(it)
            }
            val startEpoch = ToolArgumentReader.getLong(arguments, "start_epoch_ms")?.value
            val endEpoch = ToolArgumentReader.getLong(arguments, "end_epoch_ms")?.value
            val allDay = ToolArgumentReader.getBoolean(arguments, "all_day")?.value

            if (startEpoch != null && endEpoch != null && endEpoch < startEpoch) {
                val failure = ToolArgumentReader.invalidArgumentsFailure("end_epoch_ms must be >= start_epoch_ms")
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Invalid calendar patch time range",
                        provenance = worstProvenance,
                        decision = failure.errorCode
                    )
                )
                return failure
            }

            val patch = CalendarEventPatch(
                title = title,
                description = description,
                location = location,
                startEpochMs = startEpoch,
                endEpochMs = endEpoch,
                allDay = allDay
            )

            if (!patch.hasAnyChange()) {
                val failure = ToolArgumentReader.invalidArgumentsFailure("No valid update fields provided for patch")
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.CALENDAR,
                        actionSummary = "Empty calendar patch rejected",
                        provenance = worstProvenance,
                        decision = failure.errorCode
                    )
                )
                return failure
            }

            when (val updateResult = calendarGateway.updateEvent(eventId, patch)) {
                is CalendarGatewayResult.Success -> {
                    auditLog.record(
                        AuditLogEntry(
                            timestampEpochMs = nowMs,
                            toolName = metadata.name,
                            targetId = ToolTargetIds.CALENDAR,
                            actionSummary = "Updated calendar event id=$eventId",
                            provenance = worstProvenance,
                            decision = "SUCCESS"
                        )
                    )
                    ToolResult.Success(
                        message = UserMessage(
                            key = MessageKey.ACTION_CALENDAR_EVENT_UPDATED,
                            args = listOf(MessageArg.Number(eventId))
                        ),
                        outputValues = mapOf("event_id" to eventId.toString())
                    )
                }
                is CalendarGatewayResult.NotFound -> {
                    auditLog.record(
                        AuditLogEntry(
                            timestampEpochMs = nowMs,
                            toolName = metadata.name,
                            targetId = ToolTargetIds.CALENDAR,
                            actionSummary = "Calendar event not found for update: id=$eventId",
                            provenance = worstProvenance,
                            decision = ToolArgumentReader.ERROR_NOT_FOUND
                        )
                    )
                    ToolArgumentReader.notFoundFailure(eventId.toString())
                }
                is CalendarGatewayResult.MissingPermission -> {
                    auditLog.record(
                        AuditLogEntry(
                            timestampEpochMs = nowMs,
                            toolName = metadata.name,
                            targetId = ToolTargetIds.CALENDAR,
                            actionSummary = "Missing permission for calendar update: ${updateResult.permission}",
                            provenance = worstProvenance,
                            decision = ToolArgumentReader.ERROR_SYSTEM_PERMISSION_MISSING
                        )
                    )
                    ToolArgumentReader.missingPermissionFailure(updateResult.permission)
                }
                is CalendarGatewayResult.Unavailable -> {
                    auditLog.record(
                        AuditLogEntry(
                            timestampEpochMs = nowMs,
                            toolName = metadata.name,
                            targetId = ToolTargetIds.CALENDAR,
                            actionSummary = "Calendar update unavailable: ${updateResult.reason}",
                            provenance = worstProvenance,
                            decision = ToolArgumentReader.ERROR_PLATFORM_UNAVAILABLE
                        )
                    )
                    ToolArgumentReader.platformUnavailableFailure(updateResult.reason)
                }
            }
        }
    }
}

package com.nava.feature.automations.device

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.DataProvenance
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
import com.nava.feature.automations.common.AutomationOutboundActions
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.DeviceControlPlatformGateway
import com.nava.feature.automations.common.MediaCommand
import com.nava.feature.automations.common.PlatformDispatchResult
import com.nava.feature.automations.common.SettingsPanelKind
import com.nava.feature.automations.common.ToolArgumentReader
import com.nava.feature.automations.common.ToolTargetIds
import java.util.Locale

private suspend fun AuditLogPort.recordDevice(
    nowMs: Long,
    toolName: String,
    targetId: String,
    summary: String,
    provenance: DataProvenance,
    decision: String
) {
    record(
        AuditLogEntry(
            timestampEpochMs = nowMs,
            toolName = toolName,
            targetId = targetId,
            actionSummary = summary,
            provenance = provenance,
            decision = decision
        )
    )
}

private fun unavailableFailure(reason: String): ToolResult.Failure = ToolResult.Failure(
    message = UserMessage(MessageKey.ERROR_PLATFORM_UNAVAILABLE, listOf(MessageArg.Text(reason.take(80)))),
    errorCode = "PLATFORM_UNAVAILABLE"
)

private fun ToolExecutionContext.nowMs(): Long =
    if (issuedAtEpochMs > 0L) issuedAtEpochMs else System.currentTimeMillis()

/** Turns the camera flashlight on or off (`set_flashlight`). */
class FlashlightTool(
    private val gateway: DeviceControlPlatformGateway,
    private val auditLog: AuditLogPort
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.SET_FLASHLIGHT,
        displayNameKey = "tool_set_flashlight_name",
        description = "Turns the phone flashlight on or off",
        category = ToolCategory.DEVICE_SETTINGS,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = FIELD_ENABLED,
                description = "true to turn the flashlight on, false to turn it off",
                required = true,
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
        val enabled = ToolArgumentReader.getBoolean(arguments, FIELD_ENABLED)
            ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_ENABLED)
        val nowMs = context.nowMs()
        return when (val result = gateway.setFlashlight(enabled.value)) {
            is PlatformDispatchResult.Dispatched -> {
                auditLog.recordDevice(
                    nowMs, metadata.name, ToolTargetIds.FLASHLIGHT,
                    "Flashlight ${if (enabled.value) "on" else "off"}", enabled.provenance, "SUCCESS"
                )
                ToolResult.Success(
                    message = UserMessage(
                        if (enabled.value) MessageKey.ACTION_FLASHLIGHT_ON else MessageKey.ACTION_FLASHLIGHT_OFF
                    )
                )
            }
            is PlatformDispatchResult.MissingPermission -> unavailableFailure(result.permission)
            is PlatformDispatchResult.Unavailable -> unavailableFailure(result.reason)
        }
    }

    private companion object {
        const val FIELD_ENABLED: String = "enabled"
    }
}

/** Play, pause, skip, or go back in whatever app is playing media (`media_control`). */
class MediaControlTool(
    private val gateway: DeviceControlPlatformGateway,
    private val auditLog: AuditLogPort
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.MEDIA_CONTROL,
        displayNameKey = "tool_media_control_name",
        description = "Controls media playback: play, pause, toggle, next, previous",
        category = ToolCategory.DEVICE_SETTINGS,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = FIELD_COMMAND,
                description = "One of: play, pause, toggle, next, previous",
                required = true,
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
        val raw = ToolArgumentReader.getString(arguments, FIELD_COMMAND)
            ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_COMMAND)
        val command = parseCommand(raw.value)
            ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_COMMAND)
        return when (val result = gateway.sendMediaCommand(command)) {
            is PlatformDispatchResult.Dispatched -> {
                auditLog.recordDevice(
                    context.nowMs(), metadata.name, ToolTargetIds.MEDIA,
                    "Media command ${command.name}", raw.provenance, "SUCCESS"
                )
                ToolResult.Success(
                    message = UserMessage(
                        MessageKey.ACTION_MEDIA_CONTROLLED,
                        listOf(MessageArg.Text(command.name.lowercase(Locale.ROOT)))
                    )
                )
            }
            is PlatformDispatchResult.MissingPermission -> unavailableFailure(result.permission)
            is PlatformDispatchResult.Unavailable -> unavailableFailure(result.reason)
        }
    }

    private companion object {
        const val FIELD_COMMAND: String = "command"

        fun parseCommand(raw: String): MediaCommand? = when (raw.trim().lowercase(Locale.ROOT)) {
            "play", "resume" -> MediaCommand.PLAY
            "pause", "stop" -> MediaCommand.PAUSE
            "toggle", "play_pause", "playpause" -> MediaCommand.PLAY_PAUSE
            "next", "skip" -> MediaCommand.NEXT
            "previous", "prev", "back" -> MediaCommand.PREVIOUS
            else -> null
        }
    }
}

/**
 * Opens a fixed system settings panel (`open_settings_panel`): internet, wifi, bluetooth or
 * volume. The panel value is checked against the outbound channel policy allowlist; nothing is
 * toggled on the user's behalf, the user acts inside the system panel.
 */
class SettingsPanelTool(
    private val gateway: DeviceControlPlatformGateway,
    private val firewall: SecurityFirewallPort,
    private val auditLog: AuditLogPort
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.OPEN_SETTINGS_PANEL,
        displayNameKey = "tool_open_settings_panel_name",
        description = "Opens a system settings panel: internet, wifi, bluetooth, or volume",
        category = ToolCategory.DEVICE_SETTINGS,
        requiredCapability = AtomicCapability.APP_LAUNCH,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = FIELD_PANEL,
                description = "One of: internet, wifi, bluetooth, volume",
                required = true,
                slotKind = SensitiveSlotKind.INTENT_ACTION,
                valueType = SlotValueType.STRING
            )
        ),
        supportsUnattendedRule = false
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        val raw = ToolArgumentReader.getString(arguments, FIELD_PANEL)
            ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_PANEL)
        val panel = SettingsPanelKind.fromSlot(raw.value)
            ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_PANEL)
        val nowMs = context.nowMs()

        val decision = firewall.validateOutboundTarget(
            toolName = metadata.name,
            action = AutomationOutboundActions.ACTION_SETTINGS_PANEL,
            uriOrTarget = raw.map { panel.policyTarget }
        )
        if (decision is FirewallDecision.Denied) {
            auditLog.recordDevice(
                nowMs, metadata.name, ToolTargetIds.SETTINGS_PANEL,
                "Firewall denied settings panel: ${decision.reasonCode}", raw.provenance, decision.reasonCode
            )
            return ToolResult.Failure(decision.message, decision.reasonCode, isSecurityViolation = true)
        }
        if (decision !is FirewallDecision.Authorized) {
            return ToolResult.Failure(
                message = UserMessage(MessageKey.ERROR_SECURITY_VIOLATION),
                errorCode = "SETTINGS_PANEL_NOT_AUTHORIZED",
                isSecurityViolation = true
            )
        }

        return when (val result = gateway.openSettingsPanel(panel)) {
            is PlatformDispatchResult.Dispatched -> {
                auditLog.recordDevice(
                    nowMs, metadata.name, ToolTargetIds.SETTINGS_PANEL,
                    "Opened settings panel ${panel.policyTarget}", raw.provenance, "SUCCESS"
                )
                ToolResult.Success(
                    message = UserMessage(
                        MessageKey.ACTION_SETTINGS_PANEL_OPENED,
                        listOf(MessageArg.Text(panel.policyTarget))
                    )
                )
            }
            is PlatformDispatchResult.MissingPermission -> unavailableFailure(result.permission)
            is PlatformDispatchResult.Unavailable -> unavailableFailure(result.reason)
        }
    }

    private companion object {
        const val FIELD_PANEL: String = "panel"
    }
}

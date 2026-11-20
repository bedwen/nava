package com.nava.feature.automations.audio

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
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
import com.nava.feature.automations.common.AudioDndPlatformGateway
import com.nava.feature.automations.common.AudioStreamKind
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.DndFilterMode
import com.nava.feature.automations.common.PlatformDispatchResult
import com.nava.feature.automations.common.ToolArgumentReader
import com.nava.feature.automations.common.ToolTargetIds
import java.util.Locale

/**
 * Composite adapter exposing orthogonal [NavaTool] implementations for device audio and DND:
 * [SetDndTool] and [SetVolumeTool].
 */
class AudioDndTool(
    private val audioDndGateway: AudioDndPlatformGateway,
    private val auditLog: AuditLogPort,
    private val clock: () -> Long = System::currentTimeMillis
) : Iterable<NavaTool> {

    val setDndTool: NavaTool = SetDndTool(audioDndGateway, auditLog, clock)
    val setVolumeTool: NavaTool = SetVolumeTool(audioDndGateway, auditLog, clock)

    fun allTools(): List<NavaTool> = listOf(setDndTool, setVolumeTool)

    override fun iterator(): Iterator<NavaTool> = allTools().iterator()
}

/**
 * Atomic tool for toggling or configuring Do Not Disturb ([AutomationToolNames.SET_DND]).
 * Requires Notification Policy Access; fails cleanly if not granted.
 */
class SetDndTool(
    private val audioDndGateway: AudioDndPlatformGateway,
    private val auditLog: AuditLogPort,
    private val clock: () -> Long = System::currentTimeMillis
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.SET_DND,
        displayNameKey = "tool_set_dnd",
        description = "Enables or disables Do Not Disturb mode on the device.",
        category = ToolCategory.DEVICE_SETTINGS,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "enabled",
                description = "Whether Do Not Disturb is enabled or disabled",
                required = true,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.BOOLEAN
            ),
            ToolSchemaField(
                name = "mode",
                description = "Optional filter mode: 'all', 'priority', 'none', or 'alarms'",
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
        val nowMs = clock()
        val worstProvenance = ToolArgumentReader.worstProvenance(arguments)

        if (ToolArgumentReader.hasVaultSourceArgument(arguments)) {
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.AUDIO_DND,
                    actionSummary = "Blocked DND update with vault taint",
                    provenance = worstProvenance,
                    decision = "VAULT_EXFILTRATION_BLOCKED"
                )
            )
            return ToolArgumentReader.securityFailure("VAULT_DATA_EXFILTRATION_BLOCKED")
        }

        val enabled = ToolArgumentReader.getBoolean(arguments, "enabled")?.value
        if (enabled == null) {
            val failure = ToolArgumentReader.invalidArgumentsFailure("Missing 'enabled' parameter")
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.AUDIO_DND,
                    actionSummary = "Invalid DND arguments: enabled missing",
                    provenance = worstProvenance,
                    decision = failure.errorCode
                )
            )
            return failure
        }

        if (!audioDndGateway.isNotificationPolicyAccessGranted()) {
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.AUDIO_DND,
                    actionSummary = "Missing Notification Policy Access for DND",
                    provenance = worstProvenance,
                    decision = ToolArgumentReader.ERROR_SYSTEM_PERMISSION_MISSING
                )
            )
            return ToolArgumentReader.missingPermissionFailure(PERMISSION_ACCESS_NOTIFICATION_POLICY)
        }

        val targetMode = if (!enabled) {
            DndFilterMode.ALL
        } else {
            val rawMode = ToolArgumentReader.getString(arguments, "mode")?.value?.lowercase(Locale.ROOT)
            when (rawMode) {
                "all" -> DndFilterMode.ALL
                "none" -> DndFilterMode.NONE
                "alarms", "alarms_only" -> DndFilterMode.ALARMS_ONLY
                "priority" -> DndFilterMode.PRIORITY
                null -> DndFilterMode.PRIORITY
                else -> {
                    val failure = ToolArgumentReader.invalidArgumentsFailure("Unknown DND mode '$rawMode'")
                    auditLog.record(
                        AuditLogEntry(
                            timestampEpochMs = nowMs,
                            toolName = metadata.name,
                            targetId = ToolTargetIds.AUDIO_DND,
                            actionSummary = "Invalid DND mode argument: $rawMode",
                            provenance = worstProvenance,
                            decision = failure.errorCode
                        )
                    )
                    return failure
                }
            }
        }

        return when (val dispatch = audioDndGateway.setInterruptionFilter(targetMode)) {
            is PlatformDispatchResult.Dispatched -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.AUDIO_DND,
                        actionSummary = "DND interruption filter set to ${targetMode.name} (enabled=$enabled)",
                        provenance = worstProvenance,
                        decision = "SUCCESS"
                    )
                )
                ToolResult.Success(
                    message = UserMessage(
                        key = MessageKey.ACTION_DND_UPDATED,
                        args = listOf(MessageArg.Text(targetMode.name))
                    ),
                    outputValues = mapOf(
                        "enabled" to enabled.toString(),
                        "mode" to targetMode.name
                    )
                )
            }
            is PlatformDispatchResult.MissingPermission -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.AUDIO_DND,
                        actionSummary = "Missing permission for DND dispatch: ${dispatch.permission}",
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
                        targetId = ToolTargetIds.AUDIO_DND,
                        actionSummary = "Audio/DND platform unavailable: ${dispatch.reason}",
                        provenance = worstProvenance,
                        decision = ToolArgumentReader.ERROR_PLATFORM_UNAVAILABLE
                    )
                )
                ToolArgumentReader.platformUnavailableFailure(dispatch.reason)
            }
        }
    }

    companion object {
        const val PERMISSION_ACCESS_NOTIFICATION_POLICY: String =
            "android.permission.ACCESS_NOTIFICATION_POLICY"
    }
}

/**
 * Atomic tool for adjusting device stream volumes ([AutomationToolNames.SET_VOLUME]).
 * Works immediately without Notification Policy Access for standard media streams.
 */
class SetVolumeTool(
    private val audioDndGateway: AudioDndPlatformGateway,
    private val auditLog: AuditLogPort,
    private val clock: () -> Long = System::currentTimeMillis
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.SET_VOLUME,
        displayNameKey = "tool_set_volume",
        description = "Sets the device volume level for a specified audio stream.",
        category = ToolCategory.DEVICE_SETTINGS,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "level",
                description = "Target volume percentage from 0 to 100",
                required = true,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.INTEGER
            ),
            ToolSchemaField(
                name = "stream",
                description = "Optional audio stream: 'media', 'ring', 'alarm', 'notification', 'system'",
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
        val nowMs = clock()
        val worstProvenance = ToolArgumentReader.worstProvenance(arguments)

        if (ToolArgumentReader.hasVaultSourceArgument(arguments)) {
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.AUDIO_DND,
                    actionSummary = "Blocked volume update with vault taint",
                    provenance = worstProvenance,
                    decision = "VAULT_EXFILTRATION_BLOCKED"
                )
            )
            return ToolArgumentReader.securityFailure("VAULT_DATA_EXFILTRATION_BLOCKED")
        }

        val level = ToolArgumentReader.getInt(arguments, "level")?.value
        if (level == null || level !in 0..100) {
            val failure = ToolArgumentReader.invalidArgumentsFailure("level must be an integer between 0 and 100")
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.AUDIO_DND,
                    actionSummary = "Invalid volume level: $level",
                    provenance = worstProvenance,
                    decision = failure.errorCode
                )
            )
            return failure
        }

        val streamKind = parseStreamKind(arguments)
        if (streamKind == null) {
            val rawStream = ToolArgumentReader.getString(arguments, "stream")?.value
            val failure = ToolArgumentReader.invalidArgumentsFailure("Unknown stream kind '$rawStream'")
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.AUDIO_DND,
                    actionSummary = "Invalid audio stream: $rawStream",
                    provenance = worstProvenance,
                    decision = failure.errorCode
                )
            )
            return failure
        }

        return when (val dispatch = audioDndGateway.setStreamVolumePercent(streamKind, level)) {
            is PlatformDispatchResult.Dispatched -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.AUDIO_DND,
                        actionSummary = "Volume for ${streamKind.name} set to $level%",
                        provenance = worstProvenance,
                        decision = "SUCCESS"
                    )
                )
                ToolResult.Success(
                    message = UserMessage(
                        key = MessageKey.ACTION_VOLUME_UPDATED,
                        args = listOf(
                            MessageArg.Text(streamKind.name),
                            MessageArg.Number(level.toLong())
                        )
                    ),
                    outputValues = mapOf(
                        "stream" to streamKind.name,
                        "level" to level.toString()
                    )
                )
            }
            is PlatformDispatchResult.MissingPermission -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = ToolTargetIds.AUDIO_DND,
                        actionSummary = "Missing permission for volume: ${dispatch.permission}",
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
                        targetId = ToolTargetIds.AUDIO_DND,
                        actionSummary = "Audio platform unavailable: ${dispatch.reason}",
                        provenance = worstProvenance,
                        decision = ToolArgumentReader.ERROR_PLATFORM_UNAVAILABLE
                    )
                )
                ToolArgumentReader.platformUnavailableFailure(dispatch.reason)
            }
        }
    }

    private fun parseStreamKind(arguments: Map<String, Tainted<SlotValueAst>>): AudioStreamKind? {
        val raw = ToolArgumentReader.getString(arguments, "stream")?.value?.trim()?.lowercase(Locale.ROOT)
            ?: return AudioStreamKind.MEDIA

        return when (raw) {
            "media", "music" -> AudioStreamKind.MEDIA
            "ring", "ringer", "call" -> AudioStreamKind.RING
            "alarm" -> AudioStreamKind.ALARM
            "notification", "notifications" -> AudioStreamKind.NOTIFICATION
            "system" -> AudioStreamKind.SYSTEM
            else -> null
        }
    }
}

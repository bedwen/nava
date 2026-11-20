package com.nava.feature.automations.applaunch

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
import com.nava.feature.automations.common.AutomationIntentGateway
import com.nava.feature.automations.common.AutomationOutboundActions
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.PlatformDispatchResult
import com.nava.feature.automations.common.ToolArgumentReader
import com.nava.feature.automations.common.ToolTargetIds

/**
 * Atomic tool for launching installed Android applications ([AutomationToolNames.LAUNCH_APP]).
 * Enforces [SensitiveSlotKind.PACKAGE_NAME] high-risk destination slot protections,
 * untrusted taint confirmation barriers, and Outbound Channel Policy checks.
 */
class AppLaunchTool(
    private val intentGateway: AutomationIntentGateway,
    private val firewall: SecurityFirewallPort,
    private val auditLog: AuditLogPort,
    private val clock: () -> Long = System::currentTimeMillis
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.LAUNCH_APP,
        displayNameKey = "tool_launch_app",
        description = "Launches an installed Android application by display name or package identifier.",
        category = ToolCategory.DEVICE_SETTINGS,
        requiredCapability = AtomicCapability.APP_LAUNCH,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "package_name",
                description = "Android package identifier to launch",
                required = false,
                slotKind = SensitiveSlotKind.PACKAGE_NAME,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "app_name",
                description = "Application display label to resolve and launch",
                required = false,
                slotKind = SensitiveSlotKind.PACKAGE_NAME,
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
                    targetId = ToolTargetIds.APP_LAUNCH,
                    actionSummary = "Blocked app launch with vault taint",
                    provenance = worstProvenance,
                    decision = "VAULT_EXFILTRATION_BLOCKED"
                )
            )
            return ToolArgumentReader.securityFailure("VAULT_DATA_EXFILTRATION_BLOCKED")
        }

        val taintedTarget = ToolArgumentReader.getString(arguments, "package_name")
            ?: ToolArgumentReader.getString(arguments, "app_name")

        if (taintedTarget == null || taintedTarget.value.isBlank()) {
            val failure = ToolArgumentReader.invalidArgumentsFailure("Missing app_name or package_name")
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.APP_LAUNCH,
                    actionSummary = "Invalid app launch arguments: target missing",
                    provenance = worstProvenance,
                    decision = failure.errorCode
                )
            )
            return failure
        }

        val resolvedPackage = intentGateway.resolveLaunchablePackage(taintedTarget.value)
        if (resolvedPackage == null) {
            val failure = ToolArgumentReader.notFoundFailure(taintedTarget.value)
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.APP_LAUNCH,
                    actionSummary = "App target not found: '${taintedTarget.value}'",
                    provenance = worstProvenance,
                    decision = failure.errorCode
                )
            )
            return failure
        }

        val targetId = ToolTargetIds.forPackage(resolvedPackage)
        val taintedPackage = taintedTarget.map { resolvedPackage }

        val firewallDecision = firewall.validateOutboundTarget(
            toolName = metadata.name,
            action = AutomationOutboundActions.ACTION_APP_LAUNCH,
            uriOrTarget = taintedPackage
        )

        when (firewallDecision) {
            is FirewallDecision.Denied -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = targetId,
                        actionSummary = "Firewall denied app launch: ${firewallDecision.reasonCode}",
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
                        targetId = targetId,
                        actionSummary = "Firewall requested app launch confirmation",
                        provenance = worstProvenance,
                        decision = "CONFIRMATION_REQUIRED"
                    )
                )
                return ToolResult.ConfirmationRequired(
                    message = firewallDecision.message,
                    pendingToolName = metadata.name,
                    targetId = targetId,
                    canonicalArguments = mapOf("package_name" to taintedPackage),
                    requiresBiometric = false,
                    hasUntrustedHighRiskSlot = true
                )
            }
            is FirewallDecision.RequiresBiometric -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = targetId,
                        actionSummary = "Firewall requested biometric for app launch",
                        provenance = worstProvenance,
                        decision = "BIOMETRIC_REQUIRED"
                    )
                )
                return ToolResult.ConfirmationRequired(
                    message = firewallDecision.message,
                    pendingToolName = metadata.name,
                    targetId = targetId,
                    canonicalArguments = mapOf("package_name" to taintedPackage),
                    requiresBiometric = true,
                    hasUntrustedHighRiskSlot = true
                )
            }
            FirewallDecision.Authorized -> {
                val hasUntrusted = taintedPackage.isUntrusted || ToolArgumentReader.hasUntrustedArgument(arguments)
                val hasVault = ToolArgumentReader.hasVaultSourceArgument(arguments)
                if (hasUntrusted || hasVault) {
                    auditLog.record(
                        AuditLogEntry(
                            timestampEpochMs = nowMs,
                            toolName = metadata.name,
                            targetId = targetId,
                            actionSummary = "Untrusted high-risk app launch escalated to confirmation: $resolvedPackage",
                            provenance = DataProvenance.UNTRUSTED_EXTERNAL,
                            decision = "CONFIRMATION_REQUIRED"
                        )
                    )
                    return ToolResult.ConfirmationRequired(
                        message = UserMessage(
                            key = MessageKey.ACTION_CONFIRMATION_REQUIRED,
                            args = listOf(MessageArg.Text(resolvedPackage))
                        ),
                        pendingToolName = metadata.name,
                        targetId = targetId,
                        canonicalArguments = mapOf("package_name" to taintedPackage),
                        requiresBiometric = false,
                        hasUntrustedHighRiskSlot = true
                    )
                }
            }
        }

        return when (val dispatch = intentGateway.dispatchLaunchApp(resolvedPackage)) {
            is PlatformDispatchResult.Dispatched -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = targetId,
                        actionSummary = "Launched application $resolvedPackage",
                        provenance = worstProvenance,
                        decision = "SUCCESS"
                    )
                )
                ToolResult.Success(
                    message = UserMessage(
                        key = MessageKey.ACTION_APP_LAUNCHED,
                        args = listOf(MessageArg.Text(resolvedPackage))
                    ),
                    outputValues = mapOf("package_name" to resolvedPackage)
                )
            }
            is PlatformDispatchResult.MissingPermission -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowMs,
                        toolName = metadata.name,
                        targetId = targetId,
                        actionSummary = "Missing permission for app launch: ${dispatch.permission}",
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
                        targetId = targetId,
                        actionSummary = "App launch unavailable: ${dispatch.reason}",
                        provenance = worstProvenance,
                        decision = ToolArgumentReader.ERROR_PLATFORM_UNAVAILABLE
                    )
                )
                ToolArgumentReader.platformUnavailableFailure(dispatch.reason)
            }
        }
    }
}

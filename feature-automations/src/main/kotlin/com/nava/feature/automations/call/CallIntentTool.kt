package com.nava.feature.automations.call

import android.Manifest
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
import com.nava.feature.automations.common.AndroidAutomationIntentGateway
import com.nava.feature.automations.common.AutomationIntentGateway
import com.nava.feature.automations.common.AutomationOutboundActions
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.PlatformDispatchResult
import com.nava.feature.automations.common.ToolArgumentReader
import com.nava.feature.automations.common.ToolTargetIds

/**
 * Common base and companion factories for telephone communication tools in Nava.
 */
sealed class CallIntentTool(
    override val metadata: ToolMetadata,
    protected val intentGateway: AutomationIntentGateway,
    protected val firewall: SecurityFirewallPort,
    protected val auditLog: AuditLogPort
) : NavaTool {

    protected suspend fun recordCallAudit(
        timestampMs: Long,
        actionSummary: String,
        provenance: com.nava.domain.security.DataProvenance,
        decision: String
    ) {
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = timestampMs,
                toolName = metadata.name,
                targetId = ToolTargetIds.PHONE,
                actionSummary = actionSummary,
                provenance = provenance,
                decision = decision
            )
        )
    }

    /**
     * Dial call adapter (`AutomationToolNames.DIAL_CALL` / `dial_call`).
     *
     * Capability: [AtomicCapability.CREATE_DRAFT], supports unattended background rules.
     * Launches `Intent.ACTION_DIAL` (`tel:<number>`); requires zero runtime permissions.
     */
    class Dial(
        intentGateway: AutomationIntentGateway,
        firewall: SecurityFirewallPort,
        auditLog: AuditLogPort
    ) : CallIntentTool(
        metadata = ToolMetadata(
            name = AutomationToolNames.DIAL_CALL,
            displayNameKey = "action_call_intent_prepared",
            description = "Opens the device dialer with the provided phone number pre-filled",
            category = ToolCategory.COMMUNICATION,
            requiredCapability = AtomicCapability.CREATE_DRAFT,
            schemaVersion = 1,
            fields = listOf(
                ToolSchemaField(
                    name = FIELD_PHONE_NUMBER,
                    description = "Target phone number to dial",
                    required = true,
                    slotKind = SensitiveSlotKind.PHONE_NUMBER,
                    valueType = SlotValueType.STRING
                )
            ),
            supportsUnattendedRule = true
        ),
        intentGateway = intentGateway,
        firewall = firewall,
        auditLog = auditLog
    ) {
        override suspend fun execute(
            context: ToolExecutionContext,
            arguments: Map<String, Tainted<SlotValueAst>>
        ): ToolResult {
            val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else System.currentTimeMillis()

            val phoneTainted = ToolArgumentReader.getString(arguments, FIELD_PHONE_NUMBER)
                ?: ToolArgumentReader.getString(arguments, "phoneNumber")
                ?: ToolArgumentReader.getString(arguments, "number")
                ?: ToolArgumentReader.getString(arguments, "recipient")
                ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_PHONE_NUMBER)

            val rawNumber = phoneTainted.value.trim()
            if (!AndroidAutomationIntentGateway.isValidDialableNumber(rawNumber)) {
                return ToolArgumentReader.invalidArgumentsFailure("phone_number: invalid dialable format")
            }

            val taintedOutboundUri: Tainted<String> = phoneTainted.map { "tel:$rawNumber" }
            val firewallDecision = firewall.validateOutboundTarget(
                toolName = metadata.name,
                action = AutomationOutboundActions.ACTION_DIAL,
                uriOrTarget = taintedOutboundUri
            )

            val userConfirmed = context.isUserConfirmed && !context.isUnattendedBackground
            val bioApproved = context.isBiometricApproved && !context.isUnattendedBackground
            val hasUntrustedHighRisk = phoneTainted.isUntrusted

            when (firewallDecision) {
                is FirewallDecision.Denied -> {
                    recordCallAudit(
                        timestampMs = nowMs,
                        actionSummary = "Denied dialer intent for number: $rawNumber",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = firewallDecision.reasonCode
                    )
                    return ToolArgumentReader.securityFailure(
                        reasonCode = firewallDecision.reasonCode,
                        message = firewallDecision.message
                    )
                }

                is FirewallDecision.RequiresBiometric -> {
                    if (!bioApproved || (hasUntrustedHighRisk && !userConfirmed)) {
                        recordCallAudit(
                            timestampMs = nowMs,
                            actionSummary = "Biometric confirmation required for dialer intent",
                            provenance = ToolArgumentReader.worstProvenance(arguments),
                            decision = "BIOMETRIC_REQUIRED"
                        )
                        return ToolResult.ConfirmationRequired(
                            message = firewallDecision.message,
                            pendingToolName = metadata.name,
                            targetId = ToolTargetIds.PHONE,
                            canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                            requiresBiometric = true,
                            hasUntrustedHighRiskSlot = hasUntrustedHighRisk
                        )
                    }
                }

                is FirewallDecision.RequiresConfirmation -> {
                    if (!userConfirmed) {
                        recordCallAudit(
                            timestampMs = nowMs,
                            actionSummary = "User confirmation required for dialer intent",
                            provenance = ToolArgumentReader.worstProvenance(arguments),
                            decision = "CONFIRMATION_REQUIRED"
                        )
                        return ToolResult.ConfirmationRequired(
                            message = firewallDecision.message,
                            pendingToolName = metadata.name,
                            targetId = ToolTargetIds.PHONE,
                            canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                            requiresBiometric = false,
                            hasUntrustedHighRiskSlot = true
                        )
                    }
                }

                FirewallDecision.Authorized -> {
                    if (phoneTainted.isUntrusted || ToolArgumentReader.hasVaultSourceArgument(arguments)) {
                        if (!userConfirmed) {
                            val worst = ToolArgumentReader.worstProvenance(arguments)
                            recordCallAudit(
                                timestampMs = nowMs,
                                actionSummary = "Taint barrier: dialer target requires user confirmation",
                                provenance = worst,
                                decision = "CONFIRMATION_REQUIRED"
                            )
                            return ToolResult.ConfirmationRequired(
                                message = UserMessage(
                                    key = MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE,
                                    args = listOf(MessageArg.ProvenanceBadge(worst))
                                ),
                                pendingToolName = metadata.name,
                                targetId = ToolTargetIds.PHONE,
                                canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                                requiresBiometric = false,
                                hasUntrustedHighRiskSlot = phoneTainted.isUntrusted
                            )
                        }
                    }
                }
            }

            return when (val dispatchResult = intentGateway.dispatchDial(rawNumber)) {
                is PlatformDispatchResult.Dispatched -> {
                    recordCallAudit(
                        timestampMs = nowMs,
                        actionSummary = "Prepared dialer intent for number: $rawNumber",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = "SUCCESS"
                    )
                    ToolResult.Success(
                        message = UserMessage(
                            key = MessageKey.ACTION_CALL_INTENT_PREPARED,
                            args = listOf(MessageArg.Text(rawNumber))
                        ),
                        outputValues = mapOf(FIELD_PHONE_NUMBER to rawNumber)
                    )
                }

                is PlatformDispatchResult.MissingPermission -> {
                    recordCallAudit(
                        timestampMs = nowMs,
                        actionSummary = "Failed dialer intent: missing permission ${dispatchResult.permission}",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = "MISSING_PERMISSION"
                    )
                    ToolArgumentReader.missingPermissionFailure(dispatchResult.permission)
                }

                is PlatformDispatchResult.Unavailable -> {
                    recordCallAudit(
                        timestampMs = nowMs,
                        actionSummary = "Failed dialer intent: platform unavailable (${dispatchResult.reason})",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = "PLATFORM_UNAVAILABLE"
                    )
                    ToolArgumentReader.platformUnavailableFailure(dispatchResult.reason)
                }
            }
        }
    }

    /**
     * Direct place call adapter (`AutomationToolNames.PLACE_CALL` / `place_call`).
     *
     * Capability: [AtomicCapability.MODIFY_DELETE_SEND], forbidden in unattended execution.
     * Uses `Intent.ACTION_CALL` (`tel:<number>`); strictly requires runtime [Manifest.permission.CALL_PHONE].
     */
    class Place(
        intentGateway: AutomationIntentGateway,
        firewall: SecurityFirewallPort,
        auditLog: AuditLogPort
    ) : CallIntentTool(
        metadata = ToolMetadata(
            name = AutomationToolNames.PLACE_CALL,
            displayNameKey = "action_direct_call_initiated",
            description = "Places an immediate direct telephone call via ACTION_CALL",
            category = ToolCategory.COMMUNICATION,
            requiredCapability = AtomicCapability.MODIFY_DELETE_SEND,
            schemaVersion = 1,
            fields = listOf(
                ToolSchemaField(
                    name = FIELD_PHONE_NUMBER,
                    description = "Target phone number to call directly",
                    required = true,
                    slotKind = SensitiveSlotKind.PHONE_NUMBER,
                    valueType = SlotValueType.STRING
                )
            ),
            supportsUnattendedRule = false
        ),
        intentGateway = intentGateway,
        firewall = firewall,
        auditLog = auditLog
    ) {
        override suspend fun execute(
            context: ToolExecutionContext,
            arguments: Map<String, Tainted<SlotValueAst>>
        ): ToolResult {
            val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else System.currentTimeMillis()

            // Critical Security Invariant: direct call is never permitted unattended
            if (context.isUnattendedBackground) {
                recordCallAudit(
                    timestampMs = nowMs,
                    actionSummary = "Security violation: place_call attempted in unattended background",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "SECURITY_VIOLATION"
                )
                return ToolArgumentReader.securityFailure("UNATTENDED_DIRECT_CALL_FORBIDDEN")
            }

            val phoneTainted = ToolArgumentReader.getString(arguments, FIELD_PHONE_NUMBER)
                ?: ToolArgumentReader.getString(arguments, "phoneNumber")
                ?: ToolArgumentReader.getString(arguments, "number")
                ?: ToolArgumentReader.getString(arguments, "recipient")
                ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_PHONE_NUMBER)

            val rawNumber = phoneTainted.value.trim()
            if (!AndroidAutomationIntentGateway.isValidDialableNumber(rawNumber)) {
                return ToolArgumentReader.invalidArgumentsFailure("phone_number: invalid dialable format")
            }

            // Check CALL_PHONE runtime permission before dispatching
            if (!intentGateway.hasRuntimePermission(Manifest.permission.CALL_PHONE)) {
                recordCallAudit(
                    timestampMs = nowMs,
                    actionSummary = "Failed place_call: missing runtime permission CALL_PHONE",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "MISSING_PERMISSION"
                )
                return ToolArgumentReader.missingPermissionFailure(Manifest.permission.CALL_PHONE)
            }

            val taintedOutboundUri: Tainted<String> = phoneTainted.map { "tel:$rawNumber" }
            val firewallDecision = firewall.validateOutboundTarget(
                toolName = metadata.name,
                action = AutomationOutboundActions.ACTION_CALL,
                uriOrTarget = taintedOutboundUri
            )

            val userConfirmed = context.isUserConfirmed && !context.isUnattendedBackground
            val bioApproved = context.isBiometricApproved && !context.isUnattendedBackground
            val hasUntrustedHighRisk = phoneTainted.isUntrusted

            when (firewallDecision) {
                is FirewallDecision.Denied -> {
                    recordCallAudit(
                        timestampMs = nowMs,
                        actionSummary = "Denied place_call to number: $rawNumber",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = firewallDecision.reasonCode
                    )
                    return ToolArgumentReader.securityFailure(
                        reasonCode = firewallDecision.reasonCode,
                        message = firewallDecision.message
                    )
                }

                is FirewallDecision.RequiresBiometric -> {
                    if (!bioApproved || (hasUntrustedHighRisk && !userConfirmed)) {
                        recordCallAudit(
                            timestampMs = nowMs,
                            actionSummary = "Biometric confirmation required for direct call",
                            provenance = ToolArgumentReader.worstProvenance(arguments),
                            decision = "BIOMETRIC_REQUIRED"
                        )
                        return ToolResult.ConfirmationRequired(
                            message = firewallDecision.message,
                            pendingToolName = metadata.name,
                            targetId = ToolTargetIds.PHONE,
                            canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                            requiresBiometric = true,
                            hasUntrustedHighRiskSlot = hasUntrustedHighRisk
                        )
                    }
                }

                is FirewallDecision.RequiresConfirmation -> {
                    if (!userConfirmed) {
                        recordCallAudit(
                            timestampMs = nowMs,
                            actionSummary = "User confirmation required for direct call",
                            provenance = ToolArgumentReader.worstProvenance(arguments),
                            decision = "CONFIRMATION_REQUIRED"
                        )
                        return ToolResult.ConfirmationRequired(
                            message = firewallDecision.message,
                            pendingToolName = metadata.name,
                            targetId = ToolTargetIds.PHONE,
                            canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                            requiresBiometric = false,
                            hasUntrustedHighRiskSlot = true
                        )
                    }
                }

                FirewallDecision.Authorized -> {
                    if (phoneTainted.isUntrusted || ToolArgumentReader.hasVaultSourceArgument(arguments)) {
                        if (!userConfirmed) {
                            val worst = ToolArgumentReader.worstProvenance(arguments)
                            recordCallAudit(
                                timestampMs = nowMs,
                                actionSummary = "Taint barrier: direct call target requires user confirmation",
                                provenance = worst,
                                decision = "CONFIRMATION_REQUIRED"
                            )
                            return ToolResult.ConfirmationRequired(
                                message = UserMessage(
                                    key = MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE,
                                    args = listOf(MessageArg.ProvenanceBadge(worst))
                                ),
                                pendingToolName = metadata.name,
                                targetId = ToolTargetIds.PHONE,
                                canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                                requiresBiometric = false,
                                hasUntrustedHighRiskSlot = phoneTainted.isUntrusted
                            )
                        }
                    }
                }
            }

            return when (val dispatchResult = intentGateway.dispatchDirectCall(rawNumber)) {
                is PlatformDispatchResult.Dispatched -> {
                    recordCallAudit(
                        timestampMs = nowMs,
                        actionSummary = "Initiated direct call to number: $rawNumber",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = "SUCCESS"
                    )
                    ToolResult.Success(
                        message = UserMessage(
                            key = MessageKey.ACTION_DIRECT_CALL_INITIATED,
                            args = listOf(MessageArg.Text(rawNumber))
                        ),
                        outputValues = mapOf(FIELD_PHONE_NUMBER to rawNumber)
                    )
                }

                is PlatformDispatchResult.MissingPermission -> {
                    recordCallAudit(
                        timestampMs = nowMs,
                        actionSummary = "Failed place_call: missing permission ${dispatchResult.permission}",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = "MISSING_PERMISSION"
                    )
                    ToolArgumentReader.missingPermissionFailure(dispatchResult.permission)
                }

                is PlatformDispatchResult.Unavailable -> {
                    recordCallAudit(
                        timestampMs = nowMs,
                        actionSummary = "Failed place_call: platform unavailable (${dispatchResult.reason})",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = "PLATFORM_UNAVAILABLE"
                    )
                    ToolArgumentReader.platformUnavailableFailure(dispatchResult.reason)
                }
            }
        }
    }

    companion object {
        const val FIELD_PHONE_NUMBER: String = "phone_number"

        fun createDialTool(
            intentGateway: AutomationIntentGateway,
            firewall: SecurityFirewallPort,
            auditLog: AuditLogPort
        ): NavaTool = Dial(intentGateway, firewall, auditLog)

        fun createPlaceTool(
            intentGateway: AutomationIntentGateway,
            firewall: SecurityFirewallPort,
            auditLog: AuditLogPort
        ): NavaTool = Place(intentGateway, firewall, auditLog)

        fun createAll(
            intentGateway: AutomationIntentGateway,
            firewall: SecurityFirewallPort,
            auditLog: AuditLogPort
        ): List<NavaTool> = listOf(
            createDialTool(intentGateway, firewall, auditLog),
            createPlaceTool(intentGateway, firewall, auditLog)
        )
    }
}

typealias DialCallTool = CallIntentTool.Dial
typealias PlaceCallTool = CallIntentTool.Place

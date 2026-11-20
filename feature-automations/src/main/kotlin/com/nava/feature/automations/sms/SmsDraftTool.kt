package com.nava.feature.automations.sms

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
 * Atomic automation tool adapter preparing outbound SMS message drafts.
 *
 * Play Policy Compliance:
 * Uses exclusively `Intent.ACTION_SENDTO` with `smsto:<recipient>` URIs via [AutomationIntentGateway].
 * Never requests or invokes restricted `SEND_SMS` or `READ_SMS` permissions. Final sending is
 * always handed off to the user within their chosen system messaging application.
 *
 * Security & Taint Barrier:
 * - Validates outbound `smsto:<recipient>` target with [SecurityFirewallPort.validateOutboundTarget]
 *   before dispatching.
 * - Outbound Channel Taint Barrier (PLAN.md Section 5.4): If recipient or draft body originates from
 *   `UNTRUSTED_EXTERNAL` or Nava Secure Vault, forces an explicit [ToolResult.ConfirmationRequired]
 *   gate displaying canonical slot values and provenance badges.
 * - Records every dispatch attempt and decision into [AuditLogPort] without leaking body content.
 */
class SmsDraftTool(
    private val intentGateway: AutomationIntentGateway,
    private val firewall: SecurityFirewallPort,
    private val auditLog: AuditLogPort
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.CREATE_SMS_DRAFT,
        displayNameKey = "action_sms_draft_prepared",
        description = "Creates an SMS message draft in the device SMS app without directly sending messages",
        category = ToolCategory.COMMUNICATION,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = FIELD_RECIPIENT,
                description = "Recipient phone number",
                required = true,
                slotKind = SensitiveSlotKind.PHONE_NUMBER,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = FIELD_BODY,
                description = "SMS message draft body text",
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
        val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else System.currentTimeMillis()

        val recipientTainted = ToolArgumentReader.getString(arguments, FIELD_RECIPIENT)
            ?: ToolArgumentReader.getString(arguments, "phoneNumber")
            ?: ToolArgumentReader.getString(arguments, "phone_number")
            ?: ToolArgumentReader.getString(arguments, "to")
            ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_RECIPIENT)

        val bodyTainted = ToolArgumentReader.getRawString(arguments, FIELD_BODY)
            ?: ToolArgumentReader.getRawString(arguments, "message")
            ?: ToolArgumentReader.getRawString(arguments, "text")
            ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_BODY)

        val rawRecipient = recipientTainted.value.trim()
        if (!AndroidAutomationIntentGateway.isValidDialableNumber(rawRecipient)) {
            return ToolArgumentReader.invalidArgumentsFailure("recipient: invalid phone number format")
        }

        val taintedOutboundUri: Tainted<String> = recipientTainted.map { "smsto:$rawRecipient" }
        val firewallDecision = firewall.validateOutboundTarget(
            toolName = metadata.name,
            action = AutomationOutboundActions.ACTION_SENDTO,
            uriOrTarget = taintedOutboundUri
        )

        when (firewallDecision) {
            is FirewallDecision.Denied -> {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Denied outbound SMS draft to recipient: $rawRecipient",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = firewallDecision.reasonCode
                )
                return ToolArgumentReader.securityFailure(
                    reasonCode = firewallDecision.reasonCode,
                    message = firewallDecision.message
                )
            }

            is FirewallDecision.RequiresBiometric -> {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Biometric confirmation required for outbound SMS draft",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "BIOMETRIC_REQUIRED"
                )
                return ToolResult.ConfirmationRequired(
                    message = firewallDecision.message,
                    pendingToolName = metadata.name,
                    targetId = ToolTargetIds.SMS,
                    canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                    requiresBiometric = true,
                    hasUntrustedHighRiskSlot = recipientTainted.isUntrusted
                )
            }

            is FirewallDecision.RequiresConfirmation -> {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "User confirmation required for outbound SMS draft",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "CONFIRMATION_REQUIRED"
                )
                return ToolResult.ConfirmationRequired(
                    message = firewallDecision.message,
                    pendingToolName = metadata.name,
                    targetId = ToolTargetIds.SMS,
                    canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                    requiresBiometric = false,
                    hasUntrustedHighRiskSlot = true
                )
            }

            FirewallDecision.Authorized -> {
                // Outbound Channel Taint Barrier: verify passive slots (body) for untrusted or vault origin
                val hasUntrusted = ToolArgumentReader.hasUntrustedArgument(arguments)
                val hasVault = ToolArgumentReader.hasVaultSourceArgument(arguments)
                if (hasUntrusted || hasVault) {
                    val worst = ToolArgumentReader.worstProvenance(arguments)
                    recordAudit(
                        timestampMs = nowMs,
                        actionSummary = "Taint barrier: SMS draft contains untrusted or vault content",
                        provenance = worst,
                        decision = "CONFIRMATION_REQUIRED"
                    )
                    return ToolResult.ConfirmationRequired(
                        message = UserMessage(
                            key = MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE,
                            args = listOf(MessageArg.ProvenanceBadge(worst))
                        ),
                        pendingToolName = metadata.name,
                        targetId = ToolTargetIds.SMS,
                        canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                        requiresBiometric = false,
                        hasUntrustedHighRiskSlot = recipientTainted.isUntrusted
                    )
                }
            }
        }

        return when (val dispatchResult = intentGateway.dispatchSmsDraft(rawRecipient, bodyTainted.value)) {
            is PlatformDispatchResult.Dispatched -> {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Prepared SMS draft for recipient: $rawRecipient",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "SUCCESS"
                )
                ToolResult.Success(
                    message = UserMessage(
                        key = MessageKey.ACTION_SMS_DRAFT_PREPARED,
                        args = listOf(MessageArg.Text(rawRecipient))
                    ),
                    outputValues = mapOf(
                        FIELD_RECIPIENT to rawRecipient
                    )
                )
            }

            is PlatformDispatchResult.MissingPermission -> {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Failed SMS draft: missing permission ${dispatchResult.permission}",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "MISSING_PERMISSION"
                )
                ToolArgumentReader.missingPermissionFailure(dispatchResult.permission)
            }

            is PlatformDispatchResult.Unavailable -> {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Failed SMS draft: platform unavailable (${dispatchResult.reason})",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "PLATFORM_UNAVAILABLE"
                )
                ToolArgumentReader.platformUnavailableFailure(dispatchResult.reason)
            }
        }
    }

    private suspend fun recordAudit(
        timestampMs: Long,
        actionSummary: String,
        provenance: com.nava.domain.security.DataProvenance,
        decision: String
    ) {
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = timestampMs,
                toolName = metadata.name,
                targetId = ToolTargetIds.SMS,
                actionSummary = actionSummary,
                provenance = provenance,
                decision = decision
            )
        )
    }

    companion object {
        const val FIELD_RECIPIENT: String = "recipient"
        const val FIELD_BODY: String = "body"
    }
}

package com.nava.domain.usecase

import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.security.Tainted
import com.nava.domain.tool.NavaTool
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolRegistry
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage

/**
 * Executes a resolved [PlanAst] step-by-step while deterministically enforcing
 * Stage 1 [CapabilityToken] seals, [SecurityFirewallPort] taint/profile rules, and [AuditLogPort].
 */
class ExecutePlanUseCase(
    private val toolRegistry: ToolRegistry,
    private val securityFirewall: SecurityFirewallPort,
    private val auditLog: AuditLogPort
) {
    suspend operator fun invoke(
        plan: PlanAst,
        capabilityToken: CapabilityToken,
        targetId: String,
        languageTag: String,
        nowEpochMs: Long,
        confirmedStepIndices: Set<Int> = emptySet(),
        biometricApprovedStepIndices: Set<Int> = emptySet(),
        targetIdsByStep: Map<Int, String> = emptyMap(),
        startFromOrderIndex: Int = Int.MIN_VALUE
    ): List<ToolResult> {
        if (plan.calls.size > capabilityToken.maxToolCalls) {
            throw SecurityException(
                "Plan call count (${plan.calls.size}) exceeds CapabilityToken limit (${capabilityToken.maxToolCalls})"
            )
        }

        val orderedCalls = plan.calls.sortedBy { it.orderIndex }
        require(orderedCalls.map { it.orderIndex }.distinct().size == orderedCalls.size) {
            "PlanAst calls must have distinct orderIndex values"
        }

        for (call in orderedCalls) {
            capabilityToken.assertValidFor(call.toolName, nowEpochMs)
        }

        val resolvedTools = LinkedHashMap<Int, NavaTool>(orderedCalls.size)
        for (call in orderedCalls) {
            val stepTargetId = call.targetId ?: targetIdsByStep[call.orderIndex] ?: targetId
            val tool = toolRegistry.find(call.toolName)
            if (tool == null) {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowEpochMs,
                        toolName = call.toolName,
                        targetId = stepTargetId,
                        actionSummary = "Tool missing from registry",
                        provenance = callProvenance(call),
                        decision = "TOOL_NOT_FOUND"
                    )
                )
                return listOf(
                    ToolResult.Failure(
                        message = UserMessage(
                            key = MessageKey.ERROR_TOOL_NOT_FOUND,
                            args = listOf(MessageArg.Text(call.toolName))
                        ),
                        errorCode = "TOOL_NOT_FOUND"
                    )
                )
            }
            resolvedTools[call.orderIndex] = tool
        }

        val results = mutableListOf<ToolResult>()

        for (call in orderedCalls) {
            if (call.orderIndex < startFromOrderIndex) {
                continue
            }

            val tool = resolvedTools.getValue(call.orderIndex)
            val stepTargetId = call.targetId ?: targetIdsByStep[call.orderIndex] ?: targetId
            val stepConfirmed = call.orderIndex in confirmedStepIndices
            val stepBiometric = call.orderIndex in biometricApprovedStepIndices

            val decision = securityFirewall.authorizeToolCall(
                token = capabilityToken,
                toolCall = call,
                toolMetadata = tool.metadata,
                targetId = stepTargetId,
                nowEpochMs = nowEpochMs
            )

            val provenance = callProvenance(call)
            val untrustedHighRiskSlot = callHasUntrustedHighRiskSlot(call, tool.metadata)
            when (decision) {
                is FirewallDecision.Denied -> {
                    auditLog.record(
                        AuditLogEntry(
                            timestampEpochMs = nowEpochMs,
                            toolName = call.toolName,
                            targetId = stepTargetId,
                            actionSummary = decision.reasonCode,
                            provenance = provenance,
                            decision = "DENIED"
                        )
                    )
                    results.add(
                        ToolResult.Failure(
                            message = decision.message,
                            errorCode = decision.reasonCode,
                            isSecurityViolation = true
                        )
                    )
                    return results
                }

                is FirewallDecision.RequiresBiometric -> {
                    if (!stepBiometric) {
                        results.add(
                            recordConfirmationRequired(
                                call = call,
                                stepTargetId = stepTargetId,
                                nowEpochMs = nowEpochMs,
                                provenance = provenance,
                                message = decision.message,
                                actionSummary = "Biometric verification required",
                                decisionCode = "BIOMETRIC_REQUIRED",
                                requiresBiometric = true,
                                hasUntrustedHighRiskSlot = untrustedHighRiskSlot
                            )
                        )
                        return results
                    }
                    if (!stepConfirmed && untrustedHighRiskSlot) {
                        results.add(
                            recordConfirmationRequired(
                                call = call,
                                stepTargetId = stepTargetId,
                                nowEpochMs = nowEpochMs,
                                provenance = provenance,
                                message = untrustedSlotWarningMessage(),
                                actionSummary = "Untrusted high-risk slot confirmation required",
                                decisionCode = "CONFIRMATION_REQUIRED",
                                requiresBiometric = false,
                                hasUntrustedHighRiskSlot = true
                            )
                        )
                        return results
                    }
                }

                is FirewallDecision.RequiresConfirmation -> {
                    if (!stepConfirmed) {
                        results.add(
                            recordConfirmationRequired(
                                call = call,
                                stepTargetId = stepTargetId,
                                nowEpochMs = nowEpochMs,
                                provenance = provenance,
                                message = decision.message,
                                actionSummary = "User confirmation required",
                                decisionCode = "CONFIRMATION_REQUIRED",
                                requiresBiometric = false,
                                hasUntrustedHighRiskSlot = decision.untrustedHighRiskSlots.isNotEmpty() ||
                                    untrustedHighRiskSlot
                            )
                        )
                        return results
                    }
                }

                FirewallDecision.Authorized -> {
                    if (!stepConfirmed && untrustedHighRiskSlot) {
                        results.add(
                            recordConfirmationRequired(
                                call = call,
                                stepTargetId = stepTargetId,
                                nowEpochMs = nowEpochMs,
                                provenance = provenance,
                                message = untrustedSlotWarningMessage(),
                                actionSummary = "Untrusted high-risk slot confirmation required",
                                decisionCode = "CONFIRMATION_REQUIRED",
                                requiresBiometric = false,
                                hasUntrustedHighRiskSlot = true
                            )
                        )
                        return results
                    }
                }
            }

            val context = ToolExecutionContext(
                requestId = capabilityToken.requestId,
                capabilityToken = capabilityToken,
                ruleGrant = null,
                targetId = stepTargetId,
                languageTag = languageTag,
                issuedAtEpochMs = nowEpochMs,
                isUnattendedBackground = false
            )
            val result = tool.execute(context, call.arguments)
            val outcomeCode = when (result) {
                is ToolResult.Success -> "SUCCESS"
                is ToolResult.ConfirmationRequired -> "CONFIRMATION_REQUIRED"
                is ToolResult.Failure -> result.errorCode
            }
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowEpochMs,
                    toolName = call.toolName,
                    targetId = stepTargetId,
                    actionSummary = "Executed tool ${call.toolName}",
                    provenance = provenance,
                    decision = outcomeCode
                )
            )
            results.add(result)
            if (result !is ToolResult.Success) {
                break
            }
        }
        return results
    }

    private suspend fun recordConfirmationRequired(
        call: ToolCallAst,
        stepTargetId: String,
        nowEpochMs: Long,
        provenance: DataProvenance,
        message: UserMessage,
        actionSummary: String,
        decisionCode: String,
        requiresBiometric: Boolean,
        hasUntrustedHighRiskSlot: Boolean
    ): ToolResult.ConfirmationRequired {
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = nowEpochMs,
                toolName = call.toolName,
                targetId = stepTargetId,
                actionSummary = actionSummary,
                provenance = provenance,
                decision = decisionCode
            )
        )
        return ToolResult.ConfirmationRequired(
            message = message,
            pendingToolName = call.toolName,
            targetId = stepTargetId,
            canonicalArguments = canonicalArgs(call),
            requiresBiometric = requiresBiometric,
            hasUntrustedHighRiskSlot = hasUntrustedHighRiskSlot,
            pendingOrderIndex = call.orderIndex
        )
    }

    private fun untrustedSlotWarningMessage(): UserMessage {
        return UserMessage(
            key = MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE,
            args = listOf(MessageArg.ProvenanceBadge(DataProvenance.UNTRUSTED_EXTERNAL))
        )
    }

    private fun callProvenance(call: ToolCallAst): DataProvenance {
        return call.arguments.values.fold(DataProvenance.USER_UTTERANCE) { acc, arg ->
            DataProvenance.worstOf(acc, arg.provenance)
        }
    }

    private fun canonicalArgs(call: ToolCallAst): Map<String, Tainted<String>> {
        return call.arguments.mapValues { (_, taintedValue) ->
            taintedValue.map { it.asDisplayString() }
        }
    }

    private fun callHasUntrustedHighRiskSlot(call: ToolCallAst, metadata: ToolMetadata): Boolean {
        return call.arguments.any { (name, arg) ->
            arg.requiresExplicitConfirmation ||
                (arg.isUntrusted && metadata.fieldByName(name)?.slotKind?.isHighRisk == true)
        }
    }
}

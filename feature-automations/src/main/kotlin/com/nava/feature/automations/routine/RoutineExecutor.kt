package com.nava.feature.automations.routine

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.automation.RoutineExecutionOutcome
import com.nava.domain.automation.RoutineExecutorPort
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleGrantPort
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.security.Tainted
import com.nava.domain.tool.NavaTool
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolRegistry
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.common.AndroidAutomationNotificationBridge
import com.nava.feature.automations.common.AutomationNotificationBridge
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.CompletionNotificationRequest
import com.nava.feature.automations.common.InteractiveNotificationRequest
import com.nava.feature.automations.common.ToolTargetIds
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Implementation of [RoutineExecutorPort] enforcing compile-time user-approved routine constraints,
 * global pause toggles, HMAC verification, and unattended safety barriers (PLAN.md Section 5.6).
 *
 * Critical Invariants:
 * - If globally paused -> returns [RoutineExecutionOutcome.Denied] (reason `ROUTINES_GLOBALLY_PAUSED`) and audits.
 * - Fresh grant lookup -> always queries [RuleGrantPort.findRule] to avoid executing stale grants.
 * - Firewall authorization -> denies on [FirewallDecision.Denied].
 * - Interactive escalation -> any action requiring biometric verification, Nava Vault, or
 *   [AtomicCapability.MODIFY_DELETE_SEND] (or where `!supportsUnattendedRule`) must NEVER run
 *   unattended; instead, a high-priority interactive notification is posted.
 * - Stage 1/2 isolation -> background routines execute only static pre-approved actions with
 *   [DataProvenance.SYSTEM]; they never invoke Stage 2 extraction or LLM dynamic tool selection.
 */
class RoutineExecutor(
    private val ruleGrantPort: RuleGrantPort,
    private val securityFirewall: SecurityFirewallPort,
    private val toolRegistry: ToolRegistry,
    private val auditLog: AuditLogPort,
    private val notificationBridge: AutomationNotificationBridge,
    private val scheduler: RoutineWorkScheduler
) : RoutineExecutorPort {

    private val isGloballyPaused = AtomicBoolean(false)

    fun setGloballyPaused(paused: Boolean) {
        isGloballyPaused.set(paused)
    }

    fun isGloballyPaused(): Boolean = isGloballyPaused.get()

    override suspend fun executeRule(
        ruleId: String,
        nowEpochMs: Long,
        languageTag: String
    ): RoutineExecutionOutcome {
        if (isGloballyPaused.get()) {
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowEpochMs,
                    toolName = "routine_executor",
                    targetId = ToolTargetIds.ROUTINES,
                    actionSummary = "Routine execution denied: routines globally paused",
                    provenance = DataProvenance.SYSTEM,
                    decision = REASON_ROUTINES_GLOBALLY_PAUSED
                )
            )
            return RoutineExecutionOutcome.Denied(
                ruleId = ruleId,
                reasonCode = REASON_ROUTINES_GLOBALLY_PAUSED,
                message = UserMessage(
                    key = MessageKey.ROUTINE_EXECUTION_DENIED,
                    args = listOf(MessageArg.Text(REASON_ROUTINES_GLOBALLY_PAUSED))
                )
            )
        }

        // Always query fresh grant from storage to prevent stale grant execution
        val grant = ruleGrantPort.findRule(ruleId)
        if (grant == null) {
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowEpochMs,
                    toolName = "routine_executor",
                    targetId = ToolTargetIds.ROUTINES,
                    actionSummary = "Routine $ruleId not found in RuleGrantPort",
                    provenance = DataProvenance.SYSTEM,
                    decision = "RULE_NOT_FOUND"
                )
            )
            return RoutineExecutionOutcome.Failed(
                ruleId = ruleId,
                errorCode = "RULE_NOT_FOUND",
                message = UserMessage(
                    key = MessageKey.ROUTINE_EXECUTION_FAILED,
                    args = listOf(MessageArg.Text("RULE_NOT_FOUND"))
                )
            )
        }

        if (grant.approvalState != RuleApprovalState.APPROVED_ACTIVE) {
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowEpochMs,
                    toolName = "routine_executor",
                    targetId = ToolTargetIds.ROUTINES,
                    actionSummary = "Routine $ruleId is not active (state: ${grant.approvalState})",
                    provenance = DataProvenance.SYSTEM,
                    decision = "RULE_NOT_ACTIVE"
                )
            )
            return RoutineExecutionOutcome.Denied(
                ruleId = ruleId,
                reasonCode = "RULE_NOT_ACTIVE",
                message = UserMessage(
                    key = MessageKey.ROUTINE_EXECUTION_DENIED,
                    args = listOf(MessageArg.Text("RULE_NOT_ACTIVE"))
                )
            )
        }

        val firewallDecision = securityFirewall.authorizeRuleExecution(grant)
        when (firewallDecision) {
            is FirewallDecision.Denied -> {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowEpochMs,
                        toolName = "routine_executor",
                        targetId = ToolTargetIds.ROUTINES,
                        actionSummary = firewallDecision.reasonCode,
                        provenance = DataProvenance.SYSTEM,
                        decision = "DENIED"
                    )
                )
                return RoutineExecutionOutcome.Denied(
                    ruleId = ruleId,
                    reasonCode = firewallDecision.reasonCode,
                    message = firewallDecision.message
                )
            }

            is FirewallDecision.RequiresBiometric,
            is FirewallDecision.RequiresConfirmation -> {
                return escalateToInteractive(
                    grant = grant,
                    requiresBiometric = firewallDecision is FirewallDecision.RequiresBiometric ||
                        grant.staticActions.any { it.requiresBiometric || it.toolName in AutomationToolNames.VAULT_TOOLS },
                    nowEpochMs = nowEpochMs,
                    completedSteps = emptyList()
                )
            }

            FirewallDecision.Authorized -> {
                // Continue to static action checks
            }
        }

        if (grant.requiresInteractiveUpgrade) {
            return escalateToInteractive(
                grant = grant,
                requiresBiometric = grant.staticActions.any { it.requiresBiometric || it.toolName in AutomationToolNames.VAULT_TOOLS },
                nowEpochMs = nowEpochMs,
                completedSteps = emptyList()
            )
        }

        // Double-check every static action and resolved NavaTool metadata
        val resolvedTools = ArrayList<Pair<com.nava.domain.security.RuleActionSpec, NavaTool>>(grant.staticActions.size)
        for (action in grant.staticActions) {
            val tool = toolRegistry.find(action.toolName)
            if (tool == null) {
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowEpochMs,
                        toolName = action.toolName,
                        targetId = ToolTargetIds.ROUTINES,
                        actionSummary = "Tool ${action.toolName} not registered for routine $ruleId",
                        provenance = DataProvenance.SYSTEM,
                        decision = "TOOL_NOT_FOUND"
                    )
                )
                return RoutineExecutionOutcome.Failed(
                    ruleId = ruleId,
                    errorCode = "TOOL_NOT_FOUND",
                    message = UserMessage(
                        key = MessageKey.ROUTINE_EXECUTION_FAILED,
                        args = listOf(MessageArg.Text(action.toolName))
                    )
                )
            }

            if (action.requiresInteractiveConfirmation ||
                action.requiresBiometric ||
                action.toolName in AutomationToolNames.VAULT_TOOLS ||
                action.requiredCapability == AtomicCapability.MODIFY_DELETE_SEND ||
                tool.metadata.requiredCapability == AtomicCapability.MODIFY_DELETE_SEND ||
                !tool.metadata.supportsUnattendedRule
            ) {
                return escalateToInteractive(
                    grant = grant,
                    requiresBiometric = action.requiresBiometric || action.toolName in AutomationToolNames.VAULT_TOOLS,
                    nowEpochMs = nowEpochMs,
                    completedSteps = emptyList()
                )
            }

            if (action.requiredCapability != tool.metadata.requiredCapability) {
                val reasonCode = "CAPABILITY_MISMATCH"
                auditLog.record(
                    AuditLogEntry(
                        timestampEpochMs = nowEpochMs,
                        toolName = action.toolName,
                        targetId = ToolTargetIds.ROUTINES,
                        actionSummary = "Security violation: capability mismatch for tool ${action.toolName} in routine $ruleId: spec=${action.requiredCapability}, metadata=${tool.metadata.requiredCapability}",
                        provenance = DataProvenance.SYSTEM,
                        decision = "DENIED"
                    )
                )
                return RoutineExecutionOutcome.Denied(
                    ruleId = ruleId,
                    reasonCode = reasonCode,
                    message = UserMessage(
                        key = MessageKey.ROUTINE_EXECUTION_DENIED,
                        args = listOf(MessageArg.Text(reasonCode))
                    )
                )
            }
            resolvedTools.add(action to tool)
        }

        // Execute static actions unattended with DataProvenance.SYSTEM
        val completedSteps = ArrayList<ToolResult.Success>(resolvedTools.size)
        for ((action, tool) in resolvedTools) {
            val arguments = LinkedHashMap<String, Tainted<SlotValueAst>>(action.staticArguments.size)
            for ((argName, argVal) in action.staticArguments) {
                val field = tool.metadata.fieldByName(argName)
                val astValue: SlotValueAst = when (field?.valueType) {
                    SlotValueType.INTEGER -> {
                        val parsed = argVal.toLongOrNull()
                        if (parsed != null) SlotValueAst.IntValue(parsed) else SlotValueAst.StringValue(argVal)
                    }
                    SlotValueType.BOOLEAN -> {
                        val parsed = argVal.toBooleanStrictOrNull()
                        if (parsed != null) SlotValueAst.BooleanValue(parsed) else SlotValueAst.StringValue(argVal)
                    }
                    else -> SlotValueAst.StringValue(argVal)
                }
                arguments[argName] = Tainted.fromSystem(
                    value = astValue,
                    slotKind = field?.slotKind
                )
            }

            val context = ToolExecutionContext(
                requestId = "routine:${grant.ruleId}:$nowEpochMs",
                capabilityToken = null,
                ruleGrant = grant,
                targetId = ToolTargetIds.ROUTINES,
                languageTag = languageTag,
                issuedAtEpochMs = nowEpochMs,
                isUnattendedBackground = true
            )

            val result = tool.execute(context, arguments)
            when (result) {
                is ToolResult.Success -> {
                    completedSteps.add(result)
                    auditLog.record(
                        AuditLogEntry(
                            timestampEpochMs = nowEpochMs,
                            toolName = action.toolName,
                            targetId = ToolTargetIds.ROUTINES,
                            actionSummary = "Executed action ${action.toolName} in routine ${grant.ruleId}",
                            provenance = DataProvenance.SYSTEM,
                            decision = "SUCCESS"
                        )
                    )
                }

                is ToolResult.ConfirmationRequired -> {
                    return escalateToInteractive(
                        grant = grant,
                        requiresBiometric = result.requiresBiometric || action.requiresBiometric || action.toolName in AutomationToolNames.VAULT_TOOLS,
                        nowEpochMs = nowEpochMs,
                        completedSteps = completedSteps
                    )
                }

                is ToolResult.Failure -> {
                    auditLog.record(
                        AuditLogEntry(
                            timestampEpochMs = nowEpochMs,
                            toolName = action.toolName,
                            targetId = ToolTargetIds.ROUTINES,
                            actionSummary = "Action ${action.toolName} failed in routine ${grant.ruleId}: ${result.errorCode}",
                            provenance = DataProvenance.SYSTEM,
                            decision = result.errorCode
                        )
                    )
                    return RoutineExecutionOutcome.Failed(
                        ruleId = grant.ruleId,
                        errorCode = result.errorCode,
                        message = result.message,
                        completedSteps = completedSteps
                    )
                }
            }
        }

        val completionMessage = UserMessage(
            key = MessageKey.ROUTINE_EXECUTED,
            args = listOf(MessageArg.Text(grant.ruleId))
        )
        val notifId = AndroidAutomationNotificationBridge.stableNotificationId("routine_complete:${grant.ruleId}")
        notificationBridge.postCompletionNotification(
            CompletionNotificationRequest(
                notificationId = notifId,
                requestId = "routine:${grant.ruleId}:$nowEpochMs",
                message = completionMessage,
                ruleId = grant.ruleId
            )
        )

        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = nowEpochMs,
                toolName = "routine_executor",
                targetId = ToolTargetIds.ROUTINES,
                actionSummary = "Routine ${grant.ruleId} completed unattended",
                provenance = DataProvenance.SYSTEM,
                decision = "SUCCESS"
            )
        )

        return RoutineExecutionOutcome.Executed(
            ruleId = grant.ruleId,
            stepResults = completedSteps,
            message = completionMessage
        )
    }

    override suspend fun scheduleRule(grant: RuleCapabilityGrant) {
        scheduler.schedule(grant)
    }

    override suspend fun cancelRule(ruleId: String) {
        scheduler.cancel(ruleId)
    }

    override suspend fun cancelAllRules() {
        scheduler.cancelAll()
    }

    private suspend fun escalateToInteractive(
        grant: RuleCapabilityGrant,
        requiresBiometric: Boolean,
        nowEpochMs: Long,
        completedSteps: List<ToolResult.Success>
    ): RoutineExecutionOutcome.EscalatedToInteractive {
        val effectiveBiometric = requiresBiometric ||
            grant.staticActions.any { it.requiresBiometric || it.toolName in AutomationToolNames.VAULT_TOOLS }
        val pendingToolNames = grant.staticActions.map { it.toolName }
        val message = UserMessage(
            key = if (effectiveBiometric) {
                MessageKey.ROUTINE_ESCALATED_BIOMETRIC
            } else {
                MessageKey.ROUTINE_ESCALATED_CONFIRMATION
            },
            args = listOf(MessageArg.Text(grant.ruleId))
        )

        val notifId = AndroidAutomationNotificationBridge.stableNotificationId("routine:${grant.ruleId}")
        val request = InteractiveNotificationRequest(
            notificationId = notifId,
            requestId = "routine:${grant.ruleId}:$nowEpochMs",
            pendingToolNames = pendingToolNames,
            targetId = ToolTargetIds.ROUTINES,
            message = message,
            requiresBiometric = effectiveBiometric,
            hasUntrustedHighRiskSlot = false,
            ruleId = grant.ruleId
        )
        notificationBridge.postInteractiveConfirmationNotification(request)

        val decision = if (effectiveBiometric) "ESCALATED_BIOMETRIC" else "ESCALATED_CONFIRMATION"
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = nowEpochMs,
                toolName = "routine_executor",
                targetId = ToolTargetIds.ROUTINES,
                actionSummary = "Escalated routine ${grant.ruleId} to interactive confirmation notification",
                provenance = DataProvenance.SYSTEM,
                decision = decision
            )
        )

        return RoutineExecutionOutcome.EscalatedToInteractive(
            ruleId = grant.ruleId,
            requiresBiometric = effectiveBiometric,
            pendingToolNames = pendingToolNames,
            message = message,
            completedSteps = completedSteps
        )
    }

    companion object {
        const val REASON_ROUTINES_GLOBALLY_PAUSED: String = "ROUTINES_GLOBALLY_PAUSED"
    }
}

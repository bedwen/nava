package com.nava.domain.usecase

import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleGrantPort
import com.nava.domain.security.RuleTriggerSpec
import com.nava.domain.tool.ToolRegistry

/**
 * Manages the compile-time consent lifecycle of persistent background automation routines.
 *
 * Newly compiled rules always enter [RuleApprovalState.PENDING_USER_APPROVAL] and require
 * explicit user consent before an HMAC-sealed [RuleCapabilityGrant] is minted.
 */
class CompileRuleUseCase(
    private val ruleGrantPort: RuleGrantPort,
    private val toolRegistry: ToolRegistry,
    private val auditLog: AuditLogPort
) {
    suspend fun compilePendingRule(
        ruleId: String,
        triggerSpec: RuleTriggerSpec,
        staticActions: List<RuleActionSpec>,
        nowEpochMs: Long,
        provenance: DataProvenance = DataProvenance.USER_UTTERANCE
    ): RuleCapabilityGrant {
        if (provenance != DataProvenance.USER_UTTERANCE) {
            throw SecurityException(
                "Rule compilation requires USER_UTTERANCE provenance, got $provenance"
            )
        }
        require(staticActions.isNotEmpty()) { "Rule must specify at least one action" }
        for (action in staticActions) {
            val tool = toolRegistry.require(action.toolName)
            require(action.requiredCapability == tool.metadata.requiredCapability) {
                "Action capability ${action.requiredCapability} does not match tool '${action.toolName}' requirement ${tool.metadata.requiredCapability}"
            }
            if (!tool.metadata.supportsUnattendedRule) {
                require(action.requiresInteractiveConfirmation) {
                    "Tool '${action.toolName}' requires interactive confirmation"
                }
            }
            for ((k, v) in action.staticArguments) {
                require(k.isNotBlank()) { "Static argument key for '${action.toolName}' must not be blank" }
                if (Gemma4InputSanitizer.sanitize(v) != v) {
                    throw SecurityException("Unsafe control sequence in static argument '$k'")
                }
            }
        }

        val pending = ruleGrantPort.createPendingRule(
            ruleId = ruleId,
            triggerSpec = triggerSpec,
            staticActions = staticActions,
            nowEpochSec = nowEpochMs / 1000L
        )
        require(pending.approvalState == RuleApprovalState.PENDING_USER_APPROVAL) {
            "Compiled rule must start in PENDING_USER_APPROVAL state"
        }

        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = nowEpochMs,
                toolName = "system.rule_compiler",
                targetId = ruleId,
                actionSummary = "Compiled pending rule with ${staticActions.size} action(s)",
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "RULE_PENDING_APPROVAL"
            )
        )
        return pending
    }

    suspend fun approvePendingRule(
        ruleId: String,
        nowEpochMs: Long
    ): RuleCapabilityGrant {
        val approved = ruleGrantPort.approveAndSealRule(
            ruleId = ruleId,
            nowEpochSec = nowEpochMs / 1000L
        )
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = nowEpochMs,
                toolName = "system.rule_compiler",
                targetId = ruleId,
                actionSummary = "User approved and sealed rule grant ${approved.grantId}",
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "RULE_APPROVED"
            )
        )
        return approved
    }

    suspend fun pauseRule(ruleId: String, nowEpochMs: Long) {
        ruleGrantPort.pauseRule(ruleId, nowEpochMs / 1000L)
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = nowEpochMs,
                toolName = "system.rule_compiler",
                targetId = ruleId,
                actionSummary = "Paused background rule",
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "RULE_PAUSED"
            )
        )
    }

    suspend fun revokeRule(ruleId: String, nowEpochMs: Long) {
        ruleGrantPort.revokeRule(ruleId, nowEpochMs / 1000L)
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = nowEpochMs,
                toolName = "system.rule_compiler",
                targetId = ruleId,
                actionSummary = "Revoked background rule",
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "RULE_REVOKED"
            )
        )
    }

    suspend fun listRules(): List<RuleCapabilityGrant> = ruleGrantPort.listRules()
}

package com.nava.domain.security

import com.nava.domain.ai.ToolCallAst
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.ui.UserMessage

/**
 * Deterministic authorization verdict returned by [SecurityFirewallPort].
 */
sealed interface FirewallDecision {
    data object Authorized : FirewallDecision

    data class RequiresConfirmation(
        val message: UserMessage,
        val untrustedHighRiskSlots: Set<String> = emptySet()
    ) : FirewallDecision

    data class RequiresBiometric(
        val message: UserMessage
    ) : FirewallDecision

    data class Denied(
        val message: UserMessage,
        val reasonCode: String
    ) : FirewallDecision
}

/**
 * Deterministic Kotlin-side enforcement boundary for Plan-Then-Extract, Value Taint Tracking,
 * Permission Profiles, Background Rule Grants, and Outbound Channel / IPC policies.
 */
interface SecurityFirewallPort {
    /**
     * Stage 1 minting gate: only [DataProvenance.USER_UTTERANCE] may mint a [CapabilityToken].
     */
    suspend fun mintToken(
        requestId: String,
        utteranceProvenance: DataProvenance,
        candidateTools: Set<String>,
        nowEpochMs: Long
    ): CapabilityToken

    /**
     * Validates a tool invocation against [token], [toolMetadata], the target's [PermissionProfile],
     * and [Tainted] high-risk destination slot rules.
     */
    suspend fun authorizeToolCall(
        token: CapabilityToken,
        toolCall: ToolCallAst,
        toolMetadata: ToolMetadata,
        targetId: String,
        nowEpochMs: Long
    ): FirewallDecision

    /**
     * Verifies HMAC seal integrity and unattended safety constraints on [grant].
     */
    suspend fun authorizeRuleExecution(grant: RuleCapabilityGrant): FirewallDecision

    /**
     * Enforces the Outbound Channel & IPC Exfiltration Policy (blocks http/https URIs and
     * guards untrusted/vault data crossing outbound intents or SAF writes).
     */
    suspend fun validateOutboundTarget(
        toolName: String,
        action: String,
        uriOrTarget: Tainted<String>
    ): FirewallDecision
}

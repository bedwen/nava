package com.nava.domain.automation

import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.UserMessage

/**
 * Deterministic outcome of executing a compiled persistent background automation routine.
 */
sealed interface RoutineExecutionOutcome {
    val ruleId: String
    val message: UserMessage

    /** All static actions in the routine executed safely unattended. */
    data class Executed(
        override val ruleId: String,
        val stepResults: List<ToolResult.Success>,
        override val message: UserMessage
    ) : RoutineExecutionOutcome

    /**
     * One or more actions required interactive confirmation or biometric verification, so
     * unattended execution halted and a high-priority local notification was posted to open
     * Nava's interactive Action Confirmation Card.
     */
    data class EscalatedToInteractive(
        override val ruleId: String,
        val requiresBiometric: Boolean,
        val pendingToolNames: List<String>,
        override val message: UserMessage,
        val completedSteps: List<ToolResult.Success> = emptyList()
    ) : RoutineExecutionOutcome

    /** Routine was denied by SecurityFirewall, PermissionProfile, global pause, or invalid HMAC seal. */
    data class Denied(
        override val ruleId: String,
        val reasonCode: String,
        override val message: UserMessage
    ) : RoutineExecutionOutcome

    /** Routine failed due to a missing rule, unregistered tool, or platform execution error. */
    data class Failed(
        override val ruleId: String,
        val errorCode: String,
        override val message: UserMessage,
        val completedSteps: List<ToolResult.Success> = emptyList()
    ) : RoutineExecutionOutcome
}

/**
 * Port for scheduling, cancelling, and executing compile-time approved background routines
 * backed by Android `WorkManager` and enforced by [com.nava.domain.security.SecurityFirewallPort].
 */
interface RoutineExecutorPort {
    /**
     * Executes the static pre-approved actions of the routine identified by [ruleId].
     *
     * Must never invoke Stage 2 untrusted data extraction or dynamic LLM tool selection,
     * and must never run `Biometric`, `Nava Vault`, or `MODIFY_DELETE_SEND` actions unattended.
     */
    suspend fun executeRule(
        ruleId: String,
        nowEpochMs: Long,
        languageTag: String = "en"
    ): RoutineExecutionOutcome

    /** Registers or updates the background schedule for an approved [grant]. */
    suspend fun scheduleRule(grant: RuleCapabilityGrant)

    /** Cancels any scheduled background work for [ruleId]. */
    suspend fun cancelRule(ruleId: String)

    /** Cancels all scheduled background routines (e.g., when background rules are globally paused). */
    suspend fun cancelAllRules()
}

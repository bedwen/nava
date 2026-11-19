package com.nava.domain.security

/**
 * Lifecycle state of a compiled persistent background automation rule.
 */
enum class RuleApprovalState {
    PENDING_USER_APPROVAL,
    APPROVED_ACTIVE,
    PAUSED,
    REVOKED
}

/**
 * Declarative trigger condition for a background automation routine.
 */
data class RuleTriggerSpec(
    val triggerType: String,
    val parameters: Map<String, String> = emptyMap()
) {
    init {
        require(triggerType.isNotBlank()) { "triggerType must not be blank" }
    }
}

/**
 * Static, pre-approved tool action within a compiled background automation routine.
 */
data class RuleActionSpec(
    val toolName: String,
    val requiredCapability: AtomicCapability,
    val staticArguments: Map<String, String> = emptyMap(),
    val requiresBiometric: Boolean = false
) {
    init {
        require(toolName.isNotBlank()) { "toolName must not be blank" }
    }

    /** True when this action must degrade to an interactive confirmation notification rather than run silently. */
    val requiresInteractiveConfirmation: Boolean
        get() = requiresBiometric || requiredCapability == AtomicCapability.MODIFY_DELETE_SEND
}

/**
 * Compile-time user-approved capability grant bound to a persistent background routine.
 *
 * Unattended execution is forbidden for [AtomicCapability.MODIFY_DELETE_SEND] or biometric actions,
 * and requires an active [RuleApprovalState.APPROVED_ACTIVE] state with a valid [sealHmacHex].
 */
data class RuleCapabilityGrant(
    val grantId: String,
    val ruleId: String,
    val triggerSpec: RuleTriggerSpec,
    val staticActions: List<RuleActionSpec>,
    val approvalState: RuleApprovalState,
    val sealHmacHex: String = "",
    val grantedAtEpochSec: Long = 0L
) {
    init {
        require(grantId.isNotBlank()) { "grantId must not be blank" }
        require(ruleId.isNotBlank()) { "ruleId must not be blank" }
        require(staticActions.isNotEmpty()) { "RuleCapabilityGrant must define at least one static action" }
    }

    /** True when any action in the routine cannot run unattended and requires interactive user confirmation. */
    val requiresInteractiveUpgrade: Boolean
        get() = staticActions.any { it.requiresInteractiveConfirmation }

    /**
     * Returns true strictly when the rule is approved, sealed, and all actions are safe
     * for unattended background execution.
     */
    fun canExecuteUnattended(): Boolean {
        if (approvalState != RuleApprovalState.APPROVED_ACTIVE) return false
        if (sealHmacHex.isBlank()) return false
        if (requiresInteractiveUpgrade) return false
        return true
    }
}

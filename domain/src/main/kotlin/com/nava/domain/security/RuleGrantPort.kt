package com.nava.domain.security

/**
 * Port managing compile-time user-approved persistent background rules and their HMAC seals.
 */
interface RuleGrantPort {
    suspend fun createPendingRule(
        ruleId: String,
        triggerSpec: RuleTriggerSpec,
        staticActions: List<RuleActionSpec>,
        nowEpochSec: Long
    ): RuleCapabilityGrant

    suspend fun approveAndSealRule(
        ruleId: String,
        nowEpochSec: Long
    ): RuleCapabilityGrant

    suspend fun pauseRule(
        ruleId: String,
        nowEpochSec: Long
    )

    suspend fun revokeRule(
        ruleId: String,
        nowEpochSec: Long
    )

    suspend fun findRule(ruleId: String): RuleCapabilityGrant?

    suspend fun listRules(): List<RuleCapabilityGrant>
}

package com.nava.domain.tool

import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant

/**
 * Execution context passed to [NavaTool.execute], always bound to either a Stage 1
 * [CapabilityToken] (interactive query) or a compile-time sealed [RuleCapabilityGrant]
 * (unattended background routine).
 */
data class ToolExecutionContext(
    val requestId: String,
    val capabilityToken: CapabilityToken?,
    val ruleGrant: RuleCapabilityGrant?,
    val targetId: String,
    val languageTag: String,
    val issuedAtEpochMs: Long,
    val isUnattendedBackground: Boolean = false
) {
    init {
        require(requestId.isNotBlank()) { "requestId must not be blank" }
        require(targetId.isNotBlank()) { "targetId must not be blank" }
        require(languageTag.isNotBlank()) { "languageTag must not be blank" }
        if (isUnattendedBackground) {
            require(capabilityToken == null) {
                "Unattended background execution must not carry a Stage 1 CapabilityToken"
            }
            require(ruleGrant != null && ruleGrant.canExecuteUnattended()) {
                "Unattended background execution requires an active, safe RuleCapabilityGrant"
            }
        } else {
            require(capabilityToken != null) {
                "Interactive execution requires a Stage 1 CapabilityToken"
            }
            if (ruleGrant != null) {
                require(
                    ruleGrant.approvalState == RuleApprovalState.APPROVED_ACTIVE &&
                        ruleGrant.sealHmacHex.isNotBlank()
                ) {
                    "Attached RuleCapabilityGrant must be active and HMAC-sealed"
                }
            }
        }
    }
}

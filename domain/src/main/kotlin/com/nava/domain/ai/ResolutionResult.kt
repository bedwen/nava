package com.nava.domain.ai

import com.nava.domain.security.CapabilityToken
import com.nava.domain.ui.UserMessage

/**
 * Outcome produced by an [IntentResolver] tier in Nava's 3-Tier Hybrid Router.
 */
sealed interface ResolutionResult {
    data class ResolvedPlan(
        val tier: ResolutionTier,
        val plan: PlanAst,
        val capabilityToken: CapabilityToken,
        val skeletonUsed: String? = null
    ) : ResolutionResult

    data class ConversationalReply(
        val tier: ResolutionTier,
        val replyText: String,
        val languageTag: String
    ) : ResolutionResult

    data object NoMatch : ResolutionResult

    data class ClarificationNeeded(
        val message: UserMessage
    ) : ResolutionResult
}

package com.nava.domain.ai

import com.nava.domain.tool.ToolMetadata

/**
 * Chain-of-Responsibility port implemented by Tier 1 (`RuleIntentResolver`),
 * Tier 2 (`CacheIntentResolver`), and Tier 3 (`GemmaIntentResolver`).
 */
interface IntentResolver {
    val tier: ResolutionTier

    suspend fun resolve(
        request: IntentRequest,
        availableTools: List<ToolMetadata>
    ): ResolutionResult
}

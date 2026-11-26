package com.nava.domain.ai

/**
 * The tiers of Nava's Hybrid Intent Router, ordered from fastest deterministic
 * reflex execution through FunctionGemma tool routing to on-device Gemma 4 cognitive inference.
 */
enum class ResolutionTier {
    TIER_1_RULE,
    TIER_2_CACHE,
    TIER_2_5_FUNCTION_GEMMA,
    TIER_3_GEMMA
}

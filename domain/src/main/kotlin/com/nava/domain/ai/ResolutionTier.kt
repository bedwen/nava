package com.nava.domain.ai

/**
 * The three tiers of Nava's Hybrid Intent Router, ordered from fastest deterministic
 * reflex execution to on-device Gemma 4 cognitive inference.
 */
enum class ResolutionTier {
    TIER_1_RULE,
    TIER_2_CACHE,
    TIER_3_GEMMA
}

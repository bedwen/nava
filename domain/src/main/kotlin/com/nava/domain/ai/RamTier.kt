package com.nava.domain.ai

/**
 * Contiguous device RAM tiers governing Gemma 4 model selection, context length,
 * and idle mmap unload timeout.
 */
enum class RamTier(
    val defaultContextTokens: Int,
    val idleUnloadTimeoutSec: Int,
    val recommendedModelTag: String
) {
    /** Total RAM < 6.0 GB: Deterministic Tiers 1/2 + optional single-turn low-context E2B. */
    TIER_0_LOW_MEMORY(
        defaultContextTokens = 1024,
        idleUnloadTimeoutSec = 0,
        recommendedModelTag = "gemma-4-E2B-it"
    ),

    /** 6.0 GB <= Total RAM < 12.0 GB: 4-bit quantized Gemma 4 E2B with 4096-token context and 180s idle unload. */
    TIER_1_STANDARD(
        defaultContextTokens = 4096,
        idleUnloadTimeoutSec = 180,
        recommendedModelTag = "gemma-4-E2B-it"
    ),

    /** Total RAM >= 12.0 GB: Universal Gemma 4 E2B default (user may opt into E4B). */
    TIER_2_HIGH(
        defaultContextTokens = 4096,
        idleUnloadTimeoutSec = 180,
        recommendedModelTag = "gemma-4-E2B-it"
    );

    /** Optimal KV-cache context ceiling when running Gemma 4 E2B on this RAM tier. */
    val e2bOptimalContextTokens: Int
        get() = when (this) {
            TIER_0_LOW_MEMORY -> 1024
            TIER_1_STANDARD, TIER_2_HIGH -> 2048
        }

    companion object {
        private const val SIX_GB_BYTES = 6L * 1024L * 1024L * 1024L
        private const val TWELVE_GB_BYTES = 12L * 1024L * 1024L * 1024L

        fun fromTotalRamBytes(totalRamBytes: Long): RamTier {
            require(totalRamBytes >= 0L) { "totalRamBytes must be non-negative" }
            return when {
                totalRamBytes < SIX_GB_BYTES -> TIER_0_LOW_MEMORY
                totalRamBytes < TWELVE_GB_BYTES -> TIER_1_STANDARD
                else -> TIER_2_HIGH
            }
        }
    }
}

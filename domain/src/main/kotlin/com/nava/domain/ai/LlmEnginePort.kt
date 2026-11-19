package com.nava.domain.ai

import com.nava.domain.tool.ToolMetadata
import kotlinx.coroutines.flow.Flow

/**
 * Request contract for on-device LLM inference implementing the three-segment KV-cache
 * layout: Segment A (pinned system prefix), Segment B (pruned tool declarations), Segment C (user turn).
 */
data class LlmGenerationRequest(
    val requestId: String,
    val systemPrefixId: String,
    val prunedTools: List<ToolMetadata>,
    val userUtterance: String,
    val languageHintTag: String,
    val allowThoughtMode: Boolean = false,
    val maxThoughtTokens: Int = 256,
    val maxOutputTokens: Int = 512,
    val stage2BlindExtractionMode: Boolean = false
) {
    init {
        require(requestId.isNotBlank()) { "requestId must not be blank" }
        require(systemPrefixId.isNotBlank()) { "systemPrefixId must not be blank" }
        require(languageHintTag.isNotBlank()) { "languageHintTag must not be blank" }
        require(maxThoughtTokens >= 0) { "maxThoughtTokens must be non-negative" }
        require(maxOutputTokens > 0) { "maxOutputTokens must be positive" }
        require(!stage2BlindExtractionMode || prunedTools.isEmpty()) {
            "Stage 2 blind extraction mode requires empty prunedTools"
        }
    }
}

/**
 * Streaming token event emitted during on-device Gemma 4 inference.
 */
sealed interface LlmStreamChunk {
    data class ThoughtDelta(val text: String) : LlmStreamChunk
    data class OutputDelta(val text: String) : LlmStreamChunk
    data class Completed(val result: LlmGenerationResult) : LlmStreamChunk
    data class Aborted(val reason: String, val thoughtBudgetExceeded: Boolean = false) : LlmStreamChunk
}

/**
 * Completed inference payload returned by [LlmEnginePort].
 */
data class LlmGenerationResult(
    val rawOutput: String,
    val thoughtTokensUsed: Int = 0,
    val outputTokensUsed: Int = 0,
    val durationMs: Long = 0L,
    val thoughtClosedCleanly: Boolean = true
)

/**
 * Pure Kotlin inference port implemented by `LiteRtLlmEngine` in `:core-ai`.
 */
interface LlmEnginePort {
    suspend fun isModelLoaded(): Boolean
    suspend fun currentRamTier(): RamTier
    suspend fun currentThermalState(): ThermalState
    suspend fun generate(request: LlmGenerationRequest): LlmGenerationResult
    fun generateStream(request: LlmGenerationRequest): Flow<LlmStreamChunk>
    suspend fun unloadModel()
}

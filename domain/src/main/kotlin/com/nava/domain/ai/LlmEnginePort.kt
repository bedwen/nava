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
    val stage2BlindExtractionMode: Boolean = false,
    val conversationHistory: List<ConversationTurn> = emptyList(),
    val currentLocalDateTimeIso: String? = null,
    /**
     * Bounded user-authored facts (see `PersonalFactContext`) shown to the planner as context.
     * Always empty in Stage 2 blind extraction.
     */
    val userFacts: List<String> = emptyList()
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
        require(!stage2BlindExtractionMode || conversationHistory.isEmpty()) {
            "Stage 2 blind extraction mode requires empty conversationHistory"
        }
        require(!stage2BlindExtractionMode || userFacts.isEmpty()) {
            "Stage 2 blind extraction mode requires empty userFacts"
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
    suspend fun resetChatSession() {}

    /**
     * Optionally loads weights and the [systemPrefixId] prefix ahead of the first turn.
     * Returns true only if the model is resident afterwards. Implementations must honor the
     * same thermal/battery/RAM unload policy as a normal turn. Default: no prewarming.
     */
    suspend fun prewarm(systemPrefixId: String): Boolean = false
    suspend fun unloadModel()
}

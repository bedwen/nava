package com.nava.core.ai.engine

import android.content.Context
import com.google.ai.edge.litertlm.Backend
import com.google.ai.edge.litertlm.Contents
import com.google.ai.edge.litertlm.Conversation
import com.google.ai.edge.litertlm.ConversationConfig
import com.google.ai.edge.litertlm.Engine
import com.google.ai.edge.litertlm.EngineConfig
import com.google.ai.edge.litertlm.ExperimentalApi
import com.google.ai.edge.litertlm.SamplerConfig
import com.google.ai.edge.litertlm.SuppressTokensConfig
import com.google.ai.edge.litertlm.ThinkingConfig
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.core.ai.prompt.Gemma4PromptFormat
import com.nava.domain.ai.LlmEnginePort
import com.nava.domain.ai.LlmGenerationRequest
import com.nava.domain.ai.LlmGenerationResult
import com.nava.domain.ai.LlmStreamChunk
import com.nava.domain.ai.RamTier
import com.nava.domain.ai.ThermalState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Runtime turn configuration passed from [LiteRtLlmEngine] to [LiteRtRuntimeAdapter].
 */
data class RuntimeTurnConfig(
    val promptText: String,
    val allowThoughtMode: Boolean,
    val maxThoughtTokens: Int,
    val maxOutputTokens: Int,
    val stage2BlindExtractionMode: Boolean,
    val suppressTokenIds: List<Int>
)

/**
 * Single incremental chunk emitted by [LiteRtRuntimeAdapter.runClonedTurn].
 */
data class RuntimeStreamDelta(
    val thoughtDelta: String = "",
    val outputDelta: String = "",
    val toolCallDetected: Boolean = false
)

/**
 * Thin runtime abstraction over `com.google.ai.edge.litertlm` enabling deterministic JVM testing
 * of prefix pinning, cloned turns, Stage 2 suppression, thermal unloading, and thought budgets.
 */
interface LiteRtRuntimeAdapter {
    fun isLoaded(): Boolean

    suspend fun ensureMasterPrefix(
        modelPath: String,
        systemPrefixId: String,
        systemPrompt: String,
        maxNumTokens: Int
    )

    fun runClonedTurn(
        systemPrefixId: String,
        config: RuntimeTurnConfig
    ): Flow<RuntimeStreamDelta>

    suspend fun unload()
}

/**
 * Production Android adapter wrapping Google's official `com.google.ai.edge.litertlm` SDK
 * (validated in Phase 0: `litertlm-android:0.19.1`, `prefillPrefaceOnInit = true`, `Conversation.clone()`).
 */
class AndroidLiteRtRuntimeAdapter(
    private val context: Context,
    private val useGpuBackend: Boolean = true,
    private val suppressTokenIds: List<Int> = Gemma4PromptFormat.defaultStage2SuppressTokenIds
) : LiteRtRuntimeAdapter {

    private val stateMutex = Mutex()
    @Volatile
    private var activeEngine: Engine? = null
    private var loadedModelPath: String? = null
    private var loadedMaxNumTokens: Int = -1
    private val masterPrefixes = LinkedHashMap<String, Conversation>()

    override fun isLoaded(): Boolean {
        val engine = activeEngine ?: return false
        return runCatching { engine.isInitialized() }.getOrDefault(false)
    }

    @OptIn(ExperimentalApi::class)
    override suspend fun ensureMasterPrefix(
        modelPath: String,
        systemPrefixId: String,
        systemPrompt: String,
        maxNumTokens: Int
    ) {
        withContext(Dispatchers.IO) {
            stateMutex.withLock {
                val mustReinitialize = activeEngine == null ||
                    !isLoaded() ||
                    loadedModelPath != modelPath ||
                    loadedMaxNumTokens != maxNumTokens

                if (mustReinitialize) {
                    unloadLocked()
                    val backend = if (useGpuBackend) Backend.GPU() else Backend.CPU()
                    val engineConfig = EngineConfig(
                        modelPath = modelPath,
                        backend = backend,
                        maxNumTokens = maxNumTokens,
                        cacheDir = context.cacheDir.absolutePath
                    )
                    val createdEngine = Engine(engineConfig)
                    try {
                        createdEngine.initialize()
                    } catch (t: Throwable) {
                        if (createdEngine.isInitialized()) {
                            runCatching { createdEngine.close() }
                        }
                        throw t
                    }
                    activeEngine = createdEngine
                    loadedModelPath = modelPath
                    loadedMaxNumTokens = maxNumTokens
                }

                if (systemPrefixId !in masterPrefixes) {
                    val engine = activeEngine
                        ?: throw IllegalStateException("LiteRT-LM engine failed to initialize")
                    val config = ConversationConfig(
                        systemInstruction = Contents.of(systemPrompt),
                        tools = emptyList(),
                        automaticToolCalling = false,
                        prefillPrefaceOnInit = true,
                        enableResponseFormat = true,
                        maxOutputToken = DEFAULT_CONVERSATION_MAX_OUTPUT_TOKENS,
                        thinkingConfig = ThinkingConfig(
                            enableThinking = false,
                            thinkingTokenBudget = 0
                        ),
                        extraContext = mapOf("enable_thinking" to false),
                        samplerConfig = SamplerConfig(
                            topK = DEFAULT_TOP_K,
                            topP = DEFAULT_TOP_P,
                            temperature = DEFAULT_TEMPERATURE
                        )
                    )
                    masterPrefixes[systemPrefixId] = engine.createConversation(config)
                }
            }
        }
    }

    @OptIn(ExperimentalApi::class)
    override fun runClonedTurn(
        systemPrefixId: String,
        config: RuntimeTurnConfig
    ): Flow<RuntimeStreamDelta> = flow {
        val clonedConversation = stateMutex.withLock {
            val master = masterPrefixes[systemPrefixId]
                ?: throw IllegalStateException("Master prefix '$systemPrefixId' is not initialized")
            master.clone()
        }

        try {
            val effectiveThinking = if (config.allowThoughtMode && !config.stage2BlindExtractionMode) {
                ThinkingConfig(
                    enableThinking = true,
                    thinkingTokenBudget = config.maxThoughtTokens
                )
            } else {
                ThinkingConfig(
                    enableThinking = false,
                    thinkingTokenBudget = 0
                )
            }

            val effectiveSuppressIds = if (config.stage2BlindExtractionMode) {
                if (config.suppressTokenIds.isNotEmpty()) config.suppressTokenIds else suppressTokenIds
            } else {
                emptyList()
            }
            val suppressCfg = if (effectiveSuppressIds.isNotEmpty()) {
                SuppressTokensConfig(suppressTokens = effectiveSuppressIds)
            } else {
                null
            }

            clonedConversation.sendMessageAsync(
                text = config.promptText,
                extraContext = mapOf("enable_thinking" to effectiveThinking.enableThinking),
                suppressTokensConfig = suppressCfg,
                maxOutputToken = config.maxOutputTokens,
                thinkingConfig = effectiveThinking
            ).collect { chunk ->
                val thoughtDelta = chunk.channels[Gemma4PromptFormat.CHANNEL_THOUGHT] ?: ""
                val outputDelta = chunk.toString()
                val toolCallDetected = chunk.toolCalls.isNotEmpty()
                if (thoughtDelta.isNotEmpty() || outputDelta.isNotEmpty() || toolCallDetected) {
                    emit(
                        RuntimeStreamDelta(
                            thoughtDelta = thoughtDelta,
                            outputDelta = outputDelta,
                            toolCallDetected = toolCallDetected
                        )
                    )
                }
            }
        } finally {
            runCatching { clonedConversation.close() }
        }
    }.flowOn(Dispatchers.IO)

    override suspend fun unload() {
        withContext(Dispatchers.IO) {
            stateMutex.withLock {
                unloadLocked()
            }
        }
    }

    private fun unloadLocked() {
        for (conversation in masterPrefixes.values) {
            runCatching { conversation.close() }
        }
        masterPrefixes.clear()
        val engine = activeEngine
        activeEngine = null
        loadedModelPath = null
        loadedMaxNumTokens = -1
        if (engine != null) {
            runCatching {
                if (engine.isInitialized()) {
                    engine.close()
                }
            }
        }
    }

    companion object {
        private const val DEFAULT_CONVERSATION_MAX_OUTPUT_TOKENS: Int = 512
        private const val DEFAULT_TOP_K: Int = 40
        private const val DEFAULT_TOP_P: Double = 0.95
        private const val DEFAULT_TEMPERATURE: Double = 0.2
    }
}

/**
 * Production implementation of [LlmEnginePort] enforcing Segment A KV-cache prefix pinning,
 * cloned per-turn sessions, Stage 2 blind extraction isolation, bounded thought budgets,
 * and thermal/battery lifecycle policies (PLAN.md Sections 2.3, 4.1, 4.2, and 5.3).
 */
class LiteRtLlmEngine(
    private val modelPathProvider: suspend () -> String?,
    private val lifecycleManager: ThermalModelLifecycleManager,
    private val runtimeAdapter: LiteRtRuntimeAdapter,
    private val stage2SuppressTokenIds: List<Int> = Gemma4PromptFormat.defaultStage2SuppressTokenIds,
    private val clockMs: () -> Long = System::currentTimeMillis
) : LlmEnginePort {

    private val inferenceMutex = Mutex()

    override suspend fun isModelLoaded(): Boolean = runtimeAdapter.isLoaded()

    override suspend fun currentRamTier(): RamTier = lifecycleManager.currentRamTier()

    override suspend fun currentThermalState(): ThermalState = lifecycleManager.currentThermalState()

    override suspend fun unloadModel() {
        inferenceMutex.withLock {
            lifecycleManager.forceUnload {
                runtimeAdapter.unload()
            }
        }
    }

    private sealed interface TurnOutcome {
        data class Done(val result: LlmGenerationResult) : TurnOutcome
        data class FatalAbort(val reason: String) : TurnOutcome
    }

    override suspend fun generate(request: LlmGenerationRequest): LlmGenerationResult {
        return when (val outcome = runTurn(request) { /* non-streaming consumer */ }) {
            is TurnOutcome.Done -> outcome.result
            is TurnOutcome.FatalAbort -> throw IllegalStateException(outcome.reason)
        }
    }

    override fun generateStream(request: LlmGenerationRequest): Flow<LlmStreamChunk> = flow {
        runTurn(request) { chunk -> emit(chunk) }
    }

    private suspend fun runTurn(
        request: LlmGenerationRequest,
        emitChunk: suspend (LlmStreamChunk) -> Unit
    ): TurnOutcome {
        val startMs = clockMs()

        if (request.stage2BlindExtractionMode) {
            if (request.systemPrefixId != Gemma4PromptFormat.STAGE2_BLIND_EXTRACTION_PREFIX_ID) {
                throw SecurityException(
                    "Stage 2 blind extraction requires systemPrefixId '${Gemma4PromptFormat.STAGE2_BLIND_EXTRACTION_PREFIX_ID}', got '${request.systemPrefixId}'"
                )
            }
            if (request.prunedTools.isNotEmpty()) {
                val reason = "Stage 2 blind extraction requires empty tools"
                emitChunk(LlmStreamChunk.Aborted(reason = reason))
                return TurnOutcome.FatalAbort(reason)
            }
        }

        val systemPrompt = Gemma4PromptFormat.systemPromptForPrefixId(request.systemPrefixId)
        val promptText = if (request.stage2BlindExtractionMode) {
            Gemma4PromptFormat.formatStage2UserTurn(
                sanitizedPrompt = request.userUtterance,
                languageHintTag = request.languageHintTag
            )
        } else {
            Gemma4PromptFormat.formatTurnPayloadSegmentBAndC(
                prunedTools = request.prunedTools,
                languageHintTag = request.languageHintTag,
                userUtterance = request.userUtterance
            )
        }

        return inferenceMutex.withLock {
            if (lifecycleManager.currentThermalState() == ThermalState.SEVERE_OR_HIGHER) {
                lifecycleManager.forceUnload { runtimeAdapter.unload() }
                val reason = "Thermal throttling SEVERE"
                emitChunk(LlmStreamChunk.Aborted(reason = reason))
                return@withLock TurnOutcome.FatalAbort(reason)
            }

            val modelPath = modelPathProvider()
            if (modelPath.isNullOrBlank() || !File(modelPath).let { it.exists() && it.isFile }) {
                val reason = "Model not provisioned"
                emitChunk(LlmStreamChunk.Aborted(reason = reason))
                return@withLock TurnOutcome.FatalAbort(reason)
            }

            val effectiveAllowThought = request.allowThoughtMode &&
                !request.stage2BlindExtractionMode &&
                lifecycleManager.isThoughtModeAllowed() &&
                request.maxThoughtTokens > 0

            val effectiveThoughtBudget = if (effectiveAllowThought) request.maxThoughtTokens else 0
            val turnConfig = RuntimeTurnConfig(
                promptText = promptText,
                allowThoughtMode = effectiveAllowThought,
                maxThoughtTokens = effectiveThoughtBudget,
                maxOutputTokens = request.maxOutputTokens,
                stage2BlindExtractionMode = request.stage2BlindExtractionMode,
                suppressTokenIds = if (request.stage2BlindExtractionMode) stage2SuppressTokenIds else emptyList()
            )

            lifecycleManager.onEnsureLoaded {
                runtimeAdapter.ensureMasterPrefix(
                    modelPath = modelPath,
                    systemPrefixId = request.systemPrefixId,
                    systemPrompt = systemPrompt,
                    maxNumTokens = lifecycleManager.effectiveContextTokens()
                )
            }

            val outputBuilder = StringBuilder()
            var channelThoughtTokens = 0
            var inlineThoughtTokens = 0
            var outputTokens = 0
            var thoughtAbortedReason: String? = null

            try {
                try {
                    runtimeAdapter.runClonedTurn(request.systemPrefixId, turnConfig).collect { delta ->
                        if (request.stage2BlindExtractionMode && delta.toolCallDetected) {
                            emitChunk(
                                LlmStreamChunk.Aborted(
                                    reason = "Stage 2 runtime detected forbidden tool invocation"
                                )
                            )
                            throw SecurityException("Stage 2 runtime emitted forbidden tool call")
                        }

                        if (delta.thoughtDelta.isNotEmpty()) {
                            channelThoughtTokens += estimateTokenCount(delta.thoughtDelta)
                            emitChunk(LlmStreamChunk.ThoughtDelta(delta.thoughtDelta))
                            if (channelThoughtTokens > effectiveThoughtBudget) {
                                throw ThoughtBudgetAbortSignal(
                                    "Thought token budget exceeded ($channelThoughtTokens > $effectiveThoughtBudget)"
                                )
                            }
                        }

                        if (delta.outputDelta.isNotEmpty()) {
                            outputBuilder.append(delta.outputDelta)
                            inlineThoughtTokens = countInlineThoughtTokens(outputBuilder.toString())
                            if (channelThoughtTokens + inlineThoughtTokens > effectiveThoughtBudget) {
                                throw ThoughtBudgetAbortSignal(
                                    "Inline thought channel exceeded budget (${channelThoughtTokens + inlineThoughtTokens} > $effectiveThoughtBudget)"
                                )
                            }
                            outputTokens += estimateTokenCount(delta.outputDelta)
                            emitChunk(LlmStreamChunk.OutputDelta(delta.outputDelta))
                        }
                    }
                } catch (signal: ThoughtBudgetAbortSignal) {
                    thoughtAbortedReason = signal.message
                }
            } finally {
                withContext(NonCancellable) {
                    lifecycleManager.onTurnCompleted(
                        immediateUnloader = {
                            runtimeAdapter.unload()
                        },
                        deferredIdleUnloader = { expectedGen ->
                            inferenceMutex.withLock {
                                if (lifecycleManager.consumePendingIdleUnload(expectedGen)) {
                                    runtimeAdapter.unload()
                                }
                            }
                        }
                    )
                }
            }

            val elapsedMs = (clockMs() - startMs).coerceAtLeast(0L)
            val rawOutput = outputBuilder.toString()
            inlineThoughtTokens = countInlineThoughtTokens(rawOutput)
            val totalThoughtTokens = channelThoughtTokens + inlineThoughtTokens

            val abortReason = thoughtAbortedReason
            if (abortReason != null) {
                emitChunk(
                    LlmStreamChunk.Aborted(
                        reason = abortReason,
                        thoughtBudgetExceeded = true
                    )
                )
                return@withLock TurnOutcome.Done(
                    LlmGenerationResult(
                        rawOutput = "",
                        thoughtTokensUsed = totalThoughtTokens,
                        outputTokensUsed = outputTokens,
                        durationMs = elapsedMs,
                        thoughtClosedCleanly = false
                    )
                )
            }

            if (hasUnclosedThoughtChannel(rawOutput) ||
                (channelThoughtTokens > 0 && rawOutput.isBlank())
            ) {
                emitChunk(
                    LlmStreamChunk.Aborted(
                        reason = "Unclosed thought channel block",
                        thoughtBudgetExceeded = true
                    )
                )
                return@withLock TurnOutcome.Done(
                    LlmGenerationResult(
                        rawOutput = "",
                        thoughtTokensUsed = totalThoughtTokens,
                        outputTokensUsed = outputTokens,
                        durationMs = elapsedMs,
                        thoughtClosedCleanly = false
                    )
                )
            }

            val completedResult = LlmGenerationResult(
                rawOutput = rawOutput,
                thoughtTokensUsed = totalThoughtTokens,
                outputTokensUsed = outputTokens,
                durationMs = elapsedMs,
                thoughtClosedCleanly = true
            )
            emitChunk(LlmStreamChunk.Completed(completedResult))
            TurnOutcome.Done(completedResult)
        }
    }

    private class ThoughtBudgetAbortSignal(override val message: String) : RuntimeException(message)

    private fun hasUnclosedThoughtChannel(text: String): Boolean {
        var pos = 0
        while (pos < text.length) {
            val openIdx = text.indexOf(Gemma4PromptFormat.CHANNEL_OPEN, pos)
            if (openIdx < 0) return false
            val afterOpen = openIdx + Gemma4PromptFormat.CHANNEL_OPEN.length
            val closeIdx = text.indexOf(Gemma4PromptFormat.CHANNEL_CLOSE, afterOpen)
            if (closeIdx < 0) return true
            pos = closeIdx + Gemma4PromptFormat.CHANNEL_CLOSE.length
        }
        return false
    }

    private fun countInlineThoughtTokens(text: String): Int {
        var total = 0
        var pos = 0
        while (pos < text.length) {
            val openIdx = text.indexOf(Gemma4PromptFormat.CHANNEL_OPEN, pos)
            if (openIdx < 0) break
            val afterOpen = openIdx + Gemma4PromptFormat.CHANNEL_OPEN.length
            val closeIdx = text.indexOf(Gemma4PromptFormat.CHANNEL_CLOSE, afterOpen)
            val bodyEnd = if (closeIdx >= 0) closeIdx else text.length
            val body = text.substring(afterOpen, bodyEnd)
            val strippedHeader = if (body.startsWith(Gemma4PromptFormat.CHANNEL_THOUGHT)) {
                body.removePrefix(Gemma4PromptFormat.CHANNEL_THOUGHT).trim()
            } else {
                body.trim()
            }
            if (strippedHeader.isNotEmpty()) {
                total += estimateTokenCount(strippedHeader)
            }
            if (closeIdx < 0) break
            pos = closeIdx + Gemma4PromptFormat.CHANNEL_CLOSE.length
        }
        return total
    }

    private fun estimateTokenCount(text: String): Int {
        if (text.isEmpty()) return 0
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return 0
        var tokens = 0
        var inWord = false
        var wordLen = 0
        for (ch in trimmed) {
            if (ch.isWhitespace()) {
                if (inWord) {
                    tokens += if (wordLen <= 12) 1 else ((wordLen + 7) / 8)
                    inWord = false
                    wordLen = 0
                }
            } else {
                inWord = true
                wordLen++
            }
        }
        if (inWord) {
            tokens += if (wordLen <= 12) 1 else ((wordLen + 7) / 8)
        }
        return tokens.coerceAtLeast(1)
    }
}

package com.nava.core.ai.engine

import android.content.Context
import android.util.Log
import com.google.ai.edge.litertlm.Backend
import com.google.ai.edge.litertlm.Contents
import com.google.ai.edge.litertlm.Conversation
import com.google.ai.edge.litertlm.ConversationConfig
import com.google.ai.edge.litertlm.Engine
import com.google.ai.edge.litertlm.EngineConfig
import com.google.ai.edge.litertlm.ExperimentalApi
import com.google.ai.edge.litertlm.ExperimentalFlags
import com.google.ai.edge.litertlm.SamplerConfig
import com.google.ai.edge.litertlm.SuppressTokensConfig
import com.google.ai.edge.litertlm.ThinkingConfig
import com.nava.core.ai.lifecycle.ModelSlot
import com.nava.core.ai.lifecycle.MultiModelCoordinator
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.core.ai.prompt.FunctionGemmaPromptFormat
import com.nava.core.ai.prompt.Gemma4PromptFormat
import com.nava.domain.ai.LlmEnginePort
import com.nava.domain.ai.LlmGenerationRequest
import com.nava.domain.ai.LlmGenerationResult
import com.nava.domain.ai.LlmStreamChunk
import com.nava.domain.ai.RamTier
import com.nava.domain.ai.ThermalState
import kotlinx.coroutines.CancellationException
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

    fun lastDiagnostic(): String? = null

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

    suspend fun resetLiveChatSession() {}

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
    @Volatile
    private var activeBackendIsGpu: Boolean = false
    @Volatile
    private var forceCpuOnly: Boolean = false
    @Volatile
    private var lastDiagnosticMessage: String? = null

    private var loadedModelPath: String? = null
    private var loadedMaxNumTokens: Int = -1
    private val masterPrefixes = LinkedHashMap<String, Conversation>()
    private val masterSystemPrompts = LinkedHashMap<String, String>()
    private var liveChatConversation: Conversation? = null

    override fun isLoaded(): Boolean {
        val engine = activeEngine ?: return false
        return runCatching { engine.isInitialized() }.getOrDefault(false)
    }

    override fun lastDiagnostic(): String? = lastDiagnosticMessage

    @OptIn(ExperimentalApi::class)
    override suspend fun ensureMasterPrefix(
        modelPath: String,
        systemPrefixId: String,
        systemPrompt: String,
        maxNumTokens: Int
    ) {
        withContext(Dispatchers.IO) {
            stateMutex.withLock {
                masterSystemPrompts[systemPrefixId] = systemPrompt
                val mustReinitialize = activeEngine == null ||
                    !isLoaded() ||
                    loadedModelPath != modelPath ||
                    loadedMaxNumTokens != maxNumTokens

                if (mustReinitialize) {
                    initializeEngineAndPrefixLocked(
                        modelPath = modelPath,
                        systemPrefixId = systemPrefixId,
                        systemPrompt = systemPrompt,
                        maxNumTokens = maxNumTokens,
                        preferGpu = useGpuBackend && !forceCpuOnly
                    )
                } else if (systemPrefixId !in masterPrefixes) {
                    val engine = activeEngine
                        ?: throw IllegalStateException("LiteRT-LM engine failed to initialize")
                    try {
                        masterPrefixes[systemPrefixId] = createMasterConversation(engine, systemPrefixId, systemPrompt)
                        lastDiagnosticMessage = "Ready (${if (activeBackendIsGpu) "GPU" else "CPU"})"
                    } catch (ce: CancellationException) {
                        throw ce
                    } catch (t: Throwable) {
                        Log.w(TAG, "createConversation failed on active backend, attempting CPU fallback", t)
                        if (activeBackendIsGpu) {
                            forceCpuOnly = true
                            initializeEngineAndPrefixLocked(
                                modelPath = modelPath,
                                systemPrefixId = systemPrefixId,
                                systemPrompt = systemPrompt,
                                maxNumTokens = maxNumTokens,
                                preferGpu = false
                            )
                        } else {
                            lastDiagnosticMessage = "Conversation init failed: ${t.javaClass.simpleName}: ${t.message}"
                            throw t
                        }
                    }
                }
            }
        }
    }

    @OptIn(ExperimentalApi::class)
    override fun runClonedTurn(
        systemPrefixId: String,
        config: RuntimeTurnConfig
    ): Flow<RuntimeStreamDelta> = flow {
        var emittedAny = false
        try {
            collectTurnFromActiveEngine(
                systemPrefixId = systemPrefixId,
                config = config,
                onDelta = { delta ->
                    emittedAny = true
                    emit(delta)
                }
            )
        } catch (ce: CancellationException) {
            throw ce
        } catch (se: SecurityException) {
            throw se
        } catch (t: Throwable) {
            Log.e(TAG, "Turn failed (gpu=$activeBackendIsGpu, emitted=$emittedAny): ${t.message}", t)
            if (!emittedAny && activeBackendIsGpu) {
                Log.w(TAG, "Retrying turn on CPU backend after GPU turn failure")
                val recovered = stateMutex.withLock {
                    val path = loadedModelPath
                    val prompt = masterSystemPrompts[systemPrefixId]
                    val maxTokens = loadedMaxNumTokens
                    if (path != null && prompt != null && maxTokens > 0) {
                        forceCpuOnly = true
                        initializeEngineAndPrefixLocked(
                            modelPath = path,
                            systemPrefixId = systemPrefixId,
                            systemPrompt = prompt,
                            maxNumTokens = maxTokens,
                            preferGpu = false
                        )
                        true
                    } else {
                        false
                    }
                }
                if (recovered) {
                    collectTurnFromActiveEngine(
                        systemPrefixId = systemPrefixId,
                        config = config,
                        onDelta = { delta -> emit(delta) }
                    )
                    return@flow
                }
            }
            lastDiagnosticMessage = "Inference failed (${if (activeBackendIsGpu) "GPU" else "CPU"}): ${t.javaClass.simpleName}: ${t.message}"
            throw t
        }
    }.flowOn(Dispatchers.IO)

    @OptIn(ExperimentalApi::class)
    private suspend fun collectTurnFromActiveEngine(
        systemPrefixId: String,
        config: RuntimeTurnConfig,
        onDelta: suspend (RuntimeStreamDelta) -> Unit
    ) {
        val isLiveChatTurn = !config.stage2BlindExtractionMode &&
            systemPrefixId == Gemma4PromptFormat.DEFAULT_STAGE1_CHAT_SYSTEM_PREFIX_ID

        val turnConversation = stateMutex.withLock {
            val master = masterPrefixes[systemPrefixId]
            val engine = activeEngine
                ?: throw IllegalStateException("LiteRT-LM engine is not initialized")
            val prompt = masterSystemPrompts[systemPrefixId]
                ?: throw IllegalStateException("Master prefix '$systemPrefixId' is not initialized")
            if (isLiveChatTurn) {
                val existing = liveChatConversation
                if (existing != null) {
                    existing
                } else {
                    val created = createFreshTurnConversation(engine, master, systemPrefixId, prompt)
                    liveChatConversation = created
                    created
                }
            } else {
                createFreshTurnConversation(engine, master, systemPrefixId, prompt)
            }
        }

        var turnFailed = false
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

            var receivedChunk = false
            try {
                turnConversation.sendMessageAsync(
                    text = config.promptText,
                    suppressTokensConfig = suppressCfg,
                    maxOutputToken = config.maxOutputTokens,
                    thinkingConfig = effectiveThinking
                ).collect { chunk ->
                    receivedChunk = true
                    val thoughtDelta = chunk.channels[Gemma4PromptFormat.CHANNEL_THOUGHT] ?: ""
                    val outputDelta = chunk.toString()
                    val toolCallDetected = chunk.toolCalls.isNotEmpty()
                    if (thoughtDelta.isNotEmpty() || outputDelta.isNotEmpty() || toolCallDetected) {
                        onDelta(
                            RuntimeStreamDelta(
                                thoughtDelta = thoughtDelta,
                                outputDelta = outputDelta,
                                toolCallDetected = toolCallDetected
                            )
                        )
                    }
                }
            } catch (ce: CancellationException) {
                turnFailed = true
                throw ce
            } catch (se: SecurityException) {
                turnFailed = true
                throw se
            } catch (t: Throwable) {
                if (!receivedChunk && !config.stage2BlindExtractionMode) {
                    Log.w(TAG, "sendMessageAsync with ThinkingConfig failed, retrying minimal call", t)
                    try {
                        turnConversation.sendMessageAsync(text = config.promptText).collect { chunk ->
                            val thoughtDelta = chunk.channels[Gemma4PromptFormat.CHANNEL_THOUGHT] ?: ""
                            val outputDelta = chunk.toString()
                            val toolCallDetected = chunk.toolCalls.isNotEmpty()
                            if (thoughtDelta.isNotEmpty() || outputDelta.isNotEmpty() || toolCallDetected) {
                                onDelta(
                                    RuntimeStreamDelta(
                                        thoughtDelta = thoughtDelta,
                                        outputDelta = outputDelta,
                                        toolCallDetected = toolCallDetected
                                    )
                                )
                            }
                        }
                    } catch (retryError: Throwable) {
                        turnFailed = true
                        throw retryError
                    }
                } else {
                    turnFailed = true
                    throw t
                }
            }
        } finally {
            if (!isLiveChatTurn) {
                runCatching { turnConversation.close() }
            } else if (turnFailed) {
                stateMutex.withLock {
                    if (liveChatConversation === turnConversation) {
                        liveChatConversation = null
                    }
                }
                runCatching { turnConversation.close() }
            }
        }
    }

    @OptIn(ExperimentalApi::class)
    private fun createFreshTurnConversation(
        engine: Engine,
        master: Conversation?,
        systemPrefixId: String,
        prompt: String
    ): Conversation {
        return if (master != null) {
            try {
                master.clone()
            } catch (ce: CancellationException) {
                throw ce
            } catch (t: Throwable) {
                Log.w(TAG, "Conversation.clone() failed, creating fresh turn conversation", t)
                engine.createConversation(
                    buildConversationConfig(
                        systemPrefixId = systemPrefixId,
                        systemPrompt = prompt,
                        prefillPreface = false
                    )
                )
            }
        } else {
            engine.createConversation(
                buildConversationConfig(
                    systemPrefixId = systemPrefixId,
                    systemPrompt = prompt,
                    prefillPreface = false
                )
            )
        }
    }

    @OptIn(ExperimentalApi::class)
    private fun initializeEngineAndPrefixLocked(
        modelPath: String,
        systemPrefixId: String,
        systemPrompt: String,
        maxNumTokens: Int,
        preferGpu: Boolean
    ) {
        unloadLocked()
        val backendOrder = if (preferGpu) {
            listOf(true, false)
        } else {
            listOf(false)
        }

        val errors = mutableListOf<String>()
        var lastError: Throwable? = null

        val persistentCacheDir = File(context.noBackupFilesDir, ENGINE_CACHE_DIR_NAME).apply {
            mkdirs()
        }.absolutePath

        for (isGpu in backendOrder) {
            val backendLabel = if (isGpu) "GPU" else "CPU"
            val backend = if (isGpu) Backend.GPU() else Backend.CPU(threadCount = optimalCpuThreadCount())
            val engineConfig = EngineConfig(
                modelPath = modelPath,
                backend = backend,
                maxNumTokens = maxNumTokens,
                cacheDir = persistentCacheDir
            )
            val candidate = Engine(engineConfig)
            try {
                Log.i(TAG, "Initializing LiteRT-LM engine on $backendLabel (maxNumTokens=$maxNumTokens)")
                runCatching { ExperimentalFlags.filterChannelContentFromKvCache = true }
                candidate.initialize()
                val masterConv = createMasterConversation(candidate, systemPrefixId, systemPrompt)
                activeEngine = candidate
                activeBackendIsGpu = isGpu
                loadedModelPath = modelPath
                loadedMaxNumTokens = maxNumTokens
                masterPrefixes[systemPrefixId] = masterConv
                lastDiagnosticMessage = "Ready ($backendLabel)"
                Log.i(TAG, "LiteRT-LM engine and master prefix ready on $backendLabel")
                return
            } catch (ce: CancellationException) {
                runCatching { if (candidate.isInitialized()) candidate.close() }
                throw ce
            } catch (t: Throwable) {
                val summary = "$backendLabel: ${t.javaClass.simpleName}: ${t.message}"
                Log.e(TAG, "LiteRT-LM init failed on $summary", t)
                errors.add(summary)
                lastError = t
                runCatching { if (candidate.isInitialized()) candidate.close() }
            }
        }

        val combined = errors.joinToString(" | ")
        lastDiagnosticMessage = combined
        throw IllegalStateException(
            "LiteRT-LM engine failed to initialize on available backends ($combined)",
            lastError
        )
    }

    @OptIn(ExperimentalApi::class)
    private fun createMasterConversation(
        engine: Engine,
        systemPrefixId: String,
        systemPrompt: String
    ): Conversation {
        return try {
            engine.createConversation(
                buildConversationConfig(
                    systemPrefixId = systemPrefixId,
                    systemPrompt = systemPrompt,
                    prefillPreface = true
                )
            )
        } catch (ce: CancellationException) {
            throw ce
        } catch (t: Throwable) {
            Log.w(TAG, "prefillPrefaceOnInit=true failed, retrying with prefillPrefaceOnInit=false", t)
            engine.createConversation(
                buildConversationConfig(
                    systemPrefixId = systemPrefixId,
                    systemPrompt = systemPrompt,
                    prefillPreface = false
                )
            )
        }
    }

    @OptIn(ExperimentalApi::class)
    private fun buildConversationConfig(
        systemPrefixId: String,
        systemPrompt: String,
        prefillPreface: Boolean
    ): ConversationConfig {
        val isChatPrefix = systemPrefixId == Gemma4PromptFormat.DEFAULT_STAGE1_CHAT_SYSTEM_PREFIX_ID
        val sampler = if (isChatPrefix) {
            SamplerConfig(
                topK = CHAT_TOP_K,
                topP = CHAT_TOP_P,
                temperature = CHAT_TEMPERATURE
            )
        } else {
            SamplerConfig(
                topK = ACTION_TOP_K,
                topP = ACTION_TOP_P,
                temperature = ACTION_TEMPERATURE
            )
        }
        return ConversationConfig(
            systemInstruction = Contents.of(systemPrompt),
            tools = emptyList(),
            automaticToolCalling = false,
            prefillPrefaceOnInit = prefillPreface,
            enableResponseFormat = false,
            maxOutputToken = DEFAULT_CONVERSATION_MAX_OUTPUT_TOKENS,
            thinkingConfig = ThinkingConfig(
                enableThinking = false,
                thinkingTokenBudget = 0
            ),
            samplerConfig = sampler
        )
    }

    override suspend fun resetLiveChatSession() {
        withContext(Dispatchers.IO) {
            stateMutex.withLock {
                liveChatConversation?.let { runCatching { it.close() } }
                liveChatConversation = null
            }
        }
    }

    override suspend fun unload() {
        withContext(Dispatchers.IO) {
            stateMutex.withLock {
                unloadLocked()
            }
        }
    }

    private fun unloadLocked() {
        liveChatConversation?.let { runCatching { it.close() } }
        liveChatConversation = null
        for (conversation in masterPrefixes.values) {
            runCatching { conversation.close() }
        }
        masterPrefixes.clear()
        val engine = activeEngine
        activeEngine = null
        activeBackendIsGpu = false
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
        private const val TAG: String = "NavaLiteRt"
        private const val ENGINE_CACHE_DIR_NAME: String = "litert_engine_cache"
        private const val DEFAULT_CONVERSATION_MAX_OUTPUT_TOKENS: Int = 512
        private const val ACTION_TOP_K: Int = 20
        private const val ACTION_TOP_P: Double = 0.85
        private const val ACTION_TEMPERATURE: Double = 0.1
        private const val CHAT_TOP_K: Int = 64
        private const val CHAT_TOP_P: Double = 0.95
        private const val CHAT_TEMPERATURE: Double = 0.85

        fun optimalCpuThreadCount(
            availableProcessors: Int = Runtime.getRuntime().availableProcessors()
        ): Int {
            return (availableProcessors / 2).coerceIn(2, 4)
        }
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
    private val clockMs: () -> Long = System::currentTimeMillis,
    private val coordinator: MultiModelCoordinator? = null,
    private val modelSlot: ModelSlot = ModelSlot.PRIMARY_LLM
) : LlmEnginePort {

    private val inferenceMutex = Mutex()

    init {
        coordinator?.registerUnloader(modelSlot) {
            if (isModelLoaded()) {
                unloadModel()
            }
        }
    }

    override suspend fun isModelLoaded(): Boolean = runtimeAdapter.isLoaded()

    fun lastRuntimeDiagnostic(): String? = runtimeAdapter.lastDiagnostic()

    override suspend fun currentRamTier(): RamTier = lifecycleManager.currentRamTier()

    override suspend fun currentThermalState(): ThermalState = lifecycleManager.currentThermalState()

    /**
     * Resets the live native multi-turn Chat Mode conversation (e.g. when the user taps Clear).
     */
    override suspend fun resetChatSession() {
        inferenceMutex.withLock {
            runtimeAdapter.resetLiveChatSession()
        }
    }

    override suspend fun unloadModel() {
        inferenceMutex.withLock {
            lifecycleManager.forceUnload {
                runtimeAdapter.unload()
            }
            coordinator?.markUnloaded(modelSlot)
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
            val allowedStage2Prefixes = setOf(
                Gemma4PromptFormat.STAGE2_BLIND_EXTRACTION_PREFIX_ID,
                Gemma4PromptFormat.STAGE2_SHARE_ANALYSIS_PREFIX_ID
            )
            if (request.systemPrefixId !in allowedStage2Prefixes) {
                throw SecurityException(
                    "Stage 2 blind extraction requires an allowlisted Stage 2 systemPrefixId, got '${request.systemPrefixId}'"
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
        } else if (request.systemPrefixId == Gemma4PromptFormat.DEFAULT_STAGE1_CHAT_SYSTEM_PREFIX_ID) {
            Gemma4PromptFormat.formatChatUserTurn(
                userUtterance = request.userUtterance
            )
        } else if (request.systemPrefixId == FunctionGemmaPromptFormat.FUNCTION_GEMMA_SYSTEM_PREFIX_ID) {
            FunctionGemmaPromptFormat.formatTurnPayload(
                prunedTools = request.prunedTools,
                languageHintTag = request.languageHintTag,
                userUtterance = request.userUtterance,
                currentLocalDateTimeIso = request.currentLocalDateTimeIso
            )
        } else {
            Gemma4PromptFormat.formatTurnPayloadSegmentBAndC(
                prunedTools = request.prunedTools,
                languageHintTag = request.languageHintTag,
                userUtterance = request.userUtterance,
                conversationHistory = request.conversationHistory,
                currentLocalDateTimeIso = request.currentLocalDateTimeIso
            )
        }

        val precheckedPath = modelPathProvider()
        if (precheckedPath.isNullOrBlank() || !File(precheckedPath).let { it.exists() && it.isFile }) {
            coordinator?.markUnloaded(modelSlot)
            val reason = "Model not provisioned"
            emitChunk(LlmStreamChunk.Aborted(reason = reason))
            return TurnOutcome.FatalAbort(reason)
        }

        coordinator?.onBeforeLoad(modelSlot)

        return inferenceMutex.withLock {
            if (lifecycleManager.currentThermalState() == ThermalState.SEVERE_OR_HIGHER) {
                lifecycleManager.forceUnload { runtimeAdapter.unload() }
                coordinator?.markUnloaded(modelSlot)
                val reason = "Thermal throttling SEVERE"
                emitChunk(LlmStreamChunk.Aborted(reason = reason))
                return@withLock TurnOutcome.FatalAbort(reason)
            }

            val modelPath = modelPathProvider()
            if (modelPath.isNullOrBlank() || !File(modelPath).let { it.exists() && it.isFile }) {
                coordinator?.markUnloaded(modelSlot)
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

            val maxContextTokens = when {
                modelSlot == ModelSlot.FUNCTION_ROUTER ->
                    minOf(lifecycleManager.effectiveContextTokens(), 1024)
                modelPath.contains("e2b", ignoreCase = true) ->
                    lifecycleManager.currentRamTier().e2bOptimalContextTokens
                else ->
                    lifecycleManager.effectiveContextTokens()
            }

            try {
                lifecycleManager.onEnsureLoaded {
                    runtimeAdapter.ensureMasterPrefix(
                        modelPath = modelPath,
                        systemPrefixId = request.systemPrefixId,
                        systemPrompt = systemPrompt,
                        maxNumTokens = maxContextTokens
                    )
                    coordinator?.markLoaded(modelSlot)
                }
            } catch (t: Throwable) {
                if (!runtimeAdapter.isLoaded()) {
                    coordinator?.markUnloaded(modelSlot)
                }
                throw t
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
                            coordinator?.markUnloaded(modelSlot)
                        },
                        deferredIdleUnloader = { expectedGen ->
                            inferenceMutex.withLock {
                                if (lifecycleManager.consumePendingIdleUnload(expectedGen)) {
                                    runtimeAdapter.unload()
                                    coordinator?.markUnloaded(modelSlot)
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

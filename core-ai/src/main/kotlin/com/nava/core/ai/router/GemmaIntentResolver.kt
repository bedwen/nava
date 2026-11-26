package com.nava.core.ai.router

import com.nava.core.ai.diagnostics.LlmTurnDiagnosticRecord
import com.nava.core.ai.diagnostics.LlmTurnDiagnosticsSink
import com.nava.core.ai.diagnostics.LlmTurnOutcome
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.core.ai.parser.MicroDslParser
import com.nava.core.ai.prompt.Gemma4PromptFormat
import com.nava.core.ai.pruner.DynamicToolPruner
import com.nava.domain.ai.EmbeddingPort
import com.nava.domain.ai.IntentRequest
import com.nava.domain.ai.IntentResolver
import com.nava.domain.ai.LlmEnginePort
import com.nava.domain.ai.LlmGenerationRequest
import com.nava.domain.ai.LlmGenerationResult
import com.nava.domain.ai.LlmStreamChunk
import com.nava.domain.ai.MicroDslAst
import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.ResolutionResult
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.locale.LocaleRulePackLoader
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import java.util.UUID
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow

/**
 * Live token-streaming update emitted during pure Chat Mode turns so `:app` can render replies
 * word-by-word without waiting for generation completion.
 */
data class ChatStreamDelta(
    val requestId: String,
    val accumulatedText: String
)

/**
 * Tier 3 cognitive IntentResolver backed by on-device Gemma 4 via [LlmEnginePort]
 * (PLAN.md Sections 3, 4.1, 4.2, and 6.3).
 *
 * Enforces:
 * - Stage 1 provenance check (`USER_UTTERANCE` only).
 * - Thermal gate via [ThermalModelLifecycleManager.canRunLlm].
 * - Dynamic tool pruning via [DynamicToolPruner] and strict post-parse validation rejecting any
 *   hallucinated or out-of-scope tool outside the pruned subset.
 * - Bounded Thought budget enforcement and clean clarification fallback.
 * - Fresh `CapabilityToken` minting via [SecurityFirewallPort].
 */
class GemmaIntentResolver(
    private val llmEngine: LlmEnginePort,
    private val lifecycleManager: ThermalModelLifecycleManager,
    private val toolPruner: DynamicToolPruner = DynamicToolPruner(),
    private val microDslParser: MicroDslParser = MicroDslParser(),
    private val securityFirewall: SecurityFirewallPort,
    private val systemPrefixId: String = Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID,
    private val planIdGenerator: () -> String = { UUID.randomUUID().toString() },
    private val rulePackLoader: LocaleRulePackLoader? = null,
    private val diagnosticsSink: LlmTurnDiagnosticsSink? = null,
    private val monotonicClockMs: () -> Long = { System.nanoTime() / NANOS_PER_MILLI },
    private val embeddingPort: EmbeddingPort? = null,
    private val personalMemory: com.nava.domain.memory.PersonalMemoryPort? = null
) : IntentResolver {

    override val tier: ResolutionTier = ResolutionTier.TIER_3_GEMMA

    private val _streamingChatDeltas = MutableSharedFlow<ChatStreamDelta>(extraBufferCapacity = 64)
    val streamingChatDeltas: SharedFlow<ChatStreamDelta> = _streamingChatDeltas.asSharedFlow()

    override suspend fun resolve(
        request: IntentRequest,
        availableTools: List<ToolMetadata>
    ): ResolutionResult {
        if (request.provenance != DataProvenance.USER_UTTERANCE) {
            throw SecurityException(
                "Tier 3 GemmaIntentResolver requires USER_UTTERANCE provenance, got ${request.provenance}"
            )
        }

        val turnStartMs = monotonicClockMs()

        if (!lifecycleManager.canRunLlm()) {
            llmEngine.unloadModel()
            emitDiagnostics(
                request = request,
                languageTag = request.languageHint?.bcp47Tag ?: FALLBACK_LANGUAGE_TAG,
                prunedTools = emptyList(),
                allowThoughtMode = false,
                generationRequest = null,
                rawOutput = "",
                outcome = LlmTurnOutcome.THERMAL_GATE_REFUSED,
                detail = "canRunLlm() returned false",
                engineDurationMs = 0L,
                turnStartMs = turnStartMs
            )
            return ResolutionResult.ClarificationNeeded(
                UserMessage(MessageKey.ERROR_MODEL_UNAVAILABLE)
            )
        }

        val languageHintTag = request.languageHint?.bcp47Tag
            ?: request.normalizedText?.languageTag
            ?: FALLBACK_LANGUAGE_TAG
        val prunedTools: List<ToolMetadata>
        val hasActionIntent: Boolean
        if (availableTools.isEmpty()) {
            prunedTools = emptyList()
            hasActionIntent = false
        } else {
            val localeToolHints = runCatching {
                rulePackLoader?.loadRulePack(languageHintTag)?.toolHints
            }.getOrNull().orEmpty()
            val pruneResult = toolPruner.pruneWithSemanticBoost(
                request = request,
                availableTools = availableTools,
                toolHints = localeToolHints,
                embeddingPort = embeddingPort
            )
            prunedTools = pruneResult.tools
            hasActionIntent = pruneResult.hasActionIntent
        }
        val prunedByName = prunedTools.associateBy { it.name }
        val effectivePrefixId = if (hasActionIntent) {
            systemPrefixId
        } else {
            Gemma4PromptFormat.DEFAULT_STAGE1_CHAT_SYSTEM_PREFIX_ID
        }

        val isComplex = isComplexOrMultiStepQuery(request)
        val needsDateMath = hasActionIntent && needsCalendarDateMath(request, prunedTools)
        val allowThoughtMode = hasActionIntent &&
            (isComplex || needsDateMath) &&
            lifecycleManager.isThoughtModeAllowed()
        val thoughtBudget = when {
            !allowThoughtMode -> 0
            isComplex -> DEFAULT_BOUNDED_THOUGHT_TOKENS
            else -> DATE_MATH_THOUGHT_TOKENS
        }

        val currentLocalDateTimeIso = ToolPlanValidator.formatNowIso(request.issuedAtEpochMs)
        // Remembered facts are user-authored (stored only from USER_UTTERANCE slots); a locked
        // or failing store simply means no memory context for this turn.
        val userFacts = personalMemory?.let { port ->
            try {
                com.nava.domain.memory.PersonalFactContext.select(port.listFacts())
            } catch (ce: kotlinx.coroutines.CancellationException) {
                throw ce
            } catch (_: Exception) {
                emptyList()
            }
        }.orEmpty()

        val generationRequest = LlmGenerationRequest(
            requestId = request.requestId,
            systemPrefixId = effectivePrefixId,
            prunedTools = prunedTools,
            userUtterance = request.rawUtterance,
            languageHintTag = languageHintTag,
            allowThoughtMode = allowThoughtMode,
            maxThoughtTokens = thoughtBudget,
            maxOutputTokens = DEFAULT_MAX_OUTPUT_TOKENS,
            stage2BlindExtractionMode = false,
            conversationHistory = request.conversationHistory,
            currentLocalDateTimeIso = currentLocalDateTimeIso,
            userFacts = userFacts
        )

        fun diagnose(
            rawOutput: String,
            outcome: LlmTurnOutcome,
            detail: String,
            engineDurationMs: Long
        ) = emitDiagnostics(
            request = request,
            languageTag = languageHintTag,
            prunedTools = prunedTools,
            allowThoughtMode = allowThoughtMode,
            generationRequest = generationRequest,
            rawOutput = rawOutput,
            outcome = outcome,
            detail = detail,
            engineDurationMs = engineDurationMs,
            turnStartMs = turnStartMs
        )

        val isChatMode = !hasActionIntent
        val generationResult = try {
            if (isChatMode) {
                collectStreamingChatTurn(generationRequest)
            } else {
                llmEngine.generate(generationRequest)
            }
        } catch (ce: kotlinx.coroutines.CancellationException) {
            throw ce
        } catch (se: SecurityException) {
            throw se
        } catch (t: Throwable) {
            diagnose(
                rawOutput = "",
                outcome = LlmTurnOutcome.ENGINE_FAILURE,
                detail = "${t.javaClass.simpleName}: ${t.message}",
                engineDurationMs = monotonicClockMs() - turnStartMs
            )
            return ResolutionResult.ClarificationNeeded(
                UserMessage(MessageKey.ERROR_MODEL_UNAVAILABLE)
            )
        }

        if (!generationResult.thoughtClosedCleanly) {
            diagnose(
                rawOutput = generationResult.rawOutput,
                outcome = LlmTurnOutcome.THOUGHT_BUDGET_EXCEEDED,
                detail = "thoughtTokensUsed=${generationResult.thoughtTokensUsed}",
                engineDurationMs = generationResult.durationMs
            )
            return ResolutionResult.ClarificationNeeded(
                UserMessage(MessageKey.ERROR_THOUGHT_BUDGET_EXCEEDED)
            )
        }

        val parsed = microDslParser.parse(
            rawOutput = generationResult.rawOutput,
            planId = planIdGenerator(),
            languageTag = languageHintTag,
            toolMetadataByName = prunedByName,
            provenance = DataProvenance.USER_UTTERANCE
        )

        return when (parsed) {
            is MicroDslAst.Plan -> {
                // Reject any hallucinated/out-of-scope tool or schema-invalid arguments BEFORE minting a token.
                val validation = ToolPlanValidator.validateAndNormalizeCalls(
                    calls = parsed.plan.calls,
                    prunedByName = prunedByName,
                    targetContextId = request.targetContextId
                )
                val boundCalls = when (validation) {
                    is ToolPlanValidator.ValidationResult.Valid -> validation.normalizedCalls
                    is ToolPlanValidator.ValidationResult.UnknownTool -> {
                        diagnose(
                            rawOutput = generationResult.rawOutput,
                            outcome = LlmTurnOutcome.REJECTED_UNKNOWN_TOOL,
                            detail = "tool '${validation.toolName}' is not in pruned set",
                            engineDurationMs = generationResult.durationMs
                        )
                        return ResolutionResult.ClarificationNeeded(
                            UserMessage(MessageKey.ERROR_CLARIFICATION_NEEDED)
                        )
                    }
                    is ToolPlanValidator.ValidationResult.SchemaInvalid -> {
                        diagnose(
                            rawOutput = generationResult.rawOutput,
                            outcome = LlmTurnOutcome.REJECTED_SCHEMA_INVALID,
                            detail = "${validation.toolName}: ${validation.detail}",
                            engineDurationMs = generationResult.durationMs
                        )
                        return ResolutionResult.ClarificationNeeded(
                            UserMessage(MessageKey.ERROR_CLARIFICATION_NEEDED)
                        )
                    }
                }
                val finalPlan = PlanAst(
                    planId = parsed.plan.planId,
                    calls = boundCalls,
                    skeletonKey = parsed.plan.skeletonKey,
                    requiresBoundedThought = allowThoughtMode
                )

                val candidateTools = boundCalls.map { it.toolName }.toSet()
                val token = securityFirewall.mintToken(
                    requestId = request.requestId,
                    utteranceProvenance = request.provenance,
                    candidateTools = candidateTools,
                    nowEpochMs = request.issuedAtEpochMs
                )

                diagnose(
                    rawOutput = generationResult.rawOutput,
                    outcome = LlmTurnOutcome.RESOLVED_PLAN,
                    detail = "calls=${boundCalls.joinToString(",") { it.toolName }}",
                    engineDurationMs = generationResult.durationMs
                )
                ResolutionResult.ResolvedPlan(
                    tier = ResolutionTier.TIER_3_GEMMA,
                    plan = finalPlan,
                    capabilityToken = token
                )
            }

            is MicroDslAst.DirectReply -> {
                diagnose(
                    rawOutput = generationResult.rawOutput,
                    outcome = LlmTurnOutcome.DIRECT_REPLY,
                    detail = "replyChars=${parsed.text.length}",
                    engineDurationMs = generationResult.durationMs
                )
                ResolutionResult.ConversationalReply(
                    tier = ResolutionTier.TIER_3_GEMMA,
                    replyText = parsed.text,
                    languageTag = parsed.languageTag
                )
            }

            is MicroDslAst.ParseError -> {
                diagnose(
                    rawOutput = generationResult.rawOutput,
                    outcome = LlmTurnOutcome.PARSE_ERROR,
                    detail = parsed.reason,
                    engineDurationMs = generationResult.durationMs
                )
                ResolutionResult.ClarificationNeeded(
                    UserMessage(MessageKey.ERROR_CLARIFICATION_NEEDED)
                )
            }
        }
    }

    private fun emitDiagnostics(
        request: IntentRequest,
        languageTag: String,
        prunedTools: List<ToolMetadata>,
        allowThoughtMode: Boolean,
        generationRequest: LlmGenerationRequest?,
        rawOutput: String,
        outcome: LlmTurnOutcome,
        detail: String,
        engineDurationMs: Long,
        turnStartMs: Long
    ) {
        val sink = diagnosticsSink ?: return
        runCatching {
            val promptPayload = generationRequest?.let { gen ->
                if (gen.systemPrefixId == Gemma4PromptFormat.DEFAULT_STAGE1_CHAT_SYSTEM_PREFIX_ID) {
                    Gemma4PromptFormat.formatChatUserTurn(gen.userUtterance)
                } else {
                    Gemma4PromptFormat.formatTurnPayloadSegmentBAndC(
                        prunedTools = gen.prunedTools,
                        languageHintTag = gen.languageHintTag,
                        userUtterance = gen.userUtterance,
                        conversationHistory = gen.conversationHistory,
                        currentLocalDateTimeIso = gen.currentLocalDateTimeIso
                    )
                }
            }.orEmpty()
            sink.onTurn(
                LlmTurnDiagnosticRecord(
                    requestId = request.requestId,
                    languageTag = languageTag,
                    userUtterance = request.rawUtterance,
                    historyTurnCount = request.conversationHistory.size,
                    prunedToolNames = prunedTools.map { it.name },
                    allowThoughtMode = allowThoughtMode,
                    promptPayload = promptPayload,
                    rawOutput = rawOutput,
                    outcome = outcome,
                    detail = detail,
                    engineDurationMs = engineDurationMs,
                    totalDurationMs = monotonicClockMs() - turnStartMs
                )
            )
        }
    }

    /**
     * Language-agnostic structural heuristic detecting multi-step or complex requests eligible
     * for Bounded Thought Mode (`128..256` tokens) when thermal and RAM conditions permit.
     */
    private fun isComplexOrMultiStepQuery(request: IntentRequest): Boolean {
        val text = request.rawUtterance.trim()
        val tokenCount = request.normalizedText?.tokens?.size
            ?: text.split(WHITESPACE_REGEX).count { it.isNotEmpty() }

        if (tokenCount >= MULTI_STEP_TOKEN_THRESHOLD) return true
        if (text.length >= MULTI_STEP_CHAR_THRESHOLD && CLAUSE_SEPARATOR_REGEX.containsMatchIn(text)) {
            return true
        }
        val numericCount = NUMERIC_GROUP_REGEX.findAll(text).count()
        return numericCount >= 2 && CLAUSE_SEPARATOR_REGEX.containsMatchIn(text)
    }

    private suspend fun collectStreamingChatTurn(
        generationRequest: LlmGenerationRequest
    ): LlmGenerationResult {
        var completed: LlmGenerationResult? = null
        var aborted: LlmStreamChunk.Aborted? = null
        val streamedOutput = StringBuilder()
        var lastEmitMs = monotonicClockMs() - CHAT_STREAM_COALESCE_MS
        var lastEmittedText: String? = null

        llmEngine.generateStream(generationRequest).collect { chunk ->
            when (chunk) {
                is LlmStreamChunk.ThoughtDelta -> Unit
                is LlmStreamChunk.OutputDelta -> {
                    streamedOutput.append(chunk.text)
                    val trimmed = streamedOutput.toString().trimStart()
                    // Never surface raw Gemma control/tool tokens during live streaming.
                    if (trimmed.isNotEmpty() && !trimmed.startsWith("<|")) {
                        val nowMs = monotonicClockMs()
                        if (nowMs - lastEmitMs >= CHAT_STREAM_COALESCE_MS) {
                            _streamingChatDeltas.tryEmit(
                                ChatStreamDelta(
                                    requestId = generationRequest.requestId,
                                    accumulatedText = trimmed
                                )
                            )
                            lastEmitMs = nowMs
                            lastEmittedText = trimmed
                        }
                    }
                }
                is LlmStreamChunk.Completed -> completed = chunk.result
                is LlmStreamChunk.Aborted -> aborted = chunk
            }
        }

        val abortChunk = aborted
        if (abortChunk != null) {
            if (abortChunk.thoughtBudgetExceeded) {
                return LlmGenerationResult(
                    rawOutput = streamedOutput.toString(),
                    thoughtClosedCleanly = false
                )
            }
            throw IllegalStateException(abortChunk.reason)
        }

        val finalResult = completed ?: LlmGenerationResult(rawOutput = streamedOutput.toString())
        val finalTrimmed = finalResult.rawOutput.trimStart()
        if (finalTrimmed.isNotEmpty() &&
            !finalTrimmed.startsWith("<|") &&
            finalTrimmed != lastEmittedText
        ) {
            _streamingChatDeltas.tryEmit(
                ChatStreamDelta(
                    requestId = generationRequest.requestId,
                    accumulatedText = finalTrimmed
                )
            )
        }
        return finalResult
    }

    private fun needsCalendarDateMath(
        request: IntentRequest,
        prunedTools: List<ToolMetadata>
    ): Boolean {
        // Only the top-ranked tool counts: the pruner pads the set with lower-scored neighbours,
        // and a calendar tool ranked behind set_alarm must not switch thought mode on for a
        // plain clock command.
        val topTool = prunedTools.firstOrNull() ?: return false
        val topIsCalendarDateTool = topTool.name.startsWith("calendar_") &&
            topTool.fields.any { f -> f.valueType == SlotValueType.ISO_DATETIME || f.valueType == SlotValueType.ISO_DATE }
        if (!topIsCalendarDateTool) return false
        return NUMERIC_GROUP_REGEX.containsMatchIn(request.rawUtterance)
    }

    companion object {
        const val DEFAULT_BOUNDED_THOUGHT_TOKENS: Int = 256
        const val DATE_MATH_THOUGHT_TOKENS: Int = 128
        const val DEFAULT_MAX_OUTPUT_TOKENS: Int = 512
        const val CHAT_STREAM_COALESCE_MS: Long = 35L

        private const val MULTI_STEP_TOKEN_THRESHOLD: Int = 12
        private const val MULTI_STEP_CHAR_THRESHOLD: Int = 48
        private const val FALLBACK_LANGUAGE_TAG: String = "en"
        private const val NANOS_PER_MILLI: Long = 1_000_000L

        private val WHITESPACE_REGEX: Regex = Regex("""\s+""")
        private val CLAUSE_SEPARATOR_REGEX: Regex = Regex("""[;,\u060C\u3001\uFF0C]""")
        private val NUMERIC_GROUP_REGEX: Regex = Regex("""\d+(?:[:hH]\d{2})?""")
    }
}

package com.nava.core.ai.router

import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.core.ai.parser.MicroDslParser
import com.nava.core.ai.prompt.Gemma4PromptFormat
import com.nava.core.ai.pruner.DynamicToolPruner
import com.nava.domain.ai.IntentRequest
import com.nava.domain.ai.IntentResolver
import com.nava.domain.ai.LlmEnginePort
import com.nava.domain.ai.LlmGenerationRequest
import com.nava.domain.ai.MicroDslAst
import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.ResolutionResult
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolSchemaField
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.OffsetDateTime
import java.time.ZonedDateTime
import java.util.UUID

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
    private val planIdGenerator: () -> String = { UUID.randomUUID().toString() }
) : IntentResolver {

    override val tier: ResolutionTier = ResolutionTier.TIER_3_GEMMA

    override suspend fun resolve(
        request: IntentRequest,
        availableTools: List<ToolMetadata>
    ): ResolutionResult {
        if (request.provenance != DataProvenance.USER_UTTERANCE) {
            throw SecurityException(
                "Tier 3 GemmaIntentResolver requires USER_UTTERANCE provenance, got ${request.provenance}"
            )
        }

        if (!lifecycleManager.canRunLlm()) {
            llmEngine.unloadModel()
            return ResolutionResult.ClarificationNeeded(
                UserMessage(MessageKey.ERROR_MODEL_UNAVAILABLE)
            )
        }

        val prunedTools = toolPruner.prune(request, availableTools)
        val prunedByName = prunedTools.associateBy { it.name }
        val languageHintTag = request.languageHint?.bcp47Tag
            ?: request.normalizedText?.languageTag
            ?: FALLBACK_LANGUAGE_TAG

        val allowThoughtMode = isComplexOrMultiStepQuery(request) &&
            lifecycleManager.isThoughtModeAllowed()

        val generationRequest = LlmGenerationRequest(
            requestId = request.requestId,
            systemPrefixId = systemPrefixId,
            prunedTools = prunedTools,
            userUtterance = request.rawUtterance,
            languageHintTag = languageHintTag,
            allowThoughtMode = allowThoughtMode,
            maxThoughtTokens = if (allowThoughtMode) DEFAULT_BOUNDED_THOUGHT_TOKENS else 0,
            maxOutputTokens = DEFAULT_MAX_OUTPUT_TOKENS,
            stage2BlindExtractionMode = false
        )

        val generationResult = try {
            llmEngine.generate(generationRequest)
        } catch (_: IllegalStateException) {
            return ResolutionResult.ClarificationNeeded(
                UserMessage(MessageKey.ERROR_MODEL_UNAVAILABLE)
            )
        }

        if (!generationResult.thoughtClosedCleanly) {
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
                val calls = parsed.plan.calls
                // Reject any hallucinated/out-of-scope tool or schema-invalid arguments BEFORE minting a token.
                for (call in calls) {
                    val metadata = prunedByName[call.toolName]
                    if (metadata == null || !isSchemaValidToolCall(call, metadata)) {
                        return ResolutionResult.ClarificationNeeded(
                            UserMessage(MessageKey.ERROR_CLARIFICATION_NEEDED)
                        )
                    }
                }

                val boundCalls = calls.map { call ->
                    if (call.targetId == null) {
                        call.copy(targetId = request.targetContextId)
                    } else {
                        call
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

                ResolutionResult.ResolvedPlan(
                    tier = ResolutionTier.TIER_3_GEMMA,
                    plan = finalPlan,
                    capabilityToken = token
                )
            }

            is MicroDslAst.DirectReply -> {
                ResolutionResult.ConversationalReply(
                    tier = ResolutionTier.TIER_3_GEMMA,
                    replyText = parsed.text,
                    languageTag = parsed.languageTag
                )
            }

            is MicroDslAst.ParseError -> {
                ResolutionResult.ClarificationNeeded(
                    UserMessage(MessageKey.ERROR_CLARIFICATION_NEEDED)
                )
            }
        }
    }

    private fun isSchemaValidToolCall(call: ToolCallAst, metadata: ToolMetadata): Boolean {
        val fieldsByName = metadata.fields.associateBy { it.name }
        for ((argName, taintedVal) in call.arguments) {
            val field = fieldsByName[argName] ?: return false
            if (!isValueValidForField(taintedVal.value, field)) {
                return false
            }
        }
        for (field in metadata.fields) {
            if (!field.required) continue
            val present = call.arguments[field.name] ?: return false
            val value = present.value
            if (value is SlotValueAst.NullValue) return false
            if (value is SlotValueAst.StringValue && value.value.isBlank()) return false
        }
        return true
    }

    private fun isValueValidForField(value: SlotValueAst, field: ToolSchemaField): Boolean {
        if (value is SlotValueAst.NullValue) {
            return !field.required
        }
        return when (field.valueType) {
            SlotValueType.INTEGER -> value is SlotValueAst.IntValue
            SlotValueType.DURATION_SECONDS -> value is SlotValueAst.IntValue && value.value > 0L
            SlotValueType.BOOLEAN -> value is SlotValueAst.BooleanValue
            SlotValueType.ISO_TIME -> value is SlotValueAst.StringValue &&
                CANONICAL_TIME_REGEX.matches(value.value)

            SlotValueType.ISO_DATE -> value is SlotValueAst.StringValue &&
                runCatching { LocalDate.parse(value.value) }.isSuccess

            SlotValueType.ISO_DATETIME -> value is SlotValueAst.StringValue &&
                isValidIsoDateTime(value.value)

            SlotValueType.STRING -> value is SlotValueAst.StringValue &&
                (!field.required || value.value.isNotBlank())
        }
    }

    private fun isValidIsoDateTime(raw: String): Boolean {
        if (raw.isBlank()) return false
        return runCatching { OffsetDateTime.parse(raw) }.isSuccess ||
            runCatching { ZonedDateTime.parse(raw) }.isSuccess ||
            runCatching { LocalDateTime.parse(raw) }.isSuccess ||
            runCatching { Instant.parse(raw) }.isSuccess
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

    companion object {
        const val DEFAULT_BOUNDED_THOUGHT_TOKENS: Int = 256
        const val DEFAULT_MAX_OUTPUT_TOKENS: Int = 512

        private const val MULTI_STEP_TOKEN_THRESHOLD: Int = 12
        private const val MULTI_STEP_CHAR_THRESHOLD: Int = 48
        private const val FALLBACK_LANGUAGE_TAG: String = "en"

        private val CANONICAL_TIME_REGEX: Regex = Regex("""^(?:[01]\d|2[0-3]):[0-5]\d$""")
        private val WHITESPACE_REGEX: Regex = Regex("""\s+""")
        private val CLAUSE_SEPARATOR_REGEX: Regex = Regex("""[;,\u060C\u3001\uFF0C]""")
        private val NUMERIC_GROUP_REGEX: Regex = Regex("""\d+(?:[:hH]\d{2})?""")
    }
}

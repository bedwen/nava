package com.nava.core.ai.router

import com.nava.core.ai.lifecycle.ModelSlot
import com.nava.core.ai.lifecycle.MultiModelCoordinator
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.core.ai.parser.MicroDslParser
import com.nava.core.ai.prompt.FunctionGemmaPromptFormat
import com.nava.core.ai.pruner.DynamicToolPruner
import com.nava.domain.ai.EmbeddingPort
import com.nava.domain.ai.IntentRequest
import com.nava.domain.ai.IntentResolver
import com.nava.domain.ai.LlmEnginePort
import com.nava.domain.ai.LlmGenerationRequest
import com.nava.domain.ai.MicroDslAst
import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.ResolutionResult
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.locale.LocaleRulePackLoader
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.tool.ToolMetadata
import kotlinx.coroutines.CancellationException
import java.util.UUID

/**
 * Tier 2.5 fast function-calling IntentResolver backed by FunctionGemma 270M (`ResolutionTier.TIER_2_5_FUNCTION_GEMMA`).
 *
 * Designed as a low-latency bridge between deterministic Tier 1/2 matching and heavy Tier 3
 * Gemma 4 E2B reasoning. Any non-plan output, parse failure, schema violation, or engine error
 * falls back cleanly to [ResolutionResult.NoMatch] so Tier 3 handles the request.
 */
class FunctionGemmaIntentResolver(
    private val functionEngine: LlmEnginePort,
    private val isModelAvailable: suspend () -> Boolean,
    private val lifecycleManager: ThermalModelLifecycleManager,
    private val coordinator: MultiModelCoordinator? = null,
    private val toolPruner: DynamicToolPruner = DynamicToolPruner(),
    private val microDslParser: MicroDslParser = MicroDslParser(),
    private val securityFirewall: SecurityFirewallPort,
    private val rulePackLoader: LocaleRulePackLoader? = null,
    private val embeddingPort: EmbeddingPort? = null,
    private val planIdGenerator: () -> String = { UUID.randomUUID().toString() }
) : IntentResolver {

    override val tier: ResolutionTier = ResolutionTier.TIER_2_5_FUNCTION_GEMMA

    override suspend fun resolve(
        request: IntentRequest,
        availableTools: List<ToolMetadata>
    ): ResolutionResult {
        if (request.provenance != DataProvenance.USER_UTTERANCE) {
            throw SecurityException(
                "Tier 2.5 FunctionGemmaIntentResolver requires USER_UTTERANCE provenance, got ${request.provenance}"
            )
        }
        if (availableTools.isEmpty()) return ResolutionResult.NoMatch
        if (!lifecycleManager.canRunLlm()) return ResolutionResult.NoMatch
        if (!isModelAvailable()) return ResolutionResult.NoMatch
        if (isComplexMultiClauseQuery(request)) return ResolutionResult.NoMatch

        // Avoid 270M single-word hallucinations (e.g. "Summarize"): defer ambiguous 1-word
        // follow-ups to Gemma 4 E2B which has stronger conversational context understanding.
        val utteranceTokenCount = request.rawUtterance.trim()
            .split(Regex("\\s+"))
            .count { it.isNotBlank() }
        if (utteranceTokenCount < MIN_FUNCTION_GEMMA_TOKENS) {
            return ResolutionResult.NoMatch
        }

        val languageHintTag = request.languageHint?.bcp47Tag
            ?: request.normalizedText?.languageTag
            ?: FALLBACK_LANGUAGE_TAG
        val localeToolHints = runCatching {
            rulePackLoader?.loadRulePack(languageHintTag)?.toolHints
        }.getOrNull().orEmpty()

        // Require a clear lexical/hint action signal before waking 270M FunctionGemma so
        // conversational or ambiguous utterances fall through cleanly to Gemma 4 E2B.
        val pruneResult = toolPruner.pruneWithSignal(
            request = request,
            availableTools = availableTools,
            toolHints = localeToolHints
        )
        if (!pruneResult.hasActionIntent || pruneResult.tools.isEmpty()) {
            return ResolutionResult.NoMatch
        }

        // Only expose positively matched tools to 270M FunctionGemma (never 0-score padded
        // fallback tools) so the small model cannot hallucinate unrelated actions like calendar_create.
        val matchedTools = if (pruneResult.matchedToolNames.isNotEmpty()) {
            pruneResult.tools.filter { it.name in pruneResult.matchedToolNames }
        } else {
            emptyList()
        }
        if (matchedTools.isEmpty()) {
            return ResolutionResult.NoMatch
        }

        val prunedTools = matchedTools
        val prunedByName = prunedTools.associateBy { it.name }
        val generationRequest = LlmGenerationRequest(
            requestId = request.requestId,
            systemPrefixId = FunctionGemmaPromptFormat.FUNCTION_GEMMA_SYSTEM_PREFIX_ID,
            prunedTools = prunedTools,
            userUtterance = request.rawUtterance,
            languageHintTag = languageHintTag,
            allowThoughtMode = false,
            maxThoughtTokens = 0,
            maxOutputTokens = DEFAULT_MAX_OUTPUT_TOKENS,
            stage2BlindExtractionMode = false,
            conversationHistory = request.conversationHistory,
            currentLocalDateTimeIso = ToolPlanValidator.formatNowIso(request.issuedAtEpochMs)
        )

        coordinator?.onBeforeLoad(ModelSlot.FUNCTION_ROUTER)

        val generationResult = try {
            functionEngine.generate(generationRequest)
        } catch (ce: CancellationException) {
            throw ce
        } catch (se: SecurityException) {
            throw se
        } catch (_: Throwable) {
            return ResolutionResult.NoMatch
        }

        val parsed = microDslParser.parse(
            rawOutput = generationResult.rawOutput,
            planId = planIdGenerator(),
            languageTag = languageHintTag,
            toolMetadataByName = prunedByName,
            provenance = DataProvenance.USER_UTTERANCE
        )
        // FunctionGemma 270M is specialized for fast single-step mobile actions; defer multi-step
        // plans to Gemma 4 E2B for stronger multi-tool reasoning.
        if (parsed !is MicroDslAst.Plan || parsed.plan.calls.size != 1) {
            return ResolutionResult.NoMatch
        }

        val validation = ToolPlanValidator.validateAndNormalizeCalls(
            calls = parsed.plan.calls,
            prunedByName = prunedByName,
            targetContextId = request.targetContextId
        )
        val boundCalls = when (validation) {
            is ToolPlanValidator.ValidationResult.Valid -> validation.normalizedCalls
            is ToolPlanValidator.ValidationResult.UnknownTool,
            is ToolPlanValidator.ValidationResult.SchemaInvalid -> return ResolutionResult.NoMatch
        }

        val finalPlan = PlanAst(
            planId = parsed.plan.planId,
            calls = boundCalls,
            skeletonKey = parsed.plan.skeletonKey,
            requiresBoundedThought = false
        )
        val candidateTools = boundCalls.map { it.toolName }.toSet()
        val token = securityFirewall.mintToken(
            requestId = request.requestId,
            utteranceProvenance = request.provenance,
            candidateTools = candidateTools,
            nowEpochMs = request.issuedAtEpochMs,
            maxToolCalls = boundCalls.size
        )

        return ResolutionResult.ResolvedPlan(
            tier = ResolutionTier.TIER_2_5_FUNCTION_GEMMA,
            plan = finalPlan,
            capabilityToken = token
        )
    }

    private fun isComplexMultiClauseQuery(request: IntentRequest): Boolean {
        val text = request.rawUtterance.trim()
        val tokenCount = request.normalizedText?.tokens?.size
            ?: text.split(WHITESPACE_REGEX).count { it.isNotEmpty() }
        if (tokenCount < COMPLEX_TOKEN_THRESHOLD) return false
        return CLAUSE_SEPARATOR_REGEX.findAll(text).count() >= 2
    }

    companion object {
        const val DEFAULT_MAX_OUTPUT_TOKENS: Int = 160
        private const val MIN_FUNCTION_GEMMA_TOKENS: Int = 2
        private const val COMPLEX_TOKEN_THRESHOLD: Int = 16
        private const val FALLBACK_LANGUAGE_TAG: String = "en"
        private val WHITESPACE_REGEX: Regex = Regex("""\s+""")
        private val CLAUSE_SEPARATOR_REGEX: Regex = Regex("""[;,\u060C\u3001\uFF0C]""")
    }
}

package com.nava.core.ai.pruner

import com.nava.domain.ai.EmbeddingPort
import com.nava.domain.ai.IntentRequest
import com.nava.domain.tool.ToolCategory
import com.nava.domain.tool.ToolMetadata
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

/**
 * Deterministically selects the top [minTools]..[maxTools] relevant tool declarations for Segment B
 * per turn without invalidating the pinned Segment A KV-cache prefix (PLAN.md Section 4.2).
 *
 * Language-agnostic: uses lexical token overlap against tool metadata and script-neutral structural
 * format cues (time/date, phone/email, file path, percentage) with zero hardcoded language lists.
 */
class DynamicToolPruner(
    private val minTools: Int = 3,
    private val maxTools: Int = 5
) {
    init {
        require(minTools >= 1) { "minTools must be at least 1, got $minTools" }
        require(maxTools >= minTools) { "maxTools ($maxTools) must be >= minTools ($minTools)" }
    }

    private val toolEmbeddingCache = ConcurrentHashMap<String, FloatArray>()

    data class PruneResult(
        val tools: List<ToolMetadata>,
        val hasActionIntent: Boolean,
        val matchedToolNames: Set<String> = emptySet()
    )

    fun prune(
        request: IntentRequest,
        availableTools: List<ToolMetadata>,
        toolHints: Map<String, List<String>> = emptyMap()
    ): List<ToolMetadata> {
        if (availableTools.isEmpty()) return emptyList()

        val scored = rankTools(request, availableTools, toolHints, includePreviousTurn = true)
        val effectiveMin = minOf(minTools, scored.size)
        val effectiveMax = minOf(maxTools, scored.size)
        val positiveCount = scored.count { it.score > 0.0 }
        if (positiveCount == 0) {
            return selectDiverseFallback(availableTools, effectiveMin)
        }
        val takeCount = positiveCount.coerceIn(effectiveMin, effectiveMax)
        return scored.take(takeCount).map { it.tool }
    }

    /**
     * Prunes tools and reports whether the current turn actually exhibits tool/action intent.
     *
     * Pure conversational utterances (zero positive matches on the current utterance and not a
     * short `<= 2`-token follow-up to an active turn) return `PruneResult(emptyList(), false)`
     * so `GemmaIntentResolver` can route them to the clean Chat Mode prompt without `[TOOLS]`
     * or DSL clutter.
     */
    fun pruneWithSignal(
        request: IntentRequest,
        availableTools: List<ToolMetadata>,
        toolHints: Map<String, List<String>> = emptyMap()
    ): PruneResult {
        if (availableTools.isEmpty()) {
            return PruneResult(tools = emptyList(), hasActionIntent = false)
        }

        val currentTokens = extractCurrentUtteranceTokens(request)
        val currentScored = rankToolsForTokens(
            queryTokens = currentTokens,
            cues = detectStructuralCues(request),
            availableTools = availableTools,
            toolHints = toolHints
        )
        val currentPositive = currentScored.count { it.score > 0.0 }
        val effectiveMin = minOf(minTools, availableTools.size)
        val effectiveMax = minOf(maxTools, availableTools.size)

        if (currentPositive > 0) {
            val takeCount = currentPositive.coerceIn(effectiveMin, effectiveMax)
            val matchedNames = currentScored
                .asSequence()
                .filter { it.score > 0.0 }
                .take(takeCount)
                .map { it.tool.name }
                .toSet()
            return PruneResult(
                tools = currentScored.take(takeCount).map { it.tool },
                hasActionIntent = true,
                matchedToolNames = matchedNames
            )
        }

        // Only inherit previous user turn's tool tokens for short follow-ups (e.g., "try again",
        // "tekrar dene", "09:30") so new conversational turns never inherit stale tools.
        if (currentTokens.size <= SHORT_FOLLOWUP_MAX_TOKENS && request.conversationHistory.isNotEmpty()) {
            val inheritedScored = rankTools(request, availableTools, toolHints, includePreviousTurn = true)
            val inheritedPositive = inheritedScored.count { it.score > 0.0 }
            if (inheritedPositive > 0) {
                val takeCount = inheritedPositive.coerceIn(effectiveMin, effectiveMax)
                return PruneResult(
                    tools = inheritedScored.take(takeCount).map { it.tool },
                    hasActionIntent = true
                )
            }
        }

        return PruneResult(tools = emptyList(), hasActionIntent = false)
    }

    /**
     * Variant of [pruneWithSignal] that boosts matching tools using on-device embeddings when
     * [embeddingPort] is available and cosine similarity meets [SEMANTIC_BOOST_THRESHOLD] (`0.42f`).
     * Tool description embeddings are cached in memory by tool identity, schema version, and description.
     */
    suspend fun pruneWithSemanticBoost(
        request: IntentRequest,
        availableTools: List<ToolMetadata>,
        toolHints: Map<String, List<String>> = emptyMap(),
        embeddingPort: EmbeddingPort? = null
    ): PruneResult {
        if (availableTools.isEmpty()) {
            return PruneResult(tools = emptyList(), hasActionIntent = false)
        }
        val lexicalRanked = rankTools(request, availableTools, toolHints, includePreviousTurn = false)
        val topLexicalScore = lexicalRanked.firstOrNull()?.score ?: 0.0
        val effectiveMin = minOf(minTools, availableTools.size)
        val effectiveMax = minOf(maxTools, availableTools.size)

        // Short-circuit before waking EmbeddingGemma 2 when lexical/hint signals are already strong
        // (avoids multi-second CPU embedding latency on clear commands like "hatirlatici kur").
        if (topLexicalScore >= STRONG_LEXICAL_SHORT_CIRCUIT_SCORE) {
            val positiveCount = lexicalRanked.count { it.score > 0.0 }
            val takeCount = positiveCount.coerceIn(effectiveMin, effectiveMax)
            return PruneResult(
                tools = lexicalRanked.take(takeCount).map { it.tool },
                hasActionIntent = true
            )
        }

        if (embeddingPort == null || !embeddingPort.isEmbeddingModelAvailable()) {
            return pruneWithSignal(request, availableTools, toolHints)
        }
        val queryEmbedding = embeddingPort.embedQuery(request.rawUtterance)
            ?: return pruneWithSignal(request, availableTools, toolHints)

        val currentTokens = extractCurrentUtteranceTokens(request)
        val cues = detectStructuralCues(request)
        val boostedScored = ArrayList<ScoredTool>(availableTools.size)

        for (tool in availableTools) {
            var score = scoreTool(tool, currentTokens, cues, toolHints[tool.name].orEmpty())
            val toolEmbedding = getOrComputeToolEmbedding(tool, embeddingPort)
            if (toolEmbedding != null) {
                val cosine = EmbeddingPort.cosineSimilarity(queryEmbedding, toolEmbedding)
                if (cosine >= SEMANTIC_BOOST_THRESHOLD) {
                    val excess = (cosine - SEMANTIC_BOOST_THRESHOLD).toDouble().coerceAtLeast(0.0)
                    score += WEIGHT_SEMANTIC_BOOST_BASE + (excess * WEIGHT_SEMANTIC_BOOST_SCALE)
                }
            }
            boostedScored.add(ScoredTool(tool = tool, score = score))
        }

        val sorted = boostedScored.sortedWith(
            compareByDescending<ScoredTool> { it.score }
                .thenBy { it.tool.name }
        )
        val positiveCount = sorted.count { it.score > 0.0 }

        if (positiveCount > 0) {
            val takeCount = positiveCount.coerceIn(effectiveMin, effectiveMax)
            return PruneResult(
                tools = sorted.take(takeCount).map { it.tool },
                hasActionIntent = true
            )
        }

        if (currentTokens.size <= SHORT_FOLLOWUP_MAX_TOKENS && request.conversationHistory.isNotEmpty()) {
            val inheritedScored = rankTools(request, availableTools, toolHints, includePreviousTurn = true)
            val inheritedPositive = inheritedScored.count { it.score > 0.0 }
            if (inheritedPositive > 0) {
                val takeCount = inheritedPositive.coerceIn(effectiveMin, effectiveMax)
                return PruneResult(
                    tools = inheritedScored.take(takeCount).map { it.tool },
                    hasActionIntent = true
                )
            }
        }

        return PruneResult(tools = emptyList(), hasActionIntent = false)
    }

    private suspend fun getOrComputeToolEmbedding(
        tool: ToolMetadata,
        embeddingPort: EmbeddingPort
    ): FloatArray? {
        val key = "${tool.name}:${tool.schemaVersion}:${tool.description.hashCode()}"
        toolEmbeddingCache[key]?.let { return it }
        val text = "${tool.name.replace('_', ' ')}: ${tool.description}"
        val computed = embeddingPort.embedDocument(tool.name, text) ?: return null
        if (toolEmbeddingCache.size >= MAX_TOOL_EMBEDDING_CACHE) {
            toolEmbeddingCache.clear()
        }
        toolEmbeddingCache[key] = computed
        return computed
    }

    private fun selectDiverseFallback(
        availableTools: List<ToolMetadata>,
        count: Int
    ): List<ToolMetadata> {
        val sorted = availableTools.sortedBy { it.name }
        val chosen = ArrayList<ToolMetadata>(count)
        val seenCategories = LinkedHashSet<ToolCategory>()
        for (tool in sorted) {
            if (chosen.size >= count) break
            if (seenCategories.add(tool.category)) {
                chosen.add(tool)
            }
        }
        for (tool in sorted) {
            if (chosen.size >= count) break
            if (tool !in chosen) {
                chosen.add(tool)
            }
        }
        return chosen
    }

    /**
     * Selects one of the 4 core KV-cache pre-pinned category snapshot buckets
     * (`TIME_CALENDAR`, `COMMUNICATION`, `DEVICE_SETTINGS`, `NOTES_FILES`) for the Phase 0
     * fallback strategy (PHASE_0_FEASIBILITY_REPORT.md Section 3.2).
     */
    fun selectCategoryBucket(
        request: IntentRequest,
        availableTools: List<ToolMetadata>
    ): ToolCategory {
        val ranked = rankTools(request, availableTools)
        val bucketScores = LinkedHashMap<ToolCategory, Double>(CORE_BUCKETS.size)
        for (bucket in CORE_BUCKETS) {
            bucketScores[bucket] = 0.0
        }

        val cues = detectStructuralCues(request)
        for (bucket in CORE_BUCKETS) {
            bucketScores[bucket] = (bucketScores[bucket] ?: 0.0) + structuralCueBoost(bucket, cues)
        }

        for (entry in ranked) {
            val mappedBucket = mapToCoreBucket(entry.tool.category)
            bucketScores[mappedBucket] = (bucketScores[mappedBucket] ?: 0.0) + entry.score
        }

        var bestCategory = ToolCategory.TIME_CALENDAR
        var bestScore = Double.NEGATIVE_INFINITY
        for (bucket in CORE_BUCKETS) {
            val score = bucketScores[bucket] ?: 0.0
            if (score > bestScore) {
                bestScore = score
                bestCategory = bucket
            }
        }
        return bestCategory
    }

    private data class ScoredTool(
        val tool: ToolMetadata,
        val score: Double
    )

    private data class StructuralCues(
        val hasTimeOrDate: Boolean,
        val hasPhoneOrEmail: Boolean,
        val hasFilePath: Boolean,
        val hasPercentOrNumber: Boolean
    )

    private fun rankTools(
        request: IntentRequest,
        availableTools: List<ToolMetadata>,
        toolHints: Map<String, List<String>> = emptyMap(),
        includePreviousTurn: Boolean = true
    ): List<ScoredTool> {
        val queryTokens = if (includePreviousTurn) {
            extractQueryTokens(request)
        } else {
            extractCurrentUtteranceTokens(request)
        }
        val cues = detectStructuralCues(request)
        return rankToolsForTokens(queryTokens, cues, availableTools, toolHints)
    }

    private fun rankToolsForTokens(
        queryTokens: Set<String>,
        cues: StructuralCues,
        availableTools: List<ToolMetadata>,
        toolHints: Map<String, List<String>> = emptyMap()
    ): List<ScoredTool> {
        return availableTools
            .map { tool ->
                ScoredTool(
                    tool = tool,
                    score = scoreTool(tool, queryTokens, cues, toolHints[tool.name].orEmpty())
                )
            }
            .sortedWith(
                compareByDescending<ScoredTool> { it.score }
                    .thenBy { it.tool.name }
            )
    }

    private fun extractCurrentUtteranceTokens(request: IntentRequest): Set<String> {
        val tokens = LinkedHashSet<String>()
        val userLocale = Locale.forLanguageTag(request.languageHint?.bcp47Tag ?: "en")
        val normalizedTokens = request.normalizedText?.tokens
        if (!normalizedTokens.isNullOrEmpty()) {
            for (tok in normalizedTokens) {
                val lowered = tok.lowercase(userLocale)
                if (lowered.isNotEmpty()) {
                    tokens.add(lowered)
                }
            }
        }
        val rawFolded = (request.normalizedText?.matchKey ?: request.rawUtterance).lowercase(userLocale)
        for (piece in TOKEN_SPLIT_REGEX.split(rawFolded)) {
            if (piece.isNotEmpty()) {
                tokens.add(piece)
            }
        }
        return tokens
    }

    private fun extractQueryTokens(request: IntentRequest): Set<String> {
        val tokens = LinkedHashSet<String>(extractCurrentUtteranceTokens(request))
        val userLocale = Locale.forLanguageTag(request.languageHint?.bcp47Tag ?: "en")
        // Include tokens from the immediately preceding trusted user turn so short follow-ups
        // (e.g., supplying a missing note body or time) retain the relevant tool in Segment B.
        val previousUserTurn = request.conversationHistory.lastOrNull()?.userUtterance
        if (!previousUserTurn.isNullOrBlank()) {
            for (piece in TOKEN_SPLIT_REGEX.split(previousUserTurn.lowercase(userLocale))) {
                if (piece.length >= MIN_PREFIX_LEN) {
                    tokens.add(piece)
                }
            }
        }
        return tokens
    }

    private fun detectStructuralCues(request: IntentRequest): StructuralCues {
        val source = request.normalizedText?.matchKey ?: request.rawUtterance
        return StructuralCues(
            hasTimeOrDate = TIME_CUE_REGEX.containsMatchIn(source) || DATE_CUE_REGEX.containsMatchIn(source),
            hasPhoneOrEmail = PHONE_CUE_REGEX.containsMatchIn(source) || EMAIL_CUE_REGEX.containsMatchIn(source),
            hasFilePath = FILE_PATH_CUE_REGEX.containsMatchIn(source),
            hasPercentOrNumber = PERCENT_CUE_REGEX.containsMatchIn(source)
        )
    }

    private fun scoreTool(
        tool: ToolMetadata,
        queryTokens: Set<String>,
        cues: StructuralCues,
        localeHints: List<String> = emptyList()
    ): Double {
        var score = structuralCueBoost(tool.category, cues)

        val nameTokens = tokenizeAscii(tool.name)
        val categoryTokens = tokenizeAscii(tool.category.name)
        val descriptionTokens = tokenizeAscii(tool.description)
        val hintTokens = if (localeHints.isEmpty()) {
            emptySet()
        } else {
            localeHints.mapTo(LinkedHashSet(localeHints.size)) { it.lowercase(Locale.ROOT) }
        }
        val fieldNameTokens = LinkedHashSet<String>()
        val fieldDescTokens = LinkedHashSet<String>()
        for (field in tool.fields) {
            fieldNameTokens.addAll(tokenizeAscii(field.name))
            fieldDescTokens.addAll(tokenizeAscii(field.description))
        }

        for (q in queryTokens) {
            if (q in nameTokens) {
                score += WEIGHT_TOOL_NAME_EXACT
            } else if (matchesStemPrefix(q, nameTokens)) {
                score += WEIGHT_TOOL_NAME_PREFIX
            }

            if (hintTokens.isNotEmpty()) {
                if (q in hintTokens) {
                    score += WEIGHT_LOCALE_HINT_EXACT
                } else if (matchesStemPrefix(q, hintTokens)) {
                    score += WEIGHT_LOCALE_HINT_PREFIX
                }
            }

            if (q in fieldNameTokens) {
                score += WEIGHT_FIELD_NAME_EXACT
            }
            if (q in categoryTokens) {
                score += WEIGHT_CATEGORY_EXACT
            }
            if (q in descriptionTokens) {
                score += WEIGHT_DESCRIPTION_EXACT
            } else if (matchesStemPrefix(q, descriptionTokens)) {
                score += WEIGHT_DESCRIPTION_PREFIX
            }
            if (q in fieldDescTokens) {
                score += WEIGHT_FIELD_DESC_EXACT
            }
        }

        return score
    }

    private fun structuralCueBoost(category: ToolCategory, cues: StructuralCues): Double {
        var boost = 0.0
        when (category) {
            ToolCategory.TIME_CALENDAR -> {
                if (cues.hasTimeOrDate) boost += WEIGHT_STRUCTURAL_CUE
            }

            ToolCategory.COMMUNICATION -> {
                if (cues.hasPhoneOrEmail) boost += WEIGHT_STRUCTURAL_CUE
            }

            ToolCategory.NOTES_FILES -> {
                if (cues.hasFilePath) boost += WEIGHT_SECONDARY_CUE
            }

            ToolCategory.DEVICE_SETTINGS -> {
                if (cues.hasPercentOrNumber) boost += WEIGHT_SECONDARY_CUE
            }

            ToolCategory.AUTOMATION_RULES -> {
                if (cues.hasTimeOrDate) boost += WEIGHT_AUTOMATION_TIME_CUE
            }
        }
        return boost
    }

    private fun mapToCoreBucket(category: ToolCategory): ToolCategory {
        return when (category) {
            ToolCategory.TIME_CALENDAR,
            ToolCategory.AUTOMATION_RULES -> ToolCategory.TIME_CALENDAR

            ToolCategory.COMMUNICATION -> ToolCategory.COMMUNICATION
            ToolCategory.DEVICE_SETTINGS -> ToolCategory.DEVICE_SETTINGS
            ToolCategory.NOTES_FILES -> ToolCategory.NOTES_FILES
        }
    }

    private fun tokenizeAscii(text: String): Set<String> {
        val out = LinkedHashSet<String>()
        for (part in TOKEN_SPLIT_REGEX.split(text.lowercase(Locale.US))) {
            if (part.length >= 2) {
                out.add(part)
            }
        }
        return out
    }

    private fun matchesStemPrefix(query: String, candidates: Set<String>): Boolean {
        if (query.length < MIN_PREFIX_LEN) return false
        for (cand in candidates) {
            if (cand.length >= MIN_PREFIX_LEN &&
                (cand.startsWith(query) || query.startsWith(cand))
            ) {
                return true
            }
        }
        return false
    }

    companion object {
        const val SEMANTIC_BOOST_THRESHOLD: Float = 0.42f
        const val STRONG_LEXICAL_SHORT_CIRCUIT_SCORE: Double = 3.5
        private const val MAX_TOOL_EMBEDDING_CACHE: Int = 128
        private const val WEIGHT_SEMANTIC_BOOST_BASE: Double = 2.5
        private const val WEIGHT_SEMANTIC_BOOST_SCALE: Double = 8.0
        private const val MIN_PREFIX_LEN: Int = 4
        private const val SHORT_FOLLOWUP_MAX_TOKENS: Int = 2
        private const val WEIGHT_TOOL_NAME_EXACT: Double = 4.0
        private const val WEIGHT_TOOL_NAME_PREFIX: Double = 1.5
        private const val WEIGHT_LOCALE_HINT_EXACT: Double = 3.5
        private const val WEIGHT_LOCALE_HINT_PREFIX: Double = 1.5
        private const val WEIGHT_FIELD_NAME_EXACT: Double = 2.0
        private const val WEIGHT_CATEGORY_EXACT: Double = 1.5
        private const val WEIGHT_DESCRIPTION_EXACT: Double = 1.0
        private const val WEIGHT_DESCRIPTION_PREFIX: Double = 0.5
        private const val WEIGHT_FIELD_DESC_EXACT: Double = 0.75
        private const val WEIGHT_STRUCTURAL_CUE: Double = 3.0
        private const val WEIGHT_SECONDARY_CUE: Double = 2.0
        private const val WEIGHT_AUTOMATION_TIME_CUE: Double = 0.5

        private val CORE_BUCKETS: List<ToolCategory> = listOf(
            ToolCategory.TIME_CALENDAR,
            ToolCategory.COMMUNICATION,
            ToolCategory.DEVICE_SETTINGS,
            ToolCategory.NOTES_FILES
        )

        private val TOKEN_SPLIT_REGEX: Regex = Regex("[^\\p{L}\\p{Nd}]+")
        private val TIME_CUE_REGEX: Regex = Regex("""(?<!\d)\d{1,2}[:hH]\d{2}(?!\d)""")
        private val DATE_CUE_REGEX: Regex = Regex("""(?<!\d)\d{4}-\d{2}-\d{2}(?!\d)""")
        private val PHONE_CUE_REGEX: Regex = Regex("""(?:\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}""")
        private val EMAIL_CUE_REGEX: Regex = Regex("""(?<!\S)[^\s@]+@[^\s@]+\.[^\s@]+""")
        private val FILE_PATH_CUE_REGEX: Regex = Regex("""(?:^|\s)(?:/[\w./-]+|[\w-]+\.[A-Za-z0-9]{2,4})(?:\s|$)""")
        private val PERCENT_CUE_REGEX: Regex = Regex("""(?<!\d)\d{1,3}%""")
    }
}

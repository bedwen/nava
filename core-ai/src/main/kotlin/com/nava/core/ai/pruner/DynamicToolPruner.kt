package com.nava.core.ai.pruner

import com.nava.domain.ai.IntentRequest
import com.nava.domain.tool.ToolCategory
import com.nava.domain.tool.ToolMetadata
import java.util.Locale

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

    fun prune(request: IntentRequest, availableTools: List<ToolMetadata>): List<ToolMetadata> {
        if (availableTools.isEmpty()) return emptyList()

        val scored = rankTools(request, availableTools)
        val effectiveMin = minOf(minTools, scored.size)
        val effectiveMax = minOf(maxTools, scored.size)
        val positiveCount = scored.count { it.score > 0.0 }
        val takeCount = positiveCount.coerceIn(effectiveMin, effectiveMax)
        return scored.take(takeCount).map { it.tool }
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
        availableTools: List<ToolMetadata>
    ): List<ScoredTool> {
        val queryTokens = extractQueryTokens(request)
        val cues = detectStructuralCues(request)

        return availableTools
            .map { tool ->
                ScoredTool(
                    tool = tool,
                    score = scoreTool(tool, queryTokens, cues)
                )
            }
            .sortedWith(
                compareByDescending<ScoredTool> { it.score }
                    .thenBy { it.tool.name }
            )
    }

    private fun extractQueryTokens(request: IntentRequest): Set<String> {
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
        cues: StructuralCues
    ): Double {
        var score = structuralCueBoost(tool.category, cues)

        val nameTokens = tokenizeAscii(tool.name)
        val categoryTokens = tokenizeAscii(tool.category.name)
        val descriptionTokens = tokenizeAscii(tool.description)
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
        private const val MIN_PREFIX_LEN: Int = 4
        private const val WEIGHT_TOOL_NAME_EXACT: Double = 4.0
        private const val WEIGHT_TOOL_NAME_PREFIX: Double = 1.5
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

package com.nava.core.ai.router

import com.nava.domain.ai.IntentRequest
import com.nava.domain.ai.IntentResolver
import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.ResolutionResult
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.locale.GenericTextNormalizer
import com.nava.domain.locale.LocaleRulePack
import com.nava.domain.locale.LocaleRulePackLoader
import com.nava.domain.locale.RuleMatchPattern
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolSchemaField
import java.time.Instant
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Tier 1 deterministic IntentResolver (`< 2 ms`) powered entirely by declarative Layer R
 * [LocaleRulePack] data assets loaded via [LocaleRulePackLoader] (PLAN.md Sections 3 and 6.3).
 *
 * Open/Closed & Language-Agnostic: contains zero hardcoded language checks and zero tool-specific
 * `if/else` branches. Languages without a rule pack skip Tier 1 immediately (`NoMatch`).
 */
class RuleIntentResolver(
    private val rulePackLoader: LocaleRulePackLoader,
    private val securityFirewall: SecurityFirewallPort,
    private val textNormalizer: GenericTextNormalizer = GenericTextNormalizer(),
    private val timeResolver: LocaleTimeResolver = LocaleTimeResolver(),
    private val zoneIdProvider: () -> ZoneId = { ZoneId.systemDefault() },
    private val planIdGenerator: () -> String = { UUID.randomUUID().toString() }
) : IntentResolver {

    override val tier: ResolutionTier = ResolutionTier.TIER_1_RULE

    private val compiledRegexCache = ConcurrentHashMap<String, Regex>()

    override suspend fun resolve(
        request: IntentRequest,
        availableTools: List<ToolMetadata>
    ): ResolutionResult {
        if (request.provenance != DataProvenance.USER_UTTERANCE) {
            throw SecurityException(
                "Tier 1 RuleIntentResolver requires USER_UTTERANCE provenance, got ${request.provenance}"
            )
        }
        if (availableTools.isEmpty()) return ResolutionResult.NoMatch

        val detectedLang = request.languageHint?.bcp47Tag
            ?: request.normalizedText?.languageTag
            ?: FALLBACK_LANGUAGE_TAG

        val normalized = request.normalizedText
            ?: textNormalizer.normalize(request.rawUtterance, detectedLang)

        if (normalized.matchKey.isBlank() || normalized.matchKey.length > MAX_RULE_INPUT_CHARS) {
            return ResolutionResult.NoMatch
        }

        val rulePack = rulePackLoader.loadRulePack(detectedLang)
            ?: return ResolutionResult.NoMatch

        val toolsByName = availableTools.associateBy { it.name }
        val nowZdt = ZonedDateTime.ofInstant(
            Instant.ofEpochMilli(request.issuedAtEpochMs),
            zoneIdProvider()
        )

        val orderedPatterns = rulePack.patterns.sortedByDescending { it.priority }
        for (pattern in orderedPatterns) {
            val toolMetadata = toolsByName[pattern.toolName] ?: continue
            val regex = getOrCompileRegex(pattern.regexPattern) ?: continue
            val match = regex.find(normalized.matchKey) ?: continue

            val rawSlots = extractRawSlots(pattern, match)
            val capturedSlotNames = pattern.slotMappings.keys
            val resolvedArgs = bindTypedArguments(
                rawSlots = rawSlots,
                toolMetadata = toolMetadata,
                rulePack = rulePack,
                nowZdt = nowZdt,
                recoverFreeText = { slotName, captured ->
                    if (slotName in capturedSlotNames) {
                        recoverOriginalSpan(request.rawUtterance, captured, detectedLang) ?: captured
                    } else {
                        captured
                    }
                }
            ) ?: continue

            val token = securityFirewall.mintToken(
                requestId = request.requestId,
                utteranceProvenance = request.provenance,
                candidateTools = setOf(toolMetadata.name),
                nowEpochMs = request.issuedAtEpochMs
            )

            val call = ToolCallAst(
                toolName = toolMetadata.name,
                arguments = resolvedArgs,
                orderIndex = 0,
                targetId = request.targetContextId
            )
            val plan = PlanAst(
                planId = planIdGenerator(),
                calls = listOf(call)
            )
            return ResolutionResult.ResolvedPlan(
                tier = ResolutionTier.TIER_1_RULE,
                plan = plan,
                capabilityToken = token
            )
        }

        if (rulePack.conversationalPatterns.isNotEmpty()) {
            val orderedConversational = rulePack.conversationalPatterns.sortedByDescending { it.priority }
            for (convPattern in orderedConversational) {
                val regex = getOrCompileRegex(convPattern.regexPattern) ?: continue
                if (regex.matches(normalized.matchKey)) {
                    return ResolutionResult.ConversationalReply(
                        tier = ResolutionTier.TIER_1_RULE,
                        replyText = convPattern.replyText,
                        languageTag = rulePack.languageTag
                    )
                }
            }
        }

        return ResolutionResult.NoMatch
    }

    private fun extractRawSlots(
        pattern: RuleMatchPattern,
        match: MatchResult
    ): Map<String, String> {
        val rawSlots = LinkedHashMap<String, String>()
        for ((k, v) in pattern.staticSlots) {
            rawSlots[k] = v
        }
        for ((slotName, groupRef) in pattern.slotMappings) {
            val extracted = extractGroupValue(match, groupRef)?.trim()
            if (!extracted.isNullOrEmpty()) {
                rawSlots[slotName] = extracted
            }
        }
        return rawSlots
    }

    private fun extractGroupValue(match: MatchResult, groupRef: String): String? {
        val cleanedRef = groupRef.trim().removePrefix("$")
        val numericIndex = cleanedRef.toIntOrNull()
        if (numericIndex != null) {
            return if (numericIndex in 0 until match.groupValues.size) {
                match.groupValues[numericIndex].takeIf { it.isNotEmpty() }
            } else {
                null
            }
        }
        return runCatching {
            val namedGroups = match.groups as? MatchNamedGroupCollection
            namedGroups?.get(cleanedRef)?.value
        }.getOrNull()
    }

    private fun bindTypedArguments(
        rawSlots: Map<String, String>,
        toolMetadata: ToolMetadata,
        rulePack: LocaleRulePack,
        nowZdt: ZonedDateTime,
        recoverFreeText: (slotName: String, captured: String) -> String = { _, captured -> captured }
    ): Map<String, Tainted<SlotValueAst>>? {
        val bound = LinkedHashMap<String, Tainted<SlotValueAst>>()
        for (field in toolMetadata.fields) {
            val slotsForField = if (field.slotKind in FREE_TEXT_SLOT_KINDS && field.valueType == SlotValueType.STRING) {
                val captured = rawSlots[field.name]
                if (captured != null) rawSlots + (field.name to recoverFreeText(field.name, captured)) else rawSlots
            } else {
                rawSlots
            }
            val astValue = resolveFieldValue(field, slotsForField, rulePack, nowZdt)
            if (astValue == null) {
                if (field.required) return null
                continue
            }
            bound[field.name] = Tainted.fromUserUtterance(
                value = astValue,
                slotKind = field.slotKind
            )
        }
        return bound
    }

    private fun resolveFieldValue(
        field: ToolSchemaField,
        rawSlots: Map<String, String>,
        rulePack: LocaleRulePack,
        nowZdt: ZonedDateTime
    ): SlotValueAst? {
        val directRaw = rawSlots[field.name]?.trim()
        return when (field.valueType) {
            SlotValueType.ISO_TIME -> {
                val resolved = timeResolver.resolveTime(
                    rawSlots = rawSlots,
                    timeKeywords = rulePack.timeKeywords,
                    now = nowZdt,
                    languageTag = rulePack.languageTag
                ) ?: return null
                SlotValueAst.StringValue(resolved)
            }

            SlotValueType.DURATION_SECONDS -> {
                val seconds = timeResolver.resolveDurationSeconds(
                    rawSlots = rawSlots,
                    timeKeywords = rulePack.timeKeywords,
                    languageTag = rulePack.languageTag
                ) ?: directRaw?.toLongOrNull()?.takeIf { it > 0L }
                    ?: return null
                SlotValueAst.IntValue(seconds)
            }

            SlotValueType.ISO_DATE -> {
                val resolvedDate = timeResolver.resolveDate(
                    rawSlots = rawSlots,
                    timeKeywords = rulePack.timeKeywords,
                    now = nowZdt,
                    languageTag = rulePack.languageTag
                ) ?: return null
                SlotValueAst.StringValue(resolvedDate)
            }

            SlotValueType.INTEGER -> {
                val parsed = directRaw?.toLongOrNull() ?: return null
                SlotValueAst.IntValue(parsed)
            }

            SlotValueType.BOOLEAN -> {
                val parsed = parseBoolean(directRaw, rulePack.timeKeywords, rulePack.languageTag)
                    ?: return null
                SlotValueAst.BooleanValue(parsed)
            }

            SlotValueType.STRING,
            SlotValueType.ISO_DATETIME -> {
                if (directRaw.isNullOrEmpty()) return null
                val sanitized = try {
                    Gemma4InputSanitizer.sanitize(directRaw).trim()
                } catch (_: SecurityException) {
                    return null
                }
                if (sanitized.isEmpty()) return null
                SlotValueAst.StringValue(sanitized)
            }
        }
    }

    private fun parseBoolean(
        raw: String?,
        timeKeywords: Map<String, String>,
        languageTag: String
    ): Boolean? {
        if (raw.isNullOrBlank()) return null
        val userLocale = Locale.forLanguageTag(languageTag)
        val lower = raw.trim().lowercase(userLocale)
        val mapped = timeKeywords[lower]?.trim()?.lowercase(Locale.US) ?: lower
        return when (mapped) {
            "true", "1", "on", "enable", "enabled" -> true
            "false", "0", "off", "disable", "disabled" -> false
            else -> null
        }
    }

    /**
     * Maps a slot captured from the normalized match key back to the user's original words, so
     * free text keeps its case and diacritics ("Esimin adi Ayse" -> "E\u015fimin ad\u0131 Ay\u015fe").
     *
     * Each whitespace-separated original word is normalized on its own with the same
     * [textNormalizer]; the first contiguous run whose normalized form equals [captured] (ignoring
     * edge punctuation) is returned in its original spelling. Returns null when no run aligns,
     * in which case the normalized capture is used unchanged.
     */
    internal fun recoverOriginalSpan(original: String, captured: String, languageTag: String): String? {
        val target = captured.trim()
        if (target.isEmpty()) return null
        val words = original.trim().split(WHITESPACE).filter { it.isNotEmpty() }
        if (words.isEmpty() || words.size > MAX_RECOVERY_WORDS) return null
        val normalizedWords = words.map { word ->
            runCatching { textNormalizer.normalize(word, languageTag).matchKey }.getOrDefault("")
        }
        for (start in words.indices) {
            val joined = StringBuilder()
            for (end in start until words.size) {
                if (end > start) joined.append(' ')
                joined.append(normalizedWords[end])
                val candidate = joined.toString()
                if (candidate.length > target.length + EDGE_PUNCTUATION_SLACK) break
                if (candidate == target || candidate.trim(*EDGE_PUNCTUATION) == target) {
                    // The normalizer dropped invisible/bidi controls; never reintroduce them.
                    val originalRun = Gemma4InputSanitizer.stripInvisibleControls(
                        words.subList(start, end + 1).joinToString(" ")
                    )
                    return if (candidate == target) originalRun else originalRun.trim(*EDGE_PUNCTUATION)
                }
            }
        }
        return null
    }

    private fun getOrCompileRegex(pattern: String): Regex? {
        compiledRegexCache[pattern]?.let { return it }
        val compiled = runCatching { Regex(pattern) }.getOrNull() ?: return null
        if (compiledRegexCache.size >= MAX_REGEX_CACHE_ENTRIES) {
            compiledRegexCache.clear()
        }
        compiledRegexCache[pattern] = compiled
        return compiled
    }

    companion object {
        const val MAX_RULE_INPUT_CHARS: Int = 512
        private const val MAX_REGEX_CACHE_ENTRIES: Int = 512
        private const val FALLBACK_LANGUAGE_TAG: String = "en"
        private const val MAX_RECOVERY_WORDS: Int = 80
        private const val EDGE_PUNCTUATION_SLACK: Int = 4
        private val WHITESPACE: Regex = Regex("\\s+")
        private val EDGE_PUNCTUATION: CharArray = charArrayOf(
            ',', '.', ';', ':', '!', '?', '"', '\'', '\u060C', '\u061F', '\u00BF', '\u00A1'
        )

        /** Free-text slots whose original spelling (case, diacritics) is preserved. */
        private val FREE_TEXT_SLOT_KINDS: Set<SensitiveSlotKind?> = setOf(
            SensitiveSlotKind.TEXT_BODY,
            SensitiveSlotKind.EVENT_TITLE
        )
    }
}

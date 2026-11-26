package com.nava.domain.locale

/**
 * Declarative Layer R conversational rule (greetings, identity, capabilities, acknowledgements)
 * loaded from `assets/locale/<lang>/rules.json` so Tier 1 can respond in `< 2 ms` without
 * waking Gemma 4, while open-ended conversation falls through to Tier 3.
 */
data class ConversationalRulePattern(
    val patternId: String,
    val regexPattern: String,
    val replyText: String,
    val priority: Int = 100
) {
    init {
        require(patternId.isNotBlank()) { "patternId must not be blank" }
        require(regexPattern.isNotBlank()) { "regexPattern must not be blank" }
        require(replyText.isNotBlank()) { "replyText must not be blank" }
    }
}

/**
 * Declarative Layer R rule bundle loaded from `assets/locale/<lang>/rules.*`.
 */
data class LocaleRulePack(
    val languageTag: String,
    val version: Int,
    val patterns: List<RuleMatchPattern>,
    val timeKeywords: Map<String, String> = emptyMap(),
    val conversationalPatterns: List<ConversationalRulePattern> = emptyList(),
    val toolHints: Map<String, List<String>> = emptyMap()
) {
    init {
        require(languageTag.isNotBlank()) { "languageTag must not be blank" }
        require(version > 0) { "LocaleRulePack version must be positive" }
    }
}

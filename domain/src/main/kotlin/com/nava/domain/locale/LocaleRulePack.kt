package com.nava.domain.locale

/**
 * Declarative Layer R rule bundle loaded from `assets/locale/<lang>/rules.*`.
 */
data class LocaleRulePack(
    val languageTag: String,
    val version: Int,
    val patterns: List<RuleMatchPattern>,
    val timeKeywords: Map<String, String> = emptyMap()
) {
    init {
        require(languageTag.isNotBlank()) { "languageTag must not be blank" }
        require(version > 0) { "LocaleRulePack version must be positive" }
    }
}

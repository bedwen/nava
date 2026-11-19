package com.nava.domain.locale

/**
 * Extension point for optional language-specific normalization strategies (Open/Closed Principle).
 * Strategies are registered in [LocaleNormalizerRegistry] rather than hardcoded as `if (lang == ...)` branches.
 */
interface LocaleNormalizerStrategy {
    /** BCP-47 tags (or base language codes) handled by this strategy. */
    val languageTags: Set<String>

    fun normalizeFolded(text: String, languageTag: String): String = text

    fun normalizeMatchKey(text: String, languageTag: String): String = text
}

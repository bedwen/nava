package com.nava.domain.locale

/**
 * Output of [GenericTextNormalizer] preserving the original utterance alongside
 * locale-folded text, script-aware match keys, and BreakIterator word tokens.
 */
data class NormalizedText(
    val original: String,
    val languageTag: String,
    val folded: String,
    val matchKey: String,
    val tokens: List<String>
)

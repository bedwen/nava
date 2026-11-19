package com.nava.domain.locale

/**
 * Unicode script families used for data-driven language metadata and script-aware normalization.
 */
enum class ScriptFamily(
    val allowsDiacriticStrippingForMatchKeys: Boolean,
    val isSpaceLessScript: Boolean
) {
    LATIN(allowsDiacriticStrippingForMatchKeys = true, isSpaceLessScript = false),
    CYRILLIC(allowsDiacriticStrippingForMatchKeys = true, isSpaceLessScript = false),
    GREEK(allowsDiacriticStrippingForMatchKeys = true, isSpaceLessScript = false),
    ARABIC(allowsDiacriticStrippingForMatchKeys = false, isSpaceLessScript = false),
    HEBREW(allowsDiacriticStrippingForMatchKeys = false, isSpaceLessScript = false),
    DEVANAGARI(allowsDiacriticStrippingForMatchKeys = false, isSpaceLessScript = false),
    INDIC_OTHER(allowsDiacriticStrippingForMatchKeys = false, isSpaceLessScript = false),
    THAI(allowsDiacriticStrippingForMatchKeys = false, isSpaceLessScript = true),
    KHMER_LAO(allowsDiacriticStrippingForMatchKeys = false, isSpaceLessScript = true),
    CJK(allowsDiacriticStrippingForMatchKeys = false, isSpaceLessScript = true),
    HANGUL(allowsDiacriticStrippingForMatchKeys = false, isSpaceLessScript = false),
    OTHER(allowsDiacriticStrippingForMatchKeys = false, isSpaceLessScript = false)
}

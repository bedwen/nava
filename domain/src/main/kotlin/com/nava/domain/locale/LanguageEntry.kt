package com.nava.domain.locale

/**
 * Relative quality classification of a language on Gemma 4 models, measured via golden corpora.
 */
enum class QualityTier {
    HIGH_RESOURCE,
    STANDARD,
    LOW_RESOURCE_E2B_WARNING
}

/**
 * Data-driven descriptor for any language in [SupportedLanguageCatalog].
 */
data class LanguageEntry(
    val bcp47Tag: String,
    val englishName: String,
    val nativeName: String,
    val scriptFamily: ScriptFamily,
    val isRtl: Boolean,
    val qualityTier: QualityTier = QualityTier.STANDARD,
    val hasLayerRPack: Boolean = false,
    val hasLayerUTranslation: Boolean = false
) {
    init {
        require(bcp47Tag.isNotBlank()) { "bcp47Tag must not be blank" }
        require(englishName.isNotBlank()) { "englishName must not be blank" }
    }
}

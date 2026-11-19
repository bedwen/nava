package com.nava.domain.locale

/**
 * Result of on-device language identification for a single user utterance.
 */
data class DetectedLanguage(
    val bcp47Tag: String,
    val confidence: Float,
    val scriptFamily: ScriptFamily,
    val isAmbiguous: Boolean = false
) {
    init {
        require(bcp47Tag.isNotBlank()) { "bcp47Tag must not be blank" }
        require(confidence in 0.0f..1.0f) { "confidence must be in [0.0, 1.0]" }
    }
}

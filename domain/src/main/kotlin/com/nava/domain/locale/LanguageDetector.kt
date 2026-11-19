package com.nava.domain.locale

/**
 * Pure Kotlin port for on-device language identification using app locale priors,
 * script scoring, and platform text classifiers without network calls.
 */
interface LanguageDetector {
    suspend fun detect(utterance: String, appLocaleTag: String): DetectedLanguage
}

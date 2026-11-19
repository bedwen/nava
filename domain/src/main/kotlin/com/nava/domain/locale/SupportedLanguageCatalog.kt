package com.nava.domain.locale

/**
 * Data-driven port exposing the Gemma 4 supported language catalog loaded from assets.
 */
interface SupportedLanguageCatalog {
    suspend fun allLanguages(): List<LanguageEntry>
    suspend fun findByTag(bcp47Tag: String): LanguageEntry?
    suspend fun isSupported(bcp47Tag: String): Boolean
}

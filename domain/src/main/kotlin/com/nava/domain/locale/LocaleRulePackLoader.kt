package com.nava.domain.locale

/**
 * Pure Kotlin port for loading declarative Layer R [LocaleRulePack] bundles from
 * `assets/locale/<lang>/rules.*` without coupling resolvers to Android `AssetManager`
 * (PLAN.md Sections 6.1 and 6.3, Iron Law 4).
 */
interface LocaleRulePackLoader {
    /**
     * Loads the declarative Layer R rule pack for [languageTag], or returns `null` when
     * no rule pack is shipped for that language (Layer G fallback applies).
     */
    suspend fun loadRulePack(languageTag: String): LocaleRulePack?

    /** Returns the set of normalized BCP-47 language tags that have an available Layer R rule pack. */
    suspend fun availableLanguageTags(): Set<String>
}

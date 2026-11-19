package com.nava.domain.locale

import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

/**
 * Thread-safe, Open/Closed registry binding optional [LocaleNormalizerStrategy] overrides
 * to BCP-47 language tags without hardcoded conditional branches.
 */
class LocaleNormalizerRegistry(
    initialStrategies: Iterable<LocaleNormalizerStrategy> = emptyList()
) {
    private val strategies = ConcurrentHashMap<String, LocaleNormalizerStrategy>()

    init {
        for (strategy in initialStrategies) {
            register(strategy)
        }
    }

    /** Registers [strategy] for all of its declared [LocaleNormalizerStrategy.languageTags]. */
    fun register(strategy: LocaleNormalizerStrategy) {
        for (tag in strategy.languageTags) {
            val normalizedTag = canonicalizeKey(tag)
            require(normalizedTag.isNotBlank()) { "Language tag in strategy must not be blank" }
            strategies[normalizedTag] = strategy
        }
    }

    /**
     * Finds a strategy matching the full tag first (e.g., `zh-hant-tw`), progressively trimming
     * trailing subtags (`zh-hant`, then `zh`), or null if generic normalization suffices.
     */
    fun findForLanguage(languageTag: String): LocaleNormalizerStrategy? {
        var candidate = canonicalizeKey(languageTag)
        if (candidate.isBlank()) return null
        while (candidate.isNotEmpty()) {
            strategies[candidate]?.let { return it }
            val sepIndex = candidate.lastIndexOf('-')
            if (sepIndex <= 0) {
                break
            }
            candidate = candidate.substring(0, sepIndex)
        }
        return null
    }

    /** Returns an immutable snapshot of all registered language tag keys. */
    fun registeredLanguageTags(): Set<String> = strategies.keys.toSet()

    private fun canonicalizeKey(tag: String): String {
        return tag.trim().replace('_', '-').lowercase(Locale.US)
    }
}

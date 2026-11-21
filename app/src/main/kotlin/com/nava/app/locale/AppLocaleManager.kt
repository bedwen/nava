package com.nava.app.locale

import android.app.LocaleManager
import android.content.Context
import android.os.Build
import android.os.LocaleList
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import com.nava.domain.locale.LanguageEntry
import com.nava.domain.locale.SupportedLanguageCatalog
import com.nava.domain.security.Gemma4InputSanitizer
import java.util.Locale
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Abstraction over Android per-app locale APIs (`LocaleManager` on API 33+ and
 * `AppCompatDelegate.setApplicationLocales` on API 31-32) so per-app language switching
 * is deterministically unit-testable on the JVM.
 */
interface PlatformLocaleBridge {
    /** Returns the currently configured per-app BCP-47 locale tag, or `null` if unset. */
    fun getApplicationLocaleTag(): String?

    /** Persists and applies [bcp47Tag] as the application's active per-app locale. */
    fun setApplicationLocaleTag(bcp47Tag: String)

    /** Returns the device/system default BCP-47 locale tag. */
    fun getSystemDefaultLocaleTag(): String
}

/**
 * Production Android implementation of [PlatformLocaleBridge]:
 * - API 33+ (`Build.VERSION_CODES.TIRAMISU`): uses [LocaleManager.setApplicationLocales] /
 *   [LocaleManager.getApplicationLocales].
 * - API 31-32: falls back to [AppCompatDelegate.setApplicationLocales] /
 *   [AppCompatDelegate.getApplicationLocales] (PLAN.md Sections 2.3 & 6.2).
 */
class AndroidPlatformLocaleBridge(
    private val context: Context,
    private val sdkIntProvider: () -> Int = { Build.VERSION.SDK_INT }
) : PlatformLocaleBridge {

    override fun getApplicationLocaleTag(): String? {
        return runCatching {
            if (sdkIntProvider() >= Build.VERSION_CODES.TIRAMISU) {
                val localeManager = context.getSystemService(LocaleManager::class.java)
                val tags = localeManager?.applicationLocales?.toLanguageTags().orEmpty()
                val primary = extractPrimaryTag(tags)
                if (primary != null) return@runCatching primary
            }
            val compatTags = AppCompatDelegate.getApplicationLocales().toLanguageTags()
            extractPrimaryTag(compatTags)
        }.getOrNull()
    }

    override fun setApplicationLocaleTag(bcp47Tag: String) {
        val cleaned = AppLocaleManager.sanitizeTag(bcp47Tag).ifEmpty { AppLocaleManager.DEFAULT_FALLBACK_TAG }
        runCatching {
            if (sdkIntProvider() >= Build.VERSION_CODES.TIRAMISU) {
                val localeManager = context.getSystemService(LocaleManager::class.java)
                if (localeManager != null) {
                    localeManager.applicationLocales = LocaleList.forLanguageTags(cleaned)
                    return@runCatching
                }
            }
            AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(cleaned))
        }
    }

    override fun getSystemDefaultLocaleTag(): String {
        return runCatching { Locale.getDefault().toLanguageTag() }
            .getOrDefault(AppLocaleManager.DEFAULT_FALLBACK_TAG)
            .ifBlank { AppLocaleManager.DEFAULT_FALLBACK_TAG }
    }

    private fun extractPrimaryTag(languageTagsCsv: String): String? {
        if (languageTagsCsv.isBlank()) return null
        val first = languageTagsCsv.split(',').firstOrNull()?.trim().orEmpty()
        return first.takeIf { it.isNotEmpty() && !it.equals("und", ignoreCase = true) }
    }
}

/**
 * In-memory [PlatformLocaleBridge] for JVM unit tests.
 */
class InMemoryPlatformLocaleBridge(
    initialApplicationLocaleTag: String? = null,
    private val systemDefaultLocaleTag: String = AppLocaleManager.DEFAULT_FALLBACK_TAG
) : PlatformLocaleBridge {

    @Volatile
    var currentApplicationTag: String? = initialApplicationLocaleTag
        private set

    val appliedTagsHistory: MutableList<String> = mutableListOf()

    override fun getApplicationLocaleTag(): String? = currentApplicationTag

    override fun setApplicationLocaleTag(bcp47Tag: String) {
        currentApplicationTag = bcp47Tag
        appliedTagsHistory.add(bcp47Tag)
    }

    override fun getSystemDefaultLocaleTag(): String = systemDefaultLocaleTag
}

/**
 * Per-app locale manager backed by [SupportedLanguageCatalog] and [PlatformLocaleBridge]
 * (PLAN.md Sections 2.3, 6.1, 6.1.1, and 6.4).
 *
 * Invariants (Iron Law 1):
 * - Zero hardcoded language lists and zero `if (lang == ...)` branches.
 * - Implements the deterministic `exact (e.g. pt-BR) -> base (pt) -> "en"` fallback chain
 *   purely by subtag reduction against [SupportedLanguageCatalog].
 * - Exposes the active BCP-47 language tag via [activeLocaleTagFlow].
 */
class AppLocaleManager(
    private val catalog: SupportedLanguageCatalog,
    private val platformBridge: PlatformLocaleBridge,
    initialLocaleTag: String? = null
) {

    constructor(
        context: Context,
        catalog: SupportedLanguageCatalog
    ) : this(
        catalog = catalog,
        platformBridge = AndroidPlatformLocaleBridge(context.applicationContext)
    )

    private val mutex = Mutex()

    private val _activeLocaleTagFlow: MutableStateFlow<String> = MutableStateFlow(
        resolveInitialTagSnapshot(initialLocaleTag)
    )

    /** Reactive stream of the currently active BCP-47 language tag. */
    val activeLocaleTagFlow: StateFlow<String> = _activeLocaleTagFlow.asStateFlow()

    /** Returns the current active BCP-47 language tag snapshot. */
    fun currentLocaleTag(): String = _activeLocaleTagFlow.value

    /** Returns the [Locale] corresponding to [currentLocaleTag]. */
    fun currentLocale(): Locale = Locale.forLanguageTag(_activeLocaleTagFlow.value)

    /**
     * Constructs the ordered fallback chain `exact -> parent subtags -> base -> "en"`
     * (PLAN.md Section 6.1.1) without any hardcoded language list.
     *
     * Example: `"pt-BR"` -> `["pt-BR", "pt", "en"]`.
     */
    fun buildFallbackChain(requestedTag: String): List<String> {
        val cleaned = sanitizeTag(requestedTag)
        val chain = ArrayList<String>(4)
        val seenLower = LinkedHashSet<String>(4)

        fun addCandidate(tag: String) {
            if (tag.isEmpty()) return
            val lower = tag.lowercase(Locale.US)
            if (seenLower.add(lower)) {
                chain.add(tag)
            }
        }

        var cursor = cleaned
        while (cursor.isNotEmpty()) {
            addCandidate(cursor)
            val dashIndex = cursor.lastIndexOf('-')
            if (dashIndex <= 0) break
            cursor = cursor.substring(0, dashIndex)
        }

        addCandidate(DEFAULT_FALLBACK_TAG)
        return chain
    }

    /**
     * Resolves [requestedTag] against [SupportedLanguageCatalog] using the `exact -> base -> "en"`
     * fallback chain and returns the matched [LanguageEntry], or `null` if the catalog is empty.
     */
    suspend fun resolveCatalogLanguage(requestedTag: String): LanguageEntry? {
        val allEntries = catalog.allLanguages()
        val byNormalizedTag = LinkedHashMap<String, LanguageEntry>(allEntries.size)
        for (entry in allEntries) {
            byNormalizedTag[normalizeLookupKey(entry.bcp47Tag)] = entry
        }

        for (candidate in buildFallbackChain(requestedTag)) {
            val exactMatch = byNormalizedTag[normalizeLookupKey(candidate)]
            if (exactMatch != null) {
                return exactMatch
            }
            val catalogMatch = catalog.findByTag(candidate)
            if (catalogMatch != null &&
                normalizeLookupKey(catalogMatch.bcp47Tag) == normalizeLookupKey(candidate)
            ) {
                return catalogMatch
            }
        }
        return catalog.findByTag(DEFAULT_FALLBACK_TAG)
    }

    /**
     * Resolves [requestedTag] through the `exact -> base -> "en"` fallback chain against
     * [SupportedLanguageCatalog] and returns the canonical supported BCP-47 tag.
     */
    suspend fun resolveSupportedLocaleTag(requestedTag: String): String {
        return resolveCatalogLanguage(requestedTag)?.bcp47Tag ?: DEFAULT_FALLBACK_TAG
    }

    /**
     * Resolves the best available UI translation (`hasLayerUTranslation == true`) for
     * [requestedTag] following the `exact -> base -> "en"` fallback chain (PLAN.md Section 6.1.1).
     */
    suspend fun resolveUiTranslationLocaleTag(requestedTag: String): String {
        val allEntries = catalog.allLanguages()
        val byNormalizedTag = LinkedHashMap<String, LanguageEntry>(allEntries.size)
        for (entry in allEntries) {
            byNormalizedTag[normalizeLookupKey(entry.bcp47Tag)] = entry
        }

        for (candidate in buildFallbackChain(requestedTag)) {
            val entry = byNormalizedTag[normalizeLookupKey(candidate)]
                ?: catalog.findByTag(candidate)?.takeIf {
                    normalizeLookupKey(it.bcp47Tag) == normalizeLookupKey(candidate)
                }
            if (entry != null && entry.hasLayerUTranslation) {
                return entry.bcp47Tag
            }
        }
        return DEFAULT_FALLBACK_TAG
    }

    /**
     * Resolves [requestedTag] via `exact -> base -> "en"`, persists it through [PlatformLocaleBridge],
     * updates [activeLocaleTagFlow], and returns the resolved BCP-47 tag.
     */
    suspend fun setApplicationLocale(requestedTag: String): String = mutex.withLock {
        val resolvedTag = resolveSupportedLocaleTag(requestedTag)
        platformBridge.setApplicationLocaleTag(resolvedTag)
        _activeLocaleTagFlow.value = resolvedTag
        resolvedTag
    }

    /**
     * Synchronizes [activeLocaleTagFlow] from [PlatformLocaleBridge] (per-app locale if set,
     * otherwise system default locale) resolved through [SupportedLanguageCatalog].
     */
    suspend fun syncFromPlatform(): String = mutex.withLock {
        val rawPlatformTag = platformBridge.getApplicationLocaleTag()
            ?.takeIf { it.isNotBlank() }
            ?: platformBridge.getSystemDefaultLocaleTag()
        val resolvedTag = resolveSupportedLocaleTag(rawPlatformTag)
        _activeLocaleTagFlow.value = resolvedTag
        resolvedTag
    }

    /**
     * Returns all Gemma 4 languages from [SupportedLanguageCatalog] for the in-app language picker.
     */
    suspend fun availableLanguages(): List<LanguageEntry> {
        return catalog.allLanguages()
    }

    /**
     * Returns true when the currently active locale uses a Right-to-Left script, derived from
     * [SupportedLanguageCatalog] and Unicode script directionality with zero hardcoded language lists.
     */
    suspend fun isCurrentLocaleRtl(): Boolean {
        val currentTag = _activeLocaleTagFlow.value
        val entry = resolveCatalogLanguage(currentTag)
        return entry?.isRtl ?: BidiTextFormatter.isRtlLocale(Locale.forLanguageTag(currentTag))
    }

    private fun resolveInitialTagSnapshot(explicitInitialTag: String?): String {
        val candidate = explicitInitialTag?.takeIf { it.isNotBlank() }
            ?: platformBridge.getApplicationLocaleTag()?.takeIf { it.isNotBlank() }
            ?: platformBridge.getSystemDefaultLocaleTag()
        val cleaned = sanitizeTag(candidate)
        return cleaned.ifEmpty { DEFAULT_FALLBACK_TAG }
    }

    companion object {
        const val DEFAULT_FALLBACK_TAG: String = "en"

        private val SAFE_BCP47_REGEX: Regex =
            Regex("^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{1,8})*$")

        internal fun sanitizeTag(rawTag: String?): String {
            if (rawTag.isNullOrBlank()) return ""
            val stripped = Gemma4InputSanitizer.stripInvisibleControls(rawTag)
                .trim()
                .replace('_', '-')
            if (stripped.isEmpty() || stripped.equals("und", ignoreCase = true)) {
                return ""
            }
            if (!SAFE_BCP47_REGEX.matches(stripped)) {
                return ""
            }
            return stripped
        }

        private fun normalizeLookupKey(tag: String): String {
            return tag.trim().replace('_', '-').lowercase(Locale.US)
        }
    }
}

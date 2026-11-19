package com.nava.core.ai.locale

import com.nava.core.ai.json.JsonValue
import com.nava.core.ai.json.SimpleJsonParser
import com.nava.domain.locale.LanguageEntry
import com.nava.domain.locale.QualityTier
import com.nava.domain.locale.ScriptFamily
import com.nava.domain.locale.SupportedLanguageCatalog
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.Locale

/**
 * Data-driven [SupportedLanguageCatalog] loaded from `assets/locale/catalog.json`
 * (PLAN.md Section 6.1, Iron Law 1: zero hardcoded language lists in code).
 */
class AssetSupportedLanguageCatalog(
    private val assetReader: AssetTextReader,
    private val catalogPath: String = DEFAULT_CATALOG_PATH
) : SupportedLanguageCatalog {

    private data class LoadedCatalog(
        val entries: List<LanguageEntry>,
        val byTag: Map<String, LanguageEntry>,
        val keywordsByTag: Map<String, Set<String>>
    )

    private val loadMutex = Mutex()
    @Volatile
    private var cached: LoadedCatalog? = null

    override suspend fun allLanguages(): List<LanguageEntry> {
        return ensureLoaded().entries
    }

    override suspend fun findByTag(bcp47Tag: String): LanguageEntry? {
        val catalog = ensureLoaded()
        var candidate = canonicalizeTag(bcp47Tag)
        if (candidate.isEmpty()) return null
        while (candidate.isNotEmpty()) {
            catalog.byTag[candidate]?.let { return it }
            val sepIdx = candidate.lastIndexOf('-')
            if (sepIdx <= 0) break
            candidate = candidate.substring(0, sepIdx)
        }
        return null
    }

    override suspend fun isSupported(bcp47Tag: String): Boolean {
        return findByTag(bcp47Tag) != null
    }

    /**
     * Exposes data-driven script disambiguation keywords parsed from `catalog.json`
     * (`scriptKeywords` array per language entry).
     */
    suspend fun keywordsByLanguage(): Map<String, Set<String>> {
        return ensureLoaded().keywordsByTag
    }

    private suspend fun ensureLoaded(): LoadedCatalog {
        cached?.let { return it }
        return loadMutex.withLock {
            cached?.let { return@withLock it }
            val parsed = loadFromAssets()
            cached = parsed
            parsed
        }
    }

    private fun loadFromAssets(): LoadedCatalog {
        val rawJson = assetReader.readText(catalogPath)
            ?: return LoadedCatalog(emptyList(), emptyMap(), emptyMap())

        val root = SimpleJsonParser.parse(rawJson).asObject()
        val languagesArray = root["languages"]?.asArray() ?: emptyList()

        val entries = ArrayList<LanguageEntry>(languagesArray.size)
        val byTag = LinkedHashMap<String, LanguageEntry>(languagesArray.size)
        val keywordsByTag = LinkedHashMap<String, Set<String>>()

        for (item in languagesArray) {
            val obj = item.asObject()
            val bcp47Tag = obj["bcp47Tag"]?.asString()?.trim().orEmpty()
            val englishName = obj["englishName"]?.asString()?.trim().orEmpty()
            if (bcp47Tag.isEmpty() || englishName.isEmpty()) continue

            val nativeName = obj["nativeName"]?.asString()?.trim().orEmpty().ifEmpty { englishName }
            val scriptFamily = parseScriptFamily(obj["scriptFamily"]?.asString())
            val isRtl = obj["isRtl"]?.asBoolean() ?: false
            val qualityTier = parseQualityTier(obj["qualityTier"]?.asString())
            val hasLayerRPack = obj["hasLayerRPack"]?.asBoolean() ?: false
            val hasLayerUTranslation = obj["hasLayerUTranslation"]?.asBoolean() ?: false

            val entry = LanguageEntry(
                bcp47Tag = bcp47Tag,
                englishName = englishName,
                nativeName = nativeName,
                scriptFamily = scriptFamily,
                isRtl = isRtl,
                qualityTier = qualityTier,
                hasLayerRPack = hasLayerRPack,
                hasLayerUTranslation = hasLayerUTranslation
            )
            entries.add(entry)

            val key = canonicalizeTag(bcp47Tag)
            byTag[key] = entry

            val rawKeywords = (obj["scriptKeywords"] as? JsonValue.JsonArray)?.elements
            if (!rawKeywords.isNullOrEmpty()) {
                val kwSet = LinkedHashSet<String>(rawKeywords.size)
                val locale = Locale.forLanguageTag(bcp47Tag)
                for (kwVal in rawKeywords) {
                    val kw = kwVal.asString().trim().lowercase(locale)
                    if (kw.isNotEmpty()) {
                        kwSet.add(kw)
                    }
                }
                if (kwSet.isNotEmpty()) {
                    keywordsByTag[key] = kwSet
                }
            }
        }

        return LoadedCatalog(
            entries = entries,
            byTag = byTag,
            keywordsByTag = keywordsByTag
        )
    }

    private fun parseScriptFamily(raw: String?): ScriptFamily {
        if (raw.isNullOrBlank()) return ScriptFamily.OTHER
        val normalized = raw.trim().uppercase(Locale.US)
        return ScriptFamily.entries.firstOrNull { it.name == normalized } ?: ScriptFamily.OTHER
    }

    private fun parseQualityTier(raw: String?): QualityTier {
        if (raw.isNullOrBlank()) return QualityTier.STANDARD
        val normalized = raw.trim().uppercase(Locale.US)
        return QualityTier.entries.firstOrNull { it.name == normalized } ?: QualityTier.STANDARD
    }

    private fun canonicalizeTag(tag: String): String {
        return tag.trim().replace('_', '-').lowercase(Locale.US)
    }

    companion object {
        const val DEFAULT_CATALOG_PATH: String = "locale/catalog.json"
    }
}

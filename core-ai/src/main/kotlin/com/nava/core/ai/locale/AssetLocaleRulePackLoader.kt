package com.nava.core.ai.locale

import com.nava.core.ai.json.JsonValue
import com.nava.core.ai.json.SimpleJsonParser
import com.nava.domain.locale.LocaleRulePack
import com.nava.domain.locale.LocaleRulePackLoader
import com.nava.domain.locale.RuleMatchPattern
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.Locale

/**
 * Data-driven [LocaleRulePackLoader] reading declarative Layer R packs from
 * `assets/locale/<lang>/rules.json` with BCP-47 subtag fallback (`tr-TR` -> `tr`)
 * and thread-safe caching (PLAN.md Sections 6.1 and 6.3).
 */
class AssetLocaleRulePackLoader(
    private val assetReader: AssetTextReader,
    private val localeRootDir: String = DEFAULT_LOCALE_ROOT
) : LocaleRulePackLoader {

    private data class CacheSlot(val pack: LocaleRulePack?)

    private val cacheMutex = Mutex()
    private val packCache = LinkedHashMap<String, CacheSlot>()
    @Volatile
    private var cachedAvailableTags: Set<String>? = null

    override suspend fun loadRulePack(languageTag: String): LocaleRulePack? {
        val canonical = canonicalizeTag(languageTag)
        if (canonical.isEmpty() || !SAFE_TAG_REGEX.matches(canonical)) {
            return null
        }

        return cacheMutex.withLock {
            packCache[canonical]?.let { return@withLock it.pack }

            var candidate = canonical
            var loaded: LocaleRulePack? = null
            while (candidate.isNotEmpty()) {
                val cachedCandidate = packCache[candidate]
                if (cachedCandidate != null) {
                    loaded = cachedCandidate.pack
                    if (loaded != null) break
                } else {
                    val path = "$localeRootDir/$candidate/$RULES_FILE_NAME"
                    val rawJson = assetReader.readText(path)
                    if (rawJson != null) {
                        loaded = parseRulePack(rawJson)
                        packCache[candidate] = CacheSlot(loaded)
                        break
                    } else {
                        packCache[candidate] = CacheSlot(null)
                    }
                }
                val sepIdx = candidate.lastIndexOf('-')
                if (sepIdx <= 0) break
                candidate = candidate.substring(0, sepIdx)
            }

            packCache[canonical] = CacheSlot(loaded)
            loaded
        }
    }

    override suspend fun availableLanguageTags(): Set<String> {
        cachedAvailableTags?.let { return it }
        return cacheMutex.withLock {
            cachedAvailableTags?.let { return@withLock it }
            val tags = LinkedHashSet<String>()
            for (child in assetReader.listChildren(localeRootDir)) {
                val normalized = canonicalizeTag(child)
                if (normalized.isEmpty() || !SAFE_TAG_REGEX.matches(normalized)) continue
                val rulesPath = "$localeRootDir/$child/$RULES_FILE_NAME"
                if (assetReader.readText(rulesPath) != null) {
                    tags.add(normalized)
                }
            }
            val snapshot = tags.toSet()
            cachedAvailableTags = snapshot
            snapshot
        }
    }

    private fun parseRulePack(rawJson: String): LocaleRulePack {
        val root = SimpleJsonParser.parse(rawJson).asObject()
        val languageTag = root["languageTag"]?.asString()?.trim()
            ?: throw IllegalArgumentException("Rule pack missing 'languageTag'")
        val version = root["version"]?.asInt()
            ?: throw IllegalArgumentException("Rule pack missing 'version'")

        val timeKeywords = parseStringMap(root["timeKeywords"])
        val rawPatterns = root["patterns"]?.asArray() ?: emptyList()
        val patterns = ArrayList<RuleMatchPattern>(rawPatterns.size)

        for (item in rawPatterns) {
            val obj = item.asObject()
            val patternId = obj["patternId"]?.asString()?.trim()
                ?: throw IllegalArgumentException("Rule pattern missing 'patternId'")
            val toolName = obj["toolName"]?.asString()?.trim()
                ?: throw IllegalArgumentException("Rule pattern '$patternId' missing 'toolName'")
            val regexPattern = obj["regexPattern"]?.asString()
                ?: throw IllegalArgumentException("Rule pattern '$patternId' missing 'regexPattern'")
            val slotMappings = parseStringMap(obj["slotMappings"])
            val staticSlots = parseStringMap(obj["staticSlots"])
            val priority = obj["priority"]?.asInt() ?: DEFAULT_PATTERN_PRIORITY

            patterns.add(
                RuleMatchPattern(
                    patternId = patternId,
                    toolName = toolName,
                    regexPattern = regexPattern,
                    slotMappings = slotMappings,
                    staticSlots = staticSlots,
                    priority = priority
                )
            )
        }

        return LocaleRulePack(
            languageTag = languageTag,
            version = version,
            patterns = patterns,
            timeKeywords = timeKeywords
        )
    }

    private fun parseStringMap(value: JsonValue?): Map<String, String> {
        if (value == null || value is JsonValue.JsonNull) return emptyMap()
        val entries = value.asObject()
        if (entries.isEmpty()) return emptyMap()
        val out = LinkedHashMap<String, String>(entries.size)
        for ((k, v) in entries) {
            out[k] = when (v) {
                is JsonValue.JsonString -> v.value
                is JsonValue.JsonNumber -> v.raw
                is JsonValue.JsonBoolean -> v.value.toString()
                else -> throw IllegalArgumentException("Expected primitive string/number/boolean for key '$k'")
            }
        }
        return out
    }

    private fun canonicalizeTag(tag: String): String {
        return tag.trim().replace('_', '-').lowercase(Locale.US)
    }

    companion object {
        const val DEFAULT_LOCALE_ROOT: String = "locale"
        const val RULES_FILE_NAME: String = "rules.json"
        private const val DEFAULT_PATTERN_PRIORITY: Int = 100
        private val SAFE_TAG_REGEX: Regex = Regex("^[a-z0-9]+(?:-[a-z0-9]+)*$")
    }
}

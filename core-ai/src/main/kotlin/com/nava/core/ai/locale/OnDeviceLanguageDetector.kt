package com.nava.core.ai.locale

import android.content.Context
import android.view.textclassifier.TextClassificationManager
import android.view.textclassifier.TextLanguage
import com.nava.domain.locale.DetectedLanguage
import com.nava.domain.locale.GenericTextNormalizer
import com.nava.domain.locale.LanguageDetector
import com.nava.domain.locale.LanguageEntry
import com.nava.domain.locale.ScriptFamily
import com.nava.domain.security.Gemma4InputSanitizer
import java.text.Normalizer
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

/**
 * Optional platform language classifier port (for example, Android API 31+ `TextClassifier`)
 * decoupled for pure JVM unit testing. Must never perform network requests.
 */
interface PlatformLanguageClassifier {
    data class LanguageCandidate(
        val bcp47Tag: String,
        val confidence: Float
    )

    suspend fun classify(text: String): List<LanguageCandidate>
}

/**
 * On-device Android API 31+ [PlatformLanguageClassifier] using [TextClassificationManager].
 */
class AndroidTextClassifierAdapter(
    private val context: Context
) : PlatformLanguageClassifier {

    override suspend fun classify(text: String): List<PlatformLanguageClassifier.LanguageCandidate> {
        if (text.isBlank()) return emptyList()
        return runCatching {
            val manager = context.getSystemService(TextClassificationManager::class.java)
                ?: return emptyList()
            val classifier = manager.textClassifier
            val request = TextLanguage.Request.Builder(text).build()
            val detected = classifier.detectLanguage(request)
            val count = detected.localeHypothesisCount
            val out = ArrayList<PlatformLanguageClassifier.LanguageCandidate>(count)
            for (i in 0 until count) {
                val uLocale = detected.getLocale(i)
                val tag = uLocale.toLanguageTag()
                val score = detected.getConfidenceScore(uLocale).coerceIn(0.0f, 1.0f)
                if (tag.isNotBlank() && !tag.equals("und", ignoreCase = true)) {
                    out.add(
                        PlatformLanguageClassifier.LanguageCandidate(
                            bcp47Tag = tag,
                            confidence = score
                        )
                    )
                }
            }
            out
        }.getOrDefault(emptyList())
    }
}

/**
 * 100% offline, data-driven [LanguageDetector] combining:
 * 1. App locale prior (`appLocaleTag`),
 * 2. Unicode script histogram across all 12 [ScriptFamily] values,
 * 3. Optional on-device [PlatformLanguageClassifier],
 * 4. Catalog-driven keyword sets from [AssetSupportedLanguageCatalog.keywordsByLanguage].
 *
 * Zero hardcoded language lists or `if (lang == ...)` branches; zero security decisions depend
 * on language detection (PLAN.md Section 6.2, Iron Law 1).
 */
class OnDeviceLanguageDetector(
    private val catalog: AssetSupportedLanguageCatalog,
    private val platformClassifier: PlatformLanguageClassifier? = null,
    private val textNormalizer: GenericTextNormalizer = GenericTextNormalizer(SeedLocaleNormalizers.createRegistry())
) : LanguageDetector {

    private data class NormalizedKeyword(
        val raw: String,
        val folded: String,
        val matchKey: String,
        val isSpaceLess: Boolean
    )

    private val normalizedKeywordCache = ConcurrentHashMap<String, List<NormalizedKeyword>>()

    override suspend fun detect(utterance: String, appLocaleTag: String): DetectedLanguage {
        val cleaned = Gemma4InputSanitizer.stripInvisibleControls(
            Normalizer.normalize(utterance, Normalizer.Form.NFKC)
        ).trim()

        val allEntries = catalog.allLanguages()
        val keywordsByTag = catalog.keywordsByLanguage()
        val appEntry = catalog.findByTag(appLocaleTag)
        val fallbackTag = appEntry?.bcp47Tag ?: canonicalBaseTag(appLocaleTag)
        val fallbackScript = appEntry?.scriptFamily ?: ScriptFamily.OTHER

        val histogram = buildScriptHistogram(cleaned)
        if (histogram.totalLetters == 0) {
            return DetectedLanguage(
                bcp47Tag = fallbackTag,
                confidence = AMBIGUOUS_FALLBACK_CONFIDENCE,
                scriptFamily = fallbackScript,
                isAmbiguous = true
            )
        }

        val dominantScript = histogram.dominantScript
        val isMultiScriptClose = histogram.secondScriptRatio >= MULTI_SCRIPT_AMBIGUITY_RATIO
        val letterTokens = extractLetterTokens(cleaned)
        val isShortUtterance = if (dominantScript.isSpaceLessScript) {
            histogram.dominantScriptCount < MIN_SPACELESS_LETTERS
        } else {
            letterTokens.size < MIN_LETTER_TOKENS
        }

        val scriptCandidates = allEntries.filter { it.scriptFamily == dominantScript }

        if (isShortUtterance || isMultiScriptClose) {
            return DetectedLanguage(
                bcp47Tag = fallbackTag,
                confidence = AMBIGUOUS_FALLBACK_CONFIDENCE,
                scriptFamily = appEntry?.scriptFamily ?: dominantScript,
                isAmbiguous = true
            )
        }

        if (scriptCandidates.isEmpty()) {
            return DetectedLanguage(
                bcp47Tag = fallbackTag,
                confidence = AMBIGUOUS_FALLBACK_CONFIDENCE,
                scriptFamily = dominantScript,
                isAmbiguous = true
            )
        }

        if (scriptCandidates.size == 1) {
            val sole = scriptCandidates.first()
            return DetectedLanguage(
                bcp47Tag = sole.bcp47Tag,
                confidence = SINGLE_SCRIPT_CONFIDENCE,
                scriptFamily = dominantScript,
                isAmbiguous = false
            )
        }

        val classifierScores = scorePlatformCandidates(cleaned, dominantScript, allEntries)
        val appBaseTag = canonicalBaseTag(appLocaleTag)
        val scored = ArrayList<Pair<LanguageEntry, Float>>(scriptCandidates.size)

        for (entry in scriptCandidates) {
            val entryKey = canonicalTag(entry.bcp47Tag)
            val entryBase = canonicalBaseTag(entry.bcp47Tag)
            var score = 0.0f

            if (entryBase == appBaseTag) {
                score += APP_LOCALE_PRIOR_WEIGHT
            }

            val platformConf = classifierScores[entryKey] ?: classifierScores[entryBase] ?: 0.0f
            score += platformConf * PLATFORM_CLASSIFIER_WEIGHT

            val keywords = keywordsByTag[entryKey]
            if (!keywords.isNullOrEmpty()) {
                val keywordScore = scoreKeywords(cleaned, entry.bcp47Tag, entryKey, keywords)
                score += keywordScore
            }

            scored.add(entry to score)
        }

        scored.sortWith(
            compareByDescending<Pair<LanguageEntry, Float>> { it.second }
                .thenByDescending { canonicalBaseTag(it.first.bcp47Tag) == appBaseTag }
                .thenBy { it.first.bcp47Tag }
        )

        val best = scored.first()
        val runnerUpScore = if (scored.size > 1) scored[1].second else 0.0f
        val margin = best.second - runnerUpScore
        val noStrongSignal = best.second <= APP_LOCALE_PRIOR_WEIGHT + 0.01f &&
            classifierScores.isEmpty()

        val ambiguous = (margin < AMBIGUOUS_SCORE_MARGIN && best.second < CONFIDENT_THRESHOLD) ||
            (noStrongSignal && appEntry?.scriptFamily != dominantScript)

        if (ambiguous && appEntry != null && appEntry.scriptFamily == dominantScript && margin < AMBIGUOUS_SCORE_MARGIN) {
            return DetectedLanguage(
                bcp47Tag = appEntry.bcp47Tag,
                confidence = best.second.coerceIn(0.25f, 0.65f),
                scriptFamily = appEntry.scriptFamily,
                isAmbiguous = true
            )
        }

        val calibratedConfidence = best.second.coerceIn(0.20f, 0.99f)
        return DetectedLanguage(
            bcp47Tag = best.first.bcp47Tag,
            confidence = calibratedConfidence,
            scriptFamily = best.first.scriptFamily,
            isAmbiguous = ambiguous
        )
    }

    private suspend fun scorePlatformCandidates(
        cleaned: String,
        dominantScript: ScriptFamily,
        allEntries: List<LanguageEntry>
    ): Map<String, Float> {
        val classifier = platformClassifier ?: return emptyMap()
        val predictions = runCatching { classifier.classify(cleaned) }.getOrDefault(emptyList())
        if (predictions.isEmpty()) return emptyMap()

        val allowedTags = allEntries
            .filter { it.scriptFamily == dominantScript }
            .flatMap { listOf(canonicalTag(it.bcp47Tag), canonicalBaseTag(it.bcp47Tag)) }
            .toSet()

        val map = LinkedHashMap<String, Float>()
        for (pred in predictions) {
            val tag = canonicalTag(pred.bcp47Tag)
            val base = canonicalBaseTag(pred.bcp47Tag)
            if (tag in allowedTags || base in allowedTags) {
                val existing = map[tag] ?: 0.0f
                if (pred.confidence > existing) {
                    map[tag] = pred.confidence
                }
                val existingBase = map[base] ?: 0.0f
                if (pred.confidence > existingBase) {
                    map[base] = pred.confidence
                }
            }
        }
        return map
    }

    private fun scoreKeywords(
        cleaned: String,
        languageTag: String,
        cacheKey: String,
        keywords: Set<String>
    ): Float {
        val normalized = textNormalizer.normalize(cleaned, languageTag)
        val tokenSet = LinkedHashSet<String>()
        tokenSet.addAll(normalized.tokens)
        for (tok in TOKEN_SPLIT_REGEX.split(normalized.folded)) {
            if (tok.isNotEmpty()) tokenSet.add(tok)
        }
        for (tok in TOKEN_SPLIT_REGEX.split(normalized.matchKey)) {
            if (tok.isNotEmpty()) tokenSet.add(tok)
        }
        if (tokenSet.isEmpty()) return 0.0f

        val normalizedKeywords = getOrNormalizeKeywords(cacheKey, languageTag, keywords)
        var hits = 0
        for (kw in normalizedKeywords) {
            val matched = kw.raw in tokenSet ||
                kw.folded in tokenSet ||
                kw.matchKey in tokenSet ||
                (kw.isSpaceLess && kw.matchKey.length >= 2 && normalized.matchKey.contains(kw.matchKey))
            if (matched) {
                hits++
            }
        }
        if (hits == 0) return 0.0f
        val hitRatio = (hits.toFloat() / tokenSet.size.coerceAtLeast(1).toFloat()).coerceAtMost(1.0f)
        return ((hits * KEYWORD_HIT_WEIGHT) + (hitRatio * KEYWORD_RATIO_WEIGHT)).coerceAtMost(MAX_KEYWORD_SCORE)
    }

    private fun getOrNormalizeKeywords(
        cacheKey: String,
        languageTag: String,
        rawKeywords: Set<String>
    ): List<NormalizedKeyword> {
        return normalizedKeywordCache.computeIfAbsent(cacheKey) {
            rawKeywords.map { kw ->
                val normalizedKw = textNormalizer.normalize(kw, languageTag)
                val spaceLess = normalizedKw.matchKey.isNotEmpty() &&
                    mapUnicodeScript(Character.UnicodeScript.of(normalizedKw.matchKey.codePointAt(0))).isSpaceLessScript
                NormalizedKeyword(
                    raw = kw,
                    folded = normalizedKw.folded,
                    matchKey = normalizedKw.matchKey,
                    isSpaceLess = spaceLess
                )
            }
        }
    }

    private data class ScriptHistogram(
        val totalLetters: Int,
        val dominantScript: ScriptFamily,
        val dominantScriptCount: Int,
        val secondScriptRatio: Float
    )

    private fun buildScriptHistogram(text: String): ScriptHistogram {
        val counts = IntArray(ScriptFamily.entries.size)
        var totalLetters = 0
        var index = 0
        while (index < text.length) {
            val cp = text.codePointAt(index)
            if (Character.isLetter(cp)) {
                val script = mapUnicodeScript(Character.UnicodeScript.of(cp))
                counts[script.ordinal]++
                totalLetters++
            }
            index += Character.charCount(cp)
        }

        if (totalLetters == 0) {
            return ScriptHistogram(
                totalLetters = 0,
                dominantScript = ScriptFamily.OTHER,
                dominantScriptCount = 0,
                secondScriptRatio = 0.0f
            )
        }

        var bestOrdinal = ScriptFamily.OTHER.ordinal
        var bestCount = -1
        var secondCount = 0
        for (i in counts.indices) {
            val c = counts[i]
            if (c > bestCount) {
                secondCount = bestCount.coerceAtLeast(0)
                bestCount = c
                bestOrdinal = i
            } else if (c > secondCount) {
                secondCount = c
            }
        }

        return ScriptHistogram(
            totalLetters = totalLetters,
            dominantScript = ScriptFamily.entries[bestOrdinal],
            dominantScriptCount = bestCount,
            secondScriptRatio = secondCount.toFloat() / totalLetters.toFloat()
        )
    }

    private fun mapUnicodeScript(unicodeScript: Character.UnicodeScript): ScriptFamily {
        return when (unicodeScript) {
            Character.UnicodeScript.LATIN -> ScriptFamily.LATIN
            Character.UnicodeScript.CYRILLIC -> ScriptFamily.CYRILLIC
            Character.UnicodeScript.GREEK -> ScriptFamily.GREEK
            Character.UnicodeScript.ARABIC -> ScriptFamily.ARABIC
            Character.UnicodeScript.HEBREW -> ScriptFamily.HEBREW
            Character.UnicodeScript.DEVANAGARI -> ScriptFamily.DEVANAGARI
            Character.UnicodeScript.BENGALI,
            Character.UnicodeScript.GURMUKHI,
            Character.UnicodeScript.GUJARATI,
            Character.UnicodeScript.ORIYA,
            Character.UnicodeScript.TAMIL,
            Character.UnicodeScript.TELUGU,
            Character.UnicodeScript.KANNADA,
            Character.UnicodeScript.MALAYALAM,
            Character.UnicodeScript.SINHALA -> ScriptFamily.INDIC_OTHER

            Character.UnicodeScript.THAI -> ScriptFamily.THAI
            Character.UnicodeScript.KHMER,
            Character.UnicodeScript.LAO -> ScriptFamily.KHMER_LAO

            Character.UnicodeScript.HAN,
            Character.UnicodeScript.HIRAGANA,
            Character.UnicodeScript.KATAKANA,
            Character.UnicodeScript.BOPOMOFO -> ScriptFamily.CJK

            Character.UnicodeScript.HANGUL -> ScriptFamily.HANGUL
            else -> ScriptFamily.OTHER
        }
    }

    private fun extractLetterTokens(text: String): List<String> {
        val out = ArrayList<String>()
        for (part in TOKEN_SPLIT_REGEX.split(text)) {
            if (part.isNotEmpty() && containsLetter(part)) {
                out.add(part)
            }
        }
        return out
    }

    private fun containsLetter(segment: String): Boolean {
        var i = 0
        while (i < segment.length) {
            val cp = segment.codePointAt(i)
            if (Character.isLetter(cp)) return true
            i += Character.charCount(cp)
        }
        return false
    }

    private fun canonicalTag(tag: String): String {
        return tag.trim().replace('_', '-').lowercase(Locale.US)
    }

    private fun canonicalBaseTag(tag: String): String {
        val clean = canonicalTag(tag)
        if (clean.isEmpty() || clean == "und") return "en"
        return clean.substringBefore('-')
    }

    companion object {
        private const val MIN_LETTER_TOKENS: Int = 2
        private const val MIN_SPACELESS_LETTERS: Int = 2
        private const val MULTI_SCRIPT_AMBIGUITY_RATIO: Float = 0.35f
        private const val AMBIGUOUS_FALLBACK_CONFIDENCE: Float = 0.35f
        private const val SINGLE_SCRIPT_CONFIDENCE: Float = 0.92f
        private const val APP_LOCALE_PRIOR_WEIGHT: Float = 0.25f
        private const val PLATFORM_CLASSIFIER_WEIGHT: Float = 0.65f
        private const val KEYWORD_HIT_WEIGHT: Float = 0.32f
        private const val KEYWORD_RATIO_WEIGHT: Float = 0.25f
        private const val MAX_KEYWORD_SCORE: Float = 0.85f
        private const val AMBIGUOUS_SCORE_MARGIN: Float = 0.12f
        private const val CONFIDENT_THRESHOLD: Float = 0.55f

        private val TOKEN_SPLIT_REGEX: Regex = Regex("[^\\p{L}\\p{Nd}]+")
    }
}

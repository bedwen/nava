package com.nava.domain.locale

import com.nava.domain.security.Gemma4InputSanitizer
import java.text.BreakIterator
import java.text.Normalizer
import java.util.Locale

/**
 * Pure Kotlin multilingual normalization pipeline applied uniformly to every language:
 * 1. Unicode NFKC normalization.
 * 2. Zero-width and bidi control stripping.
 * 3. Locale-correct case folding via `Locale.forLanguageTag` (never `Locale.ROOT`).
 * 4. Unicode decimal-digit unification across all `Nd` scripts via `Character.digit(cp, 10)`.
 * 5. Script-aware diacritic stripping for match keys ONLY on Latin, Greek, and Cyrillic.
 * 6. Optional [LocaleNormalizerStrategy] dispatch via [LocaleNormalizerRegistry].
 * 7. Word segmentation via `java.text.BreakIterator` (supporting space-less scripts).
 */
class GenericTextNormalizer(
    private val registry: LocaleNormalizerRegistry = LocaleNormalizerRegistry()
) {
    fun normalize(rawText: String, languageTag: String): NormalizedText {
        val effectiveTag = resolveEffectiveTag(languageTag)
        val locale = Locale.forLanguageTag(effectiveTag)

        val nfkc = Normalizer.normalize(rawText, Normalizer.Form.NFKC)
        val strippedControls = Gemma4InputSanitizer.stripInvisibleControls(nfkc)
        val caseFolded = strippedControls.lowercase(locale)
        val unifiedDigits = unifyUnicodeDecimalDigits(caseFolded)
        val collapsedFolded = collapseWhitespace(unifiedDigits)

        val strategy = registry.findForLanguage(effectiveTag)
        val finalFolded = collapseWhitespace(
            strategy?.normalizeFolded(collapsedFolded, effectiveTag) ?: collapsedFolded
        )

        val diacriticStripped = stripOptionalScriptDiacritics(finalFolded)
        val strategyMatchKey = strategy?.normalizeMatchKey(diacriticStripped, effectiveTag)
            ?: diacriticStripped
        val finalMatchKey = collapseWhitespace(strategyMatchKey)

        val tokens = segmentWords(finalMatchKey, locale)
        return NormalizedText(
            original = rawText,
            languageTag = effectiveTag,
            folded = finalFolded,
            matchKey = finalMatchKey,
            tokens = tokens
        )
    }

    private fun resolveEffectiveTag(languageTag: String): String {
        val trimmed = languageTag.trim().replace('_', '-')
        if (trimmed.isEmpty() || trimmed.equals("und", ignoreCase = true)) {
            return FALLBACK_LANGUAGE_TAG
        }
        val parsed = Locale.forLanguageTag(trimmed)
        return if (parsed.language.isNullOrBlank()) FALLBACK_LANGUAGE_TAG else trimmed
    }

    private fun unifyUnicodeDecimalDigits(input: String): String {
        if (input.isEmpty()) return input
        val sb = StringBuilder(input.length)
        var index = 0
        while (index < input.length) {
            val cp = input.codePointAt(index)
            if (Character.getType(cp) == Character.DECIMAL_DIGIT_NUMBER.toInt()) {
                val digit = Character.digit(cp, 10)
                if (digit in 0..9) {
                    sb.append(('0'.code + digit).toChar())
                } else {
                    sb.appendCodePoint(cp)
                }
            } else {
                sb.appendCodePoint(cp)
            }
            index += Character.charCount(cp)
        }
        return sb.toString()
    }

    private fun stripOptionalScriptDiacritics(input: String): String {
        if (input.isEmpty()) return input
        val nfd = Normalizer.normalize(input, Normalizer.Form.NFD)
        val sb = StringBuilder(nfd.length)
        var lastBaseScript: Character.UnicodeScript? = null
        var index = 0
        while (index < nfd.length) {
            val cp = nfd.codePointAt(index)
            val charType = Character.getType(cp)
            val isNonSpacingMark = charType == Character.NON_SPACING_MARK.toInt()
            val isAnyCombiningMark = isNonSpacingMark ||
                charType == Character.COMBINING_SPACING_MARK.toInt() ||
                charType == Character.ENCLOSING_MARK.toInt()
            val markScript = Character.UnicodeScript.of(cp)

            if (
                isNonSpacingMark &&
                lastBaseScript != null &&
                lastBaseScript in STRIPPABLE_SCRIPTS &&
                (markScript == Character.UnicodeScript.INHERITED || markScript == lastBaseScript)
            ) {
                // Omit optional non-spacing mark for Latin, Greek, and Cyrillic base characters.
            } else {
                sb.appendCodePoint(cp)
                if (!isAnyCombiningMark) {
                    lastBaseScript = markScript
                }
            }
            index += Character.charCount(cp)
        }
        return Normalizer.normalize(sb.toString(), Normalizer.Form.NFC)
    }

    private fun segmentWords(text: String, locale: Locale): List<String> {
        if (text.isEmpty()) return emptyList()
        val iterator = BreakIterator.getWordInstance(locale)
        iterator.setText(text)
        val tokens = mutableListOf<String>()
        var start = iterator.first()
        var end = iterator.next()
        while (end != BreakIterator.DONE) {
            val segment = text.substring(start, end).trim()
            if (segment.isNotEmpty() && containsLetterOrDigit(segment)) {
                if (isMultiCodePointPureHan(segment)) {
                    appendCodePointTokens(segment, tokens)
                } else {
                    tokens.add(segment)
                }
            }
            start = end
            end = iterator.next()
        }
        return tokens
    }

    private fun isMultiCodePointPureHan(segment: String): Boolean {
        var index = 0
        var count = 0
        while (index < segment.length) {
            val cp = segment.codePointAt(index)
            if (Character.UnicodeScript.of(cp) != Character.UnicodeScript.HAN) {
                return false
            }
            count++
            index += Character.charCount(cp)
        }
        return count > 1
    }

    private fun appendCodePointTokens(segment: String, target: MutableList<String>) {
        var index = 0
        while (index < segment.length) {
            val cp = segment.codePointAt(index)
            val nextIndex = index + Character.charCount(cp)
            target.add(segment.substring(index, nextIndex))
            index = nextIndex
        }
    }

    private fun containsLetterOrDigit(segment: String): Boolean {
        var index = 0
        while (index < segment.length) {
            val cp = segment.codePointAt(index)
            if (Character.isLetterOrDigit(cp)) {
                return true
            }
            index += Character.charCount(cp)
        }
        return false
    }

    private fun collapseWhitespace(text: String): String {
        if (text.isEmpty()) return text
        return WHITESPACE_REGEX.replace(text.trim(), " ")
    }

    companion object {
        private const val FALLBACK_LANGUAGE_TAG = "en"
        private val WHITESPACE_REGEX = Regex("\\s+")
        private val STRIPPABLE_SCRIPTS = setOf(
            Character.UnicodeScript.LATIN,
            Character.UnicodeScript.GREEK,
            Character.UnicodeScript.CYRILLIC
        )
    }
}

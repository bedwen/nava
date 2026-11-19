package com.nava.core.ai.locale

import com.nava.domain.locale.LocaleNormalizerRegistry
import com.nava.domain.locale.LocaleNormalizerStrategy

/**
 * Seed strategy for Turkish and Azerbaijani match keys, tolerating ASCII-typed user input
 * after [com.nava.domain.locale.GenericTextNormalizer] performs locale-correct dotless-i folding
 * (PLAN.md Section 6.2). Pure ASCII source using `\uXXXX` escapes (Iron Law 1).
 */
class TurkishNormalizerStrategy : LocaleNormalizerStrategy {
    override val languageTags: Set<String> = setOf("tr", "az")

    override fun normalizeMatchKey(text: String, languageTag: String): String {
        if (text.isEmpty()) return text
        val sb = StringBuilder(text.length)
        for (ch in text) {
            when (ch) {
                '\u0131', '\u0130' -> sb.append('i')
                '\u00E7', '\u00C7' -> sb.append('c')
                '\u011F', '\u011E' -> sb.append('g')
                '\u00F6', '\u00D6' -> sb.append('o')
                '\u015F', '\u015E' -> sb.append('s')
                '\u00FC', '\u00DC' -> sb.append('u')
                else -> sb.append(ch)
            }
        }
        return sb.toString()
    }
}

/**
 * Seed strategy for Arabic-script languages (`ar`, `fa`, `ur`) removing tashkeel and tatweel
 * and unifying alef, taa marbuta, yeh, and Persian kaf variants in match keys
 * (PLAN.md Section 6.2).
 */
class ArabicScriptNormalizerStrategy : LocaleNormalizerStrategy {
    override val languageTags: Set<String> = setOf("ar", "fa", "ur")

    override fun normalizeMatchKey(text: String, languageTag: String): String {
        if (text.isEmpty()) return text
        val sb = StringBuilder(text.length)
        for (ch in text) {
            when {
                isTashkeelOrTatweel(ch) -> Unit
                ch == '\u0622' || ch == '\u0623' || ch == '\u0625' || ch == '\u0671' -> sb.append('\u0627')
                ch == '\u0629' -> sb.append('\u0647')
                ch == '\u0649' || ch == '\u06CC' -> sb.append('\u064A')
                ch == '\u06A9' -> sb.append('\u0643')
                else -> sb.append(ch)
            }
        }
        return sb.toString()
    }

    private fun isTashkeelOrTatweel(ch: Char): Boolean {
        return ch == '\u0640' ||
            ch == '\u0670' ||
            ch in '\u064B'..'\u065F' ||
            ch in '\u0610'..'\u061A' ||
            ch in '\u06D6'..'\u06ED'
    }
}

/**
 * Seed strategy for Spanish and French match keys, stripping inverted punctuation (`\u00BF`, `\u00A1`),
 * normalizing curly apostrophes, and stripping common French elision prefixes (`l'`, `d'`, `j'`,
 * `qu'`, `s'`, `n'`, `m'`, `t'`, `c'`) (PLAN.md Section 6.2).
 */
class SpanishFrenchNormalizerStrategy : LocaleNormalizerStrategy {
    override val languageTags: Set<String> = setOf("es", "fr")

    override fun normalizeMatchKey(text: String, languageTag: String): String {
        if (text.isEmpty()) return text
        val sb = StringBuilder(text.length)
        for (ch in text) {
            when (ch) {
                '\u00BF', '\u00A1' -> Unit
                '\u2019', '\u2018', '\u02BC' -> sb.append('\'')
                else -> sb.append(ch)
            }
        }
        return FRENCH_ELISION_REGEX.replace(sb.toString(), "")
    }

    companion object {
        private val FRENCH_ELISION_REGEX: Regex = Regex(
            pattern = """(?<![\p{L}\p{Nd}])(?:qu|[ldjsnmtc])'(?=\p{L})""",
            option = RegexOption.IGNORE_CASE
        )
    }
}

/**
 * Factory assembling the Open/Closed [LocaleNormalizerRegistry] populated with Nava's seed
 * normalization strategies without introducing language conditionals into resolvers.
 */
object SeedLocaleNormalizers {
    fun createRegistry(): LocaleNormalizerRegistry {
        return LocaleNormalizerRegistry(
            initialStrategies = listOf(
                TurkishNormalizerStrategy(),
                ArabicScriptNormalizerStrategy(),
                SpanishFrenchNormalizerStrategy()
            )
        )
    }
}

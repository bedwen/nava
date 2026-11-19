package com.nava.domain.locale

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GenericTextNormalizerTest {

    @Test
    fun `turkish locale folding preserves dotless i and folds dotted capital I cleanly`() {
        val normalizer = GenericTextNormalizer()
        val result = normalizer.normalize("\u0130STANBUL ISIK", "tr-TR")
        assertEquals("\u0069stanbul \u0131s\u0131k", result.folded)
        assertEquals(listOf("istanbul", "\u0131s\u0131k"), result.tokens)

        val englishResult = normalizer.normalize("ISIK", "en-US")
        assertEquals("isik", englishResult.folded)
    }

    @Test
    fun `unicode decimal digits across Arabic-Indic Devanagari and Fullwidth unify to ASCII`() {
        val normalizer = GenericTextNormalizer()
        val arabicDigits = "\u0660\u0667:\u0663\u0660"
        val devanagariDigits = "\u0967\u0968"
        val fullwidthDigits = "\uFF14\uFF15"

        assertEquals("07:30", normalizer.normalize(arabicDigits, "ar").folded)
        assertEquals("12", normalizer.normalize(devanagariDigits, "hi").folded)
        assertEquals("45", normalizer.normalize(fullwidthDigits, "ja").folded)
    }

    @Test
    fun `diacritics strip for Latin Greek Cyrillic match keys but semantic Indic and Thai marks stay intact`() {
        val normalizer = GenericTextNormalizer()

        val french = normalizer.normalize("Caf\u00E9 \u00E0 Paris", "fr")
        assertEquals("caf\u00E9 \u00E0 paris", french.folded)
        assertEquals("cafe a paris", french.matchKey)

        val greek = normalizer.normalize("\u03AC\u03BB\u03B1\u03C2", "el")
        assertEquals("\u03B1\u03BB\u03B1\u03C2", greek.matchKey)

        val cyrillic = normalizer.normalize("\u0439\u043E\u0433\u0443\u0440\u0442", "ru")
        assertEquals("\u0438\u043E\u0433\u0443\u0440\u0442", cyrillic.matchKey)

        // Devanagari vowel sign \u0947 and Thai mai han-akat \u0E31 are semantic and must NOT be stripped.
        val devanagariWord = "\u0915\u0947\u0932\u093E"
        val thaiWord = "\u0E01\u0E31\u0E19"
        assertEquals(devanagariWord, normalizer.normalize(devanagariWord, "hi").matchKey)
        assertEquals(thaiWord, normalizer.normalize(thaiWord, "th").matchKey)
    }

    @Test
    fun `BreakIterator segments space-less CJK and Thai scripts into non-empty word tokens`() {
        val normalizer = GenericTextNormalizer()

        val chinese = normalizer.normalize("\u660E\u5929\u65E9\u4E0A\u4E03\u70B9", "zh-CN")
        assertFalse(chinese.tokens.isEmpty())
        assertTrue(chinese.tokens.size > 1)
        assertEquals(6, chinese.tokens.size)
        assertTrue(chinese.tokens.all { it.isNotBlank() })

        val thai = normalizer.normalize("\u0E15\u0E31\u0E49\u0E07\u0E19\u0E32\u0E2C\u0E34\u0E01\u0E32", "th")
        assertFalse(thai.tokens.isEmpty())
        assertTrue(thai.tokens.all { it.isNotBlank() })
    }

    @Test
    fun `LocaleNormalizerRegistry extends behavior via Open-Closed strategy registration`() {
        val turkishAsciiStrategy = object : LocaleNormalizerStrategy {
            override val languageTags: Set<String> = setOf("tr")

            override fun normalizeMatchKey(text: String, languageTag: String): String {
                return text.replace('\u0131', 'i')
            }
        }
        val registry = LocaleNormalizerRegistry(listOf(turkishAsciiStrategy))
        val normalizer = GenericTextNormalizer(registry)

        val normalized = normalizer.normalize("ALARM KUR \u0130\u015E\u0130K ISIK", "tr-TR")
        assertEquals("alarm kur i\u015Fik \u0131s\u0131k", normalized.folded)
        assertEquals("alarm kur isik isik", normalized.matchKey)
        assertTrue(registry.registeredLanguageTags().contains("tr"))
    }
}

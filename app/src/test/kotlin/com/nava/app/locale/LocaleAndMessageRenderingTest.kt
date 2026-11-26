package com.nava.app.locale

import com.nava.app.di.AppContainer
import com.nava.core.ai.locale.AssetSupportedLanguageCatalog
import com.nava.domain.locale.LanguageEntry
import com.nava.domain.locale.QualityTier
import com.nava.domain.locale.ScriptFamily
import com.nava.domain.locale.SupportedLanguageCatalog
import com.nava.domain.security.DataProvenance
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import java.time.DayOfWeek
import java.time.ZoneId
import java.util.Locale
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LocaleAndMessageRenderingTest {

    @Test
    fun bidiTextFormatterStripsTrojanSourceOverridesBeforeWrappingAndIsolatesLtrInRtl() {
        val formatter = BidiTextFormatter(useAndroidxBidiFormatter = false)

        // Attacker embeds RLO (\u202E) and LRI/PDI (\u2066..\u2069) + zero-width space (\u200B)
        val maliciousPhone = "\u202E+1 555\u200B-0199\u202C\u2066evil\u2069"
        val wrappedInRtl = formatter.wrapLtrToken(maliciousPhone, isRtlContext = true)

        // The original attacker RLO (\u202E) and isolate controls (\u2066, \u2069, \u200B) are stripped,
        // and the clean LTR string is wrapped with LRE (\u202A) ... PDF (\u202C) + RLM (\u200F) for RTL UI.
        assertFalse("Attacker RLO must be stripped", '\u202E' in wrappedInRtl)
        assertFalse("Attacker LRI must be stripped", '\u2066' in wrappedInRtl)
        assertFalse("Attacker zero-width space must be stripped", '\u200B' in wrappedInRtl)
        assertTrue(wrappedInRtl.contains("+1 555-0199evil"))
        assertEquals(BidiTextFormatter.LRE, wrappedInRtl.first())
        assertEquals(BidiTextFormatter.RLM, wrappedInRtl.last())

        // Verify AndroidX BidiFormatter path also strips bidi overrides first
        val defaultFormatter = BidiTextFormatter(useAndroidxBidiFormatter = true)
        val wrappedDefault = defaultFormatter.wrapText("\u202EInvoice.pdf", Locale.forLanguageTag("ar"))
        assertFalse("RLO must be stripped before AndroidX BidiFormatter", '\u202E' in wrappedDefault)
        assertTrue(wrappedDefault.contains("Invoice.pdf"))

        // Verify script-based RTL detection works without hardcoded language lists
        assertTrue(BidiTextFormatter.isRtlLocale(Locale.forLanguageTag("ar")))
        assertTrue(BidiTextFormatter.isRtlLocale(Locale.forLanguageTag("he")))
        assertTrue(BidiTextFormatter.isRtlLocale(Locale.forLanguageTag("fa")))
        assertTrue(BidiTextFormatter.isRtlLocale(Locale.forLanguageTag("ur")))
        assertFalse(BidiTextFormatter.isRtlLocale(Locale.forLanguageTag("en")))
        assertFalse(BidiTextFormatter.isRtlLocale(Locale.forLanguageTag("tr")))
        assertFalse(BidiTextFormatter.isRtlLocale(Locale.forLanguageTag("es")))
        assertFalse(BidiTextFormatter.isRtlLocale(Locale.forLanguageTag("fr")))
    }

    @Test
    fun localeDateTimeFormatterRespects12h24hFirstDayOfWeekAndNonGregorianCalendars() {
        val utcZone = ZoneId.of("UTC")
        val formatter = LocaleDateTimeFormatter(
            defaultZoneIdProvider = { utcZone },
            preferIcuOnAndroid = false
        )

        val time24 = formatter.formatTime(
            arg = MessageArg.IsoTime("14:30"),
            locale = Locale.US,
            use24Hour = true
        )
        assertEquals("14:30", time24)

        val time12 = formatter.formatTime(
            arg = MessageArg.IsoTime("14:30"),
            locale = Locale.US,
            use24Hour = false
        )
        assertTrue("Expected 12-hour format containing '2:30', got '$time12'", time12.contains("2:30"))

        // First day of week differs by locale (US = SUNDAY, France/Turkey = MONDAY)
        assertEquals(DayOfWeek.SUNDAY, formatter.firstDayOfWeek(Locale.US))
        assertEquals(DayOfWeek.MONDAY, formatter.firstDayOfWeek(Locale.FRANCE))

        // Internal canonical values always remain ISO-8601 Gregorian
        val epochMs = 1_763_728_200_000L // 2025-11-21T12:30:00Z
        assertEquals("2025-11-21", formatter.toCanonicalIsoDate(epochMs, utcZone))
        assertEquals("12:30", formatter.toCanonicalIsoTime(epochMs, utcZone))

        // Non-Gregorian calendar display (Buddhist calendar adds 543 years -> 2568 instead of 2025)
        val gregorianUs = formatter.formatDate(
            arg = MessageArg.IsoDate("2025-11-21"),
            locale = Locale.US
        )
        val buddhistLocale = Locale.forLanguageTag("en-US-u-ca-buddhist")
        val buddhistDisplay = formatter.formatDate(
            arg = MessageArg.IsoDate("2025-11-21"),
            locale = buddhistLocale
        )
        assertTrue("Gregorian date should contain 2025, got '$gregorianUs'", gregorianUs.contains("2025"))
        assertTrue("Buddhist calendar date should contain 2568, got '$buddhistDisplay'", buddhistDisplay.contains("2568"))
        assertNotEquals(gregorianUs, buddhistDisplay)
    }

    @Test
    fun fallbackEnglishTemplateProviderAndMessageRendererCoverAll53MessageKeysSafely() {
        val provider = FallbackEnglishMessageTemplateProvider()
        val renderer = NavaMessageRenderer(
            templateProvider = provider,
            bidiFormatter = BidiTextFormatter(useAndroidxBidiFormatter = false),
            dateTimeFormatter = LocaleDateTimeFormatter(
                defaultZoneIdProvider = { ZoneId.of("UTC") },
                preferIcuOnAndroid = false
            )
        )

        assertEquals(62, MessageKey.entries.size)

        for (key in MessageKey.entries) {
            val resourceName = MessageTemplateProvider.canonicalResourceName(key)
            assertTrue(resourceName.startsWith("msg_"))
            assertEquals("msg_${key.name.lowercase(Locale.US)}", resourceName)

            val template = provider.templateFor(key)
            assertTrue("Template for $key must not be blank", template.isNotBlank())
            assertTrue(
                "Template for $key must be pure ASCII",
                template.all { it.code in 32..126 }
            )

            // Rendering with 0 args must NEVER throw MissingFormatArgumentException
            val (titleEmpty, bodyEmpty) = renderer.render(UserMessage(key), Locale.US)
            assertTrue(titleEmpty.isNotBlank())
            assertTrue("Rendered body with 0 args for $key must not be blank", bodyEmpty.isNotBlank())
            assertFalse("Unfilled placeholders must be stripped for $key: '$bodyEmpty'", "%1\$s" in bodyEmpty)
            assertFalse("Unfilled placeholders must be stripped for $key: '$bodyEmpty'", "%2\$s" in bodyEmpty)

            // Rendering with 2 args must substitute cleanly
            val (titleArgs, bodyArgs) = renderer.render(
                UserMessage(
                    key = key,
                    args = listOf(
                        MessageArg.Text("TargetOne"),
                        MessageArg.Number(80L)
                    )
                ),
                Locale.US
            )
            assertTrue(titleArgs.isNotBlank())
            assertTrue(bodyArgs.isNotBlank())
        }

        // Verify specific structured arguments (IsoTime, ProvenanceBadge, bidi spoofing defence)
        val alarmMsg = UserMessage(
            key = MessageKey.ACTION_ALARM_SET,
            args = listOf(MessageArg.IsoTime("07:30"))
        )
        val (_, alarmBody) = renderer.render(alarmMsg, Locale.US, use24Hour = true)
        assertTrue("Expected '07:30' in '$alarmBody'", alarmBody.contains("07:30"))

        val untrustedMsg = UserMessage(
            key = MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE,
            args = listOf(MessageArg.ProvenanceBadge(DataProvenance.UNTRUSTED_EXTERNAL))
        )
        val (untrustedTitle, untrustedBody) = renderer.render(untrustedMsg, Locale.forLanguageTag("ar"))
        assertTrue(untrustedTitle.contains("Untrusted Source Warning"))
        assertTrue(untrustedBody.contains("Untrusted external source"))
    }

    @Test
    fun appLocaleManagerImplementsExactToBaseToEnFallbackChainAndUpdatesStateFlow() = runTest {
        val assetReader = AppContainer.resolveDefaultTestAssetReader()
        val realCatalog = AssetSupportedLanguageCatalog(assetReader)
        val bridge = InMemoryPlatformLocaleBridge(
            initialApplicationLocaleTag = null,
            systemDefaultLocaleTag = "en-US"
        )
        val manager = AppLocaleManager(
            catalog = realCatalog,
            platformBridge = bridge
        )

        // Fallback chain construction: exact -> parent subtags -> base -> "en"
        assertEquals(listOf("pt-BR", "pt", "en"), manager.buildFallbackChain("pt-BR"))
        assertEquals(listOf("zh-Hant-HK", "zh-Hant", "zh", "en"), manager.buildFallbackChain("zh-Hant-HK"))
        assertEquals(listOf("tr", "en"), manager.buildFallbackChain("tr"))
        assertEquals(listOf("en"), manager.buildFallbackChain("en"))

        // Regional tag "tr-TR" resolves to base "tr" in catalog
        val resolvedTr = manager.setApplicationLocale("tr-TR")
        assertEquals("tr", resolvedTr)
        assertEquals("tr", manager.activeLocaleTagFlow.value)
        assertEquals("tr", bridge.getApplicationLocaleTag())
        assertFalse(manager.isCurrentLocaleRtl())

        // Arabic "ar-EG" resolves to "ar" and reports RTL = true
        val resolvedAr = manager.setApplicationLocale("ar-EG")
        assertEquals("ar", resolvedAr)
        assertEquals("ar", manager.activeLocaleTagFlow.value)
        assertTrue(manager.isCurrentLocaleRtl())

        // Unknown language tag "xx-YY" falls back deterministically to "en"
        val resolvedFallback = manager.setApplicationLocale("xx-YY")
        assertEquals("en", resolvedFallback)
        assertEquals("en", manager.activeLocaleTagFlow.value)

        // Verify exact vs base resolution when catalog contains both "pt-BR" and "pt"
        val customCatalog = object : SupportedLanguageCatalog {
            private val entries = listOf(
                LanguageEntry("en", "English", "English", ScriptFamily.LATIN, isRtl = false, hasLayerUTranslation = true),
                LanguageEntry("pt", "Portuguese", "Portugues", ScriptFamily.LATIN, isRtl = false, hasLayerUTranslation = true),
                LanguageEntry("pt-BR", "Portuguese (Brazil)", "Portugues (Brasil)", ScriptFamily.LATIN, isRtl = false, hasLayerUTranslation = false),
                LanguageEntry("sw", "Swahili", "Kiswahili", ScriptFamily.LATIN, isRtl = false, qualityTier = QualityTier.LOW_RESOURCE_E2B_WARNING, hasLayerUTranslation = false)
            )

            override suspend fun allLanguages(): List<LanguageEntry> = entries
            override suspend fun findByTag(bcp47Tag: String): LanguageEntry? {
                val lower = bcp47Tag.lowercase(Locale.US)
                return entries.firstOrNull { it.bcp47Tag.lowercase(Locale.US) == lower }
                    ?: entries.firstOrNull { it.bcp47Tag.lowercase(Locale.US) == lower.substringBefore('-') }
            }

            override suspend fun isSupported(bcp47Tag: String): Boolean = findByTag(bcp47Tag) != null
        }

        val customManager = AppLocaleManager(customCatalog, InMemoryPlatformLocaleBridge())
        // Exact match in catalog is "pt-BR", while UI translation fallback chain resolves "pt-BR" -> "pt" -> "en"
        assertEquals("pt-BR", customManager.resolveSupportedLocaleTag("pt-BR"))
        assertEquals("pt", customManager.resolveUiTranslationLocaleTag("pt-BR"))
        // Swahili has no Layer U translation, so UI translation falls back to "en" while catalog language stays "sw"
        assertEquals("sw", customManager.resolveSupportedLocaleTag("sw-KE"))
        assertEquals("en", customManager.resolveUiTranslationLocaleTag("sw-KE"))
    }
}

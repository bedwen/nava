package com.nava.core.ai.router

import com.nava.core.ai.locale.AssetLocaleRulePackLoader
import com.nava.core.ai.locale.DirectoryAssetTextReader
import com.nava.core.ai.locale.SeedLocaleNormalizers
import com.nava.core.ai.testing.CoreAiTestFixtures
import com.nava.core.ai.testing.FakeSecurityFirewallPort
import com.nava.domain.locale.GenericTextNormalizer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RuleOriginalSpanRecoveryTest {

    private val normalizer = GenericTextNormalizer(SeedLocaleNormalizers.createRegistry())
    private val resolver = RuleIntentResolver(
        rulePackLoader = AssetLocaleRulePackLoader(DirectoryAssetTextReader(CoreAiTestFixtures.resolveAssetsDir())),
        securityFirewall = FakeSecurityFirewallPort(),
        textNormalizer = normalizer
    )

    private fun recover(original: String, lang: String, captured: String = normalizedCapture(original, lang)): String? =
        resolver.recoverOriginalSpan(original, captured, lang)

    private fun normalizedCapture(text: String, lang: String) = normalizer.normalize(text, lang).matchKey

    @Test
    fun keepsTurkishCaseAndDiacritics() {
        val original = "E\u015Fimin ad\u0131 Ay\u015Fe, bunu hat\u0131rla"
        assertEquals("E\u015Fimin ad\u0131 Ay\u015Fe", recover(original, "tr", "esimin adi ayse"))
    }

    @Test
    fun alignsAcrossFrenchElision() {
        val original = "Souviens-toi que ma femme s'appelle Anne"
        val captured = normalizedCapture("ma femme s'appelle Anne", "fr")
        assertEquals("ma femme s'appelle Anne", recover(original, "fr", captured))
    }

    @Test
    fun stripsInvisibleControlsFromRecoveredText() {
        val original = "Ay\u200B\u015Fe bunu hat\u0131rla"
        assertEquals("Ay\u015Fe", recover(original, "tr", "ayse"))
    }

    @Test
    fun returnsNullWhenNothingAligns() {
        assertNull(recover("tamamen baska bir cumle", "tr", "esimin adi ayse"))
    }
}

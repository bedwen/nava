package com.nava.core.ai.locale

import com.nava.core.ai.json.SimpleJsonParser
import com.nava.core.ai.testing.CoreAiTestFixtures
import com.nava.domain.locale.GenericTextNormalizer
import com.nava.domain.locale.QualityTier
import com.nava.domain.locale.ScriptFamily
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class MultilingualLocalePipelineTest {

    private val assetsReader = DirectoryAssetTextReader(CoreAiTestFixtures.resolveAssetsDir())
    private val catalog = AssetSupportedLanguageCatalog(assetsReader)
    private val rulePackLoader = AssetLocaleRulePackLoader(assetsReader)
    private val normalizer = GenericTextNormalizer(SeedLocaleNormalizers.createRegistry())

    @Test
    fun loadsComprehensiveDataDrivenCatalogCoveringAllTwelveScriptFamilies() = runTest {
        val all = catalog.allLanguages()
        assertTrue("Expected at least 60 languages, got ${all.size}", all.size >= 60)

        val coveredScripts = all.map { it.scriptFamily }.toSet()
        assertEquals(ScriptFamily.entries.toSet(), coveredScripts)

        val seedTags = listOf("en", "tr", "ar", "es", "fr")
        for (tag in seedTags) {
            val entry = catalog.findByTag(tag)
            assertNotNull("Missing seed catalog entry for $tag", entry)
            assertTrue("Expected hasLayerRPack=true for $tag", entry!!.hasLayerRPack)
            assertTrue("Expected hasLayerUTranslation=true for $tag", entry.hasLayerUTranslation)
        }

        val lowResource = all.filter { it.qualityTier == QualityTier.LOW_RESOURCE_E2B_WARNING }
        assertTrue("Expected LOW_RESOURCE_E2B_WARNING entries in catalog", lowResource.size >= 10)
        assertTrue(catalog.isSupported("tr-TR"))
    }

    @Test
    fun loadsFiveSeedLayerRRulePacksWithFallbackAndMissingHandling() = runTest {
        val requiredTools = setOf("set_alarm", "set_timer", "set_dnd", "set_volume", "launch_app")
        val seedTags = listOf("en", "tr", "ar", "es", "fr")

        assertEquals(seedTags.toSet(), rulePackLoader.availableLanguageTags())

        for (tag in seedTags) {
            val pack = rulePackLoader.loadRulePack(tag)
            assertNotNull("Expected rule pack for $tag", pack)
            assertEquals(tag, pack!!.languageTag)
            val packTools = pack.patterns.map { it.toolName }.toSet()
            assertTrue("Pack $tag missing required tools: ${requiredTools - packTools}", packTools.containsAll(requiredTools))
        }

        val trFallback = rulePackLoader.loadRulePack("tr-TR")
        assertNotNull(trFallback)
        assertEquals("tr", trFallback!!.languageTag)

        assertNull(rulePackLoader.loadRulePack("ja"))
        assertNull(rulePackLoader.loadRulePack("sw"))
    }

    @Test
    fun seedNormalizersApplyLocaleCorrectCaseFoldingDigitUnificationAndScriptRules() {
        // Turkish dotless-i and ASCII folding
        val trNative = normalizer.normalize("SAAT 07:30 \u0130\u00C7\u0130N ALARM KUR", "tr")
        val trDotless = normalizer.normalize("Saat 07:30 i\u00E7in alarm kur", "tr")
        val trAscii = normalizer.normalize("saat 07:30 icin alarm kur", "tr")
        assertEquals("saat 07:30 icin alarm kur", trNative.matchKey)
        assertEquals(trNative.matchKey, trDotless.matchKey)
        assertEquals(trNative.matchKey, trAscii.matchKey)

        // Arabic tashkeel, tatweel, alef, taa marbuta, yeh, kaf, and Arabic-Indic digits
        val arRaw = "\u0623\u0636\u0628\u0637 \u0645\u0646\u0628\u0647 \u0627\u0644\u0633\u0627\u0639\u0629 \u0660\u0667:\u0663\u0660"
        val arNorm = normalizer.normalize(arRaw, "ar")
        assertEquals("\u0627\u0636\u0628\u0637 \u0645\u0646\u0628\u0647 \u0627\u0644\u0633\u0627\u0639\u0647 07:30", arNorm.matchKey)

        // Spanish inverted punctuation and diacritic folding
        val esNorm = normalizer.normalize("\u00BFPon una alarma a las 7 de la ma\u00F1ana?", "es")
        assertEquals("pon una alarma a las 7 de la manana?", esNorm.matchKey)

        // French elision and diacritics
        val frElision = normalizer.normalize("Ouvre l\u2019application horloge", "fr")
        assertEquals("ouvre application horloge", frElision.matchKey)
        val frTime = normalizer.normalize("R\u00E8gle une alarme \u00E0 7h30", "fr")
        assertEquals("regle une alarme a 7h30", frTime.matchKey)
    }

    @Test
    fun detectsLanguagesAcrossAllFourteenGoldenUtteranceCorpora() = runTest {
        val detector = OnDeviceLanguageDetector(catalog = catalog, textNormalizer = normalizer)
        val testResourcesDir = CoreAiTestFixtures.resolveTestResourcesDir()
        val corpusTags = listOf(
            "en", "tr", "ar", "es", "fr",
            "ru", "el", "he", "hi", "th", "ja", "zh", "ko", "sw"
        )

        for (tag in corpusTags) {
            val corpusFile = File(testResourcesDir, "locale/$tag/golden_utterances.json")
            assertTrue("Missing golden corpus: ${corpusFile.absolutePath}", corpusFile.exists())

            val root = SimpleJsonParser.parse(corpusFile.readText(Charsets.UTF_8)).asObject()
            val expectedScript = ScriptFamily.valueOf(root.getValue("scriptFamily").asString())
            val cases = root.getValue("cases").asArray()
            assertTrue("Expected non-empty cases for $tag", cases.isNotEmpty())

            for (caseNode in cases) {
                val obj = caseNode.asObject()
                val caseId = obj.getValue("id").asString()
                val utterance = obj.getValue("utterance").asString()

                val detectedWithPrior = detector.detect(utterance, appLocaleTag = tag)
                assertEquals("Script mismatch for $caseId", expectedScript, detectedWithPrior.scriptFamily)
                assertEquals("Tag mismatch with app prior for $caseId", tag, detectedWithPrior.bcp47Tag)
            }

            // Verify zero-prior cross-script / keyword detection on the first utterance of non-English corpora
            if (tag != "en") {
                val firstUtterance = cases.first().asObject().getValue("utterance").asString()
                val detectedCross = detector.detect(firstUtterance, appLocaleTag = "en")
                assertEquals("Cross-prior script mismatch for $tag", expectedScript, detectedCross.scriptFamily)
                assertEquals("Cross-prior tag mismatch for $tag", tag, detectedCross.bcp47Tag)
                assertFalse("Expected non-ambiguous detection for $tag", detectedCross.isAmbiguous)
            }
        }
    }

    @Test
    fun marksShortOrEmptyUtterancesAsAmbiguousWithAppLocaleFallback() = runTest {
        val detector = OnDeviceLanguageDetector(catalog = catalog, textNormalizer = normalizer)

        val shortOk = detector.detect("ok", appLocaleTag = "tr")
        assertTrue(shortOk.isAmbiguous)
        assertEquals("tr", shortOk.bcp47Tag)

        val empty = detector.detect("   ", appLocaleTag = "ar")
        assertTrue(empty.isAmbiguous)
        assertEquals("ar", empty.bcp47Tag)
        assertEquals(ScriptFamily.ARABIC, empty.scriptFamily)
    }
}

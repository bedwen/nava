package com.nava.app.locale

import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.NeuronNodeId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

class LocalizationResourceParityTest {

    private lateinit var resDir: File
    private lateinit var baseStrings: Map<String, String>
    private val localeStrings = mutableMapOf<String, Map<String, String>>()
    private val locales = listOf("tr", "ar", "es", "fr")

    private val placeholderRegex = Regex("%(?:\\d+\\$)?[a-zA-Z]")

    @Before
    fun setUp() {
        resDir = resolveResDir()
        val baseFile = File(resDir, "values/strings.xml")
        assertTrue("Base strings.xml must exist at ${baseFile.absolutePath}", baseFile.exists())
        baseStrings = parseStringsXml(baseFile)

        for (loc in locales) {
            val locFile = File(resDir, "values-$loc/strings.xml")
            assertTrue("Locale file must exist for $loc at ${locFile.absolutePath}", locFile.exists())
            localeStrings[loc] = parseStringsXml(locFile)
        }
    }

    @Test
    fun allLocalesHave100PercentKeyParityWithBaseStrings() {
        val baseKeys = baseStrings.keys

        for ((loc, strings) in localeStrings) {
            val locKeys = strings.keys
            val missingInLocale = baseKeys - locKeys
            val extraInLocale = locKeys - baseKeys

            assertTrue(
                "Locale '$loc' is missing keys: $missingInLocale",
                missingInLocale.isEmpty()
            )
            assertTrue(
                "Locale '$loc' has extra keys: $extraInLocale",
                extraInLocale.isEmpty()
            )
            assertEquals("Key count mismatch for locale $loc", baseKeys.size, locKeys.size)
        }
    }

    @Test
    fun everyMessageKeyHasMatchingStringResource() {
        for (key in MessageKey.entries) {
            val expectedKey = "msg_${key.name.lowercase()}"
            assertTrue(
                "Base strings.xml missing canonical key '$expectedKey' for MessageKey.$key",
                baseStrings.containsKey(expectedKey)
            )
        }
    }

    @Test
    fun allLocalesHaveFormatPlaceholderParityWithBaseStrings() {
        for ((key, baseVal) in baseStrings) {
            val basePlaceholders = extractPlaceholders(baseVal)
            for ((loc, strings) in localeStrings) {
                val locVal = strings[key]
                    ?: error("Key '$key' unexpectedly missing in locale '$loc'")
                val locPlaceholders = extractPlaceholders(locVal)
                assertEquals(
                    "Format placeholder mismatch for key '$key' in locale '$loc' (expected $basePlaceholders, got $locPlaceholders)",
                    basePlaceholders,
                    locPlaceholders
                )
            }
        }
    }

    @Test
    fun baseStringsXmlAndThemesAndXmlConfigsArePureAscii() {
        val filesToCheck = mutableListOf(
            File(resDir, "values/strings.xml"),
            File(resDir, "values/themes.xml"),
            File(resDir, "xml/locales_config.xml"),
            File(resDir, "xml/nava_voice_interaction_service.xml")
        )

        for (file in filesToCheck) {
            assertTrue("File must exist: ${file.absolutePath}", file.exists())
            val bytes = file.readBytes()
            for ((idx, b) in bytes.withIndex()) {
                val unsigned = b.toInt() and 0xFF
                assertTrue(
                    "Non-ASCII byte 0x${unsigned.toString(16)} at index $idx in ${file.name}",
                    unsigned in 0..127
                )
            }
        }
    }

    @Test
    fun allElevenOriginalKeysPreservedIntact() {
        val originalExpected = mapOf(
            "app_name" to "Nava",
            "action_approve" to "Approve",
            "action_edit" to "Edit",
            "action_cancel" to "Cancel",
            "warning_untrusted_external_source" to "Extracted from untrusted external source",
            "error_permission_denied" to "Action blocked by your permission profile",
            "error_tool_not_found" to "Requested automation tool is not available",
            "error_security_violation" to "Action blocked by security policy",
            "error_model_unavailable" to "On-device language model is unavailable",
            "error_thought_budget_exceeded" to "Reasoning limit reached; please rephrase your request",
            "error_clarification_needed" to "Please clarify what you would like Nava to do"
        )

        for ((key, expectedText) in originalExpected) {
            assertTrue("Original key '$key' must exist in base strings", baseStrings.containsKey(key))
            assertEquals("Original key '$key' text was modified", expectedText, baseStrings[key])
        }
    }

    @Test
    fun allNeuronNodesHaveCanvasNeuronKeys() {
        for (node in NeuronNodeId.entries) {
            val key = "canvas_neuron_${node.name.lowercase()}"
            assertTrue("Missing canvas neuron label for $node: '$key'", baseStrings.containsKey(key))
        }
    }

    @Test
    fun allAtomicCapabilitiesHaveKeys() {
        for (cap in AtomicCapability.entries) {
            val key = "capability_${cap.name.lowercase()}"
            val descKey = "capability_${cap.name.lowercase()}_desc"
            assertTrue("Missing capability key: '$key'", baseStrings.containsKey(key))
            assertTrue("Missing capability desc key: '$descKey'", baseStrings.containsKey(descKey))
        }
    }

    @Test
    fun allConfirmationLevelsHaveKeys() {
        for (level in ConfirmationLevel.entries) {
            val key = "confirmation_level_${level.name.lowercase()}"
            val descKey = "confirmation_level_${level.name.lowercase()}_desc"
            assertTrue("Missing confirmation level key: '$key'", baseStrings.containsKey(key))
            assertTrue("Missing confirmation level desc key: '$descKey'", baseStrings.containsKey(descKey))
        }
    }

    @Test
    fun requiredSafetyAndArchitectureNoticesArePresent() {
        val requiredKeys = listOf(
            "onboarding_default_deny_title",
            "onboarding_default_deny_description",
            "onboarding_saf_headroom_notice",
            "settings_saf_headroom_notice",
            "hub_tier_0_low_memory_notice",
            "settings_tier_0_low_memory_notice",
            "hub_e2b_to_e4b_quality_banner",
            "settings_e2b_to_e4b_quality_banner",
            "voice_pack_missing_warning",
            "voice_offline_pack_missing_desc"
        )

        for (key in requiredKeys) {
            assertTrue("Missing required notice string key: '$key'", baseStrings.containsKey(key))
        }
    }

    private fun resolveResDir(): File {
        val candidates = listOf(
            File("src/main/res"),
            File("app/src/main/res"),
            File("../app/src/main/res")
        )
        return candidates.firstOrNull { it.exists() && it.isDirectory }
            ?: error("Could not resolve app/src/main/res directory from ${File(".").absolutePath}")
    }

    private fun parseStringsXml(file: File): Map<String, String> {
        val factory = DocumentBuilderFactory.newInstance()
        val builder = factory.newDocumentBuilder()
        val doc = builder.parse(file)
        val stringNodes = doc.getElementsByTagName("string")
        val result = mutableMapOf<String, String>()
        for (i in 0 until stringNodes.length) {
            val element = stringNodes.item(i) as Element
            val name = element.getAttribute("name")
            val text = element.textContent
            result[name] = text
        }
        return result
    }

    private fun extractPlaceholders(value: String): List<String> {
        return placeholderRegex.findAll(value).map { it.value }.sorted().toList()
    }
}

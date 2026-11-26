package com.nava.core.ai.router

import com.nava.core.ai.locale.AssetLocaleRulePackLoader
import com.nava.core.ai.locale.SeedLocaleNormalizers
import com.nava.core.ai.testing.CoreAiTestFixtures
import com.nava.core.ai.locale.DirectoryAssetTextReader
import com.nava.core.ai.testing.FakeSecurityFirewallPort
import com.nava.domain.ai.IntentRequest
import com.nava.domain.ai.ResolutionResult
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.locale.GenericTextNormalizer
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolCategory
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolSchemaField
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.ZoneOffset

/**
 * Tier 1 coverage for the personal memory and device control tools in every seed language,
 * plus priority checks so "open wifi settings" never resolves to `launch_app`.
 */
class MemoryAndDeviceRulePacksTest {

    private val loader = AssetLocaleRulePackLoader(DirectoryAssetTextReader(CoreAiTestFixtures.resolveAssetsDir()))
    private val normalizer = GenericTextNormalizer(SeedLocaleNormalizers.createRegistry())

    private fun tool(name: String, cap: AtomicCapability, vararg fields: Pair<String, SlotValueType>) = ToolMetadata(
        name = name,
        displayNameKey = name,
        description = name,
        category = ToolCategory.DEVICE_SETTINGS,
        requiredCapability = cap,
        fields = fields.map { (f, t) ->
            ToolSchemaField(name = f, description = f, required = true, slotKind = SensitiveSlotKind.TEXT_BODY, valueType = t)
        }
    )

    private val tools = CoreAiTestFixtures.canonicalTools() + listOf(
        tool("remember_fact", AtomicCapability.CREATE_DRAFT, "fact" to SlotValueType.STRING),
        tool("recall_facts", AtomicCapability.DATA_READ),
        tool("forget_fact", AtomicCapability.MODIFY_DELETE_SEND, "query" to SlotValueType.STRING),
        tool("set_flashlight", AtomicCapability.CREATE_DRAFT, "enabled" to SlotValueType.BOOLEAN),
        tool("media_control", AtomicCapability.CREATE_DRAFT, "command" to SlotValueType.STRING),
        tool("open_settings_panel", AtomicCapability.APP_LAUNCH, "panel" to SlotValueType.STRING)
    )

    private fun resolve(lang: String, utterance: String): ResolutionResult = runBlocking {
        RuleIntentResolver(
            rulePackLoader = loader,
            securityFirewall = FakeSecurityFirewallPort(),
            textNormalizer = normalizer,
            zoneIdProvider = { ZoneOffset.UTC }
        ).resolve(
            IntentRequest(
                requestId = "r_$lang",
                rawUtterance = utterance,
                normalizedText = normalizer.normalize(utterance, lang),
                provenance = DataProvenance.USER_UTTERANCE,
                issuedAtEpochMs = 1_760_000_000_000L
            ),
            tools
        )
    }

    private fun expect(lang: String, utterance: String, toolName: String, slot: String? = null, value: String? = null) {
        val result = resolve(lang, utterance)
        assertTrue("No Tier 1 match for [$lang] '$utterance': $result", result is ResolutionResult.ResolvedPlan)
        val call = (result as ResolutionResult.ResolvedPlan).plan.calls.single()
        assertEquals("Tool for [$lang] '$utterance'", toolName, call.toolName)
        if (slot != null) {
            val actual = when (val v = call.arguments.getValue(slot).value) {
                is SlotValueAst.StringValue -> v.value
                is SlotValueAst.BooleanValue -> v.value.toString()
                else -> v.toString()
            }
            assertEquals("Slot '$slot' for [$lang] '$utterance'", value, actual)
        }
    }

    @Test
    fun turkish() {
        expect("tr", "E\u015fimin ad\u0131 Ay\u015fe, bunu hat\u0131rla", "remember_fact", "fact", "E\u015fimin ad\u0131 Ay\u015fe")
        expect("tr", "Neler hat\u0131rl\u0131yorsun?", "recall_facts")
        expect("tr", "E\u015fimin ad\u0131n\u0131 unut", "forget_fact", "query", "E\u015fimin ad\u0131n\u0131")
        expect("tr", "Feneri a\u00e7", "set_flashlight", "enabled", "true")
        expect("tr", "feneri kapat", "set_flashlight", "enabled", "false")
        expect("tr", "M\u00fczi\u011fi durdur", "media_control", "command", "pause")
        expect("tr", "Sonraki \u015fark\u0131", "media_control", "command", "next")
        expect("tr", "Wifi ayarlar\u0131n\u0131 a\u00e7", "open_settings_panel", "panel", "wifi")
        expect("tr", "Bluetooth a\u00e7", "open_settings_panel", "panel", "bluetooth")
    }

    @Test
    fun english() {
        expect("en", "Remember that my wife is Ayse", "remember_fact", "fact", "my wife is Ayse")
        expect("en", "What do you know about me?", "recall_facts")
        expect("en", "Forget my wife", "forget_fact", "query", "my wife")
        expect("en", "Turn on the flashlight", "set_flashlight", "enabled", "true")
        expect("en", "Turn the torch off", "set_flashlight", "enabled", "false")
        expect("en", "Pause the music", "media_control", "command", "pause")
        expect("en", "Skip this song", "media_control", "command", "next")
        expect("en", "Open wifi settings", "open_settings_panel", "panel", "wifi")
    }

    @Test
    fun spanish() {
        expect("es", "Recuerda que mi esposa se llama Ana", "remember_fact")
        expect("es", "\u00bfQu\u00e9 sabes de m\u00ed?", "recall_facts")
        expect("es", "Enciende la linterna", "set_flashlight", "enabled", "true")
        expect("es", "Pausa la m\u00fasica", "media_control", "command", "pause")
        expect("es", "Abre los ajustes de bluetooth", "open_settings_panel", "panel", "bluetooth")
    }

    @Test
    fun french() {
        expect("fr", "Souviens-toi que ma femme s'appelle Anne", "remember_fact")
        expect("fr", "Qu'est-ce que tu sais sur moi ?", "recall_facts")
        expect("fr", "Allume la lampe torche", "set_flashlight", "enabled", "true")
        expect("fr", "Chanson suivante", "media_control", "command", "next")
        expect("fr", "Ouvre les r\u00e9glages wifi", "open_settings_panel", "panel", "wifi")
    }

    @Test
    fun arabic() {
        expect("ar", "\u062a\u0630\u0643\u0631 \u0623\u0646 \u0632\u0648\u062c\u062a\u064a \u0627\u0633\u0645\u0647\u0627 \u0633\u0627\u0631\u0629", "remember_fact")
        expect("ar", "\u0645\u0627\u0630\u0627 \u062a\u0639\u0631\u0641 \u0639\u0646\u064a\u061f", "recall_facts")
        expect("ar", "\u0634\u063a\u0644 \u0627\u0644\u0645\u0635\u0628\u0627\u062d", "set_flashlight", "enabled", "true")
        expect("ar", "\u0623\u0648\u0642\u0641 \u0627\u0644\u0645\u0648\u0633\u064a\u0642\u0649", "media_control", "command", "pause")
        expect("ar", "\u0627\u0641\u062a\u062d \u0625\u0639\u062f\u0627\u062f\u0627\u062a \u0627\u0644\u0628\u0644\u0648\u062a\u0648\u062b", "open_settings_panel", "panel", "bluetooth")
    }
}

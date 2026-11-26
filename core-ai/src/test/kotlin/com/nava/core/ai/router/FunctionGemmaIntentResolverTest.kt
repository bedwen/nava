package com.nava.core.ai.router

import com.nava.core.ai.engine.LiteRtLlmEngine
import com.nava.core.ai.engine.RuntimeStreamDelta
import com.nava.core.ai.lifecycle.DeviceHardwareSnapshot
import com.nava.core.ai.lifecycle.ModelSlot
import com.nava.core.ai.lifecycle.MultiModelCoordinator
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.core.ai.prompt.FunctionGemmaPromptFormat
import com.nava.core.ai.testing.CoreAiTestFixtures
import com.nava.core.ai.testing.FakeHardwareStatusProvider
import com.nava.core.ai.testing.FakeLiteRtRuntimeAdapter
import com.nava.core.ai.testing.FakeSecurityFirewallPort
import com.nava.domain.ai.IntentRequest
import com.nava.domain.ai.ResolutionResult
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.DataProvenance
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files

class FunctionGemmaIntentResolverTest {

    private val gb = 1024L * 1024L * 1024L
    private val allTools = CoreAiTestFixtures.canonicalTools()

    private lateinit var tempDir: File
    private lateinit var fakeFunctionModelFile: File

    @Before
    fun setUp() {
        tempDir = Files.createTempDirectory("nava_fg_test").toFile()
        fakeFunctionModelFile = File(tempDir, "functiongemma-270m-it.litertlm").apply {
            writeBytes(byteArrayOf(1, 2, 3, 4))
        }
    }

    @After
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    @Test
    fun formatsFunctionGemmaDeclarationsAndResolvesValidPlan() = runTest {
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val coordinator = MultiModelCoordinator(hardware)
        val unloadedSlots = mutableListOf<ModelSlot>()
        coordinator.registerUnloader(ModelSlot.PRIMARY_LLM) { unloadedSlots.add(ModelSlot.PRIMARY_LLM) }

        val runtime = FakeLiteRtRuntimeAdapter()
        runtime.enqueueDeltas(
            listOf(
                RuntimeStreamDelta(
                    outputDelta = "<start_function_call>call:create_calendar_event{" +
                        "title:<escape>Dentist<escape>," +
                        "date:<escape>2026-11-32<escape>," +
                        "time:<escape>14:30<escape>" +
                        "}<end_function_call>"
                )
            )
        )
        val engine = LiteRtLlmEngine(
            modelPathProvider = { fakeFunctionModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime,
            coordinator = coordinator,
            modelSlot = ModelSlot.FUNCTION_ROUTER
        )
        val firewall = FakeSecurityFirewallPort()
        val resolver = FunctionGemmaIntentResolver(
            functionEngine = engine,
            isModelAvailable = { true },
            lifecycleManager = lifecycle,
            coordinator = coordinator,
            securityFirewall = firewall
        )

        val result = resolver.resolve(
            IntentRequest(
                requestId = "fg-1",
                rawUtterance = "Book a calendar event for dentist at 14:30",
                issuedAtEpochMs = 1_760_000_000_000L
            ),
            allTools
        ) as ResolutionResult.ResolvedPlan

        assertEquals(ResolutionTier.TIER_2_5_FUNCTION_GEMMA, result.tier)
        assertEquals(1, result.plan.calls.size)
        val call = result.plan.calls.single()
        assertEquals("create_calendar_event", call.toolName)
        // ISO date overflow repair (2026-11-32 -> 2026-12-02)
        assertEquals(SlotValueAst.StringValue("2026-12-02"), call.arguments.getValue("date").value)
        assertEquals(DataProvenance.USER_UTTERANCE, call.arguments.getValue("title").provenance)
        assertEquals(setOf("create_calendar_event"), result.capabilityToken.allowedTools)

        // Verify prompt used FunctionGemma declarations & Zero-Thought maxOutputTokens=160
        val turn = runtime.clonedTurnCalls.single()
        assertEquals(FunctionGemmaPromptFormat.FUNCTION_GEMMA_SYSTEM_PREFIX_ID, turn.systemPrefixId)
        assertFalse(turn.config.allowThoughtMode)
        assertEquals(0, turn.config.maxThoughtTokens)
        assertEquals(160, turn.config.maxOutputTokens)
        assertTrue(turn.config.promptText.contains("<start_function_declaration>declaration:create_calendar_event"))
        assertTrue(turn.config.promptText.contains("<end_function_declaration>"))
        assertTrue(turn.config.promptText.contains("[NOW="))
        assertTrue(unloadedSlots.isEmpty())
    }

    @Test
    fun fastSkipsWhenUnavailableSevereThermalChatQueryOrComplexMultiClause() = runTest {
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val runtime = FakeLiteRtRuntimeAdapter()
        val engine = LiteRtLlmEngine(
            modelPathProvider = { fakeFunctionModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime
        )
        var modelAvailable = false
        val resolver = FunctionGemmaIntentResolver(
            functionEngine = engine,
            isModelAvailable = { modelAvailable },
            lifecycleManager = lifecycle,
            securityFirewall = FakeSecurityFirewallPort()
        )

        // 1. Model not available -> NoMatch without invoking engine
        assertEquals(
            ResolutionResult.NoMatch,
            resolver.resolve(IntentRequest("fg-unavail", "Set alarm 07:30", issuedAtEpochMs = 100L), allTools)
        )
        assertEquals(0, runtime.clonedTurnCalls.size)

        modelAvailable = true

        // 2. Pure conversational query (no action intent) -> NoMatch
        assertEquals(
            ResolutionResult.NoMatch,
            resolver.resolve(IntentRequest("fg-chat", "Tell me a short poem about rain", issuedAtEpochMs = 200L), allTools)
        )
        assertEquals(0, runtime.clonedTurnCalls.size)

        // 3. Complex multi-clause query (>=16 tokens + multiple clause separators) -> NoMatch
        val complexUtterance =
            "Please set an alarm for 07:30 tomorrow morning, turn on do not disturb mode, and draft a long message to Alex"
        assertEquals(
            ResolutionResult.NoMatch,
            resolver.resolve(IntentRequest("fg-complex", complexUtterance, issuedAtEpochMs = 300L), allTools)
        )
        assertEquals(0, runtime.clonedTurnCalls.size)

        // 4. Severe thermal -> NoMatch
        hardware.snapshot = DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_SEVERE, 90)
        assertEquals(
            ResolutionResult.NoMatch,
            resolver.resolve(IntentRequest("fg-sev", "Set alarm 07:30", issuedAtEpochMs = 400L), allTools)
        )
        assertEquals(0, runtime.clonedTurnCalls.size)
    }

    @Test
    fun fallsBackToNoMatchOnDirectReplyParseErrorSchemaViolationAndUnknownTool() = runTest {
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val runtime = FakeLiteRtRuntimeAdapter()
        val engine = LiteRtLlmEngine(
            modelPathProvider = { fakeFunctionModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime
        )
        val firewall = FakeSecurityFirewallPort()
        val resolver = FunctionGemmaIntentResolver(
            functionEngine = engine,
            isModelAvailable = { true },
            lifecycleManager = lifecycle,
            securityFirewall = firewall
        )

        // Direct reply -> NoMatch
        runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "NO_FUNCTION_CALL")))
        assertEquals(
            ResolutionResult.NoMatch,
            resolver.resolve(IntentRequest("fg-dr", "Set alarm 07:30", issuedAtEpochMs = 100L), allTools)
        )

        // Parse error -> NoMatch
        runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "<start_function_call>call:set_alarm{time:<escape>07:30}")))
        assertEquals(
            ResolutionResult.NoMatch,
            resolver.resolve(IntentRequest("fg-pe", "Set alarm 07:30", issuedAtEpochMs = 200L), allTools)
        )

        // Unknown / hallucinated tool -> NoMatch
        runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "<start_function_call>call:wipe_device{}<end_function_call>")))
        assertEquals(
            ResolutionResult.NoMatch,
            resolver.resolve(IntentRequest("fg-unk", "Set alarm 07:30", issuedAtEpochMs = 300L), allTools)
        )

        // Schema violation -> NoMatch
        runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "<start_function_call>call:set_alarm{time:<escape>bad-time<escape>}<end_function_call>")))
        assertEquals(
            ResolutionResult.NoMatch,
            resolver.resolve(IntentRequest("fg-sch", "Set alarm 07:30", issuedAtEpochMs = 400L), allTools)
        )

        assertEquals(0, firewall.mintedTokens.size)
    }
}

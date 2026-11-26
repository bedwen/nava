package com.nava.core.ai.router

import com.nava.core.ai.diagnostics.LlmTurnDiagnosticRecord
import com.nava.core.ai.diagnostics.LlmTurnDiagnosticsSink
import com.nava.core.ai.diagnostics.LlmTurnOutcome
import com.nava.core.ai.engine.LiteRtLlmEngine
import com.nava.core.ai.engine.RuntimeStreamDelta
import com.nava.core.ai.lifecycle.DeviceHardwareSnapshot
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.core.ai.testing.CoreAiTestFixtures
import com.nava.core.ai.testing.FakeHardwareStatusProvider
import com.nava.core.ai.testing.FakeLiteRtRuntimeAdapter
import com.nava.core.ai.testing.FakeSecurityFirewallPort
import com.nava.domain.ai.IntentRequest
import com.nava.domain.ai.ResolutionResult
import com.nava.domain.ui.MessageKey
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * Verifies developer diagnostics emitted by [GemmaIntentResolver] never alter resolution results
 * and report precise rejection reasons for every Tier 3 exit path.
 */
class GemmaIntentResolverDiagnosticsTest {

    private val allTools = CoreAiTestFixtures.canonicalTools()
    private val gb = 1024L * 1024L * 1024L

    private lateinit var tempDir: File
    private lateinit var fakeModelFile: File

    private class RecordingSink : LlmTurnDiagnosticsSink {
        val records = ArrayList<LlmTurnDiagnosticRecord>()
        override fun onTurn(record: LlmTurnDiagnosticRecord) {
            records.add(record)
        }
    }

    private class Harness(
        val hardware: FakeHardwareStatusProvider,
        val runtime: FakeLiteRtRuntimeAdapter,
        val resolver: GemmaIntentResolver
    )

    @Before
    fun setUp() {
        tempDir = Files.createTempDirectory("nava_diag_test").toFile()
        fakeModelFile = File(tempDir, "gemma-4-E2B-it.litertlm").apply {
            writeBytes(byteArrayOf(1, 2, 3, 4))
        }
    }

    @After
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    private fun harness(scope: CoroutineScope, sink: LlmTurnDiagnosticsSink?): Harness {
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, scope)
        val runtime = FakeLiteRtRuntimeAdapter()
        val engine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime
        )
        val resolver = GemmaIntentResolver(
            llmEngine = engine,
            lifecycleManager = lifecycle,
            securityFirewall = FakeSecurityFirewallPort(),
            diagnosticsSink = sink
        )
        return Harness(hardware, runtime, resolver)
    }

    @Test
    fun diagnosticsReportEveryExitPathWithPreciseReasons() = runTest {
        val sink = RecordingSink()
        val h = harness(backgroundScope, sink)

        // Resolved plan
        h.runtime.enqueueDeltas(
            listOf(RuntimeStreamDelta(outputDelta = "<|tool_call>call:set_alarm{time:<|\"|>07:30<|\"|>}<tool_call|>"))
        )
        assertTrue(
            h.resolver.resolve(IntentRequest("d1", "Set alarm 07:30", issuedAtEpochMs = 100L), allTools)
                is ResolutionResult.ResolvedPlan
        )

        // Schema-invalid time value
        h.runtime.enqueueDeltas(
            listOf(RuntimeStreamDelta(outputDelta = "<|tool_call>call:set_alarm{time:<|\"|>seven thirty<|\"|>}<tool_call|>"))
        )
        val schemaInvalid = h.resolver.resolve(
            IntentRequest("d2", "Set alarm seven thirty", issuedAtEpochMs = 200L),
            allTools
        ) as ResolutionResult.ClarificationNeeded
        assertEquals(MessageKey.ERROR_CLARIFICATION_NEEDED, schemaInvalid.message.key)

        // Unknown argument name
        h.runtime.enqueueDeltas(
            listOf(RuntimeStreamDelta(outputDelta = "<|tool_call>call:set_alarm{when:<|\"|>07:30<|\"|>}<tool_call|>"))
        )
        h.resolver.resolve(IntentRequest("d3", "Set alarm 07:30", issuedAtEpochMs = 300L), allTools)

        // Hallucinated tool
        h.runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "<|tool_call>call:wipe_device{confirm:true}<tool_call|>")))
        h.resolver.resolve(IntentRequest("d4", "Do something", issuedAtEpochMs = 400L), allTools)

        // Direct reply
        h.runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "Hello there.")))
        h.resolver.resolve(IntentRequest("d5", "Hi", issuedAtEpochMs = 500L), allTools)

        // Thermal gate
        h.hardware.snapshot = DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_SEVERE, 90)
        h.resolver.resolve(IntentRequest("d6", "Save a note", issuedAtEpochMs = 600L), allTools)

        val byId = sink.records.associateBy { it.requestId }
        assertEquals(6, sink.records.size)

        assertEquals(LlmTurnOutcome.RESOLVED_PLAN, byId.getValue("d1").outcome)
        assertTrue(byId.getValue("d1").rawOutput.contains("call:set_alarm"))
        assertTrue(byId.getValue("d1").promptPayload.contains("Set alarm 07:30"))
        assertTrue(byId.getValue("d1").prunedToolNames.contains("set_alarm"))

        assertEquals(LlmTurnOutcome.REJECTED_SCHEMA_INVALID, byId.getValue("d2").outcome)
        assertTrue(byId.getValue("d2").detail.contains("'time'"))
        // Detail never echoes raw slot values.
        assertTrue(!byId.getValue("d2").detail.contains("seven thirty"))

        assertEquals(LlmTurnOutcome.REJECTED_SCHEMA_INVALID, byId.getValue("d3").outcome)
        assertTrue(byId.getValue("d3").detail.contains("unknown argument 'when'"))

        assertEquals(LlmTurnOutcome.REJECTED_UNKNOWN_TOOL, byId.getValue("d4").outcome)
        assertTrue(byId.getValue("d4").detail.contains("wipe_device"))

        assertEquals(LlmTurnOutcome.DIRECT_REPLY, byId.getValue("d5").outcome)

        assertEquals(LlmTurnOutcome.THERMAL_GATE_REFUSED, byId.getValue("d6").outcome)
        assertEquals("", byId.getValue("d6").promptPayload)
    }

    @Test
    fun throwingSinkNeverAltersResolutionResults() = runTest {
        val throwing = LlmTurnDiagnosticsSink { throw IllegalStateException("sink failure") }
        val withSink = harness(backgroundScope, throwing)
        val withoutSink = harness(backgroundScope, null)
        val output = "<|tool_call>call:set_alarm{time:<|\"|>07:30<|\"|>}<tool_call|>"

        withSink.runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = output)))
        withoutSink.runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = output)))

        val a = withSink.resolver.resolve(IntentRequest("s1", "Set alarm 07:30", issuedAtEpochMs = 100L), allTools)
        val b = withoutSink.resolver.resolve(IntentRequest("s1", "Set alarm 07:30", issuedAtEpochMs = 100L), allTools)

        assertTrue(a is ResolutionResult.ResolvedPlan)
        assertTrue(b is ResolutionResult.ResolvedPlan)
        assertEquals(
            (a as ResolutionResult.ResolvedPlan).plan.calls.map { it.toolName },
            (b as ResolutionResult.ResolvedPlan).plan.calls.map { it.toolName }
        )
    }
}

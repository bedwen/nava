package com.nava.core.ai.router

import com.nava.core.ai.engine.LiteRtLlmEngine
import com.nava.core.ai.engine.RuntimeStreamDelta
import com.nava.core.ai.lifecycle.DeviceHardwareSnapshot
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.core.ai.testing.CoreAiTestFixtures
import com.nava.core.ai.testing.FakeHardwareStatusProvider
import com.nava.core.ai.testing.FakeLiteRtRuntimeAdapter
import com.nava.core.ai.testing.FakeSecurityFirewallPort
import com.nava.domain.ai.IntentRequest
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * Bounded thought mode for date math must only trigger when the top-ranked pruned tool is a
 * calendar tool, never for a plain clock command whose pruned set merely contains one.
 */
class GemmaIntentResolverThoughtGateTest {

    private val gb = 1024L * 1024L * 1024L
    private lateinit var tempDir: File
    private lateinit var fakeModelFile: File

    @Before
    fun setUp() {
        tempDir = Files.createTempDirectory("nava_thought_gate_test").toFile()
        fakeModelFile = File(tempDir, "gemma-4-E2B-it.litertlm").apply {
            writeBytes(byteArrayOf(1, 2, 3, 4))
        }
    }

    @After
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    @Test
    fun alarmCommandWithCalendarNeighbourDoesNotEnableThoughtMode() = runTest {
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val runtime = FakeLiteRtRuntimeAdapter()
        val engine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime
        )
        val resolver = GemmaIntentResolver(
            llmEngine = engine,
            lifecycleManager = lifecycle,
            securityFirewall = FakeSecurityFirewallPort()
        )
        runtime.enqueueDeltas(
            listOf(RuntimeStreamDelta(outputDelta = "<|tool_call>call:set_alarm{time:<|\"|>07:30<|\"|>}<tool_call|>"))
        )

        resolver.resolve(
            IntentRequest("t1", "set alarm 7:30", issuedAtEpochMs = 100L),
            listOf(CoreAiTestFixtures.SET_ALARM_TOOL, CoreAiTestFixtures.CREATE_CALENDAR_EVENT_TOOL)
        )

        assertFalse(runtime.clonedTurnCalls.single().config.allowThoughtMode)
    }
}

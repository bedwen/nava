package com.nava.core.ai.engine

import com.nava.core.ai.lifecycle.DeviceHardwareSnapshot
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.core.ai.prompt.Gemma4PromptFormat
import com.nava.core.ai.testing.FakeHardwareStatusProvider
import com.nava.core.ai.testing.FakeLiteRtRuntimeAdapter
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files

@OptIn(ExperimentalCoroutinesApi::class)
class LiteRtLlmEnginePrewarmTest {

    private lateinit var tempDir: File
    private lateinit var fakeModelFile: File
    private val gb = 1024L * 1024L * 1024L

    @Before
    fun setUp() {
        tempDir = Files.createTempDirectory("nava_prewarm_test").toFile()
        fakeModelFile = File(tempDir, "gemma-4-E2B-it.litertlm").apply {
            writeBytes(byteArrayOf(1, 2, 3, 4))
        }
    }

    @After
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    private fun TestScope.engineFor(
        snapshot: DeviceHardwareSnapshot,
        runtime: FakeLiteRtRuntimeAdapter,
        modelPath: String? = fakeModelFile.absolutePath
    ): LiteRtLlmEngine {
        val lifecycle = ThermalModelLifecycleManager(FakeHardwareStatusProvider(snapshot), backgroundScope)
        return LiteRtLlmEngine(
            modelPathProvider = { modelPath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime
        )
    }

    @Test
    fun prewarmLoadsPrefixAndArmsIdleUnload() = runTest {
        val runtime = FakeLiteRtRuntimeAdapter()
        val engine = engineFor(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 85),
            runtime
        )

        assertTrue(engine.prewarm(Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID))
        assertTrue(engine.isModelLoaded())
        assertFalse(engine.isLoadingWeights.value)
        assertEquals(1, runtime.ensurePrefixCalls.size)
        assertEquals(
            Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID,
            runtime.ensurePrefixCalls[0].systemPrefixId
        )
        assertEquals(0, runtime.clonedTurnCalls.size)

        // The normal idle timer still applies: an unused prewarm never keeps weights resident.
        advanceTimeBy(181_000L)
        runCurrent()
        assertEquals(1, runtime.unloadCalls)
        assertFalse(engine.isModelLoaded())
    }

    @Test
    fun prewarmRefusedWhenPolicyWouldUnloadImmediately() = runTest {
        val runtime = FakeLiteRtRuntimeAdapter()
        val lowBattery = engineFor(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 10),
            runtime
        )
        assertFalse(lowBattery.prewarm(Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID))

        val moderate = engineFor(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_MODERATE, 85),
            runtime
        )
        assertFalse(moderate.prewarm(Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID))

        val lowRam = engineFor(
            DeviceHardwareSnapshot(3L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 85),
            runtime
        )
        assertFalse(lowRam.prewarm(Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID))

        assertEquals(0, runtime.ensurePrefixCalls.size)
    }

    @Test
    fun prewarmRefusedWhenModelNotProvisioned() = runTest {
        val runtime = FakeLiteRtRuntimeAdapter()
        val engine = engineFor(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 85),
            runtime,
            modelPath = File(tempDir, "missing.litertlm").absolutePath
        )
        assertFalse(engine.prewarm(Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID))
        assertEquals(0, runtime.ensurePrefixCalls.size)
    }
}

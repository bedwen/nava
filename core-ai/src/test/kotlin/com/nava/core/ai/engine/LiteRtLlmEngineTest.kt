package com.nava.core.ai.engine

import com.nava.core.ai.lifecycle.DeviceHardwareSnapshot
import com.nava.core.ai.lifecycle.ModelSlot
import com.nava.core.ai.lifecycle.MultiModelCoordinator
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.core.ai.prompt.Gemma4PromptFormat
import com.nava.core.ai.testing.CoreAiTestFixtures
import com.nava.core.ai.testing.FakeHardwareStatusProvider
import com.nava.core.ai.testing.FakeLiteRtRuntimeAdapter
import com.nava.domain.ai.LlmGenerationRequest
import com.nava.domain.ai.LlmStreamChunk
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files

@OptIn(ExperimentalCoroutinesApi::class)
class LiteRtLlmEngineTest {

    private lateinit var tempDir: File
    private lateinit var fakeModelFile: File

    @Before
    fun setUp() {
        tempDir = Files.createTempDirectory("nava_engine_test").toFile()
        fakeModelFile = File(tempDir, "gemma-4-E2B-it.litertlm").apply {
            writeBytes(byteArrayOf(1, 2, 3, 4))
        }
    }

    @After
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    @Test
    fun reusesPinnedSegmentAPrefixAcrossClonedTurns() = runTest {
        val gb = 1024L * 1024L * 1024L
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 85)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val runtime = FakeLiteRtRuntimeAdapter()
        runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "<|tool_call>call:set_dnd{enabled:true}<tool_call|>")))
        runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "<|tool_call>call:set_volume{level:50}<tool_call|>")))

        val engine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime
        )

        val first = engine.generate(
            LlmGenerationRequest(
                requestId = "r1",
                systemPrefixId = Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID,
                prunedTools = listOf(CoreAiTestFixtures.SET_DND_TOOL),
                userUtterance = "Turn on dnd",
                languageHintTag = "en"
            )
        )
        val second = engine.generate(
            LlmGenerationRequest(
                requestId = "r2",
                systemPrefixId = Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID,
                prunedTools = listOf(CoreAiTestFixtures.SET_VOLUME_TOOL),
                userUtterance = "Set volume to 50",
                languageHintTag = "en"
            )
        )

        assertTrue(first.thoughtClosedCleanly)
        assertTrue(second.thoughtClosedCleanly)
        assertEquals(2, runtime.ensurePrefixCalls.size)
        assertEquals(runtime.ensurePrefixCalls[0].systemPrompt, runtime.ensurePrefixCalls[1].systemPrompt)
        assertEquals(2, runtime.clonedTurnCalls.size)
        assertTrue(engine.isModelLoaded())
    }

    @Test
    fun disablesThoughtModeOnModerateThermalAndLowBattery() = runTest {
        val gb = 1024L * 1024L * 1024L
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_MODERATE, 85)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val runtime = FakeLiteRtRuntimeAdapter()
        runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "Done.")))
        runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "Done.")))

        val engine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime
        )

        engine.generate(
            LlmGenerationRequest(
                requestId = "r-mod",
                systemPrefixId = Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID,
                prunedTools = listOf(CoreAiTestFixtures.SET_ALARM_TOOL),
                userUtterance = "Set alarm for 07:30 and send a note",
                languageHintTag = "en",
                allowThoughtMode = true,
                maxThoughtTokens = 256
            )
        )
        assertFalse(runtime.clonedTurnCalls[0].config.allowThoughtMode)
        assertEquals(0, runtime.clonedTurnCalls[0].config.maxThoughtTokens)

        hardware.snapshot = DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 10)
        engine.generate(
            LlmGenerationRequest(
                requestId = "r-bat",
                systemPrefixId = Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID,
                prunedTools = listOf(CoreAiTestFixtures.SET_ALARM_TOOL),
                userUtterance = "Set alarm for 08:30",
                languageHintTag = "en",
                allowThoughtMode = true,
                maxThoughtTokens = 256
            )
        )
        assertFalse(runtime.clonedTurnCalls[1].config.allowThoughtMode)
        assertEquals(0, runtime.clonedTurnCalls[1].config.maxThoughtTokens)
    }

    @Test
    fun abortsAndUnloadsImmediatelyOnSevereThermal() = runTest {
        val gb = 1024L * 1024L * 1024L
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_SEVERE, 80)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val runtime = FakeLiteRtRuntimeAdapter()
        val engine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime
        )

        val req = LlmGenerationRequest(
            requestId = "r-sev",
            systemPrefixId = Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID,
            prunedTools = listOf(CoreAiTestFixtures.SET_ALARM_TOOL),
            userUtterance = "Set alarm",
            languageHintTag = "en"
        )

        val streamChunks = engine.generateStream(req).toList()
        assertTrue(streamChunks.single() is LlmStreamChunk.Aborted)
        assertTrue(runtime.unloadCalls >= 1)

        try {
            engine.generate(req)
            fail("Expected IllegalStateException under SEVERE thermal state")
        } catch (_: IllegalStateException) {
            // Expected
        }
    }

    @Test
    fun abortsWhenThoughtBudgetExceededAndMarksThoughtNotClosedCleanly() = runTest {
        val gb = 1024L * 1024L * 1024L
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val runtime = FakeLiteRtRuntimeAdapter()
        runtime.enqueueDeltas(
            listOf(
                RuntimeStreamDelta(thoughtDelta = "one two three four five"),
                RuntimeStreamDelta(outputDelta = "should not finish")
            )
        )

        val engine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime
        )

        val result = engine.generate(
            LlmGenerationRequest(
                requestId = "r-budget",
                systemPrefixId = Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID,
                prunedTools = listOf(CoreAiTestFixtures.SET_ALARM_TOOL),
                userUtterance = "Complex multi-step plan",
                languageHintTag = "en",
                allowThoughtMode = true,
                maxThoughtTokens = 3
            )
        )

        assertFalse(result.thoughtClosedCleanly)
        assertEquals("", result.rawOutput)
    }

    @Test
    fun stage2BlindExtractionForcesEmptyToolsDisabledThinkingAndSuppressTokenIds() = runTest {
        val gb = 1024L * 1024L * 1024L
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val runtime = FakeLiteRtRuntimeAdapter()
        runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "recipient: Alice")))

        val suppressIds = listOf(101, 102, 103)
        val engine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime,
            stage2SuppressTokenIds = suppressIds
        )

        val result = engine.generate(
            LlmGenerationRequest(
                requestId = "r-stage2",
                systemPrefixId = Gemma4PromptFormat.STAGE2_BLIND_EXTRACTION_PREFIX_ID,
                prunedTools = emptyList(),
                userUtterance = "Untrusted notification body",
                languageHintTag = "en",
                allowThoughtMode = true,
                maxThoughtTokens = 256,
                stage2BlindExtractionMode = true
            )
        )

        assertEquals("recipient: Alice", result.rawOutput)
        val turnConfig = runtime.clonedTurnCalls.single().config
        assertTrue(turnConfig.stage2BlindExtractionMode)
        assertFalse(turnConfig.allowThoughtMode)
        assertEquals(0, turnConfig.maxThoughtTokens)
        assertEquals(suppressIds, turnConfig.suppressTokenIds)
        assertFalse(turnConfig.promptText.contains("[TOOLS]"))
    }

    @Test
    fun generateStreamPreservesThoughtOutputAndCompletedOrder() = runTest {
        val gb = 1024L * 1024L * 1024L
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val runtime = FakeLiteRtRuntimeAdapter()
        runtime.enqueueDeltas(
            listOf(
                RuntimeStreamDelta(thoughtDelta = "Step 1"),
                RuntimeStreamDelta(outputDelta = "Hello "),
                RuntimeStreamDelta(outputDelta = "world")
            )
        )

        val engine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime
        )

        val chunks = engine.generateStream(
            LlmGenerationRequest(
                requestId = "r-stream",
                systemPrefixId = Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID,
                prunedTools = listOf(CoreAiTestFixtures.SET_ALARM_TOOL),
                userUtterance = "Say hello",
                languageHintTag = "en",
                allowThoughtMode = true,
                maxThoughtTokens = 64
            )
        ).toList()

        assertEquals(4, chunks.size)
        assertTrue(chunks[0] is LlmStreamChunk.ThoughtDelta)
        assertTrue(chunks[1] is LlmStreamChunk.OutputDelta)
        assertTrue(chunks[2] is LlmStreamChunk.OutputDelta)
        val completed = chunks[3] as LlmStreamChunk.Completed
        assertEquals("Hello world", completed.result.rawOutput)
        assertTrue(completed.result.thoughtClosedCleanly)
    }

    @Test
    fun unloadModelWaitsForActiveStreamingTurnBeforeClosingRuntime() = runTest {
        val gb = 1024L * 1024L * 1024L
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val turnEntered = CompletableDeferred<Unit>()
        val releaseTurn = CompletableDeferred<Unit>()

        val runtime = object : LiteRtRuntimeAdapter {
            private var loaded = false
            var unloadCalls = 0

            override fun isLoaded(): Boolean = loaded

            override suspend fun ensureMasterPrefix(
                modelPath: String,
                systemPrefixId: String,
                systemPrompt: String,
                maxNumTokens: Int
            ) {
                loaded = true
            }

            override fun runClonedTurn(
                systemPrefixId: String,
                config: RuntimeTurnConfig
            ): Flow<RuntimeStreamDelta> = flow {
                emit(RuntimeStreamDelta(outputDelta = "Part 1 "))
                turnEntered.complete(Unit)
                releaseTurn.await()
                emit(RuntimeStreamDelta(outputDelta = "Part 2"))
            }

            override suspend fun unload() {
                loaded = false
                unloadCalls++
            }
        }

        val engine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime
        )
        val req = LlmGenerationRequest(
            requestId = "r-concurrent-unload",
            systemPrefixId = Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID,
            prunedTools = listOf(CoreAiTestFixtures.SET_ALARM_TOOL),
            userUtterance = "Say hello",
            languageHintTag = "en"
        )

        val collected = mutableListOf<LlmStreamChunk>()
        val streamJob = launch {
            engine.generateStream(req).collect { collected.add(it) }
        }
        turnEntered.await()

        val unloadJob = launch { engine.unloadModel() }
        runCurrent()

        assertEquals(0, runtime.unloadCalls)
        assertTrue(engine.isModelLoaded())

        releaseTurn.complete(Unit)
        streamJob.join()
        unloadJob.join()

        assertEquals(1, runtime.unloadCalls)
        assertFalse(engine.isModelLoaded())
        assertTrue(collected.last() is LlmStreamChunk.Completed)
    }

    @Test
    fun cancellingStreamMidTurnStillUnloadsImmediatelyOnTier0AndRearmsTimerOnTier1() = runTest {
        val gb = 1024L * 1024L * 1024L

        fun createBlockingRuntime(firstChunkEmitted: CompletableDeferred<Unit>): Pair<LiteRtRuntimeAdapter, () -> Int> {
            val holdGate = CompletableDeferred<Unit>()
            var unloads = 0
            val adapter = object : LiteRtRuntimeAdapter {
                private var loaded = false

                override fun isLoaded(): Boolean = loaded

                override suspend fun ensureMasterPrefix(
                    modelPath: String,
                    systemPrefixId: String,
                    systemPrompt: String,
                    maxNumTokens: Int
                ) {
                    loaded = true
                }

                override fun runClonedTurn(
                    systemPrefixId: String,
                    config: RuntimeTurnConfig
                ): Flow<RuntimeStreamDelta> = flow {
                    emit(RuntimeStreamDelta(outputDelta = "Partial"))
                    firstChunkEmitted.complete(Unit)
                    holdGate.await()
                }

                override suspend fun unload() {
                    loaded = false
                    unloads++
                }
            }
            return adapter to { unloads }
        }

        val req = LlmGenerationRequest(
            requestId = "r-cancel-mid",
            systemPrefixId = Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID,
            prunedTools = listOf(CoreAiTestFixtures.SET_ALARM_TOOL),
            userUtterance = "Set alarm",
            languageHintTag = "en"
        )

        // TIER_0_LOW_MEMORY (0s timeout): mid-stream cancel unloads immediately
        val tier0Hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(4L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val tier0Lifecycle = ThermalModelLifecycleManager(tier0Hardware, backgroundScope)
        val tier0FirstChunk = CompletableDeferred<Unit>()
        val (tier0Runtime, tier0UnloadCount) = createBlockingRuntime(tier0FirstChunk)
        val tier0Engine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = tier0Lifecycle,
            runtimeAdapter = tier0Runtime
        )

        val tier0Job = launch {
            tier0Engine.generateStream(req).collect {}
        }
        tier0FirstChunk.await()
        tier0Job.cancel()
        tier0Job.join()

        assertTrue(tier0UnloadCount() >= 1)
        assertFalse(tier0Engine.isModelLoaded())

        // TIER_1_STANDARD (180s timeout): mid-stream cancel arms 180s idle timer
        val tier1Hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val tier1Lifecycle = ThermalModelLifecycleManager(tier1Hardware, backgroundScope)
        val tier1FirstChunk = CompletableDeferred<Unit>()
        val (tier1Runtime, tier1UnloadCount) = createBlockingRuntime(tier1FirstChunk)
        val tier1Engine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = tier1Lifecycle,
            runtimeAdapter = tier1Runtime
        )

        val tier1Job = launch {
            tier1Engine.generateStream(req).collect {}
        }
        tier1FirstChunk.await()
        tier1Job.cancel()
        tier1Job.join()

        assertEquals(0, tier1UnloadCount())
        assertTrue(tier1Engine.isModelLoaded())

        advanceTimeBy(180_000L)
        runCurrent()

        assertEquals(1, tier1UnloadCount())
        assertFalse(tier1Engine.isModelLoaded())
    }

    @Test
    fun capsE2bContextTokensTo2048OnTier1AndTier2WhileKeeping4096ForNonE2bModels() = runTest {
        val gb = 1024L * 1024L * 1024L
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(12L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val runtime = FakeLiteRtRuntimeAdapter()
        runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "ok")))
        runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "ok")))

        val e4bModelFile = File(tempDir, "gemma-4-E4B-it.litertlm").apply {
            writeBytes(byteArrayOf(5, 6, 7, 8))
        }
        var activeModelPath = fakeModelFile.absolutePath
        val engine = LiteRtLlmEngine(
            modelPathProvider = { activeModelPath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime
        )

        engine.generate(
            LlmGenerationRequest(
                requestId = "e2b-cap",
                systemPrefixId = Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID,
                prunedTools = listOf(CoreAiTestFixtures.SET_ALARM_TOOL),
                userUtterance = "Set alarm 07:00",
                languageHintTag = "en"
            )
        )
        assertEquals(2048, runtime.ensurePrefixCalls[0].maxNumTokens)

        activeModelPath = e4bModelFile.absolutePath
        engine.generate(
            LlmGenerationRequest(
                requestId = "e4b-cap",
                systemPrefixId = Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID,
                prunedTools = listOf(CoreAiTestFixtures.SET_ALARM_TOOL),
                userUtterance = "Set alarm 08:00",
                languageHintTag = "en"
            )
        )
        assertEquals(4096, runtime.ensurePrefixCalls[1].maxNumTokens)

        assertEquals(2, AndroidLiteRtRuntimeAdapter.optimalCpuThreadCount(1))
        assertEquals(4, AndroidLiteRtRuntimeAdapter.optimalCpuThreadCount(8))
        assertEquals(4, AndroidLiteRtRuntimeAdapter.optimalCpuThreadCount(16))
    }

    @Test
    fun clearsCoordinatorSlotOnMissingModelOrEnsurePrefixFailureAndCapsFunctionRouterTo1024() = runTest {
        val gb = 1024L * 1024L * 1024L
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(4L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val coordinator = MultiModelCoordinator(hardware)
        var embedUnloads = 0
        coordinator.registerUnloader(ModelSlot.EMBEDDING_ENGINE) { embedUnloads++ }

        // 1. Missing model path -> FatalAbort / Aborted, slot remains inactive, peer not evicted
        val missingRuntime = FakeLiteRtRuntimeAdapter()
        val missingEngine = LiteRtLlmEngine(
            modelPathProvider = { null },
            lifecycleManager = lifecycle,
            runtimeAdapter = missingRuntime,
            coordinator = coordinator,
            modelSlot = ModelSlot.PRIMARY_LLM
        )
        val req = LlmGenerationRequest(
            requestId = "r-missing",
            systemPrefixId = Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID,
            prunedTools = listOf(CoreAiTestFixtures.SET_ALARM_TOOL),
            userUtterance = "Set alarm 07:00",
            languageHintTag = "en"
        )
        val abortChunks = missingEngine.generateStream(req).toList()
        assertTrue(abortChunks.single() is LlmStreamChunk.Aborted)
        assertFalse(coordinator.isSlotActive(ModelSlot.PRIMARY_LLM))
        assertEquals(0, embedUnloads)

        // 2. Runtime ensureMasterPrefix throws -> coordinator slot cleared (markUnloaded)
        val failingRuntime = object : LiteRtRuntimeAdapter {
            override fun isLoaded(): Boolean = false
            override suspend fun ensureMasterPrefix(
                modelPath: String,
                systemPrefixId: String,
                systemPrompt: String,
                maxNumTokens: Int
            ) {
                throw IllegalStateException("Simulated native mmap failure")
            }
            override fun runClonedTurn(systemPrefixId: String, config: RuntimeTurnConfig): Flow<RuntimeStreamDelta> = flow {}
            override suspend fun unload() {}
        }
        val failingEngine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = failingRuntime,
            coordinator = coordinator,
            modelSlot = ModelSlot.PRIMARY_LLM
        )
        try {
            failingEngine.generate(req)
            fail("Expected IllegalStateException when ensureMasterPrefix fails")
        } catch (_: IllegalStateException) {
            // Expected
        }
        assertFalse(coordinator.isSlotActive(ModelSlot.PRIMARY_LLM))
        assertEquals(1, embedUnloads)

        // 3. FUNCTION_ROUTER slot caps maxContextTokens at 1024 even on Tier 2
        hardware.snapshot = DeviceHardwareSnapshot(12L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        val fgRuntime = FakeLiteRtRuntimeAdapter()
        fgRuntime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "NO_FUNCTION_CALL")))
        val fgModel = File(tempDir, "mobile-actions_q8_ekv1024.litertlm").apply {
            writeBytes(byteArrayOf(9, 9, 9))
        }
        val fgEngine = LiteRtLlmEngine(
            modelPathProvider = { fgModel.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = fgRuntime,
            coordinator = coordinator,
            modelSlot = ModelSlot.FUNCTION_ROUTER
        )
        fgEngine.generate(req)
        assertEquals(1024, fgRuntime.ensurePrefixCalls.single().maxNumTokens)
    }
}

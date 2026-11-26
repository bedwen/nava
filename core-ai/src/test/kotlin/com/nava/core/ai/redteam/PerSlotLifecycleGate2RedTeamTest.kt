package com.nava.core.ai.redteam

import com.nava.core.ai.embedding.EmbeddingRuntimeAdapter
import com.nava.core.ai.embedding.LiteRtEmbeddingEngine
import com.nava.core.ai.engine.LiteRtLlmEngine
import com.nava.core.ai.engine.RuntimeStreamDelta
import com.nava.core.ai.lifecycle.DeviceHardwareSnapshot
import com.nava.core.ai.lifecycle.ModelSlot
import com.nava.core.ai.lifecycle.MultiModelCoordinator
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.core.ai.prompt.Gemma4PromptFormat
import com.nava.core.ai.testing.FakeHardwareStatusProvider
import com.nava.core.ai.testing.FakeLiteRtRuntimeAdapter
import com.nava.domain.ai.LlmGenerationRequest
import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Gate 2 independent adversarial suite for commit 0114a7d (per-[ModelSlot] residency in the
 * shared [ThermalModelLifecycleManager], slot-aware [LiteRtLlmEngine], and [LiteRtEmbeddingEngine]
 * joining the idle-unload lifecycle). PLAN.md Section 2.3 items 2-3.
 *
 * All timing uses kotlinx-coroutines-test virtual time.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PerSlotLifecycleGate2RedTeamTest {

    private val gb = 1024L * 1024L * 1024L
    private lateinit var modelsDir: File
    private lateinit var modelFile: File

    @Before
    fun setUp() {
        modelsDir = Files.createTempDirectory("nava_gate2_lifecycle").toFile()
        modelFile = File(modelsDir, "gemma-4-E2B-it.litertlm").apply { writeBytes(byteArrayOf(1, 2, 3, 4)) }
    }

    @After
    fun tearDown() {
        modelsDir.deleteRecursively()
    }

    private fun snapshot(
        ramGb: Long = 8L,
        thermal: Int = ThermalModelLifecycleManager.THERMAL_STATUS_NONE,
        battery: Int = 80
    ) = DeviceHardwareSnapshot(ramGb * gb, thermal, battery, availableRamBytes = 4L * gb)

    private class FakeEmbeddingAdapter : EmbeddingRuntimeAdapter {
        @Volatile
        private var loaded = false
        var loadCalls = 0
        var unloadCalls = 0
        var computeDelayMs = 0L

        override fun isLoaded(): Boolean = loaded

        override suspend fun ensureLoaded(modelPath: String) {
            if (!loaded) loadCalls++
            loaded = true
        }

        override suspend fun computeEmbedding(formattedInput: String): FloatArray? {
            if (computeDelayMs > 0) delay(computeDelayMs) else yield()
            return floatArrayOf(0.1f, 0.2f)
        }

        override suspend fun unload() {
            if (loaded) unloadCalls++
            loaded = false
        }
    }

    private class SlotCounters {
        val immediate = IntArray(ModelSlot.entries.size)
        val deferred = IntArray(ModelSlot.entries.size)
        fun total(slot: ModelSlot) = immediate[slot.ordinal] + deferred[slot.ordinal]
    }

    private suspend fun turn(
        manager: ThermalModelLifecycleManager,
        slot: ModelSlot,
        counters: SlotCounters,
        minimumIdleTimeoutSec: Int = 0
    ) {
        manager.onEnsureLoaded(slot) { }
        manager.onTurnCompleted(
            slot = slot,
            immediateUnloader = { counters.immediate[slot.ordinal]++ },
            deferredIdleUnloader = { gen ->
                if (manager.consumePendingIdleUnload(slot, gen)) counters.deferred[slot.ordinal]++
            },
            minimumIdleTimeoutSec = minimumIdleTimeoutSec
        )
    }

    private fun request(id: String) = LlmGenerationRequest(
        requestId = id,
        systemPrefixId = Gemma4PromptFormat.DEFAULT_STAGE1_CHAT_SYSTEM_PREFIX_ID,
        prunedTools = emptyList(),
        userUtterance = "hello",
        languageHintTag = "en"
    )

    private data class Engines(
        val manager: ThermalModelLifecycleManager,
        val coordinator: MultiModelCoordinator,
        val hw: FakeHardwareStatusProvider,
        val primaryRuntime: FakeLiteRtRuntimeAdapter,
        val routerRuntime: FakeLiteRtRuntimeAdapter,
        val embeddingRuntime: FakeEmbeddingAdapter,
        val primary: LiteRtLlmEngine,
        val router: LiteRtLlmEngine,
        val embedding: LiteRtEmbeddingEngine
    )

    private fun TestScope.engines(
        primaryPathProvider: (suspend () -> String?)? = null,
        hw: FakeHardwareStatusProvider = FakeHardwareStatusProvider(snapshot())
    ): Engines {
        val manager = ThermalModelLifecycleManager(hw, backgroundScope)
        val coordinator = MultiModelCoordinator(hw)
        val primaryRuntime = FakeLiteRtRuntimeAdapter().apply {
            turnResponder = { _, _ -> listOf(RuntimeStreamDelta(outputDelta = "ok")) }
        }
        val routerRuntime = FakeLiteRtRuntimeAdapter().apply {
            turnResponder = { _, _ -> listOf(RuntimeStreamDelta(outputDelta = "ok")) }
        }
        val embeddingRuntime = FakeEmbeddingAdapter()
        val path = modelFile.absolutePath
        val primary = LiteRtLlmEngine(
            modelPathProvider = primaryPathProvider ?: { path },
            lifecycleManager = manager,
            runtimeAdapter = primaryRuntime,
            clockMs = { testScheduler.currentTime },
            coordinator = coordinator,
            modelSlot = ModelSlot.PRIMARY_LLM
        )
        val router = LiteRtLlmEngine(
            modelPathProvider = { path },
            lifecycleManager = manager,
            runtimeAdapter = routerRuntime,
            clockMs = { testScheduler.currentTime },
            coordinator = coordinator,
            modelSlot = ModelSlot.FUNCTION_ROUTER
        )
        val embedding = LiteRtEmbeddingEngine(
            modelPathProvider = { path },
            lifecycleManager = manager,
            runtimeAdapter = embeddingRuntime,
            coordinator = coordinator
        )
        return Engines(manager, coordinator, hw, primaryRuntime, routerRuntime, embeddingRuntime, primary, router, embedding)
    }

    // ---------------------------------------------------------------------------------------
    // 1. Manager-level per-slot isolation
    // ---------------------------------------------------------------------------------------

    @Test
    fun staggeredTurnsOnAllThreeSlots_eachUnloadsExactlyAtItsOwnDeadline() = runTest {
        val manager = ThermalModelLifecycleManager(FakeHardwareStatusProvider(snapshot()), backgroundScope)
        val c = SlotCounters()

        turn(manager, ModelSlot.PRIMARY_LLM, c) // deadline 180
        advanceTimeBy(50_000L)
        turn(manager, ModelSlot.FUNCTION_ROUTER, c) // deadline 230
        advanceTimeBy(50_000L)
        turn(manager, ModelSlot.EMBEDDING_ENGINE, c, minimumIdleTimeoutSec = 15) // deadline 280

        // Hammer the router repeatedly; it must never extend primary or embedding residency.
        repeat(10) {
            advanceTimeBy(5_000L)
            turn(manager, ModelSlot.FUNCTION_ROUTER, c) // last at t=150 -> deadline 330
        }

        advanceTimeBy(29_999L) // t = 179.999
        runCurrent()
        assertEquals(0, c.total(ModelSlot.PRIMARY_LLM))
        advanceTimeBy(2L)
        runCurrent()
        assertEquals("primary unloads at its own 180s deadline", 1, c.deferred[ModelSlot.PRIMARY_LLM.ordinal])
        assertTrue(manager.isSlotResident(ModelSlot.FUNCTION_ROUTER))
        assertTrue(manager.isSlotResident(ModelSlot.EMBEDDING_ENGINE))

        advanceTimeBy(100_000L) // t = 280.001
        runCurrent()
        assertEquals(1, c.deferred[ModelSlot.EMBEDDING_ENGINE.ordinal])
        assertEquals(0, c.total(ModelSlot.FUNCTION_ROUTER))

        advanceTimeBy(50_000L) // t = 330.001
        runCurrent()
        assertEquals(1, c.deferred[ModelSlot.FUNCTION_ROUTER.ordinal])
        for (slot in ModelSlot.entries) {
            assertFalse(manager.isSlotResident(slot))
            assertFalse(manager.hasPendingIdleUnload(slot))
            assertEquals("exactly one unload for $slot", 1, c.total(slot))
        }
    }

    @Test
    fun forceUnloadOfAnySlot_neverCancelsOrInvalidatesTheOtherTwo() = runTest {
        for (victim in ModelSlot.entries) {
            val manager = ThermalModelLifecycleManager(FakeHardwareStatusProvider(snapshot()), backgroundScope)
            val c = SlotCounters()
            for (slot in ModelSlot.entries) turn(manager, slot, c)
            var forced = 0
            manager.forceUnload(victim) { forced++ }
            assertEquals(1, forced)
            assertFalse(manager.hasPendingIdleUnload(victim))
            assertFalse(manager.isSlotResident(victim))
            for (other in ModelSlot.entries - victim) {
                assertTrue("$victim force-unload cancelled $other timer", manager.hasPendingIdleUnload(other))
                assertTrue(manager.isSlotResident(other))
            }
            advanceTimeBy(181_000L)
            runCurrent()
            assertEquals("victim timer must never fire after force unload", 0, c.total(victim))
            for (other in ModelSlot.entries - victim) {
                assertEquals(1, c.deferred[other.ordinal])
            }
        }
    }

    @Test
    fun staleGenerationFromOneSlotNeverUnloadsAnotherOrANewerTurn() = runTest {
        val manager = ThermalModelLifecycleManager(FakeHardwareStatusProvider(snapshot()), backgroundScope)
        val c = SlotCounters()
        turn(manager, ModelSlot.PRIMARY_LLM, c)
        turn(manager, ModelSlot.FUNCTION_ROUTER, c)
        turn(manager, ModelSlot.EMBEDDING_ENGINE, c)

        // Generations are tracked per slot, so equal numeric values exist across slots. Replaying
        // stale/foreign generation values must never consume a live residency.
        for (slot in ModelSlot.entries) {
            for (gen in 0L..0L) {
                assertFalse("stale gen $gen consumed $slot", manager.consumePendingIdleUnload(slot, gen))
            }
        }
        // Legacy primary-only overload must only ever address PRIMARY_LLM.
        manager.onEnsureLoaded(ModelSlot.FUNCTION_ROUTER) { }
        assertFalse(manager.consumePendingIdleUnload(0L))
        assertTrue(manager.isSlotResident(ModelSlot.FUNCTION_ROUTER))
        assertTrue(manager.isSlotResident(ModelSlot.PRIMARY_LLM))

        // A fresh turn on the primary invalidates its own pending timer.
        manager.onEnsureLoaded(ModelSlot.PRIMARY_LLM) { }
        assertFalse(manager.hasPendingIdleUnload(ModelSlot.PRIMARY_LLM))
        advanceTimeBy(181_000L)
        runCurrent()
        assertEquals("primary turn still running: stale timer must not fire", 0, c.total(ModelSlot.PRIMARY_LLM))
        assertEquals(1, c.deferred[ModelSlot.EMBEDDING_ENGINE.ordinal])
        assertTrue(manager.isSlotResident(ModelSlot.PRIMARY_LLM))
    }

    @Test
    fun severeAtTurnCompletion_unloadsImmediatelyEvenWithMinimumIdleTimeout() = runTest {
        val hw = FakeHardwareStatusProvider(snapshot())
        val manager = ThermalModelLifecycleManager(hw, backgroundScope)
        for (minimum in listOf(0, 15, 600, Int.MAX_VALUE / 1000)) {
            for (slot in ModelSlot.entries) {
                val c = SlotCounters()
                hw.snapshot = snapshot()
                manager.onEnsureLoaded(slot) { }
                hw.snapshot = snapshot(thermal = ThermalModelLifecycleManager.THERMAL_STATUS_SEVERE)
                manager.onTurnCompleted(
                    slot = slot,
                    immediateUnloader = { c.immediate[slot.ordinal]++ },
                    deferredIdleUnloader = { c.deferred[slot.ordinal]++ },
                    minimumIdleTimeoutSec = minimum
                )
                assertEquals("SEVERE must unload $slot immediately (minimum=$minimum)", 1, c.immediate[slot.ordinal])
                assertFalse(manager.hasPendingIdleUnload(slot))
                assertFalse(manager.isSlotResident(slot))
            }
        }
    }

    @Test
    fun severeBlocksLoadingOnEverySlot() = runTest {
        val hw = FakeHardwareStatusProvider(snapshot(thermal = ThermalModelLifecycleManager.THERMAL_STATUS_SEVERE))
        val manager = ThermalModelLifecycleManager(hw, backgroundScope)
        for (slot in ModelSlot.entries) {
            var loaded = false
            val outcome = runCatching { manager.onEnsureLoaded(slot) { loaded = true } }
            assertTrue(outcome.isFailure)
            assertFalse(loaded)
            assertFalse(manager.isSlotResident(slot))
        }
    }

    @Test
    fun moderateThermalOrLowBattery_minimumIdleTimeoutMustNotDelayImmediateUnload() = runTest {
        val hw = FakeHardwareStatusProvider(snapshot())
        val manager = ThermalModelLifecycleManager(hw, backgroundScope)
        val stressed = listOf(
            snapshot(thermal = ThermalModelLifecycleManager.THERMAL_STATUS_MODERATE),
            snapshot(battery = 9)
        )
        for (state in stressed) {
            val c = SlotCounters()
            hw.snapshot = snapshot()
            manager.onEnsureLoaded(ModelSlot.EMBEDDING_ENGINE) { }
            hw.snapshot = state
            manager.onTurnCompleted(
                slot = ModelSlot.EMBEDDING_ENGINE,
                immediateUnloader = { c.immediate[ModelSlot.EMBEDDING_ENGINE.ordinal]++ },
                deferredIdleUnloader = { c.deferred[ModelSlot.EMBEDDING_ENGINE.ordinal]++ },
                minimumIdleTimeoutSec = 15
            )
            assertEquals(
                "PLAN 2.3: MODERATE / battery<15% unloads weights immediately on turn completion ($state)",
                1,
                c.immediate[ModelSlot.EMBEDDING_ENGINE.ordinal]
            )
        }
    }

    @Test
    fun embeddingEngineUnderModerateThermal_unloadsRightAfterTheCall() = runTest {
        val hw = FakeHardwareStatusProvider(snapshot(thermal = ThermalModelLifecycleManager.THERMAL_STATUS_MODERATE))
        val e = engines(hw = hw)
        assertNotNull(e.embedding.embedQuery("weather tomorrow"))
        runCurrent()
        assertFalse("EmbeddingGemma must not stay resident under MODERATE", e.embeddingRuntime.isLoaded())
    }

    // ---------------------------------------------------------------------------------------
    // 2. Real engines sharing one manager
    // ---------------------------------------------------------------------------------------

    @Test
    fun realEngines_routerAndEmbeddingBurstsNeverExtendPrimaryResidency() = runTest {
        val e = engines()
        e.primary.generate(request("p1"))
        assertTrue(e.primaryRuntime.isLoaded())

        repeat(12) { i ->
            advanceTimeBy(10_000L)
            e.router.generate(request("r$i"))
            assertNotNull(e.embedding.embedQuery("query $i"))
        }
        // t = 120s; last router/embedding activity at 120s.
        advanceTimeBy(60_001L) // t = 180.001
        runCurrent()
        assertFalse("primary must unload 180s after its own last turn", e.primaryRuntime.isLoaded())
        assertEquals(1, e.primaryRuntime.unloadCalls)
        assertTrue(e.routerRuntime.isLoaded())
        assertTrue(e.embeddingRuntime.isLoaded())
        assertEquals("embedding burst must reuse the resident model", 1, e.embeddingRuntime.loadCalls)

        advanceTimeBy(120_000L) // t = 300.001
        runCurrent()
        assertFalse(e.routerRuntime.isLoaded())
        assertFalse(e.embeddingRuntime.isLoaded())
        assertEquals(1, e.routerRuntime.unloadCalls)
        assertEquals(1, e.embeddingRuntime.unloadCalls)
        for (slot in ModelSlot.entries) {
            assertFalse(e.manager.hasPendingIdleUnload(slot))
            assertFalse(e.coordinator.isSlotActive(slot))
        }
    }

    @Test
    fun realEngines_explicitUnloadOfOneEngineKeepsPeerTimersArmed() = runTest {
        val e = engines()
        e.primary.generate(request("p1"))
        e.router.generate(request("r1"))
        assertNotNull(e.embedding.embedQuery("q"))

        e.embedding.unloadEmbeddingModel()
        e.router.unloadModel()
        assertTrue(e.manager.hasPendingIdleUnload(ModelSlot.PRIMARY_LLM))
        assertFalse(e.manager.hasPendingIdleUnload(ModelSlot.FUNCTION_ROUTER))
        assertFalse(e.manager.hasPendingIdleUnload(ModelSlot.EMBEDDING_ENGINE))

        advanceTimeBy(181_000L)
        runCurrent()
        assertFalse(e.primaryRuntime.isLoaded())
        assertEquals(1, e.primaryRuntime.unloadCalls)
        assertEquals(1, e.routerRuntime.unloadCalls)
        assertEquals(1, e.embeddingRuntime.unloadCalls)
    }

    @Test
    fun realEngines_severeDuringPendingTimers_nextLlmTurnUnloadsEverySlotImmediately() = runTest {
        val e = engines()
        e.primary.generate(request("p1"))
        assertNotNull(e.embedding.embedQuery("q"))
        assertTrue(e.manager.hasPendingIdleUnload(ModelSlot.PRIMARY_LLM))
        assertTrue(e.manager.hasPendingIdleUnload(ModelSlot.EMBEDDING_ENGINE))

        advanceTimeBy(30_000L)
        e.hw.snapshot = snapshot(thermal = ThermalModelLifecycleManager.THERMAL_STATUS_SEVERE)
        val aborted = runCatching { e.router.generate(request("r1")) }
        assertTrue("SEVERE turn must abort", aborted.isFailure)
        runCurrent()

        assertFalse(e.primaryRuntime.isLoaded())
        assertFalse(e.embeddingRuntime.isLoaded())
        assertFalse(e.routerRuntime.isLoaded())
        for (slot in ModelSlot.entries) {
            assertFalse("$slot timer must be cancelled by SEVERE", e.manager.hasPendingIdleUnload(slot))
            assertFalse(e.manager.isSlotResident(slot))
        }
        // No stale timer may fire later and double-unload.
        advanceTimeBy(400_000L)
        runCurrent()
        assertEquals(1, e.primaryRuntime.unloadCalls)
        assertEquals(1, e.embeddingRuntime.unloadCalls)
    }

    @Test
    fun realEngines_severeEmbeddingCallNeverLeavesEmbeddingResident() = runTest {
        val e = engines()
        assertNotNull(e.embedding.embedQuery("q"))
        e.hw.snapshot = snapshot(thermal = ThermalModelLifecycleManager.THERMAL_STATUS_SEVERE)
        assertEquals(null, e.embedding.embedQuery("q2"))
        assertFalse(e.embeddingRuntime.isLoaded())
        assertFalse(e.manager.hasPendingIdleUnload(ModelSlot.EMBEDDING_ENGINE))
        assertFalse(e.manager.isSlotResident(ModelSlot.EMBEDDING_ENGINE))
    }

    @Test
    fun realEngines_timerFiringWhileNewTurnHoldsInferenceMutex_neverEvictsTheNewTurn() = runTest {
        var calls = 0
        val path = modelFile.absolutePath
        val e = engines(primaryPathProvider = {
            calls++
            // Call #4 is the in-mutex path check of the second turn: stall it across the deadline.
            if (calls == 4) delay(5_000L)
            path
        })
        e.primary.generate(request("p1")) // completes at t=0, deadline t=180
        advanceTimeBy(178_000L)

        val second = launch { e.primary.generate(request("p2")) }
        advanceTimeBy(3_000L) // t = 181: timer fired and is now waiting for inferenceMutex
        runCurrent()
        assertTrue("primary weights must stay resident while turn p2 is in flight", e.primaryRuntime.isLoaded())
        assertEquals(0, e.primaryRuntime.unloadCalls)

        advanceTimeBy(3_000L) // t = 184: p2 completed at t = 183, new deadline 363
        runCurrent()
        assertTrue(second.isCompleted)
        assertTrue(e.primaryRuntime.isLoaded())
        assertEquals("stale deferred unload must be dropped after the new turn", 0, e.primaryRuntime.unloadCalls)

        advanceTimeBy(178_000L) // t = 362
        runCurrent()
        assertTrue(e.primaryRuntime.isLoaded())
        advanceTimeBy(2_000L) // t = 364
        runCurrent()
        assertFalse(e.primaryRuntime.isLoaded())
        assertEquals(1, e.primaryRuntime.unloadCalls)
    }

    @Test
    fun realEngines_embeddingTimerRacingASlowEmbeddingCall_neverEvictsMidCall() = runTest {
        val e = engines()
        assertNotNull(e.embedding.embedQuery("q1")) // deadline t=180
        advanceTimeBy(179_000L)
        e.embeddingRuntime.computeDelayMs = 10_000L
        val slow = launch { e.embedding.embedQuery("q2") }
        advanceTimeBy(5_000L) // t = 184, inside q2's compute
        runCurrent()
        assertTrue(e.embeddingRuntime.isLoaded())
        assertEquals(0, e.embeddingRuntime.unloadCalls)
        advanceTimeBy(6_000L) // q2 done at t = 189, deadline 369
        runCurrent()
        assertTrue(slow.isCompleted)
        assertTrue(e.embeddingRuntime.isLoaded())
        advanceTimeBy(181_000L)
        runCurrent()
        assertFalse(e.embeddingRuntime.isLoaded())
        assertEquals(1, e.embeddingRuntime.unloadCalls)
    }

    @Test
    fun realEngines_concurrentTurnsUnloadsAndTimersAcrossSlots_neverDeadlock() = runTest {
        val e = engines()
        e.embeddingRuntime.computeDelayMs = 50L
        withTimeout(3_600_000L) {
            val jobs = ArrayList<kotlinx.coroutines.Job>()
            repeat(40) { i ->
                jobs += launch { runCatching { e.primary.generate(request("p$i")) } }
                jobs += launch { runCatching { e.router.generate(request("r$i")) } }
                jobs += launch { e.embedding.embedQuery("q$i") }
                if (i % 3 == 0) jobs += launch { e.primary.unloadModel() }
                if (i % 4 == 0) jobs += launch { e.embedding.unloadEmbeddingModel() }
                if (i % 5 == 0) jobs += launch { e.router.unloadModel() }
                if (i % 7 == 0) jobs += launch { e.coordinator.unloadAll() }
                // Let some idle timers expire in the middle of the storm.
                if (i % 10 == 9) advanceTimeBy(181_000L)
            }
            jobs.forEach { it.join() }
        }
        advanceTimeBy(400_000L)
        runCurrent()
        assertFalse(e.primaryRuntime.isLoaded())
        assertFalse(e.routerRuntime.isLoaded())
        assertFalse(e.embeddingRuntime.isLoaded())
        for (slot in ModelSlot.entries) {
            assertFalse(e.manager.hasPendingIdleUnload(slot))
            assertFalse(e.manager.isSlotResident(slot))
        }
    }

    @Suppress("unused")
    private fun CoroutineScope.unusedScopeMarker() = Unit
}

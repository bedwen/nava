package com.nava.core.ai.lifecycle

import com.nava.core.ai.testing.FakeHardwareStatusProvider
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A single [ThermalModelLifecycleManager] is shared by the primary LLM, the FunctionGemma router
 * and the embedding engine. A turn on one slot must never cancel or invalidate the idle unload of
 * another slot, otherwise multi-GB weights stay resident indefinitely.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PerSlotModelResidencyTest {

    private val gb = 1024L * 1024L * 1024L

    private fun normalTier1Provider() = FakeHardwareStatusProvider(
        DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 80)
    )

    @Test
    fun routerTurnDoesNotCancelPrimaryIdleUnload() = runTest {
        val manager = ThermalModelLifecycleManager(normalTier1Provider(), backgroundScope)
        var primaryUnloads = 0
        var routerUnloads = 0

        manager.onEnsureLoaded(ModelSlot.PRIMARY_LLM) { }
        manager.onTurnCompleted(ModelSlot.PRIMARY_LLM) { primaryUnloads++ }

        advanceTimeBy(60_000L)
        manager.onEnsureLoaded(ModelSlot.FUNCTION_ROUTER) { }
        manager.onTurnCompleted(ModelSlot.FUNCTION_ROUTER) { routerUnloads++ }

        advanceTimeBy(121_000L)
        runCurrent()
        assertEquals("primary must unload 180s after its own turn", 1, primaryUnloads)
        assertEquals(0, routerUnloads)

        advanceTimeBy(60_000L)
        runCurrent()
        assertEquals(1, routerUnloads)
        assertFalse(manager.isSlotResident(ModelSlot.PRIMARY_LLM))
        assertFalse(manager.isSlotResident(ModelSlot.FUNCTION_ROUTER))
    }

    @Test
    fun forceUnloadOfOneSlotKeepsOtherSlotTimerArmed() = runTest {
        val manager = ThermalModelLifecycleManager(normalTier1Provider(), backgroundScope)
        var primaryUnloads = 0

        manager.onEnsureLoaded(ModelSlot.PRIMARY_LLM) { }
        manager.onTurnCompleted(ModelSlot.PRIMARY_LLM) { primaryUnloads++ }
        manager.forceUnload(ModelSlot.EMBEDDING_ENGINE) { }

        assertTrue(manager.hasPendingIdleUnload(ModelSlot.PRIMARY_LLM))
        advanceTimeBy(181_000L)
        runCurrent()
        assertEquals(1, primaryUnloads)
    }

    @Test
    fun minimumIdleTimeoutKeepsBurstCallersResidentOnTier0() = runTest {
        val tier0 = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(4L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 80)
        )
        val manager = ThermalModelLifecycleManager(tier0, backgroundScope)
        var immediate = 0
        var deferred = 0

        manager.onEnsureLoaded(ModelSlot.EMBEDDING_ENGINE) { }
        manager.onTurnCompleted(
            slot = ModelSlot.EMBEDDING_ENGINE,
            immediateUnloader = { immediate++ },
            deferredIdleUnloader = { gen ->
                if (manager.consumePendingIdleUnload(ModelSlot.EMBEDDING_ENGINE, gen)) deferred++
            },
            minimumIdleTimeoutSec = 15
        )
        assertEquals(0, immediate)

        advanceTimeBy(16_000L)
        runCurrent()
        assertEquals(1, deferred)
    }
}

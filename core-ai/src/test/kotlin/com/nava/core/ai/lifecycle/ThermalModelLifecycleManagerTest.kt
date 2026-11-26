package com.nava.core.ai.lifecycle

import com.nava.core.ai.testing.FakeHardwareStatusProvider
import com.nava.domain.ai.RamTier
import com.nava.domain.ai.ThermalState
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ThermalModelLifecycleManagerTest {

    @Test
    fun mapsContiguousRamTiersAcrossBoundaries() {
        val gb = 1024L * 1024L * 1024L
        val provider = FakeHardwareStatusProvider()
        val manager = ThermalModelLifecycleManager(provider)

        provider.snapshot = DeviceHardwareSnapshot(4L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 80)
        assertEquals(RamTier.TIER_0_LOW_MEMORY, manager.currentRamTier())
        assertEquals(1024, manager.effectiveContextTokens())
        assertFalse(manager.isThoughtModeAllowed())
        assertEquals(0, manager.effectiveIdleUnloadTimeoutSec())

        provider.snapshot = DeviceHardwareSnapshot(6L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 80)
        assertEquals(RamTier.TIER_1_STANDARD, manager.currentRamTier())
        assertEquals(4096, manager.effectiveContextTokens())
        assertTrue(manager.isThoughtModeAllowed())
        assertEquals(180, manager.effectiveIdleUnloadTimeoutSec())

        provider.snapshot = DeviceHardwareSnapshot(12L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 80)
        assertEquals(RamTier.TIER_2_HIGH, manager.currentRamTier())
        assertEquals(4096, manager.effectiveContextTokens())
        assertTrue(manager.isThoughtModeAllowed())
        assertEquals(180, manager.effectiveIdleUnloadTimeoutSec())
    }

    @Test
    fun evaluatesThermalAndLowBatteryTransitions() {
        val gb = 1024L * 1024L * 1024L
        val provider = FakeHardwareStatusProvider()
        val manager = ThermalModelLifecycleManager(provider)

        provider.snapshot = DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_LIGHT, 15)
        assertEquals(ThermalState.NORMAL, manager.currentThermalState())
        assertTrue(manager.canRunLlm())
        assertTrue(manager.isThoughtModeAllowed())

        provider.snapshot = DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 14)
        assertEquals(ThermalState.MODERATE, manager.currentThermalState())
        assertTrue(manager.canRunLlm())
        assertFalse(manager.isThoughtModeAllowed())
        assertEquals(0, manager.effectiveIdleUnloadTimeoutSec())

        provider.snapshot = DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_MODERATE, 90)
        assertEquals(ThermalState.MODERATE, manager.currentThermalState())
        assertTrue(manager.canRunLlm())
        assertFalse(manager.isThoughtModeAllowed())
        assertEquals(0, manager.effectiveIdleUnloadTimeoutSec())

        provider.snapshot = DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_SEVERE, 90)
        assertEquals(ThermalState.SEVERE_OR_HIGHER, manager.currentThermalState())
        assertFalse(manager.canRunLlm())
        assertFalse(manager.isThoughtModeAllowed())
    }

    @Test
    fun schedulesAndCancelsIdleUnloadTimerDeterministically() = runTest {
        val gb = 1024L * 1024L * 1024L
        val provider = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 80)
        )
        val manager = ThermalModelLifecycleManager(provider, backgroundScope)
        var unloadCount = 0

        manager.onTurnCompleted { unloadCount++ }
        advanceTimeBy(100_000L)
        runCurrent()
        assertEquals(0, unloadCount)

        // New load cancels pending idle timer.
        manager.onEnsureLoaded { "loaded" }
        advanceTimeBy(180_000L)
        runCurrent()
        assertEquals(0, unloadCount)

        // Next turn completes and unloads after full 180s idle window.
        manager.onTurnCompleted { unloadCount++ }
        advanceTimeBy(180_000L)
        runCurrent()
        assertEquals(1, unloadCount)
    }

    @Test
    fun unloadsImmediatelyOnTier0OrModerateAndRejectsLoadOnSevere() = runTest {
        val gb = 1024L * 1024L * 1024L
        val provider = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(4L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 80)
        )
        val manager = ThermalModelLifecycleManager(provider, backgroundScope)
        var unloadCount = 0

        manager.onTurnCompleted { unloadCount++ }
        assertEquals(1, unloadCount)

        provider.snapshot = DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_MODERATE, 80)
        manager.onTurnCompleted { unloadCount++ }
        assertEquals(2, unloadCount)

        provider.snapshot = DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_SEVERE, 80)
        try {
            manager.onEnsureLoaded { "should_not_load" }
            fail("Expected IllegalStateException when thermal status is SEVERE")
        } catch (_: IllegalStateException) {
            // Expected
        }
    }
}

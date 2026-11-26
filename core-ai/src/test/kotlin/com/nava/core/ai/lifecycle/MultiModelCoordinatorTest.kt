package com.nava.core.ai.lifecycle

import com.nava.core.ai.testing.FakeHardwareStatusProvider
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MultiModelCoordinatorTest {

    private val gb = 1024L * 1024L * 1024L

    @Test
    fun allowsCoexistenceWhenRamAndThermalsAreHealthy() = runTest {
        val provider = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(
                totalRamBytes = 8L * gb,
                thermalStatusCode = ThermalModelLifecycleManager.THERMAL_STATUS_NONE,
                batteryLevelPercent = 85,
                availableRamBytes = 3L * gb,
                isLowMemory = false
            )
        )
        val coordinator = MultiModelCoordinator(provider)
        val unloaded = mutableListOf<ModelSlot>()
        for (slot in ModelSlot.entries) {
            coordinator.registerUnloader(slot) { unloaded.add(slot) }
        }

        coordinator.onBeforeLoad(ModelSlot.FUNCTION_ROUTER)
        coordinator.onBeforeLoad(ModelSlot.EMBEDDING_ENGINE)
        coordinator.onBeforeLoad(ModelSlot.PRIMARY_LLM)

        assertTrue(unloaded.isEmpty())
        assertTrue(coordinator.isSlotActive(ModelSlot.PRIMARY_LLM))
        assertTrue(coordinator.isSlotActive(ModelSlot.FUNCTION_ROUTER))
        assertTrue(coordinator.isSlotActive(ModelSlot.EMBEDDING_ENGINE))
    }

    @Test
    fun enforcesMutualExclusionOnTier0LowMemoryModerateThermalAndLowAvailRam() = runTest {
        val provider = FakeHardwareStatusProvider()
        val coordinator = MultiModelCoordinator(provider)
        val unloaded = mutableListOf<ModelSlot>()
        for (slot in ModelSlot.entries) {
            coordinator.registerUnloader(slot) { unloaded.add(slot) }
        }

        // 1. TIER_0_LOW_MEMORY
        provider.snapshot = DeviceHardwareSnapshot(
            totalRamBytes = 4L * gb,
            thermalStatusCode = ThermalModelLifecycleManager.THERMAL_STATUS_NONE,
            batteryLevelPercent = 80,
            availableRamBytes = 2L * gb,
            isLowMemory = false
        )
        coordinator.onBeforeLoad(ModelSlot.PRIMARY_LLM)
        assertEquals(setOf(ModelSlot.FUNCTION_ROUTER, ModelSlot.EMBEDDING_ENGINE), unloaded.toSet())
        assertTrue(coordinator.isSlotActive(ModelSlot.PRIMARY_LLM))
        assertFalse(coordinator.isSlotActive(ModelSlot.FUNCTION_ROUTER))

        // 2. isLowMemory == true
        unloaded.clear()
        provider.snapshot = DeviceHardwareSnapshot(
            totalRamBytes = 8L * gb,
            thermalStatusCode = ThermalModelLifecycleManager.THERMAL_STATUS_NONE,
            batteryLevelPercent = 80,
            availableRamBytes = 2L * gb,
            isLowMemory = true
        )
        coordinator.onBeforeLoad(ModelSlot.FUNCTION_ROUTER)
        assertEquals(setOf(ModelSlot.PRIMARY_LLM, ModelSlot.EMBEDDING_ENGINE), unloaded.toSet())

        // 3. availableRamBytes < 1_200_000_000L
        unloaded.clear()
        provider.snapshot = DeviceHardwareSnapshot(
            totalRamBytes = 8L * gb,
            thermalStatusCode = ThermalModelLifecycleManager.THERMAL_STATUS_NONE,
            batteryLevelPercent = 80,
            availableRamBytes = 1_100_000_000L,
            isLowMemory = false
        )
        coordinator.onBeforeLoad(ModelSlot.EMBEDDING_ENGINE)
        assertEquals(setOf(ModelSlot.PRIMARY_LLM, ModelSlot.FUNCTION_ROUTER), unloaded.toSet())

        // 4. ThermalState.MODERATE
        unloaded.clear()
        provider.snapshot = DeviceHardwareSnapshot(
            totalRamBytes = 12L * gb,
            thermalStatusCode = ThermalModelLifecycleManager.THERMAL_STATUS_MODERATE,
            batteryLevelPercent = 80,
            availableRamBytes = 4L * gb,
            isLowMemory = false
        )
        coordinator.onBeforeLoad(ModelSlot.PRIMARY_LLM)
        assertEquals(setOf(ModelSlot.FUNCTION_ROUTER, ModelSlot.EMBEDDING_ENGINE), unloaded.toSet())
    }

    @Test
    fun unloadsAllThreeEnginesOnSevereThermal() = runTest {
        val provider = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(
                totalRamBytes = 12L * gb,
                thermalStatusCode = ThermalModelLifecycleManager.THERMAL_STATUS_SEVERE,
                batteryLevelPercent = 90,
                availableRamBytes = 5L * gb,
                isLowMemory = false
            )
        )
        val coordinator = MultiModelCoordinator(provider)
        val unloaded = mutableListOf<ModelSlot>()
        for (slot in ModelSlot.entries) {
            coordinator.registerUnloader(slot) { unloaded.add(slot) }
        }

        coordinator.onBeforeLoad(ModelSlot.FUNCTION_ROUTER)
        assertEquals(ModelSlot.entries.toSet(), unloaded.toSet())
        assertFalse(coordinator.isSlotActive(ModelSlot.PRIMARY_LLM))
        assertFalse(coordinator.isSlotActive(ModelSlot.FUNCTION_ROUTER))
        assertFalse(coordinator.isSlotActive(ModelSlot.EMBEDDING_ENGINE))
    }
}

package com.nava.core.ai.lifecycle

import com.nava.domain.ai.RamTier
import com.nava.domain.ai.ThermalState
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap

/**
 * Slots for native AI engines managed by [MultiModelCoordinator].
 */
enum class ModelSlot {
    PRIMARY_LLM,
    FUNCTION_ROUTER,
    EMBEDDING_ENGINE
}

/**
 * Coordinates memory residency across [ModelSlot]s so Gemma 4 E2B, FunctionGemma, and
 * EmbeddingGemma 2 respect RAM, low-memory, and thermal constraints without OOM thrashing.
 */
class MultiModelCoordinator(
    private val hardwareStatusProvider: DeviceHardwareStatusProvider
) {
    private val coordinatorMutex = Mutex()
    private val unloaders = ConcurrentHashMap<ModelSlot, suspend () -> Unit>()
    private val activeSlots = ConcurrentHashMap.newKeySet<ModelSlot>()

    fun registerUnloader(slot: ModelSlot, unloader: suspend () -> Unit) {
        unloaders[slot] = unloader
    }

    fun unregisterUnloader(slot: ModelSlot) {
        unloaders.remove(slot)
        activeSlots.remove(slot)
    }

    fun markLoaded(slot: ModelSlot) {
        activeSlots.add(slot)
    }

    fun markUnloaded(slot: ModelSlot) {
        activeSlots.remove(slot)
    }

    fun isSlotActive(slot: ModelSlot): Boolean = slot in activeSlots

    fun isMemoryOrThermalConstrained(): Boolean {
        val snapshot = hardwareStatusProvider.readSnapshot()
        val thermalState = resolveThermalState(snapshot)
        val ramTier = RamTier.fromTotalRamBytes(snapshot.totalRamBytes)
        return isConstrained(snapshot, ramTier, thermalState)
    }

    /**
     * Enforces thermal and memory mutual-exclusion rules before loading [slot].
     *
     * Lock ordering invariant: `coordinatorMutex` is always acquired outside any engine's
     * `inferenceMutex`, preventing AB-BA deadlocks when unloading peer engines.
     */
    suspend fun onBeforeLoad(slot: ModelSlot) {
        coordinatorMutex.withLock {
            val snapshot = hardwareStatusProvider.readSnapshot()
            val thermalState = resolveThermalState(snapshot)
            val ramTier = RamTier.fromTotalRamBytes(snapshot.totalRamBytes)

            if (thermalState == ThermalState.SEVERE_OR_HIGHER) {
                unloadAllLocked()
                return
            }

            if (isConstrained(snapshot, ramTier, thermalState)) {
                for (candidate in ModelSlot.entries) {
                    if (candidate != slot) {
                        unloadSlotLocked(candidate)
                    }
                }
            }

            activeSlots.add(slot)
        }
    }

    suspend fun unloadAll() {
        coordinatorMutex.withLock {
            unloadAllLocked()
        }
    }

    private suspend fun unloadAllLocked() {
        for (slot in ModelSlot.entries) {
            unloadSlotLocked(slot)
        }
    }

    private suspend fun unloadSlotLocked(slot: ModelSlot) {
        activeSlots.remove(slot)
        unloaders[slot]?.invoke()
    }

    private fun isConstrained(
        snapshot: DeviceHardwareSnapshot,
        ramTier: RamTier,
        thermalState: ThermalState
    ): Boolean {
        return ramTier == RamTier.TIER_0_LOW_MEMORY ||
            thermalState == ThermalState.MODERATE ||
            snapshot.isLowMemory ||
            snapshot.availableRamBytes < LOW_AVAILABLE_RAM_BYTES
    }

    private fun resolveThermalState(snapshot: DeviceHardwareSnapshot): ThermalState {
        return when {
            snapshot.thermalStatusCode >= ThermalModelLifecycleManager.THERMAL_STATUS_SEVERE ->
                ThermalState.SEVERE_OR_HIGHER

            snapshot.thermalStatusCode >= ThermalModelLifecycleManager.THERMAL_STATUS_MODERATE ||
                snapshot.batteryLevelPercent in 0 until ThermalModelLifecycleManager.LOW_BATTERY_THRESHOLD_PERCENT ->
                ThermalState.MODERATE

            else -> ThermalState.NORMAL
        }
    }

    companion object {
        const val LOW_AVAILABLE_RAM_BYTES: Long = 1_200_000_000L
    }
}

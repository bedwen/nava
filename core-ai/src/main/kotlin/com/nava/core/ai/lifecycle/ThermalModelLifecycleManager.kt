package com.nava.core.ai.lifecycle

import android.app.ActivityManager
import android.content.Context
import android.os.BatteryManager
import android.os.PowerManager
import com.nava.domain.ai.RamTier
import com.nava.domain.ai.ThermalState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Pure Kotlin hardware telemetry snapshot decoupled from Android framework singletons
 * for deterministic JVM testing (PLAN.md Section 2.3).
 */
data class DeviceHardwareSnapshot(
    val totalRamBytes: Long,
    val thermalStatusCode: Int,
    val batteryLevelPercent: Int,
    val availableRamBytes: Long = totalRamBytes / 2,
    val isLowMemory: Boolean = false
) {
    init {
        require(totalRamBytes >= 0L) { "totalRamBytes must be non-negative, got $totalRamBytes" }
        require(availableRamBytes >= 0L) { "availableRamBytes must be non-negative, got $availableRamBytes" }
    }
}

/**
 * Port providing live RAM, thermal status, and battery level readings.
 */
interface DeviceHardwareStatusProvider {
    fun readSnapshot(): DeviceHardwareSnapshot
}

/**
 * Android API 31+ implementation backed by [ActivityManager], [PowerManager], and [BatteryManager].
 */
class AndroidDeviceHardwareStatusProvider(
    private val context: Context
) : DeviceHardwareStatusProvider {

    override fun readSnapshot(): DeviceHardwareSnapshot {
        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memoryInfo = ActivityManager.MemoryInfo()
        activityManager.getMemoryInfo(memoryInfo)

        val powerManager = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        val normalizedThermal = mapPlatformThermalStatus(powerManager.currentThermalStatus)

        val batteryManager = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        val rawBattery = batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
        val batteryLevel = if (rawBattery in 0..100) rawBattery else UNKNOWN_BATTERY_PERCENT

        return DeviceHardwareSnapshot(
            totalRamBytes = memoryInfo.totalMem.coerceAtLeast(0L),
            thermalStatusCode = normalizedThermal,
            batteryLevelPercent = batteryLevel,
            availableRamBytes = memoryInfo.availMem.coerceAtLeast(0L),
            isLowMemory = memoryInfo.lowMemory
        )
    }

    private fun mapPlatformThermalStatus(platformCode: Int): Int {
        return when {
            platformCode >= PowerManager.THERMAL_STATUS_SEVERE -> ThermalModelLifecycleManager.THERMAL_STATUS_SEVERE
            platformCode >= PowerManager.THERMAL_STATUS_MODERATE -> ThermalModelLifecycleManager.THERMAL_STATUS_MODERATE
            platformCode >= PowerManager.THERMAL_STATUS_LIGHT -> ThermalModelLifecycleManager.THERMAL_STATUS_LIGHT
            else -> ThermalModelLifecycleManager.THERMAL_STATUS_NONE
        }
    }

    companion object {
        private const val UNKNOWN_BATTERY_PERCENT: Int = -1
    }
}

/**
 * Manages Gemma 4 `.litertlm` residency, contiguous RAM tiering, thermal/battery throttling,
 * and thread-safe idle unload scheduling (PLAN.md Section 2.3).
 */
class ThermalModelLifecycleManager(
    private val hardwareStatusProvider: DeviceHardwareStatusProvider,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
) {
    /**
     * One instance is shared by every [ModelSlot] (primary LLM, FunctionGemma router,
     * EmbeddingGemma). Residency state is therefore tracked per slot, so a turn on one model never
     * cancels or invalidates the idle unload of another model.
     */
    private class SlotResidency {
        var idleUnloadJob: Job? = null
        var generation: Long = 0L
        var modelLoaded: Boolean = false
    }

    private val mutex = Mutex()
    private val residencyBySlot: Map<ModelSlot, SlotResidency> =
        ModelSlot.entries.associateWith { SlotResidency() }

    private fun residency(slot: ModelSlot): SlotResidency = residencyBySlot.getValue(slot)

    /** Returns true when [slot] is marked resident (test and diagnostics hook). */
    suspend fun isSlotResident(slot: ModelSlot): Boolean = mutex.withLock {
        residency(slot).modelLoaded
    }

    /** Returns true when [slot] has an armed idle unload timer (test and diagnostics hook). */
    suspend fun hasPendingIdleUnload(slot: ModelSlot): Boolean = mutex.withLock {
        residency(slot).idleUnloadJob?.isActive == true
    }

    fun currentRamTier(): RamTier {
        val snapshot = hardwareStatusProvider.readSnapshot()
        return RamTier.fromTotalRamBytes(snapshot.totalRamBytes)
    }

    fun currentThermalState(): ThermalState {
        val snapshot = hardwareStatusProvider.readSnapshot()
        return when {
            snapshot.thermalStatusCode >= THERMAL_STATUS_SEVERE -> ThermalState.SEVERE_OR_HIGHER
            snapshot.thermalStatusCode >= THERMAL_STATUS_MODERATE ||
                snapshot.batteryLevelPercent in 0 until LOW_BATTERY_THRESHOLD_PERCENT -> ThermalState.MODERATE

            else -> ThermalState.NORMAL
        }
    }

    /** Returns false under [ThermalState.SEVERE_OR_HIGHER] (routes Tiers 1 and 2 only). */
    fun canRunLlm(): Boolean {
        return currentThermalState() != ThermalState.SEVERE_OR_HIGHER
    }

    /**
     * Bounded Thought Mode is disabled under [ThermalState.MODERATE], [ThermalState.SEVERE_OR_HIGHER],
     * or [RamTier.TIER_0_LOW_MEMORY].
     */
    fun isThoughtModeAllowed(): Boolean {
        return currentThermalState() == ThermalState.NORMAL &&
            currentRamTier() != RamTier.TIER_0_LOW_MEMORY
    }

    /** Returns the active KV-cache context token ceiling for the current RAM tier. */
    fun effectiveContextTokens(): Int {
        return currentRamTier().defaultContextTokens
    }

    /**
     * Returns `0` (immediate post-turn unload) on [RamTier.TIER_0_LOW_MEMORY] or any non-normal
     * thermal/battery state; otherwise returns the RAM tier's idle timeout (`180` seconds).
     */
    fun effectiveIdleUnloadTimeoutSec(): Int {
        val ramTier = currentRamTier()
        val thermalState = currentThermalState()
        return if (ramTier == RamTier.TIER_0_LOW_MEMORY || thermalState != ThermalState.NORMAL) {
            0
        } else {
            ramTier.idleUnloadTimeoutSec
        }
    }

    /**
     * Cancels any pending idle unload timer of [slot], verifies thermal eligibility, advances the
     * slot's turn generation counter, and invokes [loader] under [mutex] synchronization.
     */
    suspend fun <T> onEnsureLoaded(
        slot: ModelSlot = ModelSlot.PRIMARY_LLM,
        loader: suspend () -> T
    ): T {
        return mutex.withLock {
            val state = residency(slot)
            cancelIdleTimerLocked(state)
            if (!canRunLlm()) {
                throw IllegalStateException("Thermal throttling SEVERE prevents loading LLM")
            }
            state.generation++
            val result = loader()
            state.modelLoaded = true
            result
        }
    }

    /**
     * Called when an inference turn on [slot] finishes. Unloads immediately if the effective idle
     * timeout is `0` or thermal state is `SEVERE_OR_HIGHER`; otherwise arms a cancellable idle timer.
     *
     * Never invokes [unloader] while holding [mutex], preserving a deadlock-free lock hierarchy.
     */
    suspend fun onTurnCompleted(
        slot: ModelSlot = ModelSlot.PRIMARY_LLM,
        unloader: suspend () -> Unit
    ) {
        onTurnCompleted(
            slot = slot,
            immediateUnloader = unloader,
            deferredIdleUnloader = { expectedGen ->
                if (consumePendingIdleUnload(slot, expectedGen)) {
                    unloader()
                }
            }
        )
    }

    /**
     * Overload separating immediate post-turn unloading (invoked outside [mutex] on the caller's
     * coroutine) from asynchronous idle-timer unloading (invoked outside [mutex] after the idle
     * delay so callers such as `LiteRtLlmEngine` can acquire `inferenceMutex` BEFORE checking
     * [consumePendingIdleUnload], guaranteeing strict `inferenceMutex -> lifecycleManager.mutex`
     * lock ordering).
     *
     * [minimumIdleTimeoutSec] lets bursty callers (e.g. embedding a batch of tool descriptions)
     * keep weights resident for a short grace window instead of reloading them on every call.
     * It never delays the immediate unload required under `SEVERE_OR_HIGHER` thermal state.
     */
    suspend fun onTurnCompleted(
        slot: ModelSlot = ModelSlot.PRIMARY_LLM,
        immediateUnloader: suspend () -> Unit,
        deferredIdleUnloader: suspend (expectedGeneration: Long) -> Unit,
        minimumIdleTimeoutSec: Int = 0
    ) {
        val shouldUnloadImmediately: Boolean = mutex.withLock {
            val state = residency(slot)
            cancelIdleTimerLocked(state)
            val expectedGen = state.generation
            val timeoutSec = maxOf(effectiveIdleUnloadTimeoutSec(), minimumIdleTimeoutSec)
            if (timeoutSec <= 0 || currentThermalState() == ThermalState.SEVERE_OR_HIGHER) {
                state.modelLoaded = false
                state.generation++
                true
            } else {
                val delayMs = timeoutSec.toLong() * 1000L
                state.idleUnloadJob = scope.launch {
                    delay(delayMs)
                    if (!isActive) return@launch
                    deferredIdleUnloader(expectedGen)
                }
                false
            }
        }

        if (shouldUnloadImmediately) {
            immediateUnloader()
        }
    }

    /**
     * Atomically verifies that [expectedGeneration] is still the latest active generation of
     * [slot] and marks it unloaded. Returns `true` only if the caller should proceed with
     * unloading native weights, preventing a stale idle timer from evicting a newly loaded turn.
     */
    suspend fun consumePendingIdleUnload(
        slot: ModelSlot,
        expectedGeneration: Long
    ): Boolean {
        return mutex.withLock {
            val state = residency(slot)
            if (state.generation != expectedGeneration) {
                return@withLock false
            }
            state.idleUnloadJob = null
            state.modelLoaded = false
            state.generation++
            true
        }
    }

    /** Primary-slot shorthand for [consumePendingIdleUnload]. */
    suspend fun consumePendingIdleUnload(expectedGeneration: Long): Boolean =
        consumePendingIdleUnload(ModelSlot.PRIMARY_LLM, expectedGeneration)

    /**
     * Immediately cancels any pending idle unload timer of [slot], invalidates its prior
     * generations, and executes [unloader] OUTSIDE [mutex].
     */
    suspend fun forceUnload(
        slot: ModelSlot = ModelSlot.PRIMARY_LLM,
        unloader: suspend () -> Unit
    ) {
        mutex.withLock {
            val state = residency(slot)
            cancelIdleTimerLocked(state)
            state.modelLoaded = false
            state.generation++
        }
        unloader()
    }

    private fun cancelIdleTimerLocked(state: SlotResidency) {
        state.idleUnloadJob?.cancel()
        state.idleUnloadJob = null
    }

    companion object {
        const val THERMAL_STATUS_NONE: Int = 0
        const val THERMAL_STATUS_LIGHT: Int = 1
        const val THERMAL_STATUS_MODERATE: Int = 2
        const val THERMAL_STATUS_SEVERE: Int = 4
        const val LOW_BATTERY_THRESHOLD_PERCENT: Int = 15
    }
}

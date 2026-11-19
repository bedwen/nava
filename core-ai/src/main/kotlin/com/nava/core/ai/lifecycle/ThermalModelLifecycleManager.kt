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
    val batteryLevelPercent: Int
) {
    init {
        require(totalRamBytes >= 0L) { "totalRamBytes must be non-negative, got $totalRamBytes" }
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
            batteryLevelPercent = batteryLevel
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
    private val mutex = Mutex()
    private var idleUnloadJob: Job? = null
    private var generation: Long = 0L
    private var modelLoaded: Boolean = false

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
     * Cancels any pending idle unload timer, verifies thermal eligibility, advances the turn
     * generation counter, and invokes [loader] under [mutex] synchronization.
     */
    suspend fun <T> onEnsureLoaded(loader: suspend () -> T): T {
        return mutex.withLock {
            cancelIdleTimerLocked()
            if (!canRunLlm()) {
                throw IllegalStateException("Thermal throttling SEVERE prevents loading LLM")
            }
            generation++
            val result = loader()
            modelLoaded = true
            result
        }
    }

    /**
     * Called when an inference turn finishes. Unloads immediately if the effective idle timeout
     * is `0` or thermal state is `SEVERE_OR_HIGHER`; otherwise arms a cancellable idle timer.
     *
     * Never invokes [unloader] while holding [mutex], preserving a deadlock-free lock hierarchy.
     */
    suspend fun onTurnCompleted(unloader: suspend () -> Unit) {
        onTurnCompleted(
            immediateUnloader = unloader,
            deferredIdleUnloader = { expectedGen ->
                if (consumePendingIdleUnload(expectedGen)) {
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
     */
    suspend fun onTurnCompleted(
        immediateUnloader: suspend () -> Unit,
        deferredIdleUnloader: suspend (expectedGeneration: Long) -> Unit
    ) {
        val shouldUnloadImmediately: Boolean = mutex.withLock {
            cancelIdleTimerLocked()
            val expectedGen = generation
            val timeoutSec = effectiveIdleUnloadTimeoutSec()
            if (timeoutSec <= 0 || currentThermalState() == ThermalState.SEVERE_OR_HIGHER) {
                modelLoaded = false
                generation++
                true
            } else {
                val delayMs = timeoutSec.toLong() * 1000L
                idleUnloadJob = scope.launch {
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
     * Atomically verifies that [expectedGeneration] is still the latest active generation and
     * marks the model unloaded. Returns `true` only if the caller should proceed with unloading
     * native weights, preventing a stale idle timer from evicting a newly loaded turn.
     */
    suspend fun consumePendingIdleUnload(expectedGeneration: Long): Boolean {
        return mutex.withLock {
            if (generation != expectedGeneration) {
                return@withLock false
            }
            idleUnloadJob = null
            modelLoaded = false
            generation++
            true
        }
    }

    /**
     * Immediately cancels any pending idle unload timer, invalidates prior generations, and
     * executes [unloader] OUTSIDE [mutex].
     */
    suspend fun forceUnload(unloader: suspend () -> Unit) {
        mutex.withLock {
            cancelIdleTimerLocked()
            modelLoaded = false
            generation++
        }
        unloader()
    }

    private fun cancelIdleTimerLocked() {
        idleUnloadJob?.cancel()
        idleUnloadJob = null
    }

    companion object {
        const val THERMAL_STATUS_NONE: Int = 0
        const val THERMAL_STATUS_LIGHT: Int = 1
        const val THERMAL_STATUS_MODERATE: Int = 2
        const val THERMAL_STATUS_SEVERE: Int = 4
        const val LOW_BATTERY_THRESHOLD_PERCENT: Int = 15
    }
}

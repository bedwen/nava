package com.nava.domain.ui

import com.nava.domain.ai.ThermalState

/**
 * Immutable state snapshot consumed by the 0-FPS/Zero-Allocation Dual-Core Neural Canvas.
 */
data class NeuralCanvasState(
    val coreState: CoreActivityState = CoreActivityState.IDLE,
    val activeNeurons: Set<NeuronNodeId> = emptySet(),
    val activePulse: NeuralPulseEvent? = null,
    val isVaultUnlocked: Boolean = false,
    val thermalState: ThermalState = ThermalState.NORMAL,
    val isModelResident: Boolean = false
) {
    /**
     * When true, the Neural Canvas stops subscribing to animation frames and sleeps at 0 FPS.
     */
    val isIdle: Boolean
        get() = coreState == CoreActivityState.IDLE && activePulse == null
}

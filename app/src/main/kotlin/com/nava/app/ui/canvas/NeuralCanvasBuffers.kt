package com.nava.app.ui.canvas

import com.nava.domain.ui.NeuronNodeId

/**
 * Fixed-size primitive [FloatArray] geometry and animation buffers for the Dual-Core Neural Canvas.
 *
 * Allocated ONCE via `remember` outside any draw pass and mutated strictly in-place so the
 * rendering loop performs zero heap allocations per frame (Iron Law 7 / Gate 1 Rule 4).
 */
class NeuralCanvasBuffers {
    val nodeX: FloatArray = FloatArray(NEURON_COUNT)
    val nodeY: FloatArray = FloatArray(NEURON_COUNT)
    val nodeRadii: FloatArray = FloatArray(NEURON_COUNT)
    val nodeGlowAlpha: FloatArray = FloatArray(NEURON_COUNT)
    val nodeLabelY: FloatArray = FloatArray(NEURON_COUNT)

    val edgeStartX: FloatArray = FloatArray(NEURON_COUNT)
    val edgeStartY: FloatArray = FloatArray(NEURON_COUNT)
    val edgeEndX: FloatArray = FloatArray(NEURON_COUNT)
    val edgeEndY: FloatArray = FloatArray(NEURON_COUNT)
    val edgeAlpha: FloatArray = FloatArray(NEURON_COUNT)

    val pulsePointsX: FloatArray = FloatArray(PULSE_TRAIL_SAMPLES)
    val pulsePointsY: FloatArray = FloatArray(PULSE_TRAIL_SAMPLES)
    val pulsePointsAlpha: FloatArray = FloatArray(PULSE_TRAIL_SAMPLES)

    val ringRadii: FloatArray = FloatArray(RING_COUNT)

    val formattedLabels: Array<String> = Array(NEURON_COUNT) { NEURON_NODES[it].name }

    var lastWidth: Float = -1f
    var lastHeight: Float = -1f
    var centerX: Float = 0f
    var centerY: Float = 0f
    var minDimension: Float = 0f
    var labelTextSizePx: Float = 24f
    var layoutComputeCount: Int = 0

    var activeNeuronMask: Int = 0
    var corePhaseRadians: Float = 0f
    var outerShellPulseAlpha: Float = 0f
    var innerCoreGlowAlpha: Float = 0f
    var isInnerCoreAwake: Boolean = false
    var errorFlashAlpha: Float = 0f

    var activePulseEventId: String? = null
    var pulseProgress: Float = 0f
    var pulseActive: Boolean = false
    var pulseCompleted: Boolean = false
    var pulseCompletionDispatched: Boolean = false
    var pulseIsInterNeuron: Boolean = false
    var pulseSourceIndex: Int = -1
    var pulseTargetIndex: Int = -1
    var pulseStartX: Float = 0f
    var pulseStartY: Float = 0f
    var pulseControlX: Float = 0f
    var pulseControlY: Float = 0f
    var pulseEndX: Float = 0f
    var pulseEndY: Float = 0f
    var pulseHeadX: Float = 0f
    var pulseHeadY: Float = 0f
    var pulsePointCount: Int = 0

    var stepCount: Long = 0L

    fun isNeuronActive(index: Int): Boolean {
        return (activeNeuronMask and (1 shl index)) != 0
    }

    /**
     * Pre-formats all 8 neuron labels into the fixed [formattedLabels] array outside the draw
     * loop whenever labels or layout direction change.
     */
    fun updateFormattedLabels(
        neuronLabels: Map<NeuronNodeId, String>,
        wrap: (String) -> String
    ) {
        for (i in 0 until NEURON_COUNT) {
            val node = NEURON_NODES[i]
            val raw = neuronLabels[node]
            formattedLabels[i] = wrap(if (raw.isNullOrBlank()) node.name else raw)
        }
    }

    /**
     * Resets all transient pulse and glow animation fields back to deterministic 0-FPS idle values
     * without reallocating any buffer arrays.
     */
    fun resetAnimationToIdle() {
        corePhaseRadians = 0f
        outerShellPulseAlpha = 0f
        innerCoreGlowAlpha = 0f
        isInnerCoreAwake = false
        errorFlashAlpha = 0f

        activePulseEventId = null
        pulseProgress = 0f
        pulseActive = false
        pulseCompleted = false
        pulseCompletionDispatched = false
        pulseIsInterNeuron = false
        pulseSourceIndex = -1
        pulseTargetIndex = -1
        pulseStartX = 0f
        pulseStartY = 0f
        pulseControlX = 0f
        pulseControlY = 0f
        pulseEndX = 0f
        pulseEndY = 0f
        pulseHeadX = 0f
        pulseHeadY = 0f
        pulsePointCount = 0

        for (i in 0 until PULSE_TRAIL_SAMPLES) {
            pulsePointsX[i] = 0f
            pulsePointsY[i] = 0f
            pulsePointsAlpha[i] = 0f
        }
    }

    companion object {
        const val NEURON_COUNT: Int = 8
        const val PULSE_TRAIL_SAMPLES: Int = 24
        const val RING_COUNT: Int = 4

        const val RING_INNER_CORE: Int = 0
        const val RING_OUTER_SHELL: Int = 1
        const val RING_THERMAL: Int = 2
        const val RING_ORBIT: Int = 3

        val NEURON_NODES: Array<NeuronNodeId> = NeuronNodeId.entries.toTypedArray()

        init {
            check(NEURON_NODES.size == NEURON_COUNT) {
                "Expected $NEURON_COUNT NeuronNodeId entries but found ${NEURON_NODES.size}"
            }
        }

        fun indexOf(node: NeuronNodeId): Int = node.ordinal
    }
}

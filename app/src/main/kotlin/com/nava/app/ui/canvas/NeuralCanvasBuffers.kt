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
    val edgeControlX: FloatArray = FloatArray(NEURON_COUNT)
    val edgeControlY: FloatArray = FloatArray(NEURON_COUNT)
    val edgeAlpha: FloatArray = FloatArray(NEURON_COUNT)

    val pulsePointsX: FloatArray = FloatArray(PULSE_TRAIL_SAMPLES)
    val pulsePointsY: FloatArray = FloatArray(PULSE_TRAIL_SAMPLES)
    val pulsePointsAlpha: FloatArray = FloatArray(PULSE_TRAIL_SAMPLES)

    val returnPulsePointsX: FloatArray = FloatArray(PULSE_TRAIL_SAMPLES)
    val returnPulsePointsY: FloatArray = FloatArray(PULSE_TRAIL_SAMPLES)
    val returnPulsePointsAlpha: FloatArray = FloatArray(PULSE_TRAIL_SAMPLES)

    val ringRadii: FloatArray = FloatArray(RING_COUNT)

    val formattedLabels: Array<String> = Array(NEURON_COUNT) { NEURON_NODES[it].name }

    val visibleNodeIndices: IntArray = IntArray(MAX_NODES) { if (it < NEURON_COUNT) it else -1 }
    var visibleNodeCount: Int = NEURON_COUNT
    var visibleNodeMask: Int = (1 shl NEURON_COUNT) - 1
    var permittedNodeMask: Int = (1 shl NEURON_COUNT) - 1

    fun isNodePermitted(index: Int): Boolean {
        return (permittedNodeMask and (1 shl index)) != 0
    }

    fun setPermittedNodes(permittedNodes: Set<NeuronNodeId>?): Boolean {
        val nextMask = if (permittedNodes == null) {
            (1 shl NEURON_COUNT) - 1
        } else {
            var mask = 0
            for (i in 0 until NEURON_COUNT) {
                if (permittedNodes.contains(NEURON_NODES[i])) {
                    mask = mask or (1 shl i)
                }
            }
            mask
        }
        val changed = nextMask != permittedNodeMask
        permittedNodeMask = nextMask
        return changed
    }

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

    var returnPulseProgress: Float = 0f
    var returnPulseActive: Boolean = false
    var returnPulseHeadX: Float = 0f
    var returnPulseHeadY: Float = 0f
    var returnPulsePointCount: Int = 0
    var coreConfirmRingAlpha: Float = 0f

    var stepCount: Long = 0L

    fun isNeuronActive(index: Int): Boolean {
        return (activeNeuronMask and (1 shl index)) != 0
    }

    fun isNodeVisible(index: Int): Boolean {
        return index in 0 until NEURON_COUNT && (visibleNodeMask and (1 shl index)) != 0
    }

    /**
     * Deduplicates and copies up to [MAX_VISIBLE_RING_NODES] (`<= NEURON_COUNT`) ordinals into
     * [visibleNodeIndices] in-place without allocating any collections.
     *
     * @return true if the visible node list changed and layout should be recomputed.
     */
    fun setVisibleNodes(nodes: List<NeuronNodeId>): Boolean {
        val cap = if (MAX_VISIBLE_RING_NODES < NEURON_COUNT) MAX_VISIBLE_RING_NODES else NEURON_COUNT
        var seenMask = 0
        var newCount = 0
        var changed = false

        for (i in 0 until nodes.size) {
            if (newCount >= cap) {
                break
            }
            val ordinal = nodes[i].ordinal
            if (ordinal < 0 || ordinal >= NEURON_COUNT) {
                continue
            }
            val bit = 1 shl ordinal
            if ((seenMask and bit) != 0) {
                continue
            }
            seenMask = seenMask or bit
            if (visibleNodeIndices[newCount] != ordinal) {
                visibleNodeIndices[newCount] = ordinal
                changed = true
            }
            newCount += 1
        }

        if (newCount != visibleNodeCount) {
            changed = true
        }

        for (slot in newCount until MAX_NODES) {
            if (visibleNodeIndices[slot] != -1) {
                visibleNodeIndices[slot] = -1
            }
        }

        visibleNodeCount = newCount
        visibleNodeMask = seenMask
        return changed
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

        returnPulseProgress = 0f
        returnPulseActive = false
        returnPulseHeadX = 0f
        returnPulseHeadY = 0f
        returnPulsePointCount = 0
        coreConfirmRingAlpha = 0f

        for (i in 0 until PULSE_TRAIL_SAMPLES) {
            pulsePointsX[i] = 0f
            pulsePointsY[i] = 0f
            pulsePointsAlpha[i] = 0f
            returnPulsePointsX[i] = 0f
            returnPulsePointsY[i] = 0f
            returnPulsePointsAlpha[i] = 0f
        }
    }

    companion object {
        const val MAX_NODES: Int = 16
        const val MAX_VISIBLE_RING_NODES: Int = 8
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

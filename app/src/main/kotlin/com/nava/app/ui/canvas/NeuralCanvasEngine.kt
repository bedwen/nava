package com.nava.app.ui.canvas

import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Fill
import androidx.compose.ui.graphics.nativeCanvas
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.ThermalState
import com.nava.domain.ui.CoreActivityState
import com.nava.domain.ui.NeuralCanvasState
import com.nava.domain.ui.NeuralPulseEvent
import com.nava.domain.ui.NeuronNodeId
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.hypot
import kotlin.math.sin

/**
 * Pure primitive geometry, animation stepping, hit-testing, and zero-allocation DrawScope
 * renderer for the Dual-Core Neural Canvas.
 *
 * All state is mutated in-place inside [NeuralCanvasBuffers]. No heap allocations occur during
 * [syncLayoutIfNeeded], [syncVisualState], [stepFrame], [hitTestNeuron], or [render].
 */
class NeuralCanvasEngine {

    /**
     * Recomputes radial neuron coordinates, hub rings, and synapse edge endpoints ONLY when the
     * canvas dimensions change or [forceRecompute] is true (e.g. after visible nodes change).
     *
     * @return true if layout was recomputed, false if dimensions were unchanged or non-positive.
     */
    fun syncLayoutIfNeeded(
        width: Float,
        height: Float,
        buffers: NeuralCanvasBuffers,
        forceRecompute: Boolean = false,
        ellipticalLayout: Boolean = false
    ): Boolean {
        if (width <= 0f || height <= 0f) {
            return false
        }
        if (!forceRecompute && width == buffers.lastWidth && height == buffers.lastHeight) {
            return false
        }

        buffers.lastWidth = width
        buffers.lastHeight = height

        val cx = width * 0.5f
        val cy = if (ellipticalLayout) height * 0.46f else height * 0.5f
        val minDim = if (width < height) width else height
        buffers.centerX = cx
        buffers.centerY = cy
        buffers.minDimension = minDim

        val innerCoreRadius = if (ellipticalLayout) minDim * 0.044f else minDim * INNER_CORE_RADIUS_RATIO
        val outerShellRadius = if (ellipticalLayout) minDim * 0.088f else minDim * OUTER_SHELL_RADIUS_RATIO
        val thermalRingRadius = if (ellipticalLayout) minDim * 0.110f else minDim * THERMAL_RING_RADIUS_RATIO
        val orbitRadius = minDim * ORBIT_RADIUS_RATIO
        val nodeRadius = if (ellipticalLayout) minDim * 0.076f else minDim * NODE_RADIUS_RATIO
        val labelOffset = if (ellipticalLayout) minDim * 0.048f else minDim * LABEL_OFFSET_RATIO

        buffers.ringRadii[NeuralCanvasBuffers.RING_INNER_CORE] = innerCoreRadius
        buffers.ringRadii[NeuralCanvasBuffers.RING_OUTER_SHELL] = outerShellRadius
        buffers.ringRadii[NeuralCanvasBuffers.RING_THERMAL] = thermalRingRadius
        buffers.ringRadii[NeuralCanvasBuffers.RING_ORBIT] = orbitRadius
        buffers.labelTextSizePx = (minDim * (if (ellipticalLayout) 0.036f else LABEL_TEXT_SIZE_RATIO))
            .coerceIn(MIN_LABEL_PX, MAX_LABEL_PX)

        // Default all node coordinates to hub center so hidden nodes never project to (0, 0).
        for (i in 0 until NeuralCanvasBuffers.NEURON_COUNT) {
            buffers.nodeX[i] = cx
            buffers.nodeY[i] = cy
            buffers.nodeRadii[i] = nodeRadius
            buffers.nodeLabelY[i] = cy + nodeRadius + labelOffset
        }

        val visibleCount = buffers.visibleNodeCount
        if (visibleCount > 0) {
            val angleStep = (2.0 * PI) / visibleCount.toDouble()
            val edgeEndRadius = orbitRadius - nodeRadius
            val rxMax = (width * 0.345f).coerceAtMost(width * 0.5f - nodeRadius - 18f)
            val ryMax = (height * 0.315f).coerceAtMost(cy - nodeRadius - 10f)
            val startGap = if (ellipticalLayout) minDim * 0.024f else 0f

            for (slot in 0 until visibleCount) {
                val idx = buffers.visibleNodeIndices[slot]
                if (idx < 0 || idx >= NeuralCanvasBuffers.NEURON_COUNT) {
                    continue
                }
                val angle = START_ANGLE_RAD + slot * angleStep
                val cosA = cos(angle).toFloat()
                val sinA = sin(angle).toFloat()

                val nx = if (ellipticalLayout) cx + rxMax * cosA else cx + orbitRadius * cosA
                val ny = if (ellipticalLayout) cy + ryMax * sinA else cy + orbitRadius * sinA
                buffers.nodeX[idx] = nx
                buffers.nodeY[idx] = ny
                buffers.nodeRadii[idx] = nodeRadius
                buffers.nodeLabelY[idx] = ny + nodeRadius + labelOffset

                val sx = cx + (outerShellRadius + startGap) * cosA
                val sy = cy + (outerShellRadius + startGap) * sinA
                val ex = if (ellipticalLayout) {
                    nx
                } else {
                    cx + edgeEndRadius * cosA
                }
                val ey = if (ellipticalLayout) {
                    ny
                } else {
                    cy + edgeEndRadius * sinA
                }
                buffers.edgeStartX[idx] = sx
                buffers.edgeStartY[idx] = sy
                buffers.edgeEndX[idx] = ex
                buffers.edgeEndY[idx] = ey

                // Architectural quadratic Bezier control point matching reference curvature.
                val midX = (sx + ex) * 0.5f
                val midY = (sy + ey) * 0.5f
                if (ellipticalLayout) {
                    val bend = if (cosA >= 0f) -minDim * 0.044f else minDim * 0.044f
                    buffers.edgeControlX[idx] = midX + (-sinA) * bend
                    buffers.edgeControlY[idx] = midY + cosA * bend
                } else {
                    val dx = ex - sx
                    val dy = ey - sy
                    buffers.edgeControlX[idx] = midX - dy * EDGE_CURVE_FACTOR
                    buffers.edgeControlY[idx] = midY + dx * EDGE_CURVE_FACTOR
                }
            }
        }

        buffers.layoutComputeCount += 1

        if (buffers.pulseActive && buffers.pulseTargetIndex >= 0) {
            recomputeTrajectoryFromIndices(
                sourceIndex = buffers.pulseSourceIndex,
                targetIndex = buffers.pulseTargetIndex,
                wakesInnerCore = buffers.isInnerCoreAwake,
                buffers = buffers
            )
            samplePulseTrail(buffers)
            if (buffers.returnPulseActive) {
                sampleReturnPulseTrail(buffers)
            }
        }
        return true
    }

    /**
     * Enforces the Dual-Core visibility contract:
     * Gemma 4 Inner Core stays dark/asleep unless [CoreActivityState.INNER_CORE_ACTIVE] is active
     * or the current [NeuralPulseEvent.wakesInnerCore] is true.
     */
    fun shouldWakeInnerCore(state: NeuralCanvasState): Boolean {
        return state.coreState == CoreActivityState.INNER_CORE_ACTIVE ||
            state.activePulse?.wakesInnerCore == true
    }

    /**
     * Resets transient animation progress and glow state for 0-FPS idle sleep.
     */
    fun resetToIdle(buffers: NeuralCanvasBuffers) {
        buffers.resetAnimationToIdle()
    }

    /**
     * Synchronizes discrete state flags (active neuron bitmask, inner core sleep/wake flag, and
     * idle node/edge resting intensities) without allocating any iterators or objects.
     */
    fun syncVisualState(
        state: NeuralCanvasState,
        buffers: NeuralCanvasBuffers
    ) {
        var mask = 0
        val activeNeurons = state.activeNeurons
        for (i in 0 until NeuralCanvasBuffers.NEURON_COUNT) {
            if (activeNeurons.contains(NeuralCanvasBuffers.NEURON_NODES[i])) {
                mask = mask or (1 shl i)
            }
        }
        buffers.activeNeuronMask = mask

        val wakeInner = shouldWakeInnerCore(state)
        buffers.isInnerCoreAwake = wakeInner

        if (state.isIdle) {
            buffers.outerShellPulseAlpha = 0f
            buffers.innerCoreGlowAlpha = 0f
            buffers.errorFlashAlpha = 0f
            buffers.pulseActive = false
            buffers.pulsePointCount = 0
            buffers.returnPulseActive = false
            buffers.returnPulseProgress = 0f
            buffers.returnPulsePointCount = 0
            buffers.coreConfirmRingAlpha = 0f
            for (i in 0 until NeuralCanvasBuffers.NEURON_COUNT) {
                val active = buffers.isNeuronActive(i)
                buffers.nodeGlowAlpha[i] = if (active) IDLE_ACTIVE_NODE_GLOW else 0f
                buffers.edgeAlpha[i] = if (active) IDLE_ACTIVE_EDGE_ALPHA else IDLE_RESTING_EDGE_ALPHA
            }
        } else if (!wakeInner) {
            buffers.innerCoreGlowAlpha = 0f
        }
    }

    /**
     * Advances animation buffers by [deltaMs] milliseconds.
     *
     * When [NeuralCanvasState.isIdle] is true, performs zero advancement and keeps pulse progress
     * reset at 0f.
     *
     * @return the completed [NeuralPulseEvent.eventId] exactly once when a pulse finishes, else null.
     */
    fun stepFrame(
        deltaMs: Long,
        state: NeuralCanvasState,
        buffers: NeuralCanvasBuffers
    ): String? {
        if (state.isIdle) {
            resetToIdle(buffers)
            syncVisualState(state, buffers)
            return null
        }

        val clampedDeltaMs = deltaMs.coerceIn(0L, MAX_FRAME_DELTA_MS)
        val dtSec = clampedDeltaMs * 0.001f

        buffers.stepCount += 1L
        syncVisualState(state, buffers)

        var nextPhase = buffers.corePhaseRadians + dtSec * CORE_ANGULAR_SPEED_RAD_PER_SEC
        if (nextPhase >= TWO_PI_F) {
            nextPhase -= TWO_PI_F
        }
        buffers.corePhaseRadians = nextPhase

        val wave = 0.5f + 0.5f * sin(nextPhase.toDouble()).toFloat()
        buffers.outerShellPulseAlpha = 0.38f + 0.62f * wave

        if (buffers.isInnerCoreAwake) {
            val innerWave = 0.5f + 0.5f * sin((nextPhase * 1.35f).toDouble()).toFloat()
            buffers.innerCoreGlowAlpha = 0.48f + 0.52f * innerWave
        } else {
            buffers.innerCoreGlowAlpha = 0f
        }

        if (state.coreState == CoreActivityState.ERROR_FLASH) {
            val flashWave = 0.5f + 0.5f * sin((nextPhase * 3.0f).toDouble()).toFloat()
            buffers.errorFlashAlpha = 0.45f + 0.55f * flashWave
        } else {
            buffers.errorFlashAlpha = 0f
        }

        var completedEventId: String? = null
        val pulse = state.activePulse
        if (pulse == null) {
            buffers.activePulseEventId = null
            buffers.pulseProgress = 0f
            buffers.pulseActive = false
            buffers.pulseCompleted = false
            buffers.pulseCompletionDispatched = false
            buffers.pulseIsInterNeuron = false
            buffers.pulseSourceIndex = -1
            buffers.pulseTargetIndex = -1
            buffers.pulsePointCount = 0
            buffers.returnPulseActive = false
            buffers.returnPulseProgress = 0f
            buffers.returnPulsePointCount = 0
            buffers.coreConfirmRingAlpha = 0f
        } else {
            if (buffers.activePulseEventId != pulse.eventId) {
                buffers.activePulseEventId = pulse.eventId
                buffers.pulseProgress = 0f
                buffers.pulseCompleted = false
                buffers.pulseCompletionDispatched = false
                buffers.pulseActive = true
                buffers.returnPulseActive = false
                buffers.returnPulseProgress = 0f
                buffers.returnPulsePointCount = 0
                buffers.coreConfirmRingAlpha = 0f
            }

            configurePulseTrajectory(pulse, buffers)

            val durationMs = pulseDurationMsFor(pulse.tier)
            if (!buffers.pulseCompleted) {
                val updated = (buffers.pulseProgress + clampedDeltaMs.toFloat() / durationMs)
                    .coerceIn(0f, 1f)
                buffers.pulseProgress = updated
                if (updated >= 1f) {
                    buffers.pulseCompleted = true
                }
            }

            samplePulseTrail(buffers)

            // Bidirectional return confirmation wave for hub-to-node pulses.
            if (!buffers.pulseIsInterNeuron && buffers.pulseProgress >= RETURN_PULSE_START_PROGRESS) {
                val retProgress = (
                    (buffers.pulseProgress - RETURN_PULSE_START_PROGRESS) /
                        (1f - RETURN_PULSE_START_PROGRESS)
                    ).coerceIn(0f, 1f)
                buffers.returnPulseActive = true
                buffers.returnPulseProgress = retProgress
                sampleReturnPulseTrail(buffers)
                buffers.coreConfirmRingAlpha = if (retProgress > RETURN_RING_START_PROGRESS) {
                    ((retProgress - RETURN_RING_START_PROGRESS) / (1f - RETURN_RING_START_PROGRESS))
                        .coerceIn(0f, 1f)
                } else {
                    0f
                }
            } else {
                buffers.returnPulseActive = false
                buffers.returnPulseProgress = 0f
                buffers.returnPulsePointCount = 0
                buffers.coreConfirmRingAlpha = 0f
            }

            if (buffers.pulseCompleted && !buffers.pulseCompletionDispatched) {
                buffers.pulseCompletionDispatched = true
                completedEventId = pulse.eventId
            }
        }

        val pulseTarget = buffers.pulseTargetIndex
        val pulseSource = buffers.pulseSourceIndex
        val arrivalBoost = if (buffers.pulseActive && buffers.pulseProgress > 0.65f) {
            ((buffers.pulseProgress - 0.65f) / 0.35f).coerceIn(0f, 1f)
        } else {
            0f
        }

        for (i in 0 until NeuralCanvasBuffers.NEURON_COUNT) {
            val isExplicitActive = buffers.isNeuronActive(i)
            val isPulseTarget = buffers.pulseActive && i == pulseTarget
            val isPulseSource = buffers.pulseActive && i == pulseSource

            val glow = when {
                isPulseTarget -> (0.45f + 0.55f * arrivalBoost).coerceIn(0f, 1f)
                isPulseSource -> 0.55f
                isExplicitActive -> 0.40f + 0.30f * wave
                else -> 0f
            }
            buffers.nodeGlowAlpha[i] = glow

            val edge = when {
                isPulseTarget && !buffers.pulseIsInterNeuron -> 0.65f + 0.30f * wave
                isExplicitActive -> 0.55f + 0.20f * wave
                else -> ACTIVE_RESTING_EDGE_ALPHA
            }
            buffers.edgeAlpha[i] = edge
        }

        return completedEventId
    }

    /**
     * Zero-allocation hit test mapping canvas touch coordinates to the nearest visible
     * [NeuronNodeId] within its hit radius, or null if no visible node was tapped.
     */
    fun hitTestNeuron(
        x: Float,
        y: Float,
        buffers: NeuralCanvasBuffers
    ): NeuronNodeId? {
        if (buffers.lastWidth <= 0f || buffers.lastHeight <= 0f || buffers.visibleNodeCount <= 0) {
            return null
        }

        var bestIndex = -1
        var bestDistSq = Float.MAX_VALUE

        val visibleCount = buffers.visibleNodeCount
        for (slot in 0 until visibleCount) {
            val idx = buffers.visibleNodeIndices[slot]
            if (idx < 0 || idx >= NeuralCanvasBuffers.NEURON_COUNT) {
                continue
            }
            val hitRadius = buffers.nodeRadii[idx] * HIT_RADIUS_MULTIPLIER
            val dx = x - buffers.nodeX[idx]
            val dy = y - buffers.nodeY[idx]
            val distSq = dx * dx + dy * dy
            if (distSq <= hitRadius * hitRadius && distSq < bestDistSq) {
                bestDistSq = distSq
                bestIndex = idx
            }
        }

        return if (bestIndex >= 0) {
            NeuralCanvasBuffers.NEURON_NODES[bestIndex]
        } else {
            null
        }
    }

    /**
     * Renders the complete Dual-Core Neural Canvas using strictly pre-allocated buffers, colors,
     * strokes, and text paints with zero heap allocations.
     */
    fun render(
        scope: DrawScope,
        state: NeuralCanvasState,
        palette: NeuralCanvasPalette,
        buffers: NeuralCanvasBuffers
    ) {
        if (buffers.lastWidth <= 0f || buffers.lastHeight <= 0f) {
            return
        }

        val cx = buffers.centerX
        val cy = buffers.centerY
        val center = Offset(cx, cy)
        val visibleCount = buffers.visibleNodeCount

        // 1. Subtle curved hub-to-neuron synapse edges for visible nodes only
        // (Orbit guide ring is intentionally omitted to keep the minimalist stage clean.)
        val edgeStrokeWidth = palette.synapseEdgeStroke.width
        for (slot in 0 until visibleCount) {
            val i = buffers.visibleNodeIndices[slot]
            if (i < 0 || i >= NeuralCanvasBuffers.NEURON_COUNT) {
                continue
            }
            val isEdgeActive = buffers.isNeuronActive(i) ||
                (buffers.pulseActive && i == buffers.pulseTargetIndex && !buffers.pulseIsInterNeuron)
            val edgeColor = if (isEdgeActive) palette.edgeActive else palette.edgeIdle
            val alpha = buffers.edgeAlpha[i].coerceIn(0f, 1f)
            drawQuadraticEdgeSegments(
                scope = scope,
                p0x = buffers.edgeStartX[i],
                p0y = buffers.edgeStartY[i],
                p1x = buffers.edgeControlX[i],
                p1y = buffers.edgeControlY[i],
                p2x = buffers.edgeEndX[i],
                p2y = buffers.edgeEndY[i],
                color = edgeColor,
                strokeWidth = edgeStrokeWidth,
                alpha = alpha
            )
        }

        // 3. Active outbound synapse pulse trajectory (Hub -> Neuron or Inter-Neuron Chain)
        val pulse = state.activePulse
        val headRadius = (buffers.minDimension * 0.015f).coerceAtLeast(3f)
        if (pulse != null && buffers.pulseActive && buffers.pulsePointCount >= 2) {
            val pulseColor = palette.pulseColorFor(pulse)
            val pointCount = buffers.pulsePointCount
            val strokeW = palette.synapsePulseStroke.width

            for (j in 0 until pointCount - 1) {
                val segAlpha = buffers.pulsePointsAlpha[j + 1].coerceIn(0f, 1f)
                scope.drawLine(
                    color = pulseColor,
                    start = Offset(buffers.pulsePointsX[j], buffers.pulsePointsY[j]),
                    end = Offset(buffers.pulsePointsX[j + 1], buffers.pulsePointsY[j + 1]),
                    strokeWidth = strokeW,
                    alpha = segAlpha
                )
            }

            val headCenter = Offset(buffers.pulseHeadX, buffers.pulseHeadY)
            if (pulse.isBiometricSynapse) {
                scope.drawCircle(
                    color = palette.biometricSynapseGlow,
                    radius = headRadius * 2.4f,
                    center = headCenter,
                    alpha = 0.45f,
                    style = palette.biometricRingStroke
                )
            }

            scope.drawCircle(
                color = pulseColor,
                radius = headRadius * 1.85f,
                center = headCenter,
                alpha = 0.35f,
                style = Fill
            )
            scope.drawCircle(
                color = palette.pulseHeadHighlight,
                radius = headRadius,
                center = headCenter,
                alpha = 0.95f,
                style = Fill
            )
        }

        // 3b. Bidirectional return confirmation pulse (Target Node -> Hub Core)
        if (buffers.returnPulseActive && buffers.returnPulsePointCount >= 2) {
            val retCount = buffers.returnPulsePointCount
            val retStrokeW = palette.synapsePulseStroke.width * 0.85f
            for (j in 0 until retCount - 1) {
                val segAlpha = buffers.returnPulsePointsAlpha[j + 1].coerceIn(0f, 1f)
                scope.drawLine(
                    color = palette.returnPulseColor,
                    start = Offset(buffers.returnPulsePointsX[j], buffers.returnPulsePointsY[j]),
                    end = Offset(buffers.returnPulsePointsX[j + 1], buffers.returnPulsePointsY[j + 1]),
                    strokeWidth = retStrokeW,
                    alpha = segAlpha
                )
            }
            val retHead = Offset(buffers.returnPulseHeadX, buffers.returnPulseHeadY)
            scope.drawCircle(
                color = palette.returnPulseColor,
                radius = headRadius * 1.65f,
                center = retHead,
                alpha = 0.38f,
                style = Fill
            )
            scope.drawCircle(
                color = palette.pulseHeadHighlight,
                radius = headRadius * 0.85f,
                center = retHead,
                alpha = 0.95f,
                style = Fill
            )
        }

        // 4. Central Dual-Core Hub (Thermal Ring on stress + Outer Cortex Shell + Gemma 4 Inner Core)
        val thermalRadius = buffers.ringRadii[NeuralCanvasBuffers.RING_THERMAL]
        val outerRadius = buffers.ringRadii[NeuralCanvasBuffers.RING_OUTER_SHELL]
        val innerRadius = buffers.ringRadii[NeuralCanvasBuffers.RING_INNER_CORE]

        // Thermal indicator ring drawn only under elevated thermal pressure
        if (state.thermalState != ThermalState.NORMAL) {
            val thermalColor = palette.thermalRingColorFor(state.thermalState)
            val thermalAlpha = when (state.thermalState) {
                ThermalState.MODERATE -> 0.85f
                ThermalState.SEVERE_OR_HIGHER -> 1.0f
                ThermalState.NORMAL -> 0f
            }
            scope.drawCircle(
                color = thermalColor,
                radius = thermalRadius,
                center = center,
                alpha = thermalAlpha,
                style = palette.thermalRingStroke
            )
        }

        // Outer Cortex Shell backdrop & structural ring
        val shellColor = palette.outerShellColorFor(state.coreState, pulse?.tier)
        scope.drawCircle(
            color = palette.hubBackdrop,
            radius = outerRadius,
            center = center,
            alpha = 1f,
            style = Fill
        )
        scope.drawCircle(
            color = shellColor,
            radius = outerRadius,
            center = center,
            alpha = if (buffers.outerShellPulseAlpha > 0f) 0.98f else 0.92f,
            style = palette.outerShellStroke
        )

        if (buffers.outerShellPulseAlpha > 0f) {
            val haloExpand = outerRadius + (thermalRadius - outerRadius) * 0.55f * buffers.outerShellPulseAlpha
            scope.drawCircle(
                color = shellColor,
                radius = haloExpand,
                center = center,
                alpha = (buffers.outerShellPulseAlpha * 0.42f).coerceIn(0f, 1f),
                style = palette.outerShellPulseStroke
            )
        }

        if (buffers.coreConfirmRingAlpha > 0.01f) {
            val confirmAlpha = buffers.coreConfirmRingAlpha.coerceIn(0f, 1f)
            scope.drawCircle(
                color = palette.coreConfirmRingColor,
                radius = outerRadius * (1.02f + 0.14f * confirmAlpha),
                center = center,
                alpha = confirmAlpha * 0.85f,
                style = palette.outerShellPulseStroke
            )
        }

        if (buffers.errorFlashAlpha > 0f) {
            scope.drawCircle(
                color = palette.outerShellError,
                radius = outerRadius * 1.08f,
                center = center,
                alpha = buffers.errorFlashAlpha.coerceIn(0f, 1f),
                style = palette.outerShellPulseStroke
            )
        }

        // Gemma 4 Inner Core: crisp solid center dot when dormant; glows when isInnerCoreAwake == true
        if (buffers.isInnerCoreAwake && buffers.innerCoreGlowAlpha > 0f) {
            val glowAlpha = buffers.innerCoreGlowAlpha.coerceIn(0f, 1f)
            scope.drawCircle(
                color = palette.innerCoreAwakeHalo,
                radius = innerRadius * (1.15f + 0.18f * glowAlpha),
                center = center,
                alpha = glowAlpha * 0.36f,
                style = Fill
            )
            scope.drawCircle(
                color = palette.innerCoreAwakeCore,
                radius = innerRadius * 0.88f,
                center = center,
                alpha = glowAlpha * 0.90f,
                style = Fill
            )
            scope.drawCircle(
                color = palette.pulseHeadHighlight,
                radius = innerRadius * 0.38f,
                center = center,
                alpha = glowAlpha * 0.85f,
                style = Fill
            )
        } else {
            scope.drawCircle(
                color = palette.innerCoreDormantFill,
                radius = innerRadius * 0.72f,
                center = center,
                alpha = 1f,
                style = Fill
            )
        }

        // 5. Visible Radial Neuron Squircle Cards, Line-Art Glyphs & Pre-Formatted Bidi Labels
        val labelPaint = palette.nodeLabelPaint
        if (labelPaint != null && labelPaint.textSize != buffers.labelTextSizePx) {
            labelPaint.textSize = buffers.labelTextSizePx
        }

        for (slot in 0 until visibleCount) {
            val i = buffers.visibleNodeIndices[slot]
            if (i < 0 || i >= NeuralCanvasBuffers.NEURON_COUNT) {
                continue
            }
            val nodeId = NeuralCanvasBuffers.NEURON_NODES[i]
            val nx = buffers.nodeX[i]
            val ny = buffers.nodeY[i]
            val nr = buffers.nodeRadii[i]
            val isActive = buffers.isNeuronActive(i)
            val isVault = nodeId == NeuronNodeId.VAULT
            val isBiometricNode = pulse != null &&
                pulse.isBiometricSynapse &&
                buffers.pulseActive &&
                (i == buffers.pulseTargetIndex || i == buffers.pulseSourceIndex)

            val glowAlpha = buffers.nodeGlowAlpha[i].coerceIn(0f, 1f)
            if (glowAlpha > 0.01f) {
                val haloColor: Color = when {
                    isBiometricNode -> palette.biometricSynapseGlow
                    isVault && state.isVaultUnlocked -> palette.vaultUnlockedStroke
                    isVault -> palette.vaultLockedStroke
                    else -> palette.nodeGlowActive
                }
                val haloR = nr * (1.24f + 0.14f * glowAlpha)
                val haloCorner = haloR * SQUIRCLE_CORNER_RATIO
                scope.drawRoundRect(
                    color = haloColor,
                    topLeft = Offset(nx - haloR, ny - haloR),
                    size = Size(haloR * 2f, haloR * 2f),
                    cornerRadius = CornerRadius(haloCorner, haloCorner),
                    alpha = glowAlpha * 0.28f,
                    style = Fill
                )
            }

            val fillColor: Color = when {
                isVault && state.isVaultUnlocked -> palette.vaultUnlockedFill
                isVault -> palette.vaultLockedFill
                isActive -> palette.nodeFillActive
                else -> palette.nodeFillIdle
            }
            val borderColor: Color = when {
                isBiometricNode -> palette.biometricSynapsePrimary
                isVault && state.isVaultUnlocked -> palette.vaultUnlockedStroke
                isVault -> palette.vaultLockedStroke
                isActive -> palette.nodeStrokeActive
                else -> palette.nodeStrokeIdle
            }
            val borderStroke = if (isActive || isBiometricNode || (isVault && state.isVaultUnlocked)) {
                palette.nodeActiveBorderStroke
            } else {
                palette.nodeBorderStroke
            }

            val nodeTopLeft = Offset(nx - nr, ny - nr)
            val nodeSize = Size(nr * 2f, nr * 2f)
            val nodeCornerRadius = nr * SQUIRCLE_CORNER_RATIO
            val nodeCorner = CornerRadius(nodeCornerRadius, nodeCornerRadius)

            // Subtle architectural shadow ring behind squircle card (zero allocation)
            val shadowPad = nr * 0.06f
            val shadowCorner = (nr + shadowPad) * SQUIRCLE_CORNER_RATIO
            scope.drawRoundRect(
                color = palette.nodeStrokeIdle,
                topLeft = Offset(nx - nr - shadowPad, ny - nr + shadowPad * 0.6f),
                size = Size((nr + shadowPad) * 2f, (nr + shadowPad) * 2f),
                cornerRadius = CornerRadius(shadowCorner, shadowCorner),
                alpha = 0.22f,
                style = Fill
            )

            scope.drawRoundRect(
                color = fillColor,
                topLeft = nodeTopLeft,
                size = nodeSize,
                cornerRadius = nodeCorner,
                alpha = 1f,
                style = Fill
            )
            scope.drawRoundRect(
                color = borderColor,
                topLeft = nodeTopLeft,
                size = nodeSize,
                cornerRadius = nodeCorner,
                alpha = 1f,
                style = borderStroke
            )

            if (isBiometricNode) {
                val bioR = nr * 1.18f
                val bioCorner = bioR * SQUIRCLE_CORNER_RATIO
                scope.drawRoundRect(
                    color = palette.biometricSynapsePrimary,
                    topLeft = Offset(nx - bioR, ny - bioR),
                    size = Size(bioR * 2f, bioR * 2f),
                    cornerRadius = CornerRadius(bioCorner, bioCorner),
                    alpha = 0.85f,
                    style = palette.biometricRingStroke
                )
            }

            val iconColor: Color = when {
                isVault && state.isVaultUnlocked -> palette.vaultUnlockedStroke
                isActive -> palette.nodeIconActive
                else -> palette.nodeIconIdle
            }
            drawNodeGlyph(
                scope = scope,
                nodeId = nodeId,
                cx = nx,
                cy = ny,
                radius = nr,
                isVaultUnlocked = state.isVaultUnlocked,
                color = iconColor,
                palette = palette
            )

            if (labelPaint != null) {
                val textColorArgb = when {
                    isVault && state.isVaultUnlocked -> palette.labelColorVaultUnlockedArgb
                    isVault -> palette.labelColorVaultLockedArgb
                    isActive || glowAlpha > 0.25f -> palette.labelColorActiveArgb
                    else -> palette.labelColorIdleArgb
                }
                labelPaint.color = textColorArgb
                labelPaint.alpha = if (isActive || glowAlpha > 0.25f) 250 else 235
                scope.drawContext.canvas.nativeCanvas.drawText(
                    buffers.formattedLabels[i],
                    nx,
                    buffers.nodeLabelY[i],
                    labelPaint
                )
            }
        }
    }

    private fun drawQuadraticEdgeSegments(
        scope: DrawScope,
        p0x: Float,
        p0y: Float,
        p1x: Float,
        p1y: Float,
        p2x: Float,
        p2y: Float,
        color: Color,
        strokeWidth: Float,
        alpha: Float
    ) {
        var prevX = p0x
        var prevY = p0y
        val invSegments = 1f / EDGE_BEZIER_SEGMENTS.toFloat()
        for (step in 1..EDGE_BEZIER_SEGMENTS) {
            val t = step * invSegments
            val inv = 1f - t
            val nextX = inv * inv * p0x + 2f * inv * t * p1x + t * t * p2x
            val nextY = inv * inv * p0y + 2f * inv * t * p1y + t * t * p2y
            scope.drawLine(
                color = color,
                start = Offset(prevX, prevY),
                end = Offset(nextX, nextY),
                strokeWidth = strokeWidth,
                alpha = alpha
            )
            prevX = nextX
            prevY = nextY
        }
    }

    private fun drawNodeGlyph(
        scope: DrawScope,
        nodeId: NeuronNodeId,
        cx: Float,
        cy: Float,
        radius: Float,
        isVaultUnlocked: Boolean,
        color: Color,
        palette: NeuralCanvasPalette
    ) {
        when (nodeId) {
            NeuronNodeId.CLOCK -> drawClockGlyph(scope, cx, cy, radius, color, palette)
            NeuronNodeId.CALENDAR -> drawCalendarGlyph(scope, cx, cy, radius, color, palette)
            NeuronNodeId.NOTES -> drawNotesGlyph(scope, cx, cy, radius, color, palette)
            NeuronNodeId.MESSAGES -> drawMessagesGlyph(scope, cx, cy, radius, color, palette)
            NeuronNodeId.VAULT -> drawVaultGlyph(scope, cx, cy, radius, isVaultUnlocked, color, palette)
            NeuronNodeId.FILES -> drawFilesGlyph(scope, cx, cy, radius, color, palette)
            NeuronNodeId.AUDIO_DND -> drawAudioDndGlyph(scope, cx, cy, radius, color, palette)
            NeuronNodeId.ROUTINES -> drawRoutinesGlyph(scope, cx, cy, radius, color, palette)
        }
    }

    private fun drawClockGlyph(
        scope: DrawScope,
        cx: Float,
        cy: Float,
        radius: Float,
        color: Color,
        palette: NeuralCanvasPalette
    ) {
        val strokeW = palette.lockGlyphStroke.width
        scope.drawCircle(
            color = color,
            radius = radius * 0.44f,
            center = Offset(cx, cy),
            alpha = 0.95f,
            style = palette.lockGlyphStroke
        )
        scope.drawLine(
            color = color,
            start = Offset(cx, cy),
            end = Offset(cx, cy - radius * 0.24f),
            strokeWidth = strokeW,
            cap = StrokeCap.Round,
            alpha = 0.95f
        )
        scope.drawLine(
            color = color,
            start = Offset(cx, cy),
            end = Offset(cx + radius * 0.18f, cy + radius * 0.10f),
            strokeWidth = strokeW,
            cap = StrokeCap.Round,
            alpha = 0.95f
        )
    }

    private fun drawCalendarGlyph(
        scope: DrawScope,
        cx: Float,
        cy: Float,
        radius: Float,
        color: Color,
        palette: NeuralCanvasPalette
    ) {
        val strokeW = palette.lockGlyphStroke.width
        val w = radius * 0.84f
        val h = radius * 0.72f
        val left = cx - w * 0.5f
        val top = cy - h * 0.42f
        val corner = radius * 0.12f

        scope.drawRoundRect(
            color = color,
            topLeft = Offset(left, top),
            size = Size(w, h),
            cornerRadius = CornerRadius(corner, corner),
            alpha = 0.95f,
            style = palette.lockGlyphStroke
        )
        val dividerY = top + h * 0.32f
        scope.drawLine(
            color = color,
            start = Offset(left, dividerY),
            end = Offset(left + w, dividerY),
            strokeWidth = strokeW,
            cap = StrokeCap.Round,
            alpha = 0.95f
        )
        val tickOffsetX = w * 0.24f
        val tickTop = top - radius * 0.12f
        val tickBottom = top + radius * 0.06f
        scope.drawLine(
            color = color,
            start = Offset(cx - tickOffsetX, tickTop),
            end = Offset(cx - tickOffsetX, tickBottom),
            strokeWidth = strokeW,
            cap = StrokeCap.Round,
            alpha = 0.95f
        )
        scope.drawLine(
            color = color,
            start = Offset(cx + tickOffsetX, tickTop),
            end = Offset(cx + tickOffsetX, tickBottom),
            strokeWidth = strokeW,
            cap = StrokeCap.Round,
            alpha = 0.95f
        )
    }

    private fun drawNotesGlyph(
        scope: DrawScope,
        cx: Float,
        cy: Float,
        radius: Float,
        color: Color,
        palette: NeuralCanvasPalette
    ) {
        val strokeW = palette.lockGlyphStroke.width
        val w = radius * 0.72f
        val h = radius * 0.84f
        val left = cx - w * 0.5f
        val top = cy - h * 0.5f
        val corner = radius * 0.12f

        scope.drawRoundRect(
            color = color,
            topLeft = Offset(left, top),
            size = Size(w, h),
            cornerRadius = CornerRadius(corner, corner),
            alpha = 0.95f,
            style = palette.lockGlyphStroke
        )
        val lineStartX = left + w * 0.22f
        val lineEndX = left + w * 0.78f
        val shortEndX = left + w * 0.58f
        scope.drawLine(
            color = color,
            start = Offset(lineStartX, cy - h * 0.20f),
            end = Offset(lineEndX, cy - h * 0.20f),
            strokeWidth = strokeW,
            cap = StrokeCap.Round,
            alpha = 0.95f
        )
        scope.drawLine(
            color = color,
            start = Offset(lineStartX, cy),
            end = Offset(lineEndX, cy),
            strokeWidth = strokeW,
            cap = StrokeCap.Round,
            alpha = 0.95f
        )
        scope.drawLine(
            color = color,
            start = Offset(lineStartX, cy + h * 0.20f),
            end = Offset(shortEndX, cy + h * 0.20f),
            strokeWidth = strokeW,
            cap = StrokeCap.Round,
            alpha = 0.95f
        )
    }

    private fun drawMessagesGlyph(
        scope: DrawScope,
        cx: Float,
        cy: Float,
        radius: Float,
        color: Color,
        palette: NeuralCanvasPalette
    ) {
        val strokeW = palette.lockGlyphStroke.width
        val w = radius * 0.84f
        val h = radius * 0.60f
        val left = cx - w * 0.5f
        val top = cy - h * 0.58f
        val corner = radius * 0.14f

        scope.drawRoundRect(
            color = color,
            topLeft = Offset(left, top),
            size = Size(w, h),
            cornerRadius = CornerRadius(corner, corner),
            alpha = 0.95f,
            style = palette.lockGlyphStroke
        )
        val bottomY = top + h
        val tailTipX = left + w * 0.14f
        val tailTipY = bottomY + radius * 0.18f
        scope.drawLine(
            color = color,
            start = Offset(left + w * 0.28f, bottomY),
            end = Offset(tailTipX, tailTipY),
            strokeWidth = strokeW,
            cap = StrokeCap.Round,
            alpha = 0.95f
        )
        scope.drawLine(
            color = color,
            start = Offset(tailTipX, tailTipY),
            end = Offset(left + w * 0.44f, bottomY),
            strokeWidth = strokeW,
            cap = StrokeCap.Round,
            alpha = 0.95f
        )
    }

    private fun drawFilesGlyph(
        scope: DrawScope,
        cx: Float,
        cy: Float,
        radius: Float,
        color: Color,
        palette: NeuralCanvasPalette
    ) {
        val strokeW = palette.lockGlyphStroke.width
        val w = radius * 0.86f
        val h = radius * 0.60f
        val left = cx - w * 0.5f
        val top = cy - h * 0.34f
        val corner = radius * 0.12f

        scope.drawRoundRect(
            color = color,
            topLeft = Offset(left, top),
            size = Size(w, h),
            cornerRadius = CornerRadius(corner, corner),
            alpha = 0.95f,
            style = palette.lockGlyphStroke
        )
        val tabTop = top - radius * 0.14f
        val tabLeft = left + radius * 0.06f
        val tabRight = left + w * 0.42f
        scope.drawLine(
            color = color,
            start = Offset(tabLeft, top),
            end = Offset(tabLeft, tabTop),
            strokeWidth = strokeW,
            cap = StrokeCap.Round,
            alpha = 0.95f
        )
        scope.drawLine(
            color = color,
            start = Offset(tabLeft, tabTop),
            end = Offset(tabRight, tabTop),
            strokeWidth = strokeW,
            cap = StrokeCap.Round,
            alpha = 0.95f
        )
        scope.drawLine(
            color = color,
            start = Offset(tabRight, tabTop),
            end = Offset(left + w * 0.52f, top),
            strokeWidth = strokeW,
            cap = StrokeCap.Round,
            alpha = 0.95f
        )
    }

    private fun drawAudioDndGlyph(
        scope: DrawScope,
        cx: Float,
        cy: Float,
        radius: Float,
        color: Color,
        palette: NeuralCanvasPalette
    ) {
        val r = radius * 0.42f
        scope.drawArc(
            color = color,
            startAngle = 30f,
            sweepAngle = 240f,
            useCenter = false,
            topLeft = Offset(cx - r, cy - r),
            size = Size(r * 2f, r * 2f),
            alpha = 0.95f,
            style = palette.lockGlyphStroke
        )
        val innerCx = cx + r * 0.433f
        val innerCy = cy - r * 0.25f
        val innerR = r * 0.866f
        scope.drawArc(
            color = color,
            startAngle = 60f,
            sweepAngle = 180f,
            useCenter = false,
            topLeft = Offset(innerCx - innerR, innerCy - innerR),
            size = Size(innerR * 2f, innerR * 2f),
            alpha = 0.95f,
            style = palette.lockGlyphStroke
        )
    }

    private fun drawRoutinesGlyph(
        scope: DrawScope,
        cx: Float,
        cy: Float,
        radius: Float,
        color: Color,
        palette: NeuralCanvasPalette
    ) {
        scope.drawCircle(
            color = color,
            radius = radius * 0.40f,
            center = Offset(cx, cy),
            alpha = 0.95f,
            style = palette.lockGlyphStroke
        )
        scope.drawCircle(
            color = color,
            radius = radius * 0.14f,
            center = Offset(cx, cy),
            alpha = 0.95f,
            style = Fill
        )
    }

    private fun drawVaultGlyph(
        scope: DrawScope,
        cx: Float,
        cy: Float,
        radius: Float,
        isUnlocked: Boolean,
        color: Color,
        palette: NeuralCanvasPalette
    ) {
        val bodyWidth = radius * 0.72f
        val bodyHeight = radius * 0.52f
        val bodyLeft = cx - bodyWidth * 0.5f
        val bodyTop = cy + radius * 0.02f
        val corner = radius * 0.12f

        scope.drawRoundRect(
            color = color,
            topLeft = Offset(bodyLeft, bodyTop),
            size = Size(bodyWidth, bodyHeight),
            cornerRadius = CornerRadius(corner, corner),
            alpha = 0.95f,
            style = palette.lockGlyphStroke
        )

        val shackleSize = radius * 0.44f
        val shackleLeft = cx - shackleSize * 0.5f + if (isUnlocked) radius * 0.14f else 0f
        val shackleTop = bodyTop - shackleSize * (if (isUnlocked) 0.68f else 0.52f)
        scope.drawArc(
            color = color,
            startAngle = 180f,
            sweepAngle = if (isUnlocked) 135f else 180f,
            useCenter = false,
            topLeft = Offset(shackleLeft, shackleTop),
            size = Size(shackleSize, shackleSize),
            alpha = 0.95f,
            style = palette.lockGlyphStroke
        )
    }

    private fun configurePulseTrajectory(
        pulse: NeuralPulseEvent,
        buffers: NeuralCanvasBuffers
    ) {
        val targetIndex = NeuralCanvasBuffers.indexOf(pulse.targetNode)
        val sourceNode = pulse.sourceNode
        val sourceIndex = if (sourceNode != null) {
            NeuralCanvasBuffers.indexOf(sourceNode)
        } else {
            -1
        }
        buffers.pulseSourceIndex = sourceIndex
        buffers.pulseTargetIndex = targetIndex
        buffers.pulseIsInterNeuron = sourceIndex >= 0

        recomputeTrajectoryFromIndices(
            sourceIndex = sourceIndex,
            targetIndex = targetIndex,
            wakesInnerCore = pulse.wakesInnerCore,
            buffers = buffers
        )
    }

    private fun recomputeTrajectoryFromIndices(
        sourceIndex: Int,
        targetIndex: Int,
        wakesInnerCore: Boolean,
        buffers: NeuralCanvasBuffers
    ) {
        val endX = buffers.nodeX[targetIndex]
        val endY = buffers.nodeY[targetIndex]

        if (sourceIndex < 0) {
            val startX = if (wakesInnerCore) buffers.centerX else buffers.edgeStartX[targetIndex]
            val startY = if (wakesInnerCore) buffers.centerY else buffers.edgeStartY[targetIndex]
            buffers.pulseStartX = startX
            buffers.pulseStartY = startY
            buffers.pulseEndX = endX
            buffers.pulseEndY = endY
            if (wakesInnerCore) {
                buffers.pulseControlX = (startX + endX) * 0.5f
                buffers.pulseControlY = (startY + endY) * 0.5f
            } else {
                buffers.pulseControlX = buffers.edgeControlX[targetIndex]
                buffers.pulseControlY = buffers.edgeControlY[targetIndex]
            }
            return
        }

        val startX = buffers.nodeX[sourceIndex]
        val startY = buffers.nodeY[sourceIndex]
        buffers.pulseStartX = startX
        buffers.pulseStartY = startY
        buffers.pulseEndX = endX
        buffers.pulseEndY = endY

        if (sourceIndex == targetIndex) {
            val rx = startX - buffers.centerX
            val ry = startY - buffers.centerY
            val rLen = hypot(rx.toDouble(), ry.toDouble()).toFloat()
            val dirX = if (rLen > 0.001f) rx / rLen else 0f
            val dirY = if (rLen > 0.001f) ry / rLen else -1f
            val loopOffset = buffers.nodeRadii[sourceIndex] * 1.8f
            buffers.pulseControlX = startX + dirX * loopOffset
            buffers.pulseControlY = startY + dirY * loopOffset
            return
        }

        val midX = (startX + endX) * 0.5f
        val midY = (startY + endY) * 0.5f
        val dx = endX - startX
        val dy = endY - startY
        val dist = hypot(dx.toDouble(), dy.toDouble()).toFloat()
        if (dist <= 0.001f) {
            buffers.pulseControlX = midX
            buffers.pulseControlY = midY
            return
        }

        val normalX = -dy / dist
        val normalY = dx / dist
        val curveOffset = buffers.minDimension * INTER_NEURON_CURVE_RATIO
        buffers.pulseControlX = midX + normalX * curveOffset
        buffers.pulseControlY = midY + normalY * curveOffset
    }

    private fun samplePulseTrail(buffers: NeuralCanvasBuffers) {
        val progress = buffers.pulseProgress.coerceIn(0f, 1f)
        val p0x = buffers.pulseStartX
        val p0y = buffers.pulseStartY
        val p1x = buffers.pulseControlX
        val p1y = buffers.pulseControlY
        val p2x = buffers.pulseEndX
        val p2y = buffers.pulseEndY

        val headInv = 1f - progress
        buffers.pulseHeadX = headInv * headInv * p0x + 2f * headInv * progress * p1x + progress * progress * p2x
        buffers.pulseHeadY = headInv * headInv * p0y + 2f * headInv * progress * p1y + progress * progress * p2y

        val trailStart = (progress - PULSE_TRAIL_SPAN).coerceAtLeast(0f)
        val span = progress - trailStart
        val count = NeuralCanvasBuffers.PULSE_TRAIL_SAMPLES
        val denom = (count - 1).toFloat()

        for (i in 0 until count) {
            val frac = i.toFloat() / denom
            val t = trailStart + span * frac
            val inv = 1f - t
            buffers.pulsePointsX[i] = inv * inv * p0x + 2f * inv * t * p1x + t * t * p2x
            buffers.pulsePointsY[i] = inv * inv * p0y + 2f * inv * t * p1y + t * t * p2y
            buffers.pulsePointsAlpha[i] = 0.08f + 0.92f * frac * frac
        }
        buffers.pulsePointCount = count
    }

    private fun sampleReturnPulseTrail(buffers: NeuralCanvasBuffers) {
        val progress = buffers.returnPulseProgress.coerceIn(0f, 1f)
        // Reversed curve: Target Node (pulseEnd) -> Control -> Hub Core (pulseStart)
        val p0x = buffers.pulseEndX
        val p0y = buffers.pulseEndY
        val p1x = buffers.pulseControlX
        val p1y = buffers.pulseControlY
        val p2x = buffers.pulseStartX
        val p2y = buffers.pulseStartY

        val headInv = 1f - progress
        buffers.returnPulseHeadX =
            headInv * headInv * p0x + 2f * headInv * progress * p1x + progress * progress * p2x
        buffers.returnPulseHeadY =
            headInv * headInv * p0y + 2f * headInv * progress * p1y + progress * progress * p2y

        val trailStart = (progress - RETURN_PULSE_TRAIL_SPAN).coerceAtLeast(0f)
        val span = progress - trailStart
        val count = NeuralCanvasBuffers.PULSE_TRAIL_SAMPLES
        val denom = (count - 1).toFloat()

        for (i in 0 until count) {
            val frac = i.toFloat() / denom
            val t = trailStart + span * frac
            val inv = 1f - t
            buffers.returnPulsePointsX[i] = inv * inv * p0x + 2f * inv * t * p1x + t * t * p2x
            buffers.returnPulsePointsY[i] = inv * inv * p0y + 2f * inv * t * p1y + t * t * p2y
            buffers.returnPulsePointsAlpha[i] = 0.08f + 0.88f * frac * frac
        }
        buffers.returnPulsePointCount = count
    }

    private fun pulseDurationMsFor(tier: ResolutionTier): Float {
        return when (tier) {
            ResolutionTier.TIER_1_RULE -> TIER_1_PULSE_DURATION_MS
            ResolutionTier.TIER_2_CACHE -> TIER_2_PULSE_DURATION_MS
            ResolutionTier.TIER_2_5_FUNCTION_GEMMA -> TIER_2_PULSE_DURATION_MS
            ResolutionTier.TIER_3_GEMMA -> TIER_3_PULSE_DURATION_MS
        }
    }

    companion object {
        private const val START_ANGLE_RAD: Double = -PI / 2.0
        private const val TWO_PI_F: Float = (2.0 * PI).toFloat()

        private const val INNER_CORE_RADIUS_RATIO: Float = 0.075f
        private const val OUTER_SHELL_RADIUS_RATIO: Float = 0.135f
        private const val THERMAL_RING_RADIUS_RATIO: Float = 0.162f
        private const val ORBIT_RADIUS_RATIO: Float = 0.34f
        private const val NODE_RADIUS_RATIO: Float = 0.060f
        private const val LABEL_OFFSET_RATIO: Float = 0.042f
        private const val LABEL_TEXT_SIZE_RATIO: Float = 0.030f
        private const val MIN_LABEL_PX: Float = 16f
        private const val MAX_LABEL_PX: Float = 38f

        private const val EDGE_CURVE_FACTOR: Float = 0.06f
        private const val EDGE_BEZIER_SEGMENTS: Int = 14
        private const val SQUIRCLE_CORNER_RATIO: Float = 0.50f

        private const val HIT_RADIUS_MULTIPLIER: Float = 1.35f
        private const val INTER_NEURON_CURVE_RATIO: Float = 0.14f
        private const val PULSE_TRAIL_SPAN: Float = 0.35f
        private const val RETURN_PULSE_START_PROGRESS: Float = 0.62f
        private const val RETURN_PULSE_TRAIL_SPAN: Float = 0.32f
        private const val RETURN_RING_START_PROGRESS: Float = 0.65f

        private const val CORE_ANGULAR_SPEED_RAD_PER_SEC: Float = 3.2f
        private const val MAX_FRAME_DELTA_MS: Long = 100L

        const val TIER_1_PULSE_DURATION_MS: Float = 420f
        const val TIER_2_PULSE_DURATION_MS: Float = 500f
        const val TIER_3_PULSE_DURATION_MS: Float = 850f

        private const val IDLE_ACTIVE_NODE_GLOW: Float = 0.45f
        private const val IDLE_ACTIVE_EDGE_ALPHA: Float = 0.85f
        private const val IDLE_RESTING_EDGE_ALPHA: Float = 0.72f
        private const val ACTIVE_RESTING_EDGE_ALPHA: Float = 0.45f
    }
}

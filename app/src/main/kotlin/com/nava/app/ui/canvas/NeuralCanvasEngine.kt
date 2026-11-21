package com.nava.app.ui.canvas

import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Fill
import androidx.compose.ui.graphics.nativeCanvas
import com.nava.domain.ai.ResolutionTier
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
     * canvas dimensions change.
     *
     * @return true if layout was recomputed, false if dimensions were unchanged or non-positive.
     */
    fun syncLayoutIfNeeded(
        width: Float,
        height: Float,
        buffers: NeuralCanvasBuffers
    ): Boolean {
        if (width <= 0f || height <= 0f) {
            return false
        }
        if (width == buffers.lastWidth && height == buffers.lastHeight) {
            return false
        }

        buffers.lastWidth = width
        buffers.lastHeight = height

        val cx = width * 0.5f
        val cy = height * 0.5f
        val minDim = if (width < height) width else height
        buffers.centerX = cx
        buffers.centerY = cy
        buffers.minDimension = minDim

        val innerCoreRadius = minDim * INNER_CORE_RADIUS_RATIO
        val outerShellRadius = minDim * OUTER_SHELL_RADIUS_RATIO
        val thermalRingRadius = minDim * THERMAL_RING_RADIUS_RATIO
        val orbitRadius = minDim * ORBIT_RADIUS_RATIO
        val nodeRadius = minDim * NODE_RADIUS_RATIO
        val labelOffset = minDim * LABEL_OFFSET_RATIO

        buffers.ringRadii[NeuralCanvasBuffers.RING_INNER_CORE] = innerCoreRadius
        buffers.ringRadii[NeuralCanvasBuffers.RING_OUTER_SHELL] = outerShellRadius
        buffers.ringRadii[NeuralCanvasBuffers.RING_THERMAL] = thermalRingRadius
        buffers.ringRadii[NeuralCanvasBuffers.RING_ORBIT] = orbitRadius
        buffers.labelTextSizePx = (minDim * LABEL_TEXT_SIZE_RATIO).coerceIn(MIN_LABEL_PX, MAX_LABEL_PX)

        for (i in 0 until NeuralCanvasBuffers.NEURON_COUNT) {
            val angle = START_ANGLE_RAD + i * ANGLE_STEP_RAD
            val cosA = cos(angle).toFloat()
            val sinA = sin(angle).toFloat()

            val nx = cx + orbitRadius * cosA
            val ny = cy + orbitRadius * sinA
            buffers.nodeX[i] = nx
            buffers.nodeY[i] = ny
            buffers.nodeRadii[i] = nodeRadius
            buffers.nodeLabelY[i] = ny + nodeRadius + labelOffset

            buffers.edgeStartX[i] = cx + outerShellRadius * cosA
            buffers.edgeStartY[i] = cy + outerShellRadius * sinA
            val edgeEndRadius = orbitRadius - nodeRadius
            buffers.edgeEndX[i] = cx + edgeEndRadius * cosA
            buffers.edgeEndY[i] = cy + edgeEndRadius * sinA
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
        } else {
            if (buffers.activePulseEventId != pulse.eventId) {
                buffers.activePulseEventId = pulse.eventId
                buffers.pulseProgress = 0f
                buffers.pulseCompleted = false
                buffers.pulseCompletionDispatched = false
                buffers.pulseActive = true
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
     * Zero-allocation hit test mapping canvas touch coordinates to the nearest [NeuronNodeId]
     * within its hit radius, or null if no node was tapped.
     */
    fun hitTestNeuron(
        x: Float,
        y: Float,
        buffers: NeuralCanvasBuffers
    ): NeuronNodeId? {
        if (buffers.lastWidth <= 0f || buffers.lastHeight <= 0f) {
            return null
        }

        var bestIndex = -1
        var bestDistSq = Float.MAX_VALUE

        for (i in 0 until NeuralCanvasBuffers.NEURON_COUNT) {
            val hitRadius = buffers.nodeRadii[i] * HIT_RADIUS_MULTIPLIER
            val dx = x - buffers.nodeX[i]
            val dy = y - buffers.nodeY[i]
            val distSq = dx * dx + dy * dy
            if (distSq <= hitRadius * hitRadius && distSq < bestDistSq) {
                bestDistSq = distSq
                bestIndex = i
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

        // 1. Subtle radial orbit guide ring
        scope.drawCircle(
            color = palette.orbitRing,
            radius = buffers.ringRadii[NeuralCanvasBuffers.RING_ORBIT],
            center = center,
            alpha = 0.45f,
            style = palette.orbitStroke
        )

        // 2. Base hub-to-neuron synapse edges
        for (i in 0 until NeuralCanvasBuffers.NEURON_COUNT) {
            val edgeColor = if (buffers.isNeuronActive(i) || (buffers.pulseActive && i == buffers.pulseTargetIndex && !buffers.pulseIsInterNeuron)) {
                palette.edgeActive
            } else {
                palette.edgeIdle
            }
            scope.drawLine(
                color = edgeColor,
                start = Offset(buffers.edgeStartX[i], buffers.edgeStartY[i]),
                end = Offset(buffers.edgeEndX[i], buffers.edgeEndY[i]),
                strokeWidth = palette.synapseEdgeStroke.width,
                alpha = buffers.edgeAlpha[i].coerceIn(0f, 1f)
            )
        }

        // 3. Active synapse pulse trajectory (Hub -> Neuron or Inter-Neuron Chain)
        val pulse = state.activePulse
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
            val headRadius = (buffers.minDimension * 0.015f).coerceAtLeast(3f)

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

        // 4. Central Dual-Core Hub (Thermal Ring + Outer Cortex Shell + Gemma 4 Inner Core)
        val thermalRadius = buffers.ringRadii[NeuralCanvasBuffers.RING_THERMAL]
        val outerRadius = buffers.ringRadii[NeuralCanvasBuffers.RING_OUTER_SHELL]
        val innerRadius = buffers.ringRadii[NeuralCanvasBuffers.RING_INNER_CORE]

        // Thermal indicator ring
        val thermalColor = palette.thermalRingColorFor(state.thermalState)
        val thermalAlpha = when (state.thermalState) {
            com.nava.domain.ai.ThermalState.NORMAL -> 0.55f
            com.nava.domain.ai.ThermalState.MODERATE -> 0.85f
            com.nava.domain.ai.ThermalState.SEVERE_OR_HIGHER -> 1.0f
        }
        scope.drawCircle(
            color = thermalColor,
            radius = thermalRadius,
            center = center,
            alpha = thermalAlpha,
            style = palette.thermalRingStroke
        )

        // Outer Cortex Shell backdrop & structural ring
        val shellColor = palette.outerShellColorFor(state.coreState, pulse?.tier)
        scope.drawCircle(
            color = palette.hubBackdrop,
            radius = outerRadius,
            center = center,
            alpha = 0.96f,
            style = Fill
        )
        scope.drawCircle(
            color = shellColor,
            radius = outerRadius,
            center = center,
            alpha = if (buffers.outerShellPulseAlpha > 0f) 0.95f else 0.70f,
            style = palette.outerShellStroke
        )

        if (buffers.outerShellPulseAlpha > 0f) {
            val haloExpand = outerRadius + (thermalRadius - outerRadius) * 0.55f * buffers.outerShellPulseAlpha
            scope.drawCircle(
                color = shellColor,
                radius = haloExpand,
                center = center,
                alpha = (buffers.outerShellPulseAlpha * 0.45f).coerceIn(0f, 1f),
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

        // Gemma 4 Inner Core: stays dark/asleep unless isInnerCoreAwake == true
        scope.drawCircle(
            color = palette.innerCoreDormantFill,
            radius = innerRadius,
            center = center,
            alpha = 1f,
            style = Fill
        )

        if (buffers.isInnerCoreAwake && buffers.innerCoreGlowAlpha > 0f) {
            val glowAlpha = buffers.innerCoreGlowAlpha.coerceIn(0f, 1f)
            scope.drawCircle(
                color = palette.innerCoreAwakeHalo,
                radius = innerRadius * (1.15f + 0.18f * glowAlpha),
                center = center,
                alpha = glowAlpha * 0.42f,
                style = Fill
            )
            scope.drawCircle(
                color = palette.innerCoreAwakeCore,
                radius = innerRadius * 0.88f,
                center = center,
                alpha = glowAlpha * 0.92f,
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
            val rimColor = if (state.isModelResident) {
                palette.innerCoreResidentRim
            } else {
                palette.innerCoreDormantRim
            }
            scope.drawCircle(
                color = rimColor,
                radius = innerRadius,
                center = center,
                alpha = if (state.isModelResident) 0.75f else 0.55f,
                style = palette.innerCoreRimStroke
            )
        }

        // 5. Radial Neuron Nodes & Pre-Formatted Bidi Labels
        val labelPaint = palette.nodeLabelPaint
        if (labelPaint != null && labelPaint.textSize != buffers.labelTextSizePx) {
            labelPaint.textSize = buffers.labelTextSizePx
        }

        for (i in 0 until NeuralCanvasBuffers.NEURON_COUNT) {
            val nodeId = NeuralCanvasBuffers.NEURON_NODES[i]
            val nx = buffers.nodeX[i]
            val ny = buffers.nodeY[i]
            val nr = buffers.nodeRadii[i]
            val nodeCenter = Offset(nx, ny)
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
                scope.drawCircle(
                    color = haloColor,
                    radius = nr * (1.28f + 0.16f * glowAlpha),
                    center = nodeCenter,
                    alpha = glowAlpha * 0.32f,
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

            scope.drawCircle(
                color = fillColor,
                radius = nr,
                center = nodeCenter,
                alpha = 1f,
                style = Fill
            )
            scope.drawCircle(
                color = borderColor,
                radius = nr,
                center = nodeCenter,
                alpha = 1f,
                style = borderStroke
            )

            if (isBiometricNode) {
                scope.drawCircle(
                    color = palette.biometricSynapsePrimary,
                    radius = nr * 1.18f,
                    center = nodeCenter,
                    alpha = 0.85f,
                    style = palette.biometricRingStroke
                )
            }

            if (isVault) {
                drawVaultGlyph(
                    scope = scope,
                    cx = nx,
                    cy = ny,
                    radius = nr,
                    isUnlocked = state.isVaultUnlocked,
                    color = borderColor,
                    palette = palette
                )
            } else {
                val dotRadius = nr * if (isActive) 0.30f else 0.18f
                scope.drawCircle(
                    color = borderColor,
                    radius = dotRadius,
                    center = nodeCenter,
                    alpha = if (isActive) 0.95f else 0.55f,
                    style = Fill
                )
            }

            if (labelPaint != null) {
                val textColorArgb = when {
                    isVault && state.isVaultUnlocked -> palette.labelColorVaultUnlockedArgb
                    isVault -> palette.labelColorVaultLockedArgb
                    isActive || glowAlpha > 0.25f -> palette.labelColorActiveArgb
                    else -> palette.labelColorIdleArgb
                }
                labelPaint.color = textColorArgb
                labelPaint.alpha = if (isActive || isVault || glowAlpha > 0.25f) 245 else 205
                scope.drawContext.canvas.nativeCanvas.drawText(
                    buffers.formattedLabels[i],
                    nx,
                    buffers.nodeLabelY[i],
                    labelPaint
                )
            }
        }
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
            buffers.pulseControlX = (startX + endX) * 0.5f
            buffers.pulseControlY = (startY + endY) * 0.5f
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

    private fun pulseDurationMsFor(tier: ResolutionTier): Float {
        return when (tier) {
            ResolutionTier.TIER_1_RULE -> TIER_1_PULSE_DURATION_MS
            ResolutionTier.TIER_2_CACHE -> TIER_2_PULSE_DURATION_MS
            ResolutionTier.TIER_3_GEMMA -> TIER_3_PULSE_DURATION_MS
        }
    }

    companion object {
        private const val START_ANGLE_RAD: Double = -PI / 2.0
        private const val ANGLE_STEP_RAD: Double = (2.0 * PI) / NeuralCanvasBuffers.NEURON_COUNT
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

        private const val HIT_RADIUS_MULTIPLIER: Float = 1.35f
        private const val INTER_NEURON_CURVE_RATIO: Float = 0.14f
        private const val PULSE_TRAIL_SPAN: Float = 0.35f

        private const val CORE_ANGULAR_SPEED_RAD_PER_SEC: Float = 3.2f
        private const val MAX_FRAME_DELTA_MS: Long = 100L

        const val TIER_1_PULSE_DURATION_MS: Float = 420f
        const val TIER_2_PULSE_DURATION_MS: Float = 500f
        const val TIER_3_PULSE_DURATION_MS: Float = 850f

        private const val IDLE_ACTIVE_NODE_GLOW: Float = 0.45f
        private const val IDLE_ACTIVE_EDGE_ALPHA: Float = 0.65f
        private const val IDLE_RESTING_EDGE_ALPHA: Float = 0.30f
        private const val ACTIVE_RESTING_EDGE_ALPHA: Float = 0.32f
    }
}

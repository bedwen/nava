package com.nava.app.ui.canvas

import androidx.compose.animation.core.withInfiniteAnimationFrameMillis
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.core.text.BidiFormatter
import com.nava.domain.ui.CoreActivityState
import com.nava.domain.ui.NeuralCanvasState
import com.nava.domain.ui.NeuronNodeId
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.isActive

/**
 * Thread-safe instrumentation counters for verifying 0-FPS idle behavior and draw cadence
 * in tests and diagnostics.
 */
class NeuralCanvasFrameMetrics(
    val drawCount: AtomicLong = AtomicLong(0L),
    val animationFrameCount: AtomicLong = AtomicLong(0L)
) {
    fun reset() {
        drawCount.set(0L)
        animationFrameCount.set(0L)
    }
}

/**
 * 0-FPS Zero-Allocation Dual-Core Neural Canvas.
 *
 * - Allocates [NeuralCanvasPalette], [NeuralCanvasBuffers], and [NeuralCanvasEngine] once via
 *   [remember] outside the draw loop.
 * - Pre-formats [neuronLabels] with [BidiFormatter] outside the draw loop whenever labels or
 *   [LayoutDirection] change.
 * - Sleeps at 0 FPS when [NeuralCanvasState.isIdle] is true without subscribing to
 *   [withInfiniteAnimationFrameMillis].
 */
@Composable
fun DualCoreNeuralCanvas(
    state: NeuralCanvasState,
    neuronLabels: Map<NeuronNodeId, String>,
    onNeuronTapped: (NeuronNodeId) -> Unit,
    modifier: Modifier = Modifier,
    onPulseCompleted: ((eventId: String) -> Unit)? = null,
    frameMetricsHook: NeuralCanvasFrameMetrics? = null
) {
    val density = LocalDensity.current
    val layoutDirection = LocalLayoutDirection.current
    val isRtl = layoutDirection == LayoutDirection.Rtl

    val palette = remember(density.density, density.fontScale) {
        NeuralCanvasPalette.create(
            density = density.density,
            fontScale = density.fontScale
        )
    }
    val buffers = remember { NeuralCanvasBuffers() }
    val engine = remember { NeuralCanvasEngine() }
    val bidiFormatter = remember(isRtl) { BidiFormatter.getInstance(isRtl) }

    remember(neuronLabels, isRtl) {
        buffers.updateFormattedLabels(neuronLabels) { label ->
            bidiFormatter.unicodeWrap(label)
        }
        true
    }

    val latestState by rememberUpdatedState(state)
    val latestOnNeuronTapped by rememberUpdatedState(onNeuronTapped)
    val latestOnPulseCompleted by rememberUpdatedState(onPulseCompleted)

    var frameTick by remember { mutableLongStateOf(0L) }

    LaunchedEffect(state.isIdle, state.activePulse?.eventId, state.coreState) {
        if (state.isIdle) {
            engine.resetToIdle(buffers)
            engine.syncVisualState(state, buffers)
            if (frameTick != 0L) {
                frameTick += 1L
            }
            return@LaunchedEffect
        }

        var previousFrameMs = -1L
        while (isActive) {
            val completedEventId = withInfiniteAnimationFrameMillis { frameTimeMs ->
                val deltaMs = if (previousFrameMs < 0L) {
                    DEFAULT_FIRST_FRAME_DELTA_MS
                } else {
                    (frameTimeMs - previousFrameMs).coerceAtLeast(0L)
                }
                previousFrameMs = frameTimeMs

                val doneEventId = engine.stepFrame(
                    deltaMs = deltaMs,
                    state = latestState,
                    buffers = buffers
                )
                frameMetricsHook?.animationFrameCount?.incrementAndGet()
                frameTick += 1L
                doneEventId
            }

            if (completedEventId != null) {
                latestOnPulseCompleted?.invoke(completedEventId)
            }

            if (latestState.isIdle || (latestState.coreState == CoreActivityState.IDLE && buffers.pulseCompleted)) {
                break
            }
        }
    }

    val tapModifier = modifier.pointerInput(Unit) {
        detectTapGestures { offset ->
            val tappedNode = engine.hitTestNeuron(offset.x, offset.y, buffers)
            if (tappedNode != null) {
                latestOnNeuronTapped(tappedNode)
            }
        }
    }

    Canvas(modifier = tapModifier) {
        val currentTick = frameTick
        if (currentTick < 0L) {
            return@Canvas
        }
        frameMetricsHook?.drawCount?.incrementAndGet()
        engine.syncLayoutIfNeeded(size.width, size.height, buffers)
        engine.syncVisualState(state, buffers)
        engine.render(this, state, palette, buffers)
    }
}

private const val DEFAULT_FIRST_FRAME_DELTA_MS: Long = 16L

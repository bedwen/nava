package com.nava.app.ui.canvas

import androidx.compose.animation.core.withInfiniteAnimationFrameMillis
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.core.text.BidiFormatter
import com.nava.app.R
import com.nava.domain.ui.CoreActivityState
import com.nava.domain.ui.NeuralCanvasState
import com.nava.domain.ui.NeuronNodeId
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.roundToInt
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
 * - Wraps the radial coordinate stage in [LayoutDirection.Ltr] so geometry stays direction-
 *   independent in RTL locales while text labels and overlay pills respect the user's locale.
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
    frameMetricsHook: NeuralCanvasFrameMetrics? = null,
    visibleNodes: List<NeuronNodeId>? = null,
    permittedNodes: Set<NeuronNodeId>? = null,
    isDarkTheme: Boolean = false,
    showHud: Boolean = false,
    emptyStateHint: String? = null,
    activeLayerLabel: String? = null
) {
    val density = LocalDensity.current
    val outerLayoutDirection = LocalLayoutDirection.current
    val isRtl = outerLayoutDirection == LayoutDirection.Rtl

    val palette = remember(density.density, density.fontScale, isDarkTheme) {
        NeuralCanvasPalette.create(
            density = density.density,
            fontScale = density.fontScale,
            isDarkTheme = isDarkTheme
        )
    }
    val buffers = remember { NeuralCanvasBuffers() }
    val engine = remember { NeuralCanvasEngine() }
    val bidiFormatter = remember(isRtl) { BidiFormatter.getInstance(isRtl) }

    var frameTick by remember { mutableLongStateOf(0L) }
    var layoutRevision by remember { mutableIntStateOf(0) }

    val effectiveVisibleNodes = visibleNodes ?: NeuronNodeId.entries
    remember(effectiveVisibleNodes) {
        val changed = buffers.setVisibleNodes(effectiveVisibleNodes)
        if (changed && buffers.lastWidth > 0f && buffers.lastHeight > 0f) {
            engine.syncLayoutIfNeeded(
                width = buffers.lastWidth,
                height = buffers.lastHeight,
                buffers = buffers,
                forceRecompute = true,
                ellipticalLayout = true
            )
            layoutRevision += 1
            frameTick += 1L
        }
        changed
    }

    remember(permittedNodes) {
        if (buffers.setPermittedNodes(permittedNodes)) {
            frameTick += 1L
        }
        true
    }

    remember(neuronLabels, isRtl) {
        buffers.updateFormattedLabels(neuronLabels) { label ->
            bidiFormatter.unicodeWrap(label)
        }
        true
    }

    val latestState by rememberUpdatedState(state)
    val latestOnNeuronTapped by rememberUpdatedState(onNeuronTapped)
    val latestOnPulseCompleted by rememberUpdatedState(onPulseCompleted)

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

    val halfTouchTargetPx = with(density) { (MIN_TOUCH_TARGET_DP * 0.5f).toPx() }

    Box(
        modifier = modifier.onSizeChanged { intSize ->
            val w = intSize.width.toFloat()
            val h = intSize.height.toFloat()
            if (w > 0f && h > 0f) {
                val recomputed = engine.syncLayoutIfNeeded(w, h, buffers, ellipticalLayout = true)
                if (recomputed) {
                    layoutRevision += 1
                }
            }
        }
    ) {
        // Radial coordinate stage stays direction-independent (LTR) even in RTL locales.
        CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
            Box(modifier = Modifier.fillMaxSize()) {
                Canvas(
                    modifier = Modifier
                        .fillMaxSize()
                        .pointerInput(Unit) {
                            detectTapGestures { offset ->
                                val tappedNode = engine.hitTestNeuron(offset.x, offset.y, buffers)
                                if (tappedNode != null) {
                                    latestOnNeuronTapped(tappedNode)
                                }
                            }
                        }
                ) {
                    val currentTick = frameTick
                    if (currentTick < 0L) {
                        return@Canvas
                    }
                    frameMetricsHook?.drawCount?.incrementAndGet()
                    engine.syncLayoutIfNeeded(size.width, size.height, buffers, ellipticalLayout = true)
                    engine.syncVisualState(state, buffers)
                    engine.render(this, state, palette, buffers)
                }

                // Accessible 48dp semantic touch targets positioned from pre-computed buffers.
                if (layoutRevision > 0 && buffers.visibleNodeCount > 0) {
                    for (slot in 0 until buffers.visibleNodeCount) {
                        val idx = buffers.visibleNodeIndices[slot]
                        if (idx < 0 || idx >= NeuralCanvasBuffers.NEURON_COUNT) {
                            continue
                        }
                        val nodeId = NeuralCanvasBuffers.NEURON_NODES[idx]
                        val nodeLabel = neuronLabels[nodeId].orEmpty().ifBlank { nodeId.name }
                        val targetOffsetX = (buffers.nodeX[idx] - halfTouchTargetPx).roundToInt()
                        val targetOffsetY = (buffers.nodeY[idx] - halfTouchTargetPx).roundToInt()
                        Box(
                            modifier = Modifier
                                .offset { IntOffset(targetOffsetX, targetOffsetY) }
                                .size(MIN_TOUCH_TARGET_DP)
                                .semantics {
                                    contentDescription = nodeLabel
                                    role = Role.Button
                                    onClick(label = nodeLabel) {
                                        latestOnNeuronTapped(nodeId)
                                        true
                                    }
                                }
                        )
                    }
                }
            }
        }

        // Overlay status pills respect the user's outer locale direction.
        CompositionLocalProvider(LocalLayoutDirection provides outerLayoutDirection) {
            if (visibleNodes != null && visibleNodes.isEmpty() && !emptyStateHint.isNullOrBlank()) {
                Surface(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(bottom = 12.dp, start = 20.dp, end = 20.dp),
                    shape = RoundedCornerShape(16.dp),
                    color = palette.hubBackdrop,
                    border = BorderStroke(1.dp, palette.orbitRing)
                ) {
                    Text(
                        text = emptyStateHint,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp)
                    )
                }
            } else if (!state.isIdle && !activeLayerLabel.isNullOrBlank()) {
                Surface(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(bottom = 8.dp, start = 16.dp, end = 16.dp),
                    shape = RoundedCornerShape(18.dp),
                    color = palette.hubBackdrop,
                    border = BorderStroke(1.dp, palette.edgeActive)
                ) {
                    Text(
                        text = "\u2022  $activeLayerLabel",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 5.dp)
                    )
                }
            }
        }
    }
}

private val MIN_TOUCH_TARGET_DP = 48.dp
private const val DEFAULT_FIRST_FRAME_DELTA_MS: Long = 16L

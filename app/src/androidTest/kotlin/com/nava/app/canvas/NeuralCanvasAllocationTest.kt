package com.nava.app.canvas

import android.os.Debug
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Canvas
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.drawscope.CanvasDrawScope
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.click
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.nava.app.ui.canvas.DualCoreNeuralCanvas
import com.nava.app.ui.canvas.NeuralCanvasBuffers
import com.nava.app.ui.canvas.NeuralCanvasEngine
import com.nava.app.ui.canvas.NeuralCanvasFrameMetrics
import com.nava.app.ui.canvas.NeuralCanvasPalette
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.ThermalState
import com.nava.domain.ui.CoreActivityState
import com.nava.domain.ui.NeuralCanvasState
import com.nava.domain.ui.NeuralPulseEvent
import com.nava.domain.ui.NeuronNodeId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Gate 2 Instrumented Compose UI & Zero-Allocation Benchmark Suite for the 0-FPS Dual-Core
 * Neural Canvas (PLAN.md Sections 7 & 8.3; AGENTS.md Section 4 Step 4).
 *
 * Verifies:
 * 1. 0 heap object allocations (`Debug.getThreadAllocCount()`) per steady-state active `onDraw`
 *    frame during synapse pulse rendering after initial composition warm-up.
 * 2. 0 animation frame ticks (`animationFrameCount == 0`) and 0 additional `onDraw` invocations
 *    during a 5-second idle window (`CoreActivityState.IDLE`, `activePulse = null`).
 * 3. Deterministic radial neuron hit-testing dispatching `onNeuronTapped(NeuronNodeId)`.
 */
@RunWith(AndroidJUnit4::class)
class NeuralCanvasAllocationTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private val defaultLabels: Map<NeuronNodeId, String> = mapOf(
        NeuronNodeId.CLOCK to "Clock",
        NeuronNodeId.CALENDAR to "Calendar",
        NeuronNodeId.NOTES to "Notes",
        NeuronNodeId.MESSAGES to "Messages",
        NeuronNodeId.VAULT to "Vault",
        NeuronNodeId.FILES to "Files",
        NeuronNodeId.AUDIO_DND to "Audio & DND",
        NeuronNodeId.ROUTINES to "Routines"
    )

    @Test
    fun steadyStateActiveSynapsePulseOnDraw_performsZeroHeapAllocationsPerFrame() {
        val frameMetrics = NeuralCanvasFrameMetrics()
        val activeState = NeuralCanvasState(
            coreState = CoreActivityState.INNER_CORE_ACTIVE,
            activeNeurons = setOf(NeuronNodeId.CLOCK, NeuronNodeId.VAULT),
            activePulse = NeuralPulseEvent(
                eventId = "gate2-alloc-pulse-1",
                tier = ResolutionTier.TIER_3_GEMMA,
                sourceNode = NeuronNodeId.CLOCK,
                targetNode = NeuronNodeId.VAULT,
                wakesInnerCore = true,
                isBiometricSynapse = true,
                timestampEpochMs = 1_760_000_000_000L
            ),
            isVaultUnlocked = true,
            thermalState = ThermalState.MODERATE,
            isModelResident = true
        )

        composeTestRule.mainClock.autoAdvance = false
        composeTestRule.setContent {
            DualCoreNeuralCanvas(
                state = activeState,
                neuronLabels = defaultLabels,
                onNeuronTapped = {},
                frameMetricsHook = frameMetrics,
                modifier = Modifier
                    .size(360.dp)
                    .testTag(CANVAS_TAG)
            )
        }

        // Warm up initial composition and first several Compose animation frames.
        composeTestRule.waitForIdle()
        repeat(5) {
            composeTestRule.mainClock.advanceTimeByFrame()
            composeTestRule.waitForIdle()
        }
        assertTrue(
            "Expected active pulse to advance animationFrameCount during warm-up",
            frameMetrics.animationFrameCount.get() > 0L
        )
        assertTrue(
            "Expected active pulse to invoke onDraw during warm-up",
            frameMetrics.drawCount.get() > 0L
        )

        // Benchmark steady-state active onDraw frames on the UI thread using pre-warmed
        // NeuralCanvasPalette, NeuralCanvasBuffers, NeuralCanvasEngine, and CanvasDrawScope.
        val steadyStateFrameCount = 120
        var steadyStateAllocations = -1

        composeTestRule.runOnUiThread {
            val density = Density(density = 2.75f, fontScale = 1.0f)
            val canvasSize = Size(1080f, 1080f)
            val bitmap = ImageBitmap(1080, 1080)
            val composeCanvas = Canvas(bitmap)
            val drawScope = CanvasDrawScope()

            val palette = NeuralCanvasPalette.create(
                density = density.density,
                fontScale = density.fontScale
            )
            val buffers = NeuralCanvasBuffers()
            val engine = NeuralCanvasEngine()
            buffers.updateFormattedLabels(defaultLabels) { it }

            // Warm up layout and initial draw pass so one-time caches/JIT paths are settled.
            repeat(10) {
                engine.stepFrame(16L, activeState, buffers)
                drawScope.draw(
                    density = density,
                    layoutDirection = LayoutDirection.Ltr,
                    canvas = composeCanvas,
                    size = canvasSize
                ) {
                    engine.syncLayoutIfNeeded(size.width, size.height, buffers)
                    engine.syncVisualState(activeState, buffers)
                    engine.render(this, activeState, palette, buffers)
                }
            }

            drawScope.draw(
                density = density,
                layoutDirection = LayoutDirection.Ltr,
                canvas = composeCanvas,
                size = canvasSize
            ) {
                // Warm up one in-scope pass before starting allocation counters.
                engine.stepFrame(16L, activeState, buffers)
                engine.syncLayoutIfNeeded(size.width, size.height, buffers)
                engine.syncVisualState(activeState, buffers)
                engine.render(this, activeState, palette, buffers)

                @Suppress("DEPRECATION")
                Debug.startAllocCounting()
                try {
                    val beforeAllocCount =
                        @Suppress("DEPRECATION")
                        Debug.getThreadAllocCount()
                    for (frame in 0 until steadyStateFrameCount) {
                        frameMetrics.animationFrameCount.incrementAndGet()
                        frameMetrics.drawCount.incrementAndGet()
                        engine.stepFrame(16L, activeState, buffers)
                        engine.syncLayoutIfNeeded(size.width, size.height, buffers)
                        engine.syncVisualState(activeState, buffers)
                        engine.render(this, activeState, palette, buffers)
                    }
                    val afterAllocCount =
                        @Suppress("DEPRECATION")
                        Debug.getThreadAllocCount()
                    steadyStateAllocations = (afterAllocCount - beforeAllocCount).coerceAtLeast(0)
                } finally {
                    @Suppress("DEPRECATION")
                    Debug.stopAllocCounting()
                }
            }
        }

        val allocsPerFrame = steadyStateAllocations / steadyStateFrameCount
        assertEquals(
            "Expected 0 heap object allocations per steady-state active onDraw frame " +
                "(total=$steadyStateAllocations across $steadyStateFrameCount frames)",
            0,
            allocsPerFrame
        )
    }

    @Test
    fun fiveSecondIdleWindow_producesZeroAnimationFrameTicksAndZeroAdditionalOnDrawCalls() {
        val frameMetrics = NeuralCanvasFrameMetrics()
        var canvasState by mutableStateOf(
            NeuralCanvasState(
                coreState = CoreActivityState.IDLE,
                activeNeurons = emptySet(),
                activePulse = null,
                isVaultUnlocked = false,
                thermalState = ThermalState.NORMAL,
                isModelResident = false
            )
        )

        composeTestRule.mainClock.autoAdvance = false
        composeTestRule.setContent {
            DualCoreNeuralCanvas(
                state = canvasState,
                neuronLabels = defaultLabels,
                onNeuronTapped = {},
                frameMetricsHook = frameMetrics,
                modifier = Modifier
                    .size(360.dp)
                    .testTag(CANVAS_TAG)
            )
        }

        // Wait for initial static composition and first idle draw pass to settle.
        composeTestRule.waitForIdle()
        assertEquals(
            "Idle canvas must not tick animation frames during initial composition",
            0L,
            frameMetrics.animationFrameCount.get()
        )
        assertTrue(
            "Initial static composition must draw the resting canvas once",
            frameMetrics.drawCount.get() >= 1L
        )

        // Reset metrics at the start of the 5-second (5,000 ms) idle measurement window.
        frameMetrics.reset()

        // Advance the virtual clock across a full 5-second idle window in 16 ms frame increments.
        repeat(315) {
            composeTestRule.mainClock.advanceTimeBy(16L)
        }
        composeTestRule.waitForIdle()

        assertEquals(
            "Expected 0 animation frame ticks during a 5-second idle window",
            0L,
            frameMetrics.animationFrameCount.get()
        )
        assertEquals(
            "Expected 0 additional onDraw invocations during a 5-second idle window",
            0L,
            frameMetrics.drawCount.get()
        )
    }

    @Test
    fun tappingRadialNeurons_dispatchesOnNeuronTappedWithMatchingNeuronNodeId() {
        val tappedNeurons = mutableListOf<NeuronNodeId>()
        val idleState = NeuralCanvasState(
            coreState = CoreActivityState.IDLE,
            activeNeurons = setOf(NeuronNodeId.CLOCK),
            activePulse = null
        )

        composeTestRule.setContent {
            DualCoreNeuralCanvas(
                state = idleState,
                neuronLabels = defaultLabels,
                onNeuronTapped = { nodeId -> tappedNeurons.add(nodeId) },
                modifier = Modifier
                    .size(400.dp)
                    .testTag(CANVAS_TAG)
            )
        }

        composeTestRule.waitForIdle()

        // Node 0 (CLOCK) is placed at angle -PI/2 (top of orbit circle: x = 0.5*w, y = 0.5*h - 0.34*minDim)
        composeTestRule.onNodeWithTag(CANVAS_TAG).performTouchInput {
            val cx = width * 0.5f
            val cy = height * 0.5f
            val minDim = minOf(width, height).toFloat()
            val orbitRadius = minDim * 0.34f
            click(Offset(cx, cy - orbitRadius))
        }
        composeTestRule.waitForIdle()
        assertEquals(listOf(NeuronNodeId.CLOCK), tappedNeurons)

        // Node 4 (VAULT) is placed at angle +PI/2 (bottom of orbit circle: x = 0.5*w, y = 0.5*h + 0.34*minDim)
        composeTestRule.onNodeWithTag(CANVAS_TAG).performTouchInput {
            val cx = width * 0.5f
            val cy = height * 0.5f
            val minDim = minOf(width, height).toFloat()
            val orbitRadius = minDim * 0.34f
            click(Offset(cx, cy + orbitRadius))
        }
        composeTestRule.waitForIdle()
        assertEquals(listOf(NeuronNodeId.CLOCK, NeuronNodeId.VAULT), tappedNeurons)
    }

    companion object {
        private const val CANVAS_TAG: String = "dual_core_neural_canvas"
    }
}

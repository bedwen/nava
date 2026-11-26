package com.nava.app.ui.canvas

import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ui.CoreActivityState
import com.nava.domain.ui.NeuralCanvasState
import com.nava.domain.ui.NeuralPulseEvent
import com.nava.domain.ui.NeuronNodeId
import kotlin.math.PI
import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.hypot
import kotlin.math.sin
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class NeuralCanvasStep2DynamicLayoutTest {

    @Test
    fun emptyVisibleNodes_defaultDenyLayoutSucceedsAndHitTestReturnsNullEverywhere() {
        val engine = NeuralCanvasEngine()
        val buffers = NeuralCanvasBuffers()

        buffers.setVisibleNodes(emptyList())
        assertEquals(0, buffers.visibleNodeCount)
        assertTrue(engine.syncLayoutIfNeeded(1000f, 1000f, buffers, forceRecompute = true))

        assertNull(engine.hitTestNeuron(buffers.centerX, buffers.centerY, buffers))
        val orbitR = buffers.ringRadii[NeuralCanvasBuffers.RING_ORBIT]
        for (step in 0 until 16) {
            val angle = step * (2.0 * PI / 16.0)
            val px = buffers.centerX + orbitR * cos(angle).toFloat()
            val py = buffers.centerY + orbitR * sin(angle).toFloat()
            assertNull("Hidden orbit position must return null when N=0", engine.hitTestNeuron(px, py, buffers))
        }
        for (gx in 0..10) {
            for (gy in 0..10) {
                assertNull(
                    "Canvas grid point ($gx, $gy) must return null when N=0",
                    engine.hitTestNeuron(gx * 100f, gy * 100f, buffers)
                )
            }
        }
    }

    @Test
    fun threeVisibleNodes_spacedAt120DegreesAndHiddenNodesIgnored() {
        val engine = NeuralCanvasEngine()
        val buffers = NeuralCanvasBuffers()
        val visible = listOf(NeuronNodeId.CLOCK, NeuronNodeId.CALENDAR, NeuronNodeId.NOTES)

        buffers.setVisibleNodes(visible)
        assertEquals(3, buffers.visibleNodeCount)
        assertTrue(engine.syncLayoutIfNeeded(1000f, 1000f, buffers, forceRecompute = true))

        val orbitR = buffers.ringRadii[NeuralCanvasBuffers.RING_ORBIT]
        assertTrue(orbitR > 0f)

        val angles = DoubleArray(visible.size)
        for ((i, node) in visible.withIndex()) {
            val idx = NeuralCanvasBuffers.indexOf(node)
            val nx = buffers.nodeX[idx]
            val ny = buffers.nodeY[idx]
            val dist = hypot((nx - buffers.centerX).toDouble(), (ny - buffers.centerY).toDouble()).toFloat()
            assertEquals("Visible node $node must sit on the orbit circle", orbitR, dist, 0.5f)
            assertEquals("hitTestNeuron must resolve visible node $node", node, engine.hitTestNeuron(nx, ny, buffers))
            angles[i] = atan2((ny - buffers.centerY).toDouble(), (nx - buffers.centerX).toDouble())
        }

        angles.sort()
        val expectedSpacingRad = (2.0 * PI) / 3.0
        assertEquals(expectedSpacingRad, angles[1] - angles[0], 0.01)
        assertEquals(expectedSpacingRad, angles[2] - angles[1], 0.01)
        assertEquals(expectedSpacingRad, (angles[0] + 2.0 * PI) - angles[2], 0.01)

        val vaultIdx = NeuralCanvasBuffers.indexOf(NeuronNodeId.VAULT)
        assertNotEquals(
            NeuronNodeId.VAULT,
            engine.hitTestNeuron(buffers.nodeX[vaultIdx], buffers.nodeY[vaultIdx], buffers)
        )
        assertNull(engine.hitTestNeuron(buffers.centerX, buffers.centerY + orbitR, buffers))

        val visibleSet = visible.toSet()
        for (step in 0 until 72) {
            val angle = step * (2.0 * PI / 72.0)
            val px = buffers.centerX + orbitR * cos(angle).toFloat()
            val py = buffers.centerY + orbitR * sin(angle).toFloat()
            val hit = engine.hitTestNeuron(px, py, buffers)
            if (hit != null) {
                assertTrue("Hit node $hit must belong to visible set", hit in visibleSet)
                assertNotEquals(NeuronNodeId.VAULT, hit)
            }
        }
    }

    @Test
    fun dynamicLayoutAndPulseStepping_preserveAllStep2BufferIdentities() {
        val engine = NeuralCanvasEngine()
        val buffers = NeuralCanvasBuffers()

        val edgeControlXRef = buffers.edgeControlX
        val edgeControlYRef = buffers.edgeControlY
        val returnPulsePointsXRef = buffers.returnPulsePointsX
        val returnPulsePointsYRef = buffers.returnPulsePointsY
        val returnPulsePointsAlphaRef = buffers.returnPulsePointsAlpha
        val visibleNodeIndicesRef = buffers.visibleNodeIndices

        val activeState = NeuralCanvasState(
            coreState = CoreActivityState.OUTER_SHELL_ACTIVE,
            activeNeurons = setOf(NeuronNodeId.CLOCK, NeuronNodeId.NOTES),
            activePulse = NeuralPulseEvent(
                eventId = "step2-identity-pulse",
                tier = ResolutionTier.TIER_1_RULE,
                sourceNode = null,
                targetNode = NeuronNodeId.CLOCK,
                wakesInnerCore = false,
                timestampEpochMs = 1_000L
            )
        )
        val idleState = NeuralCanvasState(coreState = CoreActivityState.IDLE)

        val nodeSubsets = listOf(
            emptyList(),
            listOf(NeuronNodeId.CLOCK, NeuronNodeId.CALENDAR, NeuronNodeId.NOTES),
            listOf(
                NeuronNodeId.CLOCK,
                NeuronNodeId.CALENDAR,
                NeuronNodeId.NOTES,
                NeuronNodeId.MESSAGES,
                NeuronNodeId.ROUTINES
            ),
            NeuronNodeId.entries.toList()
        )

        for ((round, subset) in nodeSubsets.withIndex()) {
            buffers.setVisibleNodes(subset)
            engine.syncLayoutIfNeeded(1000f + round * 40f, 960f + round * 40f, buffers, forceRecompute = true)
            repeat(35) {
                engine.stepFrame(16L, activeState, buffers)
            }
            engine.stepFrame(16L, idleState, buffers)
        }

        assertSame(edgeControlXRef, buffers.edgeControlX)
        assertSame(edgeControlYRef, buffers.edgeControlY)
        assertSame(returnPulsePointsXRef, buffers.returnPulsePointsX)
        assertSame(returnPulsePointsYRef, buffers.returnPulsePointsY)
        assertSame(returnPulsePointsAlphaRef, buffers.returnPulsePointsAlpha)
        assertSame(visibleNodeIndicesRef, buffers.visibleNodeIndices)
    }

    @Test
    fun bidirectionalReturnPulse_activatesInLatePhaseAndResetsCleanlyOnIdle() {
        val engine = NeuralCanvasEngine()
        val buffers = NeuralCanvasBuffers()

        buffers.setVisibleNodes(listOf(NeuronNodeId.CLOCK, NeuronNodeId.CALENDAR, NeuronNodeId.NOTES))
        assertTrue(engine.syncLayoutIfNeeded(1000f, 1000f, buffers, forceRecompute = true))

        val pulseState = NeuralCanvasState(
            coreState = CoreActivityState.OUTER_SHELL_ACTIVE,
            activeNeurons = setOf(NeuronNodeId.CLOCK),
            activePulse = NeuralPulseEvent(
                eventId = "step2-return-pulse",
                tier = ResolutionTier.TIER_1_RULE,
                sourceNode = null,
                targetNode = NeuronNodeId.CLOCK,
                wakesInnerCore = false,
                timestampEpochMs = 2_000L
            )
        )

        // Early frame must not activate return pulse prematurely.
        engine.stepFrame(16L, pulseState, buffers)
        assertFalse(buffers.returnPulseActive)

        var sawLateReturnPulse = false
        for (frame in 0 until 45) {
            engine.stepFrame(16L, pulseState, buffers)
            if (buffers.returnPulseActive && buffers.returnPulsePointCount >= 2) {
                sawLateReturnPulse = true
                assertTrue("Return pulse should activate in late phase", buffers.pulseProgress >= 0.4f)
                for (i in 0 until buffers.returnPulsePointCount) {
                    assertTrue(buffers.returnPulsePointsX[i].isFinite())
                    assertTrue(buffers.returnPulsePointsY[i].isFinite())
                    assertTrue(buffers.returnPulsePointsAlpha[i] in 0f..1f)
                }
            }
        }
        assertTrue(
            "Bidirectional return confirmation pulse must activate during late phase of hub-to-node pulse",
            sawLateReturnPulse
        )

        val idleState = NeuralCanvasState(coreState = CoreActivityState.IDLE, activePulse = null)
        engine.stepFrame(16L, idleState, buffers)

        assertFalse(buffers.returnPulseActive)
        assertEquals(0, buffers.returnPulsePointCount)
        assertEquals(0f, buffers.pulseProgress, 0.0f)
        for (i in 0 until NeuralCanvasBuffers.PULSE_TRAIL_SAMPLES) {
            assertEquals(0f, buffers.returnPulsePointsAlpha[i], 0.0f)
        }
    }

    @Test
    fun paletteCreateForJvm_lightAndDarkThemesProvideDistinctStageAndReturnColors() {
        val lightPalette = NeuralCanvasPalette.createForJvm(isDarkTheme = false)
        val darkPalette = NeuralCanvasPalette.createForJvm(isDarkTheme = true)

        assertNotEquals(lightPalette.stageBackground, darkPalette.stageBackground)
        assertNotEquals(lightPalette.returnPulseColor, darkPalette.returnPulseColor)

        assertTrue(
            "Warm-paper light stageBackground must be brighter than matte OLED dark stageBackground",
            lightPalette.stageBackground.red > darkPalette.stageBackground.red &&
                lightPalette.stageBackground.green > darkPalette.stageBackground.green &&
                lightPalette.stageBackground.blue > darkPalette.stageBackground.blue
        )
    }
}

package com.nava.app.ui.canvas

import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.ThermalState
import com.nava.domain.ui.CoreActivityState
import com.nava.domain.ui.NeuralCanvasState
import com.nava.domain.ui.NeuralPulseEvent
import com.nava.domain.ui.NeuronNodeId
import kotlin.math.abs
import kotlin.math.hypot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class NeuralCanvasEngineTest {

    @Test
    fun syncLayoutIfNeeded_computesSymmetricRadialGeometryForAll8NeuronsAndRecomputesOnlyOnResize() {
        val engine = NeuralCanvasEngine()
        val buffers = NeuralCanvasBuffers()

        assertFalse(engine.syncLayoutIfNeeded(0f, 800f, buffers))
        assertFalse(engine.syncLayoutIfNeeded(800f, -10f, buffers))
        assertEquals(0, buffers.layoutComputeCount)

        assertTrue(engine.syncLayoutIfNeeded(1000f, 800f, buffers))
        assertEquals(1, buffers.layoutComputeCount)
        assertEquals(500f, buffers.centerX, 0.001f)
        assertEquals(400f, buffers.centerY, 0.001f)
        assertEquals(800f, buffers.minDimension, 0.001f)

        // Concentric hub rings must be strictly ordered inward to outward.
        val innerR = buffers.ringRadii[NeuralCanvasBuffers.RING_INNER_CORE]
        val outerR = buffers.ringRadii[NeuralCanvasBuffers.RING_OUTER_SHELL]
        val thermalR = buffers.ringRadii[NeuralCanvasBuffers.RING_THERMAL]
        val orbitR = buffers.ringRadii[NeuralCanvasBuffers.RING_ORBIT]
        assertTrue(innerR > 0f && innerR < outerR)
        assertTrue(outerR < thermalR)
        assertTrue(thermalR < orbitR)

        // Every neuron sits on the orbit circle, stays within canvas bounds, and has non-overlapping neighbors.
        for (i in 0 until NeuralCanvasBuffers.NEURON_COUNT) {
            val nx = buffers.nodeX[i]
            val ny = buffers.nodeY[i]
            val nr = buffers.nodeRadii[i]
            val distFromCenter = hypot((nx - buffers.centerX).toDouble(), (ny - buffers.centerY).toDouble()).toFloat()
            assertEquals(orbitR, distFromCenter, 0.05f)
            assertTrue(nx - nr > 0f && nx + nr < 1000f)
            assertTrue(ny - nr > 0f && buffers.nodeLabelY[i] < 800f)

            val startDist = hypot(
                (buffers.edgeStartX[i] - buffers.centerX).toDouble(),
                (buffers.edgeStartY[i] - buffers.centerY).toDouble()
            ).toFloat()
            val endDist = hypot(
                (buffers.edgeEndX[i] - buffers.centerX).toDouble(),
                (buffers.edgeEndY[i] - buffers.centerY).toDouble()
            ).toFloat()
            assertEquals(outerR, startDist, 0.05f)
            assertEquals(orbitR - nr, endDist, 0.05f)

            val next = (i + 1) % NeuralCanvasBuffers.NEURON_COUNT
            val neighborDist = hypot(
                (buffers.nodeX[next] - nx).toDouble(),
                (buffers.nodeY[next] - ny).toDouble()
            ).toFloat()
            assertTrue("Adjacent neurons must not overlap", neighborDist > nr * 2.5f)
        }

        // CLOCK is at top (-PI/2), VAULT is directly opposite at bottom (+PI/2).
        val clockIdx = NeuralCanvasBuffers.indexOf(NeuronNodeId.CLOCK)
        val vaultIdx = NeuralCanvasBuffers.indexOf(NeuronNodeId.VAULT)
        assertEquals(buffers.centerX, buffers.nodeX[clockIdx], 0.05f)
        assertEquals(buffers.centerY - orbitR, buffers.nodeY[clockIdx], 0.05f)
        assertEquals(buffers.centerX, buffers.nodeX[vaultIdx], 0.05f)
        assertEquals(buffers.centerY + orbitR, buffers.nodeY[vaultIdx], 0.05f)

        // Calling with identical dimensions must NOT recompute layout.
        assertFalse(engine.syncLayoutIfNeeded(1000f, 800f, buffers))
        assertEquals(1, buffers.layoutComputeCount)

        // Resizing must recompute layout once.
        assertTrue(engine.syncLayoutIfNeeded(1080f, 1080f, buffers))
        assertEquals(2, buffers.layoutComputeCount)
        assertEquals(540f, buffers.centerX, 0.001f)
        assertEquals(540f, buffers.centerY, 0.001f)
    }

    @Test
    fun hitTestNeuron_resolvesAll8NodesAndRejectsHubAndEmptySpace() {
        val engine = NeuralCanvasEngine()
        val buffers = NeuralCanvasBuffers()

        // Uninitialized layout always returns null.
        assertNull(engine.hitTestNeuron(100f, 100f, buffers))

        engine.syncLayoutIfNeeded(1000f, 1000f, buffers)

        // Exact center and slight offset within hit radius for every NeuronNodeId.
        for (node in NeuronNodeId.entries) {
            val idx = NeuralCanvasBuffers.indexOf(node)
            val nx = buffers.nodeX[idx]
            val ny = buffers.nodeY[idx]
            val nr = buffers.nodeRadii[idx]
            assertEquals(node, engine.hitTestNeuron(nx, ny, buffers))
            assertEquals(node, engine.hitTestNeuron(nx + nr * 0.8f, ny - nr * 0.4f, buffers))
        }

        // Hub center and canvas corners must return null.
        assertNull(engine.hitTestNeuron(buffers.centerX, buffers.centerY, buffers))
        assertNull(engine.hitTestNeuron(5f, 5f, buffers))
        assertNull(engine.hitTestNeuron(995f, 995f, buffers))
    }

    @Test
    fun dualCoreVisibility_tier1AndTier2KeepInnerCoreDarkWhileTier3WakesInnerCore() {
        val engine = NeuralCanvasEngine()
        val buffers = NeuralCanvasBuffers()
        engine.syncLayoutIfNeeded(900f, 900f, buffers)

        // Tier 1 reflex pulse: Outer Cortex Shell pulses, Inner Core stays strictly dark/asleep.
        val tier1State = NeuralCanvasState(
            coreState = CoreActivityState.OUTER_SHELL_ACTIVE,
            activeNeurons = setOf(NeuronNodeId.CLOCK),
            activePulse = NeuralPulseEvent(
                eventId = "evt-tier1",
                tier = ResolutionTier.TIER_1_RULE,
                sourceNode = null,
                targetNode = NeuronNodeId.CLOCK,
                wakesInnerCore = false,
                timestampEpochMs = 1_000L
            ),
            isModelResident = true
        )
        assertFalse(engine.shouldWakeInnerCore(tier1State))
        repeat(10) {
            engine.stepFrame(16L, tier1State, buffers)
            assertFalse("Tier 1 must never wake Gemma 4 Inner Core", buffers.isInnerCoreAwake)
            assertEquals(0f, buffers.innerCoreGlowAlpha, 0.0f)
            assertTrue("Outer Cortex Shell must pulse on Tier 1", buffers.outerShellPulseAlpha > 0f)
        }

        // Tier 2 cache pulse: Outer Cortex Shell pulses, Inner Core stays strictly dark/asleep.
        val tier2State = NeuralCanvasState(
            coreState = CoreActivityState.OUTER_SHELL_ACTIVE,
            activeNeurons = setOf(NeuronNodeId.AUDIO_DND),
            activePulse = NeuralPulseEvent(
                eventId = "evt-tier2",
                tier = ResolutionTier.TIER_2_CACHE,
                sourceNode = null,
                targetNode = NeuronNodeId.AUDIO_DND,
                wakesInnerCore = false,
                timestampEpochMs = 2_000L
            ),
            isModelResident = true
        )
        assertFalse(engine.shouldWakeInnerCore(tier2State))
        repeat(10) {
            engine.stepFrame(16L, tier2State, buffers)
            assertFalse("Tier 2 must never wake Gemma 4 Inner Core", buffers.isInnerCoreAwake)
            assertEquals(0f, buffers.innerCoreGlowAlpha, 0.0f)
            assertTrue("Outer Cortex Shell must pulse on Tier 2", buffers.outerShellPulseAlpha > 0f)
        }

        // Executing tool with wakesInnerCore = false keeps Inner Core dark.
        val toolNoWakeState = NeuralCanvasState(
            coreState = CoreActivityState.EXECUTING_TOOL,
            activePulse = NeuralPulseEvent(
                eventId = "evt-tool-no-wake",
                tier = ResolutionTier.TIER_1_RULE,
                sourceNode = null,
                targetNode = NeuronNodeId.NOTES,
                wakesInnerCore = false,
                timestampEpochMs = 2_500L
            )
        )
        assertFalse(engine.shouldWakeInnerCore(toolNoWakeState))
        engine.stepFrame(16L, toolNoWakeState, buffers)
        assertFalse(buffers.isInnerCoreAwake)
        assertEquals(0f, buffers.innerCoreGlowAlpha, 0.0f)

        // Tier 3 Gemma 4 inference: Inner Core wakes and glows.
        val tier3State = NeuralCanvasState(
            coreState = CoreActivityState.INNER_CORE_ACTIVE,
            activeNeurons = setOf(NeuronNodeId.CALENDAR, NeuronNodeId.NOTES),
            activePulse = NeuralPulseEvent(
                eventId = "evt-tier3",
                tier = ResolutionTier.TIER_3_GEMMA,
                sourceNode = null,
                targetNode = NeuronNodeId.CALENDAR,
                wakesInnerCore = true,
                timestampEpochMs = 3_000L
            ),
            isModelResident = true
        )
        assertTrue(engine.shouldWakeInnerCore(tier3State))
        repeat(10) {
            engine.stepFrame(16L, tier3State, buffers)
            assertTrue("Tier 3 must wake Gemma 4 Inner Core", buffers.isInnerCoreAwake)
            assertTrue("Tier 3 Inner Core must glow", buffers.innerCoreGlowAlpha > 0f)
            assertTrue("Outer Cortex Shell also pulses on Tier 3", buffers.outerShellPulseAlpha > 0f)
        }

        // INNER_CORE_ACTIVE without an active pulse still keeps Inner Core awake & glowing.
        val thinkingOnlyState = NeuralCanvasState(
            coreState = CoreActivityState.INNER_CORE_ACTIVE,
            activePulse = null
        )
        assertTrue(engine.shouldWakeInnerCore(thinkingOnlyState))
        engine.stepFrame(16L, thinkingOnlyState, buffers)
        assertTrue(buffers.isInnerCoreAwake)
        assertTrue(buffers.innerCoreGlowAlpha > 0f)

        // A pulse with wakesInnerCore = true wakes Inner Core even if coreState is EXECUTING_TOOL.
        val pulseWakeState = NeuralCanvasState(
            coreState = CoreActivityState.EXECUTING_TOOL,
            activePulse = NeuralPulseEvent(
                eventId = "evt-pulse-wake",
                tier = ResolutionTier.TIER_3_GEMMA,
                sourceNode = NeuronNodeId.NOTES,
                targetNode = NeuronNodeId.VAULT,
                wakesInnerCore = true,
                isBiometricSynapse = true,
                timestampEpochMs = 4_000L
            )
        )
        assertTrue(engine.shouldWakeInnerCore(pulseWakeState))
        engine.stepFrame(16L, pulseWakeState, buffers)
        assertTrue(buffers.isInnerCoreAwake)
        assertTrue(buffers.innerCoreGlowAlpha > 0f)
    }

    @Test
    fun pulseTrajectories_differentiateHubToNeuronAndInterNeuronChainsAndFireCompletionOnce() {
        val engine = NeuralCanvasEngine()
        val buffers = NeuralCanvasBuffers()
        engine.syncLayoutIfNeeded(1000f, 1000f, buffers)

        // 1. Hub -> Neuron (Outer Shell edge -> CLOCK) when wakesInnerCore == false
        val clockIdx = NeuralCanvasBuffers.indexOf(NeuronNodeId.CLOCK)
        val hubPulseState = NeuralCanvasState(
            coreState = CoreActivityState.OUTER_SHELL_ACTIVE,
            activePulse = NeuralPulseEvent(
                eventId = "pulse-hub-1",
                tier = ResolutionTier.TIER_1_RULE,
                sourceNode = null,
                targetNode = NeuronNodeId.CLOCK,
                wakesInnerCore = false,
                timestampEpochMs = 100L
            )
        )

        var completedCount = 0
        var lastCompletedId: String? = null
        engine.stepFrame(0L, hubPulseState, buffers)
        assertFalse(buffers.pulseIsInterNeuron)
        assertEquals(buffers.edgeStartX[clockIdx], buffers.pulseStartX, 0.01f)
        assertEquals(buffers.edgeStartY[clockIdx], buffers.pulseStartY, 0.01f)
        assertEquals(buffers.nodeX[clockIdx], buffers.pulseEndX, 0.01f)
        assertEquals(buffers.nodeY[clockIdx], buffers.pulseEndY, 0.01f)
        assertEquals(buffers.pulseStartX, buffers.pulseHeadX, 0.01f)
        assertEquals(buffers.pulseStartY, buffers.pulseHeadY, 0.01f)

        // Step past full Tier 1 duration (420 ms) and confirm completion fires exactly once.
        repeat(40) {
            val doneId = engine.stepFrame(20L, hubPulseState, buffers)
            if (doneId != null) {
                completedCount += 1
                lastCompletedId = doneId
            }
        }
        assertEquals(1, completedCount)
        assertEquals("pulse-hub-1", lastCompletedId)
        assertEquals(1f, buffers.pulseProgress, 0.001f)
        assertEquals(buffers.nodeX[clockIdx], buffers.pulseHeadX, 0.05f)
        assertEquals(buffers.nodeY[clockIdx], buffers.pulseHeadY, 0.05f)

        // 2. Hub -> Neuron (Inner Core center -> VAULT) when wakesInnerCore == true
        val vaultIdx = NeuralCanvasBuffers.indexOf(NeuronNodeId.VAULT)
        val innerHubPulseState = NeuralCanvasState(
            coreState = CoreActivityState.INNER_CORE_ACTIVE,
            activePulse = NeuralPulseEvent(
                eventId = "pulse-hub-inner",
                tier = ResolutionTier.TIER_3_GEMMA,
                sourceNode = null,
                targetNode = NeuronNodeId.VAULT,
                wakesInnerCore = true,
                isBiometricSynapse = true,
                timestampEpochMs = 200L
            )
        )
        engine.stepFrame(0L, innerHubPulseState, buffers)
        assertFalse(buffers.pulseIsInterNeuron)
        assertEquals(buffers.centerX, buffers.pulseStartX, 0.01f)
        assertEquals(buffers.centerY, buffers.pulseStartY, 0.01f)
        assertEquals(buffers.nodeX[vaultIdx], buffers.pulseEndX, 0.01f)
        assertEquals(buffers.nodeY[vaultIdx], buffers.pulseEndY, 0.01f)

        // 3. Inter-Neuron Chain Synapse (CLOCK -> VAULT diametrically opposite) curves around hub.
        val chainPulseState = NeuralCanvasState(
            coreState = CoreActivityState.INNER_CORE_ACTIVE,
            activePulse = NeuralPulseEvent(
                eventId = "pulse-chain-1",
                tier = ResolutionTier.TIER_3_GEMMA,
                sourceNode = NeuronNodeId.CLOCK,
                targetNode = NeuronNodeId.VAULT,
                wakesInnerCore = true,
                timestampEpochMs = 300L
            )
        )
        engine.stepFrame(0L, chainPulseState, buffers)
        assertTrue(buffers.pulseIsInterNeuron)
        assertEquals(clockIdx, buffers.pulseSourceIndex)
        assertEquals(vaultIdx, buffers.pulseTargetIndex)
        assertEquals(buffers.nodeX[clockIdx], buffers.pulseStartX, 0.01f)
        assertEquals(buffers.nodeY[clockIdx], buffers.pulseStartY, 0.01f)
        assertEquals(buffers.nodeX[vaultIdx], buffers.pulseEndX, 0.01f)
        assertEquals(buffers.nodeY[vaultIdx], buffers.pulseEndY, 0.01f)

        // Control point must bow away from the straight midpoint so the arc does not cut straight through the hub.
        val straightMidX = (buffers.pulseStartX + buffers.pulseEndX) * 0.5f
        val straightMidY = (buffers.pulseStartY + buffers.pulseEndY) * 0.5f
        val controlDeviation = hypot(
            (buffers.pulseControlX - straightMidX).toDouble(),
            (buffers.pulseControlY - straightMidY).toDouble()
        ).toFloat()
        assertTrue("Inter-neuron chain control point must curve away from straight chord", controlDeviation > 50f)

        // Advance halfway: pulse head should lie off the straight chord and smoothly reach VAULT at progress == 1f.
        var chainDoneId: String? = null
        repeat(60) {
            val doneId = engine.stepFrame(20L, chainPulseState, buffers)
            if (doneId != null) {
                chainDoneId = doneId
            }
        }
        assertEquals("pulse-chain-1", chainDoneId)
        assertEquals(buffers.nodeX[vaultIdx], buffers.pulseHeadX, 0.05f)
        assertEquals(buffers.nodeY[vaultIdx], buffers.pulseHeadY, 0.05f)
        assertEquals(NeuralCanvasBuffers.PULSE_TRAIL_SAMPLES, buffers.pulsePointCount)

        // 4. Self-chain edge case (VAULT -> VAULT) produces finite non-NaN trail coordinates.
        val selfChainState = NeuralCanvasState(
            coreState = CoreActivityState.EXECUTING_TOOL,
            activePulse = NeuralPulseEvent(
                eventId = "pulse-self-chain",
                tier = ResolutionTier.TIER_2_CACHE,
                sourceNode = NeuronNodeId.VAULT,
                targetNode = NeuronNodeId.VAULT,
                wakesInnerCore = false,
                isBiometricSynapse = true,
                timestampEpochMs = 400L
            )
        )
        engine.stepFrame(100L, selfChainState, buffers)
        for (i in 0 until buffers.pulsePointCount) {
            assertTrue(buffers.pulsePointsX[i].isFinite())
            assertTrue(buffers.pulsePointsY[i].isFinite())
            assertTrue(buffers.pulsePointsAlpha[i].isFinite())
        }
    }

    @Test
    fun bufferIdentityStability_zeroFloatArrayReallocationsAcross5500Steps() {
        val engine = NeuralCanvasEngine()
        val buffers = NeuralCanvasBuffers()

        // Snapshot exact array object identities before running 5,500+ animation steps.
        val nodeXRef = buffers.nodeX
        val nodeYRef = buffers.nodeY
        val nodeRadiiRef = buffers.nodeRadii
        val nodeGlowAlphaRef = buffers.nodeGlowAlpha
        val nodeLabelYRef = buffers.nodeLabelY
        val edgeStartXRef = buffers.edgeStartX
        val edgeStartYRef = buffers.edgeStartY
        val edgeEndXRef = buffers.edgeEndX
        val edgeEndYRef = buffers.edgeEndY
        val edgeAlphaRef = buffers.edgeAlpha
        val pulsePointsXRef = buffers.pulsePointsX
        val pulsePointsYRef = buffers.pulsePointsY
        val pulsePointsAlphaRef = buffers.pulsePointsAlpha
        val ringRadiiRef = buffers.ringRadii
        val formattedLabelsRef = buffers.formattedLabels

        engine.syncLayoutIfNeeded(1080f, 1920f, buffers)

        val nodes = NeuronNodeId.entries
        val tiers = ResolutionTier.entries
        val thermals = ThermalState.entries

        val states = Array(12) { idx ->
            val target = nodes[idx % nodes.size]
            val source = if (idx % 3 == 0) nodes[(idx + 3) % nodes.size] else null
            val tier = tiers[idx % tiers.size]
            val coreState = when (idx % 5) {
                0 -> CoreActivityState.OUTER_SHELL_ACTIVE
                1 -> CoreActivityState.INNER_CORE_ACTIVE
                2 -> CoreActivityState.EXECUTING_TOOL
                3 -> CoreActivityState.ERROR_FLASH
                else -> CoreActivityState.IDLE
            }
            val pulse = if (coreState == CoreActivityState.IDLE) {
                null
            } else {
                NeuralPulseEvent(
                    eventId = "stress-evt-$idx",
                    tier = tier,
                    sourceNode = source,
                    targetNode = target,
                    wakesInnerCore = tier == ResolutionTier.TIER_3_GEMMA,
                    isBiometricSynapse = target == NeuronNodeId.VAULT,
                    timestampEpochMs = 1_000L + idx
                )
            }
            NeuralCanvasState(
                coreState = coreState,
                activeNeurons = setOf(target),
                activePulse = pulse,
                isVaultUnlocked = idx % 2 == 0,
                thermalState = thermals[idx % thermals.size],
                isModelResident = idx % 2 == 1
            )
        }

        val totalSteps = 5_500
        for (step in 0 until totalSteps) {
            if (step == 1_500) {
                engine.syncLayoutIfNeeded(720f, 1280f, buffers)
            } else if (step == 3_500) {
                engine.syncLayoutIfNeeded(1440f, 1440f, buffers)
            }
            val activeState = states[(step / 120) % states.size]
            engine.stepFrame(16L, activeState, buffers)
        }

        // Exact reference identity proves 0 FloatArray/Array reallocations across 5,500 steps.
        assertSame(nodeXRef, buffers.nodeX)
        assertSame(nodeYRef, buffers.nodeY)
        assertSame(nodeRadiiRef, buffers.nodeRadii)
        assertSame(nodeGlowAlphaRef, buffers.nodeGlowAlpha)
        assertSame(nodeLabelYRef, buffers.nodeLabelY)
        assertSame(edgeStartXRef, buffers.edgeStartX)
        assertSame(edgeStartYRef, buffers.edgeStartY)
        assertSame(edgeEndXRef, buffers.edgeEndX)
        assertSame(edgeEndYRef, buffers.edgeEndY)
        assertSame(edgeAlphaRef, buffers.edgeAlpha)
        assertSame(pulsePointsXRef, buffers.pulsePointsX)
        assertSame(pulsePointsYRef, buffers.pulsePointsY)
        assertSame(pulsePointsAlphaRef, buffers.pulsePointsAlpha)
        assertSame(ringRadiiRef, buffers.ringRadii)
        assertSame(formattedLabelsRef, buffers.formattedLabels)

        // All numeric values remain finite and in valid bounds.
        for (i in 0 until NeuralCanvasBuffers.NEURON_COUNT) {
            assertTrue(buffers.nodeX[i].isFinite())
            assertTrue(buffers.nodeY[i].isFinite())
            assertTrue(buffers.nodeGlowAlpha[i] in 0f..1f)
            assertTrue(buffers.edgeAlpha[i] in 0f..1f)
        }
        for (i in 0 until NeuralCanvasBuffers.PULSE_TRAIL_SAMPLES) {
            assertTrue(buffers.pulsePointsX[i].isFinite())
            assertTrue(buffers.pulsePointsY[i].isFinite())
            assertTrue(buffers.pulsePointsAlpha[i] in 0f..1f)
        }
        assertTrue(buffers.stepCount > 4_000L)
    }

    @Test
    fun idleState_zeroAdvanceBehaviorAndCleanResetFromActive() {
        val engine = NeuralCanvasEngine()
        val buffers = NeuralCanvasBuffers()
        engine.syncLayoutIfNeeded(800f, 800f, buffers)

        val idleState = NeuralCanvasState(
            coreState = CoreActivityState.IDLE,
            activeNeurons = setOf(NeuronNodeId.VAULT),
            activePulse = null,
            isVaultUnlocked = false,
            thermalState = ThermalState.NORMAL
        )
        assertTrue(idleState.isIdle)

        repeat(1_000) {
            val done = engine.stepFrame(16L, idleState, buffers)
            assertNull(done)
        }
        assertEquals(0L, buffers.stepCount)
        assertEquals(0f, buffers.corePhaseRadians, 0.0f)
        assertEquals(0f, buffers.pulseProgress, 0.0f)
        assertEquals(0f, buffers.outerShellPulseAlpha, 0.0f)
        assertEquals(0f, buffers.innerCoreGlowAlpha, 0.0f)
        assertFalse(buffers.pulseActive)
        assertFalse(buffers.isInnerCoreAwake)
        assertTrue(buffers.isNeuronActive(NeuralCanvasBuffers.indexOf(NeuronNodeId.VAULT)))

        // Run an active Tier 3 pulse, then transition back to idle and verify full reset.
        val activeState = NeuralCanvasState(
            coreState = CoreActivityState.INNER_CORE_ACTIVE,
            activePulse = NeuralPulseEvent(
                eventId = "evt-before-idle",
                tier = ResolutionTier.TIER_3_GEMMA,
                sourceNode = null,
                targetNode = NeuronNodeId.MESSAGES,
                wakesInnerCore = true,
                timestampEpochMs = 5_000L
            )
        )
        repeat(10) { engine.stepFrame(16L, activeState, buffers) }
        assertTrue(buffers.pulseProgress > 0f)
        assertTrue(buffers.innerCoreGlowAlpha > 0f)
        val stepsBeforeIdle = buffers.stepCount

        val resetDone = engine.stepFrame(16L, idleState, buffers)
        assertNull(resetDone)
        assertEquals(stepsBeforeIdle, buffers.stepCount)
        assertEquals(0f, buffers.pulseProgress, 0.0f)
        assertEquals(0f, buffers.corePhaseRadians, 0.0f)
        assertEquals(0f, buffers.outerShellPulseAlpha, 0.0f)
        assertEquals(0f, buffers.innerCoreGlowAlpha, 0.0f)
        assertFalse(buffers.pulseActive)
        assertFalse(buffers.isInnerCoreAwake)
    }

    @Test
    fun paletteAndLabelBuffersAndMetrics_handleThermalBiometricAndPreformattedLabels() {
        val palette = NeuralCanvasPalette.createForJvm(density = 2f)

        val normalColor = palette.thermalRingColorFor(ThermalState.NORMAL)
        val moderateColor = palette.thermalRingColorFor(ThermalState.MODERATE)
        val severeColor = palette.thermalRingColorFor(ThermalState.SEVERE_OR_HIGHER)
        assertNotEquals(normalColor, moderateColor)
        assertNotEquals(moderateColor, severeColor)
        assertNotEquals(normalColor, severeColor)

        val biometricPulse = NeuralPulseEvent(
            eventId = "bio-1",
            tier = ResolutionTier.TIER_1_RULE,
            sourceNode = null,
            targetNode = NeuronNodeId.VAULT,
            wakesInnerCore = false,
            isBiometricSynapse = true,
            timestampEpochMs = 999L
        )
        assertEquals(palette.biometricSynapsePrimary, palette.pulseColorFor(biometricPulse))

        val buffers = NeuralCanvasBuffers()
        val labelArrayRef = buffers.formattedLabels
        buffers.updateFormattedLabels(
            mapOf(
                NeuronNodeId.CLOCK to "Clock",
                NeuronNodeId.VAULT to "Vault"
            )
        ) { raw -> "[$raw]" }

        assertSame(labelArrayRef, buffers.formattedLabels)
        assertEquals("[Clock]", buffers.formattedLabels[NeuralCanvasBuffers.indexOf(NeuronNodeId.CLOCK)])
        assertEquals("[Vault]", buffers.formattedLabels[NeuralCanvasBuffers.indexOf(NeuronNodeId.VAULT)])
        assertEquals("[NOTES]", buffers.formattedLabels[NeuralCanvasBuffers.indexOf(NeuronNodeId.NOTES)])

        val metrics = NeuralCanvasFrameMetrics()
        assertNotNull(metrics.drawCount)
        assertNotNull(metrics.animationFrameCount)
        metrics.drawCount.incrementAndGet()
        metrics.animationFrameCount.addAndGet(5L)
        assertEquals(1L, metrics.drawCount.get())
        assertEquals(5L, metrics.animationFrameCount.get())
        metrics.reset()
        assertEquals(0L, metrics.drawCount.get())
        assertEquals(0L, metrics.animationFrameCount.get())
        assertTrue(abs(palette.outerShellStroke.width - 7.2f) < 0.01f)
    }
}

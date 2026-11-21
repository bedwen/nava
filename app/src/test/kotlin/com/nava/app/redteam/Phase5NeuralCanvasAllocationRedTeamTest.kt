package com.nava.app.redteam

import com.nava.app.di.NeuronToolMapper
import com.nava.app.ui.canvas.NeuralCanvasBuffers
import com.nava.app.ui.canvas.NeuralCanvasEngine
import com.nava.app.ui.canvas.NeuralCanvasFrameMetrics
import com.nava.app.ui.canvas.NeuralCanvasPalette
import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ThermalState
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.security.Tainted
import com.nava.domain.ui.CoreActivityState
import com.nava.domain.ui.NeuralCanvasState
import com.nava.domain.ui.NeuralPulseEvent
import com.nava.domain.ui.NeuronNodeId
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.ToolTargetIds
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Gate 2 Red-Team & Zero-Allocation Verification Suite for the 0-FPS Dual-Core Neural Canvas
 * (`:app` JVM unit test scope, PLAN.md Sections 7 & 8.3; AGENTS.md Section 4 Step 4).
 */
class Phase5NeuralCanvasAllocationRedTeamTest {

    @Test
    fun primitiveFloatArrayBuffers_preserveExactIdentityAcross12000StepFrameInvocations() {
        val engine = NeuralCanvasEngine()
        val buffers = NeuralCanvasBuffers()

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

        val nodeXHash = System.identityHashCode(nodeXRef)
        val nodeYHash = System.identityHashCode(nodeYRef)
        val nodeRadiiHash = System.identityHashCode(nodeRadiiRef)
        val nodeGlowAlphaHash = System.identityHashCode(nodeGlowAlphaRef)
        val nodeLabelYHash = System.identityHashCode(nodeLabelYRef)
        val edgeStartXHash = System.identityHashCode(edgeStartXRef)
        val edgeStartYHash = System.identityHashCode(edgeStartYRef)
        val edgeEndXHash = System.identityHashCode(edgeEndXRef)
        val edgeEndYHash = System.identityHashCode(edgeEndYRef)
        val edgeAlphaHash = System.identityHashCode(edgeAlphaRef)
        val pulsePointsXHash = System.identityHashCode(pulsePointsXRef)
        val pulsePointsYHash = System.identityHashCode(pulsePointsYRef)
        val pulsePointsAlphaHash = System.identityHashCode(pulsePointsAlphaRef)
        val ringRadiiHash = System.identityHashCode(ringRadiiRef)
        val formattedLabelsHash = System.identityHashCode(formattedLabelsRef)

        engine.syncLayoutIfNeeded(1080f, 1920f, buffers)

        val nodes = NeuronNodeId.entries
        val tiers = ResolutionTier.entries
        val thermals = ThermalState.entries

        val states = Array(16) { idx ->
            val target = nodes[idx % nodes.size]
            val source = when {
                idx % 4 == 0 -> null
                idx % 4 == 1 -> nodes[(idx + 2) % nodes.size]
                idx % 4 == 2 -> nodes[(idx + 4) % nodes.size]
                else -> target
            }
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
                    eventId = "redteam-pulse-$idx",
                    tier = tier,
                    sourceNode = source,
                    targetNode = target,
                    wakesInnerCore = tier == ResolutionTier.TIER_3_GEMMA,
                    isBiometricSynapse = target == NeuronNodeId.VAULT,
                    timestampEpochMs = 1_760_000_000_000L + idx
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

        val totalSteps = 12_000
        for (step in 0 until totalSteps) {
            when (step) {
                2_500 -> engine.syncLayoutIfNeeded(720f, 1280f, buffers)
                5_000 -> engine.syncLayoutIfNeeded(1440f, 2560f, buffers)
                7_500 -> engine.syncLayoutIfNeeded(900f, 900f, buffers)
                10_000 -> buffers.updateFormattedLabels(
                    mapOf(
                        NeuronNodeId.CLOCK to "Saat",
                        NeuronNodeId.VAULT to "Kasa"
                    )
                ) { it }
            }
            val state = states[(step / 50) % states.size]
            engine.stepFrame(16L, state, buffers)
        }

        // Verify both reference equality (===) and System.identityHashCode stability across 12,000+ steps
        assertTrue(nodeXRef === buffers.nodeX)
        assertTrue(nodeYRef === buffers.nodeY)
        assertTrue(nodeRadiiRef === buffers.nodeRadii)
        assertTrue(nodeGlowAlphaRef === buffers.nodeGlowAlpha)
        assertTrue(nodeLabelYRef === buffers.nodeLabelY)
        assertTrue(edgeStartXRef === buffers.edgeStartX)
        assertTrue(edgeStartYRef === buffers.edgeStartY)
        assertTrue(edgeEndXRef === buffers.edgeEndX)
        assertTrue(edgeEndYRef === buffers.edgeEndY)
        assertTrue(edgeAlphaRef === buffers.edgeAlpha)
        assertTrue(pulsePointsXRef === buffers.pulsePointsX)
        assertTrue(pulsePointsYRef === buffers.pulsePointsY)
        assertTrue(pulsePointsAlphaRef === buffers.pulsePointsAlpha)
        assertTrue(ringRadiiRef === buffers.ringRadii)
        assertTrue(formattedLabelsRef === buffers.formattedLabels)

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

        assertEquals(nodeXHash, System.identityHashCode(buffers.nodeX))
        assertEquals(nodeYHash, System.identityHashCode(buffers.nodeY))
        assertEquals(nodeRadiiHash, System.identityHashCode(buffers.nodeRadii))
        assertEquals(nodeGlowAlphaHash, System.identityHashCode(buffers.nodeGlowAlpha))
        assertEquals(nodeLabelYHash, System.identityHashCode(buffers.nodeLabelY))
        assertEquals(edgeStartXHash, System.identityHashCode(buffers.edgeStartX))
        assertEquals(edgeStartYHash, System.identityHashCode(buffers.edgeStartY))
        assertEquals(edgeEndXHash, System.identityHashCode(buffers.edgeEndX))
        assertEquals(edgeEndYHash, System.identityHashCode(buffers.edgeEndY))
        assertEquals(edgeAlphaHash, System.identityHashCode(buffers.edgeAlpha))
        assertEquals(pulsePointsXHash, System.identityHashCode(buffers.pulsePointsX))
        assertEquals(pulsePointsYHash, System.identityHashCode(buffers.pulsePointsY))
        assertEquals(pulsePointsAlphaHash, System.identityHashCode(buffers.pulsePointsAlpha))
        assertEquals(ringRadiiHash, System.identityHashCode(buffers.ringRadii))
        assertEquals(formattedLabelsHash, System.identityHashCode(buffers.formattedLabels))

        for (i in 0 until NeuralCanvasBuffers.NEURON_COUNT) {
            assertTrue(buffers.nodeX[i].isFinite())
            assertTrue(buffers.nodeY[i].isFinite())
            assertTrue(buffers.nodeGlowAlpha[i] in 0f..1f)
            assertTrue(buffers.edgeAlpha[i] in 0f..1f)
        }
    }

    @Test
    fun tier1AndTier2KeepInnerCoreAsleepWhileTier3WakesAndIlluminatesInnerCore() {
        val engine = NeuralCanvasEngine()
        val buffers = NeuralCanvasBuffers()
        val palette = NeuralCanvasPalette.createForJvm(density = 2f)
        engine.syncLayoutIfNeeded(1000f, 1000f, buffers)

        val samplePlan = PlanAst(
            planId = "plan-dual-core-verify",
            calls = listOf(
                ToolCallAst(
                    toolName = AutomationToolNames.SET_ALARM,
                    arguments = mapOf(
                        "time" to Tainted.fromUserUtterance(SlotValueAst.StringValue("07:00"))
                    ),
                    orderIndex = 0,
                    targetId = ToolTargetIds.CLOCK
                ),
                ToolCallAst(
                    toolName = AutomationToolNames.SET_DND,
                    arguments = mapOf(
                        "mode" to Tainted.fromUserUtterance(SlotValueAst.StringValue("PRIORITY"))
                    ),
                    orderIndex = 1,
                    targetId = ToolTargetIds.AUDIO_DND
                )
            )
        )

        // 1. Tier 1 Rule Engine: wakesInnerCore must be false, Inner Core stays dark/asleep
        val tier1Pulses = NeuronToolMapper.buildPulsesForPlan(
            plan = samplePlan,
            tier = ResolutionTier.TIER_1_RULE,
            timestampEpochMs = 1_000L
        )
        assertEquals(2, tier1Pulses.size)
        assertTrue(tier1Pulses.all { !it.wakesInnerCore })

        for (pulse in tier1Pulses) {
            val tier1State = NeuralCanvasState(
                coreState = CoreActivityState.OUTER_SHELL_ACTIVE,
                activeNeurons = setOf(pulse.targetNode),
                activePulse = pulse,
                isModelResident = true
            )
            assertFalse(engine.shouldWakeInnerCore(tier1State))
            repeat(25) {
                engine.stepFrame(16L, tier1State, buffers)
                assertFalse("Tier 1 must never wake Inner Core", buffers.isInnerCoreAwake)
                assertEquals(0f, buffers.innerCoreGlowAlpha, 0.0f)
                assertTrue("Tier 1 must pulse Outer Cortex Shell", buffers.outerShellPulseAlpha > 0f)
            }
            assertEquals(
                palette.outerShellTier1,
                palette.outerShellColorFor(tier1State.coreState, pulse.tier)
            )
        }

        // 2. Tier 2 Action Cache: wakesInnerCore must be false, Inner Core stays dark/asleep
        val tier2Pulses = NeuronToolMapper.buildPulsesForPlan(
            plan = samplePlan,
            tier = ResolutionTier.TIER_2_CACHE,
            timestampEpochMs = 2_000L
        )
        assertEquals(2, tier2Pulses.size)
        assertTrue(tier2Pulses.all { !it.wakesInnerCore })

        for (pulse in tier2Pulses) {
            val tier2State = NeuralCanvasState(
                coreState = CoreActivityState.OUTER_SHELL_ACTIVE,
                activeNeurons = setOf(pulse.targetNode),
                activePulse = pulse,
                isModelResident = true
            )
            assertFalse(engine.shouldWakeInnerCore(tier2State))
            repeat(25) {
                engine.stepFrame(16L, tier2State, buffers)
                assertFalse("Tier 2 must never wake Inner Core", buffers.isInnerCoreAwake)
                assertEquals(0f, buffers.innerCoreGlowAlpha, 0.0f)
                assertTrue("Tier 2 must pulse Outer Cortex Shell", buffers.outerShellPulseAlpha > 0f)
            }
            assertEquals(
                palette.outerShellTier2,
                palette.outerShellColorFor(tier2State.coreState, pulse.tier)
            )
        }

        // 3. Tier 3 Gemma 4 Engine: wakesInnerCore must be true, Inner Core wakes and illuminates
        val tier3Pulses = NeuronToolMapper.buildPulsesForPlan(
            plan = samplePlan,
            tier = ResolutionTier.TIER_3_GEMMA,
            timestampEpochMs = 3_000L
        )
        assertEquals(2, tier3Pulses.size)
        assertTrue(tier3Pulses.all { it.wakesInnerCore })

        for (pulse in tier3Pulses) {
            val tier3State = NeuralCanvasState(
                coreState = CoreActivityState.INNER_CORE_ACTIVE,
                activeNeurons = setOf(pulse.targetNode),
                activePulse = pulse,
                isModelResident = true
            )
            assertTrue(engine.shouldWakeInnerCore(tier3State))
            repeat(25) {
                engine.stepFrame(16L, tier3State, buffers)
                assertTrue("Tier 3 must wake Gemma 4 Inner Core", buffers.isInnerCoreAwake)
                assertTrue("Tier 3 must illuminate Inner Core glow", buffers.innerCoreGlowAlpha > 0f)
                assertTrue("Tier 3 also pulses Outer Cortex Shell", buffers.outerShellPulseAlpha > 0f)
            }
            assertEquals(
                palette.outerShellTier3,
                palette.outerShellColorFor(tier3State.coreState, pulse.tier)
            )
        }
    }

    @Test
    fun idleState_producesZeroAdvancesResetsPulseProgressAndHandlesFrameMetrics() {
        val engine = NeuralCanvasEngine()
        val buffers = NeuralCanvasBuffers()
        val metrics = NeuralCanvasFrameMetrics()
        engine.syncLayoutIfNeeded(1080f, 1080f, buffers)

        assertEquals(0L, metrics.drawCount.get())
        assertEquals(0L, metrics.animationFrameCount.get())

        val idleState = NeuralCanvasState(
            coreState = CoreActivityState.IDLE,
            activeNeurons = emptySet(),
            activePulse = null
        )
        assertTrue(idleState.isIdle)

        // Stepping 2,500 times while idle must perform 0 animation advances.
        repeat(2_500) {
            val doneEventId = engine.stepFrame(16L, idleState, buffers)
            assertNull(doneEventId)
        }
        assertEquals(0L, buffers.stepCount)
        assertEquals(0f, buffers.pulseProgress, 0.0f)
        assertEquals(0f, buffers.corePhaseRadians, 0.0f)
        assertEquals(0f, buffers.outerShellPulseAlpha, 0.0f)
        assertEquals(0f, buffers.innerCoreGlowAlpha, 0.0f)
        assertFalse(buffers.pulseActive)
        assertFalse(buffers.isInnerCoreAwake)
        assertEquals(0, buffers.pulsePointCount)

        // Run an active Tier 3 pulse to mid-flight, recording metrics.
        val activeState = NeuralCanvasState(
            coreState = CoreActivityState.INNER_CORE_ACTIVE,
            activeNeurons = setOf(NeuronNodeId.VAULT),
            activePulse = NeuralPulseEvent(
                eventId = "midflight-pulse",
                tier = ResolutionTier.TIER_3_GEMMA,
                sourceNode = NeuronNodeId.NOTES,
                targetNode = NeuronNodeId.VAULT,
                wakesInnerCore = true,
                isBiometricSynapse = true,
                timestampEpochMs = 5_000L
            )
        )
        assertFalse(activeState.isIdle)
        repeat(15) {
            engine.stepFrame(16L, activeState, buffers)
            metrics.animationFrameCount.incrementAndGet()
            metrics.drawCount.incrementAndGet()
        }
        assertEquals(15L, buffers.stepCount)
        assertEquals(15L, metrics.animationFrameCount.get())
        assertEquals(15L, metrics.drawCount.get())
        assertTrue(buffers.pulseProgress > 0f)
        assertTrue(buffers.isInnerCoreAwake)
        assertTrue(buffers.innerCoreGlowAlpha > 0f)
        assertTrue(buffers.pulseActive)
        assertEquals(NeuralCanvasBuffers.PULSE_TRAIL_SAMPLES, buffers.pulsePointCount)

        // Transitioning back to idle resets pulseProgress and glow alphas with 0 stepCount increment.
        val idleReturn = engine.stepFrame(16L, idleState, buffers)
        assertNull(idleReturn)
        assertEquals(15L, buffers.stepCount)
        assertEquals(0f, buffers.pulseProgress, 0.0f)
        assertEquals(0f, buffers.corePhaseRadians, 0.0f)
        assertEquals(0f, buffers.outerShellPulseAlpha, 0.0f)
        assertEquals(0f, buffers.innerCoreGlowAlpha, 0.0f)
        assertFalse(buffers.pulseActive)
        assertFalse(buffers.isInnerCoreAwake)
        assertEquals(0, buffers.pulsePointCount)
        for (i in 0 until NeuralCanvasBuffers.PULSE_TRAIL_SAMPLES) {
            assertEquals(0f, buffers.pulsePointsX[i], 0.0f)
            assertEquals(0f, buffers.pulsePointsY[i], 0.0f)
            assertEquals(0f, buffers.pulsePointsAlpha[i], 0.0f)
        }

        // Resetting frame metrics zeroes both atomic counters for the next idle window check.
        metrics.reset()
        assertEquals(0L, metrics.drawCount.get())
        assertEquals(0L, metrics.animationFrameCount.get())
    }

    @Test
    fun staticSourceAudit_canvasKotlinFilesContainZeroForbiddenAllocationsInsideDrawScopes() {
        val canvasDir = resolveCanvasSourceDirectory()
        val ktFiles = canvasDir.listFiles { f -> f.isFile && f.name.endsWith(".kt") }
            ?.sortedBy { it.name }
            .orEmpty()

        val expectedFiles = setOf(
            "DualCoreNeuralCanvas.kt",
            "NeuralCanvasBuffers.kt",
            "NeuralCanvasEngine.kt",
            "NeuralCanvasPalette.kt"
        )
        val actualFileNames = ktFiles.map { it.name }.toSet()
        assertTrue(
            "Expected all 4 Neural Canvas source files $expectedFiles in ${canvasDir.absolutePath}, found $actualFileNames",
            actualFileNames.containsAll(expectedFiles)
        )

        val violations = mutableListOf<String>()
        for (file in ktFiles) {
            val raw = file.readText(Charsets.UTF_8)
            violations.addAll(scanSourceForDrawLoopAllocations(file.name, raw))
        }

        assertTrue(
            "Forbidden heap allocation(s) detected inside Neural Canvas draw loop:\n" +
                violations.joinToString("\n"),
            violations.isEmpty()
        )

        // Self-test the scanner against synthetic violations to prove detection accuracy.
        val syntheticBadSource = """
            package com.nava.app.ui.canvas
            fun badCanvas() {
                Canvas(modifier = Modifier) {
                    val p = Paint()
                    val c = Color(0xFFFFFFFF)
                    val list = mutableListOf(1, 2)
                }
            }
            fun badDrawScope(scope: DrawScope) {
                val path = Path()
                val rect = RectF()
                val b = Brush.linearGradient()
                val l2 = listOf("a")
                val l3 = ArrayList<String>()
            }
        """.trimIndent()
        val detectedSynthetic = scanSourceForDrawLoopAllocations("SyntheticBad.kt", syntheticBadSource)
        assertEquals(
            "Scanner must detect all 8 forbidden allocation patterns in synthetic draw blocks",
            8,
            detectedSynthetic.size
        )
    }

    private fun resolveCanvasSourceDirectory(): File {
        val candidates = listOf(
            File("src/main/kotlin/com/nava/app/ui/canvas"),
            File("app/src/main/kotlin/com/nava/app/ui/canvas"),
            File("../app/src/main/kotlin/com/nava/app/ui/canvas")
        )
        return candidates.firstOrNull { it.exists() && it.isDirectory }
            ?: error("Could not resolve app/src/main/kotlin/com/nava/app/ui/canvas from ${File(".").absolutePath}")
    }

    private fun scanSourceForDrawLoopAllocations(
        fileName: String,
        rawSource: String
    ): List<String> {
        val cleaned = stripKotlinComments(rawSource)
        val lines = cleaned.lines()
        val violations = mutableListOf<String>()

        var inDrawBlock = false
        var pendingOpenBrace = false
        var braceDepth = 0

        for ((idx, line) in lines.withIndex()) {
            val lineNo = idx + 1
            if (!inDrawBlock && DRAW_ENTRY_REGEX.containsMatchIn(line)) {
                pendingOpenBrace = true
            }
            if (pendingOpenBrace || inDrawBlock) {
                val opens = line.count { it == '{' }
                val closes = line.count { it == '}' }
                if (pendingOpenBrace && opens > 0) {
                    inDrawBlock = true
                    pendingOpenBrace = false
                }
                if (inDrawBlock) {
                    for (match in FORBIDDEN_ALLOC_REGEX.findAll(line)) {
                        violations.add("$fileName:$lineNo -> forbidden '${match.value}' inside draw scope")
                    }
                    braceDepth += opens - closes
                    if (braceDepth <= 0) {
                        inDrawBlock = false
                        braceDepth = 0
                    }
                }
            }
        }
        return violations
    }

    private fun stripKotlinComments(text: String): String {
        val out = StringBuilder(text.length)
        var i = 0
        val n = text.length
        var inStr = false
        var inChar = false
        var inTriple = false
        while (i < n) {
            val ch = text[i]
            if (inTriple) {
                out.append(ch)
                if (i + 2 < n && text.substring(i, i + 3) == "\"\"\"") {
                    out.append("\"\"")
                    i += 3
                    inTriple = false
                    continue
                }
                i++
            } else if (inStr) {
                out.append(ch)
                if (ch == '\\' && i + 1 < n) {
                    out.append(text[i + 1])
                    i += 2
                    continue
                }
                if (ch == '"') {
                    inStr = false
                }
                i++
            } else if (inChar) {
                out.append(ch)
                if (ch == '\\' && i + 1 < n) {
                    out.append(text[i + 1])
                    i += 2
                    continue
                }
                if (ch == '\'') {
                    inChar = false
                }
                i++
            } else {
                if (i + 2 < n && text.substring(i, i + 3) == "\"\"\"") {
                    inTriple = True
                    out.append("\"\"\"")
                    i += 3
                } else if (ch == '"') {
                    inStr = true
                    out.append(ch)
                    i++
                } else if (ch == '\'') {
                    inChar = true
                    out.append(ch)
                    i++
                } else if (ch == '/' && i + 1 < n && text[i + 1] == '/') {
                    while (i < n && text[i] != '\n') {
                        i++
                    }
                } else if (ch == '/' && i + 1 < n && text[i + 1] == '*') {
                    i += 2
                    while (i + 1 < n && !(text[i] == '*' && text[i + 1] == '/')) {
                        if (text[i] == '\n') {
                            out.append('\n')
                        }
                        i++
                    }
                    i += 2
                } else {
                    out.append(ch)
                    i++
                }
            }
        }
        return out.toString()
    }

    companion object {
        private const val True: Boolean = true

        private val DRAW_ENTRY_REGEX: Regex =
            Regex("""\b(?:onDraw|DrawScope\b|Canvas\s*\()""")

        private val FORBIDDEN_ALLOC_REGEX: Regex =
            Regex("""(?:\bPaint\s*\(|\bPath\s*\(|\bRectF\s*\(|\bBrush\.|\bColor\s*\(|\bmutableListOf\s*\(|\blistOf\s*\(|\bArrayList\s*\()""")
    }
}

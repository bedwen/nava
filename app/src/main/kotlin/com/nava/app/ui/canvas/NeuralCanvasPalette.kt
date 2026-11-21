package com.nava.app.ui.canvas

import android.graphics.Paint
import android.graphics.Typeface
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.ThermalState
import com.nava.domain.ui.CoreActivityState
import com.nava.domain.ui.NeuralPulseEvent

/**
 * Pre-allocated colors, Compose [Stroke] instances, and [android.graphics.Paint] objects
 * for the Dual-Core Neural Canvas.
 *
 * Constructed ONCE via `remember` outside any draw pass so rendering performs zero heap
 * allocations per frame (Iron Law 7 / Gate 1 Rule 4).
 */
class NeuralCanvasPalette internal constructor(
    val hubBackdrop: Color,
    val orbitRing: Color,
    val outerShellIdle: Color,
    val outerShellTier1: Color,
    val outerShellTier2: Color,
    val outerShellTier3: Color,
    val outerShellExecuting: Color,
    val outerShellError: Color,
    val innerCoreDormantFill: Color,
    val innerCoreDormantRim: Color,
    val innerCoreResidentRim: Color,
    val innerCoreAwakeCore: Color,
    val innerCoreAwakeHalo: Color,
    val thermalNormal: Color,
    val thermalModerate: Color,
    val thermalSevere: Color,
    val nodeFillIdle: Color,
    val nodeFillActive: Color,
    val nodeStrokeIdle: Color,
    val nodeStrokeActive: Color,
    val nodeGlowActive: Color,
    val vaultLockedFill: Color,
    val vaultLockedStroke: Color,
    val vaultUnlockedFill: Color,
    val vaultUnlockedStroke: Color,
    val biometricSynapsePrimary: Color,
    val biometricSynapseGlow: Color,
    val edgeIdle: Color,
    val edgeActive: Color,
    val pulseTier1: Color,
    val pulseTier2: Color,
    val pulseTier3: Color,
    val pulseHeadHighlight: Color,
    val labelColorIdleArgb: Int,
    val labelColorActiveArgb: Int,
    val labelColorVaultLockedArgb: Int,
    val labelColorVaultUnlockedArgb: Int,
    val orbitStroke: Stroke,
    val outerShellStroke: Stroke,
    val outerShellPulseStroke: Stroke,
    val innerCoreRimStroke: Stroke,
    val thermalRingStroke: Stroke,
    val nodeBorderStroke: Stroke,
    val nodeActiveBorderStroke: Stroke,
    val synapseEdgeStroke: Stroke,
    val synapsePulseStroke: Stroke,
    val biometricRingStroke: Stroke,
    val lockGlyphStroke: Stroke,
    val nodeLabelPaint: Paint?
) {

    fun outerShellColorFor(coreState: CoreActivityState, tier: ResolutionTier?): Color {
        return when (coreState) {
            CoreActivityState.IDLE -> outerShellIdle
            CoreActivityState.ERROR_FLASH -> outerShellError
            CoreActivityState.EXECUTING_TOOL -> outerShellExecuting
            CoreActivityState.INNER_CORE_ACTIVE -> outerShellTier3
            CoreActivityState.OUTER_SHELL_ACTIVE -> when (tier) {
                ResolutionTier.TIER_2_CACHE -> outerShellTier2
                ResolutionTier.TIER_3_GEMMA -> outerShellTier3
                ResolutionTier.TIER_1_RULE, null -> outerShellTier1
            }
        }
    }

    fun pulseColorFor(pulse: NeuralPulseEvent): Color {
        if (pulse.isBiometricSynapse) {
            return biometricSynapsePrimary
        }
        return when (pulse.tier) {
            ResolutionTier.TIER_1_RULE -> pulseTier1
            ResolutionTier.TIER_2_CACHE -> pulseTier2
            ResolutionTier.TIER_3_GEMMA -> pulseTier3
        }
    }

    fun thermalRingColorFor(thermalState: ThermalState): Color {
        return when (thermalState) {
            ThermalState.NORMAL -> thermalNormal
            ThermalState.MODERATE -> thermalModerate
            ThermalState.SEVERE_OR_HIGHER -> thermalSevere
        }
    }

    companion object {
        private const val LABEL_IDLE_ARGB: Int = 0xFFB8C7DC.toInt()
        private const val LABEL_ACTIVE_ARGB: Int = 0xFFF2F7FF.toInt()
        private const val LABEL_VAULT_LOCKED_ARGB: Int = 0xFFE6B45A.toInt()
        private const val LABEL_VAULT_UNLOCKED_ARGB: Int = 0xFF69E6B8.toInt()

        /**
         * Allocates all palette colors, strokes, and Android [Paint] objects once for runtime
         * Compose rendering.
         */
        fun create(density: Float, fontScale: Float = 1f): NeuralCanvasPalette {
            val safeDensity = density.coerceAtLeast(1f)
            val safeFontScale = fontScale.coerceAtLeast(0.75f)
            val labelPaint = Paint().apply {
                isAntiAlias = true
                isSubpixelText = true
                textAlign = Paint.Align.CENTER
                typeface = Typeface.DEFAULT_BOLD
                color = LABEL_IDLE_ARGB
                textSize = 11f * safeDensity * safeFontScale
            }
            return buildPalette(safeDensity, labelPaint)
        }

        /**
         * Allocates Compose colors and strokes without constructing Android framework [Paint]
         * instances, enabling deterministic JVM unit testing.
         */
        fun createForJvm(density: Float = 1f): NeuralCanvasPalette {
            return buildPalette(density.coerceAtLeast(1f), null)
        }

        private fun buildPalette(density: Float, labelPaint: Paint?): NeuralCanvasPalette {
            return NeuralCanvasPalette(
                hubBackdrop = Color(0xFF0E1624),
                orbitRing = Color(0xFF23344D),
                outerShellIdle = Color(0xFF3A5273),
                outerShellTier1 = Color(0xFF38D9F5),
                outerShellTier2 = Color(0xFF3CE6A6),
                outerShellTier3 = Color(0xFF9C7CFF),
                outerShellExecuting = Color(0xFF4BE3D5),
                outerShellError = Color(0xFFFF5C6C),
                innerCoreDormantFill = Color(0xFF0A101B),
                innerCoreDormantRim = Color(0xFF223047),
                innerCoreResidentRim = Color(0xFF475E82),
                innerCoreAwakeCore = Color(0xFFFFB74D),
                innerCoreAwakeHalo = Color(0xFF9E7BFF),
                thermalNormal = Color(0xFF2E6F7E),
                thermalModerate = Color(0xFFF5A623),
                thermalSevere = Color(0xFFFF4D4F),
                nodeFillIdle = Color(0xFF131E30),
                nodeFillActive = Color(0xFF1A2F4A),
                nodeStrokeIdle = Color(0xFF344A68),
                nodeStrokeActive = Color(0xFF4FE3FF),
                nodeGlowActive = Color(0xFF38D9F5),
                vaultLockedFill = Color(0xFF1E1A14),
                vaultLockedStroke = Color(0xFFD9A243),
                vaultUnlockedFill = Color(0xFF112922),
                vaultUnlockedStroke = Color(0xFF45E3A8),
                biometricSynapsePrimary = Color(0xFFFFC95C),
                biometricSynapseGlow = Color(0xFFE08AFF),
                edgeIdle = Color(0xFF243650),
                edgeActive = Color(0xFF4FE3FF),
                pulseTier1 = Color(0xFF38D9F5),
                pulseTier2 = Color(0xFF3CE6A6),
                pulseTier3 = Color(0xFFB388FF),
                pulseHeadHighlight = Color(0xFFFFFFFF),
                labelColorIdleArgb = LABEL_IDLE_ARGB,
                labelColorActiveArgb = LABEL_ACTIVE_ARGB,
                labelColorVaultLockedArgb = LABEL_VAULT_LOCKED_ARGB,
                labelColorVaultUnlockedArgb = LABEL_VAULT_UNLOCKED_ARGB,
                orbitStroke = Stroke(width = 1.25f * density),
                outerShellStroke = Stroke(width = 2.5f * density, cap = StrokeCap.Round),
                outerShellPulseStroke = Stroke(width = 4.0f * density, cap = StrokeCap.Round),
                innerCoreRimStroke = Stroke(width = 1.75f * density, cap = StrokeCap.Round),
                thermalRingStroke = Stroke(width = 2.25f * density, cap = StrokeCap.Round),
                nodeBorderStroke = Stroke(width = 1.75f * density, cap = StrokeCap.Round),
                nodeActiveBorderStroke = Stroke(width = 2.75f * density, cap = StrokeCap.Round),
                synapseEdgeStroke = Stroke(width = 1.5f * density, cap = StrokeCap.Round),
                synapsePulseStroke = Stroke(width = 3.25f * density, cap = StrokeCap.Round),
                biometricRingStroke = Stroke(width = 2.0f * density, cap = StrokeCap.Round),
                lockGlyphStroke = Stroke(width = 1.8f * density, cap = StrokeCap.Round),
                nodeLabelPaint = labelPaint
            )
        }
    }
}

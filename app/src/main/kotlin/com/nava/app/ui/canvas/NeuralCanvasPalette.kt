package com.nava.app.ui.canvas

import android.graphics.Paint
import android.graphics.Typeface
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import com.nava.app.ui.theme.NavaColors
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.ThermalState
import com.nava.domain.ui.CoreActivityState
import com.nava.domain.ui.NeuralPulseEvent

/**
 * Pre-allocated colors, Compose [Stroke] instances, and [android.graphics.Paint] objects
 * for the Dual-Core Neural Canvas.
 *
 * Uses Nava's Warm Paper / Linen Light and Matte OLED Dark palettes. Constructed ONCE via
 * `remember` outside any draw pass so rendering performs zero heap allocations per frame
 * (Iron Law 7 / Gate 1 Rule 4).
 */
class NeuralCanvasPalette internal constructor(
    val stageBackground: Color,
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
    val nodeIconIdle: Color,
    val nodeIconActive: Color,
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
    val returnPulseColor: Color,
    val coreConfirmRingColor: Color,
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
                ResolutionTier.TIER_2_5_FUNCTION_GEMMA -> outerShellTier2
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
            ResolutionTier.TIER_2_5_FUNCTION_GEMMA -> pulseTier2
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
        // Warm Paper / Linen Light label ARGB values
        private const val LABEL_LIGHT_IDLE_ARGB: Int = 0xFF52606D.toInt()
        private const val LABEL_LIGHT_ACTIVE_ARGB: Int = 0xFF182026.toInt()
        private const val LABEL_LIGHT_VAULT_LOCKED_ARGB: Int = 0xFF52606D.toInt()
        private const val LABEL_LIGHT_VAULT_UNLOCKED_ARGB: Int = 0xFF1E5643.toInt()

        // Matte OLED Dark label ARGB values
        private const val LABEL_DARK_IDLE_ARGB: Int = 0xFF9FB0C2.toInt()
        private const val LABEL_DARK_ACTIVE_ARGB: Int = 0xFFF1F5F9.toInt()
        private const val LABEL_DARK_VAULT_LOCKED_ARGB: Int = 0xFF9FB0C2.toInt()
        private const val LABEL_DARK_VAULT_UNLOCKED_ARGB: Int = 0xFF6EE7B7.toInt()

        /**
         * Allocates all palette colors, strokes, and Android [Paint] objects once for runtime
         * Compose rendering.
         */
        fun create(
            density: Float,
            fontScale: Float = 1f,
            isDarkTheme: Boolean = false
        ): NeuralCanvasPalette {
            val safeDensity = density.coerceAtLeast(1f)
            val safeFontScale = fontScale.coerceAtLeast(0.75f)
            val labelPaint = Paint().apply {
                isAntiAlias = true
                isSubpixelText = true
                textAlign = Paint.Align.CENTER
                typeface = Typeface.DEFAULT
                color = if (isDarkTheme) LABEL_DARK_IDLE_ARGB else LABEL_LIGHT_IDLE_ARGB
                textSize = 11f * safeDensity * safeFontScale
            }
            return buildPalette(safeDensity, labelPaint, isDarkTheme)
        }

        /**
         * Allocates Compose colors and strokes without constructing Android framework [Paint]
         * instances, enabling deterministic JVM unit testing.
         */
        fun createForJvm(
            density: Float = 1f,
            isDarkTheme: Boolean = false
        ): NeuralCanvasPalette {
            return buildPalette(density.coerceAtLeast(1f), null, isDarkTheme)
        }

        private fun buildPalette(
            density: Float,
            labelPaint: Paint?,
            isDarkTheme: Boolean
        ): NeuralCanvasPalette {
            val orbitStroke = Stroke(width = 1.25f * density)
            val outerShellStroke = Stroke(width = 3.6f * density, cap = StrokeCap.Round)
            val outerShellPulseStroke = Stroke(width = 4.2f * density, cap = StrokeCap.Round)
            val innerCoreRimStroke = Stroke(width = 1.75f * density, cap = StrokeCap.Round)
            val thermalRingStroke = Stroke(width = 2.25f * density, cap = StrokeCap.Round)
            val nodeBorderStroke = Stroke(width = 1.0f * density, cap = StrokeCap.Round)
            val nodeActiveBorderStroke = Stroke(width = 2.25f * density, cap = StrokeCap.Round)
            val synapseEdgeStroke = Stroke(width = 1.5f * density, cap = StrokeCap.Round)
            val synapsePulseStroke = Stroke(width = 3.25f * density, cap = StrokeCap.Round)
            val biometricRingStroke = Stroke(width = 2.0f * density, cap = StrokeCap.Round)
            val lockGlyphStroke = Stroke(width = 1.7f * density, cap = StrokeCap.Round)

            if (isDarkTheme) {
                return NeuralCanvasPalette(
                    stageBackground = NavaColors.BgPaperDark,
                    hubBackdrop = NavaColors.SurfaceCardDark,
                    orbitRing = NavaColors.BorderDark,
                    outerShellIdle = NavaColors.TrustNavyTintDark,
                    outerShellTier1 = NavaColors.TrustNavyTintDark,
                    outerShellTier2 = NavaColors.TrustNavyDark,
                    outerShellTier3 = NavaColors.TrustNavyTintDark,
                    outerShellExecuting = NavaColors.TrustNavyTintDark,
                    outerShellError = NavaColors.AlertCrimsonDark,
                    innerCoreDormantFill = NavaColors.InkPrimaryDark,
                    innerCoreDormantRim = NavaColors.BorderDark,
                    innerCoreResidentRim = NavaColors.InkSecondaryDark,
                    innerCoreAwakeCore = NavaColors.TrustNavyTintDark,
                    innerCoreAwakeHalo = NavaColors.TrustNavyDark,
                    thermalNormal = NavaColors.BorderDark,
                    thermalModerate = NavaColors.UntrustedAmberDark,
                    thermalSevere = NavaColors.AlertCrimsonDark,
                    nodeFillIdle = NavaColors.SurfaceCardDark,
                    nodeFillActive = NavaColors.TrustNavyDark,
                    nodeStrokeIdle = NavaColors.BorderDark,
                    nodeStrokeActive = NavaColors.TrustNavyTintDark,
                    nodeGlowActive = NavaColors.TrustNavyTintDark,
                    nodeIconIdle = NavaColors.InkSecondaryDark,
                    nodeIconActive = Color.White,
                    vaultLockedFill = NavaColors.SurfaceCardDark,
                    vaultLockedStroke = NavaColors.BorderDark,
                    vaultUnlockedFill = NavaColors.VerifiedMintDark,
                    vaultUnlockedStroke = NavaColors.VerifiedForestDark,
                    biometricSynapsePrimary = NavaColors.UntrustedAmberDark,
                    biometricSynapseGlow = NavaColors.VerifiedForestDark,
                    edgeIdle = NavaColors.BorderDark,
                    edgeActive = NavaColors.TrustNavyTintDark,
                    pulseTier1 = NavaColors.TrustNavyTintDark,
                    pulseTier2 = NavaColors.TrustNavyDark,
                    pulseTier3 = NavaColors.TrustNavyTintDark,
                    pulseHeadHighlight = NavaColors.InkPrimaryDark,
                    returnPulseColor = NavaColors.VerifiedForestDark,
                    coreConfirmRingColor = NavaColors.VerifiedForestDark,
                    labelColorIdleArgb = LABEL_DARK_IDLE_ARGB,
                    labelColorActiveArgb = LABEL_DARK_ACTIVE_ARGB,
                    labelColorVaultLockedArgb = LABEL_DARK_VAULT_LOCKED_ARGB,
                    labelColorVaultUnlockedArgb = LABEL_DARK_VAULT_UNLOCKED_ARGB,
                    orbitStroke = orbitStroke,
                    outerShellStroke = outerShellStroke,
                    outerShellPulseStroke = outerShellPulseStroke,
                    innerCoreRimStroke = innerCoreRimStroke,
                    thermalRingStroke = thermalRingStroke,
                    nodeBorderStroke = nodeBorderStroke,
                    nodeActiveBorderStroke = nodeActiveBorderStroke,
                    synapseEdgeStroke = synapseEdgeStroke,
                    synapsePulseStroke = synapsePulseStroke,
                    biometricRingStroke = biometricRingStroke,
                    lockGlyphStroke = lockGlyphStroke,
                    nodeLabelPaint = labelPaint
                )
            }

            return NeuralCanvasPalette(
                stageBackground = NavaColors.BgPaper,
                hubBackdrop = NavaColors.SurfaceCard,
                orbitRing = NavaColors.BorderStone,
                outerShellIdle = NavaColors.TrustNavy,
                outerShellTier1 = NavaColors.TrustNavy,
                outerShellTier2 = NavaColors.CalmCobalt,
                outerShellTier3 = NavaColors.TrustNavy,
                outerShellExecuting = NavaColors.CalmCobalt,
                outerShellError = NavaColors.AlertCrimsonLight,
                innerCoreDormantFill = NavaColors.InkPrimary,
                innerCoreDormantRim = NavaColors.BorderStone,
                innerCoreResidentRim = NavaColors.InkSecondary,
                innerCoreAwakeCore = NavaColors.TrustNavy,
                innerCoreAwakeHalo = NavaColors.CalmCobalt,
                thermalNormal = NavaColors.BorderStone,
                thermalModerate = NavaColors.UntrustedAmber,
                thermalSevere = NavaColors.AlertCrimsonLight,
                nodeFillIdle = NavaColors.SurfaceCard,
                nodeFillActive = NavaColors.TrustNavy,
                nodeStrokeIdle = NavaColors.BorderStone,
                nodeStrokeActive = NavaColors.TrustNavy,
                nodeGlowActive = NavaColors.CalmCobalt,
                nodeIconIdle = NavaColors.InkSecondary,
                nodeIconActive = Color.White,
                vaultLockedFill = NavaColors.SurfaceCard,
                vaultLockedStroke = NavaColors.BorderStone,
                vaultUnlockedFill = NavaColors.VerifiedMint,
                vaultUnlockedStroke = NavaColors.VerifiedForest,
                biometricSynapsePrimary = NavaColors.UntrustedAmber,
                biometricSynapseGlow = NavaColors.VerifiedForest,
                edgeIdle = NavaColors.BorderStone,
                edgeActive = NavaColors.CalmCobalt,
                pulseTier1 = NavaColors.TrustNavy,
                pulseTier2 = NavaColors.CalmCobalt,
                pulseTier3 = NavaColors.TrustNavy,
                pulseHeadHighlight = NavaColors.SurfaceCard,
                returnPulseColor = NavaColors.VerifiedForest,
                coreConfirmRingColor = NavaColors.VerifiedForest,
                labelColorIdleArgb = LABEL_LIGHT_IDLE_ARGB,
                labelColorActiveArgb = LABEL_LIGHT_ACTIVE_ARGB,
                labelColorVaultLockedArgb = LABEL_LIGHT_VAULT_LOCKED_ARGB,
                labelColorVaultUnlockedArgb = LABEL_LIGHT_VAULT_UNLOCKED_ARGB,
                orbitStroke = orbitStroke,
                outerShellStroke = outerShellStroke,
                outerShellPulseStroke = outerShellPulseStroke,
                innerCoreRimStroke = innerCoreRimStroke,
                thermalRingStroke = thermalRingStroke,
                nodeBorderStroke = nodeBorderStroke,
                nodeActiveBorderStroke = nodeActiveBorderStroke,
                synapseEdgeStroke = synapseEdgeStroke,
                synapsePulseStroke = synapsePulseStroke,
                biometricRingStroke = biometricRingStroke,
                lockGlyphStroke = lockGlyphStroke,
                nodeLabelPaint = labelPaint
            )
        }
    }
}

package com.nava.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.sp
import com.nava.app.locale.BidiTextFormatter
import java.util.Locale

/**
 * Warm Paper / Linen Light and Matte OLED Dark palette tokens for Nava.
 */
object NavaColors {
    // Light palette
    val BgLinen = Color(0xFFF6F5F0)
    val BgPaper = Color(0xFFFDFCF9)
    val SurfaceCard = Color(0xFFFFFFFF)
    val BorderStone = Color(0xFFE5E2D9)
    val InkPrimary = Color(0xFF182026)
    val InkSecondary = Color(0xFF52606D)
    val InkMuted = Color(0xFF82909C)
    val TrustNavy = Color(0xFF1E3A5F)
    val CalmCobalt = Color(0xFF2B5B84)
    val VerifiedForest = Color(0xFF1E5643)
    val VerifiedMint = Color(0xFFEBF5F0)
    val UntrustedAmber = Color(0xFFB45309)
    val UntrustedBg = Color(0xFFF8F5EE)
    val AlertCrimsonLight = Color(0xFFB3261E)
    val AlertCrimsonBgLight = Color(0xFFFCECEC)

    // Dark palette
    val BgPaperDark = Color(0xFF0E1217)
    val SurfaceCardDark = Color(0xFF161C24)
    val SurfaceElevatedDark = Color(0xFF1D2530)
    val BorderDark = Color(0xFF26303D)
    val InkPrimaryDark = Color(0xFFF1F5F9)
    val InkSecondaryDark = Color(0xFF9FB0C2)
    val InkMutedDark = Color(0xFF708295)
    val TrustNavyDark = Color(0xFF2B5482)
    val TrustNavyTintDark = Color(0xFF7AA7D9)
    val VerifiedMintDark = Color(0xFF163027)
    val VerifiedForestDark = Color(0xFF6EE7B7)
    val UntrustedAmberDark = Color(0xFFF59E0B)
    val UntrustedBgDark = Color(0xFF271F14)
    val AlertCrimsonDark = Color(0xFFF87171)
    val AlertCrimsonBgDark = Color(0xFF33181B)
}

/**
 * Extended semantic color tokens exposed via [NavaThemeExtras.colors] for borders,
 * Warm Paper / Matte OLED surfaces, trust accents, and untrusted-provenance highlights.
 */
@Immutable
data class NavaExtendedColors(
    val bgLinen: Color,
    val bgPaper: Color,
    val surfaceCard: Color,
    val borderStone: Color,
    val inkPrimary: Color,
    val inkSecondary: Color,
    val inkMuted: Color,
    val trustNavy: Color,
    val trustNavyTint: Color,
    val verifiedForest: Color,
    val verifiedMint: Color,
    val untrustedAccent: Color,
    val untrustedSurface: Color,
    val alertCrimson: Color,
    val alertCrimsonSurface: Color,
    val navIndicator: Color
)

val LightNavaExtendedColors = NavaExtendedColors(
    bgLinen = NavaColors.BgLinen,
    bgPaper = NavaColors.BgPaper,
    surfaceCard = NavaColors.SurfaceCard,
    borderStone = NavaColors.BorderStone,
    inkPrimary = NavaColors.InkPrimary,
    inkSecondary = NavaColors.InkSecondary,
    inkMuted = NavaColors.InkMuted,
    trustNavy = NavaColors.TrustNavy,
    trustNavyTint = NavaColors.CalmCobalt,
    verifiedForest = NavaColors.VerifiedForest,
    verifiedMint = NavaColors.VerifiedMint,
    untrustedAccent = NavaColors.UntrustedAmber,
    untrustedSurface = NavaColors.UntrustedBg,
    alertCrimson = NavaColors.AlertCrimsonLight,
    alertCrimsonSurface = NavaColors.AlertCrimsonBgLight,
    navIndicator = Color(0xFFE7EDF4)
)

val DarkNavaExtendedColors = NavaExtendedColors(
    bgLinen = NavaColors.SurfaceElevatedDark,
    bgPaper = NavaColors.BgPaperDark,
    surfaceCard = NavaColors.SurfaceCardDark,
    borderStone = NavaColors.BorderDark,
    inkPrimary = NavaColors.InkPrimaryDark,
    inkSecondary = NavaColors.InkSecondaryDark,
    inkMuted = NavaColors.InkMutedDark,
    trustNavy = NavaColors.TrustNavyDark,
    trustNavyTint = NavaColors.TrustNavyTintDark,
    verifiedForest = NavaColors.VerifiedForestDark,
    verifiedMint = NavaColors.VerifiedMintDark,
    untrustedAccent = NavaColors.UntrustedAmberDark,
    untrustedSurface = NavaColors.UntrustedBgDark,
    alertCrimson = NavaColors.AlertCrimsonDark,
    alertCrimsonSurface = NavaColors.AlertCrimsonBgDark,
    navIndicator = Color(0xFF223042)
)

val LocalNavaExtendedColors = staticCompositionLocalOf { LightNavaExtendedColors }

/**
 * Accessor for Nava's extended semantic colors inside Compose.
 */
object NavaThemeExtras {
    val colors: NavaExtendedColors
        @Composable
        get() = LocalNavaExtendedColors.current
}

val NavaDarkColorScheme: ColorScheme = darkColorScheme(
    primary = NavaColors.TrustNavyTintDark,
    onPrimary = NavaColors.BgPaperDark,
    primaryContainer = NavaColors.TrustNavyDark,
    onPrimaryContainer = NavaColors.InkPrimaryDark,
    secondary = NavaColors.UntrustedAmberDark,
    onSecondary = NavaColors.BgPaperDark,
    secondaryContainer = NavaColors.UntrustedBgDark,
    onSecondaryContainer = NavaColors.UntrustedAmberDark,
    tertiary = NavaColors.VerifiedForestDark,
    onTertiary = NavaColors.BgPaperDark,
    tertiaryContainer = NavaColors.VerifiedMintDark,
    onTertiaryContainer = NavaColors.VerifiedForestDark,
    background = NavaColors.BgPaperDark,
    onBackground = NavaColors.InkPrimaryDark,
    surface = NavaColors.SurfaceCardDark,
    onSurface = NavaColors.InkPrimaryDark,
    surfaceVariant = NavaColors.SurfaceElevatedDark,
    onSurfaceVariant = NavaColors.InkSecondaryDark,
    outline = NavaColors.BorderDark,
    outlineVariant = NavaColors.BorderDark,
    error = NavaColors.AlertCrimsonDark,
    onError = NavaColors.BgPaperDark,
    errorContainer = NavaColors.AlertCrimsonBgDark,
    onErrorContainer = NavaColors.InkPrimaryDark
)

val NavaLightColorScheme: ColorScheme = lightColorScheme(
    primary = NavaColors.TrustNavy,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE3ECF5),
    onPrimaryContainer = NavaColors.TrustNavy,
    secondary = NavaColors.CalmCobalt,
    onSecondary = Color.White,
    secondaryContainer = NavaColors.UntrustedBg,
    onSecondaryContainer = NavaColors.UntrustedAmber,
    tertiary = NavaColors.VerifiedForest,
    onTertiary = Color.White,
    tertiaryContainer = NavaColors.VerifiedMint,
    onTertiaryContainer = NavaColors.VerifiedForest,
    background = NavaColors.BgPaper,
    onBackground = NavaColors.InkPrimary,
    surface = NavaColors.SurfaceCard,
    onSurface = NavaColors.InkPrimary,
    surfaceVariant = NavaColors.BgLinen,
    onSurfaceVariant = NavaColors.InkSecondary,
    outline = NavaColors.BorderStone,
    outlineVariant = NavaColors.BorderStone,
    error = NavaColors.AlertCrimsonLight,
    onError = Color.White,
    errorContainer = NavaColors.AlertCrimsonBgLight,
    onErrorContainer = NavaColors.AlertCrimsonLight
)

/**
 * System-font typography using [FontFamily.Default] (Android system Roboto + automatic Noto
 * multi-script fallback across Latin, Arabic, Cyrillic, Devanagari, CJK, and all Gemma 4 scripts;
 * PLAN.md Section 6.5). Zero bundled multi-MB custom font assets.
 */
val NavaTypography: Typography = Typography(
    displayLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Bold,
        fontSize = 32.sp,
        lineHeight = 40.sp
    ),
    displayMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Bold,
        fontSize = 28.sp,
        lineHeight = 36.sp
    ),
    displaySmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
        lineHeight = 32.sp
    ),
    headlineLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 26.sp,
        lineHeight = 34.sp
    ),
    headlineMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
        lineHeight = 32.sp
    ),
    headlineSmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
        lineHeight = 28.sp
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
        lineHeight = 28.sp
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 16.sp,
        lineHeight = 24.sp
    ),
    titleSmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        lineHeight = 20.sp
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp
    ),
    bodySmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 16.sp
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 14.sp,
        lineHeight = 20.sp
    ),
    labelMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        lineHeight = 16.sp
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        lineHeight = 16.sp
    )
)

/**
 * Resolves [LayoutDirection] for [locale] using ICU / Unicode character script directionality
 * via [BidiTextFormatter.isRtlLocale] with zero hardcoded language lists (Iron Law 1).
 */
fun resolveLayoutDirectionForLocale(locale: Locale): LayoutDirection {
    return if (BidiTextFormatter.isRtlLocale(locale)) {
        LayoutDirection.Rtl
    } else {
        LayoutDirection.Ltr
    }
}

/**
 * Root Material 3 theme for Nava.
 *
 * - Uses [NavaTypography] with [FontFamily.Default] (system Noto fallback).
 * - Applies Warm Paper / Linen Light or Matte OLED Dark color scheme and [NavaThemeExtras].
 * - Respects Compose's locale-derived [LocalLayoutDirection] automatically, or applies
 *   script-derived RTL directionality when an explicit [activeLocale] or [forceRtlOverride] is provided.
 */
@Composable
fun NavaTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    isDarkThemeOverride: Boolean? = null,
    activeLocale: Locale? = null,
    forceRtlOverride: Boolean? = null,
    content: @Composable () -> Unit
) {
    val effectiveDark = isDarkThemeOverride ?: darkTheme
    val colorScheme = if (effectiveDark) NavaDarkColorScheme else NavaLightColorScheme
    val extendedColors = if (effectiveDark) DarkNavaExtendedColors else LightNavaExtendedColors
    val currentLayoutDirection = LocalLayoutDirection.current
    val effectiveLayoutDirection = when {
        forceRtlOverride == true -> LayoutDirection.Rtl
        forceRtlOverride == false -> LayoutDirection.Ltr
        activeLocale != null -> resolveLayoutDirectionForLocale(activeLocale)
        else -> currentLayoutDirection
    }

    CompositionLocalProvider(
        LocalLayoutDirection provides effectiveLayoutDirection,
        LocalNavaExtendedColors provides extendedColors
    ) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = NavaTypography,
            content = content
        )
    }
}

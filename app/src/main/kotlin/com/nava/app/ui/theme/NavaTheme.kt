package com.nava.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
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
 * Dual-Core Neural Hub color palette tokens (PLAN.md Section 7).
 */
object NavaColors {
    val DeepObsidian = Color(0xFF0A0E17)
    val DeepSurface = Color(0xFF121826)
    val DeepSurfaceVariant = Color(0xFF1C2538)
    val OuterCortexCyan = Color(0xFF00E5FF)
    val OuterCortexCyanDim = Color(0xFF008394)
    val InnerCoreAmber = Color(0xFFFFB300)
    val InnerCoreAmberDim = Color(0xFFA67400)
    val VaultGold = Color(0xFFFFD54F)
    val AlertCrimson = Color(0xFFFF5252)
    val AlertCrimsonContainer = Color(0xFF3E1218)
    val SafeEmerald = Color(0xFF00E676)
    val TextPrimaryDark = Color(0xFFEAF0FB)
    val TextSecondaryDark = Color(0xFFA0AEC0)

    val LightBackground = Color(0xFFF6F8FC)
    val LightSurface = Color(0xFFFFFFFF)
    val LightSurfaceVariant = Color(0xFFE4EBF5)
    val OuterCortexTealLight = Color(0xFF006876)
    val InnerCoreAmberLight = Color(0xFF8A5D00)
    val AlertCrimsonLight = Color(0xFFB3261E)
    val TextPrimaryLight = Color(0xFF0F172A)
    val TextSecondaryLight = Color(0xFF475569)
}

val NavaDarkColorScheme: ColorScheme = darkColorScheme(
    primary = NavaColors.OuterCortexCyan,
    onPrimary = NavaColors.DeepObsidian,
    primaryContainer = NavaColors.OuterCortexCyanDim,
    onPrimaryContainer = NavaColors.TextPrimaryDark,
    secondary = NavaColors.InnerCoreAmber,
    onSecondary = NavaColors.DeepObsidian,
    secondaryContainer = NavaColors.InnerCoreAmberDim,
    onSecondaryContainer = NavaColors.TextPrimaryDark,
    tertiary = NavaColors.VaultGold,
    onTertiary = NavaColors.DeepObsidian,
    background = NavaColors.DeepObsidian,
    onBackground = NavaColors.TextPrimaryDark,
    surface = NavaColors.DeepSurface,
    onSurface = NavaColors.TextPrimaryDark,
    surfaceVariant = NavaColors.DeepSurfaceVariant,
    onSurfaceVariant = NavaColors.TextSecondaryDark,
    error = NavaColors.AlertCrimson,
    onError = NavaColors.DeepObsidian,
    errorContainer = NavaColors.AlertCrimsonContainer,
    onErrorContainer = NavaColors.TextPrimaryDark
)

val NavaLightColorScheme: ColorScheme = lightColorScheme(
    primary = NavaColors.OuterCortexTealLight,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFB2EBF2),
    onPrimaryContainer = NavaColors.TextPrimaryLight,
    secondary = NavaColors.InnerCoreAmberLight,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFFFECB3),
    onSecondaryContainer = NavaColors.TextPrimaryLight,
    tertiary = Color(0xFF7A5900),
    onTertiary = Color.White,
    background = NavaColors.LightBackground,
    onBackground = NavaColors.TextPrimaryLight,
    surface = NavaColors.LightSurface,
    onSurface = NavaColors.TextPrimaryLight,
    surfaceVariant = NavaColors.LightSurfaceVariant,
    onSurfaceVariant = NavaColors.TextSecondaryLight,
    error = NavaColors.AlertCrimsonLight,
    onError = Color.White
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
    headlineMedium = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
        lineHeight = 32.sp
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
 * - Respects Compose's locale-derived [LocalLayoutDirection] automatically, or applies
 *   script-derived RTL directionality when an explicit [activeLocale] is provided.
 */
@Composable
fun NavaTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    activeLocale: Locale? = null,
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) NavaDarkColorScheme else NavaLightColorScheme
    val currentLayoutDirection = LocalLayoutDirection.current
    val effectiveLayoutDirection = if (activeLocale != null) {
        resolveLayoutDirectionForLocale(activeLocale)
    } else {
        currentLayoutDirection
    }

    CompositionLocalProvider(LocalLayoutDirection provides effectiveLayoutDirection) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = NavaTypography,
            content = content
        )
    }
}

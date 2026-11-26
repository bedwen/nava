package com.nava.app.ui.theme

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import com.nava.app.di.InMemoryPreferencesStorageGateway
import com.nava.app.ui.navigation.NavaDestination
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NavaThemeAndNavigationStep1Test {

    @Test
    fun themePreferenceStore_defaultsToSystem() {
        val storage = InMemoryPreferencesStorageGateway()
        val store = ThemePreferenceStore(storage)

        assertEquals(NavaThemeMode.SYSTEM, store.themeModeFlow.value)
    }

    @Test
    fun themePreferenceStore_setThemeModeUpdatesFlowAndPersistsAcrossInstances() {
        val storage = InMemoryPreferencesStorageGateway()
        val initialStore = ThemePreferenceStore(storage)

        initialStore.setThemeMode(NavaThemeMode.DARK)
        assertEquals(NavaThemeMode.DARK, initialStore.themeModeFlow.value)

        val reloadedAfterDark = ThemePreferenceStore(storage)
        assertEquals(NavaThemeMode.DARK, reloadedAfterDark.themeModeFlow.value)

        reloadedAfterDark.setThemeMode(NavaThemeMode.LIGHT)
        assertEquals(NavaThemeMode.LIGHT, reloadedAfterDark.themeModeFlow.value)

        val reloadedAfterLight = ThemePreferenceStore(storage)
        assertEquals(NavaThemeMode.LIGHT, reloadedAfterLight.themeModeFlow.value)
    }

    @Test
    fun themePreferenceStore_toggleDarkLightSwitchesBetweenDarkAndLight() {
        val storage = InMemoryPreferencesStorageGateway()
        val store = ThemePreferenceStore(storage)

        store.toggleDarkLight(currentlyDark = false)
        assertEquals(NavaThemeMode.DARK, store.themeModeFlow.value)

        store.toggleDarkLight(currentlyDark = true)
        assertEquals(NavaThemeMode.LIGHT, store.themeModeFlow.value)
    }

    @Test
    fun themePreferenceStore_corruptedValueFallsBackToSystem() {
        val storage = InMemoryPreferencesStorageGateway()
        storage.putString(ThemePreferenceStore.KEY_THEME_MODE, "INVALID_CORRUPTED_THEME")

        val store = ThemePreferenceStore(storage)
        assertEquals(NavaThemeMode.SYSTEM, store.themeModeFlow.value)
    }

    @Test
    fun navaColorsAndSchemes_defineWarmPaperLightAndMatteOledDarkTokens() {
        assertNotEquals(Color.Unspecified, NavaColors.BgPaper)
        assertNotEquals(Color.Unspecified, NavaColors.BgPaperDark)
        assertNotEquals(Color.Unspecified, NavaColors.TrustNavy)
        assertNotEquals(Color.Unspecified, NavaColors.VerifiedForest)
        assertNotEquals(Color.Unspecified, NavaColors.UntrustedAmber)
        assertNotEquals(NavaColors.BgPaper, NavaColors.BgPaperDark)

        assertTrue(NavaColors.BgPaper.red > 0.85f && NavaColors.BgPaper.green > 0.85f && NavaColors.BgPaper.blue > 0.80f)
        assertTrue(NavaColors.BgPaperDark.red < 0.15f && NavaColors.BgPaperDark.green < 0.15f && NavaColors.BgPaperDark.blue < 0.15f)

        assertEquals(NavaColors.BgPaper, NavaLightColorScheme.background)
        assertEquals(NavaColors.BgPaperDark, NavaDarkColorScheme.background)

        assertNotNull(LightNavaExtendedColors)
        assertNotNull(DarkNavaExtendedColors)
        assertNotEquals(LightNavaExtendedColors, DarkNavaExtendedColors)
    }

    @Test
    fun navaTypography_usesDefaultSystemFontFamilyAcrossAllStyles() {
        val styles = listOf(
            NavaTypography.displayLarge,
            NavaTypography.displayMedium,
            NavaTypography.displaySmall,
            NavaTypography.headlineLarge,
            NavaTypography.headlineMedium,
            NavaTypography.headlineSmall,
            NavaTypography.titleLarge,
            NavaTypography.titleMedium,
            NavaTypography.titleSmall,
            NavaTypography.bodyLarge,
            NavaTypography.bodyMedium,
            NavaTypography.bodySmall,
            NavaTypography.labelLarge,
            NavaTypography.labelMedium,
            NavaTypography.labelSmall
        )
        for (style in styles) {
            assertEquals(FontFamily.Default, style.fontFamily)
        }
    }

    @Test
    fun navaDestination_bottomBarDestinationsAndVisibilityAreConfigured() {
        assertEquals(
            listOf(
                NavaDestination.HUB,
                NavaDestination.VAULT,
                NavaDestination.PROFILES,
                NavaDestination.SETTINGS
            ),
            NavaDestination.BOTTOM_BAR_DESTINATIONS
        )
        assertTrue(NavaDestination.BOTTOM_BAR_DESTINATIONS.all { it.showInBottomBar })
        assertFalse(NavaDestination.ONBOARDING.showInBottomBar)
        assertFalse(NavaDestination.AUDIT_LOG.showInBottomBar)
    }
}

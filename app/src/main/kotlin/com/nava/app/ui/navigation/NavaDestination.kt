package com.nava.app.ui.navigation

import androidx.annotation.StringRes
import com.nava.app.R
import com.nava.domain.ui.NeuronNodeId

/**
 * State-driven top-level navigation destinations in `:app` (zero Navigation Compose dependency).
 */
enum class NavaDestination(
    @StringRes val labelResId: Int,
    val showInBottomBar: Boolean
) {
    ONBOARDING(
        labelResId = R.string.onboarding_title,
        showInBottomBar = false
    ),
    HUB(
        labelResId = R.string.nav_hub,
        showInBottomBar = true
    ),
    PROFILES(
        labelResId = R.string.nav_profile,
        showInBottomBar = true
    ),
    ROUTINES(
        labelResId = R.string.nav_routines,
        showInBottomBar = true
    ),
    SETTINGS(
        labelResId = R.string.nav_settings,
        showInBottomBar = true
    );

    companion object {
        val BOTTOM_BAR_DESTINATIONS: List<NavaDestination> = listOf(
            HUB,
            PROFILES,
            ROUTINES,
            SETTINGS
        )
    }
}

/**
 * Immutable navigation state holding the active [NavaDestination] and optional target focus
 * when jumping from a tapped [NeuronNodeId] on the Dual-Core Neural Canvas to [NavaDestination.PROFILES].
 */
data class NavaNavigationState(
    val currentDestination: NavaDestination,
    val focusedTargetId: String? = null,
    val focusedNeuron: NeuronNodeId? = null
)

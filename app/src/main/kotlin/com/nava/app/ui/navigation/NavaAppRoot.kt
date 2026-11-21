package com.nava.app.ui.navigation

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import com.nava.app.di.AppContainer
import com.nava.app.ui.hub.NavaHubScreen
import com.nava.app.ui.hub.NavaHubViewModel
import com.nava.app.ui.onboarding.OnboardingScreen
import com.nava.app.ui.onboarding.OnboardingViewModel
import com.nava.app.ui.profiles.PermissionProfilesScreen
import com.nava.app.ui.profiles.PermissionProfilesViewModel
import com.nava.app.ui.routines.RoutinesScreen
import com.nava.app.ui.routines.RoutinesViewModel
import com.nava.app.ui.settings.SettingsScreen
import com.nava.app.ui.settings.SettingsViewModel
import com.nava.app.ui.theme.NavaTheme
import java.util.Locale

/**
 * State-driven root Compose host for `:app` (zero Navigation Compose dependency).
 *
 * - Routes to [NavaDestination.ONBOARDING] when Default-Deny onboarding is not yet completed.
 * - Routes across [NavaDestination.HUB], [NavaDestination.PROFILES], [NavaDestination.ROUTINES],
 *   and [NavaDestination.SETTINGS] via a Material 3 bottom [NavigationBar].
 */
@Composable
fun NavaAppRoot(
    appContainer: AppContainer,
    activity: FragmentActivity?,
    modifier: Modifier = Modifier
) {
    val onboardingState by appContainer.onboardingStateStore.stateFlow.collectAsState()
    val activeLocaleTag by appContainer.appLocaleManager.activeLocaleTagFlow.collectAsState()
    val activeLocale = remember(activeLocaleTag) {
        Locale.forLanguageTag(activeLocaleTag)
    }

    var navState by remember(onboardingState.isOnboardingCompleted) {
        val startDest = if (onboardingState.isOnboardingCompleted) {
            NavaDestination.HUB
        } else {
            NavaDestination.ONBOARDING
        }
        mutableStateOf(NavaNavigationState(currentDestination = startDest))
    }

    val vmFactory = remember(appContainer) { NavaViewModelFactory(appContainer) }
    val fallbackViewModelStore = remember(appContainer) { ViewModelStore() }
    val viewModelProvider = remember(activity, fallbackViewModelStore, vmFactory) {
        if (activity != null) {
            ViewModelProvider(activity, vmFactory)
        } else {
            ViewModelProvider(fallbackViewModelStore, vmFactory)
        }
    }
    val onboardingViewModel = remember(viewModelProvider) {
        viewModelProvider[OnboardingViewModel::class.java]
    }
    val hubViewModel = remember(viewModelProvider) {
        viewModelProvider[NavaHubViewModel::class.java]
    }
    val profilesViewModel = remember(viewModelProvider) {
        viewModelProvider[PermissionProfilesViewModel::class.java]
    }
    val routinesViewModel = remember(viewModelProvider) {
        viewModelProvider[RoutinesViewModel::class.java]
    }
    val settingsViewModel = remember(viewModelProvider) {
        viewModelProvider[SettingsViewModel::class.java]
    }

    DisposableEffect(appContainer, activity, fallbackViewModelStore) {
        onDispose {
            appContainer.voiceInputController.cancel()
            if (activity == null) {
                fallbackViewModelStore.clear()
            }
        }
    }

    NavaTheme(activeLocale = activeLocale) {
        Scaffold(
            modifier = modifier.fillMaxSize(),
            bottomBar = {
                if (navState.currentDestination != NavaDestination.ONBOARDING) {
                    NavigationBar {
                        for (destination in NavaDestination.BOTTOM_BAR_DESTINATIONS) {
                            val selected = navState.currentDestination == destination
                            NavigationBarItem(
                                selected = selected,
                                onClick = {
                                    navState = NavaNavigationState(currentDestination = destination)
                                },
                                icon = {
                                    Text(text = destination.name.take(1))
                                },
                                label = {
                                    Text(text = stringResource(destination.labelResId))
                                }
                            )
                        }
                    }
                }
            }
        ) { innerPadding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) {
                when (navState.currentDestination) {
                    NavaDestination.ONBOARDING -> {
                        OnboardingScreen(
                            viewModel = onboardingViewModel,
                            onOnboardingFinished = {
                                navState = NavaNavigationState(
                                    currentDestination = NavaDestination.HUB
                                )
                            }
                        )
                    }

                    NavaDestination.HUB -> {
                        NavaHubScreen(
                            viewModel = hubViewModel,
                            messageRenderer = appContainer.messageRenderer,
                            bidiFormatter = appContainer.bidiTextFormatter,
                            activity = activity,
                            onOpenProfileForTarget = { targetId, neuron ->
                                navState = NavaNavigationState(
                                    currentDestination = NavaDestination.PROFILES,
                                    focusedTargetId = targetId,
                                    focusedNeuron = neuron
                                )
                            },
                            onOpenSettings = {
                                navState = NavaNavigationState(
                                    currentDestination = NavaDestination.SETTINGS
                                )
                            }
                        )
                    }

                    NavaDestination.PROFILES -> {
                        PermissionProfilesScreen(
                            viewModel = profilesViewModel,
                            bidiFormatter = appContainer.bidiTextFormatter,
                            activeLocale = activeLocale,
                            initialFocusedTargetId = navState.focusedTargetId
                        )
                    }

                    NavaDestination.ROUTINES -> {
                        RoutinesScreen(
                            viewModel = routinesViewModel,
                            bidiFormatter = appContainer.bidiTextFormatter,
                            activeLocale = activeLocale
                        )
                    }

                    NavaDestination.SETTINGS -> {
                        SettingsScreen(
                            viewModel = settingsViewModel,
                            bidiFormatter = appContainer.bidiTextFormatter,
                            activity = activity
                        )
                    }
                }
            }
        }
    }
}

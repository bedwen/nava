package com.nava.app.ui.navigation

import androidx.compose.animation.Crossfade
import androidx.compose.animation.core.tween
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import com.nava.app.di.AppContainer
import com.nava.app.ui.audit.AuditLogScreen
import com.nava.app.ui.components.NavaIcons
import com.nava.app.ui.components.NavaTopBar
import com.nava.app.ui.hub.NavaHubScreen
import com.nava.app.ui.hub.NavaHubViewModel
import com.nava.app.ui.onboarding.OnboardingScreen
import com.nava.app.ui.onboarding.OnboardingViewModel
import com.nava.app.ui.profiles.PermissionProfilesScreen
import com.nava.app.ui.profiles.PermissionProfilesViewModel
import com.nava.app.ui.routines.RoutinesViewModel
import com.nava.app.ui.settings.SettingsScreen
import com.nava.app.ui.settings.SettingsViewModel
import com.nava.app.ui.theme.NavaTheme
import com.nava.app.ui.theme.NavaThemeExtras
import com.nava.app.ui.theme.NavaThemeMode
import com.nava.app.ui.vault.VaultScreen
import java.util.Locale
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * State-driven root Compose host for `:app` (zero Navigation Compose dependency).
 *
 * - Routes to [NavaDestination.ONBOARDING] when Default-Deny onboarding is not yet completed.
 * - Routes across [NavaDestination.HUB], [NavaDestination.PROFILES], [NavaDestination.VAULT],
 *   and [NavaDestination.AUDIT_LOG] via a Material 3 bottom [NavigationBar], with
 *   [NavaDestination.SETTINGS] reachable from [NavaTopBar].
 */
@Composable
fun NavaAppRoot(
    appContainer: AppContainer,
    activity: FragmentActivity?,
    modifier: Modifier = Modifier,
    onDarkThemeChanged: (Boolean) -> Unit = {}
) {
    val onboardingState by appContainer.onboardingStateStore.stateFlow.collectAsStateWithLifecycle()
    val activeLocaleTag by appContainer.appLocaleManager.activeLocaleTagFlow.collectAsStateWithLifecycle()
    val themeMode by appContainer.themePreferenceStore.themeModeFlow.collectAsStateWithLifecycle()
    val activeConfirmation by appContainer.pendingConfirmationStore.activeConfirmationFlow.collectAsStateWithLifecycle()

    val activeLocale = remember(activeLocaleTag) {
        Locale.forLanguageTag(activeLocaleTag)
    }

    val systemDark = isSystemInDarkTheme()
    val darkOverride = when (themeMode) {
        NavaThemeMode.DARK -> true
        NavaThemeMode.LIGHT -> false
        NavaThemeMode.SYSTEM -> null
    }
    val effectiveDarkTheme = darkOverride ?: systemDark

    SideEffect {
        onDarkThemeChanged(effectiveDarkTheme)
    }

    var navState by remember(onboardingState.isOnboardingCompleted) {
        val startDest = if (onboardingState.isOnboardingCompleted) {
            NavaDestination.HUB
        } else {
            NavaDestination.ONBOARDING
        }
        mutableStateOf(NavaNavigationState(currentDestination = startDest))
    }

    var isHudVisible by remember { mutableStateOf(false) }

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

    LaunchedEffect(navState.currentDestination) {
        if (navState.currentDestination == NavaDestination.HUB) {
            hubViewModel.refreshPermittedNeurons()
        }
    }

    DisposableEffect(appContainer, activity, fallbackViewModelStore) {
        onDispose {
            appContainer.voiceInputController.cancel()
            if (activity == null) {
                fallbackViewModelStore.clear()
            }
        }
    }

    NavaTheme(
        darkTheme = systemDark,
        isDarkThemeOverride = darkOverride,
        activeLocale = activeLocale
    ) {
        val extendedColors = NavaThemeExtras.colors

        Scaffold(
            modifier = modifier.fillMaxSize(),
            containerColor = extendedColors.bgPaper,
            topBar = {
                if (navState.currentDestination != NavaDestination.ONBOARDING) {
                    NavaTopBar(
                        showBackButton = navState.currentDestination == NavaDestination.AUDIT_LOG,
                        isDarkTheme = effectiveDarkTheme,
                        hasPendingConfirmations = activeConfirmation != null,
                        isSettingsActive = navState.currentDestination == NavaDestination.AUDIT_LOG,
                        onBackClick = {
                            navState = NavaNavigationState(currentDestination = NavaDestination.HUB)
                        },
                        onNotificationsClick = {
                            navState = NavaNavigationState(currentDestination = NavaDestination.HUB)
                        },
                        onToggleTheme = {
                            appContainer.themePreferenceStore.toggleDarkLight(effectiveDarkTheme)
                        },
                        onSettingsClick = {
                            navState = NavaNavigationState(currentDestination = NavaDestination.AUDIT_LOG)
                        },
                        onStatusPillClick = {
                            isHudVisible = !isHudVisible
                        }
                    )
                }
            },
            bottomBar = {
                if (navState.currentDestination.showInBottomBar) {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        HorizontalDivider(
                            thickness = 1.dp,
                            color = extendedColors.borderStone
                        )
                        NavigationBar(
                            containerColor = extendedColors.surfaceCard,
                            tonalElevation = 0.dp
                        ) {
                            for (destination in NavaDestination.BOTTOM_BAR_DESTINATIONS) {
                                val selected = navState.currentDestination == destination
                                val iconVector = when (destination) {
                                    NavaDestination.HUB -> NavaIcons.HubRing
                                    NavaDestination.PROFILES -> NavaIcons.Shield
                                    NavaDestination.VAULT -> NavaIcons.Calendar
                                    NavaDestination.AUDIT_LOG -> NavaIcons.AuditList
                                    NavaDestination.SETTINGS -> NavaIcons.Settings
                                    else -> NavaIcons.HubRing
                                }
                                NavigationBarItem(
                                    selected = selected,
                                    onClick = {
                                        navState = NavaNavigationState(currentDestination = destination)
                                    },
                                    icon = {
                                        Icon(
                                            imageVector = iconVector,
                                            contentDescription = null,
                                            modifier = Modifier.size(22.dp)
                                        )
                                    },
                                    label = {
                                        Text(
                                            text = stringResource(destination.labelResId),
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    },
                                    colors = NavigationBarItemDefaults.colors(
                                        selectedIconColor = extendedColors.trustNavyTint,
                                        selectedTextColor = extendedColors.inkPrimary,
                                        indicatorColor = extendedColors.navIndicator,
                                        unselectedIconColor = extendedColors.inkMuted,
                                        unselectedTextColor = extendedColors.inkMuted
                                    )
                                )
                            }
                        }
                    }
                }
            }
        ) { innerPadding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
                    .consumeWindowInsets(innerPadding)
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
                            },
                            showHud = isHudVisible
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

                    NavaDestination.VAULT -> {
                        VaultScreen(
                            settingsViewModel = settingsViewModel,
                            routinesViewModel = routinesViewModel,
                            bidiFormatter = appContainer.bidiTextFormatter,
                            activeLocale = activeLocale,
                            activity = activity
                        )
                    }

                    NavaDestination.AUDIT_LOG -> {
                        AuditLogScreen(
                            viewModel = settingsViewModel,
                            bidiFormatter = appContainer.bidiTextFormatter,
                            activeLocale = activeLocale
                        )
                    }

                    NavaDestination.SETTINGS -> {
                        SettingsScreen(
                            viewModel = settingsViewModel,
                            bidiFormatter = appContainer.bidiTextFormatter,
                            activity = activity,
                            themeMode = themeMode,
                            onSelectThemeMode = { mode ->
                                appContainer.themePreferenceStore.setThemeMode(mode)
                            }
                        )
                    }
                }
            }
        }
    }
}

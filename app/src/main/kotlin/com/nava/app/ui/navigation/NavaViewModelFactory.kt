package com.nava.app.ui.navigation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.CreationExtras
import com.nava.app.di.AppContainer
import com.nava.app.ui.hub.NavaHubViewModel
import com.nava.app.ui.onboarding.OnboardingViewModel
import com.nava.app.ui.profiles.PermissionProfilesViewModel
import com.nava.app.ui.routines.RoutinesViewModel
import com.nava.app.ui.settings.SettingsViewModel

/**
 * Pure Kotlin constructor-DI [ViewModelProvider.Factory] for `:app` (Iron Law 4: zero reflection,
 * zero Hilt/Dagger/Koin).
 */
class NavaViewModelFactory(
    private val container: AppContainer
) : ViewModelProvider.Factory {

    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        return when {
            modelClass.isAssignableFrom(OnboardingViewModel::class.java) ->
                OnboardingViewModel(container = container) as T

            modelClass.isAssignableFrom(NavaHubViewModel::class.java) ->
                NavaHubViewModel(container = container) as T

            modelClass.isAssignableFrom(PermissionProfilesViewModel::class.java) ->
                PermissionProfilesViewModel(container = container) as T

            modelClass.isAssignableFrom(RoutinesViewModel::class.java) ->
                RoutinesViewModel(container = container) as T

            modelClass.isAssignableFrom(SettingsViewModel::class.java) ->
                SettingsViewModel(container = container) as T

            else -> throw IllegalArgumentException("Unknown ViewModel class: ${modelClass.name}")
        }
    }

    override fun <T : ViewModel> create(modelClass: Class<T>, extras: CreationExtras): T {
        return create(modelClass)
    }
}

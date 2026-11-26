package com.nava.app.ui.theme

import android.content.Context
import com.nava.app.di.PreferencesStorageGateway
import com.nava.app.di.SharedPreferencesStorageGateway
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * User-selected appearance mode for Nava's Compose UI.
 */
enum class NavaThemeMode {
    SYSTEM,
    LIGHT,
    DARK
}

/**
 * Thread-safe store persisting the active [NavaThemeMode] in `MODE_PRIVATE` preferences
 * via [PreferencesStorageGateway].
 */
class ThemePreferenceStore(
    private val storage: PreferencesStorageGateway
) {

    constructor(context: Context) : this(
        SharedPreferencesStorageGateway(context)
    )

    private val lock = Any()

    private val _themeModeFlow: MutableStateFlow<NavaThemeMode> = MutableStateFlow(
        readModeFromStorage()
    )

    /** Reactive stream of the active [NavaThemeMode]. */
    val themeModeFlow: StateFlow<NavaThemeMode> = _themeModeFlow.asStateFlow()

    fun currentMode(): NavaThemeMode = _themeModeFlow.value

    fun setThemeMode(mode: NavaThemeMode): NavaThemeMode = synchronized(lock) {
        storage.putString(KEY_THEME_MODE, mode.name)
        _themeModeFlow.value = mode
        mode
    }

    fun toggleDarkLight(currentlyDark: Boolean): NavaThemeMode {
        val nextMode = if (currentlyDark) NavaThemeMode.LIGHT else NavaThemeMode.DARK
        return setThemeMode(nextMode)
    }

    private fun readModeFromStorage(): NavaThemeMode {
        val raw = storage.getString(KEY_THEME_MODE, null)?.trim()
        if (raw.isNullOrEmpty()) return NavaThemeMode.SYSTEM
        return NavaThemeMode.entries.firstOrNull { it.name.equals(raw, ignoreCase = true) }
            ?: NavaThemeMode.SYSTEM
    }

    companion object {
        const val KEY_THEME_MODE: String = "ui_theme_mode"
    }
}

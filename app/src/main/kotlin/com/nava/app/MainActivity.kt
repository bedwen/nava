package com.nava.app

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.lifecycle.lifecycleScope
import com.nava.app.assistant.AssistantIntentContract
import com.nava.app.assistant.AssistantOpenMode
import com.nava.app.assistant.ConfirmationIntentExtras
import com.nava.app.di.AppContainer
import com.nava.app.di.NavaApplication
import com.nava.app.reminders.ReminderNotificationPoster
import com.nava.app.security.NotificationResolutionResult
import com.nava.app.ui.navigation.NavaAppRoot
import com.nava.app.ui.theme.NavaThemeMode
import kotlinx.coroutines.launch
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * Primary [AppCompatActivity] entry point for Nava (PLAN.md Sections 2.3, 5.2, 6.2, and 6.4).
 *
 * Architectural & Security Invariants (Requirement 9):
 * - Extends [AppCompatActivity] (which subclasses `FragmentActivity`) so both AndroidX
 *   `BiometricPrompt` (`BIOMETRIC_STRONG`) and `AppCompatDelegate.setApplicationLocales`
 *   work seamlessly across Android 12-15 (API 31-35).
 * - Resolves incoming confirmation notification intents strictly via
 *   `PendingConfirmationStore.resolveFromIntent(intent)`. Forged, unknown, expired, or tampered
 *   extras are deterministically rejected without fabricating a confirmation card or executing
 *   any tool.
 */
class MainActivity : AppCompatActivity() {

    private val appContainer: AppContainer
        get() = (application as NavaApplication).appContainer

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        handleIncomingIntentAsync(intent)

        setContent {
            val systemDark = isSystemInDarkTheme()
            val themeMode by appContainer.themePreferenceStore.themeModeFlow.collectAsStateWithLifecycle()
            val initialDark = when (themeMode) {
                NavaThemeMode.DARK -> true
                NavaThemeMode.LIGHT -> false
                NavaThemeMode.SYSTEM -> systemDark
            }
            var effectiveDarkTheme by remember(initialDark) { mutableStateOf(initialDark) }

            DisposableEffect(effectiveDarkTheme) {
                val barStyle = if (effectiveDarkTheme) {
                    SystemBarStyle.dark(Color.TRANSPARENT)
                } else {
                    SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
                }
                enableEdgeToEdge(
                    statusBarStyle = barStyle,
                    navigationBarStyle = barStyle
                )
                onDispose {}
            }

            NavaAppRoot(
                appContainer = appContainer,
                activity = this,
                onDarkThemeChanged = { isDark ->
                    effectiveDarkTheme = isDark
                }
            )
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingIntentAsync(intent)
    }

    private fun handleIncomingIntentAsync(incomingIntent: Intent?) {
        if (incomingIntent == null) return
        if (incomingIntent.getBooleanExtra(ReminderNotificationPoster.EXTRA_OPEN_BRIEFING_SUMMARY, false)) {
            incomingIntent.removeExtra(ReminderNotificationPoster.EXTRA_OPEN_BRIEFING_SUMMARY)
            appContainer.briefingSummaryRequested.value = true
        }
        lifecycleScope.launch {
            resolveIncomingConfirmationIfPresent(
                intent = incomingIntent,
                container = appContainer
            )
        }
    }

    companion object {
        /**
         * Resolves incoming confirmation intents strictly through
         * [com.nava.app.security.PendingConfirmationStore.resolveFromIntent].
         *
         * Returns `null` when [intent] is a normal launcher intent with no confirmation action
         * or extras, or the deterministic [NotificationResolutionResult] when confirmation
         * resolution was attempted.
         */
        suspend fun resolveIncomingConfirmationIfPresent(
            intent: Intent?,
            container: AppContainer,
            nowEpochMs: Long = System.currentTimeMillis()
        ): NotificationResolutionResult? {
            if (intent == null) return null
            val openMode = AssistantIntentContract.extractOpenMode(intent)
            val extras = AssistantIntentContract.extractConfirmationExtras(intent)
            val isConfirmationAttempt = runCatching {
                intent.action == AssistantIntentContract.ACTION_OPEN_CONFIRMATION
            }.getOrDefault(false) ||
                openMode == AssistantOpenMode.CONFIRMATION ||
                (extras != null && extras.hasAnyIdentifier())
            if (!isConfirmationAttempt) {
                return null
            }
            return container.pendingConfirmationStore.resolveFromIntent(
                intent = intent,
                nowEpochMs = nowEpochMs
            )
        }

        /**
         * Pure-JVM testable entry point resolving extracted [ConfirmationIntentExtras] strictly
         * through [com.nava.app.security.PendingConfirmationStore.resolveFromNotificationExtras].
         */
        suspend fun resolveIncomingConfirmationExtras(
            extras: ConfirmationIntentExtras?,
            container: AppContainer,
            nowEpochMs: Long = System.currentTimeMillis()
        ): NotificationResolutionResult {
            return container.pendingConfirmationStore.resolveFromNotificationExtras(
                extras = extras,
                nowEpochMs = nowEpochMs
            )
        }
    }
}

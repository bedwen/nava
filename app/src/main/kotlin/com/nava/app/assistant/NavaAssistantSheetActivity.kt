package com.nava.app.assistant

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.nava.app.R
import com.nava.app.di.AppContainer
import com.nava.app.di.NavaApplication
import com.nava.app.security.BiometricPromptLabels
import com.nava.app.security.NotificationResolutionResult
import com.nava.app.ui.confirmation.ActionConfirmationCard
import com.nava.app.ui.hub.NavaHubViewModel
import com.nava.app.ui.navigation.NavaViewModelFactory
import com.nava.app.ui.theme.NavaTheme
import com.nava.app.voice.VoiceInputState
import java.util.Locale
import kotlinx.coroutines.launch

/**
 * Non-exported modal bottom-sheet [AppCompatActivity] launched by `NavaQuickSettingsTileService`,
 * `NavaVoiceInteractionSession`, or interactive confirmation notifications (PLAN.md Sections 2.3,
 * 5.7, and 6.4; Requirement 9).
 *
 * Security invariants:
 * - Extends [AppCompatActivity] so `BiometricPrompt` (`BIOMETRIC_STRONG`) and `AppCompatDelegate`
 *   work identically to `MainActivity`.
 * - Resolves incoming confirmation intents strictly via
 *   `PendingConfirmationStore.resolveFromIntent(intent)`. Forged or unknown extras are rejected
 *   without fabricating a confirmation card or executing any tool.
 */
class NavaAssistantSheetActivity : AppCompatActivity() {

    private val appContainer: AppContainer
        get() = (application as NavaApplication).appContainer

    private var openModeState by mutableStateOf(AssistantOpenMode.QUICK_SHEET)
    private var lastResolutionRejectedReason by mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        processIncomingSheetIntent(intent)

        val hubViewModel = ViewModelProvider(
            this,
            NavaViewModelFactory(appContainer)
        )[NavaHubViewModel::class.java]

        setContent {
            val activeLocaleTag by appContainer.appLocaleManager.activeLocaleTagFlow.collectAsState()
            val activeLocale = remember(activeLocaleTag) {
                Locale.forLanguageTag(activeLocaleTag)
            }

            DisposableEffect(appContainer) {
                onDispose {
                    appContainer.voiceInputController.cancel()
                }
            }

            NavaTheme(activeLocale = activeLocale) {
                NavaAssistantModalSheetContent(
                    appContainer = appContainer,
                    hubViewModel = hubViewModel,
                    openMode = openModeState,
                    rejectedReasonCode = lastResolutionRejectedReason,
                    activity = this,
                    onDismissSheet = { finish() }
                )
            }
        }
    }

    override fun onDestroy() {
        appContainer.voiceInputController.cancel()
        super.onDestroy()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        processIncomingSheetIntent(intent)
    }

    private fun processIncomingSheetIntent(incoming: Intent?) {
        val detectedMode = AssistantIntentContract.extractOpenMode(incoming)
            ?: AssistantOpenMode.QUICK_SHEET
        openModeState = detectedMode
        lastResolutionRejectedReason = null

        lifecycleScope.launch {
            val outcome = resolveSheetIntent(
                intent = incoming,
                container = appContainer
            )
            if (outcome is NotificationResolutionResult.Rejected) {
                lastResolutionRejectedReason = outcome.reasonCode
            }
        }
    }

    companion object {
        /**
         * Resolves incoming confirmation intents strictly through
         * [com.nava.app.security.PendingConfirmationStore.resolveFromIntent].
         *
         * Returns `null` when [intent] is a non-confirmation `QUICK_SHEET` or `VOICE` launch
         * without confirmation identifiers, or the deterministic [NotificationResolutionResult]
         * when confirmation resolution was attempted.
         */
        suspend fun resolveSheetIntent(
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
        suspend fun resolveSheetConfirmationExtras(
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

@Composable
private fun NavaAssistantModalSheetContent(
    appContainer: AppContainer,
    hubViewModel: NavaHubViewModel,
    openMode: AssistantOpenMode,
    rejectedReasonCode: String?,
    activity: FragmentActivity,
    onDismissSheet: () -> Unit
) {
    val state by hubViewModel.uiState.collectAsState()
    val context = LocalContext.current
    val locale = remember(state.activeLocaleTag) {
        Locale.forLanguageTag(state.activeLocaleTag)
    }

    val recordAudioLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        hubViewModel.onRecordAudioPermissionResult(granted)
    }

    val biometricLabels = BiometricPromptLabels(
        title = stringResource(R.string.confirm_biometric_title),
        subtitle = stringResource(R.string.confirm_biometric_prompt_text),
        negativeButtonText = stringResource(R.string.confirm_button_cancel)
    )

    val scrimInteraction = remember { MutableInteractionSource() }
    val sheetInteraction = remember { MutableInteractionSource() }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.55f))
            .clickable(
                interactionSource = scrimInteraction,
                indication = null,
                onClick = onDismissSheet
            ),
        contentAlignment = Alignment.BottomCenter
    ) {
        Card(
            shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface
            ),
            modifier = Modifier
                .fillMaxWidth()
                .clickable(
                    interactionSource = sheetInteraction,
                    indication = null,
                    onClick = {}
                )
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.tile_assistant_label),
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.primary
                    )
                    TextButton(onClick = onDismissSheet) {
                        Text(text = stringResource(R.string.action_cancel))
                    }
                }

                if (rejectedReasonCode != null) {
                    Surface(
                        color = MaterialTheme.colorScheme.errorContainer,
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = stringResource(R.string.error_security_violation),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            modifier = Modifier.padding(12.dp)
                        )
                    }
                }

                val activeConfirmation = state.activeConfirmation
                if (activeConfirmation != null) {
                    ActionConfirmationCard(
                        item = activeConfirmation,
                        messageRenderer = appContainer.messageRenderer,
                        bidiFormatter = appContainer.bidiTextFormatter,
                        locale = locale,
                        onApprove = { reqId ->
                            hubViewModel.onApproveConfirmation(
                                requestId = reqId,
                                activity = activity,
                                biometricLabels = biometricLabels
                            )
                        },
                        onEditSlot = { reqId, slotName, newVal ->
                            hubViewModel.onEditConfirmationSlot(reqId, slotName, newVal)
                        },
                        onCancel = { reqId ->
                            hubViewModel.onCancelConfirmation(reqId)
                        }
                    )
                } else if (openMode != AssistantOpenMode.CONFIRMATION) {
                    when (state.voiceState) {
                        is VoiceInputState.OfflinePackMissing -> {
                            Surface(
                                color = MaterialTheme.colorScheme.errorContainer,
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(12.dp)) {
                                    Text(
                                        text = stringResource(R.string.voice_pack_missing_warning),
                                        style = MaterialTheme.typography.labelLarge,
                                        color = MaterialTheme.colorScheme.error
                                    )
                                    Text(
                                        text = stringResource(R.string.voice_offline_pack_missing_desc),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onErrorContainer
                                    )
                                }
                            }
                        }

                        is VoiceInputState.Listening,
                        is VoiceInputState.PartialTranscript -> {
                            Text(
                                text = stringResource(R.string.voice_listening),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }

                        else -> Unit
                    }

                    state.statusMessage?.let { status ->
                        Text(
                            text = status,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        OutlinedTextField(
                            value = state.queryInput,
                            onValueChange = { hubViewModel.onQueryInputChanged(it) },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            placeholder = {
                                Text(text = stringResource(R.string.voice_idle))
                            }
                        )
                        OutlinedButton(
                            onClick = {
                                val hasMicPerm = ContextCompat.checkSelfPermission(
                                    context,
                                    Manifest.permission.RECORD_AUDIO
                                ) == PackageManager.PERMISSION_GRANTED
                                if (!hasMicPerm) {
                                    hubViewModel.onVoiceButtonClicked(hasRecordAudioPermission = false)
                                    recordAudioLauncher.launch(Manifest.permission.RECORD_AUDIO)
                                } else {
                                    hubViewModel.onVoiceButtonClicked(hasRecordAudioPermission = true)
                                }
                            }
                        ) {
                            Text(text = stringResource(R.string.voice_title))
                        }
                        Button(
                            onClick = { hubViewModel.submitQuery() },
                            enabled = state.queryInput.isNotBlank() && !state.isProcessing
                        ) {
                            Text(text = stringResource(R.string.onboarding_button_continue))
                        }
                    }
                }
            }
        }
    }
}

package com.nava.app.assistant

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
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
import com.nava.app.ui.components.NavaIcons
import com.nava.app.ui.confirmation.ActionConfirmationCard
import com.nava.app.ui.hub.NavaHubViewModel
import com.nava.app.ui.navigation.NavaViewModelFactory
import com.nava.app.ui.theme.NavaTheme
import com.nava.app.ui.theme.NavaThemeExtras
import com.nava.app.ui.theme.NavaThemeMode
import com.nava.app.voice.VoiceInputState
import java.util.Locale
import kotlinx.coroutines.launch
import androidx.lifecycle.compose.collectAsStateWithLifecycle

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
            val activeLocaleTag by appContainer.appLocaleManager.activeLocaleTagFlow.collectAsStateWithLifecycle()
            val activeLocale = remember(activeLocaleTag) {
                Locale.forLanguageTag(activeLocaleTag)
            }
            val themeMode by appContainer.themePreferenceStore.themeModeFlow.collectAsStateWithLifecycle()
            val darkOverride = when (themeMode) {
                NavaThemeMode.DARK -> true
                NavaThemeMode.LIGHT -> false
                NavaThemeMode.SYSTEM -> null
            }

            DisposableEffect(appContainer) {
                onDispose {
                    appContainer.voiceInputController.cancel()
                }
            }

            NavaTheme(
                isDarkThemeOverride = darkOverride,
                activeLocale = activeLocale
            ) {
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
    val state by hubViewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val colors = NavaThemeExtras.colors
    val bidiFormatter = appContainer.bidiTextFormatter
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
    val isListening = state.voiceState is VoiceInputState.Listening ||
        state.voiceState is VoiceInputState.PartialTranscript
    val canSend = state.queryInput.isNotBlank() && !state.isProcessing

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.50f))
            .clickable(
                interactionSource = scrimInteraction,
                indication = null,
                onClick = onDismissSheet
            ),
        contentAlignment = Alignment.BottomCenter
    ) {
        Surface(
            shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
            color = colors.surfaceCard,
            contentColor = colors.inkPrimary,
            border = BorderStroke(1.dp, colors.borderStone),
            modifier = Modifier
                .fillMaxWidth()
                .imePadding()
                .clickable(
                    interactionSource = sheetInteraction,
                    indication = null,
                    onClick = {}
                )
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp, vertical = 14.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Drag handle
                Box(
                    modifier = Modifier.fillMaxWidth(),
                    contentAlignment = Alignment.Center
                ) {
                    Box(
                        modifier = Modifier
                            .width(36.dp)
                            .height(4.dp)
                            .background(colors.borderStone, RoundedCornerShape(999.dp))
                    )
                }

                // Header row
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = NavaIcons.HubRing,
                            contentDescription = null,
                            tint = colors.trustNavyTint,
                            modifier = Modifier.size(20.dp)
                        )
                        Text(
                            text = stringResource(R.string.tile_assistant_label),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.SemiBold,
                            color = colors.inkPrimary
                        )
                    }
                    TextButton(onClick = onDismissSheet) {
                        Text(
                            text = stringResource(R.string.action_cancel),
                            color = colors.inkSecondary
                        )
                    }
                }

                HorizontalDivider(
                    thickness = 1.dp,
                    color = colors.borderStone
                )

                if (rejectedReasonCode != null) {
                    Surface(
                        color = colors.alertCrimsonSurface,
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, colors.borderStone),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = stringResource(R.string.error_security_violation),
                            style = MaterialTheme.typography.bodyMedium,
                            color = colors.alertCrimson,
                            modifier = Modifier.padding(12.dp)
                        )
                    }
                }

                val activeConfirmation = state.activeConfirmation
                if (activeConfirmation != null) {
                    ActionConfirmationCard(
                        item = activeConfirmation,
                        messageRenderer = appContainer.messageRenderer,
                        bidiFormatter = bidiFormatter,
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
                                color = colors.alertCrimsonSurface,
                                shape = RoundedCornerShape(10.dp),
                                border = BorderStroke(1.dp, colors.borderStone),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    Text(
                                        text = stringResource(R.string.voice_pack_missing_warning),
                                        style = MaterialTheme.typography.labelLarge,
                                        color = colors.alertCrimson
                                    )
                                    Text(
                                        text = stringResource(R.string.voice_offline_pack_missing_desc),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = colors.inkPrimary
                                    )
                                }
                            }
                        }

                        is VoiceInputState.Listening,
                        is VoiceInputState.PartialTranscript -> {
                            Surface(
                                color = colors.bgLinen,
                                shape = RoundedCornerShape(10.dp),
                                border = BorderStroke(1.dp, colors.borderStone),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(
                                    text = stringResource(R.string.voice_listening),
                                    style = MaterialTheme.typography.labelMedium,
                                    color = colors.trustNavyTint,
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)
                                )
                            }
                        }

                        else -> Unit
                    }

                    val displayMessage = state.statusMessage?.takeIf { it.isNotBlank() }
                        ?: state.conversationalReply?.takeIf { it.isNotBlank() }
                    if (displayMessage != null) {
                        Surface(
                            color = colors.bgLinen,
                            shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(1.dp, colors.borderStone),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = bidiFormatter.wrapText(displayMessage, locale),
                                style = MaterialTheme.typography.bodyMedium,
                                color = colors.inkPrimary,
                                modifier = Modifier.padding(12.dp)
                            )
                        }
                    }

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(
                            modifier = Modifier
                                .weight(1f)
                                .background(colors.bgLinen, RoundedCornerShape(22.dp))
                                .border(1.dp, colors.borderStone, RoundedCornerShape(22.dp))
                                .padding(start = 14.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            BasicTextField(
                                value = state.queryInput,
                                onValueChange = { hubViewModel.onQueryInputChanged(it) },
                                modifier = Modifier
                                    .weight(1f)
                                    .padding(vertical = 8.dp),
                                singleLine = true,
                                textStyle = MaterialTheme.typography.bodyMedium.copy(
                                    color = colors.inkPrimary
                                ),
                                cursorBrush = SolidColor(colors.trustNavyTint),
                                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                                keyboardActions = KeyboardActions(
                                    onSend = {
                                        if (canSend) {
                                            hubViewModel.submitQuery()
                                        }
                                    }
                                ),
                                decorationBox = { innerTextField ->
                                    Box(contentAlignment = Alignment.CenterStart) {
                                        if (state.queryInput.isEmpty()) {
                                            Text(
                                                text = stringResource(R.string.hub_command_placeholder),
                                                style = MaterialTheme.typography.bodyMedium,
                                                color = colors.inkMuted,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                        }
                                        innerTextField()
                                    }
                                }
                            )

                            Surface(
                                onClick = {
                                    if (canSend) {
                                        hubViewModel.submitQuery()
                                    }
                                },
                                enabled = canSend,
                                shape = CircleShape,
                                color = if (canSend) colors.trustNavy else colors.surfaceCard,
                                border = if (canSend) null else BorderStroke(1.dp, colors.borderStone),
                                modifier = Modifier.size(34.dp)
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    Icon(
                                        imageVector = NavaIcons.Send,
                                        contentDescription = stringResource(R.string.hub_send_command),
                                        tint = if (canSend) Color.White else colors.inkMuted,
                                        modifier = Modifier.size(16.dp)
                                    )
                                }
                            }
                        }

                        Surface(
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
                            },
                            shape = CircleShape,
                            color = if (isListening) colors.untrustedAccent else colors.trustNavy,
                            modifier = Modifier.size(40.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Icon(
                                    imageVector = if (isListening) {
                                        NavaIcons.Close
                                    } else {
                                        NavaIcons.VoiceSpectrum
                                    },
                                    contentDescription = if (isListening) {
                                        stringResource(R.string.hub_voice_stop)
                                    } else {
                                        stringResource(R.string.voice_title)
                                    },
                                    tint = Color.White,
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

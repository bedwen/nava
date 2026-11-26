package com.nava.app.ui.hub

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.nava.app.R
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.locale.NavaMessageRenderer
import com.nava.app.security.BiometricPromptLabels
import com.nava.app.ui.canvas.DualCoreNeuralCanvas
import com.nava.app.ui.components.NavaIcons
import com.nava.app.ui.confirmation.ActionConfirmationBottomSheet
import com.nava.app.ui.theme.NavaColors
import com.nava.app.ui.theme.NavaExtendedColors
import com.nava.app.ui.theme.NavaThemeExtras
import com.nava.app.voice.VoiceInputState
import com.nava.domain.ai.ThermalState
import com.nava.domain.ui.CoreActivityState
import com.nava.domain.ui.NeuronNodeId
import java.util.Locale
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * Dual-Core Neural Hub screen organized into three vertical zones:
 * 1. Radial Neural Stage hosting the 0-FPS [DualCoreNeuralCanvas] and optional status HUD.
 * 2. Scrollable Result Dock displaying active alerts, [ActionConfirmationCard], replies,
 *    tapped-neuron inspection details, or a calm empty-state card.
 * 3. Bottom Command Dock with quick suggestion chips, offline text input, and voice trigger.
 */
@Composable
fun NavaHubScreen(
    viewModel: NavaHubViewModel,
    messageRenderer: NavaMessageRenderer,
    bidiFormatter: BidiTextFormatter,
    activity: FragmentActivity?,
    onOpenProfileForTarget: (targetId: String, neuron: NeuronNodeId) -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier,
    showHud: Boolean = false
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val colors = NavaThemeExtras.colors
    val isDarkTheme = colors.bgPaper == NavaColors.BgPaperDark
    val activeLocale = remember(state.activeLocaleTag) {
        Locale.forLanguageTag(state.activeLocaleTag)
    }

    val recordAudioLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        viewModel.onRecordAudioPermissionResult(granted)
    }

    val neuronLabels = mapOf(
        NeuronNodeId.CLOCK to stringResource(R.string.canvas_neuron_clock),
        NeuronNodeId.CALENDAR to stringResource(R.string.canvas_neuron_calendar),
        NeuronNodeId.NOTES to stringResource(R.string.canvas_neuron_notes),
        NeuronNodeId.MESSAGES to stringResource(R.string.canvas_neuron_messages),
        NeuronNodeId.VAULT to stringResource(R.string.canvas_neuron_vault),
        NeuronNodeId.FILES to stringResource(R.string.canvas_neuron_files),
        NeuronNodeId.AUDIO_DND to stringResource(R.string.canvas_neuron_audio_dnd),
        NeuronNodeId.ROUTINES to stringResource(R.string.canvas_neuron_routines)
    )

    val biometricLabels = BiometricPromptLabels(
        title = stringResource(R.string.confirm_biometric_title),
        subtitle = stringResource(R.string.confirm_biometric_prompt_text),
        negativeButtonText = stringResource(R.string.confirm_button_cancel)
    )

    val activeLayerLabel = when (state.canvasState.coreState) {
        CoreActivityState.INNER_CORE_ACTIVE -> stringResource(R.string.hub_hud_gemma)
        CoreActivityState.OUTER_SHELL_ACTIVE,
        CoreActivityState.EXECUTING_TOOL -> stringResource(R.string.hub_hud_direct)
        else -> null
    }

    val statusSignature = remember(state.statusTitle, state.statusMessage, state.conversationalReply) {
        Triple(state.statusTitle, state.statusMessage, state.conversationalReply)
    }
    var clearedStatusSignature by remember {
        mutableStateOf<Triple<String?, String?, String?>?>(null)
    }
    LaunchedEffect(state.isProcessing) {
        if (state.isProcessing) {
            clearedStatusSignature = null
        }
    }

    val systemPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { _ ->
        viewModel.onSystemPermissionRequestHandled()
    }

    LaunchedEffect(state.pendingSystemPermissionRequest) {
        val perm = state.pendingSystemPermissionRequest
        if (!perm.isNullOrBlank()) {
            systemPermissionLauncher.launch(perm)
        }
    }

    LaunchedEffect(Unit) {
        viewModel.refreshPermittedNeurons()
    }

    val activeHistory = state.activeHistory
    val hasRawStatusOrReply = !state.statusMessage.isNullOrBlank() || !state.conversationalReply.isNullOrBlank()
    val showStatusCard = hasRawStatusOrReply && clearedStatusSignature != statusSignature
    val hasHistoryOrStatus = activeHistory.isNotEmpty() || showStatusCard
    val commandFocusRequester = remember { FocusRequester() }
    val focusManager = LocalFocusManager.current
    val haptics = LocalHapticFeedback.current
    val keyboardController = LocalSoftwareKeyboardController.current

    val density = LocalDensity.current
    val isImeVisible = WindowInsets.ime.getBottom(density) > 0

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.bgPaper)
            .imePadding()
    ) {
        // Mode Switcher: Work (hybrid router + tools + FunctionGemma/Embedding) vs Chat (direct Gemma 4 E2B)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp)
                .background(colors.bgLinen, RoundedCornerShape(12.dp))
                .padding(3.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            listOf(
                HubWorkMode.WORK to stringResource(R.string.hub_mode_work),
                HubWorkMode.CHAT to stringResource(R.string.hub_mode_chat)
            ).forEach { (mode, label) ->
                val isSelected = state.workMode == mode
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .background(
                            color = if (isSelected) colors.surfaceCard else Color.Transparent,
                            shape = RoundedCornerShape(9.dp)
                        )
                        .clickable {
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            viewModel.setWorkMode(mode)
                        }
                        .padding(vertical = 8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = label,
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Medium,
                        color = if (isSelected) colors.trustNavy else colors.inkSecondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }

        if (state.workMode == HubWorkMode.CHAT) {
            Text(
                text = stringResource(R.string.hub_chat_mode_hint),
                style = MaterialTheme.typography.labelSmall,
                color = colors.inkMuted,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 2.dp)
            )
        }

        // Zone 1: Dynamic Neural Stage - full canvas when idle; collapses into a compact live
        // status strip once conversation starts so ~80% of the viewport belongs to rich result cards.
        var isNeuralExpanded by remember { mutableStateOf(false) }
        LaunchedEffect(activeHistory.isEmpty()) {
            if (activeHistory.isEmpty()) {
                isNeuralExpanded = false
            }
        }

        if (!isImeVisible && state.workMode == HubWorkMode.WORK) {
            if (activeHistory.isEmpty() || isNeuralExpanded) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(if (activeHistory.isEmpty()) 252.dp else 216.dp),
                    contentAlignment = Alignment.Center
                ) {
                    DualCoreNeuralCanvas(
                        state = state.canvasState,
                        neuronLabels = neuronLabels,
                        onNeuronTapped = { nodeId ->
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            viewModel.onNeuronTapped(nodeId)
                        },
                        onPulseCompleted = { viewModel.onPulseCompleted(it) },
                        visibleNodes = HUB_REFERENCE_NODES,
                        permittedNodes = state.permittedNeurons,
                        isDarkTheme = isDarkTheme,
                        showHud = showHud,
                        activeLayerLabel = activeLayerLabel,
                        emptyStateHint = stringResource(R.string.hub_canvas_empty_hint),
                        modifier = Modifier.fillMaxSize()
                    )
                    if (activeHistory.isNotEmpty()) {
                        Surface(
                            onClick = {
                                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                isNeuralExpanded = false
                            },
                            color = colors.bgLinen,
                            shape = RoundedCornerShape(999.dp),
                            border = BorderStroke(1.dp, colors.borderStone),
                            modifier = Modifier
                                .align(Alignment.TopEnd)
                                .padding(horizontal = 16.dp, vertical = 4.dp)
                        ) {
                            Text(
                                text = stringResource(R.string.hub_neural_collapse),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.SemiBold,
                                color = colors.inkSecondary,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                            )
                        }
                    }
                }
            } else {
                // Compact live neural strip when conversation is active
                Surface(
                    onClick = {
                        haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        isNeuralExpanded = true
                    },
                    color = colors.surfaceCard,
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, colors.borderStone),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 2.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(8.dp)
                                    .background(
                                        color = if (state.isProcessing) {
                                            colors.verifiedForest
                                        } else {
                                            colors.trustNavyTint
                                        },
                                        shape = CircleShape
                                    )
                            )
                            Text(
                                text = activeLayerLabel
                                    ?: stringResource(R.string.hub_neural_compact_ready),
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Medium,
                                color = colors.inkPrimary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        Text(
                            text = stringResource(R.string.hub_neural_expand),
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = colors.trustNavyTint
                        )
                    }
                }
            }
        }

        // Zone 2: Scrollable Result Dock (chronological top-to-bottom chat flow)
        val dockScrollState = rememberScrollState()
        val lastHistoryItem = activeHistory.lastOrNull()
        LaunchedEffect(
            state.workMode,
            activeHistory.size,
            state.isProcessing,
            lastHistoryItem?.body,
            lastHistoryItem?.conversationalReply
        ) {
            if (activeHistory.isNotEmpty()) {
                if (state.isProcessing) {
                    dockScrollState.scrollTo(dockScrollState.maxValue)
                } else {
                    dockScrollState.animateScrollTo(dockScrollState.maxValue)
                }
            }
        }
        Column(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .verticalScroll(dockScrollState)
                .animateContentSize(animationSpec = tween(durationMillis = 200))
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            HubAlertBanners(
                state = state,
                colors = colors,
                bidiFormatter = bidiFormatter,
                activeLocale = activeLocale,
                onOpenSettings = onOpenSettings,
                onDismissMicRationale = { viewModel.dismissMicPermissionRationale() }
            )

            // Result Dock header row (shown only when actions/replies exist)
            if (hasHistoryOrStatus) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = if (state.workMode == HubWorkMode.CHAT) {
                            stringResource(R.string.hub_mode_chat).uppercase(activeLocale)
                        } else {
                            stringResource(R.string.hub_local_actions_header)
                        },
                        style = MaterialTheme.typography.labelSmall.copy(letterSpacing = 0.8.sp),
                        color = colors.inkMuted
                    )
                    TextButton(
                        onClick = {
                            viewModel.onDismissNeuronInspection()
                            viewModel.onQueryInputChanged("")
                            viewModel.clearActionHistory()
                            clearedStatusSignature = statusSignature
                        },
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = stringResource(R.string.hub_clear_actions),
                            style = MaterialTheme.typography.labelMedium,
                            color = colors.trustNavyTint
                        )
                    }
                }
            }

            // Local Action History / Chat Dock
            if (activeHistory.isNotEmpty()) {
                for (entry in activeHistory) {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.End
                        ) {
                            Surface(
                                color = colors.trustNavy,
                                shape = RoundedCornerShape(
                                    topStart = 14.dp,
                                    topEnd = 14.dp,
                                    bottomStart = 14.dp,
                                    bottomEnd = 4.dp
                                )
                            ) {
                                Text(
                                    text = bidiFormatter.wrapText(entry.userQuery, activeLocale),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color.White,
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp)
                                )
                            }
                        }

                        if (!entry.body.isNullOrBlank() || !entry.conversationalReply.isNullOrBlank()) {
                            val cardKind = inferLocalActionCardKind(
                                lastMessageKey = entry.messageKey,
                                statusTitle = entry.title,
                                statusMessage = entry.body
                            )
                            val isEntryError = entry.isError ||
                                (entry.messageKey?.name?.startsWith("ERROR_") == true)
                            val isPermissionDenied = entry.messageKey == com.nava.domain.ui.MessageKey.ERROR_PERMISSION_DENIED
                            val deniedTarget = entry.deniedTargetId
                            val deniedCapability = entry.deniedCapability
                            if (isPermissionDenied && deniedTarget != null && deniedCapability != null) {
                                PermissionGrantCard(
                                    targetId = deniedTarget,
                                    capability = deniedCapability,
                                    grantOffered = entry.permissionGrantOffered && !state.isProcessing,
                                    bidiFormatter = bidiFormatter,
                                    activeLocale = activeLocale,
                                    onGrant = { level -> viewModel.grantPermissionAndRetry(entry.id, level) },
                                    onOpenSettings = {
                                        onOpenProfileForTarget(
                                            deniedTarget,
                                            entry.deniedNeuron ?: NeuronNodeId.CLOCK
                                        )
                                    }
                                )
                            } else LocalActionResultCard(
                                kind = cardKind,
                                title = entry.title,
                                body = entry.body,
                                conversationalReply = entry.conversationalReply,
                                bidiFormatter = bidiFormatter,
                                activeLocale = activeLocale,
                                isError = isEntryError,
                                onGrantPermission = if (isPermissionDenied) {
                                    {
                                        onOpenProfileForTarget(
                                            entry.deniedTargetId
                                                ?: com.nava.feature.automations.common.ToolTargetIds.CLOCK,
                                            entry.deniedNeuron ?: NeuronNodeId.CLOCK
                                        )
                                    }
                                } else {
                                    null
                                },
                                onUndoOrClear = {
                                    haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    viewModel.undoAction(entry.id)
                                    clearedStatusSignature = statusSignature
                                }
                            )
                        } else if (state.isProcessing && entry.id == lastHistoryItem?.id) {
                            NavaTypingIndicatorCard(isModelWarmingUp = state.isModelWarmingUp)
                        }
                    }
                }
            } else if (showStatusCard) {
                val cardKind = inferLocalActionCardKind(
                    lastMessageKey = state.lastUserMessage?.key,
                    statusTitle = state.statusTitle,
                    statusMessage = state.statusMessage
                )
                LocalActionResultCard(
                    kind = cardKind,
                    title = state.statusTitle,
                    body = state.statusMessage,
                    conversationalReply = state.conversationalReply,
                    bidiFormatter = bidiFormatter,
                    activeLocale = activeLocale,
                    onUndoOrClear = {
                        viewModel.onQueryInputChanged("")
                        clearedStatusSignature = statusSignature
                    }
                )
            } else {
                // Editorial borderless time-aware greeting directly on warm paper
                val hourOfDay = remember {
                    java.util.Calendar.getInstance().get(java.util.Calendar.HOUR_OF_DAY)
                }
                val greetingResId = when (hourOfDay) {
                    in 5..11 -> R.string.hub_greeting_morning
                    in 12..17 -> R.string.hub_greeting_afternoon
                    else -> R.string.hub_greeting_evening
                }
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp, vertical = 14.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = stringResource(greetingResId),
                        style = MaterialTheme.typography.headlineSmall.copy(
                            fontFamily = FontFamily.Serif,
                            fontWeight = FontWeight.Normal,
                            fontSize = 26.sp,
                            letterSpacing = (-0.4).sp
                        ),
                        textAlign = TextAlign.Center,
                        color = colors.inkPrimary
                    )
                    Text(
                        text = stringResource(R.string.hub_empty_greeting_subtitle),
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontSize = 13.sp,
                            lineHeight = 20.sp,
                            letterSpacing = 0.1.sp
                        ),
                        textAlign = TextAlign.Center,
                        color = colors.inkMuted
                    )
                }
            }
        }

        if (state.showStructureVoiceNoteAction && !state.isProcessing) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.Center
            ) {
                Surface(
                    onClick = {
                        haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        viewModel.structureCurrentInputAsNote()
                    },
                    shape = RoundedCornerShape(20.dp),
                    color = colors.surfaceCard,
                    border = BorderStroke(1.dp, colors.trustNavy)
                ) {
                    Text(
                        text = stringResource(R.string.hub_structure_voice_note_cta),
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = colors.trustNavy,
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp)
                    )
                }
            }
        }

        // Zone 3: Bottom Command Dock (seamless floating on Warm Paper)
        HubCommandDock(
            queryInput = state.queryInput,
            isProcessing = state.isProcessing,
            activeLocaleTag = state.activeLocaleTag,
            activeLocale = activeLocale,
            voiceState = state.voiceState,
            colors = colors,
            bidiFormatter = bidiFormatter,
            commandFocusRequester = commandFocusRequester,
            inputHint = if (state.workMode == HubWorkMode.CHAT) {
                stringResource(R.string.hub_input_hint_chat)
            } else {
                stringResource(R.string.hub_input_hint_work)
            },
            onCommandFieldFocused = { viewModel.onCommandFieldFocused() },
            onQueryInputChanged = { viewModel.onQueryInputChanged(it) },
            onSubmitQuery = {
                clearedStatusSignature = null
                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                focusManager.clearFocus()
                keyboardController?.hide()
                viewModel.submitQuery()
            },
            onChipClicked = { chipText ->
                clearedStatusSignature = null
                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                focusManager.clearFocus()
                keyboardController?.hide()
                viewModel.submitQuery(chipText)
            },
            onVoiceButtonClicked = {
                val hasMicPerm = ContextCompat.checkSelfPermission(
                    context,
                    Manifest.permission.RECORD_AUDIO
                ) == PackageManager.PERMISSION_GRANTED
                if (!hasMicPerm) {
                    viewModel.onVoiceButtonClicked(hasRecordAudioPermission = false)
                    recordAudioLauncher.launch(Manifest.permission.RECORD_AUDIO)
                } else {
                    viewModel.onVoiceButtonClicked(hasRecordAudioPermission = true)
                }
            }
        )
    }

    // Modal Bottom Sheet: Action Confirmation
    val activeConfirmation = state.activeConfirmation
    if (activeConfirmation != null) {
        ActionConfirmationBottomSheet(
            item = activeConfirmation,
            messageRenderer = messageRenderer,
            bidiFormatter = bidiFormatter,
            locale = activeLocale,
            onApprove = { reqId ->
                viewModel.onApproveConfirmation(
                    requestId = reqId,
                    activity = activity,
                    biometricLabels = biometricLabels
                )
            },
            onEditSlot = { reqId, slotName, newValue ->
                viewModel.onEditConfirmationSlot(reqId, slotName, newValue)
            },
            onCancel = { reqId ->
                viewModel.onCancelConfirmation(reqId)
            }
        )
    }

    // Modal Bottom Sheet: Tapped Neuron Context
    val inspected = state.inspectedNeuron
    if (inspected != null) {
        NodeContextBottomSheet(
            inspected = inspected,
            nodeLabel = neuronLabels[inspected.nodeId] ?: inspected.nodeId.name,
            bidiFormatter = bidiFormatter,
            activeLocale = activeLocale,
            onRunTask = {
                viewModel.onDismissNeuronInspection()
                runCatching { commandFocusRequester.requestFocus() }
            },
            onOpenPermissions = { targetId, neuron ->
                onOpenProfileForTarget(targetId, neuron)
            },
            onDismiss = { viewModel.onDismissNeuronInspection() }
        )
    }
}

@Composable
private fun HubAlertBanners(
    state: NavaHubUiState,
    colors: NavaExtendedColors,
    bidiFormatter: BidiTextFormatter,
    activeLocale: Locale,
    onOpenSettings: () -> Unit,
    onDismissMicRationale: () -> Unit
) {
    if (state.canvasState.thermalState != ThermalState.NORMAL) {
        Surface(
            color = colors.alertCrimsonSurface,
            shape = RoundedCornerShape(10.dp),
            border = BorderStroke(1.dp, colors.borderStone),
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = stringResource(R.string.hub_thermal_throttled),
                style = MaterialTheme.typography.labelMedium,
                color = colors.alertCrimson,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
            )
        }
    }

    if (state.qualitySuggestion != null) {
        Surface(
            color = colors.surfaceCard,
            shape = RoundedCornerShape(10.dp),
            border = BorderStroke(1.dp, colors.borderStone),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.hub_e2b_to_e4b_quality_banner),
                    style = MaterialTheme.typography.bodySmall,
                    color = colors.inkPrimary,
                    modifier = Modifier.weight(1f)
                )
                TextButton(onClick = onOpenSettings) {
                    Text(
                        text = stringResource(R.string.nav_settings),
                        color = colors.trustNavyTint
                    )
                }
            }
        }
    }

    when (val voice = state.voiceState) {
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
                    Text(
                        text = bidiFormatter.wrapLtrToken(voice.localeTag, activeLocale),
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace,
                        color = colors.inkSecondary
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

        is VoiceInputState.Error -> {
            Surface(
                color = colors.alertCrimsonSurface,
                shape = RoundedCornerShape(10.dp),
                border = BorderStroke(1.dp, colors.borderStone),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = bidiFormatter.wrapText(voice.message, activeLocale),
                    style = MaterialTheme.typography.bodySmall,
                    color = colors.alertCrimson,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }

        else -> Unit
    }

    if (state.showMicPermissionRationale) {
        Surface(
            color = colors.alertCrimsonSurface,
            shape = RoundedCornerShape(10.dp),
            border = BorderStroke(1.dp, colors.borderStone),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.voice_mic_permission_missing),
                    style = MaterialTheme.typography.bodySmall,
                    color = colors.alertCrimson,
                    modifier = Modifier.weight(1f)
                )
                TextButton(onClick = onDismissMicRationale) {
                    Text(
                        text = stringResource(R.string.action_cancel),
                        color = colors.alertCrimson
                    )
                }
            }
        }
    }
}

@Composable
private fun HubCommandDock(
    queryInput: String,
    isProcessing: Boolean,
    activeLocaleTag: String,
    activeLocale: Locale,
    voiceState: VoiceInputState,
    colors: NavaExtendedColors,
    bidiFormatter: BidiTextFormatter,
    commandFocusRequester: FocusRequester,
    inputHint: String,
    onCommandFieldFocused: () -> Unit,
    onQueryInputChanged: (String) -> Unit,
    onSubmitQuery: () -> Unit,
    onChipClicked: (String) -> Unit,
    onVoiceButtonClicked: () -> Unit
) {
    val isListening = voiceState is VoiceInputState.Listening ||
        voiceState is VoiceInputState.PartialTranscript
    val canSend = queryInput.isNotBlank() && !isProcessing

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(colors.bgPaper)
            .padding(horizontal = 12.dp, vertical = 10.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                modifier = Modifier
                    .weight(1f)
                    .background(colors.surfaceCard, RoundedCornerShape(24.dp))
                    .border(1.dp, colors.borderStone, RoundedCornerShape(24.dp))
                    .padding(start = 14.dp, end = 4.dp, top = 2.dp, bottom = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = bidiFormatter.wrapLtrToken(
                        activeLocaleTag.uppercase(Locale.ROOT),
                        activeLocale
                    ),
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = colors.inkMuted,
                    modifier = Modifier.padding(end = 2.dp)
                )

                BasicTextField(
                    value = queryInput,
                    onValueChange = onQueryInputChanged,
                    modifier = Modifier
                        .weight(1f)
                        .focusRequester(commandFocusRequester)
                        .onFocusChanged { focusState ->
                            if (focusState.isFocused) onCommandFieldFocused()
                        }
                        .padding(vertical = 8.dp),
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(color = colors.inkPrimary),
                    cursorBrush = SolidColor(colors.trustNavyTint),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                    keyboardActions = KeyboardActions(
                        onSend = {
                            if (canSend) {
                                onSubmitQuery()
                            }
                        }
                    ),
                    decorationBox = { innerTextField ->
                        Box(contentAlignment = Alignment.CenterStart) {
                            if (queryInput.isEmpty()) {
                                Text(
                                    text = inputHint,
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

                IconButton(
                    onClick = onVoiceButtonClicked,
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        imageVector = if (isListening) NavaIcons.Close else NavaIcons.VoiceSpectrum,
                        contentDescription = if (isListening) {
                            stringResource(R.string.hub_voice_stop)
                        } else {
                            stringResource(R.string.voice_title)
                        },
                        tint = if (isListening) colors.untrustedAccent else colors.inkSecondary,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            Surface(
                onClick = onSubmitQuery,
                enabled = canSend,
                shape = CircleShape,
                color = colors.trustNavy,
                modifier = Modifier.size(44.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = NavaIcons.Send,
                        contentDescription = stringResource(R.string.hub_send_command),
                        tint = if (canSend) Color.White else Color.White.copy(alpha = 0.6f),
                        modifier = Modifier.size(19.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun NavaTypingIndicatorCard(isModelWarmingUp: Boolean) {
    val colors = NavaThemeExtras.colors
    val transition = rememberInfiniteTransition(label = "nava_typing_dots")
    val dotAlphas = List(3) { index ->
        transition.animateFloat(
            initialValue = 0.25f,
            targetValue = 1.0f,
            animationSpec = infiniteRepeatable(
                animation = tween(
                    durationMillis = 550,
                    delayMillis = index * 160,
                    easing = LinearEasing
                ),
                repeatMode = RepeatMode.Reverse
            ),
            label = "typing_dot_$index"
        )
    }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Start
    ) {
        Surface(
            color = colors.surfaceCard,
            shape = RoundedCornerShape(
                topStart = 14.dp,
                topEnd = 14.dp,
                bottomStart = 4.dp,
                bottomEnd = 14.dp
            )
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 11.dp),
                horizontalArrangement = Arrangement.spacedBy(5.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                for (alphaState in dotAlphas) {
                    Box(
                        modifier = Modifier
                            .size(6.dp)
                            .alpha(alphaState.value)
                            .background(colors.trustNavyTint, CircleShape)
                    )
                }
                if (isModelWarmingUp) {
                    Text(
                        text = stringResource(R.string.hub_model_warming_up),
                        style = MaterialTheme.typography.labelMedium,
                        color = colors.inkSecondary,
                        modifier = Modifier.padding(start = 6.dp)
                    )
                }
            }
        }
    }
}

private val HUB_REFERENCE_NODES: List<NeuronNodeId> = listOf(
    NeuronNodeId.AUDIO_DND,
    NeuronNodeId.NOTES,
    NeuronNodeId.CALENDAR,
    NeuronNodeId.FILES,
    NeuronNodeId.VAULT,
    NeuronNodeId.MESSAGES,
    NeuronNodeId.CLOCK
)

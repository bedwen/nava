package com.nava.app.ui.hub

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.nava.app.R
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.locale.NavaMessageRenderer
import com.nava.app.security.BiometricPromptLabels
import com.nava.app.ui.canvas.DualCoreNeuralCanvas
import com.nava.app.ui.confirmation.ActionConfirmationCard
import com.nava.app.voice.VoiceInputState
import com.nava.domain.ai.ThermalState
import com.nava.domain.ui.CoreActivityState
import com.nava.domain.ui.NeuronNodeId
import java.util.Locale

/**
 * Dual-Core Neural Hub screen hosting the 0-FPS [DualCoreNeuralCanvas], hardware/quality notices,
 * interactive [ActionConfirmationCard], offline voice button, and tapped-neuron security inspection.
 */
@Composable
fun NavaHubScreen(
    viewModel: NavaHubViewModel,
    messageRenderer: NavaMessageRenderer,
    bidiFormatter: BidiTextFormatter,
    activity: FragmentActivity?,
    onOpenProfileForTarget: (targetId: String, neuron: NeuronNodeId) -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    val context = LocalContext.current
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

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Header & status row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.hub_title),
                    style = MaterialTheme.typography.headlineMedium,
                    color = MaterialTheme.colorScheme.onBackground
                )
                Text(
                    text = stringResource(R.string.hub_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(
                    text = when (state.canvasState.coreState) {
                        CoreActivityState.IDLE -> stringResource(R.string.hub_status_idle)
                        CoreActivityState.OUTER_SHELL_ACTIVE -> stringResource(R.string.hub_status_outer_shell)
                        CoreActivityState.INNER_CORE_ACTIVE -> stringResource(R.string.hub_status_inner_core)
                        CoreActivityState.EXECUTING_TOOL,
                        CoreActivityState.ERROR_FLASH -> stringResource(R.string.hub_status_active)
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = when (state.canvasState.coreState) {
                        CoreActivityState.INNER_CORE_ACTIVE -> MaterialTheme.colorScheme.secondary
                        CoreActivityState.OUTER_SHELL_ACTIVE -> MaterialTheme.colorScheme.primary
                        else -> MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                )
            }
        }

        // Thermal indicator
        Text(
            text = if (state.canvasState.thermalState == ThermalState.NORMAL) {
                stringResource(R.string.hub_thermal_nominal)
            } else {
                stringResource(R.string.hub_thermal_throttled)
            },
            style = MaterialTheme.typography.labelSmall,
            color = if (state.canvasState.thermalState == ThermalState.NORMAL) {
                MaterialTheme.colorScheme.onSurfaceVariant
            } else {
                MaterialTheme.colorScheme.error
            }
        )

        // Tier 0 low-memory notice
        if (state.showTier0LowMemoryNotice) {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = stringResource(R.string.hub_tier_0_low_memory_notice),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }

        // E2B -> E4B quality suggestion banner (PLAN.md Section 6.1)
        if (state.qualitySuggestion != null) {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.secondaryContainer
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.hub_e2b_to_e4b_quality_banner),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(onClick = onOpenSettings) {
                        Text(text = stringResource(R.string.nav_settings))
                    }
                }
            }
        }

        // 0-FPS Dual-Core Neural Canvas
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(310.dp),
            contentAlignment = Alignment.Center
        ) {
            DualCoreNeuralCanvas(
                state = state.canvasState,
                neuronLabels = neuronLabels,
                onNeuronTapped = { nodeId -> viewModel.onNeuronTapped(nodeId) },
                onPulseCompleted = { eventId -> viewModel.onPulseCompleted(eventId) },
                modifier = Modifier.fillMaxSize()
            )
        }

        // Active Action Confirmation Card
        val activeConfirmation = state.activeConfirmation
        if (activeConfirmation != null) {
            ActionConfirmationCard(
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

        // Offline voice pack missing or permission banner
        when (val voice = state.voiceState) {
            is VoiceInputState.OfflinePackMissing -> {
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(
                            text = stringResource(R.string.voice_pack_missing_warning),
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.error
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = stringResource(R.string.voice_offline_pack_missing_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                        Text(
                            text = bidiFormatter.wrapLtrToken(voice.localeTag, activeLocale),
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
            }

            is VoiceInputState.Listening,
            is VoiceInputState.PartialTranscript -> {
                Surface(
                    color = MaterialTheme.colorScheme.primaryContainer,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = stringResource(R.string.voice_listening),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.padding(10.dp)
                    )
                }
            }

            is VoiceInputState.Error -> {
                Surface(
                    color = MaterialTheme.colorScheme.errorContainer,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = voice.message,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.padding(10.dp)
                    )
                }
            }

            else -> Unit
        }

        if (state.showMicPermissionRationale) {
            Surface(
                color = MaterialTheme.colorScheme.errorContainer,
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(10.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.voice_mic_permission_missing),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(onClick = { viewModel.dismissMicPermissionRationale() }) {
                        Text(text = stringResource(R.string.action_cancel))
                    }
                }
            }
        }

        // Status / Conversational reply banner
        if (!state.statusMessage.isNullOrBlank() || !state.conversationalReply.isNullOrBlank()) {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    state.statusTitle?.let { title ->
                        Text(
                            text = title,
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                    state.statusMessage?.let { msg ->
                        Text(
                            text = msg,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    state.conversationalReply?.let { reply ->
                        Text(
                            text = bidiFormatter.wrapText(reply, activeLocale),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            }
        }

        // Command input bar + Offline Voice trigger
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = state.queryInput,
                onValueChange = { viewModel.onQueryInputChanged(it) },
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
                        viewModel.onVoiceButtonClicked(hasRecordAudioPermission = false)
                        recordAudioLauncher.launch(Manifest.permission.RECORD_AUDIO)
                    } else {
                        viewModel.onVoiceButtonClicked(hasRecordAudioPermission = true)
                    }
                }
            ) {
                Text(text = stringResource(R.string.voice_title))
            }
            Button(
                onClick = { viewModel.submitQuery() },
                enabled = state.queryInput.isNotBlank() && !state.isProcessing
            ) {
                Text(text = stringResource(R.string.onboarding_button_continue))
            }
        }

        // Inspected Neuron Card (PermissionProfile + recent AuditLogDao entries)
        val inspected = state.inspectedNeuron
        if (inspected != null) {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = neuronLabels[inspected.nodeId] ?: inspected.nodeId.name,
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                        TextButton(onClick = { viewModel.onDismissNeuronInspection() }) {
                            Text(text = stringResource(R.string.action_cancel))
                        }
                    }

                    Text(
                        text = stringResource(
                            R.string.confirm_target_label,
                            bidiFormatter.wrapLtrToken(inspected.primaryTargetId, activeLocale)
                        ),
                        style = MaterialTheme.typography.labelMedium,
                        fontFamily = FontFamily.Monospace
                    )

                    Text(
                        text = "${stringResource(R.string.nav_profile)}: ${inspected.profile.name}",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold
                    )

                    OutlinedButton(
                        onClick = {
                            onOpenProfileForTarget(inspected.primaryTargetId, inspected.nodeId)
                        }
                    ) {
                        Text(text = stringResource(R.string.profile_title))
                    }

                    Text(
                        text = stringResource(R.string.audit_title),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.secondary
                    )

                    if (inspected.recentAuditEntries.isEmpty()) {
                        Text(
                            text = stringResource(R.string.audit_empty),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        for (entry in inspected.recentAuditEntries) {
                            Surface(
                                color = MaterialTheme.colorScheme.surface,
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(8.dp)) {
                                    Text(
                                        text = stringResource(
                                            R.string.audit_entry_tool,
                                            bidiFormatter.wrapLtrToken(entry.toolName, activeLocale)
                                        ),
                                        style = MaterialTheme.typography.labelMedium,
                                        fontFamily = FontFamily.Monospace
                                    )
                                    Text(
                                        text = stringResource(
                                            R.string.audit_entry_decision,
                                            bidiFormatter.wrapLtrToken(entry.decision, activeLocale)
                                        ),
                                        style = MaterialTheme.typography.bodySmall
                                    )
                                    Text(
                                        text = stringResource(
                                            R.string.audit_entry_provenance,
                                            bidiFormatter.wrapLtrToken(entry.provenance.name, activeLocale)
                                        ),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

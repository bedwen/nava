package com.nava.app.ui.hub

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.BottomSheetDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.nava.app.R
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.ui.components.NavaIcons
import com.nava.app.ui.settings.SettingsViewModel
import com.nava.app.ui.theme.NavaThemeExtras
import com.nava.domain.security.DataProvenance
import com.nava.domain.ui.NeuronNodeId
import java.util.Locale

/**
 * Material 3 modal bottom sheet presenting context for a tapped radial neuron node on the
 * Dual-Core Neural Canvas: execution layer, active [com.nava.domain.security.PermissionProfile],
 * latest [com.nava.domain.security.AuditLogEntry] in human-readable form, and direct navigation
 * to run a task or edit permissions.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodeContextBottomSheet(
    inspected: InspectedNeuronDetails,
    nodeLabel: String,
    bidiFormatter: BidiTextFormatter,
    activeLocale: Locale,
    onRunTask: (NeuronNodeId) -> Unit,
    onOpenPermissions: (targetId: String, neuron: NeuronNodeId) -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = NavaThemeExtras.colors
    val haptics = LocalHapticFeedback.current
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val latestAudit = inspected.recentAuditEntries.firstOrNull()

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = colors.surfaceCard,
        contentColor = colors.inkPrimary,
        shape = RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp),
        dragHandle = {
            BottomSheetDefaults.DragHandle(color = colors.borderStone)
        },
        modifier = modifier
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp)
                .padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Header row: circular icon disc + node label + execution layer subtitle
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(14.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(42.dp)
                        .background(color = colors.bgLinen, shape = CircleShape)
                        .border(width = 1.dp, color = colors.borderStone, shape = CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = iconForNeuronNode(inspected.nodeId),
                        contentDescription = null,
                        tint = colors.trustNavyTint,
                        modifier = Modifier.size(20.dp)
                    )
                }

                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(2.dp)
                ) {
                    Text(
                        text = bidiFormatter.wrapText(nodeLabel, activeLocale),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = colors.inkPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = stringResource(executionLayerStringRes(inspected.nodeId)),
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.inkSecondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            HorizontalDivider(thickness = 0.5.dp, color = colors.borderStone)

            // Active policy + latest audit summary (flat, borderless editorial layout)
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.sheet_active_policy),
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.inkMuted
                    )
                    Text(
                        text = bidiFormatter.wrapText(inspected.profile.name, activeLocale),
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = colors.inkPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.sheet_last_audit),
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.inkMuted
                    )
                    if (latestAudit == null) {
                        Text(
                            text = stringResource(R.string.audit_empty),
                            style = MaterialTheme.typography.bodySmall,
                            color = colors.inkMuted
                        )
                    } else {
                        val isDenied = SettingsViewModel.isDeniedOrBlockedAuditDecision(
                            latestAudit.decision
                        )
                        val decisionLabel = stringResource(
                            if (isDenied) {
                                R.string.audit_status_blocked
                            } else {
                                R.string.audit_status_approved
                            }
                        )
                        val provenanceLabel = when (latestAudit.provenance) {
                            DataProvenance.USER_UTTERANCE ->
                                stringResource(R.string.audit_provenance_user)
                            DataProvenance.SYSTEM ->
                                stringResource(R.string.audit_provenance_system)
                            DataProvenance.UNTRUSTED_EXTERNAL ->
                                stringResource(R.string.audit_provenance_external)
                        }
                        Column(
                            horizontalAlignment = Alignment.End,
                            verticalArrangement = Arrangement.spacedBy(1.dp)
                        ) {
                            Text(
                                text = bidiFormatter.wrapLtrToken(
                                    latestAudit.toolName,
                                    activeLocale
                                ),
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Medium,
                                color = colors.inkPrimary
                            )
                            Text(
                                text = "$decisionLabel - $provenanceLabel",
                                style = MaterialTheme.typography.labelSmall,
                                color = if (isDenied) {
                                    colors.alertCrimson
                                } else {
                                    colors.verifiedForest
                                }
                            )
                        }
                    }
                }
            }

            // Bottom action buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedButton(
                    onClick = {
                        haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onOpenPermissions(inspected.primaryTargetId, inspected.nodeId)
                        onDismiss()
                    },
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, colors.borderStone),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = colors.inkPrimary
                    ),
                    modifier = Modifier
                        .weight(1f)
                        .height(44.dp)
                ) {
                    Text(
                        text = stringResource(R.string.nav_permissions),
                        color = colors.inkPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Button(
                    onClick = {
                        haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                        onRunTask(inspected.nodeId)
                        onDismiss()
                    },
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = colors.trustNavy,
                        contentColor = Color.White
                    ),
                    modifier = Modifier
                        .weight(1f)
                        .height(44.dp)
                ) {
                    Text(
                        text = stringResource(R.string.sheet_run_task),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}

private fun iconForNeuronNode(nodeId: NeuronNodeId): ImageVector = when (nodeId) {
    NeuronNodeId.AUDIO_DND -> NavaIcons.FocusMoon
    NeuronNodeId.NOTES -> NavaIcons.Notes
    NeuronNodeId.VAULT -> NavaIcons.Lock
    NeuronNodeId.CALENDAR -> NavaIcons.Calendar
    NeuronNodeId.FILES -> NavaIcons.Folder
    NeuronNodeId.MESSAGES -> NavaIcons.Messages
    NeuronNodeId.CLOCK -> NavaIcons.Clock
    NeuronNodeId.ROUTINES -> NavaIcons.HubRing
}

private fun executionLayerStringRes(nodeId: NeuronNodeId): Int = when (nodeId) {
    NeuronNodeId.CLOCK,
    NeuronNodeId.AUDIO_DND,
    NeuronNodeId.ROUTINES -> R.string.sheet_layer_direct
    NeuronNodeId.NOTES,
    NeuronNodeId.VAULT,
    NeuronNodeId.CALENDAR,
    NeuronNodeId.FILES,
    NeuronNodeId.MESSAGES -> R.string.sheet_layer_gemma
}

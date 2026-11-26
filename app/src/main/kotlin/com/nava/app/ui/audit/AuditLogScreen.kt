package com.nava.app.ui.audit

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.nava.app.R
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.ui.settings.AuditLogFilter
import com.nava.app.ui.settings.SettingsViewModel
import com.nava.app.ui.theme.NavaThemeExtras
import com.nava.domain.security.AuditLogEntry
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Presentation severity bucket for an [AuditLogEntry.decision].
 */
enum class AuditDecisionSeverity {
    VERIFIED,
    WARNING,
    DENIED
}

/**
 * Pure-JVM classifier mapping an [AuditLogEntry.decision] string to [AuditDecisionSeverity].
 *
 * Case-insensitive rules:
 * - `DENIED`, `BLOCKED`, `REJECTED`, `FAILED`, `ERROR` (and security violation markers) -> [AuditDecisionSeverity.DENIED]
 * - `CONFIRM`, `ESCALATED`, `PENDING`, `BIOMETRIC` -> [AuditDecisionSeverity.WARNING]
 * - Everything else -> [AuditDecisionSeverity.VERIFIED]
 */
fun classifyAuditDecision(decision: String): AuditDecisionSeverity {
    val upper = decision.trim().uppercase(Locale.US)
    if (upper.contains("DENIED") ||
        upper.contains("BLOCKED") ||
        upper.contains("REJECTED") ||
        upper.contains("FAILED") ||
        upper.contains("ERROR") ||
        upper.contains("VIOLATION") ||
        upper.contains("FORGED") ||
        upper.contains("MISMATCH") ||
        upper.contains("EXPIRED")
    ) {
        return AuditDecisionSeverity.DENIED
    }
    if (upper.contains("CONFIRM") ||
        upper.contains("ESCALATED") ||
        upper.contains("PENDING") ||
        upper.contains("BIOMETRIC")
    ) {
        return AuditDecisionSeverity.WARNING
    }
    return AuditDecisionSeverity.VERIFIED
}

/**
 * Dedicated tamper-evident append-only Security Audit Log screen in Warm Paper / Matte OLED Dark
 * grouped card styling. Intentionally omits any unauthenticated Clear/Delete control.
 */
@Composable
fun AuditLogScreen(
    viewModel: SettingsViewModel,
    bidiFormatter: BidiTextFormatter,
    activeLocale: Locale,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    val colors = NavaThemeExtras.colors
    val haptics = LocalHapticFeedback.current
    val displayEntries = remember(state.filteredAuditEntries) {
        coalesceAuditEntries(state.filteredAuditEntries)
    }

    LaunchedEffect(Unit) {
        viewModel.refreshAuditLogs()
    }

    Surface(
        color = colors.bgPaper,
        modifier = modifier.fillMaxSize()
    ) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(colors.bgPaper)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        // Single editorial header row matching reference design (no bulky pills or boxes)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 2.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = stringResource(R.string.audit_title).uppercase(activeLocale),
                style = MaterialTheme.typography.labelSmall.copy(letterSpacing = 0.8.sp),
                fontWeight = FontWeight.Medium,
                color = colors.inkMuted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier
                    .weight(1f)
                    .padding(end = 10.dp)
            )
            Row(
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.audit_entries_count, displayEntries.size),
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFeatureSettings = "tnum"
                    ),
                    fontFamily = FontFamily.Monospace,
                    color = colors.inkMuted
                )
                val isDeniedOnly = state.auditFilter == AuditLogFilter.DENIED_ONLY
                Text(
                    text = if (isDeniedOnly) {
                        stringResource(R.string.audit_filter_all)
                    } else {
                        stringResource(R.string.audit_filter_denied)
                    },
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = if (isDeniedOnly) FontWeight.SemiBold else FontWeight.Medium,
                    color = if (isDeniedOnly) colors.alertCrimson else colors.inkSecondary,
                    modifier = Modifier
                        .clickable {
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            viewModel.setAuditFilter(
                                if (isDeniedOnly) AuditLogFilter.ALL else AuditLogFilter.DENIED_ONLY
                            )
                        }
                        .padding(vertical = 2.dp)
                )
            }
        }

        // Grouped append-only audit log list with 0.5.dp hairline dividers
        Surface(
            color = colors.surfaceCard,
            shape = RoundedCornerShape(14.dp),
            border = BorderStroke(1.dp, colors.borderStone),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.fillMaxWidth()) {
                if (displayEntries.isEmpty()) {
                    Text(
                        text = stringResource(R.string.audit_empty),
                        style = MaterialTheme.typography.bodyMedium,
                        color = colors.inkMuted,
                        modifier = Modifier.padding(16.dp)
                    )
                } else {
                    displayEntries.forEachIndexed { index, entry ->
                        AuditLogEntryRow(
                            entry = entry,
                            bidiFormatter = bidiFormatter,
                            activeLocale = activeLocale
                        )
                        if (index < displayEntries.lastIndex) {
                            HorizontalDivider(
                                thickness = 0.5.dp,
                                color = colors.borderStone
                            )
                        }
                    }
                }
            }
        }
    }
    }
}

/**
 * Coalesces consecutive internal pipeline stages for the same `(toolName, second)` into a single
 * clean user-facing audit row without modifying the underlying append-only `AuditLogDao`.
 */
internal fun coalesceAuditEntries(entries: List<AuditLogEntry>): List<AuditLogEntry> {
    if (entries.size <= 1) return entries
    val out = ArrayList<AuditLogEntry>(entries.size)
    for (entry in entries) {
        val prev = out.lastOrNull()
        val sameSecond = prev != null &&
            prev.toolName == entry.toolName &&
            (prev.timestampEpochMs / 1_000L) == (entry.timestampEpochMs / 1_000L)
        if (!sameSecond) {
            out.add(entry)
        } else {
            val prevScore = auditEntryDisplayPriority(prev)
            val currScore = auditEntryDisplayPriority(entry)
            if (currScore > prevScore) {
                out[out.lastIndex] = entry
            }
        }
    }
    return out
}

private fun auditEntryDisplayPriority(entry: AuditLogEntry): Int {
    val severityScore = when (classifyAuditDecision(entry.decision)) {
        AuditDecisionSeverity.DENIED -> 30
        AuditDecisionSeverity.WARNING -> 20
        AuditDecisionSeverity.VERIFIED -> if (entry.decision.equals("SUCCESS", ignoreCase = true)) 15 else 10
    }
    val targetScore = if (entry.targetId.contains('.')) 5 else 0
    return severityScore + targetScore
}

@Composable
private fun AuditFilterSegment(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = NavaThemeExtras.colors
    Surface(
        color = if (selected) colors.surfaceCard else Color.Transparent,
        shape = RoundedCornerShape(10.dp),
        border = if (selected) BorderStroke(1.dp, colors.borderStone) else null,
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .clickable(onClick = onClick)
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 9.dp)
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium,
                color = if (selected) colors.inkPrimary else colors.inkSecondary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun AuditLogEntryRow(
    entry: AuditLogEntry,
    bidiFormatter: BidiTextFormatter,
    activeLocale: Locale
) {
    val colors = NavaThemeExtras.colors
    val haptics = LocalHapticFeedback.current
    var expanded by remember(entry.timestampEpochMs, entry.toolName) { mutableStateOf(false) }

    val severity = classifyAuditDecision(entry.decision)
    val dotColor = when (severity) {
        AuditDecisionSeverity.VERIFIED -> colors.verifiedForest
        AuditDecisionSeverity.WARNING -> colors.untrustedAccent
        AuditDecisionSeverity.DENIED -> colors.alertCrimson
    }
    val statusLabel = when (severity) {
        AuditDecisionSeverity.VERIFIED -> stringResource(R.string.audit_status_approved)
        AuditDecisionSeverity.WARNING -> stringResource(R.string.audit_status_pending)
        AuditDecisionSeverity.DENIED -> stringResource(R.string.audit_status_blocked)
    }
    val targetDisplay = when (entry.targetId) {
        "system.clock" -> stringResource(R.string.canvas_neuron_clock)
        "nava.reminders", "system.reminders" -> stringResource(R.string.target_label_reminders)
        "system.phone" -> stringResource(R.string.target_label_phone)
        "system.calendar" -> stringResource(R.string.canvas_neuron_calendar)
        "nava.notes" -> stringResource(R.string.canvas_neuron_notes)
        "nava.vault" -> stringResource(R.string.canvas_neuron_vault)
        "system.sms" -> stringResource(R.string.canvas_neuron_messages)
        "system.notifications" -> stringResource(R.string.target_label_notifications)
        "system.audio_dnd" -> stringResource(R.string.canvas_neuron_audio_dnd)
        "system.app_launch" -> stringResource(R.string.target_label_app_launch)
        "system.saf" -> stringResource(R.string.canvas_neuron_files)
        "nava.routines" -> stringResource(R.string.canvas_neuron_routines)
        else -> entry.targetId.substringAfterLast('.')
    }
    val provenanceDisplay = when (entry.provenance) {
        com.nava.domain.security.DataProvenance.USER_UTTERANCE ->
            stringResource(R.string.audit_provenance_user)
        com.nava.domain.security.DataProvenance.SYSTEM ->
            stringResource(R.string.audit_provenance_system)
        com.nava.domain.security.DataProvenance.UNTRUSTED_EXTERNAL ->
            stringResource(R.string.audit_provenance_external)
    }
    val formattedTime = formatAuditTimeHms(entry.timestampEpochMs)
    val metaLine = "$targetDisplay  \u00B7  $provenanceDisplay"

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable {
                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                expanded = !expanded
            }
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = localizedAuditToolLabel(entry.toolName),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = colors.inkPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )

            Row(
                modifier = Modifier.padding(start = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(7.dp)
                        .background(color = dotColor, shape = CircleShape)
                )
                Text(
                    text = statusLabel,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Medium,
                    color = dotColor,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = metaLine,
                style = MaterialTheme.typography.labelSmall,
                color = colors.inkMuted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )

            Text(
                text = bidiFormatter.wrapLtrToken(formattedTime, activeLocale),
                style = MaterialTheme.typography.labelSmall.copy(
                    fontFeatureSettings = "tnum"
                ),
                fontFamily = FontFamily.Monospace,
                color = colors.inkMuted,
                modifier = Modifier.padding(start = 8.dp)
            )
        }

        AnimatedVisibility(visible = expanded) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 6.dp)
                    .background(colors.bgLinen, RoundedCornerShape(8.dp))
                    .padding(horizontal = 10.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                Text(
                    text = "${bidiFormatter.wrapLtrToken(entry.targetId, activeLocale)}  \u00B7  ${
                        bidiFormatter.wrapLtrToken(entry.decision, activeLocale)
                    }  \u00B7  ${bidiFormatter.wrapLtrToken(entry.provenance.name, activeLocale)}",
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = colors.inkSecondary
                )
                if (entry.actionSummary.isNotBlank()) {
                    Text(
                        text = bidiFormatter.wrapText(entry.actionSummary, activeLocale),
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.inkMuted
                    )
                }
            }
        }
    }
}

private fun formatAuditTimeHms(timestampEpochMs: Long): String {
    val formatter = SimpleDateFormat("HH:mm:ss", Locale.US)
    return formatter.format(Date(timestampEpochMs))
}

@Composable
private fun localizedAuditToolLabel(toolName: String): String {
    return when (toolName) {
        "schedule_reminder" -> stringResource(R.string.audit_tool_schedule_reminder)
        "cancel_reminder" -> stringResource(R.string.audit_tool_cancel_reminder)
        "calendar_query" -> stringResource(R.string.audit_tool_calendar_query)
        "calendar_create" -> stringResource(R.string.audit_tool_calendar_create)
        "calendar_modify" -> stringResource(R.string.audit_tool_calendar_modify)
        "summarize_notifications" -> stringResource(R.string.audit_tool_summarize_notifications)
        "create_notification_watcher" -> stringResource(R.string.audit_tool_watcher_created)
        "manage_notification_watchers" -> stringResource(R.string.audit_tool_watcher_managed)
        "notes_create", "vault_create" -> stringResource(R.string.audit_tool_notes_create)
        "notes_read", "vault_read" -> stringResource(R.string.audit_tool_notes_read)
        "notes_search" -> stringResource(R.string.audit_tool_notes_search)
        "notes_delete", "vault_delete" -> stringResource(R.string.audit_tool_notes_delete)
        "set_alarm" -> stringResource(R.string.audit_tool_set_alarm)
        "set_timer" -> stringResource(R.string.audit_tool_set_timer)
        "launch_app" -> stringResource(R.string.audit_tool_launch_app)
        "daily_briefing" -> stringResource(R.string.audit_tool_daily_briefing)
        "toggle_dnd", "set_volume" -> stringResource(R.string.audit_tool_audio_dnd)
        "sms_draft" -> stringResource(R.string.audit_tool_sms_draft)
        "call_intent", "direct_call" -> stringResource(R.string.audit_tool_call)
        else -> toolName.replace('_', ' ')
    }
}

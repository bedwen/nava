package com.nava.app.ui.vault

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import com.nava.app.R
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.security.BiometricPromptLabels
import com.nava.app.ui.components.NavaIcons
import com.nava.app.ui.routines.RoutineConsentCardModel
import com.nava.app.ui.routines.RoutinesViewModel
import com.nava.app.ui.settings.SettingsViewModel
import com.nava.app.ui.theme.NavaExtendedColors
import com.nava.app.ui.theme.NavaThemeExtras
import com.nava.domain.automation.MorningBriefingConfig
import com.nava.domain.automation.NotificationWatcher
import com.nava.domain.automation.ScheduledReminder
import com.nava.domain.security.RuleApprovalState
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Unified Vault and Routine Studio screen in Warm Paper / Matte OLED Dark flat editorial
 * card styling. Offline Gemma 4 model provisioning lives exclusively in Settings to avoid
 * duplicating controls across tabs.
 */
@Composable
fun VaultScreen(
    settingsViewModel: SettingsViewModel,
    routinesViewModel: RoutinesViewModel,
    bidiFormatter: BidiTextFormatter,
    activeLocale: Locale,
    activity: FragmentActivity?,
    modifier: Modifier = Modifier
) {
    val settingsState by settingsViewModel.uiState.collectAsState()
    val routinesState by routinesViewModel.uiState.collectAsState()
    val haptics = LocalHapticFeedback.current
    val colors = NavaThemeExtras.colors

    LaunchedEffect(Unit) {
        settingsViewModel.refreshAll()
        routinesViewModel.refreshRules()
    }

    val biometricLabels = BiometricPromptLabels(
        title = stringResource(R.string.vault_title),
        subtitle = stringResource(R.string.vault_unlock_prompt),
        negativeButtonText = stringResource(R.string.action_cancel)
    )

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.bgPaper)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp)
    ) {
        // Section 0: Proactive Notification Watchers (Zero-Battery Passive Alerts)
        NotificationWatchersSection(
            watchers = routinesState.notificationWatchers,
            bidiFormatter = bidiFormatter,
            activeLocale = activeLocale,
            colors = colors,
            onCreateWatcher = { label, keywords, sender, appFilter ->
                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                routinesViewModel.createNotificationWatcher(label, keywords, sender, appFilter)
            },
            onToggleWatcher = { id, enabled ->
                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                routinesViewModel.setNotificationWatcherEnabled(id, enabled)
            },
            onDeleteWatcher = { id ->
                haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                routinesViewModel.deleteNotificationWatcher(id)
            }
        )

        // Section 1: Active Scheduled Reminders (My Day primary agenda)
        ScheduledRemindersSection(
            reminders = routinesState.activeReminders,
            bidiFormatter = bidiFormatter,
            activeLocale = activeLocale,
            colors = colors,
            onComplete = { reminderId ->
                haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                routinesViewModel.completeReminder(reminderId)
            },
            onCancel = { reminderId ->
                haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                routinesViewModel.cancelReminder(reminderId)
            }
        )

        // Section 2: Morning Briefing (Zero-Battery Scheduled, 15-minute localized stepper)
        MorningBriefingSection(
            config = routinesState.morningBriefingConfig,
            activeLocale = activeLocale,
            colors = colors,
            onToggleEnabled = { enabled ->
                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                routinesViewModel.setMorningBriefingEnabled(enabled)
            },
            onAdjustMinutes = { deltaMinutes ->
                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                val currentTotal = (routinesState.morningBriefingConfig.hour * 60) +
                    routinesState.morningBriefingConfig.minute
                val wrapped = ((currentTotal + deltaMinutes) % 1440 + 1440) % 1440
                routinesViewModel.setMorningBriefingTime(
                    hour = wrapped / 60,
                    minute = wrapped % 60
                )
            },
            onToggleAiSummary = { enabled ->
                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                routinesViewModel.setMorningBriefingAiSummary(enabled)
            },
            onToggleCalendar = { enabled ->
                routinesViewModel.setMorningBriefingSources(includeCalendar = enabled)
            },
            onToggleNotifications = { enabled ->
                routinesViewModel.setMorningBriefingSources(includeNotifications = enabled)
            },
            onToggleReminders = { enabled ->
                routinesViewModel.setMorningBriefingSources(includeReminders = enabled)
            }
        )

        // Section 3: Nava Secure Vault (Hardware-Backed Biometric Secrets)
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            VaultSectionHeader(
                title = stringResource(R.string.vault_title),
                locale = activeLocale,
                colors = colors
            )
            Surface(
                color = colors.surfaceCard,
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(1.dp, colors.borderStone),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .background(color = colors.bgLinen, shape = CircleShape)
                                .border(
                                    width = 1.dp,
                                    color = colors.borderStone,
                                    shape = CircleShape
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = NavaIcons.Lock,
                                contentDescription = null,
                                tint = if (settingsState.isVaultUnlocked) {
                                    colors.verifiedForest
                                } else {
                                    colors.trustNavyTint
                                },
                                modifier = Modifier.size(19.dp)
                            )
                        }

                        Column(
                            modifier = Modifier.weight(1f),
                            verticalArrangement = Arrangement.spacedBy(2.dp)
                        ) {
                            Text(
                                text = stringResource(R.string.vault_title),
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = colors.inkPrimary
                            )
                            Text(
                                text = if (settingsState.isVaultUnlocked) {
                                    stringResource(R.string.vault_status_unlocked)
                                } else {
                                    stringResource(R.string.vault_status_locked_zeroed)
                                },
                                style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.Medium,
                                color = if (settingsState.isVaultUnlocked) {
                                    colors.verifiedForest
                                } else {
                                    colors.inkMuted
                                }
                            )
                        }
                    }

                    Text(
                        text = stringResource(R.string.vault_subtitle),
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.inkSecondary
                    )

                    settingsState.lastVaultUnlockError?.let { errorMsg ->
                        Text(
                            text = bidiFormatter.wrapText(errorMsg, activeLocale),
                            style = MaterialTheme.typography.bodySmall,
                            color = colors.alertCrimson
                        )
                    }

                    if (settingsState.isVaultUnlocked) {
                        Text(
                            text = stringResource(R.string.vault_unlocked_ready_note),
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Medium,
                            color = colors.verifiedForest
                        )
                        OutlinedButton(
                            onClick = {
                                haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                                settingsViewModel.lockVault()
                            },
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, colors.borderStone),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = colors.inkPrimary
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(44.dp)
                        ) {
                            Text(
                                text = stringResource(R.string.vault_lock_button),
                                color = colors.inkPrimary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    } else {
                        Button(
                            onClick = {
                                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                settingsViewModel.unlockVault(
                                    activity = activity,
                                    labels = biometricLabels
                                )
                            },
                            shape = RoundedCornerShape(10.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = colors.trustNavy,
                                contentColor = Color.White
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(44.dp)
                        ) {
                            Text(
                                text = stringResource(R.string.vault_unlock_button),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }
            }
        }

        // Section 4: Routine Studio
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            VaultSectionHeader(
                title = stringResource(R.string.vault_routine_studio_title),
                locale = activeLocale,
                colors = colors
            )
            Surface(
                color = colors.surfaceCard,
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(1.dp, colors.borderStone),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(
                                modifier = Modifier
                                    .weight(1f)
                                    .padding(end = 12.dp),
                                verticalArrangement = Arrangement.spacedBy(2.dp)
                            ) {
                                Text(
                                    text = stringResource(R.string.vault_routine_studio_title),
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.SemiBold,
                                    color = colors.inkPrimary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                val isActive = !routinesState.isGlobalPaused
                                Text(
                                    text = if (isActive) {
                                        stringResource(R.string.routine_status_active)
                                    } else {
                                        stringResource(R.string.routine_status_paused)
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    fontWeight = FontWeight.Medium,
                                    color = if (isActive) {
                                        colors.verifiedForest
                                    } else {
                                        colors.untrustedAccent
                                    }
                                )
                            }

                            Switch(
                                checked = !routinesState.isGlobalPaused,
                                onCheckedChange = { checked ->
                                    haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    routinesViewModel.setGlobalRulesPaused(!checked)
                                },
                                colors = SwitchDefaults.colors(
                                    checkedThumbColor = Color.White,
                                    checkedTrackColor = colors.trustNavy,
                                    uncheckedThumbColor = colors.inkMuted,
                                    uncheckedTrackColor = colors.bgLinen,
                                    uncheckedBorderColor = colors.borderStone
                                )
                            )
                        }

                        // 3-step vertical timeline preview (borderless inset)
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(
                                    color = colors.bgLinen,
                                    shape = RoundedCornerShape(10.dp)
                                )
                                .padding(horizontal = 12.dp, vertical = 10.dp)
                        ) {
                            val stepResources = listOf(
                                R.string.vault_step_trigger,
                                R.string.vault_step_condition,
                                R.string.vault_step_action
                            )
                            stepResources.forEachIndexed { index, stepResId ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(IntrinsicSize.Min),
                                    verticalAlignment = Alignment.Top
                                ) {
                                    Column(
                                        horizontalAlignment = Alignment.CenterHorizontally,
                                        modifier = Modifier
                                            .width(18.dp)
                                            .fillMaxHeight()
                                    ) {
                                        Box(
                                            modifier = Modifier
                                                .width(1.5.dp)
                                                .height(4.dp)
                                                .background(
                                                    if (index == 0) {
                                                        Color.Transparent
                                                    } else {
                                                        colors.borderStone
                                                    }
                                                )
                                        )
                                        Box(
                                            modifier = Modifier
                                                .size(8.dp)
                                                .background(
                                                    color = colors.trustNavy,
                                                    shape = CircleShape
                                                )
                                        )
                                        Box(
                                            modifier = Modifier
                                                .width(1.5.dp)
                                                .weight(1f)
                                                .background(
                                                    if (index == stepResources.lastIndex) {
                                                        Color.Transparent
                                                    } else {
                                                        colors.borderStone
                                                    }
                                                )
                                        )
                                    }
                                    Text(
                                        text = stringResource(stepResId),
                                        style = MaterialTheme.typography.bodySmall,
                                        fontWeight = FontWeight.Medium,
                                        color = colors.inkPrimary,
                                        modifier = Modifier
                                            .weight(1f)
                                            .padding(
                                                start = 10.dp,
                                                bottom = if (index < stepResources.lastIndex) {
                                                    8.dp
                                                } else {
                                                    0.dp
                                                }
                                            )
                                    )
                                }
                            }
                        }

                        routinesState.errorMessage?.let { err ->
                            Text(
                                text = bidiFormatter.wrapText(err, activeLocale),
                                style = MaterialTheme.typography.bodySmall,
                                color = colors.alertCrimson
                            )
                        }

                        routinesState.statusMessage?.let { status ->
                            Text(
                                text = bidiFormatter.wrapText(status, activeLocale),
                                style = MaterialTheme.typography.bodySmall,
                                color = colors.inkSecondary
                            )
                        }
                    }

                    HorizontalDivider(thickness = 0.5.dp, color = colors.borderStone)

                    if (routinesState.consentCards.isEmpty()) {
                        Text(
                            text = stringResource(R.string.routine_empty),
                            style = MaterialTheme.typography.bodySmall,
                            color = colors.inkMuted,
                            modifier = Modifier.padding(16.dp)
                        )
                    } else {
                        routinesState.consentCards.forEachIndexed { index, cardModel ->
                            VaultRoutineRow(
                                model = cardModel,
                                bidiFormatter = bidiFormatter,
                                activeLocale = activeLocale,
                                onApprove = {
                                    haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                                    routinesViewModel.approveRule(cardModel.ruleId)
                                },
                                onPause = {
                                    haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    routinesViewModel.pauseRule(cardModel.ruleId)
                                },
                                onResume = {
                                    haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    routinesViewModel.approveRule(cardModel.ruleId)
                                },
                                onRunNow = {
                                    haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                                    routinesViewModel.runRuleNow(cardModel.ruleId)
                                },
                                onDelete = {
                                    haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                                    routinesViewModel.revokeRule(cardModel.ruleId)
                                }
                            )
                            if (index < routinesState.consentCards.lastIndex) {
                                HorizontalDivider(thickness = 0.5.dp, color = colors.borderStone)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun VaultSectionHeader(
    title: String,
    locale: Locale,
    colors: NavaExtendedColors
) {
    Text(
        text = title.uppercase(locale),
        style = MaterialTheme.typography.labelSmall.copy(
            fontSize = 11.sp,
            letterSpacing = 0.8.sp
        ),
        fontWeight = FontWeight.SemiBold,
        color = colors.inkMuted,
        modifier = Modifier.padding(horizontal = 4.dp)
    )
}

@Composable
private fun VaultRoutineRow(
    model: RoutineConsentCardModel,
    bidiFormatter: BidiTextFormatter,
    activeLocale: Locale,
    onApprove: () -> Unit,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onRunNow: () -> Unit,
    onDelete: () -> Unit
) {
    val colors = NavaThemeExtras.colors
    val approvalState = model.grant.approvalState

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = stringResource(
                    R.string.routine_rule_id_label,
                    bidiFormatter.wrapLtrToken(model.ruleId, activeLocale)
                ),
                style = MaterialTheme.typography.titleSmall,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.SemiBold,
                color = colors.inkPrimary,
                modifier = Modifier
                    .weight(1f)
                    .padding(end = 8.dp)
            )
            Text(
                text = when (approvalState) {
                    RuleApprovalState.APPROVED_ACTIVE -> stringResource(R.string.routine_status_active)
                    RuleApprovalState.PAUSED -> stringResource(R.string.routine_status_paused)
                    else -> approvalState.name
                },
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Medium,
                color = when (approvalState) {
                    RuleApprovalState.APPROVED_ACTIVE -> colors.verifiedForest
                    RuleApprovalState.PENDING_USER_APPROVAL -> colors.untrustedAccent
                    RuleApprovalState.PAUSED -> colors.inkMuted
                    RuleApprovalState.REVOKED -> colors.alertCrimson
                }
            )
        }

        val triggerDisplay = buildString {
            append(model.triggerType)
            if (model.triggerParameters.isNotEmpty()) {
                append(" ")
                append(model.triggerParameters.entries.joinToString(", ") { (k, v) -> "$k=$v" })
            }
        }
        Text(
            text = stringResource(
                R.string.routine_trigger_time_label,
                bidiFormatter.wrapLtrToken(triggerDisplay, activeLocale)
            ),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = colors.inkSecondary
        )

        Text(
            text = stringResource(
                R.string.routine_step_count_label,
                model.staticActions.size.toString()
            ),
            style = MaterialTheme.typography.labelMedium,
            color = colors.trustNavyTint
        )

        if (model.requiresInteractiveEscalationWarning) {
            Text(
                text = stringResource(
                    R.string.msg_routine_escalated_confirmation,
                    bidiFormatter.wrapLtrToken(
                        model.nonUnattendedActionNames.joinToString(", "),
                        activeLocale
                    )
                ),
                style = MaterialTheme.typography.labelSmall,
                color = colors.untrustedAccent
            )
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.End,
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (approvalState != RuleApprovalState.REVOKED) {
                TextButton(
                    onClick = onDelete,
                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                ) {
                    Text(
                        text = stringResource(R.string.routine_action_delete),
                        style = MaterialTheme.typography.labelMedium,
                        color = colors.alertCrimson
                    )
                }
            }

            when (approvalState) {
                RuleApprovalState.PENDING_USER_APPROVAL -> {
                    Button(
                        onClick = onApprove,
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = colors.trustNavy,
                            contentColor = Color.White
                        )
                    ) {
                        Text(text = stringResource(R.string.action_approve))
                    }
                }

                RuleApprovalState.APPROVED_ACTIVE -> {
                    OutlinedButton(
                        onClick = onPause,
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, colors.borderStone),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = colors.inkPrimary
                        ),
                        modifier = Modifier.padding(end = 8.dp)
                    ) {
                        Text(
                            text = stringResource(R.string.routine_action_pause),
                            color = colors.inkPrimary
                        )
                    }
                    Button(
                        onClick = onRunNow,
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = colors.trustNavy,
                            contentColor = Color.White
                        )
                    ) {
                        Text(text = stringResource(R.string.routine_action_run))
                    }
                }

                RuleApprovalState.PAUSED -> {
                    Button(
                        onClick = onResume,
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = colors.trustNavy,
                            contentColor = Color.White
                        )
                    ) {
                        Text(text = stringResource(R.string.routine_action_resume))
                    }
                }

                RuleApprovalState.REVOKED -> Unit
            }
        }
    }
}

@Composable
private fun NotificationWatchersSection(
    watchers: List<NotificationWatcher>,
    bidiFormatter: BidiTextFormatter,
    activeLocale: Locale,
    colors: NavaExtendedColors,
    onCreateWatcher: (label: String, keywords: String, sender: String, appFilter: String) -> Unit,
    onToggleWatcher: (String, Boolean) -> Unit,
    onDeleteWatcher: (String) -> Unit
) {
    var showAddForm by remember { mutableStateOf(false) }
    var keywordsInput by remember { mutableStateOf("") }
    var senderInput by remember { mutableStateOf("") }
    var appInput by remember { mutableStateOf("") }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            VaultSectionHeader(
                title = stringResource(R.string.watcher_section_title),
                locale = activeLocale,
                colors = colors
            )
            TextButton(
                onClick = { showAddForm = !showAddForm },
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)
            ) {
                Text(
                    text = if (showAddForm) {
                        stringResource(R.string.action_cancel)
                    } else {
                        "+ ${stringResource(R.string.watcher_add_button)}"
                    },
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = colors.trustNavyTint
                )
            }
        }

        Surface(
            color = colors.surfaceCard,
            shape = RoundedCornerShape(14.dp),
            border = BorderStroke(1.dp, colors.borderStone),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                if (showAddForm) {
                    val fieldColors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = colors.trustNavyTint,
                        unfocusedBorderColor = colors.borderStone,
                        focusedTextColor = colors.inkPrimary,
                        unfocusedTextColor = colors.inkPrimary,
                        focusedContainerColor = colors.bgPaper,
                        unfocusedContainerColor = colors.bgPaper
                    )
                    OutlinedTextField(
                        value = keywordsInput,
                        onValueChange = { keywordsInput = it },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        shape = RoundedCornerShape(10.dp),
                        colors = fieldColors,
                        placeholder = {
                            Text(
                                text = stringResource(R.string.watcher_keywords_placeholder),
                                color = colors.inkMuted
                            )
                        }
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = senderInput,
                            onValueChange = { senderInput = it },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            shape = RoundedCornerShape(10.dp),
                            colors = fieldColors,
                            placeholder = {
                                Text(
                                    text = stringResource(R.string.watcher_sender_placeholder),
                                    color = colors.inkMuted
                                )
                            }
                        )
                        OutlinedTextField(
                            value = appInput,
                            onValueChange = { appInput = it },
                            modifier = Modifier.weight(1f),
                            singleLine = true,
                            shape = RoundedCornerShape(10.dp),
                            colors = fieldColors,
                            placeholder = {
                                Text(
                                    text = stringResource(R.string.watcher_app_placeholder),
                                    color = colors.inkMuted
                                )
                            }
                        )
                    }
                    Button(
                        onClick = {
                            onCreateWatcher("", keywordsInput, senderInput, appInput)
                            keywordsInput = ""
                            senderInput = ""
                            appInput = ""
                            showAddForm = false
                        },
                        enabled = keywordsInput.isNotBlank() || senderInput.isNotBlank(),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = colors.trustNavy,
                            contentColor = Color.White,
                            disabledContainerColor = colors.bgLinen,
                            disabledContentColor = colors.inkMuted
                        ),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(42.dp)
                    ) {
                        Text(text = stringResource(R.string.watcher_save_button))
                    }
                    if (watchers.isNotEmpty()) {
                        HorizontalDivider(thickness = 0.5.dp, color = colors.borderStone)
                    }
                }

                if (watchers.isEmpty() && !showAddForm) {
                    Text(
                        text = stringResource(R.string.watcher_empty_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.inkMuted
                    )
                } else {
                    watchers.forEachIndexed { index, watcher ->
                        val criteriaText = buildList {
                            if (!watcher.senderFilter.isNullOrBlank()) add(watcher.senderFilter!!)
                            if (watcher.keywords.isNotEmpty()) add(watcher.keywords.joinToString(", "))
                            if (!watcher.packageFilter.isNullOrBlank()) add(watcher.packageFilter!!)
                        }.joinToString(" / ")

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(
                                modifier = Modifier
                                    .weight(1f)
                                    .padding(end = 8.dp),
                                verticalArrangement = Arrangement.spacedBy(2.dp)
                            ) {
                                Text(
                                    text = bidiFormatter.wrapText(watcher.label, activeLocale),
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.SemiBold,
                                    color = colors.inkPrimary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                if (criteriaText.isNotBlank()) {
                                    Text(
                                        text = bidiFormatter.wrapText(criteriaText, activeLocale),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = colors.inkMuted,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                            Switch(
                                checked = watcher.enabled,
                                onCheckedChange = { onToggleWatcher(watcher.watcherId, it) },
                                colors = SwitchDefaults.colors(
                                    checkedThumbColor = Color.White,
                                    checkedTrackColor = colors.trustNavy,
                                    uncheckedThumbColor = colors.inkMuted,
                                    uncheckedTrackColor = colors.bgLinen,
                                    uncheckedBorderColor = colors.borderStone
                                )
                            )
                            TextButton(
                                onClick = { onDeleteWatcher(watcher.watcherId) },
                                contentPadding = PaddingValues(horizontal = 6.dp, vertical = 0.dp)
                            ) {
                                Text(
                                    text = stringResource(R.string.vault_delete_model),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = colors.alertCrimson
                                )
                            }
                        }

                        if (index < watchers.lastIndex) {
                            HorizontalDivider(
                                thickness = 0.5.dp,
                                color = colors.borderStone.copy(alpha = 0.6f)
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun MorningBriefingSection(
    config: MorningBriefingConfig,
    activeLocale: Locale,
    colors: NavaExtendedColors,
    onToggleEnabled: (Boolean) -> Unit,
    onAdjustMinutes: (Int) -> Unit,
    onToggleAiSummary: (Boolean) -> Unit,
    onToggleCalendar: (Boolean) -> Unit,
    onToggleNotifications: (Boolean) -> Unit,
    onToggleReminders: (Boolean) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        VaultSectionHeader(
            title = stringResource(R.string.briefing_section_title),
            locale = activeLocale,
            colors = colors
        )
        Surface(
            color = colors.surfaceCard,
            shape = RoundedCornerShape(14.dp),
            border = BorderStroke(1.dp, colors.borderStone),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(
                        modifier = Modifier
                            .weight(1f)
                            .padding(end = 12.dp),
                        verticalArrangement = Arrangement.spacedBy(2.dp)
                    ) {
                        Text(
                            text = stringResource(R.string.briefing_toggle_title),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = colors.inkPrimary
                        )
                        Text(
                            text = stringResource(R.string.briefing_toggle_subtitle),
                            style = MaterialTheme.typography.bodySmall,
                            color = colors.inkSecondary
                        )
                    }
                    Switch(
                        checked = config.enabled,
                        onCheckedChange = onToggleEnabled,
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.White,
                            checkedTrackColor = colors.trustNavy,
                            uncheckedThumbColor = colors.inkMuted,
                            uncheckedTrackColor = colors.bgLinen,
                            uncheckedBorderColor = colors.borderStone
                        )
                    )
                }

                if (config.enabled) {
                    HorizontalDivider(color = colors.borderStone, thickness = 1.dp)

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = stringResource(R.string.briefing_time_label),
                            style = MaterialTheme.typography.bodyMedium,
                            color = colors.inkPrimary
                        )
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            OutlinedButton(
                                onClick = { onAdjustMinutes(-15) },
                                shape = RoundedCornerShape(8.dp),
                                border = BorderStroke(1.dp, colors.borderStone),
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    text = stringResource(R.string.briefing_minus_15m),
                                    color = colors.inkPrimary
                                )
                            }
                            Text(
                                text = String.format(Locale.US, "%02d:%02d", config.hour, config.minute),
                                style = MaterialTheme.typography.titleMedium,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.SemiBold,
                                color = colors.inkPrimary
                            )
                            OutlinedButton(
                                onClick = { onAdjustMinutes(15) },
                                shape = RoundedCornerShape(8.dp),
                                border = BorderStroke(1.dp, colors.borderStone),
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                            ) {
                                Text(
                                    text = stringResource(R.string.briefing_plus_15m),
                                    color = colors.inkPrimary
                                )
                            }
                        }
                    }

                    BriefingSourceRow(
                        label = stringResource(R.string.briefing_source_calendar),
                        checked = config.includeCalendar,
                        colors = colors,
                        onCheckedChange = onToggleCalendar
                    )
                    BriefingSourceRow(
                        label = stringResource(R.string.briefing_source_reminders),
                        checked = config.includeReminders,
                        colors = colors,
                        onCheckedChange = onToggleReminders
                    )
                    BriefingSourceRow(
                        label = stringResource(R.string.briefing_source_notifications),
                        checked = config.includeNotifications,
                        colors = colors,
                        onCheckedChange = onToggleNotifications
                    )

                    HorizontalDivider(color = colors.borderStone, thickness = 1.dp)

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .padding(end = 12.dp),
                            verticalArrangement = Arrangement.spacedBy(2.dp)
                        ) {
                            Text(
                                text = stringResource(R.string.briefing_ai_summary_title),
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium,
                                color = colors.inkPrimary
                            )
                            Text(
                                text = stringResource(R.string.briefing_ai_summary_subtitle),
                                style = MaterialTheme.typography.bodySmall,
                                color = colors.inkSecondary
                            )
                        }
                        Switch(
                            checked = config.aiSummaryEnabled,
                            onCheckedChange = onToggleAiSummary,
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = Color.White,
                                checkedTrackColor = colors.trustNavy,
                                uncheckedThumbColor = colors.inkMuted,
                                uncheckedTrackColor = colors.bgLinen,
                                uncheckedBorderColor = colors.borderStone
                            )
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun BriefingSourceRow(
    label: String,
    checked: Boolean,
    colors: NavaExtendedColors,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = colors.inkPrimary
        )
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color.White,
                checkedTrackColor = colors.trustNavy,
                uncheckedThumbColor = colors.inkMuted,
                uncheckedTrackColor = colors.bgLinen,
                uncheckedBorderColor = colors.borderStone
            )
        )
    }
}

@Composable
private fun ScheduledRemindersSection(
    reminders: List<ScheduledReminder>,
    bidiFormatter: BidiTextFormatter,
    activeLocale: Locale,
    colors: NavaExtendedColors,
    onComplete: (String) -> Unit,
    onCancel: (String) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        VaultSectionHeader(
            title = stringResource(R.string.reminders_section_title),
            locale = activeLocale,
            colors = colors
        )
        Surface(
            color = colors.surfaceCard,
            shape = RoundedCornerShape(14.dp),
            border = BorderStroke(1.dp, colors.borderStone),
            modifier = Modifier.fillMaxWidth()
        ) {
            if (reminders.isEmpty()) {
                Text(
                    text = stringResource(R.string.reminders_empty_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = colors.inkSecondary,
                    modifier = Modifier.padding(16.dp)
                )
            } else {
                val timeFmt = SimpleDateFormat("dd MMM HH:mm", activeLocale)
                Column(modifier = Modifier.fillMaxWidth()) {
                    reminders.forEachIndexed { index, reminder ->
                        if (index > 0) {
                            HorizontalDivider(color = colors.borderStone, thickness = 1.dp)
                        }
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(
                                modifier = Modifier
                                    .weight(1f)
                                    .padding(end = 8.dp),
                                verticalArrangement = Arrangement.spacedBy(2.dp)
                            ) {
                                Text(
                                    text = bidiFormatter.wrapText(reminder.title, activeLocale),
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.Medium,
                                    color = colors.inkPrimary,
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = "${timeFmt.format(Date(reminder.triggerAtEpochMs))} - ${reminder.recurrence.name}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = colors.inkSecondary
                                )
                            }
                            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                TextButton(
                                    onClick = { onComplete(reminder.reminderId) },
                                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                                ) {
                                    Text(
                                        text = stringResource(R.string.reminder_action_done),
                                        style = MaterialTheme.typography.labelMedium,
                                        color = colors.verifiedForest
                                    )
                                }
                                TextButton(
                                    onClick = { onCancel(reminder.reminderId) },
                                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                                ) {
                                    Text(
                                        text = stringResource(R.string.action_cancel),
                                        style = MaterialTheme.typography.labelMedium,
                                        color = colors.alertCrimson
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

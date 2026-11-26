package com.nava.app.ui.routines

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.nava.app.R
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.ui.components.NavaIcons
import com.nava.app.ui.theme.NavaThemeExtras
import com.nava.domain.security.RuleApprovalState
import java.util.Locale

/**
 * Automations & Routines screen displaying the Global Pause switch, Routine Consent Cards
 * grouped by [RuleApprovalState], non-unattended escalation warnings, and single-tap
 * Approve / Pause / Revoke / Run controls (Requirement 7).
 */
@Composable
fun RoutinesScreen(
    viewModel: RoutinesViewModel,
    bidiFormatter: BidiTextFormatter,
    activeLocale: Locale = Locale.forLanguageTag("en"),
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    val locale = activeLocale
    val colors = NavaThemeExtras.colors

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.bgPaper)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(
            text = stringResource(R.string.routine_title),
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.SemiBold,
            color = colors.inkPrimary
        )
        Text(
            text = stringResource(R.string.routine_subtitle),
            style = MaterialTheme.typography.bodyMedium,
            color = colors.inkSecondary
        )

        // Global Pause Switch
        Card(
            colors = CardDefaults.cardColors(
                containerColor = if (state.isGlobalPaused) {
                    colors.untrustedSurface
                } else {
                    colors.surfaceCard
                }
            ),
            shape = RoundedCornerShape(16.dp),
            border = BorderStroke(
                width = 1.dp,
                color = if (state.isGlobalPaused) {
                    colors.untrustedAccent.copy(alpha = 0.45f)
                } else {
                    colors.borderStone
                }
            ),
            elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
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
                        text = stringResource(R.string.tile_routines_label),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = if (state.isGlobalPaused) {
                            colors.untrustedAccent
                        } else {
                            colors.inkPrimary
                        }
                    )
                    Text(
                        text = if (state.isGlobalPaused) {
                            stringResource(R.string.routine_global_paused_banner)
                        } else {
                            stringResource(R.string.tile_routines_description)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = if (state.isGlobalPaused) {
                            colors.untrustedAccent
                        } else {
                            colors.inkSecondary
                        }
                    )
                }
                Switch(
                    checked = state.isGlobalPaused,
                    onCheckedChange = { paused ->
                        viewModel.setGlobalRulesPaused(paused)
                    },
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Color.White,
                        checkedTrackColor = colors.untrustedAccent,
                        checkedBorderColor = colors.untrustedAccent,
                        uncheckedThumbColor = colors.inkMuted,
                        uncheckedTrackColor = colors.bgLinen,
                        uncheckedBorderColor = colors.borderStone
                    )
                )
            }
        }

        state.errorMessage?.let { err ->
            Surface(
                color = colors.alertCrimsonSurface,
                shape = RoundedCornerShape(12.dp),
                border = BorderStroke(1.dp, colors.alertCrimson.copy(alpha = 0.4f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = bidiFormatter.wrapText(err, locale),
                    style = MaterialTheme.typography.bodySmall,
                    color = colors.alertCrimson,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }

        state.statusMessage?.let { msg ->
            Surface(
                color = colors.verifiedMint,
                shape = RoundedCornerShape(12.dp),
                border = BorderStroke(1.dp, colors.verifiedForest.copy(alpha = 0.25f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = bidiFormatter.wrapText(msg, locale),
                    style = MaterialTheme.typography.bodyMedium,
                    color = colors.verifiedForest,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }

        if (state.consentCards.isEmpty()) {
            Card(
                colors = CardDefaults.cardColors(containerColor = colors.surfaceCard),
                shape = RoundedCornerShape(16.dp),
                border = BorderStroke(1.dp, colors.borderStone),
                elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(
                        imageVector = NavaIcons.Clock,
                        contentDescription = null,
                        tint = colors.inkMuted,
                        modifier = Modifier.size(20.dp)
                    )
                    Text(
                        text = stringResource(R.string.routine_empty),
                        style = MaterialTheme.typography.bodyMedium,
                        color = colors.inkSecondary
                    )
                }
            }
        } else {
            for (cardModel in state.consentCards) {
                RoutineConsentCard(
                    model = cardModel,
                    bidiFormatter = bidiFormatter,
                    locale = locale,
                    onApprove = { viewModel.approveRule(cardModel.ruleId) },
                    onPause = { viewModel.pauseRule(cardModel.ruleId) },
                    onRevoke = { viewModel.revokeRule(cardModel.ruleId) },
                    onRunNow = { viewModel.runRuleNow(cardModel.ruleId) }
                )
            }
        }
    }
}

/**
 * Dedicated Routine Consent Card showing trigger, conditions, static actions, non-unattended
 * escalation warnings, and single-tap Approve / Pause / Revoke / Run controls.
 */
@Composable
fun RoutineConsentCard(
    model: RoutineConsentCardModel,
    bidiFormatter: BidiTextFormatter,
    locale: Locale,
    onApprove: () -> Unit,
    onPause: () -> Unit,
    onRevoke: () -> Unit,
    onRunNow: () -> Unit,
    modifier: Modifier = Modifier
) {
    val approvalState = model.grant.approvalState
    val colors = NavaThemeExtras.colors
    val primaryButtonColors = ButtonDefaults.buttonColors(
        containerColor = colors.trustNavy,
        contentColor = Color.White
    )

    Card(
        colors = CardDefaults.cardColors(containerColor = colors.surfaceCard),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, colors.borderStone),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        modifier = modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(
                        R.string.routine_rule_id_label,
                        bidiFormatter.wrapLtrToken(model.ruleId, locale)
                    ),
                    style = MaterialTheme.typography.titleMedium,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.SemiBold,
                    color = colors.inkPrimary,
                    modifier = Modifier
                        .weight(1f)
                        .padding(end = 8.dp)
                )

                val (badgeBg, badgeText, badgeBorder) = when (approvalState) {
                    RuleApprovalState.APPROVED_ACTIVE -> Triple(
                        colors.verifiedMint,
                        colors.verifiedForest,
                        colors.verifiedForest.copy(alpha = 0.25f)
                    )

                    RuleApprovalState.PENDING_USER_APPROVAL -> Triple(
                        colors.untrustedSurface,
                        colors.untrustedAccent,
                        colors.untrustedAccent.copy(alpha = 0.35f)
                    )

                    RuleApprovalState.PAUSED -> Triple(
                        colors.bgLinen,
                        colors.inkSecondary,
                        colors.borderStone
                    )

                    RuleApprovalState.REVOKED -> Triple(
                        colors.alertCrimsonSurface,
                        colors.alertCrimson,
                        colors.alertCrimson.copy(alpha = 0.35f)
                    )
                }

                Surface(
                    color = badgeBg,
                    shape = RoundedCornerShape(999.dp),
                    border = BorderStroke(1.dp, badgeBorder)
                ) {
                    Text(
                        text = when (approvalState) {
                            RuleApprovalState.APPROVED_ACTIVE -> {
                                stringResource(R.string.routine_status_active)
                            }

                            RuleApprovalState.PAUSED -> {
                                stringResource(R.string.routine_status_paused)
                            }

                            else -> bidiFormatter.wrapLtrToken(approvalState.name, locale)
                        },
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Medium,
                        color = badgeText,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                    )
                }
            }

            // Trigger & Conditions
            val triggerDisplay = buildString {
                append(model.triggerType)
                if (model.triggerParameters.isNotEmpty()) {
                    append(" ")
                    append(
                        model.triggerParameters.entries.joinToString(", ") { (k, v) -> "$k=$v" }
                    )
                }
            }
            Text(
                text = stringResource(
                    R.string.routine_trigger_time_label,
                    bidiFormatter.wrapLtrToken(triggerDisplay, locale)
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

            // Static Actions List
            for (action in model.staticActions) {
                Surface(
                    color = colors.bgLinen,
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, colors.borderStone),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(2.dp)
                    ) {
                        Text(
                            text = bidiFormatter.wrapLtrToken(action.toolName, locale),
                            style = MaterialTheme.typography.labelLarge,
                            fontFamily = FontFamily.Monospace,
                            color = colors.trustNavyTint
                        )
                        Text(
                            text = bidiFormatter.wrapLtrToken(
                                action.requiredCapability.name,
                                locale
                            ),
                            style = MaterialTheme.typography.labelSmall,
                            color = colors.inkSecondary
                        )
                        if (action.staticArguments.isNotEmpty()) {
                            val argsSummary = action.staticArguments.entries.joinToString(", ") { (k, v) ->
                                "$k=$v"
                            }
                            Text(
                                text = bidiFormatter.wrapText(argsSummary, locale),
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = colors.inkPrimary
                            )
                        }
                    }
                }
            }

            // Clear warning for non-unattended actions (Biometric, Vault, MODIFY_DELETE_SEND)
            if (model.requiresInteractiveEscalationWarning) {
                Surface(
                    color = colors.untrustedSurface,
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, colors.untrustedAccent.copy(alpha = 0.4f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(
                            text = stringResource(
                                R.string.msg_routine_escalated_confirmation,
                                bidiFormatter.wrapLtrToken(
                                    model.nonUnattendedActionNames.joinToString(", "),
                                    locale
                                )
                            ),
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = colors.untrustedAccent
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = stringResource(R.string.confirmation_level_prompt_card_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = colors.inkPrimary
                        )
                    }
                }
            }

            // Single-tap Approve / Pause / Revoke / Run Now buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (approvalState != RuleApprovalState.REVOKED) {
                    TextButton(onClick = onRevoke) {
                        Text(
                            text = stringResource(R.string.routine_action_delete),
                            color = colors.alertCrimson
                        )
                    }
                }

                when (approvalState) {
                    RuleApprovalState.PENDING_USER_APPROVAL -> {
                        Button(
                            onClick = onApprove,
                            colors = primaryButtonColors,
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text(text = stringResource(R.string.action_approve))
                        }
                    }

                    RuleApprovalState.APPROVED_ACTIVE -> {
                        OutlinedButton(
                            onClick = onPause,
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, colors.borderStone),
                            modifier = Modifier.padding(horizontal = 6.dp)
                        ) {
                            Text(
                                text = stringResource(R.string.routine_action_pause),
                                color = colors.inkPrimary
                            )
                        }
                        Button(
                            onClick = onRunNow,
                            colors = primaryButtonColors,
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text(text = stringResource(R.string.routine_action_run))
                        }
                    }

                    RuleApprovalState.PAUSED -> {
                        Button(
                            onClick = onApprove,
                            colors = primaryButtonColors,
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text(text = stringResource(R.string.routine_action_resume))
                        }
                    }

                    RuleApprovalState.REVOKED -> Unit
                }
            }
        }
    }
}

package com.nava.app.ui.routines

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.nava.app.R
import com.nava.app.locale.BidiTextFormatter
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
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    val locale = Locale.getDefault()

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(
            text = stringResource(R.string.routine_title),
            style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.onBackground
        )
        Text(
            text = stringResource(R.string.routine_subtitle),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        // Global Pause Switch
        Card(
            colors = CardDefaults.cardColors(
                containerColor = if (state.isGlobalPaused) {
                    MaterialTheme.colorScheme.errorContainer
                } else {
                    MaterialTheme.colorScheme.surfaceVariant
                }
            ),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(14.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.tile_routines_label),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = if (state.isGlobalPaused) {
                            stringResource(R.string.routine_global_paused_banner)
                        } else {
                            stringResource(R.string.tile_routines_description)
                        },
                        style = MaterialTheme.typography.bodySmall
                    )
                }
                Switch(
                    checked = state.isGlobalPaused,
                    onCheckedChange = { paused ->
                        viewModel.setGlobalRulesPaused(paused)
                    }
                )
            }
        }

        state.errorMessage?.let { err ->
            Surface(
                color = MaterialTheme.colorScheme.errorContainer,
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = err,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.padding(10.dp)
                )
            }
        }

        state.statusMessage?.let { msg ->
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = msg,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(10.dp)
                )
            }
        }

        if (state.consentCards.isEmpty()) {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = stringResource(R.string.routine_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(16.dp)
                )
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

    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        ),
        modifier = modifier.fillMaxWidth()
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
                    text = stringResource(
                        R.string.routine_rule_id_label,
                        bidiFormatter.wrapLtrToken(model.ruleId, locale)
                    ),
                    style = MaterialTheme.typography.titleMedium,
                    fontFamily = FontFamily.Monospace
                )
                Surface(
                    color = when (approvalState) {
                        RuleApprovalState.APPROVED_ACTIVE -> MaterialTheme.colorScheme.primaryContainer
                        RuleApprovalState.PENDING_USER_APPROVAL -> MaterialTheme.colorScheme.secondaryContainer
                        RuleApprovalState.PAUSED -> MaterialTheme.colorScheme.surface
                        RuleApprovalState.REVOKED -> MaterialTheme.colorScheme.errorContainer
                    },
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        text = when (approvalState) {
                            RuleApprovalState.APPROVED_ACTIVE -> stringResource(R.string.routine_status_active)
                            RuleApprovalState.PAUSED -> stringResource(R.string.routine_status_paused)
                            else -> approvalState.name
                        },
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
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
                fontFamily = FontFamily.Monospace
            )

            Text(
                text = stringResource(
                    R.string.routine_step_count_label,
                    model.staticActions.size.toString()
                ),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary
            )

            // Static Actions List
            for (action in model.staticActions) {
                Surface(
                    color = MaterialTheme.colorScheme.surface,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text(
                            text = bidiFormatter.wrapLtrToken(action.toolName, locale),
                            style = MaterialTheme.typography.labelLarge,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = action.requiredCapability.name,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        if (action.staticArguments.isNotEmpty()) {
                            val argsSummary = action.staticArguments.entries.joinToString(", ") { (k, v) ->
                                "$k=$v"
                            }
                            Text(
                                text = bidiFormatter.wrapText(argsSummary, locale),
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }
                }
            }

            // Clear warning for non-unattended actions (Biometric, Vault, MODIFY_DELETE_SEND)
            if (model.requiresInteractiveEscalationWarning) {
                Surface(
                    color = MaterialTheme.colorScheme.errorContainer,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text(
                            text = stringResource(
                                R.string.msg_routine_escalated_confirmation,
                                bidiFormatter.wrapLtrToken(
                                    model.nonUnattendedActionNames.joinToString(", "),
                                    locale
                                )
                            ),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.error
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = stringResource(R.string.confirmation_level_prompt_card_desc),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
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
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }

                when (approvalState) {
                    RuleApprovalState.PENDING_USER_APPROVAL -> {
                        Button(onClick = onApprove) {
                            Text(text = stringResource(R.string.action_approve))
                        }
                    }

                    RuleApprovalState.APPROVED_ACTIVE -> {
                        OutlinedButton(
                            onClick = onPause,
                            modifier = Modifier.padding(horizontal = 6.dp)
                        ) {
                            Text(text = stringResource(R.string.routine_action_pause))
                        }
                        Button(onClick = onRunNow) {
                            Text(text = stringResource(R.string.routine_action_run))
                        }
                    }

                    RuleApprovalState.PAUSED -> {
                        Button(onClick = onApprove) {
                            Text(text = stringResource(R.string.routine_action_resume))
                        }
                    }

                    RuleApprovalState.REVOKED -> Unit
                }
            }
        }
    }
}

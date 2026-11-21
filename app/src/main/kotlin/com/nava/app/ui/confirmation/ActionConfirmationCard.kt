package com.nava.app.ui.confirmation

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.nava.app.R
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.locale.NavaMessageRenderer
import com.nava.app.security.PendingConfirmationItem
import com.nava.app.security.PendingConfirmationSource
import com.nava.domain.security.DataProvenance
import java.util.Locale

/**
 * Pure-JVM presentation model for a single canonical slot argument inside [ActionConfirmationCard].
 */
data class ConfirmationSlotDisplayItem(
    val slotName: String,
    val rawCanonicalValue: String,
    val bidiWrappedCanonicalValue: String,
    val provenance: DataProvenance,
    val provenanceBadgeText: String,
    val isUntrustedExternal: Boolean,
    val requiresExplicitConfirmation: Boolean
)

/**
 * Pure-JVM presentation model for [ActionConfirmationCard], enabling deterministic unit testing
 * of canonical slot rendering, bidi wrapping, provenance badges, and untrusted warning elevation
 * across any UI language (PLAN.md Sections 5.4, 6.4, and 6.6).
 */
data class ActionConfirmationCardModel(
    val requestId: String,
    val renderedTitle: String,
    val renderedPrompt: String,
    val pendingToolName: String,
    val targetId: String,
    val requiresBiometric: Boolean,
    val showUntrustedWarningBadge: Boolean,
    val showHighRiskBadge: Boolean,
    val slots: List<ConfirmationSlotDisplayItem>
)

/**
 * Builds an [ActionConfirmationCardModel] from a [PendingConfirmationItem].
 *
 * Security & localization invariants (Requirement 4):
 * - Canonical slot values are ALWAYS displayed and wrapped via [BidiTextFormatter] regardless
 *   of the active UI language.
 * - [ActionConfirmationCardModel.showUntrustedWarningBadge] is `true` whenever
 *   `item.hasUntrustedHighRiskSlot == true` OR any canonical slot argument carries
 *   [DataProvenance.UNTRUSTED_EXTERNAL].
 */
fun buildActionConfirmationCardModel(
    item: PendingConfirmationItem,
    messageRenderer: NavaMessageRenderer,
    bidiFormatter: BidiTextFormatter,
    locale: Locale = Locale.forLanguageTag(item.languageTag)
): ActionConfirmationCardModel {
    val isRtl = BidiTextFormatter.isRtlLocale(locale)
    val (renderedTitle, renderedBody) = messageRenderer.render(item.confirmation.message, locale)

    val slotItems = item.confirmation.canonicalArguments.entries.map { (slotName, taintedVal) ->
        val rawValue = taintedVal.value
        val wrappedValue = if (looksLikeLtrCanonicalToken(slotName, rawValue)) {
            bidiFormatter.wrapLtrToken(rawValue, isRtlContext = isRtl)
        } else {
            bidiFormatter.wrapText(rawValue, isRtlContext = isRtl)
        }
        val provenanceBadge = formatProvenanceBadgeText(taintedVal.provenance, bidiFormatter, isRtl)
        ConfirmationSlotDisplayItem(
            slotName = bidiFormatter.wrapLtrToken(slotName, isRtlContext = isRtl),
            rawCanonicalValue = rawValue,
            bidiWrappedCanonicalValue = wrappedValue,
            provenance = taintedVal.provenance,
            provenanceBadgeText = provenanceBadge,
            isUntrustedExternal = taintedVal.provenance == DataProvenance.UNTRUSTED_EXTERNAL,
            requiresExplicitConfirmation = taintedVal.requiresExplicitConfirmation
        )
    }

    val anyUntrustedArg = slotItems.any { it.isUntrustedExternal }
    val showUntrustedBadge = item.hasUntrustedHighRiskSlot || anyUntrustedArg

    return ActionConfirmationCardModel(
        requestId = item.requestId,
        renderedTitle = renderedTitle,
        renderedPrompt = renderedBody,
        pendingToolName = bidiFormatter.wrapLtrToken(item.confirmation.pendingToolName, isRtlContext = isRtl),
        targetId = bidiFormatter.wrapLtrToken(item.targetId, isRtlContext = isRtl),
        requiresBiometric = item.requiresBiometric,
        showUntrustedWarningBadge = showUntrustedBadge,
        showHighRiskBadge = item.hasUntrustedHighRiskSlot,
        slots = slotItems
    )
}

private fun looksLikeLtrCanonicalToken(slotName: String, rawValue: String): Boolean {
    val lowerName = slotName.lowercase(Locale.US)
    if (lowerName.contains("time") ||
        lowerName.contains("date") ||
        lowerName.contains("phone") ||
        lowerName.contains("number") ||
        lowerName.contains("uri") ||
        lowerName.contains("package") ||
        lowerName.contains("recipient") ||
        lowerName.contains("duration") ||
        lowerName.contains("hour") ||
        lowerName.contains("minute")
    ) {
        return true
    }
    return rawValue.startsWith("+") ||
        rawValue.startsWith("content://") ||
        rawValue.startsWith("saf:") ||
        rawValue.all { it.isDigit() || it == ':' || it == '-' || it == '.' || it == '+' || it == ' ' }
}

private fun formatProvenanceBadgeText(
    provenance: DataProvenance,
    bidiFormatter: BidiTextFormatter,
    isRtl: Boolean
): String {
    val label = when (provenance) {
        DataProvenance.USER_UTTERANCE -> "USER_UTTERANCE"
        DataProvenance.SYSTEM -> "SYSTEM"
        DataProvenance.UNTRUSTED_EXTERNAL -> "UNTRUSTED_EXTERNAL"
    }
    return bidiFormatter.wrapLtrToken(label, isRtlContext = isRtl)
}

/**
 * Compact Material 3 Action Confirmation Card / Sheet (PLAN.md Sections 5.4 & 6.4).
 *
 * - Presents `[Approve]`, `[Edit]`, and `[Cancel]` actions.
 * - Always displays canonical slot values wrapped with [BidiTextFormatter] and provenance badges.
 * - Displays prominent untrusted-source warning badge whenever `hasUntrustedHighRiskSlot` is true
 *   or any argument originates from [DataProvenance.UNTRUSTED_EXTERNAL].
 * - Supports inline slot editing sanitized via `PendingConfirmationStore.updateEditedSlot`.
 */
@Composable
fun ActionConfirmationCard(
    item: PendingConfirmationItem,
    messageRenderer: NavaMessageRenderer,
    bidiFormatter: BidiTextFormatter,
    locale: Locale,
    onApprove: (requestId: String) -> Unit,
    onEditSlot: (requestId: String, slotName: String, newValue: String) -> Unit,
    onCancel: (requestId: String) -> Unit,
    modifier: Modifier = Modifier
) {
    val model = remember(item, locale) {
        buildActionConfirmationCardModel(
            item = item,
            messageRenderer = messageRenderer,
            bidiFormatter = bidiFormatter,
            locale = locale
        )
    }

    val isEditable = item.source != PendingConfirmationSource.ESCALATED_ROUTINE &&
        model.slots.isNotEmpty()
    var isEditing by remember(item.requestId) { mutableStateOf(false) }
    val draftValues = remember(item.requestId) {
        mutableStateMapOf<String, String>().apply {
            for ((k, v) in item.confirmation.canonicalArguments) {
                put(k, v.value)
            }
        }
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 6.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text(
                text = if (model.requiresBiometric) {
                    stringResource(R.string.confirm_biometric_title)
                } else {
                    stringResource(R.string.confirm_title)
                },
                style = MaterialTheme.typography.titleLarge,
                color = if (model.requiresBiometric) {
                    MaterialTheme.colorScheme.tertiary
                } else {
                    MaterialTheme.colorScheme.primary
                }
            )

            Text(
                text = if (model.requiresBiometric) {
                    stringResource(R.string.confirm_biometric_prompt_text)
                } else {
                    stringResource(R.string.confirm_prompt_text)
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Text(
                text = model.renderedPrompt,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onSurface
            )

            if (model.showUntrustedWarningBadge) {
                Surface(
                    color = MaterialTheme.colorScheme.errorContainer,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text(
                            text = stringResource(R.string.warning_untrusted_external_source),
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.error
                        )
                        Text(
                            text = stringResource(R.string.confirm_untrusted_warning),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                        if (model.showHighRiskBadge) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = stringResource(R.string.confirm_high_risk_badge),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                }
            }

            Text(
                text = stringResource(R.string.confirm_tool_label, model.pendingToolName),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = stringResource(R.string.confirm_target_label, model.targetId),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            if (model.slots.isNotEmpty()) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            color = MaterialTheme.colorScheme.surface,
                            shape = RoundedCornerShape(10.dp)
                        )
                        .padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    for ((index, slot) in model.slots.withIndex()) {
                        val rawSlotKey = item.confirmation.canonicalArguments.keys.elementAtOrNull(index)
                            ?: slot.slotName
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = slot.slotName,
                                    style = MaterialTheme.typography.labelMedium,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.primary
                                )
                                Text(
                                    text = slot.provenanceBadgeText,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (slot.isUntrustedExternal) {
                                        MaterialTheme.colorScheme.error
                                    } else {
                                        MaterialTheme.colorScheme.onSurfaceVariant
                                    }
                                )
                            }

                            if (isEditing && isEditable) {
                                val currentDraft = draftValues[rawSlotKey] ?: slot.rawCanonicalValue
                                OutlinedTextField(
                                    value = currentDraft,
                                    onValueChange = { updated ->
                                        draftValues[rawSlotKey] = updated
                                        onEditSlot(item.requestId, rawSlotKey, updated)
                                    },
                                    singleLine = true,
                                    modifier = Modifier.fillMaxWidth(),
                                    textStyle = MaterialTheme.typography.bodyMedium.copy(
                                        fontFamily = FontFamily.Monospace
                                    )
                                )
                            } else {
                                Text(
                                    text = slot.bidiWrappedCanonicalValue,
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                            }
                        }
                    }
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton(
                    onClick = { onCancel(item.requestId) }
                ) {
                    Text(text = stringResource(R.string.confirm_button_cancel))
                }

                if (isEditable) {
                    OutlinedButton(
                        onClick = { isEditing = !isEditing },
                        modifier = Modifier.padding(horizontal = 8.dp)
                    ) {
                        Text(text = stringResource(R.string.confirm_button_edit))
                    }
                }

                Button(
                    onClick = { onApprove(item.requestId) },
                    colors = if (model.requiresBiometric) {
                        ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.tertiary,
                            contentColor = MaterialTheme.colorScheme.onTertiary
                        )
                    } else {
                        ButtonDefaults.buttonColors()
                    }
                ) {
                    Text(text = stringResource(R.string.confirm_button_approve))
                }
            }
        }
    }
}

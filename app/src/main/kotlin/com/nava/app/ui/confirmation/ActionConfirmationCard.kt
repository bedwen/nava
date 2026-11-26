package com.nava.app.ui.confirmation

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.BottomSheetDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
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
import androidx.compose.ui.unit.dp
import com.nava.app.R
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.locale.NavaMessageRenderer
import com.nava.app.security.PendingConfirmationItem
import com.nava.app.security.PendingConfirmationSource
import com.nava.app.ui.theme.NavaThemeExtras
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
    val colors = NavaThemeExtras.colors
    val haptics = LocalHapticFeedback.current
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

    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = colors.surfaceCard,
        border = BorderStroke(1.dp, colors.borderStone)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Top monospace tool label + confirmation title
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = model.pendingToolName,
                    style = MaterialTheme.typography.labelMedium,
                    fontFamily = FontFamily.Monospace,
                    color = colors.trustNavyTint
                )

                Text(
                    text = if (model.requiresBiometric) {
                        stringResource(R.string.confirm_biometric_title)
                    } else {
                        stringResource(R.string.confirm_title)
                    },
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = if (model.requiresBiometric) {
                        colors.verifiedForest
                    } else {
                        colors.inkPrimary
                    }
                )
            }

            Text(
                text = if (model.requiresBiometric) {
                    stringResource(R.string.confirm_biometric_prompt_text)
                } else {
                    stringResource(R.string.confirm_prompt_text)
                },
                style = MaterialTheme.typography.bodyMedium,
                color = colors.inkSecondary
            )

            Text(
                text = model.renderedPrompt,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium,
                color = colors.inkPrimary
            )

            if (model.showUntrustedWarningBadge) {
                Surface(
                    color = colors.untrustedSurface,
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, colors.borderStone),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(IntrinsicSize.Min)
                    ) {
                        Box(
                            modifier = Modifier
                                .width(3.dp)
                                .fillMaxHeight()
                                .background(colors.untrustedAccent)
                        )
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = stringResource(R.string.warning_untrusted_external_source),
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold,
                                color = colors.untrustedAccent
                            )
                            Text(
                                text = stringResource(R.string.confirm_untrusted_warning),
                                style = MaterialTheme.typography.bodySmall,
                                color = colors.inkPrimary
                            )
                            if (model.showHighRiskBadge) {
                                Text(
                                    text = stringResource(R.string.confirm_high_risk_badge),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Bold,
                                    color = colors.untrustedAccent
                                )
                            }
                        }
                    }
                }
            }

            Text(
                text = stringResource(R.string.confirm_target_label, model.targetId),
                style = MaterialTheme.typography.labelMedium,
                fontFamily = FontFamily.Monospace,
                color = colors.inkSecondary
            )

            if (model.slots.isNotEmpty()) {
                Surface(
                    color = colors.bgLinen,
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, colors.borderStone),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        for ((index, slot) in model.slots.withIndex()) {
                            if (index > 0) {
                                HorizontalDivider(
                                    thickness = 0.5.dp,
                                    color = colors.borderStone
                                )
                            }
                            val rawSlotKey =
                                item.confirmation.canonicalArguments.keys.elementAtOrNull(index)
                                    ?: slot.slotName
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
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
                                        color = colors.trustNavyTint
                                    )
                                    Text(
                                        text = slot.provenanceBadgeText,
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        color = if (slot.isUntrustedExternal) {
                                            colors.untrustedAccent
                                        } else {
                                            colors.inkMuted
                                        }
                                    )
                                }

                                if (isEditing && isEditable) {
                                    val currentDraft =
                                        draftValues[rawSlotKey] ?: slot.rawCanonicalValue
                                    OutlinedTextField(
                                        value = currentDraft,
                                        onValueChange = { updated ->
                                            draftValues[rawSlotKey] = updated
                                            onEditSlot(item.requestId, rawSlotKey, updated)
                                        },
                                        singleLine = true,
                                        modifier = Modifier.fillMaxWidth(),
                                        textStyle = MaterialTheme.typography.bodyMedium.copy(
                                            fontFamily = FontFamily.Monospace,
                                            color = colors.inkPrimary
                                        ),
                                        colors = OutlinedTextFieldDefaults.colors(
                                            focusedBorderColor = colors.trustNavyTint,
                                            unfocusedBorderColor = colors.borderStone,
                                            focusedContainerColor = colors.surfaceCard,
                                            unfocusedContainerColor = colors.surfaceCard
                                        )
                                    )
                                } else {
                                    Text(
                                        text = slot.bidiWrappedCanonicalValue,
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontFamily = FontFamily.Monospace,
                                        color = colors.inkPrimary
                                    )
                                }
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
                    onClick = {
                        haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onCancel(item.requestId)
                    }
                ) {
                    Text(
                        text = stringResource(R.string.confirm_button_cancel),
                        color = colors.inkSecondary
                    )
                }

                if (isEditable) {
                    OutlinedButton(
                        onClick = {
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            isEditing = !isEditing
                        },
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, colors.borderStone),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = colors.inkPrimary
                        ),
                        modifier = Modifier.padding(horizontal = 8.dp)
                    ) {
                        Text(text = stringResource(R.string.confirm_button_edit))
                    }
                }

                Button(
                    onClick = {
                        haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                        onApprove(item.requestId)
                    },
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (model.requiresBiometric) {
                            colors.verifiedForest
                        } else {
                            colors.trustNavy
                        },
                        contentColor = Color.White
                    )
                ) {
                    Text(text = stringResource(R.string.confirm_button_approve))
                }
            }
        }
    }
}

/**
 * Material 3 modal bottom sheet wrapper hosting [ActionConfirmationCard] for the Neural Hub.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ActionConfirmationBottomSheet(
    item: PendingConfirmationItem,
    messageRenderer: NavaMessageRenderer,
    bidiFormatter: BidiTextFormatter,
    locale: Locale,
    onApprove: (requestId: String) -> Unit,
    onEditSlot: (requestId: String, slotName: String, newValue: String) -> Unit,
    onCancel: (requestId: String) -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = NavaThemeExtras.colors
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    ModalBottomSheet(
        onDismissRequest = { onCancel(item.requestId) },
        sheetState = sheetState,
        containerColor = colors.surfaceCard,
        contentColor = colors.inkPrimary,
        shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
        dragHandle = {
            BottomSheetDefaults.DragHandle(color = colors.borderStone)
        },
        modifier = modifier
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
                .padding(bottom = 24.dp)
        ) {
            ActionConfirmationCard(
                item = item,
                messageRenderer = messageRenderer,
                bidiFormatter = bidiFormatter,
                locale = locale,
                onApprove = onApprove,
                onEditSlot = onEditSlot,
                onCancel = onCancel
            )
        }
    }
}

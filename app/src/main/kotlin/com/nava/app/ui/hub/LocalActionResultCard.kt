package com.nava.app.ui.hub

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.ui.unit.sp
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.nava.app.R
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.ui.components.NavaIcons
import com.nava.app.ui.theme.NavaThemeExtras
import com.nava.domain.ui.MessageKey
import java.util.Locale

/**
 * Visual card archetype for completed local assistant actions and replies in the Result Dock.
 */
enum class LocalActionCardKind {
    ALARM,
    NOTE,
    CALENDAR,
    SUMMARY,
    GENERAL
}

/**
 * Deterministically maps a structured [MessageKey] (from `:domain`) to a [LocalActionCardKind]
 * without relying on fragile localized string matching (Iron Law 1).
 */
@Suppress("UNUSED_PARAMETER")
fun inferLocalActionCardKind(
    lastMessageKey: MessageKey?,
    statusTitle: String?,
    statusMessage: String?
): LocalActionCardKind {
    return when (lastMessageKey) {
        MessageKey.ACTION_ALARM_SET,
        MessageKey.ACTION_TIMER_SET,
        MessageKey.ACTION_REMINDER_SCHEDULED,
        MessageKey.ACTION_REMINDER_CANCELLED -> LocalActionCardKind.ALARM

        MessageKey.ACTION_NOTE_SAVED,
        MessageKey.ACTION_NOTE_READ,
        MessageKey.ACTION_NOTE_DELETED,
        MessageKey.ACTION_NOTES_SEARCHED,
        MessageKey.ACTION_VOICE_NOTE_STRUCTURED,
        MessageKey.ACTION_VAULT_NOTE_SAVED,
        MessageKey.ACTION_VAULT_NOTE_READ,
        MessageKey.ACTION_VAULT_NOTE_DELETED -> LocalActionCardKind.NOTE

        MessageKey.ACTION_CALENDAR_EVENT_CREATED,
        MessageKey.ACTION_CALENDAR_EVENTS_QUERIED,
        MessageKey.ACTION_CALENDAR_EVENT_UPDATED,
        MessageKey.ACTION_CALENDAR_EVENT_DELETED -> LocalActionCardKind.CALENDAR

        MessageKey.ACTION_NOTIFICATIONS_SUMMARIZED,
        MessageKey.ACTION_NOTIFICATIONS_EMPTY,
        MessageKey.ACTION_BRIEFING_READY,
        MessageKey.INFO_NO_PERMITTED_NOTIFICATION_APPS,
        MessageKey.ACTION_WATCHER_CREATED,
        MessageKey.ACTION_WATCHER_DELETED,
        MessageKey.ACTION_WATCHERS_LISTED -> LocalActionCardKind.SUMMARY

        else -> LocalActionCardKind.GENERAL
    }
}

/**
 * Warm Paper / Matte OLED Dark local action result card for the Neural Hub Result Dock,
 * surfacing a verified status badge and kind-specific interactive controls for alarms and notes.
 */
@Composable
fun LocalActionResultCard(
    kind: LocalActionCardKind,
    title: String?,
    body: String?,
    conversationalReply: String?,
    bidiFormatter: BidiTextFormatter,
    activeLocale: Locale,
    onUndoOrClear: () -> Unit,
    modifier: Modifier = Modifier,
    isError: Boolean = false,
    onGrantPermission: (() -> Unit)? = null
) {
    val colors = NavaThemeExtras.colors
    val haptics = LocalHapticFeedback.current

    val rawPrimary = body?.takeIf { it.isNotBlank() }
        ?: conversationalReply?.takeIf { it.isNotBlank() }
    val primaryText = rawPrimary?.replace("**", "")
    val secondaryReply = conversationalReply?.takeIf {
        it.isNotBlank() && it != rawPrimary
    }?.replace("**", "")

    val isRichActionCard = !isError && kind != LocalActionCardKind.GENERAL
    val splitIndex = primaryText?.indexOf("\n\n") ?: -1
    val cardHeadline = if (isRichActionCard && primaryText != null && splitIndex > 0) {
        primaryText.substring(0, splitIndex).trim()
    } else {
        null
    }
    val cardDetails = if (isRichActionCard && primaryText != null && splitIndex > 0) {
        primaryText.substring(splitIndex + 2).trim().takeIf { it.isNotEmpty() }
    } else {
        null
    }

    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Start
    ) {
        Surface(
            color = if (isError) colors.untrustedSurface else colors.surfaceCard,
            shape = RoundedCornerShape(
                topStart = 14.dp,
                topEnd = 14.dp,
                bottomStart = 4.dp,
                bottomEnd = 14.dp
            ),
            border = if (isRichActionCard) BorderStroke(1.dp, colors.borderStone) else null,
            modifier = if (isRichActionCard) {
                Modifier.fillMaxWidth(0.95f)
            } else {
                Modifier.widthIn(max = 330.dp)
            }
        ) {
            Column(
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                if (isRichActionCard) {
                    val categoryLabel = when (kind) {
                        LocalActionCardKind.CALENDAR -> stringResource(R.string.card_label_calendar)
                        LocalActionCardKind.SUMMARY -> stringResource(R.string.card_label_notifications)
                        LocalActionCardKind.NOTE -> stringResource(R.string.card_label_note)
                        LocalActionCardKind.ALARM -> stringResource(R.string.card_label_alarm)
                        LocalActionCardKind.GENERAL -> null
                    }
                    if (categoryLabel != null) {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = iconForActionKind(kind),
                                contentDescription = null,
                                tint = colors.trustNavyTint,
                                modifier = Modifier.size(14.dp)
                            )
                            Text(
                                text = categoryLabel.uppercase(activeLocale),
                                style = MaterialTheme.typography.labelSmall.copy(letterSpacing = 0.6.sp),
                                fontWeight = FontWeight.SemiBold,
                                color = colors.trustNavyTint
                            )
                        }
                    }
                }

                if (primaryText != null) {
                    if (isError) {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            Icon(
                                imageVector = NavaIcons.Shield,
                                contentDescription = null,
                                tint = colors.untrustedAccent,
                                modifier = Modifier
                                    .padding(top = 2.dp)
                                    .size(15.dp)
                            )
                            Text(
                                text = bidiFormatter.wrapText(primaryText, activeLocale),
                                style = MaterialTheme.typography.bodySmall,
                                color = colors.untrustedAccent
                            )
                        }
                    } else if (cardHeadline != null && cardDetails != null) {
                        Text(
                            text = bidiFormatter.wrapText(cardHeadline, activeLocale),
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = colors.inkPrimary
                        )
                        HorizontalDivider(
                            thickness = 0.5.dp,
                            color = colors.borderStone.copy(alpha = 0.7f)
                        )
                        Text(
                            text = bidiFormatter.wrapText(cardDetails, activeLocale),
                            style = MaterialTheme.typography.bodySmall.copy(lineHeight = 20.sp),
                            color = colors.inkSecondary
                        )
                    } else {
                        Text(
                            text = bidiFormatter.wrapText(primaryText, activeLocale),
                            style = MaterialTheme.typography.bodySmall.copy(lineHeight = 20.sp),
                            fontWeight = if (isRichActionCard) FontWeight.Medium else FontWeight.Normal,
                            color = colors.inkPrimary
                        )
                    }
                }
                if (secondaryReply != null) {
                    Text(
                        text = bidiFormatter.wrapText(secondaryReply, activeLocale),
                        style = MaterialTheme.typography.bodySmall.copy(lineHeight = 20.sp),
                        color = colors.inkSecondary
                    )
                }
                if (isError && onGrantPermission != null) {
                    TextButton(
                        onClick = {
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onGrantPermission()
                        },
                        contentPadding = PaddingValues(horizontal = 4.dp, vertical = 2.dp)
                    ) {
                        Text(
                            text = stringResource(R.string.action_grant_permission),
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = colors.trustNavyTint
                        )
                    }
                }
            }
        }
    }
}

private val ALARM_TIME_REGEX = Regex("""\b([01]?\d|2[0-3]):[0-5]\d\b""")

internal fun extractAlarmTimeOrNull(text: String?): String? {
    if (text.isNullOrBlank()) return null
    return ALARM_TIME_REGEX.find(text)?.value
}

private fun iconForActionKind(kind: LocalActionCardKind): ImageVector {
    return when (kind) {
        LocalActionCardKind.ALARM -> NavaIcons.Clock
        LocalActionCardKind.NOTE -> NavaIcons.Notes
        LocalActionCardKind.CALENDAR -> NavaIcons.Calendar
        LocalActionCardKind.SUMMARY -> NavaIcons.Messages
        LocalActionCardKind.GENERAL -> NavaIcons.Check
    }
}

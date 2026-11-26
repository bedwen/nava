package com.nava.app.ui.vault

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.nava.app.R
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.ui.components.NavaIcons
import com.nava.app.ui.theme.NavaThemeExtras
import com.nava.feature.automations.briefing.DailyBriefingResult
import java.util.Locale

/**
 * "Today" timeline at the top of My Day: today's calendar events, reminders due in the next
 * day, and urgent notifications, built by `DailyBriefingBuilder` (which already enforces each
 * source's permission profile). Display only: nothing here is fed back to the planner.
 */
@Composable
fun TodayOverviewSection(
    overview: DailyBriefingResult?,
    bidiFormatter: BidiTextFormatter,
    activeLocale: Locale,
    modifier: Modifier = Modifier
) {
    val colors = NavaThemeExtras.colors
    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(
            text = stringResource(R.string.today_title),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
            color = colors.inkPrimary
        )
        Surface(
            color = colors.surfaceCard,
            shape = RoundedCornerShape(16.dp),
            border = BorderStroke(1.dp, colors.borderStone),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                val hasAny = overview != null && overview.totalItemCount > 0
                if (!hasAny) {
                    Text(
                        text = stringResource(R.string.today_empty),
                        style = MaterialTheme.typography.bodyMedium,
                        color = colors.inkSecondary
                    )
                    Text(
                        text = stringResource(R.string.today_empty_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.inkMuted
                    )
                } else {
                    var first = true
                    val packageManager = androidx.compose.ui.platform.LocalContext.current.packageManager
                    val sections = listOf(
                        Triple(NavaIcons.Calendar, R.string.today_section_calendar, overview!!.calendarLines),
                        Triple(NavaIcons.Clock, R.string.today_section_reminders, overview.reminderLines),
                        Triple(NavaIcons.Shield, R.string.today_section_urgent, overview.urgentNotificationLines.map { friendlyNotificationLine(it, packageManager) })
                    )
                    for ((icon, labelRes, lines) in sections) {
                        if (lines.isEmpty()) continue
                        if (!first) {
                            HorizontalDivider(thickness = 0.5.dp, color = colors.borderStone)
                        }
                        first = false
                        TodaySection(icon, stringResource(labelRes), lines, bidiFormatter, activeLocale)
                    }
                    if (overview.infoNotificationLines.isNotEmpty()) {
                        Text(
                            text = stringResource(R.string.today_other_notifications, overview.infoNotificationLines.size),
                            style = MaterialTheme.typography.labelSmall,
                            color = colors.inkMuted
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun TodaySection(
    icon: ImageVector,
    label: String,
    lines: List<String>,
    bidiFormatter: BidiTextFormatter,
    activeLocale: Locale
) {
    val colors = NavaThemeExtras.colors
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(imageVector = icon, contentDescription = null, tint = colors.trustNavyTint, modifier = Modifier.size(14.dp))
            Text(
                text = label.uppercase(activeLocale),
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.SemiBold,
                color = colors.trustNavyTint
            )
        }
        for (line in lines) {
            Text(
                text = bidiFormatter.wrapText(line, activeLocale),
                style = MaterialTheme.typography.bodySmall,
                color = colors.inkPrimary,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

/** "[com.google.android.gm] Title: body" -> "Gmail - Title: body" using the installed app label. */
internal fun friendlyNotificationLine(line: String, packageManager: android.content.pm.PackageManager?): String {
    if (!line.startsWith("[")) return line
    val close = line.indexOf(']')
    if (close <= 1) return line
    val pkg = line.substring(1, close)
    val rest = line.substring(close + 1).trim()
    val label = packageManager?.let { pm ->
        runCatching {
            pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
        }.getOrNull()
    }?.takeIf { it.isNotBlank() } ?: pkg.substringAfterLast('.')
    return "$label - $rest"
}

/**
 * "What I remember" list on My Day: every fact the user asked Nava to remember, each with a
 * one-tap forget action. Facts are stored encrypted on the device only.
 */
@Composable
fun PersonalMemorySection(
    facts: List<com.nava.domain.memory.PersonalFact>,
    bidiFormatter: BidiTextFormatter,
    activeLocale: Locale,
    onForget: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = NavaThemeExtras.colors
    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(
            text = stringResource(R.string.memory_section_title),
            style = MaterialTheme.typography.labelLarge,
            fontWeight = FontWeight.SemiBold,
            color = colors.inkMuted
        )
        Surface(
            color = colors.surfaceCard,
            shape = RoundedCornerShape(16.dp),
            border = BorderStroke(1.dp, colors.borderStone),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                if (facts.isEmpty()) {
                    Text(
                        text = stringResource(R.string.memory_section_empty),
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.inkSecondary
                    )
                } else {
                    for (fact in facts) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = bidiFormatter.wrapText(fact.text, activeLocale),
                                style = MaterialTheme.typography.bodySmall,
                                color = colors.inkPrimary,
                                modifier = Modifier.weight(1f)
                            )
                            androidx.compose.material3.TextButton(onClick = { onForget(fact.factId) }) {
                                Text(
                                    text = stringResource(R.string.memory_forget),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = colors.untrustedAccent
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

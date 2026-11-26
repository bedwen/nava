package com.nava.app.ui.hub

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.nava.app.R
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.ui.components.NavaIcons
import com.nava.app.ui.profiles.localizedCapabilityTitle
import com.nava.app.ui.profiles.localizedTargetLabel
import com.nava.app.ui.theme.NavaThemeExtras
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.ConfirmationLevel
import java.util.Locale

/**
 * Plain-language denial card shown when the firewall blocked a command for a missing capability.
 * When [grantOffered] is true it offers a one-tap grant scoped to this target only: "ask every
 * time" (PROMPT_CARD) and, where structurally allowed, "always allow" (AUTO). Otherwise it only
 * links to the permission settings.
 */
@Composable
fun PermissionGrantCard(
    targetId: String,
    capability: AtomicCapability,
    grantOffered: Boolean,
    bidiFormatter: BidiTextFormatter,
    activeLocale: Locale,
    onGrant: (ConfirmationLevel) -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = NavaThemeExtras.colors
    val haptics = LocalHapticFeedback.current
    val targetLabel = localizedTargetLabel(targetId)
    val capabilityLabel = localizedCapabilityTitle(capability)
    val body = stringResource(R.string.permission_needed_body, targetLabel, capabilityLabel)
    val canAlwaysAllow = ConfirmationLevel.AUTO.isValidFor(capability)

    Row(modifier = modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Start) {
        Surface(
            color = colors.surfaceCard,
            shape = RoundedCornerShape(topStart = 14.dp, topEnd = 14.dp, bottomStart = 4.dp, bottomEnd = 14.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, colors.borderStone),
            modifier = Modifier.widthIn(max = 340.dp)
        ) {
            Column(
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = NavaIcons.Shield,
                        contentDescription = null,
                        tint = colors.trustNavyTint,
                        modifier = Modifier.size(15.dp)
                    )
                    Text(
                        text = stringResource(R.string.permission_needed_title),
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.SemiBold,
                        color = colors.inkPrimary
                    )
                }
                Text(
                    text = bidiFormatter.wrapText(body, activeLocale),
                    style = MaterialTheme.typography.bodySmall,
                    color = colors.inkSecondary
                )
                if (grantOffered) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (canAlwaysAllow) {
                            Button(
                                onClick = {
                                    haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    onGrant(ConfirmationLevel.AUTO)
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = colors.trustNavy),
                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                            ) {
                                Text(
                                    text = stringResource(R.string.permission_grant_always),
                                    style = MaterialTheme.typography.labelMedium
                                )
                            }
                        }
                        OutlinedButton(
                            onClick = {
                                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                onGrant(ConfirmationLevel.PROMPT_CARD)
                            },
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                        ) {
                            Text(
                                text = stringResource(R.string.permission_grant_ask_each_time),
                                style = MaterialTheme.typography.labelMedium,
                                color = colors.trustNavyTint
                            )
                        }
                    }
                }
                TextButton(
                    onClick = onOpenSettings,
                    contentPadding = PaddingValues(horizontal = 4.dp, vertical = 0.dp)
                ) {
                    Text(
                        text = stringResource(R.string.permission_open_settings),
                        style = MaterialTheme.typography.labelSmall,
                        color = colors.inkMuted
                    )
                }
            }
        }
    }
}

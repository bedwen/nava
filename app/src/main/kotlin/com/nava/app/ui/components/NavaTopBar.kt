package com.nava.app.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.nava.app.R
import com.nava.app.ui.theme.NavaThemeExtras
import java.util.Locale

/**
 * Persistent Material 3 top bar for Nava's edge-to-edge layout.
 *
 * Displays either a back button (on sub-screens such as Settings) or the Nava concentric ring
 * emblem + lowercase bold wordmark, along with soft circular icon containers for notifications,
 * light/dark toggle, settings shortcut, and a clickable Ready status pill that toggles HUD visibility.
 */
@Composable
fun NavaTopBar(
    showBackButton: Boolean,
    isDarkTheme: Boolean,
    hasPendingConfirmations: Boolean,
    isSettingsActive: Boolean,
    onBackClick: () -> Unit,
    onNotificationsClick: () -> Unit,
    onToggleTheme: () -> Unit,
    onSettingsClick: () -> Unit,
    onStatusPillClick: () -> Unit,
    modifier: Modifier = Modifier,
    isStatusActive: Boolean = false
) {
    val extendedColors = NavaThemeExtras.colors
    val hudToggleDesc = stringResource(R.string.topbar_hud_toggle)

    Surface(
        color = extendedColors.bgPaper,
        modifier = modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .statusBarsPadding()
                    .height(56.dp)
                    .padding(horizontal = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                if (showBackButton) {
                    IconButton(onClick = onBackClick) {
                        Icon(
                            imageVector = NavaIcons.BackArrow,
                            contentDescription = stringResource(R.string.topbar_back),
                            tint = extendedColors.inkPrimary,
                            modifier = Modifier.size(22.dp)
                        )
                    }
                } else {
                    val appNameDesc = stringResource(R.string.app_name)
                    Box(
                        modifier = Modifier
                            .padding(start = 2.dp)
                            .semantics { contentDescription = appNameDesc },
                        contentAlignment = Alignment.CenterStart
                    ) {
                        Icon(
                            imageVector = NavaIcons.BrandMarkRing,
                            contentDescription = null,
                            tint = extendedColors.trustNavyTint,
                            modifier = Modifier.height(26.dp)
                        )
                        Icon(
                            imageVector = NavaIcons.BrandMarkWordmark,
                            contentDescription = null,
                            tint = extendedColors.inkPrimary,
                            modifier = Modifier.height(26.dp)
                        )
                    }
                }

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    if (hasPendingConfirmations) {
                        Surface(
                            onClick = onNotificationsClick,
                            shape = CircleShape,
                            color = extendedColors.bgLinen,
                            modifier = Modifier.size(36.dp)
                        ) {
                            Box(
                                modifier = Modifier.fillMaxSize(),
                                contentAlignment = Alignment.Center
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    Icon(
                                        imageVector = NavaIcons.Bell,
                                        contentDescription = stringResource(R.string.topbar_notifications),
                                        tint = extendedColors.inkSecondary,
                                        modifier = Modifier.size(18.dp)
                                    )
                                    Box(
                                        modifier = Modifier
                                            .align(Alignment.TopEnd)
                                            .size(6.dp)
                                            .background(
                                                color = extendedColors.untrustedAccent,
                                                shape = CircleShape
                                            )
                                    )
                                }
                            }
                        }
                    }

                    Surface(
                        onClick = onSettingsClick,
                        shape = CircleShape,
                        color = extendedColors.bgLinen,
                        modifier = Modifier.size(36.dp)
                    ) {
                        Box(
                            modifier = Modifier.fillMaxSize(),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = NavaIcons.AuditList,
                                contentDescription = stringResource(R.string.nav_audit),
                                tint = if (isSettingsActive) {
                                    extendedColors.trustNavyTint
                                } else {
                                    extendedColors.inkSecondary
                                },
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }

                    Surface(
                        shape = RoundedCornerShape(18.dp),
                        color = extendedColors.bgLinen,
                        modifier = Modifier.semantics {
                            contentDescription = hudToggleDesc
                        }
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(5.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .background(
                                        color = if (isStatusActive) {
                                            extendedColors.verifiedForest
                                        } else {
                                            extendedColors.inkMuted
                                        },
                                        shape = CircleShape
                                    )
                            )
                            Text(
                                text = stringResource(R.string.topbar_status_ready),
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Medium,
                                color = extendedColors.inkSecondary,
                                maxLines = 1
                            )
                        }
                    }
                }
            }

            HorizontalDivider(
                thickness = 1.dp,
                color = extendedColors.borderStone
            )
        }
    }
}

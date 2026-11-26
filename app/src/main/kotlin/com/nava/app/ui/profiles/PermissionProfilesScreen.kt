package com.nava.app.ui.profiles

import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.nava.app.R
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.ui.theme.NavaThemeExtras
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.PermissionProfile
import com.nava.feature.automations.common.InstalledAppInfo
import com.nava.feature.automations.common.ToolTargetIds
import java.util.Locale

private const val TAB_FEATURES: Int = 0
private const val TAB_APPS: Int = 1

/**
 * Clean, direct Security & Permissions screen with a 2-tab layout (Features & Installed Apps):
 * - Features tab: Single vertical list of all Nava features and granted SAF folders with clear
 *   status pills and inline Android OS permission indicators. Tapping any feature opens an
 *   in-place bottom sheet showing its relevant capabilities first (Off / Auto / Ask / Biometric),
 *   with all 5 orthogonal capabilities accessible under the expandable "All 5 capabilities" toggle.
 * - Apps tab: Searchable list of all installed apps with human-readable capability badges, a
 *   1-tap inline notification toggle, bulk controls, and a full per-app detail bottom sheet.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PermissionProfilesScreen(
    viewModel: PermissionProfilesViewModel,
    bidiFormatter: BidiTextFormatter,
    activeLocale: Locale = Locale.forLanguageTag("en"),
    initialFocusedTargetId: String? = null,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    val haptics = LocalHapticFeedback.current
    val locale = activeLocale
    val colors = NavaThemeExtras.colors

    val startsOnAppsTab = !initialFocusedTargetId.isNullOrBlank() &&
        !initialFocusedTargetId.startsWith("system.") &&
        !initialFocusedTargetId.startsWith("nava.") &&
        !initialFocusedTargetId.startsWith("saf:")

    var selectedTab by remember(initialFocusedTargetId) {
        mutableIntStateOf(if (startsOnAppsTab) TAB_APPS else TAB_FEATURES)
    }
    var activeFeatureTargetId by remember(initialFocusedTargetId) {
        mutableStateOf(
            if (!initialFocusedTargetId.isNullOrBlank() && !startsOnAppsTab) {
                initialFocusedTargetId
            } else {
                null
            }
        )
    }
    var activeAppForSheet by remember { mutableStateOf<InstalledAppInfo?>(null) }
    var showAllFeatureCapabilities by remember { mutableStateOf(false) }
    var showAllAppCapabilities by remember { mutableStateOf(false) }
    var showBulkFeatures by remember { mutableStateOf(false) }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                viewModel.refreshProfilesAndTarget(syncSelectedProfileToTarget = true)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
        }
    }

    LaunchedEffect(initialFocusedTargetId) {
        if (!initialFocusedTargetId.isNullOrBlank()) {
            viewModel.selectTarget(initialFocusedTargetId)
        } else {
            viewModel.refreshProfilesAndTarget(syncSelectedProfileToTarget = true)
        }
    }

    LaunchedEffect(initialFocusedTargetId, state.installedApps) {
        if (startsOnAppsTab && activeAppForSheet == null && !initialFocusedTargetId.isNullOrBlank()) {
            val matched = state.installedApps.firstOrNull { it.packageName == initialFocusedTargetId }
            if (matched != null) {
                activeAppForSheet = matched
            }
        }
    }

    val safTreeLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { treeUri ->
        if (treeUri != null) {
            val takeFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            runCatching {
                context.contentResolver.takePersistableUriPermission(treeUri, takeFlags)
            }
            viewModel.onSafDirectoryGranted(
                treeUriString = treeUri.toString(),
                profileId = PermissionProfile.DEFAULT_DENY_PROFILE_ID
            )
        }
    }

    val notifPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) {
        viewModel.refreshProfilesAndTarget()
    }

    val calendarPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) {
        viewModel.refreshProfilesAndTarget()
    }

    val phonePermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) {
        viewModel.refreshProfilesAndTarget()
    }

    val openNotificationListenerSettings: () -> Unit = {
        runCatching {
            context.startActivity(
                Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            )
        }
    }

    val openPostNotificationsSettings: () -> Unit = {
        if (Build.VERSION.SDK_INT >= 33) {
            notifPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        } else {
            runCatching {
                context.startActivity(
                    Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
                        putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                )
            }
        }
    }

    val openDndSettings: () -> Unit = {
        runCatching {
            context.startActivity(
                Intent(Settings.ACTION_NOTIFICATION_POLICY_ACCESS_SETTINGS).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            )
        }
    }

    val allFeatureTargets = remember(state.canonicalTargets, state.grantedSafTreeTargets) {
        (state.canonicalTargets + state.grantedSafTreeTargets).distinct()
    }

    val activeFeaturesCount = remember(allFeatureTargets, state.targetProfilesById) {
        allFeatureTargets.count { targetId ->
            val p = state.targetProfilesById[targetId]
            p != null && p.capabilities.values.any { it.isAllowed }
        }
    }

    val permittedAppsCount = remember(state.installedApps, state.targetProfilesById) {
        state.installedApps.count { app ->
            val p = state.targetProfilesById[app.packageName]
            p != null && p.capabilities.values.any { it.isAllowed }
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.bgPaper)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Header row with title and active count
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = stringResource(R.string.nav_permissions).uppercase(locale),
                style = MaterialTheme.typography.labelSmall.copy(
                    fontSize = 11.sp,
                    letterSpacing = 0.8.sp
                ),
                fontWeight = FontWeight.SemiBold,
                color = colors.inkMuted
            )
            if (selectedTab == TAB_FEATURES) {
                Text(
                    text = stringResource(
                        R.string.perm_summary_active_count,
                        activeFeaturesCount,
                        allFeatureTargets.size
                    ),
                    style = MaterialTheme.typography.labelSmall,
                    color = if (activeFeaturesCount > 0) colors.verifiedForest else colors.inkMuted,
                    fontWeight = FontWeight.Medium
                )
            }
        }

        // 2-Tab Segmented Selector: Features vs Installed Apps
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(colors.bgLinen, RoundedCornerShape(12.dp))
                .padding(4.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            val appsTabLabel = if (permittedAppsCount > 0) {
                "${stringResource(R.string.profile_tab_apps)} ($permittedAppsCount)"
            } else {
                stringResource(R.string.profile_tab_apps)
            }
            listOf(
                TAB_FEATURES to stringResource(R.string.profile_tab_features),
                TAB_APPS to appsTabLabel
            ).forEach { (tabId, label) ->
                val isTabSelected = selectedTab == tabId
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .background(
                            color = if (isTabSelected) colors.surfaceCard else Color.Transparent,
                            shape = RoundedCornerShape(9.dp)
                        )
                        .clickable {
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            selectedTab = tabId
                        }
                        .padding(vertical = 9.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = label,
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = if (isTabSelected) FontWeight.SemiBold else FontWeight.Medium,
                        color = if (isTabSelected) colors.trustNavy else colors.inkSecondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }

        state.errorMessage?.let { err ->
            Surface(
                color = colors.alertCrimsonSurface,
                shape = RoundedCornerShape(12.dp),
                border = BorderStroke(1.dp, colors.alertCrimson.copy(alpha = 0.35f)),
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

        if (selectedTab == TAB_FEATURES) {
            // TAB_FEATURES: Clean single vertical list of all features + SAF folders
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(bottom = 16.dp)
            ) {
                item(key = "features_list_card") {
                    Surface(
                        color = colors.surfaceCard,
                        shape = RoundedCornerShape(14.dp),
                        border = BorderStroke(1.dp, colors.borderStone),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.fillMaxWidth()) {
                            allFeatureTargets.forEachIndexed { index, targetId ->
                                val targetProfile = state.targetProfilesById[targetId]
                                    ?: PermissionProfile.defaultDeny()
                                val primaryCaps = viewModel.primaryCapabilitiesForTarget(targetId)
                                val hasAnyAllowed = targetProfile.capabilities.values.any { it.isAllowed }
                                val missingOsPerm = isTargetMissingOsPermission(targetId, state)

                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                            showAllFeatureCapabilities = false
                                            activeFeatureTargetId = targetId
                                            viewModel.selectTarget(targetId)
                                        }
                                        .padding(horizontal = 14.dp, vertical = 12.dp),
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(9.dp)
                                            .background(
                                                color = when {
                                                    missingOsPerm && hasAnyAllowed -> colors.untrustedAccent
                                                    hasAnyAllowed -> colors.verifiedForest
                                                    else -> colors.borderStone
                                                },
                                                shape = CircleShape
                                            )
                                    )

                                    Column(
                                        modifier = Modifier.weight(1f),
                                        verticalArrangement = Arrangement.spacedBy(2.dp)
                                    ) {
                                        Text(
                                            text = localizedTargetLabel(targetId),
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.SemiBold,
                                            color = colors.inkPrimary,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        Text(
                                            text = localizedTargetDescription(targetId),
                                            style = MaterialTheme.typography.labelSmall,
                                            color = colors.inkMuted,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        if (missingOsPerm) {
                                            Text(
                                                text = stringResource(R.string.perm_os_missing_badge),
                                                style = MaterialTheme.typography.labelSmall,
                                                fontWeight = FontWeight.Medium,
                                                color = colors.untrustedAccent,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                        }
                                    }

                                    Surface(
                                        color = if (hasAnyAllowed) {
                                            colors.verifiedForest.copy(alpha = 0.12f)
                                        } else {
                                            colors.bgLinen
                                        },
                                        shape = RoundedCornerShape(999.dp)
                                    ) {
                                        Text(
                                            text = featureStatusSummaryLabel(targetProfile, primaryCaps),
                                            style = MaterialTheme.typography.labelSmall,
                                            fontWeight = FontWeight.SemiBold,
                                            color = if (hasAnyAllowed) colors.verifiedForest else colors.inkMuted,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                                        )
                                    }
                                }

                                if (index < allFeatureTargets.lastIndex) {
                                    HorizontalDivider(
                                        thickness = 0.5.dp,
                                        color = colors.borderStone.copy(alpha = 0.6f),
                                        modifier = Modifier.padding(horizontal = 14.dp)
                                    )
                                }
                            }

                            HorizontalDivider(
                                thickness = 0.5.dp,
                                color = colors.borderStone.copy(alpha = 0.6f)
                            )

                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        safTreeLauncher.launch(null)
                                    }
                                    .padding(horizontal = 14.dp, vertical = 12.dp),
                                horizontalArrangement = Arrangement.Center,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = "+ ${stringResource(R.string.perm_add_folder)}",
                                    style = MaterialTheme.typography.labelLarge,
                                    fontWeight = FontWeight.SemiBold,
                                    color = colors.trustNavyTint
                                )
                            }
                        }
                    }
                }

                // Compact collapsible Quick Actions for All Features
                item(key = "features_bulk_footer") {
                    Surface(
                        color = colors.surfaceCard,
                        shape = RoundedCornerShape(14.dp),
                        border = BorderStroke(1.dp, colors.borderStone),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 10.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        showBulkFeatures = !showBulkFeatures
                                    },
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = stringResource(R.string.perm_bulk_features_title),
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.SemiBold,
                                    color = colors.inkSecondary
                                )
                                Text(
                                    text = if (showBulkFeatures) "-" else "+",
                                    style = MaterialTheme.typography.titleSmall,
                                    color = colors.inkMuted
                                )
                            }

                            if (showBulkFeatures) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    QuickActionChip(
                                        label = stringResource(R.string.perm_quick_turn_off),
                                        isActive = false,
                                        modifier = Modifier.weight(1f),
                                        onClick = {
                                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                            viewModel.applyQuickLevelToAllCoreTargets(ConfirmationLevel.DISABLED)
                                        }
                                    )
                                    QuickActionChip(
                                        label = stringResource(R.string.perm_quick_ask),
                                        isActive = false,
                                        modifier = Modifier.weight(1f),
                                        onClick = {
                                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                            viewModel.applyQuickLevelToAllCoreTargets(ConfirmationLevel.PROMPT_CARD)
                                        }
                                    )
                                    QuickActionChip(
                                        label = stringResource(R.string.perm_quick_auto),
                                        isActive = false,
                                        modifier = Modifier.weight(1f),
                                        onClick = {
                                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                            viewModel.applyQuickLevelToAllCoreTargets(ConfirmationLevel.AUTO)
                                        }
                                    )
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // TAB_APPS: Searchable, filterable LazyColumn with clear capability badges + inline toggle + bulk controls
            if (!state.isNotificationListenerEnabled) {
                PermissionSyncBanner(
                    message = stringResource(R.string.perm_banner_notif_listener),
                    actionLabel = stringResource(R.string.perm_banner_open_settings),
                    onAction = openNotificationListenerSettings
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = state.appSearchQuery,
                    onValueChange = { viewModel.onAppSearchQueryChanged(it) },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = colors.trustNavyTint,
                        unfocusedBorderColor = colors.borderStone,
                        focusedTextColor = colors.inkPrimary,
                        unfocusedTextColor = colors.inkPrimary,
                        focusedContainerColor = colors.surfaceCard,
                        unfocusedContainerColor = colors.surfaceCard
                    ),
                    placeholder = {
                        Text(
                            text = stringResource(R.string.profile_installed_apps_search),
                            color = colors.inkMuted
                        )
                    }
                )

                Surface(
                    color = if (state.showOnlyPermittedApps) colors.trustNavy else colors.surfaceCard,
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(
                        1.dp,
                        if (state.showOnlyPermittedApps) colors.trustNavy else colors.borderStone
                    ),
                    modifier = Modifier.clickable {
                        haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        viewModel.onToggleShowOnlyPermittedApps()
                    }
                ) {
                    Text(
                        text = if (state.showOnlyPermittedApps) {
                            stringResource(R.string.profile_filter_permitted)
                        } else {
                            stringResource(R.string.profile_filter_all)
                        },
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = if (state.showOnlyPermittedApps) Color.White else colors.inkSecondary,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 14.dp)
                    )
                }
            }

            val filteredApps = state.filteredInstalledApps

            // Quick bulk controls for visible apps
            if (filteredApps.isNotEmpty()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    QuickActionChip(
                        label = stringResource(R.string.perm_bulk_allow_notif),
                        isActive = false,
                        modifier = Modifier.weight(1f),
                        onClick = {
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            viewModel.applyCapabilityToApps(
                                packageNames = filteredApps.map { it.packageName },
                                capability = AtomicCapability.NOTIFICATION_READ,
                                level = ConfirmationLevel.AUTO
                            )
                        }
                    )
                    QuickActionChip(
                        label = stringResource(R.string.perm_bulk_turn_off_apps),
                        isActive = false,
                        modifier = Modifier.weight(1f),
                        onClick = {
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            viewModel.resetAppsToDefaultDeny(
                                packageNames = filteredApps.map { it.packageName }
                            )
                        }
                    )
                }
            }

            Surface(
                color = colors.surfaceCard,
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(1.dp, colors.borderStone),
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
            ) {
                if (filteredApps.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(24.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = stringResource(R.string.profile_installed_apps_empty),
                            style = MaterialTheme.typography.bodyMedium,
                            color = colors.inkMuted
                        )
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(vertical = 6.dp)
                    ) {
                        itemsIndexed(
                            items = filteredApps,
                            key = { _, app -> app.packageName }
                        ) { index, app ->
                            val appProfile = state.targetProfilesById[app.packageName]
                                ?: PermissionProfile.defaultDeny()
                            val hasAnyAllowed = appProfile.capabilities.values.any { it.isAllowed }
                            val notifAllowed = appProfile.levelFor(AtomicCapability.NOTIFICATION_READ).isAllowed

                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        showAllAppCapabilities = false
                                        activeAppForSheet = app
                                        viewModel.selectTarget(app.packageName)
                                    }
                                    .padding(horizontal = 14.dp, vertical = 11.dp),
                                horizontalArrangement = Arrangement.spacedBy(10.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                val initialChar = app.displayLabel.firstOrNull()?.uppercaseChar()?.toString() ?: "A"
                                Box(
                                    modifier = Modifier
                                        .size(34.dp)
                                        .background(
                                            color = if (hasAnyAllowed) colors.trustNavy else colors.bgLinen,
                                            shape = CircleShape
                                        ),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = initialChar,
                                        style = MaterialTheme.typography.labelMedium,
                                        fontWeight = FontWeight.Bold,
                                        color = if (hasAnyAllowed) Color.White else colors.inkPrimary
                                    )
                                }

                                Column(
                                    modifier = Modifier.weight(1f),
                                    verticalArrangement = Arrangement.spacedBy(2.dp)
                                ) {
                                    Text(
                                        text = app.displayLabel,
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Medium,
                                        color = colors.inkPrimary,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(
                                        text = appCapabilityBadgesSummary(appProfile),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = if (hasAnyAllowed) colors.verifiedForest else colors.inkMuted,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }

                                // 1-tap inline Notification Read toggle pill
                                Surface(
                                    color = if (notifAllowed) {
                                        colors.verifiedForest.copy(alpha = 0.14f)
                                    } else {
                                        colors.bgLinen
                                    },
                                    shape = RoundedCornerShape(999.dp),
                                    border = BorderStroke(
                                        width = 1.dp,
                                        color = if (notifAllowed) {
                                            colors.verifiedForest.copy(alpha = 0.4f)
                                        } else {
                                            colors.borderStone
                                        }
                                    ),
                                    modifier = Modifier.clickable {
                                        haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        viewModel.toggleAppQuickCapability(
                                            packageName = app.packageName,
                                            capability = AtomicCapability.NOTIFICATION_READ
                                        )
                                    }
                                ) {
                                    Text(
                                        text = stringResource(R.string.perm_badge_notif),
                                        style = MaterialTheme.typography.labelSmall,
                                        fontWeight = FontWeight.SemiBold,
                                        color = if (notifAllowed) colors.verifiedForest else colors.inkMuted,
                                        maxLines = 1,
                                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp)
                                    )
                                }
                            }

                            if (index < filteredApps.lastIndex) {
                                HorizontalDivider(
                                    thickness = 0.5.dp,
                                    color = colors.borderStone.copy(alpha = 0.5f),
                                    modifier = Modifier.padding(horizontal = 14.dp)
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    // In-place Bottom Sheet for Core Feature / SAF Folder Permission Management
    val sheetFeatureTargetId = activeFeatureTargetId
    if (sheetFeatureTargetId != null) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        val liveProfile = state.targetProfilesById[sheetFeatureTargetId]
            ?: PermissionProfile.defaultDeny()
        val primaryCaps = remember(sheetFeatureTargetId) {
            viewModel.primaryCapabilitiesForTarget(sheetFeatureTargetId)
        }
        val extraCaps = remember(primaryCaps) {
            AtomicCapability.entries.filter { it !in primaryCaps }
        }

        ModalBottomSheet(
            onDismissRequest = { activeFeatureTargetId = null },
            sheetState = sheetState,
            containerColor = colors.bgPaper
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 16.dp)
                    .padding(bottom = 28.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        text = localizedTargetLabel(sheetFeatureTargetId),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = colors.inkPrimary
                    )
                    Text(
                        text = localizedTargetDescription(sheetFeatureTargetId),
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.inkMuted
                    )
                }

                // Contextual Android OS Permission Banner right inside the feature sheet
                TargetOsPermissionBanner(
                    targetId = sheetFeatureTargetId,
                    state = state,
                    onRequestPostNotifications = openPostNotificationsSettings,
                    onOpenNotifListenerSettings = openNotificationListenerSettings,
                    onRequestCalendar = {
                        calendarPermissionLauncher.launch(
                            arrayOf(
                                android.Manifest.permission.READ_CALENDAR,
                                android.Manifest.permission.WRITE_CALENDAR
                            )
                        )
                    },
                    onOpenDndSettings = openDndSettings,
                    onRequestPhone = {
                        phonePermissionLauncher.launch(android.Manifest.permission.CALL_PHONE)
                    }
                )

                // Direct 3-button Quick Control Bar (replaces abstract preset radio buttons)
                val allPrimaryOff = primaryCaps.all { liveProfile.levelFor(it) == ConfirmationLevel.DISABLED }
                val allPrimaryAsk = primaryCaps.all { liveProfile.levelFor(it) == ConfirmationLevel.PROMPT_CARD }
                val allPrimaryAuto = primaryCaps.all { cap ->
                    val expected = if (ConfirmationLevel.AUTO.isValidFor(cap)) {
                        ConfirmationLevel.AUTO
                    } else {
                        ConfirmationLevel.PROMPT_CARD
                    }
                    liveProfile.levelFor(cap) == expected
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    QuickActionChip(
                        label = stringResource(R.string.perm_quick_turn_off),
                        isActive = allPrimaryOff && liveProfile.capabilities.values.none { it.isAllowed },
                        modifier = Modifier.weight(1f),
                        onClick = {
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            viewModel.applyQuickLevelToTarget(
                                targetId = sheetFeatureTargetId,
                                capabilities = AtomicCapability.entries,
                                level = ConfirmationLevel.DISABLED
                            )
                        }
                    )
                    QuickActionChip(
                        label = stringResource(R.string.perm_quick_ask),
                        isActive = allPrimaryAsk,
                        modifier = Modifier.weight(1f),
                        onClick = {
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            viewModel.applyQuickLevelToTarget(
                                targetId = sheetFeatureTargetId,
                                capabilities = primaryCaps,
                                level = ConfirmationLevel.PROMPT_CARD
                            )
                        }
                    )
                    QuickActionChip(
                        label = stringResource(R.string.perm_quick_auto),
                        isActive = allPrimaryAuto,
                        modifier = Modifier.weight(1f),
                        onClick = {
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            viewModel.applyQuickLevelToTarget(
                                targetId = sheetFeatureTargetId,
                                capabilities = primaryCaps,
                                level = ConfirmationLevel.AUTO
                            )
                        }
                    )
                }

                // Primary Relevant Capabilities for this Feature
                CapabilitySwitchesCard(
                    capabilities = primaryCaps,
                    profile = liveProfile,
                    validLevelsProvider = { viewModel.validLevelsFor(it) },
                    onSelectLevel = { capability, level ->
                        haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        viewModel.setTargetCapability(
                            targetId = sheetFeatureTargetId,
                            capability = capability,
                            level = level
                        )
                    }
                )

                // Expandable section for the remaining orthogonal switches (Iron Law 5 full control)
                if (extraCaps.isNotEmpty()) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                showAllFeatureCapabilities = !showAllFeatureCapabilities
                            }
                            .padding(horizontal = 4.dp, vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = stringResource(R.string.perm_all_capabilities_toggle),
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = colors.inkMuted
                        )
                        Text(
                            text = if (showAllFeatureCapabilities) "-" else "+",
                            style = MaterialTheme.typography.titleSmall,
                            color = colors.inkMuted
                        )
                    }

                    if (showAllFeatureCapabilities) {
                        CapabilitySwitchesCard(
                            capabilities = extraCaps,
                            profile = liveProfile,
                            validLevelsProvider = { viewModel.validLevelsFor(it) },
                            onSelectLevel = { capability, level ->
                                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                viewModel.setTargetCapability(
                                    targetId = sheetFeatureTargetId,
                                    capability = capability,
                                    level = level
                                )
                            }
                        )
                    }
                }
            }
        }
    }

    // In-place Bottom Sheet for Per-App Permission Management
    val sheetApp = activeAppForSheet
    if (sheetApp != null) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        val liveAppProfile = state.targetProfilesById[sheetApp.packageName]
            ?: PermissionProfile.defaultDeny()

        ModalBottomSheet(
            onDismissRequest = { activeAppForSheet = null },
            sheetState = sheetState,
            containerColor = colors.bgPaper
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 16.dp)
                    .padding(bottom = 28.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        text = sheetApp.displayLabel,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = colors.inkPrimary
                    )
                    Text(
                        text = sheetApp.packageName,
                        style = MaterialTheme.typography.labelSmall,
                        color = colors.inkMuted
                    )
                }

                if (!state.isNotificationListenerEnabled) {
                    PermissionSyncBanner(
                        message = stringResource(R.string.perm_banner_notif_listener),
                        actionLabel = stringResource(R.string.perm_banner_open_settings),
                        onAction = openNotificationListenerSettings
                    )
                }

                // Direct 3-button Quick Control Bar for App
                val notifOn = liveAppProfile.levelFor(AtomicCapability.NOTIFICATION_READ).isAllowed
                val launchOn = liveAppProfile.levelFor(AtomicCapability.APP_LAUNCH).isAllowed
                val anyOn = liveAppProfile.capabilities.values.any { it.isAllowed }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    QuickActionChip(
                        label = stringResource(R.string.perm_quick_turn_off),
                        isActive = !anyOn,
                        modifier = Modifier.weight(1f),
                        onClick = {
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            viewModel.applyQuickLevelToTarget(
                                targetId = sheetApp.packageName,
                                capabilities = AtomicCapability.entries,
                                level = ConfirmationLevel.DISABLED
                            )
                        }
                    )
                    QuickActionChip(
                        label = stringResource(R.string.perm_badge_notif),
                        isActive = notifOn && !launchOn,
                        modifier = Modifier.weight(1f),
                        onClick = {
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            viewModel.applyQuickLevelToTarget(
                                targetId = sheetApp.packageName,
                                capabilities = listOf(AtomicCapability.NOTIFICATION_READ),
                                level = ConfirmationLevel.AUTO
                            )
                        }
                    )
                    QuickActionChip(
                        label = "${stringResource(R.string.perm_badge_notif)} + ${stringResource(R.string.perm_badge_launch)}",
                        isActive = notifOn && launchOn,
                        modifier = Modifier.weight(1.3f),
                        onClick = {
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            viewModel.applyQuickLevelToTarget(
                                targetId = sheetApp.packageName,
                                capabilities = listOf(
                                    AtomicCapability.NOTIFICATION_READ,
                                    AtomicCapability.APP_LAUNCH
                                ),
                                level = ConfirmationLevel.AUTO
                            )
                        }
                    )
                }

                // Primary App Switches: Notification Read + App Launch
                CapabilitySwitchesCard(
                    capabilities = listOf(
                        AtomicCapability.NOTIFICATION_READ,
                        AtomicCapability.APP_LAUNCH
                    ),
                    profile = liveAppProfile,
                    validLevelsProvider = { viewModel.validLevelsFor(it) },
                    onSelectLevel = { capability, level ->
                        haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        viewModel.setTargetCapability(
                            targetId = sheetApp.packageName,
                            capability = capability,
                            level = level
                        )
                    }
                )

                // Collapsible All 5 Capabilities toggle for the remaining 3 orthogonal switches
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            showAllAppCapabilities = !showAllAppCapabilities
                        }
                        .padding(horizontal = 4.dp, vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.perm_all_capabilities_toggle),
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = colors.inkMuted
                    )
                    Text(
                        text = if (showAllAppCapabilities) "-" else "+",
                        style = MaterialTheme.typography.titleSmall,
                        color = colors.inkMuted
                    )
                }

                if (showAllAppCapabilities) {
                    CapabilitySwitchesCard(
                        capabilities = listOf(
                            AtomicCapability.DATA_READ,
                            AtomicCapability.CREATE_DRAFT,
                            AtomicCapability.MODIFY_DELETE_SEND
                        ),
                        profile = liveAppProfile,
                        validLevelsProvider = { viewModel.validLevelsFor(it) },
                        onSelectLevel = { capability, level ->
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            viewModel.setTargetCapability(
                                targetId = sheetApp.packageName,
                                capability = capability,
                                level = level
                            )
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun QuickActionChip(
    label: String,
    isActive: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = NavaThemeExtras.colors
    Box(
        modifier = modifier
            .background(
                color = if (isActive) colors.trustNavy else colors.surfaceCard,
                shape = RoundedCornerShape(10.dp)
            )
            .border(
                width = 1.dp,
                color = if (isActive) colors.trustNavy else colors.borderStone,
                shape = RoundedCornerShape(10.dp)
            )
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 9.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.SemiBold,
            color = if (isActive) Color.White else colors.inkPrimary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun TargetOsPermissionBanner(
    targetId: String,
    state: PermissionProfilesUiState,
    onRequestPostNotifications: () -> Unit,
    onOpenNotifListenerSettings: () -> Unit,
    onRequestCalendar: () -> Unit,
    onOpenDndSettings: () -> Unit,
    onRequestPhone: () -> Unit
) {
    val needsPostNotifBanner = !state.canPostNotifications && targetId in setOf(
        ToolTargetIds.REMINDERS,
        ToolTargetIds.CLOCK,
        ToolTargetIds.ROUTINES,
        ToolTargetIds.NOTIFICATIONS
    )
    if (needsPostNotifBanner) {
        PermissionSyncBanner(
            message = stringResource(R.string.perm_banner_post_notifications),
            actionLabel = stringResource(R.string.perm_banner_grant),
            onAction = onRequestPostNotifications
        )
    }
    if (targetId == ToolTargetIds.NOTIFICATIONS && !state.isNotificationListenerEnabled) {
        PermissionSyncBanner(
            message = stringResource(R.string.perm_banner_notif_listener),
            actionLabel = stringResource(R.string.perm_banner_open_settings),
            onAction = onOpenNotifListenerSettings
        )
    }
    if (targetId == ToolTargetIds.CALENDAR && (!state.hasReadCalendarPermission || !state.hasWriteCalendarPermission)) {
        PermissionSyncBanner(
            message = stringResource(R.string.perm_banner_calendar),
            actionLabel = stringResource(R.string.perm_banner_grant),
            onAction = onRequestCalendar
        )
    }
    if (targetId == ToolTargetIds.AUDIO_DND && !state.isNotificationPolicyAccessGranted) {
        PermissionSyncBanner(
            message = stringResource(R.string.perm_banner_audio_dnd),
            actionLabel = stringResource(R.string.perm_banner_open_settings),
            onAction = onOpenDndSettings
        )
    }
    if (targetId == ToolTargetIds.PHONE && !state.hasCallPhonePermission) {
        PermissionSyncBanner(
            message = stringResource(R.string.perm_banner_call_phone),
            actionLabel = stringResource(R.string.perm_banner_grant),
            onAction = onRequestPhone
        )
    }
}

private fun isTargetMissingOsPermission(
    targetId: String,
    state: PermissionProfilesUiState
): Boolean {
    return when (targetId) {
        ToolTargetIds.NOTIFICATIONS -> !state.isNotificationListenerEnabled || !state.canPostNotifications
        ToolTargetIds.CALENDAR -> !state.hasReadCalendarPermission || !state.hasWriteCalendarPermission
        ToolTargetIds.AUDIO_DND -> !state.isNotificationPolicyAccessGranted
        ToolTargetIds.PHONE -> !state.hasCallPhonePermission
        ToolTargetIds.REMINDERS, ToolTargetIds.CLOCK, ToolTargetIds.ROUTINES -> !state.canPostNotifications
        else -> false
    }
}

@Composable
private fun CapabilitySwitchesCard(
    capabilities: List<AtomicCapability>,
    profile: PermissionProfile,
    validLevelsProvider: (AtomicCapability) -> List<ConfirmationLevel>,
    onSelectLevel: (AtomicCapability, ConfirmationLevel) -> Unit
) {
    val colors = NavaThemeExtras.colors
    Surface(
        color = colors.surfaceCard,
        shape = RoundedCornerShape(14.dp),
        border = BorderStroke(1.dp, colors.borderStone),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            capabilities.forEachIndexed { index, capability ->
                val currentLevel = profile.levelFor(capability)
                val validLevels = validLevelsProvider(capability)
                val orderedLevels = remember(validLevels) {
                    buildList {
                        add(ConfirmationLevel.DISABLED)
                        for (lvl in validLevels) {
                            if (lvl != ConfirmationLevel.DISABLED) {
                                add(lvl)
                            }
                        }
                    }
                }

                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text(
                        text = localizedCapabilityTitle(capability),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.Medium,
                        color = colors.inkPrimary
                    )
                    Text(
                        text = localizedCapabilityDescription(capability),
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.inkSecondary
                    )
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 4.dp)
                            .background(colors.bgLinen, RoundedCornerShape(10.dp))
                            .padding(3.dp),
                        horizontalArrangement = Arrangement.spacedBy(2.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        for (level in orderedLevels) {
                            val levelSelected = currentLevel == level
                            val segmentBg = if (levelSelected) {
                                colors.surfaceCard
                            } else {
                                Color.Transparent
                            }
                            val segmentTextColor = when {
                                levelSelected && level == ConfirmationLevel.BIOMETRIC -> colors.untrustedAccent
                                levelSelected && level == ConfirmationLevel.AUTO -> colors.verifiedForest
                                levelSelected -> colors.inkPrimary
                                else -> colors.inkSecondary
                            }

                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .background(segmentBg, RoundedCornerShape(8.dp))
                                    .clickable { onSelectLevel(capability, level) }
                                    .padding(horizontal = 4.dp, vertical = 7.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = localizedConfirmationLevelShortTitle(level),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = if (levelSelected) {
                                        FontWeight.SemiBold
                                    } else {
                                        FontWeight.Normal
                                    },
                                    color = segmentTextColor,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }
                    }
                }

                if (index < capabilities.lastIndex) {
                    HorizontalDivider(
                        thickness = 0.5.dp,
                        color = colors.borderStone
                    )
                }
            }
        }
    }
}

@Composable
private fun featureStatusSummaryLabel(
    profile: PermissionProfile,
    primaryCaps: List<AtomicCapability>
): String {
    val activePrimary = primaryCaps
        .map { it to profile.levelFor(it) }
        .filter { (_, lvl) -> lvl.isAllowed }
    if (activePrimary.isEmpty()) {
        val anyOther = profile.capabilities.entries.filter { it.value.isAllowed }
        if (anyOther.isEmpty()) {
            return stringResource(R.string.perm_level_off)
        }
        val labels = ArrayList<String>(anyOther.size)
        for (entry in anyOther) {
            labels.add(localizedCapabilityBadge(entry.key))
        }
        return labels.joinToString(" / ")
    }
    val distinctLevels = activePrimary.map { it.second }.distinct()
    if (activePrimary.size == primaryCaps.size && distinctLevels.size == 1) {
        return localizedConfirmationLevelShortTitle(distinctLevels.first())
    }
    val labels = ArrayList<String>(activePrimary.size)
    for ((cap, _) in activePrimary) {
        labels.add(localizedCapabilityBadge(cap))
    }
    return labels.joinToString(" / ")
}

@Composable
private fun appCapabilityBadgesSummary(profile: PermissionProfile): String {
    val active = AtomicCapability.entries.filter { profile.levelFor(it).isAllowed }
    if (active.isEmpty()) {
        return stringResource(R.string.perm_level_off)
    }
    val labels = ArrayList<String>(active.size)
    for (cap in active) {
        labels.add(localizedCapabilityBadge(cap))
    }
    return labels.joinToString(" / ")
}

@Composable
private fun localizedCapabilityBadge(capability: AtomicCapability): String {
    return when (capability) {
        AtomicCapability.NOTIFICATION_READ -> stringResource(R.string.perm_badge_notif)
        AtomicCapability.DATA_READ -> stringResource(R.string.perm_badge_read)
        AtomicCapability.CREATE_DRAFT -> stringResource(R.string.perm_badge_create)
        AtomicCapability.MODIFY_DELETE_SEND -> stringResource(R.string.perm_badge_modify)
        AtomicCapability.APP_LAUNCH -> stringResource(R.string.perm_badge_launch)
    }
}

@Composable
private fun PermissionSyncBanner(
    message: String,
    actionLabel: String,
    onAction: () -> Unit
) {
    val colors = NavaThemeExtras.colors
    Surface(
        color = colors.untrustedSurface,
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, colors.untrustedAccent.copy(alpha = 0.4f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = message,
                style = MaterialTheme.typography.bodySmall,
                color = colors.inkPrimary,
                modifier = Modifier.weight(1f)
            )
            Button(
                onClick = onAction,
                shape = RoundedCornerShape(8.dp),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = colors.trustNavy,
                    contentColor = Color.White
                )
            ) {
                Text(
                    text = actionLabel,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
    }
}

@Composable
private fun localizedTargetLabel(targetId: String): String {
    return when (targetId) {
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
        else -> if (targetId.startsWith("saf:")) {
            targetId.removePrefix("saf:").substringAfterLast('/').substringAfterLast("%2F")
        } else {
            targetId.substringAfterLast('.')
        }
    }
}

@Composable
private fun localizedTargetDescription(targetId: String): String {
    return when (targetId) {
        "system.clock" -> stringResource(R.string.target_desc_clock)
        "nava.reminders", "system.reminders" -> stringResource(R.string.target_desc_reminders)
        "system.phone" -> stringResource(R.string.target_desc_phone)
        "system.calendar" -> stringResource(R.string.target_desc_calendar)
        "nava.notes" -> stringResource(R.string.target_desc_notes)
        "nava.vault" -> stringResource(R.string.target_desc_vault)
        "system.sms" -> stringResource(R.string.target_desc_sms)
        "system.notifications" -> stringResource(R.string.target_desc_notifications)
        "system.audio_dnd" -> stringResource(R.string.target_desc_audio_dnd)
        "system.app_launch" -> stringResource(R.string.target_desc_app_launch)
        "system.saf" -> stringResource(R.string.target_desc_saf)
        "nava.routines" -> stringResource(R.string.target_desc_routines)
        else -> stringResource(R.string.target_desc_saf)
    }
}

@Composable
private fun localizedCapabilityTitle(capability: AtomicCapability): String {
    return when (capability) {
        AtomicCapability.NOTIFICATION_READ -> stringResource(R.string.capability_notification_read)
        AtomicCapability.DATA_READ -> stringResource(R.string.capability_data_read)
        AtomicCapability.CREATE_DRAFT -> stringResource(R.string.capability_create_draft)
        AtomicCapability.MODIFY_DELETE_SEND -> stringResource(R.string.capability_modify_delete_send)
        AtomicCapability.APP_LAUNCH -> stringResource(R.string.capability_app_launch)
    }
}

@Composable
private fun localizedCapabilityDescription(capability: AtomicCapability): String {
    return when (capability) {
        AtomicCapability.NOTIFICATION_READ -> stringResource(R.string.capability_notification_read_desc)
        AtomicCapability.DATA_READ -> stringResource(R.string.capability_data_read_desc)
        AtomicCapability.CREATE_DRAFT -> stringResource(R.string.capability_create_draft_desc)
        AtomicCapability.MODIFY_DELETE_SEND -> stringResource(R.string.capability_modify_delete_send_desc)
        AtomicCapability.APP_LAUNCH -> stringResource(R.string.capability_app_launch_desc)
    }
}

@Composable
private fun localizedConfirmationLevelShortTitle(level: ConfirmationLevel): String {
    return when (level) {
        ConfirmationLevel.DISABLED -> stringResource(R.string.perm_level_off)
        ConfirmationLevel.AUTO -> stringResource(R.string.perm_level_auto)
        ConfirmationLevel.PROMPT_CARD -> stringResource(R.string.perm_level_ask)
        ConfirmationLevel.BIOMETRIC -> stringResource(R.string.perm_level_biometric)
    }
}

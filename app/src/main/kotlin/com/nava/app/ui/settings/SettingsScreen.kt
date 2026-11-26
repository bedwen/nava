package com.nava.app.ui.settings

import android.app.role.RoleManager
import android.content.Context
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
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
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
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import com.nava.app.R
import com.nava.app.di.PinnedModelCatalog
import com.nava.app.di.PinnedModelRole
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.ui.components.NavaIcons
import com.nava.app.ui.theme.NavaExtendedColors
import com.nava.app.ui.theme.NavaThemeExtras
import com.nava.app.ui.theme.NavaThemeMode
import java.util.Locale
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * Settings screen providing:
 * - On-device Gemma 4 model provisioning (SHA-256 verified SAF import, E2B/E4B selection,
 *   verification, and deletion).
 * - Compact single-row language selector that opens a searchable bottom sheet over
 *   `SupportedLanguageCatalog` + `AppLocaleManager`.
 * - System integration intents (`RoleManager.ROLE_ASSISTANT`, Notification Listener settings,
 *   Notification Policy Access settings).
 *
 * Vault and Security Audit Log live in their dedicated primary tabs to avoid duplication.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel,
    bidiFormatter: BidiTextFormatter,
    @Suppress("UNUSED_PARAMETER") activity: FragmentActivity?,
    modifier: Modifier = Modifier,
    themeMode: NavaThemeMode = NavaThemeMode.SYSTEM,
    onSelectThemeMode: (NavaThemeMode) -> Unit = {}
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val haptics = LocalHapticFeedback.current
    val colors = NavaThemeExtras.colors
    val locale = remember(state.activeLocaleTag) {
        Locale.forLanguageTag(state.activeLocaleTag)
    }
    var showLanguagePicker by remember { mutableStateOf(false) }
    var showTechnicalModels by remember { mutableStateOf(false) }

    val activeLanguageEntry = remember(
        state.activeLocaleTag,
        state.allLanguages,
        state.filteredLanguages
    ) {
        state.allLanguages.firstOrNull {
            it.bcp47Tag.equals(state.activeLocaleTag, ignoreCase = true)
        } ?: state.filteredLanguages.firstOrNull {
            it.bcp47Tag.equals(state.activeLocaleTag, ignoreCase = true)
        }
    }

    val safModelLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            }
            viewModel.enqueueSafModelImport(
                sourceUri = uri.toString(),
                spec = state.targetImportSpec
            )
        }
    }

    val roleRequestLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        viewModel.refreshAll()
    }

    val notifPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) {
        viewModel.refreshAll()
    }

    val primaryButtonColors = ButtonDefaults.buttonColors(
        containerColor = colors.trustNavy,
        contentColor = Color.White,
        disabledContainerColor = colors.borderStone,
        disabledContentColor = colors.inkMuted
    )

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.bgPaper)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp)
    ) {
        Text(
            text = stringResource(R.string.settings_title),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
            color = colors.inkPrimary
        )

        state.errorMessage?.let { err ->
            Text(
                text = bidiFormatter.wrapText(err, locale),
                style = MaterialTheme.typography.bodySmall,
                color = colors.alertCrimson,
                modifier = Modifier.padding(horizontal = 2.dp)
            )
        }

        // 1. Consumer-Friendly On-Device AI Engine Section (Technical files & SHA-256 collapsible)
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            SettingsGroupHeader(
                title = stringResource(R.string.settings_section_ai),
                locale = locale,
                colors = colors
            )
            Surface(
                color = colors.surfaceCard,
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(1.dp, colors.borderStone),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.fillMaxWidth()) {
                    val hasPrimary = state.selectedModelId != null
                    val hasRouter = state.selectedFunctionModelId != null
                    val hasEmbedding = state.selectedEmbeddingModelId != null

                    ConsumerModelRoleRow(
                        title = stringResource(R.string.settings_model_role_primary),
                        subtitle = state.selectedModelId
                            ?: stringResource(R.string.settings_model_status_missing),
                        isReady = hasPrimary,
                        readyLabel = stringResource(R.string.settings_model_status_ready),
                        inactiveLabel = stringResource(R.string.perm_level_off),
                        colors = colors
                    )
                    HorizontalDivider(
                        thickness = 0.5.dp,
                        color = colors.borderStone.copy(alpha = 0.6f),
                        modifier = Modifier.padding(horizontal = 16.dp)
                    )
                    ConsumerModelRoleRow(
                        title = stringResource(R.string.settings_model_role_router),
                        subtitle = state.selectedFunctionModelId
                            ?: stringResource(R.string.settings_model_status_optional),
                        isReady = hasRouter && state.isFunctionRouterEnabled,
                        readyLabel = stringResource(R.string.settings_model_status_ready),
                        inactiveLabel = if (hasRouter) {
                            stringResource(R.string.perm_level_off)
                        } else {
                            stringResource(R.string.settings_model_status_optional)
                        },
                        colors = colors,
                        toggleChecked = if (hasRouter) state.isFunctionRouterEnabled else null,
                        onToggleChanged = { enabled ->
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            viewModel.setFunctionRouterEnabled(enabled)
                        }
                    )
                    HorizontalDivider(
                        thickness = 0.5.dp,
                        color = colors.borderStone.copy(alpha = 0.6f),
                        modifier = Modifier.padding(horizontal = 16.dp)
                    )
                    ConsumerModelRoleRow(
                        title = stringResource(R.string.settings_model_role_embedding),
                        subtitle = state.selectedEmbeddingModelId
                            ?: stringResource(R.string.settings_model_status_optional),
                        isReady = hasEmbedding && state.isSemanticEmbeddingEnabled,
                        readyLabel = stringResource(R.string.settings_model_status_ready),
                        inactiveLabel = if (hasEmbedding) {
                            stringResource(R.string.perm_level_off)
                        } else {
                            stringResource(R.string.settings_model_status_optional)
                        },
                        colors = colors,
                        toggleChecked = if (hasEmbedding) state.isSemanticEmbeddingEnabled else null,
                        onToggleChanged = { enabled ->
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            viewModel.setSemanticEmbeddingEnabled(enabled)
                        }
                    )

                    if (state.isImportingModel) {
                        LinearProgressIndicator(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 4.dp),
                            color = colors.trustNavy,
                            trackColor = colors.bgLinen
                        )
                    }

                    if (state.showTier0LowMemoryNotice) {
                        Text(
                            text = stringResource(R.string.settings_tier_0_low_memory_notice),
                            style = MaterialTheme.typography.bodySmall,
                            color = colors.untrustedAccent,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp)
                        )
                    }

                    if (state.qualitySuggestion != null) {
                        Text(
                            text = stringResource(R.string.settings_e2b_to_e4b_quality_banner),
                            style = MaterialTheme.typography.bodySmall,
                            color = colors.untrustedAccent,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp)
                        )
                    }

                    HorizontalDivider(thickness = 0.5.dp, color = colors.borderStone)

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                showTechnicalModels = !showTechnicalModels
                            }
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = stringResource(R.string.settings_models_technical_toggle),
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Medium,
                            color = colors.trustNavyTint
                        )
                        Text(
                            text = if (showTechnicalModels) "-" else "+",
                            style = MaterialTheme.typography.titleSmall,
                            color = colors.inkMuted
                        )
                    }

                    if (showTechnicalModels) {
                        HorizontalDivider(thickness = 0.5.dp, color = colors.borderStone)
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            FlowRow(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(colors.bgLinen)
                                    .padding(3.dp),
                                horizontalArrangement = Arrangement.spacedBy(3.dp),
                                verticalArrangement = Arrangement.spacedBy(3.dp)
                            ) {
                                for (spec in (PinnedModelCatalog.ALL_SPECS + PinnedModelCatalog.ADDON_SPECS)) {
                                    val isSpecSelected = state.targetImportSpec.modelId == spec.modelId
                                    Box(
                                        modifier = Modifier
                                            .clip(RoundedCornerShape(8.dp))
                                            .background(
                                                if (isSpecSelected) {
                                                    colors.surfaceCard
                                                } else {
                                                    Color.Transparent
                                                }
                                            )
                                            .then(
                                                if (isSpecSelected) {
                                                    Modifier.border(
                                                        width = 0.5.dp,
                                                        color = colors.borderStone,
                                                        shape = RoundedCornerShape(8.dp)
                                                    )
                                                } else {
                                                    Modifier
                                                }
                                            )
                                            .clickable {
                                                haptics.performHapticFeedback(
                                                    HapticFeedbackType.TextHandleMove
                                                )
                                                viewModel.selectTargetImportSpec(spec)
                                            }
                                            .padding(vertical = 8.dp, horizontal = 8.dp),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Text(
                                            text = bidiFormatter.wrapLtrToken(spec.modelId, locale),
                                            style = MaterialTheme.typography.labelMedium,
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = if (isSpecSelected) {
                                                FontWeight.SemiBold
                                            } else {
                                                FontWeight.Normal
                                            },
                                            color = if (isSpecSelected) {
                                                colors.inkPrimary
                                            } else {
                                                colors.inkSecondary
                                            },
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                    }
                                }
                            }

                            Button(
                                onClick = { safModelLauncher.launch(arrayOf("*/*")) },
                                enabled = !state.isImportingModel,
                                colors = primaryButtonColors,
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(44.dp)
                            ) {
                                Text(text = stringResource(R.string.settings_model_import_button))
                            }

                            Text(
                                text = stringResource(R.string.settings_saf_headroom_notice),
                                style = MaterialTheme.typography.bodySmall,
                                color = colors.inkMuted
                            )

                            val diagnostic = state.runtimeDiagnostic
                            if (!diagnostic.isNullOrBlank()) {
                                Text(
                                    text = diagnostic,
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = colors.inkMuted,
                                    maxLines = 3,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }

                        for (modelInfo in state.provisionedModels) {
                            HorizontalDivider(thickness = 0.5.dp, color = colors.borderStone)
                            val verified = state.modelVerificationStatus[modelInfo.fileName]
                            val role = PinnedModelCatalog.roleForModelId(modelInfo.modelId)
                            val isActiveModel = when (role) {
                                PinnedModelRole.PRIMARY_LLM -> modelInfo.modelId == state.selectedModelId
                                PinnedModelRole.FUNCTION_ROUTER -> modelInfo.modelId == state.selectedFunctionModelId
                                PinnedModelRole.SEMANTIC_EMBEDDING -> modelInfo.modelId == state.selectedEmbeddingModelId
                            }
                            val roleLabel = when (role) {
                                PinnedModelRole.PRIMARY_LLM -> stringResource(R.string.settings_model_role_primary)
                                PinnedModelRole.FUNCTION_ROUTER -> stringResource(R.string.settings_model_role_router)
                                PinnedModelRole.SEMANTIC_EMBEDDING -> stringResource(R.string.settings_model_role_embedding)
                            }
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 16.dp, vertical = 12.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
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
                                            text = bidiFormatter.wrapLtrToken(modelInfo.fileName, locale),
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Medium,
                                            color = colors.inkPrimary,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        Text(
                                            text = roleLabel,
                                            style = MaterialTheme.typography.labelSmall,
                                            fontWeight = FontWeight.Medium,
                                            color = colors.trustNavyTint
                                        )
                                    }
                                    if (isActiveModel) {
                                        Text(
                                            text = stringResource(R.string.tile_state_active),
                                            style = MaterialTheme.typography.labelSmall,
                                            fontWeight = FontWeight.SemiBold,
                                            color = colors.verifiedForest
                                        )
                                    }
                                }

                                Text(
                                    text = bidiFormatter.wrapLtrToken(
                                        "SHA-256: ${modelInfo.sha256Hex.take(16)}...",
                                        locale
                                    ),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = colors.inkMuted
                                )

                                if (verified != null) {
                                    Text(
                                        text = if (verified) {
                                            stringResource(R.string.vault_sha256_verified)
                                        } else {
                                            stringResource(R.string.error_security_violation)
                                        },
                                        style = MaterialTheme.typography.labelSmall,
                                        fontWeight = FontWeight.Medium,
                                        color = if (verified) {
                                            colors.verifiedForest
                                        } else {
                                            colors.alertCrimson
                                        }
                                    )
                                }

                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.End
                                ) {
                                    TextButton(
                                        onClick = { viewModel.verifyProvisionedModel(modelInfo.fileName) }
                                    ) {
                                        Text(
                                            text = stringResource(R.string.vault_verify_sha256),
                                            color = colors.trustNavyTint
                                        )
                                    }
                                    if (!isActiveModel) {
                                        TextButton(
                                            onClick = { viewModel.selectActiveModel(modelInfo.modelId) }
                                        ) {
                                            Text(
                                                text = stringResource(R.string.settings_model_activate),
                                                color = colors.trustNavyTint
                                            )
                                        }
                                    }
                                    TextButton(
                                        onClick = { viewModel.deleteProvisionedModel(modelInfo.fileName) }
                                    ) {
                                        Text(
                                            text = stringResource(R.string.vault_delete_model),
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

        // 1b. Clean Theme Mode Selector (System / Light / Dark)
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            SettingsGroupHeader(
                title = stringResource(R.string.settings_theme_title),
                locale = locale,
                colors = colors
            )
            Surface(
                color = colors.surfaceCard,
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(1.dp, colors.borderStone),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(6.dp),
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    listOf(
                        NavaThemeMode.SYSTEM to R.string.settings_theme_system,
                        NavaThemeMode.LIGHT to R.string.settings_theme_light,
                        NavaThemeMode.DARK to R.string.settings_theme_dark
                    ).forEach { (mode, labelRes) ->
                        val isSelected = themeMode == mode
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(10.dp))
                                .background(if (isSelected) colors.trustNavy else Color.Transparent)
                                .clickable {
                                    haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    onSelectThemeMode(mode)
                                }
                                .padding(vertical = 10.dp, horizontal = 6.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = stringResource(labelRes),
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Medium,
                                color = if (isSelected) Color.White else colors.inkSecondary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }
            }
        }

        // 2. Compact Single-Row Language Selector (opens searchable bottom sheet)
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            SettingsGroupHeader(
                title = stringResource(R.string.settings_language_title),
                locale = locale,
                colors = colors
            )
            Surface(
                color = colors.surfaceCard,
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(1.dp, colors.borderStone),
                modifier = Modifier.fillMaxWidth()
            ) {
                val activeDisplayName = if (activeLanguageEntry != null) {
                    "${activeLanguageEntry.nativeName} (${activeLanguageEntry.englishName})"
                } else {
                    locale.getDisplayName(locale).ifBlank { state.activeLocaleTag }
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            showLanguagePicker = true
                        }
                        .padding(horizontal = 16.dp, vertical = 14.dp),
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
                            text = bidiFormatter.wrapText(activeDisplayName, locale),
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            color = colors.inkPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = bidiFormatter.wrapLtrToken(state.activeLocaleTag, locale),
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = colors.inkMuted
                        )
                    }
                    Icon(
                        imageVector = NavaIcons.ChevronRight,
                        contentDescription = null,
                        tint = colors.inkMuted,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }
        }

        // 3. System Integration Intents Section (ROLE_ASSISTANT, Notification Listener, DND Policy)
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            SettingsGroupHeader(
                title = stringResource(R.string.settings_section_system),
                locale = locale,
                colors = colors
            )
            Surface(
                color = colors.surfaceCard,
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(1.dp, colors.borderStone),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.fillMaxWidth()) {
                    SystemIntegrationActionRow(
                        label = stringResource(R.string.tile_assistant_label),
                        isActive = null,
                        colors = colors,
                        onClick = {
                            viewModel.onSystemIntegrationRequested(
                                SystemIntegrationTarget.ASSISTANT_ROLE
                            )
                            launchSystemIntegrationIntent(
                                context = context,
                                target = SystemIntegrationTarget.ASSISTANT_ROLE,
                                roleLauncher = { intent -> roleRequestLauncher.launch(intent) }
                            )
                        }
                    )
                    HorizontalDivider(thickness = 0.5.dp, color = colors.borderStone)
                    SystemIntegrationActionRow(
                        label = stringResource(R.string.settings_notifications_title),
                        description = stringResource(R.string.settings_notifications_desc),
                        isActive = state.isPostNotificationsGranted,
                        colors = colors,
                        onClick = {
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
                    )
                    HorizontalDivider(thickness = 0.5.dp, color = colors.borderStone)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 10.dp),
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
                                text = stringResource(R.string.settings_send_test_notification),
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium,
                                color = colors.inkPrimary
                            )
                            state.testNotificationStatus?.let { success ->
                                Text(
                                    text = stringResource(
                                        if (success) R.string.settings_test_notification_sent
                                        else R.string.settings_test_notification_failed
                                    ),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (success) colors.verifiedForest else colors.alertCrimson
                                )
                            }
                        }

                        Button(
                            onClick = {
                                haptics.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                viewModel.sendTestNotification()
                            },
                            shape = RoundedCornerShape(8.dp),
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = colors.trustNavy,
                                contentColor = Color.White
                            )
                        ) {
                            Text(
                                text = stringResource(R.string.settings_send_test_notification),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    }
                    HorizontalDivider(thickness = 0.5.dp, color = colors.borderStone)
                    SystemIntegrationActionRow(
                        label = stringResource(R.string.capability_notification_read),
                        isActive = state.isNotificationListenerEnabled,
                        colors = colors,
                        onClick = {
                            viewModel.onSystemIntegrationRequested(
                                SystemIntegrationTarget.NOTIFICATION_LISTENER
                            )
                            launchSystemIntegrationIntent(
                                context = context,
                                target = SystemIntegrationTarget.NOTIFICATION_LISTENER,
                                roleLauncher = { intent -> roleRequestLauncher.launch(intent) }
                            )
                        }
                    )
                    HorizontalDivider(thickness = 0.5.dp, color = colors.borderStone)
                    SystemIntegrationActionRow(
                        label = stringResource(R.string.canvas_neuron_audio_dnd),
                        isActive = state.isNotificationPolicyAccessGranted,
                        colors = colors,
                        onClick = {
                            viewModel.onSystemIntegrationRequested(
                                SystemIntegrationTarget.NOTIFICATION_POLICY_ACCESS
                            )
                            launchSystemIntegrationIntent(
                                context = context,
                                target = SystemIntegrationTarget.NOTIFICATION_POLICY_ACCESS,
                                roleLauncher = { intent -> roleRequestLauncher.launch(intent) }
                            )
                        }
                    )
                }
            }
        }
    }

    if (showLanguagePicker) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(
            onDismissRequest = {
                viewModel.onLanguageSearchQueryChanged("")
                showLanguagePicker = false
            },
            sheetState = sheetState,
            containerColor = colors.surfaceCard,
            contentColor = colors.inkPrimary,
            shape = RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 20.dp)
            ) {
                Text(
                    text = stringResource(R.string.settings_language_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = colors.inkPrimary,
                    modifier = Modifier.padding(horizontal = 20.dp, vertical = 4.dp)
                )

                OutlinedTextField(
                    value = state.languageSearchQuery,
                    onValueChange = { viewModel.onLanguageSearchQueryChanged(it) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    singleLine = true,
                    shape = RoundedCornerShape(10.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = colors.bgLinen,
                        unfocusedContainerColor = colors.bgLinen,
                        focusedBorderColor = colors.trustNavyTint.copy(alpha = 0.55f),
                        unfocusedBorderColor = Color.Transparent,
                        focusedTextColor = colors.inkPrimary,
                        unfocusedTextColor = colors.inkPrimary,
                        cursorColor = colors.trustNavyTint
                    ),
                    placeholder = {
                        Text(
                            text = stringResource(R.string.settings_language_title),
                            style = MaterialTheme.typography.bodyMedium,
                            color = colors.inkMuted
                        )
                    }
                )

                HorizontalDivider(thickness = 0.5.dp, color = colors.borderStone)

                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 420.dp)
                ) {
                    itemsIndexed(
                        items = state.filteredLanguages,
                        key = { _, item -> item.bcp47Tag }
                    ) { index, entry ->
                        val isSelected = entry.bcp47Tag.equals(
                            state.activeLocaleTag,
                            ignoreCase = true
                        )
                        val displayName = "${entry.nativeName} (${entry.englishName})"
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(
                                    if (isSelected) {
                                        colors.navIndicator.copy(alpha = 0.55f)
                                    } else {
                                        Color.Transparent
                                    }
                                )
                                .clickable {
                                    haptics.performHapticFeedback(
                                        HapticFeedbackType.TextHandleMove
                                    )
                                    viewModel.selectLanguage(entry.bcp47Tag)
                                    viewModel.onLanguageSearchQueryChanged("")
                                    showLanguagePicker = false
                                }
                                .padding(horizontal = 20.dp, vertical = 12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(
                                modifier = Modifier
                                    .weight(1f)
                                    .padding(end = 12.dp),
                                verticalArrangement = Arrangement.spacedBy(1.dp)
                            ) {
                                Text(
                                    text = bidiFormatter.wrapText(displayName, locale),
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = if (isSelected) {
                                        FontWeight.SemiBold
                                    } else {
                                        FontWeight.Normal
                                    },
                                    color = colors.inkPrimary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = bidiFormatter.wrapLtrToken(entry.bcp47Tag, locale),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = colors.inkMuted
                                )
                            }
                            SettingsRadioIndicator(
                                selected = isSelected,
                                colors = colors
                            )
                        }
                        if (index < state.filteredLanguages.lastIndex) {
                            HorizontalDivider(
                                thickness = 0.5.dp,
                                color = colors.borderStone,
                                modifier = Modifier.padding(horizontal = 20.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SettingsGroupHeader(
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
private fun SettingsRadioIndicator(
    selected: Boolean,
    colors: NavaExtendedColors
) {
    Box(
        modifier = Modifier
            .size(18.dp)
            .clip(CircleShape)
            .border(
                width = if (selected) 2.dp else 1.5.dp,
                color = if (selected) colors.trustNavyTint else colors.borderStone,
                shape = CircleShape
            ),
        contentAlignment = Alignment.Center
    ) {
        if (selected) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(colors.trustNavyTint)
            )
        }
    }
}

@Composable
private fun SystemIntegrationActionRow(
    label: String,
    isActive: Boolean?,
    colors: NavaExtendedColors,
    description: String? = null,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 14.dp),
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
                text = label,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                color = colors.inkPrimary
            )
            if (description != null) {
                Text(
                    text = description,
                    style = MaterialTheme.typography.labelSmall,
                    color = colors.inkMuted
                )
            }
        }
        Row(
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (isActive == true) {
                Text(
                    text = stringResource(R.string.tile_state_active),
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Medium,
                    color = colors.verifiedForest
                )
            }
            Icon(
                imageVector = NavaIcons.ChevronRight,
                contentDescription = null,
                tint = colors.inkMuted,
                modifier = Modifier.size(18.dp)
            )
        }
    }
}

private fun launchSystemIntegrationIntent(
    context: Context,
    target: SystemIntegrationTarget,
    roleLauncher: (Intent) -> Unit
) {
    runCatching {
        when (target) {
            SystemIntegrationTarget.ASSISTANT_ROLE -> {
                val roleManager = context.getSystemService(RoleManager::class.java)
                if (roleManager != null &&
                    roleManager.isRoleAvailable(RoleManager.ROLE_ASSISTANT) &&
                    !roleManager.isRoleHeld(RoleManager.ROLE_ASSISTANT)
                ) {
                    val roleIntent = roleManager.createRequestRoleIntent(RoleManager.ROLE_ASSISTANT)
                    roleLauncher(roleIntent)
                } else {
                    val fallback = Intent(Settings.ACTION_VOICE_INPUT_SETTINGS).apply {
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    context.startActivity(fallback)
                }
            }

            SystemIntegrationTarget.NOTIFICATION_LISTENER -> {
                val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                context.startActivity(intent)
            }

            SystemIntegrationTarget.NOTIFICATION_POLICY_ACCESS -> {
                val intent = Intent(Settings.ACTION_NOTIFICATION_POLICY_ACCESS_SETTINGS).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                context.startActivity(intent)
            }
        }
    }
}

@Composable
private fun ConsumerModelRoleRow(
    title: String,
    subtitle: String,
    isReady: Boolean,
    readyLabel: String,
    inactiveLabel: String,
    colors: NavaExtendedColors,
    toggleChecked: Boolean? = null,
    onToggleChanged: ((Boolean) -> Unit)? = null
) {
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
                .padding(end = 10.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                color = colors.inkPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.labelSmall,
                color = colors.inkMuted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
        if (toggleChecked != null && onToggleChanged != null) {
            Switch(
                checked = toggleChecked,
                onCheckedChange = onToggleChanged,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White,
                    checkedTrackColor = colors.trustNavy,
                    uncheckedThumbColor = colors.inkMuted,
                    uncheckedTrackColor = colors.bgLinen,
                    uncheckedBorderColor = colors.borderStone
                )
            )
        } else {
            Surface(
                color = if (isReady) {
                    colors.verifiedForest.copy(alpha = 0.12f)
                } else {
                    colors.bgLinen
                },
                shape = RoundedCornerShape(999.dp)
            ) {
                Text(
                    text = if (isReady) readyLabel else inactiveLabel,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = if (isReady) colors.verifiedForest else colors.inkMuted,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                )
            }
        }
    }
}

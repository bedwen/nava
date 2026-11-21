package com.nava.app.ui.settings

import android.app.role.RoleManager
import android.content.Context
import android.content.Intent
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.nava.app.R
import com.nava.app.di.PinnedModelCatalog
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.security.BiometricPromptLabels
import java.util.Locale

/**
 * Settings screen providing:
 * - Searchable in-app language picker over `SupportedLanguageCatalog` + `AppLocaleManager`.
 * - Provisioned `.litertlm` model list, SHA-256 verification, deletion, and SAF import.
 * - Nava Vault biometric unlock / lock controls.
 * - System integration intents (`RoleManager.ROLE_ASSISTANT`, Notification Listener settings,
 *   Notification Policy Access settings).
 * - Full Security Audit Log viewer with `ALL` vs `DENIED_ONLY` filter (Requirement 8).
 */
@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel,
    bidiFormatter: BidiTextFormatter,
    activity: FragmentActivity?,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    val locale = Locale.forLanguageTag(state.activeLocaleTag)

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

    val biometricLabels = BiometricPromptLabels(
        title = stringResource(R.string.vault_title),
        subtitle = stringResource(R.string.vault_unlock_prompt),
        negativeButtonText = stringResource(R.string.action_cancel)
    )

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = stringResource(R.string.settings_title),
            style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.onBackground
        )

        // 1. On-Device AI Engine & Provisioned Models Section
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            ),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = stringResource(R.string.settings_section_ai),
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.primary
                )

                if (state.showTier0LowMemoryNotice) {
                    Surface(
                        color = MaterialTheme.colorScheme.surface,
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = stringResource(R.string.settings_tier_0_low_memory_notice),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.secondary,
                            modifier = Modifier.padding(10.dp)
                        )
                    }
                }

                if (state.qualitySuggestion != null) {
                    Surface(
                        color = MaterialTheme.colorScheme.secondaryContainer,
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = stringResource(R.string.settings_e2b_to_e4b_quality_banner),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSecondaryContainer,
                            modifier = Modifier.padding(10.dp)
                        )
                    }
                }

                Text(
                    text = stringResource(R.string.settings_model_title),
                    style = MaterialTheme.typography.titleMedium
                )

                Text(
                    text = if (state.selectedModelId != null) {
                        stringResource(
                            R.string.settings_model_status_loaded,
                            bidiFormatter.wrapLtrToken(state.selectedModelId!!, locale)
                        )
                    } else {
                        stringResource(R.string.settings_model_status_missing)
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace
                )

                Text(
                    text = stringResource(R.string.settings_saf_headroom_notice),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                // Model spec selector for SAF import
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    for (spec in PinnedModelCatalog.ALL_SPECS) {
                        FilterChip(
                            selected = state.targetImportSpec.modelId == spec.modelId,
                            onClick = { viewModel.selectTargetImportSpec(spec) },
                            label = {
                                Text(
                                    text = spec.modelId,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        )
                    }
                }

                Button(
                    onClick = { safModelLauncher.launch(arrayOf("*/*")) },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(text = stringResource(R.string.settings_model_import_button))
                }

                // Provisioned models list with Verify / Select / Delete controls
                for (modelInfo in state.provisionedModels) {
                    val verified = state.modelVerificationStatus[modelInfo.fileName]
                    Surface(
                        color = MaterialTheme.colorScheme.surface,
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(10.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Text(
                                text = bidiFormatter.wrapLtrToken(modelInfo.fileName, locale),
                                style = MaterialTheme.typography.titleMedium,
                                fontFamily = FontFamily.Monospace
                            )
                            Text(
                                text = "SHA-256: ${modelInfo.sha256Hex.take(16)}...",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace
                            )
                            if (verified != null) {
                                Text(
                                    text = if (verified) "SHA-256: VALID" else "SHA-256: MISMATCH",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (verified) {
                                        MaterialTheme.colorScheme.primary
                                    } else {
                                        MaterialTheme.colorScheme.error
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
                                    Text(text = stringResource(R.string.action_approve))
                                }
                                TextButton(
                                    onClick = { viewModel.selectActiveModel(modelInfo.modelId) }
                                ) {
                                    Text(text = stringResource(R.string.onboarding_button_continue))
                                }
                                TextButton(
                                    onClick = { viewModel.deleteProvisionedModel(modelInfo.fileName) }
                                ) {
                                    Text(
                                        text = stringResource(R.string.action_cancel),
                                        color = MaterialTheme.colorScheme.error
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Searchable In-App Language Picker Section
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            ),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = stringResource(R.string.settings_language_title),
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.primary
                )

                OutlinedTextField(
                    value = state.languageSearchQuery,
                    onValueChange = { viewModel.onLanguageSearchQueryChanged(it) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    placeholder = {
                        Text(text = stringResource(R.string.settings_language_title))
                    }
                )

                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    for (entry in state.filteredLanguages.take(20)) {
                        val isSelected = entry.bcp47Tag.equals(state.activeLocaleTag, ignoreCase = true)
                        Surface(
                            color = if (isSelected) {
                                MaterialTheme.colorScheme.primaryContainer
                            } else {
                                MaterialTheme.colorScheme.surface
                            },
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { viewModel.selectLanguage(entry.bcp47Tag) }
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 8.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = "${entry.nativeName} (${entry.englishName})",
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                                    )
                                    Text(
                                        text = entry.bcp47Tag,
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace
                                    )
                                }
                                RadioButton(
                                    selected = isSelected,
                                    onClick = { viewModel.selectLanguage(entry.bcp47Tag) }
                                )
                            }
                        }
                    }
                }
            }
        }

        // 3. Nava Secure Vault Biometric Lock / Unlock Section
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            ),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = stringResource(R.string.vault_title),
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.tertiary
                )
                Text(
                    text = stringResource(R.string.vault_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Text(
                    text = if (state.isVaultUnlocked) {
                        stringResource(R.string.tile_state_active)
                    } else {
                        stringResource(R.string.vault_locked)
                    },
                    style = MaterialTheme.typography.titleMedium,
                    color = if (state.isVaultUnlocked) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    }
                )

                state.lastVaultUnlockError?.let { err ->
                    Text(
                        text = err,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = {
                            viewModel.unlockVault(
                                activity = activity,
                                labels = biometricLabels
                            )
                        },
                        enabled = !state.isVaultUnlocked,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(text = stringResource(R.string.vault_unlock_button))
                    }
                    OutlinedButton(
                        onClick = { viewModel.lockVault() },
                        enabled = state.isVaultUnlocked,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(text = stringResource(R.string.vault_locked))
                    }
                }
            }
        }

        // 4. System Integration Intents Section (ROLE_ASSISTANT, Notification Listener, DND Policy)
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            ),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = stringResource(R.string.settings_section_system),
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.primary
                )

                OutlinedButton(
                    onClick = {
                        viewModel.onSystemIntegrationRequested(SystemIntegrationTarget.ASSISTANT_ROLE)
                        launchSystemIntegrationIntent(
                            context = context,
                            target = SystemIntegrationTarget.ASSISTANT_ROLE,
                            roleLauncher = { intent -> roleRequestLauncher.launch(intent) }
                        )
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(text = stringResource(R.string.tile_assistant_label))
                }

                OutlinedButton(
                    onClick = {
                        viewModel.onSystemIntegrationRequested(SystemIntegrationTarget.NOTIFICATION_LISTENER)
                        launchSystemIntegrationIntent(
                            context = context,
                            target = SystemIntegrationTarget.NOTIFICATION_LISTENER,
                            roleLauncher = { intent -> roleRequestLauncher.launch(intent) }
                        )
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(text = stringResource(R.string.capability_notification_read))
                }

                OutlinedButton(
                    onClick = {
                        viewModel.onSystemIntegrationRequested(SystemIntegrationTarget.NOTIFICATION_POLICY_ACCESS)
                        launchSystemIntegrationIntent(
                            context = context,
                            target = SystemIntegrationTarget.NOTIFICATION_POLICY_ACCESS,
                            roleLauncher = { intent -> roleRequestLauncher.launch(intent) }
                        )
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(text = stringResource(R.string.canvas_neuron_audio_dnd))
                }
            }
        }

        // 5. Full Security Audit Log Viewer with All / Denied Filter
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            ),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = stringResource(R.string.audit_title),
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.secondary
                )
                Text(
                    text = stringResource(R.string.audit_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilterChip(
                        selected = state.auditFilter == AuditLogFilter.ALL,
                        onClick = { viewModel.setAuditFilter(AuditLogFilter.ALL) },
                        label = { Text(text = stringResource(R.string.audit_filter_all)) }
                    )
                    FilterChip(
                        selected = state.auditFilter == AuditLogFilter.DENIED_ONLY,
                        onClick = { viewModel.setAuditFilter(AuditLogFilter.DENIED_ONLY) },
                        label = { Text(text = stringResource(R.string.audit_filter_denied)) }
                    )
                }

                if (state.filteredAuditEntries.isEmpty()) {
                    Text(
                        text = stringResource(R.string.audit_empty),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else {
                    for (entry in state.filteredAuditEntries) {
                        val isDenied = SettingsViewModel.isDeniedOrBlockedAuditDecision(entry.decision)
                        Surface(
                            color = if (isDenied) {
                                MaterialTheme.colorScheme.errorContainer
                            } else {
                                MaterialTheme.colorScheme.surface
                            },
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(modifier = Modifier.padding(10.dp)) {
                                Text(
                                    text = stringResource(
                                        R.string.audit_entry_tool,
                                        bidiFormatter.wrapLtrToken(entry.toolName, locale)
                                    ),
                                    style = MaterialTheme.typography.labelMedium,
                                    fontFamily = FontFamily.Monospace
                                )
                                Text(
                                    text = stringResource(
                                        R.string.confirm_target_label,
                                        bidiFormatter.wrapLtrToken(entry.targetId, locale)
                                    ),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace
                                )
                                Text(
                                    text = stringResource(
                                        R.string.audit_entry_decision,
                                        bidiFormatter.wrapLtrToken(entry.decision, locale)
                                    ),
                                    style = MaterialTheme.typography.bodySmall,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Text(
                                    text = stringResource(
                                        R.string.audit_entry_provenance,
                                        bidiFormatter.wrapLtrToken(entry.provenance.name, locale)
                                    ),
                                    style = MaterialTheme.typography.labelSmall
                                )
                            }
                        }
                        Spacer(modifier = Modifier.height(2.dp))
                    }
                }
            }
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

package com.nava.app.ui.profiles

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.nava.app.R
import com.nava.app.locale.BidiTextFormatter
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.PermissionProfilePreset
import java.util.Locale

/**
 * Security & Permission Profiles screen displaying all 5 immutable built-in presets, custom profiles,
 * orthogonal 5-capability switches, SAF directory tree binding (`ACTION_OPEN_DOCUMENT_TREE` +
 * `takePersistableUriPermission`), and per-target audit log records (Requirement 6).
 */
@OptIn(ExperimentalLayoutApi::class)
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
    val locale = activeLocale

    LaunchedEffect(initialFocusedTargetId) {
        if (!initialFocusedTargetId.isNullOrBlank()) {
            viewModel.selectTarget(initialFocusedTargetId)
        }
    }

    var newProfileName by remember { mutableStateOf("") }

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
                profileId = state.selectedProfileId
            )
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(
            text = stringResource(R.string.profile_title),
            style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.onBackground
        )
        Text(
            text = stringResource(R.string.profile_description),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

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

        // Profile selector list (5 immutable presets + custom profiles)
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            for (profile in state.profiles) {
                val isSelected = profile.id == state.selectedProfileId
                val isImmutable = profile.id in PermissionProfile.IMMUTABLE_PRESET_IDS
                Surface(
                    color = if (isSelected) {
                        MaterialTheme.colorScheme.primaryContainer
                    } else {
                        MaterialTheme.colorScheme.surfaceVariant
                    },
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { viewModel.selectProfile(profile.id) }
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = localizedPresetTitle(profile),
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium
                            )
                            Text(
                                text = localizedPresetDescription(profile.preset),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            if (profile.assignedTargets.isNotEmpty()) {
                                Text(
                                    text = profile.assignedTargets.joinToString(", "),
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        }
                        if (!isImmutable) {
                            TextButton(
                                onClick = { viewModel.deleteCustomProfile(profile.id) }
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

        // Create Custom Profile Row
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            ),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = stringResource(R.string.profile_preset_custom),
                    style = MaterialTheme.typography.titleMedium
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = newProfileName,
                        onValueChange = { newProfileName = it },
                        modifier = Modifier.weight(1f),
                        singleLine = true,
                        placeholder = {
                            Text(text = stringResource(R.string.profile_preset_custom))
                        }
                    )
                    Button(
                        onClick = {
                            if (newProfileName.isNotBlank()) {
                                viewModel.createCustomProfile(customName = newProfileName)
                                newProfileName = ""
                            }
                        },
                        enabled = newProfileName.isNotBlank()
                    ) {
                        Text(text = stringResource(R.string.profile_save_button))
                    }
                }
            }
        }

        // Orthogonal 5-Capability Switches for the Selected Profile
        val selectedProfile = state.selectedProfile
        if (selectedProfile != null) {
            val isBuiltIn = selectedProfile.id in PermissionProfile.IMMUTABLE_PRESET_IDS
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text(
                        text = localizedPresetTitle(selectedProfile),
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.primary
                    )

                    for (capability in AtomicCapability.entries) {
                        val currentLevel = selectedProfile.levelFor(capability)
                        val validLevels = viewModel.validLevelsFor(capability)
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = localizedCapabilityTitle(capability),
                                style = MaterialTheme.typography.titleMedium
                            )
                            Text(
                                text = localizedCapabilityDescription(capability),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                for (level in validLevels) {
                                    FilterChip(
                                        selected = currentLevel == level,
                                        enabled = !isBuiltIn,
                                        onClick = {
                                            viewModel.updateCapabilitySwitch(
                                                profileId = selectedProfile.id,
                                                capability = capability,
                                                level = level
                                            )
                                        },
                                        label = {
                                            Text(text = localizedConfirmationLevelTitle(level))
                                        }
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        // Target Assignment & SAF Directory Grants
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
                    text = stringResource(
                        R.string.confirm_target_label,
                        bidiFormatter.wrapLtrToken(state.selectedTargetId, locale)
                    ),
                    style = MaterialTheme.typography.titleMedium,
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    text = "${stringResource(R.string.nav_profile)}: ${state.selectedTargetProfile.name}",
                    style = MaterialTheme.typography.bodyMedium
                )

                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    val allTargets = (state.canonicalTargets + state.grantedSafTreeTargets).distinct()
                    for (targetId in allTargets) {
                        FilterChip(
                            selected = targetId == state.selectedTargetId,
                            onClick = { viewModel.selectTarget(targetId) },
                            label = {
                                Text(
                                    text = bidiFormatter.wrapLtrToken(targetId, locale),
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                        )
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = {
                            viewModel.assignTargetToProfile(
                                targetId = state.selectedTargetId,
                                profileId = state.selectedProfileId
                            )
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(text = stringResource(R.string.profile_save_button))
                    }
                    OutlinedButton(
                        onClick = { safTreeLauncher.launch(null) },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(text = stringResource(R.string.canvas_neuron_files))
                    }
                }
            }
        }

        // Recent Audit Log Entries for Selected Target
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            ),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = stringResource(R.string.audit_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.secondary
                )
                if (state.targetAuditEntries.isEmpty()) {
                    Text(
                        text = stringResource(R.string.audit_empty),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else {
                    for (entry in state.targetAuditEntries) {
                        Surface(
                            color = MaterialTheme.colorScheme.surface,
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
                                        R.string.audit_entry_decision,
                                        bidiFormatter.wrapLtrToken(entry.decision, locale)
                                    ),
                                    style = MaterialTheme.typography.bodySmall
                                )
                                Text(
                                    text = stringResource(
                                        R.string.audit_entry_provenance,
                                        bidiFormatter.wrapLtrToken(entry.provenance.name, locale)
                                    ),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
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

@Composable
private fun localizedPresetTitle(profile: PermissionProfile): String {
    return when (profile.preset) {
        PermissionProfilePreset.STRICTLY_ISOLATED ->
            stringResource(R.string.profile_preset_strictly_isolated)

        PermissionProfilePreset.NOTIFICATION_SUMMARY_ONLY ->
            stringResource(R.string.profile_preset_notification_summary_only)

        PermissionProfilePreset.SAFE_DRAFT_AND_COMMUNICATION ->
            stringResource(R.string.profile_preset_safe_draft_and_communication)

        PermissionProfilePreset.TRUSTED_SYSTEM_AUTOMATION ->
            stringResource(R.string.profile_preset_trusted_system_automation)

        PermissionProfilePreset.BIOMETRIC_HIGH_SECURITY ->
            stringResource(R.string.profile_preset_biometric_high_security)

        PermissionProfilePreset.CUSTOM -> profile.name
    }
}

@Composable
private fun localizedPresetDescription(preset: PermissionProfilePreset): String {
    return when (preset) {
        PermissionProfilePreset.STRICTLY_ISOLATED ->
            stringResource(R.string.profile_preset_strictly_isolated_desc)

        PermissionProfilePreset.NOTIFICATION_SUMMARY_ONLY ->
            stringResource(R.string.profile_preset_notification_summary_only_desc)

        PermissionProfilePreset.SAFE_DRAFT_AND_COMMUNICATION ->
            stringResource(R.string.profile_preset_safe_draft_and_communication_desc)

        PermissionProfilePreset.TRUSTED_SYSTEM_AUTOMATION ->
            stringResource(R.string.profile_preset_trusted_system_automation_desc)

        PermissionProfilePreset.BIOMETRIC_HIGH_SECURITY ->
            stringResource(R.string.profile_preset_biometric_high_security_desc)

        PermissionProfilePreset.CUSTOM ->
            stringResource(R.string.profile_preset_custom_desc)
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
private fun localizedConfirmationLevelTitle(level: ConfirmationLevel): String {
    return when (level) {
        ConfirmationLevel.DISABLED -> stringResource(R.string.confirmation_level_disabled)
        ConfirmationLevel.AUTO -> stringResource(R.string.confirmation_level_auto)
        ConfirmationLevel.PROMPT_CARD -> stringResource(R.string.confirmation_level_prompt_card)
        ConfirmationLevel.BIOMETRIC -> stringResource(R.string.confirmation_level_biometric)
    }
}

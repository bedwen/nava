package com.nava.app.ui.onboarding

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
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
import androidx.compose.ui.unit.dp
import com.nava.app.R
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.ui.components.NavaIcons
import com.nava.app.ui.theme.NavaExtendedColors
import com.nava.app.ui.theme.NavaThemeExtras
import com.nava.domain.ai.RamTier
import java.util.Locale
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * Multi-step Default-Deny Onboarding Wizard Compose screen (Requirement 5).
 */
@Composable
fun OnboardingScreen(
    viewModel: OnboardingViewModel,
    onOnboardingFinished: () -> Unit,
    modifier: Modifier = Modifier
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val haptics = LocalHapticFeedback.current
    val colors = NavaThemeExtras.colors
    val bidiFormatter = remember { BidiTextFormatter() }
    val activeLocale = remember(state.activeLocaleTag) {
        Locale.forLanguageTag(state.activeLocaleTag)
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
                spec = state.selectedModelSpec
            )
        }
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
            .statusBarsPadding()
            .navigationBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Subtle Nava concentric ring emblem + title header
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Surface(
                shape = CircleShape,
                color = colors.bgLinen,
                border = BorderStroke(1.dp, colors.borderStone),
                modifier = Modifier.size(48.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        imageVector = NavaIcons.HubRing,
                        contentDescription = null,
                        tint = colors.trustNavyTint,
                        modifier = Modifier.size(26.dp)
                    )
                }
            }
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                Text(
                    text = stringResource(R.string.onboarding_title),
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold,
                    color = colors.inkPrimary
                )
                Text(
                    text = stringResource(R.string.onboarding_subtitle),
                    style = MaterialTheme.typography.bodyMedium,
                    color = colors.inkSecondary
                )
            }
        }

        // Calm 4-step architectural progress bar
        OnboardingStepProgress(
            currentStep = state.currentStep,
            colors = colors
        )

        state.errorMessage?.let { err ->
            Surface(
                color = colors.alertCrimsonSurface,
                shape = RoundedCornerShape(12.dp),
                border = BorderStroke(1.dp, colors.alertCrimson.copy(alpha = 0.4f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = bidiFormatter.wrapText(err, activeLocale),
                    style = MaterialTheme.typography.bodySmall,
                    color = colors.alertCrimson,
                    modifier = Modifier.padding(12.dp)
                )
            }
        }

        when (state.currentStep) {
            OnboardingStep.DEFAULT_DENY_EXPLANATION -> {
                OnboardingGroupCard(colors = colors) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Icon(
                            imageVector = NavaIcons.Shield,
                            contentDescription = null,
                            tint = colors.trustNavyTint,
                            modifier = Modifier.size(20.dp)
                        )
                        Text(
                            text = stringResource(R.string.onboarding_default_deny_title),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = colors.inkPrimary
                        )
                    }
                    Text(
                        text = stringResource(R.string.onboarding_default_deny_description),
                        style = MaterialTheme.typography.bodyMedium,
                        color = colors.inkSecondary
                    )
                }

                OnboardingGroupCard(colors = colors) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Icon(
                            imageVector = NavaIcons.Lock,
                            contentDescription = null,
                            tint = colors.verifiedForest,
                            modifier = Modifier.size(20.dp)
                        )
                        Text(
                            text = stringResource(R.string.onboarding_zero_network_title),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                            color = colors.inkPrimary
                        )
                    }
                    Text(
                        text = stringResource(R.string.onboarding_zero_network_description),
                        style = MaterialTheme.typography.bodyMedium,
                        color = colors.inkSecondary
                    )
                }

                Button(
                    onClick = { viewModel.acknowledgeDefaultDenyAndContinue() },
                    colors = primaryButtonColors,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp)
                ) {
                    Text(
                        text = stringResource(R.string.onboarding_button_continue),
                        style = MaterialTheme.typography.labelLarge
                    )
                }
            }

            OnboardingStep.LANGUAGE_PICKER -> {
                Surface(
                    color = colors.surfaceCard,
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, colors.borderStone),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        Column(
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Text(
                                text = stringResource(R.string.settings_language_title),
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = colors.inkPrimary
                            )

                            OutlinedTextField(
                                value = state.languageSearchQuery,
                                onValueChange = { viewModel.onLanguageSearchQueryChanged(it) },
                                modifier = Modifier.fillMaxWidth(),
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
                                        color = colors.inkMuted
                                    )
                                }
                            )
                        }

                        val visibleLanguages = state.filteredLanguages.take(25)
                        for (entry in visibleLanguages) {
                            HorizontalDivider(thickness = 0.5.dp, color = colors.borderStone)
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
                                    }
                                    .padding(horizontal = 16.dp, vertical = 12.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(
                                    modifier = Modifier
                                        .weight(1f)
                                        .padding(end = 12.dp)
                                ) {
                                    Text(
                                        text = bidiFormatter.wrapText(displayName, activeLocale),
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = if (isSelected) {
                                            FontWeight.SemiBold
                                        } else {
                                            FontWeight.Normal
                                        },
                                        color = colors.inkPrimary
                                    )
                                    Text(
                                        text = bidiFormatter.wrapLtrToken(
                                            entry.bcp47Tag,
                                            activeLocale
                                        ),
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = FontFamily.Monospace,
                                        color = colors.inkMuted
                                    )
                                }
                                Box(
                                    modifier = Modifier
                                        .size(18.dp)
                                        .clip(CircleShape)
                                        .border(
                                            width = if (isSelected) 2.dp else 1.5.dp,
                                            color = if (isSelected) {
                                                colors.trustNavyTint
                                            } else {
                                                colors.borderStone
                                            },
                                            shape = CircleShape
                                        ),
                                    contentAlignment = Alignment.Center
                                ) {
                                    if (isSelected) {
                                        Box(
                                            modifier = Modifier
                                                .size(8.dp)
                                                .clip(CircleShape)
                                                .background(colors.trustNavyTint)
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedButton(
                        onClick = { viewModel.navigateBack() },
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, colors.borderStone),
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp)
                    ) {
                        Text(
                            text = stringResource(R.string.action_cancel),
                            color = colors.inkPrimary
                        )
                    }
                    Button(
                        onClick = { viewModel.proceedToModelProvisioning() },
                        colors = primaryButtonColors,
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp)
                    ) {
                        Text(text = stringResource(R.string.onboarding_button_continue))
                    }
                }
            }

            OnboardingStep.MODEL_PROVISIONING -> {
                Text(
                    text = stringResource(R.string.settings_model_title),
                    style = MaterialTheme.typography.titleLarge,
                    color = colors.inkPrimary
                )

                if (state.ramTier == RamTier.TIER_0_LOW_MEMORY) {
                    Surface(
                        color = colors.untrustedSurface,
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, colors.untrustedAccent.copy(alpha = 0.4f)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = stringResource(R.string.hub_tier_0_low_memory_notice),
                            style = MaterialTheme.typography.bodySmall,
                            color = colors.untrustedAccent,
                            modifier = Modifier.padding(12.dp)
                        )
                    }
                }

                // 2x temporary storage headroom notice
                Surface(
                    color = colors.untrustedSurface,
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, colors.untrustedAccent.copy(alpha = 0.4f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            text = stringResource(R.string.onboarding_saf_headroom_notice),
                            style = MaterialTheme.typography.bodyMedium,
                            color = colors.untrustedAccent
                        )
                        val requiredGb = String.format(
                            Locale.US,
                            "%.2f GB",
                            state.requiredTwoTimesHeadroomBytes.toDouble() / (1024.0 * 1024.0 * 1024.0)
                        )
                        Text(
                            text = bidiFormatter.wrapLtrToken("2x + 256 MiB: $requiredGb", activeLocale),
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = colors.untrustedAccent
                        )
                    }
                }

                OnboardingGroupCard(colors = colors) {
                    for (spec in state.eligibleModelSpecs) {
                        val isSelected = spec.modelId == state.selectedModelSpec.modelId
                        Surface(
                            color = if (isSelected) colors.navIndicator else colors.bgLinen,
                            shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(
                                width = 1.dp,
                                color = if (isSelected) {
                                    colors.trustNavyTint.copy(alpha = 0.55f)
                                } else {
                                    colors.borderStone
                                }
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { viewModel.selectModelSpec(spec) }
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(
                                    modifier = Modifier
                                        .weight(1f)
                                        .padding(end = 8.dp)
                                ) {
                                    Text(
                                        text = bidiFormatter.wrapLtrToken(spec.modelId, activeLocale),
                                        style = MaterialTheme.typography.titleMedium,
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.SemiBold,
                                        color = colors.inkPrimary
                                    )
                                    Text(
                                        text = bidiFormatter.wrapLtrToken(spec.fileName, activeLocale),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = colors.inkSecondary
                                    )
                                }
                                RadioButton(
                                    selected = isSelected,
                                    onClick = { viewModel.selectModelSpec(spec) },
                                    colors = RadioButtonDefaults.colors(
                                        selectedColor = colors.trustNavyTint,
                                        unselectedColor = colors.inkMuted
                                    )
                                )
                            }
                        }
                    }
                }

                Button(
                    onClick = { safModelLauncher.launch(arrayOf("*/*")) },
                    colors = primaryButtonColors,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp)
                ) {
                    Text(text = stringResource(R.string.onboarding_button_import_model))
                }

                OutlinedButton(
                    onClick = { viewModel.continueInDeterministicMode() },
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, colors.borderStone),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp)
                ) {
                    Text(
                        text = stringResource(R.string.hub_status_outer_shell),
                        color = colors.inkPrimary
                    )
                }
            }

            OnboardingStep.COMPLETE -> {
                OnboardingGroupCard(colors = colors) {
                    Text(
                        text = stringResource(R.string.onboarding_default_deny_title),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = colors.inkPrimary
                    )
                    Text(
                        text = stringResource(R.string.profile_preset_strictly_isolated_desc),
                        style = MaterialTheme.typography.bodyMedium,
                        color = colors.inkSecondary
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    val hasModel = state.selectedModelId != null
                    Surface(
                        color = if (hasModel) colors.verifiedMint else colors.bgLinen,
                        shape = RoundedCornerShape(999.dp),
                        border = BorderStroke(
                            width = 1.dp,
                            color = if (hasModel) {
                                colors.verifiedForest.copy(alpha = 0.25f)
                            } else {
                                colors.borderStone
                            }
                        )
                    ) {
                        Text(
                            text = if (hasModel) {
                                stringResource(
                                    R.string.settings_model_status_loaded,
                                    bidiFormatter.wrapLtrToken(state.selectedModelId!!, activeLocale)
                                )
                            } else {
                                stringResource(R.string.settings_model_status_missing)
                            },
                            style = MaterialTheme.typography.labelMedium,
                            fontFamily = FontFamily.Monospace,
                            color = if (hasModel) colors.verifiedForest else colors.inkSecondary,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                        )
                    }
                }

                Button(
                    onClick = {
                        viewModel.completeOnboarding()
                        onOnboardingFinished()
                    },
                    colors = primaryButtonColors,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp)
                ) {
                    Text(
                        text = stringResource(R.string.onboarding_button_get_started),
                        style = MaterialTheme.typography.labelLarge
                    )
                }
            }
        }
    }
}

@Composable
private fun OnboardingStepProgress(
    currentStep: OnboardingStep,
    colors: NavaExtendedColors
) {
    val activeIndex = currentStep.ordinal
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        for (step in OnboardingStep.entries) {
            val isReached = step.ordinal <= activeIndex
            Box(
                modifier = Modifier
                    .weight(1f)
                    .height(4.dp)
                    .background(
                        color = if (isReached) colors.trustNavyTint else colors.borderStone,
                        shape = RoundedCornerShape(999.dp)
                    )
            )
        }
    }
}

@Composable
private fun OnboardingGroupCard(
    colors: NavaExtendedColors,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = colors.surfaceCard),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, colors.borderStone),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        modifier = modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            content = content
        )
    }
}

@Composable
private fun onboardingTextFieldColors(colors: NavaExtendedColors) = OutlinedTextFieldDefaults.colors(
    focusedContainerColor = colors.surfaceCard,
    unfocusedContainerColor = colors.bgLinen,
    focusedBorderColor = colors.trustNavyTint,
    unfocusedBorderColor = colors.borderStone,
    focusedTextColor = colors.inkPrimary,
    unfocusedTextColor = colors.inkPrimary,
    cursorColor = colors.trustNavyTint
)

package com.nava.app.share

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.nava.app.R
import com.nava.app.di.AppContainer
import com.nava.app.di.NavaApplication
import com.nava.app.locale.BidiTextFormatter
import com.nava.app.ui.components.NavaIcons
import com.nava.app.ui.theme.NavaTheme
import com.nava.app.ui.theme.NavaThemeExtras
import com.nava.app.ui.theme.NavaThemeMode
import java.util.Locale
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * Modal bottom-sheet [AppCompatActivity] receiving `Intent.ACTION_SEND` (`text/plain`) payloads
 * for offline Share -> Nava analysis, encrypted note capture, and explicit reminder confirmation.
 *
 * Security invariants:
 * - Ingested text is immediately sanitized and tagged [com.nava.domain.security.DataProvenance.UNTRUSTED_EXTERNAL].
 * - Never auto-executes tools on share launch.
 * - Extracted reminder drafts always present an explicit Untrusted External Source Confirmation Card.
 */
class NavaShareSheetActivity : AppCompatActivity() {

    private val appContainer: AppContainer
        get() = (application as NavaApplication).appContainer

    private lateinit var shareViewModel: NavaShareSheetViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        shareViewModel = ViewModelProvider(
            this,
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return NavaShareSheetViewModel(container = appContainer) as T
                }
            }
        )[NavaShareSheetViewModel::class.java]

        handleIncomingShareIntent(intent)

        setContent {
            val activeLocaleTag by appContainer.appLocaleManager.activeLocaleTagFlow.collectAsStateWithLifecycle()
            val activeLocale = remember(activeLocaleTag) {
                Locale.forLanguageTag(activeLocaleTag)
            }
            val themeMode by appContainer.themePreferenceStore.themeModeFlow.collectAsStateWithLifecycle()
            val darkOverride = when (themeMode) {
                NavaThemeMode.DARK -> true
                NavaThemeMode.LIGHT -> false
                NavaThemeMode.SYSTEM -> null
            }

            NavaTheme(
                isDarkThemeOverride = darkOverride,
                activeLocale = activeLocale
            ) {
                NavaShareSheetContent(
                    viewModel = shareViewModel,
                    bidiFormatter = appContainer.bidiTextFormatter,
                    locale = activeLocale,
                    onDismissSheet = { finish() }
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingShareIntent(intent)
    }

    private fun handleIncomingShareIntent(incoming: Intent?) {
        if (incoming == null) {
            shareViewModel.ingestSharedText(null, null)
            return
        }
        val action = runCatching { incoming.action }.getOrNull()
        if (action != Intent.ACTION_SEND) {
            shareViewModel.ingestSharedText(null, null)
            return
        }
        val rawText = runCatching { incoming.getStringExtra(Intent.EXTRA_TEXT) }.getOrNull()
        val rawSubject = runCatching { incoming.getStringExtra(Intent.EXTRA_SUBJECT) }.getOrNull()
        shareViewModel.ingestSharedText(rawText = rawText, rawSubject = rawSubject)
    }
}

@Composable
private fun NavaShareSheetContent(
    viewModel: NavaShareSheetViewModel,
    bidiFormatter: BidiTextFormatter,
    locale: Locale,
    onDismissSheet: () -> Unit
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val colors = NavaThemeExtras.colors
    val scrimInteraction = remember { MutableInteractionSource() }
    val sheetInteraction = remember { MutableInteractionSource() }
    val hasSharedText = uiState.sharedText != null
    val actionsEnabled = hasSharedText && !uiState.isBusy

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.50f))
            .clickable(
                interactionSource = scrimInteraction,
                indication = null,
                onClick = onDismissSheet
            ),
        contentAlignment = Alignment.BottomCenter
    ) {
        Surface(
            shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
            color = colors.surfaceCard,
            contentColor = colors.inkPrimary,
            border = BorderStroke(1.dp, colors.borderStone),
            modifier = Modifier
                .fillMaxWidth()
                .imePadding()
                .clickable(
                    interactionSource = sheetInteraction,
                    indication = null,
                    onClick = {}
                )
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .navigationBarsPadding()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp, vertical = 14.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Box(
                    modifier = Modifier.fillMaxWidth(),
                    contentAlignment = Alignment.Center
                ) {
                    Box(
                        modifier = Modifier
                            .width(36.dp)
                            .height(4.dp)
                            .background(colors.borderStone, RoundedCornerShape(999.dp))
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = NavaIcons.Shield,
                            contentDescription = null,
                            tint = colors.trustNavyTint,
                            modifier = Modifier.size(20.dp)
                        )
                        Text(
                            text = stringResource(R.string.share_sheet_title),
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.SemiBold,
                            color = colors.inkPrimary
                        )
                    }
                    TextButton(onClick = onDismissSheet) {
                        Text(
                            text = stringResource(R.string.action_cancel),
                            color = colors.inkSecondary
                        )
                    }
                }

                HorizontalDivider(
                    thickness = 1.dp,
                    color = colors.borderStone
                )

                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = colors.untrustedSurface,
                    border = BorderStroke(1.dp, colors.untrustedAccent.copy(alpha = 0.45f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = NavaIcons.Shield,
                            contentDescription = null,
                            tint = colors.untrustedAccent,
                            modifier = Modifier.size(16.dp)
                        )
                        Text(
                            text = stringResource(R.string.share_untrusted_badge),
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Medium,
                            color = colors.untrustedAccent
                        )
                    }
                }

                if (uiState.sharedText != null) {
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = colors.bgLinen,
                        border = BorderStroke(1.dp, colors.borderStone),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            val subject = uiState.sharedSubject
                            if (!subject.isNullOrBlank()) {
                                Text(
                                    text = bidiFormatter.wrapText(subject, locale),
                                    style = MaterialTheme.typography.labelLarge,
                                    fontWeight = FontWeight.SemiBold,
                                    color = colors.inkPrimary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                            Text(
                                text = bidiFormatter.wrapText(uiState.sharedText?.value.orEmpty(), locale),
                                style = MaterialTheme.typography.bodyMedium,
                                color = colors.inkSecondary,
                                maxLines = 4,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }

                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        ShareActionPill(
                            label = stringResource(R.string.share_action_summarize),
                            enabled = actionsEnabled,
                            onClick = { viewModel.summarizeThreeBullets() },
                            modifier = Modifier.weight(1f)
                        )
                        ShareActionPill(
                            label = stringResource(R.string.share_action_rewrite_polite),
                            enabled = actionsEnabled,
                            onClick = { viewModel.rewriteOrTranslate(ShareRewriteMode.POLITE) },
                            modifier = Modifier.weight(1f)
                        )
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        ShareActionPill(
                            label = stringResource(R.string.share_action_translate_en),
                            enabled = actionsEnabled,
                            onClick = { viewModel.rewriteOrTranslate(ShareRewriteMode.TRANSLATE_EN) },
                            modifier = Modifier.weight(1f)
                        )
                        ShareActionPill(
                            label = stringResource(R.string.share_action_translate_tr),
                            enabled = actionsEnabled,
                            onClick = { viewModel.rewriteOrTranslate(ShareRewriteMode.TRANSLATE_TR) },
                            modifier = Modifier.weight(1f)
                        )
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        ShareActionPill(
                            label = stringResource(R.string.share_action_save_note),
                            enabled = actionsEnabled,
                            onClick = { viewModel.saveToNotes() },
                            modifier = Modifier.weight(1f)
                        )
                        ShareActionPill(
                            label = stringResource(R.string.share_action_extract_date),
                            enabled = actionsEnabled,
                            onClick = { viewModel.extractDateDraft() },
                            modifier = Modifier.weight(1f)
                        )
                    }
                }

                if (uiState.isBusy) {
                    LinearProgressIndicator(
                        modifier = Modifier.fillMaxWidth(),
                        color = colors.trustNavyTint,
                        trackColor = colors.bgLinen
                    )
                }

                val resultText = uiState.resultText
                if (!resultText.isNullOrBlank()) {
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = colors.bgPaper,
                        border = BorderStroke(1.dp, colors.borderStone),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = bidiFormatter.wrapText(resultText, locale),
                            style = MaterialTheme.typography.bodyMedium,
                            color = colors.inkPrimary,
                            modifier = Modifier.padding(12.dp)
                        )
                    }
                }

                val errorMessage = uiState.errorMessage
                if (!errorMessage.isNullOrBlank()) {
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = colors.untrustedSurface,
                        border = BorderStroke(1.dp, colors.untrustedAccent.copy(alpha = 0.55f)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = errorMessage,
                            style = MaterialTheme.typography.bodyMedium,
                            color = colors.untrustedAccent,
                            modifier = Modifier.padding(12.dp)
                        )
                    }
                }

                val statusMessage = uiState.statusMessage
                if (!statusMessage.isNullOrBlank()) {
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = colors.bgLinen,
                        border = BorderStroke(1.dp, colors.borderStone),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = statusMessage,
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            color = colors.trustNavyTint,
                            modifier = Modifier.padding(12.dp)
                        )
                    }
                }

                val draft = uiState.extractedDraft
                if (draft != null) {
                    ShareExtractedDraftConfirmationCard(
                        draft = draft,
                        isBusy = uiState.isBusy,
                        bidiFormatter = bidiFormatter,
                        locale = locale,
                        onConfirm = { viewModel.confirmExtractedReminderDraft() },
                        onDismiss = { viewModel.dismissExtractedDraft() }
                    )
                }
            }
        }
    }
}

@Composable
private fun ShareActionPill(
    label: String,
    enabled: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val colors = NavaThemeExtras.colors
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        shape = RoundedCornerShape(999.dp),
        border = BorderStroke(1.dp, colors.borderStone),
        colors = ButtonDefaults.outlinedButtonColors(
            containerColor = colors.bgPaper,
            contentColor = colors.inkPrimary,
            disabledContainerColor = colors.bgLinen,
            disabledContentColor = colors.inkMuted
        ),
        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
        modifier = modifier
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun ShareExtractedDraftConfirmationCard(
    draft: ExtractedShareScheduleDraft,
    isBusy: Boolean,
    bidiFormatter: BidiTextFormatter,
    locale: Locale,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    val colors = NavaThemeExtras.colors
    Surface(
        shape = RoundedCornerShape(14.dp),
        color = colors.untrustedSurface,
        border = BorderStroke(1.dp, colors.untrustedAccent),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = stringResource(R.string.share_untrusted_badge),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = colors.untrustedAccent
            )
            Text(
                text = stringResource(R.string.share_confirm_reminder_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = colors.inkPrimary
            )
            Text(
                text = bidiFormatter.wrapText(draft.title, locale),
                style = MaterialTheme.typography.bodyMedium,
                color = colors.inkPrimary
            )
            if (!draft.triggerAtIso.isNullOrBlank()) {
                Text(
                    text = bidiFormatter.wrapLtrToken(draft.triggerAtIso),
                    style = MaterialTheme.typography.labelLarge,
                    color = colors.trustNavyTint
                )
            }
            Text(
                text = draft.sourceLabel,
                style = MaterialTheme.typography.labelSmall,
                color = colors.inkMuted
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = onDismiss,
                    enabled = !isBusy,
                    border = BorderStroke(1.dp, colors.borderStone),
                    colors = ButtonDefaults.outlinedButtonColors(
                        containerColor = colors.surfaceCard,
                        contentColor = colors.inkSecondary
                    ),
                    modifier = Modifier.weight(1f)
                ) {
                    Text(text = stringResource(R.string.action_cancel))
                }
                Button(
                    onClick = onConfirm,
                    enabled = !isBusy,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = colors.trustNavy,
                        contentColor = colors.bgPaper
                    ),
                    modifier = Modifier.weight(1f)
                ) {
                    Text(
                        text = stringResource(R.string.share_confirm_reminder_cta),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}

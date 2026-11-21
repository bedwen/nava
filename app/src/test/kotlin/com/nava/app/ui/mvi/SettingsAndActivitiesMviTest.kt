package com.nava.app.ui.mvi

import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import com.nava.app.MainActivity
import com.nava.app.assistant.AssistantIntentContract
import com.nava.app.assistant.NavaAssistantSheetActivity
import com.nava.app.di.AppContainer
import com.nava.app.di.PinnedModelCatalog
import com.nava.app.security.NotificationResolutionResult
import com.nava.app.security.PendingConfirmationStore
import com.nava.app.ui.settings.AuditLogFilter
import com.nava.app.ui.settings.SettingsViewModel
import com.nava.app.ui.settings.SystemIntegrationTarget
import com.nava.app.ui.theme.NavaTypography
import com.nava.app.ui.theme.resolveLayoutDirectionForLocale
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.DataProvenance
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.LayoutDirection
import java.io.ByteArrayInputStream
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class SettingsAndActivitiesMviTest {

    private lateinit var tempVaultDir: File
    private lateinit var tempModelsDir: File

    @Before
    fun setUp() {
        tempVaultDir = Files.createTempDirectory("nava_settings_test_vault").toFile()
        tempModelsDir = Files.createTempDirectory("nava_settings_test_models").toFile()
    }

    @After
    fun tearDown() {
        tempVaultDir.deleteRecursively()
        tempModelsDir.deleteRecursively()
    }

    @Test
    fun settingsLanguagePickerModelProvisioningVaultControlsAndAuditFilterWorkCleanly() = runTest {
        val nowMs = 1_760_000_900_000L
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            clockMs = { nowMs },
            ioDispatcher = Dispatchers.Unconfined
        )

        // Provision a synthetic model file so SettingsViewModel lists it
        val modelBytes = "synthetic-e2b-model-payload".repeat(32).toByteArray()
        val digestHex = sha256Hex(modelBytes)
        val testSpec = PinnedModelCatalog.GEMMA_4_E2B_SPEC.copy(
            expectedSha256Hex = digestHex,
            expectedSizeBytes = modelBytes.size.toLong()
        )
        container.safModelProvisioner.importFromStream(
            inputStream = ByteArrayInputStream(modelBytes),
            sourceSizeBytes = modelBytes.size.toLong(),
            pinnedSpec = testSpec
        )

        // Record both ALLOWED/SUCCESS and DENIED audit log entries
        container.auditLogDao.record(
            AuditLogEntry(
                timestampEpochMs = nowMs - 2_000L,
                toolName = "set_alarm",
                targetId = "system.clock",
                actionSummary = "Executed tool set_alarm",
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "SUCCESS"
            )
        )
        container.auditLogDao.record(
            AuditLogEntry(
                timestampEpochMs = nowMs - 1_000L,
                toolName = "place_call",
                targetId = "system.phone",
                actionSummary = "CAPABILITY_DISABLED",
                provenance = DataProvenance.UNTRUSTED_EXTERNAL,
                decision = "DENIED"
            )
        )

        val vm = SettingsViewModel(
            container = container,
            dispatcher = Dispatchers.Unconfined,
            clockMs = { nowMs }
        )
        try {
            vm.awaitRefresh()

            // 1. Searchable language picker over SupportedLanguageCatalog + AppLocaleManager
            assertTrue(vm.uiState.value.allLanguages.size >= 5)
            vm.onLanguageSearchQueryChanged("arab")
            assertTrue(vm.uiState.value.filteredLanguages.any { it.bcp47Tag == "ar" })

            vm.selectLanguage("ar").join()
            assertEquals("ar", vm.uiState.value.activeLocaleTag)
            assertTrue(container.appLocaleManager.isCurrentLocaleRtl())

            // 2. Provisioned model list, selection, and deletion
            assertEquals(1, vm.uiState.value.provisionedModels.size)
            assertEquals(PinnedModelCatalog.FILE_NAME_GEMMA4_E2B, vm.uiState.value.provisionedModels.first().fileName)

            vm.selectActiveModel(PinnedModelCatalog.MODEL_ID_GEMMA4_E2B).join()
            assertEquals(PinnedModelCatalog.MODEL_ID_GEMMA4_E2B, vm.uiState.value.selectedModelId)

            vm.deleteProvisionedModel(PinnedModelCatalog.FILE_NAME_GEMMA4_E2B).join()
            assertTrue(vm.uiState.value.provisionedModels.isEmpty())
            assertNull(vm.uiState.value.selectedModelId)

            // 3. Vault biometric unlock & immediate zeroization lock controls
            assertFalse(vm.uiState.value.isVaultUnlocked)
            vm.unlockVault(activity = null).join()
            assertTrue(vm.uiState.value.isVaultUnlocked)
            assertTrue(container.navaVault.isUnlocked())

            vm.lockVault().join()
            assertFalse(vm.uiState.value.isVaultUnlocked)
            assertFalse(container.navaVault.isUnlocked())

            // 4. System integration intent tracking
            vm.onSystemIntegrationRequested(SystemIntegrationTarget.ASSISTANT_ROLE)
            assertEquals(SystemIntegrationTarget.ASSISTANT_ROLE, vm.uiState.value.lastRequestedSystemTarget)

            // 5. Audit log viewer ALL vs DENIED_ONLY filter
            assertEquals(2, vm.uiState.value.allAuditEntries.size)
            assertEquals(2, vm.uiState.value.filteredAuditEntries.size)

            vm.setAuditFilter(AuditLogFilter.DENIED_ONLY)
            assertEquals(AuditLogFilter.DENIED_ONLY, vm.uiState.value.auditFilter)
            assertEquals(1, vm.uiState.value.filteredAuditEntries.size)
            assertEquals("DENIED", vm.uiState.value.filteredAuditEntries.first().decision)
            assertEquals("place_call", vm.uiState.value.filteredAuditEntries.first().toolName)
        } finally {
            vm.clearForTesting()
        }
    }

    @Test
    fun mainActivityAndAssistantSheetActivityExtendAppCompatActivityAndRejectForgedIntents() = runTest {
        val nowMs = 1_760_001_000_000L
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            clockMs = { nowMs },
            ioDispatcher = Dispatchers.Unconfined
        )

        // Verify both MainActivity and NavaAssistantSheetActivity extend AppCompatActivity
        assertTrue(
            "MainActivity must extend AppCompatActivity for BiometricPrompt and AppCompatDelegate",
            AppCompatActivity::class.java.isAssignableFrom(MainActivity::class.java)
        )
        assertTrue(
            "NavaAssistantSheetActivity must extend AppCompatActivity for BiometricPrompt and AppCompatDelegate",
            AppCompatActivity::class.java.isAssignableFrom(NavaAssistantSheetActivity::class.java)
        )

        // Verify NavaTheme Typography uses FontFamily.Default (system Noto fallback) and RTL resolution
        assertEquals(FontFamily.Default, NavaTypography.bodyLarge.fontFamily)
        assertEquals(FontFamily.Default, NavaTypography.titleLarge.fontFamily)
        assertEquals(LayoutDirection.Rtl, resolveLayoutDirectionForLocale(Locale.forLanguageTag("ar")))
        assertEquals(LayoutDirection.Ltr, resolveLayoutDirectionForLocale(Locale.forLanguageTag("en")))
        assertEquals(LayoutDirection.Ltr, resolveLayoutDirectionForLocale(Locale.forLanguageTag("tr")))

        // Forged confirmation extras in pure map & Intent resolution must be rejected without running any tool
        val forgedExtras = AssistantIntentContract.extractConfirmationExtrasFromMap(
            mapOf(
                AssistantIntentContract.EXTRA_OPEN_MODE to AssistantIntentContract.OPEN_MODE_CONFIRMATION,
                AssistantIntentContract.EXTRA_REQUEST_ID to "forged_req_999",
                AssistantIntentContract.EXTRA_REQUIRES_BIOMETRIC to false
            )
        )
        val storeResolution = container.pendingConfirmationStore.resolveFromNotificationExtras(
            extras = forgedExtras,
            nowEpochMs = nowMs
        )
        assertTrue(storeResolution is NotificationResolutionResult.Rejected)
        assertEquals(
            PendingConfirmationStore.REASON_UNREGISTERED_REQUEST,
            (storeResolution as NotificationResolutionResult.Rejected).reasonCode
        )
        assertNull(container.pendingConfirmationStore.activeConfirmationFlow.value)

        // Forged ruleId that is not APPROVED_ACTIVE and HMAC-sealed in RuleCapabilityGrantManager
        val forgedRuleExtras = AssistantIntentContract.extractConfirmationExtrasFromMap(
            mapOf(
                AssistantIntentContract.EXTRA_OPEN_MODE to AssistantIntentContract.OPEN_MODE_CONFIRMATION,
                AssistantIntentContract.EXTRA_RULE_ID to "forged_rule_unsealed"
            )
        )
        val ruleResolution = container.pendingConfirmationStore.resolveFromNotificationExtras(
            extras = forgedRuleExtras,
            nowEpochMs = nowMs
        )
        assertTrue(ruleResolution is NotificationResolutionResult.Rejected)
        assertEquals(
            PendingConfirmationStore.REASON_RULE_NOT_VERIFIED,
            (ruleResolution as NotificationResolutionResult.Rejected).reasonCode
        )

        // Direct resolution through MainActivity and NavaAssistantSheetActivity helpers
        val nullIntentRejected = container.pendingConfirmationStore.resolveFromIntent(null, nowMs)
        assertTrue(nullIntentRejected is NotificationResolutionResult.Rejected)

        val mainForgedResolution = MainActivity.resolveIncomingConfirmationExtras(
            extras = forgedExtras,
            container = container,
            nowEpochMs = nowMs
        )
        assertTrue(mainForgedResolution is NotificationResolutionResult.Rejected)
        assertEquals(
            PendingConfirmationStore.REASON_UNREGISTERED_REQUEST,
            (mainForgedResolution as NotificationResolutionResult.Rejected).reasonCode
        )

        val sheetForgedResolution = NavaAssistantSheetActivity.resolveSheetConfirmationExtras(
            extras = forgedRuleExtras,
            container = container,
            nowEpochMs = nowMs
        )
        assertTrue(sheetForgedResolution is NotificationResolutionResult.Rejected)
        assertEquals(
            PendingConfirmationStore.REASON_RULE_NOT_VERIFIED,
            (sheetForgedResolution as NotificationResolutionResult.Rejected).reasonCode
        )

        assertNull(MainActivity.resolveIncomingConfirmationIfPresent(null, container, nowMs))
        assertNull(NavaAssistantSheetActivity.resolveSheetIntent(null, container, nowMs))
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }
}

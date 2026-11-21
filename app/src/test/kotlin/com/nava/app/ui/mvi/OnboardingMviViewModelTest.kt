package com.nava.app.ui.mvi

import com.nava.app.di.AppContainer
import com.nava.app.di.PinnedModelCatalog
import com.nava.app.ui.onboarding.OnboardingStep
import com.nava.app.ui.onboarding.OnboardingViewModel
import com.nava.app.ui.profiles.PermissionProfilesUiState
import com.nava.domain.automation.BackgroundTaskRequest
import com.nava.domain.automation.BackgroundTaskStatus
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.PermissionProfile
import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class OnboardingMviViewModelTest {

    private lateinit var tempVaultDir: File
    private lateinit var tempModelsDir: File

    @Before
    fun setUp() {
        tempVaultDir = Files.createTempDirectory("nava_onboarding_test_vault").toFile()
        tempModelsDir = Files.createTempDirectory("nava_onboarding_test_models").toFile()
    }

    @After
    fun tearDown() {
        tempVaultDir.deleteRecursively()
        tempModelsDir.deleteRecursively()
    }

    @Test
    fun onboardingWizardPreservesStrictDefaultDenyAndEnqueuesSafModelImport() = runTest {
        val nowMs = 1_760_000_500_000L
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            clockMs = { nowMs },
            ioDispatcher = Dispatchers.Unconfined
        )

        val vm = OnboardingViewModel(
            container = container,
            dispatcher = Dispatchers.Unconfined,
            clockMs = { nowMs }
        )

        // Step 1: Starts at DEFAULT_DENY_EXPLANATION with onboarding incomplete
        assertEquals(OnboardingStep.DEFAULT_DENY_EXPLANATION, vm.uiState.value.currentStep)
        assertFalse(vm.uiState.value.isDefaultDenyAcknowledged)
        assertFalse(vm.uiState.value.isOnboardingCompleted)

        // Step 1 -> Step 2: Acknowledge Default-Deny
        vm.acknowledgeDefaultDenyAndContinue()
        assertTrue(vm.uiState.value.isDefaultDenyAcknowledged)
        assertEquals(OnboardingStep.LANGUAGE_PICKER, vm.uiState.value.currentStep)

        // Step 2: Language Picker over SupportedLanguageCatalog via AppLocaleManager
        assertTrue("Expected non-empty SupportedLanguageCatalog", vm.uiState.value.allLanguages.isNotEmpty())
        vm.onLanguageSearchQueryChanged("turk")
        assertTrue(vm.uiState.value.filteredLanguages.any { it.bcp47Tag == "tr" })

        vm.selectLanguage("tr-TR")
        assertEquals("tr", vm.uiState.value.activeLocaleTag)
        assertEquals("tr", container.appLocaleManager.currentLocaleTag())

        // Step 2 -> Step 3: Proceed to Model Provisioning
        vm.proceedToModelProvisioning()
        assertEquals(OnboardingStep.MODEL_PROVISIONING, vm.uiState.value.currentStep)

        // Verify 2x temporary storage headroom notice calculation
        vm.selectModelSpec(PinnedModelCatalog.GEMMA_4_E4B_SPEC)
        assertEquals(
            PinnedModelCatalog.temporaryTwoTimesStorageBytes(PinnedModelCatalog.GEMMA_4_E4B_SPEC),
            vm.uiState.value.requiredTwoTimesHeadroomBytes
        )

        // Step 3 -> Step 4: Enqueue SAF .litertlm model import via BackgroundTaskContinuationPort
        val safUri = "content://com.android.externalstorage.documents/document/primary%3Agemma-4-E4B-it.litertlm"
        vm.enqueueSafModelImport(
            sourceUri = safUri,
            spec = PinnedModelCatalog.GEMMA_4_E4B_SPEC
        )

        val stateAfterEnqueue = vm.uiState.value
        assertEquals(OnboardingStep.COMPLETE, stateAfterEnqueue.currentStep)
        assertEquals(PinnedModelCatalog.MODEL_ID_GEMMA4_E4B, stateAfterEnqueue.selectedModelId)
        val taskId = stateAfterEnqueue.enqueuedImportTaskId
        assertNotNull("Expected enqueued background task ID", taskId)
        assertEquals(
            BackgroundTaskStatus.ENQUEUED,
            container.backgroundTaskContinuationManager.getStatus(taskId!!)
        )
        val recordedReq = container.backgroundTaskContinuationManager.getRequest(taskId)
        assertTrue(recordedReq is BackgroundTaskRequest.ModelImportContinuation)
        val importReq = recordedReq as BackgroundTaskRequest.ModelImportContinuation
        assertEquals(safUri, importReq.sourceUri)
        assertEquals(PinnedModelCatalog.MODEL_ID_GEMMA4_E4B, importReq.expectedModelId)
        assertEquals(PinnedModelCatalog.SHA256_GEMMA4_E4B, importReq.expectedSha256Hex)

        // Step 4: Complete onboarding
        vm.completeOnboarding()
        assertTrue(vm.uiState.value.isOnboardingCompleted)
        assertTrue(container.onboardingStateStore.isOnboardingCompleted())
        assertEquals(
            PinnedModelCatalog.MODEL_ID_GEMMA4_E4B,
            container.onboardingStateStore.getSelectedModelId()
        )

        // Critical Security Invariant: 100% of targets MUST still be bound to Default-Deny (Strictly Isolated)
        for (targetId in PermissionProfilesUiState.DEFAULT_CANONICAL_TARGETS) {
            val profile = container.manageProfilesUseCase.getProfileForTarget(targetId)
            assertEquals(
                "Target '$targetId' must remain Strictly Isolated (Default-Deny) after onboarding",
                PermissionProfile.DEFAULT_DENY_PROFILE_ID,
                profile.id
            )
            for (cap in AtomicCapability.entries) {
                assertEquals(
                    "Capability $cap on target '$targetId' must remain DISABLED after onboarding",
                    ConfirmationLevel.DISABLED,
                    profile.levelFor(cap)
                )
            }
        }
    }

    @Test
    fun onboardingSupportsContinuingInDeterministicTier1Tier2ModeWithoutModelImport() = runTest {
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            ioDispatcher = Dispatchers.Unconfined
        )
        val vm = OnboardingViewModel(
            container = container,
            dispatcher = Dispatchers.Unconfined
        )

        vm.acknowledgeDefaultDenyAndContinue()
        vm.proceedToModelProvisioning()
        vm.continueInDeterministicMode()

        assertEquals(OnboardingStep.COMPLETE, vm.uiState.value.currentStep)
        assertTrue(vm.uiState.value.isDeterministicModeSelected)
        assertNull(vm.uiState.value.selectedModelId)

        vm.completeOnboarding()
        assertTrue(container.onboardingStateStore.isOnboardingCompleted())
        assertNull(container.onboardingStateStore.getSelectedModelId())
    }
}

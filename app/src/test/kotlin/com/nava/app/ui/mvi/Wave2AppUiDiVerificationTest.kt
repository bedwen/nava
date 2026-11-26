package com.nava.app.ui.mvi

import com.nava.app.di.AppContainer
import com.nava.app.di.InMemoryPreferencesStorageGateway
import com.nava.app.di.OnboardingStateStore
import com.nava.app.di.PinnedModelCatalog
import com.nava.app.di.PinnedModelRole
import com.nava.app.ui.hub.NavaHubViewModel
import com.nava.app.ui.profiles.PermissionProfilesViewModel
import com.nava.domain.ai.RamTier
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.PermissionProfile
import com.nava.feature.automations.common.ToolTargetIds
import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * End-to-end unit test suite validating Wave 2 app-ui-di invariants:
 * 1. PermissionProfilesViewModel persistence across fresh ViewModel re-opens.
 * 2. toggleTargetCapability auto-forking custom profile when target is on immutable built-in preset.
 * 3. assignAllCoreTargetsToProfile applying to all 10 core targets while isolating Vault.
 * 4. OnboardingStateStore independent 3-slot persistence for FunctionGemma & EmbeddingGemma 2.
 * 5. PinnedModelCatalog universal E2B default across RAM tiers & PinnedModelRole routing.
 * 6. NavaHubViewModel requesting POST_NOTIFICATIONS permission on reminder/routine success.
 */
class Wave2AppUiDiVerificationTest {

    private lateinit var tempVaultDir: File
    private lateinit var tempModelsDir: File

    @Before
    fun setUp() {
        tempVaultDir = Files.createTempDirectory("nava_wave2_test_vault").toFile()
        tempModelsDir = Files.createTempDirectory("nava_wave2_test_models").toFile()
    }

    @After
    fun tearDown() {
        tempVaultDir.deleteRecursively()
        tempModelsDir.deleteRecursively()
    }

    @Test
    fun permissionProfilesViewModelPersistenceAcrossReopen() = runTest {
        val nowMs = 1_760_000_100_000L
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            clockMs = { nowMs },
            ioDispatcher = Dispatchers.Unconfined
        )

        val vm1 = PermissionProfilesViewModel(
            container = container,
            dispatcher = Dispatchers.Unconfined,
            clockMs = { nowMs }
        )

        // Select SMS target and assign Safe Draft profile
        vm1.selectTarget(ToolTargetIds.SMS)
        vm1.assignTargetToProfile(
            targetId = ToolTargetIds.SMS,
            profileId = PermissionProfile.SAFE_DRAFT_PROFILE_ID
        )

        assertEquals(ToolTargetIds.SMS, vm1.uiState.value.selectedTargetId)
        assertEquals(PermissionProfile.SAFE_DRAFT_PROFILE_ID, vm1.uiState.value.selectedTargetProfile.id)

        // Simulate closing and reopening the screen with a fresh ViewModel instance
        val vm2 = PermissionProfilesViewModel(
            container = container,
            dispatcher = Dispatchers.Unconfined,
            clockMs = { nowMs + 1000L }
        )

        vm2.selectTarget(ToolTargetIds.SMS)
        assertEquals(
            "Expected assigned profile to persist in fresh ViewModel instance",
            PermissionProfile.SAFE_DRAFT_PROFILE_ID,
            vm2.uiState.value.selectedTargetProfile.id
        )
        assertEquals(
            PermissionProfile.SAFE_DRAFT_PROFILE_ID,
            vm2.uiState.value.targetProfilesById[ToolTargetIds.SMS]?.id
        )
    }

    @Test
    fun toggleTargetCapabilityAutoForksCustomProfile() = runTest {
        val nowMs = 1_760_000_200_000L
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            clockMs = { nowMs },
            ioDispatcher = Dispatchers.Unconfined
        )

        val vm = PermissionProfilesViewModel(
            container = container,
            dispatcher = Dispatchers.Unconfined,
            clockMs = { nowMs }
        )

        // CLOCK starts on DEFAULT_DENY (immutable preset)
        vm.selectTarget(ToolTargetIds.CLOCK)
        val initialProfile = vm.uiState.value.selectedProfile
        assertNotNull(initialProfile)
        assertTrue(initialProfile!!.id in PermissionProfile.IMMUTABLE_PRESET_IDS)

        // Toggling capability on an immutable preset must automatically fork a custom profile
        vm.toggleTargetCapability(
            capability = AtomicCapability.DATA_READ,
            level = ConfirmationLevel.AUTO
        )

        val forkedProfile = vm.uiState.value.selectedProfile
        assertNotNull(forkedProfile)
        assertFalse(
            "Forked profile must not be an immutable built-in preset",
            forkedProfile!!.id in PermissionProfile.IMMUTABLE_PRESET_IDS
        )
        assertTrue(
            "Forked profile ID should follow canonical naming pattern",
            forkedProfile.id.startsWith("custom_target_")
        )
        assertEquals(ConfirmationLevel.AUTO, forkedProfile.levelFor(AtomicCapability.DATA_READ))
        assertEquals(ConfirmationLevel.DISABLED, forkedProfile.levelFor(AtomicCapability.NOTIFICATION_READ))
        assertEquals(ConfirmationLevel.DISABLED, forkedProfile.levelFor(AtomicCapability.CREATE_DRAFT))

        // Target CLOCK must now be bound to the newly minted custom profile
        val boundProfile = container.manageProfilesUseCase.getProfileForTarget(ToolTargetIds.CLOCK)
        assertEquals(forkedProfile.id, boundProfile.id)
    }

    @Test
    fun assignAllCoreTargetsToProfileAppliesToAllCoreTargetsExceptVault() = runTest {
        val nowMs = 1_760_000_300_000L
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            clockMs = { nowMs },
            ioDispatcher = Dispatchers.Unconfined
        )

        val vm = PermissionProfilesViewModel(
            container = container,
            dispatcher = Dispatchers.Unconfined,
            clockMs = { nowMs }
        )

        vm.assignAllCoreTargetsToProfile(PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID)

        val coreTargets = listOf(
            ToolTargetIds.CLOCK,
            ToolTargetIds.REMINDERS,
            ToolTargetIds.CALENDAR,
            ToolTargetIds.NOTES,
            ToolTargetIds.SMS,
            ToolTargetIds.PHONE,
            ToolTargetIds.NOTIFICATIONS,
            ToolTargetIds.AUDIO_DND,
            ToolTargetIds.APP_LAUNCH,
            ToolTargetIds.ROUTINES
        )

        for (target in coreTargets) {
            val profile = container.manageProfilesUseCase.getProfileForTarget(target)
            assertEquals(
                "Target $target must be assigned to TRUSTED_SYSTEM_PROFILE_ID",
                PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID,
                profile.id
            )
        }

        // ToolTargetIds.VAULT must NEVER be batch-assigned
        val vaultProfile = container.manageProfilesUseCase.getProfileForTarget(ToolTargetIds.VAULT)
        assertEquals(
            "VAULT must remain strictly isolated (Default-Deny)",
            PermissionProfile.DEFAULT_DENY_PROFILE_ID,
            vaultProfile.id
        )
    }

    @Test
    fun onboardingStateStoreThreeSlotIndependence() = runTest {
        val storage = InMemoryPreferencesStorageGateway()
        val store1 = OnboardingStateStore(storage)

        // Select Gemma 4 E2B as primary model
        store1.setSelectedModelId(PinnedModelCatalog.MODEL_ID_GEMMA4_E2B)
        assertEquals(PinnedModelCatalog.MODEL_ID_GEMMA4_E2B, store1.getSelectedModelId())
        assertEquals(null, store1.getSelectedFunctionModelId())
        assertEquals(null, store1.getSelectedEmbeddingModelId())

        // Assign Function Router (Mobile Actions / FunctionGemma) -> must NOT overwrite E2B
        store1.assignImportedModelByRole(PinnedModelCatalog.MODEL_ID_MOBILE_ACTIONS)
        assertEquals(PinnedModelCatalog.MODEL_ID_GEMMA4_E2B, store1.getSelectedModelId())
        assertEquals(PinnedModelCatalog.MODEL_ID_MOBILE_ACTIONS, store1.getSelectedFunctionModelId())
        assertEquals(null, store1.getSelectedEmbeddingModelId())

        // Assign Semantic Embedding (EmbeddingGemma 2 270M) -> must NOT overwrite E2B or FunctionGemma
        store1.assignImportedModelByRole(PinnedModelCatalog.MODEL_ID_EMBEDDING_GEMMA_270M)
        assertEquals(PinnedModelCatalog.MODEL_ID_GEMMA4_E2B, store1.getSelectedModelId())
        assertEquals(PinnedModelCatalog.MODEL_ID_MOBILE_ACTIONS, store1.getSelectedFunctionModelId())
        assertEquals(PinnedModelCatalog.MODEL_ID_EMBEDDING_GEMMA_270M, store1.getSelectedEmbeddingModelId())

        // Fresh instance using same storage must restore all 3 independent slots
        val store2 = OnboardingStateStore(storage)
        assertEquals(PinnedModelCatalog.MODEL_ID_GEMMA4_E2B, store2.getSelectedModelId())
        assertEquals(PinnedModelCatalog.MODEL_ID_MOBILE_ACTIONS, store2.getSelectedFunctionModelId())
        assertEquals(PinnedModelCatalog.MODEL_ID_EMBEDDING_GEMMA_270M, store2.getSelectedEmbeddingModelId())
    }

    @Test
    fun pinnedModelCatalogUniversalE2BDefaultAndRoleRouting() {
        // Universal default across all RAM tiers
        assertEquals(
            PinnedModelCatalog.GEMMA_4_E2B_SPEC,
            PinnedModelCatalog.recommendedSpecForRamTier(RamTier.TIER_0_LOW_MEMORY)
        )
        assertEquals(
            PinnedModelCatalog.GEMMA_4_E2B_SPEC,
            PinnedModelCatalog.recommendedSpecForRamTier(RamTier.TIER_1_STANDARD)
        )
        assertEquals(
            PinnedModelCatalog.GEMMA_4_E2B_SPEC,
            PinnedModelCatalog.recommendedSpecForRamTier(RamTier.TIER_2_HIGH)
        )

        // PinnedModelRole routing
        assertEquals(
            PinnedModelRole.FUNCTION_ROUTER,
            PinnedModelCatalog.roleForModelId(PinnedModelCatalog.MODEL_ID_MOBILE_ACTIONS)
        )
        assertEquals(
            PinnedModelRole.SEMANTIC_EMBEDDING,
            PinnedModelCatalog.roleForModelId(PinnedModelCatalog.MODEL_ID_EMBEDDING_GEMMA_270M)
        )
        assertEquals(
            PinnedModelRole.SEMANTIC_EMBEDDING,
            PinnedModelCatalog.roleForModelId(PinnedModelCatalog.MODEL_ID_EMBEDDING_GEMMA)
        )
        assertEquals(
            PinnedModelRole.PRIMARY_LLM,
            PinnedModelCatalog.roleForModelId(PinnedModelCatalog.MODEL_ID_GEMMA4_E2B)
        )
        assertEquals(
            PinnedModelRole.PRIMARY_LLM,
            PinnedModelCatalog.roleForModelId(PinnedModelCatalog.MODEL_ID_GEMMA4_E4B)
        )
    }

    @Test
    fun navaHubViewModelRequestsPostNotificationsOnReminderSuccess() = runTest {
        val nowMs = 1_760_000_400_000L
        val gatewayWithoutNotifs = object : com.nava.feature.automations.common.AutomationIntentGateway by com.nava.app.di.NoOpTestAutomationIntentGateway() {
            override fun canPostNotifications(): Boolean = false
        }
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            clockMs = { nowMs },
            intentGateway = gatewayWithoutNotifs,
            ioDispatcher = Dispatchers.Unconfined
        )

        // Give REMINDERS full permission (reminder tools evaluate nava.reminders)
        container.manageProfilesUseCase.assignTarget(
            targetId = ToolTargetIds.REMINDERS,
            profileId = PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID,
            nowEpochMs = nowMs
        )

        val vm = NavaHubViewModel(
            container = container,
            dispatcher = Dispatchers.Unconfined,
            clockMs = { nowMs }
        )

        // Submit reminder query
        vm.submitQuery("remind me to call dentist in 15 minutes")

        // When canPostNotifications is false, POST_NOTIFICATIONS is requested
        assertEquals(
            "android.permission.POST_NOTIFICATIONS",
            vm.uiState.value.pendingSystemPermissionRequest
        )
    }
}

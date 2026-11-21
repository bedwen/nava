package com.nava.app.ui.mvi

import com.nava.app.di.AppContainer
import com.nava.app.ui.profiles.PermissionProfilesViewModel
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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class PermissionProfilesMviViewModelTest {

    private lateinit var tempVaultDir: File
    private lateinit var tempModelsDir: File

    @Before
    fun setUp() {
        tempVaultDir = Files.createTempDirectory("nava_profiles_test_vault").toFile()
        tempModelsDir = Files.createTempDirectory("nava_profiles_test_models").toFile()
    }

    @After
    fun tearDown() {
        tempVaultDir.deleteRecursively()
        tempModelsDir.deleteRecursively()
    }

    @Test
    fun builtInPresetsAreImmutableAndOrthogonalCapabilitySwitchesEnforceConstraints() = runTest {
        val nowMs = 1_760_000_600_000L
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

        // All 5 immutable built-in presets are loaded initially
        val initialProfiles = vm.uiState.value.profiles
        assertEquals(5, initialProfiles.size)
        assertEquals(
            PermissionProfile.IMMUTABLE_PRESET_IDS,
            initialProfiles.map { it.id }.toSet()
        )

        // Attempting to modify or delete a built-in preset is rejected
        vm.updateCapabilitySwitch(
            profileId = PermissionProfile.DEFAULT_DENY_PROFILE_ID,
            capability = AtomicCapability.DATA_READ,
            level = ConfirmationLevel.AUTO
        )
        assertNotNull(vm.uiState.value.errorMessage)
        assertEquals(
            ConfirmationLevel.DISABLED,
            container.manageProfilesUseCase.getProfileForTarget(ToolTargetIds.CLOCK)
                .levelFor(AtomicCapability.DATA_READ)
        )

        vm.deleteCustomProfile(PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID)
        assertNotNull(vm.uiState.value.errorMessage)
        assertEquals(5, vm.uiState.value.profiles.size)

        // Valid levels for MODIFY_DELETE_SEND must NEVER include ConfirmationLevel.AUTO
        val modifyLevels = vm.validLevelsFor(AtomicCapability.MODIFY_DELETE_SEND)
        assertFalse(
            "MODIFY_DELETE_SEND must never allow ConfirmationLevel.AUTO",
            ConfirmationLevel.AUTO in modifyLevels
        )
        assertEquals(
            listOf(ConfirmationLevel.DISABLED, ConfirmationLevel.PROMPT_CARD, ConfirmationLevel.BIOMETRIC),
            modifyLevels
        )

        // Create a custom profile derived from Strictly Isolated (Default-Deny)
        vm.createCustomProfile(
            customName = "Work Calendar & Files",
            customId = "custom_work_profile",
            baseProfileId = PermissionProfile.DEFAULT_DENY_PROFILE_ID
        )
        assertNull(vm.uiState.value.errorMessage)
        assertEquals("custom_work_profile", vm.uiState.value.selectedProfileId)

        // Toggle DATA_READ to AUTO -> verify orthogonal isolation (other 4 capabilities remain DISABLED)
        vm.updateCapabilitySwitch(
            profileId = "custom_work_profile",
            capability = AtomicCapability.DATA_READ,
            level = ConfirmationLevel.AUTO
        )
        val customAfterRead = vm.uiState.value.selectedProfile!!
        assertEquals(ConfirmationLevel.AUTO, customAfterRead.levelFor(AtomicCapability.DATA_READ))
        assertEquals(ConfirmationLevel.DISABLED, customAfterRead.levelFor(AtomicCapability.NOTIFICATION_READ))
        assertEquals(ConfirmationLevel.DISABLED, customAfterRead.levelFor(AtomicCapability.CREATE_DRAFT))
        assertEquals(ConfirmationLevel.DISABLED, customAfterRead.levelFor(AtomicCapability.MODIFY_DELETE_SEND))
        assertEquals(ConfirmationLevel.DISABLED, customAfterRead.levelFor(AtomicCapability.APP_LAUNCH))

        // Toggle MODIFY_DELETE_SEND to BIOMETRIC -> DATA_READ stays AUTO, others stay DISABLED
        vm.updateCapabilitySwitch(
            profileId = "custom_work_profile",
            capability = AtomicCapability.MODIFY_DELETE_SEND,
            level = ConfirmationLevel.BIOMETRIC
        )
        val customAfterModify = vm.uiState.value.selectedProfile!!
        assertEquals(ConfirmationLevel.AUTO, customAfterModify.levelFor(AtomicCapability.DATA_READ))
        assertEquals(ConfirmationLevel.BIOMETRIC, customAfterModify.levelFor(AtomicCapability.MODIFY_DELETE_SEND))
        assertEquals(ConfirmationLevel.DISABLED, customAfterModify.levelFor(AtomicCapability.CREATE_DRAFT))

        // Attempting to set MODIFY_DELETE_SEND to AUTO on a custom profile is rejected
        vm.updateCapabilitySwitch(
            profileId = "custom_work_profile",
            capability = AtomicCapability.MODIFY_DELETE_SEND,
            level = ConfirmationLevel.AUTO
        )
        assertNotNull(vm.uiState.value.errorMessage)
        assertEquals(
            ConfirmationLevel.BIOMETRIC,
            vm.uiState.value.selectedProfile!!.levelFor(AtomicCapability.MODIFY_DELETE_SEND)
        )
    }

    @Test
    fun safDirectoryGrantAssignmentAndCustomProfileDeletionResetToDefaultDeny() = runTest {
        val nowMs = 1_760_000_700_000L
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

        vm.createCustomProfile(
            customName = "Docs Folder Access",
            customId = "custom_docs_access",
            baseProfileId = PermissionProfile.SAFE_DRAFT_PROFILE_ID
        )

        val treeUri = "content://com.android.externalstorage.documents/tree/primary%3ADocuments"
        val expectedSafTarget = ToolTargetIds.forSafTree(treeUri)
        vm.onSafDirectoryGranted(
            treeUriString = treeUri,
            profileId = "custom_docs_access"
        )

        assertEquals(expectedSafTarget, vm.uiState.value.selectedTargetId)
        assertEquals("custom_docs_access", vm.uiState.value.selectedTargetProfile.id)
        assertTrue(expectedSafTarget in vm.uiState.value.grantedSafTreeTargets)
        assertTrue(
            "Expected audit log entry for SAF target assignment",
            vm.uiState.value.targetAuditEntries.any { it.targetId == expectedSafTarget }
        )

        // Delete the custom profile -> bound SAF target automatically resets to Default-Deny
        vm.deleteCustomProfile("custom_docs_access")
        val resetProfile = container.manageProfilesUseCase.getProfileForTarget(expectedSafTarget)
        assertEquals(PermissionProfile.DEFAULT_DENY_PROFILE_ID, resetProfile.id)
    }
}

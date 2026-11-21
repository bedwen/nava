package com.nava.app.ui.mvi

import com.nava.app.di.AppContainer
import com.nava.app.ui.routines.RoutinesViewModel
import com.nava.domain.automation.RoutineExecutionOutcome
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleTriggerSpec
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.ToolTargetIds
import com.nava.feature.automations.routine.RoutineExecutor
import com.nava.feature.automations.routine.RoutineWorkScheduler
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

class RoutinesMviViewModelTest {

    private lateinit var tempVaultDir: File
    private lateinit var tempModelsDir: File

    @Before
    fun setUp() {
        tempVaultDir = Files.createTempDirectory("nava_routines_test_vault").toFile()
        tempModelsDir = Files.createTempDirectory("nava_routines_test_models").toFile()
    }

    @After
    fun tearDown() {
        tempVaultDir.deleteRecursively()
        tempModelsDir.deleteRecursively()
    }

    @Test
    fun routineConsentCardHighlightsNonUnattendedEscalationAndSupportsApprovePauseRevokeAndGlobalPause() = runTest {
        val nowMs = 1_760_000_800_000L
        val scheduledRuleIds = mutableListOf<String>()
        val cancelledRuleIds = mutableListOf<String>()
        var cancelAllCallCount = 0

        val trackingScheduler = object : RoutineWorkScheduler {
            override suspend fun schedule(grant: RuleCapabilityGrant) {
                scheduledRuleIds.add(grant.ruleId)
            }

            override suspend fun cancel(ruleId: String) {
                cancelledRuleIds.add(ruleId)
            }

            override suspend fun cancelAll() {
                cancelAllCallCount++
            }
        }

        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            routineWorkScheduler = trackingScheduler,
            clockMs = { nowMs },
            ioDispatcher = Dispatchers.Unconfined
        )
        container.manageProfilesUseCase.assignTarget(
            targetId = ToolTargetIds.ROUTINES,
            profileId = PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID,
            nowEpochMs = nowMs
        )

        val vm = RoutinesViewModel(
            container = container,
            dispatcher = Dispatchers.Unconfined,
            clockMs = { nowMs }
        )

        // 1. Compile a safe unattended routine (set_alarm -> CREATE_DRAFT)
        vm.compilePendingRule(
            ruleId = "morning_alarm_routine",
            triggerSpec = RuleTriggerSpec(
                triggerType = "DAILY_TIME",
                parameters = mapOf("time" to "06:30")
            ),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = AutomationToolNames.SET_ALARM,
                    requiredCapability = AtomicCapability.CREATE_DRAFT,
                    staticArguments = mapOf("time" to "06:30", "label" to "Morning")
                )
            )
        )

        // 2. Compile a sensitive routine containing a MODIFY_DELETE_SEND action
        vm.compilePendingRule(
            ruleId = "cleanup_note_routine",
            triggerSpec = RuleTriggerSpec(
                triggerType = "WEEKLY_CLEANUP",
                parameters = mapOf("day" to "SUNDAY")
            ),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = AutomationToolNames.NOTES_DELETE,
                    requiredCapability = AtomicCapability.MODIFY_DELETE_SEND,
                    staticArguments = mapOf("note_id" to "temp_draft")
                )
            )
        )

        val stateAfterCompile = vm.uiState.value
        assertEquals(2, stateAfterCompile.pendingApprovalRules.size)
        assertTrue(stateAfterCompile.activeRules.isEmpty())

        val safeConsentCard = stateAfterCompile.consentCards.first { it.ruleId == "morning_alarm_routine" }
        assertFalse(safeConsentCard.requiresInteractiveEscalationWarning)

        val sensitiveConsentCard = stateAfterCompile.consentCards.first { it.ruleId == "cleanup_note_routine" }
        assertTrue(
            "Consent card must warn when a routine includes MODIFY_DELETE_SEND/Biometric/Vault actions",
            sensitiveConsentCard.requiresInteractiveEscalationWarning
        )
        assertEquals(listOf(AutomationToolNames.NOTES_DELETE), sensitiveConsentCard.nonUnattendedActionNames)

        // Single-tap Approve on morning_alarm_routine -> mints HMAC seal and schedules in WorkManager
        vm.approveRule("morning_alarm_routine")
        assertEquals(1, vm.uiState.value.activeRules.size)
        assertTrue("morning_alarm_routine" in scheduledRuleIds)
        val sealedGrant = vm.uiState.value.activeRules.first()
        assertEquals(RuleApprovalState.APPROVED_ACTIVE, sealedGrant.approvalState)
        assertTrue(sealedGrant.sealHmacHex.isNotBlank())

        // Execute active safe routine -> runs unattended
        vm.runRuleNow("morning_alarm_routine")
        assertTrue(vm.uiState.value.lastExecutionOutcome is RoutineExecutionOutcome.Executed)

        // Single-tap Approve on sensitive routine and run -> escalates to interactive confirmation!
        vm.approveRule("cleanup_note_routine")
        vm.runRuleNow("cleanup_note_routine")
        assertTrue(
            "Sensitive MODIFY_DELETE_SEND routine must escalate to interactive confirmation notification",
            vm.uiState.value.lastExecutionOutcome is RoutineExecutionOutcome.EscalatedToInteractive
        )
        assertNotNull(
            "Escalated routine must be registered in PendingConfirmationStore",
            container.pendingConfirmationStore.findByRuleId("cleanup_note_routine")
        )

        // Global Pause switch -> pauses all routines and calls cancelAllRules()
        vm.setGlobalRulesPaused(true)
        assertTrue(vm.uiState.value.isGlobalPaused)
        assertTrue(container.ruleCapabilityGrantManager.isGlobalRulesPaused())
        assertTrue(container.routineExecutor.isGloballyPaused())
        assertEquals(1, cancelAllCallCount)

        // Running any routine while globally paused is deterministically DENIED
        vm.runRuleNow("morning_alarm_routine")
        val deniedOutcome = vm.uiState.value.lastExecutionOutcome
        assertTrue(deniedOutcome is RoutineExecutionOutcome.Denied)
        assertEquals(
            RoutineExecutor.REASON_ROUTINES_GLOBALLY_PAUSED,
            (deniedOutcome as RoutineExecutionOutcome.Denied).reasonCode
        )

        // Resume Global Pause -> re-schedules active rules
        scheduledRuleIds.clear()
        vm.setGlobalRulesPaused(false)
        assertFalse(vm.uiState.value.isGlobalPaused)
        assertTrue("morning_alarm_routine" in scheduledRuleIds)

        // Single-tap Pause and Revoke
        vm.pauseRule("morning_alarm_routine")
        assertEquals(1, vm.uiState.value.pausedRules.size)
        assertTrue("morning_alarm_routine" in cancelledRuleIds)

        vm.revokeRule("morning_alarm_routine")
        assertEquals(1, vm.uiState.value.revokedRules.size)
        val revokedGrant = vm.uiState.value.revokedRules.first()
        assertEquals(RuleApprovalState.REVOKED, revokedGrant.approvalState)
        assertEquals("", revokedGrant.sealHmacHex)
    }
}

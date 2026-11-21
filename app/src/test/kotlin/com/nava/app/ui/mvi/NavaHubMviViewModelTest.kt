package com.nava.app.ui.mvi

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import com.nava.app.di.AppContainer
import com.nava.app.di.PinnedModelCatalog
import com.nava.app.ui.hub.NavaHubViewModel
import com.nava.app.ui.navigation.NavaViewModelFactory
import com.nava.app.ui.onboarding.OnboardingViewModel
import com.nava.app.ui.profiles.PermissionProfilesViewModel
import com.nava.app.ui.routines.RoutinesViewModel
import com.nava.app.ui.settings.SettingsViewModel
import com.nava.app.voice.VoiceInputState
import com.nava.core.ai.lifecycle.DeviceHardwareSnapshot
import com.nava.core.ai.lifecycle.DeviceHardwareStatusProvider
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.domain.ai.IntentRequest
import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.RamTier
import com.nava.domain.ai.ResolutionResult
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.automation.BackgroundTaskOutcome
import com.nava.domain.automation.BackgroundTaskRequest
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.ui.CoreActivityState
import com.nava.domain.ui.NeuronNodeId
import com.nava.feature.automations.common.AutomationToolNames
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
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

class NavaHubMviViewModelTest {

    private lateinit var tempVaultDir: File
    private lateinit var tempModelsDir: File

    @Before
    fun setUp() {
        tempVaultDir = Files.createTempDirectory("nava_hub_test_vault").toFile()
        tempModelsDir = Files.createTempDirectory("nava_hub_test_models").toFile()
    }

    @After
    fun tearDown() {
        tempVaultDir.deleteRecursively()
        tempModelsDir.deleteRecursively()
    }

    @Test
    fun tier1AndTier2QueriesKeepInnerCoreAsleepAndReturnToZeroFpsIdleOnPulseCompleted() = runTest {
        val nowMs = 1_760_000_000_000L
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            clockMs = { nowMs },
            ioDispatcher = Dispatchers.Unconfined
        )
        container.manageProfilesUseCase.assignTarget(
            targetId = ToolTargetIds.CLOCK,
            profileId = PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID,
            nowEpochMs = nowMs
        )

        val vm = NavaHubViewModel(
            container = container,
            dispatcher = Dispatchers.Unconfined,
            clockMs = { nowMs }
        )

        // Initially idle at 0 FPS
        assertTrue(vm.uiState.value.canvasState.isIdle)
        assertEquals(CoreActivityState.IDLE, vm.uiState.value.canvasState.coreState)
        assertNull(vm.uiState.value.canvasState.activePulse)

        // Submit Tier 1 rule query ("set alarm for 07:30")
        vm.submitQuery("set alarm for 07:30")

        val stateAfterQuery = vm.uiState.value
        assertEquals(ResolutionTier.TIER_1_RULE, stateAfterQuery.lastResolutionTier)
        assertEquals(CoreActivityState.OUTER_SHELL_ACTIVE, stateAfterQuery.canvasState.coreState)
        val activePulse = stateAfterQuery.canvasState.activePulse
        assertNotNull("Expected active pulse for Tier 1 query", activePulse)
        assertFalse(
            "Tier 1/2 reflex pulses must NEVER wake Gemma 4 Inner Core",
            activePulse!!.wakesInnerCore
        )
        assertEquals(NeuronNodeId.CLOCK, activePulse.targetNode)
        assertNull(activePulse.sourceNode)
        assertFalse(
            "Tier 1 plans must NOT be admitted into Tier 2 cache",
            stateAfterQuery.lastPlanAdmittedToCache
        )

        // When canvas signals onPulseCompleted, canvas returns to 0 FPS IDLE immediately
        vm.onPulseCompleted(activePulse.eventId)
        val idleState = vm.uiState.value.canvasState
        assertTrue("Canvas must return to 0 FPS idle after pulse completion", idleState.isIdle)
        assertEquals(CoreActivityState.IDLE, idleState.coreState)
        assertNull(idleState.activePulse)
        assertTrue(idleState.activeNeurons.isEmpty())
    }

    @Test
    fun tier3MultiStepPlanWakesInnerCoreTraversesInterNeuronSynapsesAndResetsToIdle() = runTest {
        val nowMs = 1_760_000_050_000L
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            clockMs = { nowMs },
            ioDispatcher = Dispatchers.Unconfined
        )
        container.manageProfilesUseCase.assignTarget(
            targetId = ToolTargetIds.CLOCK,
            profileId = PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID,
            nowEpochMs = nowMs
        )
        container.manageProfilesUseCase.assignTarget(
            targetId = ToolTargetIds.AUDIO_DND,
            profileId = PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID,
            nowEpochMs = nowMs
        )

        val vm = NavaHubViewModel(
            container = container,
            dispatcher = Dispatchers.Unconfined,
            clockMs = { nowMs }
        )

        val multiStepPlan = PlanAst(
            planId = "plan-chain-1",
            calls = listOf(
                ToolCallAst(
                    toolName = AutomationToolNames.SET_ALARM,
                    arguments = mapOf(
                        "time" to Tainted.fromUserUtterance(SlotValueAst.StringValue("06:45"))
                    ),
                    orderIndex = 0,
                    targetId = ToolTargetIds.CLOCK
                ),
                ToolCallAst(
                    toolName = AutomationToolNames.SET_DND,
                    arguments = mapOf(
                        "mode" to Tainted.fromUserUtterance(SlotValueAst.StringValue("PRIORITY"))
                    ),
                    orderIndex = 1,
                    targetId = ToolTargetIds.AUDIO_DND
                )
            )
        )
        val token = container.securityFirewall.mintToken(
            requestId = "req-tier3-chain",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf(AutomationToolNames.SET_ALARM, AutomationToolNames.SET_DND),
            nowEpochMs = nowMs
        )
        val intentReq = IntentRequest(
            requestId = token.requestId,
            rawUtterance = "wake me up at 06:45 and enable priority dnd",
            provenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = nowMs
        )

        vm.executeResolvedPlan(
            intentRequest = intentReq,
            tier = ResolutionTier.TIER_3_GEMMA,
            plan = multiStepPlan,
            capabilityToken = token
        )

        // Step 0 pulse: Central Hub (sourceNode = null) -> CLOCK with wakesInnerCore = true
        val step0Canvas = vm.uiState.value.canvasState
        assertEquals(CoreActivityState.INNER_CORE_ACTIVE, step0Canvas.coreState)
        assertEquals(setOf(NeuronNodeId.CLOCK, NeuronNodeId.AUDIO_DND), step0Canvas.activeNeurons)
        val pulse0 = step0Canvas.activePulse
        assertNotNull(pulse0)
        assertTrue("Tier 3 pulse must wake Gemma 4 Inner Core", pulse0!!.wakesInnerCore)
        assertNull("First pulse must originate from Central Hub", pulse0.sourceNode)
        assertEquals(NeuronNodeId.CLOCK, pulse0.targetNode)

        // Completing step 0 advances to step 1 inter-neuron synapse: CLOCK -> AUDIO_DND
        vm.onPulseCompleted(pulse0.eventId)
        val step1Canvas = vm.uiState.value.canvasState
        assertEquals(CoreActivityState.INNER_CORE_ACTIVE, step1Canvas.coreState)
        val pulse1 = step1Canvas.activePulse
        assertNotNull("Expected queued inter-neuron pulse", pulse1)
        assertTrue(pulse1!!.wakesInnerCore)
        assertEquals(NeuronNodeId.CLOCK, pulse1.sourceNode)
        assertEquals(NeuronNodeId.AUDIO_DND, pulse1.targetNode)

        // Completing step 1 resets canvas to 0 FPS IDLE
        vm.onPulseCompleted(pulse1.eventId)
        val finalCanvas = vm.uiState.value.canvasState
        assertTrue(finalCanvas.isIdle)
        assertEquals(CoreActivityState.IDLE, finalCanvas.coreState)
        assertNull(finalCanvas.activePulse)
    }

    @Test
    fun tier2CacheAdmissionGateAdmitsApprovedTier3UserPlanAndRejectsUntrustedOrVaultPlans() = runTest {
        val nowMs = 1_760_000_100_000L
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            clockMs = { nowMs },
            ioDispatcher = Dispatchers.Unconfined
        )
        container.manageProfilesUseCase.assignTarget(
            targetId = ToolTargetIds.CLOCK,
            profileId = PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID,
            nowEpochMs = nowMs
        )
        container.manageProfilesUseCase.assignTarget(
            targetId = ToolTargetIds.SMS,
            profileId = PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID,
            nowEpochMs = nowMs
        )
        container.manageProfilesUseCase.assignTarget(
            targetId = ToolTargetIds.VAULT,
            profileId = PermissionProfile.BIOMETRIC_HIGH_SECURITY_PROFILE_ID,
            nowEpochMs = nowMs
        )

        val vm = NavaHubViewModel(
            container = container,
            dispatcher = Dispatchers.Unconfined,
            clockMs = { nowMs }
        )

        // 1. Safe Tier 3 plan with 100% USER_UTTERANCE slots and no Vault tools -> admitted to Tier 2 cache
        val safeUtterance = "schedule morning alarm for 08:15"
        val safePlan = PlanAst(
            planId = "plan-safe-tier3",
            calls = listOf(
                ToolCallAst(
                    toolName = AutomationToolNames.SET_ALARM,
                    arguments = mapOf(
                        "time" to Tainted.fromUserUtterance(SlotValueAst.StringValue("08:15"))
                    ),
                    orderIndex = 0,
                    targetId = ToolTargetIds.CLOCK
                )
            )
        )
        val safeToken = container.securityFirewall.mintToken(
            requestId = "req-safe-tier3",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf(AutomationToolNames.SET_ALARM),
            nowEpochMs = nowMs
        )
        val safeIntentReq = IntentRequest(
            requestId = safeToken.requestId,
            rawUtterance = safeUtterance,
            provenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = nowMs
        )
        vm.executeResolvedPlan(
            intentRequest = safeIntentReq,
            tier = ResolutionTier.TIER_3_GEMMA,
            plan = safePlan,
            capabilityToken = safeToken
        )
        assertTrue(
            "Expected safe Tier 3 plan with 100% USER_UTTERANCE slots to be admitted to Tier 2 cache",
            vm.uiState.value.lastPlanAdmittedToCache
        )

        // Verify Tier 2 CacheIntentResolver can now replay a parameterized variation!
        val replayResult = container.cacheIntentResolver.resolve(
            request = IntentRequest(
                requestId = "req-replay-tier2",
                rawUtterance = "schedule morning alarm for 09:45",
                provenance = DataProvenance.USER_UTTERANCE,
                issuedAtEpochMs = nowMs
            ),
            availableTools = container.toolRegistry.allMetadata()
        )
        assertTrue("Expected Tier 2 cache hit on parameterized skeleton replay", replayResult is ResolutionResult.ResolvedPlan)
        assertEquals(ResolutionTier.TIER_2_CACHE, (replayResult as ResolutionResult.ResolvedPlan).tier)

        // 2. Tier 3 plan carrying an UNTRUSTED_EXTERNAL slot -> NEVER admitted even after user approval
        val untrustedPlan = PlanAst(
            planId = "plan-untrusted-tier3",
            calls = listOf(
                ToolCallAst(
                    toolName = AutomationToolNames.CREATE_SMS_DRAFT,
                    arguments = mapOf(
                        "recipient" to Tainted.fromUserUtterance(SlotValueAst.StringValue("+15550199")),
                        "body" to Tainted.fromUntrustedExternal(
                            value = SlotValueAst.StringValue("Extracted external notification text"),
                            sourceLabel = "notification:com.chat",
                            slotKind = SensitiveSlotKind.TEXT_BODY
                        )
                    ),
                    orderIndex = 0,
                    targetId = ToolTargetIds.SMS
                )
            )
        )
        val untrustedToken = container.securityFirewall.mintToken(
            requestId = "req-untrusted-tier3",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf(AutomationToolNames.CREATE_SMS_DRAFT),
            nowEpochMs = nowMs
        )
        val untrustedReq = IntentRequest(
            requestId = untrustedToken.requestId,
            rawUtterance = "draft sms to +15550199",
            provenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = nowMs
        )
        vm.executeResolvedPlan(
            intentRequest = untrustedReq,
            tier = ResolutionTier.TIER_3_GEMMA,
            plan = untrustedPlan,
            capabilityToken = untrustedToken
        )
        // Because content is UNTRUSTED_EXTERNAL with MESSAGE_BODY high-risk slot, confirmation is required
        val pendingConfirm = vm.uiState.value.activeConfirmation
        assertNotNull("Expected confirmation card for untrusted high-risk slot", pendingConfirm)
        assertTrue(pendingConfirm!!.hasUntrustedHighRiskSlot)

        // User approves confirmation card -> tool executes, but Tier 2 cache MUST reject admission!
        vm.onApproveConfirmation(requestId = pendingConfirm.requestId)
        assertFalse(
            "Tier 3 plan with UNTRUSTED_EXTERNAL slot must NEVER be admitted to Tier 2 cache",
            vm.uiState.value.lastPlanAdmittedToCache
        )

        // 3. Tier 3 plan touching Nava Vault -> NEVER admitted even after biometric approval
        val vaultPlan = PlanAst(
            planId = "plan-vault-tier3",
            calls = listOf(
                ToolCallAst(
                    toolName = AutomationToolNames.VAULT_WRITE,
                    arguments = mapOf(
                        "note_id" to Tainted.fromUserUtterance(SlotValueAst.StringValue("secret_1")),
                        "content" to Tainted.fromUserUtterance(SlotValueAst.StringValue("my recovery phrase"))
                    ),
                    orderIndex = 0,
                    targetId = ToolTargetIds.VAULT
                )
            )
        )
        val vaultToken = container.securityFirewall.mintToken(
            requestId = "req-vault-tier3",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf(AutomationToolNames.VAULT_WRITE),
            nowEpochMs = nowMs
        )
        val vaultReq = IntentRequest(
            requestId = vaultToken.requestId,
            rawUtterance = "store secret_1 in vault",
            provenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = nowMs
        )
        vm.executeResolvedPlan(
            intentRequest = vaultReq,
            tier = ResolutionTier.TIER_3_GEMMA,
            plan = vaultPlan,
            capabilityToken = vaultToken
        )
        val vaultConfirm = vm.uiState.value.activeConfirmation
        assertNotNull("Expected biometric confirmation card for Vault write", vaultConfirm)
        assertTrue(vaultConfirm!!.requiresBiometric)

        vm.onApproveConfirmation(requestId = vaultConfirm.requestId)
        assertFalse(
            "Tier 3 plan touching Nava Vault must NEVER be admitted to Tier 2 cache",
            vm.uiState.value.lastPlanAdmittedToCache
        )
    }

    @Test
    fun tappingNeuronInspectsPrimaryTargetPermissionProfileAndRecentAuditLog() = runTest {
        val nowMs = 1_760_000_200_000L
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            clockMs = { nowMs },
            ioDispatcher = Dispatchers.Unconfined
        )
        container.manageProfilesUseCase.assignTarget(
            targetId = ToolTargetIds.CLOCK,
            profileId = PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID,
            nowEpochMs = nowMs
        )

        val vm = NavaHubViewModel(
            container = container,
            dispatcher = Dispatchers.Unconfined,
            clockMs = { nowMs }
        )

        // Execute a clock alarm so an audit entry is recorded under system.clock
        vm.submitQuery("set alarm for 07:00")

        // Tap the CLOCK neuron
        vm.onNeuronTapped(NeuronNodeId.CLOCK)
        val inspected = vm.uiState.value.inspectedNeuron
        assertNotNull("Expected inspectedNeuron details after tapping CLOCK neuron", inspected)
        assertEquals(NeuronNodeId.CLOCK, inspected!!.nodeId)
        assertEquals(ToolTargetIds.CLOCK, inspected.primaryTargetId)
        assertEquals(PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID, inspected.profile.id)
        assertTrue(
            "Expected recent audit entries for system.clock",
            inspected.recentAuditEntries.isNotEmpty()
        )
        assertTrue(
            inspected.recentAuditEntries.any { it.targetId == ToolTargetIds.CLOCK }
        )

        vm.onDismissNeuronInspection()
        assertNull(vm.uiState.value.inspectedNeuron)
    }

    @Test
    fun hardwareNoticesAndVoiceLazyPermissionAndOfflinePackMissingState() = runTest {
        // 1. Tier 0 Low-Memory device (< 6 GB RAM) surfaces Tier 0 low-memory notice
        val tier0Container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            hardwareStatusProvider = object : DeviceHardwareStatusProvider {
                override fun readSnapshot(): DeviceHardwareSnapshot {
                    return DeviceHardwareSnapshot(
                        totalRamBytes = 4L * 1024L * 1024L * 1024L,
                        thermalStatusCode = ThermalModelLifecycleManager.THERMAL_STATUS_NONE,
                        batteryLevelPercent = 80
                    )
                }
            },
            ioDispatcher = Dispatchers.Unconfined
        )
        val tier0Vm = NavaHubViewModel(
            container = tier0Container,
            dispatcher = Dispatchers.Unconfined
        )
        assertEquals(RamTier.TIER_0_LOW_MEMORY, tier0Vm.uiState.value.ramTier)
        assertTrue(tier0Vm.uiState.value.showTier0LowMemoryNotice)

        // 2. Tier 2 High-Memory device (>= 12 GB RAM) with E2B + low-resource language surfaces E4B banner
        val tier2Container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            hardwareStatusProvider = object : DeviceHardwareStatusProvider {
                override fun readSnapshot(): DeviceHardwareSnapshot {
                    return DeviceHardwareSnapshot(
                        totalRamBytes = 16L * 1024L * 1024L * 1024L,
                        thermalStatusCode = ThermalModelLifecycleManager.THERMAL_STATUS_NONE,
                        batteryLevelPercent = 90
                    )
                }
            },
            ioDispatcher = Dispatchers.Unconfined
        )
        tier2Container.onboardingStateStore.setSelectedModelId(PinnedModelCatalog.MODEL_ID_GEMMA4_E2B)
        tier2Container.appLocaleManager.setApplicationLocale("sw")

        val tier2Vm = NavaHubViewModel(
            container = tier2Container,
            dispatcher = Dispatchers.Unconfined
        )
        assertNotNull(
            "Expected E2B->E4B upgrade suggestion banner on 16GB device for Swahili with E2B",
            tier2Vm.uiState.value.qualitySuggestion
        )
        assertEquals(
            PinnedModelCatalog.MODEL_ID_GEMMA4_E4B,
            tier2Vm.uiState.value.qualitySuggestion!!.suggestedModelSpec.modelId
        )

        // 3. Lazy RECORD_AUDIO permission request and OfflinePackMissing state (zero network fallback)
        tier2Vm.onVoiceButtonClicked(hasRecordAudioPermission = false)
        assertTrue(tier2Vm.uiState.value.showMicPermissionRationale)
        assertEquals(VoiceInputState.Idle, tier2Vm.uiState.value.voiceState)

        // Once RECORD_AUDIO is granted, offline recognizer reports OfflinePackMissing with zero network fallback
        tier2Vm.onRecordAudioPermissionResult(granted = true)
        assertFalse(tier2Vm.uiState.value.showMicPermissionRationale)
        assertTrue(
            "Expected OfflinePackMissing when offline voice pack is absent",
            tier2Vm.uiState.value.voiceState is VoiceInputState.OfflinePackMissing
        )
    }

    @Test
    fun multiStepConfirmationResumptionExecutesOnlyPendingStepWithoutReExecutingStep0() = runTest {
        val nowMs = 1_760_000_600_000L
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            clockMs = { nowMs },
            ioDispatcher = Dispatchers.Unconfined
        )
        // Step 0 target (CLOCK) is AUTO; Step 1 target (SMS) is PROMPT_CARD
        container.manageProfilesUseCase.assignTarget(
            targetId = ToolTargetIds.CLOCK,
            profileId = PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID,
            nowEpochMs = nowMs
        )
        container.manageProfilesUseCase.assignTarget(
            targetId = ToolTargetIds.SMS,
            profileId = PermissionProfile.SAFE_DRAFT_PROFILE_ID,
            nowEpochMs = nowMs
        )

        val vm = NavaHubViewModel(
            container = container,
            dispatcher = Dispatchers.Unconfined,
            clockMs = { nowMs }
        )

        val multiStepPlan = PlanAst(
            planId = "plan-multistep-confirm-fg",
            calls = listOf(
                ToolCallAst(
                    toolName = AutomationToolNames.SET_ALARM,
                    arguments = mapOf(
                        "time" to Tainted.fromUserUtterance(SlotValueAst.StringValue("06:30"))
                    ),
                    orderIndex = 0,
                    targetId = ToolTargetIds.CLOCK
                ),
                ToolCallAst(
                    toolName = AutomationToolNames.CREATE_SMS_DRAFT,
                    arguments = mapOf(
                        "recipient" to Tainted.fromUserUtterance(
                            value = SlotValueAst.StringValue("+15550122"),
                            slotKind = SensitiveSlotKind.RECIPIENT_ADDRESS
                        ),
                        "body" to Tainted.fromUserUtterance(
                            value = SlotValueAst.StringValue("Good morning"),
                            slotKind = SensitiveSlotKind.TEXT_BODY
                        )
                    ),
                    orderIndex = 1,
                    targetId = ToolTargetIds.SMS
                )
            )
        )
        val token = container.securityFirewall.mintToken(
            requestId = "req-multistep-fg",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf(AutomationToolNames.SET_ALARM, AutomationToolNames.CREATE_SMS_DRAFT),
            nowEpochMs = nowMs
        )
        val intentReq = IntentRequest(
            requestId = token.requestId,
            rawUtterance = "set alarm for 06:30 and draft sms to +15550122",
            provenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = nowMs
        )

        vm.executeResolvedPlan(
            intentRequest = intentReq,
            tier = ResolutionTier.TIER_3_GEMMA,
            plan = multiStepPlan,
            capabilityToken = token
        )

        // Step 0 executed immediately; Step 1 paused at confirmation (pendingOrderIndex = 1)
        val pendingConfirm = vm.uiState.value.activeConfirmation
        assertNotNull("Expected Step 1 to pause for confirmation", pendingConfirm)
        assertEquals(1, pendingConfirm!!.confirmation.pendingOrderIndex)

        val clockExecsBeforeApprove = container.auditLogDao
            .queryByTarget(ToolTargetIds.CLOCK, limit = 50)
            .count { it.toolName == AutomationToolNames.SET_ALARM && it.actionSummary == "Executed tool set_alarm" }
        assertEquals("Step 0 (set_alarm) must execute exactly once before Step 1 approval", 1, clockExecsBeforeApprove)

        // Approve Step 1 -> Step 1 must execute, and Step 0 must NOT re-execute!
        vm.onApproveConfirmation(requestId = pendingConfirm.requestId)
        assertNull(vm.uiState.value.activeConfirmation)

        val clockExecsAfterApprove = container.auditLogDao
            .queryByTarget(ToolTargetIds.CLOCK, limit = 50)
            .count { it.toolName == AutomationToolNames.SET_ALARM && it.actionSummary == "Executed tool set_alarm" }
        assertEquals(
            "Step 0 (set_alarm) must NOT be re-executed when approving Step 1",
            1,
            clockExecsAfterApprove
        )

        val smsExecsAfterApprove = container.auditLogDao
            .queryByTarget(ToolTargetIds.SMS, limit = 50)
            .count {
                it.toolName == AutomationToolNames.CREATE_SMS_DRAFT &&
                    it.actionSummary == "Executed tool create_sms_draft"
            }
        assertEquals("Step 1 (create_sms_draft) must execute once upon approval", 1, smsExecsAfterApprove)

        // Verify BACKGROUND_TASK multi-step continuation also passes startFromOrderIndex = 1
        val bgToken = container.securityFirewall.mintToken(
            requestId = "req-multistep-bg",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf(AutomationToolNames.SET_ALARM, AutomationToolNames.CREATE_SMS_DRAFT),
            nowEpochMs = nowMs
        )
        val bgPlan = multiStepPlan.copy(planId = "plan-multistep-confirm-bg")
        val bgReq = BackgroundTaskRequest.PlanContinuation(
            taskId = "task-multistep-bg",
            plan = bgPlan,
            capabilityToken = bgToken,
            targetId = ToolTargetIds.CLOCK,
            languageTag = "en",
            enqueuedAtEpochMs = nowMs,
            targetIdsByStep = mapOf(0 to ToolTargetIds.CLOCK, 1 to ToolTargetIds.SMS)
        )
        val bgInitialOutcome = container.backgroundTaskContinuationManager.executeNow(bgReq, nowMs)
        assertTrue(bgInitialOutcome is BackgroundTaskOutcome.ConfirmationRequired)
        val bgConfirmation = (bgInitialOutcome as BackgroundTaskOutcome.ConfirmationRequired).pendingConfirmation
        assertEquals(1, bgConfirmation.pendingOrderIndex)

        val clockExecsAfterBgStep0 = container.auditLogDao
            .queryByTarget(ToolTargetIds.CLOCK, limit = 50)
            .count { it.toolName == AutomationToolNames.SET_ALARM && it.actionSummary == "Executed tool set_alarm" }
        assertEquals(2, clockExecsAfterBgStep0)

        val bgPendingItem = container.pendingConfirmationStore.registerBackgroundTaskConfirmation(
            taskId = bgReq.taskId,
            request = bgReq,
            confirmation = bgConfirmation,
            nowEpochMs = nowMs
        )
        vm.onApproveConfirmation(requestId = bgPendingItem.requestId)

        val clockExecsAfterBgApprove = container.auditLogDao
            .queryByTarget(ToolTargetIds.CLOCK, limit = 50)
            .count { it.toolName == AutomationToolNames.SET_ALARM && it.actionSummary == "Executed tool set_alarm" }
        assertEquals(
            "Background task Step 0 (set_alarm) must NOT re-execute when approving Step 1",
            2,
            clockExecsAfterBgApprove
        )
    }

    @Test
    fun navaViewModelFactoryInstantiatesAllFiveViewModelsWithoutReflection() = runTest {
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            ioDispatcher = Dispatchers.Unconfined
        )
        val factory = NavaViewModelFactory(container)
        val store = ViewModelStore()
        val provider = ViewModelProvider(store, factory)

        val onboardingVm = provider[OnboardingViewModel::class.java]
        val hubVm = provider[NavaHubViewModel::class.java]
        val profilesVm = provider[PermissionProfilesViewModel::class.java]
        val routinesVm = provider[RoutinesViewModel::class.java]
        val settingsVm = provider[SettingsViewModel::class.java]

        assertNotNull(onboardingVm)
        assertNotNull(hubVm)
        assertNotNull(profilesVm)
        assertNotNull(routinesVm)
        assertNotNull(settingsVm)

        // ViewModelStore retains the same instance across lookups (config change survival)
        assertSame(hubVm, provider[NavaHubViewModel::class.java])
        assertSame(settingsVm, provider[SettingsViewModel::class.java])

        // Unknown ViewModel class is deterministically rejected
        class UnknownViewModel : ViewModel()
        try {
            factory.create(UnknownViewModel::class.java)
            fail("Expected IllegalArgumentException for unknown ViewModel class")
        } catch (_: IllegalArgumentException) {
            // Expected
        }

        // Clearing the ViewModelStore invokes onCleared() cleanly across all 5 ViewModels
        store.clear()
    }
}

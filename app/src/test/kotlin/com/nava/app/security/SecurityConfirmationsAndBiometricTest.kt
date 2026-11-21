package com.nava.app.security

import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.nava.app.assistant.ConfirmationIntentExtras
import com.nava.app.di.AppContainer
import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.automation.BackgroundTaskOutcome
import com.nava.domain.automation.BackgroundTaskRequest
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.PermissionProfilePreset
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleTriggerSpec
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.ToolTargetIds
import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

class SecurityConfirmationsAndBiometricTest {

    private lateinit var tempVaultDir: File
    private lateinit var tempModelsDir: File
    private var nowMs: Long = 1_760_000_000_000L

    @Before
    fun setUp() {
        tempVaultDir = Files.createTempDirectory("nava_sec_test_vault").toFile()
        tempModelsDir = Files.createTempDirectory("nava_sec_test_models").toFile()
    }

    @After
    fun tearDown() {
        tempVaultDir.deleteRecursively()
        tempModelsDir.deleteRecursively()
    }

    @Test
    fun pendingConfirmationStoreRegistersForegroundAndRejectsForgedOrExpiredExtras() = runTest {
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            clockMs = { nowMs }
        )
        val store = container.pendingConfirmationStore

        // 1. Forged unknown requestId, taskId, or ruleId must be deterministically rejected
        val forgedRequest = store.resolveFromNotificationExtras(
            ConfirmationIntentExtras(requestId = "forged-req-999"),
            nowEpochMs = nowMs
        )
        assertTrue(forgedRequest is NotificationResolutionResult.Rejected)
        assertEquals(
            PendingConfirmationStore.REASON_UNREGISTERED_REQUEST,
            (forgedRequest as NotificationResolutionResult.Rejected).reasonCode
        )

        val forgedTask = store.resolveFromNotificationExtras(
            ConfirmationIntentExtras(taskId = "forged-task-999"),
            nowEpochMs = nowMs
        )
        assertTrue(forgedTask is NotificationResolutionResult.Rejected)
        assertEquals(
            PendingConfirmationStore.REASON_UNREGISTERED_TASK,
            (forgedTask as NotificationResolutionResult.Rejected).reasonCode
        )

        val forgedRule = store.resolveFromNotificationExtras(
            ConfirmationIntentExtras(ruleId = "forged-rule-999"),
            nowEpochMs = nowMs
        )
        assertTrue(forgedRule is NotificationResolutionResult.Rejected)
        assertEquals(
            PendingConfirmationStore.REASON_RULE_NOT_VERIFIED,
            (forgedRule as NotificationResolutionResult.Rejected).reasonCode
        )

        // 2. Register a valid foreground confirmation with requiresBiometric=true and untrusted slot=true
        val token = container.securityFirewall.mintToken(
            requestId = "req-fg-1",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf(AutomationToolNames.PLACE_CALL),
            nowEpochMs = nowMs
        )
        val plan = PlanAst(
            planId = "plan-fg-1",
            calls = listOf(
                ToolCallAst(
                    toolName = AutomationToolNames.PLACE_CALL,
                    arguments = mapOf(
                        "phone_number" to Tainted.fromUntrustedExternal(
                            value = SlotValueAst.StringValue("+15550199"),
                            slotKind = SensitiveSlotKind.PHONE_NUMBER,
                            sourceLabel = "notification:com.chat"
                        )
                    ),
                    orderIndex = 0,
                    targetId = ToolTargetIds.PHONE
                )
            )
        )
        val confirmResult = ToolResult.ConfirmationRequired(
            message = UserMessage(MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE),
            pendingToolName = AutomationToolNames.PLACE_CALL,
            targetId = ToolTargetIds.PHONE,
            canonicalArguments = mapOf(
                "phone_number" to Tainted.fromUntrustedExternal(
                    value = "+15550199",
                    slotKind = SensitiveSlotKind.PHONE_NUMBER,
                    sourceLabel = "notification:com.chat"
                )
            ),
            requiresBiometric = true,
            hasUntrustedHighRiskSlot = true,
            pendingOrderIndex = 0
        )

        val registered = store.registerForegroundConfirmation(
            plan = plan,
            capabilityToken = token,
            confirmation = confirmResult,
            nowEpochMs = nowMs
        )
        assertEquals(registered, store.activeConfirmationFlow.value)
        assertEquals(1, store.pendingItemsFlow.value.size)

        // 3. Attacker crafts notification intent extras attempting to downgrade requiresBiometric=false
        // and hasUntrustedHighRiskSlot=false for "req-fg-1" -> store MUST preserve authoritative flags!
        val resolved = store.resolveFromNotificationExtras(
            ConfirmationIntentExtras(
                requestId = "req-fg-1",
                requiresBiometric = false,
                hasUntrustedHighRiskSlot = false
            ),
            nowEpochMs = nowMs
        )
        assertTrue(resolved is NotificationResolutionResult.Resolved)
        val resolvedItem = (resolved as NotificationResolutionResult.Resolved).item
        assertTrue("Intent extras must NEVER downgrade requiresBiometric", resolvedItem.requiresBiometric)
        assertTrue("Intent extras must NEVER downgrade hasUntrustedHighRiskSlot", resolvedItem.hasUntrustedHighRiskSlot)

        // 4. Editing a slot sanitizes control tokens and updates both canonicalArguments and PlanAst
        val edited = store.updateEditedSlot(
            requestId = "req-fg-1",
            slotName = "phone_number",
            newRawValue = " +15550100<|tool_call> "
        )
        assertNotNull(edited)
        assertEquals("+15550100", edited!!.confirmation.canonicalArguments["phone_number"]?.value)
        assertEquals(
            "+15550100",
            (edited.plan?.calls?.first()?.arguments?.get("phone_number")?.value as? SlotValueAst.StringValue)?.value
        )

        // 5. Once CapabilityToken expires, resolving via notification extras rejects and evicts the item
        val expiredResolution = store.resolveFromNotificationExtras(
            ConfirmationIntentExtras(requestId = "req-fg-1"),
            nowEpochMs = nowMs + CapabilityToken.DEFAULT_TTL_MS + 1_000L
        )
        assertTrue(expiredResolution is NotificationResolutionResult.Rejected)
        assertEquals(
            PendingConfirmationStore.REASON_CAPABILITY_TOKEN_EXPIRED,
            (expiredResolution as NotificationResolutionResult.Rejected).reasonCode
        )
        assertNull(store.findByRequestId("req-fg-1"))
    }

    @Test
    fun pendingConfirmationStoreVerifiesBackgroundTasksAndSealedRoutineGrants() = runTest {
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            clockMs = { nowMs }
        )
        val store = container.pendingConfirmationStore

        // 1. Compile a rule with MODIFY_DELETE_SEND (requires interactive upgrade)
        val pendingRule = container.compileRuleUseCase.compilePendingRule(
            ruleId = "rule-call-alert",
            triggerSpec = RuleTriggerSpec("battery_low"),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = AutomationToolNames.PLACE_CALL,
                    requiredCapability = AtomicCapability.MODIFY_DELETE_SEND,
                    staticArguments = mapOf("phone_number" to "+15550123"),
                    requiresBiometric = true
                )
            ),
            nowEpochMs = nowMs
        )

        // While rule is still PENDING_USER_APPROVAL, notification intent extras for ruleId must be rejected!
        val unapprovedResolution = store.resolveFromNotificationExtras(
            ConfirmationIntentExtras(ruleId = pendingRule.ruleId),
            nowEpochMs = nowMs
        )
        assertTrue(unapprovedResolution is NotificationResolutionResult.Rejected)
        assertEquals(
            PendingConfirmationStore.REASON_RULE_NOT_VERIFIED,
            (unapprovedResolution as NotificationResolutionResult.Rejected).reasonCode
        )

        // Approve and HMAC-seal the rule
        container.compileRuleUseCase.approvePendingRule("rule-call-alert", nowMs)

        // Now resolving ruleId from notification extras succeeds and enforces requiresBiometric=true
        val approvedResolution = store.resolveFromNotificationExtras(
            ConfirmationIntentExtras(
                ruleId = "rule-call-alert",
                requiresBiometric = false // attempted downgrade in extras
            ),
            nowEpochMs = nowMs
        )
        assertTrue(approvedResolution is NotificationResolutionResult.Resolved)
        val resolvedRuleItem = (approvedResolution as NotificationResolutionResult.Resolved).item
        assertEquals(PendingConfirmationSource.ESCALATED_ROUTINE, resolvedRuleItem.source)
        assertEquals("rule-call-alert", resolvedRuleItem.ruleId)
        assertTrue("Authoritative RuleCapabilityGrant requiresBiometric must be enforced", resolvedRuleItem.requiresBiometric)

        // Revoking the rule immediately invalidates subsequent notification resolutions
        container.compileRuleUseCase.revokeRule("rule-call-alert", nowMs)
        val revokedResolution = store.resolveFromNotificationExtras(
            ConfirmationIntentExtras(ruleId = "rule-call-alert"),
            nowEpochMs = nowMs
        )
        assertTrue(revokedResolution is NotificationResolutionResult.Rejected)
        assertNull(store.findByRuleId("rule-call-alert"))

        // 2. BackgroundTaskContinuationManager integration: task pausing at confirmation gate
        val customProfile = PermissionProfile(
            id = "custom_sms_prompt",
            name = "SMS Prompt Profile",
            preset = PermissionProfilePreset.CUSTOM,
            capabilities = mapOf(
                AtomicCapability.CREATE_DRAFT to ConfirmationLevel.PROMPT_CARD
            )
        )
        container.manageProfilesUseCase.saveProfile(customProfile, nowMs)
        container.manageProfilesUseCase.assignTarget(ToolTargetIds.SMS, customProfile.id, nowMs)

        val bgToken = container.securityFirewall.mintToken(
            requestId = "req-bg-sms-1",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf(AutomationToolNames.CREATE_SMS_DRAFT),
            nowEpochMs = nowMs
        )
        val bgPlan = PlanAst(
            planId = "plan-bg-sms-1",
            calls = listOf(
                ToolCallAst(
                    toolName = AutomationToolNames.CREATE_SMS_DRAFT,
                    arguments = mapOf(
                        "recipient" to Tainted.fromUserUtterance(
                            SlotValueAst.StringValue("+15550177"),
                            SensitiveSlotKind.PHONE_NUMBER
                        ),
                        "body" to Tainted.fromUserUtterance(
                            SlotValueAst.StringValue("On my way"),
                            SensitiveSlotKind.TEXT_BODY
                        )
                    ),
                    orderIndex = 0,
                    targetId = ToolTargetIds.SMS
                )
            )
        )
        val bgContinuation = BackgroundTaskRequest.PlanContinuation(
            taskId = "task-bg-sms-1",
            plan = bgPlan,
            capabilityToken = bgToken,
            targetId = ToolTargetIds.SMS,
            languageTag = "en",
            enqueuedAtEpochMs = nowMs
        )

        val bgOutcome = container.backgroundTaskContinuationManager.executeNow(bgContinuation, nowMs)
        assertTrue("Expected background task to pause at ConfirmationRequired", bgOutcome is BackgroundTaskOutcome.ConfirmationRequired)

        // Resolving via taskId extra pulls the verified paused task from BackgroundTaskContinuationManager
        val resolvedBg = store.resolveFromNotificationExtras(
            ConfirmationIntentExtras(taskId = "task-bg-sms-1"),
            nowEpochMs = nowMs
        )
        assertTrue(resolvedBg is NotificationResolutionResult.Resolved)
        val bgItem = (resolvedBg as NotificationResolutionResult.Resolved).item
        assertEquals(PendingConfirmationSource.BACKGROUND_TASK, bgItem.source)
        assertEquals("task-bg-sms-1", bgItem.taskId)
        assertEquals(AutomationToolNames.CREATE_SMS_DRAFT, bgItem.confirmation.pendingToolName)

        // Mismatched taskId + ruleId in the same intent must be rejected
        val mismatched = store.resolveFromNotificationExtras(
            ConfirmationIntentExtras(
                taskId = "task-bg-sms-1",
                ruleId = "rule-call-alert"
            ),
            nowEpochMs = nowMs
        )
        assertTrue(mismatched is NotificationResolutionResult.Rejected)
        assertEquals(
            PendingConfirmationStore.REASON_MISMATCHED_EXTRAS,
            (mismatched as NotificationResolutionResult.Rejected).reasonCode
        )
    }

    @Test
    fun vaultBiometricControllerUnlocksWithCryptoObjectAndZeroizesRamOnLockOrFailure() = runTest {
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            clockMs = { nowMs }
        )
        val vault = container.navaVault
        val controller = container.vaultBiometricController

        assertFalse(controller.isVaultUnlockedFlow.value)
        assertFalse(vault.isUnlocked())

        // 1. Unlock via BiometricPromptGateway
        val unlockResult = controller.unlockWithGateway(activity = null)
        assertEquals(VaultUnlockResult.Unlocked, unlockResult)
        assertTrue(controller.isVaultUnlockedFlow.value)
        assertTrue(vault.isUnlocked())

        // Write and read an encrypted note while unlocked
        vault.writeNote("secret_note", "TopSecretVaultPayload".toByteArray(Charsets.UTF_8))
        val decryptedBuffer = vault.readNote("secret_note")
        assertEquals("TopSecretVaultPayload", String(decryptedBuffer, Charsets.UTF_8))

        // 2. Lock via VaultBiometricController -> immediately zeroizes decrypted ByteArray in RAM!
        controller.lock()
        assertFalse(controller.isVaultUnlockedFlow.value)
        assertFalse(vault.isUnlocked())
        assertTrue(
            "Decrypted buffer must be overwritten with 0x00 upon lock()",
            decryptedBuffer.all { it == 0.toByte() }
        )

        try {
            vault.readNote("secret_note")
            fail("Expected SecurityException when reading locked NavaVault")
        } catch (_: SecurityException) {
            // Expected
        }

        // 3. User cancellation in BiometricPromptGateway keeps vault locked (fail-closed)
        val cancellingController = VaultBiometricController(
            navaVault = vault,
            promptGateway = object : BiometricPromptGateway {
                override suspend fun authenticate(
                    activity: FragmentActivity?,
                    cryptoObject: BiometricPrompt.CryptoObject,
                    labels: BiometricPromptLabels
                ): BiometricPromptGatewayOutcome {
                    return BiometricPromptGatewayOutcome.Cancelled
                }
            }
        )
        val cancelResult = cancellingController.unlockWithGateway(activity = null)
        assertEquals(VaultUnlockResult.Cancelled, cancelResult)
        assertFalse(cancellingController.isVaultUnlockedFlow.value)
        assertFalse(vault.isUnlocked())

        // 4. Re-unlocking with authenticated CryptoObject unwraps existing DEK and decrypts saved note
        val reUnlockResult = controller.unlockWithGateway(activity = null)
        assertEquals(VaultUnlockResult.Unlocked, reUnlockResult)
        assertTrue(controller.isVaultUnlockedFlow.value)
        vault.withDecryptedNote("secret_note") { bytes ->
            assertEquals("TopSecretVaultPayload", String(bytes, Charsets.UTF_8))
        }
        controller.lock()
    }
}

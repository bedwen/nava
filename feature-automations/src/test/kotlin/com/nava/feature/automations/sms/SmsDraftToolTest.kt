package com.nava.feature.automations.sms

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.common.AutomationIntentGateway
import com.nava.feature.automations.common.AutomationOutboundActions
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.PlatformDispatchResult
import com.nava.feature.automations.common.ToolTargetIds
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SmsDraftToolTest {

    private class FakeIntentGateway : AutomationIntentGateway {
        var dispatchedRecipient: String? = null
        var dispatchedBody: String? = null
        var dispatchResult: PlatformDispatchResult = PlatformDispatchResult.Dispatched("sms_draft")

        override fun hasRuntimePermission(permission: String): Boolean = true
        override fun isNotificationPolicyAccessGranted(): Boolean = true
        override fun isNotificationListenerEnabled(): Boolean = true
        override fun dispatchSetAlarm(hour: Int, minute: Int, label: String?, skipUi: Boolean): PlatformDispatchResult =
            PlatformDispatchResult.Dispatched()
        override fun dispatchSetTimer(durationSeconds: Int, label: String?, skipUi: Boolean): PlatformDispatchResult =
            PlatformDispatchResult.Dispatched()

        override fun dispatchSmsDraft(recipient: String, body: String): PlatformDispatchResult {
            dispatchedRecipient = recipient
            dispatchedBody = body
            return dispatchResult
        }

        override fun dispatchDial(phoneNumber: String): PlatformDispatchResult = PlatformDispatchResult.Dispatched()
        override fun dispatchDirectCall(phoneNumber: String): PlatformDispatchResult = PlatformDispatchResult.Dispatched()
        override fun resolveLaunchablePackage(appNameOrPackage: String): String? = null
        override fun dispatchLaunchApp(packageName: String): PlatformDispatchResult = PlatformDispatchResult.Dispatched()
    }

    private class FakeFirewall : SecurityFirewallPort {
        var decision: FirewallDecision = FirewallDecision.Authorized
        val outboundValidations = mutableListOf<Triple<String, String, String>>()

        override suspend fun mintToken(
            requestId: String,
            utteranceProvenance: DataProvenance,
            candidateTools: Set<String>,
            nowEpochMs: Long
        ): CapabilityToken = error("not needed")

        override suspend fun authorizeToolCall(
            token: CapabilityToken,
            toolCall: ToolCallAst,
            toolMetadata: ToolMetadata,
            targetId: String,
            nowEpochMs: Long
        ): FirewallDecision = error("not needed")

        override suspend fun authorizeRuleExecution(grant: RuleCapabilityGrant): FirewallDecision = error("not needed")

        override suspend fun validateOutboundTarget(
            toolName: String,
            action: String,
            uriOrTarget: Tainted<String>
        ): FirewallDecision {
            outboundValidations.add(Triple(toolName, action, uriOrTarget.value))
            return decision
        }
    }

    private class FakeAuditLog : AuditLogPort {
        val entries = mutableListOf<AuditLogEntry>()

        override suspend fun record(entry: AuditLogEntry) {
            entries.add(entry)
        }

        override suspend fun queryRecent(limit: Int): List<AuditLogEntry> = entries.takeLast(limit)
    }

    private fun createContext(): ToolExecutionContext {
        val token = CapabilityToken.mint(
            tokenId = "tok_sms",
            requestId = "req_sms",
            allowedTools = setOf(AutomationToolNames.CREATE_SMS_DRAFT),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = 1700000000000L
        )
        return ToolExecutionContext(
            requestId = "req_sms",
            capabilityToken = token,
            ruleGrant = null,
            targetId = ToolTargetIds.SMS,
            languageTag = "en",
            issuedAtEpochMs = 1700000000000L,
            isUnattendedBackground = false
        )
    }

    @Test
    fun successfulSmsDraftPreparesOutboundIntentAndAuditsWithoutSecretLeakage() = runBlocking {
        val gateway = FakeIntentGateway()
        val firewall = FakeFirewall()
        val auditLog = FakeAuditLog()
        val tool = SmsDraftTool(gateway, firewall, auditLog)

        val args = mapOf(
            "recipient" to Tainted.fromUserUtterance(
                SlotValueAst.StringValue("+15551234567"),
                SensitiveSlotKind.PHONE_NUMBER
            ),
            "body" to Tainted.fromUserUtterance(
                SlotValueAst.StringValue("Top secret meeting at 4 PM"),
                SensitiveSlotKind.TEXT_BODY
            )
        )

        val result = tool.execute(createContext(), args)
        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals(MessageKey.ACTION_SMS_DRAFT_PREPARED, success.message.key)
        assertEquals("+15551234567", gateway.dispatchedRecipient)
        assertEquals("Top secret meeting at 4 PM", gateway.dispatchedBody)

        // Verify outbound target validation used smsto: and ACTION_SENDTO
        assertEquals(1, firewall.outboundValidations.size)
        val validation = firewall.outboundValidations.first()
        assertEquals(AutomationToolNames.CREATE_SMS_DRAFT, validation.first)
        assertEquals(AutomationOutboundActions.ACTION_SENDTO, validation.second)
        assertEquals("smsto:+15551234567", validation.third)

        // Verify audit log recorded without leaking note/message body
        assertEquals(1, auditLog.entries.size)
        val entry = auditLog.entries.first()
        assertEquals(ToolTargetIds.SMS, entry.targetId)
        assertEquals("SUCCESS", entry.decision)
        assertTrue(entry.actionSummary.contains("+15551234567"))
        assertFalse(entry.actionSummary.contains("Top secret"))
    }

    @Test
    fun missingArgumentsProduceInvalidArgumentsFailure() = runBlocking {
        val tool = SmsDraftTool(FakeIntentGateway(), FakeFirewall(), FakeAuditLog())

        // Missing body
        val noBody = mapOf(
            "recipient" to Tainted.fromUserUtterance(SlotValueAst.StringValue("+15551234567"))
        )
        val result1 = tool.execute(createContext(), noBody)
        assertTrue(result1 is ToolResult.Failure)
        assertEquals(MessageKey.ERROR_INVALID_ARGUMENTS, (result1 as ToolResult.Failure).message.key)

        // Missing recipient
        val noRecipient = mapOf(
            "body" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Hello"))
        )
        val result2 = tool.execute(createContext(), noRecipient)
        assertTrue(result2 is ToolResult.Failure)
        assertEquals(MessageKey.ERROR_INVALID_ARGUMENTS, (result2 as ToolResult.Failure).message.key)

        // Invalid dialable phone number
        val badNumber = mapOf(
            "recipient" to Tainted.fromUserUtterance(SlotValueAst.StringValue("invalid_phone")),
            "body" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Hello"))
        )
        val result3 = tool.execute(createContext(), badNumber)
        assertTrue(result3 is ToolResult.Failure)
        assertEquals(MessageKey.ERROR_INVALID_ARGUMENTS, (result3 as ToolResult.Failure).message.key)
    }

    @Test
    fun firewallDenialReturnsSecurityViolationFailure() = runBlocking {
        val firewall = FakeFirewall().apply {
            decision = FirewallDecision.Denied(
                message = UserMessage(MessageKey.ERROR_SECURITY_VIOLATION),
                reasonCode = "BLOCKED_BY_FIREWALL"
            )
        }
        val auditLog = FakeAuditLog()
        val tool = SmsDraftTool(FakeIntentGateway(), firewall, auditLog)

        val args = mapOf(
            "recipient" to Tainted.fromUserUtterance(SlotValueAst.StringValue("+15551234567")),
            "body" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Hello"))
        )

        val result = tool.execute(createContext(), args)
        assertTrue(result is ToolResult.Failure)
        val failure = result as ToolResult.Failure
        assertTrue(failure.isSecurityViolation)
        assertEquals("BLOCKED_BY_FIREWALL", failure.errorCode)
        assertEquals("BLOCKED_BY_FIREWALL", auditLog.entries.first().decision)
    }

    @Test
    fun firewallConfirmationRequiresActionCard() = runBlocking {
        val firewall = FakeFirewall().apply {
            decision = FirewallDecision.RequiresConfirmation(
                message = UserMessage(MessageKey.ACTION_CONFIRMATION_REQUIRED)
            )
        }
        val tool = SmsDraftTool(FakeIntentGateway(), firewall, FakeAuditLog())

        val args = mapOf(
            "recipient" to Tainted.fromUserUtterance(SlotValueAst.StringValue("+15551234567")),
            "body" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Hello"))
        )

        val result = tool.execute(createContext(), args)
        assertTrue(result is ToolResult.ConfirmationRequired)
        val confirmation = result as ToolResult.ConfirmationRequired
        assertEquals(ToolTargetIds.SMS, confirmation.targetId)
        assertTrue(confirmation.hasUntrustedHighRiskSlot)
    }

    @Test
    fun outboundTaintBarrierEscalatesUntrustedRecipientOrBody() = runBlocking {
        val firewall = FakeFirewall().apply { decision = FirewallDecision.Authorized }
        val tool = SmsDraftTool(FakeIntentGateway(), firewall, FakeAuditLog())

        // 1. Untrusted external recipient forces ConfirmationRequired with hasUntrustedHighRiskSlot = true
        val untrustedRecipientArgs = mapOf(
            "recipient" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("+15559876543"),
                SensitiveSlotKind.PHONE_NUMBER,
                sourceLabel = "notification:com.chat"
            ),
            "body" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Meeting reminder"))
        )
        val result1 = tool.execute(createContext(), untrustedRecipientArgs)
        assertTrue(result1 is ToolResult.ConfirmationRequired)
        val conf1 = result1 as ToolResult.ConfirmationRequired
        assertTrue(conf1.hasUntrustedHighRiskSlot)
        assertEquals(MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE, conf1.message.key)

        // 2. Untrusted body forces ConfirmationRequired with hasUntrustedHighRiskSlot = false
        val untrustedBodyArgs = mapOf(
            "recipient" to Tainted.fromUserUtterance(
                SlotValueAst.StringValue("+15551234567"),
                SensitiveSlotKind.PHONE_NUMBER
            ),
            "body" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("Injected prompt attack"),
                SensitiveSlotKind.TEXT_BODY,
                sourceLabel = "file:saf"
            )
        )
        val result2 = tool.execute(createContext(), untrustedBodyArgs)
        assertTrue(result2 is ToolResult.ConfirmationRequired)
        val conf2 = result2 as ToolResult.ConfirmationRequired
        assertFalse(conf2.hasUntrustedHighRiskSlot)
        assertEquals(MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE, conf2.message.key)

        // 3. Vault-sourced body forces ConfirmationRequired
        val vaultBodyArgs = mapOf(
            "recipient" to Tainted.fromUserUtterance(
                SlotValueAst.StringValue("+15551234567"),
                SensitiveSlotKind.PHONE_NUMBER
            ),
            "body" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("Vault note secret"),
                SensitiveSlotKind.TEXT_BODY,
                sourceLabel = "vault:note_42"
            )
        )
        val result3 = tool.execute(createContext(), vaultBodyArgs)
        assertTrue(result3 is ToolResult.ConfirmationRequired)
        val conf3 = result3 as ToolResult.ConfirmationRequired
        assertEquals(MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE, conf3.message.key)
    }

    @Test
    fun platformUnavailableOrMissingPermissionReturnsCleanFailure() = runBlocking {
        val gateway = FakeIntentGateway().apply {
            dispatchResult = PlatformDispatchResult.Unavailable("No SMS handler installed")
        }
        val auditLog = FakeAuditLog()
        val tool = SmsDraftTool(gateway, FakeFirewall(), auditLog)

        val args = mapOf(
            "recipient" to Tainted.fromUserUtterance(SlotValueAst.StringValue("+15551234567")),
            "body" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Hello"))
        )

        val result = tool.execute(createContext(), args)
        assertTrue(result is ToolResult.Failure)
        assertEquals(MessageKey.ERROR_PLATFORM_UNAVAILABLE, (result as ToolResult.Failure).message.key)
        assertEquals("PLATFORM_UNAVAILABLE", auditLog.entries.first().decision)
    }

    @Test
    fun approvedStage2TaintedCallExecutesCleanlyWhenUserConfirmed() = runBlocking {
        val gateway = FakeIntentGateway()
        val firewall = FakeFirewall().apply { decision = FirewallDecision.Authorized }
        val auditLog = FakeAuditLog()
        val tool = SmsDraftTool(gateway, firewall, auditLog)

        val untrustedArgs = mapOf(
            "recipient" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("+15559876543"),
                SensitiveSlotKind.PHONE_NUMBER,
                sourceLabel = "notification:com.chat"
            ),
            "body" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("Hello from untrusted source"),
                SensitiveSlotKind.TEXT_BODY,
                sourceLabel = "notification:com.chat"
            )
        )

        // 1. Unconfirmed context (default isUserConfirmed = false) must escalate
        val unconfirmedResult = tool.execute(createContext(), untrustedArgs)
        assertTrue("Unconfirmed tainted SMS draft must require confirmation", unconfirmedResult is ToolResult.ConfirmationRequired)

        // 2. Confirmed context (isUserConfirmed = true) executes cleanly without deadlocking
        val confirmedContext = createContext().copy(isUserConfirmed = true)
        val confirmedResult = tool.execute(confirmedContext, untrustedArgs)
        assertTrue("Approved Stage 2 SMS draft must succeed", confirmedResult is ToolResult.Success)
        assertEquals("+15559876543", gateway.dispatchedRecipient)
        assertEquals("Hello from untrusted source", gateway.dispatchedBody)

        // 3. FirewallDecision.Denied must hard-block unconditionally even when isUserConfirmed = true
        firewall.decision = FirewallDecision.Denied(
            message = UserMessage(MessageKey.ERROR_SECURITY_VIOLATION),
            reasonCode = "POLICY_DENIED"
        )
        val deniedResult = tool.execute(confirmedContext, untrustedArgs)
        assertTrue("Denied firewall decision must hard-block even when confirmed", deniedResult is ToolResult.Failure)
        val failure = deniedResult as ToolResult.Failure
        assertTrue(failure.isSecurityViolation)
        assertEquals("POLICY_DENIED", failure.errorCode)
    }

    @Test
    fun biometricRequiredHonorsBiometricApprovalAndUserConfirmation() = runBlocking {
        val gateway = FakeIntentGateway()
        val firewall = FakeFirewall().apply {
            decision = FirewallDecision.RequiresBiometric(UserMessage(MessageKey.ACTION_CONFIRMATION_REQUIRED))
        }
        val tool = SmsDraftTool(gateway, firewall, FakeAuditLog())

        val untrustedArgs = mapOf(
            "recipient" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("+15559876543"),
                SensitiveSlotKind.PHONE_NUMBER
            ),
            "body" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Biometric SMS"))
        )

        // Biometric approved but userConfirmed false -> still requires confirmation for untrusted high-risk slot
        val bioOnlyContext = createContext().copy(isBiometricApproved = true, isUserConfirmed = false)
        val bioOnlyResult = tool.execute(bioOnlyContext, untrustedArgs)
        assertTrue(bioOnlyResult is ToolResult.ConfirmationRequired)

        // Both bioApproved and userConfirmed true -> succeeds
        val fullyApprovedContext = createContext().copy(isBiometricApproved = true, isUserConfirmed = true)
        val result = tool.execute(fullyApprovedContext, untrustedArgs)
        assertTrue(result is ToolResult.Success)
    }
}

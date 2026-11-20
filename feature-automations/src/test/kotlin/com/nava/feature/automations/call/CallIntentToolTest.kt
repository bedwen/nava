package com.nava.feature.automations.call

import android.Manifest
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleTriggerSpec
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

class CallIntentToolTest {

    private class FakeIntentGateway : AutomationIntentGateway {
        var callPhoneGranted: Boolean = true
        var dialedNumber: String? = null
        var directCalledNumber: String? = null
        var dispatchResult: PlatformDispatchResult = PlatformDispatchResult.Dispatched("call")

        override fun hasRuntimePermission(permission: String): Boolean {
            if (permission == Manifest.permission.CALL_PHONE) return callPhoneGranted
            return true
        }

        override fun isNotificationPolicyAccessGranted(): Boolean = true
        override fun isNotificationListenerEnabled(): Boolean = true
        override fun dispatchSetAlarm(hour: Int, minute: Int, label: String?, skipUi: Boolean): PlatformDispatchResult =
            PlatformDispatchResult.Dispatched()
        override fun dispatchSetTimer(durationSeconds: Int, label: String?, skipUi: Boolean): PlatformDispatchResult =
            PlatformDispatchResult.Dispatched()
        override fun dispatchSmsDraft(recipient: String, body: String): PlatformDispatchResult =
            PlatformDispatchResult.Dispatched()

        override fun dispatchDial(phoneNumber: String): PlatformDispatchResult {
            dialedNumber = phoneNumber
            return dispatchResult
        }

        override fun dispatchDirectCall(phoneNumber: String): PlatformDispatchResult {
            directCalledNumber = phoneNumber
            return dispatchResult
        }

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

    private fun createInteractiveContext(toolName: String): ToolExecutionContext {
        val token = CapabilityToken.mint(
            tokenId = "tok_call",
            requestId = "req_call",
            allowedTools = setOf(toolName),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = 1700000000000L
        )
        return ToolExecutionContext(
            requestId = "req_call",
            capabilityToken = token,
            ruleGrant = null,
            targetId = ToolTargetIds.PHONE,
            languageTag = "en",
            issuedAtEpochMs = 1700000000000L,
            isUnattendedBackground = false
        )
    }

    private fun createUnattendedContext(toolName: String): ToolExecutionContext {
        val grant = RuleCapabilityGrant(
            grantId = "grant_call",
            ruleId = "rule_call",
            triggerSpec = RuleTriggerSpec(triggerType = "time", parameters = mapOf("hour" to "9", "minute" to "0")),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = toolName,
                    requiredCapability = AtomicCapability.CREATE_DRAFT
                )
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "sealed_call_hmac"
        )
        return ToolExecutionContext(
            requestId = "req_call_unattended",
            capabilityToken = null,
            ruleGrant = grant,
            targetId = ToolTargetIds.PHONE,
            languageTag = "en",
            issuedAtEpochMs = 1700000000000L,
            isUnattendedBackground = true
        )
    }

    @Test
    fun dialCallToolOpensDialerSafelyAndAuditsTarget() = runBlocking {
        val gateway = FakeIntentGateway()
        val firewall = FakeFirewall()
        val auditLog = FakeAuditLog()
        val dialTool = DialCallTool(gateway, firewall, auditLog)

        val args = mapOf(
            "phone_number" to Tainted.fromUserUtterance(
                SlotValueAst.StringValue("+15552345678"),
                SensitiveSlotKind.PHONE_NUMBER
            )
        )

        val result = dialTool.execute(createInteractiveContext(AutomationToolNames.DIAL_CALL), args)
        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals(MessageKey.ACTION_CALL_INTENT_PREPARED, success.message.key)
        assertEquals("+15552345678", gateway.dialedNumber)

        // Verify outbound target validation
        val validation = firewall.outboundValidations.first()
        assertEquals(AutomationToolNames.DIAL_CALL, validation.first)
        assertEquals(AutomationOutboundActions.ACTION_DIAL, validation.second)
        assertEquals("tel:+15552345678", validation.third)

        // Verify audit log
        val audit = auditLog.entries.first()
        assertEquals(ToolTargetIds.PHONE, audit.targetId)
        assertEquals("SUCCESS", audit.decision)
    }

    @Test
    fun dialCallToolPermitsUnattendedExecution() = runBlocking {
        val gateway = FakeIntentGateway()
        val tool = DialCallTool(gateway, FakeFirewall(), FakeAuditLog())

        val args = mapOf(
            "phone_number" to Tainted.fromUserUtterance(
                SlotValueAst.StringValue("+15552345678"),
                SensitiveSlotKind.PHONE_NUMBER
            )
        )

        val result = tool.execute(createUnattendedContext(AutomationToolNames.DIAL_CALL), args)
        assertTrue(result is ToolResult.Success)
        assertEquals("+15552345678", gateway.dialedNumber)
    }

    @Test
    fun dialCallToolTaintBarrierRequiresConfirmation() = runBlocking {
        val tool = DialCallTool(FakeIntentGateway(), FakeFirewall(), FakeAuditLog())

        val args = mapOf(
            "phone_number" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("+15552345678"),
                SensitiveSlotKind.PHONE_NUMBER,
                sourceLabel = "notification:com.chat"
            )
        )

        val result = tool.execute(createInteractiveContext(AutomationToolNames.DIAL_CALL), args)
        assertTrue(result is ToolResult.ConfirmationRequired)
        val confirmation = result as ToolResult.ConfirmationRequired
        assertTrue(confirmation.hasUntrustedHighRiskSlot)
        assertEquals(ToolTargetIds.PHONE, confirmation.targetId)
    }

    @Test
    fun placeCallToolRejectsUnattendedBackgroundExecution() = runBlocking {
        val auditLog = FakeAuditLog()
        val tool = PlaceCallTool(FakeIntentGateway(), FakeFirewall(), auditLog)

        val args = mapOf(
            "phone_number" to Tainted.fromUserUtterance(SlotValueAst.StringValue("+15552345678"))
        )

        val result = tool.execute(createUnattendedContext(AutomationToolNames.PLACE_CALL), args)
        assertTrue(result is ToolResult.Failure)
        val failure = result as ToolResult.Failure
        assertTrue(failure.isSecurityViolation)
        assertEquals("UNATTENDED_DIRECT_CALL_FORBIDDEN", failure.errorCode)
        assertEquals("SECURITY_VIOLATION", auditLog.entries.first().decision)
    }

    @Test
    fun placeCallToolRequiresCallPhoneRuntimePermission() = runBlocking {
        val gateway = FakeIntentGateway().apply { callPhoneGranted = false }
        val auditLog = FakeAuditLog()
        val tool = PlaceCallTool(gateway, FakeFirewall(), auditLog)

        val args = mapOf(
            "phone_number" to Tainted.fromUserUtterance(SlotValueAst.StringValue("+15552345678"))
        )

        val result = tool.execute(createInteractiveContext(AutomationToolNames.PLACE_CALL), args)
        assertTrue(result is ToolResult.Failure)
        val failure = result as ToolResult.Failure
        assertEquals(MessageKey.ERROR_SYSTEM_PERMISSION_MISSING, failure.message.key)
        assertFalse(failure.isSecurityViolation)
        assertEquals("MISSING_PERMISSION", auditLog.entries.first().decision)
    }

    @Test
    fun placeCallToolInitiatesDirectCallWhenPermissionGranted() = runBlocking {
        val gateway = FakeIntentGateway().apply { callPhoneGranted = true }
        val firewall = FakeFirewall()
        val auditLog = FakeAuditLog()
        val tool = PlaceCallTool(gateway, firewall, auditLog)

        val args = mapOf(
            "phone_number" to Tainted.fromUserUtterance(
                SlotValueAst.StringValue("+15552345678"),
                SensitiveSlotKind.PHONE_NUMBER
            )
        )

        val result = tool.execute(createInteractiveContext(AutomationToolNames.PLACE_CALL), args)
        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals(MessageKey.ACTION_DIRECT_CALL_INITIATED, success.message.key)
        assertEquals("+15552345678", gateway.directCalledNumber)

        // Verify outbound target validation
        val validation = firewall.outboundValidations.first()
        assertEquals(AutomationToolNames.PLACE_CALL, validation.first)
        assertEquals(AutomationOutboundActions.ACTION_CALL, validation.second)
        assertEquals("tel:+15552345678", validation.third)

        // Verify audit log
        val audit = auditLog.entries.first()
        assertEquals(ToolTargetIds.PHONE, audit.targetId)
        assertEquals("SUCCESS", audit.decision)
    }

    @Test
    fun factoryCreatesAllAdaptersOrthogonally() {
        val tools = CallIntentTool.createAll(FakeIntentGateway(), FakeFirewall(), FakeAuditLog())
        assertEquals(2, tools.size)
        val names = tools.map { it.metadata.name }.toSet()
        assertEquals(setOf(AutomationToolNames.DIAL_CALL, AutomationToolNames.PLACE_CALL), names)
    }
}

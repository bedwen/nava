package com.nava.feature.automations.applaunch

import com.nava.domain.ai.SlotValueAst
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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AppLaunchToolTest {

    private class FakeIntentGateway : AutomationIntentGateway {
        val installedApps = mutableMapOf(
            "com.android.calculator2" to "Calculator",
            "com.google.android.deskclock" to "Clock",
            "com.example.notes" to "Notes"
        )
        var lastLaunchedPackage: String? = null
        var launchResult: PlatformDispatchResult = PlatformDispatchResult.Dispatched()

        override fun hasRuntimePermission(permission: String): Boolean = true
        override fun isNotificationPolicyAccessGranted(): Boolean = true
        override fun isNotificationListenerEnabled(): Boolean = true

        override fun dispatchSetAlarm(hour: Int, minute: Int, label: String?, skipUi: Boolean): PlatformDispatchResult =
            PlatformDispatchResult.Dispatched()

        override fun dispatchSetTimer(durationSeconds: Int, label: String?, skipUi: Boolean): PlatformDispatchResult =
            PlatformDispatchResult.Dispatched()

        override fun dispatchSmsDraft(recipient: String, body: String): PlatformDispatchResult =
            PlatformDispatchResult.Dispatched()

        override fun dispatchDial(phoneNumber: String): PlatformDispatchResult =
            PlatformDispatchResult.Dispatched()

        override fun dispatchDirectCall(phoneNumber: String): PlatformDispatchResult =
            PlatformDispatchResult.Dispatched()

        override fun resolveLaunchablePackage(appNameOrPackage: String): String? {
            val trimmed = appNameOrPackage.trim()
            if (trimmed in installedApps.keys) return trimmed
            for ((pkg, label) in installedApps) {
                if (label.equals(trimmed, ignoreCase = true)) return pkg
            }
            return null
        }

        override fun dispatchLaunchApp(packageName: String): PlatformDispatchResult {
            lastLaunchedPackage = packageName
            return launchResult
        }
    }

    private class FakeFirewall : SecurityFirewallPort {
        var outboundDecision: FirewallDecision = FirewallDecision.Authorized

        override suspend fun mintToken(
            requestId: String,
            utteranceProvenance: DataProvenance,
            candidateTools: Set<String>,
            nowEpochMs: Long
        ): CapabilityToken = error("Not used in tool unit tests")

        override suspend fun authorizeToolCall(
            token: CapabilityToken,
            toolCall: com.nava.domain.ai.ToolCallAst,
            toolMetadata: com.nava.domain.tool.ToolMetadata,
            targetId: String,
            nowEpochMs: Long
        ): FirewallDecision = FirewallDecision.Authorized

        override suspend fun authorizeRuleExecution(grant: RuleCapabilityGrant): FirewallDecision =
            FirewallDecision.Authorized

        override suspend fun validateOutboundTarget(
            toolName: String,
            action: String,
            uriOrTarget: Tainted<String>
        ): FirewallDecision = outboundDecision
    }

    private class FakeAuditLog : AuditLogPort {
        val records = mutableListOf<AuditLogEntry>()

        override suspend fun record(entry: AuditLogEntry) {
            records.add(entry)
        }

        override suspend fun queryRecent(limit: Int): List<AuditLogEntry> = records.takeLast(limit)
    }

    private val fakeGateway = FakeIntentGateway()
    private val fakeFirewall = FakeFirewall()
    private val fakeAudit = FakeAuditLog()
    private var simulatedTime: Long = 1_000_000L

    private val tool = AppLaunchTool(
        intentGateway = fakeGateway,
        firewall = fakeFirewall,
        auditLog = fakeAudit,
        clock = { simulatedTime }
    )

    private fun testContext(): ToolExecutionContext = ToolExecutionContext(
        requestId = "req-launch-1",
        capabilityToken = CapabilityToken.mint(
            tokenId = "tok-launch-1",
            requestId = "req-launch-1",
            allowedTools = setOf(AutomationToolNames.LAUNCH_APP),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = simulatedTime
        ),
        ruleGrant = null,
        targetId = ToolTargetIds.APP_LAUNCH,
        languageTag = "en",
        issuedAtEpochMs = simulatedTime,
        isUnattendedBackground = false
    )

    @Test
    fun metadataConformsToAppLaunchCapability() {
        assertEquals(AutomationToolNames.LAUNCH_APP, tool.metadata.name)
        assertEquals(com.nava.domain.security.AtomicCapability.APP_LAUNCH, tool.metadata.requiredCapability)
        assertTrue(tool.metadata.supportsUnattendedRule)
        val packageField = tool.metadata.fieldByName("package_name")
        assertNotNull(packageField)
        assertEquals(SensitiveSlotKind.PACKAGE_NAME, packageField!!.slotKind)
        val appNameField = tool.metadata.fieldByName("app_name")
        assertNotNull(appNameField)
        assertEquals(SensitiveSlotKind.TEXT_BODY, appNameField!!.slotKind)
    }

    @Test
    fun launchAppSucceedsWithDirectPackageName() = runBlocking {
        val args = mapOf(
            "package_name" to Tainted.fromUserUtterance(
                SlotValueAst.StringValue("com.android.calculator2"),
                SensitiveSlotKind.PACKAGE_NAME
            )
        )

        val result = tool.execute(testContext(), args)
        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals(MessageKey.ACTION_APP_LAUNCHED, success.message.key)
        assertEquals("com.android.calculator2", success.outputValues["package_name"])
        assertEquals("com.android.calculator2", fakeGateway.lastLaunchedPackage)

        assertEquals(1, fakeAudit.records.size)
        assertEquals("com.android.calculator2", fakeAudit.records.first().targetId)
        assertEquals("SUCCESS", fakeAudit.records.first().decision)
    }

    @Test
    fun launchAppSucceedsResolvingAppName() = runBlocking {
        val args = mapOf(
            "app_name" to Tainted.fromUserUtterance(
                SlotValueAst.StringValue("Clock"),
                SensitiveSlotKind.PACKAGE_NAME
            )
        )

        val result = tool.execute(testContext(), args)
        assertTrue(result is ToolResult.Success)
        assertEquals("com.google.android.deskclock", fakeGateway.lastLaunchedPackage)
    }

    @Test
    fun launchAppEscalatesToConfirmationWhenUntrustedExternalTaintPresent() = runBlocking {
        val args = mapOf(
            "package_name" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("com.android.calculator2"),
                SensitiveSlotKind.PACKAGE_NAME,
                sourceLabel = "notification:com.chat"
            )
        )

        val result = tool.execute(testContext(), args)
        assertTrue(result is ToolResult.ConfirmationRequired)
        val conf = result as ToolResult.ConfirmationRequired
        assertEquals(AutomationToolNames.LAUNCH_APP, conf.pendingToolName)
        assertEquals("com.android.calculator2", conf.targetId)
        assertTrue(conf.hasUntrustedHighRiskSlot)
        assertEquals(MessageKey.ACTION_CONFIRMATION_REQUIRED, conf.message.key)

        assertEquals(1, fakeAudit.records.size)
        assertEquals("CONFIRMATION_REQUIRED", fakeAudit.records.first().decision)
    }

    @Test
    fun launchAppRejectsVaultTaint() = runBlocking {
        val args = mapOf(
            "package_name" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("com.android.calculator2"),
                SensitiveSlotKind.PACKAGE_NAME,
                sourceLabel = "vault:note"
            )
        )

        val result = tool.execute(testContext(), args)
        assertTrue(result is ToolResult.Failure)
        val failure = result as ToolResult.Failure
        assertTrue(failure.isSecurityViolation)
        assertEquals("VAULT_DATA_EXFILTRATION_BLOCKED", failure.errorCode)
    }

    @Test
    fun launchAppFailsWhenTargetNotFoundOrMissing() = runBlocking {
        val unknownArgs = mapOf(
            "app_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue("NonexistentApp"))
        )
        val unknownResult = tool.execute(testContext(), unknownArgs)
        assertTrue(unknownResult is ToolResult.Failure)
        assertEquals(MessageKey.ERROR_NOT_FOUND, (unknownResult as ToolResult.Failure).message.key)

        val emptyArgs = emptyMap<String, Tainted<SlotValueAst>>()
        val emptyResult = tool.execute(testContext(), emptyArgs)
        assertTrue(emptyResult is ToolResult.Failure)
        assertEquals(MessageKey.ERROR_INVALID_ARGUMENTS, (emptyResult as ToolResult.Failure).message.key)
    }

    @Test
    fun launchAppHandlesFirewallDenialsAndPlatformErrors() = runBlocking {
        fakeFirewall.outboundDecision = FirewallDecision.Denied(
            message = UserMessage(MessageKey.ERROR_SECURITY_VIOLATION),
            reasonCode = "OUTBOUND_APP_BLOCKED"
        )
        val args = mapOf("package_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue("com.example.notes")))

        val blockedResult = tool.execute(testContext(), args)
        assertTrue(blockedResult is ToolResult.Failure)
        assertTrue((blockedResult as ToolResult.Failure).isSecurityViolation)

        fakeFirewall.outboundDecision = FirewallDecision.Authorized
        fakeGateway.launchResult = PlatformDispatchResult.Unavailable("App is disabled")

        val unavailResult = tool.execute(testContext(), args)
        assertTrue(unavailResult is ToolResult.Failure)
        assertEquals(MessageKey.ERROR_PLATFORM_UNAVAILABLE, (unavailResult as ToolResult.Failure).message.key)
    }

    @Test
    fun approvedStage2AppLaunchExecutesCleanlyWhenUserConfirmed() = runBlocking {
        fakeFirewall.outboundDecision = FirewallDecision.Authorized
        fakeGateway.launchResult = PlatformDispatchResult.Dispatched()

        val untrustedArgs = mapOf(
            "app_name" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("Calculator"),
                SensitiveSlotKind.TEXT_BODY,
                sourceLabel = "notification:com.chat"
            )
        )

        // 1. Unconfirmed launch escalates to confirmation
        val unconfResult = tool.execute(testContext(), untrustedArgs)
        assertTrue(unconfResult is ToolResult.ConfirmationRequired)

        // 2. Confirmed launch executes cleanly
        val confirmedContext = testContext().copy(isUserConfirmed = true)
        val confResult = tool.execute(confirmedContext, untrustedArgs)
        assertTrue(confResult is ToolResult.Success)
        assertEquals("com.android.calculator2", fakeGateway.lastLaunchedPackage)

        // 3. Denied firewall decision hard-blocks unconditionally even when confirmed
        fakeFirewall.outboundDecision = FirewallDecision.Denied(
            message = UserMessage(MessageKey.ERROR_SECURITY_VIOLATION),
            reasonCode = "BLOCKED_APP_LAUNCH"
        )
        val deniedResult = tool.execute(confirmedContext, untrustedArgs)
        assertTrue(deniedResult is ToolResult.Failure)
        val failure = deniedResult as ToolResult.Failure
        assertTrue(failure.isSecurityViolation)
        assertEquals("BLOCKED_APP_LAUNCH", failure.errorCode)
    }
}

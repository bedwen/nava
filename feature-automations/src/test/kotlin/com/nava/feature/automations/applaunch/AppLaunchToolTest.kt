package com.nava.feature.automations.applaunch

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.PermissionEvaluatorPort
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleTriggerSpec
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
            nowEpochMs: Long,
            maxToolCalls: Int
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

    private class FakePermissionEvaluator : PermissionEvaluatorPort {
        val targetLevels = mutableMapOf<String, ConfirmationLevel>()
        val explicitlyBoundTargets = mutableSetOf<String>()

        override suspend fun getProfileForTarget(targetId: String): PermissionProfile {
            return if (targetId in explicitlyBoundTargets) {
                val level = targetLevels[targetId] ?: ConfirmationLevel.DISABLED
                if (level.isAllowed) {
                    PermissionProfile.trustedSystemAutomation().withCapability(AtomicCapability.APP_LAUNCH, level)
                } else {
                    PermissionProfile.defaultDeny()
                }
            } else {
                PermissionProfile.defaultDeny()
            }
        }

        override suspend fun evaluateCapability(
            targetId: String,
            capability: AtomicCapability
        ): ConfirmationLevel {
            return targetLevels[targetId] ?: ConfirmationLevel.DISABLED
        }

        override suspend fun listProfiles(): List<PermissionProfile> {
            val defaultDenyTargets = explicitlyBoundTargets.filter { targetLevels[it] == ConfirmationLevel.DISABLED }.toSet()
            return listOf(
                PermissionProfile.defaultDeny().copy(assignedTargets = defaultDenyTargets)
            )
        }

        override suspend fun saveProfile(profile: PermissionProfile) {}
        override suspend fun assignTargetToProfile(targetId: String, profileId: String) {}
        override suspend fun deleteProfile(profileId: String) {}
    }

    private val fakeGateway = FakeIntentGateway()
    private val fakeFirewall = FakeFirewall()
    private val fakeAudit = FakeAuditLog()
    private val fakeEvaluator = FakePermissionEvaluator()
    private var simulatedTime: Long = 1_000_000L

    private val tool = AppLaunchTool(
        intentGateway = fakeGateway,
        firewall = fakeFirewall,
        auditLog = fakeAudit,
        clock = { simulatedTime }
    )

    private val toolWithEvaluator = AppLaunchTool(
        intentGateway = fakeGateway,
        firewall = fakeFirewall,
        auditLog = fakeAudit,
        clock = { simulatedTime },
        permissionEvaluator = fakeEvaluator
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

    @Test
    fun launchAppFallsBackFromUnresolvablePackageNameToValidAppName() = runBlocking {
        fakeFirewall.outboundDecision = FirewallDecision.Authorized
        fakeGateway.launchResult = PlatformDispatchResult.Dispatched()

        val args = mapOf(
            "package_name" to Tainted.fromUserUtterance(
                SlotValueAst.StringValue("com.nonexistent.hallucinated"),
                SensitiveSlotKind.PACKAGE_NAME
            ),
            "app_name" to Tainted.fromUserUtterance(
                SlotValueAst.StringValue("Calculator"),
                SensitiveSlotKind.TEXT_BODY
            )
        )

        val result = tool.execute(testContext(), args)
        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals("com.android.calculator2", success.outputValues["package_name"])
        assertEquals("com.android.calculator2", fakeGateway.lastLaunchedPackage)
    }

    @Test
    fun launchAppCombinesWorstProvenanceWhenFallbackAppNameResolvesWithUntrustedPackageArg() = runBlocking {
        fakeFirewall.outboundDecision = FirewallDecision.Authorized
        fakeGateway.launchResult = PlatformDispatchResult.Dispatched()

        // package_name came from untrusted source, app_name was user utterance
        val args = mapOf(
            "package_name" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("com.nonexistent.malicious"),
                SensitiveSlotKind.PACKAGE_NAME,
                sourceLabel = "notification:com.chat"
            ),
            "app_name" to Tainted.fromUserUtterance(
                SlotValueAst.StringValue("Calculator"),
                SensitiveSlotKind.TEXT_BODY
            )
        )

        // Must escalate to confirmation because package_name was untrusted and contributed to the execution context
        val result = tool.execute(testContext(), args)
        assertTrue(result is ToolResult.ConfirmationRequired)
        val conf = result as ToolResult.ConfirmationRequired
        assertEquals("com.android.calculator2", conf.targetId)
        assertTrue(conf.hasUntrustedHighRiskSlot)
        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, conf.canonicalArguments["package_name"]?.provenance)
    }

    @Test
    fun launchAppDeniesWhenResolvedPackageExplicitlyDisabledEvenIfSystemAppLaunchIsAuto() = runBlocking {
        fakeFirewall.outboundDecision = FirewallDecision.Authorized
        fakeGateway.installedApps["com.bank.app"] = "Bank"
        fakeGateway.lastLaunchedPackage = null

        // System app launch is AUTO
        fakeEvaluator.targetLevels[ToolTargetIds.APP_LAUNCH] = ConfirmationLevel.AUTO
        // But com.bank.app is explicitly bound to DEFAULT_DENY (DISABLED)
        fakeEvaluator.explicitlyBoundTargets.add("com.bank.app")
        fakeEvaluator.targetLevels["com.bank.app"] = ConfirmationLevel.DISABLED

        // Fallback from blank package_name to app_name="Bank"
        val args = mapOf(
            "package_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue("")),
            "app_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Bank"))
        )

        val result = toolWithEvaluator.execute(testContext(), args)
        assertTrue(result is ToolResult.Failure)
        val failure = result as ToolResult.Failure
        assertTrue(failure.isSecurityViolation)
        assertEquals("PERMISSION_DENIED", failure.errorCode)
        assertEquals(null, fakeGateway.lastLaunchedPackage)

        val lastAudit = fakeAudit.records.last()
        assertEquals("com.bank.app", lastAudit.targetId)
        assertEquals("PERMISSION_DENIED", lastAudit.decision)
    }

    @Test
    fun launchAppRejectsUnattendedRoutineWhenPackageRequiresPromptCard() = runBlocking {
        fakeFirewall.outboundDecision = FirewallDecision.Authorized
        fakeGateway.installedApps["com.camera.app"] = "Camera"
        fakeGateway.lastLaunchedPackage = null

        fakeEvaluator.explicitlyBoundTargets.add("com.camera.app")
        fakeEvaluator.targetLevels["com.camera.app"] = ConfirmationLevel.PROMPT_CARD

        val args = mapOf(
            "app_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Camera"))
        )

        val grant = RuleCapabilityGrant(
            grantId = "grant_app_launch",
            ruleId = "rule_app_launch",
            triggerSpec = RuleTriggerSpec("time", mapOf("hour" to "8", "minute" to "0")),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = AutomationToolNames.LAUNCH_APP,
                    requiredCapability = AtomicCapability.APP_LAUNCH
                )
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "sealed_app_launch_hmac"
        )
        val unattendedContext = ToolExecutionContext(
            requestId = "req-unattended-launch",
            capabilityToken = null,
            ruleGrant = grant,
            targetId = ToolTargetIds.ROUTINES,
            languageTag = "en",
            issuedAtEpochMs = simulatedTime,
            isUnattendedBackground = true
        )
        val result = toolWithEvaluator.execute(unattendedContext, args)

        assertTrue(result is ToolResult.Failure)
        val failure = result as ToolResult.Failure
        assertTrue(failure.isSecurityViolation)
        assertEquals("UNATTENDED_EXECUTION_FORBIDDEN", failure.errorCode)
        assertEquals(null, fakeGateway.lastLaunchedPackage)
    }

    @Test
    fun launchAppRequestsConfirmationWhenPackageRequiresPromptCardAndInteractiveUserUnconfirmed() = runBlocking {
        fakeFirewall.outboundDecision = FirewallDecision.Authorized
        fakeGateway.installedApps["com.camera.app"] = "Camera"

        fakeEvaluator.explicitlyBoundTargets.add("com.camera.app")
        fakeEvaluator.targetLevels["com.camera.app"] = ConfirmationLevel.PROMPT_CARD

        val args = mapOf(
            "app_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Camera"))
        )

        val result = toolWithEvaluator.execute(testContext().copy(isUserConfirmed = false), args)
        assertTrue(result is ToolResult.ConfirmationRequired)
        val conf = result as ToolResult.ConfirmationRequired
        assertEquals("com.camera.app", conf.targetId)

        // Confirmed context allows execution
        val confirmedResult = toolWithEvaluator.execute(testContext().copy(isUserConfirmed = true), args)
        assertTrue(confirmedResult is ToolResult.Success)
        assertEquals("com.camera.app", fakeGateway.lastLaunchedPackage)
    }

    @Test
    fun launchAppSucceedsWhenUnboundPackageInheritsAutoFromSystemAppLaunch() = runBlocking {
        fakeFirewall.outboundDecision = FirewallDecision.Authorized
        fakeGateway.installedApps["com.unbound.app"] = "Unbound"

        fakeEvaluator.targetLevels[ToolTargetIds.APP_LAUNCH] = ConfirmationLevel.AUTO

        val args = mapOf(
            "app_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Unbound"))
        )

        val result = toolWithEvaluator.execute(testContext(), args)
        assertTrue(result is ToolResult.Success)
        assertEquals("com.unbound.app", fakeGateway.lastLaunchedPackage)
    }
}

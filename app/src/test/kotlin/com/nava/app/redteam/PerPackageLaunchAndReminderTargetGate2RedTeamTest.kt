package com.nava.app.redteam

import com.nava.app.di.AppContainer
import com.nava.app.di.NoOpTestAutomationIntentGateway
import com.nava.app.ui.hub.NavaHubViewModel
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleTriggerSpec
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolResult
import com.nava.feature.automations.applaunch.AppLaunchTool
import com.nava.feature.automations.common.AutomationIntentGateway
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.PlatformDispatchResult
import com.nava.feature.automations.common.ToolTargetIds
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files
import kotlin.coroutines.Continuation
import kotlin.coroutines.intrinsics.COROUTINE_SUSPENDED
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

/**
 * Gate 2 regression suite for the Gate 3 HIGH finding (#16): per-package `APP_LAUNCH`
 * enforcement in `AppLaunchTool` cannot be bypassed through the `package_name -> app_name`
 * fallback chain while `system.app_launch` is `AUTO`, and `NavaHubViewModel` target resolution
 * and reminder target routing stay aligned with the per-package / `nava.reminders` contracts.
 */
class PerPackageLaunchAndReminderTargetGate2RedTeamTest {

    private lateinit var tempVaultDir: File
    private lateinit var tempModelsDir: File
    private val nowMs: Long = 1_760_000_000_000L

    private val blockedPkg = "com.blocked.app"
    private val promptPkg = "com.prompt.app"
    private val openPkg = "com.open.app"

    @Before
    fun setUp() {
        tempVaultDir = Files.createTempDirectory("nava_pp_launch_vault").toFile()
        tempModelsDir = Files.createTempDirectory("nava_pp_launch_models").toFile()
    }

    @After
    fun tearDown() {
        tempVaultDir.deleteRecursively()
        tempModelsDir.deleteRecursively()
    }

    private class LabelGateway : AutomationIntentGateway by NoOpTestAutomationIntentGateway() {
        var dispatched: String? = null
        private val labels = mapOf(
            "blocked app" to "com.blocked.app",
            "prompt app" to "com.prompt.app",
            "open app" to "com.open.app"
        )
        private val packages = labels.values.toSet()

        override fun resolveLaunchablePackage(appNameOrPackage: String): String? {
            val trimmed = appNameOrPackage.trim()
            if (trimmed in packages) return trimmed
            return labels[trimmed.lowercase()]
        }

        override fun dispatchLaunchApp(packageName: String): PlatformDispatchResult {
            dispatched = packageName
            return PlatformDispatchResult.Dispatched("launch:$packageName")
        }
    }

    private suspend fun newContainer(gateway: AutomationIntentGateway): AppContainer {
        val container = AppContainer.createForTesting(
            vaultDir = tempVaultDir,
            modelsDir = tempModelsDir,
            intentGateway = gateway,
            clockMs = { nowMs },
            ioDispatcher = Dispatchers.Unconfined
        )
        // system.app_launch is AUTO for APP_LAUNCH.
        container.manageProfilesUseCase.assignTarget(
            ToolTargetIds.APP_LAUNCH, PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID, nowMs
        )
        // Explicit per-package bindings.
        container.manageProfilesUseCase.assignTarget(
            blockedPkg, PermissionProfile.DEFAULT_DENY_PROFILE_ID, nowMs
        )
        container.manageProfilesUseCase.assignTarget(
            promptPkg, PermissionProfile.SAFE_DRAFT_PROFILE_ID, nowMs
        )
        container.manageProfilesUseCase.assignTarget(
            openPkg, PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID, nowMs
        )
        return container
    }

    private fun interactiveContext(confirmed: Boolean = false): ToolExecutionContext {
        val token = CapabilityToken.mint(
            tokenId = "tok_pp_launch",
            requestId = "req_pp_launch",
            allowedTools = setOf(AutomationToolNames.LAUNCH_APP),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = nowMs - 100L
        )
        return ToolExecutionContext(
            requestId = "req_pp_launch",
            capabilityToken = token,
            ruleGrant = null,
            targetId = ToolTargetIds.APP_LAUNCH,
            languageTag = "en",
            issuedAtEpochMs = nowMs,
            isUserConfirmed = confirmed
        )
    }

    private fun unattendedContext(): ToolExecutionContext {
        val grant = RuleCapabilityGrant(
            grantId = "grant_pp_launch",
            ruleId = "rule_pp_launch",
            triggerSpec = RuleTriggerSpec("time", mapOf("hour" to "8", "minute" to "0")),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = AutomationToolNames.LAUNCH_APP,
                    requiredCapability = AtomicCapability.APP_LAUNCH
                )
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "sealed_pp_launch_hmac"
        )
        return ToolExecutionContext(
            requestId = "req_pp_launch_bg",
            capabilityToken = null,
            ruleGrant = grant,
            targetId = ToolTargetIds.APP_LAUNCH,
            languageTag = "en",
            issuedAtEpochMs = nowMs,
            isUnattendedBackground = true
        )
    }

    private fun args(packageName: String?, appName: String?): Map<String, Tainted<SlotValueAst>> {
        val map = LinkedHashMap<String, Tainted<SlotValueAst>>()
        if (packageName != null) {
            map["package_name"] = Tainted.fromUserUtterance(
                SlotValueAst.StringValue(packageName), SensitiveSlotKind.PACKAGE_NAME
            )
        }
        if (appName != null) {
            map["app_name"] = Tainted.fromUserUtterance(
                SlotValueAst.StringValue(appName), SensitiveSlotKind.TEXT_BODY
            )
        }
        return map
    }

    private fun toolFor(container: AppContainer, gateway: AutomationIntentGateway): AppLaunchTool {
        return AppLaunchTool(
            intentGateway = gateway,
            firewall = container.securityFirewall,
            auditLog = container.auditLogDao,
            clock = { nowMs },
            permissionEvaluator = container.permissionProfileManager
        )
    }

    // (a) Explicit DEFAULT_DENY per-package binding beats AUTO system.app_launch via fallback chain.
    @Test
    fun fallbackToExplicitlyBlockedPackage_isDeniedEvenWhenSystemAppLaunchIsAuto() = runTest {
        val gateway = LabelGateway()
        val container = newContainer(gateway)
        val tool = toolFor(container, gateway)

        val attempts = listOf(
            args(packageName = blockedPkg, appName = null),
            args(packageName = "nonexistent.pkg", appName = "Blocked App"),
            args(packageName = "   ", appName = "Blocked App"),
            args(packageName = null, appName = "Blocked App")
        )
        for (attempt in attempts) {
            val result = tool.execute(interactiveContext(confirmed = true), attempt)
            assertTrue("Expected Failure for $attempt but got $result", result is ToolResult.Failure)
            result as ToolResult.Failure
            assertEquals("PERMISSION_DENIED", result.errorCode)
            assertTrue(result.isSecurityViolation)
        }
        assertNull("Blocked package must never be dispatched", gateway.dispatched)

        // Control: unbound/explicitly AUTO package still launches through the AUTO system target.
        val ok = tool.execute(interactiveContext(), args(packageName = null, appName = "Open App"))
        assertTrue("Expected Success for explicitly trusted package, got $ok", ok is ToolResult.Success)
        assertEquals(openPkg, gateway.dispatched)
    }

    // (b) PROMPT_CARD package -> ConfirmationRequired; unattended routine rejected.
    @Test
    fun promptCardPackage_requiresConfirmationAndUnattendedRoutineIsRejected() = runTest {
        val gateway = LabelGateway()
        val container = newContainer(gateway)
        val tool = toolFor(container, gateway)

        val pending = tool.execute(
            interactiveContext(confirmed = false),
            args(packageName = "nonexistent.pkg", appName = "Prompt App")
        )
        assertTrue("Expected ConfirmationRequired, got $pending", pending is ToolResult.ConfirmationRequired)
        pending as ToolResult.ConfirmationRequired
        assertEquals(promptPkg, pending.targetId)
        assertNull("Must not dispatch before confirmation", gateway.dispatched)

        val unattended = tool.execute(
            unattendedContext(),
            args(packageName = promptPkg, appName = null)
        )
        assertTrue("Expected Failure for unattended routine, got $unattended", unattended is ToolResult.Failure)
        unattended as ToolResult.Failure
        assertEquals("UNATTENDED_EXECUTION_FORBIDDEN", unattended.errorCode)
        assertTrue(unattended.isSecurityViolation)

        val unattendedBlocked = tool.execute(
            unattendedContext(),
            args(packageName = null, appName = "Blocked App")
        )
        assertTrue(unattendedBlocked is ToolResult.Failure)
        assertEquals("PERMISSION_DENIED", (unattendedBlocked as ToolResult.Failure).errorCode)
        assertNull("Nothing may be dispatched unattended", gateway.dispatched)
    }

    @Suppress("UNCHECKED_CAST")
    private suspend fun resolveTarget(
        vm: NavaHubViewModel,
        toolName: String,
        rawArgs: Map<String, String>
    ): String {
        val method = NavaHubViewModel::class.java.declaredMethods.first {
            it.name == "resolveTargetIdForToolName"
        }
        method.isAccessible = true
        return suspendCoroutine { cont: Continuation<String> ->
            val r = method.invoke(vm, toolName, rawArgs, cont)
            if (r !== COROUTINE_SUSPENDED) cont.resume(r as String)
        }
    }

    // (c) + (d) NavaHubViewModel target resolution.
    @Test
    fun hubTargetResolution_usesPerPackageTargetAndRemindersTarget() = runTest {
        val gateway = LabelGateway()
        val container = newContainer(gateway)
        val vm = NavaHubViewModel(
            container = container,
            dispatcher = Dispatchers.Unconfined,
            clockMs = { nowMs }
        )

        assertEquals(
            blockedPkg,
            resolveTarget(
                vm, AutomationToolNames.LAUNCH_APP,
                mapOf("package_name" to "nonexistent.pkg", "app_name" to "Blocked App")
            )
        )
        assertEquals(
            blockedPkg,
            resolveTarget(vm, AutomationToolNames.LAUNCH_APP, mapOf("app_name" to "Blocked App"))
        )
        assertEquals(
            promptPkg,
            resolveTarget(
                vm, AutomationToolNames.LAUNCH_APP,
                mapOf("package_name" to "", "app_name" to "Prompt App")
            )
        )
        // Unbound / unresolvable targets fall back to the system target, never to a bound package.
        assertEquals(
            ToolTargetIds.APP_LAUNCH,
            resolveTarget(vm, AutomationToolNames.LAUNCH_APP, mapOf("app_name" to "Totally Unknown"))
        )

        assertEquals(
            ToolTargetIds.REMINDERS,
            resolveTarget(vm, AutomationToolNames.SCHEDULE_REMINDER, emptyMap())
        )
        assertEquals(
            ToolTargetIds.REMINDERS,
            resolveTarget(vm, AutomationToolNames.CANCEL_REMINDER, emptyMap())
        )
        assertEquals("nava.reminders", ToolTargetIds.REMINDERS)
    }
}

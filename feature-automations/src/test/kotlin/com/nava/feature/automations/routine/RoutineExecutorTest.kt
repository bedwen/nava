package com.nava.feature.automations.routine

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.automation.RoutineExecutionOutcome
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleGrantPort
import com.nava.domain.security.RuleTriggerSpec
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.security.Tainted
import com.nava.domain.tool.NavaTool
import com.nava.domain.tool.ToolCategory
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolRegistry
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.common.AutomationNotificationBridge
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.CompletionNotificationRequest
import com.nava.feature.automations.common.ForegroundNotificationSpec
import com.nava.feature.automations.common.InteractiveNotificationRequest
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class RoutineExecutorTest {

    private lateinit var fakeRuleGrantPort: FakeRuleGrantPort
    private lateinit var fakeFirewall: FakeSecurityFirewall
    private lateinit var toolRegistry: ToolRegistry
    private lateinit var fakeAuditLog: FakeAuditLog
    private lateinit var fakeNotificationBridge: FakeNotificationBridge
    private lateinit var fakeScheduler: FakeRoutineScheduler
    private lateinit var routineExecutor: RoutineExecutor

    @Before
    fun setUp() {
        fakeRuleGrantPort = FakeRuleGrantPort()
        fakeFirewall = FakeSecurityFirewall()
        toolRegistry = ToolRegistry()
        fakeAuditLog = FakeAuditLog()
        fakeNotificationBridge = FakeNotificationBridge()
        fakeScheduler = FakeRoutineScheduler()

        // Register a safe unattended tool (set_alarm)
        toolRegistry.register(
            FakeTool(
                name = "set_alarm",
                requiredCapability = AtomicCapability.CREATE_DRAFT,
                supportsUnattendedRule = true
            )
        )

        // Register a sensitive tool (create_sms_draft) requiring interactive confirmation for MODIFY_DELETE_SEND
        toolRegistry.register(
            FakeTool(
                name = "delete_calendar_event",
                requiredCapability = AtomicCapability.MODIFY_DELETE_SEND,
                supportsUnattendedRule = false
            )
        )

        routineExecutor = RoutineExecutor(
            ruleGrantPort = fakeRuleGrantPort,
            securityFirewall = fakeFirewall,
            toolRegistry = toolRegistry,
            auditLog = fakeAuditLog,
            notificationBridge = fakeNotificationBridge,
            scheduler = fakeScheduler
        )
    }

    @Test
    fun globalPauseBlocksRoutineExecutionAndAudits() = runBlocking {
        routineExecutor.setGloballyPaused(true)

        val outcome = routineExecutor.executeRule("rule_1", 1000L)
        assertTrue(outcome is RoutineExecutionOutcome.Denied)
        val denied = outcome as RoutineExecutionOutcome.Denied
        assertEquals(RoutineExecutor.REASON_ROUTINES_GLOBALLY_PAUSED, denied.reasonCode)
        assertEquals(MessageKey.ROUTINE_EXECUTION_DENIED, denied.message.key)

        assertEquals(1, fakeAuditLog.entries.size)
        assertEquals(RoutineExecutor.REASON_ROUTINES_GLOBALLY_PAUSED, fakeAuditLog.entries.first().decision)
    }

    @Test
    fun missingRuleFailsGracefully() = runBlocking {
        val outcome = routineExecutor.executeRule("non_existent_rule", 1000L)
        assertTrue(outcome is RoutineExecutionOutcome.Failed)
        val failed = outcome as RoutineExecutionOutcome.Failed
        assertEquals("RULE_NOT_FOUND", failed.errorCode)
        assertEquals(MessageKey.ROUTINE_EXECUTION_FAILED, failed.message.key)
    }

    @Test
    fun nonActiveRuleApprovalStateIsDenied() = runBlocking {
        val grant = RuleCapabilityGrant(
            grantId = "grant_paused",
            ruleId = "rule_paused",
            triggerSpec = RuleTriggerSpec("interval"),
            staticActions = listOf(
                RuleActionSpec("set_alarm", AtomicCapability.CREATE_DRAFT)
            ),
            approvalState = RuleApprovalState.PAUSED,
            sealHmacHex = "valid_seal"
        )
        fakeRuleGrantPort.putRule(grant)

        val outcome = routineExecutor.executeRule("rule_paused", 1000L)
        assertTrue(outcome is RoutineExecutionOutcome.Denied)
        val denied = outcome as RoutineExecutionOutcome.Denied
        assertEquals("RULE_NOT_ACTIVE", denied.reasonCode)
    }

    @Test
    fun firewallDeniedDecisionStopsExecutionAndAudits() = runBlocking {
        val grant = RuleCapabilityGrant(
            grantId = "grant_fw_denied",
            ruleId = "rule_fw_denied",
            triggerSpec = RuleTriggerSpec("interval"),
            staticActions = listOf(
                RuleActionSpec("set_alarm", AtomicCapability.CREATE_DRAFT)
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "valid_seal"
        )
        fakeRuleGrantPort.putRule(grant)
        fakeFirewall.decision = FirewallDecision.Denied(
            message = UserMessage(MessageKey.ERROR_SECURITY_VIOLATION),
            reasonCode = "HMAC_SEAL_MISMATCH"
        )

        val outcome = routineExecutor.executeRule("rule_fw_denied", 1000L)
        assertTrue(outcome is RoutineExecutionOutcome.Denied)
        val denied = outcome as RoutineExecutionOutcome.Denied
        assertEquals("HMAC_SEAL_MISMATCH", denied.reasonCode)
        assertEquals("DENIED", fakeAuditLog.entries.first().decision)
    }

    @Test
    fun biometricActionEscalatesToInteractiveConfirmationNotification() = runBlocking {
        val grant = RuleCapabilityGrant(
            grantId = "grant_bio",
            ruleId = "rule_bio",
            triggerSpec = RuleTriggerSpec("interval"),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = "set_alarm",
                    requiredCapability = AtomicCapability.CREATE_DRAFT,
                    requiresBiometric = true
                )
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "valid_seal"
        )
        fakeRuleGrantPort.putRule(grant)

        val outcome = routineExecutor.executeRule("rule_bio", 1000L)
        assertTrue(outcome is RoutineExecutionOutcome.EscalatedToInteractive)
        val escalated = outcome as RoutineExecutionOutcome.EscalatedToInteractive
        assertTrue("Must require biometric verification", escalated.requiresBiometric)
        assertEquals(listOf("set_alarm"), escalated.pendingToolNames)
        assertEquals(MessageKey.ROUTINE_ESCALATED_BIOMETRIC, escalated.message.key)

        // High priority interactive notification must have been posted
        assertEquals(1, fakeNotificationBridge.interactiveRequests.size)
        val request = fakeNotificationBridge.interactiveRequests.first()
        assertTrue(request.requiresBiometric)
        assertEquals("rule_bio", request.ruleId)
        assertEquals(0, fakeNotificationBridge.completionRequests.size)
    }

    @Test
    fun modifyDeleteSendActionEscalatesToInteractiveConfirmationNotification() = runBlocking {
        val grant = RuleCapabilityGrant(
            grantId = "grant_delete",
            ruleId = "rule_delete",
            triggerSpec = RuleTriggerSpec("interval"),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = "delete_calendar_event",
                    requiredCapability = AtomicCapability.MODIFY_DELETE_SEND
                )
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "valid_seal"
        )
        fakeRuleGrantPort.putRule(grant)

        val outcome = routineExecutor.executeRule("rule_delete", 1000L)
        assertTrue(outcome is RoutineExecutionOutcome.EscalatedToInteractive)
        val escalated = outcome as RoutineExecutionOutcome.EscalatedToInteractive
        assertFalse(escalated.requiresBiometric)
        assertEquals(listOf("delete_calendar_event"), escalated.pendingToolNames)

        assertEquals(1, fakeNotificationBridge.interactiveRequests.size)
        assertEquals(0, fakeNotificationBridge.completionRequests.size)
    }

    @Test
    fun safeUnattendedActionExecutesSuccessfullyAndPostsCompletionNotification() = runBlocking {
        val grant = RuleCapabilityGrant(
            grantId = "grant_safe",
            ruleId = "rule_safe",
            triggerSpec = RuleTriggerSpec("charging", mapOf("requires_charging" to "true")),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = "set_alarm",
                    requiredCapability = AtomicCapability.CREATE_DRAFT,
                    staticArguments = mapOf("time" to "07:00")
                )
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "valid_seal"
        )
        fakeRuleGrantPort.putRule(grant)

        val outcome = routineExecutor.executeRule("rule_safe", 1000L)
        assertTrue(outcome is RoutineExecutionOutcome.Executed)
        val executed = outcome as RoutineExecutionOutcome.Executed
        assertEquals(1, executed.stepResults.size)
        assertEquals(MessageKey.ROUTINE_EXECUTED, executed.message.key)

        // Completion notification posted
        assertEquals(1, fakeNotificationBridge.completionRequests.size)
        val completion = fakeNotificationBridge.completionRequests.first()
        assertEquals("rule_safe", completion.ruleId)
        assertEquals(MessageKey.ROUTINE_EXECUTED, completion.message.key)
        assertEquals(0, fakeNotificationBridge.interactiveRequests.size)
    }

    @Test
    fun schedulingAndCancellingDelegatesToWorkScheduler() = runBlocking {
        val grant = RuleCapabilityGrant(
            grantId = "grant_s",
            ruleId = "rule_s",
            triggerSpec = RuleTriggerSpec("interval"),
            staticActions = listOf(RuleActionSpec("set_alarm", AtomicCapability.CREATE_DRAFT)),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "seal"
        )

        routineExecutor.scheduleRule(grant)
        assertEquals(1, fakeScheduler.scheduledRules.size)
        assertEquals("rule_s", fakeScheduler.scheduledRules.first().ruleId)

        routineExecutor.cancelRule("rule_s")
        assertEquals(listOf("rule_s"), fakeScheduler.cancelledRules)

        routineExecutor.cancelAllRules()
        assertTrue(fakeScheduler.cancelledAll)
    }

    @Test
    fun missingToolInRegistryCausesRoutineFailure() = runBlocking {
        val grant = RuleCapabilityGrant(
            grantId = "grant_missing_tool",
            ruleId = "rule_missing_tool",
            triggerSpec = RuleTriggerSpec("interval"),
            staticActions = listOf(
                RuleActionSpec("non_existent_tool_xyz", AtomicCapability.DATA_READ)
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "valid_seal"
        )
        fakeRuleGrantPort.putRule(grant)

        val outcome = routineExecutor.executeRule("rule_missing_tool", 1000L)
        assertTrue(outcome is RoutineExecutionOutcome.Failed)
        val failed = outcome as RoutineExecutionOutcome.Failed
        assertEquals("TOOL_NOT_FOUND", failed.errorCode)
        assertEquals("TOOL_NOT_FOUND", fakeAuditLog.entries.first().decision)
    }

    @Test
    fun toolNotSupportingUnattendedExecutionEscalatesToInteractive() = runBlocking {
        toolRegistry.register(
            FakeTool(
                name = "interactive_only_tool",
                requiredCapability = AtomicCapability.DATA_READ,
                supportsUnattendedRule = false
            )
        )

        val grant = RuleCapabilityGrant(
            grantId = "grant_not_unattended",
            ruleId = "rule_not_unattended",
            triggerSpec = RuleTriggerSpec("interval"),
            staticActions = listOf(
                RuleActionSpec("interactive_only_tool", AtomicCapability.DATA_READ)
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "valid_seal"
        )
        fakeRuleGrantPort.putRule(grant)

        val outcome = routineExecutor.executeRule("rule_not_unattended", 1000L)
        assertTrue(outcome is RoutineExecutionOutcome.EscalatedToInteractive)
        val escalated = outcome as RoutineExecutionOutcome.EscalatedToInteractive
        assertEquals(listOf("interactive_only_tool"), escalated.pendingToolNames)
        assertEquals(1, fakeNotificationBridge.interactiveRequests.size)
    }

    @Test
    fun vaultToolEscalatesWithBiometricEvenWhenRuleSpecClaimsFalse() = runBlocking {
        toolRegistry.register(
            FakeTool(
                name = AutomationToolNames.VAULT_READ,
                requiredCapability = AtomicCapability.DATA_READ,
                supportsUnattendedRule = false
            )
        )

        val grant = RuleCapabilityGrant(
            grantId = "grant_vault_spoof",
            ruleId = "rule_vault_spoof",
            triggerSpec = RuleTriggerSpec("interval"),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = AutomationToolNames.VAULT_READ,
                    requiredCapability = AtomicCapability.DATA_READ,
                    requiresBiometric = false
                )
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "valid_seal"
        )
        fakeRuleGrantPort.putRule(grant)

        val outcome = routineExecutor.executeRule("rule_vault_spoof", 1000L)
        assertTrue(outcome is RoutineExecutionOutcome.EscalatedToInteractive)
        val escalated = outcome as RoutineExecutionOutcome.EscalatedToInteractive
        assertTrue("Must preserve requiresBiometric=true for vault tool", escalated.requiresBiometric)
        assertEquals(MessageKey.ROUTINE_ESCALATED_BIOMETRIC, escalated.message.key)
        assertEquals(1, fakeNotificationBridge.interactiveRequests.size)
        assertTrue(fakeNotificationBridge.interactiveRequests.first().requiresBiometric)
    }

    @Test
    fun capabilityMismatchRejectsAsDeniedWithAuditLog() = runBlocking {
        toolRegistry.register(
            FakeTool(
                name = AutomationToolNames.LAUNCH_APP,
                requiredCapability = AtomicCapability.APP_LAUNCH,
                supportsUnattendedRule = true
            )
        )

        val grant = RuleCapabilityGrant(
            grantId = "grant_mismatch",
            ruleId = "rule_mismatch",
            triggerSpec = RuleTriggerSpec("interval"),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = AutomationToolNames.LAUNCH_APP,
                    requiredCapability = AtomicCapability.DATA_READ,
                    requiresBiometric = false
                )
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "valid_seal"
        )
        fakeRuleGrantPort.putRule(grant)

        val outcome = routineExecutor.executeRule("rule_mismatch", 1000L)
        assertTrue(outcome is RoutineExecutionOutcome.Denied)
        val denied = outcome as RoutineExecutionOutcome.Denied
        assertEquals("CAPABILITY_MISMATCH", denied.reasonCode)
        assertTrue(fakeAuditLog.entries.any { it.decision == "DENIED" && it.actionSummary.contains("capability mismatch", ignoreCase = true) })
    }

    @Test
    fun automationWorkerRegistryLifecycleAndRequests() {
        AutomationWorkerRegistry.unbind()
        assertNull(AutomationWorkerRegistry.getRoutineExecutor())
        assertNull(AutomationWorkerRegistry.getBackgroundTaskManager())
        assertNull(AutomationWorkerRegistry.getNotificationBridge())

        AutomationWorkerRegistry.bind(routineExecutor, FakeBackgroundTaskManager(), fakeNotificationBridge)
        assertEquals(routineExecutor, AutomationWorkerRegistry.getRoutineExecutor())
        assertEquals(fakeNotificationBridge, AutomationWorkerRegistry.getNotificationBridge())

        AutomationWorkerRegistry.unbind()
        assertNull(AutomationWorkerRegistry.getRoutineExecutor())
    }
}

class FakeRuleGrantPort : RuleGrantPort {
    private val rules = mutableMapOf<String, RuleCapabilityGrant>()

    fun putRule(grant: RuleCapabilityGrant) {
        rules[grant.ruleId] = grant
    }

    override suspend fun findRule(ruleId: String): RuleCapabilityGrant? = rules[ruleId]
    override suspend fun listRules(): List<RuleCapabilityGrant> = rules.values.toList()

    override suspend fun createPendingRule(
        ruleId: String,
        triggerSpec: RuleTriggerSpec,
        staticActions: List<RuleActionSpec>,
        nowEpochSec: Long
    ): RuleCapabilityGrant {
        val grant = RuleCapabilityGrant(
            grantId = "grant:$ruleId",
            ruleId = ruleId,
            triggerSpec = triggerSpec,
            staticActions = staticActions,
            approvalState = RuleApprovalState.PENDING_USER_APPROVAL
        )
        rules[ruleId] = grant
        return grant
    }

    override suspend fun approveAndSealRule(ruleId: String, nowEpochSec: Long): RuleCapabilityGrant {
        val existing = rules[ruleId] ?: error("Rule not found")
        val sealed = existing.copy(
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "validhmac"
        )
        rules[ruleId] = sealed
        return sealed
    }

    override suspend fun pauseRule(ruleId: String, nowEpochSec: Long) {
        rules[ruleId]?.let { rules[ruleId] = it.copy(approvalState = RuleApprovalState.PAUSED) }
    }

    override suspend fun revokeRule(ruleId: String, nowEpochSec: Long) {
        rules[ruleId]?.let { rules[ruleId] = it.copy(approvalState = RuleApprovalState.REVOKED) }
    }
}

class FakeSecurityFirewall : SecurityFirewallPort {
    var decision: FirewallDecision = FirewallDecision.Authorized

    override suspend fun authorizeRuleExecution(grant: RuleCapabilityGrant): FirewallDecision {
        return decision
    }

    override suspend fun mintToken(
        requestId: String,
        utteranceProvenance: DataProvenance,
        candidateTools: Set<String>,
        nowEpochMs: Long
    ): CapabilityToken {
        return CapabilityToken.mint(
            tokenId = "token",
            requestId = requestId,
            allowedTools = candidateTools,
            mintProvenance = utteranceProvenance,
            issuedAtEpochMs = nowEpochMs,
            expiresAtEpochMs = nowEpochMs + 60_000L,
            maxToolCalls = 5
        )
    }

    override suspend fun authorizeToolCall(
        token: CapabilityToken,
        toolCall: ToolCallAst,
        toolMetadata: ToolMetadata,
        targetId: String,
        nowEpochMs: Long
    ): FirewallDecision = decision

    override suspend fun validateOutboundTarget(
        toolName: String,
        action: String,
        uriOrTarget: Tainted<String>
    ): FirewallDecision = decision
}

class FakeRoutineScheduler : RoutineWorkScheduler {
    val scheduledRules = mutableListOf<RuleCapabilityGrant>()
    val cancelledRules = mutableListOf<String>()
    var cancelledAll: Boolean = false

    override suspend fun schedule(grant: RuleCapabilityGrant) {
        scheduledRules.add(grant)
    }

    override suspend fun cancel(ruleId: String) {
        cancelledRules.add(ruleId)
    }

    override suspend fun cancelAll() {
        cancelledAll = true
    }
}

class FakeNotificationBridge : AutomationNotificationBridge {
    val completionRequests = mutableListOf<CompletionNotificationRequest>()
    val interactiveRequests = mutableListOf<InteractiveNotificationRequest>()
    val cancelledIds = mutableListOf<Int>()

    override fun postCompletionNotification(request: CompletionNotificationRequest) {
        completionRequests.add(request)
    }

    override fun postInteractiveConfirmationNotification(request: InteractiveNotificationRequest) {
        interactiveRequests.add(request)
    }

    override fun cancelNotification(notificationId: Int) {
        cancelledIds.add(notificationId)
    }

    override fun createForegroundNotificationSpec(
        taskId: String,
        message: UserMessage
    ): ForegroundNotificationSpec {
        return ForegroundNotificationSpec(1, "channel", taskId, message)
    }
}

class FakeTool(
    name: String,
    requiredCapability: AtomicCapability,
    supportsUnattendedRule: Boolean
) : NavaTool {
    override val metadata: ToolMetadata = ToolMetadata(
        name = name,
        displayNameKey = "display_$name",
        description = "Description for $name",
        category = ToolCategory.DEVICE_SETTINGS,
        requiredCapability = requiredCapability,
        supportsUnattendedRule = supportsUnattendedRule
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        return ToolResult.Success(
            message = UserMessage(MessageKey.ROUTINE_EXECUTED),
            outputValues = mapOf("status" to "ok")
        )
    }
}

class FakeBackgroundTaskManager : com.nava.domain.automation.BackgroundTaskContinuationPort {
    override suspend fun enqueue(request: com.nava.domain.automation.BackgroundTaskRequest): String = request.taskId
    override suspend fun executeNow(
        request: com.nava.domain.automation.BackgroundTaskRequest,
        nowEpochMs: Long
    ): com.nava.domain.automation.BackgroundTaskOutcome {
        return com.nava.domain.automation.BackgroundTaskOutcome.Completed(
            taskId = request.taskId,
            message = UserMessage(MessageKey.BACKGROUND_TASK_COMPLETED)
        )
    }
    override suspend fun getStatus(taskId: String): com.nava.domain.automation.BackgroundTaskStatus? = null
    override suspend fun getOutcome(taskId: String): com.nava.domain.automation.BackgroundTaskOutcome? = null
    override suspend fun cancel(taskId: String) {}
}

class FakeAuditLog : AuditLogPort {
    val entries = mutableListOf<AuditLogEntry>()

    override suspend fun record(entry: AuditLogEntry) {
        entries.add(entry)
    }

    override suspend fun queryRecent(limit: Int): List<AuditLogEntry> = entries.takeLast(limit)
}

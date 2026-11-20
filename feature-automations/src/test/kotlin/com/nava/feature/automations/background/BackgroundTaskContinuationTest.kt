package com.nava.feature.automations.background

import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.automation.BackgroundTaskOutcome
import com.nava.domain.automation.BackgroundTaskRequest
import com.nava.domain.automation.BackgroundTaskStatus
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.NavaTool
import com.nava.domain.tool.ToolCategory
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolRegistry
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.domain.usecase.ExecutePlanUseCase
import com.nava.feature.automations.common.AutomationNotificationBridge
import com.nava.feature.automations.common.CompletionNotificationRequest
import com.nava.feature.automations.common.ForegroundNotificationSpec
import com.nava.feature.automations.common.InteractiveNotificationRequest
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class BackgroundTaskContinuationTest {

    private lateinit var toolRegistry: ToolRegistry
    private lateinit var fakeFirewall: FakeSecurityFirewall
    private lateinit var fakeAuditLog: FakeAuditLog
    private lateinit var fakeNotificationBridge: FakeNotificationBridge
    private lateinit var fakeScheduler: FakeBackgroundTaskScheduler
    private lateinit var executePlanUseCase: ExecutePlanUseCase
    private lateinit var manager: BackgroundTaskContinuationManager

    @Before
    fun setUp() {
        toolRegistry = ToolRegistry()
        fakeFirewall = FakeSecurityFirewall()
        fakeAuditLog = FakeAuditLog()
        fakeNotificationBridge = FakeNotificationBridge()
        fakeScheduler = FakeBackgroundTaskScheduler()

        executePlanUseCase = ExecutePlanUseCase(
            toolRegistry = toolRegistry,
            securityFirewall = fakeFirewall,
            auditLog = fakeAuditLog
        )

        manager = BackgroundTaskContinuationManager(
            executePlanUseCase = executePlanUseCase,
            auditLog = fakeAuditLog,
            notificationBridge = fakeNotificationBridge,
            scheduler = fakeScheduler,
            modelImportHandler = { req -> req.expectedSha256Hex == "valid_sha256" }
        )
    }

    @Test
    fun planContinuationCompletesSafelyAndPostsCompletionNotification() = runBlocking {
        toolRegistry.register(
            FakePlanTool(
                name = "test_safe_action",
                result = ToolResult.Success(
                    message = UserMessage(MessageKey.ACTION_NOTE_SAVED),
                    outputValues = mapOf("note_id" to "123")
                )
            )
        )

        val plan = PlanAst(
            planId = "plan_1",
            calls = listOf(
                ToolCallAst(
                    toolName = "test_safe_action",
                    arguments = emptyMap(),
                    orderIndex = 0
                )
            )
        )
        val token = CapabilityToken.mint(
            tokenId = "tok_1",
            requestId = "req_1",
            mintProvenance = DataProvenance.USER_UTTERANCE,
            allowedTools = setOf("test_safe_action"),
            issuedAtEpochMs = 1000L,
            expiresAtEpochMs = 60_000L,
            maxToolCalls = 5
        )

        val request = BackgroundTaskRequest.PlanContinuation(
            taskId = "task_plan_1",
            plan = plan,
            capabilityToken = token,
            targetId = "nava.notes",
            languageTag = "en",
            enqueuedAtEpochMs = 1000L
        )

        val enqueuedId = manager.enqueue(request)
        assertEquals("task_plan_1", enqueuedId)
        assertEquals(BackgroundTaskStatus.ENQUEUED, manager.getStatus("task_plan_1"))

        val outcome = manager.executeNow(request, 2000L)
        assertTrue(outcome is BackgroundTaskOutcome.Completed)
        val completed = outcome as BackgroundTaskOutcome.Completed
        assertEquals("task_plan_1", completed.taskId)
        assertEquals(1, completed.toolResults.size)
        assertEquals("123", completed.outputValues["note_id"])
        assertEquals(BackgroundTaskStatus.COMPLETED, manager.getStatus("task_plan_1"))

        // Completion notification posted
        assertEquals(1, fakeNotificationBridge.completionRequests.size)
        val notif = fakeNotificationBridge.completionRequests.first()
        assertEquals("task_plan_1", notif.taskId)
        assertEquals(MessageKey.BACKGROUND_TASK_COMPLETED, notif.message.key)
        assertEquals(0, fakeNotificationBridge.interactiveRequests.size)
    }

    @Test
    fun planContinuationPausesOnConfirmationRequiredAndPostsInteractiveNotification() = runBlocking {
        toolRegistry.register(
            FakePlanTool(
                name = "test_interactive_action",
                result = ToolResult.ConfirmationRequired(
                    message = UserMessage(MessageKey.ACTION_CONFIRMATION_REQUIRED),
                    pendingToolName = "test_interactive_action",
                    targetId = "system.sms",
                    canonicalArguments = mapOf(
                        "body" to Tainted.fromUntrustedExternal("Draft body", SensitiveSlotKind.TEXT_BODY)
                    ),
                    requiresBiometric = false,
                    hasUntrustedHighRiskSlot = true,
                    pendingOrderIndex = 0
                )
            )
        )

        val plan = PlanAst(
            planId = "plan_2",
            calls = listOf(
                ToolCallAst(
                    toolName = "test_interactive_action",
                    arguments = emptyMap(),
                    orderIndex = 0
                )
            )
        )
        val token = CapabilityToken.mint(
            tokenId = "tok_2",
            requestId = "req_2",
            mintProvenance = DataProvenance.USER_UTTERANCE,
            allowedTools = setOf("test_interactive_action"),
            issuedAtEpochMs = 1000L,
            expiresAtEpochMs = 60_000L,
            maxToolCalls = 5
        )

        val request = BackgroundTaskRequest.PlanContinuation(
            taskId = "task_plan_confirm",
            plan = plan,
            capabilityToken = token,
            targetId = "system.sms",
            languageTag = "en",
            enqueuedAtEpochMs = 1000L
        )

        val outcome = manager.executeNow(request, 2000L)
        assertTrue(outcome is BackgroundTaskOutcome.ConfirmationRequired)
        val confRequired = outcome as BackgroundTaskOutcome.ConfirmationRequired
        assertEquals("task_plan_confirm", confRequired.taskId)
        assertEquals(BackgroundTaskStatus.AWAITING_CONFIRMATION, manager.getStatus("task_plan_confirm"))

        // High priority interactive notification posted
        assertEquals(1, fakeNotificationBridge.interactiveRequests.size)
        val notif = fakeNotificationBridge.interactiveRequests.first()
        assertEquals("task_plan_confirm", notif.taskId)
        assertEquals(listOf("test_interactive_action"), notif.pendingToolNames)
        assertEquals(0, fakeNotificationBridge.completionRequests.size)
    }

    @Test
    fun modelImportContinuationCompletesWhenVerified() = runBlocking {
        val request = BackgroundTaskRequest.ModelImportContinuation(
            taskId = "task_model_1",
            sourceUri = "content://saf/model.litertlm",
            expectedModelId = "gemma-4-e2b",
            expectedSha256Hex = "valid_sha256",
            languageTag = "en",
            enqueuedAtEpochMs = 1000L
        )

        val outcome = manager.executeNow(request, 2000L)
        assertTrue(outcome is BackgroundTaskOutcome.Completed)
        assertEquals(BackgroundTaskStatus.COMPLETED, manager.getStatus("task_model_1"))
        assertEquals(1, fakeNotificationBridge.completionRequests.size)
    }

    @Test
    fun modelImportContinuationFailsWhenVerificationFails() = runBlocking {
        val request = BackgroundTaskRequest.ModelImportContinuation(
            taskId = "task_model_bad",
            sourceUri = "content://saf/model.litertlm",
            expectedModelId = "gemma-4-e2b",
            expectedSha256Hex = "corrupted_sha",
            languageTag = "en",
            enqueuedAtEpochMs = 1000L
        )

        val outcome = manager.executeNow(request, 2000L)
        assertTrue(outcome is BackgroundTaskOutcome.Failed)
        assertEquals(BackgroundTaskStatus.FAILED, manager.getStatus("task_model_bad"))
        assertEquals(0, fakeNotificationBridge.completionRequests.size)
    }

    @Test
    fun cancellationUpdatesStatusAndOutcome() = runBlocking {
        val plan = PlanAst(
            planId = "plan_cancel",
            calls = listOf(
                ToolCallAst(
                    toolName = "any_tool",
                    arguments = emptyMap(),
                    orderIndex = 0
                )
            )
        )
        val token = CapabilityToken.mint(
            tokenId = "tok_cancel",
            requestId = "req_cancel",
            mintProvenance = DataProvenance.USER_UTTERANCE,
            allowedTools = setOf("any_tool"),
            issuedAtEpochMs = 1000L,
            expiresAtEpochMs = 60_000L,
            maxToolCalls = 5
        )
        val request = BackgroundTaskRequest.PlanContinuation(
            taskId = "task_to_cancel",
            plan = plan,
            capabilityToken = token,
            targetId = "nava.notes",
            languageTag = "en",
            enqueuedAtEpochMs = 1000L
        )

        manager.enqueue(request)
        assertEquals(BackgroundTaskStatus.ENQUEUED, manager.getStatus("task_to_cancel"))

        manager.cancel("task_to_cancel")
        assertEquals(BackgroundTaskStatus.CANCELLED, manager.getStatus("task_to_cancel"))
        val outcome = manager.getOutcome("task_to_cancel")
        assertTrue(outcome is BackgroundTaskOutcome.Cancelled)
        assertEquals(listOf("task_to_cancel"), fakeScheduler.cancelledTasks)
    }

    @Test
    fun planContinuationFailsWhenToolFails() = runBlocking {
        toolRegistry.register(
            FakePlanTool(
                name = "test_failing_action",
                result = ToolResult.Failure(
                    message = UserMessage(MessageKey.ERROR_SECURITY_VIOLATION),
                    errorCode = "EXECUTION_ERROR"
                )
            )
        )

        val plan = PlanAst(
            planId = "plan_fail",
            calls = listOf(
                ToolCallAst(
                    toolName = "test_failing_action",
                    arguments = emptyMap(),
                    orderIndex = 0
                )
            )
        )
        val token = CapabilityToken.mint(
            tokenId = "tok_fail",
            requestId = "req_fail",
            mintProvenance = DataProvenance.USER_UTTERANCE,
            allowedTools = setOf("test_failing_action"),
            issuedAtEpochMs = 1000L,
            expiresAtEpochMs = 60_000L,
            maxToolCalls = 5
        )
        val request = BackgroundTaskRequest.PlanContinuation(
            taskId = "task_plan_fail",
            plan = plan,
            capabilityToken = token,
            targetId = "nava.notes",
            languageTag = "en",
            enqueuedAtEpochMs = 1000L
        )

        val outcome = manager.executeNow(request, 2000L)
        assertTrue(outcome is BackgroundTaskOutcome.Failed)
        val failed = outcome as BackgroundTaskOutcome.Failed
        assertEquals("EXECUTION_ERROR", failed.errorCode)
        assertEquals(BackgroundTaskStatus.FAILED, manager.getStatus("task_plan_fail"))
    }

    @Test
    fun modelImportContinuationFailsWhenProvisionerUnavailable() = runBlocking {
        val managerWithoutHandler = BackgroundTaskContinuationManager(
            executePlanUseCase = executePlanUseCase,
            auditLog = fakeAuditLog,
            notificationBridge = fakeNotificationBridge,
            scheduler = fakeScheduler,
            modelProvisioner = null,
            modelImportHandler = null
        )

        val request = BackgroundTaskRequest.ModelImportContinuation(
            taskId = "task_no_prov",
            sourceUri = "content://saf/model.litertlm",
            expectedModelId = "gemma-4-e2b",
            expectedSha256Hex = "valid_sha256",
            languageTag = "en",
            enqueuedAtEpochMs = 1000L
        )

        val outcome = managerWithoutHandler.executeNow(request, 2000L)
        assertTrue(outcome is BackgroundTaskOutcome.Failed)
        val failed = outcome as BackgroundTaskOutcome.Failed
        assertEquals("PROVISIONER_UNAVAILABLE", failed.errorCode)
    }
}

class FakeBackgroundTaskScheduler : BackgroundTaskWorkScheduler {
    val scheduledTasks = mutableListOf<BackgroundTaskRequest>()
    val cancelledTasks = mutableListOf<String>()

    override suspend fun schedule(request: BackgroundTaskRequest) {
        scheduledTasks.add(request)
    }

    override suspend fun cancel(taskId: String) {
        cancelledTasks.add(taskId)
    }
}

class FakePlanTool(
    name: String,
    private val result: ToolResult
) : NavaTool {
    override val metadata: ToolMetadata = ToolMetadata(
        name = name,
        displayNameKey = "display_$name",
        description = "Description for $name",
        category = ToolCategory.NOTES_FILES,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        supportsUnattendedRule = true
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult = result
}

class FakeSecurityFirewall : SecurityFirewallPort {
    override suspend fun authorizeRuleExecution(grant: com.nava.domain.security.RuleCapabilityGrant): FirewallDecision {
        return FirewallDecision.Authorized
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
    ): FirewallDecision = FirewallDecision.Authorized

    override suspend fun validateOutboundTarget(
        toolName: String,
        action: String,
        uriOrTarget: Tainted<String>
    ): FirewallDecision = FirewallDecision.Authorized
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

class FakeAuditLog : AuditLogPort {
    val entries = mutableListOf<AuditLogEntry>()

    override suspend fun record(entry: AuditLogEntry) {
        entries.add(entry)
    }

    override suspend fun queryRecent(limit: Int): List<AuditLogEntry> = entries.takeLast(limit)
}

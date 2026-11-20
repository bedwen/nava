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
import com.nava.feature.automations.routine.AutomationWorkerRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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
        assertNull(AutomationWorkerRegistry.getRequest("task_to_cancel"))

        // Late execution attempt must return Cancelled without running or notifying
        val lateOutcome = manager.executeNow(request, 2000L)
        assertTrue(lateOutcome is BackgroundTaskOutcome.Cancelled)
        assertEquals(0, fakeNotificationBridge.completionRequests.size)
        assertEquals(0, fakeNotificationBridge.interactiveRequests.size)
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
            sourceUri = "/data/local/models/model.litertlm",
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

    @Test
    fun modelImportContinuationFailsWhenContentUriLacksImportHandler() = runBlocking {
        val managerWithoutHandler = BackgroundTaskContinuationManager(
            executePlanUseCase = executePlanUseCase,
            auditLog = fakeAuditLog,
            notificationBridge = fakeNotificationBridge,
            scheduler = fakeScheduler,
            modelProvisioner = null,
            modelImportHandler = null
        )

        val request = BackgroundTaskRequest.ModelImportContinuation(
            taskId = "task_content_no_handler",
            sourceUri = "content://saf/model.litertlm",
            expectedModelId = "gemma-4-e2b",
            expectedSha256Hex = "valid_sha256",
            languageTag = "en",
            enqueuedAtEpochMs = 1000L
        )

        val outcome = managerWithoutHandler.executeNow(request, 2000L)
        assertTrue(outcome is BackgroundTaskOutcome.Failed)
        val failed = outcome as BackgroundTaskOutcome.Failed
        assertEquals("MODEL_IMPORT_HANDLER_MISSING", failed.errorCode)
        assertEquals(BackgroundTaskStatus.FAILED, managerWithoutHandler.getStatus("task_content_no_handler"))
        assertEquals(1, fakeAuditLog.entries.size)
        assertEquals("MODEL_IMPORT_HANDLER_MISSING", fakeAuditLog.entries.first().decision)
        assertNull(AutomationWorkerRegistry.getRequest("task_content_no_handler"))
    }

    @Test(expected = kotlinx.coroutines.CancellationException::class)
    fun planContinuationPropagatesCancellationException() {
        runBlocking {
            toolRegistry.register(
                FakePlanTool(
                    name = "throwing_tool",
                    exceptionToThrow = kotlinx.coroutines.CancellationException("Worker cancelled")
                )
            )
            val plan = PlanAst(
                planId = "plan_cancel_prop",
                calls = listOf(ToolCallAst("throwing_tool", emptyMap(), 0))
            )
            val token = CapabilityToken.mint(
                tokenId = "tok_prop",
                requestId = "req_prop",
                allowedTools = setOf("throwing_tool"),
                mintProvenance = DataProvenance.USER_UTTERANCE,
                issuedAtEpochMs = 1000L,
                expiresAtEpochMs = 60_000L,
                maxToolCalls = 5
            )
            val request = BackgroundTaskRequest.PlanContinuation(
                taskId = "task_cancel_prop",
                plan = plan,
                capabilityToken = token,
                targetId = "nava.notes",
                languageTag = "en",
                enqueuedAtEpochMs = 1000L
            )
            manager.executeNow(request, 2000L)
        }
    }

    @Test(expected = kotlinx.coroutines.CancellationException::class)
    fun modelImportContinuationPropagatesCancellationException() {
        runBlocking {
            val managerWithCancellingHandler = BackgroundTaskContinuationManager(
                executePlanUseCase = executePlanUseCase,
                auditLog = fakeAuditLog,
                notificationBridge = fakeNotificationBridge,
                scheduler = fakeScheduler,
                modelImportHandler = { throw kotlinx.coroutines.CancellationException("Import cancelled") }
            )
            val request = BackgroundTaskRequest.ModelImportContinuation(
                taskId = "task_import_cancel",
                sourceUri = "content://saf/model.litertlm",
                expectedModelId = "gemma-4-e2b",
                expectedSha256Hex = "valid_sha256",
                languageTag = "en",
                enqueuedAtEpochMs = 1000L
            )
            managerWithCancellingHandler.executeNow(request, 2000L)
        }
    }

    @Test
    fun planContinuationCatchesSecurityExceptionAndRecordsViolation() = runBlocking {
        toolRegistry.register(
            FakePlanTool(
                name = "sec_tool",
                result = ToolResult.Success(UserMessage(MessageKey.ACTION_NOTE_SAVED), emptyMap())
            )
        )
        val plan = PlanAst(
            planId = "plan_sec",
            calls = listOf(ToolCallAst("sec_tool", emptyMap(), 0))
        )
        val expiredToken = CapabilityToken.mint(
            tokenId = "tok_expired",
            requestId = "req_sec",
            allowedTools = setOf("sec_tool"),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = 1000L,
            expiresAtEpochMs = 1500L,
            maxToolCalls = 5
        )
        val request = BackgroundTaskRequest.PlanContinuation(
            taskId = "task_sec_fail",
            plan = plan,
            capabilityToken = expiredToken,
            targetId = "nava.notes",
            languageTag = "en",
            enqueuedAtEpochMs = 1000L
        )

        manager.enqueue(request)
        assertEquals(request, AutomationWorkerRegistry.getRequest("task_sec_fail"))

        val outcome = manager.executeNow(request, 2000L)
        assertTrue(outcome is BackgroundTaskOutcome.Failed)
        val failed = outcome as BackgroundTaskOutcome.Failed
        assertTrue("isSecurityViolation must be true", failed.isSecurityViolation)
        assertEquals(BackgroundTaskStatus.FAILED, manager.getStatus("task_sec_fail"))
        assertNull("AutomationWorkerRegistry must unregister request on security failure", AutomationWorkerRegistry.getRequest("task_sec_fail"))
        assertEquals(1, fakeAuditLog.entries.size)
        assertTrue(fakeAuditLog.entries.first().actionSummary.contains("security failure"))
    }

    @Test
    fun terminalOutcomesUnregisterFromAutomationWorkerRegistry() = runBlocking {
        toolRegistry.register(
            FakePlanTool(
                name = "tool_terminal",
                result = ToolResult.Success(UserMessage(MessageKey.ACTION_NOTE_SAVED), emptyMap())
            )
        )
        val plan = PlanAst(
            planId = "plan_term",
            calls = listOf(ToolCallAst("tool_terminal", emptyMap(), 0))
        )
        val token = CapabilityToken.mint(
            tokenId = "tok_term",
            requestId = "req_term",
            allowedTools = setOf("tool_terminal"),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = 1000L,
            expiresAtEpochMs = 60_000L,
            maxToolCalls = 5
        )

        // 1. Completed
        val completedReq = BackgroundTaskRequest.PlanContinuation(
            taskId = "task_complete",
            plan = plan,
            capabilityToken = token,
            targetId = "nava.notes",
            languageTag = "en",
            enqueuedAtEpochMs = 1000L
        )
        manager.enqueue(completedReq)
        assertEquals(completedReq, AutomationWorkerRegistry.getRequest("task_complete"))
        val completedOutcome = manager.executeNow(completedReq, 2000L)
        assertTrue(completedOutcome is BackgroundTaskOutcome.Completed)
        assertNull("Registry must be unregistered on Completed", AutomationWorkerRegistry.getRequest("task_complete"))

        // 2. Failed
        val failingReq = BackgroundTaskRequest.ModelImportContinuation(
            taskId = "task_fail",
            sourceUri = "/data/local/models/model.litertlm",
            expectedModelId = "gemma-4-e2b",
            expectedSha256Hex = "bad_sha",
            languageTag = "en",
            enqueuedAtEpochMs = 1000L
        )
        manager.enqueue(failingReq)
        assertEquals(failingReq, AutomationWorkerRegistry.getRequest("task_fail"))
        val failedOutcome = manager.executeNow(failingReq, 2000L)
        assertTrue(failedOutcome is BackgroundTaskOutcome.Failed)
        assertNull("Registry must be unregistered on Failed", AutomationWorkerRegistry.getRequest("task_fail"))

        // 3. Cancelled
        val cancelledReq = BackgroundTaskRequest.PlanContinuation(
            taskId = "task_cancel_reg",
            plan = plan,
            capabilityToken = token,
            targetId = "nava.notes",
            languageTag = "en",
            enqueuedAtEpochMs = 1000L
        )
        manager.enqueue(cancelledReq)
        assertEquals(cancelledReq, AutomationWorkerRegistry.getRequest("task_cancel_reg"))
        manager.cancel("task_cancel_reg")
        assertNull("Registry must be unregistered on Cancelled", AutomationWorkerRegistry.getRequest("task_cancel_reg"))
    }

    @Test
    fun boundedRetentionCapEvictsOldestTerminalTasksOnly() = runBlocking {
        val boundedManager = BackgroundTaskContinuationManager(
            executePlanUseCase = executePlanUseCase,
            auditLog = fakeAuditLog,
            notificationBridge = fakeNotificationBridge,
            scheduler = fakeScheduler,
            modelImportHandler = { true },
            maxRetainedTasks = 2
        )

        fun makeModelReq(id: String) = BackgroundTaskRequest.ModelImportContinuation(
            taskId = id,
            sourceUri = "content://saf/model.litertlm",
            expectedModelId = "gemma-4-e2b",
            expectedSha256Hex = "valid_sha256",
            languageTag = "en",
            enqueuedAtEpochMs = 1000L
        )

        val req1 = makeModelReq("task_1")
        boundedManager.enqueue(req1)
        boundedManager.executeNow(req1, 1000L)
        assertEquals(BackgroundTaskStatus.COMPLETED, boundedManager.getStatus("task_1"))

        val req2 = makeModelReq("task_2")
        boundedManager.enqueue(req2)
        assertEquals(BackgroundTaskStatus.ENQUEUED, boundedManager.getStatus("task_2"))

        val req3 = makeModelReq("task_3")
        boundedManager.enqueue(req3)
        boundedManager.executeNow(req3, 3000L)

        assertNull("task_1 should be evicted", boundedManager.getStatus("task_1"))
        assertNull("task_1 outcome should be evicted", boundedManager.getOutcome("task_1"))
        assertNull("task_1 request should be evicted", boundedManager.getRequest("task_1"))

        assertEquals(BackgroundTaskStatus.ENQUEUED, boundedManager.getStatus("task_2"))
        assertEquals(BackgroundTaskStatus.COMPLETED, boundedManager.getStatus("task_3"))
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
    private val result: ToolResult = ToolResult.Success(UserMessage(MessageKey.ACTION_NOTE_SAVED), emptyMap()),
    private val exceptionToThrow: Throwable? = null
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
    ): ToolResult {
        if (exceptionToThrow != null) throw exceptionToThrow
        return result
    }
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

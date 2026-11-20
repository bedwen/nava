package com.nava.feature.automations.background

import com.nava.domain.ai.ModelProvisionerPort
import com.nava.domain.automation.BackgroundTaskContinuationPort
import com.nava.domain.automation.BackgroundTaskOutcome
import com.nava.domain.automation.BackgroundTaskRequest
import com.nava.domain.automation.BackgroundTaskStatus
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.DataProvenance
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.domain.usecase.ExecutePlanUseCase
import com.nava.feature.automations.common.AndroidAutomationNotificationBridge
import com.nava.feature.automations.common.AutomationNotificationBridge
import com.nava.feature.automations.common.CompletionNotificationRequest
import com.nava.feature.automations.common.InteractiveNotificationRequest
import com.nava.feature.automations.common.ToolTargetIds
import com.nava.feature.automations.routine.AutomationWorkerRegistry
import java.util.concurrent.ConcurrentHashMap

/**
 * Implementation of [BackgroundTaskContinuationPort] executing user-initiated long-running tasks
 * (such as Stage 1 authorized plan continuations, Stage 2 extractions, and offline SAF model imports)
 * that survive app backgrounding safely.
 *
 * Invariants:
 * - Safe `Auto` completions post a completion notification via [AutomationNotificationBridge.postCompletionNotification]
 *   and record [BackgroundTaskOutcome.Completed].
 * - When any step requires user confirmation or biometric unlock, the task pauses safely, posts
 *   a high-priority interactive notification via [AutomationNotificationBridge.postInteractiveConfirmationNotification]
 *   to resume in Nava's Action Confirmation Card, and records [BackgroundTaskOutcome.ConfirmationRequired].
 * - Tracks task lifecycle states: ENQUEUED, RUNNING, COMPLETED, AWAITING_CONFIRMATION, FAILED, CANCELLED.
 */
class BackgroundTaskContinuationManager(
    private val executePlanUseCase: ExecutePlanUseCase,
    private val auditLog: AuditLogPort,
    private val notificationBridge: AutomationNotificationBridge,
    private val scheduler: BackgroundTaskWorkScheduler,
    private val modelProvisioner: ModelProvisionerPort? = null,
    private val modelImportHandler: (suspend (BackgroundTaskRequest.ModelImportContinuation) -> Boolean)? = null
) : BackgroundTaskContinuationPort {

    private val taskRequests = ConcurrentHashMap<String, BackgroundTaskRequest>()
    private val taskStatuses = ConcurrentHashMap<String, BackgroundTaskStatus>()
    private val taskOutcomes = ConcurrentHashMap<String, BackgroundTaskOutcome>()

    override suspend fun enqueue(request: BackgroundTaskRequest): String {
        taskRequests[request.taskId] = request
        taskStatuses[request.taskId] = BackgroundTaskStatus.ENQUEUED
        AutomationWorkerRegistry.registerRequest(request)
        scheduler.schedule(request)
        return request.taskId
    }

    override suspend fun executeNow(
        request: BackgroundTaskRequest,
        nowEpochMs: Long
    ): BackgroundTaskOutcome {
        taskRequests[request.taskId] = request
        taskStatuses[request.taskId] = BackgroundTaskStatus.RUNNING

        val outcome: BackgroundTaskOutcome = when (request) {
            is BackgroundTaskRequest.PlanContinuation -> executePlanContinuation(request, nowEpochMs)
            is BackgroundTaskRequest.ModelImportContinuation -> executeModelImportContinuation(request, nowEpochMs)
        }

        taskOutcomes[request.taskId] = outcome
        taskStatuses[request.taskId] = outcome.status
        return outcome
    }

    override suspend fun getStatus(taskId: String): BackgroundTaskStatus? {
        return taskStatuses[taskId]
    }

    override suspend fun getOutcome(taskId: String): BackgroundTaskOutcome? {
        return taskOutcomes[taskId]
    }

    override suspend fun cancel(taskId: String) {
        scheduler.cancel(taskId)
        taskStatuses[taskId] = BackgroundTaskStatus.CANCELLED
        val cancelledOutcome = BackgroundTaskOutcome.Cancelled(
            taskId = taskId,
            message = UserMessage(
                key = MessageKey.BACKGROUND_TASK_CANCELLED,
                args = listOf(MessageArg.Text(taskId))
            )
        )
        taskOutcomes[taskId] = cancelledOutcome
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = System.currentTimeMillis(),
                toolName = "background_task_manager",
                targetId = ToolTargetIds.BACKGROUND_TASKS,
                actionSummary = "Cancelled background task $taskId",
                provenance = DataProvenance.SYSTEM,
                decision = "CANCELLED"
            )
        )
    }

    fun getRequest(taskId: String): BackgroundTaskRequest? {
        return taskRequests[taskId]
    }

    private suspend fun executePlanContinuation(
        request: BackgroundTaskRequest.PlanContinuation,
        nowEpochMs: Long
    ): BackgroundTaskOutcome {
        val results = executePlanUseCase(
            plan = request.plan,
            capabilityToken = request.capabilityToken,
            targetId = request.targetId,
            languageTag = request.languageTag,
            nowEpochMs = nowEpochMs,
            confirmedStepIndices = request.confirmedStepIndices,
            biometricApprovedStepIndices = request.biometricApprovedStepIndices,
            targetIdsByStep = request.targetIdsByStep,
            startFromOrderIndex = request.startFromOrderIndex
        )

        val completedSteps = ArrayList<ToolResult.Success>()
        val combinedOutputs = LinkedHashMap<String, String>()

        for (result in results) {
            when (result) {
                is ToolResult.Success -> {
                    completedSteps.add(result)
                    combinedOutputs.putAll(result.outputValues)
                }

                is ToolResult.ConfirmationRequired -> {
                    val notifId = AndroidAutomationNotificationBridge.stableNotificationId("bg_confirm:${request.taskId}")
                    val notifReq = InteractiveNotificationRequest(
                        notificationId = notifId,
                        requestId = "bg:${request.taskId}:$nowEpochMs",
                        pendingToolNames = listOf(result.pendingToolName),
                        targetId = result.targetId,
                        message = result.message,
                        requiresBiometric = result.requiresBiometric,
                        hasUntrustedHighRiskSlot = result.hasUntrustedHighRiskSlot,
                        canonicalArguments = result.canonicalArguments.mapValues { it.value.value },
                        taskId = request.taskId
                    )
                    notificationBridge.postInteractiveConfirmationNotification(notifReq)

                    val outcome = BackgroundTaskOutcome.ConfirmationRequired(
                        taskId = request.taskId,
                        pendingConfirmation = result,
                        message = result.message,
                        completedResults = completedSteps
                    )

                    auditLog.record(
                        AuditLogEntry(
                            timestampEpochMs = nowEpochMs,
                            toolName = result.pendingToolName,
                            targetId = result.targetId,
                            actionSummary = "Background task ${request.taskId} paused awaiting interactive confirmation",
                            provenance = DataProvenance.SYSTEM,
                            decision = if (result.requiresBiometric) "BIOMETRIC_REQUIRED" else "CONFIRMATION_REQUIRED"
                        )
                    )
                    return outcome
                }

                is ToolResult.Failure -> {
                    val outcome = BackgroundTaskOutcome.Failed(
                        taskId = request.taskId,
                        errorCode = result.errorCode,
                        message = result.message,
                        isSecurityViolation = result.isSecurityViolation
                    )
                    auditLog.record(
                        AuditLogEntry(
                            timestampEpochMs = nowEpochMs,
                            toolName = "background_task_manager",
                            targetId = ToolTargetIds.BACKGROUND_TASKS,
                            actionSummary = "Background task ${request.taskId} failed: ${result.errorCode}",
                            provenance = DataProvenance.SYSTEM,
                            decision = result.errorCode
                        )
                    )
                    return outcome
                }
            }
        }

        // All steps succeeded safely (Auto)
        val completionMessage = UserMessage(
            key = MessageKey.BACKGROUND_TASK_COMPLETED,
            args = listOf(MessageArg.Text(request.taskId))
        )
        val notifId = AndroidAutomationNotificationBridge.stableNotificationId("bg_complete:${request.taskId}")
        notificationBridge.postCompletionNotification(
            CompletionNotificationRequest(
                notificationId = notifId,
                requestId = "bg:${request.taskId}:$nowEpochMs",
                message = completionMessage,
                taskId = request.taskId
            )
        )

        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = nowEpochMs,
                toolName = "background_task_manager",
                targetId = ToolTargetIds.BACKGROUND_TASKS,
                actionSummary = "Background task ${request.taskId} completed ${completedSteps.size} steps",
                provenance = DataProvenance.SYSTEM,
                decision = "SUCCESS"
            )
        )

        return BackgroundTaskOutcome.Completed(
            taskId = request.taskId,
            message = completionMessage,
            toolResults = completedSteps,
            outputValues = combinedOutputs
        )
    }

    private suspend fun executeModelImportContinuation(
        request: BackgroundTaskRequest.ModelImportContinuation,
        nowEpochMs: Long
    ): BackgroundTaskOutcome {
        val importSuccess: Boolean = when {
            modelImportHandler != null -> {
                try {
                    modelImportHandler.invoke(request)
                } catch (_: Exception) {
                    false
                }
            }

            modelProvisioner != null -> {
                try {
                    modelProvisioner.verifyFileIntegrity(request.sourceUri, request.expectedSha256Hex)
                } catch (_: Exception) {
                    false
                }
            }

            else -> false
        }

        if (importSuccess) {
            val completionMessage = UserMessage(
                key = MessageKey.BACKGROUND_TASK_COMPLETED,
                args = listOf(MessageArg.Text(request.expectedModelId))
            )
            val notifId = AndroidAutomationNotificationBridge.stableNotificationId("bg_complete:${request.taskId}")
            notificationBridge.postCompletionNotification(
                CompletionNotificationRequest(
                    notificationId = notifId,
                    requestId = "bg:${request.taskId}:$nowEpochMs",
                    message = completionMessage,
                    taskId = request.taskId
                )
            )

            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowEpochMs,
                    toolName = "background_task_manager",
                    targetId = ToolTargetIds.BACKGROUND_TASKS,
                    actionSummary = "Model import continuation ${request.taskId} verified successfully",
                    provenance = DataProvenance.SYSTEM,
                    decision = "SUCCESS"
                )
            )

            return BackgroundTaskOutcome.Completed(
                taskId = request.taskId,
                message = completionMessage,
                toolResults = emptyList(),
                outputValues = mapOf("modelId" to request.expectedModelId)
            )
        } else {
            val errorCode = if (modelImportHandler == null && modelProvisioner == null) {
                "PROVISIONER_UNAVAILABLE"
            } else {
                "MODEL_IMPORT_FAILED"
            }
            val outcome = BackgroundTaskOutcome.Failed(
                taskId = request.taskId,
                errorCode = errorCode,
                message = UserMessage(
                    key = MessageKey.BACKGROUND_TASK_FAILED,
                    args = listOf(MessageArg.Text(errorCode))
                )
            )

            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowEpochMs,
                    toolName = "background_task_manager",
                    targetId = ToolTargetIds.BACKGROUND_TASKS,
                    actionSummary = "Model import continuation ${request.taskId} failed: $errorCode",
                    provenance = DataProvenance.SYSTEM,
                    decision = errorCode
                )
            )

            return outcome
        }
    }
}

package com.nava.domain.automation

import com.nava.domain.ai.PlanAst
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.DataProvenance
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.UserMessage

/**
 * Classification of user-initiated long-running tasks eligible for background continuation.
 */
enum class BackgroundTaskKind {
    /** Continues execution of a Stage 1 authorized [PlanAst] after the user leaves the app. */
    PLAN_EXECUTION,

    /** Continues a two-stage extraction-to-tool workflow carrying untrusted external slot provenance. */
    STAGE2_EXTRACTION_PLAN,

    /** Continues offline SAF `.litertlm` model import with streaming SHA-256 verification. */
    MODEL_IMPORT
}

/**
 * Lifecycle state of an enqueued background continuation task.
 */
enum class BackgroundTaskStatus {
    ENQUEUED,
    RUNNING,
    COMPLETED,
    AWAITING_CONFIRMATION,
    FAILED,
    CANCELLED
}

/**
 * Descriptor of a user-initiated long-running task handed off to [BackgroundTaskContinuationPort].
 *
 * Security invariant: plan continuations carry an immutable Stage 1 [CapabilityToken] minted from
 * [DataProvenance.USER_UTTERANCE] and still pass through `ExecutePlanUseCase` and
 * [com.nava.domain.security.SecurityFirewallPort].
 */
sealed interface BackgroundTaskRequest {
    val taskId: String
    val kind: BackgroundTaskKind
    val languageTag: String
    val enqueuedAtEpochMs: Long

    data class PlanContinuation(
        override val taskId: String,
        val plan: PlanAst,
        val capabilityToken: CapabilityToken,
        val targetId: String,
        override val languageTag: String,
        override val enqueuedAtEpochMs: Long,
        val isStage2Extraction: Boolean = false,
        val confirmedStepIndices: Set<Int> = emptySet(),
        val biometricApprovedStepIndices: Set<Int> = emptySet(),
        val targetIdsByStep: Map<Int, String> = emptyMap(),
        val startFromOrderIndex: Int = Int.MIN_VALUE
    ) : BackgroundTaskRequest {
        override val kind: BackgroundTaskKind =
            if (isStage2Extraction) {
                BackgroundTaskKind.STAGE2_EXTRACTION_PLAN
            } else {
                BackgroundTaskKind.PLAN_EXECUTION
            }

        init {
            require(taskId.isNotBlank()) { "BackgroundTaskRequest taskId must not be blank" }
            require(targetId.isNotBlank()) { "PlanContinuation targetId must not be blank" }
            require(languageTag.isNotBlank()) { "PlanContinuation languageTag must not be blank" }
            require(capabilityToken.mintProvenance == DataProvenance.USER_UTTERANCE) {
                "PlanContinuation requires a Stage 1 CapabilityToken minted from USER_UTTERANCE"
            }
        }
    }

    data class ModelImportContinuation(
        override val taskId: String,
        val sourceUri: String,
        val expectedModelId: String,
        val expectedSha256Hex: String,
        override val languageTag: String,
        override val enqueuedAtEpochMs: Long
    ) : BackgroundTaskRequest {
        override val kind: BackgroundTaskKind = BackgroundTaskKind.MODEL_IMPORT

        init {
            require(taskId.isNotBlank()) { "BackgroundTaskRequest taskId must not be blank" }
            require(sourceUri.isNotBlank()) { "ModelImportContinuation sourceUri must not be blank" }
            require(expectedModelId.isNotBlank()) { "ModelImportContinuation expectedModelId must not be blank" }
            require(expectedSha256Hex.isNotBlank()) { "ModelImportContinuation expectedSha256Hex must not be blank" }
            require(languageTag.isNotBlank()) { "ModelImportContinuation languageTag must not be blank" }
        }
    }
}

/**
 * Deterministic outcome of running a background continuation task.
 */
sealed interface BackgroundTaskOutcome {
    val taskId: String
    val status: BackgroundTaskStatus
    val message: UserMessage

    /** Task completed automatically and posted a completion notification. */
    data class Completed(
        override val taskId: String,
        override val message: UserMessage,
        val toolResults: List<ToolResult.Success> = emptyList(),
        val outputValues: Map<String, String> = emptyMap()
    ) : BackgroundTaskOutcome {
        override val status: BackgroundTaskStatus = BackgroundTaskStatus.COMPLETED
    }

    /**
     * Task paused at a step requiring an interactive Action Confirmation Card or Biometric
     * verification and posted a high-priority local notification to resume in `:app`.
     */
    data class ConfirmationRequired(
        override val taskId: String,
        val pendingConfirmation: ToolResult.ConfirmationRequired,
        override val message: UserMessage,
        val completedResults: List<ToolResult.Success> = emptyList()
    ) : BackgroundTaskOutcome {
        override val status: BackgroundTaskStatus = BackgroundTaskStatus.AWAITING_CONFIRMATION
    }

    /** Task failed or was blocked by security/verification checks. */
    data class Failed(
        override val taskId: String,
        val errorCode: String,
        override val message: UserMessage,
        val isSecurityViolation: Boolean = false
    ) : BackgroundTaskOutcome {
        override val status: BackgroundTaskStatus = BackgroundTaskStatus.FAILED
    }

    /** Task was cancelled before completion. */
    data class Cancelled(
        override val taskId: String,
        override val message: UserMessage
    ) : BackgroundTaskOutcome {
        override val status: BackgroundTaskStatus = BackgroundTaskStatus.CANCELLED
    }
}

/**
 * Port for continuing long-running user-initiated tasks via Android `WorkManager`
 * (`OneTimeWorkRequest` + `ForegroundInfo`) so tasks survive app backgrounding safely.
 */
interface BackgroundTaskContinuationPort {
    /** Enqueues [request] for foreground WorkManager continuation and returns its canonical taskId. */
    suspend fun enqueue(request: BackgroundTaskRequest): String

    /** Executes [request] directly (invoked by the WorkManager worker or JVM unit tests). */
    suspend fun executeNow(request: BackgroundTaskRequest, nowEpochMs: Long): BackgroundTaskOutcome

    /** Returns the latest known [BackgroundTaskStatus] for [taskId], or null if unknown. */
    suspend fun getStatus(taskId: String): BackgroundTaskStatus?

    /** Returns the terminal or awaiting-confirmation [BackgroundTaskOutcome] for [taskId], or null. */
    suspend fun getOutcome(taskId: String): BackgroundTaskOutcome?

    /** Cancels an enqueued or running background continuation task. */
    suspend fun cancel(taskId: String)
}

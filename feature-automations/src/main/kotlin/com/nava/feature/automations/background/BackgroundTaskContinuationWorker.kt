package com.nava.feature.automations.background

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ForegroundInfo
import androidx.work.WorkerParameters
import com.nava.domain.automation.BackgroundTaskOutcome
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.common.AndroidAutomationNotificationBridge
import com.nava.feature.automations.routine.AutomationWorkerRegistry

/**
 * Android [CoroutineWorker] continuing long-running user-initiated tasks in foreground WorkManager.
 *
 * Calls [setForeground] with [ForegroundInfo] so tasks survive app backgrounding safely
 * (PLAN.md Section 5.6 and Section 9 Phase 4).
 */
class BackgroundTaskContinuationWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        val taskId = inputData.getString(KEY_TASK_ID) ?: return Result.failure()
        val manager = AutomationWorkerRegistry.getBackgroundTaskManager() ?: return Result.failure()
        val bridge = AutomationWorkerRegistry.getNotificationBridge()

        // Set foreground info if running with Android notification bridge
        if (bridge is AndroidAutomationNotificationBridge) {
            val spec = bridge.createForegroundNotificationSpec(
                taskId = taskId,
                message = UserMessage(
                    key = MessageKey.BACKGROUND_TASK_RUNNING,
                    args = listOf(MessageArg.Text(taskId))
                )
            )
            val notification = bridge.buildForegroundNotification(spec)
            val foregroundInfo = ForegroundInfo(spec.notificationId, notification)
            try {
                setForeground(foregroundInfo)
            } catch (_: Exception) {
                // Ignore foreground exception if platform restriction prevents promoting to foreground
            }
        }

        val request = AutomationWorkerRegistry.getRequest(taskId) ?: return Result.failure()

        val outcome = manager.executeNow(
            request = request,
            nowEpochMs = System.currentTimeMillis()
        )

        return when (outcome) {
            is BackgroundTaskOutcome.Completed,
            is BackgroundTaskOutcome.ConfirmationRequired -> Result.success()
            is BackgroundTaskOutcome.Failed,
            is BackgroundTaskOutcome.Cancelled -> Result.failure()
        }
    }

    companion object {
        const val KEY_TASK_ID: String = "task_id"
        const val TAG_BACKGROUND_TASK: String = "nava_background_task_worker"
    }
}

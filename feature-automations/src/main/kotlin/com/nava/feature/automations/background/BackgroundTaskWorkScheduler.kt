package com.nava.feature.automations.background

import android.content.Context
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.workDataOf
import com.nava.domain.automation.BackgroundTaskRequest

/**
 * Platform abstraction for scheduling and cancelling background continuation tasks.
 */
interface BackgroundTaskWorkScheduler {
    suspend fun schedule(request: BackgroundTaskRequest)
    suspend fun cancel(taskId: String)
}

/**
 * Production Android WorkManager implementation of [BackgroundTaskWorkScheduler].
 */
class WorkManagerBackgroundTaskScheduler(
    private val workManager: WorkManager
) : BackgroundTaskWorkScheduler {

    constructor(context: Context) : this(WorkManager.getInstance(context))

    override suspend fun schedule(request: BackgroundTaskRequest) {
        val uniqueWorkName = "bg:${request.taskId}"
        val workRequest = OneTimeWorkRequestBuilder<BackgroundTaskContinuationWorker>()
            .setInputData(workDataOf(BackgroundTaskContinuationWorker.KEY_TASK_ID to request.taskId))
            .addTag(BackgroundTaskContinuationWorker.TAG_BACKGROUND_TASK)
            .addTag(uniqueWorkName)
            .build()

        workManager.enqueueUniqueWork(
            uniqueWorkName,
            ExistingWorkPolicy.REPLACE,
            workRequest
        )
    }

    override suspend fun cancel(taskId: String) {
        workManager.cancelUniqueWork("bg:$taskId")
    }
}

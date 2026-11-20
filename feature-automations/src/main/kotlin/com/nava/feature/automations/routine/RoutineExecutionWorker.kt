package com.nava.feature.automations.routine

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import com.nava.domain.automation.RoutineExecutionOutcome
import com.nava.domain.security.RuleCapabilityGrant
import java.util.concurrent.TimeUnit

/**
 * Android [CoroutineWorker] executing persistent background automation routines via [RoutineExecutor].
 *
 * Security Invariant: delegates to bound [com.nava.domain.automation.RoutineExecutorPort],
 * failing closed if unbound.
 */
class RoutineExecutionWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        val ruleId = inputData.getString(KEY_RULE_ID) ?: return Result.failure()
        val executor = AutomationWorkerRegistry.getRoutineExecutor() ?: return Result.failure()

        val outcome = executor.executeRule(
            ruleId = ruleId,
            nowEpochMs = System.currentTimeMillis()
        )

        return when (outcome) {
            is RoutineExecutionOutcome.Executed -> Result.success()
            is RoutineExecutionOutcome.EscalatedToInteractive -> Result.success()
            is RoutineExecutionOutcome.Denied -> Result.failure()
            is RoutineExecutionOutcome.Failed -> Result.failure()
        }
    }

    companion object {
        const val KEY_RULE_ID: String = "rule_id"
        const val TAG_ROUTINE: String = "nava_routine_worker"
    }
}

/**
 * Production Android WorkManager implementation of [RoutineWorkScheduler].
 */
class WorkManagerRoutineScheduler(
    private val workManager: WorkManager
) : RoutineWorkScheduler {

    constructor(context: Context) : this(WorkManager.getInstance(context))

    override suspend fun schedule(grant: RuleCapabilityGrant) {
        val constraintsBuilder = Constraints.Builder()
        val triggerParams = grant.triggerSpec.parameters

        if (triggerParams["requires_charging"]?.toBoolean() == true) {
            constraintsBuilder.setRequiresCharging(true)
        }
        if (triggerParams["requires_battery_not_low"]?.toBoolean() == true) {
            constraintsBuilder.setRequiresBatteryNotLow(true)
        }
        if (triggerParams["requires_device_idle"]?.toBoolean() == true) {
            constraintsBuilder.setRequiresDeviceIdle(true)
        }

        val constraints = constraintsBuilder.build()
        val inputData = workDataOf(RoutineExecutionWorker.KEY_RULE_ID to grant.ruleId)
        val uniqueWorkName = "routine:${grant.ruleId}"

        val repeatIntervalMinutes = triggerParams["interval_minutes"]?.toLongOrNull()
        if (repeatIntervalMinutes != null && repeatIntervalMinutes >= MIN_PERIODIC_INTERVAL_MINUTES) {
            val periodicRequest = PeriodicWorkRequestBuilder<RoutineExecutionWorker>(
                repeatIntervalMinutes,
                TimeUnit.MINUTES
            )
                .setConstraints(constraints)
                .setInputData(inputData)
                .addTag(RoutineExecutionWorker.TAG_ROUTINE)
                .addTag(uniqueWorkName)
                .build()

            workManager.enqueueUniquePeriodicWork(
                uniqueWorkName,
                ExistingPeriodicWorkPolicy.UPDATE,
                periodicRequest
            )
        } else {
            val delayMinutes = triggerParams["delay_minutes"]?.toLongOrNull() ?: 0L
            val oneTimeRequest = OneTimeWorkRequestBuilder<RoutineExecutionWorker>()
                .setConstraints(constraints)
                .setInputData(inputData)
                .addTag(RoutineExecutionWorker.TAG_ROUTINE)
                .addTag(uniqueWorkName)

            if (delayMinutes > 0L) {
                oneTimeRequest.setInitialDelay(delayMinutes, TimeUnit.MINUTES)
            }

            workManager.enqueueUniqueWork(
                uniqueWorkName,
                ExistingWorkPolicy.REPLACE,
                oneTimeRequest.build()
            )
        }
    }

    override suspend fun cancel(ruleId: String) {
        workManager.cancelUniqueWork("routine:$ruleId")
    }

    override suspend fun cancelAll() {
        workManager.cancelAllWorkByTag(RoutineExecutionWorker.TAG_ROUTINE)
    }

    companion object {
        const val MIN_PERIODIC_INTERVAL_MINUTES: Long = 15L
    }
}

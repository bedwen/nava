package com.nava.feature.automations.routine

import com.nava.domain.automation.BackgroundTaskContinuationPort
import com.nava.domain.automation.BackgroundTaskRequest
import com.nava.domain.automation.RoutineExecutorPort
import com.nava.feature.automations.common.AutomationNotificationBridge
import java.util.concurrent.ConcurrentHashMap

/**
 * Thread-safe service locator allowing Android WorkManager workers to access domain ports
 * and notification bridges without Hilt or Dagger.
 *
 * Security invariant: fails closed whenever unbound.
 */
object AutomationWorkerRegistry {
    @Volatile
    private var routineExecutor: RoutineExecutorPort? = null

    @Volatile
    private var backgroundTaskManager: BackgroundTaskContinuationPort? = null

    @Volatile
    private var notificationBridge: AutomationNotificationBridge? = null

    private val activeRequests = ConcurrentHashMap<String, BackgroundTaskRequest>()

    fun bind(
        routineExecutor: RoutineExecutorPort,
        backgroundTaskManager: BackgroundTaskContinuationPort,
        notificationBridge: AutomationNotificationBridge
    ) {
        this.routineExecutor = routineExecutor
        this.backgroundTaskManager = backgroundTaskManager
        this.notificationBridge = notificationBridge
    }

    fun unbind() {
        routineExecutor = null
        backgroundTaskManager = null
        notificationBridge = null
        activeRequests.clear()
    }

    fun getRoutineExecutor(): RoutineExecutorPort? = routineExecutor

    fun getBackgroundTaskManager(): BackgroundTaskContinuationPort? = backgroundTaskManager

    fun getNotificationBridge(): AutomationNotificationBridge? = notificationBridge

    fun registerRequest(request: BackgroundTaskRequest) {
        activeRequests[request.taskId] = request
    }

    fun unregisterRequest(taskId: String): BackgroundTaskRequest? {
        return activeRequests.remove(taskId)
    }

    fun getRequest(taskId: String): BackgroundTaskRequest? {
        return activeRequests[taskId]
    }
}

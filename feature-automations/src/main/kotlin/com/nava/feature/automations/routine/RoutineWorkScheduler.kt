package com.nava.feature.automations.routine

import com.nava.domain.security.RuleCapabilityGrant

/**
 * Platform abstraction for scheduling and cancelling background routine work requests.
 */
interface RoutineWorkScheduler {
    suspend fun schedule(grant: RuleCapabilityGrant)
    suspend fun cancel(ruleId: String)
    suspend fun cancelAll()
}

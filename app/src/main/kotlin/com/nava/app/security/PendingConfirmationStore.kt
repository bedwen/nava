package com.nava.app.security

import android.content.Intent
import com.nava.app.assistant.AssistantIntentContract
import com.nava.app.assistant.ConfirmationIntentExtras
import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.automation.BackgroundTaskOutcome
import com.nava.domain.automation.BackgroundTaskRequest
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleGrantPort
import com.nava.domain.security.Tainted
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.background.BackgroundTaskContinuationManager
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.ToolTargetIds
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Origin of an interactive confirmation item displayed in Nava's Action Confirmation Card.
 */
enum class PendingConfirmationSource {
    /** Foreground Stage 1/Stage 2 plan execution paused at a confirmation or biometric gate. */
    FOREGROUND_PLAN,

    /** Long-running WorkManager background task continuation paused at a confirmation gate. */
    BACKGROUND_TASK,

    /** Persistent background automation routine escalated to interactive user confirmation. */
    ESCALATED_ROUTINE
}

/**
 * Immutable snapshot of a pending user confirmation or biometric approval request.
 */
data class PendingConfirmationItem(
    val requestId: String,
    val source: PendingConfirmationSource,
    val confirmation: ToolResult.ConfirmationRequired,
    val targetId: String,
    val languageTag: String = DEFAULT_LANGUAGE_TAG,
    val plan: PlanAst? = null,
    val capabilityToken: CapabilityToken? = null,
    val taskId: String? = null,
    val ruleId: String? = null,
    val ruleGrant: RuleCapabilityGrant? = null,
    val confirmedStepIndices: Set<Int> = emptySet(),
    val biometricApprovedStepIndices: Set<Int> = emptySet(),
    val createdAtEpochMs: Long
) {
    init {
        require(requestId.isNotBlank()) { "PendingConfirmationItem requestId must not be blank" }
        require(targetId.isNotBlank()) { "PendingConfirmationItem targetId must not be blank" }
        require(languageTag.isNotBlank()) { "PendingConfirmationItem languageTag must not be blank" }
        when (source) {
            PendingConfirmationSource.FOREGROUND_PLAN -> {
                requireNotNull(plan) { "FOREGROUND_PLAN confirmation requires a non-null PlanAst" }
                val token = requireNotNull(capabilityToken) {
                    "FOREGROUND_PLAN confirmation requires a non-null Stage 1 CapabilityToken"
                }
                require(token.mintProvenance == DataProvenance.USER_UTTERANCE) {
                    "FOREGROUND_PLAN CapabilityToken must have USER_UTTERANCE provenance"
                }
            }

            PendingConfirmationSource.BACKGROUND_TASK -> {
                require(!taskId.isNullOrBlank()) {
                    "BACKGROUND_TASK confirmation requires a non-blank taskId"
                }
                requireNotNull(plan) { "BACKGROUND_TASK confirmation requires a non-null PlanAst" }
                val token = requireNotNull(capabilityToken) {
                    "BACKGROUND_TASK confirmation requires a non-null Stage 1 CapabilityToken"
                }
                require(token.mintProvenance == DataProvenance.USER_UTTERANCE) {
                    "BACKGROUND_TASK CapabilityToken must have USER_UTTERANCE provenance"
                }
            }

            PendingConfirmationSource.ESCALATED_ROUTINE -> {
                require(!ruleId.isNullOrBlank()) {
                    "ESCALATED_ROUTINE confirmation requires a non-blank ruleId"
                }
                val grant = requireNotNull(ruleGrant) {
                    "ESCALATED_ROUTINE confirmation requires a verified RuleCapabilityGrant"
                }
                require(grant.ruleId == ruleId) {
                    "RuleCapabilityGrant ruleId (${grant.ruleId}) must match item ruleId ($ruleId)"
                }
                require(grant.approvalState == RuleApprovalState.APPROVED_ACTIVE) {
                    "ESCALATED_ROUTINE RuleCapabilityGrant must be in APPROVED_ACTIVE state"
                }
                require(grant.sealHmacHex.isNotBlank()) {
                    "ESCALATED_ROUTINE RuleCapabilityGrant must carry a non-blank HMAC seal"
                }
            }
        }
    }

    val requiresBiometric: Boolean
        get() = confirmation.requiresBiometric

    val hasUntrustedHighRiskSlot: Boolean
        get() = confirmation.hasUntrustedHighRiskSlot

    companion object {
        const val DEFAULT_LANGUAGE_TAG: String = "en"
    }
}

/**
 * Deterministic outcome of resolving notification [Intent] extras against [PendingConfirmationStore].
 */
sealed interface NotificationResolutionResult {
    data class Resolved(val item: PendingConfirmationItem) : NotificationResolutionResult
    data class Rejected(val reasonCode: String) : NotificationResolutionResult
}

/**
 * Thread-safe reactive store holding pending interactive Action Confirmation Card requests across
 * foreground queries, background task continuations, and escalated background routines.
 *
 * Security Invariant (Requirement 6):
 * Incoming [Intent] extras from notifications are untrusted lookup keys only. They can resolve ONLY:
 * 1. Already-registered [PendingConfirmationItem] entries in this store (whose Stage 1
 *    [CapabilityToken] is still unexpired),
 * 2. Active `AWAITING_CONFIRMATION` tasks in [BackgroundTaskContinuationManager] carrying a valid
 *    Stage 1 [CapabilityToken], or
 * 3. Persisted `APPROVED_ACTIVE` [RuleCapabilityGrant] records verified by [RuleGrantPort] and
 *    [ruleSealVerifier].
 *
 * Forged, unknown, expired, tampered, or mismatched extras are deterministically rejected and can
 * never fabricate a confirmation card or downgrade `requiresBiometric` / `hasUntrustedHighRiskSlot`.
 */
class PendingConfirmationStore(
    private val ruleGrantPort: RuleGrantPort? = null,
    private val ruleSealVerifier: suspend (RuleCapabilityGrant) -> Boolean = { it.sealHmacHex.isNotBlank() },
    private val backgroundTaskManagerProvider: () -> BackgroundTaskContinuationManager? = { null },
    private val clockMs: () -> Long = System::currentTimeMillis
) {

    private val stateLock = Any()
    private val itemsByRequestId = LinkedHashMap<String, PendingConfirmationItem>()
    private var activeRequestId: String? = null

    private val _pendingItemsFlow = MutableStateFlow<List<PendingConfirmationItem>>(emptyList())
    val pendingItemsFlow: StateFlow<List<PendingConfirmationItem>> = _pendingItemsFlow.asStateFlow()

    private val _activeConfirmationFlow = MutableStateFlow<PendingConfirmationItem?>(null)
    val activeConfirmationFlow: StateFlow<PendingConfirmationItem?> = _activeConfirmationFlow.asStateFlow()

    /**
     * Registers a foreground [PlanAst] + [CapabilityToken] + [ToolResult.ConfirmationRequired]
     * and makes it the active confirmation card item.
     */
    fun registerForegroundConfirmation(
        plan: PlanAst,
        capabilityToken: CapabilityToken,
        confirmation: ToolResult.ConfirmationRequired,
        targetId: String = confirmation.targetId,
        languageTag: String = PendingConfirmationItem.DEFAULT_LANGUAGE_TAG,
        confirmedStepIndices: Set<Int> = emptySet(),
        biometricApprovedStepIndices: Set<Int> = emptySet(),
        nowEpochMs: Long = clockMs()
    ): PendingConfirmationItem {
        capabilityToken.assertValidFor(confirmation.pendingToolName, nowEpochMs)
        val item = PendingConfirmationItem(
            requestId = capabilityToken.requestId,
            source = PendingConfirmationSource.FOREGROUND_PLAN,
            confirmation = confirmation,
            targetId = targetId,
            languageTag = languageTag,
            plan = plan,
            capabilityToken = capabilityToken,
            confirmedStepIndices = confirmedStepIndices,
            biometricApprovedStepIndices = biometricApprovedStepIndices,
            createdAtEpochMs = nowEpochMs
        )
        return register(item)
    }

    /**
     * Registers a paused [BackgroundTaskRequest.PlanContinuation] awaiting interactive confirmation.
     */
    fun registerBackgroundTaskConfirmation(
        taskId: String,
        request: BackgroundTaskRequest.PlanContinuation,
        confirmation: ToolResult.ConfirmationRequired,
        requestId: String = request.capabilityToken.requestId,
        nowEpochMs: Long = clockMs()
    ): PendingConfirmationItem {
        require(taskId == request.taskId) {
            "taskId ($taskId) must match PlanContinuation.taskId (${request.taskId})"
        }
        request.capabilityToken.assertValidFor(confirmation.pendingToolName, nowEpochMs)
        val item = PendingConfirmationItem(
            requestId = requestId,
            source = PendingConfirmationSource.BACKGROUND_TASK,
            confirmation = confirmation,
            targetId = confirmation.targetId.ifBlank { request.targetId },
            languageTag = request.languageTag,
            plan = request.plan,
            capabilityToken = request.capabilityToken,
            taskId = taskId,
            confirmedStepIndices = request.confirmedStepIndices,
            biometricApprovedStepIndices = request.biometricApprovedStepIndices,
            createdAtEpochMs = nowEpochMs
        )
        return register(item)
    }

    /**
     * Registers an escalated background routine ([RuleCapabilityGrant]) awaiting interactive confirmation.
     */
    fun registerEscalatedRoutineConfirmation(
        grant: RuleCapabilityGrant,
        requestId: String = "routine:${grant.ruleId}:${clockMs()}",
        requiresBiometric: Boolean = grantRequiresBiometric(grant),
        languageTag: String = PendingConfirmationItem.DEFAULT_LANGUAGE_TAG,
        nowEpochMs: Long = clockMs()
    ): PendingConfirmationItem {
        val authoritativeBiometric = requiresBiometric || grantRequiresBiometric(grant)
        val firstAction = grant.staticActions.first()
        val canonicalArgs = LinkedHashMap<String, Tainted<String>>()
        for (action in grant.staticActions) {
            for ((k, v) in action.staticArguments) {
                val sanitizedVal = Gemma4InputSanitizer.sanitize(v)
                canonicalArgs.putIfAbsent(k, Tainted.fromSystem(sanitizedVal))
            }
        }
        val messageKey = if (authoritativeBiometric) {
            MessageKey.ROUTINE_ESCALATED_BIOMETRIC
        } else {
            MessageKey.ROUTINE_ESCALATED_CONFIRMATION
        }
        val confirmation = ToolResult.ConfirmationRequired(
            message = UserMessage(
                key = messageKey,
                args = listOf(MessageArg.Text(grant.ruleId))
            ),
            pendingToolName = firstAction.toolName,
            targetId = ToolTargetIds.ROUTINES,
            canonicalArguments = canonicalArgs,
            requiresBiometric = authoritativeBiometric,
            hasUntrustedHighRiskSlot = false,
            pendingOrderIndex = 0
        )
        val item = PendingConfirmationItem(
            requestId = requestId,
            source = PendingConfirmationSource.ESCALATED_ROUTINE,
            confirmation = confirmation,
            targetId = ToolTargetIds.ROUTINES,
            languageTag = languageTag,
            ruleId = grant.ruleId,
            ruleGrant = grant,
            createdAtEpochMs = nowEpochMs
        )
        return register(item)
    }

    /**
     * Inserts or updates [item] in the store and promotes it to the active confirmation card item.
     */
    fun register(item: PendingConfirmationItem): PendingConfirmationItem {
        synchronized(stateLock) {
            // If an existing entry shares the same taskId or ruleId under an older requestId, replace it.
            if (item.taskId != null) {
                val staleKeys = itemsByRequestId.values
                    .filter { it.taskId == item.taskId && it.requestId != item.requestId }
                    .map { it.requestId }
                for (k in staleKeys) {
                    itemsByRequestId.remove(k)
                }
            }
            if (item.ruleId != null) {
                val staleKeys = itemsByRequestId.values
                    .filter { it.ruleId == item.ruleId && it.requestId != item.requestId }
                    .map { it.requestId }
                for (k in staleKeys) {
                    itemsByRequestId.remove(k)
                }
            }
            itemsByRequestId[item.requestId] = item
            activeRequestId = item.requestId
            publishStateLocked()
        }
        return item
    }

    fun findByRequestId(requestId: String): PendingConfirmationItem? {
        if (requestId.isBlank()) return null
        return synchronized(stateLock) {
            itemsByRequestId[requestId]
        }
    }

    fun findByTaskId(taskId: String): PendingConfirmationItem? {
        if (taskId.isBlank()) return null
        return synchronized(stateLock) {
            itemsByRequestId.values.firstOrNull { it.taskId == taskId }
        }
    }

    fun findByRuleId(ruleId: String): PendingConfirmationItem? {
        if (ruleId.isBlank()) return null
        return synchronized(stateLock) {
            itemsByRequestId.values.firstOrNull { it.ruleId == ruleId }
        }
    }

    /**
     * Extracts [ConfirmationIntentExtras] from [intent] and resolves them against the store.
     */
    suspend fun resolveFromIntent(
        intent: Intent?,
        nowEpochMs: Long = clockMs()
    ): NotificationResolutionResult {
        val extras = AssistantIntentContract.extractConfirmationExtras(intent)
            ?: return NotificationResolutionResult.Rejected(REASON_INVALID_OR_FORGED_EXTRAS)
        return resolveFromNotificationExtras(extras, nowEpochMs)
    }

    /**
     * Resolves [extras] against already-registered [PendingConfirmationItem] records,
     * active [BackgroundTaskContinuationManager] tasks, or verified [RuleCapabilityGrant] records.
     *
     * Never fabricates a confirmation card from unverified Intent extras and never allows
     * Intent extras to downgrade `requiresBiometric` or `hasUntrustedHighRiskSlot`.
     */
    suspend fun resolveFromNotificationExtras(
        extras: ConfirmationIntentExtras?,
        nowEpochMs: Long = clockMs()
    ): NotificationResolutionResult {
        if (extras == null || !extras.hasAnyIdentifier()) {
            return NotificationResolutionResult.Rejected(REASON_MISSING_IDENTIFIERS)
        }

        // Reject mutually exclusive taskId + ruleId combinations in the same intent.
        if (!extras.taskId.isNullOrBlank() && !extras.ruleId.isNullOrBlank()) {
            return NotificationResolutionResult.Rejected(REASON_MISMATCHED_EXTRAS)
        }

        // 1. If ruleId is present, ALWAYS verify against authoritative RuleGrantPort + HMAC seal.
        if (!extras.ruleId.isNullOrBlank()) {
            return resolveVerifiedRule(
                ruleId = extras.ruleId,
                expectedRequestId = extras.requestId,
                nowEpochMs = nowEpochMs
            )
        }

        // 2. If taskId is present, resolve strictly against registered item or BackgroundTaskContinuationManager.
        if (!extras.taskId.isNullOrBlank()) {
            return resolveVerifiedBackgroundTask(
                taskId = extras.taskId,
                expectedRequestId = extras.requestId,
                nowEpochMs = nowEpochMs
            )
        }

        // 3. Otherwise, requestId alone must match an ALREADY-REGISTERED foreground/task item.
        val reqId = extras.requestId
        if (reqId.isNullOrBlank()) {
            return NotificationResolutionResult.Rejected(REASON_MISSING_IDENTIFIERS)
        }
        val existing = findByRequestId(reqId)
            ?: return NotificationResolutionResult.Rejected(REASON_UNREGISTERED_REQUEST)

        if (existing.source == PendingConfirmationSource.ESCALATED_ROUTINE) {
            val ruleId = existing.ruleId
                ?: return NotificationResolutionResult.Rejected(REASON_RULE_NOT_VERIFIED)
            return resolveVerifiedRule(
                ruleId = ruleId,
                expectedRequestId = reqId,
                nowEpochMs = nowEpochMs
            )
        }

        val token = existing.capabilityToken
        if (token == null || token.isExpired(nowEpochMs)) {
            dismiss(existing.requestId)
            return NotificationResolutionResult.Rejected(REASON_CAPABILITY_TOKEN_EXPIRED)
        }

        promoteToActive(existing.requestId)
        return NotificationResolutionResult.Resolved(existing)
    }

    /**
     * Updates a user-edited slot argument in the pending confirmation item identified by [requestId].
     *
     * Security invariants:
     * - Rejects slot mutations for [PendingConfirmationSource.ESCALATED_ROUTINE] (whose actions
     *   are cryptographically bound to an HMAC-sealed [RuleCapabilityGrant]).
     * - Catches [SecurityException] from [Gemma4InputSanitizer.sanitize] cleanly and returns `null`
     *   rather than crashing the UI thread.
     */
    fun updateEditedSlot(
        requestId: String,
        slotName: String,
        newRawValue: String
    ): PendingConfirmationItem? {
        if (requestId.isBlank() || slotName.isBlank()) return null
        val sanitizedValue = try {
            Gemma4InputSanitizer.sanitize(newRawValue).trim()
        } catch (_: SecurityException) {
            return null
        }
        return synchronized(stateLock) {
            val current = itemsByRequestId[requestId] ?: return@synchronized null
            if (current.source == PendingConfirmationSource.ESCALATED_ROUTINE) {
                return@synchronized null
            }
            if (slotName !in current.confirmation.canonicalArguments) {
                return@synchronized null
            }
            val existingArg = current.confirmation.canonicalArguments.getValue(slotName)
            val updatedCanonical = LinkedHashMap(current.confirmation.canonicalArguments)
            updatedCanonical[slotName] = existingArg.map { sanitizedValue }

            val updatedPlan = current.plan?.let { plan ->
                val targetIndex = current.confirmation.pendingOrderIndex
                val updatedCalls = plan.calls.map { call ->
                    if (call.orderIndex == targetIndex && slotName in call.arguments) {
                        val oldSlot = call.arguments.getValue(slotName)
                        val newAst: SlotValueAst = when (oldSlot.value) {
                            is SlotValueAst.IntValue -> {
                                val parsed = sanitizedValue.toLongOrNull() ?: return@synchronized null
                                SlotValueAst.IntValue(parsed)
                            }

                            is SlotValueAst.BooleanValue -> {
                                val parsed = sanitizedValue.toBooleanStrictOrNull() ?: return@synchronized null
                                SlotValueAst.BooleanValue(parsed)
                            }

                            is SlotValueAst.StringValue,
                            SlotValueAst.NullValue -> SlotValueAst.StringValue(sanitizedValue)
                        }
                        val newArgs = LinkedHashMap(call.arguments)
                        newArgs[slotName] = oldSlot.map { newAst }
                        call.copy(arguments = newArgs)
                    } else {
                        call
                    }
                }
                plan.copy(calls = updatedCalls)
            }

            val updatedItem = current.copy(
                confirmation = current.confirmation.copy(canonicalArguments = updatedCanonical),
                plan = updatedPlan
            )
            itemsByRequestId[requestId] = updatedItem
            publishStateLocked()
            updatedItem
        }
    }

    /**
     * Records user confirmation (and optional biometric approval) for [stepOrderIndex] on [requestId].
     */
    fun markStepApproved(
        requestId: String,
        stepOrderIndex: Int = 0,
        biometricApproved: Boolean = false
    ): PendingConfirmationItem? {
        return synchronized(stateLock) {
            val current = itemsByRequestId[requestId] ?: return@synchronized null
            val updatedConfirmed = current.confirmedStepIndices + stepOrderIndex
            val updatedBio = if (biometricApproved) {
                current.biometricApprovedStepIndices + stepOrderIndex
            } else {
                current.biometricApprovedStepIndices
            }
            val updated = current.copy(
                confirmedStepIndices = updatedConfirmed,
                biometricApprovedStepIndices = updatedBio
            )
            itemsByRequestId[requestId] = updated
            publishStateLocked()
            updated
        }
    }

    /**
     * Removes and returns the confirmation item identified by [requestId].
     */
    fun dismiss(requestId: String): PendingConfirmationItem? {
        if (requestId.isBlank()) return null
        return synchronized(stateLock) {
            val removed = itemsByRequestId.remove(requestId)
            if (activeRequestId == requestId) {
                activeRequestId = itemsByRequestId.keys.lastOrNull()
            }
            publishStateLocked()
            removed
        }
    }

    /**
     * Clears all pending confirmation requests.
     */
    fun clearAll() {
        synchronized(stateLock) {
            itemsByRequestId.clear()
            activeRequestId = null
            publishStateLocked()
        }
    }

    private suspend fun resolveVerifiedRule(
        ruleId: String,
        expectedRequestId: String?,
        nowEpochMs: Long
    ): NotificationResolutionResult {
        val existingByRule = findByRuleId(ruleId)
        if (existingByRule != null &&
            !expectedRequestId.isNullOrBlank() &&
            existingByRule.requestId != expectedRequestId
        ) {
            return NotificationResolutionResult.Rejected(REASON_MISMATCHED_EXTRAS)
        }

        // If expectedRequestId points to a different item (e.g. a non-rule item), reject mismatch.
        if (!expectedRequestId.isNullOrBlank()) {
            val existingByReq = findByRequestId(expectedRequestId)
            if (existingByReq != null && existingByReq.ruleId != ruleId) {
                return NotificationResolutionResult.Rejected(REASON_MISMATCHED_EXTRAS)
            }
        }

        val port = ruleGrantPort
        if (port == null) {
            return NotificationResolutionResult.Rejected(REASON_RULE_NOT_VERIFIED)
        }

        val persistedGrant = port.findRule(ruleId)
        if (persistedGrant == null ||
            persistedGrant.approvalState != RuleApprovalState.APPROVED_ACTIVE ||
            persistedGrant.sealHmacHex.isBlank() ||
            !ruleSealVerifier(persistedGrant)
        ) {
            existingByRule?.let { dismiss(it.requestId) }
            return NotificationResolutionResult.Rejected(REASON_RULE_NOT_VERIFIED)
        }

        val effectiveRequestId = existingByRule?.requestId
            ?: expectedRequestId?.takeIf { it.isNotBlank() }
            ?: "routine:${persistedGrant.ruleId}:$nowEpochMs"

        val resolvedItem = registerEscalatedRoutineConfirmation(
            grant = persistedGrant,
            requestId = effectiveRequestId,
            requiresBiometric = grantRequiresBiometric(persistedGrant),
            languageTag = existingByRule?.languageTag ?: PendingConfirmationItem.DEFAULT_LANGUAGE_TAG,
            nowEpochMs = existingByRule?.createdAtEpochMs ?: nowEpochMs
        )
        return NotificationResolutionResult.Resolved(resolvedItem)
    }

    private suspend fun resolveVerifiedBackgroundTask(
        taskId: String,
        expectedRequestId: String?,
        nowEpochMs: Long
    ): NotificationResolutionResult {
        val existingByTask = findByTaskId(taskId)
        if (existingByTask != null) {
            if (!expectedRequestId.isNullOrBlank() && existingByTask.requestId != expectedRequestId) {
                return NotificationResolutionResult.Rejected(REASON_MISMATCHED_EXTRAS)
            }
            val token = existingByTask.capabilityToken
            if (token == null || token.isExpired(nowEpochMs)) {
                dismiss(existingByTask.requestId)
                return NotificationResolutionResult.Rejected(REASON_CAPABILITY_TOKEN_EXPIRED)
            }
            promoteToActive(existingByTask.requestId)
            return NotificationResolutionResult.Resolved(existingByTask)
        }

        if (!expectedRequestId.isNullOrBlank()) {
            val existingByReq = findByRequestId(expectedRequestId)
            if (existingByReq != null && existingByReq.taskId != taskId) {
                return NotificationResolutionResult.Rejected(REASON_MISMATCHED_EXTRAS)
            }
        }

        val bgManager = backgroundTaskManagerProvider()
            ?: return NotificationResolutionResult.Rejected(REASON_UNREGISTERED_TASK)

        val bgRequest = bgManager.getRequest(taskId) as? BackgroundTaskRequest.PlanContinuation
            ?: return NotificationResolutionResult.Rejected(REASON_UNREGISTERED_TASK)

        val bgOutcome = bgManager.getOutcome(taskId) as? BackgroundTaskOutcome.ConfirmationRequired
            ?: return NotificationResolutionResult.Rejected(REASON_UNREGISTERED_TASK)

        if (bgRequest.capabilityToken.isExpired(nowEpochMs)) {
            return NotificationResolutionResult.Rejected(REASON_CAPABILITY_TOKEN_EXPIRED)
        }

        val effectiveRequestId = expectedRequestId?.takeIf { it.isNotBlank() }
            ?: bgRequest.capabilityToken.requestId

        val registered = registerBackgroundTaskConfirmation(
            taskId = taskId,
            request = bgRequest,
            confirmation = bgOutcome.pendingConfirmation,
            requestId = effectiveRequestId,
            nowEpochMs = nowEpochMs
        )
        return NotificationResolutionResult.Resolved(registered)
    }

    private fun promoteToActive(requestId: String) {
        synchronized(stateLock) {
            if (requestId in itemsByRequestId) {
                activeRequestId = requestId
                publishStateLocked()
            }
        }
    }

    private fun publishStateLocked() {
        val listSnapshot = itemsByRequestId.values.toList()
        _pendingItemsFlow.value = listSnapshot
        val active = activeRequestId?.let { itemsByRequestId[it] } ?: listSnapshot.lastOrNull()
        activeRequestId = active?.requestId
        _activeConfirmationFlow.value = active
    }

    companion object {
        const val REASON_INVALID_OR_FORGED_EXTRAS: String = "INVALID_OR_FORGED_EXTRAS"
        const val REASON_MISSING_IDENTIFIERS: String = "MISSING_IDENTIFIERS"
        const val REASON_MISMATCHED_EXTRAS: String = "MISMATCHED_EXTRAS"
        const val REASON_UNREGISTERED_REQUEST: String = "UNREGISTERED_REQUEST"
        const val REASON_UNREGISTERED_TASK: String = "UNREGISTERED_TASK"
        const val REASON_RULE_NOT_VERIFIED: String = "RULE_NOT_VERIFIED"
        const val REASON_CAPABILITY_TOKEN_EXPIRED: String = "CAPABILITY_TOKEN_EXPIRED"

        private fun grantRequiresBiometric(grant: RuleCapabilityGrant): Boolean {
            return grant.staticActions.any { action ->
                action.requiresBiometric || action.toolName in AutomationToolNames.VAULT_TOOLS
            }
        }
    }
}

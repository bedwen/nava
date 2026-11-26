package com.nava.app.ui.routines

import androidx.lifecycle.ViewModel
import com.nava.app.di.AppContainer
import com.nava.domain.automation.MorningBriefingConfig
import com.nava.domain.automation.NotificationWatcher
import com.nava.domain.automation.ReminderStatus
import com.nava.domain.automation.RoutineExecutionOutcome
import com.nava.domain.automation.ScheduledReminder
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleTriggerSpec
import com.nava.feature.automations.common.AutomationToolNames
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * Pure-JVM presentation model for a Routine Consent Card (PLAN.md Section 5.6 & Requirement 7).
 */
data class RoutineConsentCardModel(
    val grant: RuleCapabilityGrant,
    val ruleId: String,
    val triggerType: String,
    val triggerParameters: Map<String, String>,
    val staticActions: List<RuleActionSpec>,
    val requiresInteractiveEscalationWarning: Boolean,
    val nonUnattendedActionNames: List<String>
)

/**
 * Builds a [RoutineConsentCardModel] evaluating whether any action in [grant] requires
 * interactive confirmation (`Biometric`, `Nava Vault`, or [AtomicCapability.MODIFY_DELETE_SEND]).
 */
fun buildRoutineConsentCardModel(grant: RuleCapabilityGrant): RoutineConsentCardModel {
    val nonUnattended = grant.staticActions
        .filter { action ->
            action.requiresInteractiveConfirmation ||
                action.requiresBiometric ||
                action.requiredCapability == AtomicCapability.MODIFY_DELETE_SEND ||
                action.toolName in AutomationToolNames.VAULT_TOOLS
        }
        .map { it.toolName }

    return RoutineConsentCardModel(
        grant = grant,
        ruleId = grant.ruleId,
        triggerType = grant.triggerSpec.triggerType,
        triggerParameters = grant.triggerSpec.parameters,
        staticActions = grant.staticActions,
        requiresInteractiveEscalationWarning = grant.requiresInteractiveUpgrade || nonUnattended.isNotEmpty(),
        nonUnattendedActionNames = nonUnattended
    )
}

/**
 * Immutable MVI state for the Automations & Routines screen (PLAN.md Section 5.6).
 */
data class RoutinesUiState(
    val allRules: List<RuleCapabilityGrant> = emptyList(),
    val pendingApprovalRules: List<RuleCapabilityGrant> = emptyList(),
    val activeRules: List<RuleCapabilityGrant> = emptyList(),
    val pausedRules: List<RuleCapabilityGrant> = emptyList(),
    val revokedRules: List<RuleCapabilityGrant> = emptyList(),
    val consentCards: List<RoutineConsentCardModel> = emptyList(),
    val isGlobalPaused: Boolean = false,
    val morningBriefingConfig: MorningBriefingConfig = MorningBriefingConfig(),
    val activeReminders: List<ScheduledReminder> = emptyList(),
    val notificationWatchers: List<NotificationWatcher> = emptyList(),
    /** Today's permission-filtered calendar, reminders and urgent notifications for My Day. */
    val todayOverview: com.nava.feature.automations.briefing.DailyBriefingResult? = null,
    /** Facts the user asked Nava to remember, newest first. */
    val personalFacts: List<com.nava.domain.memory.PersonalFact> = emptyList(),
    val lastExecutionOutcome: RoutineExecutionOutcome? = null,
    val statusMessage: String? = null,
    val errorMessage: String? = null
)

/**
 * MVI ViewModel managing compile-time user-approved [RuleCapabilityGrant] lifecycles,
 * Routine Consent Cards, single-tap Approve / Pause / Revoke actions, and the Global Pause switch.
 */
class RoutinesViewModel(
    private val container: AppContainer,
    private val dispatcher: CoroutineDispatcher = Dispatchers.Default,
    private val clockMs: () -> Long = System::currentTimeMillis
) : ViewModel() {

    private val vmScope = CoroutineScope(SupervisorJob() + dispatcher)

    private val _uiState = MutableStateFlow(
        RoutinesUiState(
            isGlobalPaused = container.ruleCapabilityGrantManager.isGlobalRulesPaused(),
            morningBriefingConfig = container.morningBriefingPreferencesStore.currentConfig()
        )
    )
    val uiState: StateFlow<RoutinesUiState> = _uiState.asStateFlow()

    init {
        refreshRules()
    }

    fun refreshRules() {
        vmScope.launch {
            val rules = container.compileRuleUseCase.listRules()
                .sortedBy { it.ruleId }
            val pending = rules.filter { it.approvalState == RuleApprovalState.PENDING_USER_APPROVAL }
            val active = rules.filter { it.approvalState == RuleApprovalState.APPROVED_ACTIVE }
            val paused = rules.filter { it.approvalState == RuleApprovalState.PAUSED }
            val revoked = rules.filter { it.approvalState == RuleApprovalState.REVOKED }
            val consentModels = rules.map(::buildRoutineConsentCardModel)
            val globalPaused = container.ruleCapabilityGrantManager.isGlobalRulesPaused()
            val activeReminders = container.scheduledReminderDao.listActiveReminders()
            val briefingConfig = container.morningBriefingPreferencesStore.currentConfig()
            val watchers = runCatching { container.notificationWatcherPort.listWatchers() }
                .getOrDefault(emptyList())
            // Always build the full view (independent of the morning-briefing toggles); the
            // builder still applies each source's permission profile.
            val today = runCatching {
                container.dailyBriefingBuilder.buildBriefing(
                    nowEpochMs = clockMs(),
                    config = MorningBriefingConfig(enabled = true)
                )
            }.getOrNull()
            val facts = runCatching { container.personalFactDao.listFacts() }.getOrDefault(emptyList())

            _uiState.update { state ->
                state.copy(
                    allRules = rules,
                    pendingApprovalRules = pending,
                    activeRules = active,
                    pausedRules = paused,
                    revokedRules = revoked,
                    todayOverview = today,
                    personalFacts = facts,
                    consentCards = consentModels,
                    isGlobalPaused = globalPaused,
                    morningBriefingConfig = briefingConfig,
                    activeReminders = activeReminders,
                    notificationWatchers = watchers
                )
            }
        }
    }

    fun createNotificationWatcher(
        label: String,
        keywordsRaw: String,
        sender: String,
        appFilter: String
    ) {
        val keywords = keywordsRaw
            .split(',', ';', '|')
            .map { com.nava.domain.security.Gemma4InputSanitizer.sanitize(it).trim() }
            .filter { it.isNotEmpty() }
            .distinct()
            .take(10)
        val cleanSender = com.nava.domain.security.Gemma4InputSanitizer.sanitize(sender)
            .trim().takeIf { it.isNotEmpty() }
        val cleanApp = com.nava.domain.security.Gemma4InputSanitizer.sanitize(appFilter)
            .trim().takeIf { it.isNotEmpty() }
        if (keywords.isEmpty() && cleanSender == null) return

        val cleanLabel = com.nava.domain.security.Gemma4InputSanitizer.sanitize(label)
            .trim()
            .ifBlank {
                listOfNotNull(
                    cleanSender,
                    keywords.take(3).joinToString(", ").takeIf { it.isNotEmpty() }
                ).joinToString(" - ")
            }
            .take(60)
        vmScope.launch {
            val now = clockMs()
            val watcher = NotificationWatcher(
                watcherId = "watch_${java.util.UUID.randomUUID().toString().replace("-", "").take(12)}",
                label = cleanLabel,
                keywords = keywords,
                senderFilter = cleanSender,
                packageFilter = cleanApp,
                enabled = true,
                createdAtEpochMs = now
            )
            container.notificationWatcherPort.saveWatcher(watcher)
            refreshRules()
        }
    }

    fun setNotificationWatcherEnabled(watcherId: String, enabled: Boolean) {
        vmScope.launch {
            container.notificationWatcherPort.setWatcherEnabled(watcherId, enabled)
            refreshRules()
        }
    }

    /** Deletes one remembered fact by direct user action on My Day, and audits it. */
    fun forgetPersonalFact(factId: String) {
        vmScope.launch {
            val removed = runCatching { container.personalFactDao.deleteFact(factId) }.getOrDefault(false)
            if (removed) {
                container.auditLogDao.record(
                    com.nava.domain.security.AuditLogEntry(
                        timestampEpochMs = clockMs(),
                        toolName = com.nava.feature.automations.common.AutomationToolNames.FORGET_FACT,
                        targetId = com.nava.feature.automations.common.ToolTargetIds.MEMORY,
                        actionSummary = "Forgot a personal fact from My Day",
                        provenance = DataProvenance.USER_UTTERANCE,
                        decision = "SUCCESS"
                    )
                )
            }
            refreshRules()
        }
    }

    fun deleteNotificationWatcher(watcherId: String) {
        vmScope.launch {
            container.notificationWatcherPort.deleteWatcher(watcherId)
            refreshRules()
        }
    }

    /**
     * Compiles a new routine into [RuleApprovalState.PENDING_USER_APPROVAL] via `CompileRuleUseCase`.
     */
    fun compilePendingRule(
        ruleId: String,
        triggerSpec: RuleTriggerSpec,
        staticActions: List<RuleActionSpec>
    ) {
        vmScope.launch {
            try {
                container.compileRuleUseCase.compilePendingRule(
                    ruleId = ruleId,
                    triggerSpec = triggerSpec,
                    staticActions = staticActions,
                    nowEpochMs = clockMs(),
                    provenance = DataProvenance.USER_UTTERANCE
                )
                _uiState.update { it.copy(errorMessage = null) }
                refreshRules()
            } catch (e: Exception) {
                _uiState.update { it.copy(errorMessage = e.message ?: "Failed to compile routine") }
            }
        }
    }

    /**
     * Single-tap Approve: Mints an `HMAC-SHA256` sealed [RuleCapabilityGrant] via
     * `CompileRuleUseCase.approvePendingRule` and schedules it in `RoutineExecutorPort`
     * (unless globally paused).
     */
    fun approveRule(ruleId: String) {
        vmScope.launch {
            try {
                val approved = container.compileRuleUseCase.approvePendingRule(
                    ruleId = ruleId,
                    nowEpochMs = clockMs()
                )
                if (!container.ruleCapabilityGrantManager.isGlobalRulesPaused()) {
                    container.routineExecutor.scheduleRule(approved)
                }
                _uiState.update { it.copy(errorMessage = null) }
                refreshRules()
            } catch (e: Exception) {
                _uiState.update { it.copy(errorMessage = e.message ?: "Failed to approve routine") }
            }
        }
    }

    /**
     * Single-tap Pause: Transitions [ruleId] to [RuleApprovalState.PAUSED] and cancels its
     * background schedule in `RoutineExecutorPort`.
     */
    fun pauseRule(ruleId: String) {
        vmScope.launch {
            try {
                container.compileRuleUseCase.pauseRule(
                    ruleId = ruleId,
                    nowEpochMs = clockMs()
                )
                container.routineExecutor.cancelRule(ruleId)
                _uiState.update { it.copy(errorMessage = null) }
                refreshRules()
            } catch (e: Exception) {
                _uiState.update { it.copy(errorMessage = e.message ?: "Failed to pause routine") }
            }
        }
    }

    /**
     * Single-tap Revoke: Permanently revokes [ruleId] (wiping its HMAC seal) and cancels its
     * background schedule in `RoutineExecutorPort`.
     */
    fun revokeRule(ruleId: String) {
        vmScope.launch {
            try {
                container.compileRuleUseCase.revokeRule(
                    ruleId = ruleId,
                    nowEpochMs = clockMs()
                )
                container.routineExecutor.cancelRule(ruleId)
                _uiState.update { it.copy(errorMessage = null) }
                refreshRules()
            } catch (e: Exception) {
                _uiState.update { it.copy(errorMessage = e.message ?: "Failed to revoke routine") }
            }
        }
    }

    /**
     * Executes [ruleId] immediately via `RoutineExecutorPort.executeRule`.
     */
    fun runRuleNow(ruleId: String) {
        vmScope.launch {
            val now = clockMs()
            val localeTag = container.appLocaleManager.currentLocaleTag()
            val outcome = container.routineExecutor.executeRule(
                ruleId = ruleId,
                nowEpochMs = now,
                languageTag = localeTag
            )
            if (outcome is RoutineExecutionOutcome.EscalatedToInteractive) {
                val persistedGrant = container.ruleCapabilityGrantManager.findRule(ruleId)
                if (persistedGrant != null &&
                    persistedGrant.approvalState == RuleApprovalState.APPROVED_ACTIVE &&
                    persistedGrant.sealHmacHex.isNotBlank()
                ) {
                    container.pendingConfirmationStore.registerEscalatedRoutineConfirmation(
                        grant = persistedGrant,
                        requiresBiometric = outcome.requiresBiometric,
                        languageTag = localeTag,
                        nowEpochMs = now
                    )
                }
            }
            val locale = container.appLocaleManager.currentLocale()
            val (_, body) = container.messageRenderer.render(outcome.message, locale)
            _uiState.update { state ->
                state.copy(
                    lastExecutionOutcome = outcome,
                    statusMessage = body,
                    errorMessage = null
                )
            }
        }
    }

    /**
     * Toggles the Global Pause switch across `RuleCapabilityGrantManager` and `RoutineExecutorPort`
     * (Requirement 7):
     * - When [paused] is `true`, sets `setGlobalRulesPaused(true)`, `routineExecutor.setGloballyPaused(true)`,
     *   and calls `routineExecutor.cancelAllRules()`.
     * - When [paused] is `false`, clears the global pause flag and re-schedules all currently
     *   [RuleApprovalState.APPROVED_ACTIVE] routines.
     */
    fun setGlobalRulesPaused(paused: Boolean) {
        vmScope.launch {
            container.ruleCapabilityGrantManager.setGlobalRulesPaused(paused)
            container.routineExecutor.setGloballyPaused(paused)
            if (paused) {
                container.routineExecutor.cancelAllRules()
            } else {
                val activeGrants = container.compileRuleUseCase.listRules()
                    .filter { it.approvalState == RuleApprovalState.APPROVED_ACTIVE }
                for (grant in activeGrants) {
                    container.routineExecutor.scheduleRule(grant)
                }
            }
            _uiState.update { state ->
                state.copy(isGlobalPaused = paused, errorMessage = null)
            }
            refreshRules()
        }
    }

    fun setMorningBriefingEnabled(enabled: Boolean) {
        val updated = container.morningBriefingPreferencesStore.updateConfig { it.copy(enabled = enabled) }
        val scheduleError: String? = if (enabled) {
            val scheduledAt = container.reminderAlarmScheduler.scheduleMorningBriefing(
                hour = updated.hour,
                minute = updated.minute,
                nowEpochMs = clockMs()
            )
            if (scheduledAt == null) "Unable to schedule Morning Briefing alarm" else null
        } else {
            container.reminderAlarmScheduler.cancelMorningBriefing()
            null
        }
        _uiState.update { it.copy(morningBriefingConfig = updated, errorMessage = scheduleError) }
    }

    fun setMorningBriefingTime(hour: Int, minute: Int) {
        val normalizedHour = ((hour % 24) + 24) % 24
        val normalizedMinute = ((minute % 60) + 60) % 60
        val updated = container.morningBriefingPreferencesStore.updateConfig {
            it.copy(hour = normalizedHour, minute = normalizedMinute)
        }
        val scheduleError: String? = if (updated.enabled) {
            val scheduledAt = container.reminderAlarmScheduler.scheduleMorningBriefing(
                hour = updated.hour,
                minute = updated.minute,
                nowEpochMs = clockMs()
            )
            if (scheduledAt == null) "Unable to reschedule Morning Briefing alarm" else null
        } else {
            null
        }
        _uiState.update { it.copy(morningBriefingConfig = updated, errorMessage = scheduleError) }
    }

    fun setMorningBriefingAiSummary(enabled: Boolean) {
        val updated = container.morningBriefingPreferencesStore.updateConfig {
            it.copy(aiSummaryEnabled = enabled)
        }
        _uiState.update { it.copy(morningBriefingConfig = updated, errorMessage = null) }
    }

    fun setMorningBriefingSources(
        includeCalendar: Boolean? = null,
        includeNotifications: Boolean? = null,
        includeReminders: Boolean? = null
    ) {
        val updated = container.morningBriefingPreferencesStore.updateConfig { current ->
            current.copy(
                includeCalendar = includeCalendar ?: current.includeCalendar,
                includeNotifications = includeNotifications ?: current.includeNotifications,
                includeReminders = includeReminders ?: current.includeReminders
            )
        }
        _uiState.update { it.copy(morningBriefingConfig = updated, errorMessage = null) }
    }

    fun completeReminder(reminderId: String) {
        vmScope.launch {
            container.scheduledReminderDao.updateStatus(
                reminderId = reminderId,
                status = ReminderStatus.COMPLETED,
                updatedAtEpochMs = clockMs()
            )
            container.reminderAlarmScheduler.cancelReminder(reminderId)
            refreshRules()
        }
    }

    fun cancelReminder(reminderId: String) {
        vmScope.launch {
            container.scheduledReminderDao.updateStatus(
                reminderId = reminderId,
                status = ReminderStatus.CANCELLED,
                updatedAtEpochMs = clockMs()
            )
            container.reminderAlarmScheduler.cancelReminder(reminderId)
            refreshRules()
        }
    }

    override fun onCleared() {
        super.onCleared()
        vmScope.cancel()
    }
}

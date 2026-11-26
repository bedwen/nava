package com.nava.app.ui.settings

import android.provider.Settings
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import com.nava.app.di.AppContainer
import com.nava.app.di.ModelQualitySuggestion
import com.nava.app.di.PinnedModelCatalog
import com.nava.app.di.PinnedModelRole
import com.nava.app.reminders.ReminderNotificationPoster
import com.nava.app.security.BiometricPromptLabels
import com.nava.app.security.VaultUnlockResult
import com.nava.domain.ai.PinnedModelSpec
import com.nava.domain.ai.ProvisionedModelInfo
import com.nava.domain.ai.RamTier
import com.nava.domain.automation.BackgroundTaskOutcome
import com.nava.domain.automation.BackgroundTaskRequest
import com.nava.domain.automation.BackgroundTaskStatus
import com.nava.domain.locale.LanguageEntry
import com.nava.domain.security.AuditLogEntry
import java.io.File
import java.util.Locale
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * Filter modes for the full Security Audit Log viewer in Settings (Requirement 8).
 */
enum class AuditLogFilter {
    ALL,
    DENIED_ONLY
}

/**
 * Pure-JVM descriptor of Android system integration settings actions (Requirement 8).
 */
enum class SystemIntegrationTarget(
    val roleOrSettingId: String,
    val fallbackSettingsAction: String
) {
    ASSISTANT_ROLE(
        roleOrSettingId = "android.app.role.ASSISTANT",
        fallbackSettingsAction = Settings.ACTION_VOICE_INPUT_SETTINGS
    ),
    NOTIFICATION_LISTENER(
        roleOrSettingId = Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS,
        fallbackSettingsAction = Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS
    ),
    NOTIFICATION_POLICY_ACCESS(
        roleOrSettingId = Settings.ACTION_NOTIFICATION_POLICY_ACCESS_SETTINGS,
        fallbackSettingsAction = Settings.ACTION_NOTIFICATION_POLICY_ACCESS_SETTINGS
    )
}

/**
 * Immutable MVI state for the Settings screen (PLAN.md Sections 2.3, 4.3, 5.2, 6.1, and 6.4).
 */
data class SettingsUiState(
    val activeLocaleTag: String = "en",
    val languageSearchQuery: String = "",
    val allLanguages: List<LanguageEntry> = emptyList(),
    val filteredLanguages: List<LanguageEntry> = emptyList(),
    val ramTier: RamTier = RamTier.TIER_1_STANDARD,
    val showTier0LowMemoryNotice: Boolean = false,
    val qualitySuggestion: ModelQualitySuggestion? = null,
    val selectedModelId: String? = null,
    val selectedFunctionModelId: String? = null,
    val selectedEmbeddingModelId: String? = null,
    val isFunctionRouterEnabled: Boolean = true,
    val isSemanticEmbeddingEnabled: Boolean = true,
    val targetImportSpec: PinnedModelSpec = PinnedModelCatalog.GEMMA_4_E2B_SPEC,
    val provisionedModels: List<ProvisionedModelInfo> = emptyList(),
    val modelVerificationStatus: Map<String, Boolean> = emptyMap(),
    val enqueuedImportTaskId: String? = null,
    val isImportingModel: Boolean = false,
    val runtimeDiagnostic: String? = null,
    val isVaultUnlocked: Boolean = false,
    val lastVaultUnlockError: String? = null,
    val auditFilter: AuditLogFilter = AuditLogFilter.ALL,
    val allAuditEntries: List<AuditLogEntry> = emptyList(),
    val filteredAuditEntries: List<AuditLogEntry> = emptyList(),
    val isNotificationListenerEnabled: Boolean = false,
    val isNotificationPolicyAccessGranted: Boolean = false,
    val isPostNotificationsGranted: Boolean = true,
    val testNotificationStatus: Boolean? = null,
    val lastRequestedSystemTarget: SystemIntegrationTarget? = null,
    val errorMessage: String? = null
)

/**
 * MVI ViewModel for Settings:
 * - Searchable data-driven language picker over `SupportedLanguageCatalog` + `AppLocaleManager`.
 * - Provisioned `.litertlm` model list, SHA-256 integrity verification, deletion, and SAF import.
 * - Nava Vault biometric unlock / immediate zeroization lock controls.
 * - System integration action triggers (`ROLE_ASSISTANT`, Notification Listener, Notification Policy Access).
 * - Full Audit Log viewer with `ALL` vs `DENIED_ONLY` filter.
 */
class SettingsViewModel(
    private val container: AppContainer,
    private val dispatcher: CoroutineDispatcher = Dispatchers.Default,
    private val clockMs: () -> Long = System::currentTimeMillis
) : ViewModel() {

    private val vmScope = CoroutineScope(SupervisorJob() + dispatcher)

    @Volatile
    private var activeRefreshJob: Job? = null

    private val _uiState = MutableStateFlow(createInitialState())
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

    init {
        observeContainerState()
        refreshAll()
    }

    suspend fun awaitRefresh() {
        activeRefreshJob?.join()
    }

    fun clearForTesting() {
        onCleared()
    }

    private fun createInitialState(): SettingsUiState {
        val ramTier = runCatching {
            container.thermalModelLifecycleManager.currentRamTier()
        }.getOrDefault(RamTier.TIER_1_STANDARD)
        val recommendedSpec = PinnedModelCatalog.recommendedSpecForRamTier(ramTier)
        val onboardingState = container.onboardingStateStore.currentState()
        val isPostNotifGranted = runCatching {
            container.intentGateway.canPostNotifications()
        }.getOrDefault(true)
        return SettingsUiState(
            activeLocaleTag = container.appLocaleManager.currentLocaleTag(),
            ramTier = ramTier,
            showTier0LowMemoryNotice = ramTier == RamTier.TIER_0_LOW_MEMORY,
            selectedModelId = onboardingState.selectedModelId,
            selectedFunctionModelId = onboardingState.selectedFunctionModelId,
            selectedEmbeddingModelId = onboardingState.selectedEmbeddingModelId,
            targetImportSpec = PinnedModelCatalog.findByModelId(onboardingState.selectedModelId) ?: recommendedSpec,
            isVaultUnlocked = container.vaultBiometricController.isVaultUnlockedFlow.value,
            isNotificationListenerEnabled = runCatching {
                container.intentGateway.isNotificationListenerEnabled()
            }.getOrDefault(false),
            isNotificationPolicyAccessGranted = runCatching {
                container.intentGateway.isNotificationPolicyAccessGranted()
            }.getOrDefault(false),
            isPostNotificationsGranted = isPostNotifGranted
        )
    }

    private fun observeContainerState() {
        vmScope.launch {
            container.appLocaleManager.activeLocaleTagFlow.collect { tag ->
                _uiState.update { it.copy(activeLocaleTag = tag) }
                refreshQualitySuggestion(tag)
            }
        }
        vmScope.launch {
            container.vaultBiometricController.isVaultUnlockedFlow.collect { unlocked ->
                _uiState.update { it.copy(isVaultUnlocked = unlocked) }
            }
        }
    }

    fun refreshAll(): Job {
        val job = vmScope.launch {
            val languages = container.appLocaleManager.availableLanguages()
            val localeTag = container.appLocaleManager.currentLocaleTag()
            val ramTier = container.thermalModelLifecycleManager.currentRamTier()
            val provisioned = container.safModelProvisioner.listProvisionedModels()
            val onboardingState = container.onboardingStateStore.currentState()
            val vaultUnlocked = container.vaultBiometricController.refreshUnlockState()
            val auditEntries = container.auditLogDao.queryRecent(DEFAULT_AUDIT_LOG_LIMIT)
            val isNotifListenerEnabled = runCatching {
                container.intentGateway.isNotificationListenerEnabled()
            }.getOrDefault(false)
            val isNotifPolicyGranted = runCatching {
                container.intentGateway.isNotificationPolicyAccessGranted()
            }.getOrDefault(false)
            val isPostNotifGranted = runCatching {
                container.intentGateway.canPostNotifications()
            }.getOrDefault(true)

            _uiState.update { state ->
                state.copy(
                    activeLocaleTag = localeTag,
                    allLanguages = languages,
                    filteredLanguages = filterLanguages(languages, state.languageSearchQuery),
                    ramTier = ramTier,
                    showTier0LowMemoryNotice = ramTier == RamTier.TIER_0_LOW_MEMORY,
                    selectedModelId = onboardingState.selectedModelId,
                    selectedFunctionModelId = onboardingState.selectedFunctionModelId,
                    selectedEmbeddingModelId = onboardingState.selectedEmbeddingModelId,
                    isFunctionRouterEnabled = container.isFunctionRouterEnabled(),
                    isSemanticEmbeddingEnabled = container.isSemanticEmbeddingEnabled(),
                    provisionedModels = provisioned,
                    runtimeDiagnostic = container.liteRtLlmEngine.lastRuntimeDiagnostic(),
                    isVaultUnlocked = vaultUnlocked,
                    allAuditEntries = auditEntries,
                    filteredAuditEntries = filterAuditEntries(auditEntries, state.auditFilter),
                    isNotificationListenerEnabled = isNotifListenerEnabled,
                    isNotificationPolicyAccessGranted = isNotifPolicyGranted,
                    isPostNotificationsGranted = isPostNotifGranted
                )
            }
            refreshQualitySuggestion(localeTag)
        }
        activeRefreshJob = job
        return job
    }

    fun setFunctionRouterEnabled(enabled: Boolean) {
        _uiState.update { it.copy(isFunctionRouterEnabled = enabled) }
        vmScope.launch {
            container.setFunctionRouterEnabled(enabled)
        }
    }

    fun setSemanticEmbeddingEnabled(enabled: Boolean) {
        _uiState.update { it.copy(isSemanticEmbeddingEnabled = enabled) }
        vmScope.launch {
            container.setSemanticEmbeddingEnabled(enabled)
        }
    }

    private suspend fun refreshQualitySuggestion(localeTag: String) {
        val ramTier = container.thermalModelLifecycleManager.currentRamTier()
        val effectiveModelId = container.onboardingStateStore.getSelectedModelId()
            ?: PinnedModelCatalog.recommendedSpecForRamTier(ramTier).modelId
        val suggestion = PinnedModelCatalog.evaluateQualitySuggestion(
            activeModelId = effectiveModelId,
            ramTier = ramTier,
            activeLanguageTag = localeTag,
            catalog = container.supportedLanguageCatalog
        )
        _uiState.update { it.copy(qualitySuggestion = suggestion) }
    }

    /**
     * Filters the [SupportedLanguageCatalog] language picker by [query] (100% data-driven,
     * zero hardcoded language lists).
     */
    fun onLanguageSearchQueryChanged(query: String) {
        _uiState.update { state ->
            state.copy(
                languageSearchQuery = query,
                filteredLanguages = filterLanguages(state.allLanguages, query)
            )
        }
    }

    /**
     * Switches the application's active locale via [AppLocaleManager.setApplicationLocale].
     */
    fun selectLanguage(bcp47Tag: String): Job {
        return vmScope.launch {
            val resolved = container.appLocaleManager.setApplicationLocale(bcp47Tag)
            _uiState.update { it.copy(activeLocaleTag = resolved, errorMessage = null) }
            refreshQualitySuggestion(resolved)
        }
    }

    /**
     * Selects the target [PinnedModelSpec] for SAF `.litertlm` model import.
     */
    fun selectTargetImportSpec(spec: PinnedModelSpec) {
        _uiState.update { it.copy(targetImportSpec = spec, errorMessage = null) }
    }

    /**
     * Selects an already-provisioned `.litertlm` model by [modelId] as the active model in
     * `OnboardingStateStore`, routed to the appropriate role slot.
     */
    fun selectActiveModel(modelId: String): Job {
        return vmScope.launch {
            try {
                val role = PinnedModelCatalog.roleForModelId(modelId)
                when (role) {
                    PinnedModelRole.PRIMARY_LLM -> {
                        val updated = container.onboardingStateStore.setSelectedModelId(modelId)
                        _uiState.update {
                            it.copy(
                                selectedModelId = updated.selectedModelId,
                                errorMessage = null
                            )
                        }
                        refreshQualitySuggestion(_uiState.value.activeLocaleTag)
                    }
                    PinnedModelRole.FUNCTION_ROUTER -> {
                        val updated = container.onboardingStateStore.setSelectedFunctionModelId(modelId)
                        _uiState.update {
                            it.copy(
                                selectedFunctionModelId = updated.selectedFunctionModelId,
                                errorMessage = null
                            )
                        }
                    }
                    PinnedModelRole.SEMANTIC_EMBEDDING -> {
                        val updated = container.onboardingStateStore.setSelectedEmbeddingModelId(modelId)
                        _uiState.update {
                            it.copy(
                                selectedEmbeddingModelId = updated.selectedEmbeddingModelId,
                                errorMessage = null
                            )
                        }
                    }
                }
            } catch (e: Exception) {
                _uiState.update { it.copy(errorMessage = e.message ?: "Invalid model ID") }
            }
        }
    }

    /**
     * Enqueues an offline SAF `.litertlm` model import continuation task via
     * `BackgroundTaskContinuationPort`.
     */
    fun enqueueSafModelImport(
        sourceUri: String,
        spec: PinnedModelSpec = _uiState.value.targetImportSpec
    ) {
        val trimmedUri = sourceUri.trim()
        if (trimmedUri.isEmpty()) {
            _uiState.update { it.copy(errorMessage = "SAF model URI must not be blank") }
            return
        }
        val now = clockMs()
        val taskId = "settings_model_import:${spec.modelId}:$now"
        val request = BackgroundTaskRequest.ModelImportContinuation(
            taskId = taskId,
            sourceUri = trimmedUri,
            expectedModelId = spec.modelId,
            expectedSha256Hex = spec.expectedSha256Hex,
            languageTag = container.appLocaleManager.currentLocaleTag(),
            enqueuedAtEpochMs = now
        )
        vmScope.launch {
            _uiState.update { it.copy(isImportingModel = true, errorMessage = null) }
            val enqueuedId = container.backgroundTaskContinuationManager.enqueue(request)
            _uiState.update { state ->
                state.copy(
                    enqueuedImportTaskId = enqueuedId,
                    errorMessage = null
                )
            }
            // Observe WorkManager import status while Settings is open so the UI reflects
            // completion or failure cleanly without blocking the UI thread.
            var attempts = 0
            while (attempts < 600) {
                delay(500L)
                attempts += 1
                val status = container.backgroundTaskContinuationManager.getStatus(enqueuedId)
                if (status == BackgroundTaskStatus.COMPLETED ||
                    status == BackgroundTaskStatus.FAILED ||
                    status == BackgroundTaskStatus.CANCELLED
                ) {
                    val outcome = container.backgroundTaskContinuationManager.getOutcome(enqueuedId)
                    val failureMessage = if (outcome is BackgroundTaskOutcome.Failed) {
                        val locale = container.appLocaleManager.currentLocale()
                        container.messageRenderer.render(outcome.message, locale).second
                    } else {
                        null
                    }
                    _uiState.update { state ->
                        state.copy(
                            isImportingModel = false,
                            errorMessage = failureMessage
                        )
                    }
                    refreshAll()
                    break
                }
            }
            if (_uiState.value.isImportingModel) {
                _uiState.update { it.copy(isImportingModel = false) }
                refreshAll()
            }
        }
    }

    /**
     * Verifies the streaming SHA-256 digest of a provisioned `.litertlm` model file against its
     * pinned digest in [PinnedModelCatalog].
     */
    fun verifyProvisionedModel(fileName: String): Job {
        return vmScope.launch {
            val spec = PinnedModelCatalog.findByFileName(fileName)
            val modelsDir = File(container.safModelProvisioner.modelsDirectoryPath())
            val candidateFile = File(modelsDir, fileName)
            val isValid = if (spec != null) {
                container.safModelProvisioner.verifyFileIntegrity(
                    absolutePath = candidateFile.absolutePath,
                    expectedSha256Hex = spec.expectedSha256Hex
                )
            } else {
                false
            }
            _uiState.update { state ->
                val updatedMap = LinkedHashMap(state.modelVerificationStatus)
                updatedMap[fileName] = isValid
                state.copy(modelVerificationStatus = updatedMap)
            }
        }
    }

    /**
     * Deletes a provisioned `.litertlm` model file from app-private storage (`filesDir/models/`).
     */
    fun deleteProvisionedModel(fileName: String): Job {
        return vmScope.launch {
            val deleted = container.safModelProvisioner.deleteProvisionedModel(fileName)
            if (deleted) {
                val deletedModelId = PinnedModelCatalog.findByFileName(fileName)?.modelId
                    ?: fileName.removeSuffix(".litertlm")
                val role = PinnedModelCatalog.roleForModelId(deletedModelId)
                when (role) {
                    PinnedModelRole.PRIMARY_LLM -> {
                        if (_uiState.value.selectedModelId.equals(deletedModelId, ignoreCase = true)) {
                            container.onboardingStateStore.setSelectedModelId(null)
                        }
                    }
                    PinnedModelRole.FUNCTION_ROUTER -> {
                        if (_uiState.value.selectedFunctionModelId.equals(deletedModelId, ignoreCase = true)) {
                            container.onboardingStateStore.setSelectedFunctionModelId(null)
                        }
                    }
                    PinnedModelRole.SEMANTIC_EMBEDDING -> {
                        if (_uiState.value.selectedEmbeddingModelId.equals(deletedModelId, ignoreCase = true)) {
                            container.onboardingStateStore.setSelectedEmbeddingModelId(null)
                        }
                    }
                }
            }
            val provisioned = container.safModelProvisioner.listProvisionedModels()
            val onboardingState = container.onboardingStateStore.currentState()
            _uiState.update { state ->
                val updatedMap = LinkedHashMap(state.modelVerificationStatus)
                updatedMap.remove(fileName)
                state.copy(
                    provisionedModels = provisioned,
                    selectedModelId = onboardingState.selectedModelId,
                    selectedFunctionModelId = onboardingState.selectedFunctionModelId,
                    selectedEmbeddingModelId = onboardingState.selectedEmbeddingModelId,
                    isFunctionRouterEnabled = container.isFunctionRouterEnabled(),
                    isSemanticEmbeddingEnabled = container.isSemanticEmbeddingEnabled(),
                    modelVerificationStatus = updatedMap
                )
            }
        }
    }

    /**
     * Posts a localized test notification on the reminders channel to verify notification delivery.
     */
    fun sendTestNotification() {
        vmScope.launch {
            val ctx = container.appContext
            val status = if (ctx != null) {
                ReminderNotificationPoster.postTestNotification(ctx)
            } else {
                false
            }
            val isPostGranted = runCatching {
                container.intentGateway.canPostNotifications()
            }.getOrDefault(true)
            _uiState.update {
                it.copy(
                    testNotificationStatus = status,
                    isPostNotificationsGranted = isPostGranted
                )
            }
        }
    }

    /**
     * Immediately locks Nava Secure Vault and zeroizes the in-memory DEK and tracked plaintexts.
     */
    fun lockVault(): Job {
        return vmScope.launch {
            container.vaultBiometricController.lock()
            _uiState.update {
                it.copy(
                    isVaultUnlocked = false,
                    lastVaultUnlockError = null
                )
            }
        }
    }

    /**
     * Unlocks Nava Secure Vault via hardware-bound `BiometricPrompt` (`BIOMETRIC_STRONG`).
     */
    fun unlockVault(
        activity: FragmentActivity? = null,
        labels: BiometricPromptLabels = BiometricPromptLabels()
    ): Job {
        return vmScope.launch {
            val outcome = if (activity != null) {
                container.vaultBiometricController.unlock(activity, labels)
            } else {
                container.vaultBiometricController.unlockWithGateway(null, labels)
            }
            when (outcome) {
                VaultUnlockResult.Unlocked -> {
                    _uiState.update {
                        it.copy(
                            isVaultUnlocked = true,
                            lastVaultUnlockError = null
                        )
                    }
                }

                VaultUnlockResult.Cancelled -> {
                    val localizedCancel = container.messageRenderer.render(
                        com.nava.domain.ui.UserMessage(com.nava.domain.ui.MessageKey.ACTION_BIOMETRIC_REQUIRED),
                        container.appLocaleManager.currentLocale()
                    ).second
                    _uiState.update {
                        it.copy(
                            isVaultUnlocked = false,
                            lastVaultUnlockError = localizedCancel
                        )
                    }
                }

                is VaultUnlockResult.Failed -> {
                    _uiState.update {
                        it.copy(
                            isVaultUnlocked = false,
                            lastVaultUnlockError = outcome.reason
                        )
                    }
                }
            }
        }
    }

    /**
     * Switches the Audit Log viewer filter between [AuditLogFilter.ALL] and [AuditLogFilter.DENIED_ONLY].
     */
    fun setAuditFilter(filter: AuditLogFilter) {
        _uiState.update { state ->
            state.copy(
                auditFilter = filter,
                filteredAuditEntries = filterAuditEntries(state.allAuditEntries, filter)
            )
        }
    }

    fun refreshAuditLogs(): Job {
        return vmScope.launch {
            val entries = container.auditLogDao.queryRecent(DEFAULT_AUDIT_LOG_LIMIT)
            _uiState.update { state ->
                state.copy(
                    allAuditEntries = entries,
                    filteredAuditEntries = filterAuditEntries(entries, state.auditFilter)
                )
            }
        }
    }

    /**
     * Records a user request to open an Android system integration settings screen
     * (`ROLE_ASSISTANT`, Notification Listener settings, or Notification Policy Access settings).
     */
    fun onSystemIntegrationRequested(target: SystemIntegrationTarget) {
        _uiState.update { it.copy(lastRequestedSystemTarget = target) }
    }

    private fun filterLanguages(
        languages: List<LanguageEntry>,
        rawQuery: String
    ): List<LanguageEntry> {
        val query = rawQuery.trim().lowercase(Locale.US)
        if (query.isEmpty()) return languages
        return languages.filter { entry ->
            entry.englishName.lowercase(Locale.US).contains(query) ||
                entry.nativeName.lowercase(Locale.ROOT).contains(query) ||
                entry.bcp47Tag.lowercase(Locale.US).contains(query)
        }
    }

    private fun filterAuditEntries(
        entries: List<AuditLogEntry>,
        filter: AuditLogFilter
    ): List<AuditLogEntry> {
        return when (filter) {
            AuditLogFilter.ALL -> entries
            AuditLogFilter.DENIED_ONLY -> entries.filter { isDeniedOrBlockedAuditDecision(it.decision) }
        }
    }

    override fun onCleared() {
        super.onCleared()
        vmScope.cancel()
    }

    companion object {
        const val DEFAULT_AUDIT_LOG_LIMIT: Int = 200

        /**
         * Determines whether an [AuditLogEntry.decision] represents a blocked, denied, or
         * security-rejected action for the `DENIED_ONLY` Audit Log filter.
         */
        fun isDeniedOrBlockedAuditDecision(decision: String): Boolean {
            val upper = decision.trim().uppercase(Locale.US)
            if (upper == "SUCCESS" ||
                upper == "PROFILE_SAVED" ||
                upper == "CAPABILITY_UPDATED" ||
                upper == "TARGET_ASSIGNED" ||
                upper == "PROFILE_DELETED" ||
                upper == "RULE_PENDING_APPROVAL" ||
                upper == "RULE_APPROVED" ||
                upper == "RULE_PAUSED" ||
                upper == "RULE_REVOKED" ||
                upper == "CONFIRMATION_REQUIRED" ||
                upper == "BIOMETRIC_REQUIRED" ||
                upper == "ESCALATED_CONFIRMATION" ||
                upper == "ESCALATED_BIOMETRIC"
            ) {
                return false
            }
            return upper == "DENIED" ||
                upper.contains("DENIED") ||
                upper.contains("BLOCKED") ||
                upper.contains("VIOLATION") ||
                upper.contains("PAUSED") ||
                upper.contains("MISMATCH") ||
                upper.contains("NOT_ACTIVE") ||
                upper.contains("NOT_FOUND") ||
                upper.contains("MISSING") ||
                upper.contains("FAILED") ||
                upper.contains("EXPIRED") ||
                upper.contains("FORGED") ||
                upper.contains("REJECTED")
        }
    }
}

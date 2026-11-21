package com.nava.app.ui.onboarding

import androidx.lifecycle.ViewModel
import com.nava.app.di.AppContainer
import com.nava.app.di.PinnedModelCatalog
import com.nava.domain.ai.PinnedModelSpec
import com.nava.domain.ai.RamTier
import com.nava.domain.automation.BackgroundTaskRequest
import com.nava.domain.locale.LanguageEntry
import java.io.File
import java.util.Locale
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
 * Ordered steps of Nava's Default-Deny Onboarding Wizard (PLAN.md Sections 1.1, 2.3, 5.1, and 6.4).
 */
enum class OnboardingStep {
    DEFAULT_DENY_EXPLANATION,
    LANGUAGE_PICKER,
    MODEL_PROVISIONING,
    COMPLETE
}

/**
 * Immutable MVI state for the 4-step Default-Deny Onboarding Wizard.
 */
data class OnboardingUiState(
    val currentStep: OnboardingStep = OnboardingStep.DEFAULT_DENY_EXPLANATION,
    val isDefaultDenyAcknowledged: Boolean = false,
    val isOnboardingCompleted: Boolean = false,
    val activeLocaleTag: String = "en",
    val languageSearchQuery: String = "",
    val allLanguages: List<LanguageEntry> = emptyList(),
    val filteredLanguages: List<LanguageEntry> = emptyList(),
    val ramTier: RamTier = RamTier.TIER_1_STANDARD,
    val recommendedModelSpec: PinnedModelSpec = PinnedModelCatalog.GEMMA_4_E2B_SPEC,
    val eligibleModelSpecs: List<PinnedModelSpec> = PinnedModelCatalog.ALL_SPECS,
    val selectedModelSpec: PinnedModelSpec = PinnedModelCatalog.GEMMA_4_E2B_SPEC,
    val selectedModelId: String? = null,
    val isDeterministicModeSelected: Boolean = false,
    val requiredTwoTimesHeadroomBytes: Long =
        PinnedModelCatalog.temporaryTwoTimesStorageBytes(PinnedModelCatalog.GEMMA_4_E2B_SPEC),
    val availableStorageBytes: Long = 0L,
    val enqueuedImportTaskId: String? = null,
    val errorMessage: String? = null
)

/**
 * MVI ViewModel for the Default-Deny Onboarding Wizard.
 *
 * Security Invariant (Requirement 5):
 * Onboarding NEVER grants any capability or modifies any [com.nava.domain.security.PermissionProfile].
 * Every target remains strictly bound to `PermissionProfile.defaultDeny()` (`Strictly Isolated`).
 */
class OnboardingViewModel(
    private val container: AppContainer,
    private val dispatcher: CoroutineDispatcher = Dispatchers.Default,
    private val clockMs: () -> Long = System::currentTimeMillis
) : ViewModel() {

    private val vmScope = CoroutineScope(SupervisorJob() + dispatcher)

    private val _uiState = MutableStateFlow(createInitialState())
    val uiState: StateFlow<OnboardingUiState> = _uiState.asStateFlow()

    init {
        loadCatalogAndHardwareState()
    }

    private fun createInitialState(): OnboardingUiState {
        val persisted = container.onboardingStateStore.currentState()
        val ramTier = runCatching {
            container.thermalModelLifecycleManager.currentRamTier()
        }.getOrDefault(RamTier.TIER_1_STANDARD)
        val recommended = PinnedModelCatalog.recommendedSpecForRamTier(ramTier)
        val eligible = PinnedModelCatalog.eligibleSpecsForRamTier(ramTier)
        val initialSpec = PinnedModelCatalog.findByModelId(persisted.selectedModelId) ?: recommended
        val modelsDir = File(container.safModelProvisioner.modelsDirectoryPath())
        val availableBytes = runCatching {
            container.storageSpaceProvider.availableBytes(modelsDir)
        }.getOrDefault(0L)

        val initialStep = when {
            persisted.isOnboardingCompleted -> OnboardingStep.COMPLETE
            persisted.isDefaultDenyAcknowledged -> OnboardingStep.LANGUAGE_PICKER
            else -> OnboardingStep.DEFAULT_DENY_EXPLANATION
        }

        return OnboardingUiState(
            currentStep = initialStep,
            isDefaultDenyAcknowledged = persisted.isDefaultDenyAcknowledged,
            isOnboardingCompleted = persisted.isOnboardingCompleted,
            activeLocaleTag = container.appLocaleManager.currentLocaleTag(),
            ramTier = ramTier,
            recommendedModelSpec = recommended,
            eligibleModelSpecs = eligible,
            selectedModelSpec = initialSpec,
            selectedModelId = persisted.selectedModelId,
            requiredTwoTimesHeadroomBytes = PinnedModelCatalog.temporaryTwoTimesStorageBytes(initialSpec),
            availableStorageBytes = availableBytes
        )
    }

    private fun loadCatalogAndHardwareState() {
        vmScope.launch {
            val languages = container.appLocaleManager.availableLanguages()
            val localeTag = container.appLocaleManager.currentLocaleTag()
            _uiState.update { state ->
                state.copy(
                    activeLocaleTag = localeTag,
                    allLanguages = languages,
                    filteredLanguages = filterLanguages(languages, state.languageSearchQuery)
                )
            }
        }
    }

    /**
     * Step 1 -> Step 2: Records user acknowledgment of Default-Deny and Zero-INTERNET posture.
     * Never grants any permission automatically.
     */
    fun acknowledgeDefaultDenyAndContinue() {
        val updated = container.onboardingStateStore.setDefaultDenyAcknowledged(true)
        _uiState.update { state ->
            state.copy(
                isDefaultDenyAcknowledged = updated.isDefaultDenyAcknowledged,
                currentStep = OnboardingStep.LANGUAGE_PICKER,
                errorMessage = null
            )
        }
    }

    /**
     * Filters the [SupportedLanguageCatalog] entries in Step 2 without hardcoded language lists.
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
     * Applies [bcp47Tag] via [AppLocaleManager.setApplicationLocale] using the
     * `exact -> base -> "en"` fallback chain.
     */
    fun selectLanguage(bcp47Tag: String) {
        vmScope.launch {
            val resolvedTag = container.appLocaleManager.setApplicationLocale(bcp47Tag)
            _uiState.update { state ->
                state.copy(
                    activeLocaleTag = resolvedTag,
                    errorMessage = null
                )
            }
        }
    }

    /**
     * Step 2 -> Step 3: Advances from Language Picker to Model Provisioning.
     */
    fun proceedToModelProvisioning() {
        _uiState.update { state ->
            state.copy(
                currentStep = OnboardingStep.MODEL_PROVISIONING,
                errorMessage = null
            )
        }
    }

    /**
     * Selects a pinned `.litertlm` specification (`E2B` or `E4B`) for SAF import and updates
     * the 2x temporary storage headroom calculation.
     */
    fun selectModelSpec(spec: PinnedModelSpec) {
        _uiState.update { state ->
            state.copy(
                selectedModelSpec = spec,
                requiredTwoTimesHeadroomBytes = PinnedModelCatalog.temporaryTwoTimesStorageBytes(spec),
                errorMessage = null
            )
        }
    }

    /**
     * Step 3 -> Step 4 (Model Import): Enqueues [BackgroundTaskRequest.ModelImportContinuation]
     * via `BackgroundTaskContinuationPort` for offline SAF streaming SHA-256 verification.
     */
    fun enqueueSafModelImport(
        sourceUri: String,
        spec: PinnedModelSpec = _uiState.value.selectedModelSpec
    ) {
        val trimmedUri = sourceUri.trim()
        if (trimmedUri.isEmpty()) {
            _uiState.update { it.copy(errorMessage = "SAF model URI must not be blank") }
            return
        }
        val now = clockMs()
        val taskId = "model_import:${spec.modelId}:$now"
        val localeTag = container.appLocaleManager.currentLocaleTag()
        val request = BackgroundTaskRequest.ModelImportContinuation(
            taskId = taskId,
            sourceUri = trimmedUri,
            expectedModelId = spec.modelId,
            expectedSha256Hex = spec.expectedSha256Hex,
            languageTag = localeTag,
            enqueuedAtEpochMs = now
        )

        vmScope.launch {
            val enqueuedId = container.backgroundTaskContinuationManager.enqueue(request)
            val persisted = container.onboardingStateStore.setSelectedModelId(spec.modelId)
            _uiState.update { state ->
                state.copy(
                    selectedModelSpec = spec,
                    selectedModelId = persisted.selectedModelId,
                    isDeterministicModeSelected = false,
                    enqueuedImportTaskId = enqueuedId,
                    currentStep = OnboardingStep.COMPLETE,
                    errorMessage = null
                )
            }
        }
    }

    /**
     * Step 3 -> Step 4 (Deterministic Mode): Allows the user to continue in Tier 1 / Tier 2
     * Deterministic Mode without importing a `.litertlm` bundle yet.
     */
    fun continueInDeterministicMode() {
        container.onboardingStateStore.setSelectedModelId(null)
        _uiState.update { state ->
            state.copy(
                selectedModelId = null,
                isDeterministicModeSelected = true,
                currentStep = OnboardingStep.COMPLETE,
                errorMessage = null
            )
        }
    }

    /**
     * Step 4: Atomically completes onboarding in `OnboardingStateStore` while preserving
     * 100% Default-Deny target permissions.
     */
    fun completeOnboarding() {
        val current = _uiState.value
        val persisted = container.onboardingStateStore.completeOnboarding(
            selectedModelId = current.selectedModelId,
            defaultDenyAcknowledged = true
        )
        _uiState.update { state ->
            state.copy(
                isDefaultDenyAcknowledged = persisted.isDefaultDenyAcknowledged,
                isOnboardingCompleted = persisted.isOnboardingCompleted,
                selectedModelId = persisted.selectedModelId,
                currentStep = OnboardingStep.COMPLETE,
                errorMessage = null
            )
        }
    }

    fun navigateBack() {
        _uiState.update { state ->
            val previous = when (state.currentStep) {
                OnboardingStep.DEFAULT_DENY_EXPLANATION -> OnboardingStep.DEFAULT_DENY_EXPLANATION
                OnboardingStep.LANGUAGE_PICKER -> OnboardingStep.DEFAULT_DENY_EXPLANATION
                OnboardingStep.MODEL_PROVISIONING -> OnboardingStep.LANGUAGE_PICKER
                OnboardingStep.COMPLETE -> OnboardingStep.MODEL_PROVISIONING
            }
            state.copy(currentStep = previous, errorMessage = null)
        }
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

    override fun onCleared() {
        super.onCleared()
        vmScope.cancel()
    }
}

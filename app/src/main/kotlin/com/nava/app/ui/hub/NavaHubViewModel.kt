package com.nava.app.ui.hub

import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import com.nava.app.di.AppContainer
import com.nava.app.di.ModelQualitySuggestion
import com.nava.app.di.NeuronToolMapper
import com.nava.app.di.PinnedModelCatalog
import com.nava.app.security.BiometricPromptLabels
import com.nava.app.security.PendingConfirmationItem
import com.nava.app.security.PendingConfirmationSource
import com.nava.app.security.VaultUnlockResult
import com.nava.app.voice.VoiceInputState
import com.nava.domain.ai.IntentRequest
import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.RamTier
import com.nava.domain.ai.ResolutionResult
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.automation.BackgroundTaskRequest
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.Tainted
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.CoreActivityState
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.NeuralCanvasState
import com.nava.domain.ui.NeuralPulseEvent
import com.nava.domain.ui.NeuronNodeId
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.ToolTargetIds
import java.util.ArrayDeque
import java.util.UUID
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
 * Snapshot of a radial app neuron inspected by tapping it on the Dual-Core Neural Canvas.
 */
data class InspectedNeuronDetails(
    val nodeId: NeuronNodeId,
    val primaryTargetId: String,
    val profile: PermissionProfile,
    val recentAuditEntries: List<AuditLogEntry>
)

/**
 * Immutable MVI state for the Dual-Core Neural Hub screen (PLAN.md Sections 2.3, 3.1, 6.4, and 7).
 */
data class NavaHubUiState(
    val canvasState: NeuralCanvasState = NeuralCanvasState(),
    val queryInput: String = "",
    val isProcessing: Boolean = false,
    val lastResolutionTier: ResolutionTier? = null,
    val statusTitle: String? = null,
    val statusMessage: String? = null,
    val lastUserMessage: UserMessage? = null,
    val conversationalReply: String? = null,
    val activeConfirmation: PendingConfirmationItem? = null,
    val ramTier: RamTier = RamTier.TIER_1_STANDARD,
    val showTier0LowMemoryNotice: Boolean = false,
    val qualitySuggestion: ModelQualitySuggestion? = null,
    val inspectedNeuron: InspectedNeuronDetails? = null,
    val voiceState: VoiceInputState = VoiceInputState.Idle,
    val isMicPermissionGranted: Boolean = false,
    val showMicPermissionRationale: Boolean = false,
    val activeLocaleTag: String = "en",
    val lastPlanAdmittedToCache: Boolean = false
)

/**
 * MVI ViewModel driving the Dual-Core Neural Hub, 3-Tier Hybrid Router execution,
 * 0-FPS Neural Canvas pulse queue, Action Confirmation Card lifecycle, and Tier 2 Cache
 * Admission Safety Gate.
 *
 * Pure-JVM testable: accepts [AppContainer] and an injectable [CoroutineDispatcher] with
 * zero Android `Context` dependency in its constructor.
 */
class NavaHubViewModel(
    private val container: AppContainer,
    private val dispatcher: CoroutineDispatcher = Dispatchers.Default,
    private val clockMs: () -> Long = System::currentTimeMillis,
    private val requestIdGenerator: () -> String = { "hub_req_${UUID.randomUUID()}" }
) : ViewModel() {

    private val vmScope = CoroutineScope(SupervisorJob() + dispatcher)
    private val pulseLock = Any()
    private val pendingPulsesQueue = ArrayDeque<NeuralPulseEvent>()

    private data class InFlightPlanContext(
        val intentRequest: IntentRequest,
        val tier: ResolutionTier,
        val plan: PlanAst,
        val capabilityToken: CapabilityToken
    )

    private val inFlightPlansByRequestId = LinkedHashMap<String, InFlightPlanContext>()

    private val _uiState = MutableStateFlow(createInitialState())
    val uiState: StateFlow<NavaHubUiState> = _uiState.asStateFlow()

    init {
        observeContainerStreams()
        refreshHardwareAndQualityTelemetry()
    }

    private fun createInitialState(): NavaHubUiState {
        val ramTier = runCatching {
            container.thermalModelLifecycleManager.currentRamTier()
        }.getOrDefault(RamTier.TIER_1_STANDARD)
        val thermalState = runCatching {
            container.thermalModelLifecycleManager.currentThermalState()
        }.getOrDefault(com.nava.domain.ai.ThermalState.NORMAL)
        val localeTag = container.appLocaleManager.currentLocaleTag()
        return NavaHubUiState(
            canvasState = NeuralCanvasState(
                coreState = CoreActivityState.IDLE,
                activeNeurons = emptySet(),
                activePulse = null,
                isVaultUnlocked = container.vaultBiometricController.isVaultUnlockedFlow.value,
                thermalState = thermalState,
                isModelResident = container.liteRtRuntimeAdapter.isLoaded()
            ),
            ramTier = ramTier,
            showTier0LowMemoryNotice = ramTier == RamTier.TIER_0_LOW_MEMORY,
            activeConfirmation = container.pendingConfirmationStore.activeConfirmationFlow.value,
            voiceState = container.voiceInputController.stateFlow.value,
            activeLocaleTag = localeTag
        )
    }

    private fun observeContainerStreams() {
        vmScope.launch {
            container.pendingConfirmationStore.activeConfirmationFlow.collect { activeItem ->
                _uiState.update { it.copy(activeConfirmation = activeItem) }
            }
        }
        vmScope.launch {
            container.vaultBiometricController.isVaultUnlockedFlow.collect { unlocked ->
                _uiState.update { state ->
                    state.copy(
                        canvasState = state.canvasState.copy(isVaultUnlocked = unlocked)
                    )
                }
            }
        }
        vmScope.launch {
            container.appLocaleManager.activeLocaleTagFlow.collect { localeTag ->
                _uiState.update { it.copy(activeLocaleTag = localeTag) }
                evaluateQualitySuggestionInternal(localeTag)
            }
        }
        vmScope.launch {
            container.voiceInputController.stateFlow.collect { voiceState ->
                when (voiceState) {
                    is VoiceInputState.PartialTranscript -> {
                        _uiState.update {
                            it.copy(
                                voiceState = voiceState,
                                queryInput = voiceState.text
                            )
                        }
                    }

                    is VoiceInputState.FinalTranscript -> {
                        _uiState.update {
                            it.copy(
                                voiceState = voiceState,
                                queryInput = voiceState.text
                            )
                        }
                    }

                    else -> {
                        _uiState.update { it.copy(voiceState = voiceState) }
                    }
                }
            }
        }
    }

    /**
     * Refreshes RAM tier, thermal status, and the data-driven `E2B -> E4B` quality suggestion banner.
     */
    fun refreshHardwareAndQualityTelemetry() {
        vmScope.launch {
            val ramTier = container.thermalModelLifecycleManager.currentRamTier()
            val thermalState = container.thermalModelLifecycleManager.currentThermalState()
            val isResident = container.liteRtRuntimeAdapter.isLoaded()
            val isVaultUnlocked = container.vaultBiometricController.refreshUnlockState()
            val localeTag = container.appLocaleManager.currentLocaleTag()

            _uiState.update { state ->
                state.copy(
                    ramTier = ramTier,
                    showTier0LowMemoryNotice = ramTier == RamTier.TIER_0_LOW_MEMORY,
                    activeLocaleTag = localeTag,
                    canvasState = state.canvasState.copy(
                        thermalState = thermalState,
                        isModelResident = isResident,
                        isVaultUnlocked = isVaultUnlocked
                    )
                )
            }
            evaluateQualitySuggestionInternal(localeTag)
        }
    }

    private suspend fun evaluateQualitySuggestionInternal(localeTag: String) {
        val ramTier = container.thermalModelLifecycleManager.currentRamTier()
        val selectedModelId = container.onboardingStateStore.getSelectedModelId()
            ?: PinnedModelCatalog.recommendedSpecForRamTier(ramTier).modelId
        val suggestion = PinnedModelCatalog.evaluateQualitySuggestion(
            activeModelId = selectedModelId,
            ramTier = ramTier,
            activeLanguageTag = localeTag,
            catalog = container.supportedLanguageCatalog
        )
        _uiState.update { it.copy(qualitySuggestion = suggestion) }
    }

    fun onQueryInputChanged(newText: String) {
        _uiState.update { it.copy(queryInput = newText) }
    }

    /**
     * Submits the current [NavaHubUiState.queryInput] (or explicit [utterance]) to
     * `ProcessQueryUseCase` strictly with [DataProvenance.USER_UTTERANCE].
     */
    fun submitQuery(utterance: String = _uiState.value.queryInput) {
        val now = clockMs()
        val reqId = requestIdGenerator()
        val localeTag = container.appLocaleManager.currentLocaleTag()

        vmScope.launch {
            _uiState.update {
                it.copy(
                    queryInput = utterance,
                    isProcessing = true,
                    conversationalReply = null,
                    lastPlanAdmittedToCache = false
                )
            }

            val resolution = try {
                container.processQueryUseCase(
                    requestId = reqId,
                    rawUtterance = utterance,
                    appLocaleTag = localeTag,
                    targetContextId = "default",
                    issuedAtEpochMs = now,
                    provenance = DataProvenance.USER_UTTERANCE
                )
            } catch (e: SecurityException) {
                val msg = UserMessage(MessageKey.ERROR_SECURITY_VIOLATION)
                applyUserMessageBanner(msg, isError = true)
                return@launch
            }

            when (resolution) {
                is ResolutionResult.ResolvedPlan -> {
                    val detected = container.languageDetector.detect(utterance, localeTag)
                    val normalized = container.textNormalizer.normalize(utterance, detected.bcp47Tag)
                    val intentRequest = IntentRequest(
                        requestId = resolution.capabilityToken.requestId,
                        rawUtterance = utterance.trim(),
                        normalizedText = normalized,
                        languageHint = detected,
                        provenance = DataProvenance.USER_UTTERANCE,
                        issuedAtEpochMs = now,
                        targetContextId = "default"
                    )
                    executeResolvedPlanInternal(
                        intentRequest = intentRequest,
                        tier = resolution.tier,
                        plan = resolution.plan,
                        capabilityToken = resolution.capabilityToken,
                        nowEpochMs = now
                    )
                }

                is ResolutionResult.ConversationalReply -> {
                    val isGemma = resolution.tier == ResolutionTier.TIER_3_GEMMA
                    val coreState = if (isGemma) {
                        CoreActivityState.INNER_CORE_ACTIVE
                    } else {
                        CoreActivityState.OUTER_SHELL_ACTIVE
                    }
                    val pulse = NeuralPulseEvent(
                        eventId = "$reqId:reply:0",
                        tier = resolution.tier,
                        sourceNode = null,
                        targetNode = NeuronNodeId.NOTES,
                        wakesInnerCore = isGemma,
                        isBiometricSynapse = false,
                        timestampEpochMs = now
                    )
                    synchronized(pulseLock) {
                        pendingPulsesQueue.clear()
                    }
                    _uiState.update { state ->
                        state.copy(
                            isProcessing = false,
                            lastResolutionTier = resolution.tier,
                            conversationalReply = resolution.replyText,
                            canvasState = state.canvasState.copy(
                                coreState = coreState,
                                activeNeurons = setOf(NeuronNodeId.NOTES),
                                activePulse = pulse,
                                isModelResident = container.liteRtRuntimeAdapter.isLoaded()
                            )
                        )
                    }
                }

                is ResolutionResult.ClarificationNeeded -> {
                    applyUserMessageBanner(resolution.message, isError = false)
                }

                ResolutionResult.NoMatch -> {
                    applyUserMessageBanner(
                        UserMessage(MessageKey.ERROR_CLARIFICATION_NEEDED),
                        isError = false
                    )
                }
            }
        }
    }

    /**
     * Executes an already-resolved [PlanAst] with its Stage 1 [CapabilityToken] and drives
     * the Dual-Core Neural Canvas state machine and Tier 2 Cache Admission Gate.
     */
    fun executeResolvedPlan(
        intentRequest: IntentRequest,
        tier: ResolutionTier,
        plan: PlanAst,
        capabilityToken: CapabilityToken
    ) {
        vmScope.launch {
            executeResolvedPlanInternal(
                intentRequest = intentRequest,
                tier = tier,
                plan = plan,
                capabilityToken = capabilityToken,
                nowEpochMs = clockMs()
            )
        }
    }

    private suspend fun executeResolvedPlanInternal(
        intentRequest: IntentRequest,
        tier: ResolutionTier,
        plan: PlanAst,
        capabilityToken: CapabilityToken,
        nowEpochMs: Long
    ) {
        inFlightPlansByRequestId[capabilityToken.requestId] = InFlightPlanContext(
            intentRequest = intentRequest,
            tier = tier,
            plan = plan,
            capabilityToken = capabilityToken
        )

        enqueuePulsesForPlan(plan = plan, tier = tier, timestampEpochMs = nowEpochMs)

        val primaryNeuron = plan.calls
            .minByOrNull { it.orderIndex }
            ?.let { NeuronToolMapper.neuronForToolCall(it) }
            ?: NeuronNodeId.ROUTINES
        val defaultTargetId = NeuronToolMapper.primaryTargetIdForNeuron(primaryNeuron)
        val targetIdsByStep = plan.calls.associate { call ->
            val stepNeuron = NeuronToolMapper.neuronForToolCall(call)
            val resolvedTarget = call.targetId ?: NeuronToolMapper.primaryTargetIdForNeuron(stepNeuron)
            call.orderIndex to resolvedTarget
        }
        val localeTag = container.appLocaleManager.currentLocaleTag()

        val results = try {
            container.executePlanUseCase(
                plan = plan,
                capabilityToken = capabilityToken,
                targetId = defaultTargetId,
                languageTag = localeTag,
                nowEpochMs = nowEpochMs,
                targetIdsByStep = targetIdsByStep
            )
        } catch (e: SecurityException) {
            applyUserMessageBanner(UserMessage(MessageKey.ERROR_SECURITY_VIOLATION), isError = true)
            return
        }

        handlePlanExecutionResults(
            requestId = capabilityToken.requestId,
            plan = plan,
            capabilityToken = capabilityToken,
            results = results,
            confirmedStepIndices = emptySet(),
            biometricApprovedStepIndices = emptySet(),
            languageTag = localeTag,
            nowEpochMs = nowEpochMs
        )
    }

    private suspend fun handlePlanExecutionResults(
        requestId: String,
        plan: PlanAst,
        capabilityToken: CapabilityToken,
        results: List<ToolResult>,
        confirmedStepIndices: Set<Int>,
        biometricApprovedStepIndices: Set<Int>,
        languageTag: String,
        nowEpochMs: Long
    ) {
        val lastResult = results.lastOrNull()
        if (lastResult == null) {
            _uiState.update { it.copy(isProcessing = false) }
            return
        }

        when (lastResult) {
            is ToolResult.ConfirmationRequired -> {
                val requiresBio = lastResult.requiresBiometric ||
                    lastResult.pendingToolName in AutomationToolNames.VAULT_TOOLS ||
                    lastResult.targetId.equals(ToolTargetIds.VAULT, ignoreCase = true)
                val effectiveConfirmation = if (requiresBio && !lastResult.requiresBiometric) {
                    lastResult.copy(requiresBiometric = true)
                } else {
                    lastResult
                }
                container.pendingConfirmationStore.registerForegroundConfirmation(
                    plan = plan,
                    capabilityToken = capabilityToken,
                    confirmation = effectiveConfirmation,
                    targetId = effectiveConfirmation.targetId,
                    languageTag = languageTag,
                    confirmedStepIndices = confirmedStepIndices,
                    biometricApprovedStepIndices = biometricApprovedStepIndices,
                    nowEpochMs = nowEpochMs
                )
                val locale = container.appLocaleManager.currentLocale()
                val (title, body) = container.messageRenderer.render(effectiveConfirmation.message, locale)
                _uiState.update { state ->
                    state.copy(
                        isProcessing = false,
                        statusTitle = title,
                        statusMessage = body,
                        lastUserMessage = effectiveConfirmation.message
                    )
                }
            }

            is ToolResult.Failure -> {
                inFlightPlansByRequestId.remove(requestId)
                applyUserMessageBanner(lastResult.message, isError = true)
            }

            is ToolResult.Success -> {
                val context = inFlightPlansByRequestId.remove(requestId)
                val admitted = if (context != null) {
                    maybeAdmitPlanToTier2Cache(
                        intentRequest = context.intentRequest,
                        tier = context.tier,
                        plan = plan,
                        nowEpochMs = nowEpochMs
                    )
                } else {
                    false
                }
                val locale = container.appLocaleManager.currentLocale()
                val (title, body) = container.messageRenderer.render(lastResult.message, locale)
                _uiState.update { state ->
                    state.copy(
                        isProcessing = false,
                        statusTitle = title,
                        statusMessage = body,
                        lastUserMessage = lastResult.message,
                        lastPlanAdmittedToCache = admitted
                    )
                }
            }
        }
    }

    /**
     * Enforces the Tier 2 Cache Admission Safety Gate (PLAN.md Section 3.1 & Requirement 3):
     * - Admits ONLY plans resolved by [ResolutionTier.TIER_3_GEMMA].
     * - Admits ONLY after successful execution or user approval.
     * - Admits ONLY when 100% of slot arguments across all calls have
     *   [DataProvenance.USER_UTTERANCE] and no `"vault:"` source label.
     * - Admits ONLY when zero Vault tools or Vault targets are present in [plan].
     */
    private suspend fun maybeAdmitPlanToTier2Cache(
        intentRequest: IntentRequest,
        tier: ResolutionTier,
        plan: PlanAst,
        nowEpochMs: Long
    ): Boolean {
        if (tier != ResolutionTier.TIER_3_GEMMA) {
            return false
        }
        val touchesVault = planTouchesVault(plan, intentRequest.targetContextId)
        if (touchesVault) {
            return false
        }
        val allUserUtterance = plan.calls.all { call ->
            call.arguments.values.all { taintedArg ->
                taintedArg.provenance == DataProvenance.USER_UTTERANCE &&
                    taintedArg.sourceLabel?.trim()?.startsWith("vault:", ignoreCase = true) != true
            }
        }
        if (!allUserUtterance) {
            return false
        }

        return container.cacheIntentResolver.admitPlan(
            request = intentRequest,
            plan = plan,
            availableTools = container.toolRegistry.allMetadata(),
            userApproved = true,
            touchesVault = false,
            nowEpochSec = nowEpochMs / 1000L
        )
    }

    private fun planTouchesVault(plan: PlanAst, targetContextId: String): Boolean {
        if (targetContextId.equals(ToolTargetIds.VAULT, ignoreCase = true) ||
            targetContextId.startsWith("vault:", ignoreCase = true)
        ) {
            return true
        }
        return plan.calls.any { call ->
            call.toolName in AutomationToolNames.VAULT_TOOLS ||
                call.targetId.equals(ToolTargetIds.VAULT, ignoreCase = true) ||
                call.targetId?.startsWith("vault:", ignoreCase = true) == true ||
                NeuronToolMapper.neuronForToolCall(call) == NeuronNodeId.VAULT
        }
    }

    private fun enqueuePulsesForPlan(
        plan: PlanAst,
        tier: ResolutionTier,
        timestampEpochMs: Long
    ) {
        val pulses = NeuronToolMapper.buildPulsesForPlan(
            plan = plan,
            tier = tier,
            timestampEpochMs = timestampEpochMs
        )
        val activeNeurons = NeuronToolMapper.activeNeuronsForPlan(plan)
        val firstPulse = pulses.firstOrNull()
        val coreState = when {
            firstPulse == null -> CoreActivityState.IDLE
            tier == ResolutionTier.TIER_3_GEMMA -> CoreActivityState.INNER_CORE_ACTIVE
            else -> CoreActivityState.OUTER_SHELL_ACTIVE
        }

        synchronized(pulseLock) {
            pendingPulsesQueue.clear()
            for (idx in 1 until pulses.size) {
                pendingPulsesQueue.addLast(pulses[idx])
            }
        }

        _uiState.update { state ->
            state.copy(
                lastResolutionTier = tier,
                canvasState = state.canvasState.copy(
                    coreState = coreState,
                    activeNeurons = activeNeurons,
                    activePulse = firstPulse,
                    thermalState = container.thermalModelLifecycleManager.currentThermalState(),
                    isModelResident = container.liteRtRuntimeAdapter.isLoaded()
                )
            )
        }
    }

    /**
     * Invoked when the 0-FPS Dual-Core Neural Canvas finishes animating the active synapse pulse.
     *
     * Advances the next queued inter-neuron pulse in a multi-step chain, or immediately resets
     * [NeuralCanvasState.coreState] to [CoreActivityState.IDLE] and [NeuralCanvasState.activePulse]
     * to `null` so the canvas returns to 0 FPS (`0%` CPU/GPU).
     */
    fun onPulseCompleted(eventId: String) {
        val currentActive = _uiState.value.canvasState.activePulse
        if (currentActive != null && currentActive.eventId != eventId) {
            return
        }

        val nextPulse: NeuralPulseEvent? = synchronized(pulseLock) {
            if (pendingPulsesQueue.isEmpty()) null else pendingPulsesQueue.removeFirst()
        }

        if (nextPulse != null) {
            val nextCoreState = if (nextPulse.wakesInnerCore) {
                CoreActivityState.INNER_CORE_ACTIVE
            } else {
                CoreActivityState.OUTER_SHELL_ACTIVE
            }
            _uiState.update { state ->
                state.copy(
                    canvasState = state.canvasState.copy(
                        coreState = nextCoreState,
                        activePulse = nextPulse
                    )
                )
            }
        } else {
            _uiState.update { state ->
                state.copy(
                    canvasState = state.canvasState.copy(
                        coreState = CoreActivityState.IDLE,
                        activePulse = null,
                        activeNeurons = emptySet()
                    )
                )
            }
        }
    }

    /**
     * Updates a user-edited slot value inside the active [PendingConfirmationItem]
     * (sanitized via `Gemma4InputSanitizer` inside `PendingConfirmationStore.updateEditedSlot`).
     */
    fun onEditConfirmationSlot(
        requestId: String,
        slotName: String,
        newRawValue: String
    ) {
        val updated = container.pendingConfirmationStore.updateEditedSlot(
            requestId = requestId,
            slotName = slotName,
            newRawValue = newRawValue
        )
        if (updated != null && updated.plan != null) {
            val existingCtx = inFlightPlansByRequestId[requestId]
            if (existingCtx != null) {
                inFlightPlansByRequestId[requestId] = existingCtx.copy(plan = updated.plan)
            }
        }
    }

    /**
     * Cancels and dismisses the confirmation request identified by [requestId].
     */
    fun onCancelConfirmation(requestId: String) {
        val removed = container.pendingConfirmationStore.dismiss(requestId)
        inFlightPlansByRequestId.remove(requestId)
        val taskId = removed?.taskId
        if (!taskId.isNullOrBlank()) {
            vmScope.launch {
                container.backgroundTaskContinuationManager.cancel(taskId)
            }
        }
    }

    /**
     * Approves the confirmation request identified by [requestId].
     *
     * Security invariant (Requirement 4):
     * When `item.requiresBiometric == true`, authenticates via [VaultBiometricController] BEFORE
     * marking the step biometric-approved or executing any tool! If biometric authentication
     * is cancelled or fails, the tool is NEVER executed.
     */
    fun onApproveConfirmation(
        requestId: String,
        activity: FragmentActivity? = null,
        biometricLabels: BiometricPromptLabels = BiometricPromptLabels()
    ) {
        vmScope.launch {
            val currentItem = container.pendingConfirmationStore.findByRequestId(requestId)
                ?: return@launch

            if (currentItem.requiresBiometric) {
                val unlockOutcome = if (activity != null) {
                    container.vaultBiometricController.unlock(activity, biometricLabels)
                } else {
                    container.vaultBiometricController.unlockWithGateway(null, biometricLabels)
                }
                if (unlockOutcome !is VaultUnlockResult.Unlocked) {
                    applyUserMessageBanner(
                        UserMessage(MessageKey.ERROR_VAULT_LOCKED),
                        isError = true
                    )
                    return@launch
                }
            }

            val approvedItem = container.pendingConfirmationStore.markStepApproved(
                requestId = requestId,
                stepOrderIndex = currentItem.confirmation.pendingOrderIndex,
                biometricApproved = currentItem.requiresBiometric
            ) ?: currentItem

            container.pendingConfirmationStore.dismiss(requestId)
            val now = clockMs()

            when (approvedItem.source) {
                PendingConfirmationSource.FOREGROUND_PLAN -> {
                    val plan = approvedItem.plan ?: return@launch
                    val token = approvedItem.capabilityToken ?: return@launch
                    val targetIdsByStep = plan.calls.associate { call ->
                        val stepNeuron = NeuronToolMapper.neuronForToolCall(call)
                        val resolvedTarget = call.targetId
                            ?: NeuronToolMapper.primaryTargetIdForNeuron(stepNeuron)
                        call.orderIndex to resolvedTarget
                    }
                    val results = try {
                        container.executePlanUseCase(
                            plan = plan,
                            capabilityToken = token,
                            targetId = approvedItem.targetId,
                            languageTag = approvedItem.languageTag,
                            nowEpochMs = now,
                            confirmedStepIndices = approvedItem.confirmedStepIndices,
                            biometricApprovedStepIndices = approvedItem.biometricApprovedStepIndices,
                            targetIdsByStep = targetIdsByStep
                        )
                    } catch (e: SecurityException) {
                        inFlightPlansByRequestId.remove(requestId)
                        applyUserMessageBanner(
                            UserMessage(MessageKey.ERROR_SECURITY_VIOLATION),
                            isError = true
                        )
                        return@launch
                    }

                    handlePlanExecutionResults(
                        requestId = requestId,
                        plan = plan,
                        capabilityToken = token,
                        results = results,
                        confirmedStepIndices = approvedItem.confirmedStepIndices,
                        biometricApprovedStepIndices = approvedItem.biometricApprovedStepIndices,
                        languageTag = approvedItem.languageTag,
                        nowEpochMs = now
                    )
                }

                PendingConfirmationSource.BACKGROUND_TASK -> {
                    val taskId = approvedItem.taskId ?: return@launch
                    val plan = approvedItem.plan ?: return@launch
                    val token = approvedItem.capabilityToken ?: return@launch
                    val continuation = BackgroundTaskRequest.PlanContinuation(
                        taskId = taskId,
                        plan = plan,
                        capabilityToken = token,
                        targetId = approvedItem.targetId,
                        languageTag = approvedItem.languageTag,
                        enqueuedAtEpochMs = now,
                        confirmedStepIndices = approvedItem.confirmedStepIndices,
                        biometricApprovedStepIndices = approvedItem.biometricApprovedStepIndices
                    )
                    val outcome = container.backgroundTaskContinuationManager.executeNow(
                        request = continuation,
                        nowEpochMs = now
                    )
                    applyUserMessageBanner(
                        message = outcome.message,
                        isError = outcome is com.nava.domain.automation.BackgroundTaskOutcome.Failed
                    )
                }

                PendingConfirmationSource.ESCALATED_ROUTINE -> {
                    val grant = approvedItem.ruleGrant ?: return@launch
                    executeInteractiveEscalatedRoutine(
                        grant = grant,
                        item = approvedItem,
                        nowEpochMs = now
                    )
                }
            }
        }
    }

    private suspend fun executeInteractiveEscalatedRoutine(
        grant: RuleCapabilityGrant,
        item: PendingConfirmationItem,
        nowEpochMs: Long
    ) {
        val editedCanonical = item.confirmation.canonicalArguments
        var lastMessage: UserMessage? = null
        for (action in grant.staticActions) {
            val tool = container.toolRegistry.find(action.toolName) ?: continue
            val args = LinkedHashMap<String, Tainted<SlotValueAst>>()
            for ((k, rawVal) in action.staticArguments) {
                val effectiveRaw = editedCanonical[k]?.value ?: rawVal
                val field = tool.metadata.fieldByName(k)
                val astVal: SlotValueAst = when (field?.valueType) {
                    SlotValueType.INTEGER -> effectiveRaw.toLongOrNull()?.let(SlotValueAst::IntValue)
                        ?: SlotValueAst.StringValue(effectiveRaw)

                    SlotValueType.BOOLEAN -> effectiveRaw.toBooleanStrictOrNull()?.let(SlotValueAst::BooleanValue)
                        ?: SlotValueAst.StringValue(effectiveRaw)

                    else -> SlotValueAst.StringValue(effectiveRaw)
                }
                args[k] = Tainted.fromSystem(value = astVal, slotKind = field?.slotKind)
            }
            val ctx = ToolExecutionContext(
                requestId = item.requestId,
                capabilityToken = null,
                ruleGrant = grant,
                targetId = ToolTargetIds.ROUTINES,
                languageTag = item.languageTag,
                issuedAtEpochMs = nowEpochMs,
                isUnattendedBackground = false,
                isUserConfirmed = true,
                isBiometricApproved = item.requiresBiometric
            )
            val result = tool.execute(ctx, args)
            lastMessage = result.message
            if (result !is ToolResult.Success) {
                applyUserMessageBanner(result.message, isError = true)
                return
            }
        }
        if (lastMessage != null) {
            applyUserMessageBanner(lastMessage, isError = false)
        }
    }

    /**
     * Tapping any radial app neuron on the Dual-Core Neural Canvas inspects that neuron's
     * primary target [PermissionProfile] and recent [AuditLogEntry] records (Requirement 3).
     */
    fun onNeuronTapped(nodeId: NeuronNodeId) {
        vmScope.launch {
            val primaryTargetId = NeuronToolMapper.primaryTargetIdForNeuron(nodeId)
            val profile = container.manageProfilesUseCase.getProfileForTarget(primaryTargetId)
            val recentEntries = container.auditLogDao.queryByTarget(
                targetId = primaryTargetId,
                limit = DEFAULT_NEURON_AUDIT_LIMIT
            )
            _uiState.update { state ->
                state.copy(
                    inspectedNeuron = InspectedNeuronDetails(
                        nodeId = nodeId,
                        primaryTargetId = primaryTargetId,
                        profile = profile,
                        recentAuditEntries = recentEntries
                    )
                )
            }
        }
    }

    fun onDismissNeuronInspection() {
        _uiState.update { it.copy(inspectedNeuron = null) }
    }

    /**
     * Handles microphone button tap with lazy `RECORD_AUDIO` permission gating.
     *
     * - If [hasRecordAudioPermission] is `false`, requests the runtime permission lazily in UI
     *   without starting the recognizer.
     * - If [hasRecordAudioPermission] is `true`, triggers [OnDeviceVoiceInputController.startListening]
     *   (which surfaces [VoiceInputState.OfflinePackMissing] if the offline pack is missing, with
     *   zero network fallback).
     */
    fun onVoiceButtonClicked(hasRecordAudioPermission: Boolean) {
        if (!hasRecordAudioPermission) {
            _uiState.update {
                it.copy(
                    isMicPermissionGranted = false,
                    showMicPermissionRationale = true
                )
            }
            return
        }

        _uiState.update {
            it.copy(
                isMicPermissionGranted = true,
                showMicPermissionRationale = false
            )
        }

        val currentVoiceState = _uiState.value.voiceState
        if (currentVoiceState is VoiceInputState.Listening ||
            currentVoiceState is VoiceInputState.PartialTranscript
        ) {
            container.voiceInputController.stopListening()
        } else {
            val localeTag = container.appLocaleManager.currentLocaleTag()
            val newState = container.voiceInputController.startListening(localeTag)
            _uiState.update { it.copy(voiceState = newState) }
        }
    }

    fun onRecordAudioPermissionResult(granted: Boolean) {
        if (granted) {
            onVoiceButtonClicked(hasRecordAudioPermission = true)
        } else {
            _uiState.update {
                it.copy(
                    isMicPermissionGranted = false,
                    showMicPermissionRationale = true
                )
            }
        }
    }

    fun dismissMicPermissionRationale() {
        _uiState.update { it.copy(showMicPermissionRationale = false) }
    }

    private fun applyUserMessageBanner(message: UserMessage, isError: Boolean) {
        val locale = container.appLocaleManager.currentLocale()
        val (title, body) = container.messageRenderer.render(message, locale)
        _uiState.update { state ->
            state.copy(
                isProcessing = false,
                statusTitle = title,
                statusMessage = body,
                lastUserMessage = message,
                canvasState = if (isError && state.canvasState.isIdle) {
                    state.canvasState.copy(coreState = CoreActivityState.IDLE)
                } else {
                    state.canvasState
                }
            )
        }
    }

    override fun onCleared() {
        super.onCleared()
        vmScope.cancel()
    }

    companion object {
        const val DEFAULT_NEURON_AUDIT_LIMIT: Int = 10
    }
}

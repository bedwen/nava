package com.nava.app.di

import android.content.Context
import android.content.SharedPreferences
import com.nava.domain.security.Gemma4InputSanitizer
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Immutable snapshot of Nava's non-sensitive onboarding and model-selection preferences.
 *
 * Security invariant: This store persists ONLY onboarding completion flags and the active
 * pinned model identifier (`gemma-4-E2B-it` / `gemma-4-E4B-it`). User utterances, notes,
 * permission profiles, audit logs, and secrets are never stored in `SharedPreferences`.
 */
data class OnboardingState(
    val isOnboardingCompleted: Boolean = false,
    val isDefaultDenyAcknowledged: Boolean = false,
    val selectedModelId: String? = null,
    val selectedFunctionModelId: String? = null,
    val selectedEmbeddingModelId: String? = null
)

/**
 * Thin key-value storage abstraction over Android `MODE_PRIVATE` [SharedPreferences]
 * enabling deterministic JVM unit testing without Android framework mocks.
 */
interface PreferencesStorageGateway {
    fun getBoolean(key: String, defaultValue: Boolean): Boolean
    fun putBoolean(key: String, value: Boolean)
    fun getString(key: String, defaultValue: String?): String?
    fun putString(key: String, value: String?)
    fun clear()
}

/**
 * Production Android implementation backed by `Context.getSharedPreferences(..., Context.MODE_PRIVATE)`.
 */
class SharedPreferencesStorageGateway(
    private val preferences: SharedPreferences
) : PreferencesStorageGateway {

    constructor(
        context: Context,
        prefsFileName: String = OnboardingStateStore.PREFS_FILE_NAME
    ) : this(
        context.applicationContext.getSharedPreferences(prefsFileName, Context.MODE_PRIVATE)
    )

    override fun getBoolean(key: String, defaultValue: Boolean): Boolean {
        return preferences.getBoolean(key, defaultValue)
    }

    override fun putBoolean(key: String, value: Boolean) {
        preferences.edit().putBoolean(key, value).apply()
    }

    override fun getString(key: String, defaultValue: String?): String? {
        return preferences.getString(key, defaultValue)
    }

    override fun putString(key: String, value: String?) {
        val editor = preferences.edit()
        if (value == null) {
            editor.remove(key)
        } else {
            editor.putString(key, value)
        }
        editor.apply()
    }

    override fun clear() {
        preferences.edit().clear().apply()
    }
}

/**
 * Thread-safe in-memory [PreferencesStorageGateway] for JVM unit testing.
 */
class InMemoryPreferencesStorageGateway : PreferencesStorageGateway {
    private val booleans = ConcurrentHashMap<String, Boolean>()
    private val strings = ConcurrentHashMap<String, String>()

    override fun getBoolean(key: String, defaultValue: Boolean): Boolean {
        return booleans[key] ?: defaultValue
    }

    override fun putBoolean(key: String, value: Boolean) {
        booleans[key] = value
    }

    override fun getString(key: String, defaultValue: String?): String? {
        return strings[key] ?: defaultValue
    }

    override fun putString(key: String, value: String?) {
        if (value == null) {
            strings.remove(key)
        } else {
            strings[key] = value
        }
    }

    override fun clear() {
        booleans.clear()
        strings.clear()
    }
}

/**
 * Persists Default-Deny onboarding completion state and user-selected `.litertlm` model ID
 * in `MODE_PRIVATE` `SharedPreferences` (Requirement 9).
 */
class OnboardingStateStore(
    private val storage: PreferencesStorageGateway
) {

    constructor(context: Context) : this(
        SharedPreferencesStorageGateway(context)
    )

    private val lock = Any()

    private val _stateFlow: MutableStateFlow<OnboardingState> = MutableStateFlow(
        readStateFromStorage()
    )

    /** Reactive stream of the current [OnboardingState]. */
    val stateFlow: StateFlow<OnboardingState> = _stateFlow.asStateFlow()

    fun currentState(): OnboardingState = _stateFlow.value

    fun isOnboardingCompleted(): Boolean = _stateFlow.value.isOnboardingCompleted

    fun isDefaultDenyAcknowledged(): Boolean = _stateFlow.value.isDefaultDenyAcknowledged

    fun getSelectedModelId(): String? = _stateFlow.value.selectedModelId

    fun getSelectedFunctionModelId(): String? = _stateFlow.value.selectedFunctionModelId

    fun getSelectedEmbeddingModelId(): String? = _stateFlow.value.selectedEmbeddingModelId

    /**
     * Marks Default-Deny onboarding as acknowledged by the user.
     */
    fun setDefaultDenyAcknowledged(acknowledged: Boolean): OnboardingState = synchronized(lock) {
        storage.putBoolean(KEY_DEFAULT_DENY_ACKNOWLEDGED, acknowledged)
        publishUpdatedStateLocked()
    }

    /**
     * Updates onboarding completion status.
     */
    fun setOnboardingCompleted(completed: Boolean): OnboardingState = synchronized(lock) {
        storage.putBoolean(KEY_ONBOARDING_COMPLETED, completed)
        publishUpdatedStateLocked()
    }

    /**
     * Persists the selected `.litertlm` model identifier (or clears it when `null`).
     *
     * Throws [IllegalArgumentException] if [modelId] is not a safe model identifier
     * (preventing utterances, paths, or control tokens from being written to preferences).
     */
    fun setSelectedModelId(modelId: String?): OnboardingState = synchronized(lock) {
        val validated = validateModelIdOrNull(modelId)
        storage.putString(KEY_SELECTED_MODEL_ID, validated)
        publishUpdatedStateLocked()
    }

    /**
     * Persists the selected `.litertlm` function-calling model identifier (or clears it when `null`).
     */
    fun setSelectedFunctionModelId(modelId: String?): OnboardingState = synchronized(lock) {
        val validated = validateModelIdOrNull(modelId)
        storage.putString(KEY_SELECTED_FUNCTION_MODEL_ID, validated)
        publishUpdatedStateLocked()
    }

    /**
     * Persists the selected `.litertlm` semantic embedding model identifier (or clears it when `null`).
     */
    fun setSelectedEmbeddingModelId(modelId: String?): OnboardingState = synchronized(lock) {
        val validated = validateModelIdOrNull(modelId)
        storage.putString(KEY_SELECTED_EMBEDDING_MODEL_ID, validated)
        publishUpdatedStateLocked()
    }

    /**
     * Routes an imported model ID to its corresponding role slot without overwriting [selectedModelId].
     */
    fun assignImportedModelByRole(modelId: String): OnboardingState = synchronized(lock) {
        when (PinnedModelCatalog.roleForModelId(modelId)) {
            PinnedModelRole.PRIMARY_LLM -> setSelectedModelId(modelId)
            PinnedModelRole.FUNCTION_ROUTER -> setSelectedFunctionModelId(modelId)
            PinnedModelRole.SEMANTIC_EMBEDDING -> setSelectedEmbeddingModelId(modelId)
        }
    }

    /**
     * Atomically completes the Default-Deny onboarding wizard and records the chosen [selectedModelId].
     */
    fun completeOnboarding(
        selectedModelId: String? = _stateFlow.value.selectedModelId,
        defaultDenyAcknowledged: Boolean = true
    ): OnboardingState = synchronized(lock) {
        val validated = validateModelIdOrNull(selectedModelId)
        storage.putBoolean(KEY_DEFAULT_DENY_ACKNOWLEDGED, defaultDenyAcknowledged)
        storage.putBoolean(KEY_ONBOARDING_COMPLETED, true)
        storage.putString(KEY_SELECTED_MODEL_ID, validated)
        publishUpdatedStateLocked()
    }

    /**
     * Resets all onboarding and model selection preferences back to their initial unconfigured state.
     */
    fun reset(): OnboardingState = synchronized(lock) {
        storage.clear()
        publishUpdatedStateLocked()
    }

    private fun publishUpdatedStateLocked(): OnboardingState {
        val snapshot = readStateFromStorage()
        _stateFlow.value = snapshot
        return snapshot
    }

    private fun readStateFromStorage(): OnboardingState {
        val completed = storage.getBoolean(KEY_ONBOARDING_COMPLETED, false)
        val acknowledged = storage.getBoolean(KEY_DEFAULT_DENY_ACKNOWLEDGED, false)
        val rawModelId = storage.getString(KEY_SELECTED_MODEL_ID, null)
        val safeModelId = runCatching { validateModelIdOrNull(rawModelId) }.getOrNull()
        val rawFunctionModelId = storage.getString(KEY_SELECTED_FUNCTION_MODEL_ID, null)
        val safeFunctionModelId = runCatching { validateModelIdOrNull(rawFunctionModelId) }.getOrNull()
        val rawEmbeddingModelId = storage.getString(KEY_SELECTED_EMBEDDING_MODEL_ID, null)
        val safeEmbeddingModelId = runCatching { validateModelIdOrNull(rawEmbeddingModelId) }.getOrNull()
        return OnboardingState(
            isOnboardingCompleted = completed,
            isDefaultDenyAcknowledged = acknowledged,
            selectedModelId = safeModelId,
            selectedFunctionModelId = safeFunctionModelId,
            selectedEmbeddingModelId = safeEmbeddingModelId
        )
    }

    private fun validateModelIdOrNull(rawModelId: String?): String? {
        if (rawModelId == null) return null
        val trimmed = rawModelId.trim()
        if (trimmed.isEmpty()) return null
        val sanitized = Gemma4InputSanitizer.sanitize(trimmed).trim()
        require(sanitized == trimmed && SAFE_MODEL_ID_REGEX.matches(sanitized)) {
            "Invalid modelId '$rawModelId'; only safe model identifiers are permitted"
        }
        // Canonicalize casing when matching an official PinnedModelCatalog entry.
        return PinnedModelCatalog.findByModelId(sanitized)?.modelId ?: sanitized
    }

    companion object {
        const val PREFS_FILE_NAME: String = "nava_onboarding_prefs"
        const val KEY_ONBOARDING_COMPLETED: String = "onboarding_completed"
        const val KEY_DEFAULT_DENY_ACKNOWLEDGED: String = "default_deny_acknowledged"
        const val KEY_SELECTED_MODEL_ID: String = "selected_model_id"
        const val KEY_SELECTED_FUNCTION_MODEL_ID: String = "selected_function_model_id"
        const val KEY_SELECTED_EMBEDDING_MODEL_ID: String = "selected_embedding_model_id"

        private val SAFE_MODEL_ID_REGEX: Regex = Regex("^[A-Za-z0-9._-]{1,64}$")
    }
}

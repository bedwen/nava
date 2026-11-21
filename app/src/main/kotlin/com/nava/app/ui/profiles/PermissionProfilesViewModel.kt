package com.nava.app.ui.profiles

import androidx.lifecycle.ViewModel
import com.nava.app.di.AppContainer
import com.nava.app.di.NeuronToolMapper
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.PermissionProfilePreset
import com.nava.domain.ui.NeuronNodeId
import com.nava.feature.automations.common.ToolTargetIds
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
 * Immutable MVI state for the Security & Permission Profiles screen (PLAN.md Section 5.1).
 */
data class PermissionProfilesUiState(
    val profiles: List<PermissionProfile> = emptyList(),
    val selectedProfileId: String = PermissionProfile.DEFAULT_DENY_PROFILE_ID,
    val selectedTargetId: String = ToolTargetIds.CLOCK,
    val selectedTargetProfile: PermissionProfile = PermissionProfile.defaultDeny(),
    val targetAuditEntries: List<AuditLogEntry> = emptyList(),
    val canonicalTargets: List<String> = DEFAULT_CANONICAL_TARGETS,
    val grantedSafTreeTargets: List<String> = emptyList(),
    val errorMessage: String? = null
) {
    val selectedProfile: PermissionProfile?
        get() = profiles.firstOrNull { it.id == selectedProfileId }

    val builtInPresets: List<PermissionProfile>
        get() = profiles.filter { it.id in PermissionProfile.IMMUTABLE_PRESET_IDS }

    val customProfiles: List<PermissionProfile>
        get() = profiles.filter { it.id !in PermissionProfile.IMMUTABLE_PRESET_IDS }

    companion object {
        val DEFAULT_CANONICAL_TARGETS: List<String> = listOf(
            ToolTargetIds.CLOCK,
            ToolTargetIds.CALENDAR,
            ToolTargetIds.NOTES,
            ToolTargetIds.VAULT,
            ToolTargetIds.SMS,
            ToolTargetIds.PHONE,
            ToolTargetIds.NOTIFICATIONS,
            ToolTargetIds.AUDIO_DND,
            ToolTargetIds.APP_LAUNCH,
            ToolTargetIds.SAF,
            ToolTargetIds.ROUTINES
        )
    }
}

/**
 * MVI ViewModel managing Nava's 5 immutable built-in presets, user-created custom profiles,
 * orthogonal 5-switch [AtomicCapability] levels constrained by [ConfirmationLevel.isValidFor],
 * per-target and per-SAF-tree assignments, and per-target [AuditLogEntry] inspection.
 */
class PermissionProfilesViewModel(
    private val container: AppContainer,
    private val dispatcher: CoroutineDispatcher = Dispatchers.Default,
    private val clockMs: () -> Long = System::currentTimeMillis
) : ViewModel() {

    private val vmScope = CoroutineScope(SupervisorJob() + dispatcher)

    private val _uiState = MutableStateFlow(PermissionProfilesUiState())
    val uiState: StateFlow<PermissionProfilesUiState> = _uiState.asStateFlow()

    init {
        refreshProfilesAndTarget()
    }

    /**
     * Returns all valid [ConfirmationLevel] options for [capability] according to
     * [ConfirmationLevel.isValidFor] (e.g., [AtomicCapability.MODIFY_DELETE_SEND] never allows
     * [ConfirmationLevel.AUTO]).
     */
    fun validLevelsFor(capability: AtomicCapability): List<ConfirmationLevel> {
        return ConfirmationLevel.entries.filter { level -> level.isValidFor(capability) }
    }

    fun refreshProfilesAndTarget(targetIdOverride: String? = null) {
        vmScope.launch {
            val allProfiles = container.manageProfilesUseCase.listProfiles()
            val targetId = targetIdOverride ?: _uiState.value.selectedTargetId
            val targetProfile = container.manageProfilesUseCase.getProfileForTarget(targetId)
            val auditEntries = container.auditLogDao.queryByTarget(
                targetId = targetId,
                limit = DEFAULT_TARGET_AUDIT_LIMIT
            )
            val safTargets = allProfiles
                .flatMap { it.assignedTargets }
                .filter { it.startsWith("saf:") }
                .distinct()

            _uiState.update { state ->
                val activeProfileId = if (allProfiles.any { it.id == state.selectedProfileId }) {
                    state.selectedProfileId
                } else {
                    targetProfile.id
                }
                state.copy(
                    profiles = allProfiles,
                    selectedProfileId = activeProfileId,
                    selectedTargetId = targetId,
                    selectedTargetProfile = targetProfile,
                    targetAuditEntries = auditEntries,
                    grantedSafTreeTargets = safTargets
                )
            }
        }
    }

    fun selectProfile(profileId: String) {
        _uiState.update { state ->
            if (state.profiles.any { it.id == profileId }) {
                state.copy(selectedProfileId = profileId, errorMessage = null)
            } else {
                state
            }
        }
    }

    /**
     * Focuses inspection on [targetId] (or a tapped [NeuronNodeId]), loading its bound
     * [PermissionProfile] and recent [AuditLogEntry] history.
     */
    fun selectTarget(targetId: String) {
        val cleaned = Gemma4InputSanitizer.sanitize(targetId).trim()
        if (cleaned.isEmpty()) return
        refreshProfilesAndTarget(targetIdOverride = cleaned)
    }

    fun selectNeuron(nodeId: NeuronNodeId) {
        val primaryTarget = NeuronToolMapper.primaryTargetIdForNeuron(nodeId)
        selectTarget(primaryTarget)
    }

    /**
     * Creates and saves a new custom [PermissionProfile] derived from [baseProfileId].
     */
    fun createCustomProfile(
        customName: String,
        customId: String = "custom_${UUID.randomUUID().toString().replace("-", "").take(12)}",
        baseProfileId: String = _uiState.value.selectedProfileId
    ) {
        val sanitizedName = Gemma4InputSanitizer.sanitize(customName).trim()
        val sanitizedId = Gemma4InputSanitizer.sanitize(customId).trim()
        if (sanitizedName.isEmpty() || sanitizedId.isEmpty()) {
            _uiState.update { it.copy(errorMessage = "Custom profile name and ID must not be blank") }
            return
        }
        if (sanitizedId in PermissionProfile.IMMUTABLE_PRESET_IDS) {
            _uiState.update {
                it.copy(errorMessage = "Built-in preset profile '$sanitizedId' cannot be modified or overwritten")
            }
            return
        }

        vmScope.launch {
            val now = clockMs()
            val allProfiles = container.manageProfilesUseCase.listProfiles()
            val baseProfile = allProfiles.firstOrNull { it.id == baseProfileId }
                ?: PermissionProfile.defaultDeny()
            val newProfile = PermissionProfile(
                id = sanitizedId,
                name = sanitizedName,
                preset = PermissionProfilePreset.CUSTOM,
                capabilities = baseProfile.capabilities,
                createdAtEpochSec = now / 1000L,
                updatedAtEpochSec = now / 1000L
            )
            try {
                container.manageProfilesUseCase.saveProfile(newProfile, now)
                _uiState.update { it.copy(selectedProfileId = sanitizedId, errorMessage = null) }
                refreshProfilesAndTarget()
            } catch (e: Exception) {
                _uiState.update { it.copy(errorMessage = e.message ?: "Failed to save custom profile") }
            }
        }
    }

    /**
     * Updates a single orthogonal [AtomicCapability] switch on [profileId] without altering
     * any of the other 4 capability switches.
     *
     * Security invariants:
     * - Built-in presets in [PermissionProfile.IMMUTABLE_PRESET_IDS] are strictly immutable and
     *   cannot be modified in place.
     * - Rejects any [ConfirmationLevel] where `!level.isValidFor(capability)`.
     */
    fun updateCapabilitySwitch(
        profileId: String,
        capability: AtomicCapability,
        level: ConfirmationLevel
    ) {
        if (profileId in PermissionProfile.IMMUTABLE_PRESET_IDS) {
            _uiState.update {
                it.copy(errorMessage = "Built-in preset profile '$profileId' is immutable")
            }
            return
        }
        if (!level.isValidFor(capability)) {
            _uiState.update {
                it.copy(errorMessage = "ConfirmationLevel $level is not allowed for capability $capability")
            }
            return
        }

        vmScope.launch {
            val currentProfiles = container.manageProfilesUseCase.listProfiles()
            val profile = currentProfiles.firstOrNull { it.id == profileId }
            if (profile == null) {
                _uiState.update { it.copy(errorMessage = "Profile '$profileId' not found") }
                return@launch
            }
            try {
                container.manageProfilesUseCase.setCapabilityLevel(
                    profile = profile,
                    capability = capability,
                    level = level,
                    nowEpochMs = clockMs()
                )
                _uiState.update { it.copy(errorMessage = null) }
                refreshProfilesAndTarget()
            } catch (e: Exception) {
                _uiState.update { it.copy(errorMessage = e.message ?: "Failed to update capability") }
            }
        }
    }

    /**
     * Deletes a custom profile by [profileId] (resetting any targets bound to it back to Default-Deny).
     * Built-in presets in [PermissionProfile.IMMUTABLE_PRESET_IDS] cannot be deleted.
     */
    fun deleteCustomProfile(profileId: String) {
        if (profileId in PermissionProfile.IMMUTABLE_PRESET_IDS) {
            _uiState.update {
                it.copy(errorMessage = "Built-in preset profile '$profileId' cannot be deleted")
            }
            return
        }

        vmScope.launch {
            try {
                container.manageProfilesUseCase.deleteProfile(profileId, clockMs())
                _uiState.update {
                    it.copy(
                        selectedProfileId = PermissionProfile.DEFAULT_DENY_PROFILE_ID,
                        errorMessage = null
                    )
                }
                refreshProfilesAndTarget()
            } catch (e: Exception) {
                _uiState.update { it.copy(errorMessage = e.message ?: "Failed to delete profile") }
            }
        }
    }

    /**
     * Assigns [targetId] to [profileId] via `ManageProfilesUseCase.assignTarget`.
     */
    fun assignTargetToProfile(
        targetId: String,
        profileId: String = _uiState.value.selectedProfileId
    ) {
        val cleanedTarget = Gemma4InputSanitizer.sanitize(targetId).trim()
        if (cleanedTarget.isEmpty()) return

        vmScope.launch {
            try {
                container.manageProfilesUseCase.assignTarget(
                    targetId = cleanedTarget,
                    profileId = profileId,
                    nowEpochMs = clockMs()
                )
                _uiState.update { it.copy(errorMessage = null) }
                refreshProfilesAndTarget(targetIdOverride = cleanedTarget)
            } catch (e: Exception) {
                _uiState.update { it.copy(errorMessage = e.message ?: "Failed to assign target") }
            }
        }
    }

    /**
     * Binds a user-granted SAF directory tree URI (`ACTION_OPEN_DOCUMENT_TREE`) using
     * canonical per-directory target ID [ToolTargetIds.forSafTree] to [profileId].
     */
    fun onSafDirectoryGranted(
        treeUriString: String,
        profileId: String = _uiState.value.selectedProfileId
    ) {
        val cleanedUri = Gemma4InputSanitizer.sanitize(treeUriString).trim()
        if (cleanedUri.isEmpty()) return
        val safTargetId = ToolTargetIds.forSafTree(cleanedUri)
        assignTargetToProfile(targetId = safTargetId, profileId = profileId)
    }

    override fun onCleared() {
        super.onCleared()
        vmScope.cancel()
    }

    companion object {
        const val DEFAULT_TARGET_AUDIT_LIMIT: Int = 15
    }
}

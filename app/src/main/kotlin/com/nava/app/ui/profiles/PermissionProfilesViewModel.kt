package com.nava.app.ui.profiles

import android.Manifest
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
import com.nava.feature.automations.common.InstalledAppInfo
import com.nava.feature.automations.common.ToolTargetIds
import com.nava.feature.automations.notification.NotificationServiceBinding
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
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

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
    val installedApps: List<InstalledAppInfo> = emptyList(),
    val appSearchQuery: String = "",
    val showOnlyPermittedApps: Boolean = false,
    val targetProfilesById: Map<String, PermissionProfile> = emptyMap(),
    val canPostNotifications: Boolean = true,
    val isNotificationListenerEnabled: Boolean = false,
    val isNotificationPolicyAccessGranted: Boolean = false,
    val hasReadCalendarPermission: Boolean = false,
    val hasWriteCalendarPermission: Boolean = false,
    val hasCallPhonePermission: Boolean = false,
    val errorMessage: String? = null
) {
    val selectedProfile: PermissionProfile?
        get() = profiles.firstOrNull { it.id == selectedProfileId }

    val builtInPresets: List<PermissionProfile>
        get() = profiles.filter { it.id in PermissionProfile.IMMUTABLE_PRESET_IDS }

    val customProfiles: List<PermissionProfile>
        get() = profiles.filter { it.id !in PermissionProfile.IMMUTABLE_PRESET_IDS }

    /** General profiles shown in the preset selector (excludes per-target auto-forked overrides). */
    val visibleGeneralProfiles: List<PermissionProfile>
        get() = profiles.filter { !it.id.startsWith(AUTO_FORK_PREFIX) }

    val filteredInstalledApps: List<InstalledAppInfo>
        get() {
            val base = if (showOnlyPermittedApps) {
                installedApps.filter { app ->
                    val p = targetProfilesById[app.packageName]
                    p != null && p.capabilities.values.any { it.isAllowed }
                }
            } else {
                installedApps
            }
            if (appSearchQuery.isBlank()) return base
            val query = appSearchQuery.trim().lowercase()
            return base.filter { app ->
                app.displayLabel.lowercase().contains(query) ||
                    app.packageName.lowercase().contains(query)
            }
        }

    companion object {
        const val AUTO_FORK_PREFIX: String = "custom_target_"
        val DEFAULT_CANONICAL_TARGETS: List<String> = listOf(
            ToolTargetIds.CLOCK,
            ToolTargetIds.REMINDERS,
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
    private val toggleMutex = Mutex()

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

    fun refreshProfilesAndTarget(
        targetIdOverride: String? = null,
        syncSelectedProfileToTarget: Boolean = true,
        reloadInstalledApps: Boolean = false
    ) {
        vmScope.launch {
            try {
                val allProfiles = runCatching {
                    container.manageProfilesUseCase.listProfiles()
                }.getOrDefault(emptyList())

                val defaultDeny = allProfiles.firstOrNull {
                    it.id == PermissionProfile.DEFAULT_DENY_PROFILE_ID
                } ?: PermissionProfile.defaultDeny()

                // O(N) in-memory index from the single listProfiles() read: eliminates 100+
                // redundant encrypted SQLite + Keystore TEE decrypt calls per tap.
                val assignedTargetIndex = HashMap<String, PermissionProfile>()
                for (profile in allProfiles) {
                    for (assigned in profile.assignedTargets) {
                        assignedTargetIndex[assigned] = profile
                    }
                }

                val targetId = targetIdOverride ?: _uiState.value.selectedTargetId
                val targetProfile = assignedTargetIndex[targetId] ?: runCatching {
                    container.manageProfilesUseCase.getProfileForTarget(targetId)
                }.getOrDefault(defaultDeny)

                val auditEntries = runCatching {
                    container.auditLogDao.queryByTarget(
                        targetId = targetId,
                        limit = DEFAULT_TARGET_AUDIT_LIMIT
                    )
                }.getOrDefault(emptyList())

                val safTargets = allProfiles
                    .flatMap { it.assignedTargets }
                    .filter { it.startsWith("saf:") }
                    .distinct()

                val existingApps = _uiState.value.installedApps
                val installed = if (existingApps.isEmpty() || reloadInstalledApps) {
                    runCatching {
                        container.intentGateway.listLaunchableApps()
                            .filterNot { it.packageName == "com.nava.app" }
                    }.getOrDefault(existingApps)
                } else {
                    existingApps
                }

                val targetProfilesMap = HashMap<String, PermissionProfile>(
                    _uiState.value.canonicalTargets.size + installed.size + safTargets.size
                )
                for (target in _uiState.value.canonicalTargets) {
                    targetProfilesMap[target] = assignedTargetIndex[target] ?: defaultDeny
                }
                for (safTarget in safTargets) {
                    targetProfilesMap[safTarget] = assignedTargetIndex[safTarget] ?: defaultDeny
                }
                for (app in installed) {
                    val pkgTarget = ToolTargetIds.forPackage(app.packageName)
                    targetProfilesMap[pkgTarget] = assignedTargetIndex[pkgTarget] ?: defaultDeny
                }

                val canPostNotifs = runCatching {
                    container.intentGateway.canPostNotifications()
                }.getOrDefault(true)

                val notifListenerEnabled = runCatching {
                    container.intentGateway.isNotificationListenerEnabled()
                }.getOrDefault(false)

                val notifPolicyGranted = runCatching {
                    container.intentGateway.isNotificationPolicyAccessGranted()
                }.getOrDefault(false)

                val readCalendarGranted = runCatching {
                    container.intentGateway.hasRuntimePermission(Manifest.permission.READ_CALENDAR)
                }.getOrDefault(false)

                val writeCalendarGranted = runCatching {
                    container.intentGateway.hasRuntimePermission(Manifest.permission.WRITE_CALENDAR)
                }.getOrDefault(false)

                val callPhoneGranted = runCatching {
                    container.intentGateway.hasRuntimePermission(Manifest.permission.CALL_PHONE)
                }.getOrDefault(false)

                _uiState.update { state ->
                    val activeProfileId = if (syncSelectedProfileToTarget) {
                        targetProfile.id
                    } else if (allProfiles.any { it.id == state.selectedProfileId }) {
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
                        grantedSafTreeTargets = safTargets,
                        installedApps = installed,
                        targetProfilesById = targetProfilesMap,
                        canPostNotifications = canPostNotifs,
                        isNotificationListenerEnabled = notifListenerEnabled,
                        isNotificationPolicyAccessGranted = notifPolicyGranted,
                        hasReadCalendarPermission = readCalendarGranted,
                        hasWriteCalendarPermission = writeCalendarGranted,
                        hasCallPhonePermission = callPhoneGranted
                    )
                }
            } catch (t: Throwable) {
                _uiState.update { it.copy(errorMessage = t.message ?: "Failed to refresh profiles") }
            }
        }
    }

    fun onAppSearchQueryChanged(query: String) {
        val sanitized = Gemma4InputSanitizer.sanitize(query)
        _uiState.update { it.copy(appSearchQuery = sanitized) }
    }

    fun onToggleShowOnlyPermittedApps() {
        _uiState.update { it.copy(showOnlyPermittedApps = !it.showOnlyPermittedApps) }
    }

    /**
     * Ensures [PermissionProfilesUiState.selectedTargetId] points to a core or SAF target when
     * the user switches back to the Features tab after inspecting an installed app package.
     */
    fun ensureCoreTargetSelected() {
        val current = _uiState.value.selectedTargetId
        val isCoreOrSaf = current in _uiState.value.canonicalTargets || current.startsWith("saf:")
        if (!isCoreOrSaf) {
            selectTarget(ToolTargetIds.CLOCK)
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
        refreshProfilesAndTarget(targetIdOverride = cleaned, syncSelectedProfileToTarget = true)
    }

    fun selectNeuron(nodeId: NeuronNodeId) {
        val primaryTarget = NeuronToolMapper.primaryTargetIdForNeuron(nodeId)
        selectTarget(primaryTarget)
    }

    /**
     * Assigns all core capability targets to [profileId] in a single atomic batch.
     */
    fun assignAllCoreTargetsToProfile(profileId: String) {
        val targetsToAssign = listOf(
            ToolTargetIds.CLOCK,
            ToolTargetIds.REMINDERS,
            ToolTargetIds.CALENDAR,
            ToolTargetIds.NOTES,
            ToolTargetIds.SMS,
            ToolTargetIds.PHONE,
            ToolTargetIds.NOTIFICATIONS,
            ToolTargetIds.AUDIO_DND,
            ToolTargetIds.APP_LAUNCH,
            ToolTargetIds.ROUTINES
        )
        vmScope.launch {
            toggleMutex.withLock {
                try {
                    val now = clockMs()
                    for (target in targetsToAssign) {
                        container.manageProfilesUseCase.assignTarget(
                            targetId = target,
                            profileId = profileId,
                            nowEpochMs = now
                        )
                    }
                    _uiState.update { it.copy(selectedProfileId = profileId, errorMessage = null) }
                    refreshProfilesAndTarget(syncSelectedProfileToTarget = true)
                } catch (e: Exception) {
                    _uiState.update { it.copy(errorMessage = e.message ?: "Failed to assign core targets") }
                }
            }
        }
    }

    /**
     * Toggles a capability switch on the currently selected target. When the active profile
     * is an immutable built-in preset, automatically forks a custom target profile and saves it.
     */
    fun toggleTargetCapability(capability: AtomicCapability, level: ConfirmationLevel) {
        setTargetCapability(_uiState.value.selectedTargetId, capability, level)
    }

    /**
     * Toggles [capability] for a specific [targetId] directly (used by both the core target
     * editor and the per-app Bottom Sheet). Automatically forks a per-target custom profile
     * when [targetId] is currently bound to an immutable built-in preset.
     */
    fun setTargetCapability(
        targetId: String,
        capability: AtomicCapability,
        level: ConfirmationLevel
    ) {
        val cleanedTarget = Gemma4InputSanitizer.sanitize(targetId).trim()
        if (cleanedTarget.isEmpty()) return
        vmScope.launch {
            toggleMutex.withLock {
                try {
                    val now = clockMs()
                    val currentTargetProfile = runCatching {
                        container.manageProfilesUseCase.getProfileForTarget(cleanedTarget)
                    }.getOrNull() ?: PermissionProfile.defaultDeny()
                    val isBuiltIn = currentTargetProfile.id in PermissionProfile.IMMUTABLE_PRESET_IDS
                    if (isBuiltIn) {
                        val customId = customTargetProfileId(cleanedTarget)
                        val customName = "${currentTargetProfile.name} ($cleanedTarget)"
                        val updated = currentTargetProfile.withCapability(
                            capability = capability,
                            level = level,
                            updatedAtEpochSec = now / 1000L,
                            newProfileId = customId,
                            newProfileName = customName
                        )
                        container.manageProfilesUseCase.saveProfile(updated, now)
                        container.manageProfilesUseCase.assignTarget(
                            targetId = cleanedTarget,
                            profileId = customId,
                            nowEpochMs = now
                        )
                    } else {
                        container.manageProfilesUseCase.setCapabilityLevel(
                            profile = currentTargetProfile,
                            capability = capability,
                            level = level,
                            nowEpochMs = now
                        )
                    }
                    val isPackageName = !cleanedTarget.startsWith("system.") &&
                        !cleanedTarget.startsWith("nava.") &&
                        !cleanedTarget.startsWith("saf:")
                    if (isPackageName && capability == AtomicCapability.NOTIFICATION_READ && level.isAllowed) {
                        val currentNotifProfile = container.manageProfilesUseCase.getProfileForTarget(ToolTargetIds.NOTIFICATIONS)
                        if (currentNotifProfile.id == PermissionProfile.DEFAULT_DENY_PROFILE_ID) {
                            container.manageProfilesUseCase.assignTarget(
                                targetId = ToolTargetIds.NOTIFICATIONS,
                                profileId = PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID,
                                nowEpochMs = now
                            )
                        }
                        NotificationServiceBinding.requestActiveNotificationsResync()
                    }
                    _uiState.update { it.copy(errorMessage = null) }
                    refreshProfilesAndTarget(targetIdOverride = cleanedTarget, syncSelectedProfileToTarget = true)
                } catch (e: Exception) {
                    _uiState.update { it.copy(errorMessage = e.message ?: "Failed to toggle capability") }
                }
            }
        }
    }

    /**
     * Returns the primary [AtomicCapability] switches that actually apply to [targetId],
     * so the UI highlights relevant controls first while still allowing full access to all 5
     * orthogonal switches (Iron Law 5).
     */
    fun primaryCapabilitiesForTarget(targetId: String): List<AtomicCapability> {
        return when {
            targetId == ToolTargetIds.CLOCK -> listOf(AtomicCapability.CREATE_DRAFT)
            targetId == ToolTargetIds.REMINDERS -> listOf(
                AtomicCapability.CREATE_DRAFT,
                AtomicCapability.MODIFY_DELETE_SEND
            )
            targetId == ToolTargetIds.CALENDAR -> listOf(
                AtomicCapability.DATA_READ,
                AtomicCapability.CREATE_DRAFT,
                AtomicCapability.MODIFY_DELETE_SEND
            )
            targetId == ToolTargetIds.NOTES || targetId == ToolTargetIds.VAULT -> listOf(
                AtomicCapability.DATA_READ,
                AtomicCapability.CREATE_DRAFT,
                AtomicCapability.MODIFY_DELETE_SEND
            )
            targetId == ToolTargetIds.SMS -> listOf(AtomicCapability.CREATE_DRAFT)
            targetId == ToolTargetIds.PHONE -> listOf(
                AtomicCapability.CREATE_DRAFT,
                AtomicCapability.MODIFY_DELETE_SEND
            )
            targetId == ToolTargetIds.NOTIFICATIONS -> listOf(
                AtomicCapability.NOTIFICATION_READ,
                AtomicCapability.CREATE_DRAFT,
                AtomicCapability.MODIFY_DELETE_SEND
            )
            targetId == ToolTargetIds.AUDIO_DND -> listOf(AtomicCapability.CREATE_DRAFT)
            targetId == ToolTargetIds.APP_LAUNCH -> listOf(AtomicCapability.APP_LAUNCH)
            targetId == ToolTargetIds.SAF || targetId.startsWith("saf:") -> listOf(
                AtomicCapability.DATA_READ,
                AtomicCapability.CREATE_DRAFT,
                AtomicCapability.MODIFY_DELETE_SEND
            )
            targetId == ToolTargetIds.ROUTINES -> listOf(AtomicCapability.CREATE_DRAFT)
            else -> listOf(
                AtomicCapability.NOTIFICATION_READ,
                AtomicCapability.APP_LAUNCH
            )
        }
    }

    /**
     * Applies a single confirmation [level] across [capabilities] for [targetId] in one atomic
     * operation. Automatically clamps [AtomicCapability.MODIFY_DELETE_SEND] from `AUTO` to
     * `PROMPT_CARD` to uphold Iron Law 5/6, and resets [targetId] to Default-Deny when all
     * capabilities become disabled.
     */
    fun applyQuickLevelToTarget(
        targetId: String,
        capabilities: List<AtomicCapability>,
        level: ConfirmationLevel
    ) {
        val cleanedTarget = Gemma4InputSanitizer.sanitize(targetId).trim()
        if (cleanedTarget.isEmpty() || capabilities.isEmpty()) return
        vmScope.launch {
            toggleMutex.withLock {
                try {
                    val now = clockMs()
                    applyQuickLevelInternal(
                        cleanedTarget = cleanedTarget,
                        capabilities = capabilities,
                        level = level,
                        now = now
                    )
                    _uiState.update { it.copy(errorMessage = null) }
                    refreshProfilesAndTarget(targetIdOverride = cleanedTarget, syncSelectedProfileToTarget = true)
                } catch (e: Exception) {
                    _uiState.update { it.copy(errorMessage = e.message ?: "Failed to update permissions") }
                }
            }
        }
    }

    /**
     * One-tap toggle for a single capability on an installed app row: switches between
     * `DISABLED` and `AUTO` (or `PROMPT_CARD` if `AUTO` is disallowed for that capability).
     */
    fun toggleAppQuickCapability(packageName: String, capability: AtomicCapability) {
        val cleaned = Gemma4InputSanitizer.sanitize(packageName).trim()
        if (cleaned.isEmpty()) return
        val currentLevel = _uiState.value.targetProfilesById[cleaned]?.levelFor(capability)
            ?: ConfirmationLevel.DISABLED
        val nextLevel = if (currentLevel.isAllowed) {
            ConfirmationLevel.DISABLED
        } else if (ConfirmationLevel.AUTO.isValidFor(capability)) {
            ConfirmationLevel.AUTO
        } else {
            ConfirmationLevel.PROMPT_CARD
        }
        setTargetCapability(targetId = cleaned, capability = capability, level = nextLevel)
    }

    /**
     * Bulk-applies [capability] = [level] to every app in [packageNames] (used by the Apps tab
     * quick bulk actions) and performs a single state refresh at the end.
     */
    fun applyCapabilityToApps(
        packageNames: List<String>,
        capability: AtomicCapability,
        level: ConfirmationLevel
    ) {
        if (packageNames.isEmpty()) return
        vmScope.launch {
            toggleMutex.withLock {
                try {
                    val now = clockMs()
                    var enabledAnyNotif = false
                    for (pkg in packageNames) {
                        val cleaned = Gemma4InputSanitizer.sanitize(pkg).trim()
                        if (cleaned.isEmpty()) continue
                        applyQuickLevelInternal(
                            cleanedTarget = cleaned,
                            capabilities = listOf(capability),
                            level = level,
                            now = now,
                            triggerNotifSync = false
                        )
                        if (capability == AtomicCapability.NOTIFICATION_READ && level.isAllowed) {
                            enabledAnyNotif = true
                        }
                    }
                    if (enabledAnyNotif) {
                        ensureSystemNotificationsEnabled(now)
                        NotificationServiceBinding.requestActiveNotificationsResync()
                    }
                    _uiState.update { it.copy(errorMessage = null) }
                    refreshProfilesAndTarget(syncSelectedProfileToTarget = true)
                } catch (e: Exception) {
                    _uiState.update { it.copy(errorMessage = e.message ?: "Failed to update apps") }
                }
            }
        }
    }

    /**
     * Resets all apps in [packageNames] back to Default-Deny (`Strictly Isolated`).
     */
    fun resetAppsToDefaultDeny(packageNames: List<String>) {
        if (packageNames.isEmpty()) return
        vmScope.launch {
            toggleMutex.withLock {
                try {
                    val now = clockMs()
                    for (pkg in packageNames) {
                        val cleaned = Gemma4InputSanitizer.sanitize(pkg).trim()
                        if (cleaned.isEmpty()) continue
                        container.manageProfilesUseCase.assignTarget(
                            targetId = cleaned,
                            profileId = PermissionProfile.DEFAULT_DENY_PROFILE_ID,
                            nowEpochMs = now
                        )
                    }
                    _uiState.update { it.copy(errorMessage = null) }
                    refreshProfilesAndTarget(syncSelectedProfileToTarget = true)
                } catch (e: Exception) {
                    _uiState.update { it.copy(errorMessage = e.message ?: "Failed to reset apps") }
                }
            }
        }
    }

    /**
     * Applies [level] across the primary capabilities of all core features (excluding Vault,
     * which stays under explicit user control).
     */
    fun applyQuickLevelToAllCoreTargets(level: ConfirmationLevel) {
        val coreTargets = listOf(
            ToolTargetIds.CLOCK,
            ToolTargetIds.REMINDERS,
            ToolTargetIds.CALENDAR,
            ToolTargetIds.NOTES,
            ToolTargetIds.SMS,
            ToolTargetIds.PHONE,
            ToolTargetIds.NOTIFICATIONS,
            ToolTargetIds.AUDIO_DND,
            ToolTargetIds.APP_LAUNCH,
            ToolTargetIds.ROUTINES
        )
        vmScope.launch {
            toggleMutex.withLock {
                try {
                    val now = clockMs()
                    for (target in coreTargets) {
                        if (level == ConfirmationLevel.DISABLED) {
                            container.manageProfilesUseCase.assignTarget(
                                targetId = target,
                                profileId = PermissionProfile.DEFAULT_DENY_PROFILE_ID,
                                nowEpochMs = now
                            )
                        } else {
                            applyQuickLevelInternal(
                                cleanedTarget = target,
                                capabilities = primaryCapabilitiesForTarget(target),
                                level = level,
                                now = now,
                                triggerNotifSync = false
                            )
                        }
                    }
                    if (level.isAllowed) {
                        NotificationServiceBinding.requestActiveNotificationsResync()
                    }
                    _uiState.update { it.copy(errorMessage = null) }
                    refreshProfilesAndTarget(syncSelectedProfileToTarget = true)
                } catch (e: Exception) {
                    _uiState.update { it.copy(errorMessage = e.message ?: "Failed to update all features") }
                }
            }
        }
    }

    private suspend fun applyQuickLevelInternal(
        cleanedTarget: String,
        capabilities: List<AtomicCapability>,
        level: ConfirmationLevel,
        now: Long,
        triggerNotifSync: Boolean = true
    ) {
        if (level == ConfirmationLevel.DISABLED && capabilities.size == AtomicCapability.entries.size) {
            container.manageProfilesUseCase.assignTarget(
                targetId = cleanedTarget,
                profileId = PermissionProfile.DEFAULT_DENY_PROFILE_ID,
                nowEpochMs = now
            )
            return
        }
        val currentTargetProfile = runCatching {
            container.manageProfilesUseCase.getProfileForTarget(cleanedTarget)
        }.getOrNull() ?: PermissionProfile.defaultDeny()

        val updatedMap = currentTargetProfile.capabilities.toMutableMap()
        for (cap in capabilities) {
            val safeLevel = if (level.isValidFor(cap)) {
                level
            } else if (level == ConfirmationLevel.AUTO) {
                ConfirmationLevel.PROMPT_CARD
            } else {
                ConfirmationLevel.DISABLED
            }
            updatedMap[cap] = safeLevel
        }

        if (updatedMap.values.none { it.isAllowed }) {
            container.manageProfilesUseCase.assignTarget(
                targetId = cleanedTarget,
                profileId = PermissionProfile.DEFAULT_DENY_PROFILE_ID,
                nowEpochMs = now
            )
            return
        }

        val isBuiltIn = currentTargetProfile.id in PermissionProfile.IMMUTABLE_PRESET_IDS
        val targetProfileId = if (isBuiltIn) customTargetProfileId(cleanedTarget) else currentTargetProfile.id
        val targetProfileName = if (isBuiltIn) {
            "${currentTargetProfile.name} ($cleanedTarget)"
        } else {
            currentTargetProfile.name
        }
        val updatedProfile = PermissionProfile(
            id = targetProfileId,
            name = targetProfileName,
            preset = PermissionProfilePreset.CUSTOM,
            capabilities = updatedMap,
            assignedTargets = currentTargetProfile.assignedTargets,
            createdAtEpochSec = currentTargetProfile.createdAtEpochSec,
            updatedAtEpochSec = now / 1000L
        )
        container.manageProfilesUseCase.saveProfile(updatedProfile, now)
        container.manageProfilesUseCase.assignTarget(
            targetId = cleanedTarget,
            profileId = targetProfileId,
            nowEpochMs = now
        )

        val isPackageName = !cleanedTarget.startsWith("system.") &&
            !cleanedTarget.startsWith("nava.") &&
            !cleanedTarget.startsWith("saf:")
        if (triggerNotifSync && isPackageName &&
            AtomicCapability.NOTIFICATION_READ in capabilities && level.isAllowed
        ) {
            ensureSystemNotificationsEnabled(now)
            NotificationServiceBinding.requestActiveNotificationsResync()
        }
    }

    private suspend fun ensureSystemNotificationsEnabled(now: Long) {
        val currentNotifProfile = container.manageProfilesUseCase.getProfileForTarget(ToolTargetIds.NOTIFICATIONS)
        if (currentNotifProfile.id == PermissionProfile.DEFAULT_DENY_PROFILE_ID) {
            container.manageProfilesUseCase.assignTarget(
                targetId = ToolTargetIds.NOTIFICATIONS,
                profileId = PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID,
                nowEpochMs = now
            )
        }
    }

    /** Collision-safe deterministic custom profile id: sanitized prefix plus hash of the full target id. */
    private fun customTargetProfileId(targetId: String): String {
        val prefix = targetId.replace(Regex("[^A-Za-z0-9_]"), "_").take(32)
        val hash = Integer.toHexString(targetId.hashCode()) + Integer.toHexString(targetId.length)
        return "custom_target_${prefix}_$hash"
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
                refreshProfilesAndTarget(syncSelectedProfileToTarget = false)
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
                refreshProfilesAndTarget(syncSelectedProfileToTarget = false)
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
                refreshProfilesAndTarget(syncSelectedProfileToTarget = false)
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
            toggleMutex.withLock {
                try {
                    val now = clockMs()
                    container.manageProfilesUseCase.assignTarget(
                        targetId = cleanedTarget,
                        profileId = profileId,
                        nowEpochMs = now
                    )
                    val isPackageName = !cleanedTarget.startsWith("system.") &&
                        !cleanedTarget.startsWith("nava.") &&
                        !cleanedTarget.startsWith("saf:")
                    if (isPackageName) {
                        val assignedProfile = container.manageProfilesUseCase.listProfiles()
                            .firstOrNull { it.id == profileId }
                        val notifLevel = assignedProfile?.capabilities?.get(AtomicCapability.NOTIFICATION_READ)
                        if (notifLevel != null && notifLevel != ConfirmationLevel.DISABLED) {
                            val currentNotifProfile = container.manageProfilesUseCase.getProfileForTarget(ToolTargetIds.NOTIFICATIONS)
                            if (currentNotifProfile.id == PermissionProfile.DEFAULT_DENY_PROFILE_ID) {
                                container.manageProfilesUseCase.assignTarget(
                                    targetId = ToolTargetIds.NOTIFICATIONS,
                                    profileId = PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID,
                                    nowEpochMs = now
                                )
                            }
                            NotificationServiceBinding.requestActiveNotificationsResync()
                        }
                    }
                    _uiState.update { it.copy(errorMessage = null) }
                    refreshProfilesAndTarget(targetIdOverride = cleanedTarget, syncSelectedProfileToTarget = true)
                } catch (e: Exception) {
                    _uiState.update { it.copy(errorMessage = e.message ?: "Failed to assign target") }
                }
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

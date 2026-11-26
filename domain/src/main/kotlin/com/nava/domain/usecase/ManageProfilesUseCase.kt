package com.nava.domain.usecase

import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.PermissionEvaluatorPort
import com.nava.domain.security.PermissionProfile

/**
 * Manages user-configured orthogonal [PermissionProfile] definitions and target bindings.
 */
class ManageProfilesUseCase(
    private val permissionEvaluator: PermissionEvaluatorPort,
    private val auditLog: AuditLogPort
) {
    suspend fun listProfiles(): List<PermissionProfile> = permissionEvaluator.listProfiles()

    suspend fun getProfileForTarget(targetId: String): PermissionProfile {
        return permissionEvaluator.getProfileForTarget(targetId)
    }

    suspend fun saveProfile(profile: PermissionProfile, nowEpochMs: Long) {
        require(profile.id !in PermissionProfile.IMMUTABLE_PRESET_IDS) {
            "Built-in preset profile '${profile.id}' cannot be modified or overwritten"
        }
        permissionEvaluator.saveProfile(profile)
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = nowEpochMs,
                toolName = "system.permission_profile",
                targetId = profile.id,
                actionSummary = "Saved permission profile '${profile.name}'",
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "PROFILE_SAVED"
            )
        )
    }

    suspend fun setCapabilityLevel(
        profile: PermissionProfile,
        capability: AtomicCapability,
        level: ConfirmationLevel,
        nowEpochMs: Long
    ): PermissionProfile {
        require(profile.id !in PermissionProfile.IMMUTABLE_PRESET_IDS) {
            "Built-in preset profile '${profile.id}' cannot be modified or overwritten"
        }
        val updated = profile.withCapability(
            capability = capability,
            level = level,
            updatedAtEpochSec = nowEpochMs / 1000L
        )
        permissionEvaluator.saveProfile(updated)
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = nowEpochMs,
                toolName = "system.permission_profile",
                targetId = updated.id,
                actionSummary = "Updated $capability to $level",
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "CAPABILITY_UPDATED"
            )
        )
        return updated
    }

    /**
     * Sets [capability] to [level] for [targetId] alone (used by the just-in-time grant on a
     * denial card). Unless [targetId] is already bound to its own per-target profile, the
     * current profile is copied into a fresh per-target profile first, so a one-tap grant can
     * never silently widen the permissions of other targets sharing a preset or custom profile.
     *
     * @throws IllegalArgumentException when [level] is not structurally valid for [capability]
     *   (for example `AUTO` for `MODIFY_DELETE_SEND`).
     */
    suspend fun setCapabilityForTarget(
        targetId: String,
        capability: AtomicCapability,
        level: ConfirmationLevel,
        nowEpochMs: Long
    ): PermissionProfile {
        require(targetId.isNotBlank()) { "targetId must not be blank" }
        require(level.isValidFor(capability)) {
            "ConfirmationLevel $level is not allowed for capability $capability"
        }
        val current = permissionEvaluator.getProfileForTarget(targetId)
        val ownId = perTargetProfileId(targetId)
        if (current.id == ownId) {
            return setCapabilityLevel(current, capability, level, nowEpochMs)
        }
        val forked = current.withCapability(
            capability = capability,
            level = level,
            updatedAtEpochSec = nowEpochMs / 1000L,
            newProfileId = ownId,
            newProfileName = "${current.name} ($targetId)"
        )
        saveProfile(forked, nowEpochMs)
        assignTarget(targetId = targetId, profileId = ownId, nowEpochMs = nowEpochMs)
        return forked
    }

    suspend fun assignTarget(targetId: String, profileId: String, nowEpochMs: Long) {
        permissionEvaluator.assignTargetToProfile(targetId, profileId)
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = nowEpochMs,
                toolName = "system.permission_profile",
                targetId = targetId,
                actionSummary = "Assigned target to profile $profileId",
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "TARGET_ASSIGNED"
            )
        )
    }

    suspend fun deleteProfile(profileId: String, nowEpochMs: Long) {
        require(profileId !in PermissionProfile.IMMUTABLE_PRESET_IDS) {
            "Built-in preset profile '$profileId' cannot be deleted"
        }
        permissionEvaluator.deleteProfile(profileId)
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = nowEpochMs,
                toolName = "system.permission_profile",
                targetId = profileId,
                actionSummary = "Deleted permission profile $profileId",
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "PROFILE_DELETED"
            )
        )
    }

    companion object {
        /**
         * Collision-safe deterministic per-target profile id: sanitized prefix plus a hash of the
         * full target id. Shared with the permission profiles screen so both edit the same profile.
         */
        fun perTargetProfileId(targetId: String): String {
            val prefix = targetId.replace(Regex("[^A-Za-z0-9_]"), "_").take(32)
            val hash = targetId.hashCode().toUInt().toString(16) + targetId.length.toString(16)
            return "custom_target_${prefix}_$hash"
        }
    }
}

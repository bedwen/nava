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
}

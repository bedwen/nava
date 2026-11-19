package com.nava.domain.security

/**
 * Port managing orthogonal [PermissionProfile] definitions and target assignments.
 */
interface PermissionEvaluatorPort {
    /**
     * Resolves the [PermissionProfile] bound to [targetId], returning
     * [PermissionProfile.defaultDeny] if [targetId] has never been explicitly granted access.
     */
    suspend fun getProfileForTarget(targetId: String): PermissionProfile

    /** Evaluates the current confirmation gate for [capability] on [targetId]. */
    suspend fun evaluateCapability(targetId: String, capability: AtomicCapability): ConfirmationLevel

    suspend fun listProfiles(): List<PermissionProfile>

    suspend fun saveProfile(profile: PermissionProfile)

    suspend fun assignTargetToProfile(targetId: String, profileId: String)

    suspend fun deleteProfile(profileId: String)
}

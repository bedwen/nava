package com.nava.domain.security

/**
 * Orthogonal capability profile assigned to apps, notification sources, or SAF directories.
 *
 * Unspecified capabilities always default to [ConfirmationLevel.DISABLED] (Default-Deny).
 */
data class PermissionProfile(
    val id: String,
    val name: String,
    val preset: PermissionProfilePreset,
    val capabilities: Map<AtomicCapability, ConfirmationLevel>,
    val assignedTargets: Set<String> = emptySet(),
    val createdAtEpochSec: Long = 0L,
    val updatedAtEpochSec: Long = 0L
) {
    init {
        require(id.isNotBlank()) { "PermissionProfile id must not be blank" }
        require(name.isNotBlank()) { "PermissionProfile name must not be blank" }
        for ((capability, level) in capabilities) {
            require(level.isValidFor(capability)) {
                "ConfirmationLevel $level is not allowed for capability $capability"
            }
        }
    }

    /** Returns the configured confirmation gate, defaulting to [ConfirmationLevel.DISABLED]. */
    fun levelFor(capability: AtomicCapability): ConfirmationLevel {
        return capabilities[capability] ?: ConfirmationLevel.DISABLED
    }

    /** Returns true if [capability] is enabled under any confirmation gate. */
    fun isCapabilityAllowed(capability: AtomicCapability): Boolean {
        return levelFor(capability).isAllowed
    }

    /**
     * Returns an updated profile with only [capability] changed, preserving all other
     * orthogonal capability switches.
     *
     * Calling this on a built-in preset automatically mints a non-preset custom profile ID
     * unless [newProfileId] supplies an explicit custom ID (built-in preset IDs are rejected).
     */
    fun withCapability(
        capability: AtomicCapability,
        level: ConfirmationLevel,
        updatedAtEpochSec: Long = this.updatedAtEpochSec,
        newProfileId: String? = null,
        newProfileName: String? = null
    ): PermissionProfile {
        require(level.isValidFor(capability)) {
            "ConfirmationLevel $level is not allowed for capability $capability"
        }
        val isBuiltInPreset = this.id in IMMUTABLE_PRESET_IDS
        val resolvedId = if (isBuiltInPreset) {
            newProfileId ?: "custom_from_${this.id}"
        } else {
            newProfileId ?: this.id
        }
        require(resolvedId !in IMMUTABLE_PRESET_IDS) {
            "Built-in preset profile ID '$resolvedId' is immutable"
        }
        val resolvedName = newProfileName ?: if (isBuiltInPreset) {
            "${this.name} (Custom)"
        } else {
            this.name
        }
        val nextMap = capabilities.toMutableMap()
        nextMap[capability] = level
        return copy(
            id = resolvedId,
            name = resolvedName,
            preset = PermissionProfilePreset.CUSTOM,
            capabilities = nextMap.toMap(),
            updatedAtEpochSec = updatedAtEpochSec
        )
    }

    companion object {
        const val DEFAULT_DENY_PROFILE_ID = "preset_strictly_isolated"
        const val NOTIFICATION_SUMMARY_PROFILE_ID = "preset_notification_summary"
        const val SAFE_DRAFT_PROFILE_ID = "preset_safe_draft_communication"
        const val TRUSTED_SYSTEM_PROFILE_ID = "preset_trusted_system_automation"
        const val BIOMETRIC_HIGH_SECURITY_PROFILE_ID = "preset_biometric_high_security"

        val IMMUTABLE_PRESET_IDS: Set<String> = setOf(
            DEFAULT_DENY_PROFILE_ID,
            NOTIFICATION_SUMMARY_PROFILE_ID,
            SAFE_DRAFT_PROFILE_ID,
            TRUSTED_SYSTEM_PROFILE_ID,
            BIOMETRIC_HIGH_SECURITY_PROFILE_ID
        )

        fun defaultDeny(): PermissionProfile = PermissionProfile(
            id = DEFAULT_DENY_PROFILE_ID,
            name = "Strictly Isolated (Default-Deny)",
            preset = PermissionProfilePreset.STRICTLY_ISOLATED,
            capabilities = mapOf(
                AtomicCapability.NOTIFICATION_READ to ConfirmationLevel.DISABLED,
                AtomicCapability.DATA_READ to ConfirmationLevel.DISABLED,
                AtomicCapability.CREATE_DRAFT to ConfirmationLevel.DISABLED,
                AtomicCapability.MODIFY_DELETE_SEND to ConfirmationLevel.DISABLED,
                AtomicCapability.APP_LAUNCH to ConfirmationLevel.DISABLED
            )
        )

        fun notificationSummaryOnly(): PermissionProfile = PermissionProfile(
            id = NOTIFICATION_SUMMARY_PROFILE_ID,
            name = "Notification Summary Only",
            preset = PermissionProfilePreset.NOTIFICATION_SUMMARY_ONLY,
            capabilities = mapOf(
                AtomicCapability.NOTIFICATION_READ to ConfirmationLevel.AUTO,
                AtomicCapability.DATA_READ to ConfirmationLevel.DISABLED,
                AtomicCapability.CREATE_DRAFT to ConfirmationLevel.DISABLED,
                AtomicCapability.MODIFY_DELETE_SEND to ConfirmationLevel.DISABLED,
                AtomicCapability.APP_LAUNCH to ConfirmationLevel.DISABLED
            )
        )

        fun safeDraftAndCommunication(): PermissionProfile = PermissionProfile(
            id = SAFE_DRAFT_PROFILE_ID,
            name = "Safe Draft & Communication",
            preset = PermissionProfilePreset.SAFE_DRAFT_AND_COMMUNICATION,
            capabilities = mapOf(
                AtomicCapability.NOTIFICATION_READ to ConfirmationLevel.AUTO,
                AtomicCapability.DATA_READ to ConfirmationLevel.PROMPT_CARD,
                AtomicCapability.CREATE_DRAFT to ConfirmationLevel.PROMPT_CARD,
                AtomicCapability.MODIFY_DELETE_SEND to ConfirmationLevel.DISABLED,
                AtomicCapability.APP_LAUNCH to ConfirmationLevel.PROMPT_CARD
            )
        )

        fun trustedSystemAutomation(): PermissionProfile = PermissionProfile(
            id = TRUSTED_SYSTEM_PROFILE_ID,
            name = "Trusted System Automation",
            preset = PermissionProfilePreset.TRUSTED_SYSTEM_AUTOMATION,
            capabilities = mapOf(
                AtomicCapability.NOTIFICATION_READ to ConfirmationLevel.DISABLED,
                AtomicCapability.DATA_READ to ConfirmationLevel.AUTO,
                AtomicCapability.CREATE_DRAFT to ConfirmationLevel.AUTO,
                AtomicCapability.MODIFY_DELETE_SEND to ConfirmationLevel.PROMPT_CARD,
                AtomicCapability.APP_LAUNCH to ConfirmationLevel.AUTO
            )
        )

        fun biometricHighSecurity(): PermissionProfile = PermissionProfile(
            id = BIOMETRIC_HIGH_SECURITY_PROFILE_ID,
            name = "Biometric High-Security",
            preset = PermissionProfilePreset.BIOMETRIC_HIGH_SECURITY,
            capabilities = mapOf(
                AtomicCapability.NOTIFICATION_READ to ConfirmationLevel.DISABLED,
                AtomicCapability.DATA_READ to ConfirmationLevel.BIOMETRIC,
                AtomicCapability.CREATE_DRAFT to ConfirmationLevel.PROMPT_CARD,
                AtomicCapability.MODIFY_DELETE_SEND to ConfirmationLevel.BIOMETRIC,
                AtomicCapability.APP_LAUNCH to ConfirmationLevel.PROMPT_CARD
            )
        )
    }
}

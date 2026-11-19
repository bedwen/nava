package com.nava.domain.security

/**
 * Confirmation gate assigned independently to each [AtomicCapability] in a [PermissionProfile].
 */
enum class ConfirmationLevel {
    /** Default-Deny: capability is completely blocked. */
    DISABLED,

    /** Capability executes without prompting (forbidden for MODIFY_DELETE_SEND). */
    AUTO,

    /** Capability requires explicit user approval on an Action Confirmation Card. */
    PROMPT_CARD,

    /** Capability requires hardware-backed BiometricPrompt verification. */
    BIOMETRIC;

    /** True when the capability is permitted under any confirmation gate. */
    val isAllowed: Boolean
        get() = this != DISABLED

    /** True when interactive user confirmation is mandatory before execution. */
    val requiresInteractivePrompt: Boolean
        get() = this == PROMPT_CARD || this == BIOMETRIC

    /** True when biometric authentication is mandatory before execution. */
    val requiresBiometric: Boolean
        get() = this == BIOMETRIC

    /**
     * Validates that [this] confirmation level is structurally permitted for [capability].
     * [AtomicCapability.MODIFY_DELETE_SEND] must never be configured as [AUTO].
     */
    fun isValidFor(capability: AtomicCapability): Boolean {
        return when (capability) {
            AtomicCapability.NOTIFICATION_READ -> this == DISABLED || this == AUTO
            AtomicCapability.DATA_READ -> true
            AtomicCapability.CREATE_DRAFT -> this == DISABLED || this == AUTO || this == PROMPT_CARD
            AtomicCapability.MODIFY_DELETE_SEND -> this == DISABLED || this == PROMPT_CARD || this == BIOMETRIC
            AtomicCapability.APP_LAUNCH -> this == DISABLED || this == AUTO || this == PROMPT_CARD
        }
    }
}

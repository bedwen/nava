package com.nava.domain.security

/**
 * Built-in presets and user-customizable tier for [PermissionProfile].
 */
enum class PermissionProfilePreset {
    STRICTLY_ISOLATED,
    NOTIFICATION_SUMMARY_ONLY,
    SAFE_DRAFT_AND_COMMUNICATION,
    TRUSTED_SYSTEM_AUTOMATION,
    BIOMETRIC_HIGH_SECURITY,
    CUSTOM
}

package com.nava.feature.automations.common

/**
 * Canonical target identifiers used for [com.nava.domain.security.PermissionProfile] evaluation
 * and [com.nava.domain.security.AuditLogEntry] recording across `:feature-automations`.
 */
object ToolTargetIds {
    const val CLOCK: String = "system.clock"
    const val CALENDAR: String = "system.calendar"
    const val NOTES: String = "nava.notes"
    const val VAULT: String = "nava.vault"
    const val SMS: String = "system.sms"
    const val PHONE: String = "system.phone"
    const val AUDIO_DND: String = "system.audio_dnd"
    const val APP_LAUNCH: String = "system.app_launch"
    const val NOTIFICATIONS: String = "system.notifications"
    const val SAF: String = "system.saf"
    const val ROUTINES: String = "nava.routines"
    const val BACKGROUND_TASKS: String = "nava.background_tasks"

    /**
     * Canonical per-directory target ID for SAF permission evaluation so each user-granted tree
     * enforces independent `DATA_READ`, `CREATE_DRAFT`, and `MODIFY_DELETE_SEND` switches.
     */
    fun forSafTree(treeUri: String): String {
        val trimmed = treeUri.trim()
        require(trimmed.isNotBlank()) { "SAF treeUri must not be blank" }
        return "saf:$trimmed"
    }

    /**
     * Canonical per-package target ID matching Android `StatusBarNotification.packageName` and
     * launchable application package identifiers in `PermissionProfile.assignedTargets`.
     */
    fun forPackage(packageName: String): String {
        val trimmed = packageName.trim()
        require(trimmed.isNotBlank()) { "packageName must not be blank" }
        return trimmed
    }
}

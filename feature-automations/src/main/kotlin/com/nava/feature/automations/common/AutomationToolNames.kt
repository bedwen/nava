package com.nava.feature.automations.common

/**
 * Canonical [com.nava.domain.tool.NavaTool] names shared across Tier 1 Layer R rule packs,
 * Tier 2 skeleton cache, Tier 3 Gemma 4 declarations, `SecurityFirewall`, and `:feature-automations`.
 *
 * Each tool maps 1-to-1 to a single orthogonal [com.nava.domain.security.AtomicCapability]
 * so `DATA_READ`, `CREATE_DRAFT`, `MODIFY_DELETE_SEND`, `NOTIFICATION_READ`, and `APP_LAUNCH`
 * are never conflated inside a single tool.
 */
object AutomationToolNames {
    // Clock (AlarmTimerTool) - CREATE_DRAFT, unattended-safe
    const val SET_ALARM: String = "set_alarm"
    const val SET_TIMER: String = "set_timer"

    // Calendar (CalendarTool) - split by orthogonal capability
    const val CALENDAR_QUERY: String = "calendar_query"
    const val CALENDAR_CREATE: String = "calendar_create"
    const val CALENDAR_MODIFY: String = "calendar_modify"

    // Standard Notes & Nava Secure Vault (NotesVaultTool) - split by storage boundary & capability
    const val NOTES_READ: String = "notes_read"
    const val NOTES_CREATE: String = "notes_create"
    const val NOTES_DELETE: String = "notes_delete"
    const val NOTES_SEARCH: String = "notes_search"
    const val VAULT_READ: String = "vault_read"
    const val VAULT_WRITE: String = "vault_write"
    const val VAULT_DELETE: String = "vault_delete"

    // Communication (SmsDraftTool, CallIntentTool, NotificationSummaryTool)
    const val CREATE_SMS_DRAFT: String = "create_sms_draft"
    const val DIAL_CALL: String = "dial_call"
    const val PLACE_CALL: String = "place_call"
    const val SUMMARIZE_NOTIFICATIONS: String = "summarize_notifications"

    // Device Settings & App Launch (AudioDndTool, AppLaunchTool)
    const val SET_DND: String = "set_dnd"
    const val SET_VOLUME: String = "set_volume"
    const val LAUNCH_APP: String = "launch_app"

    // Storage Access Framework (SafDirectoryTool) - split by orthogonal capability
    const val SAF_READ: String = "saf_read"
    const val SAF_WRITE: String = "saf_write"
    const val SAF_DELETE: String = "saf_delete"

    // Zero-Battery Reminders, Natural-Language Routines & Morning Briefing
    const val SCHEDULE_REMINDER: String = "schedule_reminder"
    const val CANCEL_REMINDER: String = "cancel_reminder"
    const val PROPOSE_ROUTINE: String = "propose_routine"
    const val DAILY_BRIEFING: String = "daily_briefing"

    // Proactive Notification Watchers (Zero-Battery Passive Alerts)
    const val CREATE_NOTIFICATION_WATCHER: String = "create_notification_watcher"
    const val MANAGE_NOTIFICATION_WATCHERS: String = "manage_notification_watchers"

    /** All canonical tool names in deterministic sorted order. */
    val ALL: Set<String> = linkedSetOf(
        CALENDAR_CREATE,
        CALENDAR_MODIFY,
        CALENDAR_QUERY,
        CANCEL_REMINDER,
        CREATE_NOTIFICATION_WATCHER,
        CREATE_SMS_DRAFT,
        DAILY_BRIEFING,
        DIAL_CALL,
        LAUNCH_APP,
        MANAGE_NOTIFICATION_WATCHERS,
        NOTES_CREATE,
        NOTES_DELETE,
        NOTES_READ,
        NOTES_SEARCH,
        PLACE_CALL,
        PROPOSE_ROUTINE,
        SAF_DELETE,
        SAF_READ,
        SAF_WRITE,
        SCHEDULE_REMINDER,
        SET_ALARM,
        SET_DND,
        SET_TIMER,
        SET_VOLUME,
        SUMMARIZE_NOTIFICATIONS,
        VAULT_DELETE,
        VAULT_READ,
        VAULT_WRITE
    )

    /** Tools targeting Nava Secure Vault (always require biometric unlock and never run unattended). */
    val VAULT_TOOLS: Set<String> = setOf(
        VAULT_READ,
        VAULT_WRITE,
        VAULT_DELETE
    )
}

/**
 * Exact allowlisted outbound action identifiers passed to
 * [com.nava.domain.security.SecurityFirewallPort.validateOutboundTarget].
 *
 * These mirror the static allowlist in `:core-security-data`'s `OutboundChannelPolicy`
 * without introducing a forbidden module dependency from `:feature-automations` to `:core-security-data`.
 */
object AutomationOutboundActions {
    const val ACTION_SET_ALARM: String = "android.intent.action.SET_ALARM"
    const val ACTION_SET_TIMER: String = "android.intent.action.SET_TIMER"
    const val ACTION_SENDTO: String = "android.intent.action.SENDTO"
    const val ACTION_DIAL: String = "android.intent.action.DIAL"
    const val ACTION_CALL: String = "android.intent.action.CALL"
    const val ACTION_OPEN_DOCUMENT_TREE: String = "android.intent.action.OPEN_DOCUMENT_TREE"
    const val ACTION_SAF_READ: String = "SAF_READ"
    const val ACTION_SAF_WRITE: String = "SAF_WRITE"
    const val ACTION_CALENDAR_PROVIDER: String = "CALENDAR_PROVIDER"
    const val ACTION_APP_LAUNCH: String = "APP_LAUNCH"
}

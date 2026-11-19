package com.nava.domain.ui

import com.nava.domain.security.DataProvenance

/**
 * Canonical localization keys rendered into user-facing text by `:app` string resources.
 * `:domain` never constructs localized sentences directly (zero-token confirmation text).
 */
enum class MessageKey {
    ACTION_ALARM_SET,
    ACTION_TIMER_SET,
    ACTION_CALENDAR_EVENT_CREATED,
    ACTION_NOTE_SAVED,
    ACTION_SMS_DRAFT_PREPARED,
    ACTION_CALL_INTENT_PREPARED,
    ACTION_DND_UPDATED,
    ACTION_CONFIRMATION_REQUIRED,
    ACTION_BIOMETRIC_REQUIRED,
    WARNING_UNTRUSTED_EXTERNAL_SOURCE,
    ERROR_PERMISSION_DENIED,
    ERROR_TOOL_NOT_FOUND,
    ERROR_SECURITY_VIOLATION,
    ERROR_MODEL_UNAVAILABLE,
    ERROR_THOUGHT_BUDGET_EXCEEDED,
    ERROR_CLARIFICATION_NEEDED,
    PROFILE_UPDATED,
    RULE_PENDING_APPROVAL,
    RULE_APPROVED,
    RULE_REVOKED
}

/**
 * Typed argument embedded inside [UserMessage] for safe, locale-aware formatting in `:app`.
 */
sealed interface MessageArg {
    data class Text(val value: String) : MessageArg
    data class Number(val value: Long) : MessageArg
    data class IsoTime(val isoString: String) : MessageArg
    data class IsoDate(val isoString: String) : MessageArg
    data class ProvenanceBadge(val provenance: DataProvenance) : MessageArg
}

/**
 * Pure Kotlin structured message descriptor resolved by `:app` resource localization.
 */
data class UserMessage(
    val key: MessageKey,
    val args: List<MessageArg> = emptyList()
)

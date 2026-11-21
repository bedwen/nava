package com.nava.app.locale

import android.content.Context
import androidx.annotation.StringRes
import com.nava.app.R
import com.nava.domain.ui.MessageKey

/**
 * Android resource-backed [MessageTemplateProvider] resolving localized format templates
 * (`%1$s`, `%2$s`) from `res/values/strings.xml` via [R.string].
 *
 * Requirements & Invariants:
 * - Explicit import of [com.nava.app.R] (non-transitive R class).
 * - Exhaustive `when (key)` without `else` branch covering all 53 [MessageKey] values.
 * - Pure ASCII Kotlin file conforming to Iron Law 1 and Gate 1.
 */
class AndroidResourceMessageTemplateProvider(
    private val context: Context? = null,
    private val fallbackProvider: MessageTemplateProvider = FallbackEnglishMessageTemplateProvider()
) : MessageTemplateProvider {

    override fun templateFor(key: MessageKey): String {
        val resId = stringResFor(key)
        return try {
            context?.getString(resId) ?: fallbackProvider.templateFor(key)
        } catch (_: Exception) {
            fallbackProvider.templateFor(key)
        }
    }

    /**
     * Resolves the canonical Android string resource ID corresponding to [key].
     *
     * Invariant: Exhaustive `when (key)` with zero `else` branch across all 53 [MessageKey] values.
     */
    @StringRes
    fun stringResFor(key: MessageKey): Int = when (key) {
        MessageKey.ACTION_ALARM_SET -> R.string.msg_action_alarm_set
        MessageKey.ACTION_TIMER_SET -> R.string.msg_action_timer_set
        MessageKey.ACTION_CALENDAR_EVENT_CREATED -> R.string.msg_action_calendar_event_created
        MessageKey.ACTION_NOTE_SAVED -> R.string.msg_action_note_saved
        MessageKey.ACTION_SMS_DRAFT_PREPARED -> R.string.msg_action_sms_draft_prepared
        MessageKey.ACTION_CALL_INTENT_PREPARED -> R.string.msg_action_call_intent_prepared
        MessageKey.ACTION_DND_UPDATED -> R.string.msg_action_dnd_updated
        MessageKey.ACTION_CONFIRMATION_REQUIRED -> R.string.msg_action_confirmation_required
        MessageKey.ACTION_BIOMETRIC_REQUIRED -> R.string.msg_action_biometric_required
        MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE -> R.string.msg_warning_untrusted_external_source
        MessageKey.ERROR_PERMISSION_DENIED -> R.string.msg_error_permission_denied
        MessageKey.ERROR_TOOL_NOT_FOUND -> R.string.msg_error_tool_not_found
        MessageKey.ERROR_SECURITY_VIOLATION -> R.string.msg_error_security_violation
        MessageKey.ERROR_MODEL_UNAVAILABLE -> R.string.msg_error_model_unavailable
        MessageKey.ERROR_THOUGHT_BUDGET_EXCEEDED -> R.string.msg_error_thought_budget_exceeded
        MessageKey.ERROR_CLARIFICATION_NEEDED -> R.string.msg_error_clarification_needed
        MessageKey.PROFILE_UPDATED -> R.string.msg_profile_updated
        MessageKey.RULE_PENDING_APPROVAL -> R.string.msg_rule_pending_approval
        MessageKey.RULE_APPROVED -> R.string.msg_rule_approved
        MessageKey.RULE_REVOKED -> R.string.msg_rule_revoked
        MessageKey.ACTION_CALENDAR_EVENTS_QUERIED -> R.string.msg_action_calendar_events_queried
        MessageKey.ACTION_CALENDAR_EVENT_UPDATED -> R.string.msg_action_calendar_event_updated
        MessageKey.ACTION_CALENDAR_EVENT_DELETED -> R.string.msg_action_calendar_event_deleted
        MessageKey.ACTION_NOTE_READ -> R.string.msg_action_note_read
        MessageKey.ACTION_NOTE_DELETED -> R.string.msg_action_note_deleted
        MessageKey.ACTION_VAULT_NOTE_SAVED -> R.string.msg_action_vault_note_saved
        MessageKey.ACTION_VAULT_NOTE_READ -> R.string.msg_action_vault_note_read
        MessageKey.ACTION_VAULT_NOTE_DELETED -> R.string.msg_action_vault_note_deleted
        MessageKey.ACTION_DIRECT_CALL_INITIATED -> R.string.msg_action_direct_call_initiated
        MessageKey.ACTION_VOLUME_UPDATED -> R.string.msg_action_volume_updated
        MessageKey.ACTION_APP_LAUNCHED -> R.string.msg_action_app_launched
        MessageKey.ACTION_NOTIFICATIONS_SUMMARIZED -> R.string.msg_action_notifications_summarized
        MessageKey.ACTION_NOTIFICATIONS_EMPTY -> R.string.msg_action_notifications_empty
        MessageKey.ACTION_SAF_DIRECTORY_LISTED -> R.string.msg_action_saf_directory_listed
        MessageKey.ACTION_SAF_FILE_READ -> R.string.msg_action_saf_file_read
        MessageKey.ACTION_SAF_FILE_WRITTEN -> R.string.msg_action_saf_file_written
        MessageKey.ACTION_SAF_FILE_DELETED -> R.string.msg_action_saf_file_deleted
        MessageKey.ROUTINE_EXECUTED -> R.string.msg_routine_executed
        MessageKey.ROUTINE_ESCALATED_CONFIRMATION -> R.string.msg_routine_escalated_confirmation
        MessageKey.ROUTINE_ESCALATED_BIOMETRIC -> R.string.msg_routine_escalated_biometric
        MessageKey.ROUTINE_EXECUTION_DENIED -> R.string.msg_routine_execution_denied
        MessageKey.ROUTINE_EXECUTION_FAILED -> R.string.msg_routine_execution_failed
        MessageKey.BACKGROUND_TASK_RUNNING -> R.string.msg_background_task_running
        MessageKey.BACKGROUND_TASK_COMPLETED -> R.string.msg_background_task_completed
        MessageKey.BACKGROUND_TASK_CONFIRMATION_REQUIRED -> R.string.msg_background_task_confirmation_required
        MessageKey.BACKGROUND_TASK_FAILED -> R.string.msg_background_task_failed
        MessageKey.BACKGROUND_TASK_CANCELLED -> R.string.msg_background_task_cancelled
        MessageKey.ERROR_INVALID_ARGUMENTS -> R.string.msg_error_invalid_arguments
        MessageKey.ERROR_SYSTEM_PERMISSION_MISSING -> R.string.msg_error_system_permission_missing
        MessageKey.ERROR_PLATFORM_UNAVAILABLE -> R.string.msg_error_platform_unavailable
        MessageKey.ERROR_NOT_FOUND -> R.string.msg_error_not_found
        MessageKey.ERROR_VAULT_LOCKED -> R.string.msg_error_vault_locked
        MessageKey.ERROR_SAF_GRANT_MISSING -> R.string.msg_error_saf_grant_missing
    }
}

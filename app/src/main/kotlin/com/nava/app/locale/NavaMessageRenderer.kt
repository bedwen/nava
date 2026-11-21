package com.nava.app.locale

import com.nava.domain.security.DataProvenance
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import java.util.Locale

/**
 * Port providing raw localized format templates (`%1$s`, `%2$s`) for every [MessageKey].
 *
 * Wave 2 wires `AndroidResourceMessageTemplateProvider` (reading `R.string.msg_*` from `strings.xml`),
 * while [FallbackEnglishMessageTemplateProvider] provides an exhaustive pure-ASCII English baseline
 * for JVM unit tests and fallback resolution.
 */
interface MessageTemplateProvider {
    fun templateFor(key: MessageKey): String

    companion object {
        /**
         * Canonical Android string resource key (`msg_<lowercase_enum_name>`) corresponding to [key].
         */
        fun canonicalResourceName(key: MessageKey): String {
            return "msg_${key.name.lowercase(Locale.US)}"
        }
    }
}

/**
 * Exhaustive pure-ASCII English [MessageTemplateProvider] covering all 53 [MessageKey] values.
 */
class FallbackEnglishMessageTemplateProvider : MessageTemplateProvider {

    override fun templateFor(key: MessageKey): String = when (key) {
        MessageKey.ACTION_ALARM_SET -> "Alarm set for %1\$s"
        MessageKey.ACTION_TIMER_SET -> "Timer set for %1\$s seconds"
        MessageKey.ACTION_CALENDAR_EVENT_CREATED -> "Calendar event created: %1\$s"
        MessageKey.ACTION_NOTE_SAVED -> "Note saved: %1\$s"
        MessageKey.ACTION_SMS_DRAFT_PREPARED -> "SMS draft prepared for %1\$s"
        MessageKey.ACTION_CALL_INTENT_PREPARED -> "Call ready in dialer for %1\$s"
        MessageKey.ACTION_DND_UPDATED -> "Do Not Disturb updated to %1\$s"
        MessageKey.ACTION_CONFIRMATION_REQUIRED -> "Confirmation required for %1\$s"
        MessageKey.ACTION_BIOMETRIC_REQUIRED -> "Biometric verification required for %1\$s"
        MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE -> "Extracted from untrusted external source (%1\$s)"
        MessageKey.ERROR_PERMISSION_DENIED -> "Action blocked by permission profile for %1\$s (%2\$s)"
        MessageKey.ERROR_TOOL_NOT_FOUND -> "Requested automation tool is not available: %1\$s"
        MessageKey.ERROR_SECURITY_VIOLATION -> "Action blocked by security policy: %1\$s"
        MessageKey.ERROR_MODEL_UNAVAILABLE -> "On-device language model is unavailable"
        MessageKey.ERROR_THOUGHT_BUDGET_EXCEEDED -> "Reasoning limit reached; please rephrase your request"
        MessageKey.ERROR_CLARIFICATION_NEEDED -> "Please clarify what you would like Nava to do"
        MessageKey.PROFILE_UPDATED -> "Permission profile updated: %1\$s"
        MessageKey.RULE_PENDING_APPROVAL -> "Automation routine pending your approval: %1\$s"
        MessageKey.RULE_APPROVED -> "Automation routine approved and sealed: %1\$s"
        MessageKey.RULE_REVOKED -> "Automation routine revoked: %1\$s"
        MessageKey.ACTION_CALENDAR_EVENTS_QUERIED -> "Found %1\$s calendar event(s)"
        MessageKey.ACTION_CALENDAR_EVENT_UPDATED -> "Calendar event updated: %1\$s"
        MessageKey.ACTION_CALENDAR_EVENT_DELETED -> "Calendar event deleted: %1\$s"
        MessageKey.ACTION_NOTE_READ -> "Note retrieved: %1\$s"
        MessageKey.ACTION_NOTE_DELETED -> "Note deleted: %1\$s"
        MessageKey.ACTION_VAULT_NOTE_SAVED -> "Encrypted Vault note saved: %1\$s"
        MessageKey.ACTION_VAULT_NOTE_READ -> "Encrypted Vault note decrypted: %1\$s"
        MessageKey.ACTION_VAULT_NOTE_DELETED -> "Encrypted Vault note deleted: %1\$s"
        MessageKey.ACTION_DIRECT_CALL_INITIATED -> "Direct call initiated to %1\$s"
        MessageKey.ACTION_VOLUME_UPDATED -> "Volume for %1\$s updated to %2\$s%%"
        MessageKey.ACTION_APP_LAUNCHED -> "Launched application %1\$s"
        MessageKey.ACTION_NOTIFICATIONS_SUMMARIZED -> "Summarized %1\$s notification(s)"
        MessageKey.ACTION_NOTIFICATIONS_EMPTY -> "No permitted notifications to summarize"
        MessageKey.ACTION_SAF_DIRECTORY_LISTED -> "Listed %1\$s item(s) in permitted directory"
        MessageKey.ACTION_SAF_FILE_READ -> "Read file from permitted directory: %1\$s"
        MessageKey.ACTION_SAF_FILE_WRITTEN -> "Wrote file to permitted directory: %1\$s"
        MessageKey.ACTION_SAF_FILE_DELETED -> "Deleted file from permitted directory: %1\$s"
        MessageKey.ROUTINE_EXECUTED -> "Automation routine executed: %1\$s"
        MessageKey.ROUTINE_ESCALATED_CONFIRMATION -> "Routine %1\$s requires your confirmation"
        MessageKey.ROUTINE_ESCALATED_BIOMETRIC -> "Routine %1\$s requires biometric authentication"
        MessageKey.ROUTINE_EXECUTION_DENIED -> "Routine execution blocked: %1\$s"
        MessageKey.ROUTINE_EXECUTION_FAILED -> "Routine execution failed: %1\$s"
        MessageKey.BACKGROUND_TASK_RUNNING -> "Background task in progress: %1\$s"
        MessageKey.BACKGROUND_TASK_COMPLETED -> "Background task completed: %1\$s"
        MessageKey.BACKGROUND_TASK_CONFIRMATION_REQUIRED -> "Background task requires confirmation"
        MessageKey.BACKGROUND_TASK_FAILED -> "Background task failed: %1\$s"
        MessageKey.BACKGROUND_TASK_CANCELLED -> "Background task cancelled: %1\$s"
        MessageKey.ERROR_INVALID_ARGUMENTS -> "Invalid tool arguments: %1\$s"
        MessageKey.ERROR_SYSTEM_PERMISSION_MISSING -> "Missing Android system permission: %1\$s"
        MessageKey.ERROR_PLATFORM_UNAVAILABLE -> "Platform feature unavailable: %1\$s"
        MessageKey.ERROR_NOT_FOUND -> "Requested item not found: %1\$s"
        MessageKey.ERROR_VAULT_LOCKED -> "Nava Secure Vault is locked; authenticate with biometrics"
        MessageKey.ERROR_SAF_GRANT_MISSING -> "Directory access grant missing for %1\$s"
    }
}

/**
 * Renders structured `:domain` [UserMessage] descriptors into localized, bidi-safe title and
 * body strings using [MessageTemplateProvider], [BidiTextFormatter], and [LocaleDateTimeFormatter]
 * (PLAN.md Sections 6.1.1, 6.4, and 6.6).
 */
class NavaMessageRenderer(
    private val templateProvider: MessageTemplateProvider = FallbackEnglishMessageTemplateProvider(),
    private val bidiFormatter: BidiTextFormatter = BidiTextFormatter(),
    private val dateTimeFormatter: LocaleDateTimeFormatter = LocaleDateTimeFormatter()
) {

    /**
     * Renders [message] into a localized `(title, body)` pair suitable for notifications,
     * Action Confirmation Cards, and status banners.
     */
    fun render(
        message: UserMessage,
        locale: Locale = Locale.getDefault(),
        use24Hour: Boolean? = null
    ): Pair<String, String> {
        val title = renderTitle(message, locale)
        val body = renderBody(message, locale, use24Hour)
        return title to body
    }

    /**
     * Renders a concise, bidi-safe title string for [message] in [locale].
     */
    fun renderTitle(
        message: UserMessage,
        locale: Locale = Locale.getDefault()
    ): String {
        val rawTitle = when (message.key) {
            MessageKey.ACTION_CONFIRMATION_REQUIRED,
            MessageKey.ROUTINE_ESCALATED_CONFIRMATION,
            MessageKey.BACKGROUND_TASK_CONFIRMATION_REQUIRED -> TITLE_CONFIRMATION_REQUIRED

            MessageKey.ACTION_BIOMETRIC_REQUIRED,
            MessageKey.ROUTINE_ESCALATED_BIOMETRIC,
            MessageKey.ERROR_VAULT_LOCKED -> TITLE_BIOMETRIC_REQUIRED

            MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE -> TITLE_UNTRUSTED_SOURCE_WARNING

            MessageKey.ERROR_PERMISSION_DENIED,
            MessageKey.ERROR_TOOL_NOT_FOUND,
            MessageKey.ERROR_SECURITY_VIOLATION,
            MessageKey.ERROR_MODEL_UNAVAILABLE,
            MessageKey.ERROR_THOUGHT_BUDGET_EXCEEDED,
            MessageKey.ERROR_CLARIFICATION_NEEDED,
            MessageKey.ROUTINE_EXECUTION_DENIED,
            MessageKey.ROUTINE_EXECUTION_FAILED,
            MessageKey.BACKGROUND_TASK_FAILED,
            MessageKey.ERROR_INVALID_ARGUMENTS,
            MessageKey.ERROR_SYSTEM_PERMISSION_MISSING,
            MessageKey.ERROR_PLATFORM_UNAVAILABLE,
            MessageKey.ERROR_NOT_FOUND,
            MessageKey.ERROR_SAF_GRANT_MISSING -> TITLE_SECURITY_OR_ERROR

            else -> TITLE_DEFAULT
        }
        return bidiFormatter.wrapText(rawTitle, locale)
    }

    /**
     * Renders [message] into a localized, bidi-safe body string for [locale].
     *
     * Safely substitutes positional placeholders (`%1$s`, `%2$s`, etc.) without throwing
     * `MissingFormatArgumentException` when a message carries fewer arguments than the template.
     */
    fun renderBody(
        message: UserMessage,
        locale: Locale = Locale.getDefault(),
        use24Hour: Boolean? = null
    ): String {
        val template = templateProvider.templateFor(message.key)
        val formattedArgs = message.args.map { arg -> formatArg(arg, locale, use24Hour) }
        val substituted = substitutePlaceholdersSafely(template, formattedArgs)
        return bidiFormatter.wrapText(substituted, locale)
    }

    /**
     * Formats a single [MessageArg] with locale-aware date/time formatting and bidi isolation.
     */
    fun formatArg(
        arg: MessageArg,
        locale: Locale = Locale.getDefault(),
        use24Hour: Boolean? = null
    ): String {
        return when (arg) {
            is MessageArg.Text -> bidiFormatter.wrapText(arg.value, locale)
            is MessageArg.Number -> bidiFormatter.wrapLtrToken(arg.value.toString(), locale)
            is MessageArg.IsoTime -> {
                val formattedTime = dateTimeFormatter.formatTime(arg, locale, use24Hour)
                bidiFormatter.wrapLtrToken(formattedTime, locale)
            }

            is MessageArg.IsoDate -> {
                val formattedDate = dateTimeFormatter.formatDate(arg, locale)
                bidiFormatter.wrapText(formattedDate, locale)
            }

            is MessageArg.ProvenanceBadge -> {
                val label = formatProvenanceBadge(arg.provenance)
                bidiFormatter.wrapText(label, locale)
            }
        }
    }

    private fun formatProvenanceBadge(provenance: DataProvenance): String {
        return when (provenance) {
            DataProvenance.USER_UTTERANCE -> "User command"
            DataProvenance.SYSTEM -> "System"
            DataProvenance.UNTRUSTED_EXTERNAL -> "Untrusted external source"
        }
    }

    private fun substitutePlaceholdersSafely(
        template: String,
        formattedArgs: List<String>
    ): String {
        val unescapedPercent = template.replace("%%", "%")
        if (!POSITIONAL_PLACEHOLDER_REGEX.containsMatchIn(unescapedPercent) &&
            !SEQUENTIAL_PLACEHOLDER_REGEX.containsMatchIn(unescapedPercent)
        ) {
            return unescapedPercent.trim()
        }

        // First substitute positional placeholders (%1$s, %2$d, etc.)
        var working = POSITIONAL_PLACEHOLDER_REGEX.replace(unescapedPercent) { match ->
            val indexOneBased = match.groupValues[1].toIntOrNull() ?: 0
            val argIndex = indexOneBased - 1
            if (argIndex in formattedArgs.indices) {
                formattedArgs[argIndex]
            } else {
                ""
            }
        }

        // Next substitute any unnumbered %s / %d sequential placeholders
        var seqCursor = 0
        working = SEQUENTIAL_PLACEHOLDER_REGEX.replace(working) {
            val replacement = if (seqCursor in formattedArgs.indices) {
                formattedArgs[seqCursor]
            } else {
                ""
            }
            seqCursor++
            replacement
        }

        return cleanDanglingPlaceholderPunctuation(working)
    }

    private fun cleanDanglingPlaceholderPunctuation(input: String): String {
        return input
            .replace("()", "")
            .replace("[]", "")
            .replace(MULTIPLE_SPACES_REGEX, " ")
            .trim()
            .trimEnd(':', '-', ',')
            .trim()
            .removeSuffix(" for")
            .removeSuffix(" to")
            .trim()
    }

    companion object {
        const val TITLE_DEFAULT: String = "Nava"
        const val TITLE_CONFIRMATION_REQUIRED: String = "Nava Action Confirmation"
        const val TITLE_BIOMETRIC_REQUIRED: String = "Nava Biometric Verification"
        const val TITLE_UNTRUSTED_SOURCE_WARNING: String = "Nava Untrusted Source Warning"
        const val TITLE_SECURITY_OR_ERROR: String = "Nava Security Notice"

        private val POSITIONAL_PLACEHOLDER_REGEX: Regex = Regex("%(\\d+)\\$[sd]")
        private val SEQUENTIAL_PLACEHOLDER_REGEX: Regex = Regex("%[sd]")
        private val MULTIPLE_SPACES_REGEX: Regex = Regex(" {2,}")
    }
}

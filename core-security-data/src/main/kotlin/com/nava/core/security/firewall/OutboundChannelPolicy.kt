package com.nava.core.security.firewall

import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.SensitiveSlotKind
import java.text.Normalizer
import java.util.Locale

/**
 * Verdict emitted by [OutboundChannelPolicy].
 */
sealed interface OutboundPolicyVerdict {
    data object Allowed : OutboundPolicyVerdict
    data class Blocked(val reasonCode: String, val detail: String) : OutboundPolicyVerdict
}

/**
 * Static Intent Template Allowlist and URI/Scheme Exfiltration Blocker (PLAN.md Section 5.4 & 5.7).
 *
 * Security invariants:
 * - All evaluations normalize via Unicode NFKC, strip invisible/bidi controls, trim whitespace,
 *   and fold case using [Locale.ROOT] before matching.
 * - `http://`, `https://`, `ftp://`, `javascript:`, `data:`, `intent:`, `file://`, `blob:`,
 *   and `about:` URIs are hard-blocked across ALL tools.
 * - Arbitrary `ACTION_VIEW`, `ACTION_SEND`, `ACTION_WEB_SEARCH`, and unallowlisted actions are
 *   unconditionally rejected.
 */
class OutboundChannelPolicy {

    /**
     * Evaluates an outbound `(action, uriOrTarget)` pair against the static allowlist and
     * hard-blocked scheme rules.
     */
    fun evaluate(action: String, uriOrTarget: String): OutboundPolicyVerdict {
        val normAction = normalize(action)
        val normTarget = normalize(uriOrTarget)

        val schemeCheck = inspectRawValueForBlockedSchemes(uriOrTarget)
        if (schemeCheck is OutboundPolicyVerdict.Blocked) {
            return schemeCheck
        }

        if (containsRawControlOrHeaderInjection(uriOrTarget) || containsRawControlOrHeaderInjection(normTarget)) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "Control characters or CRLF/null-byte injection rejected in outbound target"
            )
        }

        if (containsRawControlOrHeaderInjection(action) || normAction.isEmpty()) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_ACTION_BLOCKED,
                detail = "Outbound intent action must be non-blank and free of control characters"
            )
        }

        if (normAction !in ALLOWED_ACTIONS) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_ACTION_BLOCKED,
                detail = "Action '$normAction' is not in the static outbound allowlist"
            )
        }

        return when (normAction) {
            ACTION_SET_ALARM,
            ACTION_SET_TIMER -> validateNoExternalUri(normAction, normTarget)

            ACTION_SENDTO -> validateSmsToTarget(uriOrTarget, normTarget)

            ACTION_DIAL,
            ACTION_CALL -> validateTelTarget(uriOrTarget, normTarget)

            ACTION_OPEN_DOCUMENT_TREE,
            ACTION_SAF_READ,
            ACTION_SAF_WRITE -> validateSafContentUri(normAction, uriOrTarget, normTarget)

            ACTION_CALENDAR_PROVIDER -> validateCalendarUri(uriOrTarget, normTarget)

            ACTION_APP_LAUNCH -> validatePackageName(uriOrTarget, normTarget)

            else -> OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_ACTION_BLOCKED,
                detail = "Action '$normAction' is not permitted"
            )
        }
    }

    /**
     * Inspects an individual tool argument value according to its [SensitiveSlotKind].
     * High-risk destination/URI/action/path/package slots and unknown slots are strictly checked
     * for blocked schemes, disallowed actions, and traversal payloads.
     */
    fun inspectArgumentValue(
        slotKind: SensitiveSlotKind?,
        rawValue: String,
        argName: String = ""
    ): OutboundPolicyVerdict {
        val normValue = normalize(rawValue)
        if (rawValue.isEmpty() && normValue.isEmpty()) return OutboundPolicyVerdict.Allowed

        val shouldInspectSchemes =
            slotKind == null ||
                slotKind.isHighRisk ||
                looksLikeDestinationArgName(argName)

        if (shouldInspectSchemes) {
            val schemeVerdict = inspectRawValueForBlockedSchemes(rawValue)
            if (schemeVerdict is OutboundPolicyVerdict.Blocked) {
                return schemeVerdict
            }
        }

        return when (slotKind) {
            SensitiveSlotKind.INTENT_ACTION -> {
                if (containsRawControlOrHeaderInjection(rawValue) || normValue !in ALLOWED_ACTIONS) {
                    OutboundPolicyVerdict.Blocked(
                        reasonCode = REASON_ACTION_BLOCKED,
                        detail = "Intent action '$normValue' is not allowlisted"
                    )
                } else {
                    OutboundPolicyVerdict.Allowed
                }
            }

            SensitiveSlotKind.EXTERNAL_URI -> validateSafeExternalUri(rawValue, normValue)

            SensitiveSlotKind.PACKAGE_NAME -> validatePackageName(rawValue, normValue)

            SensitiveSlotKind.FILE_PATH -> validateSafeFilePath(rawValue, normValue)

            SensitiveSlotKind.RECIPIENT_ADDRESS,
            SensitiveSlotKind.PHONE_NUMBER -> validateSafeDestinationSlot(rawValue, normValue)

            SensitiveSlotKind.TEXT_BODY,
            SensitiveSlotKind.EVENT_TITLE,
            SensitiveSlotKind.DATE_TIME,
            SensitiveSlotKind.DURATION,
            null -> OutboundPolicyVerdict.Allowed
        }
    }

    /**
     * Hard-blocks `http://`, `https://`, and other exfiltration-capable URI schemes anywhere in
     * [rawValue], including whitespace/control-character obfuscated variants.
     */
    fun inspectRawValueForBlockedSchemes(rawValue: String): OutboundPolicyVerdict {
        val norm = normalize(rawValue)
        if (norm.isEmpty()) return OutboundPolicyVerdict.Allowed

        val lower = norm.lowercase(Locale.ROOT)
        val compactLower = lower.filterNot { it.isWhitespace() }

        if (
            HTTP_SCHEME_REGEX.containsMatchIn(lower) ||
            compactLower.startsWith("http://") ||
            compactLower.startsWith("https://") ||
            compactLower.startsWith("http:") ||
            compactLower.startsWith("https:")
        ) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_HTTP_BLOCKED,
                detail = "HTTP/HTTPS URIs are hard-blocked across all tools"
            )
        }

        if (
            OTHER_BLOCKED_SCHEME_REGEX.containsMatchIn(lower) ||
            BLOCKED_COMPACT_PREFIXES.any { compactLower.startsWith(it) }
        ) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "Disallowed URI scheme detected in outbound target"
            )
        }

        return OutboundPolicyVerdict.Allowed
    }

    private fun validateNoExternalUri(action: String, normTarget: String): OutboundPolicyVerdict {
        if (normTarget.isNotEmpty()) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "Action '$action' does not permit an external URI"
            )
        }
        return OutboundPolicyVerdict.Allowed
    }

    private fun validateSmsToTarget(rawTarget: String, normTarget: String): OutboundPolicyVerdict {
        if (containsRawControlOrHeaderInjection(rawTarget) || containsRawControlOrHeaderInjection(normTarget)) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "Control characters rejected in smsto: URI"
            )
        }
        val lower = normTarget.lowercase(Locale.ROOT)
        if (!lower.startsWith("smsto:")) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "ACTION_SENDTO permits strictly 'smsto:' URIs"
            )
        }
        val recipient = normTarget.substring(6).trim()
        if (recipient.isEmpty() || !SAFE_DIALABLE_REGEX.matches(recipient) || !recipient.any { it.isDigit() }) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "Invalid or unsafe recipient in smsto: URI"
            )
        }
        return OutboundPolicyVerdict.Allowed
    }

    private fun validateTelTarget(rawTarget: String, normTarget: String): OutboundPolicyVerdict {
        if (containsRawControlOrHeaderInjection(rawTarget) || containsRawControlOrHeaderInjection(normTarget)) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "Control characters rejected in tel: URI"
            )
        }
        val lower = normTarget.lowercase(Locale.ROOT)
        if (!lower.startsWith("tel:")) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "ACTION_DIAL/ACTION_CALL permits strictly 'tel:' URIs"
            )
        }
        val number = normTarget.substring(4).trim()
        if (number.isEmpty() || !SAFE_DIALABLE_REGEX.matches(number) || !number.any { it.isDigit() }) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "Invalid or unsafe dialable number in tel: URI"
            )
        }
        return OutboundPolicyVerdict.Allowed
    }

    private fun validateSafContentUri(
        action: String,
        rawTarget: String,
        normTarget: String
    ): OutboundPolicyVerdict {
        if (
            containsRawControlOrHeaderInjection(rawTarget) ||
            !CONTENT_URI_REGEX.matches(normTarget) ||
            hasPathTraversal(rawTarget, normTarget)
        ) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "Action '$action' permits strictly traversal-free 'content://' URIs"
            )
        }
        return OutboundPolicyVerdict.Allowed
    }

    private fun validateCalendarUri(rawTarget: String, normTarget: String): OutboundPolicyVerdict {
        if (containsRawControlOrHeaderInjection(rawTarget)) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "Control characters rejected in CALENDAR_PROVIDER URI"
            )
        }
        if (normTarget.isEmpty()) return OutboundPolicyVerdict.Allowed
        val lower = normTarget.lowercase(Locale.ROOT)
        val validPrefix = lower == CALENDAR_URI_PREFIX || lower.startsWith("$CALENDAR_URI_PREFIX/")
        if (!validPrefix || hasPathTraversal(rawTarget, normTarget)) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "CALENDAR_PROVIDER permits only '$CALENDAR_URI_PREFIX' URIs"
            )
        }
        return OutboundPolicyVerdict.Allowed
    }

    private fun validatePackageName(rawTarget: String, normTarget: String): OutboundPolicyVerdict {
        if (
            containsRawControlOrHeaderInjection(rawTarget) ||
            containsRawControlOrHeaderInjection(normTarget) ||
            ':' in normTarget ||
            '/' in normTarget ||
            !ANDROID_PACKAGE_REGEX.matches(normTarget)
        ) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "APP_LAUNCH requires a valid Android package name without URI schemes"
            )
        }
        return OutboundPolicyVerdict.Allowed
    }

    private fun validateSafeExternalUri(rawTarget: String, normTarget: String): OutboundPolicyVerdict {
        if (containsRawControlOrHeaderInjection(rawTarget) || containsRawControlOrHeaderInjection(normTarget)) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "Control characters or CRLF/null-byte injection rejected in EXTERNAL_URI"
            )
        }
        val lower = normTarget.lowercase(Locale.ROOT)
        return when {
            lower.startsWith("smsto:") -> validateSmsToTarget(rawTarget, normTarget)
            lower.startsWith("tel:") -> validateTelTarget(rawTarget, normTarget)
            lower.startsWith("content://") -> validateSafContentUri("EXTERNAL_URI", rawTarget, normTarget)
            else -> OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "EXTERNAL_URI must use an allowlisted scheme (content://, smsto:, tel:)"
            )
        }
    }

    private fun validateSafeFilePath(rawTarget: String, normTarget: String): OutboundPolicyVerdict {
        if (hasPathTraversal(rawTarget, normTarget)) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "Path traversal rejected in FILE_PATH slot"
            )
        }
        val lower = normTarget.lowercase(Locale.ROOT)
        if ("://" in lower && !lower.startsWith("content://")) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "Disallowed URI scheme in FILE_PATH slot"
            )
        }
        return OutboundPolicyVerdict.Allowed
    }

    private fun validateSafeDestinationSlot(rawTarget: String, normTarget: String): OutboundPolicyVerdict {
        if (containsRawControlOrHeaderInjection(rawTarget) || containsRawControlOrHeaderInjection(normTarget)) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "CRLF or null-byte injection rejected in destination slot"
            )
        }
        if ('?' in normTarget || '&' in normTarget) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "Query-string characters rejected in destination slot"
            )
        }
        val lower = normTarget.lowercase(Locale.ROOT)
        if ("%0d" in lower || "%0a" in lower || "%00" in lower) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "Percent-encoded control characters rejected in destination slot"
            )
        }
        if (lower.startsWith("smsto:")) return validateSmsToTarget(rawTarget, normTarget)
        if (lower.startsWith("tel:")) return validateTelTarget(rawTarget, normTarget)
        if ("://" in lower) {
            return OutboundPolicyVerdict.Blocked(
                reasonCode = REASON_SCHEME_BLOCKED,
                detail = "Disallowed URI scheme in destination slot"
            )
        }
        return OutboundPolicyVerdict.Allowed
    }

    private fun containsRawControlOrHeaderInjection(value: String): Boolean {
        return '\r' in value || '\n' in value || '\u0000' in value
    }

    private fun hasPathTraversal(rawValue: String, normValue: String): Boolean {
        if (containsRawControlOrHeaderInjection(rawValue) || '\\' in rawValue || ".." in rawValue) {
            return true
        }
        var current = normValue
        for (pass in 0 until MAX_PERCENT_DECODE_PASSES) {
            if (containsRawControlOrHeaderInjection(current)) return true
            val lower = current.lowercase(Locale.ROOT)
            if (
                ".." in lower ||
                '\\' in lower ||
                "%5c" in lower ||
                "%00" in lower ||
                "%0a" in lower ||
                "%0d" in lower
            ) {
                return true
            }
            val decoded = decodePercentOnce(current)
            if (decoded == current) {
                return false
            }
            if (containsRawControlOrHeaderInjection(decoded) || '\\' in decoded || ".." in decoded) {
                return true
            }
            current = Normalizer.normalize(decoded, Normalizer.Form.NFKC)
        }
        // Final check after MAX_PERCENT_DECODE_PASSES; reject residual multi-encoded dot/slash/backslash.
        val finalLower = current.lowercase(Locale.ROOT)
        return containsRawControlOrHeaderInjection(current) ||
            ".." in finalLower ||
            '\\' in finalLower ||
            "%2e" in finalLower ||
            "%5c" in finalLower ||
            "%2f" in finalLower ||
            "%00" in finalLower ||
            "%0a" in finalLower ||
            "%0d" in finalLower
    }

    private fun decodePercentOnce(input: String): String {
        if ('%' !in input) return input
        val sb = StringBuilder(input.length)
        var i = 0
        while (i < input.length) {
            val ch = input[i]
            if (ch == '%' && i + 2 < input.length) {
                val hi = hexDigit(input[i + 1])
                val lo = hexDigit(input[i + 2])
                if (hi >= 0 && lo >= 0) {
                    val decodedByte = (hi shl 4) or lo
                    sb.append(decodedByte.toChar())
                    i += 3
                    continue
                }
            }
            sb.append(ch)
            i++
        }
        return sb.toString()
    }

    private fun hexDigit(ch: Char): Int = when (ch) {
        in '0'..'9' -> ch - '0'
        in 'a'..'f' -> ch - 'a' + 10
        in 'A'..'F' -> ch - 'A' + 10
        else -> -1
    }

    private fun looksLikeDestinationArgName(argName: String): Boolean {
        if (argName.isEmpty()) return false
        val lower = argName.lowercase(Locale.ROOT)
        return DESTINATION_ARG_TOKENS.any { token -> lower.contains(token) }
    }

    private fun normalize(raw: String): String {
        if (raw.isEmpty()) return ""
        val nfkc = Normalizer.normalize(raw, Normalizer.Form.NFKC)
        return Gemma4InputSanitizer.stripInvisibleControls(nfkc).trim()
    }

    companion object {
        const val REASON_HTTP_BLOCKED: String = "OUTBOUND_HTTP_BLOCKED"
        const val REASON_SCHEME_BLOCKED: String = "OUTBOUND_SCHEME_BLOCKED"
        const val REASON_ACTION_BLOCKED: String = "OUTBOUND_ACTION_BLOCKED"

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

        private const val CALENDAR_URI_PREFIX: String = "content://com.android.calendar"
        private const val MAX_PERCENT_DECODE_PASSES: Int = 5

        val ALLOWED_ACTIONS: Set<String> = setOf(
            ACTION_SET_ALARM,
            ACTION_SET_TIMER,
            ACTION_SENDTO,
            ACTION_DIAL,
            ACTION_CALL,
            ACTION_OPEN_DOCUMENT_TREE,
            ACTION_SAF_READ,
            ACTION_SAF_WRITE,
            ACTION_CALENDAR_PROVIDER,
            ACTION_APP_LAUNCH
        )

        private val HTTP_SCHEME_REGEX: Regex = Regex(
            pattern = """(?:^|[^a-z0-9_])https?\s*://""",
            option = RegexOption.IGNORE_CASE
        )

        private val OTHER_BLOCKED_SCHEME_REGEX: Regex = Regex(
            pattern = """(?:^|[^a-z0-9_])(?:(?:ftps?|file)\s*://|(?:javascript|data|intent|blob|about|vbscript)\s*:)""",
            option = RegexOption.IGNORE_CASE
        )

        private val BLOCKED_COMPACT_PREFIXES: List<String> = listOf(
            "ftp://",
            "ftps://",
            "ftp:",
            "javascript:",
            "data:",
            "intent:",
            "file://",
            "file:",
            "blob:",
            "about:",
            "vbscript:"
        )

        private val SAFE_DIALABLE_REGEX: Regex = Regex("""^[+0-9*#()\- ]{1,64}$""")
        private val CONTENT_URI_REGEX: Regex = Regex(
            pattern = """^content://[A-Za-z0-9._-]+(?:/[^\s]*)?$""",
            option = RegexOption.IGNORE_CASE
        )
        private val ANDROID_PACKAGE_REGEX: Regex = Regex(
            pattern = """^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+$"""
        )
        private val DESTINATION_ARG_TOKENS: Set<String> = setOf(
            "uri",
            "url",
            "link",
            "href",
            "action",
            "intent",
            "target",
            "recipient",
            "phone",
            "number",
            "destination",
            "package",
            "path"
        )
    }
}

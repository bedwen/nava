package com.nava.feature.automations.common

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.Tainted
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import java.text.Normalizer
import java.util.Locale

/**
 * Pure Kotlin helper for safely extracting typed [Tainted] slot values from tool argument maps
 * without ever stripping provenance or Vault taint markers.
 */
object ToolArgumentReader {
    const val VAULT_SOURCE_PREFIX: String = "vault:"

    const val ERROR_INVALID_ARGUMENTS: String = "INVALID_ARGUMENTS"
    const val ERROR_SYSTEM_PERMISSION_MISSING: String = "SYSTEM_PERMISSION_MISSING"
    const val ERROR_PLATFORM_UNAVAILABLE: String = "PLATFORM_UNAVAILABLE"
    const val ERROR_NOT_FOUND: String = "NOT_FOUND"
    const val ERROR_VAULT_LOCKED: String = "VAULT_LOCKED"
    const val ERROR_SAF_GRANT_MISSING: String = "SAF_GRANT_MISSING"

    /**
     * Extracts a trimmed non-blank [String] from a [SlotValueAst.StringValue], preserving
     * [Tainted] provenance, slot kind, and source label. Returns null if missing, null-valued,
     * wrong type, or blank.
     */
    fun getString(
        arguments: Map<String, Tainted<SlotValueAst>>,
        key: String
    ): Tainted<String>? {
        val tainted = arguments[key] ?: return null
        val ast = tainted.value
        if (ast !is SlotValueAst.StringValue) return null
        val trimmed = ast.value.trim()
        if (trimmed.isEmpty()) return null
        return tainted.map { trimmed }
    }

    /**
     * Extracts a raw (untrimmed) [String] from a [SlotValueAst.StringValue], allowing empty
     * strings (e.g., empty note body) while returning null only when missing, null-valued,
     * or non-string.
     */
    fun getRawString(
        arguments: Map<String, Tainted<SlotValueAst>>,
        key: String
    ): Tainted<String>? {
        val tainted = arguments[key] ?: return null
        val ast = tainted.value
        if (ast !is SlotValueAst.StringValue) return null
        return tainted.map { ast.value }
    }

    /**
     * Extracts any non-null [SlotValueAst] rendered via [SlotValueAst.asDisplayString],
     * returning null if missing, [SlotValueAst.NullValue], or blank.
     */
    fun getDisplayString(
        arguments: Map<String, Tainted<SlotValueAst>>,
        key: String
    ): Tainted<String>? {
        val tainted = arguments[key] ?: return null
        if (tainted.value is SlotValueAst.NullValue) return null
        val rendered = tainted.value.asDisplayString().trim()
        if (rendered.isEmpty()) return null
        return tainted.map { rendered }
    }

    /**
     * Extracts a [Long] from [SlotValueAst.IntValue] or a decimal-formatted [SlotValueAst.StringValue],
     * preserving [Tainted] provenance.
     */
    fun getLong(
        arguments: Map<String, Tainted<SlotValueAst>>,
        key: String
    ): Tainted<Long>? {
        val tainted = arguments[key] ?: return null
        val parsed: Long = when (val ast = tainted.value) {
            is SlotValueAst.IntValue -> ast.value
            is SlotValueAst.StringValue -> ast.value.trim().toLongOrNull() ?: return null
            is SlotValueAst.BooleanValue,
            SlotValueAst.NullValue -> return null
        }
        return tainted.map { parsed }
    }

    /**
     * Extracts a bounds-checked [Int] from [SlotValueAst.IntValue] or decimal [SlotValueAst.StringValue],
     * preserving [Tainted] provenance.
     */
    fun getInt(
        arguments: Map<String, Tainted<SlotValueAst>>,
        key: String
    ): Tainted<Int>? {
        val taintedLong = getLong(arguments, key) ?: return null
        val raw = taintedLong.value
        if (raw < Int.MIN_VALUE.toLong() || raw > Int.MAX_VALUE.toLong()) {
            return null
        }
        return taintedLong.map { raw.toInt() }
    }

    /**
     * Extracts a [Boolean] from [SlotValueAst.BooleanValue] or `"true"` / `"false"` strings,
     * preserving [Tainted] provenance.
     */
    fun getBoolean(
        arguments: Map<String, Tainted<SlotValueAst>>,
        key: String
    ): Tainted<Boolean>? {
        val tainted = arguments[key] ?: return null
        val parsed: Boolean = when (val ast = tainted.value) {
            is SlotValueAst.BooleanValue -> ast.value
            is SlotValueAst.StringValue -> when (ast.value.trim().lowercase(Locale.ROOT)) {
                "true", "1", "on", "yes", "enabled" -> true
                "false", "0", "off", "no", "disabled" -> false
                else -> return null
            }
            is SlotValueAst.IntValue -> when (ast.value) {
                1L -> true
                0L -> false
                else -> return null
            }
            SlotValueAst.NullValue -> return null
        }
        return tainted.map { parsed }
    }

    /**
     * Computes the worst (least trusted) [DataProvenance] across all entries in [arguments].
     */
    fun worstProvenance(
        arguments: Map<String, Tainted<SlotValueAst>>,
        fallback: DataProvenance = DataProvenance.USER_UTTERANCE
    ): DataProvenance {
        var current = fallback
        for (value in arguments.values) {
            current = DataProvenance.worstOf(current, value.provenance)
        }
        return current
    }

    /** True if any slot in [arguments] carries [DataProvenance.UNTRUSTED_EXTERNAL]. */
    fun hasUntrustedArgument(arguments: Map<String, Tainted<SlotValueAst>>): Boolean {
        return arguments.values.any { it.isUntrusted }
    }

    /** True if any slot in [arguments] carries a `vault:` source label. */
    fun hasVaultSourceArgument(arguments: Map<String, Tainted<SlotValueAst>>): Boolean {
        return arguments.values.any { isVaultSource(it.sourceLabel) }
    }

    /**
     * True when [sourceLabel] identifies content originating from Nava Secure Vault,
     * normalized via NFKC and invisible-control stripping to match `SecurityFirewall`.
     */
    fun isVaultSource(sourceLabel: String?): Boolean {
        if (sourceLabel.isNullOrBlank()) return false
        val normalized = Gemma4InputSanitizer.stripInvisibleControls(
            Normalizer.normalize(sourceLabel, Normalizer.Form.NFKC)
        ).trim().lowercase(Locale.ROOT)
        return normalized.startsWith(VAULT_SOURCE_PREFIX)
    }

    /** Converts typed slot arguments to canonical display strings while preserving taint. */
    fun toCanonicalDisplayMap(
        arguments: Map<String, Tainted<SlotValueAst>>
    ): Map<String, Tainted<String>> {
        return arguments.mapValues { (_, taintedValue) ->
            taintedValue.map { it.asDisplayString() }
        }
    }

    fun invalidArgumentsFailure(fieldNameOrDetail: String): ToolResult.Failure {
        return ToolResult.Failure(
            message = UserMessage(
                key = MessageKey.ERROR_INVALID_ARGUMENTS,
                args = listOf(MessageArg.Text(fieldNameOrDetail))
            ),
            errorCode = ERROR_INVALID_ARGUMENTS,
            isSecurityViolation = false
        )
    }

    fun missingPermissionFailure(permissionName: String): ToolResult.Failure {
        return ToolResult.Failure(
            message = UserMessage(
                key = MessageKey.ERROR_SYSTEM_PERMISSION_MISSING,
                args = listOf(MessageArg.Text(permissionName))
            ),
            errorCode = ERROR_SYSTEM_PERMISSION_MISSING,
            isSecurityViolation = false
        )
    }

    fun platformUnavailableFailure(reason: String): ToolResult.Failure {
        return ToolResult.Failure(
            message = UserMessage(
                key = MessageKey.ERROR_PLATFORM_UNAVAILABLE,
                args = listOf(MessageArg.Text(reason))
            ),
            errorCode = ERROR_PLATFORM_UNAVAILABLE,
            isSecurityViolation = false
        )
    }

    fun notFoundFailure(entityId: String): ToolResult.Failure {
        return ToolResult.Failure(
            message = UserMessage(
                key = MessageKey.ERROR_NOT_FOUND,
                args = listOf(MessageArg.Text(entityId))
            ),
            errorCode = ERROR_NOT_FOUND,
            isSecurityViolation = false
        )
    }

    fun securityFailure(
        reasonCode: String,
        message: UserMessage = UserMessage(
            key = MessageKey.ERROR_SECURITY_VIOLATION,
            args = listOf(MessageArg.Text(reasonCode))
        )
    ): ToolResult.Failure {
        return ToolResult.Failure(
            message = message,
            errorCode = reasonCode,
            isSecurityViolation = true
        )
    }
}

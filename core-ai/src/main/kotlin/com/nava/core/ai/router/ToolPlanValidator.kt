package com.nava.core.ai.router

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolSchemaField
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.Locale

/**
 * Shared deterministic plan normalization and schema validation helpers for Tier 2.5
 * ([FunctionGemmaIntentResolver]) and Tier 3 ([GemmaIntentResolver]).
 */
internal object ToolPlanValidator {

    sealed interface ValidationResult {
        data class Valid(val normalizedCalls: List<ToolCallAst>) : ValidationResult
        data class UnknownTool(val toolName: String) : ValidationResult
        data class SchemaInvalid(val toolName: String, val detail: String) : ValidationResult
    }

    fun formatNowIso(issuedAtEpochMs: Long): String? {
        if (issuedAtEpochMs <= 0L) return null
        return runCatching {
            val zoned = ZonedDateTime.ofInstant(
                Instant.ofEpochMilli(issuedAtEpochMs),
                ZoneId.systemDefault()
            )
            val daysInMonth = zoned.toLocalDate().lengthOfMonth()
            "${zoned.format(NOW_FORMATTER)}, daysInMonth=$daysInMonth"
        }.getOrNull()
    }

    fun validateAndNormalizeCalls(
        calls: List<ToolCallAst>,
        prunedByName: Map<String, ToolMetadata>,
        targetContextId: String
    ): ValidationResult {
        val normalizedCalls = ArrayList<ToolCallAst>(calls.size)
        for (rawCall in calls) {
            val metadata = prunedByName[rawCall.toolName]
                ?: return ValidationResult.UnknownTool(rawCall.toolName)
            val cleanedCall = stripPlaceholderOptionalPackageArguments(rawCall, metadata)
            val call = normalizeIsoDateTimeArguments(cleanedCall, metadata)
            val violation = schemaViolation(call, metadata)
            if (violation != null) {
                return ValidationResult.SchemaInvalid(call.toolName, violation)
            }
            val boundCall = if (call.targetId == null) {
                call.copy(targetId = targetContextId)
            } else {
                call
            }
            normalizedCalls.add(boundCall)
        }
        return ValidationResult.Valid(normalizedCalls)
    }

    /**
     * Returns `null` when [call] satisfies [metadata], otherwise a short English description of
     * the first schema violation (field names and value types only, never slot values).
     */
    fun schemaViolation(call: ToolCallAst, metadata: ToolMetadata): String? {
        val fieldsByName = metadata.fields.associateBy { it.name }
        for ((argName, taintedVal) in call.arguments) {
            val field = fieldsByName[argName]
                ?: return "unknown argument '$argName' (allowed: ${fieldsByName.keys.joinToString(",")})"
            if (!isValueValidForField(taintedVal.value, field)) {
                return "argument '$argName' has invalid ${describeValueKind(taintedVal.value)} " +
                    "for type ${field.valueType}"
            }
        }
        for (field in metadata.fields) {
            if (!field.required) continue
            val present = call.arguments[field.name]
                ?: return "missing required argument '${field.name}'"
            val value = present.value
            if (value is SlotValueAst.NullValue) return "required argument '${field.name}' is null"
            if (value is SlotValueAst.StringValue && value.value.isBlank()) {
                return "required argument '${field.name}' is blank"
            }
        }
        return null
    }

    /**
     * Deterministically repairs common small-model calendar date overflow (e.g. `2026-11-32T00:00:00`
     * rolled forward to `2026-12-02T00:00:00`) and appends a default `T09:00:00` time when an
     * `ISO_DATETIME` slot receives a valid date-only `YYYY-MM-DD`. Always preserves `Tainted<T>`
     * provenance unchanged.
     */
    fun normalizeIsoDateTimeArguments(
        call: ToolCallAst,
        metadata: ToolMetadata
    ): ToolCallAst {
        val fieldsByName = metadata.fields.associateBy { it.name }
        var changed = false
        val updated = LinkedHashMap<String, Tainted<SlotValueAst>>(call.arguments.size)
        for ((argName, tainted) in call.arguments) {
            val field = fieldsByName[argName]
            val value = tainted.value
            if (field != null && value is SlotValueAst.StringValue &&
                (field.valueType == SlotValueType.ISO_DATETIME || field.valueType == SlotValueType.ISO_DATE)
            ) {
                val repaired = repairIsoDateOrDateTime(
                    raw = value.value.trim(),
                    expectDateTime = field.valueType == SlotValueType.ISO_DATETIME
                )
                if (repaired != null && repaired != value.value) {
                    updated[argName] = tainted.map { SlotValueAst.StringValue(repaired) }
                    changed = true
                    continue
                }
            }
            updated[argName] = tainted
        }
        return if (changed) call.copy(arguments = updated) else call
    }

    private fun describeValueKind(value: SlotValueAst): String {
        return when (value) {
            is SlotValueAst.StringValue -> "string value"
            is SlotValueAst.IntValue -> "integer value"
            is SlotValueAst.BooleanValue -> "boolean value"
            is SlotValueAst.NullValue -> "null value"
        }
    }

    private fun isValueValidForField(value: SlotValueAst, field: ToolSchemaField): Boolean {
        if (value is SlotValueAst.NullValue) {
            return !field.required
        }
        return when (field.valueType) {
            SlotValueType.INTEGER -> value is SlotValueAst.IntValue
            SlotValueType.DURATION_SECONDS -> value is SlotValueAst.IntValue && value.value > 0L
            SlotValueType.BOOLEAN -> value is SlotValueAst.BooleanValue
            SlotValueType.ISO_TIME -> value is SlotValueAst.StringValue &&
                CANONICAL_TIME_REGEX.matches(value.value)

            SlotValueType.ISO_DATE -> value is SlotValueAst.StringValue &&
                runCatching { LocalDate.parse(value.value) }.isSuccess

            SlotValueType.ISO_DATETIME -> value is SlotValueAst.StringValue &&
                isValidIsoDateTime(value.value)

            SlotValueType.STRING -> value is SlotValueAst.StringValue &&
                (!field.required || value.value.isNotBlank())
        }
    }

    private fun isValidIsoDateTime(raw: String): Boolean {
        if (raw.isBlank()) return false
        return runCatching { OffsetDateTime.parse(raw) }.isSuccess ||
            runCatching { ZonedDateTime.parse(raw) }.isSuccess ||
            runCatching { LocalDateTime.parse(raw) }.isSuccess ||
            runCatching { Instant.parse(raw) }.isSuccess
    }

    private fun repairIsoDateOrDateTime(raw: String, expectDateTime: Boolean): String? {
        val match = LENIENT_ISO_DATE_REGEX.matchEntire(raw) ?: return null
        val year = match.groupValues[1].toIntOrNull() ?: return null
        val month = match.groupValues[2].toIntOrNull() ?: return null
        val day = match.groupValues[3].toIntOrNull() ?: return null
        val timePart = match.groupValues[4]
        if (month !in 1..12 || day !in 1..62) return null

        val rolledDate = runCatching {
            LocalDate.of(year, month, 1).plusDays((day - 1).toLong())
        }.getOrNull() ?: return null

        if (!expectDateTime) {
            return rolledDate.toString()
        }
        val normalizedTime = if (timePart.isEmpty()) "T09:00:00" else timePart
        return "${rolledDate}$normalizedTime"
    }

    /**
     * Strips generic LLM placeholder values (e.g. `"default"`, `"all"`, `"any"`) from optional
     * [SensitiveSlotKind.PACKAGE_NAME] filter arguments on non-launch tools (such as
     * `summarize_notifications`), preventing false `OUTBOUND_SCHEME_BLOCKED` rejections while
     * leaving real package identifiers, URI schemes, and traversal payloads untouched for
     * `SecurityFirewall` enforcement.
     */
    fun stripPlaceholderOptionalPackageArguments(
        call: ToolCallAst,
        metadata: ToolMetadata
    ): ToolCallAst {
        if (call.toolName == LAUNCH_APP_TOOL_NAME || call.arguments.isEmpty()) {
            return call
        }
        val fieldsByName = metadata.fields.associateBy { it.name }
        var changed = false
        val updated = LinkedHashMap<String, Tainted<SlotValueAst>>(call.arguments.size)
        for ((argName, tainted) in call.arguments) {
            val field = fieldsByName[argName]
            val value = tainted.value
            val isOptionalPackageFilter = field != null &&
                !field.required &&
                (field.slotKind == SensitiveSlotKind.PACKAGE_NAME || argName == "package_name")
            if (isOptionalPackageFilter && value is SlotValueAst.StringValue) {
                val normalized = value.value.trim().lowercase(Locale.ROOT)
                if (normalized in OPTIONAL_PACKAGE_PLACEHOLDERS) {
                    changed = true
                    continue
                }
            }
            updated[argName] = tainted
        }
        return if (changed) call.copy(arguments = updated) else call
    }

    private val LAUNCH_APP_TOOL_NAME: String = "launch_app"
    private val OPTIONAL_PACKAGE_PLACEHOLDERS: Set<String> = setOf(
        "",
        "default",
        "all",
        "any",
        "none",
        "null",
        "n/a",
        "*",
        "hepsi",
        "tumu"
    )
    private val CANONICAL_TIME_REGEX: Regex = Regex("""^(?:[01]\d|2[0-3]):[0-5]\d$""")
    private val LENIENT_ISO_DATE_REGEX: Regex =
        Regex("""^(\d{4})-(\d{1,2})-(\d{1,2})(T\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})?)?$""")
    private val NOW_FORMATTER: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm EEEE", Locale.US)
}

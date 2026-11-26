package com.nava.core.ai.prompt

import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolMetadata

/**
 * Token constants and declaration/prompt formatter for Google's FunctionGemma 270M router
 * (Tier 2.5, `PLAN.md` Section 4 & `ResolutionTier.TIER_2_5_FUNCTION_GEMMA`).
 */
object FunctionGemmaPromptFormat {
    const val FUNCTION_GEMMA_SYSTEM_PREFIX_ID: String = "nava_function_gemma_v1"

    const val FUNCTION_CALL_OPEN: String = "<start_function_call>"
    const val FUNCTION_CALL_CLOSE: String = "<end_function_call>"
    const val FUNCTION_DECL_OPEN: String = "<start_function_declaration>"
    const val FUNCTION_DECL_CLOSE: String = "<end_function_declaration>"
    const val FUNCTION_RESPONSE_OPEN: String = "<start_function_response>"
    const val FUNCTION_RESPONSE_CLOSE: String = "<end_function_response>"
    const val ESCAPE_TOKEN: String = "<escape>"
    const val DECLARATION_PREFIX: String = "declaration:"
    const val CALL_PREFIX: String = "call:"

    const val FUNCTION_GEMMA_SYSTEM_PROMPT: String =
        "You are Nava's offline Android function router. " +
            "You are a model that can do function calling with the following functions. " +
            "Evaluate ONLY the user request, [NOW], and the declared functions. " +
            "When an action matches a declared function, respond strictly with one or more function calls " +
            "in the exact format <start_function_call>call:NAME{key:<escape>value<escape>}<end_function_call> " +
            "with no extra prose. " +
            "Emit canonical formats for structured slots (ISO-8601 dates YYYY-MM-DD, ISO-8601 datetimes " +
            "YYYY-MM-DDTHH:MM:SS, 24h times HH:MM, integer durations in seconds, E.164 phone numbers) " +
            "regardless of user language, and use [NOW] to resolve relative dates or times. " +
            "Preserve free-text slots (labels, titles, note bodies, message drafts) in the user's language. " +
            "If no declared function matches the request, respond briefly with NO_FUNCTION_CALL."

    fun formatFunctionDeclaration(tool: ToolMetadata): String {
        val visibleFields = Gemma4PromptFormat.filterPromptVisibleFields(tool)
        val requiredFields = visibleFields.filter { it.required }
        return buildString {
            append(FUNCTION_DECL_OPEN)
            append(DECLARATION_PREFIX).append(tool.name)
            append("{description:").append(escapeString(tool.description))
            append(",parameters:{properties:{")
            for (index in visibleFields.indices) {
                val field = visibleFields[index]
                if (index > 0) append(',')
                append(field.name).append(":{description:")
                append(escapeString(formatFieldDescription(field.description, field.valueType)))
                append(",type:").append(escapeString(schemaTypeName(field.valueType)))
                append('}')
            }
            append('}')
            if (requiredFields.isNotEmpty()) {
                append(",required:[")
                for (index in requiredFields.indices) {
                    if (index > 0) append(',')
                    append(escapeString(requiredFields[index].name))
                }
                append(']')
            }
            append(",type:").append(escapeString("OBJECT"))
            append("}}")
            append(FUNCTION_DECL_CLOSE)
        }
    }

    fun formatDeclarations(tools: List<ToolMetadata>): String {
        if (tools.isEmpty()) return ""
        return buildString {
            for (index in tools.indices) {
                if (index > 0) append('\n')
                append(formatFunctionDeclaration(tools[index]))
            }
        }
    }

    fun formatTurnPayload(
        prunedTools: List<ToolMetadata>,
        languageHintTag: String,
        userUtterance: String,
        currentLocalDateTimeIso: String? = null
    ): String {
        val safeLang = Gemma4InputSanitizer.sanitize(languageHintTag).trim().ifEmpty { "en" }
        val safeUtterance = Gemma4InputSanitizer.sanitize(userUtterance).trim()
        val safeNow = currentLocalDateTimeIso?.let { Gemma4InputSanitizer.sanitize(it).trim() }
        val declarations = formatDeclarations(prunedTools)

        return buildString {
            if (declarations.isNotEmpty()) {
                append(declarations).append('\n')
            }
            if (!safeNow.isNullOrEmpty()) {
                append("[NOW=").append(safeNow).append("]\n")
            }
            append("[LANG=").append(safeLang).append("]\n")
            append(safeUtterance)
        }
    }

    private fun escapeString(value: String): String {
        val cleaned = Gemma4InputSanitizer.sanitize(value)
        return "$ESCAPE_TOKEN$cleaned$ESCAPE_TOKEN"
    }

    private fun formatFieldDescription(description: String, type: SlotValueType): String {
        val hint = when (type) {
            SlotValueType.ISO_DATE -> " (YYYY-MM-DD)"
            SlotValueType.ISO_TIME -> " (HH:MM)"
            SlotValueType.ISO_DATETIME -> " (YYYY-MM-DDTHH:MM:SS)"
            SlotValueType.DURATION_SECONDS -> " (integer seconds)"
            else -> ""
        }
        return if (hint.isEmpty() || description.contains(hint.trim())) {
            description
        } else {
            description + hint
        }
    }

    private fun schemaTypeName(type: SlotValueType): String {
        return when (type) {
            SlotValueType.INTEGER,
            SlotValueType.DURATION_SECONDS -> "INTEGER"

            SlotValueType.BOOLEAN -> "BOOLEAN"

            SlotValueType.STRING,
            SlotValueType.ISO_DATE,
            SlotValueType.ISO_TIME,
            SlotValueType.ISO_DATETIME -> "STRING"
        }
    }
}

package com.nava.core.security.firewall

import com.nava.domain.ai.LlmEnginePort
import com.nava.domain.ai.LlmGenerationRequest
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.Tainted
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolSchemaField
import java.text.Normalizer
import java.util.Locale
import java.util.UUID

/**
 * Deterministic Kotlin-side Stage 2 slot extractor implementing Plan-Then-Extract (PLAN.md Section 5.3).
 *
 * Security invariants:
 * - Never permits Stage 2 to select, invoke, or reference tools; any control token, tool-call grammar,
 *   function-call JSON payload, undeclared tool-like key, or duplicate slot key immediately throws
 *   [SecurityException] in Kotlin.
 * - 100% of extracted values are sanitized via [Gemma4InputSanitizer] and wrapped in
 *   [Tainted.fromUntrustedExternal] tagged with each declared field's [com.nava.domain.security.SensitiveSlotKind].
 * - Zero security decisions depend on language detection.
 */
class BlindSlotExtractor(
    private val llmEngine: LlmEnginePort? = null,
    private val requestIdGenerator: () -> String = { UUID.randomUUID().toString() }
) {

    /**
     * Executes Stage 2 blind extraction via [LlmEnginePort] with empty `prunedTools`,
     * `stage2BlindExtractionMode = true`, and `allowThoughtMode = false`, then validates and wraps
     * extracted passive slots via [parseAndValidateStage2Output].
     */
    suspend fun extractSlots(
        capabilityToken: CapabilityToken,
        targetTool: ToolMetadata,
        rawExternalContent: String,
        sourceLabel: String,
        languageHintTag: String,
        nowEpochMs: Long
    ): Map<String, Tainted<SlotValueAst>> {
        capabilityToken.assertValidFor(targetTool.name, nowEpochMs)
        require(sourceLabel.isNotBlank()) { "sourceLabel must not be blank" }
        require(languageHintTag.isNotBlank()) { "languageHintTag must not be blank" }
        val engine = llmEngine
            ?: throw IllegalStateException("LlmEnginePort is required to execute Stage 2 extraction")

        val sanitizedExternal = Gemma4InputSanitizer.sanitize(rawExternalContent)
        val prompt = buildPassiveExtractionPrompt(targetTool, sanitizedExternal)
        val request = LlmGenerationRequest(
            requestId = requestIdGenerator(),
            systemPrefixId = STAGE2_SYSTEM_PREFIX_ID,
            prunedTools = emptyList(),
            userUtterance = prompt,
            languageHintTag = languageHintTag,
            allowThoughtMode = false,
            maxThoughtTokens = 0,
            maxOutputTokens = MAX_STAGE2_OUTPUT_TOKENS,
            stage2BlindExtractionMode = true
        )
        val result = engine.generate(request)
        return parseAndValidateStage2Output(
            rawModelOutput = result.rawOutput,
            capabilityToken = capabilityToken,
            targetTool = targetTool,
            sourceLabel = sourceLabel,
            nowEpochMs = nowEpochMs
        )
    }

    /**
     * Deterministically inspects [rawModelOutput] in Kotlin, throwing [SecurityException] on any
     * control-token or tool-call smuggling attempt, and returns declared passive slot values wrapped
     * as [Tainted.fromUntrustedExternal].
     */
    fun parseAndValidateStage2Output(
        rawModelOutput: String,
        capabilityToken: CapabilityToken,
        targetTool: ToolMetadata,
        sourceLabel: String,
        nowEpochMs: Long
    ): Map<String, Tainted<SlotValueAst>> {
        capabilityToken.assertValidFor(targetTool.name, nowEpochMs)
        require(sourceLabel.isNotBlank()) { "sourceLabel must not be blank" }

        val nfkc = Normalizer.normalize(rawModelOutput, Normalizer.Form.NFKC)
        val stripped = Gemma4InputSanitizer.stripInvisibleControls(nfkc)

        assertNoControlTokensOrToolCalls(rawModelOutput, stripped)

        val declaredFieldsByName = targetTool.fields.associateBy { it.name }
        val extracted = LinkedHashMap<String, Tainted<SlotValueAst>>()

        for (rawLine in stripped.lineSequence()) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue

            if (isStandaloneJsonObjectLine(line)) {
                throw SecurityException(
                    "Stage 2 output attempted standalone JSON object syntax: '$line'"
                )
            }

            if (FUNCTION_CALL_LINE_REGEX.matches(line)) {
                throw SecurityException("Stage 2 output attempted function-call invocation: '$line'")
            }

            val sepIdx = findKeyValueSeparator(line)
            if (sepIdx <= 0) {
                if (CALL_LINE_PREFIX_REGEX.containsMatchIn(line)) {
                    throw SecurityException("Stage 2 output attempted tool call directive: '$line'")
                }
                continue
            }

            val rawKey = line.substring(0, sepIdx).trim()
                .removePrefix("-")
                .removePrefix("*")
                .trim()
                .trim('"', '\'')
            val rawVal = line.substring(sepIdx + 1).trim()

            if (rawKey.isEmpty()) continue
            val lowerKey = rawKey.lowercase(Locale.ROOT)

            if (lowerKey in FORBIDDEN_TOOL_KEYS) {
                throw SecurityException(
                    "Stage 2 output attempted to emit forbidden tool-control key '$rawKey'"
                )
            }

            val field = declaredFieldsByName[rawKey]
            if (field == null) {
                if (UNDECLARED_IDENTIFIER_KEY_REGEX.matches(rawKey)) {
                    throw SecurityException(
                        "Stage 2 output emitted undeclared slot/tool key '$rawKey' not in '${targetTool.name}' schema"
                    )
                }
                continue
            }

            if (rawKey in extracted) {
                throw SecurityException(
                    "Stage 2 output emitted duplicate slot key '$rawKey' (possible overwrite injection)"
                )
            }

            if (CALL_GRAMMAR_REGEX.containsMatchIn(rawVal) ||
                JSON_TOOL_INJECTION_REGEX.containsMatchIn(rawVal) ||
                containsJsonActionObject(rawVal)
            ) {
                throw SecurityException(
                    "Stage 2 slot '$rawKey' contained embedded tool-call syntax"
                )
            }

            val parsedAst = parseSlotValue(field, rawVal)
            extracted[field.name] = Tainted.fromUntrustedExternal(
                value = parsedAst,
                slotKind = field.slotKind,
                sourceLabel = sourceLabel
            )
        }

        return extracted
    }

    private fun assertNoControlTokensOrToolCalls(rawOutput: String, normalizedStripped: String) {
        if (CONTROL_TOKEN_DETECT_REGEX.containsMatchIn(normalizedStripped)) {
            throw SecurityException("Stage 2 output contained forbidden Gemma 4 control token")
        }
        val sanitized = Gemma4InputSanitizer.sanitize(rawOutput)
        if (sanitized != normalizedStripped) {
            throw SecurityException("Stage 2 output contained smuggled Gemma 4 control sequence")
        }
        if (CALL_GRAMMAR_REGEX.containsMatchIn(normalizedStripped)) {
            throw SecurityException("Stage 2 output attempted native tool-call grammar")
        }
        if (JSON_TOOL_INJECTION_REGEX.containsMatchIn(normalizedStripped)) {
            throw SecurityException("Stage 2 output attempted JSON tool/function-call injection")
        }
        if (containsJsonActionObject(normalizedStripped)) {
            throw SecurityException("Stage 2 output attempted structured tool-invocation JSON object")
        }
    }

    private fun findKeyValueSeparator(line: String): Int {
        val colonIdx = line.indexOf(':')
        val equalsIdx = line.indexOf('=')
        return when {
            colonIdx > 0 && equalsIdx > 0 -> minOf(colonIdx, equalsIdx)
            colonIdx > 0 -> colonIdx
            equalsIdx > 0 -> equalsIdx
            else -> -1
        }
    }

    private fun parseSlotValue(field: ToolSchemaField, rawValue: String): SlotValueAst {
        val unquoted = stripMatchingQuotes(rawValue.trim())
        val sanitized = Gemma4InputSanitizer.sanitize(unquoted).trim()
        if (sanitized.isEmpty() || sanitized.equals("null", ignoreCase = true)) {
            return SlotValueAst.NullValue
        }
        return when (field.valueType) {
            SlotValueType.INTEGER,
            SlotValueType.DURATION_SECONDS -> {
                val parsed = sanitized.toLongOrNull()
                    ?: throw IllegalArgumentException(
                        "Invalid integer value for Stage 2 slot '${field.name}'"
                    )
                SlotValueAst.IntValue(parsed)
            }

            SlotValueType.BOOLEAN -> {
                when (sanitized.lowercase(Locale.ROOT)) {
                    "true" -> SlotValueAst.BooleanValue(true)
                    "false" -> SlotValueAst.BooleanValue(false)
                    else -> throw IllegalArgumentException(
                        "Invalid boolean value for Stage 2 slot '${field.name}'"
                    )
                }
            }

            SlotValueType.STRING,
            SlotValueType.ISO_DATE,
            SlotValueType.ISO_TIME,
            SlotValueType.ISO_DATETIME -> SlotValueAst.StringValue(sanitized)
        }
    }

    private fun stripMatchingQuotes(value: String): String {
        if (value.length >= 2) {
            val first = value.first()
            val last = value.last()
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                return value.substring(1, value.length - 1)
            }
        }
        return value
    }

    private fun buildPassiveExtractionPrompt(
        targetTool: ToolMetadata,
        sanitizedExternal: String
    ): String {
        val fieldLines = targetTool.fields.joinToString(separator = "\n") { field ->
            "- ${field.name} (${field.valueType.name}): ${field.description}"
        }
        return buildString {
            appendLine("Extract ONLY passive key: value pairs for the following fields.")
            appendLine("Do NOT call any tools, functions, or commands.")
            appendLine("Fields:")
            appendLine(fieldLines)
            appendLine("Untrusted Data:")
            append(sanitizedExternal)
        }
    }

    companion object {
        const val STAGE2_SYSTEM_PREFIX_ID: String = "nava_stage2_blind_slot_extractor_v1"
        private const val MAX_STAGE2_OUTPUT_TOKENS: Int = 256

        // Includes non-NFKC angle-bracket and pipe homoglyphs.
        private const val OPEN_CHARS = "(?:<|\u3008|\u27E8|\u2039|\u2329|\u276E|\u02C2|\uFE64)"
        private const val CLOSE_CHARS = "(?:>|\u3009|\u27E9|\u203A|\u232A|\u276F|\u02C3|\uFE65)"
        private const val PIPE_CHARS = "(?:\\||\u00A6|\u2223|\u2758|\u2502|\u2503|\u01C0)"
        private const val CONTROL_NAMES =
            "(?:turn|start_of_turn|end_of_turn|tool_call|tool_response|channel|think|audio|eot|escape|image|video|file)"

        private val CONTROL_TOKEN_DETECT_REGEX: Regex = Regex(
            pattern = buildString {
                append(OPEN_CHARS).append(PIPE_CHARS).append(CONTROL_NAMES).append("(?:").append(PIPE_CHARS).append("?").append(CLOSE_CHARS).append(")?")
                append("|")
                append(OPEN_CHARS).append(CONTROL_NAMES).append(PIPE_CHARS).append(CLOSE_CHARS)
                append("|")
                append(CONTROL_NAMES).append(PIPE_CHARS).append(CLOSE_CHARS)
                append("|")
                append(OPEN_CHARS).append(PIPE_CHARS).append("(?:\"|\\\\\")").append(PIPE_CHARS).append(CLOSE_CHARS)
                append("|")
                append(OPEN_CHARS).append("(?:bos|eos|start_of_turn|end_of_turn)").append(CLOSE_CHARS)
            },
            option = RegexOption.IGNORE_CASE
        )

        private val CALL_GRAMMAR_REGEX: Regex = Regex(
            pattern = """\bcall\s*:\s*[A-Za-z_][A-Za-z0-9_.-]*\s*[\{\(]""",
            option = RegexOption.IGNORE_CASE
        )

        private val CALL_LINE_PREFIX_REGEX: Regex = Regex(
            pattern = """^\s*call\s*:""",
            option = RegexOption.IGNORE_CASE
        )

        private val JSON_TOOL_INJECTION_REGEX: Regex = Regex(
            pattern = """["'](?:tool_call|tool_calls|function_call|function_calls|tool_name|toolName|function_name|invoke_tool|execute_tool)["']\s*:|\b(?:tool_call|function_call)\s*[:=\(\{]""",
            option = RegexOption.IGNORE_CASE
        )

        private val JSON_ACTION_NAME_KEY_REGEX: Regex = Regex(
            pattern = """["'](?:name|tool|function|action|callee)["']\s*:""",
            option = RegexOption.IGNORE_CASE
        )

        private val JSON_ACTION_ARGS_KEY_REGEX: Regex = Regex(
            pattern = """["'](?:args|arguments|params|parameters|input)["']\s*:""",
            option = RegexOption.IGNORE_CASE
        )

        private val FUNCTION_CALL_LINE_REGEX: Regex = Regex(
            pattern = """^[A-Za-z_][A-Za-z0-9_.-]*\s*\(.*\)\s*;?$"""
        )

        private val UNDECLARED_IDENTIFIER_KEY_REGEX: Regex = Regex(
            pattern = """^[A-Za-z_][A-Za-z0-9_.-]*$"""
        )

        private val FORBIDDEN_TOOL_KEYS: Set<String> = setOf(
            "tool",
            "tools",
            "tool_name",
            "toolname",
            "tool_call",
            "tool_calls",
            "call",
            "function",
            "function_name",
            "function_call",
            "invoke",
            "invoke_tool",
            "execute",
            "execute_tool",
            "exec",
            "command",
            "system_override",
            "override"
        )

        /**
         * Deterministic check shared with [SecurityFirewall] to detect Gemma 4 control tokens
         * (including unclosed and extended angle/pipe homoglyph variants), native `call:` grammar,
         * and JSON tool/function-call payloads across single-line or multi-line text.
         */
        internal fun containsControlTokenOrToolCallSyntax(raw: String): Boolean {
            if (raw.isEmpty()) return false
            val nfkc = Normalizer.normalize(raw, Normalizer.Form.NFKC)
            val stripped = Gemma4InputSanitizer.stripInvisibleControls(nfkc)
            if (CONTROL_TOKEN_DETECT_REGEX.containsMatchIn(stripped)) return true
            if (Gemma4InputSanitizer.sanitize(raw) != stripped) return true
            if (CALL_GRAMMAR_REGEX.containsMatchIn(stripped)) return true
            if (JSON_TOOL_INJECTION_REGEX.containsMatchIn(stripped)) return true
            if (containsJsonActionObject(stripped)) return true
            return false
        }

        private fun isStandaloneJsonObjectLine(trimmedLine: String): Boolean {
            if (!trimmedLine.startsWith("{")) return false
            return trimmedLine == "{" ||
                trimmedLine.endsWith("}") ||
                trimmedLine.contains(":")
        }

        /**
         * Scans every `{...}` JSON-like object block (including multi-line, nested, and unclosed
         * blocks) in linear time and returns true if any block contains both an action/name key
         * and an arguments/payload key in any order with any intervening fields.
         */
        private fun containsJsonActionObject(text: String): Boolean {
            if ('{' !in text) return false
            val openStack = ArrayList<Int>()
            var inDoubleQuote = false
            var inSingleQuote = false
            var escaped = false

            for (i in text.indices) {
                val ch = text[i]
                if (escaped) {
                    escaped = false
                    continue
                }
                if (inDoubleQuote) {
                    when (ch) {
                        '\\' -> escaped = true
                        '"' -> inDoubleQuote = false
                    }
                    continue
                }
                if (inSingleQuote) {
                    when (ch) {
                        '\\' -> escaped = true
                        '\'' -> inSingleQuote = false
                    }
                    continue
                }
                when (ch) {
                    '"' -> inDoubleQuote = true
                    '\'' -> inSingleQuote = true
                    '{' -> openStack.add(i)
                    '}' -> {
                        if (openStack.isNotEmpty()) {
                            val start = openStack.removeAt(openStack.lastIndex)
                            val block = text.substring(start, i + 1)
                            if (
                                JSON_ACTION_NAME_KEY_REGEX.containsMatchIn(block) &&
                                JSON_ACTION_ARGS_KEY_REGEX.containsMatchIn(block)
                            ) {
                                return true
                            }
                        }
                    }
                }
            }

            // Also inspect any unclosed `{...` fragment reaching EOF (e.g., truncated injection).
            if (openStack.isNotEmpty()) {
                val outerStart = openStack.first()
                val tail = text.substring(outerStart)
                if (
                    JSON_ACTION_NAME_KEY_REGEX.containsMatchIn(tail) &&
                    JSON_ACTION_ARGS_KEY_REGEX.containsMatchIn(tail)
                ) {
                    return true
                }
            }

            return false
        }
    }
}

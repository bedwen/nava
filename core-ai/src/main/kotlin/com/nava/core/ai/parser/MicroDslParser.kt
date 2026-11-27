package com.nava.core.ai.parser

import com.nava.core.ai.prompt.FunctionGemmaPromptFormat
import com.nava.core.ai.prompt.Gemma4PromptFormat
import com.nava.domain.ai.MicroDslAst
import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.ToolMetadata

/**
 * Deterministic, zero-reflection, depth- and size-bounded recursive-descent parser converting
 * Gemma 4 tool-call streams into strongly-typed [MicroDslAst] nodes (PLAN.md Section 4.2).
 */
class MicroDslParser {

    fun parse(
        rawOutput: String,
        planId: String,
        languageTag: String,
        toolMetadataByName: Map<String, ToolMetadata> = emptyMap(),
        provenance: DataProvenance = DataProvenance.USER_UTTERANCE
    ): MicroDslAst {
        if (planId.isBlank() || languageTag.isBlank()) {
            return MicroDslAst.ParseError(
                rawFragment = rawOutput.take(ERROR_FRAGMENT_LIMIT),
                reason = "planId and languageTag must not be blank"
            )
        }
        if (rawOutput.length > MAX_OUTPUT_CHARS) {
            return MicroDslAst.ParseError(
                rawFragment = rawOutput.take(ERROR_FRAGMENT_LIMIT),
                reason = "Model output exceeds maximum allowed size of $MAX_OUTPUT_CHARS characters"
            )
        }

        val strippedThought = stripThoughtBlocks(rawOutput)
        if (strippedThought.error != null) {
            return strippedThought.error
        }

        val working = strippedThought.cleaned
        val hasToolCallMarkers = containsToolCallMarker(working)

        if (!hasToolCallMarkers) {
            val sanitizedReply = try {
                Gemma4InputSanitizer.sanitize(working).trim()
            } catch (e: SecurityException) {
                return MicroDslAst.ParseError(
                    rawFragment = working.take(ERROR_FRAGMENT_LIMIT),
                    reason = e.message ?: "Sanitization rejected control-token nesting"
                )
            }
            if (sanitizedReply.isEmpty()) {
                return MicroDslAst.ParseError(
                    rawFragment = rawOutput.take(ERROR_FRAGMENT_LIMIT),
                    reason = "Model output is empty after stripping thought channel"
                )
            }
            return MicroDslAst.DirectReply(text = sanitizedReply, languageTag = languageTag)
        }

        return parseToolCallSequence(
            working = working,
            planId = planId,
            toolMetadataByName = toolMetadataByName,
            provenance = provenance
        )
    }

    private data class ThoughtStripResult(
        val cleaned: String,
        val error: MicroDslAst.ParseError? = null
    )

    private fun stripThoughtBlocks(raw: String): ThoughtStripResult {
        val sb = StringBuilder(raw.length)
        var pos = 0
        val len = raw.length
        while (pos < len) {
            val openIdx = raw.indexOf(Gemma4PromptFormat.CHANNEL_OPEN, pos)
            val closeIdx = raw.indexOf(Gemma4PromptFormat.CHANNEL_CLOSE, pos)

            if (closeIdx >= 0 && (openIdx < 0 || closeIdx < openIdx)) {
                return ThoughtStripResult(
                    cleaned = "",
                    error = MicroDslAst.ParseError(
                        rawFragment = raw.substring(closeIdx).take(ERROR_FRAGMENT_LIMIT),
                        reason = "Unexpected closing thought channel token without opening block"
                    )
                )
            }

            if (openIdx < 0) {
                sb.append(raw, pos, len)
                break
            }

            sb.append(raw, pos, openIdx)
            val afterOpen = openIdx + Gemma4PromptFormat.CHANNEL_OPEN.length
            val matchingClose = raw.indexOf(Gemma4PromptFormat.CHANNEL_CLOSE, afterOpen)
            if (matchingClose < 0) {
                return ThoughtStripResult(
                    cleaned = "",
                    error = MicroDslAst.ParseError(
                        rawFragment = raw.substring(openIdx).take(ERROR_FRAGMENT_LIMIT),
                        reason = "Unclosed thought channel block"
                    )
                )
            }

            val nestedOpen = raw.indexOf(Gemma4PromptFormat.CHANNEL_OPEN, afterOpen)
            if (nestedOpen in afterOpen until matchingClose) {
                return ThoughtStripResult(
                    cleaned = "",
                    error = MicroDslAst.ParseError(
                        rawFragment = raw.substring(openIdx, matchingClose + Gemma4PromptFormat.CHANNEL_CLOSE.length)
                            .take(ERROR_FRAGMENT_LIMIT),
                        reason = "Nested channel block is not allowed"
                    )
                )
            }

            val channelBody = raw.substring(afterOpen, matchingClose)
            val thoughtPrefix = Gemma4PromptFormat.CHANNEL_THOUGHT
            val hasValidThoughtHeader = channelBody.startsWith(thoughtPrefix) &&
                (channelBody.length == thoughtPrefix.length || channelBody[thoughtPrefix.length].isWhitespace())
            if (!hasValidThoughtHeader) {
                return ThoughtStripResult(
                    cleaned = "",
                    error = MicroDslAst.ParseError(
                        rawFragment = raw.substring(openIdx, matchingClose + Gemma4PromptFormat.CHANNEL_CLOSE.length)
                            .take(ERROR_FRAGMENT_LIMIT),
                        reason = "Unsupported channel type inside <|channel> block"
                    )
                )
            }

            pos = matchingClose + Gemma4PromptFormat.CHANNEL_CLOSE.length
        }

        // Reject truncated partial `<|channel` marker.
        if (sb.contains(PARTIAL_CHANNEL_MARKER)) {
            return ThoughtStripResult(
                cleaned = "",
                error = MicroDslAst.ParseError(
                    rawFragment = sb.toString().take(ERROR_FRAGMENT_LIMIT),
                    reason = "Unclosed thought channel block"
                )
            )
        }

        return ThoughtStripResult(cleaned = sb.toString())
    }

    private fun containsToolCallMarker(text: String): Boolean {
        return text.contains(Gemma4PromptFormat.TOOL_CALL_OPEN) ||
            text.contains(Gemma4PromptFormat.TOOL_CALL_CLOSE) ||
            text.contains(PARTIAL_TOOL_CALL_MARKER) ||
            text.contains(FunctionGemmaPromptFormat.FUNCTION_CALL_OPEN) ||
            text.contains(FunctionGemmaPromptFormat.FUNCTION_CALL_CLOSE) ||
            text.contains(PARTIAL_FUNCTION_CALL_OPEN) ||
            text.contains(PARTIAL_FUNCTION_CALL_CLOSE) ||
            BARE_CALL_PREFIX_REGEX.containsMatchIn(text)
    }

    private fun containsAnyNestedCallMarker(body: String): Boolean {
        return body.contains(Gemma4PromptFormat.TOOL_CALL_OPEN) ||
            body.contains(Gemma4PromptFormat.TOOL_CALL_CLOSE) ||
            body.contains(PARTIAL_TOOL_CALL_MARKER) ||
            body.contains(FunctionGemmaPromptFormat.FUNCTION_CALL_OPEN) ||
            body.contains(FunctionGemmaPromptFormat.FUNCTION_CALL_CLOSE) ||
            body.contains(PARTIAL_FUNCTION_CALL_OPEN) ||
            body.contains(PARTIAL_FUNCTION_CALL_CLOSE)
    }

    private fun parseToolCallSequence(
        working: String,
        planId: String,
        toolMetadataByName: Map<String, ToolMetadata>,
        provenance: DataProvenance
    ): MicroDslAst {
        val calls = ArrayList<ToolCallAst>()
        var pos = 0
        val len = working.length

        while (pos < len) {
            pos = skipWhitespace(working, pos)
            if (pos >= len) break

            val (openTag, closeTag) = when {
                working.startsWith(Gemma4PromptFormat.TOOL_CALL_OPEN, pos) ->
                    Gemma4PromptFormat.TOOL_CALL_OPEN to Gemma4PromptFormat.TOOL_CALL_CLOSE

                working.startsWith(FunctionGemmaPromptFormat.FUNCTION_CALL_OPEN, pos) ->
                    FunctionGemmaPromptFormat.FUNCTION_CALL_OPEN to FunctionGemmaPromptFormat.FUNCTION_CALL_CLOSE

                else -> return MicroDslAst.ParseError(
                    rawFragment = working.substring(pos).take(ERROR_FRAGMENT_LIMIT),
                    reason = "Malformed or unexpected content outside tool call block"
                )
            }

            val contentStart = pos + openTag.length
            val closeIdx = working.indexOf(closeTag, contentStart)
            if (closeIdx < 0) {
                return MicroDslAst.ParseError(
                    rawFragment = working.substring(pos).take(ERROR_FRAGMENT_LIMIT),
                    reason = "Unclosed $openTag block"
                )
            }

            val blockBody = working.substring(contentStart, closeIdx)
            if (containsAnyNestedCallMarker(blockBody)) {
                return MicroDslAst.ParseError(
                    rawFragment = blockBody.take(ERROR_FRAGMENT_LIMIT),
                    reason = "Nested tool call block is forbidden"
                )
            }

            if (calls.size >= MAX_CALLS_PER_PLAN) {
                return MicroDslAst.ParseError(
                    rawFragment = blockBody.take(ERROR_FRAGMENT_LIMIT),
                    reason = "Plan exceeds maximum of $MAX_CALLS_PER_PLAN tool calls"
                )
            }

            val parsedCall = parseSingleCallBlock(
                blockBody = blockBody,
                orderIndex = calls.size,
                toolMetadataByName = toolMetadataByName,
                provenance = provenance
            )
            if (parsedCall.error != null) {
                return parsedCall.error
            }
            calls.add(parsedCall.call!!)

            pos = closeIdx + closeTag.length
        }

        if (calls.isEmpty()) {
            return MicroDslAst.ParseError(
                rawFragment = working.take(ERROR_FRAGMENT_LIMIT),
                reason = "No valid tool calls parsed"
            )
        }

        return MicroDslAst.Plan(PlanAst(planId = planId, calls = calls))
    }

    private data class SingleCallResult(
        val call: ToolCallAst? = null,
        val error: MicroDslAst.ParseError? = null
    )

    private fun parseSingleCallBlock(
        blockBody: String,
        orderIndex: Int,
        toolMetadataByName: Map<String, ToolMetadata>,
        provenance: DataProvenance
    ): SingleCallResult {
        val reader = CallReader(blockBody)
        reader.skipWhitespace()

        if (!reader.consumePrefix(Gemma4PromptFormat.CALL_PREFIX)) {
            return SingleCallResult(
                error = MicroDslAst.ParseError(
                    rawFragment = blockBody.take(ERROR_FRAGMENT_LIMIT),
                    reason = "Tool call block must begin with '${Gemma4PromptFormat.CALL_PREFIX}'"
                )
            )
        }

        val toolName = reader.readIdentifier()
        if (toolName == null || !IDENTIFIER_REGEX.matches(toolName)) {
            return SingleCallResult(
                error = MicroDslAst.ParseError(
                    rawFragment = blockBody.take(ERROR_FRAGMENT_LIMIT),
                    reason = "Invalid or missing tool name identifier"
                )
            )
        }

        reader.skipWhitespace()
        val closeDelimiter: Char = when {
            reader.consumeChar('{') -> '}'
            reader.consumeChar('(') -> ')'
            else -> {
                return SingleCallResult(
                    error = MicroDslAst.ParseError(
                        rawFragment = blockBody.take(ERROR_FRAGMENT_LIMIT),
                        reason = "Expected '{' after tool name '$toolName'"
                    )
                )
            }
        }

        val toolMetadata = toolMetadataByName[toolName]
        val args = LinkedHashMap<String, Tainted<SlotValueAst>>()
        reader.skipWhitespace()

        if (!reader.consumeChar(closeDelimiter)) {
            while (true) {
                reader.skipWhitespace()
                val key = reader.readIdentifier()
                if (key == null || !IDENTIFIER_REGEX.matches(key)) {
                    return SingleCallResult(
                        error = MicroDslAst.ParseError(
                            rawFragment = reader.remainingFragment(),
                            reason = "Invalid or missing argument key in tool call '$toolName'"
                        )
                    )
                }
                if (key in args) {
                    return SingleCallResult(
                        error = MicroDslAst.ParseError(
                            rawFragment = blockBody.take(ERROR_FRAGMENT_LIMIT),
                            reason = "Duplicate argument key '$key' in tool call '$toolName'"
                        )
                    )
                }
                if (args.size >= MAX_ARGS_PER_CALL) {
                    return SingleCallResult(
                        error = MicroDslAst.ParseError(
                            rawFragment = blockBody.take(ERROR_FRAGMENT_LIMIT),
                            reason = "Tool call '$toolName' exceeds maximum of $MAX_ARGS_PER_CALL arguments"
                        )
                    )
                }

                reader.skipWhitespace()
                if (!reader.consumeChar(':')) {
                    return SingleCallResult(
                        error = MicroDslAst.ParseError(
                            rawFragment = reader.remainingFragment(),
                            reason = "Expected ':' after key '$key' in tool call '$toolName'"
                        )
                    )
                }

                reader.skipWhitespace()
                val parsedValue = reader.readValue()
                if (parsedValue.error != null) {
                    return SingleCallResult(error = parsedValue.error)
                }

                val slotKind = toolMetadata?.fieldByName(key)?.slotKind
                val sanitizedAst = sanitizeSlotValue(parsedValue.value!!)
                    ?: return SingleCallResult(
                        error = MicroDslAst.ParseError(
                            rawFragment = blockBody.take(ERROR_FRAGMENT_LIMIT),
                            reason = "Argument '$key' exceeded control-token sanitization nesting limit"
                        )
                    )
                args[key] = wrapTainted(sanitizedAst, provenance, slotKind)

                reader.skipWhitespace()
                when {
                    reader.consumeChar(',') -> {
                        reader.skipWhitespace()
                        if (reader.peekOrNull() == closeDelimiter) {
                            return SingleCallResult(
                                error = MicroDslAst.ParseError(
                                    rawFragment = blockBody.take(ERROR_FRAGMENT_LIMIT),
                                    reason = "Trailing comma in argument list for tool '$toolName'"
                                )
                            )
                        }
                    }

                    reader.consumeChar(closeDelimiter) -> break
                    else -> {
                        return SingleCallResult(
                            error = MicroDslAst.ParseError(
                                rawFragment = reader.remainingFragment(),
                                reason = "Unclosed argument block or missing ',' in tool call '$toolName'"
                            )
                        )
                    }
                }
            }
        }

        reader.skipWhitespace()
        if (!reader.isEof()) {
            return SingleCallResult(
                error = MicroDslAst.ParseError(
                    rawFragment = reader.remainingFragment(),
                    reason = "Unexpected trailing content after '}' in tool call '$toolName'"
                )
            )
        }

        return SingleCallResult(
            call = ToolCallAst(
                toolName = toolName,
                arguments = args,
                orderIndex = orderIndex
            )
        )
    }

    private fun sanitizeSlotValue(ast: SlotValueAst): SlotValueAst? {
        return when (ast) {
            is SlotValueAst.StringValue -> {
                try {
                    SlotValueAst.StringValue(Gemma4InputSanitizer.sanitize(ast.value))
                } catch (_: SecurityException) {
                    null
                }
            }

            is SlotValueAst.IntValue,
            is SlotValueAst.BooleanValue,
            SlotValueAst.NullValue -> ast
        }
    }

    private fun wrapTainted(
        value: SlotValueAst,
        provenance: DataProvenance,
        slotKind: SensitiveSlotKind?
    ): Tainted<SlotValueAst> {
        return when (provenance) {
            DataProvenance.USER_UTTERANCE -> Tainted.fromUserUtterance(value, slotKind = slotKind)
            DataProvenance.SYSTEM -> Tainted.fromSystem(value, slotKind = slotKind)
            DataProvenance.UNTRUSTED_EXTERNAL -> Tainted.fromUntrustedExternal(value, slotKind = slotKind)
        }
    }

    private data class ValueResult(
        val value: SlotValueAst? = null,
        val error: MicroDslAst.ParseError? = null
    )

    private class CallReader(private val src: String) {
        private var pos: Int = 0
        private val len: Int = src.length

        fun isEof(): Boolean = pos >= len

        fun peekOrNull(): Char? = if (pos < len) src[pos] else null

        fun remainingFragment(): String {
            return if (pos < len) src.substring(pos).take(ERROR_FRAGMENT_LIMIT) else src.take(ERROR_FRAGMENT_LIMIT)
        }

        fun skipWhitespace() {
            while (pos < len && src[pos].isWhitespace()) {
                pos++
            }
        }

        fun consumePrefix(prefix: String): Boolean {
            if (src.startsWith(prefix, pos)) {
                pos += prefix.length
                return true
            }
            return false
        }

        fun consumeChar(expected: Char): Boolean {
            if (pos < len && src[pos] == expected) {
                pos++
                return true
            }
            return false
        }

        fun readIdentifier(): String? {
            if (isEof()) return null
            val start = pos
            val first = src[pos]
            if (!isIdentifierStart(first)) return null
            pos++
            while (pos < len && isIdentifierPart(src[pos])) {
                pos++
            }
            return src.substring(start, pos)
        }

        fun readValue(): ValueResult {
            if (isEof()) {
                return ValueResult(
                    error = MicroDslAst.ParseError(
                        rawFragment = remainingFragment(),
                        reason = "Missing argument value"
                    )
                )
            }

            if (src.startsWith(Gemma4PromptFormat.STRING_QUOTE, pos)) {
                return readDelimitedString(Gemma4PromptFormat.STRING_QUOTE)
            }
            if (src.startsWith(FunctionGemmaPromptFormat.ESCAPE_TOKEN, pos)) {
                return readDelimitedString(FunctionGemmaPromptFormat.ESCAPE_TOKEN)
            }

            return when (val ch = src[pos]) {
                '"' -> readDoubleQuotedString()
                // Small models sometimes emit typographic quotes; accept them as plain string
                // delimiters (same rules: no line breaks, no nesting, no escapes).
                '\u201C' -> readTypographicQuotedString()
                '{', '[' -> ValueResult(
                    error = MicroDslAst.ParseError(
                        rawFragment = remainingFragment(),
                        reason = "Nested objects or arrays are not permitted in MicroDsl arguments"
                    )
                )

                '-', in '0'..'9' -> readInteger()
                't' -> readKeyword("true", SlotValueAst.BooleanValue(true))
                'f' -> readKeyword("false", SlotValueAst.BooleanValue(false))
                'n' -> readKeyword("null", SlotValueAst.NullValue)
                else -> ValueResult(
                    error = MicroDslAst.ParseError(
                        rawFragment = remainingFragment(),
                        reason = "Unexpected value token starting with '$ch'"
                    )
                )
            }
        }

        private fun readDelimitedString(delimiter: String): ValueResult {
            pos += delimiter.length
            val sb = StringBuilder()
            while (pos < len) {
                if (src.startsWith(delimiter, pos)) {
                    pos += delimiter.length
                    return ValueResult(value = SlotValueAst.StringValue(sb.toString()))
                }
                val ch = src[pos++]
                if (ch == '\\') {
                    val escaped = readEscapeSequence() ?: return ValueResult(
                        error = MicroDslAst.ParseError(
                            rawFragment = remainingFragment(),
                            reason = "Invalid escape sequence inside $delimiter string"
                        )
                    )
                    sb.append(escaped)
                } else {
                    sb.append(ch)
                }
            }
            return ValueResult(
                error = MicroDslAst.ParseError(
                    rawFragment = src.take(ERROR_FRAGMENT_LIMIT),
                    reason = "Unterminated string delimiter $delimiter"
                )
            )
        }

        private fun readDoubleQuotedString(): ValueResult {
            pos++ // consume opening '"'
            val sb = StringBuilder()
            while (pos < len) {
                val ch = src[pos++]
                when {
                    ch == '"' -> return ValueResult(value = SlotValueAst.StringValue(sb.toString()))
                    ch == '\\' -> {
                        val escaped = readEscapeSequence() ?: return ValueResult(
                            error = MicroDslAst.ParseError(
                                rawFragment = remainingFragment(),
                                reason = "Invalid escape sequence inside quoted string"
                            )
                        )
                        sb.append(escaped)
                    }

                    ch == '\n' || ch == '\r' -> return ValueResult(
                        error = MicroDslAst.ParseError(
                            rawFragment = remainingFragment(),
                            reason = "Unescaped line break inside quoted string"
                        )
                    )

                    else -> sb.append(ch)
                }
            }
            return ValueResult(
                error = MicroDslAst.ParseError(
                    rawFragment = src.take(ERROR_FRAGMENT_LIMIT),
                    reason = "Unterminated quoted string"
                )
            )
        }

        private fun readTypographicQuotedString(): ValueResult {
            pos++ // consume opening U+201C
            val sb = StringBuilder()
            while (pos < len) {
                val ch = src[pos++]
                when (ch) {
                    '\u201D', '\u201C' -> return ValueResult(value = SlotValueAst.StringValue(sb.toString()))
                    '\n', '\r' -> return ValueResult(
                        error = MicroDslAst.ParseError(
                            rawFragment = remainingFragment(),
                            reason = "Unescaped line break inside quoted string"
                        )
                    )
                    else -> sb.append(ch)
                }
            }
            return ValueResult(
                error = MicroDslAst.ParseError(
                    rawFragment = src.take(ERROR_FRAGMENT_LIMIT),
                    reason = "Unterminated quoted string"
                )
            )
        }

        private fun readEscapeSequence(): String? {
            if (pos >= len) return null
            return when (val esc = src[pos++]) {
                '"' -> "\""
                '\\' -> "\\"
                'n' -> "\n"
                't' -> "\t"
                'r' -> "\r"
                'u' -> readUnicodeEscape()
                else -> null
            }
        }

        private fun readUnicodeEscape(): String? {
            val firstUnit = readHex4() ?: return null
            val firstChar = firstUnit.toChar()
            if (Character.isHighSurrogate(firstChar)) {
                if (pos + 6 <= len && src[pos] == '\\' && src[pos + 1] == 'u') {
                    pos += 2
                    val lowUnit = readHex4() ?: return null
                    val lowChar = lowUnit.toChar()
                    if (!Character.isLowSurrogate(lowChar)) return null
                    return String(charArrayOf(firstChar, lowChar))
                }
                return null
            }
            if (Character.isLowSurrogate(firstChar)) return null
            return firstChar.toString()
        }

        private fun readHex4(): Int? {
            if (pos + 4 > len) return null
            var result = 0
            for (i in 0 until 4) {
                val ch = src[pos++]
                val digit = when (ch) {
                    in '0'..'9' -> ch - '0'
                    in 'a'..'f' -> ch - 'a' + 10
                    in 'A'..'F' -> ch - 'A' + 10
                    else -> return null
                }
                result = (result shl 4) or digit
            }
            return result
        }

        private fun readInteger(): ValueResult {
            val start = pos
            if (src[pos] == '-') {
                pos++
                if (isEof() || src[pos] !in '0'..'9') {
                    return ValueResult(
                        error = MicroDslAst.ParseError(
                            rawFragment = remainingFragment(),
                            reason = "Malformed integer literal"
                        )
                    )
                }
            }
            while (pos < len && src[pos] in '0'..'9') {
                pos++
            }
            // Accept unquoted HH:MM time literals (e.g. time:12:34) emitted by small on-device models.
            if (pos < len && src[pos] == ':' && src[start] != '-') {
                val hourStr = src.substring(start, pos)
                val hourInt = hourStr.toIntOrNull()
                if (hourInt != null && hourInt in 0..23 && pos + 2 < len &&
                    src[pos + 1] in '0'..'9' && src[pos + 2] in '0'..'9'
                ) {
                    val minStart = pos + 1
                    val minEnd = pos + 3
                    if (minEnd == len || isValueDelimiter(src[minEnd])) {
                        val minInt = src.substring(minStart, minEnd).toIntOrNull()
                        if (minInt != null && minInt in 0..59) {
                            pos = minEnd
                            val canonicalTime = "${hourInt.toString().padStart(2, '0')}:${minInt.toString().padStart(2, '0')}"
                            return ValueResult(value = SlotValueAst.StringValue(canonicalTime))
                        }
                    }
                }
            }
            if (pos < len && !isValueDelimiter(src[pos])) {
                return ValueResult(
                    error = MicroDslAst.ParseError(
                        rawFragment = src.substring(start).take(ERROR_FRAGMENT_LIMIT),
                        reason = "Invalid numeric literal in MicroDsl argument"
                    )
                )
            }
            val raw = src.substring(start, pos)
            val parsed = raw.toLongOrNull() ?: return ValueResult(
                error = MicroDslAst.ParseError(
                    rawFragment = raw,
                    reason = "Integer literal out of Long range"
                )
            )
            return ValueResult(value = SlotValueAst.IntValue(parsed))
        }

        private fun readKeyword(keyword: String, ast: SlotValueAst): ValueResult {
            if (!src.startsWith(keyword, pos)) {
                return ValueResult(
                    error = MicroDslAst.ParseError(
                        rawFragment = remainingFragment(),
                        reason = "Unexpected literal; expected '$keyword'"
                    )
                )
            }
            val end = pos + keyword.length
            if (end < len && !isValueDelimiter(src[end])) {
                return ValueResult(
                    error = MicroDslAst.ParseError(
                        rawFragment = src.substring(pos).take(ERROR_FRAGMENT_LIMIT),
                        reason = "Unexpected suffix on literal '$keyword'"
                    )
                )
            }
            pos = end
            return ValueResult(value = ast)
        }

        private fun isValueDelimiter(ch: Char): Boolean {
            return ch == ',' || ch == '}' || ch.isWhitespace()
        }

        private fun isIdentifierStart(ch: Char): Boolean {
            return ch in 'a'..'z' || ch in 'A'..'Z' || ch == '_'
        }

        private fun isIdentifierPart(ch: Char): Boolean {
            return isIdentifierStart(ch) || ch in '0'..'9' || ch == '.' || ch == '-'
        }
    }

    private fun skipWhitespace(text: String, start: Int): Int {
        var idx = start
        while (idx < text.length && text[idx].isWhitespace()) {
            idx++
        }
        return idx
    }

    companion object {
        const val MAX_OUTPUT_CHARS: Int = 32_768
        const val MAX_CALLS_PER_PLAN: Int = 16
        const val MAX_ARGS_PER_CALL: Int = 32

        private const val ERROR_FRAGMENT_LIMIT: Int = 256
        private const val PARTIAL_TOOL_CALL_MARKER: String = "<|tool_call"
        private const val PARTIAL_FUNCTION_CALL_OPEN: String = "<start_function_call"
        private const val PARTIAL_FUNCTION_CALL_CLOSE: String = "<end_function_call"
        private const val PARTIAL_CHANNEL_MARKER: String = "<|channel"
        private val IDENTIFIER_REGEX: Regex = Regex("^[a-zA-Z_][a-zA-Z0-9_.-]*$")
        private val BARE_CALL_PREFIX_REGEX: Regex = Regex(
            """(?i)(?:^|[\s>])call\s*:\s*[a-zA-Z_][a-zA-Z0-9_.-]*\s*[\{\(]"""
        )
    }
}

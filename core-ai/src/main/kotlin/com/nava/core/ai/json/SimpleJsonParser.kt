package com.nava.core.ai.json

/**
 * Pure Kotlin, zero-dependency, depth- and size-bounded strict RFC 8259 JSON parser and compact
 * stringifier (Iron Law 2: zero external JSON libraries; JVM unit-testable without org.json stubs).
 */
sealed interface JsonValue {
    fun asObject(): Map<String, JsonValue> {
        throw IllegalArgumentException("Expected JSON object, got ${this::class.simpleName}")
    }

    fun asArray(): List<JsonValue> {
        throw IllegalArgumentException("Expected JSON array, got ${this::class.simpleName}")
    }

    fun asString(): String {
        throw IllegalArgumentException("Expected JSON string, got ${this::class.simpleName}")
    }

    fun asLong(): Long {
        throw IllegalArgumentException("Expected JSON integer number, got ${this::class.simpleName}")
    }

    fun asInt(): Int {
        val v = asLong()
        if (v < Int.MIN_VALUE || v > Int.MAX_VALUE) {
            throw IllegalArgumentException("JSON integer out of Int range: $v")
        }
        return v.toInt()
    }

    fun asDouble(): Double {
        throw IllegalArgumentException("Expected JSON number, got ${this::class.simpleName}")
    }

    fun asBoolean(): Boolean {
        throw IllegalArgumentException("Expected JSON boolean, got ${this::class.simpleName}")
    }

    data class JsonObject(val entries: Map<String, JsonValue>) : JsonValue {
        override fun asObject(): Map<String, JsonValue> = entries
    }

    data class JsonArray(val elements: List<JsonValue>) : JsonValue {
        override fun asArray(): List<JsonValue> = elements
    }

    data class JsonString(val value: String) : JsonValue {
        override fun asString(): String = value
    }

    data class JsonNumber(val raw: String) : JsonValue {
        override fun asLong(): Long {
            if ('.' in raw || 'e' in raw || 'E' in raw) {
                throw IllegalArgumentException("JSON number is not an integer: $raw")
            }
            return raw.toLongOrNull()
                ?: throw IllegalArgumentException("JSON integer out of Long range: $raw")
        }

        override fun asDouble(): Double {
            val parsed = raw.toDoubleOrNull()
                ?: throw IllegalArgumentException("Invalid JSON number: $raw")
            if (parsed.isNaN() || parsed.isInfinite()) {
                throw IllegalArgumentException("Non-finite JSON number: $raw")
            }
            return parsed
        }
    }

    data class JsonBoolean(val value: Boolean) : JsonValue {
        override fun asBoolean(): Boolean = value
    }

    data object JsonNull : JsonValue
}

object SimpleJsonParser {
    const val MAX_DEPTH: Int = 32
    const val MAX_INPUT_CHARS: Int = 512 * 1024

    /**
     * Parses [input] strictly according to RFC 8259 with bounded depth ([MAX_DEPTH]) and
     * bounded input size ([MAX_INPUT_CHARS]). Throws [IllegalArgumentException] on invalid JSON.
     */
    fun parse(input: String): JsonValue {
        if (input.length > MAX_INPUT_CHARS) {
            throw IllegalArgumentException(
                "JSON input length ${input.length} exceeds limit of $MAX_INPUT_CHARS characters"
            )
        }
        val reader = Reader(input)
        reader.skipWhitespace()
        if (reader.isEof()) {
            throw IllegalArgumentException("Empty JSON input")
        }
        val value = reader.parseValue(depth = 0)
        reader.skipWhitespace()
        if (!reader.isEof()) {
            throw IllegalArgumentException(
                "Unexpected trailing character '${reader.peek()}' at index ${reader.pos}"
            )
        }
        return value
    }

    /**
     * Serializes [value] into a compact, standards-compliant JSON string.
     */
    fun stringify(value: JsonValue): String {
        val sb = StringBuilder()
        writeValue(value, sb, depth = 0)
        return sb.toString()
    }

    private fun writeValue(value: JsonValue, sb: StringBuilder, depth: Int) {
        if (depth > MAX_DEPTH) {
            throw IllegalArgumentException("JSON serialization exceeded max depth $MAX_DEPTH")
        }
        when (value) {
            is JsonValue.JsonObject -> {
                sb.append('{')
                var first = true
                for ((k, v) in value.entries) {
                    if (!first) sb.append(',')
                    first = false
                    writeEscapedString(k, sb)
                    sb.append(':')
                    writeValue(v, sb, depth + 1)
                }
                sb.append('}')
            }

            is JsonValue.JsonArray -> {
                sb.append('[')
                for (i in value.elements.indices) {
                    if (i > 0) sb.append(',')
                    writeValue(value.elements[i], sb, depth + 1)
                }
                sb.append(']')
            }

            is JsonValue.JsonString -> writeEscapedString(value.value, sb)
            is JsonValue.JsonNumber -> sb.append(value.raw)
            is JsonValue.JsonBoolean -> sb.append(if (value.value) "true" else "false")
            JsonValue.JsonNull -> sb.append("null")
        }
    }

    private fun writeEscapedString(text: String, sb: StringBuilder) {
        sb.append('"')
        for (ch in text) {
            when (ch) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> {
                    if (ch.code < 0x20) {
                        sb.append("\\u")
                        val hex = ch.code.toString(16).padStart(4, '0')
                        sb.append(hex)
                    } else {
                        sb.append(ch)
                    }
                }
            }
        }
        sb.append('"')
    }

    private class Reader(private val src: String) {
        var pos: Int = 0
        private val len: Int = src.length

        fun isEof(): Boolean = pos >= len

        fun peek(): Char {
            if (isEof()) {
                throw IllegalArgumentException("Unexpected end of JSON input at index $pos")
            }
            return src[pos]
        }

        fun skipWhitespace() {
            while (pos < len) {
                when (src[pos]) {
                    ' ', '\t', '\n', '\r' -> pos++
                    else -> return
                }
            }
        }

        fun parseValue(depth: Int): JsonValue {
            if (depth > MAX_DEPTH) {
                throw IllegalArgumentException("JSON nesting depth exceeded maximum of $MAX_DEPTH")
            }
            skipWhitespace()
            return when (val ch = peek()) {
                '{' -> parseObject(depth + 1)
                '[' -> parseArray(depth + 1)
                '"' -> JsonValue.JsonString(parseString())
                't' -> parseLiteral("true", JsonValue.JsonBoolean(true))
                'f' -> parseLiteral("false", JsonValue.JsonBoolean(false))
                'n' -> parseLiteral("null", JsonValue.JsonNull)
                '-', in '0'..'9' -> parseNumber()
                else -> throw IllegalArgumentException("Unexpected token '$ch' at index $pos")
            }
        }

        private fun parseObject(nextDepth: Int): JsonValue.JsonObject {
            if (nextDepth > MAX_DEPTH) {
                throw IllegalArgumentException("JSON nesting depth exceeded maximum of $MAX_DEPTH")
            }
            pos++ // consume '{'
            skipWhitespace()
            val map = LinkedHashMap<String, JsonValue>()
            if (!isEof() && src[pos] == '}') {
                pos++
                return JsonValue.JsonObject(map)
            }
            while (true) {
                skipWhitespace()
                if (isEof() || src[pos] != '"') {
                    throw IllegalArgumentException("Expected string key in JSON object at index $pos")
                }
                val key = parseString()
                if (key in map) {
                    throw IllegalArgumentException("Duplicate JSON object key '$key' at index $pos")
                }
                skipWhitespace()
                if (isEof() || src[pos] != ':') {
                    throw IllegalArgumentException("Expected ':' after object key '$key' at index $pos")
                }
                pos++ // consume ':'
                val value = parseValue(nextDepth)
                map[key] = value
                skipWhitespace()
                if (isEof()) {
                    throw IllegalArgumentException("Unclosed JSON object at index $pos")
                }
                when (src[pos]) {
                    ',' -> pos++
                    '}' -> {
                        pos++
                        return JsonValue.JsonObject(map)
                    }

                    else -> throw IllegalArgumentException(
                        "Expected ',' or '}' in JSON object at index $pos"
                    )
                }
            }
        }

        private fun parseArray(nextDepth: Int): JsonValue.JsonArray {
            if (nextDepth > MAX_DEPTH) {
                throw IllegalArgumentException("JSON nesting depth exceeded maximum of $MAX_DEPTH")
            }
            pos++ // consume '['
            skipWhitespace()
            val list = ArrayList<JsonValue>()
            if (!isEof() && src[pos] == ']') {
                pos++
                return JsonValue.JsonArray(list)
            }
            while (true) {
                val elem = parseValue(nextDepth)
                list.add(elem)
                skipWhitespace()
                if (isEof()) {
                    throw IllegalArgumentException("Unclosed JSON array at index $pos")
                }
                when (src[pos]) {
                    ',' -> pos++
                    ']' -> {
                        pos++
                        return JsonValue.JsonArray(list)
                    }

                    else -> throw IllegalArgumentException(
                        "Expected ',' or ']' in JSON array at index $pos"
                    )
                }
            }
        }

        private fun parseString(): String {
            pos++ // consume opening '"'
            val sb = StringBuilder()
            while (pos < len) {
                val ch = src[pos++]
                when {
                    ch == '"' -> return sb.toString()
                    ch == '\\' -> sb.append(parseEscape())
                    ch.code < 0x20 -> throw IllegalArgumentException(
                        "Unescaped control character U+${ch.code.toString(16).padStart(4, '0')} in string at index ${pos - 1}"
                    )

                    Character.isHighSurrogate(ch) -> {
                        if (pos >= len || !Character.isLowSurrogate(src[pos])) {
                            throw IllegalArgumentException(
                                "Unpaired raw high surrogate in JSON string at index ${pos - 1}"
                            )
                        }
                        sb.append(ch)
                        sb.append(src[pos++])
                    }

                    Character.isLowSurrogate(ch) -> throw IllegalArgumentException(
                        "Unpaired raw low surrogate in JSON string at index ${pos - 1}"
                    )

                    else -> sb.append(ch)
                }
            }
            throw IllegalArgumentException("Unterminated JSON string")
        }

        private fun parseEscape(): String {
            if (pos >= len) {
                throw IllegalArgumentException("Unterminated escape sequence in JSON string")
            }
            return when (val esc = src[pos++]) {
                '"' -> "\""
                '\\' -> "\\"
                '/' -> "/"
                'b' -> "\b"
                'f' -> "\u000C"
                'n' -> "\n"
                'r' -> "\r"
                't' -> "\t"
                'u' -> parseUnicodeEscape()
                else -> throw IllegalArgumentException("Invalid escape sequence '\\$esc' at index ${pos - 1}")
            }
        }

        private fun parseUnicodeEscape(): String {
            val codeUnit = readHex4()
            val firstChar = codeUnit.toChar()
            if (Character.isHighSurrogate(firstChar)) {
                if (pos + 6 <= len && src[pos] == '\\' && src[pos + 1] == 'u') {
                    pos += 2
                    val lowUnit = readHex4()
                    val lowChar = lowUnit.toChar()
                    if (!Character.isLowSurrogate(lowChar)) {
                        throw IllegalArgumentException("Invalid low surrogate in JSON \\uXXXX pair at index $pos")
                    }
                    return String(charArrayOf(firstChar, lowChar))
                }
                throw IllegalArgumentException("Unpaired high surrogate in JSON string at index $pos")
            }
            if (Character.isLowSurrogate(firstChar)) {
                throw IllegalArgumentException("Unpaired low surrogate in JSON string at index $pos")
            }
            return firstChar.toString()
        }

        private fun readHex4(): Int {
            if (pos + 4 > len) {
                throw IllegalArgumentException("Truncated \\uXXXX escape at index $pos")
            }
            var result = 0
            for (i in 0 until 4) {
                val ch = src[pos++]
                val digit = when (ch) {
                    in '0'..'9' -> ch - '0'
                    in 'a'..'f' -> ch - 'a' + 10
                    in 'A'..'F' -> ch - 'A' + 10
                    else -> throw IllegalArgumentException(
                        "Invalid hex character '$ch' in \\uXXXX escape at index ${pos - 1}"
                    )
                }
                result = (result shl 4) or digit
            }
            return result
        }

        private fun parseNumber(): JsonValue.JsonNumber {
            val start = pos
            if (src[pos] == '-') {
                pos++
                if (isEof()) {
                    throw IllegalArgumentException("Malformed JSON number '-' at index $start")
                }
            }
            if (src[pos] == '0') {
                pos++
                if (!isEof() && src[pos] in '0'..'9') {
                    throw IllegalArgumentException("Leading zeros not allowed in JSON number at index $start")
                }
            } else if (src[pos] in '1'..'9') {
                while (pos < len && src[pos] in '0'..'9') {
                    pos++
                }
            } else {
                throw IllegalArgumentException("Invalid JSON number at index $start")
            }

            if (pos < len && src[pos] == '.') {
                pos++
                if (isEof() || src[pos] !in '0'..'9') {
                    throw IllegalArgumentException("Expected digit after decimal point at index $pos")
                }
                while (pos < len && src[pos] in '0'..'9') {
                    pos++
                }
            }

            if (pos < len && (src[pos] == 'e' || src[pos] == 'E')) {
                pos++
                if (pos < len && (src[pos] == '+' || src[pos] == '-')) {
                    pos++
                }
                if (isEof() || src[pos] !in '0'..'9') {
                    throw IllegalArgumentException("Expected digit in exponent at index $pos")
                }
                while (pos < len && src[pos] in '0'..'9') {
                    pos++
                }
            }

            val raw = src.substring(start, pos)
            return JsonValue.JsonNumber(raw)
        }

        private fun parseLiteral(expected: String, result: JsonValue): JsonValue {
            if (!src.startsWith(expected, pos)) {
                throw IllegalArgumentException("Expected '$expected' at index $pos")
            }
            pos += expected.length
            return result
        }
    }
}

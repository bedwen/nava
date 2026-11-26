package com.nava.domain.security

import java.text.Normalizer

/**
 * Pure Kotlin input sanitizer hardening untrusted and user inputs against Gemma 4 control-token
 * smuggling, Unicode fullwidth/homoglyph evasion, and bidi Trojan Source display spoofing.
 */
object Gemma4InputSanitizer {
    private const val MAX_SANITIZATION_PASSES = 256

    // Angle brackets and pipe lookalikes that NFKC does not fold to ASCII <, >, |.
    private const val OPEN = "(?:<|\u3008|\u27E8|\u2039)"
    private const val CLOSE = "(?:>|\u3009|\u27E9|\u203A)"
    private const val PIPE = "(?:\\||\u00A6|\u2223|\u2758|\u2502|\u2503)"
    private const val TOKEN_NAMES =
        "(?:turn|start_of_turn|end_of_turn|tool_call|tool_response|call|tool|channel|think|audio|eot|escape|image|video|file)"

    private val CONTROL_TOKEN_REGEX = Regex(
        pattern = buildString {
            append(OPEN).append(PIPE)
            append(TOKEN_NAMES)
            append(PIPE).append("?").append(CLOSE)
            append("|")
            append(OPEN)
            append(TOKEN_NAMES)
            append(PIPE).append(CLOSE)
            append("|")
            append(OPEN).append(PIPE).append("(?:\"|\\\\\")").append(PIPE).append(CLOSE)
            append("|")
            append(OPEN).append("(?:bos|eos|start_of_turn|end_of_turn|start_function_call|end_function_call|start_function_declaration|end_function_declaration|start_function_response|end_function_response|escape)").append(CLOSE)
        },
        option = RegexOption.IGNORE_CASE
    )

    /**
     * Strips invisible format characters, C0/C1 control characters (preserving tab, LF, CR),
     * Unicode line/paragraph separators, and invisible filler/joiner code points without altering
     * printable text.
     */
    fun stripInvisibleControls(text: String): String {
        if (text.isEmpty()) return text
        val sb = StringBuilder(text.length)
        var index = 0
        while (index < text.length) {
            val cp = text.codePointAt(index)
            if (!isInvisibleOrControl(cp)) {
                sb.appendCodePoint(cp)
            }
            index += Character.charCount(cp)
        }
        return sb.toString()
    }

    private fun isInvisibleOrControl(cp: Int): Boolean {
        if (cp == '\t'.code || cp == '\n'.code || cp == '\r'.code) {
            return false
        }
        if (
            cp in 0x200B..0x200F ||
            cp in 0x202A..0x202E ||
            cp in 0x2060..0x206F ||
            cp == 0xFEFF ||
            cp == 0x061C ||
            cp == 0x00AD ||
            cp == 0x034F ||
            cp == 0x180E ||
            cp == 0x115F ||
            cp == 0x1160 ||
            cp == 0x3164 ||
            cp == 0xFFA0
        ) {
            return true
        }
        return when (Character.getType(cp)) {
            Character.CONTROL.toInt(),
            Character.FORMAT.toInt(),
            Character.LINE_SEPARATOR.toInt(),
            Character.PARAGRAPH_SEPARATOR.toInt() -> true
            else -> false
        }
    }

    /**
     * Applies NFKC normalization, strips zero-width/bidi controls, and iteratively removes
     * Gemma 4 control tokens (including nested/smuggled sequences) until a fixed point is reached.
     *
     * Throws [SecurityException] if an adversarial input exceeds [MAX_SANITIZATION_PASSES].
     */
    fun sanitize(rawInput: String): String {
        if (rawInput.isEmpty()) return rawInput
        var current = Normalizer.normalize(rawInput, Normalizer.Form.NFKC)
        var pass = 0
        while (pass < MAX_SANITIZATION_PASSES) {
            val withoutInvisible = stripInvisibleControls(current)
            val cleaned = CONTROL_TOKEN_REGEX.replace(withoutInvisible, "")
            if (cleaned == current) {
                return cleaned
            }
            current = cleaned
            pass++
        }
        throw SecurityException("Input exceeded maximum control-token sanitization nesting depth")
    }

    /**
     * Sanitizes untrusted external content and wraps it in [Tainted] tagged with
     * [DataProvenance.UNTRUSTED_EXTERNAL].
     */
    fun sanitizeExternal(
        rawExternalInput: String,
        slotKind: SensitiveSlotKind? = null,
        sourceLabel: String? = null
    ): Tainted<String> {
        return Tainted.fromUntrustedExternal(
            value = sanitize(rawExternalInput),
            slotKind = slotKind,
            sourceLabel = sourceLabel
        )
    }
}

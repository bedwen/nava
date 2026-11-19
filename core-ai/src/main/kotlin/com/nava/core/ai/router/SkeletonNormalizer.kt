package com.nava.core.ai.router

import com.nava.domain.security.Gemma4InputSanitizer
import java.util.Locale

/**
 * Typed placeholder kinds extracted from normalized utterances for Tier 2 skeleton caching
 * (PLAN.md Section 3.1).
 */
enum class PlaceholderKind {
    TIME,
    DATE,
    INT,
    STR
}

/**
 * Single literal value extracted during skeleton normalization and mapped to a canonical token
 * (`$TIME_0`, `$DATE_0`, `$INT_0`, `$STR_0`).
 */
data class ExtractedPlaceholder(
    val token: String,
    val kind: PlaceholderKind,
    val rawValue: String
)

/**
 * Output of [SkeletonNormalizer]: a canonical parameterized skeleton string paired with its
 * extracted literal placeholders in deterministic order.
 */
data class NormalizedSkeleton(
    val canonicalSkeleton: String,
    val placeholders: Map<String, ExtractedPlaceholder>
)

/**
 * Single-pass, language-agnostic literal extractor replacing times (`HH:MM`, `7h30`),
 * ISO dates (`YYYY-MM-DD`), quoted strings (`"..."`), and standalone integers with ordered
 * placeholders (`$TIME_0`, `$DATE_0`, `$INT_0`, `$STR_0`) for Tier 2 HMAC-SHA256 cache lookup.
 *
 * Uses an iterative O(n) character scanner (O(1) stack depth) for quoted strings so arbitrarily
 * long or heavily escaped inputs can never trigger JVM regex `StackOverflowError`.
 */
class SkeletonNormalizer {

    fun normalize(
        matchKey: String,
        originalUtterance: String? = null
    ): NormalizedSkeleton {
        val trimmed = matchKey.trim()
        if (trimmed.isEmpty()) {
            return NormalizedSkeleton(canonicalSkeleton = "", placeholders = emptyMap())
        }

        val originalQuotedStrings = if (originalUtterance != null) {
            extractQuotedStringsIterative(originalUtterance)
        } else {
            emptyList()
        }

        var timeIdx = 0
        var dateIdx = 0
        var intIdx = 0
        var strIdx = 0
        val placeholders = LinkedHashMap<String, ExtractedPlaceholder>()
        val strTokens = ArrayList<String>()

        val sb = StringBuilder(trimmed.length)
        var pos = 0
        val len = trimmed.length

        while (pos < len) {
            val quoteStart = trimmed.indexOf('"', pos)
            val segEnd = if (quoteStart < 0) len else quoteStart

            if (segEnd > pos) {
                val segment = trimmed.substring(pos, segEnd)
                var segLastEnd = 0
                for (match in NON_QUOTED_LITERAL_REGEX.findAll(segment)) {
                    sb.append(segment, segLastEnd, match.range.first)

                    val dateGroup = match.groups[GROUP_DATE]
                    val timeGroup = match.groups[GROUP_TIME]
                    val intGroup = match.groups[GROUP_INT]

                    val extracted = when {
                        dateGroup != null -> {
                            val token = "\$DATE_${dateIdx++}"
                            ExtractedPlaceholder(
                                token = token,
                                kind = PlaceholderKind.DATE,
                                rawValue = dateGroup.value
                            )
                        }

                        timeGroup != null -> {
                            val token = "\$TIME_${timeIdx++}"
                            val canonicalTime = canonicalizeTimeLiteral(timeGroup.value)
                            ExtractedPlaceholder(
                                token = token,
                                kind = PlaceholderKind.TIME,
                                rawValue = canonicalTime
                            )
                        }

                        intGroup != null -> {
                            val token = "\$INT_${intIdx++}"
                            ExtractedPlaceholder(
                                token = token,
                                kind = PlaceholderKind.INT,
                                rawValue = intGroup.value
                            )
                        }

                        else -> null
                    }

                    if (extracted != null) {
                        placeholders[extracted.token] = extracted
                        sb.append(extracted.token)
                    } else {
                        sb.append(match.value)
                    }
                    segLastEnd = match.range.last + 1
                }
                sb.append(segment, segLastEnd, segment.length)
            }

            if (quoteStart < 0) break

            val quoteEnd = findClosingDoubleQuoteIterative(trimmed, quoteStart)
            if (quoteEnd < 0) {
                sb.append('"')
                pos = quoteStart + 1
            } else {
                val token = "\$STR_${strIdx++}"
                strTokens.add(token)
                val unquoted = unquoteDoubleQuoted(trimmed.substring(quoteStart, quoteEnd + 1))
                val extracted = ExtractedPlaceholder(
                    token = token,
                    kind = PlaceholderKind.STR,
                    rawValue = unquoted
                )
                placeholders[token] = extracted
                sb.append(token)
                pos = quoteEnd + 1
            }
        }

        if (originalUtterance != null && strTokens.isNotEmpty() && originalQuotedStrings.size == strTokens.size) {
            for (i in strTokens.indices) {
                val token = strTokens[i]
                val sanitizedOriginal = try {
                    Gemma4InputSanitizer.sanitize(originalQuotedStrings[i])
                } catch (_: SecurityException) {
                    null
                }
                if (sanitizedOriginal != null) {
                    placeholders[token] = ExtractedPlaceholder(
                        token = token,
                        kind = PlaceholderKind.STR,
                        rawValue = sanitizedOriginal
                    )
                }
            }
        }

        val collapsed = WHITESPACE_REGEX.replace(sb.toString().trim(), " ")
        return NormalizedSkeleton(
            canonicalSkeleton = collapsed,
            placeholders = placeholders
        )
    }

    private fun extractQuotedStringsIterative(text: String): List<String> {
        val result = ArrayList<String>()
        var pos = 0
        val len = text.length
        while (pos < len) {
            val start = text.indexOf('"', pos)
            if (start < 0) break
            val end = findClosingDoubleQuoteIterative(text, start)
            if (end < 0) {
                pos = start + 1
            } else {
                result.add(unquoteDoubleQuoted(text.substring(start, end + 1)))
                pos = end + 1
            }
        }
        return result
    }

    private fun findClosingDoubleQuoteIterative(text: String, openIndex: Int): Int {
        var i = openIndex + 1
        val len = text.length
        while (i < len) {
            val ch = text[i]
            if (ch == '\\') {
                i += 2
            } else if (ch == '"') {
                return i
            } else {
                i++
            }
        }
        return -1
    }

    private fun canonicalizeTimeLiteral(raw: String): String {
        val match = TIME_PARTS_REGEX.matchEntire(raw) ?: return raw
        val hour = match.groupValues[1].toIntOrNull() ?: return raw
        val minute = match.groupValues[2].toIntOrNull() ?: return raw
        if (hour !in 0..23 || minute !in 0..59) return raw
        return String.format(Locale.US, "%02d:%02d", hour, minute)
    }

    private fun unquoteDoubleQuoted(quoted: String): String {
        if (quoted.length < 2) return quoted
        val inner = quoted.substring(1, quoted.length - 1)
        val sb = StringBuilder(inner.length)
        var i = 0
        while (i < inner.length) {
            val ch = inner[i]
            if (ch == '\\' && i + 1 < inner.length) {
                val next = inner[i + 1]
                when (next) {
                    '"', '\\' -> {
                        sb.append(next)
                        i += 2
                    }

                    else -> {
                        sb.append(ch)
                        i++
                    }
                }
            } else {
                sb.append(ch)
                i++
            }
        }
        return sb.toString()
    }

    companion object {
        private const val GROUP_DATE: Int = 1
        private const val GROUP_TIME: Int = 2
        private const val GROUP_INT: Int = 3

        // Flat alternation without nested quantifiers: linear time and O(1) stack depth.
        private val NON_QUOTED_LITERAL_REGEX: Regex = Regex(
            """((?<!\d)\d{4}-\d{2}-\d{2}(?!\d))|((?<!\d)\d{1,2}[:hH]\d{2}(?!\d))|((?<![\p{L}\d_])\d+(?![\p{L}\d_]))"""
        )
        private val TIME_PARTS_REGEX: Regex = Regex("""^(\d{1,2})[:hH](\d{2})$""")
        private val WHITESPACE_REGEX: Regex = Regex("""\s+""")
    }
}

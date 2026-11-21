package com.nava.app.locale

import android.icu.util.ULocale
import androidx.core.text.BidiFormatter
import androidx.core.text.TextDirectionHeuristicsCompat
import com.nava.domain.security.Gemma4InputSanitizer
import java.util.Locale

/**
 * Hardened bidirectional text formatter for Nava's UI, Action Confirmation Cards, and
 * Dual-Core Neural Canvas labels (PLAN.md Sections 6.4 & 6.6).
 *
 * Security & localization invariants:
 * - Always calls [Gemma4InputSanitizer.stripInvisibleControls] first to strip any attacker-supplied
 *   Unicode bidi override/isolate controls (`U+202A-U+202E`, `U+2066-U+2069`) and zero-width characters
 *   ("Trojan Source" defense).
 * - Wraps sanitized strings via [BidiFormatter] (`androidx.core.text`) with a deterministic pure-JVM
 *   fallback so mixed-direction text (such as phone numbers, timestamps, and package names inside
 *   RTL Arabic/Hebrew/Persian/Urdu screens) renders safely.
 * - Derives RTL context from the active [Locale]'s script directionality without any hardcoded
 *   language list (Iron Law 1).
 */
class BidiTextFormatter(
    private val useAndroidxBidiFormatter: Boolean = true
) {

    /**
     * Strips invisible/bidi override controls from [rawText] and wraps it for safe rendering in
     * a context whose base direction is determined by [isRtlContext].
     */
    fun wrapText(
        rawText: String,
        isRtlContext: Boolean = false
    ): String {
        val cleaned = Gemma4InputSanitizer.stripInvisibleControls(rawText)
        if (cleaned.isEmpty()) return cleaned
        return wrapWithFirstStrongHeuristic(cleaned, isRtlContext)
    }

    /**
     * Strips invisible/bidi override controls from [rawText] and wraps it for safe rendering in [locale].
     */
    fun wrapText(
        rawText: String,
        locale: Locale
    ): String {
        return wrapText(
            rawText = rawText,
            isRtlContext = isRtlLocale(locale)
        )
    }

    /**
     * Strips invisible/bidi override controls from a canonical LTR token (such as a phone number
     * `+1 555-0199`, ISO-8601 timestamp `07:30`, URI, or package identifier) and wraps it with
     * explicit LTR directionality so signs and digits never invert inside RTL sentences.
     */
    fun wrapLtrToken(
        rawToken: String,
        isRtlContext: Boolean = false
    ): String {
        val cleaned = Gemma4InputSanitizer.stripInvisibleControls(rawToken)
        if (cleaned.isEmpty()) return cleaned
        return wrapWithExplicitLtrHeuristic(cleaned, isRtlContext)
    }

    /**
     * Strips invisible/bidi override controls from a canonical LTR token and wraps it for [locale].
     */
    fun wrapLtrToken(
        rawToken: String,
        locale: Locale
    ): String {
        return wrapLtrToken(
            rawToken = rawToken,
            isRtlContext = isRtlLocale(locale)
        )
    }

    /**
     * Full sanitization helper that strips both invisible/bidi controls and Gemma 4 control tokens
     * before applying bidi wrapping.
     */
    fun sanitizeAndWrap(
        rawText: String,
        isRtlContext: Boolean = false
    ): String {
        val sanitized = Gemma4InputSanitizer.sanitize(rawText)
        if (sanitized.isEmpty()) return sanitized
        return wrapWithFirstStrongHeuristic(sanitized, isRtlContext)
    }

    private fun wrapWithFirstStrongHeuristic(
        cleaned: String,
        isRtlContext: Boolean
    ): String {
        if (useAndroidxBidiFormatter) {
            val wrapped = runCatching {
                BidiFormatter.getInstance(isRtlContext)
                    .unicodeWrap(cleaned, TextDirectionHeuristicsCompat.FIRSTSTRONG_LTR, true)
            }.getOrNull()
            if (wrapped != null) {
                return wrapped
            }
        }
        return pureJvmWrap(
            cleaned = cleaned,
            isRtlContext = isRtlContext,
            forceLtrContent = false
        )
    }

    private fun wrapWithExplicitLtrHeuristic(
        cleaned: String,
        isRtlContext: Boolean
    ): String {
        if (useAndroidxBidiFormatter) {
            val wrapped = runCatching {
                BidiFormatter.getInstance(isRtlContext)
                    .unicodeWrap(cleaned, TextDirectionHeuristicsCompat.LTR, true)
            }.getOrNull()
            if (wrapped != null) {
                return wrapped
            }
        }
        return pureJvmWrap(
            cleaned = cleaned,
            isRtlContext = isRtlContext,
            forceLtrContent = true
        )
    }

    companion object {
        const val LRM: Char = '\u200E'
        const val RLM: Char = '\u200F'
        const val LRE: Char = '\u202A'
        const val RLE: Char = '\u202B'
        const val PDF: Char = '\u202C'

        /**
         * Determines whether [locale] is Right-to-Left directly from ICU / Unicode character
         * directionality of the locale's native script without any hardcoded language list.
         */
        fun isRtlLocale(locale: Locale): Boolean {
            val icuResult = runCatching {
                ULocale.forLocale(locale).isRightToLeft
            }.getOrNull()
            if (icuResult != null) {
                return icuResult
            }
            val nativeDisplay = buildString {
                append(locale.getDisplayScript(locale))
                append(' ')
                append(locale.getDisplayLanguage(locale))
            }
            return detectFirstStrongRtl(nativeDisplay)
        }

        /**
         * Returns true if the first strong directional character in [text] is RTL.
         */
        internal fun detectFirstStrongRtl(text: String): Boolean {
            var index = 0
            while (index < text.length) {
                val cp = text.codePointAt(index)
                when (Character.getDirectionality(cp)) {
                    Character.DIRECTIONALITY_RIGHT_TO_LEFT,
                    Character.DIRECTIONALITY_RIGHT_TO_LEFT_ARABIC -> return true

                    Character.DIRECTIONALITY_LEFT_TO_RIGHT -> return false
                }
                index += Character.charCount(cp)
            }
            return false
        }

        private fun hasAnyWeakOrOppositeChar(text: String, isContentRtl: Boolean): Boolean {
            var index = 0
            while (index < text.length) {
                val cp = text.codePointAt(index)
                when (Character.getDirectionality(cp)) {
                    Character.DIRECTIONALITY_RIGHT_TO_LEFT,
                    Character.DIRECTIONALITY_RIGHT_TO_LEFT_ARABIC -> if (!isContentRtl) return true

                    Character.DIRECTIONALITY_LEFT_TO_RIGHT -> if (isContentRtl) return true
                    Character.DIRECTIONALITY_EUROPEAN_NUMBER,
                    Character.DIRECTIONALITY_ARABIC_NUMBER,
                    Character.DIRECTIONALITY_EUROPEAN_NUMBER_SEPARATOR,
                    Character.DIRECTIONALITY_EUROPEAN_NUMBER_TERMINATOR -> return true
                }
                index += Character.charCount(cp)
            }
            return false
        }

        internal fun pureJvmWrap(
            cleaned: String,
            isRtlContext: Boolean,
            forceLtrContent: Boolean
        ): String {
            if (cleaned.isEmpty()) return cleaned
            val isContentRtl = if (forceLtrContent) false else detectFirstStrongRtl(cleaned)
            val needsWrap = (isContentRtl != isRtlContext) ||
                forceLtrContent && isRtlContext ||
                hasAnyWeakOrOppositeChar(cleaned, isContentRtl)
            if (!needsWrap) return cleaned

            val embeddingPrefix = if (isContentRtl) RLE else LRE
            val trailingMark = if (isRtlContext) RLM else LRM
            return buildString(cleaned.length + 3) {
                append(embeddingPrefix)
                append(cleaned)
                append(PDF)
                append(trailingMark)
            }
        }
    }
}

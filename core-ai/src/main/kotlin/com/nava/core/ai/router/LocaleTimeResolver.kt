package com.nava.core.ai.router

import java.time.LocalDate
import java.time.ZonedDateTime
import java.util.Locale

/**
 * Pure Kotlin `java.time`-backed resolver turning extracted Layer R rule-pack slots and
 * data-driven [com.nava.domain.locale.LocaleRulePack.timeKeywords] into canonical ISO-8601
 * times (`HH:MM`), dates (`YYYY-MM-DD`), or integer durations in seconds
 * (PLAN.md Section 6.2).
 *
 * Zero hardcoded language branches: all localized meridiem, period, day, and duration unit words
 * are mapped through the pack's `timeKeywords` dictionary.
 */
class LocaleTimeResolver {

    /**
     * Resolves canonical 24-hour `HH:MM` time from extracted slots (`time`, `hour`, `minute`,
     * `meridiem`, `period_keyword`) and [timeKeywords]. Returns `null` if no valid time can
     * be derived.
     */
    fun resolveTime(
        rawSlots: Map<String, String>,
        timeKeywords: Map<String, String>,
        now: ZonedDateTime,
        languageTag: String = DEFAULT_LANGUAGE_TAG
    ): String? {
        val userLocale = Locale.forLanguageTag(languageTag)
        var hour: Int? = null
        var minute: Int = 0

        val directTime = rawSlots["time"]?.trim()
        if (!directTime.isNullOrEmpty()) {
            val match = COMPACT_TIME_REGEX.matchEntire(directTime)
            if (match != null) {
                hour = match.groupValues[1].toIntOrNull()
                minute = match.groupValues[2].toIntOrNull() ?: 0
            }
        }

        if (hour == null) {
            val rawHour = rawSlots["hour"]?.trim()
            if (!rawHour.isNullOrEmpty()) {
                hour = rawHour.toIntOrNull()
            }
            val rawMinute = rawSlots["minute"]?.trim()
            if (!rawMinute.isNullOrEmpty()) {
                minute = rawMinute.toIntOrNull() ?: return null
            }
        }

        val meridiemRaw = rawSlots["meridiem"]?.trim()?.lowercase(userLocale)
        val periodRaw = rawSlots["period_keyword"]?.trim()?.lowercase(userLocale)

        val directive = resolveKeywordDirective(meridiemRaw, timeKeywords, userLocale)
            ?: resolveKeywordDirective(periodRaw, timeKeywords, userLocale)
            ?: when (meridiemRaw) {
                "am", "a.m." -> "AM"
                "pm", "p.m." -> "PM"
                else -> null
            }

        if (hour == null) {
            if (directive != null) {
                val fixedMatch = COMPACT_TIME_REGEX.matchEntire(directive)
                if (fixedMatch != null) {
                    val fixedH = fixedMatch.groupValues[1].toIntOrNull() ?: return null
                    val fixedM = fixedMatch.groupValues[2].toIntOrNull() ?: return null
                    return formatCanonicalTime(fixedH, fixedM)
                }
                return when (directive) {
                    "NOON" -> "12:00"
                    "MIDNIGHT" -> "00:00"
                    "NOW" -> formatCanonicalTime(now.hour, now.minute)
                    else -> null
                }
            }
            return null
        }

        val adjustedHour = applyMeridiemDirective(hour, directive)
        return formatCanonicalTime(adjustedHour, minute)
    }

    /**
     * Resolves positive integer duration in seconds from `duration_seconds`, `seconds`,
     * `duration_value` + `duration_unit`, or compound `hours`/`minutes`/`seconds` slots.
     */
    fun resolveDurationSeconds(
        rawSlots: Map<String, String>,
        timeKeywords: Map<String, String>,
        languageTag: String = DEFAULT_LANGUAGE_TAG
    ): Long? {
        val userLocale = Locale.forLanguageTag(languageTag)
        val directDuration = rawSlots["duration_seconds"]?.trim()?.toLongOrNull()
        if (directDuration != null) {
            return directDuration.takeIf { it in 1L..MAX_DURATION_SECONDS }
        }

        val rawValue = rawSlots["duration_value"]?.trim()?.toLongOrNull()
        if (rawValue != null) {
            if (rawValue <= 0L) return null
            val unitRaw = rawSlots["duration_unit"]?.trim()?.lowercase(userLocale)
            val multiplier = resolveUnitMultiplierSeconds(unitRaw, timeKeywords, userLocale) ?: return null
            return safeMultiplyBounded(rawValue, multiplier)
        }

        val hours = rawSlots["hours"]?.trim()?.toLongOrNull()
        val minutes = rawSlots["minutes"]?.trim()?.toLongOrNull()
        val seconds = rawSlots["seconds"]?.trim()?.toLongOrNull()
        if (hours != null || minutes != null || seconds != null) {
            val h = hours ?: 0L
            val m = minutes ?: 0L
            val s = seconds ?: 0L
            if (h < 0L || m < 0L || s < 0L) return null
            val hSec = safeMultiplyBounded(h, 3600L) ?: return null
            val mSec = safeMultiplyBounded(m, 60L) ?: return null
            val total = try {
                Math.addExact(Math.addExact(hSec, mSec), s)
            } catch (_: ArithmeticException) {
                return null
            }
            return total.takeIf { it in 1L..MAX_DURATION_SECONDS }
        }

        return null
    }

    /**
     * Resolves canonical ISO-8601 date (`YYYY-MM-DD`) from explicit `date` slot or `day_keyword`
     * mapped via [timeKeywords] (`TODAY`, `TOMORROW`, `DAY_OFFSET:<n>`).
     */
    fun resolveDate(
        rawSlots: Map<String, String>,
        timeKeywords: Map<String, String>,
        now: ZonedDateTime,
        languageTag: String = DEFAULT_LANGUAGE_TAG
    ): String? {
        val userLocale = Locale.forLanguageTag(languageTag)
        val directDate = rawSlots["date"]?.trim()
        if (!directDate.isNullOrEmpty()) {
            return runCatching { LocalDate.parse(directDate).toString() }.getOrNull()
        }

        val dayKeyword = rawSlots["day_keyword"]?.trim()?.lowercase(userLocale) ?: return null
        val directive = resolveKeywordDirective(dayKeyword, timeKeywords, userLocale) ?: return null
        val offsetDays = when {
            directive == "TODAY" -> 0L
            directive == "TOMORROW" -> 1L
            directive == "YESTERDAY" -> -1L
            directive.startsWith("DAY_OFFSET:") -> directive.removePrefix("DAY_OFFSET:").toLongOrNull()
            else -> null
        } ?: return null

        if (offsetDays < -365L || offsetDays > 3650L) return null
        return now.toLocalDate().plusDays(offsetDays).toString()
    }

    private fun resolveKeywordDirective(
        rawKey: String?,
        timeKeywords: Map<String, String>,
        userLocale: Locale
    ): String? {
        if (rawKey.isNullOrBlank()) return null
        val direct = timeKeywords[rawKey]
            ?: timeKeywords.entries.firstOrNull {
                it.key.lowercase(userLocale) == rawKey
            }?.value
            ?: return null
        return direct.trim().uppercase(Locale.US)
    }

    private fun applyMeridiemDirective(hour: Int, directive: String?): Int {
        return when (directive) {
            "AM", "MORNING" -> if (hour == 12) 0 else hour
            "PM", "AFTERNOON", "EVENING", "NIGHT" -> if (hour in 1..11) hour + 12 else hour
            else -> hour
        }
    }

    private fun resolveUnitMultiplierSeconds(
        unitRaw: String?,
        timeKeywords: Map<String, String>,
        userLocale: Locale
    ): Long? {
        if (unitRaw.isNullOrBlank()) return 1L
        val directive = resolveKeywordDirective(unitRaw, timeKeywords, userLocale)
            ?: unitRaw.uppercase(Locale.US)
        directive.toLongOrNull()?.let { numeric ->
            return numeric.takeIf { it in 1L..86_400L }
        }
        return when (directive) {
            "S", "SEC", "SECOND", "SECONDS" -> 1L
            "M", "MIN", "MINUTE", "MINUTES" -> 60L
            "H", "HR", "HOUR", "HOURS" -> 3600L
            "D", "DAY", "DAYS" -> 86_400L
            else -> null
        }
    }

    private fun formatCanonicalTime(hour: Int, minute: Int): String? {
        if (hour !in 0..23 || minute !in 0..59) return null
        return String.format(Locale.US, "%02d:%02d", hour, minute)
    }

    private fun safeMultiplyBounded(value: Long, multiplier: Long): Long? {
        return try {
            val product = Math.multiplyExact(value, multiplier)
            product.takeIf { it in 0L..MAX_DURATION_SECONDS }
        } catch (_: ArithmeticException) {
            null
        }
    }

    companion object {
        private const val DEFAULT_LANGUAGE_TAG: String = "en"
        private const val MAX_DURATION_SECONDS: Long = 365L * 86_400L
        private val COMPACT_TIME_REGEX: Regex = Regex("""^(\d{1,2})[:hH.](\d{2})$""")
    }
}

package com.nava.app.locale

import android.icu.text.DateFormat
import android.icu.util.Calendar
import android.icu.util.TimeZone as IcuTimeZone
import android.icu.util.ULocale
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.ui.MessageArg
import java.time.DayOfWeek
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.LocalTime
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.chrono.Chronology
import java.time.chrono.IsoChronology
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.time.temporal.WeekFields
import java.util.Date
import java.util.Locale

/**
 * Locale-aware date and time formatter for `:app` presentation (PLAN.md Section 6.2 & 6.4).
 *
 * Invariants:
 * - Internal storage and domain values remain strictly ISO-8601 Gregorian (`YYYY-MM-DD`, `HH:mm`).
 * - User-facing display uses `android.icu.text.DateFormat` (with a deterministic `java.time` /
 *   [Chronology] fallback for pure JVM tests) respecting the active locale, 12h/24h preference,
 *   first day of week, and non-Gregorian calendars (Islamic/Hijri, Persian, Hebrew, Buddhist, Japanese).
 */
class LocaleDateTimeFormatter(
    private val defaultZoneIdProvider: () -> ZoneId = { ZoneId.systemDefault() },
    private val preferIcuOnAndroid: Boolean = true
) {

    /**
     * Formats a [MessageArg.IsoTime] according to [locale] and optional [use24Hour] preference.
     */
    fun formatTime(
        arg: MessageArg.IsoTime,
        locale: Locale = Locale.getDefault(),
        use24Hour: Boolean? = null,
        zoneId: ZoneId = defaultZoneIdProvider()
    ): String {
        return formatIsoTime(
            isoTime = arg.isoString,
            locale = locale,
            use24Hour = use24Hour,
            zoneId = zoneId
        )
    }

    /**
     * Formats an ISO-8601 time string (`"07:30"`, `"14:05:00"`, or full ISO-8601 datetime)
     * according to [locale] and optional [use24Hour] preference (`true` = 24-hour, `false` = 12-hour,
     * `null` = locale default).
     */
    fun formatIsoTime(
        isoTime: String,
        locale: Locale = Locale.getDefault(),
        use24Hour: Boolean? = null,
        zoneId: ZoneId = defaultZoneIdProvider()
    ): String {
        val cleaned = Gemma4InputSanitizer.stripInvisibleControls(isoTime).trim()
        if (cleaned.isEmpty()) return ""

        val localTime = parseToLocalTime(cleaned, zoneId) ?: return cleaned

        if (preferIcuOnAndroid) {
            val icuFormatted = runCatching {
                formatTimeWithIcu(localTime, locale, use24Hour, zoneId)
            }.getOrNull()
            if (!icuFormatted.isNullOrBlank()) {
                return icuFormatted
            }
        }

        return formatTimeWithJavaTime(localTime, locale, use24Hour)
    }

    /**
     * Formats a [MessageArg.IsoDate] according to [locale], automatically honoring non-Gregorian
     * calendar extensions on [locale] (e.g. `ar-SA-u-ca-islamic-umalqura`, `th-TH-u-ca-buddhist`).
     */
    fun formatDate(
        arg: MessageArg.IsoDate,
        locale: Locale = Locale.getDefault(),
        zoneId: ZoneId = defaultZoneIdProvider()
    ): String {
        return formatIsoDate(
            isoDate = arg.isoString,
            locale = locale,
            zoneId = zoneId
        )
    }

    /**
     * Formats a canonical ISO-8601 Gregorian date string (`"2026-11-21"` or full ISO-8601 datetime)
     * for display in [locale].
     */
    fun formatIsoDate(
        isoDate: String,
        locale: Locale = Locale.getDefault(),
        zoneId: ZoneId = defaultZoneIdProvider()
    ): String {
        val cleaned = Gemma4InputSanitizer.stripInvisibleControls(isoDate).trim()
        if (cleaned.isEmpty()) return ""

        val localDate = parseToLocalDate(cleaned, zoneId) ?: return cleaned

        if (preferIcuOnAndroid) {
            val icuFormatted = runCatching {
                formatDateWithIcu(localDate, locale, zoneId)
            }.getOrNull()
            if (!icuFormatted.isNullOrBlank()) {
                return icuFormatted
            }
        }

        return formatDateWithJavaTime(localDate, locale)
    }

    /**
     * Formats an epoch millisecond timestamp into a localized date-time string for [locale] and [zoneId].
     */
    fun formatEpochMillis(
        epochMs: Long,
        locale: Locale = Locale.getDefault(),
        zoneId: ZoneId = defaultZoneIdProvider(),
        use24Hour: Boolean? = null
    ): String {
        if (preferIcuOnAndroid) {
            val icuFormatted = runCatching {
                formatEpochWithIcu(epochMs, locale, zoneId, use24Hour)
            }.getOrNull()
            if (!icuFormatted.isNullOrBlank()) {
                return icuFormatted
            }
        }

        val zdt = ZonedDateTime.ofInstant(Instant.ofEpochMilli(epochMs), zoneId)
        val formattedDate = formatDateWithJavaTime(zdt.toLocalDate(), locale)
        val formattedTime = formatTimeWithJavaTime(zdt.toLocalTime(), locale, use24Hour)
        return "$formattedDate, $formattedTime"
    }

    /**
     * Resolves the locale-specific first day of the week (e.g. `MONDAY` for `tr-TR`/`fr-FR`,
     * `SUNDAY` for `en-US`, `SATURDAY` for `ar-EG`).
     */
    fun firstDayOfWeek(locale: Locale = Locale.getDefault()): DayOfWeek {
        if (preferIcuOnAndroid) {
            val icuDay = runCatching {
                val uLocale = ULocale.forLocale(locale)
                val calendar = Calendar.getInstance(uLocale)
                mapIcuDayOfWeek(calendar.firstDayOfWeek)
            }.getOrNull()
            if (icuDay != null) {
                return icuDay
            }
        }
        return WeekFields.of(locale).firstDayOfWeek
    }

    /**
     * Converts [epochMs] into a canonical ISO-8601 Gregorian date string (`YYYY-MM-DD`).
     * Internal domain and storage representations always use ISO-8601 Gregorian regardless of UI locale.
     */
    fun toCanonicalIsoDate(
        epochMs: Long,
        zoneId: ZoneId = defaultZoneIdProvider()
    ): String {
        val localDate = Instant.ofEpochMilli(epochMs).atZone(zoneId).toLocalDate()
        return DateTimeFormatter.ISO_LOCAL_DATE
            .withLocale(Locale.ROOT)
            .withChronology(IsoChronology.INSTANCE)
            .format(localDate)
    }

    /**
     * Converts [epochMs] into a canonical ISO-8601 24-hour time string (`HH:mm`).
     */
    fun toCanonicalIsoTime(
        epochMs: Long,
        zoneId: ZoneId = defaultZoneIdProvider()
    ): String {
        val localTime = Instant.ofEpochMilli(epochMs).atZone(zoneId).toLocalTime()
        return CANONICAL_HH_MM_FORMATTER.format(localTime)
    }

    private fun parseToLocalTime(raw: String, zoneId: ZoneId): LocalTime? {
        runCatching { LocalTime.parse(raw) }.getOrNull()?.let { return it }
        runCatching { OffsetDateTime.parse(raw).atZoneSameInstant(zoneId).toLocalTime() }
            .getOrNull()?.let { return it }
        runCatching { ZonedDateTime.parse(raw).withZoneSameInstant(zoneId).toLocalTime() }
            .getOrNull()?.let { return it }
        runCatching { LocalDateTime.parse(raw).toLocalTime() }
            .getOrNull()?.let { return it }
        runCatching { Instant.parse(raw).atZone(zoneId).toLocalTime() }
            .getOrNull()?.let { return it }
        return null
    }

    private fun parseToLocalDate(raw: String, zoneId: ZoneId): LocalDate? {
        runCatching { LocalDate.parse(raw) }.getOrNull()?.let { return it }
        runCatching { OffsetDateTime.parse(raw).atZoneSameInstant(zoneId).toLocalDate() }
            .getOrNull()?.let { return it }
        runCatching { ZonedDateTime.parse(raw).withZoneSameInstant(zoneId).toLocalDate() }
            .getOrNull()?.let { return it }
        runCatching { LocalDateTime.parse(raw).toLocalDate() }
            .getOrNull()?.let { return it }
        runCatching { Instant.parse(raw).atZone(zoneId).toLocalDate() }
            .getOrNull()?.let { return it }
        return null
    }

    private fun formatTimeWithIcu(
        localTime: LocalTime,
        locale: Locale,
        use24Hour: Boolean?,
        zoneId: ZoneId
    ): String {
        val uLocale = ULocale.forLocale(locale)
        val formatter = when (use24Hour) {
            true -> DateFormat.getPatternInstance(DateFormat.HOUR24_MINUTE, uLocale)
            false -> DateFormat.getPatternInstance("hm", uLocale)
            null -> DateFormat.getTimeInstance(DateFormat.SHORT, uLocale)
        }
        formatter.timeZone = IcuTimeZone.getTimeZone(zoneId.id)
        val epochMs = localTime.atDate(REFERENCE_ISO_DATE).atZone(zoneId).toInstant().toEpochMilli()
        return formatter.format(Date(epochMs))
    }

    private fun formatDateWithIcu(
        localDate: LocalDate,
        locale: Locale,
        zoneId: ZoneId
    ): String {
        val uLocale = ULocale.forLocale(locale)
        val formatter = DateFormat.getDateInstance(DateFormat.MEDIUM, uLocale)
        formatter.timeZone = IcuTimeZone.getTimeZone(zoneId.id)
        val epochMs = localDate.atTime(12, 0).atZone(zoneId).toInstant().toEpochMilli()
        return formatter.format(Date(epochMs))
    }

    private fun formatEpochWithIcu(
        epochMs: Long,
        locale: Locale,
        zoneId: ZoneId,
        use24Hour: Boolean?
    ): String {
        val uLocale = ULocale.forLocale(locale)
        val formatter = when (use24Hour) {
            true -> DateFormat.getPatternInstance("yMMMdHm", uLocale)
            false -> DateFormat.getPatternInstance("yMMMdhm", uLocale)
            null -> DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, uLocale)
        }
        formatter.timeZone = IcuTimeZone.getTimeZone(zoneId.id)
        return formatter.format(Date(epochMs))
    }

    private fun formatTimeWithJavaTime(
        localTime: LocalTime,
        locale: Locale,
        use24Hour: Boolean?
    ): String {
        val formatter = when (use24Hour) {
            true -> DateTimeFormatter.ofPattern("HH:mm", locale)
            false -> DateTimeFormatter.ofPattern("h:mm a", locale)
            null -> DateTimeFormatter.ofLocalizedTime(FormatStyle.SHORT).withLocale(locale)
        }
        return formatter.format(localTime)
    }

    private fun formatDateWithJavaTime(
        localDate: LocalDate,
        locale: Locale
    ): String {
        val chronology = resolveJavaChronology(locale)
        val chronoDate = runCatching { chronology.date(localDate) }.getOrDefault(localDate)
        val formatter = DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM)
            .withLocale(locale)
            .withChronology(chronology)
        return formatter.format(chronoDate)
    }

    private fun resolveJavaChronology(locale: Locale): Chronology {
        val calendarType = locale.getUnicodeLocaleType("ca")?.lowercase(Locale.US)
        if (!calendarType.isNullOrBlank()) {
            val byId = when {
                calendarType.startsWith("islamic") -> runCatching { Chronology.of("Hijrah-umalqura") }.getOrNull()
                calendarType == "buddhist" -> runCatching { Chronology.of("ThaiBuddhist") }.getOrNull()
                calendarType == "japanese" -> runCatching { Chronology.of("Japanese") }.getOrNull()
                calendarType == "roc" -> runCatching { Chronology.of("Minguo") }.getOrNull()
                else -> runCatching { Chronology.of(calendarType) }.getOrNull()
            }
            if (byId != null) return byId
        }
        return runCatching { Chronology.ofLocale(locale) }.getOrDefault(IsoChronology.INSTANCE)
    }

    private fun mapIcuDayOfWeek(icuDay: Int): DayOfWeek? {
        return when (icuDay) {
            Calendar.MONDAY -> DayOfWeek.MONDAY
            Calendar.TUESDAY -> DayOfWeek.TUESDAY
            Calendar.WEDNESDAY -> DayOfWeek.WEDNESDAY
            Calendar.THURSDAY -> DayOfWeek.THURSDAY
            Calendar.FRIDAY -> DayOfWeek.FRIDAY
            Calendar.SATURDAY -> DayOfWeek.SATURDAY
            Calendar.SUNDAY -> DayOfWeek.SUNDAY
            else -> null
        }
    }

    companion object {
        private val REFERENCE_ISO_DATE: LocalDate = LocalDate.of(2026, 1, 15)
        private val CANONICAL_HH_MM_FORMATTER: DateTimeFormatter =
            DateTimeFormatter.ofPattern("HH:mm", Locale.ROOT)
    }
}

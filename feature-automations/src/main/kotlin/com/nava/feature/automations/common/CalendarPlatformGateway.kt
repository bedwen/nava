package com.nava.feature.automations.common

import android.Manifest
import android.content.ContentUris
import android.content.ContentValues
import android.content.Context
import android.content.pm.PackageManager
import android.provider.CalendarContract
import androidx.core.content.ContextCompat
import java.util.TimeZone

/**
 * Snapshot of a calendar event returned by [CalendarPlatformGateway].
 */
data class CalendarEventRecord(
    val eventId: Long,
    val calendarId: Long,
    val title: String,
    val description: String = "",
    val location: String = "",
    val startEpochMs: Long,
    val endEpochMs: Long,
    val allDay: Boolean = false
)

/**
 * Parameters for creating a new calendar event via [CalendarPlatformGateway].
 */
data class CalendarEventDraft(
    val title: String,
    val startEpochMs: Long,
    val endEpochMs: Long,
    val description: String = "",
    val location: String = "",
    val allDay: Boolean = false,
    val calendarId: Long? = null,
    val timeZoneId: String = TimeZone.getDefault().id
) {
    init {
        require(title.isNotBlank()) { "CalendarEventDraft title must not be blank" }
        require(endEpochMs >= startEpochMs) { "CalendarEventDraft endEpochMs must be >= startEpochMs" }
    }
}

/**
 * Partial update payload for modifying an existing calendar event.
 */
data class CalendarEventPatch(
    val title: String? = null,
    val description: String? = null,
    val location: String? = null,
    val startEpochMs: Long? = null,
    val endEpochMs: Long? = null,
    val allDay: Boolean? = null
) {
    fun hasAnyChange(): Boolean {
        return title != null ||
            description != null ||
            location != null ||
            startEpochMs != null ||
            endEpochMs != null ||
            allDay != null
    }
}

/**
 * Typed outcome returned by [CalendarPlatformGateway] operations.
 */
sealed interface CalendarGatewayResult<out T> {
    data class Success<T>(val value: T) : CalendarGatewayResult<T>
    data class MissingPermission(val permission: String) : CalendarGatewayResult<Nothing>
    data class NotFound(val eventId: Long) : CalendarGatewayResult<Nothing>
    data class Unavailable(val reason: String) : CalendarGatewayResult<Nothing>
}

/**
 * Thin, JVM-testable abstraction over Android `CalendarContract` `ContentResolver` operations.
 */
interface CalendarPlatformGateway {
    suspend fun queryEvents(
        startEpochMs: Long,
        endEpochMs: Long,
        limit: Int = DEFAULT_QUERY_LIMIT
    ): CalendarGatewayResult<List<CalendarEventRecord>>

    suspend fun createEvent(draft: CalendarEventDraft): CalendarGatewayResult<Long>

    suspend fun updateEvent(eventId: Long, patch: CalendarEventPatch): CalendarGatewayResult<Boolean>

    suspend fun deleteEvent(eventId: Long): CalendarGatewayResult<Boolean>

    companion object {
        const val DEFAULT_QUERY_LIMIT: Int = 50
        const val CALENDAR_PROVIDER_BASE_URI: String = "content://com.android.calendar"
    }
}

/**
 * Production Android SDK implementation of [CalendarPlatformGateway] backed by `CalendarContract`.
 */
class AndroidCalendarPlatformGateway(
    private val context: Context
) : CalendarPlatformGateway {

    override suspend fun queryEvents(
        startEpochMs: Long,
        endEpochMs: Long,
        limit: Int
    ): CalendarGatewayResult<List<CalendarEventRecord>> {
        if (!hasPermission(Manifest.permission.READ_CALENDAR)) {
            return CalendarGatewayResult.MissingPermission(Manifest.permission.READ_CALENDAR)
        }
        if (endEpochMs < startEpochMs || limit <= 0) {
            return CalendarGatewayResult.Success(emptyList())
        }
        val builder = CalendarContract.Instances.CONTENT_URI.buildUpon()
        ContentUris.appendId(builder, startEpochMs)
        ContentUris.appendId(builder, endEpochMs)
        val projection = arrayOf(
            CalendarContract.Instances.EVENT_ID,
            CalendarContract.Instances.CALENDAR_ID,
            CalendarContract.Instances.TITLE,
            CalendarContract.Instances.DESCRIPTION,
            CalendarContract.Instances.EVENT_LOCATION,
            CalendarContract.Instances.BEGIN,
            CalendarContract.Instances.END,
            CalendarContract.Instances.ALL_DAY
        )
        return try {
            val records = ArrayList<CalendarEventRecord>()
            context.contentResolver.query(
                builder.build(),
                projection,
                null,
                null,
                "${CalendarContract.Instances.BEGIN} ASC"
            )?.use { cursor ->
                while (cursor.moveToNext() && records.size < limit) {
                    records.add(
                        CalendarEventRecord(
                            eventId = cursor.getLong(0),
                            calendarId = cursor.getLong(1),
                            title = cursor.getString(2).orEmpty(),
                            description = cursor.getString(3).orEmpty(),
                            location = cursor.getString(4).orEmpty(),
                            startEpochMs = cursor.getLong(5),
                            endEpochMs = cursor.getLong(6),
                            allDay = cursor.getInt(7) != 0
                        )
                    )
                }
            }
            CalendarGatewayResult.Success(records)
        } catch (_: SecurityException) {
            CalendarGatewayResult.MissingPermission(Manifest.permission.READ_CALENDAR)
        } catch (e: RuntimeException) {
            CalendarGatewayResult.Unavailable(e.message ?: "Calendar query failed")
        }
    }

    override suspend fun createEvent(draft: CalendarEventDraft): CalendarGatewayResult<Long> {
        if (!hasPermission(Manifest.permission.WRITE_CALENDAR)) {
            return CalendarGatewayResult.MissingPermission(Manifest.permission.WRITE_CALENDAR)
        }
        val resolvedCalendarId = draft.calendarId ?: resolvePrimaryCalendarId()
            ?: return CalendarGatewayResult.Unavailable("No writable local calendar found")

        val values = ContentValues().apply {
            put(CalendarContract.Events.CALENDAR_ID, resolvedCalendarId)
            put(CalendarContract.Events.TITLE, draft.title)
            put(CalendarContract.Events.DESCRIPTION, draft.description)
            put(CalendarContract.Events.EVENT_LOCATION, draft.location)
            put(CalendarContract.Events.DTSTART, draft.startEpochMs)
            put(CalendarContract.Events.DTEND, draft.endEpochMs)
            put(CalendarContract.Events.ALL_DAY, if (draft.allDay) 1 else 0)
            put(CalendarContract.Events.EVENT_TIMEZONE, draft.timeZoneId)
        }
        return try {
            val inserted = context.contentResolver.insert(CalendarContract.Events.CONTENT_URI, values)
                ?: return CalendarGatewayResult.Unavailable("Calendar provider returned null URI")
            val eventId = ContentUris.parseId(inserted)
            if (eventId < 0L) {
                CalendarGatewayResult.Unavailable("Calendar provider returned invalid event ID")
            } else {
                CalendarGatewayResult.Success(eventId)
            }
        } catch (_: SecurityException) {
            CalendarGatewayResult.MissingPermission(Manifest.permission.WRITE_CALENDAR)
        } catch (e: RuntimeException) {
            CalendarGatewayResult.Unavailable(e.message ?: "Calendar insert failed")
        }
    }

    override suspend fun updateEvent(
        eventId: Long,
        patch: CalendarEventPatch
    ): CalendarGatewayResult<Boolean> {
        if (!hasPermission(Manifest.permission.WRITE_CALENDAR)) {
            return CalendarGatewayResult.MissingPermission(Manifest.permission.WRITE_CALENDAR)
        }
        if (eventId <= 0L) {
            return CalendarGatewayResult.NotFound(eventId)
        }
        if (!patch.hasAnyChange()) {
            return CalendarGatewayResult.Success(false)
        }
        val values = ContentValues().apply {
            patch.title?.let { put(CalendarContract.Events.TITLE, it) }
            patch.description?.let { put(CalendarContract.Events.DESCRIPTION, it) }
            patch.location?.let { put(CalendarContract.Events.EVENT_LOCATION, it) }
            patch.startEpochMs?.let { put(CalendarContract.Events.DTSTART, it) }
            patch.endEpochMs?.let { put(CalendarContract.Events.DTEND, it) }
            patch.allDay?.let { put(CalendarContract.Events.ALL_DAY, if (it) 1 else 0) }
        }
        val eventUri = ContentUris.withAppendedId(CalendarContract.Events.CONTENT_URI, eventId)
        return try {
            val updated = context.contentResolver.update(eventUri, values, null, null)
            if (updated <= 0) {
                CalendarGatewayResult.NotFound(eventId)
            } else {
                CalendarGatewayResult.Success(true)
            }
        } catch (_: SecurityException) {
            CalendarGatewayResult.MissingPermission(Manifest.permission.WRITE_CALENDAR)
        } catch (e: RuntimeException) {
            CalendarGatewayResult.Unavailable(e.message ?: "Calendar update failed")
        }
    }

    override suspend fun deleteEvent(eventId: Long): CalendarGatewayResult<Boolean> {
        if (!hasPermission(Manifest.permission.WRITE_CALENDAR)) {
            return CalendarGatewayResult.MissingPermission(Manifest.permission.WRITE_CALENDAR)
        }
        if (eventId <= 0L) {
            return CalendarGatewayResult.NotFound(eventId)
        }
        val eventUri = ContentUris.withAppendedId(CalendarContract.Events.CONTENT_URI, eventId)
        return try {
            val deleted = context.contentResolver.delete(eventUri, null, null)
            if (deleted <= 0) {
                CalendarGatewayResult.NotFound(eventId)
            } else {
                CalendarGatewayResult.Success(true)
            }
        } catch (_: SecurityException) {
            CalendarGatewayResult.MissingPermission(Manifest.permission.WRITE_CALENDAR)
        } catch (e: RuntimeException) {
            CalendarGatewayResult.Unavailable(e.message ?: "Calendar delete failed")
        }
    }

    private fun resolvePrimaryCalendarId(): Long? {
        if (!hasPermission(Manifest.permission.READ_CALENDAR)) return null
        val projection = arrayOf(
            CalendarContract.Calendars._ID,
            CalendarContract.Calendars.IS_PRIMARY
        )
        val selection = "${CalendarContract.Calendars.CALENDAR_ACCESS_LEVEL} >= ?"
        val selectionArgs = arrayOf(CalendarContract.Calendars.CAL_ACCESS_CONTRIBUTOR.toString())
        return try {
            var fallbackId: Long? = null
            context.contentResolver.query(
                CalendarContract.Calendars.CONTENT_URI,
                projection,
                selection,
                selectionArgs,
                null
            )?.use { cursor ->
                while (cursor.moveToNext()) {
                    val id = cursor.getLong(0)
                    val isPrimary = cursor.getInt(1) == 1
                    if (isPrimary) return id
                    if (fallbackId == null) fallbackId = id
                }
            }
            fallbackId
        } catch (_: RuntimeException) {
            null
        }
    }

    private fun hasPermission(permission: String): Boolean {
        return ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
    }
}

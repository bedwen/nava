package com.nava.app.ui.hub

import com.nava.domain.ui.MessageKey
import org.junit.Assert.assertEquals
import org.junit.Test

class LocalActionResultCardStep3Test {

    @Test
    fun inferLocalActionCardKind_alarmAndTimerKeysMapToAlarm() {
        assertEquals(
            LocalActionCardKind.ALARM,
            inferLocalActionCardKind(
                lastMessageKey = MessageKey.ACTION_ALARM_SET,
                statusTitle = "Alarm set",
                statusMessage = "Alarm set for 08:30"
            )
        )
        assertEquals(
            LocalActionCardKind.ALARM,
            inferLocalActionCardKind(
                lastMessageKey = MessageKey.ACTION_TIMER_SET,
                statusTitle = "Timer set",
                statusMessage = "Timer set for 60 seconds"
            )
        )
    }

    @Test
    fun inferLocalActionCardKind_noteAndVaultNoteSavedKeysMapToNote() {
        assertEquals(
            LocalActionCardKind.NOTE,
            inferLocalActionCardKind(
                lastMessageKey = MessageKey.ACTION_NOTE_SAVED,
                statusTitle = "Note saved",
                statusMessage = "Note saved: Grocery list"
            )
        )
        assertEquals(
            LocalActionCardKind.NOTE,
            inferLocalActionCardKind(
                lastMessageKey = MessageKey.ACTION_VAULT_NOTE_SAVED,
                statusTitle = "Vault note saved",
                statusMessage = "Encrypted note saved in Vault: Recovery codes"
            )
        )
    }

    @Test
    fun inferLocalActionCardKind_calendarEventCreatedMapsToCalendar() {
        assertEquals(
            LocalActionCardKind.CALENDAR,
            inferLocalActionCardKind(
                lastMessageKey = MessageKey.ACTION_CALENDAR_EVENT_CREATED,
                statusTitle = "Calendar event",
                statusMessage = "Calendar event created: Design sync"
            )
        )
    }

    @Test
    fun inferLocalActionCardKind_notificationsSummarizedMapsToSummary() {
        assertEquals(
            LocalActionCardKind.SUMMARY,
            inferLocalActionCardKind(
                lastMessageKey = MessageKey.ACTION_NOTIFICATIONS_SUMMARIZED,
                statusTitle = "Notifications",
                statusMessage = "Summarized 3 notifications"
            )
        )
    }

    @Test
    fun inferLocalActionCardKind_nullAndDndUpdatedMapToGeneral() {
        assertEquals(
            LocalActionCardKind.GENERAL,
            inferLocalActionCardKind(
                lastMessageKey = null,
                statusTitle = null,
                statusMessage = null
            )
        )
        assertEquals(
            LocalActionCardKind.GENERAL,
            inferLocalActionCardKind(
                lastMessageKey = MessageKey.ACTION_DND_UPDATED,
                statusTitle = "Do Not Disturb",
                statusMessage = "Do Not Disturb updated to ON"
            )
        )
    }

    @Test
    fun inferLocalActionCardKind_ignoresTitleAndMessageTextWhenMessageKeyIsSet() {
        assertEquals(
            LocalActionCardKind.ALARM,
            inferLocalActionCardKind(
                lastMessageKey = MessageKey.ACTION_ALARM_SET,
                statusTitle = "Calendar meeting note summary",
                statusMessage = "Unrelated text should not override MessageKey"
            )
        )
        assertEquals(
            LocalActionCardKind.GENERAL,
            inferLocalActionCardKind(
                lastMessageKey = null,
                statusTitle = "Alarm set",
                statusMessage = "Alarm set for 07:00"
            )
        )
    }
}

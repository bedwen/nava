package com.nava.core.security.dao

import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.testing.InMemoryRowStorage
import com.nava.core.security.testing.InMemorySoftwareKeyProvider
import com.nava.domain.automation.ReminderRecurrence
import com.nava.domain.automation.ReminderStatus
import com.nava.domain.automation.ScheduledReminder
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ScheduledReminderDaoTest {

    private fun newStore(): Pair<EncryptedSqliteStore, InMemoryRowStorage> {
        val storage = InMemoryRowStorage()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = InMemorySoftwareKeyProvider()
        )
        return store to storage
    }

    @Test
    fun saveFindListAndUpdateStatusRoundTripEncrypted() = runTest {
        val (store, storage) = newStore()
        val dao = ScheduledReminderDao(store)

        val rem1 = ScheduledReminder(
            reminderId = "rem_drink_water",
            title = "Drink water",
            message = "Hydration check",
            triggerAtEpochMs = 1_700_000_600_000L,
            recurrence = ReminderRecurrence.DAILY,
            status = ReminderStatus.ACTIVE,
            createdAtEpochMs = 1_700_000_000_000L,
            updatedAtEpochMs = 1_700_000_000_000L
        )
        val rem2 = ScheduledReminder(
            reminderId = "rem_call_dentist",
            title = "Call dentist",
            triggerAtEpochMs = 1_700_000_300_000L,
            recurrence = ReminderRecurrence.ONCE,
            status = ReminderStatus.ACTIVE,
            createdAtEpochMs = 1_700_000_000_000L,
            updatedAtEpochMs = 1_700_000_000_000L
        )

        dao.saveReminder(rem1)
        dao.saveReminder(rem2)

        // Verify plaintext title/message do not appear in raw encrypted SQLite blob
        val rawRows = storage.listRows(EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS)
        assertEquals(2, rawRows.size)
        for (raw in rawRows) {
            val rawText = raw.payloadBlob.decodeToString()
            assertFalse(rawText.contains("Drink water"))
            assertFalse(rawText.contains("Call dentist"))
        }

        val loaded = dao.findReminder("rem_drink_water")
        assertNotNull(loaded)
        assertEquals("Drink water", loaded!!.title)
        assertEquals(ReminderRecurrence.DAILY, loaded.recurrence)

        val activeSorted = dao.listActiveReminders()
        assertEquals(listOf("rem_call_dentist", "rem_drink_water"), activeSorted.map { it.reminderId })

        assertTrue(dao.updateStatus("rem_call_dentist", ReminderStatus.COMPLETED, 1_700_000_900_000L))
        assertEquals(listOf("rem_drink_water"), dao.listActiveReminders().map { it.reminderId })

        assertTrue(dao.deleteReminder("rem_drink_water"))
        assertNull(dao.findReminder("rem_drink_water"))
    }
}

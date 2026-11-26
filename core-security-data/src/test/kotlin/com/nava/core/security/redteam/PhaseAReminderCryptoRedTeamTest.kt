package com.nava.core.security.redteam

import com.nava.core.security.dao.AuditLogDao
import com.nava.core.security.dao.EncryptedNote
import com.nava.core.security.dao.EncryptedNoteDao
import com.nava.core.security.dao.ScheduledReminderDao
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.testing.InMemoryRowStorage
import com.nava.core.security.testing.InMemorySoftwareKeyProvider
import com.nava.domain.automation.ReminderRecurrence
import com.nava.domain.automation.ReminderStatus
import com.nava.domain.automation.ScheduledReminder
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.DataProvenance
import javax.crypto.AEADBadTagException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Gate 2 Independent Adversarial Red-Team Suite for Phase A Scheduled Reminders:
 * - Row-bound AES-256-GCM AAD integrity against cross-row and cross-table ciphertext swaps.
 * - Bit-flip / truncation tamper rejection in IV, ciphertext, and GCM tag.
 * - Zero plaintext title, message, or reminderId leakage in `RawEncryptedRow` columns.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PhaseAReminderCryptoRedTeamTest {

    @Test
    fun scheduledReminderDaoRejectsCrossRowCiphertextSwappingWithAeadBadTagException() = runTest {
        val storage = InMemoryRowStorage()
        val keyProvider = InMemorySoftwareKeyProvider()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = keyProvider,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val dao = ScheduledReminderDao(store)

        val alpha = ScheduledReminder(
            reminderId = "rem_alpha_001",
            title = "Pay secret tax bill",
            message = "Account 9988-7766",
            triggerAtEpochMs = 1_750_000_600_000L,
            recurrence = ReminderRecurrence.ONCE,
            status = ReminderStatus.ACTIVE,
            createdAtEpochMs = 1_750_000_000_000L,
            updatedAtEpochMs = 1_750_000_000_000L
        )
        val beta = ScheduledReminder(
            reminderId = "rem_beta_002",
            title = "Take evening medication",
            message = "Dosage 5mg",
            triggerAtEpochMs = 1_750_001_200_000L,
            recurrence = ReminderRecurrence.DAILY,
            status = ReminderStatus.ACTIVE,
            createdAtEpochMs = 1_750_000_000_000L,
            updatedAtEpochMs = 1_750_000_000_000L
        )

        dao.saveReminder(alpha)
        dao.saveReminder(beta)

        val rows = storage.allRawRows(EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS)
        assertEquals(2, rows.size)
        val rowAlpha = rows[0]
        val rowBeta = rows[1]
        assertTrue("Expected distinct synthetic row IDs", rowAlpha.rowId != rowBeta.rowId)

        // Attack 1: Cross-row ciphertext swap (copy rowAlpha's payloadBlob into rowBeta)
        assertTrue(
            storage.replaceRawBlob(
                EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS,
                rowBeta.rowId,
                rowAlpha.payloadBlob
            )
        )

        try {
            dao.findReminder(beta.reminderId)
            fail("Expected AEADBadTagException when finding cross-row swapped reminder")
        } catch (_: AEADBadTagException) {
            // Expected: AAD binds tableName + rowId + columnName
        }

        try {
            dao.listAllReminders()
            fail("Expected AEADBadTagException when listing all reminders with a swapped row")
        } catch (_: AEADBadTagException) {
            // Expected
        }

        try {
            dao.listActiveReminders()
            fail("Expected AEADBadTagException when listing active reminders with a swapped row")
        } catch (_: AEADBadTagException) {
            // Expected
        }

        try {
            dao.updateStatus(beta.reminderId, ReminderStatus.CANCELLED, 1_750_002_000_000L)
            fail("Expected AEADBadTagException when updating status of a tampered reminder row")
        } catch (_: AEADBadTagException) {
            // Expected
        }
    }

    @Test
    fun scheduledReminderDaoRejectsCrossTableCiphertextSwappingEvenWithIdenticalRowIds() = runTest {
        val storage = InMemoryRowStorage()
        val keyProvider = InMemorySoftwareKeyProvider()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = keyProvider,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val reminderDao = ScheduledReminderDao(store)
        val noteDao = EncryptedNoteDao(store)
        val auditDao = AuditLogDao(store)

        val reminder = ScheduledReminder(
            reminderId = "rem_cross_01",
            title = "Cross table canary reminder",
            message = "Confidential briefing item",
            triggerAtEpochMs = 1_750_000_900_000L,
            recurrence = ReminderRecurrence.WEEKLY,
            status = ReminderStatus.ACTIVE,
            createdAtEpochMs = 1_750_000_000_000L,
            updatedAtEpochMs = 1_750_000_000_000L
        )
        val note = EncryptedNote(
            noteId = "note_cross_01",
            title = "Cross table canary note",
            body = "Secret note payload",
            updatedEpochSec = 1_750_000_000L
        )
        val audit = AuditLogEntry(
            timestampEpochMs = 1_750_000_000_000L,
            toolName = "schedule_reminder",
            targetId = "nava.reminders",
            actionSummary = "Scheduled cross-table canary",
            provenance = DataProvenance.USER_UTTERANCE,
            decision = "SUCCESS"
        )

        reminderDao.saveReminder(reminder)
        noteDao.saveNote(note)
        auditDao.record(audit)

        val remRaw = storage.allRawRows(EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS).single()
        val noteRaw = storage.allRawRows(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES).single()
        val auditRaw = storage.allRawRows(EncryptedTableSchema.TABLE_AUDIT_LOGS).single()
        assertEquals("Expected identical rowId=1 across independent tables", remRaw.rowId, noteRaw.rowId)
        assertEquals("Expected identical rowId=1 across independent tables", remRaw.rowId, auditRaw.rowId)

        // Attack 1: Swap encrypted_notes row 1 blob into scheduled_reminders row 1
        assertTrue(
            storage.replaceRawBlob(
                EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS,
                remRaw.rowId,
                noteRaw.payloadBlob
            )
        )
        try {
            reminderDao.findReminder(reminder.reminderId)
            fail("Expected AEADBadTagException on encrypted_notes -> scheduled_reminders swap")
        } catch (_: AEADBadTagException) {
            // Expected
        }
        try {
            reminderDao.listAllReminders()
            fail("Expected AEADBadTagException on listAllReminders after cross-table swap")
        } catch (_: AEADBadTagException) {
            // Expected
        }

        // Attack 2: Swap audit_logs row 1 blob into scheduled_reminders row 1
        assertTrue(
            storage.replaceRawBlob(
                EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS,
                remRaw.rowId,
                auditRaw.payloadBlob
            )
        )
        try {
            reminderDao.findReminder(reminder.reminderId)
            fail("Expected AEADBadTagException on audit_logs -> scheduled_reminders swap")
        } catch (_: AEADBadTagException) {
            // Expected
        }

        // Restore valid reminder blob and confirm decryption succeeds again
        assertTrue(
            storage.replaceRawBlob(
                EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS,
                remRaw.rowId,
                remRaw.payloadBlob
            )
        )
        val restored = reminderDao.findReminder(reminder.reminderId)
        assertNotNull(restored)
        assertEquals(reminder.title, restored!!.title)

        // Attack 3: Reverse direction (scheduled_reminders row 1 -> encrypted_notes row 1)
        assertTrue(
            storage.replaceRawBlob(
                EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
                noteRaw.rowId,
                remRaw.payloadBlob
            )
        )
        try {
            noteDao.findNote(note.noteId)
            fail("Expected AEADBadTagException on scheduled_reminders -> encrypted_notes swap")
        } catch (_: AEADBadTagException) {
            // Expected
        }
    }

    @Test
    fun scheduledReminderDaoRejectsTamperedIvCiphertextTagAndTruncatedPayload() = runTest {
        val storage = InMemoryRowStorage()
        val keyProvider = InMemorySoftwareKeyProvider()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = keyProvider,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val dao = ScheduledReminderDao(store)

        val reminder = ScheduledReminder(
            reminderId = "rem_tamper_01",
            title = "Board meeting",
            message = "Room 4B confidential",
            triggerAtEpochMs = 1_750_005_000_000L
        )
        dao.saveReminder(reminder)

        val raw = storage.allRawRows(EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS).single()
        val originalBlob = raw.payloadBlob

        // Flip 1 bit in IV (offset 0), ciphertext body (offset 14), and GCM tag (last byte)
        for (offset in listOf(0, 14, originalBlob.lastIndex)) {
            val tampered = originalBlob.copyOf()
            tampered[offset] = (tampered[offset].toInt() xor 0x01).toByte()
            assertTrue(
                storage.replaceRawBlob(
                    EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS,
                    raw.rowId,
                    tampered
                )
            )
            try {
                dao.findReminder(reminder.reminderId)
                fail("Expected AEADBadTagException on bit flip at offset $offset")
            } catch (_: AEADBadTagException) {
                // Expected
            }
        }

        // Truncated blob shorter than 12-byte IV + 16-byte GCM tag
        assertTrue(
            storage.replaceRawBlob(
                EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS,
                raw.rowId,
                originalBlob.copyOfRange(0, 20)
            )
        )
        try {
            dao.findReminder(reminder.reminderId)
            fail("Expected IllegalArgumentException on truncated reminder payloadBlob")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }

    @Test
    fun scheduledReminderRawEncryptedRowColumnsLeakZeroPlaintextAndRejectNullByteId() = runTest {
        val storage = InMemoryRowStorage()
        val keyProvider = InMemorySoftwareKeyProvider()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = keyProvider,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val dao = ScheduledReminderDao(store)

        val secretId1 = "rem_canary_id_7419"
        val secretTitle1 = "CANARY_REMINDER_TITLE_ALPHA_9931"
        val secretMsg1 = "CANARY_REMINDER_MESSAGE_SECRET_4482"

        val secretId2 = "rem_canary_id_8520"
        val secretTitle2 = "UNI_CANARY_\u0645\u0631\u062D\u0628\u0627_6610"
        val secretMsg2 = "PIN_CODE_SECRET_7391_\u4F60\u597D"

        dao.saveReminder(
            ScheduledReminder(
                reminderId = secretId1,
                title = secretTitle1,
                message = secretMsg1,
                triggerAtEpochMs = 1_750_010_000_000L,
                recurrence = ReminderRecurrence.DAILY,
                createdAtEpochMs = 1_750_000_000_000L,
                updatedAtEpochMs = 1_750_000_000_000L
            )
        )
        dao.saveReminder(
            ScheduledReminder(
                reminderId = secretId2,
                title = secretTitle2,
                message = secretMsg2,
                triggerAtEpochMs = 1_750_020_000_000L,
                recurrence = ReminderRecurrence.WEEKLY,
                createdAtEpochMs = 1_750_000_000_000L,
                updatedAtEpochMs = 1_750_000_000_000L
            )
        )

        val rawRows = storage.allRawRows(EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS)
        assertEquals(2, rawRows.size)

        val sensitiveMarkers = listOf(
            secretId1,
            secretTitle1,
            secretMsg1,
            "ALPHA_9931",
            "SECRET_4482",
            secretId2,
            secretTitle2,
            secretMsg2,
            "UNI_CANARY",
            "PIN_CODE_SECRET_7391"
        )

        val hexPattern = Regex("^[0-9a-f]{64}$")
        for (row in rawRows) {
            assertTrue(
                "lookupHmac must be an opaque 64-hex HMAC-SHA256 digest, got '${row.lookupHmac}'",
                hexPattern.matches(row.lookupHmac)
            )
            val blobUtf8Text = row.payloadBlob.decodeToString()
            for (marker in sensitiveMarkers) {
                assertFalse(
                    "Raw lookupHmac leaked plaintext marker '$marker'",
                    row.lookupHmac.contains(marker, ignoreCase = true)
                )
                assertFalse(
                    "Raw payloadBlob text leaked plaintext marker '$marker'",
                    blobUtf8Text.contains(marker, ignoreCase = true)
                )
                for (charset in listOf(Charsets.UTF_8, Charsets.UTF_16BE, Charsets.UTF_16LE)) {
                    assertFalse(
                        "Raw payloadBlob (${charset.name()}) leaked byte pattern for '$marker'",
                        containsSubarray(row.payloadBlob, marker.toByteArray(charset))
                    )
                }
            }
        }

        // Null-byte injection in reminderId must be rejected by DAO
        try {
            dao.saveReminder(
                ScheduledReminder(
                    reminderId = "rem\u0000injected",
                    title = "Valid title",
                    triggerAtEpochMs = 1_750_030_000_000L
                )
            )
            fail("Expected IllegalArgumentException for null-byte reminderId")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
        assertNull(dao.findReminder("rem\u0000injected"))
        assertFalse(dao.deleteReminder("rem\u0000injected"))
    }

    private fun containsSubarray(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (i in 0..(haystack.size - needle.size)) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }
}

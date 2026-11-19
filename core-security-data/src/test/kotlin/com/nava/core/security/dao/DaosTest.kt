package com.nava.core.security.dao

import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.testing.InMemoryRowStorage
import com.nava.core.security.testing.InMemorySoftwareKeyProvider
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.DataProvenance
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class DaosTest {

    @Test
    fun auditLogDaoRecordQueryRecentAndQueryByTarget() = runTest {
        val store = EncryptedSqliteStore(
            storage = InMemoryRowStorage(),
            keyProvider = InMemorySoftwareKeyProvider(),
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val dao = AuditLogDao(store)

        dao.record(
            AuditLogEntry(
                timestampEpochMs = 1_000L,
                toolName = "set_alarm",
                targetId = "com.android.deskclock",
                actionSummary = "Set alarm 07:30",
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "AUTHORIZED"
            )
        )
        dao.record(
            AuditLogEntry(
                timestampEpochMs = 2_000L,
                toolName = "create_sms_draft",
                targetId = "com.example.sms",
                actionSummary = "Prepared SMS draft",
                provenance = DataProvenance.UNTRUSTED_EXTERNAL,
                decision = "REQUIRES_CONFIRMATION_TAINTED"
            )
        )
        dao.record(
            AuditLogEntry(
                timestampEpochMs = 3_000L,
                toolName = "set_timer",
                targetId = "com.android.deskclock",
                actionSummary = "Set timer 5m",
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "AUTHORIZED"
            )
        )

        val recent2 = dao.queryRecent(limit = 2)
        assertEquals(2, recent2.size)
        assertEquals(3_000L, recent2[0].timestampEpochMs)
        assertEquals("set_timer", recent2[0].toolName)
        assertTrue(recent2[0].id > 0L)
        assertEquals(2_000L, recent2[1].timestampEpochMs)

        assertTrue(dao.queryRecent(limit = 0).isEmpty())

        val clockEntries = dao.queryByTarget("com.android.deskclock", limit = 10)
        assertEquals(2, clockEntries.size)
        assertEquals(3_000L, clockEntries[0].timestampEpochMs)
        assertEquals(1_000L, clockEntries[1].timestampEpochMs)

        val clockTop1 = dao.queryByTarget("com.android.deskclock", limit = 1)
        assertEquals(1, clockTop1.size)
        assertEquals("set_timer", clockTop1[0].toolName)

        assertTrue(dao.queryByTarget("com.unknown.app", limit = 5).isEmpty())
        assertTrue(dao.queryByTarget(" ", limit = 5).isEmpty())
        assertTrue(dao.queryByTarget("com.android.deskclock", limit = 0).isEmpty())
    }

    @Test
    fun actionCacheDaoAdmissionPolicyLookupLruEvictionAndInvalidation() = runTest {
        val storage = InMemoryRowStorage()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = InMemorySoftwareKeyProvider(),
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val dao = ActionCacheDao(store)

        assertEquals(500, ActionCacheDao.MAX_CACHE_ENTRIES)

        val sampleTemplate = CachedActionTemplate(
            languageCode = "en",
            canonicalSkeleton = "wake me up at \$TIME_0",
            toolNames = listOf("set_alarm"),
            toolSchemaVersions = mapOf("set_alarm" to 1),
            serializedPlanTemplate = "call:set_alarm{time:\$TIME_0}",
            lastUsedEpochSec = 100L
        )

        try {
            dao.putTemplate(
                template = sampleTemplate,
                provenance = DataProvenance.UNTRUSTED_EXTERNAL,
                touchesVault = false,
                nowEpochSec = 100L
            )
            fail("Expected SecurityException for UNTRUSTED_EXTERNAL cache admission")
        } catch (_: SecurityException) {
            // Expected
        }

        try {
            dao.putTemplate(
                template = sampleTemplate,
                provenance = DataProvenance.SYSTEM,
                touchesVault = false,
                nowEpochSec = 100L
            )
            fail("Expected SecurityException for SYSTEM provenance cache admission")
        } catch (_: SecurityException) {
            // Expected
        }

        try {
            dao.putTemplate(
                template = sampleTemplate,
                provenance = DataProvenance.USER_UTTERANCE,
                touchesVault = true,
                nowEpochSec = 100L
            )
            fail("Expected SecurityException when plan touches Nava Vault")
        } catch (_: SecurityException) {
            // Expected
        }

        assertTrue(
            dao.putTemplate(
                template = sampleTemplate,
                provenance = DataProvenance.USER_UTTERANCE,
                touchesVault = false,
                nowEpochSec = 100L
            )
        )

        val rawBeforeTouch = storage.allRawRows(EncryptedTableSchema.TABLE_ACTION_CACHE).single()
        val hit = dao.findTemplate("en", "wake me up at \$TIME_0", nowEpochSec = 250L)
        assertNotNull(hit)
        assertEquals(250L, hit!!.lastUsedEpochSec)
        assertEquals("call:set_alarm{time:\$TIME_0}", hit.serializedPlanTemplate)

        val rawAfterTouch = storage.allRawRows(EncryptedTableSchema.TABLE_ACTION_CACHE).single()
        assertEquals(250L, rawAfterTouch.updatedEpochSec)
        assertArrayEquals(rawBeforeTouch.payloadBlob, rawAfterTouch.payloadBlob)

        assertNull(dao.findTemplate("tr", "wake me up at \$TIME_0", nowEpochSec = 260L))
        assertNull(dao.findTemplate(" ", "wake me up at \$TIME_0", nowEpochSec = 260L))

        val otherToolTemplate = CachedActionTemplate(
            languageCode = "tr",
            canonicalSkeleton = "alarmi \$TIME_0 kur",
            toolNames = listOf("set_alarm", "set_dnd"),
            toolSchemaVersions = mapOf("set_alarm" to 2, "set_dnd" to 1),
            serializedPlanTemplate = "call:set_alarm{time:\$TIME_0};call:set_dnd{mode:priority}",
            lastUsedEpochSec = 300L
        )
        dao.putTemplate(
            template = otherToolTemplate,
            provenance = DataProvenance.USER_UTTERANCE,
            touchesVault = false,
            nowEpochSec = 300L
        )

        val invalidated = dao.invalidateForToolSchemaChange(
            toolName = "set_alarm",
            currentSchemaVersion = 2
        )
        assertEquals(1, invalidated)
        assertNull(dao.findTemplate("en", "wake me up at \$TIME_0", nowEpochSec = 310L))
        assertNotNull(dao.findTemplate("tr", "alarmi \$TIME_0 kur", nowEpochSec = 310L))

        val cleared = dao.invalidateAll()
        assertEquals(1, cleared)
        assertNull(dao.findTemplate("tr", "alarmi \$TIME_0 kur", nowEpochSec = 320L))
    }

    @Test
    fun actionCacheDaoEnforcesMax500EntriesLruEviction() = runTest {
        val storage = InMemoryRowStorage()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = InMemorySoftwareKeyProvider(),
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val dao = ActionCacheDao(store)

        for (i in 0 until ActionCacheDao.MAX_CACHE_ENTRIES) {
            dao.putTemplate(
                template = CachedActionTemplate(
                    languageCode = "en",
                    canonicalSkeleton = "command_$i \$TIME_0",
                    toolNames = listOf("set_alarm"),
                    toolSchemaVersions = mapOf("set_alarm" to 1),
                    serializedPlanTemplate = "call:set_alarm{idx:$i}",
                    lastUsedEpochSec = 1_000L + i
                ),
                provenance = DataProvenance.USER_UTTERANCE,
                touchesVault = false,
                nowEpochSec = 1_000L + i
            )
        }
        assertEquals(500, storage.allRawRows(EncryptedTableSchema.TABLE_ACTION_CACHE).size)

        // Touch entry 0 so entry 1 becomes the least-recently-used entry.
        val touchedZero = dao.findTemplate("en", "command_0 \$TIME_0", nowEpochSec = 5_000L)
        assertNotNull(touchedZero)

        // Inserting the 501st entry must evict entry 1 and retain entry 0.
        dao.putTemplate(
            template = CachedActionTemplate(
                languageCode = "en",
                canonicalSkeleton = "command_500 \$TIME_0",
                toolNames = listOf("set_alarm"),
                toolSchemaVersions = mapOf("set_alarm" to 1),
                serializedPlanTemplate = "call:set_alarm{idx:500}",
                lastUsedEpochSec = 5_001L
            ),
            provenance = DataProvenance.USER_UTTERANCE,
            touchesVault = false,
            nowEpochSec = 5_001L
        )

        assertEquals(500, storage.allRawRows(EncryptedTableSchema.TABLE_ACTION_CACHE).size)
        assertNotNull(dao.findTemplate("en", "command_0 \$TIME_0", nowEpochSec = 5_002L))
        assertNull(dao.findTemplate("en", "command_1 \$TIME_0", nowEpochSec = 5_002L))
        assertNotNull(dao.findTemplate("en", "command_500 \$TIME_0", nowEpochSec = 5_002L))
    }

    @Test
    fun encryptedNoteDaoCrudLifecycle() = runTest {
        val store = EncryptedSqliteStore(
            storage = InMemoryRowStorage(),
            keyProvider = InMemorySoftwareKeyProvider(),
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val dao = EncryptedNoteDao(store)

        val note1 = EncryptedNote(
            noteId = "note_1",
            title = "Groceries",
            body = "Coffee and apples",
            updatedEpochSec = 100L
        )
        val note2 = EncryptedNote(
            noteId = "note_2",
            title = "Presentation",
            body = "Slides ready",
            updatedEpochSec = 200L
        )
        dao.saveNote(note1)
        dao.saveNote(note2)

        assertEquals(note1, dao.findNote("note_1"))
        assertNull(dao.findNote("missing"))
        assertNull(dao.findNote(" "))

        val listed = dao.listNotes()
        assertEquals(listOf(note2, note1), listed)

        val updated1 = note1.copy(body = "Coffee, apples, bread", updatedEpochSec = 300L)
        dao.saveNote(updated1)
        assertEquals(updated1, dao.findNote("note_1"))
        assertEquals(listOf(updated1, note2), dao.listNotes())

        assertTrue(dao.deleteNote("note_2"))
        assertFalse(dao.deleteNote("note_2"))
        assertFalse(dao.deleteNote(" "))
        assertEquals(listOf(updated1), dao.listNotes())

        try {
            EncryptedNote(noteId = " ", title = "t", body = "b", updatedEpochSec = 1L)
            fail("Expected IllegalArgumentException for blank noteId")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }

    @Test
    fun auditLogDaoPersistsNullByteTargetsAndQueriesByIndexedTarget() = runTest {
        val store = EncryptedSqliteStore(
            storage = InMemoryRowStorage(),
            keyProvider = InMemorySoftwareKeyProvider(),
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val auditDao = AuditLogDao(store)
        val cacheDao = ActionCacheDao(store)
        val noteDao = EncryptedNoteDao(store)

        val nullByteTarget = "com.example\u0000injected"
        val cleanTarget = "com.example"

        auditDao.record(
            AuditLogEntry(
                timestampEpochMs = 1_000L,
                toolName = "set_alarm",
                targetId = nullByteTarget,
                actionSummary = "First null-byte target audit",
                provenance = DataProvenance.UNTRUSTED_EXTERNAL,
                decision = "PERMISSION_DENIED"
            )
        )
        auditDao.record(
            AuditLogEntry(
                timestampEpochMs = 2_000L,
                toolName = "set_alarm",
                targetId = cleanTarget,
                actionSummary = "Clean target audit",
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "AUTHORIZED"
            )
        )
        auditDao.record(
            AuditLogEntry(
                timestampEpochMs = 3_000L,
                toolName = "set_timer",
                targetId = nullByteTarget,
                actionSummary = "Second null-byte target audit",
                provenance = DataProvenance.UNTRUSTED_EXTERNAL,
                decision = "PERMISSION_DENIED"
            )
        )

        val nullByteMatches = auditDao.queryByTarget(nullByteTarget, limit = 10)
        assertEquals(2, nullByteMatches.size)
        assertEquals(3_000L, nullByteMatches[0].timestampEpochMs)
        assertEquals(nullByteTarget, nullByteMatches[0].targetId)
        assertEquals(1_000L, nullByteMatches[1].timestampEpochMs)

        val limitedMatch = auditDao.queryByTarget(nullByteTarget, limit = 1)
        assertEquals(1, limitedMatch.size)
        assertEquals(3_000L, limitedMatch[0].timestampEpochMs)

        val cleanMatches = auditDao.queryByTarget(cleanTarget, limit = 10)
        assertEquals(1, cleanMatches.size)
        assertEquals(2_000L, cleanMatches[0].timestampEpochMs)
        assertEquals(cleanTarget, cleanMatches[0].targetId)

        assertNull(cacheDao.findTemplate("en\u0000bad", "skeleton", nowEpochSec = 10L))
        assertNull(cacheDao.findTemplate("en", "bad\u0000skeleton", nowEpochSec = 10L))
        assertNull(noteDao.findNote("bad\u0000note"))
        assertFalse(noteDao.deleteNote("bad\u0000note"))
    }
}

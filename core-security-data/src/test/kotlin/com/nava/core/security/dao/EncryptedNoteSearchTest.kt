package com.nava.core.security.dao

import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.testing.InMemoryRowStorage
import com.nava.core.security.testing.InMemorySoftwareKeyProvider
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class EncryptedNoteSearchTest {

    @Test
    fun bm25LexicalRankingPrioritizesTitleAndHigherTermFrequencyNote() = runTest {
        val storage = InMemoryRowStorage()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = InMemorySoftwareKeyProvider(),
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val dao = EncryptedNoteDao(store)

        dao.saveNote(
            EncryptedNote(
                noteId = "n_unrelated",
                title = "Grocery List",
                body = "Milk, apples, sourdough bread, and coffee beans.",
                updatedEpochSec = 500L
            )
        )
        dao.saveNote(
            EncryptedNote(
                noteId = "n_body_only",
                title = "Weekly Checklist",
                body = "Prepare slides before Friday review.",
                updatedEpochSec = 400L
            )
        )
        dao.saveNote(
            EncryptedNote(
                noteId = "n_best",
                title = "Quarterly Budget Roadmap",
                body = "Budget allocation for hardware and offline budget modeling.",
                updatedEpochSec = 300L
            )
        )
        dao.saveNote(
            EncryptedNote(
                noteId = "n_secondary",
                title = "Team Sync",
                body = "Briefly discussed annual budget numbers.",
                updatedEpochSec = 200L
            )
        )

        val hits = dao.searchNotes(query = "budget", limit = 2)

        assertEquals(2, hits.size)
        assertEquals("n_best", hits[0].note.noteId)
        assertEquals("n_secondary", hits[1].note.noteId)
        assertTrue(hits[0].score > hits[1].score)
        assertTrue(hits[0].excerpt.contains("Budget allocation"))
    }

    @Test
    fun prefixMatchingAndDiacriticNormalizationFindInflectedNotes() = runTest {
        val storage = InMemoryRowStorage()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = InMemorySoftwareKeyProvider(),
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val dao = EncryptedNoteDao(store)

        dao.saveNote(
            EncryptedNote(
                noteId = "n_diacritic",
                title = "Caf\u00E9 R\u00E9sum\u00E9 Notes",
                body = "Schedule reimbursements and quarterly meetings at the downtown bistro.",
                updatedEpochSec = 1_000L
            )
        )
        dao.saveNote(
            EncryptedNote(
                noteId = "n_other",
                title = "Parking",
                body = "Level B2 spot 14 near the elevator.",
                updatedEpochSec = 900L
            )
        )

        // Diacritic-stripped query matches title tokens normalized via NFKD
        val diacriticHits = dao.searchNotes(query = "cafe resume", limit = 3)
        assertEquals(1, diacriticHits.size)
        assertEquals("n_diacritic", diacriticHits[0].note.noteId)
        assertTrue(diacriticHits[0].excerpt.contains("Schedule reimbursements"))

        // Inflected / prefix query (length >= 4) matches pluralized token in body
        val prefixHits = dao.searchNotes(query = "reimbursement meeting", limit = 3)
        assertEquals(1, prefixHits.size)
        assertEquals("n_diacritic", prefixHits[0].note.noteId)
    }

    @Test
    fun searchCreatesZeroPlaintextIndexRowsOutsideEncryptedNotesAndBuildsWindowedExcerpt() = runTest {
        val storage = InMemoryRowStorage()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = InMemorySoftwareKeyProvider(),
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val dao = EncryptedNoteDao(store)

        val longBody = "Alpha intro paragraph repeated filler text. ".repeat(6) +
            "Critical passport renewal appointment confirmed for Tuesday morning. " +
            "Closing checklist items."
        dao.saveNote(
            EncryptedNote(
                noteId = "n_long",
                title = "Travel Prep",
                body = longBody,
                updatedEpochSec = 1_200L
            )
        )

        assertTrue(dao.searchNotes(query = "   ", limit = 3).isEmpty())
        assertTrue(dao.searchNotes(query = "a", limit = 3).isEmpty())

        val hits = dao.searchNotes(query = "passport", limit = 3)
        assertEquals(1, hits.size)
        assertEquals("n_long", hits[0].note.noteId)
        assertTrue(hits[0].excerpt.length <= 180)
        assertTrue(hits[0].excerpt.contains("passport renewal appointment"))

        // Zero plaintext index tables or rows may be written outside TABLE_ENCRYPTED_NOTES
        for (table in EncryptedTableSchema.ALLOWED_TABLES) {
            if (table == EncryptedTableSchema.TABLE_ENCRYPTED_NOTES) {
                assertEquals(1, storage.allRawRows(table).size)
            } else {
                assertTrue(
                    "Expected zero rows in non-note table '$table'",
                    storage.allRawRows(table).isEmpty()
                )
            }
        }

        // Verify stored payloadBlob does not contain plaintext tokens
        val rawBlobString = storage.allRawRows(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES)
            .single()
            .payloadBlob
            .toString(Charsets.UTF_8)
        assertFalse(rawBlobString.contains("passport"))
        assertFalse(rawBlobString.contains("Travel Prep"))
    }
}

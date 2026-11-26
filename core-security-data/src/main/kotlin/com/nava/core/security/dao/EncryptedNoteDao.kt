package com.nava.core.security.dao

import com.nava.core.security.crypto.SecureMemory
import com.nava.core.security.storage.DecryptedRow
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.storage.StructuredPayloadCodec
import com.nava.domain.security.NoteSearchHit
import com.nava.domain.security.NoteStoragePort
import com.nava.domain.security.StoredNote
import java.text.Normalizer
import java.util.Locale
import kotlin.math.ln

/**
 * Source-compatible alias for the canonical `:domain` [StoredNote].
 */
typealias EncryptedNote = StoredNote

/**
 * DAO for standard encrypted local notes over [EncryptedSqliteStore] (`encrypted_notes` table),
 * implementing the `:domain` [NoteStoragePort].
 */
class EncryptedNoteDao(
    private val store: EncryptedSqliteStore
) : NoteStoragePort {

    /** Inserts or updates [note] keyed by its `HMAC-SHA256` blind index. */
    override suspend fun saveNote(note: EncryptedNote) {
        val lookupHmac = store.computeBlindIndex(DOMAIN_NOTE, note.noteId)
        val encoded = encodeNote(note)
        SecureMemory.withZeroizedBytes(encoded) { payload ->
            store.upsertEncryptedByBlindIndex(
                tableName = EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
                lookupHmac = lookupHmac,
                plaintext = payload,
                epochSec = note.updatedEpochSec,
                schemaVersion = NOTE_SCHEMA_VERSION
            )
        }
    }

    /** Finds and decrypts the note identified by [noteId], or returns null if absent. */
    override suspend fun findNote(noteId: String): EncryptedNote? {
        if (noteId.isBlank() || '\u0000' in noteId) return null
        val lookupHmac = store.computeBlindIndex(DOMAIN_NOTE, noteId)
        val row = store.findDecryptedByBlindIndex(
            tableName = EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
            lookupHmac = lookupHmac
        ) ?: return null
        val decoded = try {
            decodeNote(row)
        } finally {
            row.zeroize()
        }
        return if (decoded.noteId == noteId) decoded else null
    }

    /** Lists and decrypts all stored notes ordered by `updatedEpochSec DESC, noteId ASC`. */
    override suspend fun listNotes(): List<EncryptedNote> {
        val rows = store.listAllDecrypted(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES)
        return try {
            val notes = ArrayList<EncryptedNote>(rows.size)
            for (row in rows) {
                notes.add(decodeNote(row))
            }
            notes.sortWith(compareByDescending<EncryptedNote> { it.updatedEpochSec }.thenBy { it.noteId })
            notes
        } finally {
            for (row in rows) {
                row.zeroize()
            }
        }
    }

    /** Deletes the note identified by [noteId]; returns true if a note was removed. */
    override suspend fun deleteNote(noteId: String): Boolean {
        if (noteId.isBlank() || '\u0000' in noteId) return false
        val lookupHmac = store.computeBlindIndex(DOMAIN_NOTE, noteId)
        return store.deleteByBlindIndex(
            tableName = EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
            lookupHmac = lookupHmac
        )
    }

    /**
     * In-memory lexical/BM25 search over decrypted standard notes.
     *
     * Security invariants:
     * - Zero plaintext search index is persisted to SQLite or disk.
     * - Decrypted row byte buffers are immediately zeroized inside [listNotes] `finally` blocks.
     * - Strictly scoped to `encrypted_notes`; locked `NavaVault` entries are never read.
     */
    override suspend fun searchNotes(query: String, limit: Int): List<NoteSearchHit> {
        val queryTokens = tokenizeForSearch(query)
        if (queryTokens.isEmpty()) return emptyList()
        val boundedLimit = limit.coerceIn(1, MAX_SEARCH_LIMIT)
        val notes = listNotes()
        if (notes.isEmpty()) return emptyList()

        val docCount = notes.size
        val docTokenLists = ArrayList<List<String>>(docCount)
        val titleTokenSets = ArrayList<Set<String>>(docCount)
        val docFreq = HashMap<String, Int>()
        var totalDocLength = 0

        for (note in notes) {
            val titleTokens = tokenizeForSearch(note.title)
            val bodyTokens = tokenizeForSearch(note.body)
            val combined = ArrayList<String>(titleTokens.size + bodyTokens.size).apply {
                addAll(titleTokens)
                addAll(bodyTokens)
            }
            docTokenLists.add(combined)
            titleTokenSets.add(titleTokens.toHashSet())
            totalDocLength += combined.size
            val uniqueTerms = combined.toHashSet()
            for (term in uniqueTerms) {
                docFreq[term] = (docFreq[term] ?: 0) + 1
            }
        }

        val avgDocLength = (totalDocLength.toDouble() / docCount.toDouble()).coerceAtLeast(1.0)
        val hits = ArrayList<NoteSearchHit>()

        for (index in notes.indices) {
            val note = notes[index]
            val tokens = docTokenLists[index]
            if (tokens.isEmpty()) continue
            val titleSet = titleTokenSets[index]
            val termFreq = HashMap<String, Int>()
            for (t in tokens) {
                termFreq[t] = (termFreq[t] ?: 0) + 1
            }

            var score = 0.0
            for (qTerm in queryTokens) {
                var tf = termFreq[qTerm] ?: 0
                if (tf == 0 && qTerm.length >= 4) {
                    // Prefix match for inflected/agglutinative languages (e.g. Turkish, Finnish)
                    for ((docTerm, freq) in termFreq) {
                        if (docTerm.startsWith(qTerm) || (docTerm.length >= 4 && qTerm.startsWith(docTerm))) {
                            tf += freq
                        }
                    }
                }
                if (tf <= 0) continue
                val df = (docFreq[qTerm] ?: 1).toDouble()
                val idf = ln(1.0 + (docCount - df + 0.5) / (df + 0.5))
                val denom = tf + BM25_K1 * (1.0 - BM25_B + BM25_B * (tokens.size.toDouble() / avgDocLength))
                var termScore = idf * ((tf * (BM25_K1 + 1.0)) / denom)
                if (qTerm in titleSet) {
                    termScore *= TITLE_BOOST
                }
                score += termScore
            }

            if (score > 0.0) {
                hits.add(
                    NoteSearchHit(
                        note = note,
                        score = score,
                        excerpt = buildExcerpt(note, queryTokens)
                    )
                )
            }
        }

        hits.sortWith(
            compareByDescending<NoteSearchHit> { it.score }
                .thenByDescending { it.note.updatedEpochSec }
                .thenBy { it.note.noteId }
        )
        return hits.take(boundedLimit)
    }

    private fun tokenizeForSearch(text: String): List<String> {
        if (text.isBlank()) return emptyList()
        val normalized = Normalizer.normalize(text, Normalizer.Form.NFKD)
            .replace(DIACRITICS_REGEX, "")
            .lowercase(Locale.ROOT)
        val tokens = ArrayList<String>()
        val sb = StringBuilder()
        for (ch in normalized) {
            if (ch.isLetterOrDigit()) {
                sb.append(ch)
            } else if (sb.isNotEmpty()) {
                if (sb.length >= 2) tokens.add(sb.toString())
                sb.setLength(0)
            }
        }
        if (sb.length >= 2) {
            tokens.add(sb.toString())
        }
        return tokens
    }

    private fun buildExcerpt(note: EncryptedNote, queryTokens: List<String>): String {
        val cleanBody = note.body.replace('\r', ' ').replace('\n', ' ').trim()
        if (cleanBody.length <= MAX_EXCERPT_CHARS) return cleanBody
        val lowerBody = Normalizer.normalize(cleanBody, Normalizer.Form.NFKD)
            .replace(DIACRITICS_REGEX, "")
            .lowercase(Locale.ROOT)
        var bestPos = 0
        for (term in queryTokens) {
            val idx = lowerBody.indexOf(term)
            if (idx >= 0) {
                bestPos = idx
                break
            }
        }
        val start = (bestPos - 40).coerceAtLeast(0)
        val end = (start + MAX_EXCERPT_CHARS).coerceAtMost(cleanBody.length)
        return cleanBody.substring(start, end).trim()
    }

    private fun encodeNote(note: EncryptedNote): ByteArray {
        return StructuredPayloadCodec.encode(formatVersion = NOTE_SCHEMA_VERSION) {
            writeString(note.noteId)
            writeString(note.title)
            writeString(note.body)
            writeLong(note.updatedEpochSec)
        }
    }

    private fun decodeNote(row: DecryptedRow): EncryptedNote {
        return StructuredPayloadCodec.decode(
            bytes = row.plaintext,
            expectedVersion = NOTE_SCHEMA_VERSION
        ) {
            EncryptedNote(
                noteId = readString(),
                title = readString(),
                body = readString(),
                updatedEpochSec = readLong()
            )
        }
    }

    companion object {
        private const val DOMAIN_NOTE: String = "note"
        private const val NOTE_SCHEMA_VERSION: Int = 1
        private const val MAX_SEARCH_LIMIT: Int = 10
        private const val MAX_EXCERPT_CHARS: Int = 180
        private const val BM25_K1: Double = 1.2
        private const val BM25_B: Double = 0.75
        private const val TITLE_BOOST: Double = 1.5
        private val DIACRITICS_REGEX: Regex = Regex("\\p{Mn}+")
    }
}

package com.nava.core.security.dao

import com.nava.core.security.crypto.SecureMemory
import com.nava.core.security.storage.DecryptedRow
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.storage.StructuredPayloadCodec

/**
 * Standard encrypted local note persisted in [EncryptedSqliteStore] under `nava_db_master_key`.
 */
data class EncryptedNote(
    val noteId: String,
    val title: String,
    val body: String,
    val updatedEpochSec: Long
) {
    init {
        require(noteId.isNotBlank()) { "EncryptedNote noteId must not be blank" }
    }
}

/**
 * DAO for standard encrypted local notes over [EncryptedSqliteStore] (`encrypted_notes` table).
 */
class EncryptedNoteDao(
    private val store: EncryptedSqliteStore
) {

    /** Inserts or updates [note] keyed by its `HMAC-SHA256` blind index. */
    suspend fun saveNote(note: EncryptedNote) {
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
    suspend fun findNote(noteId: String): EncryptedNote? {
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
    suspend fun listNotes(): List<EncryptedNote> {
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
    suspend fun deleteNote(noteId: String): Boolean {
        if (noteId.isBlank() || '\u0000' in noteId) return false
        val lookupHmac = store.computeBlindIndex(DOMAIN_NOTE, noteId)
        return store.deleteByBlindIndex(
            tableName = EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
            lookupHmac = lookupHmac
        )
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
    }
}

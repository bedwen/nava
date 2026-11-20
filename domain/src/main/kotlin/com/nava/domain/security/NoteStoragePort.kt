package com.nava.domain.security

/**
 * Standard encrypted local note persisted outside Nava Vault under `nava_db_master_key`.
 */
data class StoredNote(
    val noteId: String,
    val title: String,
    val body: String,
    val updatedEpochSec: Long
) {
    init {
        require(noteId.isNotBlank()) { "StoredNote noteId must not be blank" }
    }
}

/**
 * Port for standard encrypted local notes stored via `EncryptedSqliteStore` (`encrypted_notes`).
 *
 * Unlike [VaultPort], notes persisted through this port are encrypted under `nava_db_master_key`
 * rather than the biometric-bound `nava_vault_biometric_key`.
 */
interface NoteStoragePort {
    /** Inserts or updates [note] keyed by its `HMAC-SHA256` blind index. */
    suspend fun saveNote(note: StoredNote)

    /** Finds and decrypts the note identified by [noteId], or returns null if absent. */
    suspend fun findNote(noteId: String): StoredNote?

    /** Lists and decrypts all stored notes ordered by `updatedEpochSec DESC, noteId ASC`. */
    suspend fun listNotes(): List<StoredNote>

    /** Deletes the note identified by [noteId]; returns true if a note was removed. */
    suspend fun deleteNote(noteId: String): Boolean
}

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
 * Ranked in-memory search hit returned by [NoteStoragePort.searchNotes].
 *
 * Security invariant: Search executes strictly in memory over decrypted standard notes;
 * zero plaintext search index is persisted to disk, and locked `NavaVault` entries are never read.
 */
data class NoteSearchHit(
    val note: StoredNote,
    val score: Double,
    val excerpt: String
)

/**
 * Optional pluggable semantic re-ranker interface (e.g., for an opt-in EmbeddingGemma add-on).
 * Default deployments pass `null` and rely on 0 MB in-memory lexical/BM25 scoring.
 */
interface NoteSemanticRankerPort {
    suspend fun rerank(query: String, candidates: List<NoteSearchHit>, limit: Int): List<NoteSearchHit>
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

    /**
     * Searches standard encrypted notes in memory without persisting any plaintext search index.
     */
    suspend fun searchNotes(query: String, limit: Int = 3): List<NoteSearchHit> = emptyList()
}

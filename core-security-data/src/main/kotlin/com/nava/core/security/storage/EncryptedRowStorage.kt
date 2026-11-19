package com.nava.core.security.storage

import com.nava.core.security.crypto.SecureMemory

/**
 * Encrypted row representation persisted in SQLite with zero plaintext user columns.
 */
data class RawEncryptedRow(
    val rowId: Long,
    val lookupHmac: String,
    val schemaVersion: Int,
    val createdEpochSec: Long,
    val updatedEpochSec: Long,
    val payloadBlob: ByteArray
) {
    init {
        require(rowId > 0L) { "RawEncryptedRow rowId must be positive, got $rowId" }
        require(lookupHmac.isNotBlank()) { "RawEncryptedRow lookupHmac must not be blank" }
        require(schemaVersion > 0) { "RawEncryptedRow schemaVersion must be positive, got $schemaVersion" }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RawEncryptedRow) return false
        return rowId == other.rowId &&
            lookupHmac == other.lookupHmac &&
            schemaVersion == other.schemaVersion &&
            createdEpochSec == other.createdEpochSec &&
            updatedEpochSec == other.updatedEpochSec &&
            payloadBlob.contentEquals(other.payloadBlob)
    }

    override fun hashCode(): Int {
        var result = rowId.hashCode()
        result = 31 * result + lookupHmac.hashCode()
        result = 31 * result + schemaVersion
        result = 31 * result + createdEpochSec.hashCode()
        result = 31 * result + updatedEpochSec.hashCode()
        result = 31 * result + payloadBlob.contentHashCode()
        return result
    }
}

/**
 * Decrypted row returned by [EncryptedSqliteStore]. Callers should invoke [zeroize] once
 * deserialization of [plaintext] completes.
 */
data class DecryptedRow(
    val rowId: Long,
    val lookupHmac: String,
    val schemaVersion: Int,
    val createdEpochSec: Long,
    val updatedEpochSec: Long,
    val plaintext: ByteArray
) {
    /** Overwrites [plaintext] in place with `0x00`. */
    fun zeroize() {
        SecureMemory.zeroize(plaintext)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DecryptedRow) return false
        return rowId == other.rowId &&
            lookupHmac == other.lookupHmac &&
            schemaVersion == other.schemaVersion &&
            createdEpochSec == other.createdEpochSec &&
            updatedEpochSec == other.updatedEpochSec &&
            plaintext.contentEquals(other.plaintext)
    }

    override fun hashCode(): Int {
        var result = rowId.hashCode()
        result = 31 * result + lookupHmac.hashCode()
        result = 31 * result + schemaVersion
        result = 31 * result + createdEpochSec.hashCode()
        result = 31 * result + updatedEpochSec.hashCode()
        result = 31 * result + plaintext.contentHashCode()
        return result
    }
}

/**
 * Storage backend contract separating SQLite row I/O from cryptographic AAD encryption in
 * [EncryptedSqliteStore].
 */
interface EncryptedRowStorage {
    /** Allocates a strictly positive, monotonically increasing row ID for [tableName]. */
    fun allocateRowId(tableName: String): Long

    /** Inserts a new encrypted [row] into [tableName]. */
    fun insertRow(tableName: String, row: RawEncryptedRow)

    /** Atomically inserts or replaces the row matching [row.lookupHmac] in [tableName]. */
    fun upsertByLookupHmac(tableName: String, row: RawEncryptedRow)

    /** Looks up the most recent row matching [lookupHmac] in [tableName], or null if absent. */
    fun findByLookupHmac(tableName: String, lookupHmac: String): RawEncryptedRow?

    /** Looks up a row by synthetic [rowId] in [tableName], or null if absent. */
    fun findByRowId(tableName: String, rowId: Long): RawEncryptedRow?

    /** Lists all encrypted rows in [tableName] ordered by `row_id ASC`. */
    fun listRows(tableName: String): List<RawEncryptedRow>

    /** Lists up to [limit] most recently updated rows ordered by `updated_epoch_sec DESC, row_id DESC`. */
    fun listRecent(tableName: String, limit: Int): List<RawEncryptedRow>

    /**
     * Lists up to [limit] most recently updated rows matching [lookupHmac] in [tableName],
     * ordered by `updated_epoch_sec DESC, row_id DESC`.
     */
    fun listRecentByLookupHmac(
        tableName: String,
        lookupHmac: String,
        limit: Int
    ): List<RawEncryptedRow>

    /** Deletes rows matching [lookupHmac] in [tableName]; returns true if at least one row was removed. */
    fun deleteByLookupHmac(tableName: String, lookupHmac: String): Boolean

    /** Deletes the row matching [rowId] in [tableName]; returns true if removed. */
    fun deleteByRowId(tableName: String, rowId: Long): Boolean

    /**
     * Evicts least-recently-updated rows beyond [maxEntries] from [tableName].
     * Returns the number of rows deleted.
     */
    fun deleteOlderThanMaxCount(tableName: String, maxEntries: Int): Int

    /**
     * Updates only `updated_epoch_sec` for [rowId] in [tableName] without altering `payload_blob`
     * (preserving row-bound GCM AAD for fast LRU touch on cache hits).
     */
    fun touchUpdatedEpochSec(tableName: String, rowId: Long, updatedEpochSec: Long): Boolean

    /** Executes [block] inside an atomic storage transaction. */
    fun <T> withTransaction(block: () -> T): T

    /** Releases underlying database handles. */
    fun close()
}

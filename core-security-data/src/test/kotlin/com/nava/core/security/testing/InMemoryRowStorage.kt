package com.nava.core.security.testing

import com.nava.core.security.storage.EncryptedRowStorage
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.storage.RawEncryptedRow

/**
 * Thread-safe, transaction-rollback-capable in-memory [EncryptedRowStorage] test double
 * with raw blob inspection and tampering helpers for unit and Gate 2 verification suites.
 */
class InMemoryRowStorage : EncryptedRowStorage {

    private val lock = Any()
    private val tables: MutableMap<String, MutableList<RawEncryptedRow>> = LinkedHashMap()
    private val sequences: MutableMap<String, Long> = LinkedHashMap()
    private var transactionDepth: Int = 0

    init {
        for (table in EncryptedTableSchema.ALLOWED_TABLES) {
            tables[table] = mutableListOf()
            sequences[table] = 0L
        }
    }

    override fun allocateRowId(tableName: String): Long {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        return synchronized(lock) {
            val nextId = (sequences[validTable] ?: 0L) + 1L
            sequences[validTable] = nextId
            nextId
        }
    }

    override fun insertRow(tableName: String, row: RawEncryptedRow) {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        synchronized(lock) {
            val tableRows = tables.getValue(validTable)
            if (tableRows.any { it.rowId == row.rowId }) {
                throw IllegalStateException(
                    "Duplicate rowId ${row.rowId} in table '$validTable'"
                )
            }
            tableRows.add(copyRow(row))
        }
    }

    override fun upsertByLookupHmac(tableName: String, row: RawEncryptedRow) {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        synchronized(lock) {
            val tableRows = tables.getValue(validTable)
            tableRows.removeAll { it.lookupHmac == row.lookupHmac || it.rowId == row.rowId }
            tableRows.add(copyRow(row))
        }
    }

    override fun findByLookupHmac(tableName: String, lookupHmac: String): RawEncryptedRow? {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        return synchronized(lock) {
            tables.getValue(validTable)
                .asSequence()
                .filter { it.lookupHmac == lookupHmac }
                .sortedWith(RECENT_ORDER)
                .firstOrNull()
                ?.let(::copyRow)
        }
    }

    override fun findByRowId(tableName: String, rowId: Long): RawEncryptedRow? {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        return synchronized(lock) {
            tables.getValue(validTable)
                .firstOrNull { it.rowId == rowId }
                ?.let(::copyRow)
        }
    }

    override fun listRows(tableName: String): List<RawEncryptedRow> {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        return synchronized(lock) {
            tables.getValue(validTable)
                .sortedBy { it.rowId }
                .map(::copyRow)
        }
    }

    override fun listRecent(tableName: String, limit: Int): List<RawEncryptedRow> {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        if (limit <= 0) return emptyList()
        return synchronized(lock) {
            tables.getValue(validTable)
                .sortedWith(RECENT_ORDER)
                .take(limit)
                .map(::copyRow)
        }
    }

    override fun listRecentByLookupHmac(
        tableName: String,
        lookupHmac: String,
        limit: Int
    ): List<RawEncryptedRow> {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        if (limit <= 0) return emptyList()
        return synchronized(lock) {
            tables.getValue(validTable)
                .asSequence()
                .filter { it.lookupHmac == lookupHmac }
                .sortedWith(RECENT_ORDER)
                .take(limit)
                .map(::copyRow)
                .toList()
        }
    }

    override fun deleteByLookupHmac(tableName: String, lookupHmac: String): Boolean {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        return synchronized(lock) {
            tables.getValue(validTable).removeAll { it.lookupHmac == lookupHmac }
        }
    }

    override fun deleteByRowId(tableName: String, rowId: Long): Boolean {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        return synchronized(lock) {
            tables.getValue(validTable).removeAll { it.rowId == rowId }
        }
    }

    override fun deleteOlderThanMaxCount(tableName: String, maxEntries: Int): Int {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        require(maxEntries >= 0) { "maxEntries must be non-negative, got $maxEntries" }
        return synchronized(lock) {
            val tableRows = tables.getValue(validTable)
            if (tableRows.size <= maxEntries) {
                return@synchronized 0
            }
            val evictCount = tableRows.size - maxEntries
            val evictRowIds = tableRows
                .sortedWith(LRU_EVICTION_ORDER)
                .take(evictCount)
                .mapTo(HashSet(evictCount)) { it.rowId }
            tableRows.removeAll { it.rowId in evictRowIds }
            evictRowIds.size
        }
    }

    override fun touchUpdatedEpochSec(tableName: String, rowId: Long, updatedEpochSec: Long): Boolean {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        return synchronized(lock) {
            val tableRows = tables.getValue(validTable)
            val idx = tableRows.indexOfFirst { it.rowId == rowId }
            if (idx < 0) return@synchronized false
            val existing = tableRows[idx]
            tableRows[idx] = existing.copy(updatedEpochSec = updatedEpochSec)
            true
        }
    }

    override fun <T> withTransaction(block: () -> T): T {
        return synchronized(lock) {
            val isOutermost = transactionDepth == 0
            val tableSnapshot = if (isOutermost) snapshotTables() else null
            val seqSnapshot = if (isOutermost) HashMap(sequences) else null
            transactionDepth++
            try {
                block()
            } catch (e: Throwable) {
                if (isOutermost && tableSnapshot != null && seqSnapshot != null) {
                    restoreSnapshot(tableSnapshot, seqSnapshot)
                }
                throw e
            } finally {
                transactionDepth--
            }
        }
    }

    override fun close() {
        // In-memory storage remains inspectable by tests after close().
    }

    /** Returns a defensive copy of the raw encrypted row for test inspection. */
    fun inspectRawRow(tableName: String, rowId: Long): RawEncryptedRow? {
        return findByRowId(tableName, rowId)
    }

    /** Replaces the raw `payloadBlob` of [rowId] in [tableName] for tamper testing. */
    fun replaceRawBlob(tableName: String, rowId: Long, blob: ByteArray): Boolean {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        return synchronized(lock) {
            val tableRows = tables.getValue(validTable)
            val idx = tableRows.indexOfFirst { it.rowId == rowId }
            if (idx < 0) return@synchronized false
            tableRows[idx] = tableRows[idx].copy(payloadBlob = blob.copyOf())
            true
        }
    }

    /** Returns defensive copies of all raw encrypted rows in [tableName] ordered by `rowId ASC`. */
    fun allRawRows(tableName: String): List<RawEncryptedRow> {
        return listRows(tableName)
    }

    private fun copyRow(row: RawEncryptedRow): RawEncryptedRow {
        return row.copy(payloadBlob = row.payloadBlob.copyOf())
    }

    private fun snapshotTables(): Map<String, MutableList<RawEncryptedRow>> {
        val copy = LinkedHashMap<String, MutableList<RawEncryptedRow>>(tables.size)
        for ((tableName, rows) in tables) {
            val copiedRows = ArrayList<RawEncryptedRow>(rows.size)
            for (row in rows) {
                copiedRows.add(copyRow(row))
            }
            copy[tableName] = copiedRows
        }
        return copy
    }

    private fun restoreSnapshot(
        tableSnapshot: Map<String, MutableList<RawEncryptedRow>>,
        seqSnapshot: Map<String, Long>
    ) {
        tables.clear()
        tables.putAll(tableSnapshot)
        sequences.clear()
        sequences.putAll(seqSnapshot)
    }

    companion object {
        private val RECENT_ORDER: Comparator<RawEncryptedRow> =
            compareByDescending<RawEncryptedRow> { it.updatedEpochSec }
                .thenByDescending { it.rowId }

        private val LRU_EVICTION_ORDER: Comparator<RawEncryptedRow> =
            compareBy<RawEncryptedRow> { it.updatedEpochSec }
                .thenBy { it.rowId }
    }
}

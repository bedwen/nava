package com.nava.core.security.dao

import com.nava.core.security.crypto.KeyUnavailability
import com.nava.core.security.crypto.SecureMemory
import com.nava.core.security.storage.DecryptedRow
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.storage.StructuredPayloadCodec
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.DataProvenance
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Encrypted persistent DAO implementing [AuditLogPort] over [EncryptedSqliteStore]
 * (`audit_logs` table) with blind-indexed target queries and immediate plaintext zeroization.
 */
class AuditLogDao(
    private val store: EncryptedSqliteStore
) : AuditLogPort {

    /**
     * Entries that could not be encrypted because the `nava_db_master_key` was transiently
     * unavailable (device locked). They are flushed, in order, on the next successful write so
     * background firewall decisions are never lost and never abort the action being audited.
     * Bounded to [MAX_PENDING_ENTRIES]; the oldest entries are dropped first and counted.
     */
    private val pendingEntries = ArrayDeque<AuditLogEntry>()
    private val pendingMutex = Mutex()
    private var droppedPendingEntries: Long = 0L
    private var reportedDroppedEntries: Long = 0L

    /** Number of audit entries buffered while the master key was unavailable. */
    suspend fun pendingBufferedCount(): Int = pendingMutex.withLock { pendingEntries.size }

    /** Number of buffered entries dropped because the bounded buffer overflowed. */
    suspend fun droppedBufferedCount(): Long = pendingMutex.withLock { droppedPendingEntries }

    override suspend fun record(entry: AuditLogEntry) {
        pendingMutex.withLock {
            try {
                while (pendingEntries.isNotEmpty()) {
                    try {
                        persist(pendingEntries.first())
                    } catch (ce: CancellationException) {
                        throw ce
                    } catch (e: Exception) {
                        // Key-level failures keep the buffer intact: transient ones are retried
                        // later, permanent key loss is surfaced to the caller below.
                        if (KeyUnavailability.isTransient(e) || KeyUnavailability.isPermanentKeyLoss(e)) {
                            throw e
                        }
                        // A permanently unpersistable buffered entry must not wedge the log.
                        droppedPendingEntries++
                    }
                    pendingEntries.removeFirst()
                }
                persistGapMarkerIfNeeded(entry.timestampEpochMs)
                persist(entry)
            } catch (ce: CancellationException) {
                throw ce
            } catch (e: Exception) {
                if (!KeyUnavailability.isTransient(e)) {
                    throw e
                }
                if (pendingEntries.size >= MAX_PENDING_ENTRIES) {
                    pendingEntries.removeFirst()
                    droppedPendingEntries++
                }
                pendingEntries.addLast(entry)
            }
        }
    }

    /**
     * Makes buffer losses visible in the durable trail: whenever entries were dropped (overflow or
     * an unpersistable record) since the last marker, writes one `AUDIT_BUFFER_GAP` entry before
     * the next real entry. Must be called while holding [pendingMutex].
     */
    private suspend fun persistGapMarkerIfNeeded(nowEpochMs: Long) {
        val unreported = droppedPendingEntries - reportedDroppedEntries
        if (unreported <= 0L) return
        persist(
            AuditLogEntry(
                timestampEpochMs = nowEpochMs,
                toolName = AUDIT_GAP_TOOL_NAME,
                targetId = AUDIT_GAP_TOOL_NAME,
                actionSummary = "Audit buffer dropped $unreported entries while the master key was unavailable",
                provenance = DataProvenance.SYSTEM,
                decision = DECISION_AUDIT_BUFFER_GAP
            )
        )
        reportedDroppedEntries = droppedPendingEntries
    }

    private suspend fun persist(entry: AuditLogEntry) {
        val lookupHmac = store.computeStructuredBlindIndex(DOMAIN_AUDIT_TARGET, entry.targetId)
        val encoded = encodeEntry(entry)
        SecureMemory.withZeroizedBytes(encoded) { payload ->
            store.insertEncrypted(
                tableName = EncryptedTableSchema.TABLE_AUDIT_LOGS,
                lookupHmac = lookupHmac,
                plaintext = payload,
                epochSec = entry.timestampEpochMs / 1000L,
                schemaVersion = AUDIT_SCHEMA_VERSION
            )
        }
    }

    override suspend fun queryRecent(limit: Int): List<AuditLogEntry> {
        if (limit <= 0) return emptyList()
        val rows = store.listRecentDecrypted(EncryptedTableSchema.TABLE_AUDIT_LOGS, limit)
        return try {
            val entries = ArrayList<AuditLogEntry>(rows.size)
            for (row in rows) {
                entries.add(decodeEntry(row))
            }
            entries.sortWith(NEWEST_FIRST_COMPARATOR)
            entries
        } finally {
            for (row in rows) {
                row.zeroize()
            }
        }
    }

    /**
     * Queries up to [limit] most recent audit entries for [targetId] using its `HMAC-SHA256`
     * structured blind index, ordered newest-first.
     */
    suspend fun queryByTarget(targetId: String, limit: Int): List<AuditLogEntry> {
        if (targetId.isBlank() || limit <= 0) return emptyList()
        val targetHmac = store.computeStructuredBlindIndex(DOMAIN_AUDIT_TARGET, targetId)
        val rows = store.listRecentDecryptedByBlindIndex(
            tableName = EncryptedTableSchema.TABLE_AUDIT_LOGS,
            lookupHmac = targetHmac,
            limit = limit
        )
        return try {
            val matching = ArrayList<AuditLogEntry>(rows.size)
            for (row in rows) {
                val entry = decodeEntry(row)
                if (entry.targetId == targetId) {
                    matching.add(entry)
                }
            }
            matching.sortWith(NEWEST_FIRST_COMPARATOR)
            matching
        } finally {
            for (row in rows) {
                row.zeroize()
            }
        }
    }

    private fun encodeEntry(entry: AuditLogEntry): ByteArray {
        return StructuredPayloadCodec.encode(formatVersion = AUDIT_SCHEMA_VERSION) {
            writeLong(entry.timestampEpochMs)
            writeString(entry.toolName)
            writeString(entry.targetId)
            writeString(entry.actionSummary)
            writeString(entry.provenance.name)
            writeString(entry.decision)
        }
    }

    private fun decodeEntry(row: DecryptedRow): AuditLogEntry {
        return StructuredPayloadCodec.decode(
            bytes = row.plaintext,
            expectedVersion = AUDIT_SCHEMA_VERSION
        ) {
            val timestampEpochMs = readLong()
            val toolName = readString()
            val targetId = readString()
            val actionSummary = readString()
            val provenance = DataProvenance.valueOf(readString())
            val decision = readString()
            AuditLogEntry(
                id = row.rowId,
                timestampEpochMs = timestampEpochMs,
                toolName = toolName,
                targetId = targetId,
                actionSummary = actionSummary,
                provenance = provenance,
                decision = decision
            )
        }
    }

    companion object {
        private const val DOMAIN_AUDIT_TARGET: String = "audit_target"
        private const val AUDIT_SCHEMA_VERSION: Int = 1
        private const val MAX_PENDING_ENTRIES: Int = 256
        const val AUDIT_GAP_TOOL_NAME: String = "audit_log"
        const val DECISION_AUDIT_BUFFER_GAP: String = "AUDIT_BUFFER_GAP"
        private val NEWEST_FIRST_COMPARATOR: Comparator<AuditLogEntry> =
            compareByDescending<AuditLogEntry> { it.timestampEpochMs }.thenByDescending { it.id }
    }
}

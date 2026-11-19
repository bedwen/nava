package com.nava.core.security.dao

import com.nava.core.security.crypto.SecureMemory
import com.nava.core.security.storage.DecryptedRow
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.storage.StructuredPayloadCodec
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.DataProvenance

/**
 * Encrypted persistent DAO implementing [AuditLogPort] over [EncryptedSqliteStore]
 * (`audit_logs` table) with blind-indexed target queries and immediate plaintext zeroization.
 */
class AuditLogDao(
    private val store: EncryptedSqliteStore
) : AuditLogPort {

    override suspend fun record(entry: AuditLogEntry) {
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
        private val NEWEST_FIRST_COMPARATOR: Comparator<AuditLogEntry> =
            compareByDescending<AuditLogEntry> { it.timestampEpochMs }.thenByDescending { it.id }
    }
}

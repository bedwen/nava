package com.nava.domain.security

/**
 * Structured security and automation execution record persisted in encrypted audit storage.
 */
data class AuditLogEntry(
    val id: Long = 0L,
    val timestampEpochMs: Long,
    val toolName: String,
    val targetId: String,
    val actionSummary: String,
    val provenance: DataProvenance,
    val decision: String
) {
    init {
        require(toolName.isNotBlank()) { "AuditLogEntry toolName must not be blank" }
        require(targetId.isNotBlank()) { "AuditLogEntry targetId must not be blank" }
        require(decision.isNotBlank()) { "AuditLogEntry decision must not be blank" }
    }
}

/**
 * Port for appending and querying encrypted audit records.
 */
interface AuditLogPort {
    suspend fun record(entry: AuditLogEntry)
    suspend fun queryRecent(limit: Int): List<AuditLogEntry>
}

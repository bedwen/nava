package com.nava.core.security.dao

import com.nava.core.security.crypto.SecureMemory
import com.nava.core.security.storage.DecryptedRow
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.storage.StructuredPayloadCodec
import com.nava.domain.automation.NotificationWatcher
import com.nava.domain.automation.NotificationWatcherPort
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * AES-256-GCM encrypted DAO for [NotificationWatcher] records persisted in
 * [EncryptedTableSchema.TABLE_NOTIFICATION_WATCHERS], implementing `:domain` [NotificationWatcherPort].
 *
 * Plaintext Metadata Minimization (PLAN.md Section 5.5):
 * Only synthetic `row_id`, `lookup_hmac`, `schema_version`, and coarse timestamps exist in SQLite
 * primitive columns; watcher labels, keywords, sender/package filters, and trigger counters are
 * encrypted inside `payload_blob` with row-bound AAD.
 */
class NotificationWatcherDao(
    private val store: EncryptedSqliteStore
) : NotificationWatcherPort {

    private val daoMutex = Mutex()

    override suspend fun saveWatcher(watcher: NotificationWatcher) {
        daoMutex.withLock {
            saveWatcherLocked(watcher)
        }
    }

    private suspend fun saveWatcherLocked(watcher: NotificationWatcher) {
        require('\u0000' !in watcher.watcherId) { "watcherId must not contain null characters" }
        val lookupHmac = store.computeBlindIndex(DOMAIN_WATCHER, watcher.watcherId)
        val encoded = encodeWatcher(watcher)
        val epochSec = (if (watcher.lastTriggeredEpochMs > 0L) watcher.lastTriggeredEpochMs else watcher.createdAtEpochMs) / 1000L
        SecureMemory.withZeroizedBytes(encoded) { payload ->
            store.upsertEncryptedByBlindIndex(
                tableName = EncryptedTableSchema.TABLE_NOTIFICATION_WATCHERS,
                lookupHmac = lookupHmac,
                plaintext = payload,
                epochSec = epochSec.coerceAtLeast(1L),
                schemaVersion = WATCHER_SCHEMA_VERSION
            )
        }
    }

    override suspend fun findWatcher(watcherId: String): NotificationWatcher? {
        if (watcherId.isBlank() || '\u0000' in watcherId) return null
        val lookupHmac = store.computeBlindIndex(DOMAIN_WATCHER, watcherId)
        val row = store.findDecryptedByBlindIndex(
            tableName = EncryptedTableSchema.TABLE_NOTIFICATION_WATCHERS,
            lookupHmac = lookupHmac
        ) ?: return null
        val decoded = try {
            decodeWatcher(row)
        } finally {
            row.zeroize()
        }
        return if (decoded.watcherId == watcherId) decoded else null
    }

    override suspend fun listWatchers(): List<NotificationWatcher> {
        val rows = store.listAllDecrypted(EncryptedTableSchema.TABLE_NOTIFICATION_WATCHERS)
        return try {
            val result = ArrayList<NotificationWatcher>(rows.size)
            for (row in rows) {
                result.add(decodeWatcher(row))
            }
            result.sortedWith(
                compareByDescending<NotificationWatcher> { it.enabled }
                    .thenByDescending { it.createdAtEpochMs }
                    .thenBy { it.watcherId }
            )
        } finally {
            for (row in rows) {
                row.zeroize()
            }
        }
    }

    override suspend fun listEnabledWatchers(): List<NotificationWatcher> {
        return listWatchers().filter { it.enabled }
    }

    override suspend fun setWatcherEnabled(watcherId: String, enabled: Boolean): Boolean {
        return daoMutex.withLock {
            val existing = findWatcher(watcherId) ?: return@withLock false
            saveWatcherLocked(existing.copy(enabled = enabled))
            true
        }
    }

    override suspend fun recordTrigger(watcherId: String, triggeredAtEpochMs: Long) {
        daoMutex.withLock {
            val existing = findWatcher(watcherId) ?: return@withLock
            saveWatcherLocked(
                existing.copy(
                    lastTriggeredEpochMs = triggeredAtEpochMs,
                    triggerCount = existing.triggerCount + 1
                )
            )
        }
    }

    override suspend fun deleteWatcher(watcherId: String): Boolean {
        if (watcherId.isBlank() || '\u0000' in watcherId) return false
        return daoMutex.withLock {
            val lookupHmac = store.computeBlindIndex(DOMAIN_WATCHER, watcherId)
            store.deleteByBlindIndex(
                tableName = EncryptedTableSchema.TABLE_NOTIFICATION_WATCHERS,
                lookupHmac = lookupHmac
            )
        }
    }

    private fun encodeWatcher(watcher: NotificationWatcher): ByteArray {
        return StructuredPayloadCodec.encode(formatVersion = WATCHER_SCHEMA_VERSION) {
            writeString(watcher.watcherId)
            writeString(watcher.label)
            writeString(watcher.keywords.joinToString(KEYWORD_SEPARATOR))
            writeString(watcher.senderFilter.orEmpty())
            writeString(watcher.packageFilter.orEmpty())
            writeString(watcher.enabled.toString())
            writeLong(watcher.createdAtEpochMs)
            writeLong(watcher.lastTriggeredEpochMs)
            writeLong(watcher.triggerCount.toLong())
        }
    }

    private fun decodeWatcher(row: DecryptedRow): NotificationWatcher {
        return StructuredPayloadCodec.decode(
            bytes = row.plaintext,
            expectedVersion = WATCHER_SCHEMA_VERSION
        ) {
            val id = readString()
            val label = readString().ifBlank { "Watcher" }
            val rawKeywords = readString()
            val keywords = if (rawKeywords.isBlank()) {
                emptyList()
            } else {
                rawKeywords.split(KEYWORD_SEPARATOR).map { it.trim() }.filter { it.isNotEmpty() }
            }
            val sender = readString().trim().takeIf { it.isNotEmpty() }
            val pkg = readString().trim().takeIf { it.isNotEmpty() }
            val enabled = readString().toBooleanStrictOrNull() ?: true
            val createdMs = readLong()
            val lastTriggeredMs = readLong()
            val triggerCount = readLong().toInt()
            NotificationWatcher(
                watcherId = id,
                label = label,
                keywords = keywords,
                senderFilter = sender,
                packageFilter = pkg,
                enabled = enabled,
                createdAtEpochMs = createdMs,
                lastTriggeredEpochMs = lastTriggeredMs,
                triggerCount = triggerCount
            )
        }
    }

    companion object {
        private const val DOMAIN_WATCHER: String = "notification_watcher"
        private const val WATCHER_SCHEMA_VERSION: Int = 1
        private const val MAX_WATCHER_LIST_LIMIT: Int = 200
        private const val KEYWORD_SEPARATOR: String = "\u001F"
    }
}

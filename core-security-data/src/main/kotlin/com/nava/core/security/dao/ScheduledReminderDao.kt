package com.nava.core.security.dao

import com.nava.core.security.crypto.SecureMemory
import com.nava.core.security.storage.DecryptedRow
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.storage.StructuredPayloadCodec
import com.nava.domain.automation.ReminderRecurrence
import com.nava.domain.automation.ReminderStatus
import com.nava.domain.automation.ScheduledReminder
import com.nava.domain.automation.ScheduledReminderPort
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * AES-256-GCM encrypted DAO for [ScheduledReminder] records persisted in
 * [EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS], implementing `:domain` [ScheduledReminderPort].
 *
 * Plaintext Metadata Minimization (PLAN.md Section 5.5):
 * Only synthetic `row_id`, `lookup_hmac`, `schema_version`, and coarse timestamps exist in SQLite
 * primitive columns; reminder title, message, trigger time, recurrence, and status are encrypted
 * inside `payload_blob` with row-bound AAD.
 */
class ScheduledReminderDao(
    private val store: EncryptedSqliteStore
) : ScheduledReminderPort {

    private val daoMutex = Mutex()

    override suspend fun saveReminder(reminder: ScheduledReminder) {
        daoMutex.withLock {
            saveReminderLocked(reminder)
        }
    }

    private suspend fun saveReminderLocked(reminder: ScheduledReminder) {
        require('\u0000' !in reminder.reminderId) { "reminderId must not contain null characters" }
        val lookupHmac = store.computeBlindIndex(DOMAIN_REMINDER, reminder.reminderId)
        val encoded = encodeReminder(reminder)
        val epochSec = (if (reminder.updatedAtEpochMs > 0L) reminder.updatedAtEpochMs else reminder.triggerAtEpochMs) / 1000L
        SecureMemory.withZeroizedBytes(encoded) { payload ->
            store.upsertEncryptedByBlindIndex(
                tableName = EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS,
                lookupHmac = lookupHmac,
                plaintext = payload,
                epochSec = epochSec.coerceAtLeast(1L),
                schemaVersion = REMINDER_SCHEMA_VERSION
            )
        }
    }

    override suspend fun findReminder(reminderId: String): ScheduledReminder? {
        if (reminderId.isBlank() || '\u0000' in reminderId) return null
        val lookupHmac = store.computeBlindIndex(DOMAIN_REMINDER, reminderId)
        val row = store.findDecryptedByBlindIndex(
            tableName = EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS,
            lookupHmac = lookupHmac
        ) ?: return null
        val decoded = try {
            decodeReminder(row)
        } finally {
            row.zeroize()
        }
        return if (decoded.reminderId == reminderId) decoded else null
    }

    override suspend fun listActiveReminders(): List<ScheduledReminder> {
        return listAllReminders()
            .filter { it.status == ReminderStatus.ACTIVE }
            .sortedWith(compareBy<ScheduledReminder> { it.triggerAtEpochMs }.thenBy { it.reminderId })
    }

    override suspend fun listAllReminders(): List<ScheduledReminder> {
        val rows = store.listAllDecrypted(EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS)
        return try {
            val reminders = ArrayList<ScheduledReminder>(rows.size)
            for (row in rows) {
                reminders.add(decodeReminder(row))
            }
            reminders.sortWith(compareBy<ScheduledReminder> { it.triggerAtEpochMs }.thenBy { it.reminderId })
            reminders
        } finally {
            for (row in rows) {
                row.zeroize()
            }
        }
    }

    override suspend fun updateStatus(
        reminderId: String,
        status: ReminderStatus,
        updatedAtEpochMs: Long
    ): Boolean = daoMutex.withLock {
        val existing = findReminder(reminderId) ?: return@withLock false
        saveReminderLocked(
            existing.copy(
                status = status,
                updatedAtEpochMs = updatedAtEpochMs
            )
        )
        true
    }

    override suspend fun deleteReminder(reminderId: String): Boolean = daoMutex.withLock {
        if (reminderId.isBlank() || '\u0000' in reminderId) return@withLock false
        val lookupHmac = store.computeBlindIndex(DOMAIN_REMINDER, reminderId)
        store.deleteByBlindIndex(
            tableName = EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS,
            lookupHmac = lookupHmac
        )
    }

    private fun encodeReminder(reminder: ScheduledReminder): ByteArray {
        return StructuredPayloadCodec.encode(formatVersion = REMINDER_SCHEMA_VERSION) {
            writeString(reminder.reminderId)
            writeString(reminder.title)
            writeString(reminder.message)
            writeLong(reminder.triggerAtEpochMs)
            writeString(reminder.recurrence.name)
            writeString(reminder.status.name)
            writeLong(reminder.createdAtEpochMs)
            writeLong(reminder.updatedAtEpochMs)
        }
    }

    private fun decodeReminder(row: DecryptedRow): ScheduledReminder {
        return StructuredPayloadCodec.decode(
            bytes = row.plaintext,
            expectedVersion = REMINDER_SCHEMA_VERSION
        ) {
            ScheduledReminder(
                reminderId = readString(),
                title = readString(),
                message = readString(),
                triggerAtEpochMs = readLong(),
                recurrence = runCatching { ReminderRecurrence.valueOf(readString()) }
                    .getOrDefault(ReminderRecurrence.ONCE),
                status = runCatching { ReminderStatus.valueOf(readString()) }
                    .getOrDefault(ReminderStatus.ACTIVE),
                createdAtEpochMs = readLong(),
                updatedAtEpochMs = readLong()
            )
        }
    }

    companion object {
        private const val DOMAIN_REMINDER: String = "reminder"
        private const val REMINDER_SCHEMA_VERSION: Int = 1
    }
}

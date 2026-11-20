package com.nava.feature.automations.notification

import com.nava.domain.automation.CapturedNotification
import com.nava.domain.automation.NotificationInboxPort
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Thread-safe, bounded ring-buffer implementation of [NotificationInboxPort].
 *
 * Invariants:
 * - Strictly in-memory: notifications are never written to unencrypted disk or persistent storage.
 * - Sanitization: title and body content pass through [Gemma4InputSanitizer] to strip control tokens.
 * - Provenance: all stored notifications strictly enforce [DataProvenance.UNTRUSTED_EXTERNAL].
 * - Bounded buffer: oldest notifications are evicted when [maxCapacity] is exceeded.
 */
class InMemoryNotificationInbox(
    val maxCapacity: Int = DEFAULT_CAPACITY
) : NotificationInboxPort {

    init {
        require(maxCapacity > 0) { "maxCapacity must be positive, got $maxCapacity" }
    }

    private val mutex = Mutex()
    // LinkedHashMap preserves insertion order (oldest at head, newest at tail).
    private val buffer = LinkedHashMap<String, CapturedNotification>(maxCapacity)

    override suspend fun ingest(notification: CapturedNotification) = mutex.withLock {
        val sanitizedTitle = Gemma4InputSanitizer.sanitizeExternal(
            rawExternalInput = notification.title.value,
            slotKind = SensitiveSlotKind.TEXT_BODY,
            sourceLabel = notification.packageName
        )
        val sanitizedBody = Gemma4InputSanitizer.sanitizeExternal(
            rawExternalInput = notification.body.value,
            slotKind = SensitiveSlotKind.TEXT_BODY,
            sourceLabel = notification.packageName
        )

        val sanitizedNotification = CapturedNotification(
            notificationKey = notification.notificationKey,
            packageName = notification.packageName,
            title = sanitizedTitle,
            body = sanitizedBody,
            postedAtEpochMs = notification.postedAtEpochMs,
            channelId = notification.channelId
        )

        // If key already present, remove it so re-insertion places it at the tail (newest).
        buffer.remove(sanitizedNotification.notificationKey)

        while (buffer.size >= maxCapacity) {
            val oldestKey = buffer.keys.firstOrNull() ?: break
            buffer.remove(oldestKey)
        }

        buffer[sanitizedNotification.notificationKey] = sanitizedNotification
    }

    override suspend fun removeByKey(notificationKey: String): Boolean = mutex.withLock {
        buffer.remove(notificationKey) != null
    }

    override suspend fun listRecent(
        packageFilter: Set<String>?,
        sinceEpochMs: Long?,
        limit: Int
    ): List<CapturedNotification> = mutex.withLock {
        if (limit <= 0) return emptyList()

        val results = ArrayList<CapturedNotification>(minOf(limit, buffer.size))
        val iterator = buffer.values.toList().asReversed().iterator()

        while (iterator.hasNext() && results.size < limit) {
            val item = iterator.next()
            if (packageFilter != null && item.packageName !in packageFilter) {
                continue
            }
            if (sinceEpochMs != null && item.postedAtEpochMs < sinceEpochMs) {
                continue
            }
            results.add(item)
        }

        results
    }

    override suspend fun clearForPackage(packageName: String): Int = mutex.withLock {
        var removedCount = 0
        val iterator = buffer.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.value.packageName == packageName) {
                iterator.remove()
                removedCount++
            }
        }
        removedCount
    }

    override suspend fun clearAll(): Unit = mutex.withLock {
        buffer.clear()
    }

    suspend fun size(): Int = mutex.withLock {
        buffer.size
    }

    companion object {
        const val DEFAULT_CAPACITY: Int = 100
    }
}

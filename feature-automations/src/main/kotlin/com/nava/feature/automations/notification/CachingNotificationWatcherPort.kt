package com.nava.feature.automations.notification

import com.nava.domain.automation.NotificationWatcher
import com.nava.domain.automation.NotificationWatcherPort
import kotlinx.coroutines.CancellationException

/**
 * [NotificationWatcherPort] decorator that keeps an in-memory snapshot of enabled watchers so
 * notifications that arrive while the device is locked can still be evaluated: the encrypted
 * watcher store cannot be decrypted then (`nava_db_master_key` uses
 * `setUnlockedDeviceRequired(true)`).
 *
 * Every mutation goes through this decorator and refreshes the snapshot right after it succeeds,
 * so a watcher deleted or disabled while unlocked can never keep firing from a stale snapshot.
 * Reads always try the store first; only when the store fails is the last snapshot served.
 * The snapshot holds watcher configuration only (labels, keywords, filters), never notification
 * content.
 */
class CachingNotificationWatcherPort(
    private val delegate: NotificationWatcherPort
) : NotificationWatcherPort {

    @Volatile
    private var enabledSnapshot: List<NotificationWatcher>? = null

    /** Loads the snapshot while the store is readable (call once after startup). */
    suspend fun warmUp() {
        refreshSnapshot()
    }

    override suspend fun listEnabledWatchers(): List<NotificationWatcher> {
        return try {
            delegate.listEnabledWatchers().also { enabledSnapshot = it }
        } catch (ce: CancellationException) {
            throw ce
        } catch (e: Exception) {
            enabledSnapshot ?: throw e
        }
    }

    override suspend fun saveWatcher(watcher: NotificationWatcher) {
        delegate.saveWatcher(watcher)
        refreshAfterMutation()
    }

    override suspend fun setWatcherEnabled(watcherId: String, enabled: Boolean): Boolean {
        return delegate.setWatcherEnabled(watcherId, enabled).also { refreshAfterMutation() }
    }

    override suspend fun deleteWatcher(watcherId: String): Boolean {
        return delegate.deleteWatcher(watcherId).also { refreshAfterMutation() }
    }

    override suspend fun findWatcher(watcherId: String): NotificationWatcher? =
        delegate.findWatcher(watcherId)

    override suspend fun listWatchers(): List<NotificationWatcher> = delegate.listWatchers()

    override suspend fun recordTrigger(watcherId: String, triggeredAtEpochMs: Long) {
        delegate.recordTrigger(watcherId, triggeredAtEpochMs)
    }

    private suspend fun refreshAfterMutation() {
        if (!refreshSnapshot()) {
            // The mutation succeeded but the re-read did not: drop the snapshot rather than keep
            // one that may still contain a deleted or disabled watcher (fail closed).
            enabledSnapshot = null
        }
    }

    private suspend fun refreshSnapshot(): Boolean {
        return try {
            enabledSnapshot = delegate.listEnabledWatchers()
            true
        } catch (ce: CancellationException) {
            throw ce
        } catch (_: Exception) {
            false
        }
    }
}

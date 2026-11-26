package com.nava.domain.automation

/**
 * User-defined proactive notification watcher rule persisted in AES-256-GCM storage.
 *
 * Security & battery invariants (PLAN.md 5.5, 5.7, Iron Laws 5 & 6):
 * - Evaluated strictly AFTER Default-Deny `NOTIFICATION_READ` filtering confirms the source
 *   package is permitted.
 * - 100% passive alert-only: matching an `UNTRUSTED_EXTERNAL` notification may only post a
 *   read-only local alert notification to the user; it can never invoke tools or mutate state.
 * - Zero background polling or LLM wakeups on match (0% idle battery drain).
 */
data class NotificationWatcher(
    val watcherId: String,
    val label: String,
    val keywords: List<String> = emptyList(),
    val senderFilter: String? = null,
    val packageFilter: String? = null,
    val enabled: Boolean = true,
    val createdAtEpochMs: Long = 0L,
    val lastTriggeredEpochMs: Long = 0L,
    val triggerCount: Int = 0
) {
    init {
        require(watcherId.isNotBlank()) { "watcherId must not be blank" }
        require(label.isNotBlank()) { "label must not be blank" }
    }
}

/**
 * Pure Kotlin encrypted persistence port for [NotificationWatcher] records.
 */
interface NotificationWatcherPort {
    suspend fun saveWatcher(watcher: NotificationWatcher)
    suspend fun findWatcher(watcherId: String): NotificationWatcher?
    suspend fun listWatchers(): List<NotificationWatcher>
    suspend fun listEnabledWatchers(): List<NotificationWatcher>
    suspend fun setWatcherEnabled(watcherId: String, enabled: Boolean): Boolean
    suspend fun recordTrigger(watcherId: String, triggeredAtEpochMs: Long)
    suspend fun deleteWatcher(watcherId: String): Boolean
}

/**
 * Pure Kotlin alert poster port invoked when a permitted incoming notification matches an
 * active [NotificationWatcher]. Strictly passive (local alert notification only).
 */
fun interface NotificationWatcherAlertPort {
    fun postWatcherAlert(
        watcher: NotificationWatcher,
        sourcePackageName: String,
        title: String,
        snippet: String
    )
}

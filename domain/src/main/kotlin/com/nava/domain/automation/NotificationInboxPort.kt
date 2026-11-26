package com.nava.domain.automation

import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Tainted

/**
 * In-memory snapshot of a notification captured from a package explicitly granted
 * `NOTIFICATION_READ` in its [com.nava.domain.security.PermissionProfile].
 *
 * Security invariant: notification title and body always carry [DataProvenance.UNTRUSTED_EXTERNAL]
 * so downstream summarization or Stage 2 extraction can never treat notification text as trusted
 * user intent.
 *
 * [senderHints] holds sender identity extracted from structured notification metadata (for
 * example `Notification.EXTRA_PEOPLE_LIST` names and `mailto:`/`tel:` addresses), kept separate
 * from [body] so sender-based matching never trusts free text written by whoever sent the message.
 */
data class CapturedNotification(
    val notificationKey: String,
    val packageName: String,
    val title: Tainted<String>,
    val body: Tainted<String>,
    val postedAtEpochMs: Long,
    val channelId: String? = null,
    val senderHints: Tainted<String>? = null
) {
    init {
        require(notificationKey.isNotBlank()) { "CapturedNotification notificationKey must not be blank" }
        require(packageName.isNotBlank()) { "CapturedNotification packageName must not be blank" }
        require(title.provenance == DataProvenance.UNTRUSTED_EXTERNAL) {
            "CapturedNotification title must carry UNTRUSTED_EXTERNAL provenance"
        }
        require(body.provenance == DataProvenance.UNTRUSTED_EXTERNAL) {
            "CapturedNotification body must carry UNTRUSTED_EXTERNAL provenance"
        }
        require(senderHints == null || senderHints.provenance == DataProvenance.UNTRUSTED_EXTERNAL) {
            "CapturedNotification senderHints must carry UNTRUSTED_EXTERNAL provenance"
        }
    }
}

/**
 * Bounded in-memory inbox shared between `NavaNotificationListenerService` and
 * `NotificationSummaryTool`.
 *
 * Notifications from `DENIED` packages must be dropped in memory before extraction and must
 * never be passed to [ingest].
 */
interface NotificationInboxPort {
    /** Records a notification from an already-authorized source package. */
    suspend fun ingest(notification: CapturedNotification)

    /** Removes a previously captured notification when dismissed by the user or system. */
    suspend fun removeByKey(notificationKey: String): Boolean

    /**
     * Lists recent captured notifications ordered newest-first (`postedAtEpochMs DESC`).
     *
     * @param packageFilter Optional set of package names to include; null includes all captured packages.
     * @param sinceEpochMs Optional inclusive lower timestamp bound in epoch milliseconds.
     * @param limit Maximum number of notifications to return (non-positive returns empty list).
     */
    suspend fun listRecent(
        packageFilter: Set<String>? = null,
        sinceEpochMs: Long? = null,
        limit: Int = DEFAULT_LIMIT
    ): List<CapturedNotification>

    /** Purges all buffered notifications for [packageName] (e.g., on permission revocation). */
    suspend fun clearForPackage(packageName: String): Int

    /** Purges all buffered notifications from memory. */
    suspend fun clearAll()

    companion object {
        const val DEFAULT_LIMIT: Int = 50
    }
}

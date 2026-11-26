package com.nava.feature.automations.notification

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.automation.CapturedNotification
import com.nava.domain.automation.NotificationInboxPort
import com.nava.domain.automation.NotificationWatcher
import com.nava.domain.automation.NotificationWatcherAlertPort
import com.nava.domain.automation.NotificationWatcherPort
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.PermissionEvaluatorPort
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolResult
import com.nava.feature.automations.common.ToolTargetIds
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NotificationWatcherTest {

    private class InMemoryWatcherPort : NotificationWatcherPort {
        val map = LinkedHashMap<String, NotificationWatcher>()
        override suspend fun saveWatcher(watcher: NotificationWatcher) {
            map[watcher.watcherId] = watcher
        }
        override suspend fun findWatcher(watcherId: String): NotificationWatcher? = map[watcherId]
        override suspend fun listWatchers(): List<NotificationWatcher> = map.values.toList()
        override suspend fun listEnabledWatchers(): List<NotificationWatcher> =
            map.values.filter { it.enabled }
        override suspend fun setWatcherEnabled(watcherId: String, enabled: Boolean): Boolean {
            val w = map[watcherId] ?: return false
            map[watcherId] = w.copy(enabled = enabled)
            return true
        }
        override suspend fun recordTrigger(watcherId: String, triggeredAtEpochMs: Long) {
            val w = map[watcherId] ?: return
            map[watcherId] = w.copy(
                lastTriggeredEpochMs = triggeredAtEpochMs,
                triggerCount = w.triggerCount + 1
            )
        }
        override suspend fun deleteWatcher(watcherId: String): Boolean = map.remove(watcherId) != null
    }

    private class NoOpAuditLog : AuditLogPort {
        override suspend fun record(entry: AuditLogEntry) = Unit
        override suspend fun queryRecent(limit: Int): List<AuditLogEntry> = emptyList()
    }

    private class InMemoryInbox : NotificationInboxPort {
        val items = mutableListOf<CapturedNotification>()
        override suspend fun ingest(notification: CapturedNotification) {
            items.add(notification)
        }
        override suspend fun removeByKey(notificationKey: String): Boolean =
            items.removeAll { it.notificationKey == notificationKey }
        override suspend fun listRecent(
            packageFilter: Set<String>?,
            sinceEpochMs: Long?,
            limit: Int
        ): List<CapturedNotification> = items.take(limit)
        override suspend fun clearForPackage(packageName: String): Int {
            val before = items.size
            items.removeAll { it.packageName == packageName }
            return before - items.size
        }
        override suspend fun clearAll() {
            items.clear()
        }
    }

    private fun testContext() = ToolExecutionContext(
        requestId = "req_watch_test",
        languageTag = "tr",
        targetId = ToolTargetIds.NOTIFICATIONS,
        capabilityToken = com.nava.domain.security.CapabilityToken.mint(
            tokenId = "tok_watch_test",
            requestId = "req_watch_test",
            allowedTools = setOf(
                com.nava.feature.automations.common.AutomationToolNames.CREATE_NOTIFICATION_WATCHER,
                com.nava.feature.automations.common.AutomationToolNames.MANAGE_NOTIFICATION_WATCHERS
            ),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = 1_700_000_000_000L,
            expiresAtEpochMs = 1_700_000_060_000L,
            maxToolCalls = 2
        ),
        ruleGrant = null,
        issuedAtEpochMs = 1_700_000_000_000L,
        isUserConfirmed = true,
        isUnattendedBackground = false
    )

    private fun userString(value: String): Tainted<SlotValueAst> = Tainted.fromUserUtterance(
        value = SlotValueAst.StringValue(value),
        slotKind = SensitiveSlotKind.TEXT_BODY
    )

    private fun extText(value: String, pkg: String): Tainted<String> = Tainted.fromUntrustedExternal(
        value = value,
        slotKind = SensitiveSlotKind.TEXT_BODY,
        sourceLabel = pkg
    )

    @Test
    fun matcherHandlesDiacriticsAndAppAliases() {
        val watcher = NotificationWatcher(
            watcherId = "watch_1",
            label = "Fatura Takibi",
            keywords = listOf("fatura", "odeme"),
            senderFilter = "elektrik",
            packageFilter = "gmail",
            enabled = true
        )
        val matching = CapturedNotification(
            notificationKey = "k1",
            packageName = "com.google.android.gm",
            title = extText("Elektrik Faturas\u0131", "com.google.android.gm"),
            body = extText("Son \u00F6deme tarihi yar\u0131n", "com.google.android.gm"),
            postedAtEpochMs = 1000L
        )
        val wrongApp = matching.copy(packageName = "com.whatsapp")
        assertTrue(NotificationWatcherMatcher.matches(watcher, matching))
        assertFalse(NotificationWatcherMatcher.matches(watcher, wrongApp))
    }

    @Test
    fun deniedPackageNeverTriggersWatcherEngine() = runTest {
        val watcherPort = InMemoryWatcherPort()
        watcherPort.saveWatcher(
            NotificationWatcher(
                watcherId = "watch_deny",
                label = "Urgent",
                keywords = listOf("urgent"),
                enabled = true
            )
        )
        var alertCount = 0
        val engine = NotificationWatcherEngine(
            watcherPort = watcherPort,
            alertPort = NotificationWatcherAlertPort { _, _, _, _ -> alertCount++ },
            clockMs = { 10_000L }
        )
        val denyAllEvaluator = object : PermissionEvaluatorPort {
            override suspend fun evaluateCapability(targetId: String, capability: AtomicCapability) =
                ConfirmationLevel.DISABLED
            override suspend fun getProfileForTarget(targetId: String) = PermissionProfile.defaultDeny()
            override suspend fun listProfiles() = listOf(PermissionProfile.defaultDeny())
            override suspend fun saveProfile(profile: PermissionProfile) = Unit
            override suspend fun assignTargetToProfile(targetId: String, profileId: String) = Unit
            override suspend fun deleteProfile(profileId: String) = Unit
        }

        val filter = NotificationIngestionFilter(
            permissionEvaluator = denyAllEvaluator,
            inbox = InMemoryInbox(),
            onLiveIngested = { engine.onLiveNotificationIngested(it) }
        )
        var extractorCalled = false
        val accepted = filter.onPosted(
            notificationKey = "k_denied",
            packageName = "com.google.android.gm",
            postedAtEpochMs = 10_000L
        ) {
            extractorCalled = true
            "Urgent" to "Urgent payment due"
        }

        assertFalse(accepted)
        assertFalse(extractorCalled)
        assertEquals(0, alertCount)
    }

    @Test
    fun watcherEngineDeduplicatesWithinCooldownWindow() = runTest {
        val watcherPort = InMemoryWatcherPort()
        watcherPort.saveWatcher(
            NotificationWatcher(
                watcherId = "watch_cd",
                label = "Kargo",
                keywords = listOf("kargo"),
                enabled = true
            )
        )
        var now = 100_000L
        var alertCount = 0
        val engine = NotificationWatcherEngine(
            watcherPort = watcherPort,
            alertPort = NotificationWatcherAlertPort { _, _, _, _ -> alertCount++ },
            clockMs = { now }
        )
        val notif = CapturedNotification(
            notificationKey = "same_key",
            packageName = "com.google.android.gm",
            title = extText("Kargo yolda", "com.google.android.gm"),
            body = extText("Teslimat bug\u00FCn", "com.google.android.gm"),
            postedAtEpochMs = now
        )

        engine.onLiveNotificationIngested(notif)
        assertEquals(1, alertCount)

        // Second identical notification within 30s cooldown is suppressed
        now += 5_000L
        engine.onLiveNotificationIngested(notif)
        assertEquals(1, alertCount)

        // After cooldown expires, fires again
        now += NotificationWatcherEngine.DEDUP_COOLDOWN_MS + 1_000L
        engine.onLiveNotificationIngested(notif)
        assertEquals(2, alertCount)
    }

    @Test
    fun createAndManageWatcherToolsWorkEndToEnd() = runTest {
        val port = InMemoryWatcherPort()
        val createTool = CreateNotificationWatcherTool(port, NoOpAuditLog(), clockMs = { 50_000L })
        val manageTool = ManageNotificationWatchersTool(port, NoOpAuditLog(), clockMs = { 51_000L })

        val createResult = createTool.execute(
            context = testContext(),
            arguments = mapOf(
                "keywords" to userString("fatura, kargo"),
                "app_name" to userString("gmail")
            )
        )
        assertTrue(createResult is ToolResult.Success)
        assertEquals(1, port.listWatchers().size)

        val listResult = manageTool.execute(
            context = testContext(),
            arguments = mapOf(
                "operation" to userString("LIST")
            )
        )
        assertTrue(listResult is ToolResult.Success)
        assertEquals("1", (listResult as ToolResult.Success).outputValues["count"])

        val deleteResult = manageTool.execute(
            context = testContext(),
            arguments = mapOf(
                "operation" to userString("DELETE"),
                "watcher_id" to userString("fatura")
            )
        )
        assertTrue(deleteResult is ToolResult.Success)
        assertEquals(0, port.listWatchers().size)
    }

    @Test
    fun emailAddressFilterMatchesGmailDisplayNameNotifications() {
        val singleNameWatcher = NotificationWatcher(
            watcherId = "watch_email_1",
            label = "Sender Email",
            keywords = listOf("alice.smith@gmail.com"),
            senderFilter = "alice.smith@gmail.com",
            packageFilter = "Gmail",
            enabled = true
        )
        val gmailNotif = CapturedNotification(
            notificationKey = "gm_1",
            packageName = "com.google.android.gm",
            title = extText("Alice Smith", "com.google.android.gm"),
            body = extText("Meeting tomorrow at 10", "com.google.android.gm"),
            postedAtEpochMs = 2_000L
        )
        assertTrue(NotificationWatcherMatcher.matches(singleNameWatcher, gmailNotif))

        val multiWordWatcher = NotificationWatcher(
            watcherId = "watch_email_2",
            label = "Professor Email",
            keywords = listOf("firstsecond.lastname@university.edu.tr"),
            senderFilter = "firstsecond.lastname@university.edu.tr",
            packageFilter = "mail",
            enabled = true
        )
        val uniNotif = CapturedNotification(
            notificationKey = "gm_2",
            packageName = "com.google.android.gm",
            title = extText("First Second Lastname", "com.google.android.gm"),
            body = extText("Exam schedule posted", "com.google.android.gm"),
            postedAtEpochMs = 3_000L
        )
        assertTrue(NotificationWatcherMatcher.matches(multiWordWatcher, uniNotif))
    }

    @Test
    fun watcherEngineUsesCachedSnapshotWhenKeystoreIsLocked() = runTest {
        var locked = false
        val inner = InMemoryWatcherPort()
        inner.saveWatcher(
            NotificationWatcher(
                watcherId = "watch_lock",
                label = "Lock Screen Test",
                keywords = listOf("invoice"),
                enabled = true
            )
        )
        val lockablePort = object : NotificationWatcherPort by inner {
            override suspend fun listEnabledWatchers(): List<NotificationWatcher> {
                if (locked) throw SecurityException("Device is locked")
                return inner.listEnabledWatchers()
            }
        }
        var alertCount = 0
        val cachingPort = CachingNotificationWatcherPort(lockablePort)
        val engine = NotificationWatcherEngine(
            watcherPort = cachingPort,
            alertPort = NotificationWatcherAlertPort { _, _, _, _ -> alertCount++ },
            clockMs = { 90_000L }
        )

        // Warm cache while unlocked
        cachingPort.warmUp()

        // Simulate device locked when email arrives
        locked = true
        val notif = CapturedNotification(
            notificationKey = "gm_locked",
            packageName = "com.google.android.gm",
            title = extText("Billing", "com.google.android.gm"),
            body = extText("Your invoice is ready", "com.google.android.gm"),
            postedAtEpochMs = 90_000L
        )
        engine.onLiveNotificationIngested(notif)
        assertEquals(1, alertCount)
    }

    private fun gmail(title: String, body: String, sender: String? = null, key: String = "gm_x") =
        CapturedNotification(
            notificationKey = key,
            packageName = "com.google.android.gm",
            title = extText(title, "com.google.android.gm"),
            body = extText(body, "com.google.android.gm"),
            postedAtEpochMs = 5_000L,
            senderHints = sender?.let { extText(it, "com.google.android.gm") }
        )

    private fun senderWatcher(sender: String, keywords: List<String> = emptyList()) = NotificationWatcher(
        watcherId = "w_${sender.hashCode()}",
        label = "Sender",
        keywords = keywords,
        senderFilter = sender,
        enabled = true
    )

    @Test
    fun senderFilterIgnoresNamesWrittenInTheBody() {
        val watcher = senderWatcher("Nezih Erbay")
        assertFalse(
            "a stranger typing the watched name into the body must not match",
            NotificationWatcherMatcher.matches(watcher, gmail("Spam Sender", "Hi, I am Nezih Erbay, wire money"))
        )
        assertTrue(NotificationWatcherMatcher.matches(watcher, gmail("Nezih Erbay", "Lunch?")))
        assertTrue(
            "structured sender metadata counts as sender identity",
            NotificationWatcherMatcher.matches(watcher, gmail("Project group", "Update", sender = "Nezih Erbay"))
        )
    }

    @Test
    fun emailTokensMatchWholeWordsOnly() {
        assertFalse(
            "short local-part tokens must not match inside other words",
            NotificationWatcherMatcher.matches(senderWatcher("ed@example.com"), gmail("Needed Reddy", "x"))
        )
        assertFalse(
            "tokens must not match as a substring of a longer word",
            NotificationWatcherMatcher.matches(senderWatcher("ali.can@example.com"), gmail("Alican Kalinin", "x"))
        )
        assertTrue(
            "trailing digits in the local part are ignored",
            NotificationWatcherMatcher.matches(senderWatcher("john.doe92@example.com"), gmail("John Doe", "x"))
        )
        assertTrue(
            "full address in structured sender metadata matches",
            NotificationWatcherMatcher.matches(
                senderWatcher("nerbay@example.com"),
                gmail("Nezih", "x", sender = "Nezih nerbay@example.com")
            )
        )
    }

    @Test
    fun singleWordKeywordsNeverMatchAcrossWordBoundaries() {
        val watcher = NotificationWatcher(
            watcherId = "w_pay",
            label = "Pay",
            keywords = listOf("pay"),
            enabled = true
        )
        assertFalse(NotificationWatcherMatcher.matches(watcher, gmail("Shop", "go to top ay now")))
        assertTrue(NotificationWatcherMatcher.matches(watcher, gmail("Shop", "Payment due")))
        val multi = watcher.copy(watcherId = "w_multi", keywords = listOf("nezih erbay"))
        assertTrue(NotificationWatcherMatcher.matches(multi, gmail("NezihErbay", "x")))
    }

    @Test
    fun cachingPortNeverServesWatchersDeletedOrDisabledBeforeLock() = runTest {
        var locked = false
        val inner = InMemoryWatcherPort()
        val lockable = object : NotificationWatcherPort by inner {
            override suspend fun listEnabledWatchers(): List<NotificationWatcher> {
                if (locked) throw SecurityException("Device is locked")
                return inner.listEnabledWatchers()
            }
        }
        val port = CachingNotificationWatcherPort(lockable)
        port.saveWatcher(NotificationWatcher(watcherId = "a", label = "A", keywords = listOf("invoice"), enabled = true))
        port.saveWatcher(NotificationWatcher(watcherId = "b", label = "B", keywords = listOf("bill"), enabled = true))
        port.deleteWatcher("a")
        port.setWatcherEnabled("b", false)

        locked = true
        assertTrue(port.listEnabledWatchers().isEmpty())
    }

    @Test
    fun cachingPortDropsSnapshotWhenPostMutationReadFails() = runTest {
        var locked = false
        val inner = InMemoryWatcherPort()
        val lockable = object : NotificationWatcherPort by inner {
            override suspend fun listEnabledWatchers(): List<NotificationWatcher> {
                if (locked) throw SecurityException("Device is locked")
                return inner.listEnabledWatchers()
            }
        }
        val port = CachingNotificationWatcherPort(lockable)
        port.saveWatcher(NotificationWatcher(watcherId = "a", label = "A", keywords = listOf("invoice"), enabled = true))
        assertEquals(1, port.listEnabledWatchers().size)

        locked = true
        port.deleteWatcher("a") // succeeds in the store, but the snapshot cannot be re-read
        try {
            port.listEnabledWatchers()
            org.junit.Assert.fail("a possibly stale snapshot must not be served")
        } catch (_: SecurityException) {
            // expected: fail closed
        }
    }
}

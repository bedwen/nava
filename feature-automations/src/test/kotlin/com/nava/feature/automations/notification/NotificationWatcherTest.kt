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
}

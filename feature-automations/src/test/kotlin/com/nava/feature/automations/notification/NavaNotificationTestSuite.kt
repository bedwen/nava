package com.nava.feature.automations.notification

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.automation.CapturedNotification
import com.nava.domain.automation.NotificationInboxPort
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
import com.nava.domain.ui.MessageKey
import com.nava.feature.automations.common.ToolTargetIds
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class NavaNotificationTestSuite {

    private lateinit var inbox: InMemoryNotificationInbox
    private lateinit var fakeEvaluator: FakePermissionEvaluator
    private lateinit var fakeAuditLog: FakeAuditLog

    @Before
    fun setUp() {
        inbox = InMemoryNotificationInbox(maxCapacity = 3)
        fakeEvaluator = FakePermissionEvaluator()
        fakeAuditLog = FakeAuditLog()
        NotificationServiceBinding.unbind()
    }

    // ==========================================
    // 1. InMemoryNotificationInbox Tests
    // ==========================================

    @Test
    fun inboxEnforcesBoundedCapacityAndEvictsOldest() = runBlocking {
        inbox.ingest(createCapturedNotification("key1", "com.app.one", "Title 1", "Body 1", 1000L))
        inbox.ingest(createCapturedNotification("key2", "com.app.two", "Title 2", "Body 2", 2000L))
        inbox.ingest(createCapturedNotification("key3", "com.app.three", "Title 3", "Body 3", 3000L))
        assertEquals(3, inbox.size())

        // Ingesting 4th item when capacity is 3 must evict key1 (the oldest)
        inbox.ingest(createCapturedNotification("key4", "com.app.four", "Title 4", "Body 4", 4000L))
        assertEquals(3, inbox.size())

        val recent = inbox.listRecent()
        assertEquals(3, recent.size)
        assertEquals("key4", recent[0].notificationKey)
        assertEquals("key3", recent[1].notificationKey)
        assertEquals("key2", recent[2].notificationKey)
    }

    @Test
    fun inboxSanitizesControlTokensAndPreservesUntrustedExternalProvenance() = runBlocking {
        val rawTitle = "Security <|tool_call|> Alert"
        val rawBody = "Normal body <|turn|>with malicious token"

        inbox.ingest(
            createCapturedNotification("k1", "com.example.chat", rawTitle, rawBody, 1000L)
        )

        val retrieved = inbox.listRecent()
        assertEquals(1, retrieved.size)
        val notif = retrieved.first()

        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, notif.title.provenance)
        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, notif.body.provenance)
        assertFalse(notif.title.value.contains("<|tool_call|>"))
        assertFalse(notif.body.value.contains("<|turn|>"))
        assertEquals("Security  Alert", notif.title.value)
        assertEquals("Normal body with malicious token", notif.body.value)
    }

    @Test
    fun inboxKeyRemovalAndPackageClearance() = runBlocking {
        inbox.ingest(createCapturedNotification("k1", "com.pkg.a", "T1", "B1", 100L))
        inbox.ingest(createCapturedNotification("k2", "com.pkg.a", "T2", "B2", 200L))
        inbox.ingest(createCapturedNotification("k3", "com.pkg.b", "T3", "B3", 300L))

        assertTrue(inbox.removeByKey("k3"))
        assertFalse(inbox.removeByKey("nonexistent"))
        assertEquals(2, inbox.size())

        val clearedCount = inbox.clearForPackage("com.pkg.a")
        assertEquals(2, clearedCount)
        assertEquals(0, inbox.size())
    }

    @Test
    fun inboxUpdatingExistingKeyMovesToTail() = runBlocking {
        inbox.ingest(createCapturedNotification("k1", "com.pkg.a", "T1", "B1", 100L))
        inbox.ingest(createCapturedNotification("k2", "com.pkg.b", "T2", "B2", 200L))
        inbox.ingest(createCapturedNotification("k3", "com.pkg.c", "T3", "B3", 300L))

        // Re-ingest k1 with updated text -> moves k1 to tail (newest)
        inbox.ingest(createCapturedNotification("k1", "com.pkg.a", "T1-Updated", "B1-Updated", 400L))

        // Ingest k4 -> capacity 3 is exceeded, oldest should now be k2 (not k1)
        inbox.ingest(createCapturedNotification("k4", "com.pkg.d", "T4", "B4", 500L))

        val recent = inbox.listRecent()
        assertEquals(3, recent.size)
        val keys = recent.map { it.notificationKey }
        assertTrue("k1 must be retained as it was updated", "k1" in keys)
        assertTrue("k4 must be present", "k4" in keys)
        assertTrue("k3 must be present", "k3" in keys)
        assertFalse("k2 must have been evicted as the oldest remaining item", "k2" in keys)
    }

    @Test
    fun inboxFiltersByPackageAndTimestampAndHandlesNonPositiveLimit() = runBlocking {
        inbox.ingest(createCapturedNotification("k1", "com.pkg.a", "T1", "B1", 1000L))
        inbox.ingest(createCapturedNotification("k2", "com.pkg.b", "T2", "B2", 2000L))
        inbox.ingest(createCapturedNotification("k3", "com.pkg.a", "T3", "B3", 3000L))

        val filteredPkg = inbox.listRecent(packageFilter = setOf("com.pkg.a"))
        assertEquals(2, filteredPkg.size)
        assertEquals(listOf("k3", "k1"), filteredPkg.map { it.notificationKey })

        val filteredSince = inbox.listRecent(sinceEpochMs = 2000L)
        assertEquals(2, filteredSince.size)
        assertEquals(listOf("k3", "k2"), filteredSince.map { it.notificationKey })

        val emptyLimitZero = inbox.listRecent(limit = 0)
        assertTrue(emptyLimitZero.isEmpty())

        val emptyLimitNegative = inbox.listRecent(limit = -5)
        assertTrue(emptyLimitNegative.isEmpty())
    }

    // ==========================================
    // 2. NotificationIngestionFilter & Default-Deny
    // ==========================================

    @Test
    fun defaultDenyInvariant_lazyContentExtractorNeverCalledForDeniedPackage() = runBlocking {
        val filter = NotificationIngestionFilter(fakeEvaluator, inbox)
        // com.blocked.chat has no permission granted (Default-Deny)

        var extractorCalled = false
        val ingested = filter.onPosted(
            notificationKey = "key_denied",
            packageName = "com.blocked.chat",
            postedAtEpochMs = 12345L,
            channelId = null,
            lazyContentExtractor = {
                extractorCalled = true
                "Secret Title" to "Secret Body"
            }
        )

        assertFalse("Ingestion must return false for denied package", ingested)
        assertFalse("CRITICAL: lazyContentExtractor must NEVER be called for denied package!", extractorCalled)
        assertEquals("Inbox must remain empty", 0, inbox.size())
    }

    @Test
    fun defaultDenyInvariant_lazyContentExtractorNeverCalledWhenDisabledInProfile() = runBlocking {
        fakeEvaluator.setCapability("com.chat.explicit", ConfirmationLevel.DISABLED)
        val filter = NotificationIngestionFilter(fakeEvaluator, inbox)

        var extractorCalled = false
        val ingested = filter.onPosted(
            notificationKey = "key_disabled",
            packageName = "com.chat.explicit",
            postedAtEpochMs = 12345L,
            channelId = "messages",
            lazyContentExtractor = {
                extractorCalled = true
                "Forbidden Title" to "Forbidden Body"
            }
        )

        assertFalse(ingested)
        assertFalse("lazyContentExtractor must NEVER be called when capability is DISABLED!", extractorCalled)
        assertEquals(0, inbox.size())
    }

    @Test
    fun filterRejectsBlankKeyOrPackageName() = runBlocking {
        val filter = NotificationIngestionFilter(fakeEvaluator, inbox)
        var extractorCalled = false
        val extract = {
            extractorCalled = true
            "Title" to "Body"
        }

        assertFalse(filter.onPosted("", "com.allowed", 1000L, null, extract))
        assertFalse(filter.onPosted("key", "", 1000L, null, extract))
        assertFalse(filter.onPosted("   ", "com.allowed", 1000L, null, extract))
        assertFalse(filter.onPosted("key", "   ", 1000L, null, extract))
        assertFalse(filter.onRemoved(""))
        assertFalse(filter.onRemoved("  "))
        assertFalse(extractorCalled)
    }

    @Test
    fun permittedPackageIngestionInvokesExtractorAndStoresInInbox() = runBlocking {
        fakeEvaluator.setCapability("com.allowed.messenger", ConfirmationLevel.AUTO)
        val filter = NotificationIngestionFilter(fakeEvaluator, inbox)

        var extractorCalled = false
        val ingested = filter.onPosted(
            notificationKey = "key_allowed",
            packageName = "com.allowed.messenger",
            postedAtEpochMs = 5000L,
            channelId = "general",
            lazyContentExtractor = {
                extractorCalled = true
                "Lunch Meeting" to "Are we meeting at noon?"
            }
        )

        assertTrue(ingested)
        assertTrue("lazyContentExtractor must be called for permitted package", extractorCalled)
        assertEquals(1, inbox.size())

        val stored = inbox.listRecent().first()
        assertEquals("key_allowed", stored.notificationKey)
        assertEquals("Lunch Meeting", stored.title.value)
        assertEquals("Are we meeting at noon?", stored.body.value)
        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, stored.title.provenance)
        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, stored.body.provenance)
    }

    // ==========================================
    // 3. NotificationServiceBinding
    // ==========================================

    @Test
    fun serviceBindingFailsClosedWhenUnbound() {
        assertNull(NotificationServiceBinding.getFilter())
        assertNull(NotificationServiceBinding.getEvaluator())
        assertNull(NotificationServiceBinding.getInbox())

        NotificationServiceBinding.bind(fakeEvaluator, inbox)
        assertNotNull(NotificationServiceBinding.getFilter())
        assertEquals(fakeEvaluator, NotificationServiceBinding.getEvaluator())
        assertEquals(inbox, NotificationServiceBinding.getInbox())

        NotificationServiceBinding.unbind()
        assertNull(NotificationServiceBinding.getFilter())
    }

    // ==========================================
    // 4. NotificationSummaryTool Tests
    // ==========================================

    @Test
    fun notificationSummaryToolReturnsUntrustedProvenanceAndSummaryText() = runBlocking {
        fakeEvaluator.setCapability("com.allowed.app", ConfirmationLevel.AUTO)
        inbox.ingest(createCapturedNotification("k1", "com.allowed.app", "Email Alert", "New project docs", 1000L))

        val tool = NotificationSummaryTool(inbox, fakeEvaluator, fakeAuditLog)
        val context = ToolExecutionContext(
            requestId = "req-1",
            capabilityToken = null,
            ruleGrant = com.nava.domain.security.RuleCapabilityGrant(
                grantId = "grant-1",
                ruleId = "rule-1",
                triggerSpec = com.nava.domain.security.RuleTriggerSpec("interval"),
                staticActions = listOf(
                    com.nava.domain.security.RuleActionSpec(
                        toolName = "summarize_notifications",
                        requiredCapability = AtomicCapability.NOTIFICATION_READ
                    )
                ),
                approvalState = com.nava.domain.security.RuleApprovalState.APPROVED_ACTIVE,
                sealHmacHex = "validhmac"
            ),
            targetId = ToolTargetIds.NOTIFICATIONS,
            languageTag = "en",
            issuedAtEpochMs = 2000L,
            isUnattendedBackground = true
        )

        val result = tool.execute(context, emptyMap())
        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success

        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, success.outputProvenance)
        assertEquals(MessageKey.ACTION_NOTIFICATIONS_SUMMARIZED, success.message.key)
        assertEquals("1", success.outputValues["count"])
        assertTrue(success.outputValues["summary"]!!.contains("com.allowed.app"))
        assertTrue(success.outputValues["summary"]!!.contains("Email Alert"))

        assertEquals(1, fakeAuditLog.entries.size)
        assertEquals("SUCCESS", fakeAuditLog.entries.first().decision)
        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, fakeAuditLog.entries.first().provenance)
    }

    @Test
    fun notificationSummaryToolReturnsEmptyWhenNoNotificationsExist() = runBlocking {
        val tool = NotificationSummaryTool(inbox, fakeEvaluator, fakeAuditLog)
        val context = ToolExecutionContext(
            requestId = "req-empty",
            capabilityToken = null,
            ruleGrant = com.nava.domain.security.RuleCapabilityGrant(
                grantId = "grant-1",
                ruleId = "rule-1",
                triggerSpec = com.nava.domain.security.RuleTriggerSpec("interval"),
                staticActions = listOf(
                    com.nava.domain.security.RuleActionSpec(
                        toolName = "summarize_notifications",
                        requiredCapability = AtomicCapability.NOTIFICATION_READ
                    )
                ),
                approvalState = com.nava.domain.security.RuleApprovalState.APPROVED_ACTIVE,
                sealHmacHex = "validhmac"
            ),
            targetId = ToolTargetIds.NOTIFICATIONS,
            languageTag = "en",
            issuedAtEpochMs = 2000L,
            isUnattendedBackground = true
        )

        val result = tool.execute(context, emptyMap())
        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals(MessageKey.ACTION_NOTIFICATIONS_EMPTY, success.message.key)
        assertEquals("0", success.outputValues["count"])
    }

    @Test
    fun notificationSummaryToolDeniesExplicitBlockedPackageFilter() = runBlocking {
        val tool = NotificationSummaryTool(inbox, fakeEvaluator, fakeAuditLog)
        val context = ToolExecutionContext(
            requestId = "req-filter",
            capabilityToken = null,
            ruleGrant = com.nava.domain.security.RuleCapabilityGrant(
                grantId = "grant-1",
                ruleId = "rule-1",
                triggerSpec = com.nava.domain.security.RuleTriggerSpec("interval"),
                staticActions = listOf(
                    com.nava.domain.security.RuleActionSpec(
                        toolName = "summarize_notifications",
                        requiredCapability = AtomicCapability.NOTIFICATION_READ
                    )
                ),
                approvalState = com.nava.domain.security.RuleApprovalState.APPROVED_ACTIVE,
                sealHmacHex = "validhmac"
            ),
            targetId = ToolTargetIds.NOTIFICATIONS,
            languageTag = "en",
            issuedAtEpochMs = 2000L,
            isUnattendedBackground = true
        )

        val args = mapOf(
            "package_name" to Tainted.fromUserUtterance(
                SlotValueAst.StringValue("com.unauthorized.app"),
                SensitiveSlotKind.PACKAGE_NAME
            )
        )

        val result = tool.execute(context, args)
        assertTrue(result is ToolResult.Failure)
        val failure = result as ToolResult.Failure
        assertEquals("PERMISSION_DENIED", failure.errorCode)
        assertTrue(failure.isSecurityViolation)
    }

    @Test
    fun summaryToolFiltersOutConcurrentlyRevokedPackage() = runBlocking {
        // App was allowed at ingestion time
        fakeEvaluator.setCapability("com.chat.revoked", ConfirmationLevel.AUTO)
        fakeEvaluator.setCapability("com.chat.active", ConfirmationLevel.AUTO)

        inbox.ingest(createCapturedNotification("k1", "com.chat.revoked", "Old Msg", "Content", 1000L))
        inbox.ingest(createCapturedNotification("k2", "com.chat.active", "New Msg", "Active content", 2000L))

        // Permission is now revoked for com.chat.revoked
        fakeEvaluator.setCapability("com.chat.revoked", ConfirmationLevel.DISABLED)

        val tool = NotificationSummaryTool(inbox, fakeEvaluator, fakeAuditLog)
        val context = ToolExecutionContext(
            requestId = "req-revocation",
            capabilityToken = null,
            ruleGrant = com.nava.domain.security.RuleCapabilityGrant(
                grantId = "grant-1",
                ruleId = "rule-1",
                triggerSpec = com.nava.domain.security.RuleTriggerSpec("interval"),
                staticActions = listOf(
                    com.nava.domain.security.RuleActionSpec(
                        toolName = "summarize_notifications",
                        requiredCapability = AtomicCapability.NOTIFICATION_READ
                    )
                ),
                approvalState = com.nava.domain.security.RuleApprovalState.APPROVED_ACTIVE,
                sealHmacHex = "validhmac"
            ),
            targetId = ToolTargetIds.NOTIFICATIONS,
            languageTag = "en",
            issuedAtEpochMs = 3000L,
            isUnattendedBackground = true
        )

        val result = tool.execute(context, emptyMap())
        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success

        assertEquals("1", success.outputValues["count"])
        assertTrue(success.outputValues["summary"]!!.contains("com.chat.active"))
        assertFalse(success.outputValues["summary"]!!.contains("com.chat.revoked"))
    }

    private fun createCapturedNotification(
        key: String,
        pkg: String,
        title: String,
        body: String,
        postTime: Long
    ): CapturedNotification {
        return CapturedNotification(
            notificationKey = key,
            packageName = pkg,
            title = Tainted.fromUntrustedExternal(title, SensitiveSlotKind.TEXT_BODY, pkg),
            body = Tainted.fromUntrustedExternal(body, SensitiveSlotKind.TEXT_BODY, pkg),
            postedAtEpochMs = postTime
        )
    }
}

class FakePermissionEvaluator : PermissionEvaluatorPort {
    private val capabilities = mutableMapOf<String, ConfirmationLevel>()

    fun setCapability(packageName: String, level: ConfirmationLevel) {
        val targetId = ToolTargetIds.forPackage(packageName)
        capabilities[targetId] = level
    }

    override suspend fun evaluateCapability(
        targetId: String,
        capability: AtomicCapability
    ): ConfirmationLevel {
        if (capability == AtomicCapability.NOTIFICATION_READ) {
            return capabilities[targetId] ?: ConfirmationLevel.DISABLED
        }
        return ConfirmationLevel.DISABLED
    }

    override suspend fun getProfileForTarget(targetId: String): PermissionProfile {
        return PermissionProfile.defaultDeny()
    }

    override suspend fun listProfiles(): List<PermissionProfile> = emptyList()
    override suspend fun saveProfile(profile: PermissionProfile) {}
    override suspend fun assignTargetToProfile(targetId: String, profileId: String) {}
    override suspend fun deleteProfile(profileId: String) {}
}

class FakeAuditLog : AuditLogPort {
    val entries = mutableListOf<AuditLogEntry>()

    override suspend fun record(entry: AuditLogEntry) {
        entries.add(entry)
    }

    override suspend fun queryRecent(limit: Int): List<AuditLogEntry> {
        return entries.takeLast(limit)
    }
}

package com.nava.feature.automations.notification

import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.PermissionEvaluatorPort
import com.nava.domain.security.PermissionProfile
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageKey
import com.nava.feature.automations.common.ToolTargetIds
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NotificationSummaryResyncAndTargetTest {

    @After
    fun tearDown() {
        NotificationServiceBinding.unbind()
    }

    @Test
    fun reportsNoPermittedNotificationAppsWhenOnlyCoreTargetIsAssigned() = runTest {
        val inbox = InMemoryNotificationInbox()
        val evaluator = StaticNotificationEvaluator(
            profiles = listOf(
                PermissionProfile.notificationSummaryOnly().copy(
                    assignedTargets = setOf(ToolTargetIds.NOTIFICATIONS)
                )
            )
        )
        val tool = NotificationSummaryTool(inbox, evaluator, NoOpAuditLog())

        val result = tool.execute(
            context = testContext("req-1"),
            arguments = emptyMap()
        ) as ToolResult.Success

        assertEquals(MessageKey.INFO_NO_PERMITTED_NOTIFICATION_APPS, result.message.key)
        assertEquals("false", result.outputValues["has_permitted_apps"])
    }

    @Test
    fun resyncsActiveNotificationsForPermittedAppWhileKeepingUnpermittedAppsDropped() = runTest {
        val inbox = InMemoryNotificationInbox()
        val permittedPkg = "com.example.chat"
        val deniedPkg = "com.example.bank"
        val evaluator = StaticNotificationEvaluator(
            profiles = listOf(
                PermissionProfile.notificationSummaryOnly().copy(
                    assignedTargets = setOf(ToolTargetIds.forPackage(permittedPkg))
                )
            )
        )
        NotificationServiceBinding.bind(evaluator, inbox)
        var deniedExtractorCalled = false
        NotificationServiceBinding.registerResyncHandler {
            val filter = NotificationServiceBinding.getFilter() ?: return@registerResyncHandler
            filter.onPosted(
                notificationKey = "0|$deniedPkg|1",
                packageName = deniedPkg,
                postedAtEpochMs = 900L,
                lazyContentExtractor = {
                    deniedExtractorCalled = true
                    "Secret" to "OTP 123456"
                }
            )
            filter.onPosted(
                notificationKey = "0|$permittedPkg|2",
                packageName = permittedPkg,
                postedAtEpochMs = 950L,
                lazyContentExtractor = { "Alex" to "See you at 5" }
            )
        }

        val tool = NotificationSummaryTool(inbox, evaluator, NoOpAuditLog())
        val result = tool.execute(
            context = testContext("req-2"),
            arguments = emptyMap()
        ) as ToolResult.Success

        assertFalse("Unpermitted app extras must never be read during resync", deniedExtractorCalled)
        assertEquals(MessageKey.ACTION_NOTIFICATIONS_SUMMARIZED, result.message.key)
        assertEquals("1", result.outputValues["count"])
        assertTrue(result.outputValues["summary"].orEmpty().contains("Alex: See you at 5"))
    }

    private fun testContext(requestId: String): ToolExecutionContext {
        return ToolExecutionContext(
            requestId = requestId,
            targetId = ToolTargetIds.NOTIFICATIONS,
            capabilityToken = CapabilityToken.mint(
                tokenId = "tok-$requestId",
                requestId = requestId,
                allowedTools = setOf("summarize_notifications"),
                mintProvenance = DataProvenance.USER_UTTERANCE,
                issuedAtEpochMs = 1_000L,
                expiresAtEpochMs = 61_000L,
                maxToolCalls = 1
            ),
            ruleGrant = null,
            languageTag = "tr",
            issuedAtEpochMs = 1_000L
        )
    }

    private class StaticNotificationEvaluator(
        private val profiles: List<PermissionProfile>
    ) : PermissionEvaluatorPort {
        override suspend fun evaluateCapability(
            targetId: String,
            capability: AtomicCapability
        ): ConfirmationLevel {
            val match = profiles.firstOrNull { targetId in it.assignedTargets }
            return match?.levelFor(capability) ?: ConfirmationLevel.DISABLED
        }

        override suspend fun getProfileForTarget(targetId: String): PermissionProfile {
            return profiles.firstOrNull { targetId in it.assignedTargets }
                ?: PermissionProfile.defaultDeny()
        }

        override suspend fun listProfiles(): List<PermissionProfile> = profiles
        override suspend fun saveProfile(profile: PermissionProfile) = Unit
        override suspend fun assignTargetToProfile(targetId: String, profileId: String) = Unit
        override suspend fun deleteProfile(profileId: String) = Unit
    }

    private class NoOpAuditLog : AuditLogPort {
        override suspend fun record(entry: AuditLogEntry) = Unit
        override suspend fun queryRecent(limit: Int): List<AuditLogEntry> = emptyList()
    }
}

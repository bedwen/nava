package com.nava.core.security.policy

import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.testing.InMemoryRowStorage
import com.nava.core.security.testing.InMemorySoftwareKeyProvider
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.PermissionProfilePreset
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleTriggerSpec
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class PermissionProfileAndRuleGrantTest {

    @Test
    fun permissionProfileManagerPresetsDefaultDenyAndCustomCrud() = runTest {
        val store = EncryptedSqliteStore(
            storage = InMemoryRowStorage(),
            keyProvider = InMemorySoftwareKeyProvider(),
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        var nowSec = 1_000L
        val manager = PermissionProfileManager(
            store = store,
            clockEpochSec = { nowSec }
        )

        val defaultProfile = manager.getProfileForTarget("com.unassigned.app")
        assertEquals(PermissionProfile.DEFAULT_DENY_PROFILE_ID, defaultProfile.id)
        for (cap in AtomicCapability.entries) {
            assertEquals(ConfirmationLevel.DISABLED, manager.evaluateCapability("com.unassigned.app", cap))
        }
        assertFalse(manager.isNotificationReadEnabled("com.unassigned.app"))
        assertFalse(manager.isNotificationReadEnabled(" "))

        val initialProfiles = manager.listProfiles()
        assertEquals(5, initialProfiles.size)
        assertTrue(initialProfiles.all { it.id in PermissionProfile.IMMUTABLE_PRESET_IDS })

        try {
            manager.saveProfile(PermissionProfile.defaultDeny())
            fail("Expected SecurityException when saving built-in preset")
        } catch (_: SecurityException) {
            // Expected
        }
        try {
            manager.deleteProfile(PermissionProfile.DEFAULT_DENY_PROFILE_ID)
            fail("Expected SecurityException when deleting built-in preset")
        } catch (_: SecurityException) {
            // Expected
        }

        val custom = PermissionProfile(
            id = "custom_chat_profile",
            name = "Custom Chat",
            preset = PermissionProfilePreset.CUSTOM,
            capabilities = mapOf(
                AtomicCapability.NOTIFICATION_READ to ConfirmationLevel.AUTO,
                AtomicCapability.DATA_READ to ConfirmationLevel.PROMPT_CARD,
                AtomicCapability.CREATE_DRAFT to ConfirmationLevel.AUTO,
                AtomicCapability.MODIFY_DELETE_SEND to ConfirmationLevel.DISABLED,
                AtomicCapability.APP_LAUNCH to ConfirmationLevel.PROMPT_CARD
            )
        )
        manager.saveProfile(custom)
        manager.assignTargetToProfile("com.example.chat", custom.id)

        assertTrue(manager.isNotificationReadEnabled("com.example.chat"))
        assertEquals(ConfirmationLevel.AUTO, manager.evaluateCapability("com.example.chat", AtomicCapability.NOTIFICATION_READ))
        assertEquals(ConfirmationLevel.PROMPT_CARD, manager.evaluateCapability("com.example.chat", AtomicCapability.DATA_READ))
        assertEquals(ConfirmationLevel.AUTO, manager.evaluateCapability("com.example.chat", AtomicCapability.CREATE_DRAFT))
        assertEquals(ConfirmationLevel.DISABLED, manager.evaluateCapability("com.example.chat", AtomicCapability.MODIFY_DELETE_SEND))
        assertEquals(ConfirmationLevel.PROMPT_CARD, manager.evaluateCapability("com.example.chat", AtomicCapability.APP_LAUNCH))

        nowSec = 2_000L
        val updatedCustom = custom.withCapability(
            capability = AtomicCapability.DATA_READ,
            level = ConfirmationLevel.BIOMETRIC,
            updatedAtEpochSec = nowSec
        )
        manager.saveProfile(updatedCustom)

        assertEquals(ConfirmationLevel.AUTO, manager.evaluateCapability("com.example.chat", AtomicCapability.NOTIFICATION_READ))
        assertEquals(ConfirmationLevel.BIOMETRIC, manager.evaluateCapability("com.example.chat", AtomicCapability.DATA_READ))
        assertEquals(ConfirmationLevel.AUTO, manager.evaluateCapability("com.example.chat", AtomicCapability.CREATE_DRAFT))

        val listedAfterSave = manager.listProfiles()
        assertEquals(6, listedAfterSave.size)
        val loadedCustom = listedAfterSave.first { it.id == custom.id }
        assertTrue("com.example.chat" in loadedCustom.assignedTargets)

        manager.deleteProfile(custom.id)
        assertFalse(manager.isNotificationReadEnabled("com.example.chat"))
        assertEquals(
            PermissionProfile.DEFAULT_DENY_PROFILE_ID,
            manager.getProfileForTarget("com.example.chat").id
        )
        assertEquals(5, manager.listProfiles().size)
    }

    @Test
    fun permissionProfileManagerPresetBindingForNotifications() = runTest {
        val store = EncryptedSqliteStore(
            storage = InMemoryRowStorage(),
            keyProvider = InMemorySoftwareKeyProvider(),
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val manager = PermissionProfileManager(store = store)

        manager.assignTargetToProfile(
            targetId = "com.example.mail",
            profileId = PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID
        )
        assertTrue(manager.isNotificationReadEnabled("com.example.mail"))
        assertEquals(
            ConfirmationLevel.DISABLED,
            manager.evaluateCapability("com.example.mail", AtomicCapability.CREATE_DRAFT)
        )
    }

    @Test
    fun ruleCapabilityGrantLifecycleSealPauseRevokeAndGlobalPause() = runTest {
        val keyProvider = InMemorySoftwareKeyProvider()
        val store = EncryptedSqliteStore(
            storage = InMemoryRowStorage(),
            keyProvider = keyProvider,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        var grantCounter = 0
        val ruleManager = RuleCapabilityGrantManager(
            store = store,
            keyProvider = keyProvider,
            grantIdGenerator = { "grant_${++grantCounter}" }
        )

        val trigger = RuleTriggerSpec(
            triggerType = "CHARGING_AFTER_TIME",
            parameters = mapOf("after_time" to "23:00")
        )
        val actions = listOf(
            RuleActionSpec(
                toolName = "set_dnd",
                requiredCapability = AtomicCapability.CREATE_DRAFT,
                staticArguments = mapOf("mode" to "priority"),
                requiresBiometric = false
            )
        )

        val pending = ruleManager.createPendingRule(
            ruleId = "night_quiet",
            triggerSpec = trigger,
            staticActions = actions,
            nowEpochSec = 100L
        )
        assertEquals("grant_1", pending.grantId)
        assertEquals(RuleApprovalState.PENDING_USER_APPROVAL, pending.approvalState)
        assertEquals("", pending.sealHmacHex)
        assertFalse(ruleManager.verifySeal(pending))
        assertFalse(pending.canExecuteUnattended())

        val approved = ruleManager.approveAndSealRule("night_quiet", nowEpochSec = 200L)
        assertEquals(RuleApprovalState.APPROVED_ACTIVE, approved.approvalState)
        assertEquals(200L, approved.grantedAtEpochSec)
        assertTrue(approved.sealHmacHex.isNotBlank())
        assertTrue(ruleManager.verifySeal(approved))
        assertTrue(approved.canExecuteUnattended())

        val tampered = approved.copy(
            staticActions = listOf(
                RuleActionSpec(
                    toolName = "send_sms_draft",
                    requiredCapability = AtomicCapability.CREATE_DRAFT,
                    staticArguments = mapOf("recipient" to "+15550009999")
                )
            )
        )
        assertFalse(ruleManager.verifySeal(tampered))

        ruleManager.pauseRule("night_quiet", nowEpochSec = 300L)
        val paused = ruleManager.findRule("night_quiet")
        assertNotNull(paused)
        assertEquals(RuleApprovalState.PAUSED, paused!!.approvalState)
        assertFalse(paused.canExecuteUnattended())

        val resumed = ruleManager.approveAndSealRule("night_quiet", nowEpochSec = 400L)
        assertEquals(RuleApprovalState.APPROVED_ACTIVE, resumed.approvalState)
        assertTrue(ruleManager.verifySeal(resumed))

        assertFalse(ruleManager.isGlobalRulesPaused())
        ruleManager.setGlobalRulesPaused(true)
        assertTrue(ruleManager.isGlobalRulesPaused())
        ruleManager.setGlobalRulesPaused(false)
        assertFalse(ruleManager.isGlobalRulesPaused())

        ruleManager.revokeRule("night_quiet", nowEpochSec = 500L)
        val revoked = ruleManager.findRule("night_quiet")!!
        assertEquals(RuleApprovalState.REVOKED, revoked.approvalState)
        assertEquals("", revoked.sealHmacHex)
        assertFalse(ruleManager.verifySeal(revoked))
        assertEquals(1, ruleManager.listRules().size)
        assertNull(ruleManager.findRule("missing_rule"))

        try {
            ruleManager.pauseRule("night_quiet", nowEpochSec = 600L)
            fail("Expected SecurityException when pausing a revoked rule")
        } catch (_: SecurityException) {
            // Expected
        }
        try {
            ruleManager.approveAndSealRule("night_quiet", nowEpochSec = 600L)
            fail("Expected SecurityException when approving a revoked rule")
        } catch (_: SecurityException) {
            // Expected
        }
    }
}

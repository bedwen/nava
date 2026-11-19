package com.nava.domain.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class TaintedAndSecurityDomainTest {

    @Test
    fun `Tainted preserves and monotonically escalates provenance across transformations`() {
        val userText = Tainted.fromUserUtterance("Send to ", SensitiveSlotKind.TEXT_BODY)
        val externalNumber = Tainted.fromUntrustedExternal(
            value = "+15550101",
            slotKind = SensitiveSlotKind.PHONE_NUMBER,
            sourceLabel = "notification:com.chat.app"
        )

        val mapped = externalNumber.map { it.trim() }
        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, mapped.provenance)
        assertEquals(SensitiveSlotKind.PHONE_NUMBER, mapped.slotKind)
        assertTrue(mapped.requiresExplicitConfirmation)

        val combined = userText.combineWith(externalNumber) { a, b -> a + b }
        assertEquals("Send to +15550101", combined.value)
        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, combined.provenance)
        assertEquals(SensitiveSlotKind.PHONE_NUMBER, combined.slotKind)
        assertTrue(combined.requiresExplicitConfirmation)

        try {
            combined.requireTrustedForPlanning()
            fail("Expected SecurityException when unwrapping UNTRUSTED_EXTERNAL for planning")
        } catch (_: SecurityException) {
            // Expected
        }
    }

    @Test
    fun `SensitiveSlotKind distinguishes high-risk targets from passive content`() {
        val highRisk = listOf(
            SensitiveSlotKind.RECIPIENT_ADDRESS,
            SensitiveSlotKind.PHONE_NUMBER,
            SensitiveSlotKind.EXTERNAL_URI,
            SensitiveSlotKind.FILE_PATH,
            SensitiveSlotKind.PACKAGE_NAME,
            SensitiveSlotKind.INTENT_ACTION
        )
        val passive = listOf(
            SensitiveSlotKind.TEXT_BODY,
            SensitiveSlotKind.EVENT_TITLE,
            SensitiveSlotKind.DATE_TIME,
            SensitiveSlotKind.DURATION
        )

        assertTrue(highRisk.all { it.isHighRisk })
        assertTrue(passive.none { it.isHighRisk })

        val untrustedPassive = Tainted.fromUntrustedExternal("Meeting Notes", SensitiveSlotKind.TEXT_BODY)
        assertTrue(untrustedPassive.isUntrusted)
        assertFalse(untrustedPassive.requiresExplicitConfirmation)
    }

    @Test
    fun `CapabilityToken enforces USER_UTTERANCE provenance and defensive immutability`() {
        try {
            CapabilityToken.mint(
                tokenId = "tok-bad",
                requestId = "req-1",
                allowedTools = setOf("alarm.set"),
                mintProvenance = DataProvenance.UNTRUSTED_EXTERNAL,
                issuedAtEpochMs = 1000L
            )
            fail("Expected SecurityException when minting CapabilityToken from UNTRUSTED_EXTERNAL")
        } catch (_: SecurityException) {
            // Expected
        }

        val mutableTools = mutableSetOf("alarm.set")
        val token = CapabilityToken.mint(
            tokenId = "tok-1",
            requestId = "req-1",
            allowedTools = mutableTools,
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = 1000L,
            expiresAtEpochMs = 2000L
        )
        mutableTools.add("sms.send")

        assertTrue(token.allowsTool("alarm.set"))
        assertFalse(token.allowsTool("sms.send"))
        token.assertValidFor("alarm.set", nowEpochMs = 1500L)

        try {
            token.assertValidFor("sms.send", nowEpochMs = 1500L)
            fail("Expected SecurityException for unsealed tool")
        } catch (_: SecurityException) {
            // Expected
        }

        try {
            token.assertValidFor("alarm.set", nowEpochMs = 2500L)
            fail("Expected SecurityException for expired token")
        } catch (_: SecurityException) {
            // Expected
        }

        val multiToken = CapabilityToken.mint(
            tokenId = "tok-multi",
            requestId = "req-multi",
            allowedTools = mutableSetOf("alarm.set", "notes.save"),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = 1000L
        )
        try {
            @Suppress("UNCHECKED_CAST")
            (multiToken.allowedTools as MutableSet<String>).add("sms.send")
            fail("Expected UnsupportedOperationException when mutating allowedTools")
        } catch (_: UnsupportedOperationException) {
            // Expected
        }
    }

    @Test
    fun `PermissionProfile enforces Default-Deny orthogonal switches and forbids AUTO on MODIFY_DELETE_SEND`() {
        val defaultDeny = PermissionProfile.defaultDeny()
        for (cap in AtomicCapability.entries) {
            assertEquals(ConfirmationLevel.DISABLED, defaultDeny.levelFor(cap))
            assertFalse(defaultDeny.isCapabilityAllowed(cap))
        }

        val updated = defaultDeny.withCapability(AtomicCapability.NOTIFICATION_READ, ConfirmationLevel.AUTO)
        assertTrue(updated.isCapabilityAllowed(AtomicCapability.NOTIFICATION_READ))
        assertEquals(ConfirmationLevel.DISABLED, updated.levelFor(AtomicCapability.DATA_READ))
        assertEquals(ConfirmationLevel.DISABLED, updated.levelFor(AtomicCapability.CREATE_DRAFT))
        assertEquals(ConfirmationLevel.DISABLED, updated.levelFor(AtomicCapability.MODIFY_DELETE_SEND))
        assertEquals(ConfirmationLevel.DISABLED, updated.levelFor(AtomicCapability.APP_LAUNCH))

        try {
            defaultDeny.withCapability(AtomicCapability.MODIFY_DELETE_SEND, ConfirmationLevel.AUTO)
            fail("Expected IllegalArgumentException for AUTO on MODIFY_DELETE_SEND")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }

    @Test
    fun `RuleCapabilityGrant prohibits unattended execution for pending unsealed or high-risk rules`() {
        val safeTrigger = RuleTriggerSpec("CHARGING_CONNECTED")
        val safeAction = RuleActionSpec("audio.set_dnd", AtomicCapability.CREATE_DRAFT)
        val highRiskAction = RuleActionSpec("sms.send", AtomicCapability.MODIFY_DELETE_SEND)
        val biometricAction = RuleActionSpec("vault.read", AtomicCapability.DATA_READ, requiresBiometric = true)

        val pending = RuleCapabilityGrant(
            grantId = "g1",
            ruleId = "r1",
            triggerSpec = safeTrigger,
            staticActions = listOf(safeAction),
            approvalState = RuleApprovalState.PENDING_USER_APPROVAL
        )
        assertFalse(pending.canExecuteUnattended())

        val unsealed = pending.copy(approvalState = RuleApprovalState.APPROVED_ACTIVE, sealHmacHex = "")
        assertFalse(unsealed.canExecuteUnattended())

        val approvedSafe = pending.copy(
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "deadbeef"
        )
        assertTrue(approvedSafe.canExecuteUnattended())

        val approvedHighRisk = approvedSafe.copy(staticActions = listOf(safeAction, highRiskAction))
        assertTrue(approvedHighRisk.requiresInteractiveUpgrade)
        assertFalse(approvedHighRisk.canExecuteUnattended())

        val approvedBiometric = approvedSafe.copy(staticActions = listOf(biometricAction))
        assertTrue(approvedBiometric.requiresInteractiveUpgrade)
        assertFalse(approvedBiometric.canExecuteUnattended())
    }
}

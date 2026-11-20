package com.nava.feature.automations.common

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class AutomationCommonFoundationTest {

    @Test
    fun canonicalToolNamesCoverTier1AndAllPhase4CapabilitiesWithoutConflation() {
        val tier1Tools = setOf(
            AutomationToolNames.SET_ALARM,
            AutomationToolNames.SET_TIMER,
            AutomationToolNames.SET_DND,
            AutomationToolNames.SET_VOLUME,
            AutomationToolNames.LAUNCH_APP
        )
        assertEquals(setOf("set_alarm", "set_timer", "set_dnd", "set_volume", "launch_app"), tier1Tools)
        assertTrue(AutomationToolNames.ALL.containsAll(tier1Tools))

        // Every vault tool name contains "vault" so SecurityFirewall detects it deterministically.
        assertEquals(3, AutomationToolNames.VAULT_TOOLS.size)
        for (toolName in AutomationToolNames.VAULT_TOOLS) {
            assertTrue("Vault tool '$toolName' must contain 'vault'", "vault" in toolName)
            assertTrue(toolName in AutomationToolNames.ALL)
        }

        // Standard note tools must not contain "vault" so they are not misclassified as Vault tools.
        assertFalse("vault" in AutomationToolNames.NOTES_READ)
        assertFalse("vault" in AutomationToolNames.NOTES_CREATE)
        assertFalse("vault" in AutomationToolNames.NOTES_DELETE)

        // All outbound action constants must be non-blank.
        assertEquals("android.intent.action.SET_ALARM", AutomationOutboundActions.ACTION_SET_ALARM)
        assertEquals("android.intent.action.SET_TIMER", AutomationOutboundActions.ACTION_SET_TIMER)
        assertEquals("android.intent.action.SENDTO", AutomationOutboundActions.ACTION_SENDTO)
        assertEquals("android.intent.action.DIAL", AutomationOutboundActions.ACTION_DIAL)
        assertEquals("android.intent.action.CALL", AutomationOutboundActions.ACTION_CALL)
        assertEquals("SAF_READ", AutomationOutboundActions.ACTION_SAF_READ)
        assertEquals("SAF_WRITE", AutomationOutboundActions.ACTION_SAF_WRITE)
        assertEquals("CALENDAR_PROVIDER", AutomationOutboundActions.ACTION_CALENDAR_PROVIDER)
        assertEquals("APP_LAUNCH", AutomationOutboundActions.ACTION_APP_LAUNCH)
    }

    @Test
    fun toolTargetIdsFormatSafTreesAndPackagesSafely() {
        assertEquals(
            "saf:content://com.android.externalstorage.documents/tree/primary%3ADocs",
            ToolTargetIds.forSafTree("  content://com.android.externalstorage.documents/tree/primary%3ADocs  ")
        )
        assertEquals("com.example.messaging", ToolTargetIds.forPackage("  com.example.messaging "))

        try {
            ToolTargetIds.forSafTree("  ")
            fail("Expected IllegalArgumentException for blank SAF tree URI")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
        try {
            ToolTargetIds.forPackage("")
            fail("Expected IllegalArgumentException for blank package name")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }

    @Test
    fun toolArgumentReaderPreservesTaintAndDetectsVaultSources() {
        val args = mapOf(
            "title" to Tainted.fromUserUtterance(
                SlotValueAst.StringValue("  Standup  "),
                SensitiveSlotKind.EVENT_TITLE
            ),
            "count" to Tainted.fromSystem(SlotValueAst.IntValue(42L)),
            "count_str" to Tainted.fromUserUtterance(SlotValueAst.StringValue("17")),
            "enabled" to Tainted.fromUserUtterance(SlotValueAst.BooleanValue(true)),
            "enabled_str" to Tainted.fromUserUtterance(SlotValueAst.StringValue("off")),
            "empty" to Tainted.fromUserUtterance(SlotValueAst.StringValue("   ")),
            "null_slot" to Tainted.fromUserUtterance(SlotValueAst.NullValue),
            "external_body" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("Meeting at 10"),
                SensitiveSlotKind.TEXT_BODY,
                sourceLabel = "notification:com.example.chat"
            )
        )

        val title = ToolArgumentReader.getString(args, "title")
        assertNotNull(title)
        assertEquals("Standup", title!!.value)
        assertEquals(DataProvenance.USER_UTTERANCE, title.provenance)
        assertEquals(SensitiveSlotKind.EVENT_TITLE, title.slotKind)

        assertNull(ToolArgumentReader.getString(args, "empty"))
        assertEquals("   ", ToolArgumentReader.getRawString(args, "empty")?.value)
        assertNull(ToolArgumentReader.getString(args, "null_slot"))
        assertNull(ToolArgumentReader.getDisplayString(args, "null_slot"))

        assertEquals(42L, ToolArgumentReader.getLong(args, "count")?.value)
        assertEquals(17, ToolArgumentReader.getInt(args, "count_str")?.value)
        assertEquals(true, ToolArgumentReader.getBoolean(args, "enabled")?.value)
        assertEquals(false, ToolArgumentReader.getBoolean(args, "enabled_str")?.value)

        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, ToolArgumentReader.worstProvenance(args))
        assertTrue(ToolArgumentReader.hasUntrustedArgument(args))
        assertFalse(ToolArgumentReader.hasVaultSourceArgument(args))

        val vaultArgs = mapOf(
            "body" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("Secret"),
                SensitiveSlotKind.TEXT_BODY,
                sourceLabel = "VAULT\u200B:note_7"
            )
        )
        assertTrue(ToolArgumentReader.hasVaultSourceArgument(vaultArgs))
        assertTrue(ToolArgumentReader.isVaultSource("vault:passport"))
        assertFalse(ToolArgumentReader.isVaultSource("notification:com.chat"))

        val canonical = ToolArgumentReader.toCanonicalDisplayMap(args)
        assertEquals("42", canonical["count"]?.value)
        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, canonical["external_body"]?.provenance)
    }

    @Test
    fun platformValidationHelpersRejectTraversalAndInvalidDestinations() {
        assertTrue(SafPlatformGateway.isSafeDocumentName("meeting_notes.txt"))
        assertFalse(SafPlatformGateway.isSafeDocumentName(""))
        assertFalse(SafPlatformGateway.isSafeDocumentName("."))
        assertFalse(SafPlatformGateway.isSafeDocumentName(".."))
        assertFalse(SafPlatformGateway.isSafeDocumentName("../secret.txt"))
        assertFalse(SafPlatformGateway.isSafeDocumentName("sub/file.txt"))
        assertFalse(SafPlatformGateway.isSafeDocumentName("sub\\file.txt"))
        assertFalse(SafPlatformGateway.isSafeDocumentName("bad\u0000name.txt"))
        assertFalse(SafPlatformGateway.isSafeDocumentName("bad\nname.txt"))

        assertTrue(AndroidAutomationIntentGateway.isValidDialableNumber("+1 (555) 123-4567"))
        assertFalse(AndroidAutomationIntentGateway.isValidDialableNumber("https://evil.test"))
        assertFalse(AndroidAutomationIntentGateway.isValidDialableNumber("555?body=leak"))
        assertFalse(AndroidAutomationIntentGateway.isValidDialableNumber("---"))

        assertTrue(AndroidAutomationIntentGateway.isValidPackageName("com.android.deskclock"))
        assertFalse(AndroidAutomationIntentGateway.isValidPackageName("https://evil.test"))
        assertFalse(AndroidAutomationIntentGateway.isValidPackageName("singleword"))
        assertFalse(AndroidAutomationIntentGateway.isValidPackageName("com.example/Main"))

        val id1 = AndroidAutomationNotificationBridge.stableNotificationId("task-1")
        val id2 = AndroidAutomationNotificationBridge.stableNotificationId("task-1")
        assertTrue(id1 > 0)
        assertEquals(id1, id2)

        val interactive = InteractiveNotificationRequest(
            notificationId = id1,
            requestId = "req-1",
            pendingToolNames = listOf(AutomationToolNames.PLACE_CALL),
            targetId = ToolTargetIds.PHONE,
            message = UserMessage(MessageKey.ACTION_CONFIRMATION_REQUIRED),
            requiresBiometric = false,
            hasUntrustedHighRiskSlot = true
        )
        assertEquals(listOf("place_call"), interactive.pendingToolNames)
    }
}

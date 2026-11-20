package com.nava.domain.automation

import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.StoredNote
import com.nava.domain.security.Tainted
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class Phase4DomainContractsTest {

    @Test
    fun storedNoteRejectsBlankNoteIdAndPreservesFields() {
        val note = StoredNote(
            noteId = "note_1",
            title = "Shopping",
            body = "Milk and eggs",
            updatedEpochSec = 1_700_000_000L
        )
        assertEquals("note_1", note.noteId)
        assertEquals("Shopping", note.title)
        assertEquals("Milk and eggs", note.body)
        assertEquals(1_700_000_000L, note.updatedEpochSec)

        try {
            StoredNote(noteId = "   ", title = "t", body = "b", updatedEpochSec = 1L)
            fail("Expected IllegalArgumentException for blank noteId")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }

    @Test
    fun capturedNotificationEnforcesUntrustedExternalProvenance() {
        val valid = CapturedNotification(
            notificationKey = "0|com.example.chat|1|null|1000",
            packageName = "com.example.chat",
            title = Tainted.fromUntrustedExternal("Alex", sourceLabel = "notification:com.example.chat"),
            body = Tainted.fromUntrustedExternal("See you at 9", sourceLabel = "notification:com.example.chat"),
            postedAtEpochMs = 10_000L,
            channelId = "messages"
        )
        assertEquals("com.example.chat", valid.packageName)
        assertTrue(valid.title.isUntrusted)
        assertTrue(valid.body.isUntrusted)

        try {
            CapturedNotification(
                notificationKey = "key-1",
                packageName = "com.example.chat",
                title = Tainted.fromUserUtterance("Spoofed title"),
                body = Tainted.fromUntrustedExternal("Body"),
                postedAtEpochMs = 10_000L
            )
            fail("Expected IllegalArgumentException when notification title is not UNTRUSTED_EXTERNAL")
        } catch (_: IllegalArgumentException) {
            // Expected
        }

        try {
            CapturedNotification(
                notificationKey = "key-2",
                packageName = "com.example.chat",
                title = Tainted.fromUntrustedExternal("Title"),
                body = Tainted.fromSystem("Spoofed system body"),
                postedAtEpochMs = 10_000L
            )
            fail("Expected IllegalArgumentException when notification body is not UNTRUSTED_EXTERNAL")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }

    @Test
    fun backgroundTaskRequestValidatesPlanAndModelImportContracts() {
        val token = CapabilityToken.mint(
            tokenId = "tok-1",
            requestId = "req-1",
            allowedTools = setOf("notes_create"),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = 1_000L
        )
        val plan = PlanAst(
            planId = "plan-1",
            calls = listOf(
                ToolCallAst(
                    toolName = "notes_create",
                    arguments = mapOf(
                        "title" to Tainted.fromUntrustedExternal(
                            SlotValueAst.StringValue("Meeting"),
                            SensitiveSlotKind.EVENT_TITLE
                        )
                    )
                )
            )
        )

        val stage2Task = BackgroundTaskRequest.PlanContinuation(
            taskId = "task-1",
            plan = plan,
            capabilityToken = token,
            targetId = "nava.notes",
            languageTag = "en",
            enqueuedAtEpochMs = 2_000L,
            isStage2Extraction = true
        )
        assertEquals(BackgroundTaskKind.STAGE2_EXTRACTION_PLAN, stage2Task.kind)

        val regularTask = stage2Task.copy(isStage2Extraction = false)
        assertEquals(BackgroundTaskKind.PLAN_EXECUTION, regularTask.kind)

        val importTask = BackgroundTaskRequest.ModelImportContinuation(
            taskId = "task-import-1",
            sourceUri = "content://com.android.externalstorage.documents/document/model.litertlm",
            expectedModelId = "gemma-4-e2b-it",
            expectedSha256Hex = "a".repeat(64),
            languageTag = "en",
            enqueuedAtEpochMs = 3_000L
        )
        assertEquals(BackgroundTaskKind.MODEL_IMPORT, importTask.kind)

        try {
            BackgroundTaskRequest.ModelImportContinuation(
                taskId = " ",
                sourceUri = "content://example/model",
                expectedModelId = "m1",
                expectedSha256Hex = "deadbeef",
                languageTag = "en",
                enqueuedAtEpochMs = 1L
            )
            fail("Expected IllegalArgumentException for blank taskId")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }

    @Test
    fun routineAndBackgroundOutcomesMapStatusAndMessageKeysCleanly() {
        val successStep = ToolResult.Success(UserMessage(MessageKey.ACTION_ALARM_SET))
        val executed = RoutineExecutionOutcome.Executed(
            ruleId = "rule-night",
            stepResults = listOf(successStep),
            message = UserMessage(MessageKey.ROUTINE_EXECUTED)
        )
        assertEquals("rule-night", executed.ruleId)
        assertEquals(1, executed.stepResults.size)

        val escalated = RoutineExecutionOutcome.EscalatedToInteractive(
            ruleId = "rule-vault",
            requiresBiometric = true,
            pendingToolNames = listOf("vault_read"),
            message = UserMessage(MessageKey.ROUTINE_ESCALATED_BIOMETRIC)
        )
        assertTrue(escalated.requiresBiometric)

        val confirmation = ToolResult.ConfirmationRequired(
            message = UserMessage(MessageKey.ACTION_CONFIRMATION_REQUIRED),
            pendingToolName = "create_sms_draft",
            targetId = "system.sms",
            canonicalArguments = emptyMap(),
            requiresBiometric = false,
            hasUntrustedHighRiskSlot = true
        )
        val paused = BackgroundTaskOutcome.ConfirmationRequired(
            taskId = "task-2",
            pendingConfirmation = confirmation,
            message = UserMessage(MessageKey.BACKGROUND_TASK_CONFIRMATION_REQUIRED)
        )
        assertEquals(BackgroundTaskStatus.AWAITING_CONFIRMATION, paused.status)
        assertFalse(paused.pendingConfirmation.requiresBiometric)
        assertTrue(paused.pendingConfirmation.hasUntrustedHighRiskSlot)

        // Ensure Phase 1 message keys remain present alongside Phase 4 keys.
        assertTrue(MessageKey.entries.contains(MessageKey.ACTION_ALARM_SET))
        assertTrue(MessageKey.entries.contains(MessageKey.ACTION_CALENDAR_EVENTS_QUERIED))
        assertTrue(MessageKey.entries.contains(MessageKey.ACTION_VAULT_NOTE_SAVED))
        assertTrue(MessageKey.entries.contains(MessageKey.ACTION_VOLUME_UPDATED))
        assertTrue(MessageKey.entries.contains(MessageKey.ACTION_APP_LAUNCHED))
        assertTrue(MessageKey.entries.contains(MessageKey.ACTION_NOTIFICATIONS_SUMMARIZED))
        assertTrue(MessageKey.entries.contains(MessageKey.ACTION_SAF_FILE_WRITTEN))
        assertTrue(MessageKey.entries.contains(MessageKey.ERROR_SYSTEM_PERMISSION_MISSING))
        assertTrue(MessageKey.entries.contains(MessageKey.ERROR_SAF_GRANT_MISSING))
    }
}

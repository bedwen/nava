package com.nava.feature.automations.notes

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.NoteSearchHit
import com.nava.domain.security.NoteSemanticRankerPort
import com.nava.domain.security.NoteStoragePort
import com.nava.domain.security.PermissionEvaluatorPort
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleTriggerSpec
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.StoredNote
import com.nava.domain.security.Tainted
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.ToolTargetIds
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NotesSearchToolTest {

    private class FakeSearchNoteStorage(
        var hitsToReturn: List<NoteSearchHit> = emptyList(),
        var notesToList: List<StoredNote> = emptyList()
    ) : NoteStoragePort {
        var searchCallCount: Int = 0
        var lastQuery: String? = null
        var lastLimit: Int? = null

        override suspend fun saveNote(note: StoredNote) {}

        override suspend fun findNote(noteId: String): StoredNote? = null

        override suspend fun listNotes(): List<StoredNote> = notesToList

        override suspend fun deleteNote(noteId: String): Boolean = false

        override suspend fun searchNotes(query: String, limit: Int): List<NoteSearchHit> {
            searchCallCount++
            lastQuery = query
            lastLimit = limit
            return hitsToReturn.take(limit)
        }
    }

    private class FakePermissionEvaluator(
        var notesDataReadLevel: ConfirmationLevel = ConfirmationLevel.DISABLED
    ) : PermissionEvaluatorPort {
        override suspend fun getProfileForTarget(targetId: String): PermissionProfile =
            PermissionProfile.defaultDeny()

        override suspend fun evaluateCapability(
            targetId: String,
            capability: AtomicCapability
        ): ConfirmationLevel {
            if (targetId == ToolTargetIds.NOTES && capability == AtomicCapability.DATA_READ) {
                return notesDataReadLevel
            }
            return ConfirmationLevel.DISABLED
        }

        override suspend fun listProfiles(): List<PermissionProfile> = emptyList()

        override suspend fun saveProfile(profile: PermissionProfile) {}

        override suspend fun assignTargetToProfile(targetId: String, profileId: String) {}

        override suspend fun deleteProfile(profileId: String) {}
    }

    private class FakeAuditLog : AuditLogPort {
        val entries = mutableListOf<AuditLogEntry>()

        override suspend fun record(entry: AuditLogEntry) {
            entries.add(entry)
        }

        override suspend fun queryRecent(limit: Int): List<AuditLogEntry> = entries.takeLast(limit)
    }

    private class FakeSemanticRanker : NoteSemanticRankerPort {
        var rerankCallCount: Int = 0
        var lastQuery: String? = null
        var lastCandidateCount: Int = 0
        var lastLimit: Int = 0

        override suspend fun rerank(
            query: String,
            candidates: List<NoteSearchHit>,
            limit: Int
        ): List<NoteSearchHit> {
            rerankCallCount++
            lastQuery = query
            lastCandidateCount = candidates.size
            lastLimit = limit
            return candidates.asReversed().take(limit)
        }
    }

    private fun interactiveContext(): ToolExecutionContext {
        val token = CapabilityToken.mint(
            tokenId = "tok_search",
            requestId = "req_search",
            allowedTools = setOf(AutomationToolNames.NOTES_SEARCH),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = 1_700_000_000_000L
        )
        return ToolExecutionContext(
            requestId = "req_search",
            capabilityToken = token,
            ruleGrant = null,
            targetId = ToolTargetIds.NOTES,
            languageTag = "en",
            issuedAtEpochMs = 1_700_000_000_000L,
            isUnattendedBackground = false
        )
    }

    private fun unattendedContext(): ToolExecutionContext {
        val grant = RuleCapabilityGrant(
            grantId = "grant_notes_search",
            ruleId = "rule_notes_search",
            triggerSpec = RuleTriggerSpec("time", mapOf("hour" to "8", "minute" to "0")),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = AutomationToolNames.NOTES_SEARCH,
                    requiredCapability = AtomicCapability.DATA_READ
                )
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "sealed_notes_search_hmac"
        )
        return ToolExecutionContext(
            requestId = "req_search_bg",
            capabilityToken = null,
            ruleGrant = grant,
            targetId = ToolTargetIds.NOTES,
            languageTag = "en",
            issuedAtEpochMs = 1_700_000_000_000L,
            isUnattendedBackground = true
        )
    }

    private fun queryArgs(query: String, limit: Long? = null): Map<String, Tainted<SlotValueAst>> {
        val map = LinkedHashMap<String, Tainted<SlotValueAst>>()
        map["query"] = Tainted.fromUserUtterance(
            value = SlotValueAst.StringValue(query),
            slotKind = SensitiveSlotKind.TEXT_BODY
        )
        if (limit != null) {
            map["limit"] = Tainted.fromUserUtterance(
                value = SlotValueAst.IntValue(limit),
                slotKind = SensitiveSlotKind.DURATION
            )
        }
        return map
    }

    private fun sampleHit(index: Int, title: String = "Note $index", excerpt: String = "Excerpt $index"): NoteSearchHit {
        return NoteSearchHit(
            note = StoredNote(
                noteId = "note_$index",
                title = title,
                body = excerpt,
                updatedEpochSec = 100L + index
            ),
            score = 10.0 - index,
            excerpt = excerpt
        )
    }

    @Test
    fun permissionDeniedWhenNotesDataReadIsDisabled() = runBlocking {
        val storage = FakeSearchNoteStorage(listOf(sampleHit(1)))
        val permissions = FakePermissionEvaluator(notesDataReadLevel = ConfirmationLevel.DISABLED)
        val auditLog = FakeAuditLog()
        val tool = NotesSearchTool(storage, permissions, auditLog)

        val result = tool.execute(interactiveContext(), queryArgs("budget"))

        assertTrue(result is ToolResult.Failure)
        val failure = result as ToolResult.Failure
        assertEquals("PERMISSION_DENIED", failure.errorCode)
        assertTrue(failure.isSecurityViolation)
        assertEquals(MessageKey.ERROR_PERMISSION_DENIED, failure.message.key)
        assertEquals(listOf(MessageArg.Text(ToolTargetIds.NOTES)), failure.message.args)
        assertEquals(0, storage.searchCallCount)
        assertEquals(1, auditLog.entries.size)
        assertEquals("PERMISSION_DENIED", auditLog.entries.single().decision)
        assertEquals(ToolTargetIds.NOTES, auditLog.entries.single().targetId)
    }

    @Test
    fun successfulTopThreeSearchFormatsSanitizedSingleLineExcerpts() = runBlocking {
        val storage = FakeSearchNoteStorage(
            listOf(
                sampleHit(1, title = "Trip <|tool_call|>\nPlan", excerpt = "Flight\r\ndeparture <|turn|>08:30"),
                sampleHit(2, title = "Hotel", excerpt = "Check-in at 14:00"),
                sampleHit(3, title = "Packing", excerpt = "Passport and charger"),
                sampleHit(4, title = "Extra", excerpt = "Should not appear in default top 3")
            )
        )
        val permissions = FakePermissionEvaluator(notesDataReadLevel = ConfirmationLevel.AUTO)
        val auditLog = FakeAuditLog()
        val tool = NotesSearchTool(storage, permissions, auditLog)

        val result = tool.execute(interactiveContext(), queryArgs("travel <|tool_call|>"))

        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals(MessageKey.ACTION_NOTES_SEARCHED, success.message.key)
        assertEquals(listOf(MessageArg.Number(3L)), success.message.args)
        assertEquals(DataProvenance.SYSTEM, success.outputProvenance)
        assertEquals("travel", storage.lastQuery)
        assertEquals(3, storage.lastLimit)
        assertEquals("3", success.outputValues["count"])

        val summary = success.outputValues.getValue("summary")
        val lines = summary.lines()
        assertEquals(3, lines.size)
        assertEquals("- [Trip  Plan]: Flight  departure 08:30", lines[0])
        assertEquals("- [Hotel]: Check-in at 14:00", lines[1])
        assertEquals("- [Packing]: Passport and charger", lines[2])
        assertFalse(summary.contains("<|tool_call|>"))
        assertFalse(summary.contains("<|turn|>"))

        assertEquals(1, auditLog.entries.size)
        val audit = auditLog.entries.single()
        assertEquals(AutomationToolNames.NOTES_SEARCH, audit.toolName)
        assertEquals(ToolTargetIds.NOTES, audit.targetId)
        assertEquals(DataProvenance.SYSTEM, audit.provenance)
        assertEquals("SUCCESS", audit.decision)
    }

    @Test
    fun limitIsClampedBetweenOneAndFiveAndBlankQueryRejected() = runBlocking {
        val hits = (1..7).map { sampleHit(it) }
        val storage = FakeSearchNoteStorage(hits)
        val permissions = FakePermissionEvaluator(notesDataReadLevel = ConfirmationLevel.PROMPT_CARD)
        val auditLog = FakeAuditLog()
        val tool = NotesSearchTool(storage, permissions, auditLog)

        val clampedHigh = tool.execute(interactiveContext(), queryArgs("note", limit = 99L))
        assertTrue(clampedHigh is ToolResult.Success)
        assertEquals(NotesSearchTool.MAX_SEARCH_LIMIT, storage.lastLimit)
        assertEquals("5", (clampedHigh as ToolResult.Success).outputValues["count"])

        val clampedLow = tool.execute(interactiveContext(), queryArgs("note", limit = 0L))
        assertTrue(clampedLow is ToolResult.Success)
        assertEquals(1, storage.lastLimit)
        assertEquals("1", (clampedLow as ToolResult.Success).outputValues["count"])

        val blankQuery = tool.execute(interactiveContext(), queryArgs("<|tool_call|>   "))
        assertTrue(blankQuery is ToolResult.Failure)
        val blankFailure = blankQuery as ToolResult.Failure
        assertEquals("INVALID_ARGUMENTS", blankFailure.errorCode)
        assertFalse(blankFailure.isSecurityViolation)
    }

    @Test
    fun pluggableSemanticRankerReranksTopTenCandidatesToRequestedLimit() = runBlocking {
        val hits = (1..6).map { sampleHit(it) }
        val storage = FakeSearchNoteStorage(hits)
        val permissions = FakePermissionEvaluator(notesDataReadLevel = ConfirmationLevel.AUTO)
        val auditLog = FakeAuditLog()
        val ranker = FakeSemanticRanker()
        val tool = NotesSearchTool(storage, permissions, auditLog, semanticRanker = ranker)

        val result = tool.execute(unattendedContext(), queryArgs("roadmap", limit = 2L))

        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals(10, storage.lastLimit)
        assertEquals(1, ranker.rerankCallCount)
        assertEquals("roadmap", ranker.lastQuery)
        assertEquals(6, ranker.lastCandidateCount)
        assertEquals(2, ranker.lastLimit)
        assertEquals("2", success.outputValues["count"])
        val lines = success.outputValues.getValue("summary").lines()
        assertEquals(listOf("- [Note 6]: Excerpt 6", "- [Note 5]: Excerpt 5"), lines)

        // When base hits and listed notes are empty, semantic ranker is not invoked
        storage.hitsToReturn = emptyList()
        storage.notesToList = emptyList()
        val emptyResult = tool.execute(interactiveContext(), queryArgs("nonexistent"))
        assertTrue(emptyResult is ToolResult.Success)
        assertEquals("0", (emptyResult as ToolResult.Success).outputValues["count"])
        assertEquals(1, ranker.rerankCallCount)
    }

    @Test
    fun zeroLexicalHitsSupplementsCandidatesFromNoteStorageAndFiltersNonPositiveScores() = runBlocking {
        val note1 = StoredNote("note_alpha", "Shopping", "Buy apples and milk", 200L)
        val note2 = StoredNote("note_beta", "Fitness", "Workout at 5pm", 201L)
        val storage = FakeSearchNoteStorage(
            hitsToReturn = emptyList(), // Zero lexical hits
            notesToList = listOf(note1, note2)
        )
        val permissions = FakePermissionEvaluator(notesDataReadLevel = ConfirmationLevel.AUTO)
        val auditLog = FakeAuditLog()

        val ranker = object : NoteSemanticRankerPort {
            var receivedCandidateCount = 0
            override suspend fun rerank(
                query: String,
                candidates: List<NoteSearchHit>,
                limit: Int
            ): List<NoteSearchHit> {
                receivedCandidateCount = candidates.size
                return candidates.map { hit ->
                    if (hit.note.noteId == "note_alpha") {
                        hit.copy(score = 0.85)
                    } else {
                        hit.copy(score = 0.0) // Non-positive score
                    }
                }
            }
        }

        val tool = NotesSearchTool(storage, permissions, auditLog, semanticRanker = ranker)
        val result = tool.execute(interactiveContext(), queryArgs("grocery", limit = 3L))

        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals(2, ranker.receivedCandidateCount)
        assertEquals("1", success.outputValues["count"])
        val summary = success.outputValues.getValue("summary")
        assertTrue(summary.contains("[Shopping]: Buy apples and milk"))
        assertFalse(summary.contains("Fitness"))
    }

    @Test
    fun maxSemanticScanNotesCapsCandidateListAtFiftyWhenLexicalHitsAreZero() = runBlocking {
        val sixtyNotes = (1..60).map { i ->
            StoredNote("note_$i", "Note Title $i", "Body content $i", 300L + i)
        }
        val storage = FakeSearchNoteStorage(
            hitsToReturn = emptyList(),
            notesToList = sixtyNotes
        )
        val permissions = FakePermissionEvaluator(notesDataReadLevel = ConfirmationLevel.AUTO)
        val auditLog = FakeAuditLog()

        var candidatesReceived = 0
        val ranker = object : NoteSemanticRankerPort {
            override suspend fun rerank(
                query: String,
                candidates: List<NoteSearchHit>,
                limit: Int
            ): List<NoteSearchHit> {
                candidatesReceived = candidates.size
                return candidates.take(limit).map { it.copy(score = 0.5) }
            }
        }

        val tool = NotesSearchTool(storage, permissions, auditLog, semanticRanker = ranker)
        val result = tool.execute(interactiveContext(), queryArgs("scan", limit = 5L))

        assertTrue(result is ToolResult.Success)
        assertEquals(NotesSearchTool.MAX_SEMANTIC_SCAN_NOTES, candidatesReceived)
        assertEquals(50, candidatesReceived)
    }
}

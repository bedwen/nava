package com.nava.feature.automations.notes

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.NoteSearchHit
import com.nava.domain.security.NoteSemanticRankerPort
import com.nava.domain.security.NoteStoragePort
import com.nava.domain.security.PermissionEvaluatorPort
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.StoredNote
import com.nava.domain.security.Tainted
import com.nava.domain.tool.NavaTool
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolCategory
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolResult
import com.nava.domain.tool.ToolSchemaField
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.ToolArgumentReader
import com.nava.feature.automations.common.ToolTargetIds

/**
 * [NavaTool] adapter for offline lexical/semantic search across standard encrypted notes
 * (`encrypted_notes` via [NoteStoragePort]).
 *
 * Security invariants:
 * - Requires [AtomicCapability.DATA_READ] granted on [ToolTargetIds.NOTES].
 * - Searches strictly standard notes; biometric `NavaVault` entries are never read.
 * - Sanitizes query input and returned note titles/excerpts via [Gemma4InputSanitizer] to
 *   prevent Gemma 4 control-token smuggling and multiline formatting spoofing.
 * - Never writes query strings or note plaintexts into [AuditLogEntry.actionSummary].
 */
class NotesSearchTool(
    private val noteStorage: NoteStoragePort,
    private val permissionEvaluator: PermissionEvaluatorPort,
    private val auditLog: AuditLogPort,
    private val semanticRanker: NoteSemanticRankerPort? = null,
    private val clock: () -> Long = System::currentTimeMillis
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.NOTES_SEARCH,
        displayNameKey = "tool_notes_search_name",
        description = "Searches the user's encrypted local notes offline and returns top matching excerpts",
        category = ToolCategory.NOTES_FILES,
        requiredCapability = AtomicCapability.DATA_READ,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = FIELD_QUERY,
                description = "Search query keywords or phrase",
                required = true,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = FIELD_LIMIT,
                description = "Maximum number of matching notes to return (1 to 5)",
                required = false,
                slotKind = SensitiveSlotKind.DURATION,
                valueType = SlotValueType.INTEGER
            )
        ),
        supportsUnattendedRule = true
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else clock()

        val level = permissionEvaluator.evaluateCapability(ToolTargetIds.NOTES, AtomicCapability.DATA_READ)
        if (!level.isAllowed) {
            auditLog.record(
                AuditLogEntry(
                    timestampEpochMs = nowMs,
                    toolName = metadata.name,
                    targetId = ToolTargetIds.NOTES,
                    actionSummary = "Notes search access denied for ${ToolTargetIds.NOTES}",
                    provenance = DataProvenance.SYSTEM,
                    decision = DECISION_PERMISSION_DENIED
                )
            )
            return ToolResult.Failure(
                message = UserMessage(
                    key = MessageKey.ERROR_PERMISSION_DENIED,
                    args = listOf(MessageArg.Text(ToolTargetIds.NOTES))
                ),
                errorCode = DECISION_PERMISSION_DENIED,
                isSecurityViolation = true
            )
        }

        val rawQuery = ToolArgumentReader.getString(arguments, FIELD_QUERY)?.value
            ?: return ToolArgumentReader.invalidArgumentsFailure("query is required")
        val query = Gemma4InputSanitizer.sanitize(rawQuery).trim()
        if (query.isBlank()) {
            return ToolArgumentReader.invalidArgumentsFailure("query is required")
        }

        val limit = (ToolArgumentReader.getInt(arguments, FIELD_LIMIT)?.value ?: DEFAULT_SEARCH_LIMIT)
            .coerceIn(1, MAX_SEARCH_LIMIT)

        val candidateLimit = if (semanticRanker != null) SEMANTIC_CANDIDATE_LIMIT else limit
        val baseHits = noteStorage.searchNotes(query, candidateLimit)
        val hits = if (semanticRanker != null) {
            val candidates = if (baseHits.size < candidateLimit) {
                val existingIds = baseHits.map { it.note.noteId }.toSet()
                val additional = noteStorage.listNotes()
                    .filter { it.noteId !in existingIds }
                    .take(MAX_SEMANTIC_SCAN_NOTES)
                    .map { note ->
                        NoteSearchHit(
                            note = note,
                            score = 0.0,
                            excerpt = note.body.take(EXCERPT_PREVIEW_LIMIT)
                        )
                    }
                baseHits + additional
            } else {
                baseHits
            }

            if (candidates.isNotEmpty()) {
                val reranked = semanticRanker.rerank(query, candidates, limit)
                if (baseHits.isEmpty()) {
                    reranked.filter { it.score > 0.0 }.take(limit)
                } else {
                    reranked.take(limit)
                }
            } else {
                emptyList()
            }
        } else {
            baseHits.take(limit)
        }

        val summary = hits.joinToString("\n") { hit ->
            val cleanTitle = sanitizeSingleLine(hit.note.title).ifBlank { hit.note.noteId }
            val cleanExcerpt = sanitizeSingleLine(hit.excerpt)
            "- [$cleanTitle]: $cleanExcerpt"
        }

        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = nowMs,
                toolName = metadata.name,
                targetId = ToolTargetIds.NOTES,
                actionSummary = "Searched encrypted notes (results=${hits.size})",
                provenance = DataProvenance.SYSTEM,
                decision = DECISION_SUCCESS
            )
        )

        return ToolResult.Success(
            message = UserMessage(
                key = MessageKey.ACTION_NOTES_SEARCHED,
                args = listOf(MessageArg.Number(hits.size.toLong()))
            ),
            outputValues = mapOf(
                "count" to hits.size.toString(),
                "summary" to summary
            ),
            outputProvenance = DataProvenance.SYSTEM
        )
    }

    private fun sanitizeSingleLine(value: String): String {
        return Gemma4InputSanitizer.sanitize(value)
            .replace('\r', ' ')
            .replace('\n', ' ')
            .trim()
    }

    companion object {
        const val FIELD_QUERY: String = "query"
        const val FIELD_LIMIT: String = "limit"
        const val DEFAULT_SEARCH_LIMIT: Int = 3
        const val MAX_SEARCH_LIMIT: Int = 5
        const val MAX_SEMANTIC_SCAN_NOTES: Int = 50
        private const val SEMANTIC_CANDIDATE_LIMIT: Int = 10
        private const val EXCERPT_PREVIEW_LIMIT: Int = 180
        private const val DECISION_PERMISSION_DENIED: String = "PERMISSION_DENIED"
        private const val DECISION_SUCCESS: String = "SUCCESS"
    }
}

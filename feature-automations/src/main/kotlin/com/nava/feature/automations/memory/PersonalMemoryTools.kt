package com.nava.feature.automations.memory

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.memory.PersonalFact
import com.nava.domain.memory.PersonalMemoryPort
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.SensitiveSlotKind
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
import java.text.Normalizer
import java.util.Locale
import java.util.UUID

/**
 * Shared helpers for the personal memory tools (`remember_fact`, `recall_facts`, `forget_fact`).
 */
internal object PersonalMemorySupport {
    const val FIELD_FACT: String = "fact"
    const val FIELD_QUERY: String = "query"

    private val DIACRITICS = Regex("\\p{InCombiningDiacriticalMarks}+")

    fun fold(raw: String): String {
        val nfd = Normalizer.normalize(raw, Normalizer.Form.NFD)
        return DIACRITICS.replace(nfd, "")
            .replace('\u0131', 'i')
            .replace('\u0130', 'i')
            .lowercase(Locale.ROOT)
            .replace(Regex("\\s+"), " ")
            .trim()
    }

    private val NON_WORD = Regex("[^\\p{L}\\p{N}]+")

    /**
     * True when every meaningful query word shares a stem with some word of the fact, so
     * inflected forms still match ("esimin adini" vs "Esimin adi Ayse"). Stems are compared on a
     * common prefix of at least [MIN_STEM_CHARS] characters; short filler words are ignored.
     */
    fun matchesForgetQuery(factText: String, foldedQuery: String): Boolean {
        val factFolded = fold(factText)
        if (factFolded.contains(foldedQuery)) return true
        val factWords = factFolded.split(NON_WORD).filter { it.isNotEmpty() }
        val queryWords = foldedQuery.split(NON_WORD).filter { it.length >= MIN_STEM_CHARS }
        if (queryWords.isEmpty()) return false
        return queryWords.all { q -> factWords.any { f -> f == q || commonPrefix(q, f) >= MIN_STEM_CHARS } }
    }

    private fun commonPrefix(a: String, b: String): Int {
        val n = minOf(a.length, b.length)
        var i = 0
        while (i < n && a[i] == b[i]) i++
        return i
    }

    private const val MIN_STEM_CHARS: Int = 3

    suspend fun audit(
        auditLog: AuditLogPort,
        nowMs: Long,
        toolName: String,
        summary: String,
        provenance: DataProvenance,
        decision: String
    ) {
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = nowMs,
                toolName = toolName,
                targetId = ToolTargetIds.MEMORY,
                actionSummary = summary,
                provenance = provenance,
                decision = decision
            )
        )
    }
}

/**
 * Stores a fact the user explicitly asked Nava to remember.
 *
 * Security invariants (Iron Law 6): the fact must come from a
 * [DataProvenance.USER_UTTERANCE] slot. Any other provenance is refused, because remembered facts
 * are later shown to the Stage 1 planner and must never carry text from notifications, files,
 * or other external sources. Never runs unattended.
 */
class RememberFactTool(
    private val memory: PersonalMemoryPort,
    private val auditLog: AuditLogPort,
    private val idGenerator: () -> String = { "fact_" + UUID.randomUUID().toString() }
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.REMEMBER_FACT,
        displayNameKey = "tool_remember_fact_name",
        description = "Remembers a personal fact the user states about themselves (names, routines, preferences)",
        category = ToolCategory.NOTES_FILES,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = PersonalMemorySupport.FIELD_FACT,
                description = "The fact to remember, as a short sentence",
                required = true,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            )
        ),
        supportsUnattendedRule = false
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else System.currentTimeMillis()
        val raw = ToolArgumentReader.getString(arguments, PersonalMemorySupport.FIELD_FACT)
            ?: return ToolArgumentReader.invalidArgumentsFailure(PersonalMemorySupport.FIELD_FACT)

        if (context.isUnattendedBackground || raw.provenance != DataProvenance.USER_UTTERANCE) {
            PersonalMemorySupport.audit(
                auditLog, nowMs, metadata.name,
                "Refused to remember a fact that did not come from the user",
                raw.provenance, "SECURITY_VIOLATION"
            )
            return ToolResult.Failure(
                message = UserMessage(MessageKey.ERROR_SECURITY_VIOLATION),
                errorCode = "MEMORY_UNTRUSTED_SOURCE",
                isSecurityViolation = true
            )
        }

        val text = try {
            Gemma4InputSanitizer.sanitize(raw.value).trim().replace(Regex("\\s+"), " ")
        } catch (_: SecurityException) {
            ""
        }.take(PersonalFact.MAX_FACT_CHARS)
        if (text.isEmpty()) {
            return ToolArgumentReader.invalidArgumentsFailure(PersonalMemorySupport.FIELD_FACT)
        }

        val existing = memory.listFacts()
        val folded = PersonalMemorySupport.fold(text)
        if (existing.none { PersonalMemorySupport.fold(it.text) == folded }) {
            if (existing.size >= PersonalFact.MAX_FACTS) {
                return ToolResult.Failure(
                    message = UserMessage(
                        MessageKey.ERROR_MEMORY_FULL,
                        listOf(MessageArg.Number(PersonalFact.MAX_FACTS.toLong()))
                    ),
                    errorCode = "MEMORY_FULL"
                )
            }
            memory.saveFact(PersonalFact(factId = idGenerator(), text = text, createdAtEpochMs = nowMs))
        }

        PersonalMemorySupport.audit(
            auditLog, nowMs, metadata.name, "Remembered a personal fact",
            DataProvenance.USER_UTTERANCE, "SUCCESS"
        )
        return ToolResult.Success(
            message = UserMessage(MessageKey.ACTION_FACT_REMEMBERED, listOf(MessageArg.Text(text)))
        )
    }
}

/** Lists what Nava remembers about the user (`recall_facts`). */
class RecallFactsTool(
    private val memory: PersonalMemoryPort,
    private val auditLog: AuditLogPort
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.RECALL_FACTS,
        displayNameKey = "tool_recall_facts_name",
        description = "Lists the personal facts Nava remembers about the user",
        category = ToolCategory.NOTES_FILES,
        requiredCapability = AtomicCapability.DATA_READ,
        schemaVersion = 1,
        fields = emptyList(),
        supportsUnattendedRule = false
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else System.currentTimeMillis()
        val facts = memory.listFacts()
        PersonalMemorySupport.audit(
            auditLog, nowMs, metadata.name, "Listed ${facts.size} personal facts",
            DataProvenance.USER_UTTERANCE, "SUCCESS"
        )
        if (facts.isEmpty()) {
            return ToolResult.Success(message = UserMessage(MessageKey.ACTION_FACTS_EMPTY))
        }
        val listing = facts.joinToString("\n") { "\u2022 ${it.text}" }
        return ToolResult.Success(
            message = UserMessage(
                MessageKey.ACTION_FACTS_LISTED,
                listOf(MessageArg.Number(facts.size.toLong()), MessageArg.Text(listing))
            ),
            outputValues = mapOf("count" to facts.size.toString()),
            // Facts are user-authored: they were only ever stored from USER_UTTERANCE slots.
            outputProvenance = DataProvenance.USER_UTTERANCE
        )
    }
}

/**
 * Forgets remembered facts matching a query (`forget_fact`). Deletion uses
 * [AtomicCapability.MODIFY_DELETE_SEND], so it always goes through a confirmation card.
 */
class ForgetFactTool(
    private val memory: PersonalMemoryPort,
    private val auditLog: AuditLogPort
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.FORGET_FACT,
        displayNameKey = "tool_forget_fact_name",
        description = "Forgets remembered personal facts that contain the given words",
        category = ToolCategory.NOTES_FILES,
        requiredCapability = AtomicCapability.MODIFY_DELETE_SEND,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = PersonalMemorySupport.FIELD_QUERY,
                description = "Words identifying the fact to forget",
                required = true,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            )
        ),
        supportsUnattendedRule = false
    )

    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else System.currentTimeMillis()
        val query = ToolArgumentReader.getString(arguments, PersonalMemorySupport.FIELD_QUERY)
            ?: return ToolArgumentReader.invalidArgumentsFailure(PersonalMemorySupport.FIELD_QUERY)
        val foldedQuery = PersonalMemorySupport.fold(query.value)
        if (foldedQuery.length < MIN_QUERY_CHARS) {
            return ToolArgumentReader.invalidArgumentsFailure(PersonalMemorySupport.FIELD_QUERY)
        }
        val matches = memory.listFacts().filter { PersonalMemorySupport.matchesForgetQuery(it.text, foldedQuery) }
        if (matches.isEmpty()) {
            return ToolResult.Failure(
                message = UserMessage(MessageKey.ERROR_NOT_FOUND, listOf(MessageArg.Text(query.value))),
                errorCode = "NOT_FOUND"
            )
        }
        for (fact in matches) {
            memory.deleteFact(fact.factId)
        }
        PersonalMemorySupport.audit(
            auditLog, nowMs, metadata.name, "Forgot ${matches.size} personal facts",
            query.provenance, "SUCCESS"
        )
        return ToolResult.Success(
            message = UserMessage(
                MessageKey.ACTION_FACT_FORGOTTEN,
                listOf(MessageArg.Number(matches.size.toLong()))
            )
        )
    }

    private companion object {
        const val MIN_QUERY_CHARS: Int = 2
    }
}

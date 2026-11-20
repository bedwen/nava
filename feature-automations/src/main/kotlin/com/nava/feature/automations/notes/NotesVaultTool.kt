package com.nava.feature.automations.notes

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.NoteStoragePort
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.StoredNote
import com.nava.domain.security.Tainted
import com.nava.domain.security.VaultPort
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
 * Standard encrypted local notes and biometric Nava Secure Vault tools.
 *
 * Security Invariants (PLAN.md 5.2, 5.6, 5.7):
 * - Standard notes operate over [NoteStoragePort] (encrypted with `nava_db_master_key`).
 * - Vault notes operate over [VaultPort] (backed by Android Keystore `nava_vault_biometric_key`).
 * - Vault tools strictly forbid unattended background execution (`isUnattendedBackground == true`).
 * - While the vault is locked (`!vaultPort.isUnlocked()`), vault operations immediately return
 *   [ToolResult.ConfirmationRequired] with `requiresBiometric = true` and targetId [ToolTargetIds.VAULT].
 * - Decrypted and encoded [ByteArray] buffers for vault notes are strictly zeroized (`fill(0)`)
 *   in a `finally` block immediately after use.
 * - Note bodies and secret plaintexts are never leaked into [AuditLogEntry.actionSummary].
 */
sealed class NotesVaultTool(
    override val metadata: ToolMetadata,
    protected val auditLog: AuditLogPort,
    protected val targetId: String
) : NavaTool {

    protected suspend fun recordAudit(
        timestampMs: Long,
        actionSummary: String,
        provenance: com.nava.domain.security.DataProvenance,
        decision: String
    ) {
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = timestampMs,
                toolName = metadata.name,
                targetId = targetId,
                actionSummary = actionSummary,
                provenance = provenance,
                decision = decision
            )
        )
    }

    /**
     * Standard notes query tool (`notes_read`).
     */
    class StandardNotesRead(
        private val noteStorage: NoteStoragePort,
        auditLog: AuditLogPort
    ) : NotesVaultTool(
        metadata = ToolMetadata(
            name = AutomationToolNames.NOTES_READ,
            displayNameKey = "action_note_read",
            description = "Reads a specific stored note or lists all saved notes",
            category = ToolCategory.NOTES_FILES,
            requiredCapability = AtomicCapability.DATA_READ,
            schemaVersion = 1,
            fields = listOf(
                ToolSchemaField(
                    name = FIELD_NOTE_ID,
                    description = "Optional identifier of the note to read",
                    required = false,
                    slotKind = SensitiveSlotKind.TEXT_BODY,
                    valueType = SlotValueType.STRING
                )
            ),
            supportsUnattendedRule = true
        ),
        auditLog = auditLog,
        targetId = ToolTargetIds.NOTES
    ) {
        override suspend fun execute(
            context: ToolExecutionContext,
            arguments: Map<String, Tainted<SlotValueAst>>
        ): ToolResult {
            val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else System.currentTimeMillis()
            val noteIdTainted = ToolArgumentReader.getString(arguments, FIELD_NOTE_ID)
                ?: ToolArgumentReader.getString(arguments, "id")
                ?: ToolArgumentReader.getString(arguments, "noteId")

            if (noteIdTainted == null || noteIdTainted.value.isBlank()) {
                val notes = noteStorage.listNotes()
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Listed all standard notes (count=${notes.size})",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "SUCCESS"
                )
                return ToolResult.Success(
                    message = UserMessage(
                        key = MessageKey.ACTION_NOTE_READ,
                        args = listOf(MessageArg.Number(notes.size.toLong()))
                    ),
                    outputValues = mapOf(
                        "count" to notes.size.toString(),
                        "note_ids" to notes.joinToString(",") { it.noteId }
                    )
                )
            }

            val noteId = noteIdTainted.value.trim()
            val found = noteStorage.findNote(noteId)
            if (found == null) {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Failed read note: not found ($noteId)",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "NOT_FOUND"
                )
                return ToolArgumentReader.notFoundFailure(noteId)
            }

            recordAudit(
                timestampMs = nowMs,
                actionSummary = "Read standard note: $noteId",
                provenance = ToolArgumentReader.worstProvenance(arguments),
                decision = "SUCCESS"
            )
            return ToolResult.Success(
                message = UserMessage(
                    key = MessageKey.ACTION_NOTE_READ,
                    args = listOf(MessageArg.Text(found.title.ifBlank { found.noteId }))
                ),
                outputValues = mapOf(
                    FIELD_NOTE_ID to found.noteId,
                    "title" to found.title,
                    FIELD_BODY to found.body
                )
            )
        }
    }

    /**
     * Standard notes create or update tool (`notes_create`).
     */
    class StandardNotesCreate(
        private val noteStorage: NoteStoragePort,
        auditLog: AuditLogPort
    ) : NotesVaultTool(
        metadata = ToolMetadata(
            name = AutomationToolNames.NOTES_CREATE,
            displayNameKey = "action_note_saved",
            description = "Creates or updates a standard encrypted note",
            category = ToolCategory.NOTES_FILES,
            requiredCapability = AtomicCapability.CREATE_DRAFT,
            schemaVersion = 1,
            fields = listOf(
                ToolSchemaField(
                    name = FIELD_BODY,
                    description = "Content body of the note",
                    required = true,
                    slotKind = SensitiveSlotKind.TEXT_BODY,
                    valueType = SlotValueType.STRING
                ),
                ToolSchemaField(
                    name = FIELD_TITLE,
                    description = "Optional title of the note",
                    required = false,
                    slotKind = SensitiveSlotKind.EVENT_TITLE,
                    valueType = SlotValueType.STRING
                ),
                ToolSchemaField(
                    name = FIELD_NOTE_ID,
                    description = "Optional custom note identifier",
                    required = false,
                    slotKind = SensitiveSlotKind.TEXT_BODY,
                    valueType = SlotValueType.STRING
                )
            ),
            supportsUnattendedRule = true
        ),
        auditLog = auditLog,
        targetId = ToolTargetIds.NOTES
    ) {
        override suspend fun execute(
            context: ToolExecutionContext,
            arguments: Map<String, Tainted<SlotValueAst>>
        ): ToolResult {
            val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else System.currentTimeMillis()

            val bodyTainted = ToolArgumentReader.getRawString(arguments, FIELD_BODY)
                ?: ToolArgumentReader.getRawString(arguments, "content")
                ?: ToolArgumentReader.getRawString(arguments, "text")
                ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_BODY)

            val title = ToolArgumentReader.getString(arguments, FIELD_TITLE)?.value.orEmpty()
            val noteId = ToolArgumentReader.getString(arguments, FIELD_NOTE_ID)?.value
                ?: "note_${nowMs}_${(1000..9999).random()}"

            val storedNote = StoredNote(
                noteId = noteId,
                title = title,
                body = bodyTainted.value,
                updatedEpochSec = nowMs / 1000L
            )
            noteStorage.saveNote(storedNote)

            recordAudit(
                timestampMs = nowMs,
                actionSummary = "Saved standard note: $noteId",
                provenance = ToolArgumentReader.worstProvenance(arguments),
                decision = "SUCCESS"
            )

            return ToolResult.Success(
                message = UserMessage(
                    key = MessageKey.ACTION_NOTE_SAVED,
                    args = listOf(MessageArg.Text(title.ifBlank { noteId }))
                ),
                outputValues = mapOf(
                    FIELD_NOTE_ID to noteId
                )
            )
        }
    }

    /**
     * Standard notes delete tool (`notes_delete`).
     */
    class StandardNotesDelete(
        private val noteStorage: NoteStoragePort,
        auditLog: AuditLogPort
    ) : NotesVaultTool(
        metadata = ToolMetadata(
            name = AutomationToolNames.NOTES_DELETE,
            displayNameKey = "action_note_deleted",
            description = "Deletes a standard encrypted note by identifier",
            category = ToolCategory.NOTES_FILES,
            requiredCapability = AtomicCapability.MODIFY_DELETE_SEND,
            schemaVersion = 1,
            fields = listOf(
                ToolSchemaField(
                    name = FIELD_NOTE_ID,
                    description = "Identifier of the note to delete",
                    required = true,
                    slotKind = SensitiveSlotKind.TEXT_BODY,
                    valueType = SlotValueType.STRING
                )
            ),
            supportsUnattendedRule = false
        ),
        auditLog = auditLog,
        targetId = ToolTargetIds.NOTES
    ) {
        override suspend fun execute(
            context: ToolExecutionContext,
            arguments: Map<String, Tainted<SlotValueAst>>
        ): ToolResult {
            val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else System.currentTimeMillis()

            if (context.isUnattendedBackground) {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Security violation: notes_delete attempted in unattended background",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "SECURITY_VIOLATION"
                )
                return ToolArgumentReader.securityFailure("UNATTENDED_DELETE_FORBIDDEN")
            }

            val noteIdTainted = ToolArgumentReader.getString(arguments, FIELD_NOTE_ID)
                ?: ToolArgumentReader.getString(arguments, "id")
                ?: ToolArgumentReader.getString(arguments, "noteId")
                ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_NOTE_ID)

            val noteId = noteIdTainted.value.trim()
            val deleted = noteStorage.deleteNote(noteId)
            if (!deleted) {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Failed delete note: not found ($noteId)",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "NOT_FOUND"
                )
                return ToolArgumentReader.notFoundFailure(noteId)
            }

            recordAudit(
                timestampMs = nowMs,
                actionSummary = "Deleted standard note: $noteId",
                provenance = ToolArgumentReader.worstProvenance(arguments),
                decision = "SUCCESS"
            )

            return ToolResult.Success(
                message = UserMessage(
                    key = MessageKey.ACTION_NOTE_DELETED,
                    args = listOf(MessageArg.Text(noteId))
                ),
                outputValues = mapOf(
                    FIELD_NOTE_ID to noteId,
                    "deleted" to "true"
                )
            )
        }
    }

    /**
     * Vault notes read / query tool (`vault_read`).
     */
    class VaultRead(
        private val vaultPort: VaultPort,
        auditLog: AuditLogPort
    ) : NotesVaultTool(
        metadata = ToolMetadata(
            name = AutomationToolNames.VAULT_READ,
            displayNameKey = "action_vault_note_read",
            description = "Reads an encrypted note or lists note identifiers from Nava Secure Vault",
            category = ToolCategory.NOTES_FILES,
            requiredCapability = AtomicCapability.DATA_READ,
            schemaVersion = 1,
            fields = listOf(
                ToolSchemaField(
                    name = FIELD_NOTE_ID,
                    description = "Optional identifier of the vault note to read",
                    required = false,
                    slotKind = SensitiveSlotKind.TEXT_BODY,
                    valueType = SlotValueType.STRING
                )
            ),
            supportsUnattendedRule = false
        ),
        auditLog = auditLog,
        targetId = ToolTargetIds.VAULT
    ) {
        override suspend fun execute(
            context: ToolExecutionContext,
            arguments: Map<String, Tainted<SlotValueAst>>
        ): ToolResult {
            val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else System.currentTimeMillis()

            if (context.isUnattendedBackground) {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Security violation: vault_read attempted in unattended background",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "SECURITY_VIOLATION"
                )
                return ToolArgumentReader.securityFailure("UNATTENDED_VAULT_FORBIDDEN")
            }

            if (!vaultPort.isUnlocked()) {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Vault locked: biometric authentication required",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "BIOMETRIC_REQUIRED"
                )
                return ToolResult.ConfirmationRequired(
                    message = UserMessage(MessageKey.ERROR_VAULT_LOCKED),
                    pendingToolName = metadata.name,
                    targetId = ToolTargetIds.VAULT,
                    canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                    requiresBiometric = true
                )
            }

            val noteIdTainted = ToolArgumentReader.getString(arguments, FIELD_NOTE_ID)
                ?: ToolArgumentReader.getString(arguments, "id")
                ?: ToolArgumentReader.getString(arguments, "noteId")

            if (noteIdTainted == null || noteIdTainted.value.isBlank()) {
                val ids = vaultPort.listNoteIds()
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Listed vault note identifiers (count=${ids.size})",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "SUCCESS"
                )
                return ToolResult.Success(
                    message = UserMessage(
                        key = MessageKey.ACTION_VAULT_NOTE_READ,
                        args = listOf(MessageArg.Number(ids.size.toLong()))
                    ),
                    outputValues = mapOf(
                        "count" to ids.size.toString(),
                        "note_ids" to ids.joinToString(",")
                    )
                )
            }

            val noteId = noteIdTainted.value.trim()
            val text: String
            try {
                val bytes = vaultPort.readNote(noteId)
                try {
                    text = bytes.toString(Charsets.UTF_8)
                } finally {
                    bytes.fill(0)
                }
            } catch (e: Exception) {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Failed read vault note: not found ($noteId)",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "NOT_FOUND"
                )
                return ToolArgumentReader.notFoundFailure(noteId)
            }

            recordAudit(
                timestampMs = nowMs,
                actionSummary = "Read vault note: $noteId",
                provenance = ToolArgumentReader.worstProvenance(arguments),
                decision = "SUCCESS"
            )

            return ToolResult.Success(
                message = UserMessage(
                    key = MessageKey.ACTION_VAULT_NOTE_READ,
                    args = listOf(MessageArg.Text(noteId))
                ),
                outputValues = mapOf(
                    FIELD_NOTE_ID to noteId,
                    FIELD_CONTENT to text
                )
            )
        }
    }

    /**
     * Vault notes write tool (`vault_write`).
     */
    class VaultWrite(
        private val vaultPort: VaultPort,
        auditLog: AuditLogPort
    ) : NotesVaultTool(
        metadata = ToolMetadata(
            name = AutomationToolNames.VAULT_WRITE,
            displayNameKey = "action_vault_note_saved",
            description = "Writes an encrypted note into Nava Secure Vault",
            category = ToolCategory.NOTES_FILES,
            requiredCapability = AtomicCapability.CREATE_DRAFT,
            schemaVersion = 1,
            fields = listOf(
                ToolSchemaField(
                    name = FIELD_CONTENT,
                    description = "Content text of the note to store in vault",
                    required = true,
                    slotKind = SensitiveSlotKind.TEXT_BODY,
                    valueType = SlotValueType.STRING
                ),
                ToolSchemaField(
                    name = FIELD_NOTE_ID,
                    description = "Optional custom identifier for the vault note",
                    required = false,
                    slotKind = SensitiveSlotKind.TEXT_BODY,
                    valueType = SlotValueType.STRING
                )
            ),
            supportsUnattendedRule = false
        ),
        auditLog = auditLog,
        targetId = ToolTargetIds.VAULT
    ) {
        override suspend fun execute(
            context: ToolExecutionContext,
            arguments: Map<String, Tainted<SlotValueAst>>
        ): ToolResult {
            val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else System.currentTimeMillis()

            if (context.isUnattendedBackground) {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Security violation: vault_write attempted in unattended background",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "SECURITY_VIOLATION"
                )
                return ToolArgumentReader.securityFailure("UNATTENDED_VAULT_FORBIDDEN")
            }

            if (!vaultPort.isUnlocked()) {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Vault locked: biometric authentication required",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "BIOMETRIC_REQUIRED"
                )
                return ToolResult.ConfirmationRequired(
                    message = UserMessage(MessageKey.ERROR_VAULT_LOCKED),
                    pendingToolName = metadata.name,
                    targetId = ToolTargetIds.VAULT,
                    canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                    requiresBiometric = true
                )
            }

            val contentTainted = ToolArgumentReader.getRawString(arguments, FIELD_CONTENT)
                ?: ToolArgumentReader.getRawString(arguments, "body")
                ?: ToolArgumentReader.getRawString(arguments, "text")
                ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_CONTENT)

            val noteId = ToolArgumentReader.getString(arguments, FIELD_NOTE_ID)?.value
                ?: "vault_note_${nowMs}_${(1000..9999).random()}"

            val bytes = contentTainted.value.toByteArray(Charsets.UTF_8)
            try {
                vaultPort.writeNote(noteId, bytes)
            } finally {
                bytes.fill(0)
            }

            recordAudit(
                timestampMs = nowMs,
                actionSummary = "Saved vault note: $noteId",
                provenance = ToolArgumentReader.worstProvenance(arguments),
                decision = "SUCCESS"
            )

            return ToolResult.Success(
                message = UserMessage(
                    key = MessageKey.ACTION_VAULT_NOTE_SAVED,
                    args = listOf(MessageArg.Text(noteId))
                ),
                outputValues = mapOf(
                    FIELD_NOTE_ID to noteId
                )
            )
        }
    }

    /**
     * Vault notes delete tool (`vault_delete`).
     */
    class VaultDelete(
        private val vaultPort: VaultPort,
        auditLog: AuditLogPort
    ) : NotesVaultTool(
        metadata = ToolMetadata(
            name = AutomationToolNames.VAULT_DELETE,
            displayNameKey = "action_vault_note_deleted",
            description = "Deletes an encrypted note from Nava Secure Vault",
            category = ToolCategory.NOTES_FILES,
            requiredCapability = AtomicCapability.MODIFY_DELETE_SEND,
            schemaVersion = 1,
            fields = listOf(
                ToolSchemaField(
                    name = FIELD_NOTE_ID,
                    description = "Identifier of the vault note to delete",
                    required = true,
                    slotKind = SensitiveSlotKind.TEXT_BODY,
                    valueType = SlotValueType.STRING
                )
            ),
            supportsUnattendedRule = false
        ),
        auditLog = auditLog,
        targetId = ToolTargetIds.VAULT
    ) {
        override suspend fun execute(
            context: ToolExecutionContext,
            arguments: Map<String, Tainted<SlotValueAst>>
        ): ToolResult {
            val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else System.currentTimeMillis()

            if (context.isUnattendedBackground) {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Security violation: vault_delete attempted in unattended background",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "SECURITY_VIOLATION"
                )
                return ToolArgumentReader.securityFailure("UNATTENDED_VAULT_FORBIDDEN")
            }

            if (!vaultPort.isUnlocked()) {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Vault locked: biometric authentication required",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "BIOMETRIC_REQUIRED"
                )
                return ToolResult.ConfirmationRequired(
                    message = UserMessage(MessageKey.ERROR_VAULT_LOCKED),
                    pendingToolName = metadata.name,
                    targetId = ToolTargetIds.VAULT,
                    canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                    requiresBiometric = true
                )
            }

            val noteIdTainted = ToolArgumentReader.getString(arguments, FIELD_NOTE_ID)
                ?: ToolArgumentReader.getString(arguments, "id")
                ?: ToolArgumentReader.getString(arguments, "noteId")
                ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_NOTE_ID)

            val noteId = noteIdTainted.value.trim()
            try {
                vaultPort.deleteNote(noteId)
            } catch (e: Exception) {
                recordAudit(
                    timestampMs = nowMs,
                    actionSummary = "Failed delete vault note: not found ($noteId)",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "NOT_FOUND"
                )
                return ToolArgumentReader.notFoundFailure(noteId)
            }

            recordAudit(
                timestampMs = nowMs,
                actionSummary = "Deleted vault note: $noteId",
                provenance = ToolArgumentReader.worstProvenance(arguments),
                decision = "SUCCESS"
            )

            return ToolResult.Success(
                message = UserMessage(
                    key = MessageKey.ACTION_VAULT_NOTE_DELETED,
                    args = listOf(MessageArg.Text(noteId))
                ),
                outputValues = mapOf(
                    FIELD_NOTE_ID to noteId,
                    "deleted" to "true"
                )
            )
        }
    }

    companion object {
        const val FIELD_NOTE_ID: String = "note_id"
        const val FIELD_TITLE: String = "title"
        const val FIELD_BODY: String = "body"
        const val FIELD_CONTENT: String = "content"

        fun createNotesReadTool(noteStorage: NoteStoragePort, auditLog: AuditLogPort): NavaTool =
            StandardNotesRead(noteStorage, auditLog)

        fun createNotesCreateTool(noteStorage: NoteStoragePort, auditLog: AuditLogPort): NavaTool =
            StandardNotesCreate(noteStorage, auditLog)

        fun createNotesDeleteTool(noteStorage: NoteStoragePort, auditLog: AuditLogPort): NavaTool =
            StandardNotesDelete(noteStorage, auditLog)

        fun createVaultReadTool(vaultPort: VaultPort, auditLog: AuditLogPort): NavaTool =
            VaultRead(vaultPort, auditLog)

        fun createVaultWriteTool(vaultPort: VaultPort, auditLog: AuditLogPort): NavaTool =
            VaultWrite(vaultPort, auditLog)

        fun createVaultDeleteTool(vaultPort: VaultPort, auditLog: AuditLogPort): NavaTool =
            VaultDelete(vaultPort, auditLog)

        fun createAll(
            noteStorage: NoteStoragePort,
            vaultPort: VaultPort,
            auditLog: AuditLogPort
        ): List<NavaTool> = listOf(
            createNotesReadTool(noteStorage, auditLog),
            createNotesCreateTool(noteStorage, auditLog),
            createNotesDeleteTool(noteStorage, auditLog),
            createVaultReadTool(vaultPort, auditLog),
            createVaultWriteTool(vaultPort, auditLog),
            createVaultDeleteTool(vaultPort, auditLog)
        )
    }
}

typealias NotesReadTool = NotesVaultTool.StandardNotesRead
typealias NotesCreateTool = NotesVaultTool.StandardNotesCreate
typealias NotesDeleteTool = NotesVaultTool.StandardNotesDelete
typealias VaultReadTool = NotesVaultTool.VaultRead
typealias VaultWriteTool = NotesVaultTool.VaultWrite
typealias VaultDeleteTool = NotesVaultTool.VaultDelete

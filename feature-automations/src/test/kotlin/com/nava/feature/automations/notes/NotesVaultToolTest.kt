package com.nava.feature.automations.notes

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.NoteStoragePort
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleTriggerSpec
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.StoredNote
import com.nava.domain.security.Tainted
import com.nava.domain.security.VaultPort
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageKey
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.ToolTargetIds
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.AEADBadTagException

class NotesVaultToolTest {

    private class FakeNoteStorage : NoteStoragePort {
        val notes = mutableMapOf<String, StoredNote>()

        override suspend fun saveNote(note: StoredNote) {
            notes[note.noteId] = note
        }

        override suspend fun findNote(noteId: String): StoredNote? = notes[noteId]

        override suspend fun listNotes(): List<StoredNote> =
            notes.values.sortedByDescending { it.updatedEpochSec }

        override suspend fun deleteNote(noteId: String): Boolean = notes.remove(noteId) != null
    }

    private class FakeVaultPort : VaultPort {
        var unlocked: Boolean = true
        val storedNotes = mutableMapOf<String, ByteArray>()
        var lastReturnedReadBuffer: ByteArray? = null
        var lastPassedWriteBuffer: ByteArray? = null
        var throwOnRead: (() -> Throwable)? = null
        var throwOnWrite: (() -> Throwable)? = null
        var throwOnDelete: (() -> Throwable)? = null

        override suspend fun isUnlocked(): Boolean = unlocked

        override suspend fun listNoteIds(): List<String> = storedNotes.keys.toList()

        override suspend fun readNote(noteId: String): ByteArray {
            throwOnRead?.invoke()?.let { throw it }
            val content = storedNotes[noteId] ?: throw NoSuchElementException("Vault note not found: $noteId")
            val buffer = content.copyOf()
            lastReturnedReadBuffer = buffer
            return buffer
        }

        override suspend fun writeNote(noteId: String, content: ByteArray) {
            lastPassedWriteBuffer = content
            throwOnWrite?.invoke()?.let { throw it }
            storedNotes[noteId] = content.copyOf()
        }

        override suspend fun deleteNote(noteId: String) {
            throwOnDelete?.invoke()?.let { throw it }
            if (!storedNotes.containsKey(noteId)) {
                throw NoSuchElementException("Vault note not found: $noteId")
            }
            storedNotes.remove(noteId)
        }

        override suspend fun lock() {
            unlocked = false
        }
    }

    private class FakeAuditLog : AuditLogPort {
        val entries = mutableListOf<AuditLogEntry>()

        override suspend fun record(entry: AuditLogEntry) {
            entries.add(entry)
        }

        override suspend fun queryRecent(limit: Int): List<AuditLogEntry> = entries.takeLast(limit)
    }

    private fun createInteractiveContext(toolName: String, targetId: String): ToolExecutionContext {
        val token = CapabilityToken.mint(
            tokenId = "tok_notes",
            requestId = "req_notes",
            allowedTools = setOf(toolName),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = 1700000000000L
        )
        return ToolExecutionContext(
            requestId = "req_notes",
            capabilityToken = token,
            ruleGrant = null,
            targetId = targetId,
            languageTag = "en",
            issuedAtEpochMs = 1700000000000L,
            isUnattendedBackground = false
        )
    }

    private fun createUnattendedContext(toolName: String, targetId: String): ToolExecutionContext {
        val grant = RuleCapabilityGrant(
            grantId = "grant_notes",
            ruleId = "rule_notes",
            triggerSpec = RuleTriggerSpec(triggerType = "time", parameters = mapOf("hour" to "7", "minute" to "30")),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = toolName,
                    requiredCapability = AtomicCapability.DATA_READ
                )
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "sealed_notes_hmac"
        )
        return ToolExecutionContext(
            requestId = "req_notes_unattended",
            capabilityToken = null,
            ruleGrant = grant,
            targetId = targetId,
            languageTag = "en",
            issuedAtEpochMs = 1700000000000L,
            isUnattendedBackground = true
        )
    }

    // --- Standard Notes Tests ---

    @Test
    fun standardNotesReadListsAndReadsSingleNote() = runBlocking {
        val storage = FakeNoteStorage().apply {
            saveNote(StoredNote("n1", "Groceries", "Milk, Eggs", 1000L))
            saveNote(StoredNote("n2", "Todo", "Write unit tests", 2000L))
        }
        val auditLog = FakeAuditLog()
        val readTool = NotesReadTool(storage, auditLog)

        // 1. List notes when note_id is omitted
        val listResult = readTool.execute(
            createInteractiveContext(AutomationToolNames.NOTES_READ, ToolTargetIds.NOTES),
            emptyMap()
        )
        assertTrue(listResult is ToolResult.Success)
        val listSuccess = listResult as ToolResult.Success
        assertEquals(MessageKey.ACTION_NOTE_READ, listSuccess.message.key)
        assertEquals("2", listSuccess.outputValues["count"])

        // 2. Read single note
        val singleResult = readTool.execute(
            createInteractiveContext(AutomationToolNames.NOTES_READ, ToolTargetIds.NOTES),
            mapOf("note_id" to Tainted.fromUserUtterance(SlotValueAst.StringValue("n1")))
        )
        assertTrue(singleResult is ToolResult.Success)
        val singleSuccess = singleResult as ToolResult.Success
        assertEquals("Groceries", singleSuccess.outputValues["title"])
        assertEquals("Milk, Eggs", singleSuccess.outputValues["body"])

        // 3. Not found note
        val missingResult = readTool.execute(
            createInteractiveContext(AutomationToolNames.NOTES_READ, ToolTargetIds.NOTES),
            mapOf("note_id" to Tainted.fromUserUtterance(SlotValueAst.StringValue("n999")))
        )
        assertTrue(missingResult is ToolResult.Failure)
        assertEquals(MessageKey.ERROR_NOT_FOUND, (missingResult as ToolResult.Failure).message.key)

        // 4. Verify audit log never leaked body plaintext
        assertTrue(auditLog.entries.none { it.actionSummary.contains("Milk") })
        assertTrue(auditLog.entries.none { it.actionSummary.contains("Write unit tests") })
    }

    @Test
    fun standardNotesCreateSavesNoteAndPermitsUnattended() = runBlocking {
        val storage = FakeNoteStorage()
        val auditLog = FakeAuditLog()
        val createTool = NotesCreateTool(storage, auditLog)

        val args = mapOf(
            "title" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Secret Diary")),
            "body" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Very confidential body text")),
            "note_id" to Tainted.fromUserUtterance(SlotValueAst.StringValue("custom_id_1"))
        )

        val result = createTool.execute(
            createUnattendedContext(AutomationToolNames.NOTES_CREATE, ToolTargetIds.NOTES),
            args
        )
        assertTrue(result is ToolResult.Success)
        val stored = storage.findNote("custom_id_1")
        assertNotNull(stored)
        assertEquals("Secret Diary", stored!!.title)
        assertEquals("Very confidential body text", stored.body)

        // Verify audit log did not leak body
        val entry = auditLog.entries.first()
        assertEquals(ToolTargetIds.NOTES, entry.targetId)
        assertTrue(entry.actionSummary.contains("custom_id_1"))
        assertFalse(entry.actionSummary.contains("confidential"))
    }

    @Test
    fun standardNotesDeleteRejectsUnattendedAndDeletesNote() = runBlocking {
        val storage = FakeNoteStorage().apply {
            saveNote(StoredNote("del_1", "Title", "Body", 1000L))
        }
        val auditLog = FakeAuditLog()
        val deleteTool = NotesDeleteTool(storage, auditLog)

        val args = mapOf("note_id" to Tainted.fromUserUtterance(SlotValueAst.StringValue("del_1")))

        // 1. Unattended execution MUST fail with security violation
        val unattendedResult = deleteTool.execute(
            createUnattendedContext(AutomationToolNames.NOTES_DELETE, ToolTargetIds.NOTES),
            args
        )
        assertTrue(unattendedResult is ToolResult.Failure)
        assertTrue((unattendedResult as ToolResult.Failure).isSecurityViolation)

        // 2. Interactive execution succeeds
        val interactiveResult = deleteTool.execute(
            createInteractiveContext(AutomationToolNames.NOTES_DELETE, ToolTargetIds.NOTES),
            args
        )
        assertTrue(interactiveResult is ToolResult.Success)
        assertFalse(storage.notes.containsKey("del_1"))
    }

    // --- Nava Secure Vault Tests ---

    @Test
    fun vaultReadRejectsUnattendedAndDemandsBiometricWhenLocked() = runBlocking {
        val vault = FakeVaultPort().apply {
            unlocked = false
            storedNotes["v1"] = "Secret passport data".toByteArray(Charsets.UTF_8)
        }
        val auditLog = FakeAuditLog()
        val readTool = VaultReadTool(vault, auditLog)

        val args = mapOf("note_id" to Tainted.fromUserUtterance(SlotValueAst.StringValue("v1")))

        // 1. Unattended background execution MUST fail with security violation
        val unattendedResult = readTool.execute(
            createUnattendedContext(AutomationToolNames.VAULT_READ, ToolTargetIds.VAULT),
            args
        )
        assertTrue(unattendedResult is ToolResult.Failure)
        assertTrue((unattendedResult as ToolResult.Failure).isSecurityViolation)

        // 2. When locked, returns ConfirmationRequired with requiresBiometric = true
        val lockedResult = readTool.execute(
            createInteractiveContext(AutomationToolNames.VAULT_READ, ToolTargetIds.VAULT),
            args
        )
        assertTrue(lockedResult is ToolResult.ConfirmationRequired)
        val conf = lockedResult as ToolResult.ConfirmationRequired
        assertEquals(ToolTargetIds.VAULT, conf.targetId)
        assertTrue(conf.requiresBiometric)
        assertEquals(MessageKey.ERROR_VAULT_LOCKED, conf.message.key)
    }

    @Test
    fun vaultReadUnlockedZeroizesMemoryBufferImmediatelyAfterUse() = runBlocking {
        val vault = FakeVaultPort().apply {
            unlocked = true
            storedNotes["v_pass"] = "SuperSecretVaultData123".toByteArray(Charsets.UTF_8)
        }
        val auditLog = FakeAuditLog()
        val readTool = VaultReadTool(vault, auditLog)

        val args = mapOf("note_id" to Tainted.fromUserUtterance(SlotValueAst.StringValue("v_pass")))

        val result = readTool.execute(
            createInteractiveContext(AutomationToolNames.VAULT_READ, ToolTargetIds.VAULT),
            args
        )
        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals("SuperSecretVaultData123", success.outputValues["content"])

        // CRITICAL INVARIANT: The ByteArray returned by vault was zeroized in finally block!
        val returnedBuffer = vault.lastReturnedReadBuffer
        assertNotNull(returnedBuffer)
        assertTrue("Decrypted vault ByteArray must be zeroized in finally block!", returnedBuffer!!.all { it == 0.toByte() })

        // Audit log must not leak secret
        assertTrue(auditLog.entries.none { it.actionSummary.contains("SuperSecret") })
    }

    @Test
    fun vaultWriteUnlockedZeroizesMemoryBufferAndSavesNote() = runBlocking {
        val vault = FakeVaultPort().apply { unlocked = true }
        val auditLog = FakeAuditLog()
        val writeTool = VaultWriteTool(vault, auditLog)

        val args = mapOf(
            "note_id" to Tainted.fromUserUtterance(SlotValueAst.StringValue("v_cred")),
            "content" to Tainted.fromUserUtterance(SlotValueAst.StringValue("ConfidentialApiKey987"))
        )

        val result = writeTool.execute(
            createInteractiveContext(AutomationToolNames.VAULT_WRITE, ToolTargetIds.VAULT),
            args
        )
        assertTrue(result is ToolResult.Success)
        assertTrue(vault.storedNotes.containsKey("v_cred"))
        assertEquals("ConfidentialApiKey987", vault.storedNotes["v_cred"]!!.toString(Charsets.UTF_8))

        // CRITICAL INVARIANT: The encoded ByteArray was zeroized in finally block!
        val writeBuffer = vault.lastPassedWriteBuffer
        assertNotNull(writeBuffer)
        assertTrue("Vault write ByteArray must be zeroized in finally block!", writeBuffer!!.all { it == 0.toByte() })

        // Audit log must not leak secret
        assertTrue(auditLog.entries.none { it.actionSummary.contains("ConfidentialApiKey") })
    }

    @Test
    fun vaultDeleteRejectsUnattendedAndDeletesNoteWhenUnlocked() = runBlocking {
        val vault = FakeVaultPort().apply {
            unlocked = true
            storedNotes["v_del"] = "to_delete".toByteArray(Charsets.UTF_8)
        }
        val auditLog = FakeAuditLog()
        val deleteTool = VaultDeleteTool(vault, auditLog)

        val args = mapOf("note_id" to Tainted.fromUserUtterance(SlotValueAst.StringValue("v_del")))

        // 1. Unattended execution fails with security violation
        val unattendedResult = deleteTool.execute(
            createUnattendedContext(AutomationToolNames.VAULT_DELETE, ToolTargetIds.VAULT),
            args
        )
        assertTrue(unattendedResult is ToolResult.Failure)
        assertTrue((unattendedResult as ToolResult.Failure).isSecurityViolation)

        // 2. Interactive execution succeeds
        val result = deleteTool.execute(
            createInteractiveContext(AutomationToolNames.VAULT_DELETE, ToolTargetIds.VAULT),
            args
        )
        assertTrue(result is ToolResult.Success)
        assertFalse(vault.storedNotes.containsKey("v_del"))
    }

    @Test
    fun factoryCreatesAllSixAdaptersOrthogonally() {
        val tools = NotesVaultTool.createAll(FakeNoteStorage(), FakeVaultPort(), FakeAuditLog())
        assertEquals(6, tools.size)
        val names = tools.map { it.metadata.name }.toSet()
        assertEquals(
            setOf(
                AutomationToolNames.NOTES_READ,
                AutomationToolNames.NOTES_CREATE,
                AutomationToolNames.NOTES_DELETE,
                AutomationToolNames.VAULT_READ,
                AutomationToolNames.VAULT_WRITE,
                AutomationToolNames.VAULT_DELETE
            ),
            names
        )
    }

    @Test
    fun standardNotesCreateGuardsVaultSourceContent() = runBlocking {
        val storage = FakeNoteStorage()
        val auditLog = FakeAuditLog()
        val createTool = NotesCreateTool(storage, auditLog)

        val vaultSecretArgs = mapOf(
            "title" to Tainted.fromUserUtterance(SlotValueAst.StringValue("SecretNote")),
            "body" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("VaultSeedPhrase1234"),
                SensitiveSlotKind.TEXT_BODY,
                sourceLabel = "vault:note_pin"
            )
        )

        // 1. Unconfirmed context escalates to ConfirmationRequired
        val unconfResult = createTool.execute(
            createInteractiveContext(AutomationToolNames.NOTES_CREATE, ToolTargetIds.NOTES),
            vaultSecretArgs
        )
        assertTrue(unconfResult is ToolResult.ConfirmationRequired)
        val conf = unconfResult as ToolResult.ConfirmationRequired
        assertEquals(ToolTargetIds.NOTES, conf.targetId)
        assertEquals("CONFIRMATION_REQUIRED", auditLog.entries.first().decision)

        // 2. Confirmed context allows saving cleanly
        val confirmedContext = createInteractiveContext(AutomationToolNames.NOTES_CREATE, ToolTargetIds.NOTES)
            .copy(isUserConfirmed = true)
        val confResult = createTool.execute(confirmedContext, vaultSecretArgs)
        assertTrue(confResult is ToolResult.Success)
        val savedId = (confResult as ToolResult.Success).outputValues[NotesVaultTool.FIELD_NOTE_ID]
        assertNotNull(savedId)
        assertEquals("VaultSeedPhrase1234", storage.findNote(savedId!!)?.body)
    }

    @Test
    fun vaultReadHandlesCancellationExceptionToctouLockAndAeadBadTag() = runBlocking {
        val vault = FakeVaultPort().apply { unlocked = true }
        val auditLog = FakeAuditLog()
        val readTool = VaultReadTool(vault, auditLog)
        val args = mapOf("note_id" to Tainted.fromUserUtterance(SlotValueAst.StringValue("k1")))

        // 1. CancellationException must be rethrown immediately
        vault.throwOnRead = { CancellationException("Job was cancelled") }
        var caughtCancellation = false
        try {
            readTool.execute(createInteractiveContext(AutomationToolNames.VAULT_READ, ToolTargetIds.VAULT), args)
        } catch (_: CancellationException) {
            caughtCancellation = true
        }
        assertTrue("CancellationException must be rethrown by VaultRead", caughtCancellation)

        // 2. TOCTOU lock: SecurityException when vault is locked -> ConfirmationRequired(requiresBiometric = true)
        vault.throwOnRead = {
            vault.unlocked = false
            SecurityException("Vault locked concurrently")
        }
        val lockResult = readTool.execute(createInteractiveContext(AutomationToolNames.VAULT_READ, ToolTargetIds.VAULT), args)
        assertTrue(lockResult is ToolResult.ConfirmationRequired)
        val confLock = lockResult as ToolResult.ConfirmationRequired
        assertTrue(confLock.requiresBiometric)
        assertEquals("BIOMETRIC_REQUIRED", auditLog.entries.last().decision)

        // 3. Ciphertext tamper: AEADBadTagException -> security failure
        vault.unlocked = true
        vault.throwOnRead = { AEADBadTagException("Tag mismatch! Ciphertext tampered") }
        val tamperResult = readTool.execute(createInteractiveContext(AutomationToolNames.VAULT_READ, ToolTargetIds.VAULT), args)
        assertTrue(tamperResult is ToolResult.Failure)
        val failTamper = tamperResult as ToolResult.Failure
        assertTrue(failTamper.isSecurityViolation)
        assertEquals("VAULT_CRYPTO_FAILURE", failTamper.errorCode)
        assertEquals("SECURITY_VIOLATION", auditLog.entries.last().decision)
    }

    @Test
    fun vaultWriteHandlesCancellationExceptionToctouLockAndAeadBadTag() = runBlocking {
        val vault = FakeVaultPort().apply { unlocked = true }
        val auditLog = FakeAuditLog()
        val writeTool = VaultWriteTool(vault, auditLog)
        val args = mapOf(
            "note_id" to Tainted.fromUserUtterance(SlotValueAst.StringValue("k_w")),
            "content" to Tainted.fromUserUtterance(SlotValueAst.StringValue("SecretData"))
        )

        // 1. CancellationException must be rethrown and buffer zeroized
        vault.throwOnWrite = { CancellationException("Write cancelled") }
        var caughtCancellation = false
        try {
            writeTool.execute(createInteractiveContext(AutomationToolNames.VAULT_WRITE, ToolTargetIds.VAULT), args)
        } catch (_: CancellationException) {
            caughtCancellation = true
        }
        assertTrue("CancellationException must be rethrown by VaultWrite", caughtCancellation)
        val passedBuf = vault.lastPassedWriteBuffer
        assertNotNull(passedBuf)
        assertTrue("Passed write buffer must be zeroized in finally even on cancellation!", passedBuf!!.all { it == 0.toByte() })

        // 2. TOCTOU lock: SecurityException when vault locked -> ConfirmationRequired
        vault.throwOnWrite = {
            vault.unlocked = false
            SecurityException("Vault locked during write")
        }
        val lockResult = writeTool.execute(createInteractiveContext(AutomationToolNames.VAULT_WRITE, ToolTargetIds.VAULT), args)
        assertTrue(lockResult is ToolResult.ConfirmationRequired)
        assertTrue((lockResult as ToolResult.ConfirmationRequired).requiresBiometric)

        // 3. AEADBadTagException -> security failure
        vault.unlocked = true
        vault.throwOnWrite = { AEADBadTagException("Key derivation bad tag") }
        val tamperResult = writeTool.execute(createInteractiveContext(AutomationToolNames.VAULT_WRITE, ToolTargetIds.VAULT), args)
        assertTrue(tamperResult is ToolResult.Failure)
        assertTrue((tamperResult as ToolResult.Failure).isSecurityViolation)
        assertEquals("VAULT_CRYPTO_FAILURE", tamperResult.errorCode)
    }

    @Test
    fun vaultDeleteHandlesCancellationExceptionToctouLockAndAeadBadTag() = runBlocking {
        val vault = FakeVaultPort().apply { unlocked = true }
        val auditLog = FakeAuditLog()
        val deleteTool = VaultDeleteTool(vault, auditLog)
        val args = mapOf("note_id" to Tainted.fromUserUtterance(SlotValueAst.StringValue("k_d")))

        // 1. CancellationException
        vault.throwOnDelete = { CancellationException("Delete cancelled") }
        var caughtCancellation = false
        try {
            deleteTool.execute(createInteractiveContext(AutomationToolNames.VAULT_DELETE, ToolTargetIds.VAULT), args)
        } catch (_: CancellationException) {
            caughtCancellation = true
        }
        assertTrue("CancellationException must be rethrown by VaultDelete", caughtCancellation)

        // 2. TOCTOU lock
        vault.throwOnDelete = {
            vault.unlocked = false
            SecurityException("Vault locked during delete")
        }
        val lockResult = deleteTool.execute(createInteractiveContext(AutomationToolNames.VAULT_DELETE, ToolTargetIds.VAULT), args)
        assertTrue(lockResult is ToolResult.ConfirmationRequired)
        assertTrue((lockResult as ToolResult.ConfirmationRequired).requiresBiometric)

        // 3. GeneralSecurityException
        vault.unlocked = true
        vault.throwOnDelete = { AEADBadTagException("Bad tag during delete") }
        val tamperResult = deleteTool.execute(createInteractiveContext(AutomationToolNames.VAULT_DELETE, ToolTargetIds.VAULT), args)
        assertTrue(tamperResult is ToolResult.Failure)
        assertTrue((tamperResult as ToolResult.Failure).isSecurityViolation)
        assertEquals("VAULT_CRYPTO_FAILURE", tamperResult.errorCode)
    }
}

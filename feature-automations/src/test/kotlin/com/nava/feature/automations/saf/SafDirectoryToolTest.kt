package com.nava.feature.automations.saf

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleTriggerSpec
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.common.AutomationOutboundActions
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.SafDocumentEntry
import com.nava.feature.automations.common.SafGatewayResult
import com.nava.feature.automations.common.SafPlatformGateway
import com.nava.feature.automations.common.ToolTargetIds
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SafDirectoryToolTest {

    private class FakeSafGateway : SafPlatformGateway {
        val grantedTrees = mutableMapOf<String, Boolean>() // treeUri -> isWriteGranted
        val documents = mutableMapOf<String, MutableMap<String, ByteArray>>() // treeUri -> (fileName -> content)

        override fun hasPersistedGrant(treeUri: String, requireWrite: Boolean): Boolean {
            val isWrite = grantedTrees[treeUri] ?: return false
            return !requireWrite || isWrite
        }

        override fun listPersistedTreeUris(): Set<String> = grantedTrees.keys

        override suspend fun listDocuments(treeUri: String): SafGatewayResult<List<SafDocumentEntry>> {
            if (!hasPersistedGrant(treeUri, requireWrite = false)) {
                return SafGatewayResult.GrantMissing(treeUri)
            }
            val docs = documents[treeUri] ?: return SafGatewayResult.Success(emptyList())
            val entries = docs.map { (name, bytes) ->
                SafDocumentEntry(
                    documentUri = "$treeUri/$name",
                    displayName = name,
                    mimeType = "text/plain",
                    isDirectory = false,
                    sizeBytes = bytes.size.toLong(),
                    lastModifiedEpochMs = 1700000000000L
                )
            }
            return SafGatewayResult.Success(entries)
        }

        override suspend fun readDocument(
            treeUri: String,
            fileName: String,
            maxBytes: Int
        ): SafGatewayResult<ByteArray> {
            if (!hasPersistedGrant(treeUri, requireWrite = false)) {
                return SafGatewayResult.GrantMissing(treeUri)
            }
            if (!SafPlatformGateway.isSafeDocumentName(fileName)) {
                return SafGatewayResult.Unavailable("Unsafe document name")
            }
            val bytes = documents[treeUri]?.get(fileName)
                ?: return SafGatewayResult.NotFound(fileName)
            return SafGatewayResult.Success(bytes.copyOf(minOf(bytes.size, maxBytes)))
        }

        override suspend fun writeDocument(
            treeUri: String,
            fileName: String,
            mimeType: String,
            content: ByteArray,
            overwrite: Boolean
        ): SafGatewayResult<SafDocumentEntry> {
            if (!hasPersistedGrant(treeUri, requireWrite = true)) {
                return SafGatewayResult.GrantMissing(treeUri)
            }
            if (!SafPlatformGateway.isSafeDocumentName(fileName)) {
                return SafGatewayResult.Unavailable("Unsafe document name")
            }
            val treeDocs = documents.getOrPut(treeUri) { mutableMapOf() }
            if (treeDocs.containsKey(fileName) && !overwrite) {
                return SafGatewayResult.Unavailable("Document already exists")
            }
            treeDocs[fileName] = content.copyOf()
            return SafGatewayResult.Success(
                SafDocumentEntry(
                    documentUri = "$treeUri/$fileName",
                    displayName = fileName,
                    mimeType = mimeType,
                    isDirectory = false,
                    sizeBytes = content.size.toLong(),
                    lastModifiedEpochMs = 1700000000000L
                )
            )
        }

        override suspend fun deleteDocument(treeUri: String, fileName: String): SafGatewayResult<Boolean> {
            if (!hasPersistedGrant(treeUri, requireWrite = true)) {
                return SafGatewayResult.GrantMissing(treeUri)
            }
            if (!SafPlatformGateway.isSafeDocumentName(fileName)) {
                return SafGatewayResult.Unavailable("Unsafe document name")
            }
            val treeDocs = documents[treeUri] ?: return SafGatewayResult.NotFound(fileName)
            if (!treeDocs.containsKey(fileName)) {
                return SafGatewayResult.NotFound(fileName)
            }
            treeDocs.remove(fileName)
            return SafGatewayResult.Success(true)
        }
    }

    private class FakeFirewall : SecurityFirewallPort {
        var decision: FirewallDecision = FirewallDecision.Authorized
        val outboundValidations = mutableListOf<Triple<String, String, String>>()

        override suspend fun mintToken(
            requestId: String,
            utteranceProvenance: DataProvenance,
            candidateTools: Set<String>,
            nowEpochMs: Long,
            maxToolCalls: Int
        ): CapabilityToken = error("not needed")

        override suspend fun authorizeToolCall(
            token: CapabilityToken,
            toolCall: ToolCallAst,
            toolMetadata: ToolMetadata,
            targetId: String,
            nowEpochMs: Long
        ): FirewallDecision = error("not needed")

        override suspend fun authorizeRuleExecution(grant: RuleCapabilityGrant): FirewallDecision = error("not needed")

        override suspend fun validateOutboundTarget(
            toolName: String,
            action: String,
            uriOrTarget: Tainted<String>
        ): FirewallDecision {
            outboundValidations.add(Triple(toolName, action, uriOrTarget.value))
            return decision
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
            tokenId = "tok_saf",
            requestId = "req_saf",
            allowedTools = setOf(toolName),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = 1700000000000L
        )
        return ToolExecutionContext(
            requestId = "req_saf",
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
            grantId = "grant_saf",
            ruleId = "rule_saf",
            triggerSpec = RuleTriggerSpec(triggerType = "time", parameters = mapOf("hour" to "6", "minute" to "0")),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = toolName,
                    requiredCapability = AtomicCapability.DATA_READ
                )
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "sealed_saf_hmac"
        )
        return ToolExecutionContext(
            requestId = "req_saf_unattended",
            capabilityToken = null,
            ruleGrant = grant,
            targetId = targetId,
            languageTag = "en",
            issuedAtEpochMs = 1700000000000L,
            isUnattendedBackground = true
        )
    }

    private val treeUri = "content://com.android.externalstorage.documents/tree/primary%3ANotes"

    @Test
    fun safReadListsDirectoryAndReadsDocumentWithUntrustedProvenance() = runBlocking {
        val gateway = FakeSafGateway().apply {
            grantedTrees[treeUri] = false // read-only grant
            documents[treeUri] = mutableMapOf(
                "report.txt" to "Financial report data".toByteArray(Charsets.UTF_8),
                "summary.md" to "Summary markdown".toByteArray(Charsets.UTF_8)
            )
        }
        val firewall = FakeFirewall()
        val auditLog = FakeAuditLog()
        val readTool = SafReadTool(gateway, firewall, auditLog)

        val targetId = ToolTargetIds.forSafTree(treeUri)

        // 1. List directory
        val listArgs = mapOf(
            "tree_uri" to Tainted.fromUserUtterance(SlotValueAst.StringValue(treeUri))
        )
        val listResult = readTool.execute(createInteractiveContext(AutomationToolNames.SAF_READ, targetId), listArgs)
        assertTrue(listResult is ToolResult.Success)
        val listSuccess = listResult as ToolResult.Success
        assertEquals(MessageKey.ACTION_SAF_DIRECTORY_LISTED, listSuccess.message.key)
        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, listSuccess.outputProvenance)
        assertEquals("2", listSuccess.outputValues["count"])

        // 2. Read single document
        val readArgs = mapOf(
            "tree_uri" to Tainted.fromUserUtterance(SlotValueAst.StringValue(treeUri)),
            "file_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue("report.txt"))
        )
        val readResult = readTool.execute(createInteractiveContext(AutomationToolNames.SAF_READ, targetId), readArgs)
        assertTrue(readResult is ToolResult.Success)
        val readSuccess = readResult as ToolResult.Success
        assertEquals(MessageKey.ACTION_SAF_FILE_READ, readSuccess.message.key)
        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, readSuccess.outputProvenance)
        assertEquals("Financial report data", readSuccess.outputValues["content"])

        // 3. Verify audit logging
        assertTrue(auditLog.entries.any { it.actionSummary.contains("Listed SAF directory") })
        assertTrue(auditLog.entries.any { it.actionSummary.contains("Read SAF document") })
        // Never leak content into audit
        assertTrue(auditLog.entries.none { it.actionSummary.contains("Financial report data") })
    }

    @Test
    fun safReadRejectsPathTraversalNames() = runBlocking {
        val gateway = FakeSafGateway().apply {
            grantedTrees[treeUri] = true
        }
        val readTool = SafReadTool(gateway, FakeFirewall(), FakeAuditLog())
        val targetId = ToolTargetIds.forSafTree(treeUri)

        val attacks = listOf("../secret.txt", "/etc/passwd", "sub\\file.txt", "evil/doc.txt", "bad\u0000name.txt")
        for (badName in attacks) {
            val args = mapOf(
                "tree_uri" to Tainted.fromUserUtterance(SlotValueAst.StringValue(treeUri)),
                "file_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue(badName))
            )
            val result = readTool.execute(createInteractiveContext(AutomationToolNames.SAF_READ, targetId), args)
            assertTrue("Expected Failure for traversal payload '$badName'", result is ToolResult.Failure)
            val failure = result as ToolResult.Failure
            assertEquals(MessageKey.ERROR_INVALID_ARGUMENTS, failure.message.key)
        }
    }

    @Test
    fun safReadMissingGrantReturnsCleanFailure() = runBlocking {
        val gateway = FakeSafGateway() // No grants
        val readTool = SafReadTool(gateway, FakeFirewall(), FakeAuditLog())
        val targetId = ToolTargetIds.forSafTree(treeUri)

        val args = mapOf(
            "tree_uri" to Tainted.fromUserUtterance(SlotValueAst.StringValue(treeUri))
        )
        val result = readTool.execute(createInteractiveContext(AutomationToolNames.SAF_READ, targetId), args)
        assertTrue(result is ToolResult.Failure)
        assertEquals(MessageKey.ERROR_SAF_GRANT_MISSING, (result as ToolResult.Failure).message.key)
    }

    @Test
    fun safWriteTaintBarrierRequiresConfirmationForUntrustedOrVaultData() = runBlocking {
        val gateway = FakeSafGateway().apply {
            grantedTrees[treeUri] = true // write grant
        }
        val firewall = FakeFirewall()
        val auditLog = FakeAuditLog()
        val writeTool = SafWriteTool(gateway, firewall, auditLog)
        val targetId = ToolTargetIds.forSafTree(treeUri)

        // 1. Untrusted external content in SAF write
        val untrustedArgs = mapOf(
            "tree_uri" to Tainted.fromUserUtterance(SlotValueAst.StringValue(treeUri)),
            "file_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue("untrusted.txt")),
            "content" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("Injected payload from chat"),
                SensitiveSlotKind.TEXT_BODY,
                sourceLabel = "notification:com.chat"
            )
        )
        val result1 = writeTool.execute(createInteractiveContext(AutomationToolNames.SAF_WRITE, targetId), untrustedArgs)
        assertTrue(result1 is ToolResult.ConfirmationRequired)
        val conf1 = result1 as ToolResult.ConfirmationRequired
        assertEquals(MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE, conf1.message.key)
        assertEquals(targetId, conf1.targetId)

        // 2. Vault-sourced content in SAF write
        val vaultArgs = mapOf(
            "tree_uri" to Tainted.fromUserUtterance(SlotValueAst.StringValue(treeUri)),
            "file_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue("exfil.txt")),
            "content" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("Leaked vault secret"),
                SensitiveSlotKind.TEXT_BODY,
                sourceLabel = "vault:note_99"
            )
        )
        val result2 = writeTool.execute(createInteractiveContext(AutomationToolNames.SAF_WRITE, targetId), vaultArgs)
        assertTrue(result2 is ToolResult.ConfirmationRequired)
        val conf2 = result2 as ToolResult.ConfirmationRequired
        assertEquals(MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE, conf2.message.key)
    }

    @Test
    fun safWriteSucceedsWithValidGrantAndAuditsWithoutContentLeakage() = runBlocking {
        val gateway = FakeSafGateway().apply {
            grantedTrees[treeUri] = true
        }
        val firewall = FakeFirewall()
        val auditLog = FakeAuditLog()
        val writeTool = SafWriteTool(gateway, firewall, auditLog)
        val targetId = ToolTargetIds.forSafTree(treeUri)

        val args = mapOf(
            "tree_uri" to Tainted.fromUserUtterance(SlotValueAst.StringValue(treeUri)),
            "file_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue("diary.txt")),
            "content" to Tainted.fromUserUtterance(SlotValueAst.StringValue("A lovely quiet day"))
        )

        val result = writeTool.execute(createInteractiveContext(AutomationToolNames.SAF_WRITE, targetId), args)
        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals(MessageKey.ACTION_SAF_FILE_WRITTEN, success.message.key)
        assertEquals("diary.txt", success.outputValues["file_name"])

        // Verify document was written to gateway
        assertEquals("A lovely quiet day", gateway.documents[treeUri]?.get("diary.txt")?.toString(Charsets.UTF_8))

        // Verify audit log did not leak body content
        val entry = auditLog.entries.first()
        assertEquals(targetId, entry.targetId)
        assertTrue(entry.actionSummary.contains("diary.txt"))
        assertFalse(entry.actionSummary.contains("quiet day"))
    }

    @Test
    fun safDeleteRejectsUnattendedAndDeletesDocument() = runBlocking {
        val gateway = FakeSafGateway().apply {
            grantedTrees[treeUri] = true
            documents[treeUri] = mutableMapOf("old.txt" to "to delete".toByteArray(Charsets.UTF_8))
        }
        val deleteTool = SafDeleteTool(gateway, FakeFirewall(), FakeAuditLog())
        val targetId = ToolTargetIds.forSafTree(treeUri)

        val args = mapOf(
            "tree_uri" to Tainted.fromUserUtterance(SlotValueAst.StringValue(treeUri)),
            "file_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue("old.txt"))
        )

        // 1. Unattended execution MUST fail with security violation
        val unattendedResult = deleteTool.execute(
            createUnattendedContext(AutomationToolNames.SAF_DELETE, targetId),
            args
        )
        assertTrue(unattendedResult is ToolResult.Failure)
        assertTrue((unattendedResult as ToolResult.Failure).isSecurityViolation)

        // 2. Interactive execution succeeds
        val result = deleteTool.execute(createInteractiveContext(AutomationToolNames.SAF_DELETE, targetId), args)
        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals(MessageKey.ACTION_SAF_FILE_DELETED, success.message.key)
        assertFalse(gateway.documents[treeUri]!!.containsKey("old.txt"))
    }

    @Test
    fun factoryCreatesAllThreeSafAdaptersOrthogonally() {
        val tools = SafDirectoryTool.createAll(FakeSafGateway(), FakeFirewall(), FakeAuditLog())
        assertEquals(3, tools.size)
        val names = tools.map { it.metadata.name }.toSet()
        assertEquals(
            setOf(
                AutomationToolNames.SAF_READ,
                AutomationToolNames.SAF_WRITE,
                AutomationToolNames.SAF_DELETE
            ),
            names
        )
    }

    @Test
    fun approvedStage2SafCallsExecuteCleanlyWhenUserConfirmed() = runBlocking {
        val gateway = FakeSafGateway().apply {
            grantedTrees[treeUri] = true
            documents[treeUri] = mutableMapOf(
                "doc.txt" to "sample text".toByteArray(Charsets.UTF_8)
            )
        }
        val firewall = FakeFirewall().apply { decision = FirewallDecision.Authorized }
        val auditLog = FakeAuditLog()
        val readTool = SafReadTool(gateway, firewall, auditLog)
        val writeTool = SafWriteTool(gateway, firewall, auditLog)
        val deleteTool = SafDeleteTool(gateway, firewall, auditLog)
        val targetId = ToolTargetIds.forSafTree(treeUri)

        val untrustedWriteArgs = mapOf(
            "tree_uri" to Tainted.fromUserUtterance(SlotValueAst.StringValue(treeUri)),
            "file_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue("stage2.txt")),
            "content" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("Tainted payload from web"),
                SensitiveSlotKind.TEXT_BODY,
                sourceLabel = "notification:com.chat"
            )
        )

        // 1. Unconfirmed write escalates to ConfirmationRequired
        val unconfWrite = writeTool.execute(createInteractiveContext(AutomationToolNames.SAF_WRITE, targetId), untrustedWriteArgs)
        assertTrue(unconfWrite is ToolResult.ConfirmationRequired)

        // 2. Confirmed write succeeds cleanly
        val confirmedContext = createInteractiveContext(AutomationToolNames.SAF_WRITE, targetId).copy(isUserConfirmed = true)
        val confWriteRes = writeTool.execute(confirmedContext, untrustedWriteArgs)
        assertTrue(confWriteRes is ToolResult.Success)
        assertEquals("Tainted payload from web", gateway.documents[treeUri]?.get("stage2.txt")?.toString(Charsets.UTF_8))

        // 3. Unconfirmed delete with untrusted args escalates
        val untrustedDeleteArgs = mapOf(
            "tree_uri" to Tainted.fromUserUtterance(SlotValueAst.StringValue(treeUri)),
            "file_name" to Tainted.fromUntrustedExternal(
                SlotValueAst.StringValue("stage2.txt"),
                SensitiveSlotKind.TEXT_BODY,
                sourceLabel = "notification:com.chat"
            )
        )
        val unconfDelete = deleteTool.execute(createInteractiveContext(AutomationToolNames.SAF_DELETE, targetId), untrustedDeleteArgs)
        assertTrue(unconfDelete is ToolResult.ConfirmationRequired)

        // Confirmed delete succeeds
        val confDeleteRes = deleteTool.execute(confirmedContext, untrustedDeleteArgs)
        assertTrue(confDeleteRes is ToolResult.Success)
        assertFalse(gateway.documents[treeUri]!!.containsKey("stage2.txt"))

        // 4. Denied firewall decision hard-blocks unconditionally even when confirmed
        firewall.decision = FirewallDecision.Denied(
            message = UserMessage(MessageKey.ERROR_SECURITY_VIOLATION),
            reasonCode = "SAF_ACCESS_DENIED"
        )
        val deniedWrite = writeTool.execute(confirmedContext, untrustedWriteArgs)
        assertTrue(deniedWrite is ToolResult.Failure)
        val failure = deniedWrite as ToolResult.Failure
        assertTrue(failure.isSecurityViolation)
        assertEquals("SAF_ACCESS_DENIED", failure.errorCode)
    }

    @Test
    fun biometricRequiredSafWriteHonorsBioApproval() = runBlocking {
        val gateway = FakeSafGateway().apply { grantedTrees[treeUri] = true }
        val firewall = FakeFirewall().apply {
            decision = FirewallDecision.RequiresBiometric(UserMessage(MessageKey.ACTION_CONFIRMATION_REQUIRED))
        }
        val writeTool = SafWriteTool(gateway, firewall, FakeAuditLog())
        val targetId = ToolTargetIds.forSafTree(treeUri)

        val args = mapOf(
            "tree_uri" to Tainted.fromUserUtterance(SlotValueAst.StringValue(treeUri)),
            "file_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue("bio.txt")),
            "content" to Tainted.fromUserUtterance(SlotValueAst.StringValue("bio data"))
        )

        // Bio false -> confirmation required with requiresBiometric = true
        val bioFalse = createInteractiveContext(AutomationToolNames.SAF_WRITE, targetId).copy(isBiometricApproved = false)
        val res1 = writeTool.execute(bioFalse, args)
        assertTrue(res1 is ToolResult.ConfirmationRequired)
        assertTrue((res1 as ToolResult.ConfirmationRequired).requiresBiometric)

        // Bio true -> succeeds
        val bioTrue = createInteractiveContext(AutomationToolNames.SAF_WRITE, targetId).copy(isBiometricApproved = true)
        val res2 = writeTool.execute(bioTrue, args)
        assertTrue(res2 is ToolResult.Success)
    }
}

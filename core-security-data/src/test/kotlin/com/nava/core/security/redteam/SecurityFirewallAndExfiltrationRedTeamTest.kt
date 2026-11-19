package com.nava.core.security.redteam

import com.nava.core.security.dao.AuditLogDao
import com.nava.core.security.firewall.OutboundChannelPolicy
import com.nava.core.security.firewall.SecurityFirewall
import com.nava.core.security.policy.PermissionProfileManager
import com.nava.core.security.policy.RuleCapabilityGrantManager
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.testing.InMemoryRowStorage
import com.nava.core.security.testing.InMemorySoftwareKeyProvider
import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.PermissionProfilePreset
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleTriggerSpec
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.NavaTool
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolCategory
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolRegistry
import com.nava.domain.tool.ToolResult
import com.nava.domain.tool.ToolSchemaField
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.domain.usecase.ExecutePlanUseCase
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Gate 2 Independent Adversarial Red-Team Suite:
 * Value Taint, High-Risk Sensitive-Slot Escalation, Outbound IPC / Deep-Link Exfiltration,
 * Vault Taint Barrier, and [ExecutePlanUseCase] End-to-End Integration.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SecurityFirewallAndExfiltrationRedTeamTest {

    private val nowMs: Long = 1_750_000_000_000L

    private data class FirewallHarness(
        val storage: InMemoryRowStorage,
        val keyProvider: InMemorySoftwareKeyProvider,
        val store: EncryptedSqliteStore,
        val profileManager: PermissionProfileManager,
        val ruleGrantManager: RuleCapabilityGrantManager,
        val auditLogDao: AuditLogDao,
        val firewall: SecurityFirewall
    )

    private fun TestScope.createHarness(): FirewallHarness {
        val storage = InMemoryRowStorage()
        val keyProvider = InMemorySoftwareKeyProvider()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = keyProvider,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val profileManager = PermissionProfileManager(store = store, clockEpochSec = { nowMs / 1000L })
        val ruleGrantManager = RuleCapabilityGrantManager(store = store, keyProvider = keyProvider)
        val auditLogDao = AuditLogDao(store = store)
        val firewall = SecurityFirewall(
            permissionEvaluator = profileManager,
            ruleGrantManager = ruleGrantManager,
            auditLog = auditLogDao,
            clockMs = { nowMs }
        )
        return FirewallHarness(
            storage = storage,
            keyProvider = keyProvider,
            store = store,
            profileManager = profileManager,
            ruleGrantManager = ruleGrantManager,
            auditLogDao = auditLogDao,
            firewall = firewall
        )
    }

    private suspend fun assignAutoProfile(
        profileManager: PermissionProfileManager,
        targetId: String
    ) {
        val autoProfile = PermissionProfile(
            id = "custom_auto_all_safe",
            name = "Custom Auto Safe",
            preset = PermissionProfilePreset.CUSTOM,
            capabilities = mapOf(
                AtomicCapability.NOTIFICATION_READ to ConfirmationLevel.AUTO,
                AtomicCapability.DATA_READ to ConfirmationLevel.AUTO,
                AtomicCapability.CREATE_DRAFT to ConfirmationLevel.AUTO,
                AtomicCapability.MODIFY_DELETE_SEND to ConfirmationLevel.PROMPT_CARD,
                AtomicCapability.APP_LAUNCH to ConfirmationLevel.AUTO
            )
        )
        profileManager.saveProfile(autoProfile)
        profileManager.assignTargetToProfile(targetId, autoProfile.id)
    }

    @Test
    fun allHighRiskSensitiveSlotKindsFromUntrustedExternalBlockAutoExecutionEvenWhenProfileIsAutoAndArgSlotKindIsNull() =
        runTest {
            val h = createHarness()
            val targetId = "com.nava.trusted.target"
            assignAutoProfile(h.profileManager, targetId)

            val safeValuesByKind = linkedMapOf(
                SensitiveSlotKind.RECIPIENT_ADDRESS to "alice@example.com",
                SensitiveSlotKind.PHONE_NUMBER to "+15550199",
                SensitiveSlotKind.EXTERNAL_URI to "content://com.android.calendar/events",
                SensitiveSlotKind.FILE_PATH to "notes/meeting.txt",
                SensitiveSlotKind.PACKAGE_NAME to "com.example.clock",
                SensitiveSlotKind.INTENT_ACTION to OutboundChannelPolicy.ACTION_SET_ALARM
            )

            assertEquals(
                SensitiveSlotKind.entries.filter { it.isHighRisk }.toSet(),
                safeValuesByKind.keys
            )

            for ((kind, safeVal) in safeValuesByKind) {
                val toolName = "test.tool.${kind.name.lowercase()}"
                val metadata = ToolMetadata(
                    name = toolName,
                    displayNameKey = "tool_test",
                    description = "Test tool for $kind",
                    category = ToolCategory.TIME_CALENDAR,
                    requiredCapability = AtomicCapability.CREATE_DRAFT,
                    fields = listOf(
                        ToolSchemaField(
                            name = "target_slot",
                            description = "High risk slot",
                            required = true,
                            slotKind = kind,
                            valueType = SlotValueType.STRING
                        )
                    )
                )
                val token = h.firewall.mintToken(
                    requestId = "req-${kind.name}",
                    utteranceProvenance = DataProvenance.USER_UTTERANCE,
                    candidateTools = setOf(toolName),
                    nowEpochMs = nowMs
                )

                // Case 1: Tainted argument explicitly tagged with slotKind
                val taggedCall = ToolCallAst(
                    toolName = toolName,
                    arguments = mapOf(
                        "target_slot" to Tainted.fromUntrustedExternal(
                            value = SlotValueAst.StringValue(safeVal),
                            slotKind = kind,
                            sourceLabel = "notification:com.attacker"
                        )
                    )
                )
                val taggedDecision = h.firewall.authorizeToolCall(
                    token = token,
                    toolCall = taggedCall,
                    toolMetadata = metadata,
                    targetId = targetId,
                    nowEpochMs = nowMs
                )
                assertTrue(
                    "Expected RequiresConfirmation for tagged untrusted $kind, got $taggedDecision",
                    taggedDecision is FirewallDecision.RequiresConfirmation
                )
                val taggedConfirm = taggedDecision as FirewallDecision.RequiresConfirmation
                assertTrue("target_slot" in taggedConfirm.untrustedHighRiskSlots)
                assertEquals(MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE, taggedConfirm.message.key)

                // Case 2: Tainted argument has slotKind == null while ToolMetadata declares the field high-risk
                val nullKindCall = ToolCallAst(
                    toolName = toolName,
                    arguments = mapOf(
                        "target_slot" to Tainted.fromUntrustedExternal(
                            value = SlotValueAst.StringValue(safeVal),
                            slotKind = null,
                            sourceLabel = "notification:com.attacker"
                        )
                    )
                )
                val nullKindDecision = h.firewall.authorizeToolCall(
                    token = token,
                    toolCall = nullKindCall,
                    toolMetadata = metadata,
                    targetId = targetId,
                    nowEpochMs = nowMs
                )
                assertTrue(
                    "Expected RequiresConfirmation when arg.slotKind==null and ToolMetadata declares $kind, got $nullKindDecision",
                    nullKindDecision is FirewallDecision.RequiresConfirmation
                )
                assertTrue(
                    "target_slot" in (nullKindDecision as FirewallDecision.RequiresConfirmation).untrustedHighRiskSlots
                )
            }
        }

    @Test
    fun stage1MintTokenRejectsUntrustedExternalAndSystemWithAuditEntry() = runTest {
        val h = createHarness()

        for (forbiddenProvenance in listOf(DataProvenance.UNTRUSTED_EXTERNAL, DataProvenance.SYSTEM)) {
            try {
                h.firewall.mintToken(
                    requestId = "req-${forbiddenProvenance.name}",
                    utteranceProvenance = forbiddenProvenance,
                    candidateTools = setOf("sms.create_draft"),
                    nowEpochMs = nowMs
                )
                fail("Expected SecurityException when minting token from $forbiddenProvenance")
            } catch (_: SecurityException) {
                // Expected
            }
        }

        val entries = h.auditLogDao.queryRecent(10)
        assertEquals(2, entries.size)
        assertTrue(entries.all { it.decision == SecurityFirewall.DECISION_TOKEN_MINT_DENIED })
        assertEquals(
            setOf(DataProvenance.UNTRUSTED_EXTERNAL, DataProvenance.SYSTEM),
            entries.map { it.provenance }.toSet()
        )
    }

    @Test
    fun metadataMismatchAndExpiredOrUnsealedTokenThrowSecurityExceptionAndRecordAudit() = runTest {
        val h = createHarness()
        val targetId = "com.nava.clock"
        assignAutoProfile(h.profileManager, targetId)

        val alarmMeta = ToolMetadata(
            name = "alarm.set",
            displayNameKey = "tool_alarm",
            description = "Set alarm",
            category = ToolCategory.TIME_CALENDAR,
            requiredCapability = AtomicCapability.CREATE_DRAFT
        )
        val validToken = h.firewall.mintToken(
            requestId = "req-1",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf("alarm.set"),
            nowEpochMs = nowMs
        )

        // 1. Tool name vs metadata mismatch
        try {
            h.firewall.authorizeToolCall(
                token = validToken,
                toolCall = ToolCallAst(toolName = "sms.send", arguments = emptyMap()),
                toolMetadata = alarmMeta,
                targetId = targetId,
                nowEpochMs = nowMs
            )
            fail("Expected SecurityException for tool/metadata mismatch")
        } catch (_: SecurityException) {
            // Expected
        }

        // 2. Expired token
        val expiredToken = CapabilityToken.mint(
            tokenId = "tok-expired",
            requestId = "req-expired",
            allowedTools = setOf("alarm.set"),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = nowMs - 10_000L,
            expiresAtEpochMs = nowMs - 1L
        )
        try {
            h.firewall.authorizeToolCall(
                token = expiredToken,
                toolCall = ToolCallAst(toolName = "alarm.set", arguments = emptyMap()),
                toolMetadata = alarmMeta,
                targetId = targetId,
                nowEpochMs = nowMs
            )
            fail("Expected SecurityException for expired token")
        } catch (_: SecurityException) {
            // Expected
        }

        // 3. Unsealed tool token
        val otherToolToken = h.firewall.mintToken(
            requestId = "req-other",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf("calendar.insert"),
            nowEpochMs = nowMs
        )
        try {
            h.firewall.authorizeToolCall(
                token = otherToolToken,
                toolCall = ToolCallAst(toolName = "alarm.set", arguments = emptyMap()),
                toolMetadata = alarmMeta,
                targetId = targetId,
                nowEpochMs = nowMs
            )
            fail("Expected SecurityException for unsealed tool")
        } catch (_: SecurityException) {
            // Expected
        }

        val logs = h.auditLogDao.queryRecent(10)
        assertEquals(3, logs.size)
        val decisions = logs.map { it.decision }
        assertTrue(SecurityFirewall.DECISION_TOOL_METADATA_MISMATCH in decisions)
        assertEquals(2, decisions.count { it == SecurityFirewall.DECISION_CAPABILITY_TOKEN_DENIED })
    }

    @Test
    fun outboundSchemesAndDisallowedActionsHardBlockedInBothValidateOutboundTargetAndAuthorizeToolCall() =
        runTest {
            val h = createHarness()
            val targetId = "com.nava.saf"
            assignAutoProfile(h.profileManager, targetId)

            val blockedSchemes = listOf(
                "http://evil.example/leak?d=1",
                "https://evil.example/leak?d=1",
                "HtTpS://Evil.Example/Exfil",
                "  h\u200Bttps://evil.example/leak",
                "\uFF48\uFF54\uFF54\uFF50\uFF53\uFF1A//evil.example/fullwidth",
                "ftp://evil.example/drop",
                "javascript:alert(1)",
                "data:text/html;base64,PHNjcmlwdD4=",
                "file:///etc/passwd",
                "intent://evil.example/#Intent;scheme=https;end",
                "blob:https://evil.example/uuid",
                "about:blank"
            )

            // 1. Hard-blocked in validateOutboundTarget
            for (uri in blockedSchemes) {
                val decision = h.firewall.validateOutboundTarget(
                    toolName = "saf.write",
                    action = OutboundChannelPolicy.ACTION_SAF_WRITE,
                    uriOrTarget = Tainted.fromUserUtterance(uri, SensitiveSlotKind.EXTERNAL_URI)
                )
                assertTrue(
                    "validateOutboundTarget must deny '$uri', got $decision",
                    decision is FirewallDecision.Denied
                )
            }

            // 2. Hard-blocked in authorizeToolCall arguments
            val safWriteTool = ToolMetadata(
                name = "saf.write",
                displayNameKey = "tool_saf_write",
                description = "Write to SAF URI",
                category = ToolCategory.NOTES_FILES,
                requiredCapability = AtomicCapability.CREATE_DRAFT,
                fields = listOf(
                    ToolSchemaField(
                        name = "uri",
                        description = "Destination URI",
                        required = true,
                        slotKind = SensitiveSlotKind.EXTERNAL_URI,
                        valueType = SlotValueType.STRING
                    )
                )
            )
            val token = h.firewall.mintToken(
                requestId = "req-schemes",
                utteranceProvenance = DataProvenance.USER_UTTERANCE,
                candidateTools = setOf("saf.write"),
                nowEpochMs = nowMs
            )

            for (uri in blockedSchemes) {
                val decision = h.firewall.authorizeToolCall(
                    token = token,
                    toolCall = ToolCallAst(
                        toolName = "saf.write",
                        arguments = mapOf(
                            "uri" to Tainted.fromUserUtterance(
                                value = SlotValueAst.StringValue(uri),
                                slotKind = SensitiveSlotKind.EXTERNAL_URI
                            )
                        )
                    ),
                    toolMetadata = safWriteTool,
                    targetId = targetId,
                    nowEpochMs = nowMs
                )
                assertTrue(
                    "authorizeToolCall must deny '$uri', got $decision",
                    decision is FirewallDecision.Denied
                )
            }

            // 3. Hard-blocked arbitrary Android actions
            val blockedActions = listOf(
                "android.intent.action.VIEW",
                "android.intent.action.SEND",
                "android.intent.action.WEB_SEARCH",
                "android.intent.action.PROCESS_TEXT"
            )
            for (action in blockedActions) {
                val decision = h.firewall.validateOutboundTarget(
                    toolName = "launcher.intent",
                    action = action,
                    uriOrTarget = Tainted.fromUserUtterance("content://com.android.calendar/events")
                )
                assertTrue(
                    "validateOutboundTarget must deny action '$action', got $decision",
                    decision is FirewallDecision.Denied
                )
                assertEquals(
                    OutboundChannelPolicy.REASON_ACTION_BLOCKED,
                    (decision as FirewallDecision.Denied).reasonCode
                )
            }
        }

    @Test
    fun smsToTelAndSafWriteInjectionAttacksAreDenied() = runTest {
        val h = createHarness()

        val smsAttacks = listOf(
            "smsto:+15550199?body=https://evil.com/leak",
            "smsto:+15550199?body=secret_exfil",
            "smsto:+15550199\r\nX-Injected: evil",
            "smsto:+15550199\nBcc:+15550000",
            "smsto:attacker@evil.com;exec",
            "smsto:",
            "mailto:attacker@evil.com"
        )
        for (payload in smsAttacks) {
            val d = h.firewall.validateOutboundTarget(
                toolName = "sms.create_draft",
                action = OutboundChannelPolicy.ACTION_SENDTO,
                uriOrTarget = Tainted.fromUserUtterance(payload, SensitiveSlotKind.EXTERNAL_URI)
            )
            assertTrue("Expected Denied for smsto attack '$payload', got $d", d is FirewallDecision.Denied)
        }

        val telAttacks = listOf(
            "tel:+15550199;postd=1234",
            "tel:+15550199?redirect=https://evil.com",
            "tel:+15550199\r\n9999",
            "tel:abc",
            "tel:"
        )
        for (payload in telAttacks) {
            val d = h.firewall.validateOutboundTarget(
                toolName = "call.dial",
                action = OutboundChannelPolicy.ACTION_DIAL,
                uriOrTarget = Tainted.fromUserUtterance(payload, SensitiveSlotKind.PHONE_NUMBER)
            )
            assertTrue("Expected Denied for tel attack '$payload', got $d", d is FirewallDecision.Denied)
        }

        val safAttacks = listOf(
            "file:///etc/passwd",
            "https://evil.example/upload",
            "content://com.android.externalstorage.documents/tree/../secret",
            "content://com.android.externalstorage.documents/tree/%2e%2e/secret"
        )
        for (payload in safAttacks) {
            val d = h.firewall.validateOutboundTarget(
                toolName = "saf.write",
                action = OutboundChannelPolicy.ACTION_SAF_WRITE,
                uriOrTarget = Tainted.fromUserUtterance(payload, SensitiveSlotKind.EXTERNAL_URI)
            )
            assertTrue("Expected Denied for SAF_WRITE attack '$payload', got $d", d is FirewallDecision.Denied)
        }
    }

    @Test
    fun bareRecipientCrlfInjectionAndPartialPercentEncodedSafTraversalMustBeDenied() = runTest {
        // Adversarial probes for two subtle OutboundChannelPolicy bypasses:
        // 1. Bare RECIPIENT_ADDRESS / PHONE_NUMBER carrying CRLF injection without "smsto:" prefix.
        // 2. Partial URL-encoded path traversal (".%2e" / "%2e.") in SAF_WRITE / FILE_PATH.
        val h = createHarness()
        val targetId = "com.nava.sms"
        assignAutoProfile(h.profileManager, targetId)

        val smsTool = ToolMetadata(
            name = "sms.create_draft",
            displayNameKey = "tool_sms_draft",
            description = "Create SMS draft",
            category = ToolCategory.COMMUNICATION,
            requiredCapability = AtomicCapability.CREATE_DRAFT,
            fields = listOf(
                ToolSchemaField(
                    name = "recipient",
                    description = "Recipient phone number",
                    required = true,
                    slotKind = SensitiveSlotKind.PHONE_NUMBER,
                    valueType = SlotValueType.STRING
                ),
                ToolSchemaField(
                    name = "body",
                    description = "Message body",
                    required = true,
                    slotKind = SensitiveSlotKind.TEXT_BODY,
                    valueType = SlotValueType.STRING
                )
            )
        )
        val token = h.firewall.mintToken(
            requestId = "req-crlf",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf("sms.create_draft"),
            nowEpochMs = nowMs
        )

        val crlfDecision = h.firewall.authorizeToolCall(
            token = token,
            toolCall = ToolCallAst(
                toolName = "sms.create_draft",
                arguments = mapOf(
                    "recipient" to Tainted.fromUserUtterance(
                        value = SlotValueAst.StringValue("+15550199\r\nBcc:+15550999"),
                        slotKind = SensitiveSlotKind.PHONE_NUMBER
                    ),
                    "body" to Tainted.fromUserUtterance(
                        value = SlotValueAst.StringValue("Hello"),
                        slotKind = SensitiveSlotKind.TEXT_BODY
                    )
                )
            ),
            toolMetadata = smsTool,
            targetId = targetId,
            nowEpochMs = nowMs
        )
        assertTrue(
            "CRLF header injection in bare PHONE_NUMBER slot must be Denied, got $crlfDecision",
            crlfDecision is FirewallDecision.Denied
        )

        val partialEncodedSaf = h.firewall.validateOutboundTarget(
            toolName = "saf.write",
            action = OutboundChannelPolicy.ACTION_SAF_WRITE,
            uriOrTarget = Tainted.fromUserUtterance(
                "content://com.android.externalstorage.documents/document/primary:.%2e/secret.txt",
                SensitiveSlotKind.EXTERNAL_URI
            )
        )
        assertTrue(
            "Partial percent-encoded traversal (.%2e) in SAF_WRITE must be Denied, got $partialEncodedSaf",
            partialEncodedSaf is FirewallDecision.Denied
        )
    }

    @Test
    fun vaultAndUntrustedDataCrossingSmsDraftSafWriteOrOutboundTargetRequireConfirmationAndAudit() =
        runTest {
            val h = createHarness()
            val targetId = "com.nava.outbound"
            assignAutoProfile(h.profileManager, targetId)

            // 1. Vault-sourced data in SMS draft body (passive TEXT_BODY slot on COMMUNICATION tool)
            val smsTool = ToolMetadata(
                name = "sms.create_draft",
                displayNameKey = "tool_sms_draft",
                description = "Create SMS draft",
                category = ToolCategory.COMMUNICATION,
                requiredCapability = AtomicCapability.CREATE_DRAFT,
                fields = listOf(
                    ToolSchemaField("recipient", "Phone", true, SensitiveSlotKind.PHONE_NUMBER),
                    ToolSchemaField("body", "Text", true, SensitiveSlotKind.TEXT_BODY)
                )
            )
            val safWriteTool = ToolMetadata(
                name = "saf.write",
                displayNameKey = "tool_saf_write",
                description = "Write file via SAF",
                category = ToolCategory.NOTES_FILES,
                requiredCapability = AtomicCapability.CREATE_DRAFT,
                fields = listOf(
                    ToolSchemaField("uri", "SAF URI", true, SensitiveSlotKind.EXTERNAL_URI),
                    ToolSchemaField("content", "File content", true, SensitiveSlotKind.TEXT_BODY)
                )
            )

            val token = h.firewall.mintToken(
                requestId = "req-vault-barrier",
                utteranceProvenance = DataProvenance.USER_UTTERANCE,
                candidateTools = setOf("sms.create_draft", "saf.write"),
                nowEpochMs = nowMs
            )

            // Vault data tagged via sourceLabel = "vault:secret_key"
            val vaultTaintedBody = Tainted.fromUntrustedExternal(
                value = SlotValueAst.StringValue("Vault secret PIN 9999"),
                slotKind = SensitiveSlotKind.TEXT_BODY,
                sourceLabel = "vault:secret_key"
            )
            val smsVaultDecision = h.firewall.authorizeToolCall(
                token = token,
                toolCall = ToolCallAst(
                    toolName = "sms.create_draft",
                    arguments = mapOf(
                        "recipient" to Tainted.fromUserUtterance(
                            SlotValueAst.StringValue("+15550199"),
                            SensitiveSlotKind.PHONE_NUMBER
                        ),
                        "body" to vaultTaintedBody
                    )
                ),
                toolMetadata = smsTool,
                targetId = targetId,
                nowEpochMs = nowMs
            )
            assertTrue(
                "Vault data crossing SMS draft must require confirmation, got $smsVaultDecision",
                smsVaultDecision is FirewallDecision.RequiresConfirmation
            )
            assertTrue("body" in (smsVaultDecision as FirewallDecision.RequiresConfirmation).untrustedHighRiskSlots)

            // Untrusted external data crossing SAF write
            val safUntrustedDecision = h.firewall.authorizeToolCall(
                token = token,
                toolCall = ToolCallAst(
                    toolName = "saf.write",
                    arguments = mapOf(
                        "uri" to Tainted.fromUserUtterance(
                            SlotValueAst.StringValue("content://com.android.externalstorage.documents/tree/primary:Docs"),
                            SensitiveSlotKind.EXTERNAL_URI
                        ),
                        "content" to Tainted.fromUntrustedExternal(
                            SlotValueAst.StringValue("Extracted notification snippet"),
                            SensitiveSlotKind.TEXT_BODY,
                            sourceLabel = "notification:com.chat.app"
                        )
                    )
                ),
                toolMetadata = safWriteTool,
                targetId = targetId,
                nowEpochMs = nowMs
            )
            assertTrue(
                "UNTRUSTED_EXTERNAL data crossing SAF write must require confirmation, got $safUntrustedDecision",
                safUntrustedDecision is FirewallDecision.RequiresConfirmation
            )
            assertTrue("content" in (safUntrustedDecision as FirewallDecision.RequiresConfirmation).untrustedHighRiskSlots)

            // Vault-sourced and untrusted targets crossing allowlisted validateOutboundTarget
            val outboundVault = h.firewall.validateOutboundTarget(
                toolName = "sms.create_draft",
                action = OutboundChannelPolicy.ACTION_SENDTO,
                uriOrTarget = Tainted.fromUntrustedExternal(
                    value = "smsto:+15550199",
                    slotKind = SensitiveSlotKind.EXTERNAL_URI,
                    sourceLabel = "vault:secret_key"
                )
            )
            assertTrue(
                "Vault target crossing validateOutboundTarget must require confirmation",
                outboundVault is FirewallDecision.RequiresConfirmation
            )

            val outboundUntrusted = h.firewall.validateOutboundTarget(
                toolName = "saf.write",
                action = OutboundChannelPolicy.ACTION_SAF_WRITE,
                uriOrTarget = Tainted.fromUntrustedExternal(
                    value = "content://com.android.externalstorage.documents/tree/primary:Docs",
                    slotKind = SensitiveSlotKind.EXTERNAL_URI,
                    sourceLabel = "notification:com.evil"
                )
            )
            assertTrue(
                "UNTRUSTED_EXTERNAL target crossing validateOutboundTarget must require confirmation",
                outboundUntrusted is FirewallDecision.RequiresConfirmation
            )

            // Every single decision must be recorded in encrypted AuditLogDao
            val audits = h.auditLogDao.queryRecent(20)
            assertEquals(4, audits.size)
            assertEquals(
                2,
                audits.count { it.decision == SecurityFirewall.DECISION_REQUIRES_CONFIRMATION_TAINTED }
            )
            assertEquals(
                2,
                audits.count { it.decision == SecurityFirewall.DECISION_OUTBOUND_CONFIRMATION_REQUIRED }
            )
        }

    @Test
    fun endToEndExecutePlanBlocksAutoSmsDraftAndUrlExfiltrationFromNotificationPayload() = runTest {
        val h = createHarness()
        val smsTargetId = "com.android.mms"
        assignAutoProfile(h.profileManager, smsTargetId)

        var smsExecutedCount = 0
        val smsTool = object : NavaTool {
            override val metadata = ToolMetadata(
                name = "sms.create_draft",
                displayNameKey = "tool_sms_draft",
                description = "Create SMS draft",
                category = ToolCategory.COMMUNICATION,
                requiredCapability = AtomicCapability.CREATE_DRAFT,
                fields = listOf(
                    ToolSchemaField("recipient", "Phone", true, SensitiveSlotKind.PHONE_NUMBER),
                    ToolSchemaField("body", "Message body", true, SensitiveSlotKind.TEXT_BODY)
                )
            )

            override suspend fun execute(
                context: ToolExecutionContext,
                arguments: Map<String, Tainted<SlotValueAst>>
            ): ToolResult {
                smsExecutedCount++
                return ToolResult.Success(UserMessage(MessageKey.ACTION_SMS_DRAFT_PREPARED))
            }
        }

        val registry = ToolRegistry(listOf(smsTool))
        val executePlanUseCase = ExecutePlanUseCase(
            toolRegistry = registry,
            securityFirewall = h.firewall,
            auditLog = h.auditLogDao
        )

        val token = h.firewall.mintToken(
            requestId = "req-e2e-1",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf("sms.create_draft"),
            nowEpochMs = nowMs
        )

        // Attack 1: Attacker recipient extracted from untrusted notification -> must NOT auto-execute
        val untrustedSmsPlan = PlanAst(
            planId = "plan-e2e-tainted",
            calls = listOf(
                ToolCallAst(
                    toolName = "sms.create_draft",
                    arguments = mapOf(
                        "recipient" to Tainted.fromUntrustedExternal(
                            value = SlotValueAst.StringValue("+15550199"),
                            slotKind = SensitiveSlotKind.PHONE_NUMBER,
                            sourceLabel = "notification:com.attacker.chat"
                        ),
                        "body" to Tainted.fromUserUtterance(
                            value = SlotValueAst.StringValue("On my way"),
                            slotKind = SensitiveSlotKind.TEXT_BODY
                        )
                    ),
                    orderIndex = 0
                )
            )
        )
        val taintedResults = executePlanUseCase(
            plan = untrustedSmsPlan,
            capabilityToken = token,
            targetId = smsTargetId,
            languageTag = "en",
            nowEpochMs = nowMs
        )
        assertEquals(0, smsExecutedCount)
        assertEquals(1, taintedResults.size)
        val confirmResult = taintedResults.single()
        assertTrue(
            "Expected ToolResult.ConfirmationRequired, got $confirmResult",
            confirmResult is ToolResult.ConfirmationRequired
        )
        assertTrue((confirmResult as ToolResult.ConfirmationRequired).hasUntrustedHighRiskSlot)
        assertEquals(MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE, confirmResult.message.key)

        // Attack 2: URL exfiltration smuggled inside destination slot -> hard-denied with zero execution
        val exfilPlan = PlanAst(
            planId = "plan-e2e-exfil",
            calls = listOf(
                ToolCallAst(
                    toolName = "sms.create_draft",
                    arguments = mapOf(
                        "recipient" to Tainted.fromUntrustedExternal(
                            value = SlotValueAst.StringValue("https://evil.example/steal?token=xyz"),
                            slotKind = SensitiveSlotKind.PHONE_NUMBER,
                            sourceLabel = "notification:com.attacker.chat"
                        ),
                        "body" to Tainted.fromUserUtterance(
                            value = SlotValueAst.StringValue("secret"),
                            slotKind = SensitiveSlotKind.TEXT_BODY
                        )
                    ),
                    orderIndex = 0
                )
            )
        )
        val exfilResults = executePlanUseCase(
            plan = exfilPlan,
            capabilityToken = token,
            targetId = smsTargetId,
            languageTag = "en",
            nowEpochMs = nowMs
        )
        assertEquals(0, smsExecutedCount)
        assertEquals(1, exfilResults.size)
        val failureResult = exfilResults.single()
        assertTrue("Expected ToolResult.Failure, got $failureResult", failureResult is ToolResult.Failure)
        assertTrue((failureResult as ToolResult.Failure).isSecurityViolation)
        assertEquals(OutboundChannelPolicy.REASON_HTTP_BLOCKED, failureResult.errorCode)

        // Verify encrypted audit log captured both firewall and use-case audit entries
        val auditEntries = h.auditLogDao.queryRecent(20)
        assertTrue(auditEntries.any { it.decision == OutboundChannelPolicy.REASON_HTTP_BLOCKED })
        assertTrue(auditEntries.any { it.decision == SecurityFirewall.DECISION_REQUIRES_CONFIRMATION_TAINTED })
    }

    @Test
    fun nullByteAdversarialInputsFailClosedAndPersistEncryptedAuditEntries() = runTest {
        val h = createHarness()

        // 1. validateOutboundTarget with embedded null byte in action -> Denied + encrypted audit entry
        val outboundDecision = h.firewall.validateOutboundTarget(
            toolName = "alarm.set",
            action = "${OutboundChannelPolicy.ACTION_SET_ALARM}\u0000",
            uriOrTarget = Tainted.fromUserUtterance("")
        )
        assertTrue(
            "Null-byte action in validateOutboundTarget must return Denied, got $outboundDecision",
            outboundDecision is FirewallDecision.Denied
        )

        // 2. authorizeToolCall with embedded null byte in targetId -> Denied + encrypted audit entry
        val alarmMeta = ToolMetadata(
            name = "alarm.set",
            displayNameKey = "tool_alarm",
            description = "Set alarm",
            category = ToolCategory.TIME_CALENDAR,
            requiredCapability = AtomicCapability.CREATE_DRAFT
        )
        val validToken = h.firewall.mintToken(
            requestId = "req-null-byte-auth",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf("alarm.set"),
            nowEpochMs = nowMs
        )
        val toolCallDecision = h.firewall.authorizeToolCall(
            token = validToken,
            toolCall = ToolCallAst(toolName = "alarm.set", arguments = emptyMap()),
            toolMetadata = alarmMeta,
            targetId = "com.evil\u0000.app",
            nowEpochMs = nowMs
        )
        assertTrue(
            "Null-byte targetId in authorizeToolCall must return Denied, got $toolCallDecision",
            toolCallDecision is FirewallDecision.Denied
        )

        // 3. mintToken with embedded null byte in requestId and untrusted provenance -> SecurityException + audit
        try {
            h.firewall.mintToken(
                requestId = "req\u00001",
                utteranceProvenance = DataProvenance.UNTRUSTED_EXTERNAL,
                candidateTools = setOf("alarm.set"),
                nowEpochMs = nowMs
            )
            fail("Expected SecurityException for untrusted mintToken with null-byte requestId")
        } catch (_: SecurityException) {
            // Expected (must NOT throw IllegalArgumentException from AuditLogDao blind index)
        }

        // 4. authorizeRuleExecution with forged grant carrying null-byte ruleId -> Denied + audit
        val forgedNullRuleGrant = RuleCapabilityGrant(
            grantId = "grant-null-1",
            ruleId = "rule\u00001",
            triggerSpec = RuleTriggerSpec("TIME_DAILY", mapOf("time" to "07:00")),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = "alarm.set",
                    requiredCapability = AtomicCapability.CREATE_DRAFT,
                    staticArguments = mapOf("time" to "07:00")
                )
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "a".repeat(64),
            grantedAtEpochSec = nowMs / 1000L
        )
        val ruleDecision = h.firewall.authorizeRuleExecution(forgedNullRuleGrant)
        assertTrue(
            "Null-byte ruleId in authorizeRuleExecution must return Denied, got $ruleDecision",
            ruleDecision is FirewallDecision.Denied
        )

        // Verify all 4 adversarial null-byte events were persisted in encrypted AuditLogDao
        val audits = h.auditLogDao.queryRecent(20)
        assertEquals(4, audits.size)
        val decisions = audits.map { it.decision }
        assertTrue(OutboundChannelPolicy.REASON_ACTION_BLOCKED in decisions)
        assertTrue(SecurityFirewall.DECISION_PERMISSION_DENIED in decisions)
        assertTrue(SecurityFirewall.DECISION_TOKEN_MINT_DENIED in decisions)
        assertTrue(SecurityFirewall.DECISION_RULE_SEAL_INVALID in decisions)
    }

    @Test
    fun obfuscatedVaultSourceLabelsStillTriggerVaultTaintBarrier() = runTest {
        val h = createHarness()
        val targetId = "com.nava.outbound.obfuscated"
        assignAutoProfile(h.profileManager, targetId)

        val smsTool = ToolMetadata(
            name = "sms.create_draft",
            displayNameKey = "tool_sms_draft",
            description = "Create SMS draft",
            category = ToolCategory.COMMUNICATION,
            requiredCapability = AtomicCapability.CREATE_DRAFT,
            fields = listOf(
                ToolSchemaField("recipient", "Phone", true, SensitiveSlotKind.PHONE_NUMBER),
                ToolSchemaField("body", "Text", true, SensitiveSlotKind.TEXT_BODY)
            )
        )
        val token = h.firewall.mintToken(
            requestId = "req-obfuscated-vault",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf("sms.create_draft"),
            nowEpochMs = nowMs
        )

        val obfuscatedLabels = listOf(
            "v\u200Bault:secret",
            "\uFF56\uFF41\uFF55\uFF4C\uFF54:secret"
        )

        for (label in obfuscatedLabels) {
            val smsDecision = h.firewall.authorizeToolCall(
                token = token,
                toolCall = ToolCallAst(
                    toolName = "sms.create_draft",
                    arguments = mapOf(
                        "recipient" to Tainted.fromUserUtterance(
                            SlotValueAst.StringValue("+15550199"),
                            SensitiveSlotKind.PHONE_NUMBER
                        ),
                        "body" to Tainted.fromUntrustedExternal(
                            value = SlotValueAst.StringValue("Sensitive vault note"),
                            slotKind = SensitiveSlotKind.TEXT_BODY,
                            sourceLabel = label
                        )
                    )
                ),
                toolMetadata = smsTool,
                targetId = targetId,
                nowEpochMs = nowMs
            )
            assertTrue(
                "Obfuscated vault sourceLabel '$label' on SMS draft must require confirmation, got $smsDecision",
                smsDecision is FirewallDecision.RequiresConfirmation
            )
            assertTrue("body" in (smsDecision as FirewallDecision.RequiresConfirmation).untrustedHighRiskSlots)

            val outboundDecision = h.firewall.validateOutboundTarget(
                toolName = "sms.create_draft",
                action = OutboundChannelPolicy.ACTION_SENDTO,
                uriOrTarget = Tainted.fromUntrustedExternal(
                    value = "smsto:+15550199",
                    slotKind = SensitiveSlotKind.EXTERNAL_URI,
                    sourceLabel = label
                )
            )
            assertTrue(
                "Obfuscated vault sourceLabel '$label' on validateOutboundTarget must require confirmation, got $outboundDecision",
                outboundDecision is FirewallDecision.RequiresConfirmation
            )
        }
    }
}

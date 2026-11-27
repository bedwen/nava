package com.nava.core.security.firewall

import com.nava.core.security.dao.AuditLogDao
import com.nava.core.security.policy.PermissionProfileManager
import com.nava.core.security.policy.RuleCapabilityGrantManager
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.testing.InMemoryRowStorage
import com.nava.core.security.testing.InMemorySoftwareKeyProvider
import com.nava.domain.ai.LlmEnginePort
import com.nava.domain.ai.LlmGenerationRequest
import com.nava.domain.ai.LlmGenerationResult
import com.nava.domain.ai.LlmStreamChunk
import com.nava.domain.ai.RamTier
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ThermalState
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.PermissionProfilePreset
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleTriggerSpec
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolCategory
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolSchemaField
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class FirewallAndExtractorUnitTest {

    private class FakeStage2LlmEngine(
        private val responseText: String
    ) : LlmEnginePort {
        var lastRequest: LlmGenerationRequest? = null

        override suspend fun isModelLoaded(): Boolean = true
        override suspend fun currentRamTier(): RamTier = RamTier.TIER_1_STANDARD
        override suspend fun currentThermalState(): ThermalState = ThermalState.NORMAL
        override suspend fun generate(request: LlmGenerationRequest): LlmGenerationResult {
            lastRequest = request
            return LlmGenerationResult(rawOutput = responseText)
        }
        override fun generateStream(request: LlmGenerationRequest): Flow<LlmStreamChunk> = emptyFlow()
        override suspend fun unloadModel() {}
    }

    private fun calendarInsertMetadata(): ToolMetadata = ToolMetadata(
        name = "calendar_insert",
        displayNameKey = "tool_calendar_insert",
        description = "Create a calendar event",
        category = ToolCategory.TIME_CALENDAR,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "title",
                description = "Event title",
                required = true,
                slotKind = SensitiveSlotKind.EVENT_TITLE,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "start_time",
                description = "Event start ISO datetime",
                required = true,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.ISO_DATETIME
            ),
            ToolSchemaField(
                name = "duration_sec",
                description = "Duration in seconds",
                required = false,
                slotKind = SensitiveSlotKind.DURATION,
                valueType = SlotValueType.DURATION_SECONDS
            ),
            ToolSchemaField(
                name = "all_day",
                description = "All-day flag",
                required = false,
                slotKind = SensitiveSlotKind.EVENT_TITLE,
                valueType = SlotValueType.BOOLEAN
            ),
            ToolSchemaField(
                name = "notes",
                description = "Optional notes",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            )
        )
    )

    @Test
    fun blindSlotExtractorExtractsTypedPassiveSlotsWrappedAsUntrusted() = runTest {
        val fakeEngine = FakeStage2LlmEngine(
            responseText = """
                title: "Design Review"
                start_time: 2026-11-20T09:00:00Z
                duration_sec: 3600
                all_day: false
                notes: null
            """.trimIndent()
        )
        val extractor = BlindSlotExtractor(
            llmEngine = fakeEngine,
            requestIdGenerator = { "req_stage2_1" }
        )
        val metadata = calendarInsertMetadata()
        val token = CapabilityToken.mint(
            tokenId = "tok_1",
            requestId = "req_1",
            allowedTools = setOf("calendar_insert"),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = 1_000L
        )

        val slots = extractor.extractSlots(
            capabilityToken = token,
            targetTool = metadata,
            rawExternalContent = "Let us meet for Design Review tomorrow at 9 AM for one hour.",
            sourceLabel = "notif:com.example.mail",
            languageHintTag = "en",
            nowEpochMs = 2_000L
        )

        val sentRequest = fakeEngine.lastRequest!!
        assertTrue(sentRequest.prunedTools.isEmpty())
        assertTrue(sentRequest.stage2BlindExtractionMode)
        assertEquals(false, sentRequest.allowThoughtMode)

        assertEquals(5, slots.size)
        val titleSlot = slots.getValue("title")
        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, titleSlot.provenance)
        assertEquals(SensitiveSlotKind.EVENT_TITLE, titleSlot.slotKind)
        assertEquals("notif:com.example.mail", titleSlot.sourceLabel)
        assertEquals(SlotValueAst.StringValue("Design Review"), titleSlot.value)

        assertEquals(SlotValueAst.StringValue("2026-11-20T09:00:00Z"), slots.getValue("start_time").value)
        assertEquals(SlotValueAst.IntValue(3600L), slots.getValue("duration_sec").value)
        assertEquals(SlotValueAst.BooleanValue(false), slots.getValue("all_day").value)
        assertEquals(SlotValueAst.NullValue, slots.getValue("notes").value)
    }

    @Test
    fun outboundChannelPolicyAllowsStaticSystemIntentTemplates() {
        val policy = OutboundChannelPolicy()

        assertEquals(
            OutboundPolicyVerdict.Allowed,
            policy.evaluate(OutboundChannelPolicy.ACTION_SENDTO, "smsto:+15551234567")
        )
        assertEquals(
            OutboundPolicyVerdict.Allowed,
            policy.evaluate(OutboundChannelPolicy.ACTION_DIAL, "tel:+15551234567")
        )
        assertEquals(
            OutboundPolicyVerdict.Allowed,
            policy.evaluate(
                OutboundChannelPolicy.ACTION_SAF_WRITE,
                "content://com.android.externalstorage.documents/tree/primary"
            )
        )
        assertEquals(
            OutboundPolicyVerdict.Allowed,
            policy.evaluate(OutboundChannelPolicy.ACTION_SET_ALARM, "")
        )
        assertEquals(
            OutboundPolicyVerdict.Allowed,
            policy.evaluate(OutboundChannelPolicy.ACTION_APP_LAUNCH, "com.example.notes")
        )
        assertEquals(
            OutboundPolicyVerdict.Allowed,
            policy.evaluate(
                OutboundChannelPolicy.ACTION_CALENDAR_PROVIDER,
                "content://com.android.calendar/events"
            )
        )

        assertEquals(
            OutboundPolicyVerdict.Allowed,
            policy.inspectArgumentValue(SensitiveSlotKind.PHONE_NUMBER, "+15551234567", "phone")
        )
        assertEquals(
            OutboundPolicyVerdict.Allowed,
            policy.inspectArgumentValue(SensitiveSlotKind.TEXT_BODY, "See you at 9", "body")
        )
    }

    @Test
    fun securityFirewallMintTokenAuthorizationGatesRulesAndOutboundValidation() = runTest {
        val keyProvider = InMemorySoftwareKeyProvider()
        val store = EncryptedSqliteStore(
            storage = InMemoryRowStorage(),
            keyProvider = keyProvider,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val profileManager = PermissionProfileManager(store)
        val ruleManager = RuleCapabilityGrantManager(store, keyProvider)
        val auditDao = AuditLogDao(store)
        var clockNowMs = 10_000L
        val firewall = SecurityFirewall(
            permissionEvaluator = profileManager,
            ruleGrantManager = ruleManager,
            auditLog = auditDao,
            clockMs = { clockNowMs }
        )

        // Minting fails for non-USER_UTTERANCE and records audit log.
        try {
            firewall.mintToken(
                requestId = "req_bad",
                utteranceProvenance = DataProvenance.UNTRUSTED_EXTERNAL,
                candidateTools = setOf("set_alarm"),
                nowEpochMs = clockNowMs
            )
            fail("Expected SecurityException for non-user provenance mint")
        } catch (_: SecurityException) {
            // Expected
        }

        val token = firewall.mintToken(
            requestId = "req_ok",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf("calendar_insert"),
            nowEpochMs = clockNowMs
        )
        assertEquals(1, token.maxToolCalls)

        // A plan that calls the same tool twice gets a two-call token; the ceiling still applies.
        val repeated = firewall.mintToken(
            requestId = "req_repeat",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf("calendar_insert"),
            nowEpochMs = clockNowMs,
            maxToolCalls = 2
        )
        assertEquals(2, repeated.maxToolCalls)
        val capped = firewall.mintToken(
            requestId = "req_many",
            utteranceProvenance = DataProvenance.USER_UTTERANCE,
            candidateTools = setOf("calendar_insert"),
            nowEpochMs = clockNowMs,
            maxToolCalls = 1_000
        )
        assertEquals(SecurityFirewall.MAX_PLAN_CALLS, capped.maxToolCalls)

        val calMeta = calendarInsertMetadata()
        val userCall = ToolCallAst(
            toolName = "calendar_insert",
            arguments = mapOf(
                "title" to Tainted.fromUserUtterance(
                    SlotValueAst.StringValue("Standup"),
                    SensitiveSlotKind.EVENT_TITLE
                ),
                "start_time" to Tainted.fromUserUtterance(
                    SlotValueAst.StringValue("2026-11-20T09:00:00Z"),
                    SensitiveSlotKind.DATE_TIME
                )
            )
        )

        // Unassigned target -> DISABLED (Default-Deny)
        val deniedDecision = firewall.authorizeToolCall(
            token = token,
            toolCall = userCall,
            toolMetadata = calMeta,
            targetId = "com.example.unassigned",
            nowEpochMs = clockNowMs
        )
        assertTrue(deniedDecision is FirewallDecision.Denied)
        assertEquals(SecurityFirewall.DECISION_PERMISSION_DENIED, (deniedDecision as FirewallDecision.Denied).reasonCode)

        // AUTO profile -> Authorized
        clockNowMs = 11_000L
        profileManager.assignTargetToProfile(
            targetId = "com.example.auto_cal",
            profileId = PermissionProfile.TRUSTED_SYSTEM_PROFILE_ID
        )
        val autoDecision = firewall.authorizeToolCall(
            token = token,
            toolCall = userCall,
            toolMetadata = calMeta,
            targetId = "com.example.auto_cal",
            nowEpochMs = clockNowMs
        )
        assertEquals(FirewallDecision.Authorized, autoDecision)

        // PROMPT_CARD profile -> RequiresConfirmation
        clockNowMs = 12_000L
        profileManager.assignTargetToProfile(
            targetId = "com.example.prompt_cal",
            profileId = PermissionProfile.SAFE_DRAFT_PROFILE_ID
        )
        val promptDecision = firewall.authorizeToolCall(
            token = token,
            toolCall = userCall,
            toolMetadata = calMeta,
            targetId = "com.example.prompt_cal",
            nowEpochMs = clockNowMs
        )
        assertTrue(promptDecision is FirewallDecision.RequiresConfirmation)

        // BIOMETRIC profile -> RequiresBiometric
        clockNowMs = 13_000L
        val bioProfile = PermissionProfile(
            id = "custom_bio_cal",
            name = "Biometric Calendar",
            preset = PermissionProfilePreset.CUSTOM,
            capabilities = mapOf(
                AtomicCapability.DATA_READ to ConfirmationLevel.BIOMETRIC,
                AtomicCapability.CREATE_DRAFT to ConfirmationLevel.PROMPT_CARD,
                AtomicCapability.MODIFY_DELETE_SEND to ConfirmationLevel.BIOMETRIC
            )
        )
        profileManager.saveProfile(bioProfile)
        profileManager.assignTargetToProfile("com.example.bio_cal", bioProfile.id)
        val readMeta = ToolMetadata(
            name = "calendar_insert",
            displayNameKey = "tool_cal_read",
            description = "Read calendar",
            category = ToolCategory.TIME_CALENDAR,
            requiredCapability = AtomicCapability.DATA_READ
        )
        val bioDecision = firewall.authorizeToolCall(
            token = token,
            toolCall = userCall,
            toolMetadata = readMeta,
            targetId = "com.example.bio_cal",
            nowEpochMs = clockNowMs
        )
        assertTrue(bioDecision is FirewallDecision.RequiresBiometric)

        // Rule execution authorization
        clockNowMs = 14_000L
        ruleManager.createPendingRule(
            ruleId = "safe_rule",
            triggerSpec = RuleTriggerSpec("TIME_DAILY", mapOf("time" to "07:00")),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = "set_dnd",
                    requiredCapability = AtomicCapability.CREATE_DRAFT,
                    staticArguments = mapOf("mode" to "off")
                )
            ),
            nowEpochSec = 14L
        )
        val approvedRule = ruleManager.approveAndSealRule("safe_rule", nowEpochSec = 15L)
        assertEquals(FirewallDecision.Authorized, firewall.authorizeRuleExecution(approvedRule))

        ruleManager.setGlobalRulesPaused(true)
        val pausedRuleDecision = firewall.authorizeRuleExecution(approvedRule)
        assertTrue(pausedRuleDecision is FirewallDecision.Denied)
        ruleManager.setGlobalRulesPaused(false)

        // Outbound target validation
        clockNowMs = 15_000L
        assertEquals(
            FirewallDecision.Authorized,
            firewall.validateOutboundTarget(
                toolName = "sms_draft",
                action = OutboundChannelPolicy.ACTION_SENDTO,
                uriOrTarget = Tainted.fromUserUtterance("smsto:+15551234567", SensitiveSlotKind.EXTERNAL_URI)
            )
        )

        val untrustedOutbound = firewall.validateOutboundTarget(
            toolName = "sms_draft",
            action = OutboundChannelPolicy.ACTION_SENDTO,
            uriOrTarget = Tainted.fromUntrustedExternal(
                "smsto:+15551234567",
                SensitiveSlotKind.EXTERNAL_URI,
                "notif:chat"
            )
        )
        assertTrue(untrustedOutbound is FirewallDecision.RequiresConfirmation)

        val recentAudits = auditDao.queryRecent(20)
        assertTrue(recentAudits.size >= 7)
    }
}

package com.nava.feature.automations.alarm

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.common.AutomationIntentGateway
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.PlatformDispatchResult
import com.nava.feature.automations.common.ToolTargetIds
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AlarmTimerToolTest {

    private class FakeIntentGateway : AutomationIntentGateway {
        var lastAlarmHour: Int? = null
        var lastAlarmMinute: Int? = null
        var lastAlarmLabel: String? = null
        var lastAlarmSkipUi: Boolean? = null
        var alarmResult: PlatformDispatchResult = PlatformDispatchResult.Dispatched()

        var lastTimerSeconds: Int? = null
        var lastTimerLabel: String? = null
        var lastTimerSkipUi: Boolean? = null
        var timerResult: PlatformDispatchResult = PlatformDispatchResult.Dispatched()

        override fun hasRuntimePermission(permission: String): Boolean = true
        override fun isNotificationPolicyAccessGranted(): Boolean = true
        override fun isNotificationListenerEnabled(): Boolean = true

        override fun dispatchSetAlarm(
            hour: Int,
            minute: Int,
            label: String?,
            skipUi: Boolean
        ): PlatformDispatchResult {
            lastAlarmHour = hour
            lastAlarmMinute = minute
            lastAlarmLabel = label
            lastAlarmSkipUi = skipUi
            return alarmResult
        }

        override fun dispatchSetTimer(
            durationSeconds: Int,
            label: String?,
            skipUi: Boolean
        ): PlatformDispatchResult {
            lastTimerSeconds = durationSeconds
            lastTimerLabel = label
            lastTimerSkipUi = skipUi
            return timerResult
        }

        override fun dispatchSmsDraft(recipient: String, body: String): PlatformDispatchResult =
            PlatformDispatchResult.Dispatched()

        override fun dispatchDial(phoneNumber: String): PlatformDispatchResult =
            PlatformDispatchResult.Dispatched()

        override fun dispatchDirectCall(phoneNumber: String): PlatformDispatchResult =
            PlatformDispatchResult.Dispatched()

        override fun resolveLaunchablePackage(appNameOrPackage: String): String? = appNameOrPackage
        override fun dispatchLaunchApp(packageName: String): PlatformDispatchResult =
            PlatformDispatchResult.Dispatched()
    }

    private class FakeFirewall : SecurityFirewallPort {
        var outboundDecision: FirewallDecision = FirewallDecision.Authorized

        override suspend fun mintToken(
            requestId: String,
            utteranceProvenance: DataProvenance,
            candidateTools: Set<String>,
            nowEpochMs: Long
        ): CapabilityToken = error("Not used in tool unit tests")

        override suspend fun authorizeToolCall(
            token: CapabilityToken,
            toolCall: com.nava.domain.ai.ToolCallAst,
            toolMetadata: com.nava.domain.tool.ToolMetadata,
            targetId: String,
            nowEpochMs: Long
        ): FirewallDecision = FirewallDecision.Authorized

        override suspend fun authorizeRuleExecution(grant: RuleCapabilityGrant): FirewallDecision =
            FirewallDecision.Authorized

        override suspend fun validateOutboundTarget(
            toolName: String,
            action: String,
            uriOrTarget: Tainted<String>
        ): FirewallDecision = outboundDecision
    }

    private class FakeAuditLog : AuditLogPort {
        val records = mutableListOf<AuditLogEntry>()

        override suspend fun record(entry: AuditLogEntry) {
            records.add(entry)
        }

        override suspend fun queryRecent(limit: Int): List<AuditLogEntry> = records.takeLast(limit)
    }

    private val fakeGateway = FakeIntentGateway()
    private val fakeFirewall = FakeFirewall()
    private val fakeAudit = FakeAuditLog()
    private var simulatedTime: Long = 1_000_000L

    private val composite = AlarmTimerTool(
        intentGateway = fakeGateway,
        firewall = fakeFirewall,
        auditLog = fakeAudit,
        clock = { simulatedTime }
    )

    private fun testContext(): ToolExecutionContext = ToolExecutionContext(
        requestId = "req-alarm-1",
        capabilityToken = CapabilityToken.mint(
            tokenId = "tok-1",
            requestId = "req-alarm-1",
            allowedTools = setOf(AutomationToolNames.SET_ALARM, AutomationToolNames.SET_TIMER),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = simulatedTime
        ),
        ruleGrant = null,
        targetId = ToolTargetIds.CLOCK,
        languageTag = "en",
        issuedAtEpochMs = simulatedTime,
        isUnattendedBackground = false
    )

    @Test
    fun compositeExposesBothToolsWithCorrectMetadata() {
        val tools = composite.allTools()
        assertEquals(2, tools.size)
        assertEquals(AutomationToolNames.SET_ALARM, tools[0].metadata.name)
        assertEquals(AutomationToolNames.SET_TIMER, tools[1].metadata.name)

        var count = 0
        for (tool in composite) {
            count++
            assertTrue(tool.metadata.supportsUnattendedRule)
        }
        assertEquals(2, count)
    }

    @Test
    fun setAlarmDispatchesSuccessfullyWithHourAndMinute() = runBlocking {
        val args = mapOf(
            "hour" to Tainted.fromUserUtterance(SlotValueAst.IntValue(7)),
            "minute" to Tainted.fromUserUtterance(SlotValueAst.IntValue(30)),
            "label" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Work standup"))
        )

        val result = composite.setAlarmTool.execute(testContext(), args)
        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals(MessageKey.ACTION_ALARM_SET, success.message.key)
        assertEquals("07:30", success.outputValues["time"])

        assertEquals(7, fakeGateway.lastAlarmHour)
        assertEquals(30, fakeGateway.lastAlarmMinute)
        assertEquals("Work standup", fakeGateway.lastAlarmLabel)

        assertEquals(1, fakeAudit.records.size)
        assertEquals("SUCCESS", fakeAudit.records.first().decision)
        assertEquals(ToolTargetIds.CLOCK, fakeAudit.records.first().targetId)
    }

    @Test
    fun setAlarmParsesCanonicalTimeString() = runBlocking {
        val args = mapOf(
            "time" to Tainted.fromUserUtterance(SlotValueAst.StringValue("18:45"))
        )

        val result = composite.setAlarmTool.execute(testContext(), args)
        assertTrue(result is ToolResult.Success)
        assertEquals(18, fakeGateway.lastAlarmHour)
        assertEquals(45, fakeGateway.lastAlarmMinute)
    }

    @Test
    fun setAlarmParsesMeridiemAndKeywords() = runBlocking {
        val pmArgs = mapOf(
            "hour" to Tainted.fromUserUtterance(SlotValueAst.IntValue(8)),
            "meridiem" to Tainted.fromUserUtterance(SlotValueAst.StringValue("pm"))
        )
        val pmResult = composite.setAlarmTool.execute(testContext(), pmArgs)
        assertTrue(pmResult is ToolResult.Success)
        assertEquals(20, fakeGateway.lastAlarmHour)
        assertEquals(0, fakeGateway.lastAlarmMinute)

        val morningArgs = mapOf(
            "hour" to Tainted.fromUserUtterance(SlotValueAst.IntValue(12)),
            "period_keyword" to Tainted.fromUserUtterance(SlotValueAst.StringValue("morning"))
        )
        val morningResult = composite.setAlarmTool.execute(testContext(), morningArgs)
        assertTrue(morningResult is ToolResult.Success)
        assertEquals(0, fakeGateway.lastAlarmHour)
    }

    @Test
    fun setAlarmRejectsInvalidBounds() = runBlocking {
        val badArgs = mapOf(
            "hour" to Tainted.fromUserUtterance(SlotValueAst.IntValue(25)),
            "minute" to Tainted.fromUserUtterance(SlotValueAst.IntValue(70))
        )
        val result = composite.setAlarmTool.execute(testContext(), badArgs)
        assertTrue(result is ToolResult.Failure)
        val failure = result as ToolResult.Failure
        assertEquals(MessageKey.ERROR_INVALID_ARGUMENTS, failure.message.key)
    }

    @Test
    fun setAlarmRejectsVaultTaint() = runBlocking {
        val vaultArgs = mapOf(
            "hour" to Tainted.fromUntrustedExternal(
                SlotValueAst.IntValue(8),
                SensitiveSlotKind.DATE_TIME,
                sourceLabel = "vault:secret"
            )
        )
        val result = composite.setAlarmTool.execute(testContext(), vaultArgs)
        assertTrue(result is ToolResult.Failure)
        val failure = result as ToolResult.Failure
        assertTrue(failure.isSecurityViolation)
        assertEquals("VAULT_DATA_EXFILTRATION_BLOCKED", failure.errorCode)
    }

    @Test
    fun setAlarmHandlesFirewallDenialAndPermissions() = runBlocking {
        fakeFirewall.outboundDecision = FirewallDecision.Denied(
            message = UserMessage(MessageKey.ERROR_SECURITY_VIOLATION),
            reasonCode = "OUTBOUND_BLOCKED"
        )
        val args = mapOf("hour" to Tainted.fromUserUtterance(SlotValueAst.IntValue(8)))
        val blockedResult = composite.setAlarmTool.execute(testContext(), args)
        assertTrue(blockedResult is ToolResult.Failure)
        assertTrue((blockedResult as ToolResult.Failure).isSecurityViolation)

        fakeFirewall.outboundDecision = FirewallDecision.Authorized
        fakeGateway.alarmResult = PlatformDispatchResult.MissingPermission("com.android.alarm.permission.SET_ALARM")
        val permResult = composite.setAlarmTool.execute(testContext(), args)
        assertTrue(permResult is ToolResult.Failure)
        assertEquals(MessageKey.ERROR_SYSTEM_PERMISSION_MISSING, (permResult as ToolResult.Failure).message.key)

        fakeGateway.alarmResult = PlatformDispatchResult.Unavailable("Clock app disabled")
        val unavailResult = composite.setAlarmTool.execute(testContext(), args)
        assertTrue(unavailResult is ToolResult.Failure)
        assertEquals(MessageKey.ERROR_PLATFORM_UNAVAILABLE, (unavailResult as ToolResult.Failure).message.key)
    }

    @Test
    fun setTimerDispatchesSuccessfullyWithSeconds() = runBlocking {
        val args = mapOf(
            "duration_seconds" to Tainted.fromUserUtterance(SlotValueAst.IntValue(300)),
            "label" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Tea"))
        )

        val result = composite.setTimerTool.execute(testContext(), args)
        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals(MessageKey.ACTION_TIMER_SET, success.message.key)
        assertEquals("300", success.outputValues["duration_seconds"])

        assertEquals(300, fakeGateway.lastTimerSeconds)
        assertEquals("Tea", fakeGateway.lastTimerLabel)
    }

    @Test
    fun setTimerCalculatesValueWithUnits() = runBlocking {
        val minArgs = mapOf(
            "duration_value" to Tainted.fromUserUtterance(SlotValueAst.IntValue(5)),
            "duration_unit" to Tainted.fromUserUtterance(SlotValueAst.StringValue("minutes"))
        )
        val minResult = composite.setTimerTool.execute(testContext(), minArgs)
        assertTrue(minResult is ToolResult.Success)
        assertEquals(300, fakeGateway.lastTimerSeconds)

        val hourArgs = mapOf(
            "duration_value" to Tainted.fromUserUtterance(SlotValueAst.IntValue(2)),
            "duration_unit" to Tainted.fromUserUtterance(SlotValueAst.StringValue("hr"))
        )
        val hourResult = composite.setTimerTool.execute(testContext(), hourArgs)
        assertTrue(hourResult is ToolResult.Success)
        assertEquals(7200, fakeGateway.lastTimerSeconds)
    }

    @Test
    fun setTimerRejectsNonPositiveOrInvalidUnits() = runBlocking {
        val nonPosArgs = mapOf(
            "duration_seconds" to Tainted.fromUserUtterance(SlotValueAst.IntValue(0))
        )
        val result1 = composite.setTimerTool.execute(testContext(), nonPosArgs)
        assertTrue(result1 is ToolResult.Failure)

        val badUnitArgs = mapOf(
            "duration_value" to Tainted.fromUserUtterance(SlotValueAst.IntValue(10)),
            "duration_unit" to Tainted.fromUserUtterance(SlotValueAst.StringValue("lightyears"))
        )
        val result2 = composite.setTimerTool.execute(testContext(), badUnitArgs)
        assertTrue(result2 is ToolResult.Failure)
    }

    @Test
    fun auditLogRedactsUserSuppliedAlarmAndTimerLabels() = runBlocking {
        fakeFirewall.outboundDecision = FirewallDecision.Authorized
        val alarmLabel = "CONFIDENTIAL_ALARM_LABEL"
        val alarmArgs = mapOf(
            "hour" to Tainted.fromUserUtterance(SlotValueAst.IntValue(7)),
            "minute" to Tainted.fromUserUtterance(SlotValueAst.IntValue(30)),
            "label" to Tainted.fromUserUtterance(SlotValueAst.StringValue(alarmLabel))
        )
        val alarmRes = composite.setAlarmTool.execute(testContext(), alarmArgs)
        assertTrue(alarmRes is ToolResult.Success)

        val alarmEntry = fakeAudit.records.lastOrNull { it.toolName == AutomationToolNames.SET_ALARM && it.decision == "SUCCESS" }
        assertNotNull(alarmEntry)
        assertFalse("Audit log must redact alarm label from actionSummary", alarmEntry!!.actionSummary.contains(alarmLabel))
        assertEquals("Set alarm for 07:30", alarmEntry.actionSummary)

        val timerLabel = "CONFIDENTIAL_TIMER_LABEL"
        val timerArgs = mapOf(
            "duration_seconds" to Tainted.fromUserUtterance(SlotValueAst.IntValue(300)),
            "label" to Tainted.fromUserUtterance(SlotValueAst.StringValue(timerLabel))
        )
        val timerRes = composite.setTimerTool.execute(testContext(), timerArgs)
        assertTrue(timerRes is ToolResult.Success)

        val timerEntry = fakeAudit.records.lastOrNull { it.toolName == AutomationToolNames.SET_TIMER && it.decision == "SUCCESS" }
        assertNotNull(timerEntry)
        assertFalse("Audit log must redact timer label from actionSummary", timerEntry!!.actionSummary.contains(timerLabel))
        assertEquals("Set timer for 300s", timerEntry.actionSummary)
    }
}

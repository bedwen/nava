package com.nava.feature.automations.reminder

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.automation.CapturedNotification
import com.nava.domain.automation.MorningBriefingConfig
import com.nava.domain.automation.ReminderRecurrence
import com.nava.domain.automation.ReminderSchedulerPort
import com.nava.domain.automation.ReminderStatus
import com.nava.domain.automation.ScheduledReminder
import com.nava.domain.automation.ScheduledReminderPort
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.PermissionEvaluatorPort
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.PermissionProfilePreset
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleGrantPort
import com.nava.domain.security.RuleTriggerSpec
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolRegistry
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageKey
import com.nava.feature.automations.briefing.DailyBriefingBuilder
import com.nava.feature.automations.briefing.DailyBriefingTool
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.ToolTargetIds
import com.nava.feature.automations.notification.InMemoryNotificationInbox
import com.nava.feature.automations.notification.NotificationSummaryTool
import com.nava.feature.automations.routine.ProposeRoutineTool
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PhaseARemindersAndBriefingTest {

    private class FakeReminderPort : ScheduledReminderPort {
        val items = LinkedHashMap<String, ScheduledReminder>()
        override suspend fun saveReminder(reminder: ScheduledReminder) {
            items[reminder.reminderId] = reminder
        }

        override suspend fun findReminder(reminderId: String): ScheduledReminder? = items[reminderId]
        override suspend fun listActiveReminders(): List<ScheduledReminder> =
            items.values.filter { it.status == ReminderStatus.ACTIVE }.sortedBy { it.triggerAtEpochMs }

        override suspend fun listAllReminders(): List<ScheduledReminder> =
            items.values.sortedBy { it.triggerAtEpochMs }

        override suspend fun updateStatus(reminderId: String, status: ReminderStatus, updatedAtEpochMs: Long): Boolean {
            val existing = items[reminderId] ?: return false
            items[reminderId] = existing.copy(status = status, updatedAtEpochMs = updatedAtEpochMs)
            return true
        }

        override suspend fun deleteReminder(reminderId: String): Boolean = items.remove(reminderId) != null
    }

    private class FakeSchedulerPort : ReminderSchedulerPort {
        val scheduledIds = mutableListOf<String>()
        val cancelledIds = mutableListOf<String>()
        override fun scheduleReminder(reminder: ScheduledReminder): Boolean {
            scheduledIds.add(reminder.reminderId)
            return true
        }

        override fun cancelReminder(reminderId: String) {
            cancelledIds.add(reminderId)
        }

        override fun scheduleMorningBriefing(hour: Int, minute: Int, nowEpochMs: Long): Long =
            nowEpochMs + 3_600_000L

        override fun cancelMorningBriefing() = Unit
    }

    private class FakeAuditLog : AuditLogPort {
        val entries = mutableListOf<AuditLogEntry>()
        override suspend fun record(entry: AuditLogEntry) {
            entries.add(entry)
        }

        override suspend fun queryRecent(limit: Int): List<AuditLogEntry> = entries.takeLast(limit)
    }

    private class FakePermissionEvaluator(
        private val allowedPackages: Set<String> = emptySet()
    ) : PermissionEvaluatorPort {
        override suspend fun getProfileForTarget(targetId: String): PermissionProfile =
            if (targetId in allowedPackages) PermissionProfile.notificationSummaryOnly() else PermissionProfile.defaultDeny()

        override suspend fun evaluateCapability(targetId: String, capability: AtomicCapability): ConfirmationLevel =
            when {
                targetId in allowedPackages && capability == AtomicCapability.NOTIFICATION_READ -> ConfirmationLevel.AUTO
                (targetId == ToolTargetIds.CLOCK || targetId == ToolTargetIds.REMINDERS) && capability == AtomicCapability.DATA_READ -> ConfirmationLevel.AUTO
                else -> ConfirmationLevel.DISABLED
            }

        override suspend fun listProfiles(): List<PermissionProfile> =
            if (allowedPackages.isEmpty()) {
                listOf(PermissionProfile.defaultDeny())
            } else {
                listOf(
                    PermissionProfile.notificationSummaryOnly().copy(assignedTargets = allowedPackages)
                )
            }

        override suspend fun saveProfile(profile: PermissionProfile) = Unit
        override suspend fun assignTargetToProfile(targetId: String, profileId: String) = Unit
        override suspend fun deleteProfile(profileId: String) = Unit
    }

    private class FakeRuleGrantPort : RuleGrantPort {
        val rules = LinkedHashMap<String, RuleCapabilityGrant>()
        override suspend fun createPendingRule(
            ruleId: String,
            triggerSpec: RuleTriggerSpec,
            staticActions: List<RuleActionSpec>,
            nowEpochSec: Long
        ): RuleCapabilityGrant {
            val grant = RuleCapabilityGrant(
                grantId = "grant_$ruleId",
                ruleId = ruleId,
                triggerSpec = triggerSpec,
                staticActions = staticActions,
                approvalState = RuleApprovalState.PENDING_USER_APPROVAL
            )
            rules[ruleId] = grant
            return grant
        }

        override suspend fun approveAndSealRule(ruleId: String, nowEpochSec: Long): RuleCapabilityGrant =
            error("Not used in proposal test")

        override suspend fun pauseRule(ruleId: String, nowEpochSec: Long) = Unit
        override suspend fun revokeRule(ruleId: String, nowEpochSec: Long) = Unit
        override suspend fun findRule(ruleId: String): RuleCapabilityGrant? = rules[ruleId]
        override suspend fun listRules(): List<RuleCapabilityGrant> = rules.values.toList()
    }

    private fun userContext(toolName: String, nowMs: Long = 1_700_000_000_000L): ToolExecutionContext {
        val token = CapabilityToken.mint(
            tokenId = "tok-1",
            requestId = "req-1",
            allowedTools = setOf(toolName),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = nowMs
        )
        return ToolExecutionContext(
            requestId = "req-1",
            capabilityToken = token,
            ruleGrant = null,
            targetId = ToolTargetIds.REMINDERS,
            languageTag = "en",
            issuedAtEpochMs = nowMs
        )
    }

    @Test
    fun scheduleAndCancelReminderPersistsAndSchedulesAlarm() = runBlocking {
        val nowMs = 1_700_000_000_000L
        val port = FakeReminderPort()
        val scheduler = FakeSchedulerPort()
        val audit = FakeAuditLog()

        val scheduleTool = ScheduleReminderTool(port, scheduler, audit, clock = { nowMs })
        val cancelTool = CancelReminderTool(port, scheduler, audit, clock = { nowMs + 1000L })

        val result = scheduleTool.execute(
            userContext(AutomationToolNames.SCHEDULE_REMINDER, nowMs),
            mapOf(
                "title" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Drink water"), SensitiveSlotKind.EVENT_TITLE),
                "delay_minutes" to Tainted.fromUserUtterance(SlotValueAst.IntValue(10), SensitiveSlotKind.DURATION),
                "recurrence" to Tainted.fromUserUtterance(SlotValueAst.StringValue("DAILY"), SensitiveSlotKind.TEXT_BODY)
            )
        )

        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals(MessageKey.ACTION_REMINDER_SCHEDULED, success.message.key)
        val reminderId = success.outputValues["reminder_id"]!!
        assertEquals(listOf(reminderId), scheduler.scheduledIds)

        val stored = port.findReminder(reminderId)
        assertNotNull(stored)
        assertEquals(nowMs + 600_000L, stored!!.triggerAtEpochMs)
        assertEquals(ReminderRecurrence.DAILY, stored.recurrence)

        val cancelResult = cancelTool.execute(
            userContext(AutomationToolNames.CANCEL_REMINDER, nowMs + 1000L),
            mapOf("title" to Tainted.fromUserUtterance(SlotValueAst.StringValue("water"), SensitiveSlotKind.EVENT_TITLE))
        )
        assertTrue(cancelResult is ToolResult.Success)
        assertEquals(MessageKey.ACTION_REMINDER_CANCELLED, (cancelResult as ToolResult.Success).message.key)
        assertEquals(listOf(reminderId), scheduler.cancelledIds)
        assertTrue(port.listActiveReminders().isEmpty())
    }

    @Test
    fun recurrenceMathAdvancesStrictlyPastNow() {
        val once = ScheduledReminder(
            reminderId = "r1",
            title = "Once",
            triggerAtEpochMs = 1000L,
            recurrence = ReminderRecurrence.ONCE
        )
        assertNull(once.nextOccurrenceEpochMs(2000L))

        val daily = ScheduledReminder(
            reminderId = "r2",
            title = "Daily",
            triggerAtEpochMs = 1000L,
            recurrence = ReminderRecurrence.DAILY
        )
        val nextDaily = daily.nextOccurrenceEpochMs(1000L + ScheduledReminder.MILLIS_PER_DAY + 50L)
        assertEquals(1000L + 2L * ScheduledReminder.MILLIS_PER_DAY, nextDaily)
    }

    @Test
    fun proposeRoutineCreatesPendingRuleNeverAutoApproved() = runBlocking {
        val rulePort = FakeRuleGrantPort()
        val audit = FakeAuditLog()
        val reminderPort = FakeReminderPort()
        val scheduler = FakeSchedulerPort()
        val scheduleTool = ScheduleReminderTool(reminderPort, scheduler, audit)
        val registry = ToolRegistry(listOf(scheduleTool))

        val proposeTool = ProposeRoutineTool(
            ruleGrantPort = rulePort,
            toolRegistryProvider = { registry },
            auditLog = audit,
            clock = { 1_700_000_000_000L }
        )

        val res = proposeTool.execute(
            userContext(AutomationToolNames.PROPOSE_ROUTINE),
            mapOf(
                "rule_name" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Night hydration"), SensitiveSlotKind.EVENT_TITLE),
                "trigger_type" to Tainted.fromUserUtterance(SlotValueAst.StringValue("TIME_OF_DAY"), SensitiveSlotKind.TEXT_BODY),
                "trigger_time" to Tainted.fromUserUtterance(SlotValueAst.StringValue("22:30"), SensitiveSlotKind.DATE_TIME),
                "action_tool" to Tainted.fromUserUtterance(SlotValueAst.StringValue("schedule_reminder"), SensitiveSlotKind.INTENT_ACTION)
            )
        )

        assertTrue(res is ToolResult.Success)
        val success = res as ToolResult.Success
        assertEquals(MessageKey.RULE_PENDING_APPROVAL, success.message.key)
        val created = rulePort.findRule("night_hydration")
        assertNotNull(created)
        assertEquals(RuleApprovalState.PENDING_USER_APPROVAL, created!!.approvalState)
        assertFalse(created.canExecuteUnattended())
    }

    private fun routineArgs(actionTool: String, actionArgs: String? = null) = buildMap {
        put("rule_name", Tainted.fromUserUtterance<SlotValueAst>(SlotValueAst.StringValue("Evening"), SensitiveSlotKind.EVENT_TITLE))
        put("trigger_type", Tainted.fromUserUtterance<SlotValueAst>(SlotValueAst.StringValue("TIME_OF_DAY"), SensitiveSlotKind.TEXT_BODY))
        put("trigger_time", Tainted.fromUserUtterance<SlotValueAst>(SlotValueAst.StringValue("22:00"), SensitiveSlotKind.DATE_TIME))
        put("action_tool", Tainted.fromUserUtterance<SlotValueAst>(SlotValueAst.StringValue(actionTool), SensitiveSlotKind.INTENT_ACTION))
        if (actionArgs != null) {
            put("action_args", Tainted.fromUserUtterance<SlotValueAst>(SlotValueAst.StringValue(actionArgs), SensitiveSlotKind.TEXT_BODY))
        }
    }

    @Test
    fun proposeRoutineSupportsMultiStepActionsInOrder() = runBlocking {
        val rulePort = FakeRuleGrantPort()
        val audit = FakeAuditLog()
        val scheduleTool = ScheduleReminderTool(FakeReminderPort(), FakeSchedulerPort(), audit)
        val registry = ToolRegistry(listOf(scheduleTool, ProposeRoutineTool(rulePort, { ToolRegistry(emptyList()) }, audit)))
        val proposeTool = ProposeRoutineTool(rulePort, { registry }, audit, clock = { 1_700_000_000_000L })
        val ctx = userContext(AutomationToolNames.PROPOSE_ROUTINE)

        val ok = proposeTool.execute(
            ctx,
            routineArgs("schedule_reminder, schedule_reminder", "title=Water;delay_minutes=5|title=Sleep;delay_minutes=30")
        )
        assertTrue(ok is ToolResult.Success)
        val actions = rulePort.findRule("evening")!!.staticActions
        assertEquals(2, actions.size)
        assertEquals("Water", actions[0].staticArguments["title"])
        assertEquals("Sleep", actions[1].staticArguments["title"])
        assertEquals(RuleApprovalState.PENDING_USER_APPROVAL, rulePort.findRule("evening")!!.approvalState)

        // Too many actions, a routine that proposes routines, and unknown tools are all refused.
        assertTrue(proposeTool.execute(ctx, routineArgs("schedule_reminder,schedule_reminder,schedule_reminder,schedule_reminder")) is ToolResult.Failure)
        assertTrue(proposeTool.execute(ctx, routineArgs("schedule_reminder,propose_routine")) is ToolResult.Failure)
        assertTrue(proposeTool.execute(ctx, routineArgs("schedule_reminder,wipe_device")) is ToolResult.Failure)
        assertTrue(proposeTool.execute(ctx, routineArgs("schedule_reminder,schedule_reminder", "a=1|b=2|c=3")) is ToolResult.Failure)
    }

    @Test
    fun proposeRoutineMergesSplitCallsIntoOnePendingDraft() = runBlocking {
        val rulePort = FakeRuleGrantPort()
        val audit = FakeAuditLog()
        val registry = ToolRegistry(
            listOf(
                ScheduleReminderTool(FakeReminderPort(), FakeSchedulerPort(), audit),
                CancelReminderTool(FakeReminderPort(), FakeSchedulerPort(), audit)
            )
        )
        var now = 1_700_000_000_000L
        val proposeTool = ProposeRoutineTool(rulePort, { registry }, audit, clock = { now })
        val ctx = userContext(AutomationToolNames.PROPOSE_ROUTINE)

        assertTrue(proposeTool.execute(ctx, routineArgs("schedule_reminder", "title=Water;delay_minutes=5")) is ToolResult.Success)
        now += 1_000L
        assertTrue(proposeTool.execute(ctx, routineArgs("cancel_reminder", "reminder_id=r1")) is ToolResult.Success)
        assertEquals(
            listOf("schedule_reminder", "cancel_reminder"),
            rulePort.findRule("evening")!!.staticActions.map { it.toolName }
        )

        // Outside the merge window the routine is replaced, not extended.
        now += 120_000L
        assertTrue(proposeTool.execute(ctx, routineArgs("schedule_reminder", "title=Tea;delay_minutes=5")) is ToolResult.Success)
        assertEquals(listOf("schedule_reminder"), rulePort.findRule("evening")!!.staticActions.map { it.toolName })
    }

    @Test
    fun proposeRoutineNormalizesSmallModelSpellings() = runBlocking {
        val rulePort = FakeRuleGrantPort()
        val audit = FakeAuditLog()
        val registry = ToolRegistry(listOf(ScheduleReminderTool(FakeReminderPort(), FakeSchedulerPort(), audit)))
        val proposeTool = ProposeRoutineTool(rulePort, { registry }, audit, clock = { 1_700_000_000_000L })
        val args = routineArgs("schedule_reminder", "{\"title\":\"Water\", \"delay_minutes\":5, \"note\":null}").toMutableMap()
        args["trigger_type"] = Tainted.fromUserUtterance<SlotValueAst>(SlotValueAst.StringValue("time"), SensitiveSlotKind.TEXT_BODY)
        args["trigger_time"] = Tainted.fromUserUtterance<SlotValueAst>(SlotValueAst.StringValue("22"), SensitiveSlotKind.DATE_TIME)

        assertTrue(proposeTool.execute(userContext(AutomationToolNames.PROPOSE_ROUTINE), args) is ToolResult.Success)
        val rule = rulePort.findRule("evening")!!
        assertEquals("TIME_OF_DAY", rule.triggerSpec.triggerType)
        assertEquals("22:00", rule.triggerSpec.parameters["time"])
        assertEquals(mapOf("title" to "Water", "delay_minutes" to "5"), rule.staticActions.single().staticArguments)
    }

    @Test
    fun notificationSummaryDifferentiatesNoPermittedAppsAndGroupsUrgency() = runBlocking {
        val inbox = InMemoryNotificationInbox()
        val audit = FakeAuditLog()

        // Case 1: Zero apps permitted -> INFO_NO_PERMITTED_NOTIFICATION_APPS
        val toolNoPerms = NotificationSummaryTool(inbox, FakePermissionEvaluator(emptySet()), audit)
        val emptyNoPerms = toolNoPerms.execute(userContext(AutomationToolNames.SUMMARIZE_NOTIFICATIONS), emptyMap())
        assertTrue(emptyNoPerms is ToolResult.Success)
        assertEquals(MessageKey.INFO_NO_PERMITTED_NOTIFICATION_APPS, (emptyNoPerms as ToolResult.Success).message.key)

        // Case 2: Permitted app exists, but 0 notifications -> ACTION_NOTIFICATIONS_EMPTY
        val evaluatorWithApp = FakePermissionEvaluator(setOf("com.example.chat"))
        val toolWithPerms = NotificationSummaryTool(inbox, evaluatorWithApp, audit)
        val emptyWithPerms = toolWithPerms.execute(userContext(AutomationToolNames.SUMMARIZE_NOTIFICATIONS), emptyMap())
        assertEquals(MessageKey.ACTION_NOTIFICATIONS_EMPTY, (emptyWithPerms as ToolResult.Success).message.key)

        // Case 3: Permitted notifications grouped by urgency, strictly UNTRUSTED_EXTERNAL
        inbox.ingest(
            CapturedNotification(
                notificationKey = "n1",
                packageName = "com.example.chat",
                title = Tainted.fromUntrustedExternal("Bank OTP", SensitiveSlotKind.EVENT_TITLE, "notif:com.example.chat"),
                body = Tainted.fromUntrustedExternal("Your verification code is 482910", SensitiveSlotKind.TEXT_BODY, "notif:com.example.chat"),
                postedAtEpochMs = 1_700_000_000_000L
            )
        )
        inbox.ingest(
            CapturedNotification(
                notificationKey = "n2",
                packageName = "com.example.chat",
                title = Tainted.fromUntrustedExternal("Flash Sale", SensitiveSlotKind.EVENT_TITLE, "notif:com.example.chat"),
                body = Tainted.fromUntrustedExternal("50% discount promo today", SensitiveSlotKind.TEXT_BODY, "notif:com.example.chat"),
                postedAtEpochMs = 1_700_000_000_100L
            )
        )

        val summarized = toolWithPerms.execute(userContext(AutomationToolNames.SUMMARIZE_NOTIFICATIONS), emptyMap()) as ToolResult.Success
        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, summarized.outputProvenance)
        val summaryText = summarized.outputValues["summary"].orEmpty()
        assertTrue(summaryText.contains("[URGENT]"))
        assertTrue(summaryText.contains("[NOISE]"))
    }

    @Test
    fun dailyBriefingCombinesRemindersAndPermittedNotificationsAsUntrusted() = runBlocking {
        val nowMs = 1_700_000_000_000L
        val remPort = FakeReminderPort()
        remPort.saveReminder(
            ScheduledReminder(
                reminderId = "r1",
                title = "Take vitamins",
                triggerAtEpochMs = nowMs + 3_600_000L
            )
        )
        val inbox = InMemoryNotificationInbox()
        inbox.ingest(
            CapturedNotification(
                notificationKey = "n1",
                packageName = "com.example.mail",
                title = Tainted.fromUntrustedExternal("Meeting alert", SensitiveSlotKind.EVENT_TITLE, "notif:com.example.mail"),
                body = Tainted.fromUntrustedExternal("Standup at 10:00", SensitiveSlotKind.TEXT_BODY, "notif:com.example.mail"),
                postedAtEpochMs = nowMs - 1000L
            )
        )
        val eval = FakePermissionEvaluator(setOf("com.example.mail"))
        val builder = DailyBriefingBuilder(remPort, inbox, eval)
        val tool = DailyBriefingTool(builder, FakeAuditLog(), clock = { nowMs })

        val result = tool.execute(userContext(AutomationToolNames.DAILY_BRIEFING, nowMs), emptyMap()) as ToolResult.Success
        assertEquals(MessageKey.ACTION_BRIEFING_READY, result.message.key)
        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, result.outputProvenance)
        assertTrue(result.outputValues["summary"].orEmpty().contains("Take vitamins"))
        assertTrue(result.outputValues["summary"].orEmpty().contains("Meeting alert"))
    }
}

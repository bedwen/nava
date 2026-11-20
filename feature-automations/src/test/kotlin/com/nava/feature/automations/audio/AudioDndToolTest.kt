package com.nava.feature.automations.audio

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageKey
import com.nava.feature.automations.common.AudioDndPlatformGateway
import com.nava.feature.automations.common.AudioStreamKind
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.DndFilterMode
import com.nava.feature.automations.common.PlatformDispatchResult
import com.nava.feature.automations.common.ToolTargetIds
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AudioDndToolTest {

    private class FakeAudioDndGateway : AudioDndPlatformGateway {
        var policyAccessGranted: Boolean = true
        var lastFilterMode: DndFilterMode? = null
        var lastStream: AudioStreamKind? = null
        var lastVolumePercent: Int? = null

        var filterResult: PlatformDispatchResult = PlatformDispatchResult.Dispatched()
        var volumeResult: PlatformDispatchResult = PlatformDispatchResult.Dispatched()

        override fun isNotificationPolicyAccessGranted(): Boolean = policyAccessGranted

        override fun setInterruptionFilter(mode: DndFilterMode): PlatformDispatchResult {
            lastFilterMode = mode
            return filterResult
        }

        override fun setStreamVolumePercent(stream: AudioStreamKind, percent: Int): PlatformDispatchResult {
            lastStream = stream
            lastVolumePercent = percent
            return volumeResult
        }

        override fun getStreamVolumePercent(stream: AudioStreamKind): Int = 50
    }

    private class FakeAuditLog : AuditLogPort {
        val records = mutableListOf<AuditLogEntry>()

        override suspend fun record(entry: AuditLogEntry) {
            records.add(entry)
        }

        override suspend fun queryRecent(limit: Int): List<AuditLogEntry> = records.takeLast(limit)
    }

    private val fakeGateway = FakeAudioDndGateway()
    private val fakeAudit = FakeAuditLog()
    private var simulatedTime: Long = 1_000_000L

    private val composite = AudioDndTool(
        audioDndGateway = fakeGateway,
        auditLog = fakeAudit,
        clock = { simulatedTime }
    )

    private fun testContext(): ToolExecutionContext = ToolExecutionContext(
        requestId = "req-audio-1",
        capabilityToken = CapabilityToken.mint(
            tokenId = "tok-audio-1",
            requestId = "req-audio-1",
            allowedTools = setOf(AutomationToolNames.SET_DND, AutomationToolNames.SET_VOLUME),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = simulatedTime
        ),
        ruleGrant = null,
        targetId = ToolTargetIds.AUDIO_DND,
        languageTag = "en",
        issuedAtEpochMs = simulatedTime,
        isUnattendedBackground = false
    )

    @Test
    fun compositeExposesBothToolsWithCorrectCategory() {
        val tools = composite.allTools()
        assertEquals(2, tools.size)
        assertEquals(AutomationToolNames.SET_DND, tools[0].metadata.name)
        assertEquals(AutomationToolNames.SET_VOLUME, tools[1].metadata.name)

        for (tool in composite) {
            assertTrue(tool.metadata.supportsUnattendedRule)
            assertEquals(com.nava.domain.tool.ToolCategory.DEVICE_SETTINGS, tool.metadata.category)
        }
    }

    @Test
    fun setDndFailsWhenNotificationPolicyAccessIsMissing() = runBlocking {
        fakeGateway.policyAccessGranted = false
        val args = mapOf("enabled" to Tainted.fromUserUtterance(SlotValueAst.BooleanValue(true)))

        val result = composite.setDndTool.execute(testContext(), args)
        assertTrue(result is ToolResult.Failure)
        val failure = result as ToolResult.Failure
        assertEquals(MessageKey.ERROR_SYSTEM_PERMISSION_MISSING, failure.message.key)
        assertEquals(1, fakeAudit.records.size)
        assertEquals(ToolTargetIds.AUDIO_DND, fakeAudit.records.first().targetId)
    }

    @Test
    fun setDndEnablesPriorityModeByDefault() = runBlocking {
        fakeGateway.policyAccessGranted = true
        val args = mapOf("enabled" to Tainted.fromUserUtterance(SlotValueAst.BooleanValue(true)))

        val result = composite.setDndTool.execute(testContext(), args)
        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals(MessageKey.ACTION_DND_UPDATED, success.message.key)
        assertEquals(DndFilterMode.PRIORITY, fakeGateway.lastFilterMode)
    }

    @Test
    fun setDndSetsSpecificFilterModes() = runBlocking {
        fakeGateway.policyAccessGranted = true
        val args = mapOf(
            "enabled" to Tainted.fromUserUtterance(SlotValueAst.BooleanValue(true)),
            "mode" to Tainted.fromUserUtterance(SlotValueAst.StringValue("alarms"))
        )
        val result = composite.setDndTool.execute(testContext(), args)
        assertTrue(result is ToolResult.Success)
        assertEquals(DndFilterMode.ALARMS_ONLY, fakeGateway.lastFilterMode)

        val disableArgs = mapOf("enabled" to Tainted.fromUserUtterance(SlotValueAst.BooleanValue(false)))
        val disableResult = composite.setDndTool.execute(testContext(), disableArgs)
        assertTrue(disableResult is ToolResult.Success)
        assertEquals(DndFilterMode.ALL, fakeGateway.lastFilterMode)
    }

    @Test
    fun setDndRejectsVaultTaintAndInvalidModes() = runBlocking {
        fakeGateway.policyAccessGranted = true
        val vaultArgs = mapOf(
            "enabled" to Tainted.fromUntrustedExternal(
                SlotValueAst.BooleanValue(true),
                SensitiveSlotKind.TEXT_BODY,
                sourceLabel = "vault:secret"
            )
        )
        val vaultResult = composite.setDndTool.execute(testContext(), vaultArgs)
        assertTrue(vaultResult is ToolResult.Failure)
        assertTrue((vaultResult as ToolResult.Failure).isSecurityViolation)

        val badModeArgs = mapOf(
            "enabled" to Tainted.fromUserUtterance(SlotValueAst.BooleanValue(true)),
            "mode" to Tainted.fromUserUtterance(SlotValueAst.StringValue("super_silent"))
        )
        val badModeResult = composite.setDndTool.execute(testContext(), badModeArgs)
        assertTrue(badModeResult is ToolResult.Failure)
    }

    @Test
    fun setVolumeDispatchesSuccessfullyWithoutNotificationPolicyAccess() = runBlocking {
        fakeGateway.policyAccessGranted = false
        val args = mapOf(
            "level" to Tainted.fromUserUtterance(SlotValueAst.IntValue(75)),
            "stream" to Tainted.fromUserUtterance(SlotValueAst.StringValue("media"))
        )

        val result = composite.setVolumeTool.execute(testContext(), args)
        assertTrue(result is ToolResult.Success)
        val success = result as ToolResult.Success
        assertEquals(MessageKey.ACTION_VOLUME_UPDATED, success.message.key)
        assertEquals(AudioStreamKind.MEDIA, fakeGateway.lastStream)
        assertEquals(75, fakeGateway.lastVolumePercent)
    }

    @Test
    fun setVolumeSupportsAllStreamKinds() = runBlocking {
        val streamMap = mapOf(
            "ring" to AudioStreamKind.RING,
            "alarm" to AudioStreamKind.ALARM,
            "notification" to AudioStreamKind.NOTIFICATION,
            "system" to AudioStreamKind.SYSTEM
        )

        for ((streamName, expectedKind) in streamMap) {
            val args = mapOf(
                "level" to Tainted.fromUserUtterance(SlotValueAst.IntValue(40)),
                "stream" to Tainted.fromUserUtterance(SlotValueAst.StringValue(streamName))
            )
            val result = composite.setVolumeTool.execute(testContext(), args)
            assertTrue(result is ToolResult.Success)
            assertEquals(expectedKind, fakeGateway.lastStream)
            assertEquals(40, fakeGateway.lastVolumePercent)
        }
    }

    @Test
    fun setVolumeRejectsOutOfBoundsLevelsAndVaultTaint() = runBlocking {
        val lowArgs = mapOf("level" to Tainted.fromUserUtterance(SlotValueAst.IntValue(-5)))
        val lowResult = composite.setVolumeTool.execute(testContext(), lowArgs)
        assertTrue(lowResult is ToolResult.Failure)

        val highArgs = mapOf("level" to Tainted.fromUserUtterance(SlotValueAst.IntValue(105)))
        val highResult = composite.setVolumeTool.execute(testContext(), highArgs)
        assertTrue(highResult is ToolResult.Failure)

        val vaultArgs = mapOf(
            "level" to Tainted.fromUntrustedExternal(
                SlotValueAst.IntValue(50),
                SensitiveSlotKind.TEXT_BODY,
                sourceLabel = "vault:vol"
            )
        )
        val vaultResult = composite.setVolumeTool.execute(testContext(), vaultArgs)
        assertTrue(vaultResult is ToolResult.Failure)
        assertTrue((vaultResult as ToolResult.Failure).isSecurityViolation)
    }
}

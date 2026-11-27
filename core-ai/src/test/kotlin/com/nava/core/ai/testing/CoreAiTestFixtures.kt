package com.nava.core.ai.testing

import com.nava.core.ai.engine.LiteRtRuntimeAdapter
import com.nava.core.ai.engine.RuntimeStreamDelta
import com.nava.core.ai.engine.RuntimeTurnConfig
import com.nava.core.ai.lifecycle.DeviceHardwareSnapshot
import com.nava.core.ai.lifecycle.DeviceHardwareStatusProvider
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.core.ai.provisioning.StorageSpaceProvider
import com.nava.domain.ai.ActionCachePort
import com.nava.domain.ai.CachedActionTemplate
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.SecurityFirewallPort
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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import java.io.File
import java.util.concurrent.atomic.AtomicInteger

class FakeSecurityFirewallPort : SecurityFirewallPort {
    private val tokenCounter = AtomicInteger(0)
    val mintedTokens: MutableList<CapabilityToken> = mutableListOf()

    override suspend fun mintToken(
        requestId: String,
        utteranceProvenance: DataProvenance,
        candidateTools: Set<String>,
        nowEpochMs: Long,
        maxToolCalls: Int
    ): CapabilityToken {
        val tokenId = "tok_${tokenCounter.incrementAndGet()}"
        val token = CapabilityToken.mint(
            tokenId = tokenId,
            requestId = requestId,
            allowedTools = candidateTools,
            mintProvenance = utteranceProvenance,
            issuedAtEpochMs = nowEpochMs
        )
        mintedTokens.add(token)
        return token
    }

    override suspend fun authorizeToolCall(
        token: CapabilityToken,
        toolCall: ToolCallAst,
        toolMetadata: ToolMetadata,
        targetId: String,
        nowEpochMs: Long
    ): FirewallDecision = FirewallDecision.Authorized

    override suspend fun authorizeRuleExecution(grant: RuleCapabilityGrant): FirewallDecision =
        FirewallDecision.Authorized

    override suspend fun validateOutboundTarget(
        toolName: String,
        action: String,
        uriOrTarget: Tainted<String>
    ): FirewallDecision = FirewallDecision.Authorized
}

class InMemoryActionCachePort : ActionCachePort {
    private val entries = LinkedHashMap<String, CachedActionTemplate>()
    var putCalls: Int = 0
        private set
    var invalidationCalls: Int = 0
        private set

    override suspend fun putTemplate(
        template: CachedActionTemplate,
        provenance: DataProvenance,
        touchesVault: Boolean,
        nowEpochSec: Long
    ): Boolean {
        putCalls++
        if (provenance != DataProvenance.USER_UTTERANCE || touchesVault) {
            return false
        }
        val key = compositeKey(template.languageCode, template.canonicalSkeleton)
        entries[key] = template.copy(lastUsedEpochSec = nowEpochSec)
        return true
    }

    override suspend fun findTemplate(
        languageCode: String,
        canonicalSkeleton: String,
        nowEpochSec: Long
    ): CachedActionTemplate? {
        val key = compositeKey(languageCode, canonicalSkeleton)
        val existing = entries[key] ?: return null
        val updated = existing.copy(lastUsedEpochSec = nowEpochSec)
        entries[key] = updated
        return updated
    }

    override suspend fun invalidateForToolSchemaChange(
        toolName: String,
        currentSchemaVersion: Int
    ): Int {
        invalidationCalls++
        val iterator = entries.entries.iterator()
        var removed = 0
        while (iterator.hasNext()) {
            val tpl = iterator.next().value
            if (toolName in tpl.toolNames && tpl.toolSchemaVersions[toolName] != currentSchemaVersion) {
                iterator.remove()
                removed++
            }
        }
        return removed
    }

    override suspend fun invalidateAll(): Int {
        val count = entries.size
        entries.clear()
        return count
    }

    fun size(): Int = entries.size

    private fun compositeKey(languageCode: String, canonicalSkeleton: String): String {
        return "$languageCode\u0000$canonicalSkeleton"
    }
}

class FakeLiteRtRuntimeAdapter : LiteRtRuntimeAdapter {
    data class EnsurePrefixCall(
        val modelPath: String,
        val systemPrefixId: String,
        val systemPrompt: String,
        val maxNumTokens: Int
    )

    data class ClonedTurnCall(
        val systemPrefixId: String,
        val config: RuntimeTurnConfig
    )

    private var loaded: Boolean = false
    val ensurePrefixCalls: MutableList<EnsurePrefixCall> = mutableListOf()
    val clonedTurnCalls: MutableList<ClonedTurnCall> = mutableListOf()
    var unloadCalls: Int = 0
        private set

    private val scriptedDeltas = ArrayDeque<List<RuntimeStreamDelta>>()
    var turnResponder: ((String, RuntimeTurnConfig) -> List<RuntimeStreamDelta>)? = null

    fun enqueueDeltas(deltas: List<RuntimeStreamDelta>) {
        scriptedDeltas.addLast(deltas)
    }

    override fun isLoaded(): Boolean = loaded

    override suspend fun ensureMasterPrefix(
        modelPath: String,
        systemPrefixId: String,
        systemPrompt: String,
        maxNumTokens: Int
    ) {
        loaded = true
        ensurePrefixCalls.add(
            EnsurePrefixCall(
                modelPath = modelPath,
                systemPrefixId = systemPrefixId,
                systemPrompt = systemPrompt,
                maxNumTokens = maxNumTokens
            )
        )
    }

    override fun runClonedTurn(
        systemPrefixId: String,
        config: RuntimeTurnConfig
    ): Flow<RuntimeStreamDelta> = flow {
        clonedTurnCalls.add(ClonedTurnCall(systemPrefixId = systemPrefixId, config = config))
        val deltas = when {
            scriptedDeltas.isNotEmpty() -> scriptedDeltas.removeFirst()
            turnResponder != null -> turnResponder!!.invoke(systemPrefixId, config)
            else -> emptyList()
        }
        for (delta in deltas) {
            emit(delta)
        }
    }

    override suspend fun unload() {
        loaded = false
        unloadCalls++
    }
}

class FakeHardwareStatusProvider(
    var snapshot: DeviceHardwareSnapshot = DeviceHardwareSnapshot(
        totalRamBytes = 8L * 1024L * 1024L * 1024L,
        thermalStatusCode = ThermalModelLifecycleManager.THERMAL_STATUS_NONE,
        batteryLevelPercent = 85
    )
) : DeviceHardwareStatusProvider {
    override fun readSnapshot(): DeviceHardwareSnapshot = snapshot
}

class FakeStorageSpaceProvider(
    var availableBytesValue: Long = 16L * 1024L * 1024L * 1024L
) : StorageSpaceProvider {
    override fun availableBytes(directory: File): Long = availableBytesValue
}

class FakeNavaTool(
    override val metadata: ToolMetadata
) : NavaTool {
    override suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult {
        return ToolResult.Success(message = UserMessage(MessageKey.ACTION_ALARM_SET))
    }
}

object CoreAiTestFixtures {
    val SET_ALARM_TOOL: ToolMetadata = ToolMetadata(
        name = "set_alarm",
        displayNameKey = "tool_set_alarm",
        description = "Set a clock alarm at an exact time with optional label",
        category = ToolCategory.TIME_CALENDAR,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "time",
                description = "Canonical 24-hour alarm time HH:MM",
                required = true,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.ISO_TIME
            ),
            ToolSchemaField(
                name = "label",
                description = "Optional alarm label",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            )
        )
    )

    val SET_TIMER_TOOL: ToolMetadata = ToolMetadata(
        name = "set_timer",
        displayNameKey = "tool_set_timer",
        description = "Start a countdown timer for a duration in seconds",
        category = ToolCategory.TIME_CALENDAR,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "duration_seconds",
                description = "Timer duration in integer seconds",
                required = true,
                slotKind = SensitiveSlotKind.DURATION,
                valueType = SlotValueType.DURATION_SECONDS
            ),
            ToolSchemaField(
                name = "label",
                description = "Optional timer label",
                required = false,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            )
        )
    )

    val SET_DND_TOOL: ToolMetadata = ToolMetadata(
        name = "set_dnd",
        displayNameKey = "tool_set_dnd",
        description = "Enable or disable Do Not Disturb mode",
        category = ToolCategory.DEVICE_SETTINGS,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "enabled",
                description = "Whether DND is enabled",
                required = true,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.BOOLEAN
            )
        )
    )

    val SET_VOLUME_TOOL: ToolMetadata = ToolMetadata(
        name = "set_volume",
        displayNameKey = "tool_set_volume",
        description = "Adjust media or system volume percentage between 0 and 100",
        category = ToolCategory.DEVICE_SETTINGS,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "level",
                description = "Volume level integer 0 to 100",
                required = true,
                slotKind = SensitiveSlotKind.DURATION,
                valueType = SlotValueType.INTEGER
            )
        )
    )

    val LAUNCH_APP_TOOL: ToolMetadata = ToolMetadata(
        name = "launch_app",
        displayNameKey = "tool_launch_app",
        description = "Launch an installed Android application by name",
        category = ToolCategory.DEVICE_SETTINGS,
        requiredCapability = AtomicCapability.APP_LAUNCH,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "app_name",
                description = "Target application name or package",
                required = true,
                slotKind = SensitiveSlotKind.PACKAGE_NAME,
                valueType = SlotValueType.STRING
            )
        )
    )

    val CREATE_CALENDAR_EVENT_TOOL: ToolMetadata = ToolMetadata(
        name = "create_calendar_event",
        displayNameKey = "tool_create_calendar_event",
        description = "Create a calendar event on a date and time with title",
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
                name = "date",
                description = "Event date YYYY-MM-DD",
                required = true,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.ISO_DATE
            ),
            ToolSchemaField(
                name = "time",
                description = "Optional start time HH:MM",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.ISO_TIME
            )
        )
    )

    val CREATE_SMS_DRAFT_TOOL: ToolMetadata = ToolMetadata(
        name = "create_sms_draft",
        displayNameKey = "tool_create_sms_draft",
        description = "Prepare an SMS message draft for a recipient phone number",
        category = ToolCategory.COMMUNICATION,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "recipient",
                description = "Recipient phone number or contact",
                required = true,
                slotKind = SensitiveSlotKind.PHONE_NUMBER,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "body",
                description = "SMS draft message text",
                required = true,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            )
        )
    )

    val SAVE_NOTE_TOOL: ToolMetadata = ToolMetadata(
        name = "save_note",
        displayNameKey = "tool_save_note",
        description = "Save a local note with title and text body",
        category = ToolCategory.NOTES_FILES,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "title",
                description = "Note title",
                required = true,
                slotKind = SensitiveSlotKind.EVENT_TITLE,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "body",
                description = "Note body content",
                required = true,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            )
        )
    )

    fun canonicalTools(): List<ToolMetadata> = listOf(
        SET_ALARM_TOOL,
        SET_TIMER_TOOL,
        SET_DND_TOOL,
        SET_VOLUME_TOOL,
        LAUNCH_APP_TOOL,
        CREATE_CALENDAR_EVENT_TOOL,
        CREATE_SMS_DRAFT_TOOL,
        SAVE_NOTE_TOOL
    )

    fun canonicalToolsByName(): Map<String, ToolMetadata> =
        canonicalTools().associateBy { it.name }

    fun canonicalToolRegistry(
        tools: List<ToolMetadata> = canonicalTools()
    ): ToolRegistry {
        return ToolRegistry(tools.map { FakeNavaTool(it) })
    }

    fun resolveAssetsDir(): File {
        val candidates = listOf(
            File("src/main/assets"),
            File("core-ai/src/main/assets"),
            File("../core-ai/src/main/assets")
        )
        return candidates.firstOrNull { it.exists() && it.isDirectory }
            ?: error("Could not locate core-ai/src/main/assets from ${File(".").absolutePath}")
    }

    fun resolveTestResourcesDir(): File {
        val candidates = listOf(
            File("src/test/resources"),
            File("core-ai/src/test/resources"),
            File("../core-ai/src/test/resources")
        )
        return candidates.firstOrNull { it.exists() && it.isDirectory }
            ?: error("Could not locate core-ai/src/test/resources from ${File(".").absolutePath}")
    }
}

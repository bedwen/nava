package com.nava.feature.automations.routine

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleGrantPort
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
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.ToolArgumentReader
import com.nava.feature.automations.common.ToolTargetIds
import java.util.Locale

/**
 * [NavaTool] adapter that compiles a natural-language routine request into a
 * [com.nava.domain.security.RuleApprovalState.PENDING_USER_APPROVAL] draft via [RuleGrantPort].
 *
 * Security invariants (PLAN.md Section 5.6 & Iron Laws 5-6):
 * - NEVER activates or seals a routine automatically; every proposed routine enters
 *   `PENDING_USER_APPROVAL` and requires explicit 1-tap user approval in Routine Studio.
 * - Rejects unknown tools and forbids unattended Vault actions.
 * - Records every proposal in [AuditLogPort].
 */
class ProposeRoutineTool(
    private val ruleGrantPort: RuleGrantPort,
    private val toolRegistryProvider: () -> ToolRegistry,
    private val auditLog: AuditLogPort,
    private val clock: () -> Long = System::currentTimeMillis
) : NavaTool {

    override val metadata: ToolMetadata = ToolMetadata(
        name = AutomationToolNames.PROPOSE_ROUTINE,
        displayNameKey = "tool_propose_routine_name",
        description = "Drafts a Trigger -> Action automation routine for explicit user approval. Example: " +
            "rule_name=Evening, trigger_type=TIME_OF_DAY, trigger_time=22:00, " +
            "action_tool=set_dnd,set_volume, action_args=enabled=true|level=20",
        category = ToolCategory.AUTOMATION_RULES,
        requiredCapability = AtomicCapability.CREATE_DRAFT,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "rule_name",
                description = "Short descriptive name or identifier for the routine",
                required = true,
                slotKind = SensitiveSlotKind.EVENT_TITLE,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "trigger_type",
                description = "Trigger type: TIME_OF_DAY, CHARGING, BOOT, or MANUAL",
                required = true,
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "trigger_time",
                description = "Optional HH:MM local time for TIME_OF_DAY triggers",
                required = false,
                slotKind = SensitiveSlotKind.DATE_TIME,
                valueType = SlotValueType.ISO_TIME
            ),
            ToolSchemaField(
                name = "action_tool",
                description = "Nava tool to run when triggered; up to 3 comma-separated tools run in order (e.g. set_dnd,set_volume)",
                required = true,
                // A Nava tool name, not an Android intent action: it is validated against the
                // ToolRegistry here, and the outbound intent allowlist would reject every tool.
                slotKind = SensitiveSlotKind.TEXT_BODY,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "action_args",
                description = "Optional key=value;key=value static arguments; separate each tool's group with | in tool order (e.g. enabled=true|level=20)",
                required = false,
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
        if (ToolArgumentReader.worstProvenance(arguments) != DataProvenance.USER_UTTERANCE) {
            return ToolArgumentReader.securityFailure("UNTRUSTED_ROUTINE_PROPOSAL")
        }

        val rawName = ToolArgumentReader.getString(arguments, "rule_name")?.value
            ?: return ToolArgumentReader.invalidArgumentsFailure("rule_name is required")
        val triggerTypeRaw = ToolArgumentReader.getString(arguments, "trigger_type")?.value
            ?: return ToolArgumentReader.invalidArgumentsFailure("trigger_type is required")
        val actionToolRaw = ToolArgumentReader.getString(arguments, "action_tool")?.value
            ?: return ToolArgumentReader.invalidArgumentsFailure("action_tool is required")
        val triggerTimeRaw = ToolArgumentReader.getString(arguments, "trigger_time")?.value
        val actionArgsRaw = ToolArgumentReader.getString(arguments, "action_args")?.value

        val rawFieldsToCheck = listOfNotNull(rawName, triggerTypeRaw, actionToolRaw, triggerTimeRaw, actionArgsRaw)
        for (raw in rawFieldsToCheck) {
            if (Gemma4InputSanitizer.sanitize(raw) != raw) {
                return ToolArgumentReader.securityFailure("CONTROL_TOKEN_REJECTED")
            }
        }

        val ruleId = normalizeRuleId(rawName.trim())
        if (ruleId.isBlank()) {
            return ToolArgumentReader.invalidArgumentsFailure("rule_name must contain alphanumeric characters")
        }

        val triggerType = normalizeTriggerType(triggerTypeRaw)
        if (triggerType !in ALLOWED_TRIGGER_TYPES) {
            return ToolArgumentReader.invalidArgumentsFailure(
                "Unsupported trigger_type '$triggerType'; allowed: ${ALLOWED_TRIGGER_TYPES.joinToString()}"
            )
        }

        val actionToolNames = actionToolRaw.split(',')
            .map { it.trim().lowercase(Locale.US) }
            .filter { it.isNotEmpty() }
        if (actionToolNames.isEmpty() || actionToolNames.size > MAX_ROUTINE_ACTIONS) {
            return ToolArgumentReader.invalidArgumentsFailure(
                "action_tool must name 1 to $MAX_ROUTINE_ACTIONS tools"
            )
        }
        val rawGroups = actionArgsRaw?.split('|').orEmpty()
        // With a single tool, '|' can only be a separator between that tool's own arguments.
        val argGroups = if (actionToolNames.size == 1 && rawGroups.size > 1) {
            listOf(rawGroups.joinToString(";"))
        } else {
            rawGroups
        }
        if (argGroups.size > actionToolNames.size) {
            return ToolArgumentReader.invalidArgumentsFailure("action_args has more groups than action_tool")
        }

        val registry = toolRegistryProvider()
        val actionSpecs = ArrayList<RuleActionSpec>(actionToolNames.size)
        for ((index, actionToolName) in actionToolNames.withIndex()) {
            if (actionToolName in NON_ROUTINE_ACTIONS) {
                return ToolArgumentReader.invalidArgumentsFailure(
                    "Tool '$actionToolName' cannot be an action of a routine"
                )
            }
            val targetTool = registry.find(actionToolName)
                ?: return ToolResult.Failure(
                    message = UserMessage(
                        key = MessageKey.ERROR_TOOL_NOT_FOUND,
                        args = listOf(MessageArg.Text(actionToolName))
                    ),
                    errorCode = "TOOL_NOT_FOUND"
                )
            val actionSpec = RuleActionSpec(
                toolName = targetTool.metadata.name,
                requiredCapability = targetTool.metadata.requiredCapability,
                staticArguments = parseStaticArguments(argGroups.getOrNull(index)),
                requiresBiometric = actionToolName in AutomationToolNames.VAULT_TOOLS
            )
            if (!targetTool.metadata.supportsUnattendedRule && !actionSpec.requiresInteractiveConfirmation) {
                return ToolArgumentReader.invalidArgumentsFailure(
                    "Tool '${targetTool.metadata.name}' cannot be scheduled in a background routine"
                )
            }
            actionSpecs.add(actionSpec)
        }
        val actionToolName = actionToolNames.joinToString(",")

        val triggerParams = LinkedHashMap<String, String>()
        if (!triggerTimeRaw.isNullOrBlank()) {
            triggerParams["time"] = normalizeTriggerTime(triggerTimeRaw)
        }

        val nowMs = clock()
        val triggerSpec = RuleTriggerSpec(triggerType = triggerType, parameters = triggerParams)
        // Small models often split one multi-step request into several calls with the same
        // routine name. Merge them into the draft this tool created moments ago, as long as it is
        // still pending approval and has the same trigger; never touch approved routines.
        val recent = recentDrafts[ruleId]
        val existing = ruleGrantPort.findRule(ruleId)
        if (recent != null && nowMs - recent.first in 0..MERGE_WINDOW_MS && recent.second == triggerSpec &&
            existing != null && existing.approvalState == RuleApprovalState.PENDING_USER_APPROVAL &&
            existing.triggerSpec == triggerSpec
        ) {
            val merged = (existing.staticActions + actionSpecs).distinctBy { it.toolName }
            if (merged.size > MAX_ROUTINE_ACTIONS) {
                return ToolArgumentReader.invalidArgumentsFailure(
                    "A routine can have at most $MAX_ROUTINE_ACTIONS actions"
                )
            }
            actionSpecs.clear()
            actionSpecs.addAll(merged)
        }
        recentDrafts[ruleId] = nowMs to triggerSpec
        val pendingGrant = ruleGrantPort.createPendingRule(
            ruleId = ruleId,
            triggerSpec = triggerSpec,
            staticActions = actionSpecs,
            nowEpochSec = nowMs / 1000L
        )

        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = nowMs,
                toolName = metadata.name,
                targetId = ToolTargetIds.ROUTINES,
                actionSummary = "Drafted pending routine ${pendingGrant.ruleId} ($triggerType -> $actionToolName)",
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "PENDING_USER_APPROVAL"
            )
        )

        return ToolResult.Success(
            message = UserMessage(
                key = MessageKey.RULE_PENDING_APPROVAL,
                args = listOf(MessageArg.Text(pendingGrant.ruleId))
            ),
            outputValues = mapOf(
                "rule_id" to pendingGrant.ruleId,
                "trigger_type" to triggerType,
                "action_tool" to actionToolName,
                "approval_state" to pendingGrant.approvalState.name
            ),
            outputProvenance = DataProvenance.SYSTEM
        )
    }

    private val recentDrafts = java.util.concurrent.ConcurrentHashMap<String, Pair<Long, RuleTriggerSpec>>()

    private fun normalizeRuleId(name: String): String {
        val sb = StringBuilder(name.length)
        var lastWasDash = false
        for (ch in name.lowercase(Locale.US)) {
            if (ch in 'a'..'z' || ch in '0'..'9') {
                sb.append(ch)
                lastWasDash = false
            } else if (!lastWasDash && sb.isNotEmpty()) {
                sb.append('_')
                lastWasDash = true
            }
        }
        return sb.toString().trim('_').take(48)
    }

    /** Maps common model spellings ("time", "daily", "every day") onto the canonical trigger types. */
    private fun normalizeTriggerType(raw: String): String {
        val upper = raw.trim().uppercase(Locale.US).replace(' ', '_').replace('-', '_')
        return TRIGGER_TYPE_ALIASES[upper] ?: upper
    }

    /** "22" -> "22:00", "7.30" -> "07:30"; anything else is kept and validated downstream. */
    private fun normalizeTriggerTime(raw: String): String {
        val trimmed = raw.trim()
        val match = TIME_REGEX.matchEntire(trimmed) ?: return trimmed
        val hour = match.groupValues[1].toInt()
        val minute = match.groupValues[2].ifEmpty { "0" }.toInt()
        if (hour !in 0..23 || minute !in 0..59) return trimmed
        return "%02d:%02d".format(Locale.US, hour, minute)
    }

    private fun parseStaticArguments(raw: String?): Map<String, String> {
        if (raw.isNullOrBlank()) return emptyMap()
        val result = LinkedHashMap<String, String>()
        // Also accept "key:value" and comma-separated pairs, which small models often emit.
        for (segment in raw.split(';', ',')) {
            val idx = segment.indexOf('=').takeIf { it > 0 } ?: segment.indexOf(':')
            if (idx <= 0 || idx >= segment.lastIndex) continue
            val key = segment.substring(0, idx).trim(*ARG_EDGE_CHARS)
            val value = segment.substring(idx + 1).trim(*ARG_EDGE_CHARS)
            if (value == "null") continue
            if (key.isNotEmpty() && value.isNotEmpty()) {
                result[key] = value
            }
        }
        return result
    }

    companion object {
        const val MAX_ROUTINE_ACTIONS: Int = 3
        private const val MERGE_WINDOW_MS: Long = 60_000L

        /** Tools that must never run from a routine (no self-replicating or memory-writing routines). */
        val NON_ROUTINE_ACTIONS: Set<String> = setOf(
            AutomationToolNames.PROPOSE_ROUTINE,
            AutomationToolNames.REMEMBER_FACT,
            AutomationToolNames.FORGET_FACT
        )

        private val ARG_EDGE_CHARS: CharArray = charArrayOf(' ', '"', '\'', '{', '}', '\u201C', '\u201D')

        private val TIME_REGEX = Regex("^(\\d{1,2})(?:[:.](\\d{2}))?$")

        private val TRIGGER_TYPE_ALIASES: Map<String, String> = mapOf(
            "TIME" to "TIME_OF_DAY",
            "DAILY" to "TIME_OF_DAY",
            "EVERY_DAY" to "TIME_OF_DAY",
            "SCHEDULE" to "TIME_OF_DAY",
            "SCHEDULED" to "TIME_OF_DAY",
            "AT_TIME" to "TIME_OF_DAY",
            "CHARGER" to "CHARGING",
            "POWER_CONNECTED" to "CHARGING",
            "STARTUP" to "BOOT",
            "ON_BOOT" to "BOOT"
        )

        val ALLOWED_TRIGGER_TYPES: Set<String> = setOf(
            "TIME_OF_DAY",
            "CHARGING",
            "BOOT",
            "MANUAL"
        )
    }
}

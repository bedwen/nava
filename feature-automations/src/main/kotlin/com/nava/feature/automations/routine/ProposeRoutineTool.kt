package com.nava.feature.automations.routine

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.RuleActionSpec
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
        description = "Drafts a Trigger -> Action automation routine for explicit user approval",
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
                description = "Canonical Nava tool name to execute when triggered (e.g. set_dnd, summarize_notifications)",
                required = true,
                slotKind = SensitiveSlotKind.INTENT_ACTION,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "action_args",
                description = "Optional semicolon-separated key=value static arguments (e.g. mode=PRIORITY)",
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

        val triggerType = triggerTypeRaw.trim().uppercase(Locale.US)
        if (triggerType !in ALLOWED_TRIGGER_TYPES) {
            return ToolArgumentReader.invalidArgumentsFailure(
                "Unsupported trigger_type '$triggerType'; allowed: ${ALLOWED_TRIGGER_TYPES.joinToString()}"
            )
        }

        val actionToolName = actionToolRaw.trim().lowercase(Locale.US)
        val registry = toolRegistryProvider()
        val targetTool = registry.find(actionToolName)
            ?: return ToolResult.Failure(
                message = UserMessage(
                    key = MessageKey.ERROR_TOOL_NOT_FOUND,
                    args = listOf(MessageArg.Text(actionToolName))
                ),
                errorCode = "TOOL_NOT_FOUND"
            )

        val triggerParams = LinkedHashMap<String, String>()
        if (!triggerTimeRaw.isNullOrBlank()) {
            triggerParams["time"] = triggerTimeRaw.trim()
        }

        val staticArgs = parseStaticArguments(actionArgsRaw)

        val requiresBiometric = actionToolName in AutomationToolNames.VAULT_TOOLS
        val actionSpec = RuleActionSpec(
            toolName = targetTool.metadata.name,
            requiredCapability = targetTool.metadata.requiredCapability,
            staticArguments = staticArgs,
            requiresBiometric = requiresBiometric
        )
        if (!targetTool.metadata.supportsUnattendedRule && !actionSpec.requiresInteractiveConfirmation) {
            return ToolArgumentReader.invalidArgumentsFailure(
                "Tool '${targetTool.metadata.name}' cannot be scheduled in a background routine"
            )
        }

        val nowMs = clock()
        val pendingGrant = ruleGrantPort.createPendingRule(
            ruleId = ruleId,
            triggerSpec = RuleTriggerSpec(
                triggerType = triggerType,
                parameters = triggerParams
            ),
            staticActions = listOf(actionSpec),
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

    private fun parseStaticArguments(raw: String?): Map<String, String> {
        if (raw.isNullOrBlank()) return emptyMap()
        val result = LinkedHashMap<String, String>()
        for (segment in raw.split(';')) {
            val idx = segment.indexOf('=')
            if (idx <= 0 || idx >= segment.lastIndex) continue
            val key = segment.substring(0, idx).trim()
            val value = segment.substring(idx + 1).trim()
            if (key.isNotEmpty() && value.isNotEmpty()) {
                result[key] = value
            }
        }
        return result
    }

    companion object {
        val ALLOWED_TRIGGER_TYPES: Set<String> = setOf(
            "TIME_OF_DAY",
            "CHARGING",
            "BOOT",
            "MANUAL"
        )
    }
}

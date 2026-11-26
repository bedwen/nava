package com.nava.app.di

import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.ui.NeuralPulseEvent
import com.nava.domain.ui.NeuronNodeId
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.ToolTargetIds
import java.util.Locale

/**
 * Canonical mapping between `:feature-automations` tool names ([AutomationToolNames]),
 * permission target identifiers ([ToolTargetIds]), and the 8 radial [NeuronNodeId] nodes
 * rendered on the Dual-Core Neural Canvas (PLAN.md Section 7).
 */
object NeuronToolMapper {

    private val toolToNeuron: Map<String, NeuronNodeId> = linkedMapOf(
        // Clock & Reminders
        AutomationToolNames.SET_ALARM to NeuronNodeId.CLOCK,
        AutomationToolNames.SET_TIMER to NeuronNodeId.CLOCK,
        AutomationToolNames.SCHEDULE_REMINDER to NeuronNodeId.CLOCK,
        AutomationToolNames.CANCEL_REMINDER to NeuronNodeId.CLOCK,

        // Calendar
        AutomationToolNames.CALENDAR_QUERY to NeuronNodeId.CALENDAR,
        AutomationToolNames.CALENDAR_CREATE to NeuronNodeId.CALENDAR,
        AutomationToolNames.CALENDAR_MODIFY to NeuronNodeId.CALENDAR,

        // Standard Notes
        AutomationToolNames.NOTES_READ to NeuronNodeId.NOTES,
        AutomationToolNames.NOTES_CREATE to NeuronNodeId.NOTES,
        AutomationToolNames.NOTES_DELETE to NeuronNodeId.NOTES,
        AutomationToolNames.NOTES_SEARCH to NeuronNodeId.NOTES,

        // Nava Secure Vault
        AutomationToolNames.VAULT_READ to NeuronNodeId.VAULT,
        AutomationToolNames.VAULT_WRITE to NeuronNodeId.VAULT,
        AutomationToolNames.VAULT_DELETE to NeuronNodeId.VAULT,

        // Communication / Messages / Notifications
        AutomationToolNames.CREATE_SMS_DRAFT to NeuronNodeId.MESSAGES,
        AutomationToolNames.DIAL_CALL to NeuronNodeId.MESSAGES,
        AutomationToolNames.PLACE_CALL to NeuronNodeId.MESSAGES,
        AutomationToolNames.SUMMARIZE_NOTIFICATIONS to NeuronNodeId.MESSAGES,
        AutomationToolNames.CREATE_NOTIFICATION_WATCHER to NeuronNodeId.MESSAGES,
        AutomationToolNames.MANAGE_NOTIFICATION_WATCHERS to NeuronNodeId.MESSAGES,
        AutomationToolNames.DAILY_BRIEFING to NeuronNodeId.MESSAGES,

        // Device Audio / DND / App Launch
        AutomationToolNames.SET_DND to NeuronNodeId.AUDIO_DND,
        AutomationToolNames.SET_VOLUME to NeuronNodeId.AUDIO_DND,
        AutomationToolNames.LAUNCH_APP to NeuronNodeId.AUDIO_DND,

        // Storage Access Framework (Files)
        AutomationToolNames.SAF_READ to NeuronNodeId.FILES,
        AutomationToolNames.SAF_WRITE to NeuronNodeId.FILES,
        AutomationToolNames.SAF_DELETE to NeuronNodeId.FILES,

        // Routines
        AutomationToolNames.PROPOSE_ROUTINE to NeuronNodeId.ROUTINES,

        // Personal memory
        AutomationToolNames.REMEMBER_FACT to NeuronNodeId.NOTES,
        AutomationToolNames.RECALL_FACTS to NeuronNodeId.NOTES,
        AutomationToolNames.FORGET_FACT to NeuronNodeId.NOTES,

        // Device controls
        AutomationToolNames.SET_FLASHLIGHT to NeuronNodeId.AUDIO_DND,
        AutomationToolNames.MEDIA_CONTROL to NeuronNodeId.AUDIO_DND,
        AutomationToolNames.OPEN_SETTINGS_PANEL to NeuronNodeId.AUDIO_DND
    )

    private val targetToNeuron: Map<String, NeuronNodeId> = linkedMapOf(
        ToolTargetIds.CLOCK to NeuronNodeId.CLOCK,
        ToolTargetIds.REMINDERS to NeuronNodeId.CLOCK,
        ToolTargetIds.CALENDAR to NeuronNodeId.CALENDAR,
        ToolTargetIds.NOTES to NeuronNodeId.NOTES,
        ToolTargetIds.VAULT to NeuronNodeId.VAULT,
        ToolTargetIds.SMS to NeuronNodeId.MESSAGES,
        ToolTargetIds.PHONE to NeuronNodeId.MESSAGES,
        ToolTargetIds.NOTIFICATIONS to NeuronNodeId.MESSAGES,
        ToolTargetIds.AUDIO_DND to NeuronNodeId.AUDIO_DND,
        ToolTargetIds.APP_LAUNCH to NeuronNodeId.AUDIO_DND,
        ToolTargetIds.SAF to NeuronNodeId.FILES,
        ToolTargetIds.ROUTINES to NeuronNodeId.ROUTINES,
        ToolTargetIds.BACKGROUND_TASKS to NeuronNodeId.ROUTINES,
        ToolTargetIds.MEMORY to NeuronNodeId.NOTES,
        ToolTargetIds.FLASHLIGHT to NeuronNodeId.AUDIO_DND,
        ToolTargetIds.MEDIA to NeuronNodeId.AUDIO_DND,
        ToolTargetIds.SETTINGS_PANEL to NeuronNodeId.AUDIO_DND
    )

    private val neuronToPrimaryTarget: Map<NeuronNodeId, String> = linkedMapOf(
        NeuronNodeId.CLOCK to ToolTargetIds.CLOCK,
        NeuronNodeId.CALENDAR to ToolTargetIds.CALENDAR,
        NeuronNodeId.NOTES to ToolTargetIds.NOTES,
        NeuronNodeId.MESSAGES to ToolTargetIds.SMS,
        NeuronNodeId.VAULT to ToolTargetIds.VAULT,
        NeuronNodeId.FILES to ToolTargetIds.SAF,
        NeuronNodeId.AUDIO_DND to ToolTargetIds.AUDIO_DND,
        NeuronNodeId.ROUTINES to ToolTargetIds.ROUTINES
    )

    /**
     * Resolves the [NeuronNodeId] corresponding to a canonical [AutomationToolNames] tool name,
     * or returns `null` if unknown.
     */
    fun neuronForToolName(toolName: String?): NeuronNodeId? {
        if (toolName.isNullOrBlank()) return null
        val normalized = toolName.trim().lowercase(Locale.US)
        return toolToNeuron[normalized]
    }

    /**
     * Resolves the [NeuronNodeId] corresponding to a [ToolTargetIds] target identifier
     * (including `"saf:<treeUri>"` per-directory SAF targets), or returns `null` if unrecognized.
     */
    fun neuronForTargetId(targetId: String?): NeuronNodeId? {
        if (targetId.isNullOrBlank()) return null
        val trimmed = targetId.trim()
        targetToNeuron[trimmed]?.let { return it }
        val lower = trimmed.lowercase(Locale.US)
        targetToNeuron[lower]?.let { return it }
        if (lower.startsWith("saf:")) {
            return NeuronNodeId.FILES
        }
        if (lower.startsWith("vault:")) {
            return NeuronNodeId.VAULT
        }
        if (lower.startsWith("routine:")) {
            return NeuronNodeId.ROUTINES
        }
        return null
    }

    /**
     * Resolves the [NeuronNodeId] for a [ToolCallAst], checking the tool name first and falling
     * back to the call's `targetId` or [NeuronNodeId.ROUTINES].
     */
    fun neuronForToolCall(call: ToolCallAst): NeuronNodeId {
        return neuronForToolName(call.toolName)
            ?: neuronForTargetId(call.targetId)
            ?: NeuronNodeId.ROUTINES
    }

    /**
     * Returns the canonical primary [ToolTargetIds] identifier associated with [nodeId]
     * (used when tapping an app neuron on the Dual-Core Neural Canvas to inspect its
     * `PermissionProfile` and `AuditLogDao` entries).
     */
    fun primaryTargetIdForNeuron(nodeId: NeuronNodeId): String {
        return neuronToPrimaryTarget.getValue(nodeId)
    }

    /**
     * Returns all canonical [ToolTargetIds] routed to [nodeId].
     */
    fun targetIdsForNeuron(nodeId: NeuronNodeId): Set<String> {
        return targetToNeuron.entries
            .filter { it.value == nodeId }
            .mapTo(LinkedHashSet()) { it.key }
    }

    /**
     * Returns all canonical [AutomationToolNames] routed to [nodeId].
     */
    fun toolsForNeuron(nodeId: NeuronNodeId): Set<String> {
        return toolToNeuron.entries
            .filter { it.value == nodeId }
            .mapTo(LinkedHashSet()) { it.key }
    }

    /**
     * Resolves the set of active [NeuronNodeId]s touched by [plan].
     */
    fun activeNeuronsForPlan(plan: PlanAst): Set<NeuronNodeId> {
        return plan.calls
            .sortedBy { it.orderIndex }
            .mapTo(LinkedHashSet()) { call -> neuronForToolCall(call) }
    }

    /**
     * Builds the ordered sequence of [NeuralPulseEvent] synapse trajectories for a resolved [plan]
     * (PLAN.md Section 7):
     * - Step 0 fires from the Central Dual-Core Hub (`sourceNode = null`) to the first target neuron.
     * - Subsequent chained steps fire across the inter-neuron synapse edge (`sourceNode = prevNode`)
     *   whenever the target neuron changes, or from the hub if targeting the same neuron.
     * - `wakesInnerCore` is `true` strictly for [ResolutionTier.TIER_3_GEMMA]; Tiers 1 and 2 pulse
     *   only the Outer Cortex Shell while the Inner Core stays asleep.
     */
    fun buildPulsesForPlan(
        plan: PlanAst,
        tier: ResolutionTier,
        timestampEpochMs: Long
    ): List<NeuralPulseEvent> {
        val orderedCalls = plan.calls.sortedBy { it.orderIndex }
        if (orderedCalls.isEmpty()) return emptyList()

        val wakesInnerCore = tier == ResolutionTier.TIER_3_GEMMA
        val pulses = ArrayList<NeuralPulseEvent>(orderedCalls.size)
        var previousNode: NeuronNodeId? = null

        for ((idx, call) in orderedCalls.withIndex()) {
            val targetNode = neuronForToolCall(call)
            val sourceNode = if (idx == 0 || previousNode == targetNode) {
                null
            } else {
                previousNode
            }
            val isBiometric = targetNode == NeuronNodeId.VAULT ||
                call.toolName in AutomationToolNames.VAULT_TOOLS

            pulses.add(
                NeuralPulseEvent(
                    eventId = "${plan.planId}:pulse:$idx",
                    tier = tier,
                    sourceNode = sourceNode,
                    targetNode = targetNode,
                    wakesInnerCore = wakesInnerCore,
                    isBiometricSynapse = isBiometric,
                    timestampEpochMs = timestampEpochMs
                )
            )
            previousNode = targetNode
        }
        return pulses
    }
}

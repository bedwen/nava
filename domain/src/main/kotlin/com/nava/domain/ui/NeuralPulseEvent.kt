package com.nava.domain.ui

import com.nava.domain.ai.ResolutionTier

/**
 * One-shot synapse trajectory command rendered by the Dual-Core Neural Canvas.
 *
 * When [sourceNode] is null, the pulse radiates from the Central Dual-Core Hub to [targetNode].
 * When [sourceNode] is non-null, the pulse travels across the inter-neuron chain synapse.
 */
data class NeuralPulseEvent(
    val eventId: String,
    val tier: ResolutionTier,
    val sourceNode: NeuronNodeId?,
    val targetNode: NeuronNodeId,
    val wakesInnerCore: Boolean,
    val isBiometricSynapse: Boolean = false,
    val timestampEpochMs: Long
) {
    init {
        require(eventId.isNotBlank()) { "eventId must not be blank" }
    }
}

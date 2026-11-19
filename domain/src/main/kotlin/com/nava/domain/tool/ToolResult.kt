package com.nava.domain.tool

import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Tainted
import com.nava.domain.ui.UserMessage

/**
 * Deterministic outcome produced by executing a [NavaTool] or evaluating its security gates.
 */
sealed interface ToolResult {
    val message: UserMessage

    data class Success(
        override val message: UserMessage,
        val outputValues: Map<String, String> = emptyMap(),
        val outputProvenance: DataProvenance = DataProvenance.SYSTEM
    ) : ToolResult

    data class ConfirmationRequired(
        override val message: UserMessage,
        val pendingToolName: String,
        val targetId: String,
        val canonicalArguments: Map<String, Tainted<String>>,
        val requiresBiometric: Boolean = false,
        val hasUntrustedHighRiskSlot: Boolean = false,
        val pendingOrderIndex: Int = 0
    ) : ToolResult

    data class Failure(
        override val message: UserMessage,
        val errorCode: String,
        val isSecurityViolation: Boolean = false
    ) : ToolResult
}

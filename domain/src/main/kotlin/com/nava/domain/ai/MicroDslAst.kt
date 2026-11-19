package com.nava.domain.ai

import com.nava.domain.security.Tainted

/**
 * Strongly-typed primitive slot value parsed deterministically from MicroDsl or rule packs.
 */
sealed interface SlotValueAst {
    fun asDisplayString(): String

    data class StringValue(val value: String) : SlotValueAst {
        override fun asDisplayString(): String = value
    }

    data class IntValue(val value: Long) : SlotValueAst {
        override fun asDisplayString(): String = value.toString()
    }

    data class BooleanValue(val value: Boolean) : SlotValueAst {
        override fun asDisplayString(): String = value.toString()
    }

    data object NullValue : SlotValueAst {
        override fun asDisplayString(): String = ""
    }
}

/**
 * Single parsed tool invocation inside a [PlanAst], carrying provenance-tracked slot values.
 */
data class ToolCallAst(
    val toolName: String,
    val arguments: Map<String, Tainted<SlotValueAst>>,
    val orderIndex: Int = 0,
    val targetId: String? = null
) {
    init {
        require(toolName.isNotBlank()) { "ToolCallAst toolName must not be blank" }
        require(orderIndex >= 0) { "ToolCallAst orderIndex must be non-negative" }
        require(targetId == null || targetId.isNotBlank()) { "ToolCallAst targetId must not be blank" }
    }
}

/**
 * Ordered sequence of tool invocations resolved by Tier 1, Tier 2, or Tier 3.
 */
data class PlanAst(
    val planId: String,
    val calls: List<ToolCallAst>,
    val skeletonKey: String? = null,
    val requiresBoundedThought: Boolean = false
) {
    init {
        require(planId.isNotBlank()) { "PlanAst planId must not be blank" }
        require(calls.isNotEmpty()) { "PlanAst must contain at least one ToolCallAst" }
    }
}

/**
 * Root AST produced by `MicroDslParser` from Gemma 4 output.
 */
sealed interface MicroDslAst {
    data class Plan(val plan: PlanAst) : MicroDslAst
    data class DirectReply(val text: String, val languageTag: String) : MicroDslAst
    data class ParseError(val rawFragment: String, val reason: String) : MicroDslAst
}

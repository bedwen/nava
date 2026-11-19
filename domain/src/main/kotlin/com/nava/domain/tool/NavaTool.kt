package com.nava.domain.tool

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.Tainted

/**
 * Port implemented by every atomic automation tool adapter in `:feature-automations`.
 *
 * Adding a new tool requires only implementing [NavaTool] and registering it in [ToolRegistry]
 * (Open/Closed Principle).
 */
interface NavaTool {
    val metadata: ToolMetadata

    suspend fun execute(
        context: ToolExecutionContext,
        arguments: Map<String, Tainted<SlotValueAst>>
    ): ToolResult
}

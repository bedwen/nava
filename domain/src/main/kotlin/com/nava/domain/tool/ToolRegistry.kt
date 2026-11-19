package com.nava.domain.tool

import java.util.concurrent.ConcurrentHashMap

/**
 * Thread-safe, Open/Closed registry mapping canonical tool names to [NavaTool] adapters.
 *
 * New tools register without modifying [com.nava.domain.ai.IntentResolver] or
 * [com.nava.domain.ai.LlmEnginePort] implementations.
 */
class ToolRegistry(
    initialTools: Iterable<NavaTool> = emptyList()
) {
    private val tools = ConcurrentHashMap<String, NavaTool>()

    init {
        registerAll(initialTools)
    }

    /**
     * Registers [tool] by its unique [ToolMetadata.name].
     * Throws [IllegalArgumentException] if a tool with the same name is already registered.
     */
    fun register(tool: NavaTool) {
        val name = tool.metadata.name
        val previous = tools.putIfAbsent(name, tool)
        require(previous == null) {
            "Duplicate tool registration for name '$name'"
        }
    }

    /** Registers all [items] atomically per tool, rejecting duplicates. */
    fun registerAll(items: Iterable<NavaTool>) {
        for (tool in items) {
            register(tool)
        }
    }

    /** Finds a registered tool by [toolName], or null if unregistered. */
    fun find(toolName: String): NavaTool? = tools[toolName]

    /** Returns the registered tool for [toolName] or throws [NoSuchElementException]. */
    fun require(toolName: String): NavaTool {
        return tools[toolName]
            ?: throw NoSuchElementException("Tool '$toolName' is not registered in ToolRegistry")
    }

    /** True if [toolName] is registered. */
    fun contains(toolName: String): Boolean = tools.containsKey(toolName)

    /** Returns a deterministic snapshot of all registered tools sorted by tool name. */
    fun allTools(): List<NavaTool> = tools.values.sortedBy { it.metadata.name }

    /** Returns metadata for all registered tools sorted by tool name. */
    fun allMetadata(): List<ToolMetadata> = allTools().map { it.metadata }

    /** Returns all registered tools belonging to [category], sorted by tool name. */
    fun byCategory(category: ToolCategory): List<NavaTool> {
        return allTools().filter { it.metadata.category == category }
    }

    /** Current number of registered tools. */
    val size: Int
        get() = tools.size
}

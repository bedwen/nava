package com.nava.domain.tool

import com.nava.domain.security.AtomicCapability

/**
 * Self-describing metadata for a registered [NavaTool].
 * Used by DynamicToolPruner, Tier 2 cache invalidation ([schemaVersion]), and SecurityFirewall.
 */
data class ToolMetadata(
    val name: String,
    val displayNameKey: String,
    val description: String,
    val category: ToolCategory,
    val requiredCapability: AtomicCapability,
    val schemaVersion: Int = 1,
    val fields: List<ToolSchemaField> = emptyList(),
    val supportsUnattendedRule: Boolean = requiredCapability != AtomicCapability.MODIFY_DELETE_SEND
) {
    init {
        require(name.isNotBlank()) { "ToolMetadata name must not be blank" }
        require(displayNameKey.isNotBlank()) { "ToolMetadata displayNameKey must not be blank" }
        require(description.isNotBlank()) { "ToolMetadata description must not be blank" }
        require(schemaVersion > 0) { "ToolMetadata schemaVersion must be positive" }
        if (requiredCapability == AtomicCapability.MODIFY_DELETE_SEND) {
            require(!supportsUnattendedRule) {
                "Tools requiring MODIFY_DELETE_SEND cannot support unattended rule execution"
            }
        }
    }

    /** Looks up a declared parameter field by [fieldName]. */
    fun fieldByName(fieldName: String): ToolSchemaField? = fields.firstOrNull { it.name == fieldName }
}

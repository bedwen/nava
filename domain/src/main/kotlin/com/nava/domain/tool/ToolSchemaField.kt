package com.nava.domain.tool

import com.nava.domain.security.SensitiveSlotKind

/**
 * Canonical typed primitive formats expected for tool slot values.
 */
enum class SlotValueType {
    STRING,
    INTEGER,
    BOOLEAN,
    ISO_DATE,
    ISO_TIME,
    ISO_DATETIME,
    DURATION_SECONDS
}

/**
 * Declarative schema definition for a single argument accepted by a [NavaTool].
 */
data class ToolSchemaField(
    val name: String,
    val description: String,
    val required: Boolean,
    val slotKind: SensitiveSlotKind,
    val valueType: SlotValueType = SlotValueType.STRING
) {
    init {
        require(name.isNotBlank()) { "ToolSchemaField name must not be blank" }
        require(description.isNotBlank()) { "ToolSchemaField description must not be blank" }
    }
}

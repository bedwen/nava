package com.nava.domain.locale

/**
 * Declarative Layer R pattern matching frequent literal commands in under 2 ms.
 */
data class RuleMatchPattern(
    val patternId: String,
    val toolName: String,
    val regexPattern: String,
    val slotMappings: Map<String, String> = emptyMap(),
    val staticSlots: Map<String, String> = emptyMap(),
    val priority: Int = 0
) {
    init {
        require(patternId.isNotBlank()) { "patternId must not be blank" }
        require(toolName.isNotBlank()) { "toolName must not be blank" }
        require(regexPattern.isNotBlank()) { "regexPattern must not be blank" }
    }
}

package com.nava.domain.ui

/**
 * Cognitive execution state driving the Dual-Core Neural Canvas rendering mode.
 */
enum class CoreActivityState {
    /** 0-FPS idle state: neither Outer Cortex Shell nor Gemma 4 Inner Core is animating. */
    IDLE,

    /** Tier 1 or Tier 2 reflex pulse active; Gemma 4 Inner Core stays dark/asleep. */
    OUTER_SHELL_ACTIVE,

    /** Tier 3 cognitive inference active; Gemma 4 Inner Core wakes and glows. */
    INNER_CORE_ACTIVE,

    /** Tool execution or action confirmation in flight. */
    EXECUTING_TOOL,

    /** Brief error/security-rejection visual feedback pulse. */
    ERROR_FLASH
}

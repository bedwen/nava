package com.nava.domain.ai

/**
 * Device thermal classification used by ThermalModelLifecycleManager and the Neural Canvas.
 */
enum class ThermalState {
    /** Thermal status <= LIGHT and battery >= 15%: normal model residency. */
    NORMAL,

    /** Thermal status == MODERATE or battery < 15%: disables thought mode and unloads immediately. */
    MODERATE,

    /** Thermal status >= SEVERE: forces immediate model unload and routes Tiers 1 & 2 only. */
    SEVERE_OR_HIGHER
}

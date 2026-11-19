package com.nava.domain.security

/**
 * Broad risk classification for tool argument slots.
 */
enum class SlotSensitivity {
    /** Destination, target, or invocation slots that control who or what receives an action. */
    HIGH_RISK_TARGET,

    /** Passive content slots such as bodies, titles, timestamps, or durations. */
    PASSIVE_CONTENT
}

/**
 * Classifies tool parameters so [SecurityFirewallPort] can enforce taint gates on sensitive targets.
 */
enum class SensitiveSlotKind(val sensitivity: SlotSensitivity) {
    RECIPIENT_ADDRESS(SlotSensitivity.HIGH_RISK_TARGET),
    PHONE_NUMBER(SlotSensitivity.HIGH_RISK_TARGET),
    EXTERNAL_URI(SlotSensitivity.HIGH_RISK_TARGET),
    FILE_PATH(SlotSensitivity.HIGH_RISK_TARGET),
    PACKAGE_NAME(SlotSensitivity.HIGH_RISK_TARGET),
    INTENT_ACTION(SlotSensitivity.HIGH_RISK_TARGET),

    TEXT_BODY(SlotSensitivity.PASSIVE_CONTENT),
    EVENT_TITLE(SlotSensitivity.PASSIVE_CONTENT),
    DATE_TIME(SlotSensitivity.PASSIVE_CONTENT),
    DURATION(SlotSensitivity.PASSIVE_CONTENT);

    /** True when populating this slot from [DataProvenance.UNTRUSTED_EXTERNAL] must force confirmation. */
    val isHighRisk: Boolean
        get() = sensitivity == SlotSensitivity.HIGH_RISK_TARGET
}

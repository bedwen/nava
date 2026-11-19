package com.nava.domain.security

/**
 * Tracks the origin and trust level of every string or slot value inside Nava.
 *
 * Security invariants enforced in Kotlin:
 * - Only [USER_UTTERANCE] may authorize minting a Stage 1 [CapabilityToken].
 * - [UNTRUSTED_EXTERNAL] dominates all combinations so untrusted data can never be laundered.
 */
enum class DataProvenance {
    /** Direct command issued by the authenticated user. */
    USER_UTTERANCE,

    /** Trusted system clock, timezone, or static local configuration metadata. */
    SYSTEM,

    /** Data originating from notifications, messages, files, clipboard, or external providers. */
    UNTRUSTED_EXTERNAL;

    /** Returns true when this provenance represents untrusted external content. */
    val isUntrusted: Boolean
        get() = this == UNTRUSTED_EXTERNAL

    companion object {
        /**
         * Monotonically combines two provenances along the trust lattice:
         * `USER_UTTERANCE < SYSTEM < UNTRUSTED_EXTERNAL`.
         */
        fun worstOf(first: DataProvenance, second: DataProvenance): DataProvenance {
            return when {
                first == UNTRUSTED_EXTERNAL || second == UNTRUSTED_EXTERNAL -> UNTRUSTED_EXTERNAL
                first == SYSTEM || second == SYSTEM -> SYSTEM
                else -> USER_UTTERANCE
            }
        }
    }
}

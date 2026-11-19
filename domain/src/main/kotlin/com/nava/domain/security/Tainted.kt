package com.nava.domain.security

/**
 * Immutable provenance-tracked wrapper around any extracted or user-provided value.
 *
 * Instances may only be constructed via the companion factory methods ([fromUserUtterance],
 * [fromSystem], [fromUntrustedExternal]), preventing provenance laundering through public
 * constructors or generated `.copy(...)` calls. Transformations via [map], [withSlotKind],
 * and [combineWith] preserve or monotonically escalate taint.
 */
class Tainted<out T> private constructor(
    val value: T,
    val provenance: DataProvenance,
    val slotKind: SensitiveSlotKind? = null,
    val sourceLabel: String? = null
) {
    /** True when the underlying value originated from an untrusted external source. */
    val isUntrusted: Boolean
        get() = provenance.isUntrusted

    /**
     * True when this value is both untrusted and bound to a high-risk target slot,
     * requiring an explicit Action Confirmation Card with an untrusted-source badge.
     */
    val requiresExplicitConfirmation: Boolean
        get() = isUntrusted && (slotKind?.isHighRisk == true)

    /** Applies [transform] to [value] while preserving provenance, slot kind, and source label. */
    fun <R> map(transform: (T) -> R): Tainted<R> {
        return Tainted(
            value = transform(value),
            provenance = provenance,
            slotKind = slotKind,
            sourceLabel = sourceLabel
        )
    }

    /**
     * Attaches or updates the [SensitiveSlotKind] classification while preserving provenance.
     * Sensitivity is monotonic: a high-risk target slot can never be downgraded to passive content.
     */
    fun withSlotKind(kind: SensitiveSlotKind): Tainted<T> {
        if (this.slotKind?.isHighRisk == true && !kind.isHighRisk) {
            return this
        }
        return Tainted(
            value = value,
            provenance = provenance,
            slotKind = kind,
            sourceLabel = sourceLabel
        )
    }

    /** Combines two tainted values, monotonically escalating provenance along the trust lattice. */
    fun <B, R> combineWith(
        other: Tainted<B>,
        transform: (T, B) -> R
    ): Tainted<R> {
        val mergedProvenance = DataProvenance.worstOf(this.provenance, other.provenance)
        val mergedSlotKind = when {
            this.slotKind?.isHighRisk == true -> this.slotKind
            other.slotKind?.isHighRisk == true -> other.slotKind
            else -> this.slotKind ?: other.slotKind
        }
        val mergedLabel = if (other.isUntrusted && !this.isUntrusted) {
            other.sourceLabel ?: this.sourceLabel
        } else {
            this.sourceLabel ?: other.sourceLabel
        }
        return Tainted(
            value = transform(this.value, other.value),
            provenance = mergedProvenance,
            slotKind = mergedSlotKind,
            sourceLabel = mergedLabel
        )
    }

    /**
     * Unwraps [value] only if this value is not [DataProvenance.UNTRUSTED_EXTERNAL].
     * Throws [SecurityException] if untrusted data attempts to enter trusted planning.
     */
    fun requireTrustedForPlanning(): T {
        if (isUntrusted) {
            throw SecurityException("Untrusted external data cannot participate in Stage 1 planning")
        }
        return value
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Tainted<*>) return false
        return value == other.value &&
            provenance == other.provenance &&
            slotKind == other.slotKind &&
            sourceLabel == other.sourceLabel
    }

    override fun hashCode(): Int {
        var result = value?.hashCode() ?: 0
        result = 31 * result + provenance.hashCode()
        result = 31 * result + (slotKind?.hashCode() ?: 0)
        result = 31 * result + (sourceLabel?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "Tainted(value=$value, provenance=$provenance, slotKind=$slotKind, sourceLabel=$sourceLabel)"
    }

    companion object {
        fun <T> fromUserUtterance(
            value: T,
            slotKind: SensitiveSlotKind? = null
        ): Tainted<T> = Tainted(
            value = value,
            provenance = DataProvenance.USER_UTTERANCE,
            slotKind = slotKind
        )

        fun <T> fromSystem(
            value: T,
            slotKind: SensitiveSlotKind? = null
        ): Tainted<T> = Tainted(
            value = value,
            provenance = DataProvenance.SYSTEM,
            slotKind = slotKind
        )

        fun <T> fromUntrustedExternal(
            value: T,
            slotKind: SensitiveSlotKind? = null,
            sourceLabel: String? = null
        ): Tainted<T> = Tainted(
            value = value,
            provenance = DataProvenance.UNTRUSTED_EXTERNAL,
            slotKind = slotKind,
            sourceLabel = sourceLabel
        )
    }
}

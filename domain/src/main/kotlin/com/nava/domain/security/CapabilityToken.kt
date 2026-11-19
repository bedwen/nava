package com.nava.domain.security

import java.util.Collections

/**
 * Immutable Stage 1 authorization token sealing the exact tool names allowed for a single request.
 *
 * Security invariants:
 * - May ONLY be minted from [DataProvenance.USER_UTTERANCE].
 * - Never cached across turns in Tier 2 cache.
 * - Defensive copy ensures [allowedTools] cannot be mutated after minting.
 */
class CapabilityToken private constructor(
    val tokenId: String,
    val requestId: String,
    val allowedTools: Set<String>,
    val mintProvenance: DataProvenance,
    val maxToolCalls: Int,
    val issuedAtEpochMs: Long,
    val expiresAtEpochMs: Long
) {
    init {
        require(tokenId.isNotBlank()) { "tokenId must not be blank" }
        require(requestId.isNotBlank()) { "requestId must not be blank" }
        require(allowedTools.isNotEmpty()) { "CapabilityToken must authorize at least one tool" }
        require(allowedTools.all { it.isNotBlank() }) { "Tool names in CapabilityToken must not be blank" }
        require(maxToolCalls > 0) { "maxToolCalls must be positive" }
        require(expiresAtEpochMs >= issuedAtEpochMs) { "expiresAtEpochMs must not precede issuedAtEpochMs" }
        if (mintProvenance != DataProvenance.USER_UTTERANCE) {
            throw SecurityException(
                "CapabilityToken can only be minted from USER_UTTERANCE provenance, got $mintProvenance"
            )
        }
    }

    /** True if [toolName] is sealed inside this token's allowlist. */
    fun allowsTool(toolName: String): Boolean = toolName in allowedTools

    /** True if [nowEpochMs] is past [expiresAtEpochMs]. */
    fun isExpired(nowEpochMs: Long): Boolean = nowEpochMs > expiresAtEpochMs

    /**
     * Deterministically validates token expiry and tool authorization.
     * Throws [SecurityException] if expired or if [toolName] is outside the sealed set.
     */
    fun assertValidFor(toolName: String, nowEpochMs: Long) {
        if (isExpired(nowEpochMs)) {
            throw SecurityException("CapabilityToken $tokenId is expired at $nowEpochMs")
        }
        if (!allowsTool(toolName)) {
            throw SecurityException(
                "Tool '$toolName' is not authorized by CapabilityToken $tokenId (allowed=$allowedTools)"
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CapabilityToken) return false
        return tokenId == other.tokenId &&
            requestId == other.requestId &&
            allowedTools == other.allowedTools &&
            mintProvenance == other.mintProvenance &&
            maxToolCalls == other.maxToolCalls &&
            issuedAtEpochMs == other.issuedAtEpochMs &&
            expiresAtEpochMs == other.expiresAtEpochMs
    }

    override fun hashCode(): Int {
        var result = tokenId.hashCode()
        result = 31 * result + requestId.hashCode()
        result = 31 * result + allowedTools.hashCode()
        result = 31 * result + mintProvenance.hashCode()
        result = 31 * result + maxToolCalls
        result = 31 * result + issuedAtEpochMs.hashCode()
        result = 31 * result + expiresAtEpochMs.hashCode()
        return result
    }

    override fun toString(): String {
        return "CapabilityToken(tokenId='$tokenId', requestId='$requestId', allowedTools=$allowedTools, " +
            "mintProvenance=$mintProvenance, maxToolCalls=$maxToolCalls, " +
            "issuedAtEpochMs=$issuedAtEpochMs, expiresAtEpochMs=$expiresAtEpochMs)"
    }

    companion object {
        /** Default single-request validity window (5 minutes). */
        const val DEFAULT_TTL_MS: Long = 5L * 60L * 1000L

        /**
         * Mints an immutable [CapabilityToken] after asserting [mintProvenance] is [DataProvenance.USER_UTTERANCE]
         * and taking a defensive immutable snapshot of [allowedTools].
         */
        fun mint(
            tokenId: String,
            requestId: String,
            allowedTools: Set<String>,
            mintProvenance: DataProvenance,
            issuedAtEpochMs: Long,
            expiresAtEpochMs: Long = issuedAtEpochMs + DEFAULT_TTL_MS,
            maxToolCalls: Int = allowedTools.size.coerceAtLeast(1)
        ): CapabilityToken {
            return CapabilityToken(
                tokenId = tokenId,
                requestId = requestId,
                allowedTools = Collections.unmodifiableSet(allowedTools.toCollection(LinkedHashSet())),
                mintProvenance = mintProvenance,
                maxToolCalls = maxToolCalls,
                issuedAtEpochMs = issuedAtEpochMs,
                expiresAtEpochMs = expiresAtEpochMs
            )
        }
    }
}

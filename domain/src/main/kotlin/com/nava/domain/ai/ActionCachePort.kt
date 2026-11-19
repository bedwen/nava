package com.nava.domain.ai

import com.nava.domain.security.DataProvenance

/**
 * Parameterized Tier 2 plan skeleton cached under `(languageCode, canonicalSkeleton)`.
 *
 * `CapabilityToken`s and untrusted or Vault slot values are never persisted inside cached
 * templates (PLAN.md Sections 3.1 and 6.3).
 */
data class CachedActionTemplate(
    val languageCode: String,
    val canonicalSkeleton: String,
    val toolNames: List<String>,
    val toolSchemaVersions: Map<String, Int>,
    val serializedPlanTemplate: String,
    val lastUsedEpochSec: Long
) {
    init {
        require(languageCode.isNotBlank()) { "CachedActionTemplate languageCode must not be blank" }
        require(canonicalSkeleton.isNotBlank()) {
            "CachedActionTemplate canonicalSkeleton must not be blank"
        }
        require('\u0000' !in languageCode) {
            "CachedActionTemplate languageCode must not contain NUL"
        }
        require('\u0000' !in canonicalSkeleton) {
            "CachedActionTemplate canonicalSkeleton must not contain NUL"
        }
        require(toolNames.isNotEmpty()) { "CachedActionTemplate toolNames must not be empty" }
        require(toolNames.all { it.isNotBlank() }) {
            "CachedActionTemplate toolNames entries must not be blank"
        }
        require(serializedPlanTemplate.isNotBlank()) {
            "CachedActionTemplate serializedPlanTemplate must not be blank"
        }
        for ((toolName, version) in toolSchemaVersions) {
            require(toolName.isNotBlank()) {
                "CachedActionTemplate toolSchemaVersions key must not be blank"
            }
            require(version > 0) {
                "CachedActionTemplate schema version for '$toolName' must be positive, got $version"
            }
        }
    }
}

/**
 * Pure Kotlin Tier 2 encrypted skeleton cache port implemented by `ActionCacheDao`
 * in `:core-security-data` (Dependency Inversion Principle, Iron Law 4).
 *
 * Lookup keys use `HMAC-SHA256(languageCode + "\u0000" + canonicalSkeleton)` blind indexing
 * with strict cache admission rules (PLAN.md Section 3.1).
 */
interface ActionCachePort {
    /**
     * Persists [template] if and only if 100% of slot values originated from
     * [DataProvenance.USER_UTTERANCE] and the plan does not touch `Nava Vault`.
     *
     * Implementations must enforce this admission policy deterministically when
     * [provenance] is not [DataProvenance.USER_UTTERANCE] or [touchesVault] is `true`,
     * by either throwing [SecurityException] (as `ActionCacheDao` does) or returning `false`.
     */
    suspend fun putTemplate(
        template: CachedActionTemplate,
        provenance: DataProvenance,
        touchesVault: Boolean,
        nowEpochSec: Long
    ): Boolean

    /**
     * Performs a blind-index lookup for `(languageCode, canonicalSkeleton)`, refreshes its
     * LRU timestamp, and returns the cached template if present.
     */
    suspend fun findTemplate(
        languageCode: String,
        canonicalSkeleton: String,
        nowEpochSec: Long
    ): CachedActionTemplate?

    /**
     * Removes cached templates referencing [toolName] whose stored schema version differs from
     * [currentSchemaVersion]. Returns the number of invalidated entries.
     */
    suspend fun invalidateForToolSchemaChange(
        toolName: String,
        currentSchemaVersion: Int
    ): Int

    /** Clears all cached templates (for example, when a `PermissionProfile` changes). */
    suspend fun invalidateAll(): Int
}

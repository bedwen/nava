package com.nava.core.security.dao

import com.nava.core.security.crypto.SecureMemory
import com.nava.core.security.storage.DecryptedRow
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.storage.StructuredPayloadCodec
import com.nava.domain.security.DataProvenance

/**
 * Parameterized Tier 2 plan skeleton cached under `(languageCode, canonicalSkeleton)`.
 *
 * `CapabilityToken`s and untrusted/Vault slot values are never persisted inside cached templates
 * (PLAN.md Section 3.1 & 6.3).
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
        require(canonicalSkeleton.isNotBlank()) { "CachedActionTemplate canonicalSkeleton must not be blank" }
        require(toolNames.isNotEmpty()) { "CachedActionTemplate toolNames must not be empty" }
        require(toolNames.all { it.isNotBlank() }) { "CachedActionTemplate toolNames entries must not be blank" }
        require(serializedPlanTemplate.isNotBlank()) {
            "CachedActionTemplate serializedPlanTemplate must not be blank"
        }
        for ((toolName, version) in toolSchemaVersions) {
            require(toolName.isNotBlank()) { "CachedActionTemplate toolSchemaVersions key must not be blank" }
            require(version > 0) {
                "CachedActionTemplate schema version for '$toolName' must be positive, got $version"
            }
        }
    }
}

/**
 * Tier 2 encrypted skeleton cache DAO over [EncryptedSqliteStore] (`action_cache` table).
 *
 * Enforces PLAN.md Section 3.1 Cache Admission Policy, `HMAC-SHA256(languageCode + "\u0000" + canonicalSkeleton)`
 * blind indexing, [MAX_CACHE_ENTRIES] LRU eviction, and tool-schema / profile invalidation.
 */
class ActionCacheDao(
    private val store: EncryptedSqliteStore
) {

    /**
     * Persists [template] if and only if 100% of slot values originated from
     * [DataProvenance.USER_UTTERANCE] and the plan does not touch `Nava Vault`.
     *
     * Throws [SecurityException] if admission policy is violated, then enforces
     * [MAX_CACHE_ENTRIES] LRU eviction.
     */
    suspend fun putTemplate(
        template: CachedActionTemplate,
        provenance: DataProvenance,
        touchesVault: Boolean,
        nowEpochSec: Long
    ): Boolean {
        if (provenance != DataProvenance.USER_UTTERANCE || touchesVault) {
            throw SecurityException(
                "Tier 2 cache admission denied (provenance=$provenance, touchesVault=$touchesVault)"
            )
        }
        val persistedTemplate = template.copy(lastUsedEpochSec = nowEpochSec)
        val lookupHmac = store.computeBlindIndex(
            persistedTemplate.languageCode,
            persistedTemplate.canonicalSkeleton
        )
        val encoded = encodeTemplate(persistedTemplate)
        SecureMemory.withZeroizedBytes(encoded) { payload ->
            store.upsertEncryptedByBlindIndex(
                tableName = EncryptedTableSchema.TABLE_ACTION_CACHE,
                lookupHmac = lookupHmac,
                plaintext = payload,
                epochSec = nowEpochSec,
                schemaVersion = CACHE_ENTRY_SCHEMA_VERSION
            )
        }
        store.evictLru(EncryptedTableSchema.TABLE_ACTION_CACHE, MAX_CACHE_ENTRIES)
        return true
    }

    /**
     * Performs an O(1) blind-index lookup for `(languageCode, canonicalSkeleton)`, refreshes its
     * LRU timestamp via [EncryptedSqliteStore.touchUpdatedEpochSec], and returns the template.
     */
    suspend fun findTemplate(
        languageCode: String,
        canonicalSkeleton: String,
        nowEpochSec: Long
    ): CachedActionTemplate? {
        if (
            languageCode.isBlank() ||
            canonicalSkeleton.isBlank() ||
            '\u0000' in languageCode ||
            '\u0000' in canonicalSkeleton
        ) {
            return null
        }
        val lookupHmac = store.computeBlindIndex(languageCode, canonicalSkeleton)
        val row = store.findDecryptedByBlindIndex(
            tableName = EncryptedTableSchema.TABLE_ACTION_CACHE,
            lookupHmac = lookupHmac
        ) ?: return null

        val decoded = try {
            decodeTemplate(row)
        } finally {
            row.zeroize()
        }
        if (decoded.languageCode != languageCode || decoded.canonicalSkeleton != canonicalSkeleton) {
            return null
        }
        store.touchUpdatedEpochSec(
            tableName = EncryptedTableSchema.TABLE_ACTION_CACHE,
            rowId = row.rowId,
            updatedEpochSec = nowEpochSec
        )
        return decoded.copy(lastUsedEpochSec = nowEpochSec)
    }

    /**
     * Removes cached templates referencing [toolName] whose stored schema version differs from
     * [currentSchemaVersion]. Returns the number of invalidated entries.
     */
    suspend fun invalidateForToolSchemaChange(
        toolName: String,
        currentSchemaVersion: Int
    ): Int {
        require(toolName.isNotBlank()) { "toolName must not be blank" }
        require(currentSchemaVersion > 0) { "currentSchemaVersion must be positive" }

        val rows = store.listAllDecrypted(EncryptedTableSchema.TABLE_ACTION_CACHE)
        val rowIdsToDelete = ArrayList<Long>()
        try {
            for (row in rows) {
                val template = decodeTemplate(row)
                val referencesTool =
                    toolName in template.toolNames || toolName in template.toolSchemaVersions
                if (referencesTool && template.toolSchemaVersions[toolName] != currentSchemaVersion) {
                    rowIdsToDelete.add(row.rowId)
                }
            }
        } finally {
            for (row in rows) {
                row.zeroize()
            }
        }

        var deleted = 0
        for (rowId in rowIdsToDelete) {
            if (store.deleteByRowId(EncryptedTableSchema.TABLE_ACTION_CACHE, rowId)) {
                deleted++
            }
        }
        return deleted
    }

    /** Clears all cached templates (e.g., on `PermissionProfile` change). */
    suspend fun invalidateAll(): Int {
        return store.evictLru(EncryptedTableSchema.TABLE_ACTION_CACHE, 0)
    }

    private fun encodeTemplate(template: CachedActionTemplate): ByteArray {
        val versionsAsStrings = LinkedHashMap<String, String>(template.toolSchemaVersions.size)
        for ((name, version) in template.toolSchemaVersions) {
            versionsAsStrings[name] = version.toString()
        }
        return StructuredPayloadCodec.encode(formatVersion = CACHE_ENTRY_SCHEMA_VERSION) {
            writeString(template.languageCode)
            writeString(template.canonicalSkeleton)
            writeStringList(template.toolNames)
            writeStringMap(versionsAsStrings)
            writeString(template.serializedPlanTemplate)
            writeLong(template.lastUsedEpochSec)
        }
    }

    private fun decodeTemplate(row: DecryptedRow): CachedActionTemplate {
        return StructuredPayloadCodec.decode(
            bytes = row.plaintext,
            expectedVersion = CACHE_ENTRY_SCHEMA_VERSION
        ) {
            val languageCode = readString()
            val canonicalSkeleton = readString()
            val toolNames = readStringList()
            val rawVersions = readStringMap()
            val toolSchemaVersions = LinkedHashMap<String, Int>(rawVersions.size)
            for ((name, rawVer) in rawVersions) {
                toolSchemaVersions[name] = rawVer.toInt()
            }
            val serializedPlanTemplate = readString()
            val lastUsedEpochSec = readLong()
            CachedActionTemplate(
                languageCode = languageCode,
                canonicalSkeleton = canonicalSkeleton,
                toolNames = toolNames,
                toolSchemaVersions = toolSchemaVersions,
                serializedPlanTemplate = serializedPlanTemplate,
                lastUsedEpochSec = lastUsedEpochSec
            )
        }
    }

    companion object {
        const val MAX_CACHE_ENTRIES: Int = 500
        private const val CACHE_ENTRY_SCHEMA_VERSION: Int = 1
    }
}

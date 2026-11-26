package com.nava.core.security.policy

import com.nava.core.security.crypto.CryptoKeyProvider
import com.nava.core.security.crypto.HmacSha256Engine
import com.nava.core.security.crypto.KeyUnavailability
import com.nava.core.security.crypto.RuleSealKeyStore
import com.nava.core.security.crypto.RuleSealKeyStores
import com.nava.core.security.crypto.SecureMemory
import com.nava.core.security.storage.DecryptedRow
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.storage.StructuredPayloadCodec
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleGrantPort
import com.nava.domain.security.RuleTriggerSpec
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.SecretKey
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Encrypted persistent manager for compile-time user-approved [RuleCapabilityGrant] records
 * sealed with constant-time `HMAC-SHA256` integrity tags (PLAN.md Section 5.6).
 */
class RuleCapabilityGrantManager(
    private val store: EncryptedSqliteStore,
    private val keyProvider: CryptoKeyProvider,
    private val hmacEngine: HmacSha256Engine = HmacSha256Engine(),
    private val grantIdGenerator: () -> String = { UUID.randomUUID().toString() },
    private val sealKeyStore: RuleSealKeyStore = RuleSealKeyStores.forProvider(keyProvider)
) : RuleGrantPort {

    /** Set once the per-process seal maintenance pass completed; avoids re-scanning. */
    private val sealMaintenanceDone = AtomicBoolean(false)

    /**
     * Set when a maintenance pass failed because the device was locked. Further passes are not
     * attempted (each would cost a failing decrypt-all under [ruleStateMutex]) until a read
     * succeeds again, which proves the master key is usable.
     */
    @Volatile
    private var maintenanceBlockedByLock: Boolean = false

    /** Cached once true: legacy retirement is permanent. */
    private val legacyRetiredCached = AtomicBoolean(false)

    /** Seal-key aliases are deterministic per (ruleId, grantId); cache them to save HMAC calls. */
    private val sealAliasCache = ConcurrentHashMap<String, String>()

    /**
     * Seal keys whose deletion failed after the owning rule left APPROVED_ACTIVE. Retried on every
     * access until they are gone (anti-rollback must not depend on a single Keystore call).
     */
    private val pendingSealKeyDeletions = ConcurrentHashMap<String, String>() // alias -> ruleId

    private val globalRulesPaused = AtomicBoolean(false)
    private val ruleStateMutex = Mutex()

    /**
     * Exact copy of each grant last written or read through this manager, served ONLY when the
     * `nava_db_master_key` is transiently unavailable (device locked). Background routines fire
     * mostly while the screen is off, and previously failed on every locked-device decrypt.
     * The HMAC seal is still verified on every execution; a cache miss fails closed.
     */
    private val lastKnownGrantByRuleId = ConcurrentHashMap<String, RuleCapabilityGrant>()
    private val grantWriteVersion = AtomicLong(0L)

    /**
     * Writer-only record of the newest grant persisted by this process, updated under
     * [ruleStateMutex] right after the database write. Readers never write it, so a stale copy
     * that an in-flight reader briefly publishes to [lastKnownGrantByRuleId] can never shadow a
     * completed revoke/pause for a locked-device read.
     */
    private val lastWrittenGrantByRuleId = ConcurrentHashMap<String, RuleCapabilityGrant>()

    /** Globally pauses or resumes all background automation rule execution. */
    fun setGlobalRulesPaused(paused: Boolean) {
        globalRulesPaused.set(paused)
    }

    /** Returns true when all background automation routines are globally paused. */
    fun isGlobalRulesPaused(): Boolean = globalRulesPaused.get()

    override suspend fun createPendingRule(
        ruleId: String,
        triggerSpec: RuleTriggerSpec,
        staticActions: List<RuleActionSpec>,
        nowEpochSec: Long
    ): RuleCapabilityGrant {
        require(ruleId.isNotBlank() && NULL_CHAR !in ruleId) {
            "ruleId must be non-blank and must not contain null characters"
        }
        require(staticActions.isNotEmpty()) { "staticActions must not be empty" }
        return ruleStateMutex.withLock {
            // Re-proposing a routine under an existing id replaces its grant. Destroy the replaced
            // grant's seal key so its old APPROVED ciphertext can never verify again.
            val replaced = findRuleUnlocked(ruleId)
            val deleteFailure = replaced?.let { destroySealKeyCapturingFailure(it) }
            val grant = RuleCapabilityGrant(
                grantId = grantIdGenerator(),
                ruleId = ruleId,
                triggerSpec = triggerSpec,
                staticActions = staticActions.toList(),
                approvalState = RuleApprovalState.PENDING_USER_APPROVAL,
                sealHmacHex = "",
                grantedAtEpochSec = 0L
            )
            persistGrant(grant, nowEpochSec)
            deleteFailure?.let { throw it }
            grant
        }
    }

    override suspend fun approveAndSealRule(
        ruleId: String,
        nowEpochSec: Long
    ): RuleCapabilityGrant {
        require(ruleId.isNotBlank() && NULL_CHAR !in ruleId) {
            "ruleId must be non-blank and must not contain null characters"
        }
        return ruleStateMutex.withLock {
            val existing = findRuleUnlocked(ruleId)
                ?: throw SecurityException("Cannot approve missing rule '$ruleId'")
            if (
                existing.approvalState != RuleApprovalState.PENDING_USER_APPROVAL &&
                existing.approvalState != RuleApprovalState.PAUSED
            ) {
                throw SecurityException(
                    "Cannot approve rule '$ruleId' from state ${existing.approvalState}"
                )
            }
            val unsealed = existing.copy(
                approvalState = RuleApprovalState.APPROVED_ACTIVE,
                sealHmacHex = "",
                grantedAtEpochSec = nowEpochSec
            )
            // Each approval gets a brand-new Keystore seal key, so a seal from any earlier approval
            // of this rule can never verify again (anti-rollback, see RuleSealKeyStore).
            val alias = sealKeyAlias(unsealed)
            // A queued retry for this alias belongs to an older approval; never let it delete
            // the key we are about to create.
            pendingSealKeyDeletions.remove(alias)
            val sealKey = sealKeyStore.createFreshSealKey(alias)
            val approved = unsealed.copy(sealHmacHex = computeV2Seal(sealKey, unsealed))
            persistGrant(approved, nowEpochSec)
            approved
        }
    }

    override suspend fun pauseRule(ruleId: String, nowEpochSec: Long) {
        require(ruleId.isNotBlank() && NULL_CHAR !in ruleId) {
            "ruleId must be non-blank and must not contain null characters"
        }
        ruleStateMutex.withLock {
            val existing = findRuleUnlocked(ruleId)
                ?: throw SecurityException("Cannot pause missing rule '$ruleId'")
            if (existing.approvalState == RuleApprovalState.REVOKED) {
                throw SecurityException("Revoked rule '$ruleId' cannot be paused")
            }
            // Destroy the seal key first, then make the state change durable even if the delete
            // failed (the failure is retried and surfaced): a replayed APPROVED row can then
            // never verify again (anti-rollback).
            val deleteFailure = destroySealKeyCapturingFailure(existing)
            val paused = existing.copy(approvalState = RuleApprovalState.PAUSED, sealHmacHex = "")
            persistGrant(paused, nowEpochSec)
            deleteFailure?.let { throw it }
        }
    }

    override suspend fun revokeRule(ruleId: String, nowEpochSec: Long) {
        require(ruleId.isNotBlank() && NULL_CHAR !in ruleId) {
            "ruleId must be non-blank and must not contain null characters"
        }
        ruleStateMutex.withLock {
            val existing = findRuleUnlocked(ruleId) ?: return
            val deleteFailure = destroySealKeyCapturingFailure(existing)
            val revoked = existing.copy(
                approvalState = RuleApprovalState.REVOKED,
                sealHmacHex = ""
            )
            persistGrant(revoked, nowEpochSec)
            deleteFailure?.let { throw it }
        }
    }

    override suspend fun findRule(ruleId: String): RuleCapabilityGrant? {
        if (ruleId.isBlank() || NULL_CHAR in ruleId) return null
        retryPendingSealKeyDeletions()
        if (!maintenanceBlockedByLock) runSealMaintenanceIfNeeded()
        var attempt = 0
        while (true) {
            val versionAtStart = grantWriteVersion.get()
            val found = try {
                findRuleUnlocked(ruleId)
            } catch (ce: CancellationException) {
                throw ce
            } catch (e: Exception) {
                if (KeyUnavailability.isTransient(e)) {
                    (lastWrittenGrantByRuleId[ruleId] ?: lastKnownGrantByRuleId[ruleId])?.let { return it }
                }
                throw e
            }
            if (maintenanceBlockedByLock && !sealMaintenanceDone.get()) {
                // The master key is usable again: finish the deferred maintenance, then re-read
                // because it may have re-sealed this very row.
                maintenanceBlockedByLock = false
                runSealMaintenanceIfNeeded()
                if (!maintenanceBlockedByLock) continue
            }
            if (found == null) {
                lastKnownGrantByRuleId.remove(ruleId)
                return null
            }
            // Publish, then re-check: if any write (e.g. revokeRule) landed while this read was in
            // flight, retract exactly the value we published and re-read the fresh state. Every
            // interleaving therefore ends with the newest grant cached, or no entry (fail closed).
            lastKnownGrantByRuleId.put(ruleId, found)
            if (grantWriteVersion.get() == versionAtStart) {
                return found
            }
            lastKnownGrantByRuleId.remove(ruleId, found)
            attempt++
            if (attempt >= MAX_CACHE_PUBLISH_ATTEMPTS) {
                return found
            }
        }
    }

    override suspend fun listRules(): List<RuleCapabilityGrant> {
        retryPendingSealKeyDeletions()
        runSealMaintenanceIfNeeded()
        val rows = store.listAllDecrypted(EncryptedTableSchema.TABLE_AUTOMATION_RULES)
        return try {
            val grants = ArrayList<RuleCapabilityGrant>(rows.size)
            for (row in rows) {
                grants.add(decodeGrantAndZeroize(row))
            }
            grants
        } finally {
            for (row in rows) {
                row.zeroize()
            }
        }
    }

    private suspend fun findRuleUnlocked(ruleId: String): RuleCapabilityGrant? {
        if (ruleId.isBlank() || NULL_CHAR in ruleId) return null
        val lookupHmac = store.computeBlindIndex(DOMAIN_RULE, ruleId)
        val row = store.findDecryptedByBlindIndex(
            tableName = EncryptedTableSchema.TABLE_AUTOMATION_RULES,
            lookupHmac = lookupHmac
        ) ?: return null
        val decoded = decodeGrantAndZeroize(row)
        return if (decoded.ruleId == ruleId) decoded else null
    }

    /**
     * Returns the v2 seal [grant] would carry under its current Keystore seal key, or an empty
     * string when that key does not exist (never approved, paused, revoked, or rolled back).
     */
    fun computeSeal(grant: RuleCapabilityGrant): String {
        val key = sealKeyStore.findSealKey(sealKeyAlias(grant)) ?: return ""
        return computeV2Seal(key, grant)
    }

    /**
     * Verifies [grant.sealHmacHex] in constant time.
     *
     * - When this approval's Keystore seal key exists, only a v2 seal verifies. v2 covers the full
     *   grant including approval state and approval time. Pausing or revoking deletes the key, so
     *   a replayed old `APPROVED_ACTIVE` ciphertext never verifies again.
     * - Without a seal key, a legacy seal (shared blind-index key, no state coverage) is accepted
     *   only until legacy seals are retired by the one-time upgrade; afterwards a Keystore marker
     *   rejects them permanently.
     */
    fun verifySeal(grant: RuleCapabilityGrant): Boolean {
        val seal = grant.sealHmacHex
        if (seal.isBlank()) return false
        val key = sealKeyStore.findSealKey(sealKeyAlias(grant))
        if (key != null) {
            if (grant.approvalState != RuleApprovalState.APPROVED_ACTIVE) return false
            val payload = encodeV2SealPayload(grant)
            return SecureMemory.withZeroizedBytes(payload) { bytes ->
                hmacEngine.verifyHmacHex(key = key, data = bytes, expectedHex = seal)
            }
        }
        if (legacySealsRetired()) return false
        return verifyLegacySeal(grant)
    }

    private fun legacySealsRetired(): Boolean {
        if (legacyRetiredCached.get()) return true
        val retired = sealKeyStore.areLegacySealsRetired()
        if (retired) legacyRetiredCached.set(true)
        return retired
    }

    private fun verifyV2Seal(grant: RuleCapabilityGrant): Boolean {
        if (grant.sealHmacHex.isBlank() || grant.approvalState != RuleApprovalState.APPROVED_ACTIVE) {
            return false
        }
        val key = sealKeyStore.findSealKey(sealKeyAlias(grant)) ?: return false
        val payload = encodeV2SealPayload(grant)
        return SecureMemory.withZeroizedBytes(payload) { bytes ->
            hmacEngine.verifyHmacHex(key = key, data = bytes, expectedHex = grant.sealHmacHex)
        }
    }

    /**
     * Deletes the seal key of [grant]. If the delete fails, the key is immediately ROTATED (replaced
     * by a fresh random key under the same alias), so the old seal can never verify again even if
     * this process dies before the delete is retried. The failed delete is remembered for retry
     * and returned (not thrown) so callers can still make the state change durable before
     * surfacing it. Must be called while holding [ruleStateMutex].
     */
    private fun destroySealKeyCapturingFailure(grant: RuleCapabilityGrant): Exception? {
        val alias = sealKeyAlias(grant)
        return try {
            sealKeyStore.deleteSealKey(alias)
            pendingSealKeyDeletions.remove(alias)
            null
        } catch (e: Exception) {
            try {
                sealKeyStore.createFreshSealKey(alias)
            } catch (rotationFailure: Exception) {
                e.addSuppressed(rotationFailure)
            }
            pendingSealKeyDeletions[alias] = grant.ruleId
            e
        }
    }

    /**
     * Retries failed seal-key deletions under [ruleStateMutex]. An alias that belongs to the
     * rule's CURRENT approval (the user re-approved meanwhile) is dropped from the queue instead of
     * deleted, so a stale retry can never destroy a live approval's key.
     */
    private suspend fun retryPendingSealKeyDeletions() {
        if (pendingSealKeyDeletions.isEmpty()) return
        try {
            ruleStateMutex.withLock {
                for ((alias, ruleId) in pendingSealKeyDeletions.entries.toList()) {
                    val current = findRuleUnlocked(ruleId)
                    if (
                        current != null &&
                        current.approvalState == RuleApprovalState.APPROVED_ACTIVE &&
                        sealKeyAlias(current) == alias
                    ) {
                        pendingSealKeyDeletions.remove(alias, ruleId)
                        continue
                    }
                    try {
                        sealKeyStore.deleteSealKey(alias)
                        pendingSealKeyDeletions.remove(alias, ruleId)
                    } catch (_: Exception) {
                        // Still failing; the key was rotated, so the old seal is already dead.
                    }
                }
            }
        } catch (ce: CancellationException) {
            throw ce
        } catch (e: Exception) {
            if (!KeyUnavailability.isTransient(e)) throw e
            // Device locked: retried on a later access.
        }
    }

    /** Test hook: the pre-v2 seal format, used to build legacy rows for migration tests. */
    internal fun legacySealForTest(grant: RuleCapabilityGrant): String {
        val payload = encodeCanonicalSealPayload(grant)
        return SecureMemory.withZeroizedBytes(payload) { bytes ->
            hmacEngine.computeHmacHex(keyProvider.getOrCreateBlindIndexKey(), bytes)
        }
    }

    /** Test hook: persists [grant] verbatim, bypassing the approval state machine. */
    internal suspend fun writeGrantRowForTest(grant: RuleCapabilityGrant) {
        ruleStateMutex.withLock {
            persistGrant(grant, grant.grantedAtEpochSec.coerceAtLeast(1L))
        }
    }

    private fun verifyLegacySeal(grant: RuleCapabilityGrant): Boolean {
        val payload = encodeCanonicalSealPayload(grant)
        return SecureMemory.withZeroizedBytes(payload) { bytes ->
            hmacEngine.verifyHmacHex(
                key = keyProvider.getOrCreateBlindIndexKey(),
                data = bytes,
                expectedHex = grant.sealHmacHex
            )
        }
    }

    private fun computeV2Seal(key: SecretKey, grant: RuleCapabilityGrant): String {
        val payload = encodeV2SealPayload(grant)
        return SecureMemory.withZeroizedBytes(payload) { bytes ->
            hmacEngine.computeHmacHex(key, bytes)
        }
    }

    /**
     * Keystore alias of the seal key for one approval of a rule. Derived with the blind-index key
     * (usable while locked) so aliases never expose rule ids.
     */
    private fun sealKeyAlias(grant: RuleCapabilityGrant): String {
        val cacheKey = grant.ruleId + NULL_CHAR + grant.grantId
        sealAliasCache[cacheKey]?.let { return it }
        val payload = StructuredPayloadCodec.encode(formatVersion = SEAL_FORMAT_VERSION_V2) {
            writeString(SEAL_ALIAS_DOMAIN_TAG)
            writeString(grant.ruleId)
            writeString(grant.grantId)
        }
        val digest = SecureMemory.withZeroizedBytes(payload) { bytes ->
            hmacEngine.computeHmacHex(keyProvider.getOrCreateBlindIndexKey(), bytes)
        }
        val alias = RuleSealKeyStore.ALIAS_PREFIX + digest.take(SEAL_ALIAS_DIGEST_CHARS)
        sealAliasCache[cacheKey] = alias
        return alias
    }

    /**
     * Per-process seal maintenance, run lazily on the first unlocked access:
     * 1. Sweep: deletes the seal key of every rule that is not APPROVED_ACTIVE (covers deletes that
     *    failed earlier or in a previous process).
     * 2. Upgrade (until legacy retirement): re-seals every APPROVED_ACTIVE rule whose v2 seal does
     *    not verify but whose legacy seal does, with a fresh seal key. This also completes upgrades
     *    interrupted between key creation and persist.
     * 3. Retires legacy seals permanently.
     * Rows that cannot be decrypted (tampered/corrupted) or decoded are skipped, so one bad row
     * never blocks every routine. While the master key is unavailable (device locked) the pass is
     * deferred until the next successful read ([maintenanceBlockedByLock]).
     *
     * Residual risk (inherent to migrating from a seal that never covered approval state): a
     * legacy APPROVED ciphertext replayed over a revoked row BEFORE the first unlocked run of this
     * version is indistinguishable from a genuine legacy approval and gets upgraded.
     */
    private suspend fun runSealMaintenanceIfNeeded() {
        if (sealMaintenanceDone.get()) return
        try {
            ruleStateMutex.withLock {
                if (sealMaintenanceDone.get()) return@withLock
                val upgradeLegacy = !legacySealsRetired()
                val rows = store.listAllDecryptedSkippingCorrupt(EncryptedTableSchema.TABLE_AUTOMATION_RULES)
                val grants = ArrayList<RuleCapabilityGrant>(rows.size)
                try {
                    for (row in rows) {
                        try {
                            grants.add(decodeGrantAndZeroize(row))
                        } catch (ce: CancellationException) {
                            throw ce
                        } catch (_: Exception) {
                            // Undecodable row: skipped; it can never verify anyway.
                        }
                    }
                } finally {
                    for (row in rows) row.zeroize()
                }
                for (grant in grants) {
                    if (grant.approvalState != RuleApprovalState.APPROVED_ACTIVE) {
                        destroySealKeyCapturingFailure(grant)
                        continue
                    }
                    if (!upgradeLegacy) continue
                    if (grant.sealHmacHex.isBlank() || verifyV2Seal(grant) || !verifyLegacySeal(grant)) {
                        continue
                    }
                    val unsealed = grant.copy(sealHmacHex = "")
                    val sealKey = sealKeyStore.createFreshSealKey(sealKeyAlias(unsealed))
                    val upgraded = unsealed.copy(sealHmacHex = computeV2Seal(sealKey, unsealed))
                    persistGrant(upgraded, grant.grantedAtEpochSec.coerceAtLeast(1L))
                }
                if (upgradeLegacy) {
                    sealKeyStore.retireLegacySeals()
                    legacyRetiredCached.set(true)
                }
                sealMaintenanceDone.set(true)
            }
        } catch (ce: CancellationException) {
            throw ce
        } catch (e: Exception) {
            if (!KeyUnavailability.isTransient(e)) throw e
            // Device locked: legacy seals stay accepted until the next unlocked access.
            maintenanceBlockedByLock = true
        }
    }

    private suspend fun persistGrant(grant: RuleCapabilityGrant, epochSec: Long) {
        val encoded = encodeGrant(grant)
        SecureMemory.withZeroizedBytes(encoded) { payload ->
            val lookupHmac = store.computeBlindIndex(DOMAIN_RULE, grant.ruleId)
            store.upsertEncryptedByBlindIndex(
                tableName = EncryptedTableSchema.TABLE_AUTOMATION_RULES,
                lookupHmac = lookupHmac,
                plaintext = payload,
                epochSec = epochSec,
                schemaVersion = RULE_SCHEMA_VERSION
            )
        }
        lastWrittenGrantByRuleId[grant.ruleId] = grant
        grantWriteVersion.incrementAndGet()
        lastKnownGrantByRuleId[grant.ruleId] = grant
    }

    private fun encodeCanonicalSealPayload(grant: RuleCapabilityGrant): ByteArray {
        return StructuredPayloadCodec.encode(formatVersion = SEAL_FORMAT_VERSION) {
            writeString(SEAL_DOMAIN_TAG)
            writeString(grant.grantId)
            writeString(grant.ruleId)
            writeString(grant.triggerSpec.triggerType)
            writeStringMap(grant.triggerSpec.parameters)
            writeInt(grant.staticActions.size)
            for (action in grant.staticActions) {
                writeString(action.toolName)
                writeString(action.requiredCapability.name)
                writeStringMap(action.staticArguments)
                writeBoolean(action.requiresBiometric)
            }
        }
    }

    /** v2 seal payload: the legacy canonical fields plus approval state and approval time. */
    private fun encodeV2SealPayload(grant: RuleCapabilityGrant): ByteArray {
        return StructuredPayloadCodec.encode(formatVersion = SEAL_FORMAT_VERSION_V2) {
            writeString(SEAL_V2_DOMAIN_TAG)
            writeString(grant.grantId)
            writeString(grant.ruleId)
            writeString(grant.triggerSpec.triggerType)
            writeStringMap(grant.triggerSpec.parameters)
            writeInt(grant.staticActions.size)
            for (action in grant.staticActions) {
                writeString(action.toolName)
                writeString(action.requiredCapability.name)
                writeStringMap(action.staticArguments)
                writeBoolean(action.requiresBiometric)
            }
            writeString(grant.approvalState.name)
            writeLong(grant.grantedAtEpochSec)
        }
    }

    private fun encodeGrant(grant: RuleCapabilityGrant): ByteArray {
        return StructuredPayloadCodec.encode(formatVersion = RULE_SCHEMA_VERSION) {
            writeString(grant.grantId)
            writeString(grant.ruleId)
            writeString(grant.triggerSpec.triggerType)
            writeStringMap(grant.triggerSpec.parameters)
            writeInt(grant.staticActions.size)
            for (action in grant.staticActions) {
                writeString(action.toolName)
                writeString(action.requiredCapability.name)
                writeStringMap(action.staticArguments)
                writeBoolean(action.requiresBiometric)
            }
            writeString(grant.approvalState.name)
            writeString(grant.sealHmacHex)
            writeLong(grant.grantedAtEpochSec)
        }
    }

    private fun decodeGrantAndZeroize(row: DecryptedRow): RuleCapabilityGrant {
        return try {
            StructuredPayloadCodec.decode(
                bytes = row.plaintext,
                expectedVersion = RULE_SCHEMA_VERSION
            ) {
                val grantId = readString()
                val ruleId = readString()
                val triggerType = readString()
                val triggerParams = readStringMap()
                val actionCount = readInt()
                require(actionCount in 1..StructuredPayloadCodec.MAX_COLLECTION_SIZE) {
                    "Invalid persisted rule action count: $actionCount"
                }
                val actions = ArrayList<RuleActionSpec>(actionCount)
                repeat(actionCount) {
                    val toolName = readString()
                    val capability = AtomicCapability.valueOf(readString())
                    val staticArgs = readStringMap()
                    val requiresBiometric = readBoolean()
                    actions.add(
                        RuleActionSpec(
                            toolName = toolName,
                            requiredCapability = capability,
                            staticArguments = staticArgs,
                            requiresBiometric = requiresBiometric
                        )
                    )
                }
                val approvalState = RuleApprovalState.valueOf(readString())
                val sealHmacHex = readString()
                val grantedAtEpochSec = readLong()
                RuleCapabilityGrant(
                    grantId = grantId,
                    ruleId = ruleId,
                    triggerSpec = RuleTriggerSpec(
                        triggerType = triggerType,
                        parameters = triggerParams
                    ),
                    staticActions = actions,
                    approvalState = approvalState,
                    sealHmacHex = sealHmacHex,
                    grantedAtEpochSec = grantedAtEpochSec
                )
            }
        } finally {
            row.zeroize()
        }
    }

    companion object {
        private const val MAX_CACHE_PUBLISH_ATTEMPTS: Int = 3
        private const val DOMAIN_RULE: String = "rule"
        private const val SEAL_DOMAIN_TAG: String = "nava:rule_grant_seal:v1"
        private const val SEAL_FORMAT_VERSION: Int = 1
        private const val SEAL_FORMAT_VERSION_V2: Int = 2
        private const val SEAL_V2_DOMAIN_TAG: String = "nava:rule_grant_seal:v2"
        private const val SEAL_ALIAS_DOMAIN_TAG: String = "nava:rule_grant_seal_alias:v2"
        private const val SEAL_ALIAS_DIGEST_CHARS: Int = 40
        private const val RULE_SCHEMA_VERSION: Int = 1
        private const val NULL_CHAR: Char = '\u0000'
    }
}

package com.nava.core.security.policy

import com.nava.core.security.crypto.CryptoKeyProvider
import com.nava.core.security.crypto.HmacSha256Engine
import com.nava.core.security.crypto.KeyUnavailability
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
    private val grantIdGenerator: () -> String = { UUID.randomUUID().toString() }
) : RuleGrantPort {

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
            val sealHex = computeSeal(existing)
            val approved = existing.copy(
                approvalState = RuleApprovalState.APPROVED_ACTIVE,
                sealHmacHex = sealHex,
                grantedAtEpochSec = nowEpochSec
            )
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
            val paused = existing.copy(approvalState = RuleApprovalState.PAUSED)
            persistGrant(paused, nowEpochSec)
        }
    }

    override suspend fun revokeRule(ruleId: String, nowEpochSec: Long) {
        require(ruleId.isNotBlank() && NULL_CHAR !in ruleId) {
            "ruleId must be non-blank and must not contain null characters"
        }
        ruleStateMutex.withLock {
            val existing = findRuleUnlocked(ruleId) ?: return
            val revoked = existing.copy(
                approvalState = RuleApprovalState.REVOKED,
                sealHmacHex = ""
            )
            persistGrant(revoked, nowEpochSec)
        }
    }

    override suspend fun findRule(ruleId: String): RuleCapabilityGrant? {
        if (ruleId.isBlank() || NULL_CHAR in ruleId) return null
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
     * Computes the canonical `HMAC-SHA256` seal over `(grantId, ruleId, triggerSpec, staticActions)`.
     */
    fun computeSeal(grant: RuleCapabilityGrant): String {
        val payload = encodeCanonicalSealPayload(grant)
        return SecureMemory.withZeroizedBytes(payload) { bytes ->
            hmacEngine.computeHmacHex(keyProvider.getOrCreateBlindIndexKey(), bytes)
        }
    }

    /**
     * Verifies [grant.sealHmacHex] in constant time against a freshly computed canonical seal.
     */
    fun verifySeal(grant: RuleCapabilityGrant): Boolean {
        if (grant.sealHmacHex.isBlank()) return false
        val payload = encodeCanonicalSealPayload(grant)
        return SecureMemory.withZeroizedBytes(payload) { bytes ->
            hmacEngine.verifyHmacHex(
                key = keyProvider.getOrCreateBlindIndexKey(),
                data = bytes,
                expectedHex = grant.sealHmacHex
            )
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
        private const val RULE_SCHEMA_VERSION: Int = 1
        private const val NULL_CHAR: Char = '\u0000'
    }
}

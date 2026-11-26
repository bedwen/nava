package com.nava.core.security.redteam

import com.nava.core.security.crypto.CryptoKeyProvider
import com.nava.core.security.crypto.InMemoryRuleSealKeyStore
import com.nava.core.security.crypto.RuleSealKeyStore
import com.nava.core.security.dao.AuditLogDao
import com.nava.core.security.firewall.SecurityFirewall
import com.nava.core.security.policy.PermissionProfileManager
import com.nava.core.security.policy.RuleCapabilityGrantManager
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.testing.InMemoryRowStorage
import com.nava.core.security.testing.InMemorySoftwareKeyProvider
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleTriggerSpec
import java.security.InvalidKeyException
import java.util.Collections
import javax.crypto.AEADBadTagException
import javax.crypto.SecretKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Ignore
import org.junit.Test

/**
 * Gate 2 independent adversarial suite for the per-approval Keystore seal keys that fix same-row
 * ciphertext rollback of [RuleCapabilityGrant] rows (PLAN.md Sections 5.5, 5.6 and 8.3).
 *
 * Threat model: the attacker can read and write the app's database file (e.g. root or a
 * filesystem exploit) and replays earlier ciphertexts into the same row, but cannot read or
 * restore Android Keystore entries.
 */
class RuleSealAntiRollbackGate2RedTeamTest {

    private class LockableKeyProvider(
        private val delegate: CryptoKeyProvider = InMemorySoftwareKeyProvider()
    ) : CryptoKeyProvider by delegate {
        @Volatile
        var deviceLocked: Boolean = false

        @Volatile
        var permanentFailure: Throwable? = null

        override fun getOrCreateDbMasterKey(): SecretKey {
            permanentFailure?.let { throw it }
            if (deviceLocked) throw InvalidKeyException("Key user not authenticated (device locked)")
            return delegate.getOrCreateDbMasterKey()
        }
    }

    /** Observable / fault-injecting [RuleSealKeyStore] standing in for Android Keystore. */
    private class HookedSealKeyStore(
        private val delegate: InMemoryRuleSealKeyStore = InMemoryRuleSealKeyStore()
    ) : RuleSealKeyStore {
        val createdAliases: MutableList<String> = Collections.synchronizedList(ArrayList())
        val deletedAliases: MutableList<String> = Collections.synchronizedList(ArrayList())

        @Volatile
        var deleteFault: Throwable? = null

        @Volatile
        var afterCreate: ((String) -> Unit)? = null

        override fun createFreshSealKey(alias: String): SecretKey {
            val key = delegate.createFreshSealKey(alias)
            createdAliases.add(alias)
            afterCreate?.invoke(alias)
            return key
        }

        override fun findSealKey(alias: String): SecretKey? = delegate.findSealKey(alias)

        override fun deleteSealKey(alias: String) {
            deleteFault?.let { throw it }
            deletedAliases.add(alias)
            delegate.deleteSealKey(alias)
        }

        override fun areLegacySealsRetired(): Boolean = delegate.areLegacySealsRetired()

        override fun retireLegacySeals() = delegate.retireLegacySeals()
    }

    /** Mirrors `android.security.keystore.KeyPermanentlyInvalidatedException` (extends InvalidKeyException). */
    private class KeyPermanentlyInvalidatedExceptionDouble : InvalidKeyException("Key permanently invalidated")

    private class Fixture(
        val storage: InMemoryRowStorage,
        val keys: LockableKeyProvider,
        val store: EncryptedSqliteStore,
        val seals: HookedSealKeyStore
    ) {
        private var counter = 0

        fun manager(grantIds: (() -> String)? = null): RuleCapabilityGrantManager = RuleCapabilityGrantManager(
            store = store,
            keyProvider = keys,
            grantIdGenerator = grantIds ?: { "grant_${++counter}" },
            sealKeyStore = seals
        )
    }

    private fun fixture(): Fixture {
        val storage = InMemoryRowStorage()
        val keys = LockableKeyProvider()
        val store = EncryptedSqliteStore(storage = storage, keyProvider = keys, dispatcher = Dispatchers.Unconfined)
        return Fixture(storage, keys, store, HookedSealKeyStore())
    }

    private val actions = listOf(
        RuleActionSpec(toolName = "set_dnd", requiredCapability = AtomicCapability.CREATE_DRAFT)
    )

    private suspend fun RuleCapabilityGrantManager.pending(ruleId: String, now: Long = 100L) =
        createPendingRule(ruleId, RuleTriggerSpec(triggerType = "CHARGING"), actions, now)

    private fun rawRule(f: Fixture): ByteArray =
        f.storage.allRawRows(EncryptedTableSchema.TABLE_AUTOMATION_RULES).single().payloadBlob

    private fun replay(f: Fixture, blob: ByteArray) {
        val row = f.storage.allRawRows(EncryptedTableSchema.TABLE_AUTOMATION_RULES).single()
        assertTrue(f.storage.replaceRawBlob(EncryptedTableSchema.TABLE_AUTOMATION_RULES, row.rowId, blob))
    }

    /** True when the stored rule would pass the manager-side checks an executor performs. */
    private suspend fun executable(rules: RuleCapabilityGrantManager, ruleId: String): Boolean {
        val g = try {
            rules.findRule(ruleId)
        } catch (_: AEADBadTagException) {
            null
        } ?: return false
        return g.approvalState == RuleApprovalState.APPROVED_ACTIVE && rules.verifySeal(g)
    }

    private fun firewall(f: Fixture, rules: RuleCapabilityGrantManager) = SecurityFirewall(
        permissionEvaluator = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L }),
        ruleGrantManager = rules,
        auditLog = AuditLogDao(f.store),
        clockMs = { 1_000_000L }
    )

    private fun reasonOf(decision: FirewallDecision): String? = (decision as? FirewallDecision.Denied)?.reasonCode

    /** Writes a pre-v2 (legacy-sealed) APPROVED_ACTIVE row, as the previous app version did. */
    private suspend fun writeLegacyApproved(rules: RuleCapabilityGrantManager, ruleId: String): RuleCapabilityGrant {
        val pending = rules.pending(ruleId)
        val unsealed = pending.copy(approvalState = RuleApprovalState.APPROVED_ACTIVE, grantedAtEpochSec = 200L)
        val legacy = unsealed.copy(sealHmacHex = rules.legacySealForTest(unsealed))
        rules.writeGrantRowForTest(legacy)
        return legacy
    }

    // ---------------------------------------------------------------------------------------
    // 1. Same-row rollback across the approval state machine
    // ---------------------------------------------------------------------------------------

    @Test
    fun rollbackAcrossApprovePauseReapproveRevoke_neverRevivesAnyEarlierApproval() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("r")
        rules.approveAndSealRule("r", 200L)
        val approved1 = rawRule(f)
        rules.pauseRule("r", 250L)
        val paused = rawRule(f)
        rules.approveAndSealRule("r", 300L)
        val approved2 = rawRule(f)
        assertTrue(executable(rules, "r"))

        // While approval #2 is live, approval #1 must not verify.
        replay(f, approved1)
        assertFalse("approval #1 replayed over live approval #2", executable(rules, "r"))
        replay(f, approved2)
        assertTrue(executable(rules, "r"))

        rules.revokeRule("r", 400L)
        for ((name, blob) in listOf("approved1" to approved1, "paused" to paused, "approved2" to approved2)) {
            replay(f, blob)
            assertFalse("replayed $name after revoke must not be executable", executable(rules, "r"))
            assertFalse("fresh manager, replayed $name", executable(f.manager(), "r"))
        }
    }

    @Test
    fun rollbackAfterPause_isRejectedAndReapprovalStillWorks() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("r")
        rules.approveAndSealRule("r", 200L)
        val approved = rawRule(f)
        rules.pauseRule("r", 250L)
        replay(f, approved)
        assertFalse(executable(rules, "r"))
        // The replayed row is APPROVED, so re-approval from it is refused; the user re-approves
        // from the real PAUSED state only after the attacker's row is gone.
        assertTrue(runCatching { rules.approveAndSealRule("r", 260L) }.isFailure)
    }

    @Test
    fun crossRowReplayOfAnotherRule_isRejectedByAad() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("victim")
        rules.pending("attacker")
        rules.approveAndSealRule("attacker", 200L)
        val rows = f.storage.allRawRows(EncryptedTableSchema.TABLE_AUTOMATION_RULES)
        val victimRow = rows.first()
        val attackerRow = rows.last()
        f.storage.replaceRawBlob(EncryptedTableSchema.TABLE_AUTOMATION_RULES, victimRow.rowId, attackerRow.payloadBlob)
        try {
            rules.findRule("victim")
            fail("cross-row replay must raise AEADBadTagException")
        } catch (_: AEADBadTagException) {
        }
    }

    @Test
    fun reproposedRule_oldApprovalReplayMustNotVerify() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("night_quiet")
        rules.approveAndSealRule("night_quiet", 200L)
        val oldApproved = rawRule(f)

        // The user re-proposes a routine with the same name: it must wait for a new approval.
        val repro = rules.pending("night_quiet", now = 300L)
        assertEquals(RuleApprovalState.PENDING_USER_APPROVAL, repro.approvalState)
        assertFalse(executable(rules, "night_quiet"))

        replay(f, oldApproved)
        assertFalse("old approval replayed over a re-proposed pending rule", executable(rules, "night_quiet"))
        val replayed = rules.findRule("night_quiet")!!
        assertEquals(
            SecurityFirewall.DECISION_RULE_SEAL_INVALID,
            reasonOf(firewall(f, rules).authorizeRuleExecution(replayed))
        )
    }

    // ---------------------------------------------------------------------------------------
    // 2. Seal verification semantics
    // ---------------------------------------------------------------------------------------

    @Test
    fun verifySeal_withLiveKeyRejectsEveryNonApprovedOrAlteredCopy() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("r")
        val approved = rules.approveAndSealRule("r", 200L)
        assertTrue(rules.verifySeal(approved))

        val forged = listOf(
            approved.copy(approvalState = RuleApprovalState.PAUSED),
            approved.copy(approvalState = RuleApprovalState.REVOKED),
            approved.copy(approvalState = RuleApprovalState.PENDING_USER_APPROVAL),
            approved.copy(grantedAtEpochSec = 201L),
            approved.copy(grantId = "grant_other"),
            approved.copy(triggerSpec = RuleTriggerSpec("ALWAYS")),
            approved.copy(staticActions = listOf(actions.single().copy(requiresBiometric = true))),
            approved.copy(sealHmacHex = approved.sealHmacHex.dropLast(1) + (if (approved.sealHmacHex.endsWith("0")) "1" else "0")),
            approved.copy(sealHmacHex = rules.legacySealForTest(approved)),
            approved.copy(sealHmacHex = "")
        )
        for (g in forged) {
            assertFalse("forged copy verified: $g", rules.verifySeal(g))
        }
    }

    @Test
    fun pauseOrRevokeWithKeyStillPresent_neverVerifies() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("r")
        val approved = rules.approveAndSealRule("r", 200L)
        f.seals.deleteFault = IllegalStateException("keystore delete failed")
        assertTrue(runCatching { rules.pauseRule("r", 250L) }.isFailure)
        // The key survived; PAUSED / REVOKED copies with the old seal must still never verify.
        assertFalse(rules.verifySeal(approved.copy(approvalState = RuleApprovalState.PAUSED)))
        assertFalse(rules.verifySeal(approved.copy(approvalState = RuleApprovalState.REVOKED)))
        assertFalse(executable(rules, "r"))
    }

    @Test
    fun revokeWithFailingKeyDeletion_isDurableSurfacedAndRetryRestoresAntiRollback() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("r")
        rules.approveAndSealRule("r", 200L)
        val approved = rawRule(f)

        f.seals.deleteFault = IllegalStateException("keystore delete failed")
        val outcome = runCatching { rules.revokeRule("r", 300L) }
        assertTrue("seal-key deletion failure must be surfaced", outcome.isFailure)
        assertEquals("revoke must be durable", RuleApprovalState.REVOKED, f.manager().findRule("r")?.approvalState)
        assertEquals(RuleApprovalState.REVOKED, rules.findRule("r")?.approvalState)
        f.keys.deviceLocked = true
        assertEquals(RuleApprovalState.REVOKED, rules.findRule("r")?.approvalState)
        f.keys.deviceLocked = false

        // Retrying the revoke deletes the surviving key; afterwards rollback is dead.
        f.seals.deleteFault = null
        rules.revokeRule("r", 301L)
        replay(f, approved)
        assertFalse(executable(rules, "r"))
    }

    @Test
    fun sealKeyAliases_areDomainSeparatedUniqueAndOpaque() = runBlocking {
        val f = fixture()
        val ids = ArrayDeque(listOf("bc", "c", "\u0000", "x", "y:z", "y"))
        val rules = f.manager { ids.removeFirst() }
        val pairs = listOf("a" to "bc", "ab" to "c", "abc" to "\u0000", "q\u0000" to "x", "y" to "y:z", "y:z" to "y")
        for ((ruleId, _) in pairs) {
            if ('\u0000' in ruleId) {
                assertTrue(runCatching { rules.pending(ruleId) }.isFailure)
                ids.removeFirst()
                continue
            }
            rules.pending(ruleId)
            rules.approveAndSealRule(ruleId, 200L)
        }
        val aliases = f.seals.createdAliases
        assertEquals(5, aliases.size)
        assertEquals("aliases must be unique", aliases.size, aliases.toSet().size)
        for (alias in aliases) {
            assertTrue(alias.startsWith(RuleSealKeyStore.ALIAS_PREFIX))
            val suffix = alias.removePrefix(RuleSealKeyStore.ALIAS_PREFIX)
            assertTrue("opaque hex suffix: $alias", suffix.matches(Regex("[0-9a-f]{40}")))
            assertFalse(alias.contains("legacy_retired"))
        }
        // Every approved rule still verifies independently.
        for (ruleId in listOf("a", "ab", "abc", "y", "y:z")) assertTrue(ruleId, executable(rules, ruleId))
    }

    // ---------------------------------------------------------------------------------------
    // 3. Legacy seal migration
    // ---------------------------------------------------------------------------------------

    @Test
    fun legacyRowReplayAfterRetirement_isRejected() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        writeLegacyApproved(rules, "r")
        val legacyBlob = rawRule(f)

        // First unlocked access upgrades and retires legacy seals.
        assertTrue(executable(rules, "r"))
        assertTrue(f.seals.areLegacySealsRetired())
        assertNotEquals("row must have been re-sealed", legacyBlob.toList(), rawRule(f).toList())

        // Legacy row replayed while the v2 approval is live: rejected.
        replay(f, legacyBlob)
        assertFalse(executable(rules, "r"))
        assertFalse(executable(f.manager(), "r"))

        rules.revokeRule("r", 300L)
        replay(f, legacyBlob)
        assertFalse(executable(rules, "r"))
        assertFalse(executable(f.manager(), "r"))
    }

    @Test
    fun freshInstall_retiresLegacyAtFirstUnlockedAccessSoCraftedLegacySealsNeverVerify() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.listRules()
        assertTrue(f.seals.areLegacySealsRetired())
        // A row crafted later with a legacy-format seal (e.g. written by a downgraded build).
        val legacy = writeLegacyApproved(rules, "late")
        assertFalse(rules.verifySeal(legacy))
        assertFalse(executable(rules, "late"))
    }

    @Test
    fun upgradeSkipsRevokedPausedAndForgedLegacyRows() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        val good = writeLegacyApproved(rules, "good")
        val forgedPending = rules.pending("forged")
        rules.writeGrantRowForTest(
            forgedPending.copy(approvalState = RuleApprovalState.APPROVED_ACTIVE, sealHmacHex = "ab".repeat(32))
        )
        val pausedPending = rules.pending("paused")
        val pausedUnsealed = pausedPending.copy(approvalState = RuleApprovalState.PAUSED)
        rules.writeGrantRowForTest(pausedUnsealed.copy(sealHmacHex = rules.legacySealForTest(pausedUnsealed)))

        rules.listRules()
        assertTrue(executable(rules, "good"))
        assertFalse("forged legacy seal must not be upgraded", executable(rules, "forged"))
        assertFalse("paused legacy row must not be upgraded", executable(rules, "paused"))
        assertEquals(1, f.seals.createdAliases.size)
        assertNotNull(good)
    }

    @Test
    fun upgradeWhileLocked_isSkippedAndLegacyKeepsWorkingUntilUnlock() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        writeLegacyApproved(rules, "r")
        val warm = f.manager()
        f.keys.deviceLocked = true
        // Cold manager while locked fails closed; nothing retired.
        assertTrue(runCatching { warm.findRule("r") }.isFailure)
        assertFalse(f.seals.areLegacySealsRetired())
        f.keys.deviceLocked = false
        assertTrue(executable(warm, "r"))
        assertTrue(f.seals.areLegacySealsRetired())
        f.keys.deviceLocked = true
        assertTrue("upgraded routine must verify while locked", executable(warm, "r"))
    }

    @Test
    fun upgradeInterruptedByLockMidway_legitRoutineStillVerifiesAfterUnlock() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        writeLegacyApproved(rules, "r")
        f.seals.afterCreate = { f.keys.deviceLocked = true }
        runCatching { rules.listRules() }
        f.seals.afterCreate = null
        f.keys.deviceLocked = false
        assertTrue("legitimately approved legacy routine must survive the migration", executable(rules, "r"))
    }

    @Test
    @Ignore(
        "GATE2-RESIDUAL (LOW, inherent to migrating unauthenticated legacy state): a legacy APPROVED row " +
            "replayed over a legacy REVOKED row BEFORE the first unlocked access of the new build verifies " +
            "while locked and is then re-sealed as a genuine v2 approval by upgradeLegacySealsIfNeeded"
    )
    fun legacyRollbackBeforeMigration_isNotLaunderedIntoV2() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        val legacy = writeLegacyApproved(rules, "r")
        val legacyApprovedBlob = rawRule(f)
        rules.writeGrantRowForTest(legacy.copy(approvalState = RuleApprovalState.REVOKED, sealHmacHex = ""))
        replay(f, legacyApprovedBlob) // attacker acts before the new build ever ran unlocked
        assertFalse("revoked legacy routine revived by pre-migration rollback", executable(rules, "r"))
    }

    @Test
    fun concurrentRevokeAndUpgradeInOneManager_revocationAlwaysWins() = runBlocking {
        repeat(20) { iteration ->
            val f = fixture()
            val rules = f.manager()
            val ruleIds = (1..5).map { "r$it" }
            for (id in ruleIds) writeLegacyApproved(rules, id)
            val legacyRows = f.storage.allRawRows(EncryptedTableSchema.TABLE_AUTOMATION_RULES).associate { it.rowId to it.payloadBlob }
            withTimeout(20_000L) {
                withContext(Dispatchers.Default) {
                    val jobs = ruleIds.map { id -> async { rules.revokeRule(id, 900L) } } +
                        (1..4).map { async { rules.listRules() } } +
                        ruleIds.map { id -> async { rules.findRule(id) } }
                    jobs.awaitAll()
                }
            }
            for (id in ruleIds) {
                assertEquals("iteration $iteration $id", RuleApprovalState.REVOKED, f.manager().findRule(id)?.approvalState)
            }
            // Replaying every captured legacy row after the race: nothing becomes executable.
            for ((rowId, blob) in legacyRows) {
                f.storage.replaceRawBlob(EncryptedTableSchema.TABLE_AUTOMATION_RULES, rowId, blob)
            }
            for (id in ruleIds) assertFalse("iteration $iteration $id", executable(rules, id))
        }
    }

    // ---------------------------------------------------------------------------------------
    // 4. Locked device and firewall end to end
    // ---------------------------------------------------------------------------------------

    @Test
    fun lockedDevice_sealVerificationWorksAndPauseWinsAfterLock() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("r")
        val approved = rules.approveAndSealRule("r", 200L)
        val fw = firewall(f, rules)
        f.keys.deviceLocked = true
        assertTrue(executable(rules, "r"))
        assertNotEquals(SecurityFirewall.DECISION_RULE_SEAL_INVALID, reasonOf(fw.authorizeRuleExecution(approved)))
        f.keys.deviceLocked = false
        rules.pauseRule("r", 250L)
        f.keys.deviceLocked = true
        assertFalse(executable(rules, "r"))
        assertNotEquals(FirewallDecision.Authorized, fw.authorizeRuleExecution(approved))
    }

    @Test
    fun firewallEndToEnd_replayedRevokedRowIsDeniedAsSealInvalid() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("r")
        val approved = rules.approveAndSealRule("r", 200L)
        val fw = firewall(f, rules)
        assertNotEquals(SecurityFirewall.DECISION_RULE_SEAL_INVALID, reasonOf(fw.authorizeRuleExecution(approved)))
        val approvedBlob = rawRule(f)
        rules.revokeRule("r", 300L)
        replay(f, approvedBlob)

        for (manager in listOf(rules, f.manager())) {
            val replayed = manager.findRule("r")!!
            assertEquals(RuleApprovalState.APPROVED_ACTIVE, replayed.approvalState)
            val decision = firewall(f, manager).authorizeRuleExecution(replayed)
            assertEquals(SecurityFirewall.DECISION_RULE_SEAL_INVALID, reasonOf(decision))
        }
        f.keys.deviceLocked = true
        assertNotEquals(FirewallDecision.Authorized, fw.authorizeRuleExecution(approved))
    }
    // ---------------------------------------------------------------------------------------
    // 5. Re-check of the remediation: delete failures, maintenance sweep, deferral
    // ---------------------------------------------------------------------------------------

    @Test
    fun reproposeWithDeleteFailure_isDurableSurfacedAndRetryKillsReplay() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("r")
        rules.approveAndSealRule("r", 200L)
        val oldApproved = rawRule(f)

        f.seals.deleteFault = IllegalStateException("keystore delete failed")
        val outcome = runCatching { rules.pending("r", now = 300L) }
        assertTrue("delete failure must be surfaced", outcome.isFailure)
        assertEquals(
            "re-proposal must be durable",
            RuleApprovalState.PENDING_USER_APPROVAL,
            f.manager().findRule("r")?.approvalState
        )

        // Keystore recovers; the next access retries the pending deletion before reading.
        f.seals.deleteFault = null
        replay(f, oldApproved)
        assertFalse("old approval replayed after retried deletion", executable(rules, "r"))
    }

    @Test
    @Ignore(
        "GATE2-DEFECT (LOW, DB-write attacker + Keystore delete failure): pendingSealKeyDeletions is " +
            "process memory only and the maintenance sweep derives aliases from the CURRENT row; after a " +
            "re-proposal whose key delete failed, the old grantId's key is orphaned forever in a new process " +
            "and a replayed old APPROVED row verifies"
    )
    fun reproposeDeleteFailedInPreviousProcess_oldApprovalNeverVerifiesInNewProcess() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("r")
        rules.approveAndSealRule("r", 200L)
        val oldApproved = rawRule(f)
        f.seals.deleteFault = IllegalStateException("keystore delete failed")
        runCatching { rules.pending("r", now = 300L) }
        f.seals.deleteFault = null

        // Process restart: a new manager over the same Keystore-backed seal store.
        val restarted = f.manager()
        assertFalse(executable(restarted, "r"))
        replay(f, oldApproved)
        assertFalse("orphaned seal key revived the replaced approval", executable(restarted, "r"))
        assertFalse(executable(f.manager(), "r"))
    }

    @Test
    @Ignore(
        "GATE2-DEFECT (LOW, DB-write attacker + Keystore delete failure): when a revoke's key delete failed " +
            "in a previous process, an APPROVED row replayed BEFORE the new process's maintenance sweep is " +
            "seen as APPROVED_ACTIVE with a valid v2 seal, so the sweep keeps the key and the rule runs"
    )
    fun revokeDeleteFailedInPreviousProcess_replayBeforeSweepNeverVerifies() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("r")
        rules.approveAndSealRule("r", 200L)
        val approved = rawRule(f)
        f.seals.deleteFault = IllegalStateException("keystore delete failed")
        assertTrue(runCatching { rules.revokeRule("r", 300L) }.isFailure)
        f.seals.deleteFault = null

        replay(f, approved) // attacker acts while the app is not running
        val restarted = f.manager()
        assertFalse("revoked rule revived after failed key deletion", executable(restarted, "r"))
    }

    @Test
    fun revokeDeleteFailedInPreviousProcess_sweepDeletesKeyBeforeAnyReplay() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("r")
        rules.approveAndSealRule("r", 200L)
        val approved = rawRule(f)
        f.seals.deleteFault = IllegalStateException("keystore delete failed")
        assertTrue(runCatching { rules.revokeRule("r", 300L) }.isFailure)
        f.seals.deleteFault = null

        val restarted = f.manager()
        assertEquals(RuleApprovalState.REVOKED, restarted.findRule("r")?.approvalState) // runs the sweep
        replay(f, approved)
        assertFalse(executable(restarted, "r"))
        assertFalse(executable(f.manager(), "r"))
    }

    @Test
    fun pauseWithPersistentDeleteFailure_isRetriedOnEveryAccessUntilItSucceeds() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("r")
        rules.approveAndSealRule("r", 200L)
        val approved = rawRule(f)
        f.seals.deleteFault = IllegalStateException("keystore delete failed")
        assertTrue(runCatching { rules.pauseRule("r", 250L) }.isFailure)
        repeat(3) { assertEquals(RuleApprovalState.PAUSED, rules.findRule("r")?.approvalState) }
        assertTrue(f.seals.deletedAliases.isEmpty())
        f.seals.deleteFault = null
        rules.listRules()
        assertEquals(1, f.seals.deletedAliases.toSet().size)
        replay(f, approved)
        assertFalse(executable(rules, "r"))
    }

    @Test
    fun tamperedRowDuringMaintenance_isSkippedAndOtherRulesUpgrade() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        writeLegacyApproved(rules, "bad")
        writeLegacyApproved(rules, "good")
        val badRow = f.storage.allRawRows(EncryptedTableSchema.TABLE_AUTOMATION_RULES).first()
        val blob = badRow.payloadBlob.copyOf()
        blob[blob.size - 1] = (blob[blob.size - 1].toInt() xor 1).toByte()
        f.storage.replaceRawBlob(EncryptedTableSchema.TABLE_AUTOMATION_RULES, badRow.rowId, blob)

        val fresh = f.manager()
        assertTrue("good rule must upgrade despite a tampered sibling", executable(fresh, "good"))
        assertTrue(f.seals.areLegacySealsRetired())
        assertFalse(executable(fresh, "bad"))
    }

    @Test
    @Ignore(
        "GATE2-DEFECT (LOW, availability): EncryptedSqliteStore.listAllDecryptedSkippingCorrupt only skips " +
            "GeneralSecurityException; a truncated rule ciphertext raises IllegalArgumentException from " +
            "AesGcmCryptoEngine.decrypt, so seal maintenance throws and every findRule of every routine fails"
    )
    fun truncatedRowDuringMaintenance_doesNotBlockOtherRoutines() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("bad")
        rules.pending("good")
        rules.approveAndSealRule("good", 200L)
        val badRow = f.storage.allRawRows(EncryptedTableSchema.TABLE_AUTOMATION_RULES).first()
        f.storage.replaceRawBlob(EncryptedTableSchema.TABLE_AUTOMATION_RULES, badRow.rowId, ByteArray(10))

        val fresh = f.manager()
        val outcome = runCatching { executable(fresh, "good") }
        assertTrue("a corrupted sibling row must not block 'good': ${outcome.exceptionOrNull()}", outcome.getOrNull() == true)
    }

    @Test
    fun permanentKeyLossDuringMaintenance_surfacesAndNeverRetiresOrServesStale() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        writeLegacyApproved(rules, "r")
        val fresh = f.manager()
        f.keys.permanentFailure = KeyPermanentlyInvalidatedExceptionDouble()
        val outcome = runCatching { fresh.findRule("r") }
        assertTrue("permanent key loss must surface", outcome.isFailure)
        assertFalse("legacy must not be retired by a failed pass", f.seals.areLegacySealsRetired())
        assertTrue(runCatching { fresh.listRules() }.isFailure)
        f.keys.permanentFailure = null
        assertTrue(executable(fresh, "r"))
        assertTrue(f.seals.areLegacySealsRetired())
    }

    @Test
    fun deferredMaintenance_unlockViaUnknownIdLookupRunsIt() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        val legacy = writeLegacyApproved(rules, "r")
        val fresh = f.manager()
        f.keys.deviceLocked = true
        assertTrue(runCatching { fresh.findRule("r") }.isFailure) // cold + locked: fail closed, deferred
        assertEquals(null, fresh.findRule("unknown")) // still locked: no decrypt needed
        assertFalse(f.seals.areLegacySealsRetired())
        f.keys.deviceLocked = false
        assertEquals(null, fresh.findRule("unknown"))
        assertTrue("maintenance must run on the first unlocked access", f.seals.areLegacySealsRetired())
        val upgraded = fresh.findRule("r")!!
        assertNotEquals(legacy.sealHmacHex, upgraded.sealHmacHex)
        assertTrue(fresh.verifySeal(upgraded))
        assertFalse(fresh.verifySeal(legacy))
    }

    @Test
    fun deferredMaintenance_unlockViaKnownIdReturnsReSealedRow() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        val legacy = writeLegacyApproved(rules, "r")
        val fresh = f.manager()
        f.keys.deviceLocked = true
        assertTrue(runCatching { fresh.findRule("r") }.isFailure)
        f.keys.deviceLocked = false
        val found = fresh.findRule("r")!!
        assertNotEquals("the re-read must return the re-sealed row", legacy.sealHmacHex, found.sealHmacHex)
        assertTrue(fresh.verifySeal(found))
        f.keys.deviceLocked = true
        assertEquals(found, fresh.findRule("r"))
        assertTrue(fresh.verifySeal(fresh.findRule("r")!!))
    }

    @Test
    fun createPendingRuleWhileLocked_failsWithoutDestroyingTheLiveApproval() = runBlocking {
        val f = fixture()
        val rules = f.manager()
        rules.pending("r")
        rules.approveAndSealRule("r", 200L)
        f.keys.deviceLocked = true
        assertTrue(runCatching { rules.pending("r", now = 300L) }.isFailure)
        assertTrue(runCatching { rules.pending("new_rule", now = 300L) }.isFailure)
        assertTrue("live approval must survive a failed locked re-proposal", f.seals.deletedAliases.isEmpty())
        assertTrue(executable(rules, "r"))
        f.keys.deviceLocked = false
        assertTrue(executable(f.manager(), "r"))
        assertEquals(null, rules.findRule("new_rule"))
    }
}

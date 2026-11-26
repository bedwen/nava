package com.nava.core.security.policy

import com.nava.core.security.crypto.CryptoKeyProvider
import com.nava.core.security.crypto.RuleSealKeyStores
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.testing.InMemoryRowStorage
import com.nava.core.security.testing.InMemorySoftwareKeyProvider
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleTriggerSpec
import java.security.InvalidKeyException
import javax.crypto.SecretKey
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Anti-rollback for routine grants: an attacker who can write the database file must not be able
 * to revive a paused or revoked routine by replaying an older APPROVED_ACTIVE ciphertext into the
 * same row, and legacy (pre-v2) seals must stop verifying once upgraded.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class RuleSealAntiRollbackTest {

    private class LockableKeyProvider(
        private val delegate: CryptoKeyProvider = InMemorySoftwareKeyProvider()
    ) : CryptoKeyProvider by delegate {
        @Volatile
        var deviceLocked: Boolean = false

        override fun getOrCreateDbMasterKey(): SecretKey {
            if (deviceLocked) throw InvalidKeyException("device locked")
            return delegate.getOrCreateDbMasterKey()
        }
    }

    private class Fixture(
        val storage: InMemoryRowStorage,
        val keys: LockableKeyProvider,
        val store: EncryptedSqliteStore
    )

    private fun kotlinx.coroutines.test.TestScope.fixture(): Fixture {
        val storage = InMemoryRowStorage()
        val keys = LockableKeyProvider()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = keys,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        return Fixture(storage, keys, store)
    }

    private fun manager(f: Fixture): RuleCapabilityGrantManager {
        var counter = 0
        return RuleCapabilityGrantManager(
            store = f.store,
            keyProvider = f.keys,
            grantIdGenerator = { "grant_${++counter}" }
        )
    }

    private suspend fun createPending(rules: RuleCapabilityGrantManager, ruleId: String): RuleCapabilityGrant {
        return rules.createPendingRule(
            ruleId = ruleId,
            triggerSpec = RuleTriggerSpec(triggerType = "CHARGING"),
            staticActions = listOf(
                RuleActionSpec(toolName = "set_dnd", requiredCapability = AtomicCapability.CREATE_DRAFT)
            ),
            nowEpochSec = 100L
        )
    }

    private fun rawRow(f: Fixture) = f.storage.allRawRows(EncryptedTableSchema.TABLE_AUTOMATION_RULES).single()

    private fun executable(rules: RuleCapabilityGrantManager, grant: RuleCapabilityGrant?): Boolean =
        grant != null && grant.approvalState == RuleApprovalState.APPROVED_ACTIVE && rules.verifySeal(grant)

    @Test
    fun replayAfterRevokeNeverVerifies() = runTest {
        val f = fixture()
        val rules = manager(f)
        createPending(rules, "night")
        val approved = rules.approveAndSealRule("night", nowEpochSec = 200L)
        assertTrue(rules.verifySeal(approved))
        val approvedBlob = rawRow(f).payloadBlob

        rules.revokeRule("night", nowEpochSec = 300L)
        f.storage.replaceRawBlob(EncryptedTableSchema.TABLE_AUTOMATION_RULES, rawRow(f).rowId, approvedBlob)

        val replayed = rules.findRule("night")
        assertEquals("replay decrypts to the old APPROVED grant", RuleApprovalState.APPROVED_ACTIVE, replayed?.approvalState)
        assertFalse("its seal key was destroyed on revoke", executable(rules, replayed))
    }

    @Test
    fun replayAfterPauseNeverVerifiesAndReapprovalUsesFreshKey() = runTest {
        val f = fixture()
        val rules = manager(f)
        createPending(rules, "night")
        val first = rules.approveAndSealRule("night", nowEpochSec = 200L)
        val firstBlob = rawRow(f).payloadBlob

        rules.pauseRule("night", nowEpochSec = 250L)
        assertFalse(rules.verifySeal(first))

        val second = rules.approveAndSealRule("night", nowEpochSec = 260L)
        assertTrue(rules.verifySeal(second))
        assertNotEquals(first.sealHmacHex, second.sealHmacHex)

        // Replaying the first approval's ciphertext must not verify under the second approval's key.
        f.storage.replaceRawBlob(EncryptedTableSchema.TABLE_AUTOMATION_RULES, rawRow(f).rowId, firstBlob)
        assertFalse(executable(rules, rules.findRule("night")))
    }

    @Test
    fun sealKeysStayUsableWhileDeviceLocked() = runTest {
        val f = fixture()
        val rules = manager(f)
        createPending(rules, "night")
        rules.approveAndSealRule("night", nowEpochSec = 200L)

        f.keys.deviceLocked = true
        val locked = rules.findRule("night")
        assertTrue("unattended routines must verify while locked", executable(rules, locked))
    }

    @Test
    fun legacySealIsUpgradedOnceAndThenPermanentlyRetired() = runTest {
        val f = fixture()
        val rules = manager(f)
        // Build a pre-v2 row before ANY read: APPROVED_ACTIVE with a legacy blind-index seal and
        // no seal key (the first read of a fresh install retires legacy seals immediately).
        val pending = createPending(rules, "legacy")
        val legacyApproved = pending.copy(
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            grantedAtEpochSec = 150L
        )
        val legacyGrant = legacyApproved.copy(sealHmacHex = rules.legacySealForTest(legacyApproved))
        rules.writeGrantRowForTest(legacyGrant)
        val legacyBlob = rawRow(f).payloadBlob

        // A fresh manager (new process) upgrades on first access.
        val upgraded = manager(f).findRule("legacy")!!
        assertEquals(RuleApprovalState.APPROVED_ACTIVE, upgraded.approvalState)
        assertNotEquals(legacyGrant.sealHmacHex, upgraded.sealHmacHex)
        assertTrue(rules.verifySeal(upgraded))
        assertTrue(RuleSealKeyStores.forProvider(f.keys).areLegacySealsRetired())

        // Replaying the legacy row after retirement must never verify again.
        rules.revokeRule("legacy", nowEpochSec = 400L)
        f.storage.replaceRawBlob(EncryptedTableSchema.TABLE_AUTOMATION_RULES, rawRow(f).rowId, legacyBlob)
        assertFalse(executable(manager(f), manager(f).findRule("legacy")))
    }

    @Test
    fun freshInstallRetiresLegacySealsSoCraftedLegacyRowsNeverVerify() = runTest {
        val f = fixture()
        val rules = manager(f)
        val pending = createPending(rules, "night")
        rules.listRules() // first unlocked access on a store without legacy rules
        assertTrue(RuleSealKeyStores.forProvider(f.keys).areLegacySealsRetired())

        val crafted = pending.copy(approvalState = RuleApprovalState.APPROVED_ACTIVE, grantedAtEpochSec = 150L)
        val craftedGrant = crafted.copy(sealHmacHex = rules.legacySealForTest(crafted))
        rules.writeGrantRowForTest(craftedGrant)
        assertFalse(executable(rules, rules.findRule("night")))
    }

    @Test
    fun legacyUpgradeWaitsForUnlockAndKeepsLegacyRoutinesWorkingMeanwhile() = runTest {
        val f = fixture()
        val rules = manager(f)
        val pending = createPending(rules, "legacy")
        val legacyApproved = pending.copy(approvalState = RuleApprovalState.APPROVED_ACTIVE, grantedAtEpochSec = 150L)
        val legacyGrant = legacyApproved.copy(sealHmacHex = rules.legacySealForTest(legacyApproved))
        rules.writeGrantRowForTest(legacyGrant)

        val cold = manager(f)
        f.keys.deviceLocked = true
        // Upgrade cannot decrypt while locked; it must not throw and must not retire legacy seals.
        assertTrue(cold.verifySeal(legacyGrant))
        assertFalse(RuleSealKeyStores.forProvider(f.keys).areLegacySealsRetired())

        f.keys.deviceLocked = false
        val upgraded = cold.findRule("legacy")!!
        assertTrue(cold.verifySeal(upgraded))
        assertFalse("legacy seal is rejected after the upgrade", cold.verifySeal(legacyGrant))
    }
}

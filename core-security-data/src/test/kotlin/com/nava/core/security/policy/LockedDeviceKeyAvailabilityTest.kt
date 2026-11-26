package com.nava.core.security.policy

import com.nava.core.security.crypto.CryptoKeyProvider
import com.nava.core.security.crypto.KeyUnavailability
import com.nava.core.security.dao.AuditLogDao
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.testing.InMemoryRowStorage
import com.nava.core.security.testing.InMemorySoftwareKeyProvider
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleTriggerSpec
import java.security.InvalidKeyException
import java.security.ProviderException
import javax.crypto.AEADBadTagException
import javax.crypto.SecretKey
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The `nava_db_master_key` uses `setUnlockedDeviceRequired(true)`, so it is unusable while the
 * screen is locked. Background callers (notification listener, routines, firewall audit) must
 * keep honoring the user's last decisions, fail closed on anything unknown, and never mask
 * ciphertext tampering as a "locked" condition.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class LockedDeviceKeyAvailabilityTest {

    /** Simulates Android Keystore refusing the master key while the device is locked. */
    private class LockableKeyProvider(
        private val delegate: CryptoKeyProvider = InMemorySoftwareKeyProvider()
    ) : CryptoKeyProvider by delegate {
        @Volatile
        var deviceLocked: Boolean = false

        override fun getOrCreateDbMasterKey(): SecretKey {
            if (deviceLocked) {
                throw InvalidKeyException("Key user not authenticated (device locked)")
            }
            return delegate.getOrCreateDbMasterKey()
        }
    }

    @Test
    fun classifierSeparatesLockedKeyFromTampering() {
        assertTrue(KeyUnavailability.isTransient(InvalidKeyException("locked")))
        assertTrue(KeyUnavailability.isTransient(ProviderException("keystore busy")))
        assertTrue(KeyUnavailability.isTransient(IllegalStateException("wrap", InvalidKeyException("locked"))))
        assertFalse(KeyUnavailability.isTransient(AEADBadTagException("tag mismatch")))
        assertFalse(
            KeyUnavailability.isTransient(InvalidKeyException("x").apply { initCause(AEADBadTagException("tag")) })
        )
        assertFalse(KeyUnavailability.isTransient(IllegalArgumentException("bad input")))
    }

    @Test
    fun profilesResolvedWhileUnlockedKeepApplyingWhileLocked() = runTest {
        val keys = LockableKeyProvider()
        val store = EncryptedSqliteStore(
            storage = InMemoryRowStorage(),
            keyProvider = keys,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val manager = PermissionProfileManager(store = store, clockEpochSec = { 1_000L })
        manager.assignTargetToProfile("pkg:com.chat", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
        manager.assignTargetToProfile("pkg:com.bank", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)

        // One unlocked evaluation warms the snapshot for every explicitly bound target.
        val unlockedLevel = manager.evaluateCapability("pkg:com.chat", AtomicCapability.NOTIFICATION_READ)
        assertTrue(unlockedLevel.isAllowed)

        keys.deviceLocked = true
        assertEquals(
            unlockedLevel,
            manager.evaluateCapability("pkg:com.chat", AtomicCapability.NOTIFICATION_READ)
        )
        assertEquals(
            "a bound target never queried before locking must use the warmed snapshot",
            unlockedLevel,
            manager.evaluateCapability("pkg:com.bank", AtomicCapability.NOTIFICATION_READ)
        )
        // Unbound targets need no decryption (blind-index miss) and stay Default-Deny.
        assertEquals(
            ConfirmationLevel.DISABLED,
            manager.evaluateCapability("pkg:com.unknown", AtomicCapability.NOTIFICATION_READ)
        )
    }

    @Test
    fun boundTargetNeverResolvedWhileUnlockedFailsClosedWhenLocked() = runTest {
        val keys = LockableKeyProvider()
        val store = EncryptedSqliteStore(
            storage = InMemoryRowStorage(),
            keyProvider = keys,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val manager = PermissionProfileManager(store = store, clockEpochSec = { 1_000L })
        manager.assignTargetToProfile("pkg:com.chat", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)

        // Process restarted while locked: no snapshot exists yet.
        val coldManager = PermissionProfileManager(store = store, clockEpochSec = { 1_000L })
        keys.deviceLocked = true
        try {
            coldManager.evaluateCapability("pkg:com.chat", AtomicCapability.NOTIFICATION_READ)
            fail("A bound target with no snapshot must fail closed while the master key is unavailable")
        } catch (e: InvalidKeyException) {
            assertTrue(KeyUnavailability.isTransient(e))
        }
    }

    @Test
    fun profileChangeInvalidatesLockedFallback() = runTest {
        val keys = LockableKeyProvider()
        val store = EncryptedSqliteStore(
            storage = InMemoryRowStorage(),
            keyProvider = keys,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val manager = PermissionProfileManager(store = store, clockEpochSec = { 1_000L })
        manager.assignTargetToProfile("pkg:com.chat", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
        assertTrue(manager.evaluateCapability("pkg:com.chat", AtomicCapability.NOTIFICATION_READ).isAllowed)

        // User revokes access (unlocked), then the device locks before any new evaluation.
        manager.assignTargetToProfile("pkg:com.chat", PermissionProfile.DEFAULT_DENY_PROFILE_ID)
        keys.deviceLocked = true
        try {
            val level = manager.evaluateCapability("pkg:com.chat", AtomicCapability.NOTIFICATION_READ)
            assertEquals(ConfirmationLevel.DISABLED, level)
        } catch (e: InvalidKeyException) {
            // Failing closed is also acceptable; serving the revoked grant is not.
        }
    }

    @Test
    fun approvedRoutineGrantIsReadableWhileLockedAndRevocationWins() = runTest {
        val keys = LockableKeyProvider()
        val store = EncryptedSqliteStore(
            storage = InMemoryRowStorage(),
            keyProvider = keys,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        var counter = 0
        val rules = RuleCapabilityGrantManager(
            store = store,
            keyProvider = keys,
            grantIdGenerator = { "grant_${++counter}" }
        )
        rules.createPendingRule(
            ruleId = "night_quiet",
            triggerSpec = RuleTriggerSpec(triggerType = "CHARGING"),
            staticActions = listOf(
                RuleActionSpec(toolName = "set_dnd", requiredCapability = AtomicCapability.CREATE_DRAFT)
            ),
            nowEpochSec = 100L
        )
        val approved = rules.approveAndSealRule("night_quiet", nowEpochSec = 200L)

        keys.deviceLocked = true
        val lockedRead = rules.findRule("night_quiet")
        assertNotNull(lockedRead)
        assertEquals(approved, lockedRead)
        assertTrue(rules.verifySeal(lockedRead!!))

        keys.deviceLocked = false
        rules.revokeRule("night_quiet", nowEpochSec = 300L)
        keys.deviceLocked = true
        assertEquals(RuleApprovalState.REVOKED, rules.findRule("night_quiet")?.approvalState)
    }

    @Test
    fun auditEntriesAreBufferedWhileLockedAndFlushedInOrder() = runTest {
        val keys = LockableKeyProvider()
        val store = EncryptedSqliteStore(
            storage = InMemoryRowStorage(),
            keyProvider = keys,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        val audit = AuditLogDao(store)
        fun entry(i: Int) = AuditLogEntry(
            timestampEpochMs = 1_000L * i,
            toolName = "set_dnd",
            targetId = "routines",
            actionSummary = "step $i",
            provenance = DataProvenance.SYSTEM,
            decision = "SUCCESS"
        )

        keys.deviceLocked = true
        audit.record(entry(1))
        audit.record(entry(2))
        assertEquals(2, audit.pendingBufferedCount())

        keys.deviceLocked = false
        audit.record(entry(3))
        assertEquals(0, audit.pendingBufferedCount())
        val summaries = audit.queryRecent(10).map { it.actionSummary }.sorted()
        assertEquals(listOf("step 1", "step 2", "step 3"), summaries)
    }
}

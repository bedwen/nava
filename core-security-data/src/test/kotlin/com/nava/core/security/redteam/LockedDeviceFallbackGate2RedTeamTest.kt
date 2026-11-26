package com.nava.core.security.redteam

import com.nava.core.security.crypto.CryptoKeyProvider
import com.nava.core.security.crypto.KeyUnavailability
import com.nava.core.security.dao.AuditLogDao
import com.nava.core.security.policy.PermissionProfileManager
import com.nava.core.security.policy.RuleCapabilityGrantManager
import com.nava.core.security.storage.EncryptedRowStorage
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.storage.RawEncryptedRow
import com.nava.core.security.testing.InMemoryRowStorage
import com.nava.core.security.testing.InMemorySoftwareKeyProvider
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.PermissionProfilePreset
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleTriggerSpec
import java.security.InvalidKeyException
import java.security.ProviderException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.AEADBadTagException
import javax.crypto.SecretKey
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Ignore
import org.junit.Test

/**
 * Gate 2 independent adversarial suite for commit ba98e84 (locked-device fallback caches in
 * [PermissionProfileManager] / [RuleCapabilityGrantManager], [KeyUnavailability] classifier and
 * the bounded [AuditLogDao] buffer). PLAN.md Sections 5.1, 5.5, 5.6 and 8.3.
 *
 * Attacker goals exercised here:
 * - make the cache mask ciphertext tampering (locked or unlocked),
 * - make a revoked / downgraded / deleted decision survive into the locked-device fallback,
 * - make an unknown or never-resolved target resolve to anything but Default-Deny / fail closed,
 * - make the audit buffer lose, reorder, duplicate or wedge entries.
 */
class LockedDeviceFallbackGate2RedTeamTest {

    /** Simulates Android Keystore refusing `nava_db_master_key` while the device is locked. */
    private class LockableKeyProvider(
        private val delegate: CryptoKeyProvider = InMemorySoftwareKeyProvider()
    ) : CryptoKeyProvider by delegate {
        @Volatile
        var deviceLocked: Boolean = false

        @Volatile
        var permanentFailure: Throwable? = null

        override fun getOrCreateDbMasterKey(): SecretKey {
            permanentFailure?.let { throw it }
            if (deviceLocked) {
                throw InvalidKeyException("Key user not authenticated (device locked)")
            }
            return delegate.getOrCreateDbMasterKey()
        }
    }

    /**
     * Mirrors `android.security.keystore.KeyPermanentlyInvalidatedException`, which extends
     * [InvalidKeyException] in the Android SDK. Defined locally because the JVM unit-test
     * classpath only has throwing SDK stubs.
     */
    private class KeyPermanentlyInvalidatedExceptionDouble :
        InvalidKeyException("Key permanently invalidated")

    /** Storage decorator that can fail specific inserts with arbitrary throwables. */
    private class FaultInjectingRowStorage(
        val delegate: InMemoryRowStorage = InMemoryRowStorage()
    ) : EncryptedRowStorage by delegate {
        @Volatile
        var insertFault: ((RawEncryptedRow) -> Throwable?)? = null

        override fun insertRow(tableName: String, row: RawEncryptedRow) {
            insertFault?.invoke(row)?.let { throw it }
            delegate.insertRow(tableName, row)
        }
    }

    /** Map whose `put` runs [onPut] first, used to schedule a writer inside a reader's window. */
    private class InterposingMap<K : Any, V : Any>(
        private val onPut: (K, V) -> Unit
    ) : ConcurrentHashMap<K, V>() {
        override fun put(key: K, value: V): V? {
            onPut(key, value)
            return super.put(key, value)
        }
    }

    /** Map with hooks before/after `put` and before `putAll`, to place writers inside reader windows. */
    private class HookMap<K : Any, V : Any>(
        private val beforePut: (K, V) -> Unit = { _, _ -> },
        private val afterPut: (K, V) -> Unit = { _, _ -> },
        private val beforePutAll: (Map<out K, V>) -> Unit = { }
    ) : ConcurrentHashMap<K, V>() {
        override fun put(key: K, value: V): V? {
            beforePut(key, value)
            val previous = super.put(key, value)
            afterPut(key, value)
            return previous
        }

        override fun putAll(from: Map<out K, V>) {
            beforePutAll(from)
            super.putAll(from)
        }
    }

    private data class Fixture(
        val keys: LockableKeyProvider,
        val storage: InMemoryRowStorage,
        val store: EncryptedSqliteStore
    )

    private fun fixture(storage: InMemoryRowStorage = InMemoryRowStorage()): Fixture {
        val keys = LockableKeyProvider()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = keys,
            dispatcher = Dispatchers.Unconfined
        )
        return Fixture(keys, storage, store)
    }

    private fun bindingRows(f: Fixture): List<RawEncryptedRow> =
        f.storage.allRawRows(EncryptedTableSchema.TABLE_PERMISSION_TARGET_BINDINGS)

    private fun flipLastByte(f: Fixture, table: String, rowId: Long) {
        val raw = f.storage.inspectRawRow(table, rowId)!!
        val blob = raw.payloadBlob.copyOf()
        blob[blob.size - 1] = (blob[blob.size - 1].toInt() xor 0x01).toByte()
        assertTrue(f.storage.replaceRawBlob(table, rowId, blob))
    }

    private fun customProfile(id: String, notificationRead: ConfirmationLevel) = PermissionProfile(
        id = id,
        name = id,
        preset = PermissionProfilePreset.CUSTOM,
        capabilities = mapOf(
            AtomicCapability.NOTIFICATION_READ to notificationRead,
            AtomicCapability.DATA_READ to ConfirmationLevel.DISABLED,
            AtomicCapability.CREATE_DRAFT to ConfirmationLevel.DISABLED,
            AtomicCapability.MODIFY_DELETE_SEND to ConfirmationLevel.DISABLED,
            AtomicCapability.APP_LAUNCH to ConfirmationLevel.DISABLED
        )
    )

    /** Evaluates NOTIFICATION_READ; returns null when the manager failed closed with an exception. */
    private suspend fun levelOrFailClosed(manager: PermissionProfileManager, target: String): ConfirmationLevel? {
        return try {
            manager.evaluateCapability(target, AtomicCapability.NOTIFICATION_READ)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            null
        }
    }

    private fun assertNeverAllowed(message: String, level: ConfirmationLevel?) {
        assertTrue("$message (got $level)", level == null || !level.isAllowed)
    }

    private fun injectField(target: Any, fieldName: String, value: Any) {
        val field = target.javaClass.getDeclaredField(fieldName)
        field.isAccessible = true
        field.set(target, value)
    }

    /** Decodes every audit row in rowId (insertion) order and returns the action summaries. */
    private suspend fun decodeInRowOrder(f: Fixture, audit: AuditLogDao): List<String> =
        decodeInRowOrder(f.storage, audit)

    private suspend fun decodeInRowOrder(storage: InMemoryRowStorage, audit: AuditLogDao): List<String> {
        val rowIds = storage.allRawRows(EncryptedTableSchema.TABLE_AUDIT_LOGS).sortedBy { it.rowId }
        val entries = audit.queryRecent(10_000)
        // Rows are inserted in call order and each entry has a unique (timestamp, summary) pair here,
        // so map rows back to entries by their createdEpochSec and the decoded list order.
        val byRowOrder = ArrayList<String>(rowIds.size)
        val pool = entries.toMutableList()
        for (row in rowIds) {
            val candidates = pool.filter { it.timestampEpochMs / 1000L == row.createdEpochSec }
            val pick = if (candidates.size == 1) {
                candidates.single()
            } else {
                // Gap marker shares the triggering entry's timestamp and is always inserted first.
                candidates.firstOrNull { it.decision == AuditLogDao.DECISION_AUDIT_BUFFER_GAP } ?: candidates.first()
            }
            pool.remove(pick)
            byRowOrder.add(pick.actionSummary)
        }
        return byRowOrder
    }

    private fun entry(i: Int, target: String = "routines") = AuditLogEntry(
        timestampEpochMs = 1_000L * i,
        toolName = "set_dnd",
        targetId = target,
        actionSummary = "step $i",
        provenance = DataProvenance.SYSTEM,
        decision = "SUCCESS"
    )

    private suspend fun newRules(f: Fixture): RuleCapabilityGrantManager {
        var counter = 0
        return RuleCapabilityGrantManager(
            store = f.store,
            keyProvider = f.keys,
            grantIdGenerator = { "grant_${++counter}" }
        )
    }

    private suspend fun approvedRule(rules: RuleCapabilityGrantManager, ruleId: String): RuleCapabilityGrant {
        rules.createPendingRule(
            ruleId = ruleId,
            triggerSpec = RuleTriggerSpec(triggerType = "CHARGING"),
            staticActions = listOf(
                RuleActionSpec(toolName = "set_dnd", requiredCapability = AtomicCapability.CREATE_DRAFT)
            ),
            nowEpochSec = 100L
        )
        return rules.approveAndSealRule(ruleId, nowEpochSec = 200L)
    }

    // ---------------------------------------------------------------------------------------
    // 1. KeyUnavailability classifier
    // ---------------------------------------------------------------------------------------

    @Test
    fun classifier_tamperAnywhereInCauseChainIsNeverTransient() {
        val nestedTamper = IllegalStateException(
            "outer",
            ProviderException("provider", InvalidKeyException("key").apply { initCause(AEADBadTagException("tag")) })
        )
        assertFalse(KeyUnavailability.isTransient(nestedTamper))
        assertFalse(KeyUnavailability.isTransient(SecurityException("wrap", AEADBadTagException("tag"))))
        assertFalse(KeyUnavailability.isTransient(IllegalArgumentException("Encrypted blob must be at least 28 bytes")))
        assertFalse(KeyUnavailability.isTransient(RuntimeException("disk full")))
        // Self-referencing cause chains must terminate.
        val selfCause = object : RuntimeException("self") {
            override val cause: Throwable get() = this
        }
        assertFalse(KeyUnavailability.isTransient(selfCause))
    }

    @Test
    fun classifier_permanentlyInvalidatedKeyIsNotTransient() {
        assertFalse(KeyUnavailability.isTransient(KeyPermanentlyInvalidatedExceptionDouble()))
    }

    @Test
    fun audit_permanentKeyFailureMustSurfaceInsteadOfSilentBuffering() = runBlocking {
        val f = fixture()
        val audit = AuditLogDao(f.store)
        f.keys.permanentFailure = KeyPermanentlyInvalidatedExceptionDouble()
        try {
            audit.record(entry(1))
            fail("A permanently invalidated master key must not be treated as a locked device")
        } catch (e: InvalidKeyException) {
            // expected: fail loudly
        }
    }

    // ---------------------------------------------------------------------------------------
    // 2. Tamper must never be masked by the fallback cache
    // ---------------------------------------------------------------------------------------

    @Test
    fun tamperedBindingWhileUnlocked_propagatesAeadEvenWithWarmCache() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.assignTargetToProfile("pkg:com.chat", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
        assertTrue(manager.evaluateCapability("pkg:com.chat", AtomicCapability.NOTIFICATION_READ).isAllowed)

        val row = bindingRows(f).single()
        flipLastByte(f, EncryptedTableSchema.TABLE_PERMISSION_TARGET_BINDINGS, row.rowId)

        repeat(3) {
            try {
                manager.evaluateCapability("pkg:com.chat", AtomicCapability.NOTIFICATION_READ)
                fail("Unlocked tamper must never be served from the locked-device cache")
            } catch (e: AEADBadTagException) {
                assertFalse(KeyUnavailability.isTransient(e))
            }
        }
    }

    @Test
    fun crossRowBlobSwap_isDetectedAndNeverRedirectsAllowToAnotherTarget() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.assignTargetToProfile("pkg:com.bank", PermissionProfile.DEFAULT_DENY_PROFILE_ID)
        manager.assignTargetToProfile("pkg:com.chat", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
        assertFalse(manager.evaluateCapability("pkg:com.bank", AtomicCapability.NOTIFICATION_READ).isAllowed)

        val rows = bindingRows(f)
        assertEquals(2, rows.size)
        f.storage.replaceRawBlob(EncryptedTableSchema.TABLE_PERMISSION_TARGET_BINDINGS, rows[0].rowId, rows[1].payloadBlob)
        f.storage.replaceRawBlob(EncryptedTableSchema.TABLE_PERMISSION_TARGET_BINDINGS, rows[1].rowId, rows[0].payloadBlob)

        for (target in listOf("pkg:com.bank", "pkg:com.chat")) {
            try {
                manager.evaluateCapability(target, AtomicCapability.NOTIFICATION_READ)
                fail("Swapped binding ciphertext for $target must raise AEADBadTagException")
            } catch (_: AEADBadTagException) {
            }
        }
        // While locked the swapped rows cannot even be decrypted: only pre-tamper decisions remain.
        f.keys.deviceLocked = true
        assertNeverAllowed("bank must never inherit chat's ALLOW", levelOrFailClosed(manager, "pkg:com.bank"))
    }

    @Test
    fun tamperedProfileRowWhileUnlocked_propagatesAead() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.saveProfile(customProfile("custom_allow", ConfirmationLevel.AUTO))
        manager.assignTargetToProfile("pkg:com.chat", "custom_allow")
        assertTrue(manager.evaluateCapability("pkg:com.chat", AtomicCapability.NOTIFICATION_READ).isAllowed)

        val profileRow = f.storage.allRawRows(EncryptedTableSchema.TABLE_PERMISSION_PROFILES).single()
        flipLastByte(f, EncryptedTableSchema.TABLE_PERMISSION_PROFILES, profileRow.rowId)
        try {
            manager.evaluateCapability("pkg:com.chat", AtomicCapability.NOTIFICATION_READ)
            fail("Tampered profile ciphertext must propagate AEADBadTagException")
        } catch (_: AEADBadTagException) {
        }
    }

    @Test
    fun revokedThenTamperedThenLocked_neverRevivesOldAllow() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.assignTargetToProfile("pkg:com.chat", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
        assertTrue(manager.evaluateCapability("pkg:com.chat", AtomicCapability.NOTIFICATION_READ).isAllowed)

        manager.assignTargetToProfile("pkg:com.chat", PermissionProfile.DEFAULT_DENY_PROFILE_ID)
        flipLastByte(f, EncryptedTableSchema.TABLE_PERMISSION_TARGET_BINDINGS, bindingRows(f).single().rowId)
        f.keys.deviceLocked = true
        assertNeverAllowed("revoked + tampered + locked", levelOrFailClosed(manager, "pkg:com.chat"))
    }

    @Test
    fun tamperedRuleRowWhileUnlocked_propagatesAeadDespiteCachedGrant() = runBlocking {
        val f = fixture()
        val rules = newRules(f)
        approvedRule(rules, "night_quiet")
        assertEquals(RuleApprovalState.APPROVED_ACTIVE, rules.findRule("night_quiet")?.approvalState)

        val raw = f.storage.allRawRows(EncryptedTableSchema.TABLE_AUTOMATION_RULES).single()
        flipLastByte(f, EncryptedTableSchema.TABLE_AUTOMATION_RULES, raw.rowId)
        try {
            rules.findRule("night_quiet")
            fail("Tampered rule ciphertext must propagate AEADBadTagException, not the cached grant")
        } catch (_: AEADBadTagException) {
        }
    }

    @Test
    fun forgedGrantInCache_isStillRejectedBySealVerification() = runBlocking {
        val f = fixture()
        val rules = newRules(f)
        val approved = approvedRule(rules, "night_quiet")
        f.keys.deviceLocked = true
        val locked = rules.findRule("night_quiet")!!
        assertTrue(rules.verifySeal(locked))
        // Any escalation of the cached copy's actions must break the seal.
        val escalated = locked.copy(
            staticActions = listOf(
                RuleActionSpec(
                    toolName = "send_sms",
                    requiredCapability = AtomicCapability.MODIFY_DELETE_SEND
                )
            )
        )
        assertFalse(rules.verifySeal(escalated))
        assertFalse(rules.verifySeal(approved.copy(triggerSpec = RuleTriggerSpec("ALWAYS"))))
    }

    @Test
    fun sameRowCiphertextRollback_mustNotReviveRevokedRule() = runBlocking {
        val f = fixture()
        val rules = newRules(f)
        approvedRule(rules, "night_quiet")
        val approvedRaw = f.storage.allRawRows(EncryptedTableSchema.TABLE_AUTOMATION_RULES).single()

        rules.revokeRule("night_quiet", nowEpochSec = 300L)
        val revokedRaw = f.storage.allRawRows(EncryptedTableSchema.TABLE_AUTOMATION_RULES).single()
        assertEquals("upsert reuses the rowId", approvedRaw.rowId, revokedRaw.rowId)

        // Attacker with write access to the database file replays the old APPROVED ciphertext.
        f.storage.replaceRawBlob(EncryptedTableSchema.TABLE_AUTOMATION_RULES, revokedRaw.rowId, approvedRaw.payloadBlob)
        val revived = try {
            rules.findRule("night_quiet")
        } catch (_: AEADBadTagException) {
            null
        }
        val executable = revived != null &&
            revived.approvalState == RuleApprovalState.APPROVED_ACTIVE &&
            rules.verifySeal(revived)
        assertFalse("A revoked rule must never become executable again via ciphertext rollback", executable)
    }

    // ---------------------------------------------------------------------------------------
    // 3. Default-Deny and fail-closed while locked
    // ---------------------------------------------------------------------------------------

    @Test
    fun locked_unknownTargetsAndHostileIdsStayDefaultDeny() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.assignTargetToProfile("pkg:com.chat", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
        assertTrue(manager.evaluateCapability("pkg:com.chat", AtomicCapability.NOTIFICATION_READ).isAllowed)
        f.keys.deviceLocked = true

        val hostile = listOf(
            "pkg:com.unknown",
            "pkg:com.chat ",
            " pkg:com.chat",
            "PKG:COM.CHAT",
            "pkg:com.chat\u0000",
            "pkg:com.c\u200Bhat",
            "pkg:com.\u0441hat", // Cyrillic es homoglyph
            "pkg:com.chat\u202E",
            "",
            "   "
        )
        for (target in hostile) {
            assertNeverAllowed("locked lookup of '$target'", levelOrFailClosed(manager, target))
        }
    }

    @Test
    fun coldManagerWhileLocked_failsClosedForBoundAndDeniesUnknown() = runBlocking {
        val f = fixture()
        PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
            .assignTargetToProfile("pkg:com.chat", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
        val cold = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        f.keys.deviceLocked = true
        assertNull("bound target with no snapshot must fail closed", levelOrFailClosed(cold, "pkg:com.chat"))
        assertEquals(
            ConfirmationLevel.DISABLED,
            cold.evaluateCapability("pkg:com.unknown", AtomicCapability.NOTIFICATION_READ)
        )
        assertFalse(cold.isNotificationReadEnabled("pkg:com.unknown"))

        val coldRules = newRules(f)
        assertNull(runCatching { coldRules.findRule("never_seen") }.getOrNull())
    }

    @Test
    fun deleteProfileThenLock_neverServesDeletedProfile() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.saveProfile(customProfile("custom_allow", ConfirmationLevel.AUTO))
        manager.assignTargetToProfile("pkg:com.a", "custom_allow")
        manager.assignTargetToProfile("pkg:com.b", "custom_allow")
        assertTrue(manager.evaluateCapability("pkg:com.a", AtomicCapability.NOTIFICATION_READ).isAllowed)

        manager.deleteProfile("custom_allow")
        f.keys.deviceLocked = true
        assertNeverAllowed("deleted profile target a", levelOrFailClosed(manager, "pkg:com.a"))
        assertNeverAllowed("deleted profile target b (only warmed)", levelOrFailClosed(manager, "pkg:com.b"))
    }

    @Test
    fun deleteProfileInterruptedByLock_neverServesDeletedProfile() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.saveProfile(customProfile("custom_allow", ConfirmationLevel.AUTO))
        manager.assignTargetToProfile("pkg:com.a", "custom_allow")
        assertTrue(manager.evaluateCapability("pkg:com.a", AtomicCapability.NOTIFICATION_READ).isAllowed)

        // The profile row delete needs no master key, but the binding scan does: lock right before.
        f.keys.deviceLocked = true
        val outcome = runCatching { manager.deleteProfile("custom_allow") }
        assertTrue("binding scan must fail while locked", outcome.isFailure)
        assertNeverAllowed("half-deleted profile while locked", levelOrFailClosed(manager, "pkg:com.a"))
        f.keys.deviceLocked = false
        assertFalse(manager.evaluateCapability("pkg:com.a", AtomicCapability.NOTIFICATION_READ).isAllowed)
    }

    @Test
    fun downgradeOfSharedCustomProfile_invalidatesEverySnapshottedTarget() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.saveProfile(customProfile("shared", ConfirmationLevel.AUTO))
        val targets = (1..20).map { "pkg:com.app$it" }
        for (t in targets) manager.assignTargetToProfile(t, "shared")
        assertTrue(manager.evaluateCapability(targets.first(), AtomicCapability.NOTIFICATION_READ).isAllowed)

        manager.saveProfile(customProfile("shared", ConfirmationLevel.DISABLED))
        f.keys.deviceLocked = true
        for (t in targets) {
            assertNeverAllowed("downgraded shared profile for $t", levelOrFailClosed(manager, t))
        }
    }

    @Test
    fun failedWriteWhileLocked_doesNotPoisonCacheOrRevokeSilently() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.assignTargetToProfile("pkg:com.chat", PermissionProfile.DEFAULT_DENY_PROFILE_ID)
        assertFalse(manager.evaluateCapability("pkg:com.chat", AtomicCapability.NOTIFICATION_READ).isAllowed)

        f.keys.deviceLocked = true
        // An attempted upgrade while locked must fail and must not leak into the fallback cache.
        assertTrue(
            runCatching {
                manager.assignTargetToProfile("pkg:com.chat", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
            }.isFailure
        )
        assertNeverAllowed("failed locked upgrade", levelOrFailClosed(manager, "pkg:com.chat"))
    }

    // ---------------------------------------------------------------------------------------
    // 4. Revocation must always win, including under concurrency
    // ---------------------------------------------------------------------------------------

    @Test
    fun revokeAfterLockedRead_revocationWinsForRules() = runBlocking {
        val f = fixture()
        val rules = newRules(f)
        approvedRule(rules, "night_quiet")
        f.keys.deviceLocked = true
        assertEquals(RuleApprovalState.APPROVED_ACTIVE, rules.findRule("night_quiet")?.approvalState)
        f.keys.deviceLocked = false
        rules.pauseRule("night_quiet", nowEpochSec = 250L)
        f.keys.deviceLocked = true
        assertEquals(RuleApprovalState.PAUSED, rules.findRule("night_quiet")?.approvalState)
        f.keys.deviceLocked = false
        rules.revokeRule("night_quiet", nowEpochSec = 300L)
        f.keys.deviceLocked = true
        val locked = rules.findRule("night_quiet")!!
        assertEquals(RuleApprovalState.REVOKED, locked.approvalState)
        assertFalse(rules.verifySeal(locked))
        // Re-approval of a revoked rule is impossible even with a warm cache.
        f.keys.deviceLocked = false
        assertTrue(runCatching { rules.approveAndSealRule("night_quiet", 400L) }.isFailure)
    }

    @Test
    fun concurrentReadersAndWriters_finalRevocationAlwaysWinsAfterLock() = runBlocking {
        repeat(25) { iteration ->
            val f = fixture()
            val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
            val rules = newRules(f)
            approvedRule(rules, "r")
            val targets = (1..6).map { "pkg:com.t$it" }
            for (t in targets) manager.assignTargetToProfile(t, PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)

            withTimeout(20_000L) {
                withContext(Dispatchers.Default) {
                    val readers = (1..8).map { r ->
                        async {
                            repeat(40) {
                                runCatching { manager.evaluateCapability(targets[(r + it) % targets.size], AtomicCapability.NOTIFICATION_READ) }
                                runCatching { rules.findRule("r") }
                            }
                        }
                    }
                    val writers = (1..2).map { w ->
                        async {
                            repeat(20) { i ->
                                val preset = if ((i + w) % 2 == 0) {
                                    PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID
                                } else {
                                    PermissionProfile.DEFAULT_DENY_PROFILE_ID
                                }
                                manager.assignTargetToProfile(targets[(i * w) % targets.size], preset)
                                runCatching { rules.pauseRule("r", 500L + i) }
                                runCatching { rules.approveAndSealRule("r", 600L + i) }
                            }
                        }
                    }
                    (readers + writers).awaitAll()
                }
            }

            // Final, user-visible decisions taken while unlocked.
            for (t in targets) manager.assignTargetToProfile(t, PermissionProfile.DEFAULT_DENY_PROFILE_ID)
            rules.revokeRule("r", nowEpochSec = 9_999L)
            f.keys.deviceLocked = true
            for (t in targets) {
                assertNeverAllowed("iteration $iteration target $t", levelOrFailClosed(manager, t))
            }
            val lockedRule = runCatching { rules.findRule("r") }.getOrNull()
            assertTrue(
                "iteration $iteration: revoked rule must not be served as active",
                lockedRule == null || lockedRule.approvalState == RuleApprovalState.REVOKED
            )
        }
    }

    @Test
    fun readerWriterTocTou_profileDowngradeInsideCacheWindowMustNotSurviveLock() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.assignTargetToProfile("pkg:com.bank", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)

        val armed = AtomicBoolean(false)
        val interposed = InterposingMap<String, PermissionProfile> { key, value ->
            if (key == "pkg:com.bank" &&
                value.id == PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID &&
                armed.compareAndSet(true, false)
            ) {
                // A second thread (e.g. the settings screen) revokes access exactly between the
                // reader's version check and its cache write.
                runBlocking {
                    manager.assignTargetToProfile("pkg:com.bank", PermissionProfile.DEFAULT_DENY_PROFILE_ID)
                }
            }
        }
        injectField(manager, "lastKnownProfileByTarget", interposed)

        armed.set(true)
        // Reader linearized before the revoke: returning ALLOW here is legitimate.
        manager.evaluateCapability("pkg:com.bank", AtomicCapability.NOTIFICATION_READ)
        assertFalse("hook must have fired", armed.get())

        f.keys.deviceLocked = true
        assertNeverAllowed(
            "revoked target served from locked-device cache",
            levelOrFailClosed(manager, "pkg:com.bank")
        )
    }

    @Test
    fun readerWriterTocTou_ruleRevokeInsideCacheWindowMustNotSurviveLock() = runBlocking {
        val f = fixture()
        val rules = newRules(f)
        approvedRule(rules, "night_quiet")

        val armed = AtomicBoolean(false)
        val interposed = InterposingMap<String, RuleCapabilityGrant> { key, value ->
            if (key == "night_quiet" &&
                value.approvalState == RuleApprovalState.APPROVED_ACTIVE &&
                armed.compareAndSet(true, false)
            ) {
                runBlocking { rules.revokeRule("night_quiet", nowEpochSec = 300L) }
            }
        }
        injectField(rules, "lastKnownGrantByRuleId", interposed)

        armed.set(true)
        rules.findRule("night_quiet")
        assertFalse("hook must have fired", armed.get())

        f.keys.deviceLocked = true
        val locked = rules.findRule("night_quiet")
        val executable = locked != null &&
            locked.approvalState == RuleApprovalState.APPROVED_ACTIVE &&
            rules.verifySeal(locked)
        assertFalse("revoked routine must never be executable from the locked-device cache", executable)
    }

    // ---------------------------------------------------------------------------------------
    // 5. Bounded audit buffer
    // ---------------------------------------------------------------------------------------

    @Test
    fun auditOverflow_dropsOldestCountsDropsAndFlushesRemainderInOrder() = runBlocking {
        val f = fixture()
        val audit = AuditLogDao(f.store)
        f.keys.deviceLocked = true
        for (i in 1..300) audit.record(entry(i))
        assertEquals(256, audit.pendingBufferedCount())
        assertEquals(44L, audit.droppedBufferedCount())

        f.keys.deviceLocked = false
        audit.record(entry(301))
        assertEquals(0, audit.pendingBufferedCount())

        val stored = f.storage.allRawRows(EncryptedTableSchema.TABLE_AUDIT_LOGS)
        assertEquals("256 survivors + 1 gap marker + the new entry", 258, stored.size)
        val all = audit.queryRecent(1_000)
        val markers = all.filter { it.decision == AuditLogDao.DECISION_AUDIT_BUFFER_GAP }
        assertEquals(1, markers.size)
        val marker = markers.single()
        assertEquals(AuditLogDao.AUDIT_GAP_TOOL_NAME, marker.toolName)
        assertEquals(AuditLogDao.AUDIT_GAP_TOOL_NAME, marker.targetId)
        assertEquals(DataProvenance.SYSTEM, marker.provenance)
        assertTrue(marker.actionSummary, marker.actionSummary.contains("dropped 44 entries"))
        // Position: after every flushed survivor and immediately before the triggering entry.
        val summariesInRowOrder = decodeInRowOrder(f, audit)
        assertEquals((45..300).map { "step $it" }, summariesInRowOrder.subList(0, 256))
        assertEquals(marker.actionSummary, summariesInRowOrder[256])
        assertEquals("step 301", summariesInRowOrder[257])
        val inRowOrder = all.filter { it.decision != AuditLogDao.DECISION_AUDIT_BUFFER_GAP }
            .sortedBy { it.timestampEpochMs }.map { it.actionSummary }
        assertEquals((45..301).map { "step $it" }, inRowOrder)
        // Row ids must follow original call order (no reordering during flush).
        val rowIds = stored.map { it.rowId }
        assertEquals(rowIds.sorted(), rowIds)
        val byRow = stored.sortedBy { it.rowId }.map { it.createdEpochSec }
        assertEquals(byRow.sorted(), byRow)
        assertEquals("no duplicates", inRowOrder.toSet().size, inRowOrder.size)
    }

    @Test
    fun auditRepeatedLockUnlockCycles_neverDuplicateOrLose() = runBlocking {
        val f = fixture()
        val audit = AuditLogDao(f.store)
        var n = 0
        repeat(10) { cycle ->
            f.keys.deviceLocked = cycle % 2 == 0
            repeat(7) { audit.record(entry(++n)) }
        }
        f.keys.deviceLocked = false
        audit.record(entry(++n))
        assertEquals(0, audit.pendingBufferedCount())
        assertEquals(0L, audit.droppedBufferedCount())
        val stored = f.storage.allRawRows(EncryptedTableSchema.TABLE_AUDIT_LOGS)
        assertEquals(n, stored.size)
        val createdInRowOrder = stored.sortedBy { it.rowId }.map { it.createdEpochSec }
        assertEquals((1..n).map { it.toLong() }, createdInRowOrder)
    }

    @Test
    fun auditNonTransientFailureOnNewEntry_propagatesButStillFlushesBuffer() = runBlocking {
        val faulty = FaultInjectingRowStorage()
        val keys = LockableKeyProvider()
        val store = EncryptedSqliteStore(storage = faulty, keyProvider = keys, dispatcher = Dispatchers.Unconfined)
        val audit = AuditLogDao(store)

        keys.deviceLocked = true
        for (i in 1..3) audit.record(entry(i))
        keys.deviceLocked = false

        var inserts = 0
        faulty.insertFault = { _ -> if (++inserts == 4) IllegalStateException("disk I/O error") else null }
        try {
            audit.record(entry(4))
            fail("A non-transient storage failure must propagate to the caller")
        } catch (e: IllegalStateException) {
            assertFalse(KeyUnavailability.isTransient(e))
        }
        assertEquals(0, audit.pendingBufferedCount())
        assertEquals(3, faulty.delegate.allRawRows(EncryptedTableSchema.TABLE_AUDIT_LOGS).size)
    }

    @Test
    fun auditPoisonedBufferedEntry_isDroppedAndCountedWithoutWedging() = runBlocking {
        val faulty = FaultInjectingRowStorage()
        val keys = LockableKeyProvider()
        val store = EncryptedSqliteStore(storage = faulty, keyProvider = keys, dispatcher = Dispatchers.Unconfined)
        val audit = AuditLogDao(store)

        keys.deviceLocked = true
        for (i in 1..5) audit.record(entry(i))
        keys.deviceLocked = false

        var inserts = 0
        faulty.insertFault = { _ -> if (++inserts == 2) IllegalArgumentException("poison row") else null }
        audit.record(entry(6))
        assertEquals(0, audit.pendingBufferedCount())
        assertEquals(1L, audit.droppedBufferedCount())
        val summaries = decodeInRowOrder(faulty.delegate, audit)
        assertEquals(
            listOf(
                "step 1", "step 3", "step 4", "step 5",
                "Audit buffer dropped 1 entries while the master key was unavailable",
                "step 6"
            ),
            summaries
        )
        val marker = audit.queryRecent(100).single { it.decision == AuditLogDao.DECISION_AUDIT_BUFFER_GAP }
        assertEquals(AuditLogDao.AUDIT_GAP_TOOL_NAME, marker.toolName)
        assertEquals(entry(6).timestampEpochMs, marker.timestampEpochMs)

        // The log keeps working afterwards and the gap is reported exactly once.
        faulty.insertFault = null
        audit.record(entry(7))
        assertEquals(7, faulty.delegate.allRawRows(EncryptedTableSchema.TABLE_AUDIT_LOGS).size)
        assertEquals(1, audit.queryRecent(100).count { it.decision == AuditLogDao.DECISION_AUDIT_BUFFER_GAP })
    }

    @Test
    fun auditTransientFailureMidFlush_keepsRemainingEntriesInOrder() = runBlocking {
        val faulty = FaultInjectingRowStorage()
        val keys = LockableKeyProvider()
        val store = EncryptedSqliteStore(storage = faulty, keyProvider = keys, dispatcher = Dispatchers.Unconfined)
        val audit = AuditLogDao(store)

        keys.deviceLocked = true
        for (i in 1..4) audit.record(entry(i))
        keys.deviceLocked = false

        var inserts = 0
        faulty.insertFault = { _ -> if (++inserts == 3) ProviderException("keystore busy") else null }
        audit.record(entry(5))
        // Entries 1 and 2 were flushed; 3, 4 and the new 5 remain buffered in order.
        assertEquals(3, audit.pendingBufferedCount())
        faulty.insertFault = null
        audit.record(entry(6))
        val stored = faulty.delegate.allRawRows(EncryptedTableSchema.TABLE_AUDIT_LOGS)
            .sortedBy { it.rowId }.map { it.createdEpochSec }
        assertEquals(listOf(1L, 2L, 3L, 4L, 5L, 6L), stored)
        assertEquals(0L, audit.droppedBufferedCount())
    }

    @Test
    fun auditCancellationDuringFlush_losesNothing() = runBlocking {
        val faulty = FaultInjectingRowStorage()
        val keys = LockableKeyProvider()
        val store = EncryptedSqliteStore(storage = faulty, keyProvider = keys, dispatcher = Dispatchers.Unconfined)
        val audit = AuditLogDao(store)

        keys.deviceLocked = true
        for (i in 1..3) audit.record(entry(i))
        keys.deviceLocked = false

        var inserts = 0
        faulty.insertFault = { _ -> if (++inserts == 2) CancellationException("worker stopped") else null }
        try {
            audit.record(entry(4))
            fail("cancellation must propagate")
        } catch (_: CancellationException) {
        }
        faulty.insertFault = null
        audit.record(entry(5))
        val stored = faulty.delegate.allRawRows(EncryptedTableSchema.TABLE_AUDIT_LOGS)
            .sortedBy { it.rowId }.map { it.createdEpochSec }
        // Entry 4 was the in-flight caller's own entry and was never acknowledged; buffered ones survive.
        assertTrue(stored.containsAll(listOf(1L, 2L, 3L, 5L)))
        assertEquals(stored.sorted(), stored)
        assertEquals(stored.toSet().size, stored.size)
    }

    @Test
    fun auditConcurrentRecordersAcrossLockFlaps_neverLoseOrDuplicateBelowBound() = runBlocking {
        val f = fixture()
        val audit = AuditLogDao(f.store)
        withTimeout(20_000L) {
            withContext(Dispatchers.Default) {
                val flapper = launch {
                    repeat(200) {
                        f.keys.deviceLocked = it % 2 == 0
                        kotlinx.coroutines.yield()
                    }
                }
                (1..8).map { w ->
                    async { for (i in 0 until 25) audit.record(entry(w * 1_000 + i)) }
                }.awaitAll()
                flapper.join()
            }
        }
        f.keys.deviceLocked = false
        audit.record(entry(999_999))
        assertEquals(0, audit.pendingBufferedCount())
        assertEquals(0L, audit.droppedBufferedCount())
        val stored = audit.queryRecent(1_000).map { it.actionSummary }
        assertEquals(201, stored.size)
        assertEquals(201, stored.toSet().size)
        // Per-writer order must be preserved (rowId order == call order for each writer).
        val rows = f.storage.allRawRows(EncryptedTableSchema.TABLE_AUDIT_LOGS).sortedBy { it.rowId }
        for (w in 1..8) {
            val seq = rows.map { it.createdEpochSec }.filter { it / 1_000L == w.toLong() }
            assertEquals(seq.sorted(), seq)
            assertEquals(25, seq.size)
        }
        assertNotEquals(0, rows.size)
    }
    // ---------------------------------------------------------------------------------------
    // 6. Re-run attacks against the publish-then-recheck retry loop
    // ---------------------------------------------------------------------------------------

    @Test
    fun relentlessRuleWriterRacingEveryAttempt_cacheEndsAtDatabaseStateOrEmpty() = runBlocking {
        val f = fixture()
        val rules = newRules(f)
        approvedRule(rules, "r")
        var races = 0
        val reentrant = AtomicBoolean(false)
        val hook = HookMap<String, RuleCapabilityGrant>(beforePut = { _, value ->
            if (races < 10 && reentrant.compareAndSet(false, true)) {
                races++
                runBlocking {
                    if (value.approvalState == RuleApprovalState.APPROVED_ACTIVE) {
                        rules.pauseRule("r", 1_000L + races)
                    } else {
                        rules.approveAndSealRule("r", 2_000L + races)
                    }
                }
                reentrant.set(false)
            }
        })
        injectField(rules, "lastKnownGrantByRuleId", hook)
        races = 0
        rules.findRule("r")
        assertTrue("writer must have raced every publish attempt", races >= 3)

        val truth = newRules(f).findRule("r")!!
        f.keys.deviceLocked = true
        val locked = runCatching { rules.findRule("r") }.getOrNull()
        assertTrue(
            "locked fallback must equal the latest DB state or fail closed (got ${locked?.approvalState}, db ${truth.approvalState})",
            locked == null || locked == truth
        )
    }

    @Test
    fun relentlessRuleWriterThatFinallyRevokes_revocationWinsAfterLock() = runBlocking {
        val f = fixture()
        val rules = newRules(f)
        approvedRule(rules, "r")
        var races = 0
        val reentrant = AtomicBoolean(false)
        val hook = HookMap<String, RuleCapabilityGrant>(beforePut = { _, value ->
            if (races < 3 && value.approvalState != RuleApprovalState.REVOKED && reentrant.compareAndSet(false, true)) {
                races++
                runBlocking {
                    when (races) {
                        1 -> rules.pauseRule("r", 1_001L)
                        2 -> rules.approveAndSealRule("r", 1_002L)
                        else -> rules.revokeRule("r", 1_003L)
                    }
                }
                reentrant.set(false)
            }
        })
        injectField(rules, "lastKnownGrantByRuleId", hook)
        rules.findRule("r")
        assertEquals(3, races)
        f.keys.deviceLocked = true
        val locked = runCatching { rules.findRule("r") }.getOrNull()
        val executable = locked != null &&
            locked.approvalState == RuleApprovalState.APPROVED_ACTIVE && rules.verifySeal(locked)
        assertFalse("revoked rule executable from cache after retry exhaustion", executable)
    }

    @Test
    fun relentlessProfileWriterRacingEveryAttempt_cacheEndsAtDatabaseStateOrEmpty() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.assignTargetToProfile("pkg:com.bank", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
        var races = 0
        val reentrant = AtomicBoolean(false)
        val hook = HookMap<String, PermissionProfile>(beforePut = { key, value ->
            if (key == "pkg:com.bank" && races < 10 && reentrant.compareAndSet(false, true)) {
                races++
                val next = if (value.id == PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID) {
                    PermissionProfile.DEFAULT_DENY_PROFILE_ID
                } else {
                    PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID
                }
                runBlocking { manager.assignTargetToProfile("pkg:com.bank", next) }
                reentrant.set(false)
            }
        })
        injectField(manager, "lastKnownProfileByTarget", hook)
        manager.evaluateCapability("pkg:com.bank", AtomicCapability.NOTIFICATION_READ)
        assertTrue(races >= 3)

        val truth = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
            .evaluateCapability("pkg:com.bank", AtomicCapability.NOTIFICATION_READ)
        f.keys.deviceLocked = true
        val locked = levelOrFailClosed(manager, "pkg:com.bank")
        assertTrue("locked level $locked must equal DB level $truth or fail closed", locked == null || locked == truth)
        if (!truth.isAllowed) assertNeverAllowed("racing downgrade", locked)
    }

    @Test
    fun relentlessProfileWriterEndingInDeny_neverAllowsAfterLock() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.assignTargetToProfile("pkg:com.bank", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
        var races = 0
        val reentrant = AtomicBoolean(false)
        val sequence = listOf(
            PermissionProfile.DEFAULT_DENY_PROFILE_ID,
            PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID,
            PermissionProfile.DEFAULT_DENY_PROFILE_ID
        )
        val hook = HookMap<String, PermissionProfile>(beforePut = { key, _ ->
            if (key == "pkg:com.bank" && races < sequence.size && reentrant.compareAndSet(false, true)) {
                val next = sequence[races++]
                runBlocking { manager.assignTargetToProfile("pkg:com.bank", next) }
                reentrant.set(false)
            }
        })
        injectField(manager, "lastKnownProfileByTarget", hook)
        manager.evaluateCapability("pkg:com.bank", AtomicCapability.NOTIFICATION_READ)
        assertEquals(3, races)
        f.keys.deviceLocked = true
        assertNeverAllowed("final DENY must win after retry exhaustion", levelOrFailClosed(manager, "pkg:com.bank"))
    }

    @Test
    fun warmSnapshotRacingAReassignment_neverLeavesStaleAllowForWarmedOnlyTarget() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.assignTargetToProfile("pkg:com.a", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
        manager.assignTargetToProfile("pkg:com.b", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
        val armed = AtomicBoolean(true)
        val hook = HookMap<String, PermissionProfile>(beforePutAll = { snapshot ->
            if (snapshot.containsKey("pkg:com.b") && armed.compareAndSet(true, false)) {
                // Snapshot was loaded with b=ALLOW; the user revokes b before it is published.
                runBlocking {
                    manager.assignTargetToProfile("pkg:com.b", PermissionProfile.DEFAULT_DENY_PROFILE_ID)
                }
            }
        })
        injectField(manager, "lastKnownProfileByTarget", hook)
        assertTrue(manager.evaluateCapability("pkg:com.a", AtomicCapability.NOTIFICATION_READ).isAllowed)
        assertFalse("warm hook must have fired", armed.get())
        f.keys.deviceLocked = true
        assertNeverAllowed("warmed-only target b after concurrent revoke", levelOrFailClosed(manager, "pkg:com.b"))
    }

    @Test
    fun lockedReaderInsidePublishWindow_neverSeesRuleAlreadyRevoked() = runBlocking {
        val f = fixture()
        val rules = newRules(f)
        approvedRule(rules, "r")
        val armed = AtomicBoolean(false)
        var observedInWindow: RuleCapabilityGrant? = null
        var windowProbed = false
        val hook = HookMap<String, RuleCapabilityGrant>(
            beforePut = { _, value ->
                if (value.approvalState == RuleApprovalState.APPROVED_ACTIVE && armed.get()) {
                    runBlocking { rules.revokeRule("r", 300L) } // revoke fully completes here
                }
            },
            afterPut = { _, value ->
                if (value.approvalState == RuleApprovalState.APPROVED_ACTIVE && armed.compareAndSet(true, false)) {
                    // A background routine on another thread, device now locked.
                    f.keys.deviceLocked = true
                    observedInWindow = runCatching { runBlocking { rules.findRule("r") } }.getOrNull()
                    windowProbed = true
                    f.keys.deviceLocked = false
                }
            }
        )
        injectField(rules, "lastKnownGrantByRuleId", hook)
        armed.set(true)
        rules.findRule("r")
        assertTrue(windowProbed)
        val seen = observedInWindow
        val executable = seen != null &&
            seen.approvalState == RuleApprovalState.APPROVED_ACTIVE && rules.verifySeal(seen)
        assertFalse("locked read after a completed revoke must not see the rule as executable", executable)
    }

    @Test
    fun auditPermanentKeyLossDuringFlush_keepsBufferIntactAndSurfaces() = runBlocking {
        val f = fixture()
        val audit = AuditLogDao(f.store)
        f.keys.deviceLocked = true
        for (i in 1..5) audit.record(entry(i))
        assertEquals(5, audit.pendingBufferedCount())

        for (failure in listOf<Throwable>(
            KeyPermanentlyInvalidatedExceptionDouble(),
            IllegalStateException("wrapped", KeyPermanentlyInvalidatedExceptionDouble()),
            ProviderException("outer", KeyPermanentlyInvalidatedExceptionDouble())
        )) {
            f.keys.permanentFailure = failure
            assertTrue(KeyUnavailability.isPermanentKeyLoss(failure))
            assertFalse(KeyUnavailability.isTransient(failure))
            val outcome = runCatching { audit.record(entry(99)) }
            assertTrue("permanent key loss must surface ($failure)", outcome.isFailure)
            assertEquals("buffer must stay intact ($failure)", 5, audit.pendingBufferedCount())
            assertEquals(0L, audit.droppedBufferedCount())
        }
        f.keys.permanentFailure = null
        f.keys.deviceLocked = false
        audit.record(entry(6))
        assertEquals(0, audit.pendingBufferedCount())
        val summaries = decodeInRowOrder(f, audit)
        assertEquals((1..6).map { "step $it" }, summaries)
    }

    @Test
    fun auditGapMarker_isEmittedOncePerLossEpochWithOnlyNewDrops() = runBlocking {
        val f = fixture()
        val audit = AuditLogDao(f.store)
        f.keys.deviceLocked = true
        for (i in 1..258) audit.record(entry(i)) // drops 1, 2
        f.keys.deviceLocked = false
        audit.record(entry(259))
        audit.record(entry(260)) // no new drops -> no new marker
        f.keys.deviceLocked = true
        for (i in 261..520) audit.record(entry(i)) // 260 recorded, drops 261..264 (4)
        f.keys.deviceLocked = false
        audit.record(entry(521))

        val markers = audit.queryRecent(10_000).filter { it.decision == AuditLogDao.DECISION_AUDIT_BUFFER_GAP }
            .sortedBy { it.timestampEpochMs }
        assertEquals(2, markers.size)
        assertTrue(markers[0].actionSummary, markers[0].actionSummary.contains("dropped 2 entries"))
        assertTrue(markers[1].actionSummary, markers[1].actionSummary.contains("dropped 4 entries"))
        assertEquals(entry(259).timestampEpochMs, markers[0].timestampEpochMs)
        assertEquals(entry(521).timestampEpochMs, markers[1].timestampEpochMs)
        assertEquals(6L, audit.droppedBufferedCount())
    }

    @Test
    fun auditGapMarkerHittingTransientFailure_isRetriedAndNeverDuplicated() = runBlocking {
        val faulty = FaultInjectingRowStorage()
        val keys = LockableKeyProvider()
        val store = EncryptedSqliteStore(storage = faulty, keyProvider = keys, dispatcher = Dispatchers.Unconfined)
        val audit = AuditLogDao(store)
        keys.deviceLocked = true
        for (i in 1..258) audit.record(entry(i))
        keys.deviceLocked = false

        var inserts = 0
        // Inserts 1..256 flush the buffer; insert 257 is the gap marker.
        faulty.insertFault = { _ -> if (++inserts == 257) ProviderException("keystore busy") else null }
        audit.record(entry(259))
        assertEquals("entry 259 must be buffered, not lost", 1, audit.pendingBufferedCount())
        faulty.insertFault = null
        audit.record(entry(260))
        assertEquals(0, audit.pendingBufferedCount())
        val all = audit.queryRecent(10_000)
        assertEquals(1, all.count { it.decision == AuditLogDao.DECISION_AUDIT_BUFFER_GAP })
        assertEquals(258, all.count { it.decision != AuditLogDao.DECISION_AUDIT_BUFFER_GAP })
        val summaries = decodeInRowOrder(faulty.delegate, audit)
        assertEquals("step 259", summaries[256])
        assertTrue(summaries[257].startsWith("Audit buffer dropped 2 entries"))
        assertEquals("step 260", summaries[258])
    }

    @Test
    fun auditNoDropsMeansNoGapMarker() = runBlocking {
        val f = fixture()
        val audit = AuditLogDao(f.store)
        repeat(4) { cycle ->
            f.keys.deviceLocked = cycle % 2 == 0
            for (i in 1..50) audit.record(entry(cycle * 100 + i))
        }
        f.keys.deviceLocked = false
        audit.record(entry(9_999))
        assertEquals(0, audit.queryRecent(10_000).count { it.decision == AuditLogDao.DECISION_AUDIT_BUFFER_GAP })
    }
    // ---------------------------------------------------------------------------------------
    // 7. Writer-only records (locked-device fallback) - publish window and record attacks
    // ---------------------------------------------------------------------------------------

    /** Binds [target] through a separate manager instance, i.e. before this process started. */
    private suspend fun bindInPreviousProcess(f: Fixture, target: String, profileId: String, custom: PermissionProfile? = null) {
        val previous = PermissionProfileManager(store = f.store, clockEpochSec = { 500L })
        if (custom != null) previous.saveProfile(custom)
        previous.assignTargetToProfile(target, profileId)
    }

    /**
     * Runs [writer] inside the reader's publish window (before the stale put) and probes a
     * locked-device read right after the stale value was published. Returns the probed level.
     */
    private suspend fun probeProfilePublishWindow(
        f: Fixture,
        manager: PermissionProfileManager,
        target: String,
        writer: suspend () -> Unit
    ): ConfirmationLevel? {
        val armed = AtomicBoolean(true)
        var probed: ConfirmationLevel? = null
        var probedOnce = false
        val hook = HookMap<String, PermissionProfile>(
            beforePut = { key, value ->
                if (key == target && value.levelFor(AtomicCapability.NOTIFICATION_READ).isAllowed && armed.get()) {
                    runBlocking { writer() }
                }
            },
            afterPut = { key, value ->
                if (key == target && value.levelFor(AtomicCapability.NOTIFICATION_READ).isAllowed &&
                    armed.compareAndSet(true, false)
                ) {
                    f.keys.deviceLocked = true
                    probed = runBlocking { levelOrFailClosed(manager, target) }
                    probedOnce = true
                    f.keys.deviceLocked = false
                }
            }
        )
        injectField(manager, "lastKnownProfileByTarget", hook)
        manager.evaluateCapability(target, AtomicCapability.NOTIFICATION_READ)
        assertTrue("publish window must have been probed", probedOnce)
        return probed
    }

    @Test
    fun profilePublishWindow_reassignToDenyIsNeverShadowedForLockedRead() = runBlocking {
        val f = fixture()
        bindInPreviousProcess(f, "pkg:com.bank", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        val probed = probeProfilePublishWindow(f, manager, "pkg:com.bank") {
            manager.assignTargetToProfile("pkg:com.bank", PermissionProfile.DEFAULT_DENY_PROFILE_ID)
        }
        assertNeverAllowed("locked read in publish window after reassign", probed)
        f.keys.deviceLocked = true
        assertNeverAllowed("locked read after window", levelOrFailClosed(manager, "pkg:com.bank"))
    }

    @Test
    fun profilePublishWindow_profileEditToDenyIsNeverShadowedForLockedRead() = runBlocking {
        val f = fixture()
        bindInPreviousProcess(f, "pkg:com.bank", "custom_c", customProfile("custom_c", ConfirmationLevel.AUTO))
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        val probed = probeProfilePublishWindow(f, manager, "pkg:com.bank") {
            manager.saveProfile(customProfile("custom_c", ConfirmationLevel.DISABLED))
        }
        assertNeverAllowed("locked read in publish window after profile edit", probed)
        f.keys.deviceLocked = true
        assertNeverAllowed("locked read after window", levelOrFailClosed(manager, "pkg:com.bank"))
    }

    @Test
    fun profilePublishWindow_profileDeleteIsNeverShadowedForLockedRead() = runBlocking {
        val f = fixture()
        bindInPreviousProcess(f, "pkg:com.bank", "custom_c", customProfile("custom_c", ConfirmationLevel.AUTO))
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        val probed = probeProfilePublishWindow(f, manager, "pkg:com.bank") {
            manager.deleteProfile("custom_c")
        }
        assertNeverAllowed("locked read in publish window after profile delete", probed)
        f.keys.deviceLocked = true
        assertNeverAllowed("locked read after window", levelOrFailClosed(manager, "pkg:com.bank"))
    }

    @Test
    fun rulePublishWindow_pauseIsNeverShadowedForLockedRead() = runBlocking {
        val f = fixture()
        approvedRule(newRules(f), "r") // previous process
        val rules = newRules(f)
        val armed = AtomicBoolean(true)
        var seen: RuleCapabilityGrant? = null
        val hook = HookMap<String, RuleCapabilityGrant>(
            beforePut = { _, v ->
                if (v.approvalState == RuleApprovalState.APPROVED_ACTIVE && armed.get()) {
                    runBlocking { rules.pauseRule("r", 300L) }
                }
            },
            afterPut = { _, v ->
                if (v.approvalState == RuleApprovalState.APPROVED_ACTIVE && armed.compareAndSet(true, false)) {
                    f.keys.deviceLocked = true
                    seen = runCatching { runBlocking { rules.findRule("r") } }.getOrNull()
                    f.keys.deviceLocked = false
                }
            }
        )
        injectField(rules, "lastKnownGrantByRuleId", hook)
        rules.findRule("r")
        assertFalse(armed.get())
        assertTrue(
            "paused rule seen as ${seen?.approvalState}",
            seen == null || seen!!.approvalState == RuleApprovalState.PAUSED
        )
    }

    @Test
    fun writerRecords_reassignAfterDeleteUsesNewestBinding() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.saveProfile(customProfile("custom_c", ConfirmationLevel.AUTO))
        manager.assignTargetToProfile("pkg:com.x", "custom_c")
        manager.deleteProfile("custom_c")
        manager.assignTargetToProfile("pkg:com.x", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
        manager.assignTargetToProfile("pkg:com.x", PermissionProfile.DEFAULT_DENY_PROFILE_ID)
        f.keys.deviceLocked = true
        assertNeverAllowed("newest binding is Default-Deny", levelOrFailClosed(manager, "pkg:com.x"))
        f.keys.deviceLocked = false
        manager.assignTargetToProfile("pkg:com.x", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
        f.keys.deviceLocked = true
        assertEquals(
            "newest binding to an allowing preset is honored while locked",
            ConfirmationLevel.AUTO,
            manager.evaluateCapability("pkg:com.x", AtomicCapability.NOTIFICATION_READ)
        )
    }

    @Test
    fun writerRecords_deletedProfileStaysDenyForPreBoundAndInProcessTargets() = runBlocking {
        val f = fixture()
        bindInPreviousProcess(f, "pkg:com.pre", "custom_c", customProfile("custom_c", ConfirmationLevel.AUTO))
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.assignTargetToProfile("pkg:com.live", "custom_c")
        assertTrue(manager.evaluateCapability("pkg:com.pre", AtomicCapability.NOTIFICATION_READ).isAllowed)
        manager.deleteProfile("custom_c")
        f.keys.deviceLocked = true
        assertNeverAllowed("pre-bound target of deleted profile", levelOrFailClosed(manager, "pkg:com.pre"))
        assertNeverAllowed("in-process target of deleted profile", levelOrFailClosed(manager, "pkg:com.live"))
    }

    @Test
    fun writerRecords_deleteThenRecreateSameIdNeverResurrectsDeletedBinding() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.saveProfile(customProfile("work", ConfirmationLevel.DISABLED))
        manager.assignTargetToProfile("pkg:com.x", "work")
        manager.deleteProfile("work") // binding pkg:com.x -> work is deleted: Default-Deny
        manager.saveProfile(customProfile("work", ConfirmationLevel.AUTO)) // unrelated new profile
        assertFalse(
            "unlocked truth: deleted binding is Default-Deny",
            manager.evaluateCapability("pkg:com.x", AtomicCapability.NOTIFICATION_READ).isAllowed
        )
        f.keys.deviceLocked = true
        assertNeverAllowed("deleted binding resurrected by recreated id", levelOrFailClosed(manager, "pkg:com.x"))
    }

    @Test
    fun writerRecords_presetIdsCannotBeOverwrittenOrEscalated() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.assignTargetToProfile("pkg:com.x", PermissionProfile.NOTIFICATION_SUMMARY_PROFILE_ID)
        for (presetId in PermissionProfile.IMMUTABLE_PRESET_IDS) {
            val forged = customProfile(presetId, ConfirmationLevel.AUTO).copy(
                capabilities = AtomicCapability.entries.associateWith {
                    if (it == AtomicCapability.MODIFY_DELETE_SEND) ConfirmationLevel.PROMPT_CARD else ConfirmationLevel.AUTO
                }
            )
            assertTrue(runCatching { manager.saveProfile(forged) }.isFailure)
            assertTrue(runCatching { manager.deleteProfile(presetId) }.isFailure)
        }
        f.keys.deviceLocked = true
        val locked = manager.getProfileForTarget("pkg:com.x")
        assertEquals(PermissionProfile.notificationSummaryOnly().capabilities, locked.capabilities)
        assertEquals(ConfirmationLevel.DISABLED, locked.levelFor(AtomicCapability.MODIFY_DELETE_SEND))
        assertEquals(ConfirmationLevel.DISABLED, locked.levelFor(AtomicCapability.DATA_READ))
    }

    @Test
    fun writerRecords_preBoundTargetNeverWrittenInProcess() = runBlocking {
        val f = fixture()
        bindInPreviousProcess(f, "pkg:com.pre", "custom_c", customProfile("custom_c", ConfirmationLevel.AUTO))
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })

        // Never resolved in-process: fails closed while locked.
        f.keys.deviceLocked = true
        assertNull(levelOrFailClosed(manager, "pkg:com.pre"))
        f.keys.deviceLocked = false

        // Resolved once: honored while locked.
        assertTrue(manager.evaluateCapability("pkg:com.pre", AtomicCapability.NOTIFICATION_READ).isAllowed)
        f.keys.deviceLocked = true
        assertEquals(ConfirmationLevel.AUTO, manager.evaluateCapability("pkg:com.pre", AtomicCapability.NOTIFICATION_READ))
        f.keys.deviceLocked = false

        // Editing the profile (only the profile, not the binding) is reflected while locked.
        manager.saveProfile(customProfile("custom_c", ConfirmationLevel.DISABLED))
        f.keys.deviceLocked = true
        assertNeverAllowed("edited pre-bound profile", levelOrFailClosed(manager, "pkg:com.pre"))
        f.keys.deviceLocked = false

        // Re-enabling the profile without any unlocked read must not exceed the DB truth.
        manager.saveProfile(customProfile("custom_c", ConfirmationLevel.AUTO))
        f.keys.deviceLocked = true
        val level = levelOrFailClosed(manager, "pkg:com.pre")
        assertTrue("got $level", level == null || level == ConfirmationLevel.AUTO)
    }

    @Test
    fun writerRecords_unrelatedTargetsOfEditedProfileNeverEscalate() = runBlocking {
        val f = fixture()
        val manager = PermissionProfileManager(store = f.store, clockEpochSec = { 1_000L })
        manager.saveProfile(customProfile("c1", ConfirmationLevel.DISABLED))
        manager.saveProfile(customProfile("c2", ConfirmationLevel.AUTO))
        manager.assignTargetToProfile("pkg:com.x", "c1")
        assertFalse(manager.evaluateCapability("pkg:com.x", AtomicCapability.NOTIFICATION_READ).isAllowed)
        // Editing / binding other profiles must not change x's locked decision.
        manager.assignTargetToProfile("pkg:com.y", "c2")
        manager.saveProfile(customProfile("c2", ConfirmationLevel.AUTO))
        f.keys.deviceLocked = true
        assertNeverAllowed("x stays on c1", levelOrFailClosed(manager, "pkg:com.x"))
        assertNeverAllowed("unknown target", levelOrFailClosed(manager, "pkg:com.z"))
    }
}

package com.nava.core.security.redteam

import com.nava.core.security.dao.ActionCacheDao
import com.nava.core.security.dao.AuditLogDao
import com.nava.core.security.dao.CachedActionTemplate
import com.nava.core.security.dao.EncryptedNote
import com.nava.core.security.dao.EncryptedNoteDao
import com.nava.core.security.policy.PermissionProfileManager
import com.nava.core.security.policy.RuleCapabilityGrantManager
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.storage.StructuredPayloadCodec
import com.nava.core.security.testing.InMemoryRowStorage
import com.nava.core.security.testing.InMemorySoftwareKeyProvider
import com.nava.core.security.vault.NavaVault
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.PermissionProfilePreset
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleTriggerSpec
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import javax.crypto.AEADBadTagException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Gate 2 Independent Adversarial Red-Team Suite:
 * [EncryptedSqliteStore] AAD / Ciphertext Tampering, Opacity, Blind-Index Collision Probes,
 * [StructuredPayloadCodec] Malformed Binary Fuzzing, and [NavaVault] AI Lock, Memory Zeroization,
 * Path Traversal, and Envelope Tampering.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CryptoTamperAndVaultZeroizationRedTeamTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun crossRowCrossTableAndCrossColumnCiphertextSwapsThrowAeadBadTagException() = runTest {
        val storage = InMemoryRowStorage()
        val keyProvider = InMemorySoftwareKeyProvider()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = keyProvider,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )

        val row1Id = store.insertEncrypted(
            tableName = EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
            lookupHmac = store.computeBlindIndex("note", "n1"),
            plaintext = "TOP_SECRET_NOTE_ONE".toByteArray(Charsets.UTF_8),
            epochSec = 100L
        )
        val row2Id = store.insertEncrypted(
            tableName = EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
            lookupHmac = store.computeBlindIndex("note", "n2"),
            plaintext = "TOP_SECRET_NOTE_TWO".toByteArray(Charsets.UTF_8),
            epochSec = 101L
        )
        val auditRow1Id = store.insertEncrypted(
            tableName = EncryptedTableSchema.TABLE_AUDIT_LOGS,
            lookupHmac = store.computeBlindIndex("audit", "a1"),
            plaintext = "AUDIT_PAYLOAD_ONE".toByteArray(Charsets.UTF_8),
            epochSec = 102L
        )
        assertEquals(row1Id, auditRow1Id)

        val rawNote1 = storage.inspectRawRow(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, row1Id)!!

        // 1. Cross-row swap in the same table (copy row 1 blob into row 2)
        assertTrue(
            storage.replaceRawBlob(
                EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
                row2Id,
                rawNote1.payloadBlob
            )
        )
        try {
            store.findDecryptedByRowId(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, row2Id)
            fail("Expected AEADBadTagException on cross-row ciphertext swap")
        } catch (_: AEADBadTagException) {
            // Expected
        }

        // 2. Cross-table swap with IDENTICAL rowId (copy encrypted_notes row 1 blob into audit_logs row 1)
        assertTrue(
            storage.replaceRawBlob(
                EncryptedTableSchema.TABLE_AUDIT_LOGS,
                auditRow1Id,
                rawNote1.payloadBlob
            )
        )
        try {
            store.findDecryptedByRowId(EncryptedTableSchema.TABLE_AUDIT_LOGS, auditRow1Id)
            fail("Expected AEADBadTagException on cross-table ciphertext swap")
        } catch (_: AEADBadTagException) {
            // Expected
        }

        // 3. Cross-column AAD mismatch (encrypt under col_a, attempt decrypt under col_b)
        val colABlob = store.encryptColumn(
            tableName = EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
            rowId = 7L,
            columnName = "col_a",
            plaintext = "COLUMN_BOUND_SECRET".toByteArray(Charsets.UTF_8)
        )
        try {
            store.decryptColumn(
                tableName = EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
                rowId = 7L,
                columnName = "col_b",
                blob = colABlob
            )
            fail("Expected AEADBadTagException on cross-column AAD mismatch")
        } catch (_: AEADBadTagException) {
            // Expected
        }
    }

    @Test
    fun singleBitFlipsInIvCiphertextTagAndTruncatedBlobFailAuthentication() = runTest {
        val storage = InMemoryRowStorage()
        val keyProvider = InMemorySoftwareKeyProvider()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = keyProvider,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )

        val rowId = store.insertEncrypted(
            tableName = EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
            lookupHmac = store.computeBlindIndex("note", "bitflip"),
            plaintext = "AUTHENTICATED_PAYLOAD_DATA".toByteArray(Charsets.UTF_8),
            epochSec = 200L
        )
        val originalBlob = storage.inspectRawRow(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, rowId)!!.payloadBlob

        // Flip bit in IV (byte 0), ciphertext body (byte 14), and GCM tag (last byte)
        val flipPositions = listOf(0, 14, originalBlob.lastIndex)
        for (pos in flipPositions) {
            val mutated = originalBlob.copyOf()
            mutated[pos] = (mutated[pos].toInt() xor 0x01).toByte()
            storage.replaceRawBlob(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, rowId, mutated)
            try {
                store.findDecryptedByRowId(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, rowId)
                fail("Expected AEADBadTagException when flipping bit at offset $pos")
            } catch (_: AEADBadTagException) {
                // Expected
            }
        }

        // Truncated blob (< IV + TAG = 28 bytes)
        storage.replaceRawBlob(
            EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
            rowId,
            originalBlob.copyOfRange(0, 20)
        )
        try {
            store.findDecryptedByRowId(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, rowId)
            fail("Expected IllegalArgumentException for truncated blob")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }

    @Test
    fun ciphertextOpacityAcrossAllFiveEncryptedTablesContainsZeroPlaintextSubstrings() = runTest {
        val storage = InMemoryRowStorage()
        val keyProvider = InMemorySoftwareKeyProvider()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = keyProvider,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )

        val auditMarker = "CANARY_AUDIT_SECRET_9821"
        val profileMarker = "CANARY_PROFILE_SECRET_7742"
        val ruleMarker = "CANARY_RULE_SECRET_5519"
        val cacheMarker = "CANARY_CACHE_SECRET_3390"
        val noteMarker = "CANARY_NOTE_SECRET_1184"

        AuditLogDao(store).record(
            AuditLogEntry(
                timestampEpochMs = 1_750_000_000_000L,
                toolName = "sms.create_draft",
                targetId = "com.canary.sms",
                actionSummary = auditMarker,
                provenance = DataProvenance.USER_UTTERANCE,
                decision = "AUTHORIZED"
            )
        )
        PermissionProfileManager(store).saveProfile(
            PermissionProfile(
                id = "custom_canary_id",
                name = profileMarker,
                preset = PermissionProfilePreset.CUSTOM,
                capabilities = mapOf(AtomicCapability.DATA_READ to ConfirmationLevel.PROMPT_CARD)
            )
        )
        RuleCapabilityGrantManager(store, keyProvider).createPendingRule(
            ruleId = "rule_canary",
            triggerSpec = RuleTriggerSpec("TIME_DAILY", mapOf("label" to ruleMarker)),
            staticActions = listOf(RuleActionSpec("alarm.set", AtomicCapability.CREATE_DRAFT)),
            nowEpochSec = 100L
        )
        ActionCacheDao(store).putTemplate(
            template = CachedActionTemplate(
                languageCode = "en",
                canonicalSkeleton = cacheMarker,
                toolNames = listOf("alarm.set"),
                toolSchemaVersions = mapOf("alarm.set" to 1),
                serializedPlanTemplate = "alarm.set(label=$cacheMarker)",
                lastUsedEpochSec = 100L
            ),
            provenance = DataProvenance.USER_UTTERANCE,
            touchesVault = false,
            nowEpochSec = 100L
        )
        EncryptedNoteDao(store).saveNote(
            EncryptedNote(
                noteId = "note_canary",
                title = "Secret Title",
                body = noteMarker,
                updatedEpochSec = 100L
            )
        )

        val checks = mapOf(
            EncryptedTableSchema.TABLE_AUDIT_LOGS to auditMarker,
            EncryptedTableSchema.TABLE_PERMISSION_PROFILES to profileMarker,
            EncryptedTableSchema.TABLE_AUTOMATION_RULES to ruleMarker,
            EncryptedTableSchema.TABLE_ACTION_CACHE to cacheMarker,
            EncryptedTableSchema.TABLE_ENCRYPTED_NOTES to noteMarker
        )

        for ((table, marker) in checks) {
            val rows = storage.allRawRows(table)
            assertTrue("Expected persisted rows in $table", rows.isNotEmpty())
            val markerBytes = marker.toByteArray(Charsets.UTF_8)
            for (row in rows) {
                assertFalse(
                    "Raw payloadBlob in $table leaked plaintext marker '$marker'",
                    containsSubarray(row.payloadBlob, markerBytes)
                )
                assertFalse(
                    "Raw lookupHmac in $table leaked plaintext marker '$marker'",
                    row.lookupHmac.contains(marker)
                )
            }
        }
    }

    @Test
    fun blindIndexRejectsNullByteDelimiterInjectionInAnySegment() {
        val storage = InMemoryRowStorage()
        val keyProvider = InMemorySoftwareKeyProvider()
        val store = EncryptedSqliteStore(storage = storage, keyProvider = keyProvider)

        val invalidSegmentLists = listOf(
            arrayOf("en\u0000skeleton"),
            arrayOf("en", "wake\u0000up"),
            arrayOf("\u0000", "valid")
        )
        for (segments in invalidSegmentLists) {
            try {
                store.computeBlindIndex(*segments)
                fail("Expected IllegalArgumentException for null byte in blind index segment")
            } catch (_: IllegalArgumentException) {
                // Expected
            }
        }
    }

    @Test
    fun structuredPayloadCodecRejectsMalformedAndOversizedAdversarialInputs() {
        // 1. Bad magic header
        assertCodecIoFailure(byteArrayOf('E'.code.toByte(), 'V'.code.toByte(), 'I'.code.toByte(), 'L'.code.toByte(), 0, 0, 0, 1)) {
            readInt()
        }

        // 2. Version 0
        assertCodecIoFailure(rawHeaderBytes(version = 0)) {
            readInt()
        }

        // 3. Oversized length prefix (Int.MAX_VALUE) -> must throw IOException without OOM
        val oversizedString = buildRawPayload(version = 1) {
            writeInt(Int.MAX_VALUE)
        }
        assertCodecIoFailure(oversizedString) {
            readString()
        }

        // 4. Negative collection size
        val negativeList = buildRawPayload(version = 1) {
            writeInt(-5)
        }
        assertCodecIoFailure(negativeList) {
            readStringList()
        }

        // 5. Trailing garbage bytes after valid payload
        val valid = StructuredPayloadCodec.encode(formatVersion = 1) {
            writeString("ok")
        }
        val withTrailing = valid + byteArrayOf(0x42)
        assertCodecIoFailure(withTrailing) {
            readString()
        }
    }

    @Test
    fun navaVaultEnforcesStrictAiLockWhenLocked() = runTest {
        val vaultDir = File(tempFolder.root, "vault_locked")
        val keyProvider = InMemorySoftwareKeyProvider()
        val vault = NavaVault(
            vaultDir = vaultDir,
            keyProvider = keyProvider,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )

        assertFalse(vault.isUnlocked())
        assertThrowsSecurity("listNoteIds while locked") { vault.listNoteIds() }
        assertThrowsSecurity("readNote while locked") { vault.readNote("secret_note") }
        assertThrowsSecurity("writeNote while locked") {
            vault.writeNote("secret_note", "blocked".toByteArray(Charsets.UTF_8))
        }
        assertThrowsSecurity("deleteNote while locked") { vault.deleteNote("secret_note") }
    }

    @Test
    fun navaVaultZeroizesPlaintextBuffersOnLockCloseScopedBlockTimeoutAndNegativeClockSkew() = runTest {
        val vaultDir = File(tempFolder.root, "vault_zeroize")
        val keyProvider = InMemorySoftwareKeyProvider()
        var nowMs = 100_000L
        val vault = NavaVault(
            vaultDir = vaultDir,
            keyProvider = keyProvider,
            sessionTimeoutMs = 15_000L,
            clockMs = { nowMs },
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )

        // Unlock and seed notes
        vault.unlockWithAuthenticatedCipher(vault.prepareUnlockCipher())
        vault.writeNote("note_a", "ALPHA_SECRET_BUFFER".toByteArray(Charsets.UTF_8))
        vault.writeNote("note_b", "BRAVO_SECRET_BUFFER".toByteArray(Charsets.UTF_8))

        // 1. Explicit lock() zeroizes ALL returned ByteArrays from multiple readNote calls
        val bufA = vault.readNote("note_a")
        val bufB = vault.readNote("note_b")
        assertEquals("ALPHA_SECRET_BUFFER", bufA.toString(Charsets.UTF_8))
        assertEquals("BRAVO_SECRET_BUFFER", bufB.toString(Charsets.UTF_8))
        vault.lock()
        assertFalse(vault.isUnlocked())
        assertAllZero(bufA, "bufA after lock()")
        assertAllZero(bufB, "bufB after lock()")

        // 2. close() zeroizes buffers
        vault.unlockWithAuthenticatedCipher(vault.prepareUnlockCipher())
        val bufClose = vault.readNote("note_a")
        vault.close()
        assertFalse(vault.isUnlocked())
        assertAllZero(bufClose, "bufClose after close()")

        // 3. withDecryptedNote zeroizes on both normal completion AND exception thrown in lambda
        vault.unlockWithAuthenticatedCipher(vault.prepareUnlockCipher())
        var capturedNormal: ByteArray? = null
        val text = vault.withDecryptedNote("note_a") { bytes ->
            capturedNormal = bytes
            bytes.toString(Charsets.UTF_8)
        }
        assertEquals("ALPHA_SECRET_BUFFER", text)
        assertNotNull(capturedNormal)
        assertAllZero(capturedNormal!!, "withDecryptedNote normal completion")

        var capturedOnError: ByteArray? = null
        try {
            vault.withDecryptedNote("note_b") { bytes ->
                capturedOnError = bytes
                throw IllegalStateException("Simulated consumer failure")
            }
            fail("Expected IllegalStateException to propagate")
        } catch (_: IllegalStateException) {
            // Expected
        }
        assertNotNull(capturedOnError)
        assertAllZero(capturedOnError!!, "withDecryptedNote exception path")

        // 4. Automatic session-timeout expiration zeroizes buffers and blocks subsequent readNote
        val bufTimeout = vault.readNote("note_a")
        nowMs += 15_001L
        assertFalse(vault.isUnlocked())
        assertAllZero(bufTimeout, "bufTimeout after session timeout")
        assertThrowsSecurity("readNote after session timeout") { vault.readNote("note_a") }

        // 5. Negative clock skew auto-locks and zeroizes
        vault.unlockWithAuthenticatedCipher(vault.prepareUnlockCipher())
        val bufSkew = vault.readNote("note_b")
        nowMs -= 1L
        assertFalse(vault.isUnlocked())
        assertAllZero(bufSkew, "bufSkew after negative clock skew")
        assertThrowsSecurity("readNote after negative clock skew") { vault.readNote("note_b") }
    }

    @Test
    fun navaVaultRejectsPathTraversalAndHiddenFileNoteIds() = runTest {
        val vaultDir = File(tempFolder.root, "vault_traversal")
        val keyProvider = InMemorySoftwareKeyProvider()
        val vault = NavaVault(
            vaultDir = vaultDir,
            keyProvider = keyProvider,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )
        vault.unlockWithAuthenticatedCipher(vault.prepareUnlockCipher())

        val evilIds = listOf(
            "../outside",
            "../../etc/passwd",
            ".vault_dek",
            ".hidden",
            "sub/note",
            "sub\\note",
            "note\u0000id",
            "",
            "a".repeat(129),
            "note..id"
        )

        for (evilId in evilIds) {
            assertThrowsSecurity("writeNote('$evilId')") {
                vault.writeNote(evilId, "evil".toByteArray(Charsets.UTF_8))
            }
            assertThrowsSecurity("readNote('$evilId')") {
                vault.readNote(evilId)
            }
            assertThrowsSecurity("deleteNote('$evilId')") {
                vault.deleteNote(evilId)
            }
        }
        vault.lock()
    }

    @Test
    fun navaVaultRejectsCrossNoteSwapDekTamperAndBiometricKeyRotation() = runTest {
        val vaultDir = File(tempFolder.root, "vault_tamper")
        val keyProvider = InMemorySoftwareKeyProvider()
        val vault = NavaVault(
            vaultDir = vaultDir,
            keyProvider = keyProvider,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )

        vault.unlockWithAuthenticatedCipher(vault.prepareUnlockCipher())
        vault.writeNote("noteA", "SECRET_A".toByteArray(Charsets.UTF_8))
        vault.writeNote("noteB", "SECRET_B".toByteArray(Charsets.UTF_8))

        // 1. Cross-note ciphertext swap: copy noteA.nava bytes onto noteB.nava -> AEADBadTagException
        val fileA = File(vaultDir, "noteA.nava")
        val fileB = File(vaultDir, "noteB.nava")
        val originalBBytes = fileB.readBytes()
        fileB.writeBytes(fileA.readBytes())
        try {
            vault.readNote("noteB")
            fail("Expected AEADBadTagException on swapped vault note ciphertext")
        } catch (_: AEADBadTagException) {
            // Expected (noteId-bound AAD)
        }
        // Restore noteB and verify clean decrypt
        fileB.writeBytes(originalBBytes)
        assertArrayEquals("SECRET_B".toByteArray(Charsets.UTF_8), vault.readNote("noteB"))
        vault.lock()

        // 2. Bit-flipping .vault_dek.bin -> AEADBadTagException and vault stays locked
        val dekFile = File(vaultDir, ".vault_dek.bin")
        val originalDekBytes = dekFile.readBytes()
        val tamperedDek = originalDekBytes.copyOf()
        tamperedDek[tamperedDek.lastIndex] = (tamperedDek[tamperedDek.lastIndex].toInt() xor 0x01).toByte()
        dekFile.writeBytes(tamperedDek)

        try {
            val cipher = vault.prepareUnlockCipher()
            vault.unlockWithAuthenticatedCipher(cipher)
            fail("Expected AEADBadTagException when .vault_dek.bin tag is tampered")
        } catch (_: AEADBadTagException) {
            // Expected
        }
        assertFalse(vault.isUnlocked())

        // Restore .vault_dek.bin, then rotate nava_vault_biometric_key -> AEADBadTagException and stays locked
        dekFile.writeBytes(originalDekBytes)
        keyProvider.rotateVaultKey()
        try {
            val cipher = vault.prepareUnlockCipher()
            vault.unlockWithAuthenticatedCipher(cipher)
            fail("Expected AEADBadTagException after biometric key rotation")
        } catch (_: AEADBadTagException) {
            // Expected
        }
        assertFalse(vault.isUnlocked())
    }

    private suspend fun assertThrowsSecurity(label: String, block: suspend () -> Unit) {
        try {
            block()
            fail("Expected SecurityException for $label")
        } catch (_: SecurityException) {
            // Expected
        }
    }

    private fun assertAllZero(buffer: ByteArray, label: String) {
        assertTrue("Expected buffer [$label] to be completely zeroized (0x00)", buffer.all { it == 0.toByte() })
    }

    private fun assertCodecIoFailure(
        bytes: ByteArray,
        readerBlock: StructuredPayloadCodec.PayloadReader.(Int) -> Any?
    ) {
        try {
            StructuredPayloadCodec.decode(bytes = bytes, expectedVersion = 1, block = readerBlock)
            fail("Expected IOException from StructuredPayloadCodec.decode")
        } catch (_: IOException) {
            // Expected
        }
    }

    private fun rawHeaderBytes(version: Int): ByteArray = buildRawPayload(version) {}

    private fun buildRawPayload(version: Int, body: DataOutputStream.() -> Unit): ByteArray {
        val baos = ByteArrayOutputStream()
        DataOutputStream(baos).use { dos ->
            dos.write('N'.code)
            dos.write('A'.code)
            dos.write('V'.code)
            dos.write('A'.code)
            dos.writeInt(version)
            dos.body()
            dos.flush()
        }
        return baos.toByteArray()
    }

    private fun containsSubarray(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (i in 0..(haystack.size - needle.size)) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }
}

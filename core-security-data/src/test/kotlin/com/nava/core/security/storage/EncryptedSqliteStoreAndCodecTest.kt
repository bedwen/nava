package com.nava.core.security.storage

import com.nava.core.security.testing.InMemoryRowStorage
import com.nava.core.security.testing.InMemorySoftwareKeyProvider
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.IOException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class EncryptedSqliteStoreAndCodecTest {

    @Test
    fun structuredPayloadCodecRoundTripAllSupportedTypes() {
        val sampleBytes = byteArrayOf(1, 2, 3, 127, -1)
        val encoded = StructuredPayloadCodec.encode(formatVersion = 1) {
            writeInt(42)
            writeLong(9_876_543_210L)
            writeBoolean(true)
            writeString("Hello \u0130stanbul")
            writeNullableString(null)
            writeNullableString("present")
            writeBytes(sampleBytes)
            writeStringList(listOf("alpha", "beta"))
            writeStringSet(setOf("z", "a", "m"))
            writeStringMap(mapOf("k2" to "v2", "k1" to "v1"))
        }

        StructuredPayloadCodec.decode(encoded, expectedVersion = 1) { version ->
            assertEquals(1, version)
            assertEquals(42, readInt())
            assertEquals(9_876_543_210L, readLong())
            assertTrue(readBoolean())
            assertEquals("Hello \u0130stanbul", readString())
            assertNull(readNullableString())
            assertEquals("present", readNullableString())
            assertArrayEquals(sampleBytes, readBytes())
            assertEquals(listOf("alpha", "beta"), readStringList())
            assertEquals(setOf("a", "m", "z"), readStringSet())
            assertEquals(mapOf("k1" to "v1", "k2" to "v2"), readStringMap())
        }
    }

    @Test
    fun structuredPayloadCodecRejectsMalformedHeaderVersionBoundsAndTrailingBytes() {
        assertIoException {
            StructuredPayloadCodec.decode(byteArrayOf(1, 2, 3)) { }
        }

        val badMagic = "BAD!1234".toByteArray(Charsets.UTF_8)
        assertIoException {
            StructuredPayloadCodec.decode(badMagic) { }
        }

        val zeroVersionBytes = buildRawHeaderPayload(version = 0)
        assertIoException {
            StructuredPayloadCodec.decode(zeroVersionBytes, expectedVersion = 0) { }
        }

        val v2Bytes = StructuredPayloadCodec.encode(formatVersion = 2) { writeInt(1) }
        assertIoException {
            StructuredPayloadCodec.decode(v2Bytes, expectedVersion = 1) { readInt() }
        }

        val oversizedLenBytes = ByteArrayOutputStream().apply {
            DataOutputStream(this).use { dos ->
                dos.write("NAVA".toByteArray(Charsets.US_ASCII))
                dos.writeInt(1)
                dos.writeInt(StructuredPayloadCodec.MAX_STRING_BYTES + 1)
            }
        }.toByteArray()
        assertIoException {
            StructuredPayloadCodec.decode(oversizedLenBytes) { readString() }
        }

        val truncatedBytes = ByteArrayOutputStream().apply {
            DataOutputStream(this).use { dos ->
                dos.write("NAVA".toByteArray(Charsets.US_ASCII))
                dos.writeInt(1)
                dos.writeInt(50)
                dos.writeByte(65)
            }
        }.toByteArray()
        assertIoException {
            StructuredPayloadCodec.decode(truncatedBytes) { readString() }
        }

        val validWithExtra = StructuredPayloadCodec.encode {
            writeInt(10)
            writeInt(20)
        }
        assertIoException {
            StructuredPayloadCodec.decode(validWithExtra) { readInt() }
        }
    }

    @Test
    fun storeInsertUpsertLookupTouchEvictAndDelete() = runTest {
        val storage = InMemoryRowStorage()
        val keyProvider = InMemorySoftwareKeyProvider()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = keyProvider,
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )

        val hmac1 = store.computeBlindIndex("note", "n1")
        val rowId1 = store.insertEncrypted(
            tableName = EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
            lookupHmac = hmac1,
            plaintext = "First body".toByteArray(Charsets.UTF_8),
            epochSec = 100L,
            schemaVersion = 1
        )
        assertEquals(1L, rowId1)

        val foundByIndex = store.findDecryptedByBlindIndex(
            EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
            hmac1
        )
        assertNotNull(foundByIndex)
        assertEquals("First body", foundByIndex!!.plaintext.toString(Charsets.UTF_8))
        foundByIndex.zeroize()

        val foundById = store.findDecryptedByRowId(
            EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
            rowId1
        )
        assertNotNull(foundById)
        assertEquals(rowId1, foundById!!.rowId)
        foundById.zeroize()

        val rawBeforeUpsert = storage.inspectRawRow(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, rowId1)!!

        val upsertedRowId = store.upsertEncryptedByBlindIndex(
            tableName = EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
            lookupHmac = hmac1,
            plaintext = "Updated body".toByteArray(Charsets.UTF_8),
            epochSec = 200L,
            schemaVersion = 1
        )
        assertEquals(rowId1, upsertedRowId)

        val afterUpsert = store.findDecryptedByRowId(
            EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
            rowId1
        )!!
        assertEquals(100L, afterUpsert.createdEpochSec)
        assertEquals(200L, afterUpsert.updatedEpochSec)
        assertEquals("Updated body", afterUpsert.plaintext.toString(Charsets.UTF_8))
        afterUpsert.zeroize()

        val rawAfterUpsert = storage.inspectRawRow(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, rowId1)!!
        assertFalse(rawBeforeUpsert.payloadBlob.contentEquals(rawAfterUpsert.payloadBlob))

        assertTrue(
            store.touchUpdatedEpochSec(
                tableName = EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
                rowId = rowId1,
                updatedEpochSec = 500L
            )
        )
        val rawAfterTouch = storage.inspectRawRow(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, rowId1)!!
        assertArrayEquals(rawAfterUpsert.payloadBlob, rawAfterTouch.payloadBlob)
        assertEquals(500L, rawAfterTouch.updatedEpochSec)

        val hmac2 = store.computeBlindIndex("note", "n2")
        val hmac3 = store.computeBlindIndex("note", "n3")
        store.insertEncrypted(
            tableName = EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
            lookupHmac = hmac2,
            plaintext = "Second".toByteArray(Charsets.UTF_8),
            epochSec = 300L
        )
        store.insertEncrypted(
            tableName = EncryptedTableSchema.TABLE_ENCRYPTED_NOTES,
            lookupHmac = hmac3,
            plaintext = "Third".toByteArray(Charsets.UTF_8),
            epochSec = 400L
        )

        val recent = store.listRecentDecrypted(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, limit = 2)
        assertEquals(2, recent.size)
        assertEquals("Updated body", recent[0].plaintext.toString(Charsets.UTF_8))
        assertEquals("Third", recent[1].plaintext.toString(Charsets.UTF_8))
        recent.forEach { it.zeroize() }

        val evictedCount = store.evictLru(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, maxEntries = 2)
        assertEquals(1, evictedCount)
        assertNull(store.findDecryptedByBlindIndex(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, hmac2))

        assertTrue(store.deleteByBlindIndex(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, hmac3))
        assertFalse(store.deleteByBlindIndex(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, hmac3))

        val remaining = store.listAllDecrypted(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES)
        assertEquals(1, remaining.size)
        remaining.forEach { it.zeroize() }

        assertTrue(store.deleteByRowId(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, rowId1))
        assertFalse(store.deleteByRowId(EncryptedTableSchema.TABLE_ENCRYPTED_NOTES, rowId1))

        store.close()
    }

    @Test
    fun storeRejectsDisallowedTablesAndInvalidParameters() = runTest {
        val store = EncryptedSqliteStore(
            storage = InMemoryRowStorage(),
            keyProvider = InMemorySoftwareKeyProvider(),
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )

        try {
            store.insertEncrypted(
                tableName = "sqlite_master",
                lookupHmac = "abcd",
                plaintext = byteArrayOf(1),
                epochSec = 10L
            )
            fail("Expected IllegalArgumentException for disallowed table")
        } catch (_: IllegalArgumentException) {
            // Expected
        }

        try {
            store.insertEncrypted(
                tableName = EncryptedTableSchema.TABLE_AUDIT_LOGS,
                lookupHmac = " ",
                plaintext = byteArrayOf(1),
                epochSec = 10L
            )
            fail("Expected IllegalArgumentException for blank lookupHmac")
        } catch (_: IllegalArgumentException) {
            // Expected
        }

        try {
            store.insertEncrypted(
                tableName = EncryptedTableSchema.TABLE_AUDIT_LOGS,
                lookupHmac = "abcd",
                plaintext = byteArrayOf(1),
                epochSec = 10L,
                schemaVersion = 0
            )
            fail("Expected IllegalArgumentException for non-positive schemaVersion")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }

    @Test
    fun computeStructuredBlindIndexIsNullByteSafeAndSeparatesSegments() = runTest {
        val store = EncryptedSqliteStore(
            storage = InMemoryRowStorage(),
            keyProvider = InMemorySoftwareKeyProvider(),
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )

        val h1 = store.computeStructuredBlindIndex("audit_target", "app\u0000injected")
        val h2 = store.computeStructuredBlindIndex("audit_target", "app\u0000injected")
        assertEquals(64, h1.length)
        assertEquals(h1, h2)

        val boundary1 = store.computeStructuredBlindIndex("a", "bc")
        val boundary2 = store.computeStructuredBlindIndex("ab", "c")
        assertFalse(boundary1 == boundary2)

        val nullBoundary1 = store.computeStructuredBlindIndex("a\u0000b", "c")
        val nullBoundary2 = store.computeStructuredBlindIndex("a", "b\u0000c")
        assertFalse(nullBoundary1 == nullBoundary2)

        try {
            store.computeStructuredBlindIndex()
            fail("Expected IllegalArgumentException for empty segments")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }

    @Test
    fun listRecentDecryptedByBlindIndexReturnsIndexedRowsNewestFirst() = runTest {
        val store = EncryptedSqliteStore(
            storage = InMemoryRowStorage(),
            keyProvider = InMemorySoftwareKeyProvider(),
            dispatcher = UnconfinedTestDispatcher(testScheduler)
        )

        val targetHmac = store.computeStructuredBlindIndex("audit_target", "com.example.target")
        val otherHmac = store.computeStructuredBlindIndex("audit_target", "com.example.other")

        store.insertEncrypted(
            tableName = EncryptedTableSchema.TABLE_AUDIT_LOGS,
            lookupHmac = targetHmac,
            plaintext = "oldest".toByteArray(Charsets.UTF_8),
            epochSec = 100L
        )
        store.insertEncrypted(
            tableName = EncryptedTableSchema.TABLE_AUDIT_LOGS,
            lookupHmac = otherHmac,
            plaintext = "other".toByteArray(Charsets.UTF_8),
            epochSec = 500L
        )
        store.insertEncrypted(
            tableName = EncryptedTableSchema.TABLE_AUDIT_LOGS,
            lookupHmac = targetHmac,
            plaintext = "middle".toByteArray(Charsets.UTF_8),
            epochSec = 200L
        )
        store.insertEncrypted(
            tableName = EncryptedTableSchema.TABLE_AUDIT_LOGS,
            lookupHmac = targetHmac,
            plaintext = "newest".toByteArray(Charsets.UTF_8),
            epochSec = 300L
        )

        assertTrue(
            store.listRecentDecryptedByBlindIndex(
                tableName = EncryptedTableSchema.TABLE_AUDIT_LOGS,
                lookupHmac = targetHmac,
                limit = 0
            ).isEmpty()
        )

        val top2 = store.listRecentDecryptedByBlindIndex(
            tableName = EncryptedTableSchema.TABLE_AUDIT_LOGS,
            lookupHmac = targetHmac,
            limit = 2
        )
        assertEquals(2, top2.size)
        assertEquals("newest", top2[0].plaintext.toString(Charsets.UTF_8))
        assertEquals("middle", top2[1].plaintext.toString(Charsets.UTF_8))
        top2.forEach { it.zeroize() }
    }

    private fun buildRawHeaderPayload(version: Int): ByteArray {
        val baos = ByteArrayOutputStream()
        DataOutputStream(baos).use { dos ->
            dos.write("NAVA".toByteArray(Charsets.US_ASCII))
            dos.writeInt(version)
        }
        return baos.toByteArray()
    }

    private fun assertIoException(block: () -> Unit) {
        try {
            block()
            fail("Expected IOException")
        } catch (_: IOException) {
            // Expected
        }
    }
}

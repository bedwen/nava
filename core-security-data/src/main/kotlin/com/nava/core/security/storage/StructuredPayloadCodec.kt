package com.nava.core.security.storage

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException

/**
 * Pure Kotlin binary length-prefixed codec over standard JDK streams.
 *
 * Wire format:
 * - 4-byte ASCII magic header: `"NAVA"`
 * - 4-byte big-endian format version integer
 * - Length-prefixed typed fields with strict allocation bounds ([MAX_STRING_BYTES], [MAX_COLLECTION_SIZE])
 *
 * Replaces external serialization libraries (Gson/Moshi/kotlinx-serialization) per Iron Law 2.
 */
object StructuredPayloadCodec {
    private val MAGIC_BYTES: ByteArray = byteArrayOf(
        'N'.code.toByte(),
        'A'.code.toByte(),
        'V'.code.toByte(),
        'A'.code.toByte()
    )

    const val CURRENT_FORMAT_VERSION: Int = 1
    const val MAX_STRING_BYTES: Int = 1024 * 1024
    const val MAX_COLLECTION_SIZE: Int = 10_000
    private const val HEADER_SIZE_BYTES: Int = 8

    /**
     * Encodes structured fields using [block] prefixed with the `"NAVA"` header and [formatVersion].
     */
    fun encode(
        formatVersion: Int = CURRENT_FORMAT_VERSION,
        block: PayloadWriter.() -> Unit
    ): ByteArray {
        require(formatVersion > 0) { "formatVersion must be positive, got $formatVersion" }
        val baos = ByteArrayOutputStream(128)
        DataOutputStream(baos).use { dos ->
            dos.write(MAGIC_BYTES)
            dos.writeInt(formatVersion)
            PayloadWriter(dos).block()
            dos.flush()
        }
        return baos.toByteArray()
    }

    /**
     * Decodes [bytes], validating the `"NAVA"` magic header, version constraint, bounded field
     * lengths, and trailing-byte exhaustion.
     *
     * Pass [expectedVersion] = `0` to accept any positive format version and inspect `version`
     * inside [block].
     */
    fun <T> decode(
        bytes: ByteArray,
        expectedVersion: Int = CURRENT_FORMAT_VERSION,
        block: PayloadReader.(version: Int) -> T
    ): T {
        if (bytes.size < HEADER_SIZE_BYTES) {
            throw IOException("Structured payload too short: ${bytes.size} bytes")
        }
        for (i in MAGIC_BYTES.indices) {
            if (bytes[i] != MAGIC_BYTES[i]) {
                throw IOException("Invalid structured payload magic header")
            }
        }
        val bais = ByteArrayInputStream(bytes, MAGIC_BYTES.size, bytes.size - MAGIC_BYTES.size)
        return DataInputStream(bais).use { dis ->
            val version = dis.readInt()
            if (version <= 0) {
                throw IOException("Invalid structured payload version: $version")
            }
            if (expectedVersion > 0 && version != expectedVersion) {
                throw IOException(
                    "Unexpected structured payload version: expected $expectedVersion, got $version"
                )
            }
            val reader = PayloadReader(dis, bais)
            val result = reader.block(version)
            reader.assertFullyConsumed()
            result
        }
    }

    /**
     * Bounded binary writer for deterministic structured payload encoding.
     */
    class PayloadWriter internal constructor(
        private val out: DataOutputStream
    ) {
        fun writeInt(value: Int) {
            out.writeInt(value)
        }

        fun writeLong(value: Long) {
            out.writeLong(value)
        }

        fun writeBoolean(value: Boolean) {
            out.writeBoolean(value)
        }

        fun writeString(value: String) {
            val encoded = value.toByteArray(Charsets.UTF_8)
            require(encoded.size <= MAX_STRING_BYTES) {
                "String byte length ${encoded.size} exceeds MAX_STRING_BYTES ($MAX_STRING_BYTES)"
            }
            out.writeInt(encoded.size)
            out.write(encoded)
        }

        fun writeNullableString(value: String?) {
            if (value == null) {
                out.writeInt(NULL_LENGTH_MARKER)
            } else {
                writeString(value)
            }
        }

        fun writeBytes(value: ByteArray) {
            require(value.size <= MAX_STRING_BYTES) {
                "Byte array length ${value.size} exceeds MAX_STRING_BYTES ($MAX_STRING_BYTES)"
            }
            out.writeInt(value.size)
            out.write(value)
        }

        fun writeStringList(values: List<String>) {
            require(values.size <= MAX_COLLECTION_SIZE) {
                "List size ${values.size} exceeds MAX_COLLECTION_SIZE ($MAX_COLLECTION_SIZE)"
            }
            out.writeInt(values.size)
            for (item in values) {
                writeString(item)
            }
        }

        fun writeStringSet(values: Set<String>) {
            require(values.size <= MAX_COLLECTION_SIZE) {
                "Set size ${values.size} exceeds MAX_COLLECTION_SIZE ($MAX_COLLECTION_SIZE)"
            }
            val sorted = values.sorted()
            out.writeInt(sorted.size)
            for (item in sorted) {
                writeString(item)
            }
        }

        fun writeStringMap(values: Map<String, String>) {
            require(values.size <= MAX_COLLECTION_SIZE) {
                "Map size ${values.size} exceeds MAX_COLLECTION_SIZE ($MAX_COLLECTION_SIZE)"
            }
            val sortedKeys = values.keys.sorted()
            out.writeInt(sortedKeys.size)
            for (key in sortedKeys) {
                writeString(key)
                writeString(values.getValue(key))
            }
        }
    }

    /**
     * Bounded binary reader protecting against oversized length prefixes and trailing garbage.
     */
    class PayloadReader internal constructor(
        private val input: DataInputStream,
        private val backingStream: ByteArrayInputStream
    ) {
        fun readInt(): Int = input.readInt()

        fun readLong(): Long = input.readLong()

        fun readBoolean(): Boolean = input.readBoolean()

        fun readString(): String {
            val length = input.readInt()
            val bytes = readBoundedBytes(length)
            return String(bytes, Charsets.UTF_8)
        }

        fun readNullableString(): String? {
            val length = input.readInt()
            if (length == NULL_LENGTH_MARKER) {
                return null
            }
            val bytes = readBoundedBytes(length)
            return String(bytes, Charsets.UTF_8)
        }

        fun readBytes(): ByteArray {
            val length = input.readInt()
            return readBoundedBytes(length)
        }

        fun readStringList(): List<String> {
            val size = readBoundedCollectionSize()
            val list = ArrayList<String>(size)
            repeat(size) {
                list.add(readString())
            }
            return list
        }

        fun readStringSet(): Set<String> {
            val size = readBoundedCollectionSize()
            val set = LinkedHashSet<String>(size)
            repeat(size) {
                set.add(readString())
            }
            return set
        }

        fun readStringMap(): Map<String, String> {
            val size = readBoundedCollectionSize()
            val map = LinkedHashMap<String, String>(size)
            repeat(size) {
                val key = readString()
                val value = readString()
                map[key] = value
            }
            return map
        }

        fun assertFullyConsumed() {
            if (backingStream.available() != 0) {
                throw IOException(
                    "Unexpected trailing bytes in structured payload: ${backingStream.available()} remaining"
                )
            }
        }

        private fun readBoundedCollectionSize(): Int {
            val size = input.readInt()
            if (size < 0 || size > MAX_COLLECTION_SIZE) {
                throw IOException(
                    "Collection size $size out of bounds [0, $MAX_COLLECTION_SIZE]"
                )
            }
            return size
        }

        private fun readBoundedBytes(length: Int): ByteArray {
            if (length < 0 || length > MAX_STRING_BYTES) {
                throw IOException(
                    "Field byte length $length out of bounds [0, $MAX_STRING_BYTES]"
                )
            }
            if (length > backingStream.available()) {
                throw IOException(
                    "Declared field length $length exceeds remaining payload bytes (${backingStream.available()})"
                )
            }
            val buffer = ByteArray(length)
            input.readFully(buffer)
            return buffer
        }
    }

    private const val NULL_LENGTH_MARKER: Int = -1
}

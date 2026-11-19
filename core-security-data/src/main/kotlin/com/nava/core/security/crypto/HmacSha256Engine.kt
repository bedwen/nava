package com.nava.core.security.crypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Deterministic `HmacSHA256` engine for blind-index computation and constant-time seal verification.
 */
class HmacSha256Engine {

    /** Computes the raw 32-byte HMAC-SHA256 tag over [data] using [key]. */
    fun computeHmac(key: SecretKey, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(key)
        return mac.doFinal(data)
    }

    /** Computes the lowercase 64-character hex HMAC-SHA256 tag over [data] using [key]. */
    fun computeHmacHex(key: SecretKey, data: ByteArray): String {
        val raw = computeHmac(key, data)
        return toHex(raw)
    }

    /**
     * Computes a domain-separated blind index by joining [segments] with `\u0000`.
     *
     * Rejects any segment containing `\u0000` to prevent ambiguity or domain-separator collisions.
     */
    fun computeBlindIndex(key: SecretKey, vararg segments: String): String {
        require(segments.isNotEmpty()) { "Blind index requires at least one segment" }
        for (segment in segments) {
            require(DOMAIN_SEPARATOR !in segment) {
                "Blind index segment must not contain null byte delimiter"
            }
        }
        val joined = segments.joinToString(separator = DOMAIN_SEPARATOR.toString())
        val payload = joined.toByteArray(Charsets.UTF_8)
        return SecureMemory.withZeroizedBytes(payload) { computeHmacHex(key, it) }
    }

    /**
     * Verifies [expectedHex] against the freshly computed HMAC-SHA256 of [data] in constant time
     * using [MessageDigest.isEqual].
     */
    fun verifyHmacHex(key: SecretKey, data: ByteArray, expectedHex: String): Boolean {
        val expectedBytes = decodeHexOrNull(expectedHex) ?: return false
        if (expectedBytes.size != DIGEST_LENGTH_BYTES) return false
        val actualBytes = computeHmac(key, data)
        return try {
            MessageDigest.isEqual(actualBytes, expectedBytes)
        } finally {
            SecureMemory.zeroize(actualBytes)
            SecureMemory.zeroize(expectedBytes)
        }
    }

    private fun toHex(bytes: ByteArray): String {
        val chars = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            chars[i * 2] = HEX_CHARS[v ushr 4]
            chars[i * 2 + 1] = HEX_CHARS[v and 0x0F]
        }
        return String(chars)
    }

    private fun decodeHexOrNull(hex: String): ByteArray? {
        if (hex.length != DIGEST_LENGTH_BYTES * 2) return null
        val out = ByteArray(DIGEST_LENGTH_BYTES)
        for (i in 0 until DIGEST_LENGTH_BYTES) {
            val hi = hexDigit(hex[i * 2])
            val lo = hexDigit(hex[i * 2 + 1])
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    private fun hexDigit(ch: Char): Int = when (ch) {
        in '0'..'9' -> ch - '0'
        in 'a'..'f' -> ch - 'a' + 10
        in 'A'..'F' -> ch - 'A' + 10
        else -> -1
    }

    companion object {
        const val ALGORITHM: String = "HmacSHA256"
        const val DIGEST_LENGTH_BYTES: Int = 32
        private const val DOMAIN_SEPARATOR: Char = '\u0000'
        private val HEX_CHARS: CharArray = "0123456789abcdef".toCharArray()
    }
}

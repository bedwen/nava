package com.nava.core.security.crypto

/**
 * Explicit memory zeroization utilities for sensitive plaintext and key material.
 */
object SecureMemory {

    /** Overwrites every byte in [buffer] with `0x00`. */
    fun zeroize(buffer: ByteArray?) {
        buffer?.fill(0)
    }

    /** Overwrites every character in [buffer] with `\u0000`. */
    fun zeroize(buffer: CharArray?) {
        buffer?.fill('\u0000')
    }

    /** Executes [block] with [bytes] and unconditionally zeroizes [bytes] in `finally`. */
    inline fun <R> withZeroizedBytes(bytes: ByteArray, block: (ByteArray) -> R): R {
        return try {
            block(bytes)
        } finally {
            zeroize(bytes)
        }
    }
}

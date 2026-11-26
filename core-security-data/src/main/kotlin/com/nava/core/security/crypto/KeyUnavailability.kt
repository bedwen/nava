package com.nava.core.security.crypto

import java.security.InvalidKeyException
import java.security.ProviderException
import javax.crypto.AEADBadTagException

/**
 * Classifies Keystore failures that are transient by design, such as the
 * `nava_db_master_key` being unusable while the device is locked
 * (`setUnlockedDeviceRequired(true)` raises `UserNotAuthenticatedException`, an
 * [InvalidKeyException], or a keystore/provider error).
 *
 * Never transient (always propagate, fail closed):
 * - [AEADBadTagException] anywhere in the cause chain: a tampered or swapped ciphertext.
 * - `KeyPermanentlyInvalidatedException` (or any `KeyPermanentlyInvalidated*` type) anywhere in
 *   the cause chain: the key is gone for good, so cached decisions must not be served and audit
 *   writes must surface the failure instead of buffering forever.
 */
object KeyUnavailability {
    private const val MAX_CAUSE_DEPTH: Int = 8
    private const val ANDROID_KEYSTORE_EXCEPTION: String = "android.security.KeyStoreException"
    private const val ANDROID_KEY_PERMANENTLY_INVALIDATED: String =
        "android.security.keystore.KeyPermanentlyInvalidatedException"
    private const val PERMANENT_INVALIDATION_MARKER: String = "KeyPermanentlyInvalidated"

    fun isTransient(error: Throwable): Boolean {
        var current: Throwable? = error
        var depth = 0
        var transient = false
        while (current != null && depth < MAX_CAUSE_DEPTH) {
            if (current is AEADBadTagException || isPermanentInvalidation(current)) {
                return false
            }
            if (
                current is InvalidKeyException ||
                current is ProviderException ||
                current.javaClass.name == ANDROID_KEYSTORE_EXCEPTION
            ) {
                transient = true
            }
            current = current.cause?.takeIf { it !== current }
            depth++
        }
        return transient
    }

    /**
     * True when the master key itself is permanently gone. Callers must treat this as a key-level
     * failure (surface it), never as a defect of the individual record being written.
     */
    fun isPermanentKeyLoss(error: Throwable): Boolean {
        var current: Throwable? = error
        var depth = 0
        while (current != null && depth < MAX_CAUSE_DEPTH) {
            if (isPermanentInvalidation(current)) return true
            current = current.cause?.takeIf { it !== current }
            depth++
        }
        return false
    }

    private fun isPermanentInvalidation(error: Throwable): Boolean {
        var type: Class<*>? = error.javaClass
        while (type != null && type != Throwable::class.java) {
            if (
                type.name == ANDROID_KEY_PERMANENTLY_INVALIDATED ||
                type.simpleName.contains(PERMANENT_INVALIDATION_MARKER)
            ) {
                return true
            }
            type = type.superclass
        }
        return false
    }
}

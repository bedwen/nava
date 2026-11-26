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
 * Integrity failures are never transient: an [AEADBadTagException] anywhere in the cause chain
 * means a tampered or swapped ciphertext and must always propagate (fail closed).
 */
object KeyUnavailability {
    private const val MAX_CAUSE_DEPTH: Int = 8
    private const val ANDROID_KEYSTORE_EXCEPTION: String = "android.security.KeyStoreException"

    fun isTransient(error: Throwable): Boolean {
        var current: Throwable? = error
        var depth = 0
        var transient = false
        while (current != null && depth < MAX_CAUSE_DEPTH) {
            if (current is AEADBadTagException) {
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
}

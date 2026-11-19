package com.nava.core.security.crypto

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Authenticated encryption engine backed by standard JCA `AES/GCM/NoPadding`
 * (96-bit IV / 12 bytes, 128-bit authentication tag).
 *
 * Wire format for blobs: `iv (12 bytes) || ciphertext || gcmTag (16 bytes)`.
 */
class AesGcmCryptoEngine {

    /**
     * Encrypts [plaintext] using [key] and binds [aad] (Associated Authenticated Data).
     *
     * The cipher is initialized without a caller-supplied IV so Android Keystore's
     * randomized encryption enforcement (`setRandomizedEncryptionRequired(true)`) succeeds.
     */
    fun encrypt(key: SecretKey, plaintext: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return encryptWithCipher(cipher, plaintext, aad)
    }

    /**
     * Decrypts [blob] (`iv || ciphertext || tag`) using [key] and verifies [aad].
     *
     * Propagates `AEADBadTagException` (or `GeneralSecurityException`) on any ciphertext
     * modification, truncation, key mismatch, or AAD mismatch.
     */
    fun decrypt(key: SecretKey, blob: ByteArray, aad: ByteArray): ByteArray {
        require(blob.size >= MIN_BLOB_BYTES) {
            "Encrypted blob must be at least $MIN_BLOB_BYTES bytes, got ${blob.size}"
        }
        val iv = blob.copyOfRange(0, IV_LENGTH_BYTES)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_LENGTH_BITS, iv))
        if (aad.isNotEmpty()) {
            cipher.updateAAD(aad)
        }
        return cipher.doFinal(blob, IV_LENGTH_BYTES, blob.size - IV_LENGTH_BYTES)
    }

    /**
     * Encrypts [plaintext] with a pre-initialized [cipher] (such as one authenticated via
     * `BiometricPrompt.CryptoObject`), returning `iv (12B) || ciphertext || tag (16B)`.
     */
    fun encryptWithCipher(cipher: Cipher, plaintext: ByteArray, aad: ByteArray): ByteArray {
        val iv = cipher.iv ?: throw IllegalStateException("AES-GCM cipher produced a null IV")
        require(iv.size == IV_LENGTH_BYTES) {
            "Expected $IV_LENGTH_BYTES-byte GCM IV, got ${iv.size}"
        }
        if (aad.isNotEmpty()) {
            cipher.updateAAD(aad)
        }
        val ciphertextWithTag = cipher.doFinal(plaintext)
        val output = ByteArray(IV_LENGTH_BYTES + ciphertextWithTag.size)
        System.arraycopy(iv, 0, output, 0, IV_LENGTH_BYTES)
        System.arraycopy(ciphertextWithTag, 0, output, IV_LENGTH_BYTES, ciphertextWithTag.size)
        return output
    }

    /**
     * Decrypts [ciphertextWithTag] (without leading IV) using a pre-initialized [cipher]
     * authenticated via `BiometricPrompt.CryptoObject`, verifying [aad].
     */
    fun decryptWithCipher(cipher: Cipher, ciphertextWithTag: ByteArray, aad: ByteArray): ByteArray {
        require(ciphertextWithTag.size >= TAG_LENGTH_BYTES) {
            "Ciphertext with GCM tag must be at least $TAG_LENGTH_BYTES bytes, got ${ciphertextWithTag.size}"
        }
        if (aad.isNotEmpty()) {
            cipher.updateAAD(aad)
        }
        return cipher.doFinal(ciphertextWithTag)
    }

    /**
     * Builds canonical row-bound Associated Data (`"$tableName:$rowId:$columnName"`) in UTF-8
     * so ciphertexts cannot be swapped across tables, rows, or columns without triggering
     * `AEADBadTagException`.
     */
    fun buildRowAad(tableName: String, rowId: Long, columnName: String): ByteArray {
        require(tableName.isNotBlank() && ':' !in tableName) {
            "AAD tableName must be non-blank and must not contain ':'"
        }
        require(rowId > 0L) {
            "AAD rowId must be strictly positive, got $rowId"
        }
        require(columnName.isNotBlank() && ':' !in columnName) {
            "AAD columnName must be non-blank and must not contain ':'"
        }
        return "$tableName:$rowId:$columnName".toByteArray(Charsets.UTF_8)
    }

    companion object {
        const val TRANSFORMATION: String = "AES/GCM/NoPadding"
        const val IV_LENGTH_BYTES: Int = 12
        const val TAG_LENGTH_BITS: Int = 128
        const val TAG_LENGTH_BYTES: Int = 16
        const val MIN_BLOB_BYTES: Int = IV_LENGTH_BYTES + TAG_LENGTH_BYTES
    }
}

package com.nava.core.security.crypto

import com.nava.core.security.testing.InMemorySoftwareKeyProvider
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CryptoEnginesTest {

    private val keyProvider = InMemorySoftwareKeyProvider()
    private val aesGcmEngine = AesGcmCryptoEngine()
    private val hmacEngine = HmacSha256Engine()

    @Test
    fun aesGcmEncryptDecryptRoundTripWithRowAad() {
        val key = keyProvider.getOrCreateDbMasterKey()
        val plaintext = "Secret Nava payload".toByteArray(Charsets.UTF_8)
        val aad = aesGcmEngine.buildRowAad("audit_logs", 42L, "payload_blob")

        val encrypted = aesGcmEngine.encrypt(key, plaintext, aad)
        assertTrue(encrypted.size >= AesGcmCryptoEngine.MIN_BLOB_BYTES + plaintext.size)

        val decrypted = aesGcmEngine.decrypt(key, encrypted, aad)
        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun aesGcmGeneratesUniqueRandom12ByteIvs() {
        val key = keyProvider.getOrCreateDbMasterKey()
        val plaintext = "Identical input".toByteArray(Charsets.UTF_8)
        val aad = aesGcmEngine.buildRowAad("action_cache", 1L, "payload_blob")

        val ivs = HashSet<String>()
        repeat(16) {
            val blob = aesGcmEngine.encrypt(key, plaintext, aad)
            val iv = blob.copyOfRange(0, AesGcmCryptoEngine.IV_LENGTH_BYTES)
            assertEquals(12, iv.size)
            ivs.add(iv.joinToString(","))
        }
        assertEquals(16, ivs.size)
    }

    @Test
    fun aesGcmRejectsMismatchedAad() {
        val key = keyProvider.getOrCreateDbMasterKey()
        val plaintext = "Protected row".toByteArray(Charsets.UTF_8)
        val aadRow1 = aesGcmEngine.buildRowAad("encrypted_notes", 1L, "payload_blob")
        val aadRow2 = aesGcmEngine.buildRowAad("encrypted_notes", 2L, "payload_blob")

        val blob = aesGcmEngine.encrypt(key, plaintext, aadRow1)
        try {
            aesGcmEngine.decrypt(key, blob, aadRow2)
            fail("Expected AEADBadTagException when AAD does not match")
        } catch (_: AEADBadTagException) {
            // Expected
        }
    }

    @Test
    fun aesGcmEncryptAndDecryptWithPreInitializedCipher() {
        val key = keyProvider.getOrCreateVaultBiometricKey()
        val plaintext = "Biometric DEK bytes".toByteArray(Charsets.UTF_8)
        val aad = "vault:dek:v1".toByteArray(Charsets.UTF_8)

        val encryptCipher = Cipher.getInstance(AesGcmCryptoEngine.TRANSFORMATION)
        encryptCipher.init(Cipher.ENCRYPT_MODE, key)
        val blob = aesGcmEngine.encryptWithCipher(encryptCipher, plaintext, aad)

        val iv = blob.copyOfRange(0, AesGcmCryptoEngine.IV_LENGTH_BYTES)
        val ciphertextWithTag = blob.copyOfRange(AesGcmCryptoEngine.IV_LENGTH_BYTES, blob.size)

        val decryptCipher = Cipher.getInstance(AesGcmCryptoEngine.TRANSFORMATION)
        decryptCipher.init(
            Cipher.DECRYPT_MODE,
            key,
            GCMParameterSpec(AesGcmCryptoEngine.TAG_LENGTH_BITS, iv)
        )
        val decrypted = aesGcmEngine.decryptWithCipher(decryptCipher, ciphertextWithTag, aad)
        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun buildRowAadValidatesInputs() {
        assertEquals("action_cache:7:payload_blob", aesGcmEngine.buildRowAad("action_cache", 7L, "payload_blob").toString(Charsets.UTF_8))

        assertIllegalArgument { aesGcmEngine.buildRowAad("", 1L, "col") }
        assertIllegalArgument { aesGcmEngine.buildRowAad("bad:table", 1L, "col") }
        assertIllegalArgument { aesGcmEngine.buildRowAad("table", 0L, "col") }
        assertIllegalArgument { aesGcmEngine.buildRowAad("table", -5L, "col") }
        assertIllegalArgument { aesGcmEngine.buildRowAad("table", 1L, "") }
        assertIllegalArgument { aesGcmEngine.buildRowAad("table", 1L, "bad:col") }
    }

    @Test
    fun hmacSha256DeterministicBlindIndexAndConstantTimeVerification() {
        val key = keyProvider.getOrCreateBlindIndexKey()
        val index1 = hmacEngine.computeBlindIndex(key, "en", "set alarm for \$TIME_0")
        val index2 = hmacEngine.computeBlindIndex(key, "en", "set alarm for \$TIME_0")
        val indexOtherLang = hmacEngine.computeBlindIndex(key, "tr", "set alarm for \$TIME_0")

        assertEquals(64, index1.length)
        assertEquals(index1, index2)
        assertFalse(index1 == indexOtherLang)

        assertIllegalArgument { hmacEngine.computeBlindIndex(key) }
        assertIllegalArgument { hmacEngine.computeBlindIndex(key, "en\u0000bad", "skeleton") }

        val data = "rule_payload".toByteArray(Charsets.UTF_8)
        val tagHex = hmacEngine.computeHmacHex(key, data)
        assertEquals(64, tagHex.length)
        assertTrue(hmacEngine.verifyHmacHex(key, data, tagHex))
        assertTrue(hmacEngine.verifyHmacHex(key, data, tagHex.uppercase()))
        assertFalse(hmacEngine.verifyHmacHex(key, "tampered".toByteArray(Charsets.UTF_8), tagHex))
        assertFalse(hmacEngine.verifyHmacHex(key, data, tagHex.dropLast(2) + "00"))
        assertFalse(hmacEngine.verifyHmacHex(key, data, "short"))
        assertFalse(hmacEngine.verifyHmacHex(key, data, "z".repeat(64)))
    }

    @Test
    fun secureMemoryZeroizeAndWithZeroizedBytes() {
        val bytes = byteArrayOf(1, 2, 3, 4, 5)
        SecureMemory.zeroize(bytes)
        assertArrayEquals(byteArrayOf(0, 0, 0, 0, 0), bytes)

        val chars = charArrayOf('a', 'b', 'c')
        SecureMemory.zeroize(chars)
        assertArrayEquals(charArrayOf('\u0000', '\u0000', '\u0000'), chars)

        SecureMemory.zeroize(null as ByteArray?)
        SecureMemory.zeroize(null as CharArray?)

        val scoped = byteArrayOf(10, 20, 30)
        val result = SecureMemory.withZeroizedBytes(scoped) { it.sum() }
        assertEquals(60, result)
        assertArrayEquals(byteArrayOf(0, 0, 0), scoped)

        val failingScoped = byteArrayOf(7, 8, 9)
        try {
            SecureMemory.withZeroizedBytes(failingScoped) {
                throw IllegalStateException("Boom")
            }
            fail("Expected IllegalStateException")
        } catch (_: IllegalStateException) {
            assertArrayEquals(byteArrayOf(0, 0, 0), failingScoped)
        }
    }

    @Test
    fun aesGcmCipherInitVerifiesKeyUsability() {
        val masterKey = keyProvider.getOrCreateDbMasterKey()
        val cipher = Cipher.getInstance(AesGcmCryptoEngine.TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, masterKey)
        assertNotNull(cipher.iv)
        assertEquals(12, cipher.iv.size)

        // Verifying an incompatible key (HMAC key passed to AES cipher) fails
        val hmacKey = keyProvider.getOrCreateBlindIndexKey()
        try {
            cipher.init(Cipher.ENCRYPT_MODE, hmacKey)
            fail("Expected InvalidKeyException when passing HMAC key to AES cipher")
        } catch (_: java.security.InvalidKeyException) {
            // Expected
        }
    }

    private fun assertIllegalArgument(block: () -> Unit) {
        try {
            block()
            fail("Expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }
}

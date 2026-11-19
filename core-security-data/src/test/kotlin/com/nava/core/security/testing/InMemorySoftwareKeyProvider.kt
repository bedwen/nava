package com.nava.core.security.testing

import com.nava.core.security.crypto.CryptoKeyProvider
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * JVM software-backed [CryptoKeyProvider] double using standard JCA [KeyGenerator]
 * (`AES` 256-bit and `HmacSHA256` 256-bit) for unit and adversarial testing.
 */
class InMemorySoftwareKeyProvider(
    private val strongBoxAliases: Set<String> = emptySet()
) : CryptoKeyProvider {

    private val lock = Any()
    private var dbMasterKey: SecretKey? = null
    private var blindIndexKey: SecretKey? = null
    private var vaultBiometricKey: SecretKey? = null

    override fun getOrCreateDbMasterKey(): SecretKey {
        return synchronized(lock) {
            dbMasterKey ?: generateAes256Key().also { dbMasterKey = it }
        }
    }

    override fun getOrCreateBlindIndexKey(): SecretKey {
        return synchronized(lock) {
            blindIndexKey ?: generateHmacSha256Key().also { blindIndexKey = it }
        }
    }

    override fun getOrCreateVaultBiometricKey(): SecretKey {
        return synchronized(lock) {
            vaultBiometricKey ?: generateAes256Key().also { vaultBiometricKey = it }
        }
    }

    override fun isStrongBoxBacked(alias: String): Boolean {
        if (alias.isBlank()) return false
        return alias in strongBoxAliases
    }

    /**
     * Replaces `nava_vault_biometric_key` with a fresh 256-bit AES key to simulate
     * biometric re-enrollment key invalidation.
     */
    fun rotateVaultKey(): SecretKey {
        return synchronized(lock) {
            generateAes256Key().also { vaultBiometricKey = it }
        }
    }

    private fun generateAes256Key(): SecretKey {
        val generator = KeyGenerator.getInstance(AES_ALGORITHM)
        generator.init(KEY_SIZE_BITS)
        return generator.generateKey()
    }

    private fun generateHmacSha256Key(): SecretKey {
        val generator = KeyGenerator.getInstance(HMAC_ALGORITHM)
        generator.init(KEY_SIZE_BITS)
        return generator.generateKey()
    }

    companion object {
        private const val AES_ALGORITHM: String = "AES"
        private const val HMAC_ALGORITHM: String = "HmacSHA256"
        private const val KEY_SIZE_BITS: Int = 256
    }
}

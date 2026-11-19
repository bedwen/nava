package com.nava.core.security.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * Production [CryptoKeyProvider] backed by Android Keystore (API 31+).
 *
 * Every key attempts hardware StrongBox provisioning first and falls back cleanly to TEE
 * when StrongBox is unavailable or unsupported for the requested algorithm/constraints.
 */
class AndroidKeystoreKeyProvider : CryptoKeyProvider {
    private val keyLock = Any()

    override fun getOrCreateDbMasterKey(): SecretKey {
        return getOrCreateKey(
            alias = KeyAliases.DB_MASTER_KEY,
            algorithm = KeyProperties.KEY_ALGORITHM_AES
        ) { strongBox ->
            KeyGenParameterSpec.Builder(
                KeyAliases.DB_MASTER_KEY,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(AES_KEY_SIZE_BITS)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUnlockedDeviceRequired(true)
                .setIsStrongBoxBacked(strongBox)
                .build()
        }
    }

    override fun getOrCreateBlindIndexKey(): SecretKey {
        return getOrCreateKey(
            alias = KeyAliases.BLIND_INDEX_KEY,
            algorithm = KeyProperties.KEY_ALGORITHM_HMAC_SHA256
        ) { strongBox ->
            KeyGenParameterSpec.Builder(
                KeyAliases.BLIND_INDEX_KEY,
                KeyProperties.PURPOSE_SIGN
            )
                .setKeySize(HMAC_KEY_SIZE_BITS)
                .setIsStrongBoxBacked(strongBox)
                .build()
        }
    }

    override fun getOrCreateVaultBiometricKey(): SecretKey {
        return getOrCreateKey(
            alias = KeyAliases.VAULT_BIOMETRIC_KEY,
            algorithm = KeyProperties.KEY_ALGORITHM_AES
        ) { strongBox ->
            KeyGenParameterSpec.Builder(
                KeyAliases.VAULT_BIOMETRIC_KEY,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(AES_KEY_SIZE_BITS)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(
                    AUTH_VALIDITY_PER_USE_SECONDS,
                    KeyProperties.AUTH_BIOMETRIC_STRONG
                )
                .setInvalidatedByBiometricEnrollment(true)
                .setIsStrongBoxBacked(strongBox)
                .build()
        }
    }

    override fun isStrongBoxBacked(alias: String): Boolean {
        if (alias.isBlank()) return false
        return synchronized(keyLock) {
            try {
                val keyStore = loadKeyStore()
                val secretKey = keyStore.getKey(alias, null) as? SecretKey ?: return@synchronized false
                val factory = SecretKeyFactory.getInstance(secretKey.algorithm, ANDROID_KEYSTORE)
                val keyInfo = factory.getKeySpec(secretKey, KeyInfo::class.java) as? KeyInfo
                    ?: return@synchronized false
                keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
            } catch (_: GeneralSecurityException) {
                false
            } catch (_: ProviderException) {
                false
            }
        }
    }

    private fun getOrCreateKey(
        alias: String,
        algorithm: String,
        specFactory: (strongBox: Boolean) -> KeyGenParameterSpec
    ): SecretKey {
        return synchronized(keyLock) {
            val keyStore = loadKeyStore()
            if (keyStore.containsAlias(alias)) {
                val existing = keyStore.getKey(alias, null) as? SecretKey
                if (existing != null) {
                    return@synchronized existing
                }
            }
            generateWithStrongBoxFallback(algorithm, specFactory)
        }
    }

    private fun generateWithStrongBoxFallback(
        algorithm: String,
        specFactory: (strongBox: Boolean) -> KeyGenParameterSpec
    ): SecretKey {
        return try {
            val generator = KeyGenerator.getInstance(algorithm, ANDROID_KEYSTORE)
            generator.init(specFactory(true))
            generator.generateKey()
        } catch (_: StrongBoxUnavailableException) {
            generateTeeKey(algorithm, specFactory)
        } catch (_: InvalidAlgorithmParameterException) {
            generateTeeKey(algorithm, specFactory)
        } catch (_: ProviderException) {
            generateTeeKey(algorithm, specFactory)
        }
    }

    private fun generateTeeKey(
        algorithm: String,
        specFactory: (strongBox: Boolean) -> KeyGenParameterSpec
    ): SecretKey {
        val generator = KeyGenerator.getInstance(algorithm, ANDROID_KEYSTORE)
        generator.init(specFactory(false))
        return generator.generateKey()
    }

    private fun loadKeyStore(): KeyStore {
        return KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AES_KEY_SIZE_BITS = 256
        private const val HMAC_KEY_SIZE_BITS = 256
        private const val AUTH_VALIDITY_PER_USE_SECONDS = 0
    }
}

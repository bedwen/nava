package com.nava.core.security.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.GeneralSecurityException
import java.security.InvalidAlgorithmParameterException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * Production [CryptoKeyProvider] backed by Android Keystore (API 31+).
 *
 * Every key attempts hardware StrongBox provisioning first and falls back cleanly to TEE
 * when StrongBox is unavailable or unsupported for the requested algorithm/constraints.
 */
class AndroidKeystoreKeyProvider : CryptoKeyProvider, RuleSealKeyStore {
    private val keyLock = Any()

    override fun getOrCreateDbMasterKey(): SecretKey {
        return synchronized(keyLock) {
            val keyStore = loadKeyStore()
            if (keyStore.containsAlias(KeyAliases.DB_MASTER_KEY)) {
                val existing = keyStore.getKey(KeyAliases.DB_MASTER_KEY, null) as? SecretKey
                if (existing != null) {
                    return@synchronized existing
                }
            }

            val fallbackTiers = listOf(
                true to true,   // 1) StrongBox=true, unlockedDeviceRequired=true
                false to true,  // 2) StrongBox=false (TEE), unlockedDeviceRequired=true
                false to false  // 3) StrongBox=false (TEE), unlockedDeviceRequired=false
            )

            var lastFailure: Exception? = null
            for ((strongBox, unlockedRequired) in fallbackTiers) {
                try {
                    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                    generator.init(buildDbMasterKeySpec(strongBox, unlockedRequired))
                    val key = generator.generateKey()
                    if (verifyAesKeyUsable(key)) {
                        return@synchronized key
                    } else {
                        deleteAliasQuietly(loadKeyStore(), KeyAliases.DB_MASTER_KEY)
                    }
                } catch (e: Exception) {
                    deleteAliasQuietly(loadKeyStore(), KeyAliases.DB_MASTER_KEY)
                    lastFailure = e
                }
            }

            throw lastFailure ?: GeneralSecurityException(
                "Failed to provision usable DB master key across all hardware and unlock tiers"
            )
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

    override fun createFreshSealKey(alias: String): SecretKey {
        require(alias.startsWith(RULE_SEAL_ALIAS_PREFIX)) { "Unexpected rule seal key alias" }
        return synchronized(keyLock) {
            deleteAliasQuietly(loadKeyStore(), alias)
            generateWithStrongBoxFallback(KeyProperties.KEY_ALGORITHM_HMAC_SHA256) { strongBox ->
                buildRuleSealKeySpec(alias, strongBox)
            }
        }
    }

    override fun findSealKey(alias: String): SecretKey? {
        if (!alias.startsWith(RULE_SEAL_ALIAS_PREFIX)) return null
        return synchronized(keyLock) {
            loadKeyStore().getKey(alias, null) as? SecretKey
        }
    }

    override fun deleteSealKey(alias: String) {
        require(alias.startsWith(RULE_SEAL_ALIAS_PREFIX)) { "Unexpected rule seal key alias" }
        synchronized(keyLock) {
            val keyStore = loadKeyStore()
            if (keyStore.containsAlias(alias)) {
                // Propagate failures: a seal key that survives a revoke would allow rollback.
                keyStore.deleteEntry(alias)
            }
        }
    }

    override fun areLegacySealsRetired(): Boolean {
        return synchronized(keyLock) {
            loadKeyStore().containsAlias(LEGACY_SEALS_RETIRED_MARKER_ALIAS)
        }
    }

    override fun retireLegacySeals() {
        synchronized(keyLock) {
            if (loadKeyStore().containsAlias(LEGACY_SEALS_RETIRED_MARKER_ALIAS)) return
            generateWithStrongBoxFallback(KeyProperties.KEY_ALGORITHM_HMAC_SHA256) { strongBox ->
                buildRuleSealKeySpec(LEGACY_SEALS_RETIRED_MARKER_ALIAS, strongBox)
            }
        }
    }

    /**
     * Rule seal keys must verify while the device is locked (unattended routines), so they require
     * neither user authentication nor an unlocked device; their protection is that they live in
     * Keystore, outside the app's rollback-able database files.
     */
    private fun buildRuleSealKeySpec(alias: String, strongBox: Boolean): KeyGenParameterSpec {
        return KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setKeySize(HMAC_KEY_SIZE_BITS)
            .setIsStrongBoxBacked(strongBox)
            .build()
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

    private fun buildDbMasterKeySpec(
        strongBox: Boolean,
        unlockedRequired: Boolean
    ): KeyGenParameterSpec {
        return KeyGenParameterSpec.Builder(
            KeyAliases.DB_MASTER_KEY,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(AES_KEY_SIZE_BITS)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUnlockedDeviceRequired(unlockedRequired)
            .setIsStrongBoxBacked(strongBox)
            .build()
    }

    private fun verifyAesKeyUsable(key: SecretKey): Boolean {
        return try {
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            true
        } catch (_: GeneralSecurityException) {
            false
        } catch (_: ProviderException) {
            false
        } catch (_: Exception) {
            false
        }
    }

    private fun deleteAliasQuietly(keyStore: KeyStore, alias: String) {
        try {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        } catch (_: Exception) {
            // Ignored
        }
    }

    private fun loadKeyStore(): KeyStore {
        return KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val AES_KEY_SIZE_BITS = 256
        private const val HMAC_KEY_SIZE_BITS = 256
        private const val AUTH_VALIDITY_PER_USE_SECONDS = 0
        private const val RULE_SEAL_ALIAS_PREFIX: String = RuleSealKeyStore.ALIAS_PREFIX
        private const val LEGACY_SEALS_RETIRED_MARKER_ALIAS: String =
            "nava_rule_seal_legacy_retired_v1"
    }
}

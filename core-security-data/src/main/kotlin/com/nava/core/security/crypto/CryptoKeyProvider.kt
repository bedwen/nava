package com.nava.core.security.crypto

import javax.crypto.SecretKey

/**
 * Abstraction over hardware-backed cryptographic key storage (Android Keystore StrongBox/TEE)
 * enabling deterministic verification and clean separation of cryptographic policy from JCA plumbing.
 */
interface CryptoKeyProvider {
    /** Returns or generates the AES-256-GCM key used to encrypt database column payloads. */
    fun getOrCreateDbMasterKey(): SecretKey

    /** Returns or generates the 256-bit HMAC-SHA256 key used for blind indexes and rule seals. */
    fun getOrCreateBlindIndexKey(): SecretKey

    /** Returns or generates the biometric-authenticated AES-256-GCM key protecting Nava Vault. */
    fun getOrCreateVaultBiometricKey(): SecretKey

    /** Returns true when the key identified by [alias] is backed by a StrongBox hardware security module. */
    fun isStrongBoxBacked(alias: String): Boolean
}

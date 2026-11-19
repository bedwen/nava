package com.nava.core.security.crypto

/**
 * Canonical Android Keystore key alias constants defining Nava's three-key hierarchy.
 */
object KeyAliases {
    /** AES-256-GCM master key encrypting column payloads in EncryptedSqliteStore. */
    const val DB_MASTER_KEY: String = "nava_db_master_key"

    /** HMAC-SHA256 key computing deterministic blind indexes and rule grant integrity seals. */
    const val BLIND_INDEX_KEY: String = "nava_blind_index_key"

    /** Biometric-bound AES-256-GCM key wrapping the Nava Secure Vault DEK. */
    const val VAULT_BIOMETRIC_KEY: String = "nava_vault_biometric_key"
}

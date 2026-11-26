package com.nava.core.security.crypto

import java.util.WeakHashMap
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Anti-rollback key storage for [com.nava.domain.security.RuleCapabilityGrant] seals.
 *
 * Every approval of a background routine gets its own fresh `HMAC-SHA256` seal key; pausing or
 * revoking the routine deletes that key. Because the keys live outside the app's database files
 * (Android Keystore in production), an attacker who can write `nava.db` and replays an old
 * `APPROVED_ACTIVE` ciphertext cannot also restore the deleted key, so the replayed seal never
 * verifies again.
 *
 * The legacy-retirement marker is stored the same way: once set, seals created by the previous
 * format (a single shared blind-index key) are rejected for good, even if old rows are replayed.
 *
 * Seal keys must stay usable while the device is locked (unattended routines verify seals in
 * the background), so implementations must not require user authentication or an unlocked device.
 */
interface RuleSealKeyStore {
    /** Deletes any key under [alias] and creates a fresh, never-before-used seal key. */
    fun createFreshSealKey(alias: String): SecretKey

    /** Returns the seal key under [alias], or null when it was never created or was deleted. */
    fun findSealKey(alias: String): SecretKey?

    /** Deletes the seal key under [alias]; a no-op when it does not exist. */
    fun deleteSealKey(alias: String)

    /** True once legacy (pre-v2) seals have been permanently retired. */
    fun areLegacySealsRetired(): Boolean

    /** Permanently retires legacy (pre-v2) seals. Idempotent. */
    fun retireLegacySeals()

    companion object {
        /** Every rule seal key alias starts with this prefix. */
        const val ALIAS_PREFIX: String = "nava_rule_seal_"
    }
}

/**
 * Process-memory [RuleSealKeyStore] for JVM tests and non-Keystore [CryptoKeyProvider] doubles.
 *
 * It offers no protection against a process restart (keys vanish, so every sealed routine fails
 * closed and must be re-approved); production uses [AndroidKeystoreKeyProvider], which implements
 * [RuleSealKeyStore] on top of Android Keystore.
 */
class InMemoryRuleSealKeyStore : RuleSealKeyStore {
    private val lock = Any()
    private val keys = HashMap<String, SecretKey>()
    private var legacyRetired = false

    override fun createFreshSealKey(alias: String): SecretKey {
        require(alias.isNotBlank()) { "Seal key alias must not be blank" }
        val generator = KeyGenerator.getInstance(HMAC_ALGORITHM)
        generator.init(KEY_SIZE_BITS)
        val key = generator.generateKey()
        synchronized(lock) {
            keys[alias] = key
        }
        return key
    }

    override fun findSealKey(alias: String): SecretKey? = synchronized(lock) { keys[alias] }

    override fun deleteSealKey(alias: String) {
        synchronized(lock) {
            keys.remove(alias)
        }
    }

    override fun areLegacySealsRetired(): Boolean = synchronized(lock) { legacyRetired }

    override fun retireLegacySeals() {
        synchronized(lock) {
            legacyRetired = true
        }
    }

    private companion object {
        const val HMAC_ALGORITHM: String = "HmacSHA256"
        const val KEY_SIZE_BITS: Int = 256
    }
}

/** Resolves the [RuleSealKeyStore] that belongs to a [CryptoKeyProvider]. */
object RuleSealKeyStores {
    private val inMemoryByProvider = WeakHashMap<CryptoKeyProvider, InMemoryRuleSealKeyStore>()

    /**
     * Returns [provider] itself when it is Keystore-backed (implements [RuleSealKeyStore]);
     * otherwise one in-memory store per provider instance, so several managers built over the same
     * provider (e.g. a re-created manager in the same process) share seal keys.
     */
    fun forProvider(provider: CryptoKeyProvider): RuleSealKeyStore {
        if (provider is RuleSealKeyStore) return provider
        return synchronized(inMemoryByProvider) {
            inMemoryByProvider.getOrPut(provider) { InMemoryRuleSealKeyStore() }
        }
    }
}

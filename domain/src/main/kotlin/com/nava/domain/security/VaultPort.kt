package com.nava.domain.security

/**
 * Port for Nava Secure Vault encrypted storage under `filesDir/vault`.
 *
 * Implementations back decryption with Android Keystore `BiometricPrompt.CryptoObject`
 * and zeroize decrypted `ByteArray` buffers (`ByteArray.fill(0)`) immediately on close or lock.
 */
interface VaultPort {
    suspend fun isUnlocked(): Boolean
    suspend fun listNoteIds(): List<String>
    suspend fun readNote(noteId: String): ByteArray
    suspend fun writeNote(noteId: String, content: ByteArray)
    suspend fun deleteNote(noteId: String)
    suspend fun lock()
}

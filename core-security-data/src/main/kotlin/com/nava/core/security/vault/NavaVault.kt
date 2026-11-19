package com.nava.core.security.vault

import androidx.biometric.BiometricPrompt
import com.nava.core.security.crypto.AesGcmCryptoEngine
import com.nava.core.security.crypto.CryptoKeyProvider
import com.nava.core.security.crypto.SecureMemory
import com.nava.domain.security.VaultPort
import java.io.File
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.IOException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Hardware biometric-protected encrypted note and file vault (`filesDir/vault`).
 *
 * Security invariants (PLAN.md Section 5.2):
 * - Strict AI Lock: All read/write/list/delete operations throw [SecurityException] while locked
 *   or once [sessionTimeoutMs] elapses.
 * - Envelope encryption: A 256-bit random DEK is wrapped/unwrapped strictly by a hardware-authenticated
 *   `BiometricPrompt.CryptoObject` cipher backed by `nava_vault_biometric_key`.
 * - Immediate RAM zeroization: Every decrypted `ByteArray` returned from [readNote] and the in-memory
 *   DEK bytes are overwritten with `0x00` immediately upon [lock], [close], or timeout expiration.
 */
class NavaVault(
    private val vaultDir: File,
    private val keyProvider: CryptoKeyProvider,
    private val aesGcmEngine: AesGcmCryptoEngine = AesGcmCryptoEngine(),
    private val sessionTimeoutMs: Long = DEFAULT_SESSION_TIMEOUT_MS,
    private val clockMs: () -> Long = System::currentTimeMillis,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val secureRandom: SecureRandom = SecureRandom()
) : VaultPort, AutoCloseable {

    private val ioMutex = Mutex()
    private val stateLock = Any()

    private var unlockedDekBytes: ByteArray? = null
    private var unlockedDekKey: SecretKey? = null
    private var unlockedAtMs: Long = 0L
    private val trackedPlaintexts: MutableList<ByteArray> = mutableListOf()

    init {
        require(sessionTimeoutMs > 0L) {
            "sessionTimeoutMs must be strictly positive, got $sessionTimeoutMs"
        }
    }

    /**
     * Prepares a [Cipher] initialized with `nava_vault_biometric_key` for hardware biometric
     * authentication (`ENCRYPT_MODE` on initial vault setup, `DECRYPT_MODE` with stored IV thereafter).
     */
    suspend fun prepareUnlockCipher(): Cipher = withContext(dispatcher) {
        ioMutex.withLock {
            ensureVaultDir()
            val biometricKey = keyProvider.getOrCreateVaultBiometricKey()
            val dekFile = File(vaultDir, DEK_FILE_NAME)
            val cipher = Cipher.getInstance(AesGcmCryptoEngine.TRANSFORMATION)
            if (!dekFile.exists()) {
                cipher.init(Cipher.ENCRYPT_MODE, biometricKey)
            } else {
                val dekBlob = dekFile.readBytes()
                if (dekBlob.size < AesGcmCryptoEngine.MIN_BLOB_BYTES) {
                    throw SecurityException("Corrupted vault DEK envelope")
                }
                val iv = dekBlob.copyOfRange(0, AesGcmCryptoEngine.IV_LENGTH_BYTES)
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    biometricKey,
                    GCMParameterSpec(AesGcmCryptoEngine.TAG_LENGTH_BITS, iv)
                )
            }
            cipher
        }
    }

    /**
     * Wraps [prepareUnlockCipher] into a [BiometricPrompt.CryptoObject] for `BiometricPrompt.authenticate`.
     */
    suspend fun prepareUnlockCryptoObject(): BiometricPrompt.CryptoObject {
        return BiometricPrompt.CryptoObject(prepareUnlockCipher())
    }

    /**
     * Unlocks the vault using the hardware-authenticated [BiometricPrompt.CryptoObject] returned by
     * `BiometricPrompt.AuthenticationResult`.
     */
    suspend fun unlockWithCryptoObject(cryptoObject: BiometricPrompt.CryptoObject) {
        val cipher = cryptoObject.cipher
            ?: throw SecurityException("BiometricPrompt.CryptoObject does not contain an authenticated Cipher")
        unlockWithAuthenticatedCipher(cipher)
    }

    /**
     * Unlocks the vault using a pre-authenticated AES-GCM [cipher].
     *
     * On first initialization (when `.vault_dek.bin` does not exist), generates a 256-bit random DEK,
     * wraps it under AAD `"vault:dek:v1"`, and writes `.vault_dek.bin` atomically. On subsequent unlocks,
     * unwraps `.vault_dek.bin` under AAD `"vault:dek:v1"`.
     */
    suspend fun unlockWithAuthenticatedCipher(cipher: Cipher) = withContext(dispatcher) {
        ioMutex.withLock {
            synchronized(stateLock) {
                lockInternalLocked()
            }
            ensureVaultDir()
            val dekFile = File(vaultDir, DEK_FILE_NAME)
            val rawDek: ByteArray = if (!dekFile.exists()) {
                val generatedDek = ByteArray(DEK_LENGTH_BYTES)
                secureRandom.nextBytes(generatedDek)
                try {
                    val wrappedBlob = aesGcmEngine.encryptWithCipher(cipher, generatedDek, DEK_AAD)
                    writeFileAtomically(dekFile, wrappedBlob)
                    generatedDek
                } catch (e: Throwable) {
                    SecureMemory.zeroize(generatedDek)
                    throw e
                }
            } else {
                val dekBlob = dekFile.readBytes()
                if (dekBlob.size < AesGcmCryptoEngine.MIN_BLOB_BYTES) {
                    throw SecurityException("Corrupted vault DEK envelope")
                }
                val ciphertextWithTag = dekBlob.copyOfRange(
                    AesGcmCryptoEngine.IV_LENGTH_BYTES,
                    dekBlob.size
                )
                val unwrapped = aesGcmEngine.decryptWithCipher(cipher, ciphertextWithTag, DEK_AAD)
                if (unwrapped.size != DEK_LENGTH_BYTES) {
                    SecureMemory.zeroize(unwrapped)
                    throw SecurityException(
                        "Invalid unwrapped vault DEK length: ${unwrapped.size} bytes"
                    )
                }
                unwrapped
            }

            synchronized(stateLock) {
                unlockedDekBytes = rawDek
                unlockedDekKey = SecretKeySpec(rawDek, AES_ALGORITHM)
                unlockedAtMs = clockMs()
            }
        }
    }

    override suspend fun isUnlocked(): Boolean {
        return synchronized(stateLock) {
            isUnlockedOrAutoLockLocked()
        }
    }

    override suspend fun listNoteIds(): List<String> = withContext(dispatcher) {
        ioMutex.withLock {
            requireUnlockedDekKey()
            if (!vaultDir.exists()) {
                return@withLock emptyList()
            }
            val files = vaultDir.listFiles() ?: return@withLock emptyList()
            val ids = ArrayList<String>(files.size)
            for (file in files) {
                if (!file.isFile) continue
                val name = file.name
                if (name.startsWith(".") || !name.endsWith(NOTE_FILE_SUFFIX)) continue
                val candidateId = name.removeSuffix(NOTE_FILE_SUFFIX)
                if (isValidNoteId(candidateId)) {
                    ids.add(candidateId)
                }
            }
            ids.sort()
            ids
        }
    }

    override suspend fun readNote(noteId: String): ByteArray = withContext(dispatcher) {
        val targetFile = resolveValidatedNoteFile(noteId)
        ioMutex.withLock {
            val dek = requireUnlockedDekKey()
            if (!targetFile.isFile) {
                throw FileNotFoundException("Vault note '$noteId' not found")
            }
            val blob = targetFile.readBytes()
            val plaintext = aesGcmEngine.decrypt(dek, blob, noteAad(noteId))
            synchronized(stateLock) {
                if (!isUnlockedOrAutoLockLocked()) {
                    SecureMemory.zeroize(plaintext)
                    throw SecurityException(VAULT_LOCKED_MESSAGE)
                }
                trackedPlaintexts.add(plaintext)
            }
            plaintext
        }
    }

    /**
     * Reads [noteId], invokes [block] with the decrypted bytes, and unconditionally overwrites
     * the buffer with `0x00` in `finally`.
     */
    suspend fun <R> withDecryptedNote(noteId: String, block: (ByteArray) -> R): R {
        val bytes = readNote(noteId)
        return try {
            block(bytes)
        } finally {
            synchronized(stateLock) {
                SecureMemory.zeroize(bytes)
                trackedPlaintexts.removeAll { it === bytes }
            }
        }
    }

    override suspend fun writeNote(noteId: String, content: ByteArray) = withContext(dispatcher) {
        val targetFile = resolveValidatedNoteFile(noteId)
        ioMutex.withLock {
            val dek = requireUnlockedDekKey()
            ensureVaultDir()
            val encryptedBlob = aesGcmEngine.encrypt(dek, content, noteAad(noteId))
            writeFileAtomically(targetFile, encryptedBlob)
        }
    }

    override suspend fun deleteNote(noteId: String) = withContext(dispatcher) {
        val targetFile = resolveValidatedNoteFile(noteId)
        ioMutex.withLock {
            requireUnlockedDekKey()
            if (targetFile.exists() && !targetFile.delete()) {
                throw IOException("Failed to delete vault note '$noteId'")
            }
        }
    }

    override suspend fun lock() {
        synchronized(stateLock) {
            lockInternalLocked()
        }
    }

    override fun close() {
        synchronized(stateLock) {
            lockInternalLocked()
        }
    }

    private fun requireUnlockedDekKey(): SecretKey {
        return synchronized(stateLock) {
            if (!isUnlockedOrAutoLockLocked()) {
                throw SecurityException(VAULT_LOCKED_MESSAGE)
            }
            unlockedDekKey ?: throw SecurityException(VAULT_LOCKED_MESSAGE)
        }
    }

    private fun isUnlockedOrAutoLockLocked(): Boolean {
        if (unlockedDekBytes == null || unlockedDekKey == null) {
            return false
        }
        val now = clockMs()
        val elapsed = now - unlockedAtMs
        if (elapsed < 0L || elapsed > sessionTimeoutMs) {
            lockInternalLocked()
            return false
        }
        return true
    }

    private fun lockInternalLocked() {
        for (buffer in trackedPlaintexts) {
            SecureMemory.zeroize(buffer)
        }
        trackedPlaintexts.clear()
        SecureMemory.zeroize(unlockedDekBytes)
        unlockedDekBytes = null
        unlockedDekKey = null
        unlockedAtMs = 0L
    }

    private fun ensureVaultDir() {
        if (!vaultDir.exists() && !vaultDir.mkdirs()) {
            throw IOException("Failed to create vault directory: ${vaultDir.path}")
        }
        if (!vaultDir.isDirectory) {
            throw IOException("Vault path is not a directory: ${vaultDir.path}")
        }
    }

    private fun resolveValidatedNoteFile(noteId: String): File {
        if (!isValidNoteId(noteId)) {
            throw SecurityException("Invalid vault noteId: '$noteId'")
        }
        val canonicalVaultDir = vaultDir.canonicalFile
        val targetFile = File(canonicalVaultDir, "$noteId$NOTE_FILE_SUFFIX")
        val canonicalTargetPath = targetFile.canonicalPath
        val requiredPrefix = canonicalVaultDir.path + File.separator
        if (!canonicalTargetPath.startsWith(requiredPrefix)) {
            throw SecurityException("Vault path traversal rejected for noteId '$noteId'")
        }
        return targetFile
    }

    private fun isValidNoteId(noteId: String): Boolean {
        if (noteId.isEmpty() || noteId.length > MAX_NOTE_ID_LENGTH) return false
        if (noteId.startsWith(".")) return false
        if (".." in noteId || '/' in noteId || '\\' in noteId || '\u0000' in noteId) return false
        return NOTE_ID_REGEX.matches(noteId)
    }

    private fun noteAad(noteId: String): ByteArray {
        return "vault:note:$noteId".toByteArray(Charsets.UTF_8)
    }

    private fun writeFileAtomically(targetFile: File, data: ByteArray) {
        val parent = targetFile.parentFile ?: throw IOException("Target file has no parent directory")
        val tempFile = File(parent, ".${targetFile.name}.${System.nanoTime()}.tmp")
        var moved = false
        try {
            FileOutputStream(tempFile).use { fos ->
                fos.write(data)
                fos.flush()
                fos.fd.sync()
            }
            if (!tempFile.renameTo(targetFile)) {
                if (targetFile.exists() && !targetFile.delete()) {
                    throw IOException("Failed to replace existing vault file '${targetFile.name}'")
                }
                if (!tempFile.renameTo(targetFile)) {
                    throw IOException("Failed to atomically move temp file into '${targetFile.name}'")
                }
            }
            moved = true
        } finally {
            if (!moved && tempFile.exists()) {
                tempFile.delete()
            }
        }
    }

    companion object {
        const val DEFAULT_SESSION_TIMEOUT_MS: Long = 60_000L
        private const val DEK_LENGTH_BYTES: Int = 32
        private const val AES_ALGORITHM: String = "AES"
        private const val DEK_FILE_NAME: String = ".vault_dek.bin"
        private const val NOTE_FILE_SUFFIX: String = ".nava"
        private const val MAX_NOTE_ID_LENGTH: Int = 128
        private const val VAULT_LOCKED_MESSAGE: String = "Nava Vault is locked"
        private val DEK_AAD: ByteArray = "vault:dek:v1".toByteArray(Charsets.UTF_8)
        private val NOTE_ID_REGEX: Regex = Regex("^[A-Za-z0-9._-]{1,128}$")
    }
}

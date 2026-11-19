package com.nava.core.ai.provisioning

import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.StatFs
import android.provider.OpenableColumns
import com.nava.domain.ai.ModelProvisionerPort
import com.nava.domain.ai.PinnedModelSpec
import com.nava.domain.ai.ProvisionedModelInfo
import com.nava.domain.ai.ProvisioningProgress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

/**
 * Abstraction over filesystem free-space inspection so storage pre-checks are deterministically
 * unit-testable on the JVM without Android [StatFs] stubs.
 */
interface StorageSpaceProvider {
    fun availableBytes(directory: File): Long
}

/**
 * Production Android [StorageSpaceProvider] backed by [StatFs].
 */
class AndroidStatFsStorageSpaceProvider : StorageSpaceProvider {
    override fun availableBytes(directory: File): Long {
        if (!directory.exists()) {
            directory.mkdirs()
        }
        return StatFs(directory.absolutePath).availableBytes
    }
}

/**
 * Offline SAF `.litertlm` model provisioner implementing [ModelProvisionerPort] with zero
 * `INTERNET` permission (PLAN.md Section 1.1 Law 3 and PHASE_0_FEASIBILITY_REPORT.md Section 6.3).
 *
 * Security & durability guarantees:
 * - Rejects path traversal, separators, NUL bytes, and non-`.litertlm` extensions; verifies
 *   canonical path containment inside `modelsDir`.
 * - Enforces 2x temporary storage headroom (`max(sourceSizeBytes, expectedSizeBytes) + 256 MiB`).
 * - Streams in 1 MiB chunks while hashing SHA-256, calls `fd.sync()`, verifies digest in
 *   constant time via [MessageDigest.isEqual], atomically renames `.tmp` -> `.litertlm`,
 *   and deletes `.tmp` on any failure or coroutine cancellation.
 */
class SafModelProvisioner(
    private val modelsDir: File,
    private val storageSpaceProvider: StorageSpaceProvider = AndroidStatFsStorageSpaceProvider(),
    private val clockMs: () -> Long = System::currentTimeMillis
) : ModelProvisionerPort {

    private val mutationMutex = Mutex()

    constructor(
        context: Context,
        storageSpaceProvider: StorageSpaceProvider = AndroidStatFsStorageSpaceProvider(),
        clockMs: () -> Long = System::currentTimeMillis
    ) : this(
        modelsDir = File(context.filesDir, MODELS_DIR_NAME),
        storageSpaceProvider = storageSpaceProvider,
        clockMs = clockMs
    )

    /**
     * Constructs an offline Android SAF document picker intent (zero network permissions).
     */
    fun buildOpenDocumentIntent(): Intent {
        return Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
    }

    override fun modelsDirectoryPath(): String {
        ensureModelsDirectory()
        return modelsDir.absolutePath
    }

    /**
     * Locates a provisioned `.litertlm` model and computes its full-file SHA-256 digest on
     * `Dispatchers.IO`. Because hashing 2.5-3.7 GB bundles performs sequential disk IO, callers
     * should invoke this during startup/settings inspection rather than on the hot per-turn path.
     */
    override suspend fun findProvisionedModel(fileName: String): ProvisionedModelInfo? =
        withContext(Dispatchers.IO) {
            val targetFile = resolveContainedModelFile(fileName)
            if (!targetFile.exists() || !targetFile.isFile || targetFile.length() <= 0L) {
                return@withContext null
            }
            val shaHex = computeFileSha256Hex(targetFile)
            ProvisionedModelInfo(
                modelId = fileName.removeSuffix(LITERTLM_EXTENSION),
                fileName = fileName,
                absolutePath = targetFile.absolutePath,
                sha256Hex = shaHex,
                sizeBytes = targetFile.length(),
                verifiedAtEpochMs = targetFile.lastModified().coerceAtLeast(0L)
            )
        }

    /**
     * Enumerates provisioned `.litertlm` models and computes full-file SHA-256 digests on
     * `Dispatchers.IO`. Intended for provisioning management screens and cold verification,
     * not per-turn inference calls.
     */
    override suspend fun listProvisionedModels(): List<ProvisionedModelInfo> =
        withContext(Dispatchers.IO) {
            ensureModelsDirectory()
            val files = modelsDir.listFiles() ?: return@withContext emptyList()
            val results = ArrayList<ProvisionedModelInfo>()
            for (file in files.sortedBy { it.name }) {
                if (!file.isFile || !file.name.endsWith(LITERTLM_EXTENSION) || file.length() <= 0L) {
                    continue
                }
                if (!isSafelyContained(file)) {
                    continue
                }
                val shaHex = computeFileSha256Hex(file)
                results.add(
                    ProvisionedModelInfo(
                        modelId = file.name.removeSuffix(LITERTLM_EXTENSION),
                        fileName = file.name,
                        absolutePath = file.absolutePath,
                        sha256Hex = shaHex,
                        sizeBytes = file.length(),
                        verifiedAtEpochMs = file.lastModified().coerceAtLeast(0L)
                    )
                )
            }
            results
        }

    override suspend fun verifyFileIntegrity(
        absolutePath: String,
        expectedSha256Hex: String
    ): Boolean = withContext(Dispatchers.IO) {
        val expectedBytes = decodeSha256Hex(expectedSha256Hex) ?: return@withContext false
        if (absolutePath.isBlank() || '\u0000' in absolutePath) return@withContext false

        val candidate = File(absolutePath)
        if (!candidate.exists() || !candidate.isFile) return@withContext false
        if (!candidate.name.endsWith(LITERTLM_EXTENSION)) return@withContext false
        if (!isSafelyContained(candidate)) return@withContext false

        val computedBytes = computeFileSha256Bytes(candidate)
        MessageDigest.isEqual(computedBytes, expectedBytes)
    }

    override suspend fun deleteProvisionedModel(fileName: String): Boolean =
        withContext(Dispatchers.IO) {
            mutationMutex.withLock {
                val targetFile = resolveContainedModelFile(fileName)
                if (targetFile.exists() && targetFile.isFile) {
                    targetFile.delete()
                } else {
                    false
                }
            }
        }

    /**
     * Imports a user-selected SAF URI offline into app-private `filesDir/models/` and verifies
     * its streaming SHA-256 digest against [pinnedSpec].
     */
    suspend fun importFromSafUri(
        context: Context,
        sourceUri: Uri,
        pinnedSpec: PinnedModelSpec,
        onProgress: ((ProvisioningProgress) -> Unit)? = null
    ): ProvisionedModelInfo = withContext(Dispatchers.IO) {
        require(sourceUri.scheme == ContentResolver.SCHEME_CONTENT) {
            "SAF model import requires a '${ContentResolver.SCHEME_CONTENT}' URI, got scheme='${sourceUri.scheme}'"
        }
        val reportedSize = queryUriSizeBytes(context, sourceUri)
        val inputStream = context.contentResolver.openInputStream(sourceUri)
            ?: throw IllegalStateException("ContentResolver returned null InputStream for $sourceUri")
        inputStream.use { stream ->
            importFromStream(
                inputStream = stream,
                sourceSizeBytes = reportedSize,
                pinnedSpec = pinnedSpec,
                onProgress = onProgress
            )
        }
    }

    /**
     * Streams [inputStream] into a temporary `.tmp` file inside `modelsDir`, verifies its
     * SHA-256 digest in constant time against [pinnedSpec], and atomically promotes it to
     * `modelsDir/<pinnedSpec.fileName>`.
     */
    suspend fun importFromStream(
        inputStream: InputStream,
        sourceSizeBytes: Long,
        pinnedSpec: PinnedModelSpec,
        onProgress: ((ProvisioningProgress) -> Unit)? = null
    ): ProvisionedModelInfo = withContext(Dispatchers.IO) {
        mutationMutex.withLock {
            ensureModelsDirectory()
            val finalFile = resolveContainedModelFile(pinnedSpec.fileName)
            val tempFile = resolveContainedTempFile(pinnedSpec.fileName)

            val expectedDigestBytes = decodeSha256Hex(pinnedSpec.expectedSha256Hex)
                ?: throw IllegalArgumentException("Invalid expected SHA-256 hex digest in PinnedModelSpec")

            val effectiveSizeBytes = maxOf(sourceSizeBytes, pinnedSpec.expectedSizeBytes)
            if (effectiveSizeBytes > Long.MAX_VALUE - SAFETY_HEADROOM_BYTES) {
                throw IllegalStateException(
                    "Model size overflow during storage pre-check: effectiveSizeBytes=$effectiveSizeBytes"
                )
            }
            val requiredBytes = effectiveSizeBytes + SAFETY_HEADROOM_BYTES
            val availableBytes = storageSpaceProvider.availableBytes(modelsDir)
            if (availableBytes < requiredBytes) {
                throw IllegalStateException(
                    "Insufficient storage for offline model import: available=$availableBytes bytes, " +
                        "required=$requiredBytes bytes (2x temporary storage headroom applies)"
                )
            }

            if (tempFile.exists()) {
                tempFile.delete()
            }

            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(STREAM_BUFFER_BYTES)
            var bytesCopied = 0L

            try {
                FileOutputStream(tempFile).use { output ->
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val read = inputStream.read(buffer)
                        if (read < 0) break
                        if (read == 0) continue
                        if (read.toLong() > pinnedSpec.expectedSizeBytes - bytesCopied) {
                            throw SecurityException(
                                "Model stream exceeded pinned expected size of ${pinnedSpec.expectedSizeBytes} bytes for ${pinnedSpec.fileName}"
                            )
                        }
                        output.write(buffer, 0, read)
                        digest.update(buffer, 0, read)
                        bytesCopied += read
                        val reportedTotal = when {
                            sourceSizeBytes > 0L && bytesCopied <= sourceSizeBytes -> sourceSizeBytes
                            pinnedSpec.expectedSizeBytes > 0L && bytesCopied <= pinnedSpec.expectedSizeBytes ->
                                pinnedSpec.expectedSizeBytes

                            else -> 0L
                        }
                        onProgress?.invoke(
                            ProvisioningProgress(
                                bytesCopied = bytesCopied,
                                totalBytes = reportedTotal
                            )
                        )
                    }
                    output.flush()
                    output.fd.sync()
                }

                if (bytesCopied <= 0L) {
                    throw IllegalStateException("Imported model stream was empty for ${pinnedSpec.fileName}")
                }

                val computedDigestBytes = digest.digest()
                if (!MessageDigest.isEqual(computedDigestBytes, expectedDigestBytes)) {
                    tempFile.delete()
                    throw SecurityException(
                        "Model SHA-256 verification failed for ${pinnedSpec.fileName}"
                    )
                }

                atomicPromote(tempFile, finalFile)

                ProvisionedModelInfo(
                    modelId = pinnedSpec.modelId,
                    fileName = pinnedSpec.fileName,
                    absolutePath = finalFile.absolutePath,
                    sha256Hex = toHexLower(computedDigestBytes),
                    sizeBytes = bytesCopied,
                    verifiedAtEpochMs = clockMs()
                )
            } catch (t: Throwable) {
                if (tempFile.exists()) {
                    tempFile.delete()
                }
                throw t
            }
        }
    }

    private fun queryUriSizeBytes(context: Context, sourceUri: Uri): Long {
        var size = -1L
        context.contentResolver.query(
            sourceUri,
            arrayOf(OpenableColumns.SIZE),
            null,
            null,
            null
        )?.use { cursor ->
            if (cursor.moveToFirst()) {
                val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) {
                    size = cursor.getLong(sizeIndex)
                }
            }
        }
        return size
    }

    private fun atomicPromote(tempFile: File, finalFile: File) {
        try {
            Files.move(
                tempFile.toPath(),
                finalFile.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE
            )
        } catch (_: Exception) {
            if (!tempFile.renameTo(finalFile)) {
                if (finalFile.exists() && !finalFile.delete()) {
                    throw IllegalStateException(
                        "Failed to replace existing model file at ${finalFile.absolutePath}"
                    )
                }
                if (!tempFile.renameTo(finalFile)) {
                    throw IllegalStateException(
                        "Failed to promote verified model file into ${finalFile.absolutePath}"
                    )
                }
            }
        }
    }

    private fun ensureModelsDirectory() {
        if (!modelsDir.exists()) {
            modelsDir.mkdirs()
        }
    }

    private fun resolveContainedModelFile(fileName: String): File {
        validateModelFileNameStrict(fileName)
        ensureModelsDirectory()
        val file = File(modelsDir, fileName)
        if (!isSafelyContained(file)) {
            throw SecurityException("Model file path escapes models directory: $fileName")
        }
        return file
    }

    private fun resolveContainedTempFile(fileName: String): File {
        validateModelFileNameStrict(fileName)
        ensureModelsDirectory()
        val file = File(modelsDir, "$fileName$TEMP_SUFFIX")
        if (!isSafelyContained(file)) {
            throw SecurityException("Temp model file path escapes models directory: $fileName")
        }
        return file
    }

    private fun validateModelFileNameStrict(fileName: String) {
        require(fileName.isNotBlank()) { "Model fileName must not be blank" }
        require('\u0000' !in fileName) { "Model fileName must not contain NUL" }
        require('/' !in fileName && '\\' !in fileName) {
            "Model fileName must not contain path separators: $fileName"
        }
        require(".." !in fileName) { "Model fileName must not contain '..': $fileName" }
        require(fileName.endsWith(LITERTLM_EXTENSION) && fileName.length > LITERTLM_EXTENSION.length) {
            "Model fileName must end with '$LITERTLM_EXTENSION': $fileName"
        }
    }

    private fun isSafelyContained(candidate: File): Boolean {
        val rootCanonical = modelsDir.canonicalFile
        val targetCanonical = candidate.canonicalFile
        val rootPrefix = rootCanonical.path + File.separator
        return targetCanonical.path.startsWith(rootPrefix)
    }

    private suspend fun computeFileSha256Bytes(file: File): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(STREAM_BUFFER_BYTES)
        FileInputStream(file).use { input ->
            while (true) {
                currentCoroutineContext().ensureActive()
                val read = input.read(buffer)
                if (read < 0) break
                if (read == 0) continue
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest()
    }

    private suspend fun computeFileSha256Hex(file: File): String {
        return toHexLower(computeFileSha256Bytes(file))
    }

    private fun decodeSha256Hex(hex: String): ByteArray? {
        val trimmed = hex.trim()
        if (trimmed.length != SHA256_HEX_LENGTH) return null
        val out = ByteArray(SHA256_HEX_LENGTH / 2)
        for (i in out.indices) {
            val hi = hexNibble(trimmed[i * 2]) ?: return null
            val lo = hexNibble(trimmed[i * 2 + 1]) ?: return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    private fun hexNibble(ch: Char): Int? {
        return when (ch) {
            in '0'..'9' -> ch - '0'
            in 'a'..'f' -> ch - 'a' + 10
            in 'A'..'F' -> ch - 'A' + 10
            else -> null
        }
    }

    private fun toHexLower(bytes: ByteArray): String {
        val chars = CharArray(bytes.size * 2)
        val hex = "0123456789abcdef"
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            chars[i * 2] = hex[v ushr 4]
            chars[i * 2 + 1] = hex[v and 0x0F]
        }
        return String(chars)
    }

    companion object {
        const val MODELS_DIR_NAME: String = "models"
        const val LITERTLM_EXTENSION: String = ".litertlm"
        const val STREAM_BUFFER_BYTES: Int = 1024 * 1024 // 1 MiB streaming buffer
        const val SAFETY_HEADROOM_BYTES: Long = 256L * 1024L * 1024L // 256 MiB headroom

        private const val TEMP_SUFFIX: String = ".tmp"
        private const val SHA256_HEX_LENGTH: Int = 64
    }
}

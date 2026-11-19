package com.nava.spike.phase0

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.StatFs
import android.os.SystemClock
import android.provider.OpenableColumns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest

/**
 * Offline SAF model provisioner for Phase 0 validation (PLAN.md Section 1.1 Law 3 & Section 9 Item 6).
 *
 * Imports a user-selected .litertlm file via Intent.ACTION_OPEN_DOCUMENT into app-private
 * filesDir/models/ while computing a streaming SHA-256 digest and verifying free disk space
 * for the temporary 2x storage requirement (source download + private copy).
 */
class Phase0SafProvisioner(private val context: Context) {

    data class SafFileMetadata(
        val displayName: String,
        val sizeBytes: Long
    )

    data class ProvisioningResult(
        val modelFile: File,
        val sha256Hex: String,
        val bytesCopied: Long,
        val durationMs: Long,
        val availableBytesAfter: Long
    )

    fun modelsDirectory(): File {
        return File(context.filesDir, MODELS_DIR_NAME).apply {
            if (!exists()) {
                mkdirs()
            }
        }
    }

    fun buildOpenDocumentIntent(): Intent {
        return Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
    }

    fun queryMetadata(sourceUri: Uri): SafFileMetadata {
        var displayName = DEFAULT_MODEL_FILE_NAME
        var sizeBytes = -1L

        context.contentResolver.query(
            sourceUri,
            arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
            null,
            null,
            null
        )?.use { cursor ->
            if (cursor.moveToFirst()) {
                val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                if (nameIndex >= 0) {
                    val queriedName = cursor.getString(nameIndex)
                    if (!queriedName.isNullOrBlank()) {
                        displayName = queriedName
                    }
                }
                if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) {
                    sizeBytes = cursor.getLong(sizeIndex)
                }
            }
        }

        return SafFileMetadata(
            displayName = sanitizeFileName(displayName),
            sizeBytes = sizeBytes
        )
    }

    suspend fun importAndVerifyModel(
        sourceUri: Uri,
        targetFileName: String? = null,
        expectedSha256Hex: String? = null,
        onProgress: ((bytesCopied: Long, totalBytes: Long) -> Unit)? = null
    ): ProvisioningResult = withContext(Dispatchers.IO) {
        val metadata = queryMetadata(sourceUri)
        val safeName = sanitizeFileName(targetFileName ?: metadata.displayName)
        require(safeName.endsWith(LITERTLM_EXTENSION)) {
            "Expected a .litertlm model file, got: $safeName"
        }

        val modelsDir = modelsDirectory()
        val availableBytes = StatFs(modelsDir.absolutePath).availableBytes
        val requiredBytes = if (metadata.sizeBytes > 0L) {
            metadata.sizeBytes + SAFETY_HEADROOM_BYTES
        } else {
            MIN_UNKNOWN_SIZE_REQUIRED_BYTES
        }
        check(availableBytes >= requiredBytes) {
            "Insufficient internal storage for offline model copy: available=$availableBytes bytes, " +
                "required=$requiredBytes bytes (2x temporary storage applies while external source remains)."
        }

        val tempFile = File(modelsDir, "$safeName.tmp")
        val finalFile = File(modelsDir, safeName)
        if (tempFile.exists()) {
            tempFile.delete()
        }

        val startMs = SystemClock.elapsedRealtime()
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(STREAM_BUFFER_BYTES)
        var totalCopied = 0L

        try {
            val inputStream = context.contentResolver.openInputStream(sourceUri)
                ?: throw IllegalStateException("ContentResolver returned null InputStream for $sourceUri")

            inputStream.use { input ->
                FileOutputStream(tempFile).use { output ->
                    while (true) {
                        val read = input.read(buffer)
                        if (read <= 0) break
                        output.write(buffer, 0, read)
                        digest.update(buffer, 0, read)
                        totalCopied += read
                        onProgress?.invoke(totalCopied, metadata.sizeBytes)
                    }
                    output.flush()
                    output.fd.sync()
                }
            }

            val computedSha256 = digest.digest().toHexLower()
            if (!expectedSha256Hex.isNullOrBlank()) {
                val normalizedExpected = expectedSha256Hex.trim().lowercase()
                if (computedSha256 != normalizedExpected) {
                    tempFile.delete()
                    throw SecurityException(
                        "Model SHA-256 verification failed: expected=$normalizedExpected, actual=$computedSha256"
                    )
                }
            }

            if (!tempFile.renameTo(finalFile)) {
                if (finalFile.exists() && !finalFile.delete()) {
                    throw IllegalStateException("Failed to replace existing model file: ${finalFile.absolutePath}")
                }
                if (!tempFile.renameTo(finalFile)) {
                    throw IllegalStateException("Failed to atomically move verified model into ${finalFile.absolutePath}")
                }
            }

            val durationMs = SystemClock.elapsedRealtime() - startMs
            ProvisioningResult(
                modelFile = finalFile,
                sha256Hex = computedSha256,
                bytesCopied = totalCopied,
                durationMs = durationMs,
                availableBytesAfter = StatFs(modelsDir.absolutePath).availableBytes
            )
        } catch (t: Throwable) {
            if (tempFile.exists()) {
                tempFile.delete()
            }
            throw t
        }
    }

    suspend fun computeSha256(file: File): String = withContext(Dispatchers.IO) {
        require(file.exists() && file.isFile) { "Model file does not exist: ${file.absolutePath}" }
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(STREAM_BUFFER_BYTES)
        FileInputStream(file).use { input ->
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        digest.digest().toHexLower()
    }

    private fun sanitizeFileName(rawName: String): String {
        val base = rawName.substringAfterLast('/').substringAfterLast('\\').trim()
        val cleaned = base.replace(Regex("[^A-Za-z0-9._-]"), "_")
        check(!cleaned.contains("..")) { "Invalid model file name: $rawName" }
        return if (cleaned.isBlank()) DEFAULT_MODEL_FILE_NAME else cleaned
    }

    private fun ByteArray.toHexLower(): String {
        val chars = CharArray(size * 2)
        val hex = "0123456789abcdef"
        for (i in indices) {
            val v = this[i].toInt() and 0xFF
            chars[i * 2] = hex[v ushr 4]
            chars[i * 2 + 1] = hex[v and 0x0F]
        }
        return String(chars)
    }

    companion object {
        private const val MODELS_DIR_NAME = "models"
        private const val DEFAULT_MODEL_FILE_NAME = "gemma-4-E2B-it.litertlm"
        private const val LITERTLM_EXTENSION = ".litertlm"
        private const val STREAM_BUFFER_BYTES = 1024 * 1024 // 1 MiB streaming buffer
        private const val SAFETY_HEADROOM_BYTES = 256L * 1024L * 1024L // 256 MiB headroom
        private const val MIN_UNKNOWN_SIZE_REQUIRED_BYTES = 4L * 1024L * 1024L * 1024L // 4 GiB fallback (E4B + headroom)
    }
}

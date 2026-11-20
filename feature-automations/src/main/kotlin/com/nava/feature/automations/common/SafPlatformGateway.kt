package com.nava.feature.automations.common

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import com.nava.domain.security.Gemma4InputSanitizer
import java.io.ByteArrayOutputStream
import java.text.Normalizer
import java.util.Locale

/**
 * Metadata descriptor for a file or subdirectory inside a user-granted SAF tree URI.
 */
data class SafDocumentEntry(
    val documentUri: String,
    val displayName: String,
    val mimeType: String,
    val isDirectory: Boolean,
    val sizeBytes: Long,
    val lastModifiedEpochMs: Long
)

/**
 * Typed outcome returned by [SafPlatformGateway] operations.
 */
sealed interface SafGatewayResult<out T> {
    data class Success<T>(val value: T) : SafGatewayResult<T>
    data class GrantMissing(val treeUri: String) : SafGatewayResult<Nothing>
    data class NotFound(val fileName: String) : SafGatewayResult<Nothing>
    data class Unavailable(val reason: String) : SafGatewayResult<Nothing>
}

/**
 * Thin, JVM-testable abstraction over Android Storage Access Framework (`DocumentsContract`)
 * restricted strictly to user-granted persistable tree URIs (no `MANAGE_EXTERNAL_STORAGE`).
 */
interface SafPlatformGateway {
    fun hasPersistedGrant(treeUri: String, requireWrite: Boolean): Boolean

    fun listPersistedTreeUris(): Set<String>

    suspend fun listDocuments(treeUri: String): SafGatewayResult<List<SafDocumentEntry>>

    suspend fun readDocument(
        treeUri: String,
        fileName: String,
        maxBytes: Int = DEFAULT_MAX_READ_BYTES
    ): SafGatewayResult<ByteArray>

    suspend fun writeDocument(
        treeUri: String,
        fileName: String,
        mimeType: String,
        content: ByteArray,
        overwrite: Boolean = true
    ): SafGatewayResult<SafDocumentEntry>

    suspend fun deleteDocument(
        treeUri: String,
        fileName: String
    ): SafGatewayResult<Boolean>

    companion object {
        const val DEFAULT_MAX_READ_BYTES: Int = 512 * 1024

        private const val MAX_PERCENT_DECODE_PASSES: Int = 4

        /**
         * Validates that [fileName] is a single traversal-free document name inside a SAF folder.
         *
         * Hardened against path traversal, homoglyphs, invisible/bidi controls, CRLF, null bytes,
         * and multi-pass percent-encoded payloads matching OutboundChannelPolicy.
         */
        fun isSafeDocumentName(fileName: String): Boolean {
            if (fileName.isEmpty()) return false
            if (containsRawControlOrBadChar(fileName)) return false

            val nfkc = Normalizer.normalize(fileName, Normalizer.Form.NFKC)
            val normalized = Gemma4InputSanitizer.stripInvisibleControls(nfkc).trim()
            if (normalized.isEmpty() || normalized == "." || normalized == "..") return false
            if (normalized.length > 255) return false
            if (containsRawControlOrBadChar(normalized)) return false
            if (".." in normalized) return false

            var current = normalized
            for (pass in 0 until MAX_PERCENT_DECODE_PASSES) {
                val lower = current.lowercase(Locale.ROOT)
                if (
                    ".." in lower ||
                    '/' in lower ||
                    '\\' in lower ||
                    "%5c" in lower ||
                    "%2f" in lower ||
                    "%00" in lower ||
                    "%0a" in lower ||
                    "%0d" in lower
                ) {
                    return false
                }
                val decoded = decodePercentOnce(current)
                if (decoded == current) {
                    break
                }
                if (containsRawControlOrBadChar(decoded) || ".." in decoded || '/' in decoded || '\\' in decoded) {
                    return false
                }
                val decodedNfkc = Normalizer.normalize(decoded, Normalizer.Form.NFKC)
                current = Gemma4InputSanitizer.stripInvisibleControls(decodedNfkc).trim()
                if (containsRawControlOrBadChar(current) || ".." in current || '/' in current || '\\' in current) {
                    return false
                }
            }

            if (containsRawControlOrBadChar(current)) return false
            val finalLower = current.lowercase(Locale.ROOT)
            return !(
                ".." in finalLower ||
                '/' in finalLower ||
                '\\' in finalLower ||
                "%2e" in finalLower ||
                "%5c" in finalLower ||
                "%2f" in finalLower ||
                "%00" in finalLower ||
                "%0a" in finalLower ||
                "%0d" in finalLower
            )
        }

        private fun containsRawControlOrBadChar(s: String): Boolean {
            for (ch in s) {
                if (ch == '/' || ch == '\\' || ch == '\u0000' || ch == '\r' || ch == '\n' || ch.code < 32 || ch.code == 127) {
                    return true
                }
            }
            return false
        }

        private fun decodePercentOnce(input: String): String {
            if ('%' !in input) return input
            val sb = StringBuilder(input.length)
            var i = 0
            while (i < input.length) {
                val ch = input[i]
                if (ch == '%' && i + 2 < input.length) {
                    val hi = hexDigit(input[i + 1])
                    val lo = hexDigit(input[i + 2])
                    if (hi >= 0 && lo >= 0) {
                        val decodedByte = (hi shl 4) or lo
                        sb.append(decodedByte.toChar())
                        i += 3
                        continue
                    }
                }
                sb.append(ch)
                i++
            }
            return sb.toString()
        }

        private fun hexDigit(ch: Char): Int = when (ch) {
            in '0'..'9' -> ch - '0'
            in 'a'..'f' -> ch - 'a' + 10
            in 'A'..'F' -> ch - 'A' + 10
            else -> -1
        }
    }
}

/**
 * Production Android SDK implementation of [SafPlatformGateway] using `DocumentsContract`
 * and `ContentResolver.persistedUriPermissions`.
 */
class AndroidSafPlatformGateway(
    private val context: Context
) : SafPlatformGateway {

    override fun hasPersistedGrant(treeUri: String, requireWrite: Boolean): Boolean {
        val target = treeUri.trim()
        if (target.isEmpty()) return false
        return context.contentResolver.persistedUriPermissions.any { perm ->
            perm.uri.toString() == target &&
                perm.isReadPermission &&
                (!requireWrite || perm.isWritePermission)
        }
    }

    override fun listPersistedTreeUris(): Set<String> {
        return context.contentResolver.persistedUriPermissions
            .filter { it.isReadPermission }
            .map { it.uri.toString() }
            .toCollection(LinkedHashSet())
    }

    override suspend fun listDocuments(treeUri: String): SafGatewayResult<List<SafDocumentEntry>> {
        if (!hasPersistedGrant(treeUri, requireWrite = false)) {
            return SafGatewayResult.GrantMissing(treeUri)
        }
        return try {
            val parsedTree = Uri.parse(treeUri)
            val rootDocId = DocumentsContract.getTreeDocumentId(parsedTree)
            val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(parsedTree, rootDocId)
            val projection = arrayOf(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_SIZE,
                DocumentsContract.Document.COLUMN_LAST_MODIFIED
            )
            val entries = ArrayList<SafDocumentEntry>()
            context.contentResolver.query(childrenUri, projection, null, null, null)?.use { cursor ->
                while (cursor.moveToNext()) {
                    val docId = cursor.getString(0) ?: continue
                    val name = cursor.getString(1).orEmpty()
                    val mime = cursor.getString(2).orEmpty()
                    val size = if (cursor.isNull(3)) 0L else cursor.getLong(3)
                    val modified = if (cursor.isNull(4)) 0L else cursor.getLong(4)
                    val docUri = DocumentsContract.buildDocumentUriUsingTree(parsedTree, docId)
                    entries.add(
                        SafDocumentEntry(
                            documentUri = docUri.toString(),
                            displayName = name,
                            mimeType = mime,
                            isDirectory = mime == DocumentsContract.Document.MIME_TYPE_DIR,
                            sizeBytes = size,
                            lastModifiedEpochMs = modified
                        )
                    )
                }
            }
            entries.sortBy { it.displayName }
            SafGatewayResult.Success(entries)
        } catch (_: SecurityException) {
            SafGatewayResult.GrantMissing(treeUri)
        } catch (e: RuntimeException) {
            SafGatewayResult.Unavailable(e.message ?: "Failed to list SAF directory")
        }
    }

    override suspend fun readDocument(
        treeUri: String,
        fileName: String,
        maxBytes: Int
    ): SafGatewayResult<ByteArray> {
        if (!hasPersistedGrant(treeUri, requireWrite = false)) {
            return SafGatewayResult.GrantMissing(treeUri)
        }
        if (!SafPlatformGateway.isSafeDocumentName(fileName) || maxBytes <= 0) {
            return SafGatewayResult.Unavailable("Invalid document name or read limit")
        }
        val listing = listDocuments(treeUri)
        if (listing !is SafGatewayResult.Success) {
            return when (listing) {
                is SafGatewayResult.GrantMissing -> listing
                is SafGatewayResult.NotFound -> listing
                is SafGatewayResult.Unavailable -> listing
                is SafGatewayResult.Success -> error("unreachable")
            }
        }
        val match = listing.value.firstOrNull { !it.isDirectory && it.displayName == fileName }
            ?: return SafGatewayResult.NotFound(fileName)
        return try {
            val stream = context.contentResolver.openInputStream(Uri.parse(match.documentUri))
                ?: return SafGatewayResult.Unavailable("Unable to open SAF document stream")
            stream.use { input ->
                val out = ByteArrayOutputStream()
                val buf = ByteArray(8192)
                var remaining = maxBytes
                while (remaining > 0) {
                    val toRead = minOf(buf.size, remaining)
                    val read = input.read(buf, 0, toRead)
                    if (read <= 0) break
                    out.write(buf, 0, read)
                    remaining -= read
                }
                SafGatewayResult.Success(out.toByteArray())
            }
        } catch (_: SecurityException) {
            SafGatewayResult.GrantMissing(treeUri)
        } catch (e: Exception) {
            SafGatewayResult.Unavailable(e.message ?: "Failed to read SAF document")
        }
    }

    override suspend fun writeDocument(
        treeUri: String,
        fileName: String,
        mimeType: String,
        content: ByteArray,
        overwrite: Boolean
    ): SafGatewayResult<SafDocumentEntry> {
        if (!hasPersistedGrant(treeUri, requireWrite = true)) {
            return SafGatewayResult.GrantMissing(treeUri)
        }
        if (!SafPlatformGateway.isSafeDocumentName(fileName) || mimeType.isBlank()) {
            return SafGatewayResult.Unavailable("Invalid document name or MIME type")
        }
        val listing = listDocuments(treeUri)
        if (listing !is SafGatewayResult.Success) {
            return when (listing) {
                is SafGatewayResult.GrantMissing -> listing
                is SafGatewayResult.NotFound -> listing
                is SafGatewayResult.Unavailable -> listing
                is SafGatewayResult.Success -> error("unreachable")
            }
        }
        val existing = listing.value.firstOrNull { !it.isDirectory && it.displayName == fileName }
        if (existing != null && !overwrite) {
            return SafGatewayResult.Unavailable("Document '$fileName' already exists")
        }
        return try {
            val parsedTree = Uri.parse(treeUri)
            val targetDocUri: Uri = if (existing != null) {
                Uri.parse(existing.documentUri)
            } else {
                val rootDocId = DocumentsContract.getTreeDocumentId(parsedTree)
                val parentDocUri = DocumentsContract.buildDocumentUriUsingTree(parsedTree, rootDocId)
                DocumentsContract.createDocument(context.contentResolver, parentDocUri, mimeType, fileName)
                    ?: return SafGatewayResult.Unavailable("Failed to create SAF document '$fileName'")
            }
            val outputStream = context.contentResolver.openOutputStream(targetDocUri, "wt")
                ?: return SafGatewayResult.Unavailable("Unable to open SAF document output stream")
            outputStream.use { out ->
                out.write(content)
                out.flush()
            }
            SafGatewayResult.Success(
                SafDocumentEntry(
                    documentUri = targetDocUri.toString(),
                    displayName = fileName,
                    mimeType = mimeType,
                    isDirectory = false,
                    sizeBytes = content.size.toLong(),
                    lastModifiedEpochMs = System.currentTimeMillis()
                )
            )
        } catch (_: SecurityException) {
            SafGatewayResult.GrantMissing(treeUri)
        } catch (e: Exception) {
            SafGatewayResult.Unavailable(e.message ?: "Failed to write SAF document")
        }
    }

    override suspend fun deleteDocument(
        treeUri: String,
        fileName: String
    ): SafGatewayResult<Boolean> {
        if (!hasPersistedGrant(treeUri, requireWrite = true)) {
            return SafGatewayResult.GrantMissing(treeUri)
        }
        if (!SafPlatformGateway.isSafeDocumentName(fileName)) {
            return SafGatewayResult.Unavailable("Invalid document name")
        }
        val listing = listDocuments(treeUri)
        if (listing !is SafGatewayResult.Success) {
            return when (listing) {
                is SafGatewayResult.GrantMissing -> listing
                is SafGatewayResult.NotFound -> listing
                is SafGatewayResult.Unavailable -> listing
                is SafGatewayResult.Success -> error("unreachable")
            }
        }
        val match = listing.value.firstOrNull { !it.isDirectory && it.displayName == fileName }
            ?: return SafGatewayResult.NotFound(fileName)
        return try {
            val deleted = DocumentsContract.deleteDocument(
                context.contentResolver,
                Uri.parse(match.documentUri)
            )
            SafGatewayResult.Success(deleted)
        } catch (_: SecurityException) {
            SafGatewayResult.GrantMissing(treeUri)
        } catch (e: RuntimeException) {
            SafGatewayResult.Unavailable(e.message ?: "Failed to delete SAF document")
        }
    }
}

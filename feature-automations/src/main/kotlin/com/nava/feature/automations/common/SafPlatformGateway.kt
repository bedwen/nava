package com.nava.feature.automations.common

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import java.io.ByteArrayOutputStream

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

        /**
         * Validates that [fileName] is a single traversal-free document name inside a SAF folder.
         */
        fun isSafeDocumentName(fileName: String): Boolean {
            val trimmed = fileName.trim()
            if (trimmed.isEmpty() || trimmed == "." || trimmed == "..") return false
            if (trimmed.length > 255) return false
            for (ch in trimmed) {
                if (ch == '/' || ch == '\\' || ch == '\u0000' || ch == '\r' || ch == '\n' || ch.code < 32) {
                    return false
                }
            }
            if (".." in trimmed) return false
            return true
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

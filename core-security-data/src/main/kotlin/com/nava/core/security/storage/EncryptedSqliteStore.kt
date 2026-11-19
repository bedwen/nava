package com.nava.core.security.storage

import com.nava.core.security.crypto.AesGcmCryptoEngine
import com.nava.core.security.crypto.CryptoKeyProvider
import com.nava.core.security.crypto.HmacSha256Engine
import com.nava.core.security.crypto.SecureMemory
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Thread-safe encrypted SQLite store providing column-level `AES-256-GCM` encryption with
 * row-bound Associated Authenticated Data (`AAD = "$tableName:$rowId:$columnName"`) and
 * deterministic `HMAC-SHA256` blind indexing.
 */
class EncryptedSqliteStore(
    private val storage: EncryptedRowStorage,
    private val keyProvider: CryptoKeyProvider,
    private val aesGcmEngine: AesGcmCryptoEngine = AesGcmCryptoEngine(),
    private val hmacEngine: HmacSha256Engine = HmacSha256Engine(),
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO
) {
    private val storeMutex = Mutex()

    /**
     * Computes a deterministic `HMAC-SHA256` blind index over `\u0000`-separated [segments]
     * using `nava_blind_index_key` (PLAN.md Section 3.1 `languageCode + "\u0000" + canonicalSkeleton`).
     */
    fun computeBlindIndex(vararg segments: String): String {
        val key = keyProvider.getOrCreateBlindIndexKey()
        return hmacEngine.computeBlindIndex(key, *segments)
    }

    /**
     * Computes a null-byte-safe, domain-collision-free `HMAC-SHA256` blind index over
     * length-prefixed [segments] encoded via [StructuredPayloadCodec].
     */
    fun computeStructuredBlindIndex(vararg segments: String): String {
        require(segments.isNotEmpty()) { "Structured blind index requires at least one segment" }
        val encoded = StructuredPayloadCodec.encode {
            writeStringList(segments.toList())
        }
        return SecureMemory.withZeroizedBytes(encoded) { payload ->
            hmacEngine.computeHmacHex(keyProvider.getOrCreateBlindIndexKey(), payload)
        }
    }

    /**
     * Encrypts [plaintext] with `nava_db_master_key` and row-bound AAD
     * (`"$tableName:$rowId:$columnName"`).
     */
    fun encryptColumn(
        tableName: String,
        rowId: Long,
        columnName: String,
        plaintext: ByteArray
    ): ByteArray {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        val aad = aesGcmEngine.buildRowAad(validTable, rowId, columnName)
        val masterKey = keyProvider.getOrCreateDbMasterKey()
        return aesGcmEngine.encrypt(masterKey, plaintext, aad)
    }

    /**
     * Decrypts [blob] with `nava_db_master_key` verifying row-bound AAD
     * (`"$tableName:$rowId:$columnName"`).
     *
     * Propagates `AEADBadTagException` if ciphertext was tampered with or swapped across rows,
     * columns, or tables.
     */
    fun decryptColumn(
        tableName: String,
        rowId: Long,
        columnName: String,
        blob: ByteArray
    ): ByteArray {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        val aad = aesGcmEngine.buildRowAad(validTable, rowId, columnName)
        val masterKey = keyProvider.getOrCreateDbMasterKey()
        return aesGcmEngine.decrypt(masterKey, blob, aad)
    }

    /**
     * Allocates a fresh row ID, encrypts [plaintext] bound to that row ID, and inserts the row.
     */
    suspend fun insertEncrypted(
        tableName: String,
        lookupHmac: String,
        plaintext: ByteArray,
        epochSec: Long,
        schemaVersion: Int = 1
    ): Long = withContext(dispatcher) {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        require(lookupHmac.isNotBlank()) { "lookupHmac must not be blank" }
        require(schemaVersion > 0) { "schemaVersion must be positive" }
        storeMutex.withLock {
            storage.withTransaction {
                val rowId = storage.allocateRowId(validTable)
                val encryptedBlob = encryptColumn(
                    tableName = validTable,
                    rowId = rowId,
                    columnName = EncryptedTableSchema.COL_PAYLOAD_BLOB,
                    plaintext = plaintext
                )
                storage.insertRow(
                    validTable,
                    RawEncryptedRow(
                        rowId = rowId,
                        lookupHmac = lookupHmac,
                        schemaVersion = schemaVersion,
                        createdEpochSec = epochSec,
                        updatedEpochSec = epochSec,
                        payloadBlob = encryptedBlob
                    )
                )
                rowId
            }
        }
    }

    /**
     * Atomically updates an existing row matching [lookupHmac] (reusing its `rowId` and
     * `createdEpochSec` while re-encrypting with a fresh IV) or inserts a newly allocated row.
     */
    suspend fun upsertEncryptedByBlindIndex(
        tableName: String,
        lookupHmac: String,
        plaintext: ByteArray,
        epochSec: Long,
        schemaVersion: Int = 1
    ): Long = withContext(dispatcher) {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        require(lookupHmac.isNotBlank()) { "lookupHmac must not be blank" }
        require(schemaVersion > 0) { "schemaVersion must be positive" }
        storeMutex.withLock {
            storage.withTransaction {
                val existing = storage.findByLookupHmac(validTable, lookupHmac)
                val rowId = existing?.rowId ?: storage.allocateRowId(validTable)
                val createdEpochSec = existing?.createdEpochSec ?: epochSec
                val encryptedBlob = encryptColumn(
                    tableName = validTable,
                    rowId = rowId,
                    columnName = EncryptedTableSchema.COL_PAYLOAD_BLOB,
                    plaintext = plaintext
                )
                storage.upsertByLookupHmac(
                    validTable,
                    RawEncryptedRow(
                        rowId = rowId,
                        lookupHmac = lookupHmac,
                        schemaVersion = schemaVersion,
                        createdEpochSec = createdEpochSec,
                        updatedEpochSec = epochSec,
                        payloadBlob = encryptedBlob
                    )
                )
                rowId
            }
        }
    }

    /** Looks up and decrypts the row matching [lookupHmac] in [tableName], or returns null. */
    suspend fun findDecryptedByBlindIndex(
        tableName: String,
        lookupHmac: String
    ): DecryptedRow? = withContext(dispatcher) {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        require(lookupHmac.isNotBlank()) { "lookupHmac must not be blank" }
        storeMutex.withLock {
            val raw = storage.findByLookupHmac(validTable, lookupHmac) ?: return@withLock null
            decryptRow(validTable, raw)
        }
    }

    /** Looks up and decrypts the row matching [rowId] in [tableName], or returns null. */
    suspend fun findDecryptedByRowId(
        tableName: String,
        rowId: Long
    ): DecryptedRow? = withContext(dispatcher) {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        require(rowId > 0L) { "rowId must be positive" }
        storeMutex.withLock {
            val raw = storage.findByRowId(validTable, rowId) ?: return@withLock null
            decryptRow(validTable, raw)
        }
    }

    /** Lists and decrypts all rows in [tableName]. */
    suspend fun listAllDecrypted(tableName: String): List<DecryptedRow> = withContext(dispatcher) {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        storeMutex.withLock {
            decryptRowsOrZeroize(validTable, storage.listRows(validTable))
        }
    }

    /** Lists and decrypts up to [limit] most recently updated rows in [tableName]. */
    suspend fun listRecentDecrypted(
        tableName: String,
        limit: Int
    ): List<DecryptedRow> = withContext(dispatcher) {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        if (limit <= 0) return@withContext emptyList()
        storeMutex.withLock {
            decryptRowsOrZeroize(validTable, storage.listRecent(validTable, limit))
        }
    }

    /**
     * Lists and decrypts up to [limit] most recently updated rows matching [lookupHmac]
     * in [tableName], zeroizing already-decrypted rows if any row fails authentication.
     */
    suspend fun listRecentDecryptedByBlindIndex(
        tableName: String,
        lookupHmac: String,
        limit: Int
    ): List<DecryptedRow> = withContext(dispatcher) {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        require(lookupHmac.isNotBlank()) { "lookupHmac must not be blank" }
        if (limit <= 0) return@withContext emptyList()
        storeMutex.withLock {
            decryptRowsOrZeroize(
                validTable,
                storage.listRecentByLookupHmac(validTable, lookupHmac, limit)
            )
        }
    }

    /** Deletes rows matching [lookupHmac] in [tableName]. */
    suspend fun deleteByBlindIndex(
        tableName: String,
        lookupHmac: String
    ): Boolean = withContext(dispatcher) {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        require(lookupHmac.isNotBlank()) { "lookupHmac must not be blank" }
        storeMutex.withLock {
            storage.deleteByLookupHmac(validTable, lookupHmac)
        }
    }

    /** Deletes the row matching [rowId] in [tableName]. */
    suspend fun deleteByRowId(
        tableName: String,
        rowId: Long
    ): Boolean = withContext(dispatcher) {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        require(rowId > 0L) { "rowId must be positive" }
        storeMutex.withLock {
            storage.deleteByRowId(validTable, rowId)
        }
    }

    /** Evicts least-recently-updated rows beyond [maxEntries] from [tableName]. */
    suspend fun evictLru(
        tableName: String,
        maxEntries: Int
    ): Int = withContext(dispatcher) {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        storeMutex.withLock {
            storage.deleteOlderThanMaxCount(validTable, maxEntries)
        }
    }

    /** Updates `updated_epoch_sec` for LRU tracking without re-encrypting `payload_blob`. */
    suspend fun touchUpdatedEpochSec(
        tableName: String,
        rowId: Long,
        updatedEpochSec: Long
    ): Boolean = withContext(dispatcher) {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        require(rowId > 0L) { "rowId must be positive" }
        storeMutex.withLock {
            storage.touchUpdatedEpochSec(validTable, rowId, updatedEpochSec)
        }
    }

    /** Closes the underlying storage backend. */
    suspend fun close() = withContext(dispatcher) {
        storeMutex.withLock {
            storage.close()
        }
    }

    private fun decryptRowsOrZeroize(
        validTable: String,
        rawRows: List<RawEncryptedRow>
    ): List<DecryptedRow> {
        val result = ArrayList<DecryptedRow>(rawRows.size)
        try {
            for (raw in rawRows) {
                result.add(decryptRow(validTable, raw))
            }
            return result
        } catch (e: Throwable) {
            for (decrypted in result) {
                decrypted.zeroize()
            }
            throw e
        }
    }

    private fun decryptRow(validTable: String, raw: RawEncryptedRow): DecryptedRow {
        val plaintext = decryptColumn(
            tableName = validTable,
            rowId = raw.rowId,
            columnName = EncryptedTableSchema.COL_PAYLOAD_BLOB,
            blob = raw.payloadBlob
        )
        return DecryptedRow(
            rowId = raw.rowId,
            lookupHmac = raw.lookupHmac,
            schemaVersion = raw.schemaVersion,
            createdEpochSec = raw.createdEpochSec,
            updatedEpochSec = raw.updatedEpochSec,
            plaintext = plaintext
        )
    }
}

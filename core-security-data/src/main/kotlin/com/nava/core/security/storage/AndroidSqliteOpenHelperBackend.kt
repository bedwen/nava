package com.nava.core.security.storage

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * Production Android [SQLiteOpenHelper] implementation of [EncryptedRowStorage].
 *
 * Security & performance properties:
 * - Enables SQLite Write-Ahead Logging (WAL) in [onConfigure].
 * - Validates every table name against [EncryptedTableSchema.ALLOWED_TABLES] before executing SQL.
 * - Uses strictly parameterized SQL queries and [ContentValues] for all dynamic values.
 */
class AndroidSqliteOpenHelperBackend(
    context: Context,
    databaseName: String = EncryptedTableSchema.DATABASE_NAME
) : SQLiteOpenHelper(
    context.applicationContext,
    databaseName,
    null,
    EncryptedTableSchema.DATABASE_VERSION
), EncryptedRowStorage {

    override fun onConfigure(db: SQLiteDatabase) {
        super.onConfigure(db)
        db.enableWriteAheadLogging()
    }

    override fun onCreate(db: SQLiteDatabase) {
        for (statement in EncryptedTableSchema.allCreateStatements()) {
            db.execSQL(statement)
        }
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // Additive schema migrations preserve all existing encrypted blobs and row-bound AAD IDs.
        if (oldVersion < 2) {
            for (statement in EncryptedTableSchema.createStatementsForTable(
                EncryptedTableSchema.TABLE_SCHEDULED_REMINDERS
            )) {
                db.execSQL(statement)
            }
        }
        if (oldVersion < 3) {
            for (statement in EncryptedTableSchema.createStatementsForTable(
                EncryptedTableSchema.TABLE_NOTIFICATION_WATCHERS
            )) {
                db.execSQL(statement)
            }
        }
        if (oldVersion < 4) {
            for (statement in EncryptedTableSchema.createStatementsForTable(
                EncryptedTableSchema.TABLE_PERSONAL_FACTS
            )) {
                db.execSQL(statement)
            }
        }
    }

    override fun allocateRowId(tableName: String): Long {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        return withTransaction {
            val db = writableDatabase
            val currentSeq = readCurrentSequence(db, validTable)
            val maxExisting = readMaxRowId(db, validTable)
            val nextId = maxOf(currentSeq, maxExisting) + 1L
            val values = ContentValues(2).apply {
                put(EncryptedTableSchema.COL_SEQ_TABLE_NAME, validTable)
                put(EncryptedTableSchema.COL_SEQ_LAST_ROW_ID, nextId)
            }
            val result = db.insertWithOnConflict(
                EncryptedTableSchema.TABLE_ROW_SEQUENCES,
                null,
                values,
                SQLiteDatabase.CONFLICT_REPLACE
            )
            check(result != -1L) { "Failed to persist next row_id sequence for table '$validTable'" }
            nextId
        }
    }

    override fun insertRow(tableName: String, row: RawEncryptedRow) {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        val db = writableDatabase
        val result = db.insertOrThrow(validTable, null, row.toContentValues())
        check(result != -1L) { "Failed to insert encrypted row into '$validTable'" }
    }

    override fun upsertByLookupHmac(tableName: String, row: RawEncryptedRow) {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        withTransaction {
            val db = writableDatabase
            db.delete(
                validTable,
                "${EncryptedTableSchema.COL_LOOKUP_HMAC} = ? AND ${EncryptedTableSchema.COL_ROW_ID} != ?",
                arrayOf(row.lookupHmac, row.rowId.toString())
            )
            val result = db.insertWithOnConflict(
                validTable,
                null,
                row.toContentValues(),
                SQLiteDatabase.CONFLICT_REPLACE
            )
            check(result != -1L) { "Failed to upsert encrypted row into '$validTable'" }
        }
    }

    override fun findByLookupHmac(tableName: String, lookupHmac: String): RawEncryptedRow? {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        val db = readableDatabase
        return db.query(
            validTable,
            ROW_COLUMNS,
            "${EncryptedTableSchema.COL_LOOKUP_HMAC} = ?",
            arrayOf(lookupHmac),
            null,
            null,
            "${EncryptedTableSchema.COL_ROW_ID} DESC",
            "1"
        ).use { cursor ->
            if (cursor.moveToFirst()) cursor.toRawEncryptedRow() else null
        }
    }

    override fun findByRowId(tableName: String, rowId: Long): RawEncryptedRow? {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        val db = readableDatabase
        return db.query(
            validTable,
            ROW_COLUMNS,
            "${EncryptedTableSchema.COL_ROW_ID} = ?",
            arrayOf(rowId.toString()),
            null,
            null,
            null,
            "1"
        ).use { cursor ->
            if (cursor.moveToFirst()) cursor.toRawEncryptedRow() else null
        }
    }

    override fun listRows(tableName: String): List<RawEncryptedRow> {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        val db = readableDatabase
        val rows = ArrayList<RawEncryptedRow>()
        db.query(
            validTable,
            ROW_COLUMNS,
            null,
            null,
            null,
            null,
            "${EncryptedTableSchema.COL_ROW_ID} ASC"
        ).use { cursor ->
            while (cursor.moveToNext()) {
                rows.add(cursor.toRawEncryptedRow())
            }
        }
        return rows
    }

    override fun listRecent(tableName: String, limit: Int): List<RawEncryptedRow> {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        if (limit <= 0) return emptyList()
        val db = readableDatabase
        val rows = ArrayList<RawEncryptedRow>(minOf(limit, 128))
        db.query(
            validTable,
            ROW_COLUMNS,
            null,
            null,
            null,
            null,
            "${EncryptedTableSchema.COL_UPDATED_EPOCH_SEC} DESC, ${EncryptedTableSchema.COL_ROW_ID} DESC",
            limit.toString()
        ).use { cursor ->
            while (cursor.moveToNext()) {
                rows.add(cursor.toRawEncryptedRow())
            }
        }
        return rows
    }

    override fun listRecentByLookupHmac(
        tableName: String,
        lookupHmac: String,
        limit: Int
    ): List<RawEncryptedRow> {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        if (limit <= 0) return emptyList()
        val db = readableDatabase
        val rows = ArrayList<RawEncryptedRow>(minOf(limit, 128))
        db.query(
            validTable,
            ROW_COLUMNS,
            "${EncryptedTableSchema.COL_LOOKUP_HMAC} = ?",
            arrayOf(lookupHmac),
            null,
            null,
            "${EncryptedTableSchema.COL_UPDATED_EPOCH_SEC} DESC, ${EncryptedTableSchema.COL_ROW_ID} DESC",
            limit.toString()
        ).use { cursor ->
            while (cursor.moveToNext()) {
                rows.add(cursor.toRawEncryptedRow())
            }
        }
        return rows
    }

    override fun deleteByLookupHmac(tableName: String, lookupHmac: String): Boolean {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        val deleted = writableDatabase.delete(
            validTable,
            "${EncryptedTableSchema.COL_LOOKUP_HMAC} = ?",
            arrayOf(lookupHmac)
        )
        return deleted > 0
    }

    override fun deleteByRowId(tableName: String, rowId: Long): Boolean {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        val deleted = writableDatabase.delete(
            validTable,
            "${EncryptedTableSchema.COL_ROW_ID} = ?",
            arrayOf(rowId.toString())
        )
        return deleted > 0
    }

    override fun deleteOlderThanMaxCount(tableName: String, maxEntries: Int): Int {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        return withTransaction {
            val db = writableDatabase
            if (maxEntries <= 0) {
                return@withTransaction db.delete(validTable, "1", null)
            }
            val whereClause = "${EncryptedTableSchema.COL_ROW_ID} NOT IN (" +
                "SELECT ${EncryptedTableSchema.COL_ROW_ID} FROM $validTable " +
                "ORDER BY ${EncryptedTableSchema.COL_UPDATED_EPOCH_SEC} DESC, " +
                "${EncryptedTableSchema.COL_ROW_ID} DESC LIMIT ?)"
            db.delete(validTable, whereClause, arrayOf(maxEntries.toString()))
        }
    }

    override fun touchUpdatedEpochSec(
        tableName: String,
        rowId: Long,
        updatedEpochSec: Long
    ): Boolean {
        val validTable = EncryptedTableSchema.validateTableName(tableName)
        val values = ContentValues(1).apply {
            put(EncryptedTableSchema.COL_UPDATED_EPOCH_SEC, updatedEpochSec)
        }
        val updated = writableDatabase.update(
            validTable,
            values,
            "${EncryptedTableSchema.COL_ROW_ID} = ?",
            arrayOf(rowId.toString())
        )
        return updated > 0
    }

    override fun <T> withTransaction(block: () -> T): T {
        val db = writableDatabase
        db.beginTransaction()
        return try {
            val result = block()
            db.setTransactionSuccessful()
            result
        } finally {
            db.endTransaction()
        }
    }

    override fun close() {
        super.close()
    }

    private fun readCurrentSequence(db: SQLiteDatabase, validTable: String): Long {
        return db.query(
            EncryptedTableSchema.TABLE_ROW_SEQUENCES,
            arrayOf(EncryptedTableSchema.COL_SEQ_LAST_ROW_ID),
            "${EncryptedTableSchema.COL_SEQ_TABLE_NAME} = ?",
            arrayOf(validTable),
            null,
            null,
            null,
            "1"
        ).use { cursor ->
            if (cursor.moveToFirst()) cursor.getLong(0) else 0L
        }
    }

    private fun readMaxRowId(db: SQLiteDatabase, validTable: String): Long {
        return db.rawQuery(
            "SELECT COALESCE(MAX(${EncryptedTableSchema.COL_ROW_ID}), 0) FROM $validTable",
            null
        ).use { cursor ->
            if (cursor.moveToFirst()) cursor.getLong(0) else 0L
        }
    }

    private fun RawEncryptedRow.toContentValues(): ContentValues {
        return ContentValues(6).apply {
            put(EncryptedTableSchema.COL_ROW_ID, rowId)
            put(EncryptedTableSchema.COL_LOOKUP_HMAC, lookupHmac)
            put(EncryptedTableSchema.COL_SCHEMA_VERSION, schemaVersion)
            put(EncryptedTableSchema.COL_CREATED_EPOCH_SEC, createdEpochSec)
            put(EncryptedTableSchema.COL_UPDATED_EPOCH_SEC, updatedEpochSec)
            put(EncryptedTableSchema.COL_PAYLOAD_BLOB, payloadBlob)
        }
    }

    private fun Cursor.toRawEncryptedRow(): RawEncryptedRow {
        return RawEncryptedRow(
            rowId = getLong(0),
            lookupHmac = getString(1),
            schemaVersion = getInt(2),
            createdEpochSec = getLong(3),
            updatedEpochSec = getLong(4),
            payloadBlob = getBlob(5)
        )
    }

    companion object {
        private val ROW_COLUMNS: Array<String> = arrayOf(
            EncryptedTableSchema.COL_ROW_ID,
            EncryptedTableSchema.COL_LOOKUP_HMAC,
            EncryptedTableSchema.COL_SCHEMA_VERSION,
            EncryptedTableSchema.COL_CREATED_EPOCH_SEC,
            EncryptedTableSchema.COL_UPDATED_EPOCH_SEC,
            EncryptedTableSchema.COL_PAYLOAD_BLOB
        )
    }
}

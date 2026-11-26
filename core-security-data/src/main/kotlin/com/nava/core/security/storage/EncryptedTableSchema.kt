package com.nava.core.security.storage

/**
 * Canonical SQLite schema definitions for [EncryptedSqliteStore].
 *
 * Plaintext Metadata Minimization (PLAN.md Section 5.5):
 * Every user-facing table stores ONLY synthetic `row_id`, `lookup_hmac`, `schema_version`,
 * coarse timestamps (`created_epoch_sec`, `updated_epoch_sec`), and the AES-256-GCM encrypted
 * `payload_blob`. Zero plaintext user utterances, slots, notes, or audit details appear in
 * SQLite primitive columns.
 */
object EncryptedTableSchema {
    const val DATABASE_NAME: String = "nava_encrypted_store.db"
    const val DATABASE_VERSION: Int = 4

    const val TABLE_ACTION_CACHE: String = "action_cache"
    const val TABLE_AUTOMATION_RULES: String = "automation_rules"
    const val TABLE_PERMISSION_PROFILES: String = "permission_profiles"
    const val TABLE_PERMISSION_TARGET_BINDINGS: String = "permission_target_bindings"
    const val TABLE_AUDIT_LOGS: String = "audit_logs"
    const val TABLE_ENCRYPTED_NOTES: String = "encrypted_notes"
    const val TABLE_SCHEDULED_REMINDERS: String = "scheduled_reminders"
    const val TABLE_NOTIFICATION_WATCHERS: String = "notification_watchers"
    const val TABLE_PERSONAL_FACTS: String = "personal_facts"

    /** Internal monotonic row-ID allocator table (not exposed to caller allowlist). */
    internal const val TABLE_ROW_SEQUENCES: String = "nava_row_sequences"

    const val COL_ROW_ID: String = "row_id"
    const val COL_LOOKUP_HMAC: String = "lookup_hmac"
    const val COL_SCHEMA_VERSION: String = "schema_version"
    const val COL_CREATED_EPOCH_SEC: String = "created_epoch_sec"
    const val COL_UPDATED_EPOCH_SEC: String = "updated_epoch_sec"
    const val COL_PAYLOAD_BLOB: String = "payload_blob"

    internal const val COL_SEQ_TABLE_NAME: String = "table_name"
    internal const val COL_SEQ_LAST_ROW_ID: String = "last_row_id"

    /** Static allowlist of encrypted tables preventing SQL identifier injection. */
    val ALLOWED_TABLES: Set<String> = setOf(
        TABLE_ACTION_CACHE,
        TABLE_AUTOMATION_RULES,
        TABLE_PERMISSION_PROFILES,
        TABLE_PERMISSION_TARGET_BINDINGS,
        TABLE_AUDIT_LOGS,
        TABLE_ENCRYPTED_NOTES,
        TABLE_SCHEDULED_REMINDERS,
        TABLE_NOTIFICATION_WATCHERS,
        TABLE_PERSONAL_FACTS
    )

    /** Throws [IllegalArgumentException] if [tableName] is not in [ALLOWED_TABLES]. */
    fun validateTableName(tableName: String): String {
        require(tableName in ALLOWED_TABLES) {
            "Unknown or disallowed encrypted table '$tableName'"
        }
        return tableName
    }

    /** Returns DDL statements creating a single allowlisted encrypted table and its indexes. */
    fun createStatementsForTable(tableName: String): List<String> {
        val validTable = validateTableName(tableName)
        return listOf(
            """
            CREATE TABLE IF NOT EXISTS $validTable (
                $COL_ROW_ID INTEGER PRIMARY KEY NOT NULL,
                $COL_LOOKUP_HMAC TEXT NOT NULL,
                $COL_SCHEMA_VERSION INTEGER NOT NULL,
                $COL_CREATED_EPOCH_SEC INTEGER NOT NULL,
                $COL_UPDATED_EPOCH_SEC INTEGER NOT NULL,
                $COL_PAYLOAD_BLOB BLOB NOT NULL
            )
            """.trimIndent(),
            "CREATE INDEX IF NOT EXISTS idx_${validTable}_lookup_hmac ON $validTable($COL_LOOKUP_HMAC)",
            "CREATE INDEX IF NOT EXISTS idx_${validTable}_created_epoch ON $validTable($COL_CREATED_EPOCH_SEC)",
            "CREATE INDEX IF NOT EXISTS idx_${validTable}_updated_epoch ON $validTable($COL_UPDATED_EPOCH_SEC)"
        )
    }

    /** Returns all DDL statements creating the sequence table, encrypted tables, and indexes. */
    fun allCreateStatements(): List<String> {
        val statements = ArrayList<String>(1 + ALLOWED_TABLES.size * 4)
        statements.add(
            """
            CREATE TABLE IF NOT EXISTS $TABLE_ROW_SEQUENCES (
                $COL_SEQ_TABLE_NAME TEXT PRIMARY KEY NOT NULL,
                $COL_SEQ_LAST_ROW_ID INTEGER NOT NULL
            )
            """.trimIndent()
        )
        for (table in ALLOWED_TABLES.sorted()) {
            statements.addAll(createStatementsForTable(table))
        }
        return statements
    }
}

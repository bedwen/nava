package com.nava.core.security.dao

import com.nava.core.security.crypto.SecureMemory
import com.nava.core.security.storage.DecryptedRow
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.storage.StructuredPayloadCodec
import com.nava.domain.memory.PersonalFact
import com.nava.domain.memory.PersonalMemoryPort
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * AES-256-GCM encrypted DAO for [PersonalFact]s in [EncryptedTableSchema.TABLE_PERSONAL_FACTS].
 * Fact text lives only inside the row-bound-AAD `payload_blob`; SQLite columns hold the blind
 * index and coarse timestamps only (PLAN.md Section 5.5).
 */
class PersonalFactDao(
    private val store: EncryptedSqliteStore
) : PersonalMemoryPort {

    private val daoMutex = Mutex()

    override suspend fun saveFact(fact: PersonalFact) {
        require('\u0000' !in fact.factId) { "factId must not contain null characters" }
        daoMutex.withLock {
            val lookupHmac = store.computeBlindIndex(DOMAIN_FACT, fact.factId)
            val encoded = StructuredPayloadCodec.encode(formatVersion = FACT_SCHEMA_VERSION) {
                writeString(fact.factId)
                writeString(fact.text)
                writeLong(fact.createdAtEpochMs)
            }
            SecureMemory.withZeroizedBytes(encoded) { payload ->
                store.upsertEncryptedByBlindIndex(
                    tableName = EncryptedTableSchema.TABLE_PERSONAL_FACTS,
                    lookupHmac = lookupHmac,
                    plaintext = payload,
                    epochSec = (fact.createdAtEpochMs / 1000L).coerceAtLeast(1L),
                    schemaVersion = FACT_SCHEMA_VERSION
                )
            }
        }
    }

    override suspend fun listFacts(): List<PersonalFact> {
        val rows = store.listAllDecrypted(EncryptedTableSchema.TABLE_PERSONAL_FACTS)
        return try {
            rows.map(::decodeFact).sortedByDescending { it.createdAtEpochMs }
        } finally {
            for (row in rows) row.zeroize()
        }
    }

    override suspend fun deleteFact(factId: String): Boolean {
        if (factId.isBlank() || '\u0000' in factId) return false
        return daoMutex.withLock {
            store.deleteByBlindIndex(
                tableName = EncryptedTableSchema.TABLE_PERSONAL_FACTS,
                lookupHmac = store.computeBlindIndex(DOMAIN_FACT, factId)
            )
        }
    }

    private fun decodeFact(row: DecryptedRow): PersonalFact {
        return StructuredPayloadCodec.decode(bytes = row.plaintext, expectedVersion = FACT_SCHEMA_VERSION) {
            val id = readString()
            val text = readString()
            val created = readLong()
            PersonalFact(factId = id, text = text, createdAtEpochMs = created)
        }
    }

    companion object {
        private const val DOMAIN_FACT: String = "personal_fact"
        private const val FACT_SCHEMA_VERSION: Int = 1
    }
}

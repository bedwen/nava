package com.nava.core.ai.embedding

import com.nava.domain.ai.EmbeddingPort
import com.nava.domain.security.NoteSearchHit
import com.nava.domain.security.NoteSemanticRankerPort

/**
 * Semantic re-ranker over [NoteSearchHit] candidates backed by [EmbeddingPort] (EmbeddingGemma 2).
 *
 * Maintains a bounded 256-entry in-memory LRU cache of document embeddings keyed by
 * `"${note.noteId}:${note.updatedEpochSec}"`, never persisting any plaintext index to disk.
 */
class EmbeddingNoteSemanticRanker(
    private val embeddingPort: EmbeddingPort
) : NoteSemanticRankerPort {

    private val cacheLock = Any()
    private val docEmbeddingCache = object : LinkedHashMap<String, FloatArray>(
        MAX_CACHE_ENTRIES,
        0.75f,
        true
    ) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, FloatArray>?): Boolean {
            return size > MAX_CACHE_ENTRIES
        }
    }

    override suspend fun rerank(
        query: String,
        candidates: List<NoteSearchHit>,
        limit: Int
    ): List<NoteSearchHit> {
        if (limit <= 0 || candidates.isEmpty()) return emptyList()
        if (query.isBlank() || !embeddingPort.isEmbeddingModelAvailable()) {
            return candidates.take(limit)
        }

        val queryEmbedding = embeddingPort.embedQuery(query) ?: return candidates.take(limit)
        val maxBaseScore = candidates.maxOf { it.score.coerceAtLeast(0.0) }

        val rescored = ArrayList<NoteSearchHit>(candidates.size)
        for (hit in candidates) {
            val docEmbedding = getOrComputeDocEmbedding(hit)
            val semanticScore = if (docEmbedding != null) {
                EmbeddingPort.cosineSimilarity(queryEmbedding, docEmbedding)
                    .toDouble()
                    .coerceIn(0.0, 1.0)
            } else {
                0.0
            }

            val fusedScore = if (maxBaseScore > 0.0 && hit.score > 0.0) {
                val normalizedLexical = (hit.score / maxBaseScore).coerceIn(0.0, 1.0)
                LEXICAL_WEIGHT * normalizedLexical + SEMANTIC_WEIGHT * semanticScore
            } else if (maxBaseScore > 0.0) {
                SEMANTIC_WEIGHT * semanticScore
            } else {
                semanticScore
            }

            rescored.add(hit.copy(score = fusedScore))
        }

        return rescored
            .sortedWith(
                compareByDescending<NoteSearchHit> { it.score }
                    .thenByDescending { it.note.updatedEpochSec }
                    .thenBy { it.note.noteId }
            )
            .take(limit)
    }

    private suspend fun getOrComputeDocEmbedding(hit: NoteSearchHit): FloatArray? {
        val key = "${hit.note.noteId}:${hit.note.updatedEpochSec}"
        synchronized(cacheLock) {
            docEmbeddingCache[key]?.let { return it }
        }
        val computed = embeddingPort.embedDocument(hit.note.title, hit.note.body) ?: return null
        synchronized(cacheLock) {
            docEmbeddingCache[key] = computed
        }
        return computed
    }

    internal fun cacheSize(): Int = synchronized(cacheLock) { docEmbeddingCache.size }

    companion object {
        const val MAX_CACHE_ENTRIES: Int = 256
        private const val LEXICAL_WEIGHT: Double = 0.35
        private const val SEMANTIC_WEIGHT: Double = 0.65
    }
}

package com.nava.domain.ai

import kotlin.math.sqrt

/**
 * Pure Kotlin port for on-device text embedding inference (e.g., EmbeddingGemma 2 via LiteRT-LM).
 */
interface EmbeddingPort {
    suspend fun isEmbeddingModelAvailable(): Boolean

    suspend fun embedQuery(query: String): FloatArray?

    suspend fun embedDocument(title: String, text: String): FloatArray?

    suspend fun unloadEmbeddingModel()

    companion object {
        /**
         * Computes cosine similarity between [a] and [b] using a pure primitive loop with zero
         * heap boxing. Returns `0f` on empty vectors, length mismatch, zero norm, or non-finite values.
         */
        fun cosineSimilarity(a: FloatArray, b: FloatArray): Float {
            if (a.isEmpty() || a.size != b.size) return 0f
            var dot = 0.0
            var normA = 0.0
            var normB = 0.0
            var i = 0
            val len = a.size
            while (i < len) {
                val va = a[i].toDouble()
                val vb = b[i].toDouble()
                dot += va * vb
                normA += va * va
                normB += vb * vb
                i++
            }
            if (normA <= 0.0 || normB <= 0.0) return 0f
            val denom = sqrt(normA) * sqrt(normB)
            if (denom <= 0.0 || !dot.isFinite() || !denom.isFinite()) return 0f
            val sim = (dot / denom).toFloat()
            return if (sim.isFinite()) sim.coerceIn(-1f, 1f) else 0f
        }
    }
}

package com.nava.domain.memory

/**
 * A short fact the user explicitly asked Nava to remember (for example "My wife's name is Ayse"
 * or "I leave for work at 8:30").
 *
 * Security invariant: a fact is only ever created from a
 * [com.nava.domain.security.DataProvenance.USER_UTTERANCE] slot, so it may be shown to the
 * Stage 1 planner as user context. Text from notifications, files, or any other external source
 * must never become a fact.
 */
data class PersonalFact(
    val factId: String,
    val text: String,
    val createdAtEpochMs: Long
) {
    init {
        require(factId.isNotBlank()) { "factId must not be blank" }
        require(text.isNotBlank()) { "fact text must not be blank" }
        require(text.length <= MAX_FACT_CHARS) { "fact text must be at most $MAX_FACT_CHARS chars" }
    }

    companion object {
        const val MAX_FACT_CHARS: Int = 200
        const val MAX_FACTS: Int = 50
    }
}

/** Encrypted on-device store of [PersonalFact]s. */
interface PersonalMemoryPort {
    suspend fun saveFact(fact: PersonalFact)
    suspend fun listFacts(): List<PersonalFact>
    suspend fun deleteFact(factId: String): Boolean
}

/**
 * Selects the bounded set of facts shown to the planner: newest first, capped by count and
 * total characters so memory can never crowd out the user's actual request.
 */
object PersonalFactContext {
    const val MAX_CONTEXT_FACTS: Int = 12
    const val MAX_CONTEXT_CHARS: Int = 600

    fun select(facts: List<PersonalFact>): List<String> {
        val selected = ArrayList<String>()
        var used = 0
        for (fact in facts.sortedByDescending { it.createdAtEpochMs }) {
            if (selected.size >= MAX_CONTEXT_FACTS) break
            val text = fact.text.trim()
            if (text.isEmpty()) continue
            if (used + text.length > MAX_CONTEXT_CHARS) break
            selected.add(text)
            used += text.length
        }
        return selected
    }
}

package com.nava.domain.ai

import com.nava.domain.locale.DetectedLanguage
import com.nava.domain.locale.NormalizedText
import com.nava.domain.security.DataProvenance

/**
 * Single trusted user/assistant turn retained in the active foreground session for
 * multi-turn follow-up resolution. Must never contain untrusted external payloads.
 */
data class ConversationTurn(
    val userUtterance: String,
    val assistantReply: String
)

/**
 * Stage 1 intent-resolution request originating strictly from trusted user commands.
 */
data class IntentRequest(
    val requestId: String,
    val rawUtterance: String,
    val normalizedText: NormalizedText? = null,
    val languageHint: DetectedLanguage? = null,
    val provenance: DataProvenance = DataProvenance.USER_UTTERANCE,
    val issuedAtEpochMs: Long,
    val targetContextId: String = "default",
    val conversationHistory: List<ConversationTurn> = emptyList()
) {
    init {
        require(requestId.isNotBlank()) { "IntentRequest requestId must not be blank" }
        require(targetContextId.isNotBlank()) { "IntentRequest targetContextId must not be blank" }
        if (provenance != DataProvenance.USER_UTTERANCE) {
            throw SecurityException(
                "Stage 1 intent resolution requires USER_UTTERANCE provenance, got $provenance"
            )
        }
    }
}

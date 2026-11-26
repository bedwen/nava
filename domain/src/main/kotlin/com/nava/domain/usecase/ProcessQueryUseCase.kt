package com.nava.domain.usecase

import com.nava.domain.ai.ConversationTurn
import com.nava.domain.ai.IntentRequest
import com.nava.domain.ai.IntentResolver
import com.nava.domain.ai.ResolutionResult
import com.nava.domain.locale.GenericTextNormalizer
import com.nava.domain.locale.LanguageDetector
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.tool.ToolRegistry
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage

/**
 * Orchestrates Nava's 3-Tier Hybrid Router (Tier 1 Rule -> Tier 2 Cache -> Tier 3 Gemma 4)
 * using Chain-of-Responsibility and Open/Closed [ToolRegistry] discovery.
 */
class ProcessQueryUseCase(
    resolvers: List<IntentResolver>,
    private val toolRegistry: ToolRegistry,
    private val languageDetector: LanguageDetector,
    private val textNormalizer: GenericTextNormalizer = GenericTextNormalizer()
) {
    private val orderedResolvers: List<IntentResolver> = resolvers.sortedBy { it.tier.ordinal }

    suspend operator fun invoke(
        requestId: String,
        rawUtterance: String,
        appLocaleTag: String,
        targetContextId: String = "default",
        issuedAtEpochMs: Long,
        provenance: DataProvenance = DataProvenance.USER_UTTERANCE,
        conversationHistory: List<ConversationTurn> = emptyList()
    ): ResolutionResult {
        if (provenance != DataProvenance.USER_UTTERANCE) {
            throw SecurityException(
                "Stage 1 intent resolution requires USER_UTTERANCE provenance, got $provenance"
            )
        }

        val sanitizedUtterance = Gemma4InputSanitizer.sanitize(rawUtterance).trim()
        if (sanitizedUtterance.isEmpty()) {
            return ResolutionResult.ClarificationNeeded(
                UserMessage(MessageKey.ERROR_CLARIFICATION_NEEDED)
            )
        }

        val sanitizedHistory = if (conversationHistory.isEmpty()) {
            emptyList()
        } else {
            conversationHistory.mapNotNull { turn ->
                val userText = Gemma4InputSanitizer.sanitize(turn.userUtterance).trim()
                val assistantText = Gemma4InputSanitizer.sanitize(turn.assistantReply).trim()
                if (userText.isNotEmpty() && assistantText.isNotEmpty()) {
                    ConversationTurn(userUtterance = userText, assistantReply = assistantText)
                } else {
                    null
                }
            }
        }

        val detectedLanguage = languageDetector.detect(sanitizedUtterance, appLocaleTag)
        val normalizedText = textNormalizer.normalize(sanitizedUtterance, detectedLanguage.bcp47Tag)

        val request = IntentRequest(
            requestId = requestId,
            rawUtterance = sanitizedUtterance,
            normalizedText = normalizedText,
            languageHint = detectedLanguage,
            provenance = provenance,
            issuedAtEpochMs = issuedAtEpochMs,
            targetContextId = targetContextId,
            conversationHistory = sanitizedHistory
        )

        val availableTools = toolRegistry.allMetadata()
        for (resolver in orderedResolvers) {
            val result = resolver.resolve(request, availableTools)
            if (result !is ResolutionResult.NoMatch) {
                return result
            }
        }

        return ResolutionResult.ClarificationNeeded(
            UserMessage(MessageKey.ERROR_CLARIFICATION_NEEDED)
        )
    }
}

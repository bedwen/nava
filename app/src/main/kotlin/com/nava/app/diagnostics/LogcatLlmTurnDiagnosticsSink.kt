package com.nava.app.diagnostics

import android.util.Log
import com.nava.core.ai.diagnostics.LlmTurnDiagnosticRecord
import com.nava.core.ai.diagnostics.LlmTurnDiagnosticsSink
import com.nava.domain.ai.ResolutionResult

/**
 * Developer-only Logcat sink for Tier 3 Gemma turn diagnostics and router tier outcomes.
 *
 * SECURITY: records contain raw user utterances and raw model output. `AppContainer` wires this
 * sink ONLY when the application is debuggable (`ApplicationInfo.FLAG_DEBUGGABLE`); release
 * builds never instantiate it. Nothing is persisted to disk or sent off-device.
 *
 * Inspect with: `adb logcat -s NavaLlmDiag`
 */
class LogcatLlmTurnDiagnosticsSink : LlmTurnDiagnosticsSink {

    override fun onTurn(record: LlmTurnDiagnosticRecord) {
        runCatching {
            val text = buildString {
                append("===== TIER3 TURN ").append(record.requestId).append(" =====\n")
                append("outcome=").append(record.outcome)
                append(" detail=").append(record.detail).append('\n')
                append("lang=").append(record.languageTag)
                append(" thought=").append(record.allowThoughtMode)
                append(" historyTurns=").append(record.historyTurnCount)
                append(" engineMs=").append(record.engineDurationMs)
                append(" totalMs=").append(record.totalDurationMs).append('\n')
                append("prunedTools=").append(record.prunedToolNames.joinToString(",")).append('\n')
                append("utterance=").append(record.userUtterance).append('\n')
                append("--- prompt payload (segments B+C) ---\n")
                append(record.promptPayload).append('\n')
                append("--- raw model output ---\n")
                append(record.rawOutput).append('\n')
                append("===== END ").append(record.requestId).append(" =====")
            }
            logChunked(text)
        }
    }

    /**
     * Logs which router tier produced [result] so Tier 1 rule and Tier 2 cache hits are visible
     * alongside Tier 3 turns.
     */
    fun onResolution(requestId: String, utterance: String, result: ResolutionResult) {
        runCatching {
            val summary = when (result) {
                is ResolutionResult.ResolvedPlan ->
                    "ResolvedPlan tier=${result.tier} calls=" +
                        result.plan.calls.joinToString(",") { it.toolName }

                is ResolutionResult.ConversationalReply ->
                    "ConversationalReply tier=${result.tier}"

                is ResolutionResult.ClarificationNeeded ->
                    "ClarificationNeeded key=${result.message.key}"

                ResolutionResult.NoMatch -> "NoMatch"
            }
            Log.d(TAG, "ROUTER $requestId utterance=\"$utterance\" -> $summary")
        }
    }

    private fun logChunked(text: String) {
        var start = 0
        while (start < text.length) {
            val end = minOf(text.length, start + MAX_LOG_CHUNK_CHARS)
            Log.d(TAG, text.substring(start, end))
            start = end
        }
    }

    private companion object {
        const val TAG: String = "NavaLlmDiag"
        const val MAX_LOG_CHUNK_CHARS: Int = 3500
    }
}

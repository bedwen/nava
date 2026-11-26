package com.nava.core.ai.diagnostics

/**
 * Terminal outcome of a single Tier 3 Gemma resolution turn, recorded for developer diagnostics.
 */
enum class LlmTurnOutcome {
    /** Thermal, battery, or RAM gate refused to run the model. */
    THERMAL_GATE_REFUSED,

    /** The inference engine threw before producing a usable output. */
    ENGINE_FAILURE,

    /** The bounded thought channel exceeded its budget or was left unclosed. */
    THOUGHT_BUDGET_EXCEEDED,

    /** The raw model output could not be parsed by `MicroDslParser`. */
    PARSE_ERROR,

    /** The model called a tool outside the pruned subset. */
    REJECTED_UNKNOWN_TOOL,

    /** The model called a pruned tool with schema-invalid or missing arguments. */
    REJECTED_SCHEMA_INVALID,

    /** A schema-valid plan was produced and a capability token was minted. */
    RESOLVED_PLAN,

    /** The model replied conversationally without a tool call. */
    DIRECT_REPLY
}

/**
 * Immutable developer-diagnostics snapshot of one Tier 3 turn.
 *
 * Contains raw user text and raw model output, so sinks MUST only be wired in debuggable builds
 * and MUST NEVER persist records to disk or transmit them off-device.
 */
data class LlmTurnDiagnosticRecord(
    val requestId: String,
    val languageTag: String,
    val userUtterance: String,
    val historyTurnCount: Int,
    val prunedToolNames: List<String>,
    val allowThoughtMode: Boolean,
    val promptPayload: String,
    val rawOutput: String,
    val outcome: LlmTurnOutcome,
    val detail: String,
    val engineDurationMs: Long,
    val totalDurationMs: Long
)

/**
 * Optional observer receiving one [LlmTurnDiagnosticRecord] per Tier 3 turn.
 *
 * Implementations must be non-blocking and must never throw; `GemmaIntentResolver` additionally
 * isolates sink failures so diagnostics can never alter resolution results.
 */
fun interface LlmTurnDiagnosticsSink {
    fun onTurn(record: LlmTurnDiagnosticRecord)
}

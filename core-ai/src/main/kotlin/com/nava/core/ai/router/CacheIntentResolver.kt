package com.nava.core.ai.router

import com.nava.core.ai.json.JsonValue
import com.nava.core.ai.json.SimpleJsonParser
import com.nava.core.ai.parser.MicroDslParser
import com.nava.domain.ai.ActionCachePort
import com.nava.domain.ai.CachedActionTemplate
import com.nava.domain.ai.IntentRequest
import com.nava.domain.ai.IntentResolver
import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.ResolutionResult
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.locale.GenericTextNormalizer
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.security.Tainted
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolSchemaField
import java.time.LocalDate
import java.util.Locale
import java.util.UUID

/**
 * Tier 2 deterministic IntentResolver (`< 5 ms`, zero embeddings) performing exact normalized
 * skeleton replay via [ActionCachePort] (PLAN.md Section 3.1).
 *
 * Security invariants:
 * - Never caches `CapabilityToken`s; every replay mints a fresh token via [SecurityFirewallPort].
 * - Strict admission gate in [admitPlan]: admits plans ONLY if user-approved, not touching Vault,
 *   and 100% of slot arguments originate from [DataProvenance.USER_UTTERANCE] without `vault:` labels.
 * - Automatically invalidates stale templates when a tool's `schemaVersion` changes.
 */
class CacheIntentResolver(
    private val actionCachePort: ActionCachePort,
    private val securityFirewall: SecurityFirewallPort,
    private val textNormalizer: GenericTextNormalizer = GenericTextNormalizer(),
    private val skeletonNormalizer: SkeletonNormalizer = SkeletonNormalizer(),
    private val planIdGenerator: () -> String = { UUID.randomUUID().toString() }
) : IntentResolver {

    override val tier: ResolutionTier = ResolutionTier.TIER_2_CACHE

    override suspend fun resolve(
        request: IntentRequest,
        availableTools: List<ToolMetadata>
    ): ResolutionResult {
        if (request.provenance != DataProvenance.USER_UTTERANCE) {
            throw SecurityException(
                "Tier 2 CacheIntentResolver requires USER_UTTERANCE provenance, got ${request.provenance}"
            )
        }
        if (availableTools.isEmpty()) return ResolutionResult.NoMatch
        if (request.rawUtterance.length > MAX_CACHE_INPUT_CHARS) return ResolutionResult.NoMatch
        val preNormalizedLen = request.normalizedText?.matchKey?.length ?: 0
        if (preNormalizedLen > MAX_CACHE_INPUT_CHARS) return ResolutionResult.NoMatch

        val lang = resolveValidatedLanguageTag(request) ?: return ResolutionResult.NoMatch
        val normalized = request.normalizedText
            ?: textNormalizer.normalize(request.rawUtterance, lang)
        if (normalized.matchKey.length > MAX_CACHE_INPUT_CHARS) return ResolutionResult.NoMatch
        val skeleton = skeletonNormalizer.normalize(normalized.matchKey, request.rawUtterance)
        if (skeleton.canonicalSkeleton.isBlank() || '\u0000' in skeleton.canonicalSkeleton) {
            return ResolutionResult.NoMatch
        }

        val nowEpochSec = request.issuedAtEpochMs / 1000L
        val cachedTemplate = actionCachePort.findTemplate(
            languageCode = lang,
            canonicalSkeleton = skeleton.canonicalSkeleton,
            nowEpochSec = nowEpochSec
        ) ?: return ResolutionResult.NoMatch

        val toolsByName = availableTools.associateBy { it.name }
        val declaredTemplateTools = cachedTemplate.toolNames.toSet()
        for (toolName in declaredTemplateTools) {
            val tool = toolsByName[toolName] ?: return ResolutionResult.NoMatch
            val cachedVersion = cachedTemplate.toolSchemaVersions[toolName]
            if (cachedVersion == null || cachedVersion != tool.schemaVersion) {
                actionCachePort.invalidateForToolSchemaChange(tool.name, tool.schemaVersion)
                return ResolutionResult.NoMatch
            }
        }

        val replayedCalls = deserializeAndRebindTemplate(
            serializedTemplate = cachedTemplate.serializedPlanTemplate,
            allowedToolNames = declaredTemplateTools,
            placeholders = skeleton.placeholders,
            toolsByName = toolsByName,
            defaultTargetId = request.targetContextId
        ) ?: return ResolutionResult.NoMatch

        val candidateTools = replayedCalls.map { it.toolName }.toSet()
        val freshToken = securityFirewall.mintToken(
            requestId = request.requestId,
            utteranceProvenance = request.provenance,
            candidateTools = candidateTools,
            nowEpochMs = request.issuedAtEpochMs
        )

        val plan = PlanAst(
            planId = planIdGenerator(),
            calls = replayedCalls,
            skeletonKey = skeleton.canonicalSkeleton
        )
        return ResolutionResult.ResolvedPlan(
            tier = ResolutionTier.TIER_2_CACHE,
            plan = plan,
            capabilityToken = freshToken,
            skeletonUsed = skeleton.canonicalSkeleton
        )
    }

    /**
     * Admits a confirmed Tier 3 [plan] into Tier 2 parameterized template cache strictly enforcing
     * PLAN.md Section 3.1:
     * - Must be [userApproved] == `true`.
     * - Must have [touchesVault] == `false`.
     * - 100% of slot values across all calls must have `provenance == DataProvenance.USER_UTTERANCE`
     *   and must NOT carry a `vault:` source label.
     * - Never persists any `CapabilityToken`.
     */
    suspend fun admitPlan(
        request: IntentRequest,
        plan: PlanAst,
        availableTools: List<ToolMetadata>,
        userApproved: Boolean,
        touchesVault: Boolean,
        nowEpochSec: Long
    ): Boolean {
        if (!userApproved || touchesVault) return false
        if (request.provenance != DataProvenance.USER_UTTERANCE) return false
        if (request.rawUtterance.length > MAX_CACHE_INPUT_CHARS) return false
        if ((request.normalizedText?.matchKey?.length ?: 0) > MAX_CACHE_INPUT_CHARS) return false
        if (request.targetContextId.trim().startsWith(VAULT_SOURCE_PREFIX, ignoreCase = true)) return false
        if (plan.calls.size > MicroDslParser.MAX_CALLS_PER_PLAN) return false

        val lang = resolveValidatedLanguageTag(request) ?: return false

        val toolsByName = availableTools.associateBy { it.name }
        val toolNames = ArrayList<String>(plan.calls.size)
        val schemaVersions = LinkedHashMap<String, Int>()

        for (call in plan.calls) {
            val metadata = toolsByName[call.toolName] ?: return false
            if (call.targetId?.trim()?.startsWith(VAULT_SOURCE_PREFIX, ignoreCase = true) == true) {
                return false
            }
            toolNames.add(call.toolName)
            schemaVersions[call.toolName] = metadata.schemaVersion

            for (taintedArg in call.arguments.values) {
                if (taintedArg.provenance != DataProvenance.USER_UTTERANCE) {
                    return false
                }
                if (taintedArg.sourceLabel?.trim()?.startsWith(VAULT_SOURCE_PREFIX, ignoreCase = true) == true) {
                    return false
                }
            }
        }

        val normalized = request.normalizedText
            ?: textNormalizer.normalize(request.rawUtterance, lang)
        if (normalized.matchKey.length > MAX_CACHE_INPUT_CHARS) return false
        val skeleton = skeletonNormalizer.normalize(normalized.matchKey, request.rawUtterance)
        if (skeleton.canonicalSkeleton.isBlank() || '\u0000' in skeleton.canonicalSkeleton) return false

        val userLocale = Locale.forLanguageTag(lang)
        val serializedTemplate = serializeParameterizedPlan(
            plan = plan,
            placeholders = skeleton.placeholders,
            toolsByName = toolsByName,
            requestTargetContextId = request.targetContextId,
            userLocale = userLocale
        ) ?: return false

        val template = CachedActionTemplate(
            languageCode = lang,
            canonicalSkeleton = skeleton.canonicalSkeleton,
            toolNames = toolNames,
            toolSchemaVersions = schemaVersions,
            serializedPlanTemplate = serializedTemplate,
            lastUsedEpochSec = nowEpochSec
        )

        return actionCachePort.putTemplate(
            template = template,
            provenance = DataProvenance.USER_UTTERANCE,
            touchesVault = false,
            nowEpochSec = nowEpochSec
        )
    }

    private fun serializeParameterizedPlan(
        plan: PlanAst,
        placeholders: Map<String, ExtractedPlaceholder>,
        toolsByName: Map<String, ToolMetadata>,
        requestTargetContextId: String,
        userLocale: Locale
    ): String? {
        val callNodes = ArrayList<JsonValue>(plan.calls.size)
        for (call in plan.calls) {
            val toolMeta = toolsByName[call.toolName] ?: return null
            val argEntries = LinkedHashMap<String, JsonValue>()
            for ((argName, taintedVal) in call.arguments) {
                val field = toolMeta.fieldByName(argName) ?: return null
                val encoded = encodeArgValue(
                    value = taintedVal.value,
                    field = field,
                    placeholders = placeholders,
                    userLocale = userLocale
                ) ?: return null
                argEntries[argName] = encoded
            }
            val callObj = LinkedHashMap<String, JsonValue>()
            callObj["toolName"] = JsonValue.JsonString(call.toolName)
            callObj["orderIndex"] = JsonValue.JsonNumber(call.orderIndex.toString())
            // Omit default/request-bound targetId so replays bind to the caller's active targetContextId.
            val explicitTargetId = call.targetId
            if (explicitTargetId != null && explicitTargetId != requestTargetContextId) {
                callObj["targetId"] = JsonValue.JsonString(explicitTargetId)
            }
            callObj["args"] = JsonValue.JsonObject(argEntries)
            callNodes.add(JsonValue.JsonObject(callObj))
        }

        val root = LinkedHashMap<String, JsonValue>()
        root["version"] = JsonValue.JsonNumber(TEMPLATE_SCHEMA_VERSION.toString())
        root["calls"] = JsonValue.JsonArray(callNodes)
        return SimpleJsonParser.stringify(JsonValue.JsonObject(root))
    }

    private fun encodeArgValue(
        value: SlotValueAst,
        field: ToolSchemaField,
        placeholders: Map<String, ExtractedPlaceholder>,
        userLocale: Locale
    ): JsonValue? {
        val isTemporalField = field.valueType == SlotValueType.ISO_DATE ||
            field.valueType == SlotValueType.ISO_DATETIME ||
            field.valueType == SlotValueType.ISO_TIME

        return when (value) {
            is SlotValueAst.StringValue -> {
                if (isTemporalField) {
                    val temporalPlaceholder = findMatchingTemporalPlaceholder(
                        value = value.value,
                        valueType = field.valueType,
                        placeholders = placeholders
                    ) ?: return null
                    placeholderNode(temporalPlaceholder.token, multiplier = null)
                } else {
                    val matchingPlaceholder = findMatchingStringPlaceholder(
                        value = value.value,
                        placeholders = placeholders,
                        userLocale = userLocale
                    )
                    if (matchingPlaceholder != null) {
                        placeholderNode(matchingPlaceholder.token, multiplier = null)
                    } else {
                        JsonValue.JsonObject(
                            mapOf(
                                "type" to JsonValue.JsonString(TYPE_STRING),
                                "value" to JsonValue.JsonString(value.value)
                            )
                        )
                    }
                }
            }

            is SlotValueAst.IntValue -> {
                if (isTemporalField) return null
                val matched = findMatchingIntPlaceholder(value.value, placeholders)
                if (matched != null) {
                    placeholderNode(matched.first.token, multiplier = matched.second)
                } else {
                    JsonValue.JsonObject(
                        mapOf(
                            "type" to JsonValue.JsonString(TYPE_INT),
                            "value" to JsonValue.JsonNumber(value.value.toString())
                        )
                    )
                }
            }

            is SlotValueAst.BooleanValue -> {
                if (isTemporalField) return null
                JsonValue.JsonObject(
                    mapOf(
                        "type" to JsonValue.JsonString(TYPE_BOOL),
                        "value" to JsonValue.JsonBoolean(value.value)
                    )
                )
            }

            SlotValueAst.NullValue -> {
                if (isTemporalField && field.required) return null
                JsonValue.JsonObject(
                    mapOf("type" to JsonValue.JsonString(TYPE_NULL))
                )
            }
        }
    }

    private fun findMatchingTemporalPlaceholder(
        value: String,
        valueType: SlotValueType,
        placeholders: Map<String, ExtractedPlaceholder>
    ): ExtractedPlaceholder? {
        for (p in placeholders.values) {
            val kindMatches = when (valueType) {
                SlotValueType.ISO_DATE -> p.kind == PlaceholderKind.DATE
                SlotValueType.ISO_TIME -> p.kind == PlaceholderKind.TIME
                SlotValueType.ISO_DATETIME -> p.kind == PlaceholderKind.DATE || p.kind == PlaceholderKind.TIME
                else -> false
            }
            if (kindMatches && p.rawValue.equals(value, ignoreCase = true)) {
                return p
            }
        }
        return null
    }

    private fun placeholderNode(ref: String, multiplier: Long?): JsonValue.JsonObject {
        val entries = LinkedHashMap<String, JsonValue>()
        entries["type"] = JsonValue.JsonString(TYPE_PLACEHOLDER)
        entries["ref"] = JsonValue.JsonString(ref)
        if (multiplier != null && multiplier != 1L) {
            entries["multiplier"] = JsonValue.JsonNumber(multiplier.toString())
        }
        return JsonValue.JsonObject(entries)
    }

    private fun findMatchingStringPlaceholder(
        value: String,
        placeholders: Map<String, ExtractedPlaceholder>,
        userLocale: Locale
    ): ExtractedPlaceholder? {
        val loweredValue = value.lowercase(userLocale)
        for (p in placeholders.values) {
            when (p.kind) {
                PlaceholderKind.TIME,
                PlaceholderKind.DATE -> {
                    if (p.rawValue == value || p.rawValue.equals(value, ignoreCase = true)) return p
                }

                PlaceholderKind.STR -> {
                    if (p.rawValue == value ||
                        p.rawValue.equals(value, ignoreCase = true) ||
                        p.rawValue.lowercase(userLocale) == loweredValue
                    ) {
                        return p
                    }
                }

                PlaceholderKind.INT -> Unit
            }
        }
        return null
    }

    private fun findMatchingIntPlaceholder(
        value: Long,
        placeholders: Map<String, ExtractedPlaceholder>
    ): Pair<ExtractedPlaceholder, Long>? {
        for (p in placeholders.values) {
            if (p.kind != PlaceholderKind.INT) continue
            val parsed = p.rawValue.toLongOrNull() ?: continue
            if (parsed == value) return p to 1L
            if (parsed > 0L) {
                if (safeMultiply(parsed, 60L) == value) return p to 60L
                if (safeMultiply(parsed, 3600L) == value) return p to 3600L
            }
        }
        return null
    }

    private fun deserializeAndRebindTemplate(
        serializedTemplate: String,
        allowedToolNames: Set<String>,
        placeholders: Map<String, ExtractedPlaceholder>,
        toolsByName: Map<String, ToolMetadata>,
        defaultTargetId: String
    ): List<ToolCallAst>? {
        val root = runCatching { SimpleJsonParser.parse(serializedTemplate).asObject() }.getOrNull()
            ?: return null
        val version = runCatching { root["version"]?.asInt() }.getOrNull()
        if (version != TEMPLATE_SCHEMA_VERSION) return null

        val callArray = runCatching { root["calls"]?.asArray() }.getOrNull() ?: return null
        if (callArray.isEmpty() || callArray.size > MicroDslParser.MAX_CALLS_PER_PLAN) return null

        val resolvedCalls = ArrayList<ToolCallAst>(callArray.size)
        for (idx in callArray.indices) {
            val callObj = runCatching { callArray[idx].asObject() }.getOrNull() ?: return null
            val toolName = runCatching { callObj["toolName"]?.asString() }.getOrNull() ?: return null
            if (toolName !in allowedToolNames) return null
            val toolMeta = toolsByName[toolName] ?: return null
            val targetId = validateDeserializedTargetId(callObj["targetId"], defaultTargetId)
                ?: return null
            val argsObj = runCatching { callObj["args"]?.asObject() }.getOrNull() ?: return null

            val reboundArgs = LinkedHashMap<String, Tainted<SlotValueAst>>()
            for ((argName, rawArgNode) in argsObj) {
                val field = toolMeta.fieldByName(argName) ?: return null
                val boundValue = rebindArgNode(rawArgNode, field, placeholders) ?: return null
                reboundArgs[argName] = Tainted.fromUserUtterance(
                    value = boundValue,
                    slotKind = field.slotKind
                )
            }

            // Ensure all required schema fields are satisfied after placeholder substitution.
            for (field in toolMeta.fields) {
                if (field.required && field.name !in reboundArgs) {
                    return null
                }
            }

            resolvedCalls.add(
                ToolCallAst(
                    toolName = toolName,
                    arguments = reboundArgs,
                    orderIndex = idx,
                    targetId = targetId
                )
            )
        }

        return resolvedCalls
    }

    private fun rebindArgNode(
        node: JsonValue,
        field: ToolSchemaField,
        placeholders: Map<String, ExtractedPlaceholder>
    ): SlotValueAst? {
        val obj = runCatching { node.asObject() }.getOrNull() ?: return null
        val type = runCatching { obj["type"]?.asString() }.getOrNull() ?: return null

        return when (type) {
            TYPE_PLACEHOLDER -> {
                val ref = runCatching { obj["ref"]?.asString() }.getOrNull() ?: return null
                val placeholder = placeholders[ref] ?: return null
                val multiplier = runCatching { obj["multiplier"]?.asLong() }.getOrNull() ?: 1L
                coercePlaceholderToField(placeholder, multiplier, field)
            }

            TYPE_STRING -> {
                val raw = runCatching { obj["value"]?.asString() }.getOrNull() ?: return null
                coerceStringToField(raw, field)
            }

            TYPE_INT -> {
                val num = runCatching { obj["value"]?.asLong() }.getOrNull() ?: return null
                when (field.valueType) {
                    SlotValueType.INTEGER -> SlotValueAst.IntValue(num)
                    SlotValueType.DURATION_SECONDS -> if (num > 0L) SlotValueAst.IntValue(num) else null
                    else -> null
                }
            }

            TYPE_BOOL -> {
                val b = runCatching { obj["value"]?.asBoolean() }.getOrNull() ?: return null
                if (field.valueType == SlotValueType.BOOLEAN) SlotValueAst.BooleanValue(b) else null
            }

            TYPE_NULL -> {
                if (field.required) null else SlotValueAst.NullValue
            }

            else -> null
        }
    }

    private fun coercePlaceholderToField(
        placeholder: ExtractedPlaceholder,
        multiplier: Long,
        field: ToolSchemaField
    ): SlotValueAst? {
        return when (field.valueType) {
            SlotValueType.INTEGER -> {
                val base = placeholder.rawValue.toLongOrNull() ?: return null
                val scaled = safeMultiply(base, multiplier) ?: return null
                SlotValueAst.IntValue(scaled)
            }

            SlotValueType.DURATION_SECONDS -> {
                val base = placeholder.rawValue.toLongOrNull() ?: return null
                if (base <= 0L || multiplier <= 0L) return null
                val scaled = safeMultiply(base, multiplier) ?: return null
                SlotValueAst.IntValue(scaled)
            }

            SlotValueType.ISO_TIME -> {
                if (!CANONICAL_TIME_REGEX.matches(placeholder.rawValue)) return null
                SlotValueAst.StringValue(placeholder.rawValue)
            }

            SlotValueType.ISO_DATE -> {
                val valid = runCatching { LocalDate.parse(placeholder.rawValue).toString() }.getOrNull()
                    ?: return null
                SlotValueAst.StringValue(valid)
            }

            SlotValueType.STRING,
            SlotValueType.ISO_DATETIME -> coerceStringToField(placeholder.rawValue, field)

            SlotValueType.BOOLEAN -> null
        }
    }

    private fun coerceStringToField(raw: String, field: ToolSchemaField): SlotValueAst? {
        val sanitized = try {
            Gemma4InputSanitizer.sanitize(raw).trim()
        } catch (_: SecurityException) {
            return null
        }
        return when (field.valueType) {
            SlotValueType.ISO_TIME -> {
                if (CANONICAL_TIME_REGEX.matches(sanitized)) SlotValueAst.StringValue(sanitized) else null
            }

            SlotValueType.ISO_DATE -> {
                val valid = runCatching { LocalDate.parse(sanitized).toString() }.getOrNull()
                    ?: return null
                SlotValueAst.StringValue(valid)
            }

            SlotValueType.STRING,
            SlotValueType.ISO_DATETIME -> SlotValueAst.StringValue(sanitized)

            else -> null
        }
    }

    private fun validateDeserializedTargetId(
        rawTargetNode: JsonValue?,
        defaultTargetId: String
    ): String? {
        if (rawTargetNode == null || rawTargetNode is JsonValue.JsonNull) {
            return defaultTargetId
        }
        val rawTarget = runCatching { rawTargetNode.asString() }.getOrNull() ?: return null
        if ('\u0000' in rawTarget) return null
        val sanitized = try {
            Gemma4InputSanitizer.sanitize(rawTarget).trim()
        } catch (_: SecurityException) {
            return null
        }
        if (sanitized.isBlank() || sanitized != rawTarget) return null
        if (sanitized.startsWith(VAULT_SOURCE_PREFIX, ignoreCase = true)) return null
        return sanitized
    }

    private fun resolveValidatedLanguageTag(request: IntentRequest): String? {
        val raw = request.languageHint?.bcp47Tag
            ?: request.normalizedText?.languageTag
            ?: FALLBACK_LANGUAGE_TAG
        if ('\u0000' in raw) return null
        val normalizedTag = raw.trim().replace('_', '-').lowercase(Locale.US)
        if (normalizedTag.isEmpty() || '\u0000' in normalizedTag) return null
        if (!SAFE_BCP47_REGEX.matches(normalizedTag)) return null
        return normalizedTag
    }

    private fun safeMultiply(a: Long, b: Long): Long? {
        return try {
            Math.multiplyExact(a, b)
        } catch (_: ArithmeticException) {
            null
        }
    }

    companion object {
        const val MAX_CACHE_INPUT_CHARS: Int = 1024

        private const val TEMPLATE_SCHEMA_VERSION: Int = 1
        private const val TYPE_PLACEHOLDER: String = "placeholder"
        private const val TYPE_STRING: String = "string"
        private const val TYPE_INT: String = "int"
        private const val TYPE_BOOL: String = "bool"
        private const val TYPE_NULL: String = "null"
        private const val VAULT_SOURCE_PREFIX: String = "vault:"
        private const val FALLBACK_LANGUAGE_TAG: String = "en"

        private val SAFE_BCP47_REGEX: Regex = Regex("""^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$""")
        private val CANONICAL_TIME_REGEX: Regex = Regex("""^(?:[01]\d|2[0-3]):[0-5]\d$""")
    }
}

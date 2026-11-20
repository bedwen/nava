package com.nava.feature.automations.redteam

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.PermissionEvaluatorPort
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleGrantPort
import com.nava.domain.security.RuleTriggerSpec
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.common.AutomationIntentGateway
import com.nava.feature.automations.common.AutomationNotificationBridge
import com.nava.feature.automations.common.AutomationOutboundActions
import com.nava.feature.automations.common.CalendarEventDraft
import com.nava.feature.automations.common.CalendarEventPatch
import com.nava.feature.automations.common.CalendarEventRecord
import com.nava.feature.automations.common.CalendarGatewayResult
import com.nava.feature.automations.common.CalendarPlatformGateway
import com.nava.feature.automations.common.CompletionNotificationRequest
import com.nava.feature.automations.common.ForegroundNotificationSpec
import com.nava.feature.automations.common.InteractiveNotificationRequest
import com.nava.feature.automations.common.PlatformDispatchResult
import com.nava.feature.automations.common.SafDocumentEntry
import com.nava.feature.automations.common.SafGatewayResult
import com.nava.feature.automations.common.SafPlatformGateway
import java.text.Normalizer
import java.util.Locale

internal data class OutboundCheckRecord(
    val toolName: String,
    val action: String,
    val uriOrTarget: Tainted<String>
)

internal class RecordingAuditLog(
    var throwOnRecord: (() -> Throwable)? = null
) : AuditLogPort {
    val entries: MutableList<AuditLogEntry> = mutableListOf()

    override suspend fun record(entry: AuditLogEntry) {
        throwOnRecord?.invoke()?.let { throw it }
        entries.add(entry)
    }

    override suspend fun queryRecent(limit: Int): List<AuditLogEntry> = entries.takeLast(limit)
}

internal class RecordingIntentGateway(
    var callPhonePermissionGranted: Boolean = true,
    var dndAccessGranted: Boolean = true,
    var notificationListenerEnabled: Boolean = true,
    val launchablePackages: MutableMap<String, String> = mutableMapOf(
        "com.nava.safeapp" to "com.nava.safeapp",
        "Safe App" to "com.nava.safeapp"
    )
) : AutomationIntentGateway {
    val alarmDispatches: MutableList<String> = mutableListOf()
    val timerDispatches: MutableList<String> = mutableListOf()
    val smsDispatches: MutableList<Pair<String, String>> = mutableListOf()
    val dialDispatches: MutableList<String> = mutableListOf()
    val directCallDispatches: MutableList<String> = mutableListOf()
    val launchDispatches: MutableList<String> = mutableListOf()

    fun totalDispatchCount(): Int =
        alarmDispatches.size +
            timerDispatches.size +
            smsDispatches.size +
            dialDispatches.size +
            directCallDispatches.size +
            launchDispatches.size

    override fun hasRuntimePermission(permission: String): Boolean = callPhonePermissionGranted

    override fun isNotificationPolicyAccessGranted(): Boolean = dndAccessGranted

    override fun isNotificationListenerEnabled(): Boolean = notificationListenerEnabled

    override fun dispatchSetAlarm(
        hour: Int,
        minute: Int,
        label: String?,
        skipUi: Boolean
    ): PlatformDispatchResult {
        alarmDispatches.add("$hour:$minute:${label.orEmpty()}")
        return PlatformDispatchResult.Dispatched("alarm")
    }

    override fun dispatchSetTimer(
        durationSeconds: Int,
        label: String?,
        skipUi: Boolean
    ): PlatformDispatchResult {
        timerDispatches.add("$durationSeconds:${label.orEmpty()}")
        return PlatformDispatchResult.Dispatched("timer")
    }

    override fun dispatchSmsDraft(recipient: String, body: String): PlatformDispatchResult {
        smsDispatches.add(recipient to body)
        return PlatformDispatchResult.Dispatched("sms")
    }

    override fun dispatchDial(phoneNumber: String): PlatformDispatchResult {
        dialDispatches.add(phoneNumber)
        return PlatformDispatchResult.Dispatched("dial")
    }

    override fun dispatchDirectCall(phoneNumber: String): PlatformDispatchResult {
        directCallDispatches.add(phoneNumber)
        return PlatformDispatchResult.Dispatched("call")
    }

    override fun resolveLaunchablePackage(appNameOrPackage: String): String? {
        return launchablePackages[appNameOrPackage.trim()]
    }

    override fun dispatchLaunchApp(packageName: String): PlatformDispatchResult {
        launchDispatches.add(packageName)
        return PlatformDispatchResult.Dispatched(packageName)
    }
}

internal class RecordingCalendarGateway(
    val seededEvents: MutableList<CalendarEventRecord> = mutableListOf()
) : CalendarPlatformGateway {
    var queryCalls: Int = 0
    val createCalls: MutableList<CalendarEventDraft> = mutableListOf()
    val updateCalls: MutableList<Pair<Long, CalendarEventPatch>> = mutableListOf()
    val deleteCalls: MutableList<Long> = mutableListOf()

    fun totalWriteCalls(): Int = createCalls.size + updateCalls.size + deleteCalls.size

    override suspend fun queryEvents(
        startEpochMs: Long,
        endEpochMs: Long,
        limit: Int
    ): CalendarGatewayResult<List<CalendarEventRecord>> {
        queryCalls++
        return CalendarGatewayResult.Success(seededEvents.take(limit))
    }

    override suspend fun createEvent(draft: CalendarEventDraft): CalendarGatewayResult<Long> {
        createCalls.add(draft)
        return CalendarGatewayResult.Success(100L + createCalls.size)
    }

    override suspend fun updateEvent(
        eventId: Long,
        patch: CalendarEventPatch
    ): CalendarGatewayResult<Boolean> {
        updateCalls.add(eventId to patch)
        return CalendarGatewayResult.Success(true)
    }

    override suspend fun deleteEvent(eventId: Long): CalendarGatewayResult<Boolean> {
        deleteCalls.add(eventId)
        return CalendarGatewayResult.Success(true)
    }
}

internal class RecordingSafGateway : SafPlatformGateway {
    val grantedTrees: MutableMap<String, Boolean> = mutableMapOf()
    val documents: MutableMap<String, MutableMap<String, ByteArray>> = mutableMapOf()
    var listCalls: Int = 0
    val readCalls: MutableList<Pair<String, String>> = mutableListOf()
    val writeCalls: MutableList<Triple<String, String, ByteArray>> = mutableListOf()
    val deleteCalls: MutableList<Pair<String, String>> = mutableListOf()

    fun totalOperationCount(): Int = listCalls + readCalls.size + writeCalls.size + deleteCalls.size

    override fun hasPersistedGrant(treeUri: String, requireWrite: Boolean): Boolean {
        val writeGranted = grantedTrees[treeUri] ?: return false
        return !requireWrite || writeGranted
    }

    override fun listPersistedTreeUris(): Set<String> = grantedTrees.keys.toSet()

    override suspend fun listDocuments(treeUri: String): SafGatewayResult<List<SafDocumentEntry>> {
        listCalls++
        val files = documents[treeUri].orEmpty()
        val entries = files.map { (name, bytes) ->
            SafDocumentEntry(
                documentUri = "$treeUri/$name",
                displayName = name,
                mimeType = "text/plain",
                isDirectory = false,
                sizeBytes = bytes.size.toLong(),
                lastModifiedEpochMs = 1_700_000_000_000L
            )
        }
        return SafGatewayResult.Success(entries)
    }

    override suspend fun readDocument(
        treeUri: String,
        fileName: String,
        maxBytes: Int
    ): SafGatewayResult<ByteArray> {
        readCalls.add(treeUri to fileName)
        val bytes = documents[treeUri]?.get(fileName)
            ?: return SafGatewayResult.NotFound(fileName)
        return SafGatewayResult.Success(bytes.copyOf(minOf(bytes.size, maxBytes)))
    }

    override suspend fun writeDocument(
        treeUri: String,
        fileName: String,
        mimeType: String,
        content: ByteArray,
        overwrite: Boolean
    ): SafGatewayResult<SafDocumentEntry> {
        writeCalls.add(Triple(treeUri, fileName, content.copyOf()))
        documents.getOrPut(treeUri) { mutableMapOf() }[fileName] = content.copyOf()
        return SafGatewayResult.Success(
            SafDocumentEntry(
                documentUri = "$treeUri/$fileName",
                displayName = fileName,
                mimeType = mimeType,
                isDirectory = false,
                sizeBytes = content.size.toLong(),
                lastModifiedEpochMs = 1_700_000_000_000L
            )
        )
    }

    override suspend fun deleteDocument(
        treeUri: String,
        fileName: String
    ): SafGatewayResult<Boolean> {
        deleteCalls.add(treeUri to fileName)
        val removed = documents[treeUri]?.remove(fileName) != null
        return if (removed) SafGatewayResult.Success(true) else SafGatewayResult.NotFound(fileName)
    }
}

internal class RecordingNotificationBridge : AutomationNotificationBridge {
    val completionRequests: MutableList<CompletionNotificationRequest> = mutableListOf()
    val interactiveRequests: MutableList<InteractiveNotificationRequest> = mutableListOf()
    val cancelledIds: MutableList<Int> = mutableListOf()

    override fun postCompletionNotification(request: CompletionNotificationRequest) {
        completionRequests.add(request)
    }

    override fun postInteractiveConfirmationNotification(request: InteractiveNotificationRequest) {
        interactiveRequests.add(request)
    }

    override fun cancelNotification(notificationId: Int) {
        cancelledIds.add(notificationId)
    }

    override fun createForegroundNotificationSpec(
        taskId: String,
        message: UserMessage
    ): ForegroundNotificationSpec {
        return ForegroundNotificationSpec(
            notificationId = 9001,
            channelId = AutomationNotificationBridge.CHANNEL_FOREGROUND_TASK,
            taskId = taskId,
            message = message
        )
    }
}

internal class MapPermissionEvaluator(
    private val grants: MutableMap<Pair<String, AtomicCapability>, ConfirmationLevel> = mutableMapOf(),
    var throwForPackages: Set<String> = emptySet()
) : PermissionEvaluatorPort {
    fun grant(targetId: String, capability: AtomicCapability, level: ConfirmationLevel) {
        grants[targetId to capability] = level
    }

    override suspend fun getProfileForTarget(targetId: String): PermissionProfile =
        PermissionProfile.defaultDeny()

    override suspend fun evaluateCapability(
        targetId: String,
        capability: AtomicCapability
    ): ConfirmationLevel {
        if (targetId in throwForPackages) {
            throw IllegalStateException("Simulated evaluator fault for $targetId")
        }
        return grants[targetId to capability] ?: ConfirmationLevel.DISABLED
    }

    override suspend fun listProfiles(): List<PermissionProfile> = emptyList()

    override suspend fun saveProfile(profile: PermissionProfile) = Unit

    override suspend fun assignTargetToProfile(targetId: String, profileId: String) = Unit

    override suspend fun deleteProfile(profileId: String) = Unit
}

internal class InMemoryRuleGrantStore : RuleGrantPort {
    val rules: MutableMap<String, RuleCapabilityGrant> = mutableMapOf()

    fun saveRule(grant: RuleCapabilityGrant) {
        rules[grant.ruleId] = grant
    }

    override suspend fun createPendingRule(
        ruleId: String,
        triggerSpec: RuleTriggerSpec,
        staticActions: List<RuleActionSpec>,
        nowEpochSec: Long
    ): RuleCapabilityGrant {
        val grant = RuleCapabilityGrant(
            grantId = "grant_$ruleId",
            ruleId = ruleId,
            triggerSpec = triggerSpec,
            staticActions = staticActions,
            approvalState = RuleApprovalState.PENDING_USER_APPROVAL,
            sealHmacHex = "",
            grantedAtEpochSec = nowEpochSec
        )
        rules[ruleId] = grant
        return grant
    }

    override suspend fun approveAndSealRule(ruleId: String, nowEpochSec: Long): RuleCapabilityGrant {
        val existing = rules[ruleId] ?: error("Rule not found: $ruleId")
        val approved = existing.copy(
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "sealed_$ruleId",
            grantedAtEpochSec = nowEpochSec
        )
        rules[ruleId] = approved
        return approved
    }

    override suspend fun pauseRule(ruleId: String, nowEpochSec: Long) {
        val existing = rules[ruleId] ?: return
        rules[ruleId] = existing.copy(approvalState = RuleApprovalState.PAUSED)
    }

    override suspend fun revokeRule(ruleId: String, nowEpochSec: Long) {
        val existing = rules[ruleId] ?: return
        rules[ruleId] = existing.copy(approvalState = RuleApprovalState.REVOKED)
    }

    override suspend fun findRule(ruleId: String): RuleCapabilityGrant? = rules[ruleId]

    override suspend fun listRules(): List<RuleCapabilityGrant> = rules.values.toList()
}

/**
 * Policy-faithful SecurityFirewallPort test double enforcing OutboundChannelPolicy semantics,
 * taint escalation, and configurable forced decisions for Gate 2 red-team verification.
 */
internal class StrictRedTeamFirewall(
    var forcedOutboundDecision: FirewallDecision? = null,
    var forcedToolCallDecision: FirewallDecision? = null,
    var forcedRuleDecision: FirewallDecision? = null,
    var permissiveOutbound: Boolean = false
) : SecurityFirewallPort {
    val outboundChecks: MutableList<OutboundCheckRecord> = mutableListOf()
    val toolCallChecks: MutableList<ToolCallAst> = mutableListOf()
    val ruleChecks: MutableList<RuleCapabilityGrant> = mutableListOf()

    override suspend fun mintToken(
        requestId: String,
        utteranceProvenance: DataProvenance,
        candidateTools: Set<String>,
        nowEpochMs: Long
    ): CapabilityToken {
        if (utteranceProvenance != DataProvenance.USER_UTTERANCE) {
            throw SecurityException("Minting denied for provenance $utteranceProvenance")
        }
        return CapabilityToken.mint(
            tokenId = "rt_tok_$requestId",
            requestId = requestId,
            allowedTools = candidateTools,
            mintProvenance = utteranceProvenance,
            issuedAtEpochMs = nowEpochMs
        )
    }

    override suspend fun authorizeToolCall(
        token: CapabilityToken,
        toolCall: ToolCallAst,
        toolMetadata: ToolMetadata,
        targetId: String,
        nowEpochMs: Long
    ): FirewallDecision {
        toolCallChecks.add(toolCall)
        forcedToolCallDecision?.let { return it }
        token.assertValidFor(toolCall.toolName, nowEpochMs)
        val untrustedHighRisk = toolCall.arguments.entries
            .filter { (k, v) -> v.requiresExplicitConfirmation || (v.isUntrusted && toolMetadata.fieldByName(k)?.slotKind?.isHighRisk == true) }
            .map { it.key }
            .toSet()
        if (untrustedHighRisk.isNotEmpty()) {
            return FirewallDecision.RequiresConfirmation(
                message = UserMessage(
                    key = MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE,
                    args = listOf(MessageArg.ProvenanceBadge(DataProvenance.UNTRUSTED_EXTERNAL))
                ),
                untrustedHighRiskSlots = untrustedHighRisk
            )
        }
        return FirewallDecision.Authorized
    }

    override suspend fun authorizeRuleExecution(grant: RuleCapabilityGrant): FirewallDecision {
        ruleChecks.add(grant)
        forcedRuleDecision?.let { return it }
        if (grant.approvalState != RuleApprovalState.APPROVED_ACTIVE) {
            return FirewallDecision.Denied(
                message = UserMessage(MessageKey.ERROR_SECURITY_VIOLATION, listOf(MessageArg.Text("RULE_NOT_APPROVED"))),
                reasonCode = "RULE_NOT_APPROVED"
            )
        }
        if (grant.sealHmacHex.isBlank() || grant.sealHmacHex.startsWith("TAMPERED")) {
            return FirewallDecision.Denied(
                message = UserMessage(MessageKey.ERROR_SECURITY_VIOLATION, listOf(MessageArg.Text("RULE_SEAL_INVALID"))),
                reasonCode = "RULE_SEAL_INVALID"
            )
        }
        if (grant.staticActions.any { it.requiresBiometric || it.toolName.contains("vault", ignoreCase = true) }) {
            return FirewallDecision.RequiresBiometric(
                message = UserMessage(MessageKey.ACTION_BIOMETRIC_REQUIRED, listOf(MessageArg.Text(grant.ruleId)))
            )
        }
        if (grant.requiresInteractiveUpgrade) {
            return FirewallDecision.RequiresConfirmation(
                message = UserMessage(MessageKey.ACTION_CONFIRMATION_REQUIRED, listOf(MessageArg.Text(grant.ruleId)))
            )
        }
        return FirewallDecision.Authorized
    }

    override suspend fun validateOutboundTarget(
        toolName: String,
        action: String,
        uriOrTarget: Tainted<String>
    ): FirewallDecision {
        outboundChecks.add(OutboundCheckRecord(toolName, action, uriOrTarget))
        forcedOutboundDecision?.let { return it }
        if (permissiveOutbound) {
            return FirewallDecision.Authorized
        }

        val normalizedAction = normalize(action)
        val raw = uriOrTarget.value
        val normalizedTarget = normalize(raw)
        val lower = normalizedTarget.lowercase(Locale.ROOT)
        val compact = lower.filterNot { it.isWhitespace() }

        if (normalizedAction !in ALLOWED_ACTIONS) {
            return denied("OUTBOUND_ACTION_BLOCKED")
        }
        if ('\r' in raw || '\n' in raw || '\u0000' in raw || '\r' in normalizedTarget || '\n' in normalizedTarget || '\u0000' in normalizedTarget) {
            return denied("OUTBOUND_SCHEME_BLOCKED")
        }
        if (compact.contains("http://") || compact.contains("https://") || compact.startsWith("http:") || compact.startsWith("https:")) {
            return denied("OUTBOUND_HTTP_BLOCKED")
        }
        val blockedSchemes = listOf("ftp://", "ftps://", "javascript:", "data:", "intent:", "file://", "file:", "blob:", "about:")
        if (blockedSchemes.any { compact.contains(it) }) {
            return denied("OUTBOUND_SCHEME_BLOCKED")
        }
        if (hasTraversal(raw, normalizedTarget)) {
            return denied("OUTBOUND_SCHEME_BLOCKED")
        }
        if (normalizedAction == AutomationOutboundActions.ACTION_SAF_READ ||
            normalizedAction == AutomationOutboundActions.ACTION_SAF_WRITE
        ) {
            if (!lower.startsWith("content://")) {
                return denied("OUTBOUND_SCHEME_BLOCKED")
            }
        }
        if (normalizedAction == AutomationOutboundActions.ACTION_APP_LAUNCH) {
            if (!PACKAGE_REGEX.matches(normalizedTarget)) {
                return denied("OUTBOUND_SCHEME_BLOCKED")
            }
        }

        if (uriOrTarget.isUntrusted || isVaultSource(uriOrTarget.sourceLabel)) {
            return FirewallDecision.RequiresConfirmation(
                message = UserMessage(
                    key = MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE,
                    args = listOf(MessageArg.ProvenanceBadge(uriOrTarget.provenance))
                ),
                untrustedHighRiskSlots = setOf("uriOrTarget")
            )
        }
        return FirewallDecision.Authorized
    }

    private fun denied(code: String): FirewallDecision.Denied = FirewallDecision.Denied(
        message = UserMessage(MessageKey.ERROR_SECURITY_VIOLATION, listOf(MessageArg.Text(code))),
        reasonCode = code
    )

    private fun normalize(value: String): String {
        val nfkc = Normalizer.normalize(value, Normalizer.Form.NFKC)
        return Gemma4InputSanitizer.stripInvisibleControls(nfkc).trim()
    }

    private fun isVaultSource(label: String?): Boolean {
        if (label.isNullOrBlank()) return false
        return normalize(label).lowercase(Locale.ROOT).startsWith("vault:")
    }

    private fun hasTraversal(raw: String, norm: String): Boolean {
        if (".." in raw || '\\' in raw) return true
        var current = norm
        repeat(5) {
            val l = current.lowercase(Locale.ROOT)
            if (".." in l || '\\' in l || "%5c" in l || "%00" in l || "%0a" in l || "%0d" in l) {
                return true
            }
            val decoded = decodeOnce(current)
            if (decoded == current) return false
            current = Normalizer.normalize(decoded, Normalizer.Form.NFKC)
        }
        val l = current.lowercase(Locale.ROOT)
        return ".." in l || '\\' in l || "%2e" in l || "%5c" in l
    }

    private fun decodeOnce(input: String): String {
        if ('%' !in input) return input
        val sb = StringBuilder(input.length)
        var i = 0
        while (i < input.length) {
            if (input[i] == '%' && i + 2 < input.length) {
                val hi = Character.digit(input[i + 1], 16)
                val lo = Character.digit(input[i + 2], 16)
                if (hi >= 0 && lo >= 0) {
                    sb.append(((hi shl 4) or lo).toChar())
                    i += 3
                    continue
                }
            }
            sb.append(input[i])
            i++
        }
        return sb.toString()
    }

    companion object {
        private val ALLOWED_ACTIONS: Set<String> = setOf(
            AutomationOutboundActions.ACTION_SET_ALARM,
            AutomationOutboundActions.ACTION_SET_TIMER,
            AutomationOutboundActions.ACTION_SENDTO,
            AutomationOutboundActions.ACTION_DIAL,
            AutomationOutboundActions.ACTION_CALL,
            AutomationOutboundActions.ACTION_OPEN_DOCUMENT_TREE,
            AutomationOutboundActions.ACTION_SAF_READ,
            AutomationOutboundActions.ACTION_SAF_WRITE,
            AutomationOutboundActions.ACTION_CALENDAR_PROVIDER,
            AutomationOutboundActions.ACTION_APP_LAUNCH
        )
        private val PACKAGE_REGEX: Regex = Regex("""^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+$""")
    }
}

internal object RedTeamContexts {
    const val FIXED_NOW_MS: Long = 1_750_000_000_000L

    fun interactive(toolName: String, targetId: String): ToolExecutionContext {
        val token = CapabilityToken.mint(
            tokenId = "rt_tok_$toolName",
            requestId = "rt_req_$toolName",
            allowedTools = setOf(toolName),
            mintProvenance = DataProvenance.USER_UTTERANCE,
            issuedAtEpochMs = FIXED_NOW_MS,
            expiresAtEpochMs = FIXED_NOW_MS + 60_000L,
            maxToolCalls = 5
        )
        return ToolExecutionContext(
            requestId = "rt_req_$toolName",
            capabilityToken = token,
            ruleGrant = null,
            targetId = targetId,
            languageTag = "en",
            issuedAtEpochMs = FIXED_NOW_MS,
            isUnattendedBackground = false
        )
    }

    fun unattended(toolName: String, targetId: String): ToolExecutionContext {
        val grant = RuleCapabilityGrant(
            grantId = "rt_grant_$toolName",
            ruleId = "rt_rule_$toolName",
            triggerSpec = RuleTriggerSpec("time", mapOf("hour" to "7", "minute" to "0")),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = toolName,
                    requiredCapability = AtomicCapability.DATA_READ
                )
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "valid_hmac_hex_deadbeef"
        )
        return ToolExecutionContext(
            requestId = "rt_unattended_$toolName",
            capabilityToken = null,
            ruleGrant = grant,
            targetId = targetId,
            languageTag = "en",
            issuedAtEpochMs = FIXED_NOW_MS,
            isUnattendedBackground = true
        )
    }

    fun userStr(value: String, slotKind: SensitiveSlotKind? = null): Tainted<SlotValueAst> =
        Tainted.fromUserUtterance(SlotValueAst.StringValue(value), slotKind)

    fun userInt(value: Long, slotKind: SensitiveSlotKind? = null): Tainted<SlotValueAst> =
        Tainted.fromUserUtterance(SlotValueAst.IntValue(value), slotKind)

    fun untrustedStr(
        value: String,
        slotKind: SensitiveSlotKind? = null,
        sourceLabel: String = "notification:com.untrusted.chat"
    ): Tainted<SlotValueAst> =
        Tainted.fromUntrustedExternal(SlotValueAst.StringValue(value), slotKind, sourceLabel)

    fun untrustedInt(
        value: Long,
        slotKind: SensitiveSlotKind? = null,
        sourceLabel: String = "notification:com.untrusted.chat"
    ): Tainted<SlotValueAst> =
        Tainted.fromUntrustedExternal(SlotValueAst.IntValue(value), slotKind, sourceLabel)

    fun vaultStr(
        value: String,
        slotKind: SensitiveSlotKind? = null,
        sourceLabel: String = "vault:secret_note_01"
    ): Tainted<SlotValueAst> =
        Tainted.fromUntrustedExternal(SlotValueAst.StringValue(value), slotKind, sourceLabel)
}

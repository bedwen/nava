package com.nava.core.security.firewall

import com.nava.core.security.policy.RuleCapabilityGrantManager
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
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.ToolCategory
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import java.text.Normalizer
import java.util.Locale
import java.util.UUID

/**
 * Deterministic Kotlin-side security enforcement boundary implementing [SecurityFirewallPort].
 *
 * Enforces:
 * - Stage 1 [CapabilityToken] minting strictly from [DataProvenance.USER_UTTERANCE].
 * - Default-Deny orthogonal [com.nava.domain.security.PermissionProfile] evaluation.
 * - Value-level [Tainted] & [SensitiveSlotKind] high-risk destination confirmation rules.
 * - Outbound Channel & IPC Exfiltration Policy (including Vault/untrusted taint barrier).
 * - Constant-time HMAC-SHA256 verification and unattended safety boundaries for [RuleCapabilityGrant].
 * - Mandatory encrypted audit logging via [AuditLogPort].
 */
class SecurityFirewall(
    private val permissionEvaluator: PermissionEvaluatorPort,
    private val ruleGrantManager: RuleCapabilityGrantManager,
    private val auditLog: AuditLogPort,
    private val outboundPolicy: OutboundChannelPolicy = OutboundChannelPolicy(),
    private val clockMs: () -> Long = System::currentTimeMillis,
    private val tokenIdGenerator: () -> String = { UUID.randomUUID().toString() }
) : SecurityFirewallPort {

    override suspend fun mintToken(
        requestId: String,
        utteranceProvenance: DataProvenance,
        candidateTools: Set<String>,
        nowEpochMs: Long
    ): CapabilityToken {
        require(requestId.isNotBlank()) { "requestId must not be blank" }
        if (utteranceProvenance != DataProvenance.USER_UTTERANCE) {
            recordAudit(
                timestampEpochMs = nowEpochMs,
                toolName = candidateTools.firstOrNull()?.takeIf { it.isNotBlank() } ?: "mint_token",
                targetId = requestId,
                actionSummary = "Denied CapabilityToken mint from provenance $utteranceProvenance",
                provenance = utteranceProvenance,
                decision = DECISION_TOKEN_MINT_DENIED
            )
            throw SecurityException(
                "CapabilityToken may only be minted from USER_UTTERANCE, got $utteranceProvenance"
            )
        }
        return CapabilityToken.mint(
            tokenId = tokenIdGenerator(),
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
        val safeTargetId = targetId.ifBlank { "unknown_target" }
        val aggregateProvenance = computeAggregateProvenance(toolCall, token.mintProvenance)

        if (toolCall.toolName != toolMetadata.name) {
            recordAudit(
                timestampEpochMs = nowEpochMs,
                toolName = toolCall.toolName,
                targetId = safeTargetId,
                actionSummary = "Tool metadata mismatch: call='${toolCall.toolName}', metadata='${toolMetadata.name}'",
                provenance = aggregateProvenance,
                decision = DECISION_TOOL_METADATA_MISMATCH
            )
            throw SecurityException(
                "ToolCallAst toolName '${toolCall.toolName}' does not match ToolMetadata '${toolMetadata.name}'"
            )
        }

        try {
            token.assertValidFor(toolCall.toolName, nowEpochMs)
        } catch (e: SecurityException) {
            recordAudit(
                timestampEpochMs = nowEpochMs,
                toolName = toolCall.toolName,
                targetId = safeTargetId,
                actionSummary = e.message ?: "CapabilityToken rejected tool invocation",
                provenance = aggregateProvenance,
                decision = DECISION_CAPABILITY_TOKEN_DENIED
            )
            throw e
        }

        val outboundViolation = scanArgumentsForOutboundViolations(toolCall, toolMetadata)
        if (outboundViolation != null) {
            recordAudit(
                timestampEpochMs = nowEpochMs,
                toolName = toolMetadata.name,
                targetId = safeTargetId,
                actionSummary = outboundViolation.detail,
                provenance = aggregateProvenance,
                decision = outboundViolation.reasonCode
            )
            return FirewallDecision.Denied(
                message = UserMessage(
                    key = MessageKey.ERROR_SECURITY_VIOLATION,
                    args = listOf(MessageArg.Text(outboundViolation.reasonCode))
                ),
                reasonCode = outboundViolation.reasonCode
            )
        }

        val confirmationLevel = permissionEvaluator.evaluateCapability(
            targetId = targetId,
            capability = toolMetadata.requiredCapability
        )
        if (confirmationLevel == ConfirmationLevel.DISABLED) {
            recordAudit(
                timestampEpochMs = nowEpochMs,
                toolName = toolMetadata.name,
                targetId = safeTargetId,
                actionSummary = "Capability ${toolMetadata.requiredCapability} denied for target '$safeTargetId'",
                provenance = aggregateProvenance,
                decision = DECISION_PERMISSION_DENIED
            )
            return FirewallDecision.Denied(
                message = UserMessage(
                    key = MessageKey.ERROR_PERMISSION_DENIED,
                    args = listOf(
                        MessageArg.Text(safeTargetId),
                        MessageArg.Text(toolMetadata.requiredCapability.name)
                    )
                ),
                reasonCode = DECISION_PERMISSION_DENIED
            )
        }

        val untrustedHighRiskSlots = LinkedHashSet<String>()
        val outboundTaintSlots = LinkedHashSet<String>()
        var hasAnyUntrustedArg = false
        var hasVaultSourceArg = false

        for ((argName, taintedArg) in toolCall.arguments) {
            val declaredField = toolMetadata.fieldByName(argName)
            val isUntrusted = taintedArg.isUntrusted
            val isVault = isVaultSource(taintedArg.sourceLabel)
            if (isUntrusted) {
                hasAnyUntrustedArg = true
            }
            if (isVault) {
                hasVaultSourceArg = true
            }
            if (
                taintedArg.requiresExplicitConfirmation ||
                (isUntrusted && declaredField?.slotKind?.isHighRisk == true)
            ) {
                untrustedHighRiskSlots.add(argName)
            }
            if (isUntrusted || isVault) {
                outboundTaintSlots.add(argName)
            }
        }

        val outboundTaintBarrierTriggered =
            isOutboundOrSafWriteTool(toolMetadata) && (hasAnyUntrustedArg || hasVaultSourceArg)

        if (outboundTaintBarrierTriggered) {
            untrustedHighRiskSlots.addAll(outboundTaintSlots)
        }

        if (confirmationLevel == ConfirmationLevel.BIOMETRIC) {
            recordAudit(
                timestampEpochMs = nowEpochMs,
                toolName = toolMetadata.name,
                targetId = safeTargetId,
                actionSummary = "Biometric authentication required for '${toolMetadata.name}'",
                provenance = aggregateProvenance,
                decision = DECISION_REQUIRES_BIOMETRIC
            )
            return FirewallDecision.RequiresBiometric(
                message = UserMessage(
                    key = MessageKey.ACTION_BIOMETRIC_REQUIRED,
                    args = listOf(MessageArg.Text(toolMetadata.name))
                )
            )
        }

        if (untrustedHighRiskSlots.isNotEmpty() || outboundTaintBarrierTriggered) {
            val badgeProvenance = if (hasAnyUntrustedArg) {
                DataProvenance.UNTRUSTED_EXTERNAL
            } else {
                aggregateProvenance
            }
            recordAudit(
                timestampEpochMs = nowEpochMs,
                toolName = toolMetadata.name,
                targetId = safeTargetId,
                actionSummary = "Explicit confirmation required due to tainted/vault slots: $untrustedHighRiskSlots",
                provenance = badgeProvenance,
                decision = DECISION_REQUIRES_CONFIRMATION_TAINTED
            )
            return FirewallDecision.RequiresConfirmation(
                message = UserMessage(
                    key = MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE,
                    args = listOf(MessageArg.ProvenanceBadge(badgeProvenance))
                ),
                untrustedHighRiskSlots = untrustedHighRiskSlots.toSet()
            )
        }

        if (confirmationLevel == ConfirmationLevel.PROMPT_CARD) {
            recordAudit(
                timestampEpochMs = nowEpochMs,
                toolName = toolMetadata.name,
                targetId = safeTargetId,
                actionSummary = "Action confirmation card required by PermissionProfile",
                provenance = aggregateProvenance,
                decision = DECISION_REQUIRES_CONFIRMATION
            )
            return FirewallDecision.RequiresConfirmation(
                message = UserMessage(
                    key = MessageKey.ACTION_CONFIRMATION_REQUIRED,
                    args = listOf(MessageArg.Text(toolMetadata.name))
                ),
                untrustedHighRiskSlots = emptySet()
            )
        }

        recordAudit(
            timestampEpochMs = nowEpochMs,
            toolName = toolMetadata.name,
            targetId = safeTargetId,
            actionSummary = "Authorized tool execution '${toolMetadata.name}'",
            provenance = aggregateProvenance,
            decision = DECISION_AUTHORIZED
        )
        return FirewallDecision.Authorized
    }

    override suspend fun authorizeRuleExecution(grant: RuleCapabilityGrant): FirewallDecision {
        val nowMs = clockMs()
        val auditToolName = grant.staticActions.firstOrNull()?.toolName ?: "automation_rule"

        if (ruleGrantManager.isGlobalRulesPaused()) {
            recordAudit(
                timestampEpochMs = nowMs,
                toolName = auditToolName,
                targetId = grant.ruleId,
                actionSummary = "Background rule '${grant.ruleId}' blocked because rules are globally paused",
                provenance = DataProvenance.SYSTEM,
                decision = DECISION_RULES_GLOBALLY_PAUSED
            )
            return FirewallDecision.Denied(
                message = UserMessage(
                    key = MessageKey.ERROR_PERMISSION_DENIED,
                    args = listOf(MessageArg.Text(DECISION_RULES_GLOBALLY_PAUSED))
                ),
                reasonCode = DECISION_RULES_GLOBALLY_PAUSED
            )
        }

        if (grant.approvalState != RuleApprovalState.APPROVED_ACTIVE) {
            recordAudit(
                timestampEpochMs = nowMs,
                toolName = auditToolName,
                targetId = grant.ruleId,
                actionSummary = "Background rule '${grant.ruleId}' is in state ${grant.approvalState}",
                provenance = DataProvenance.SYSTEM,
                decision = DECISION_RULE_NOT_APPROVED
            )
            return FirewallDecision.Denied(
                message = UserMessage(
                    key = MessageKey.ERROR_SECURITY_VIOLATION,
                    args = listOf(MessageArg.Text(DECISION_RULE_NOT_APPROVED))
                ),
                reasonCode = DECISION_RULE_NOT_APPROVED
            )
        }

        val persisted = ruleGrantManager.findRule(grant.ruleId)
        val sealValid = persisted != null &&
            persisted.approvalState == RuleApprovalState.APPROVED_ACTIVE &&
            persisted == grant &&
            ruleGrantManager.verifySeal(grant)

        if (!sealValid) {
            recordAudit(
                timestampEpochMs = nowMs,
                toolName = auditToolName,
                targetId = grant.ruleId,
                actionSummary = "Background rule '${grant.ruleId}' failed persisted state or HMAC seal verification",
                provenance = DataProvenance.SYSTEM,
                decision = DECISION_RULE_SEAL_INVALID
            )
            return FirewallDecision.Denied(
                message = UserMessage(
                    key = MessageKey.ERROR_SECURITY_VIOLATION,
                    args = listOf(MessageArg.Text(DECISION_RULE_SEAL_INVALID))
                ),
                reasonCode = DECISION_RULE_SEAL_INVALID
            )
        }

        if (BlindSlotExtractor.containsControlTokenOrToolCallSyntax(grant.triggerSpec.triggerType)) {
            recordAudit(
                timestampEpochMs = nowMs,
                toolName = auditToolName,
                targetId = grant.ruleId,
                actionSummary = "Background rule '${grant.ruleId}' triggerType contained forbidden control tokens",
                provenance = DataProvenance.SYSTEM,
                decision = DECISION_RULE_CONTROL_TOKEN_BLOCKED
            )
            return FirewallDecision.Denied(
                message = UserMessage(
                    key = MessageKey.ERROR_SECURITY_VIOLATION,
                    args = listOf(MessageArg.Text(DECISION_RULE_CONTROL_TOKEN_BLOCKED))
                ),
                reasonCode = DECISION_RULE_CONTROL_TOKEN_BLOCKED
            )
        }

        for ((paramKey, paramVal) in grant.triggerSpec.parameters) {
            if (
                BlindSlotExtractor.containsControlTokenOrToolCallSyntax(paramKey) ||
                BlindSlotExtractor.containsControlTokenOrToolCallSyntax(paramVal)
            ) {
                recordAudit(
                    timestampEpochMs = nowMs,
                    toolName = auditToolName,
                    targetId = grant.ruleId,
                    actionSummary = "Background rule '${grant.ruleId}' trigger parameter contained forbidden control tokens",
                    provenance = DataProvenance.SYSTEM,
                    decision = DECISION_RULE_CONTROL_TOKEN_BLOCKED
                )
                return FirewallDecision.Denied(
                    message = UserMessage(
                        key = MessageKey.ERROR_SECURITY_VIOLATION,
                        args = listOf(MessageArg.Text(DECISION_RULE_CONTROL_TOKEN_BLOCKED))
                    ),
                    reasonCode = DECISION_RULE_CONTROL_TOKEN_BLOCKED
                )
            }
            val triggerSchemeVerdict = outboundPolicy.inspectRawValueForBlockedSchemes(paramVal)
            if (triggerSchemeVerdict is OutboundPolicyVerdict.Blocked) {
                recordAudit(
                    timestampEpochMs = nowMs,
                    toolName = auditToolName,
                    targetId = grant.ruleId,
                    actionSummary = "Background rule '${grant.ruleId}' trigger blocked outbound scheme: ${triggerSchemeVerdict.detail}",
                    provenance = DataProvenance.SYSTEM,
                    decision = triggerSchemeVerdict.reasonCode
                )
                return FirewallDecision.Denied(
                    message = UserMessage(
                        key = MessageKey.ERROR_SECURITY_VIOLATION,
                        args = listOf(MessageArg.Text(triggerSchemeVerdict.reasonCode))
                    ),
                    reasonCode = triggerSchemeVerdict.reasonCode
                )
            }
        }

        for (action in grant.staticActions) {
            if (BlindSlotExtractor.containsControlTokenOrToolCallSyntax(action.toolName)) {
                recordAudit(
                    timestampEpochMs = nowMs,
                    toolName = action.toolName,
                    targetId = grant.ruleId,
                    actionSummary = "Background rule '${grant.ruleId}' toolName contained forbidden control tokens",
                    provenance = DataProvenance.SYSTEM,
                    decision = DECISION_RULE_CONTROL_TOKEN_BLOCKED
                )
                return FirewallDecision.Denied(
                    message = UserMessage(
                        key = MessageKey.ERROR_SECURITY_VIOLATION,
                        args = listOf(MessageArg.Text(DECISION_RULE_CONTROL_TOKEN_BLOCKED))
                    ),
                    reasonCode = DECISION_RULE_CONTROL_TOKEN_BLOCKED
                )
            }
            for ((argKey, argVal) in action.staticArguments) {
                if (
                    BlindSlotExtractor.containsControlTokenOrToolCallSyntax(argKey) ||
                    BlindSlotExtractor.containsControlTokenOrToolCallSyntax(argVal)
                ) {
                    recordAudit(
                        timestampEpochMs = nowMs,
                        toolName = action.toolName,
                        targetId = grant.ruleId,
                        actionSummary = "Background rule '${grant.ruleId}' contained forbidden control tokens",
                        provenance = DataProvenance.SYSTEM,
                        decision = DECISION_RULE_CONTROL_TOKEN_BLOCKED
                    )
                    return FirewallDecision.Denied(
                        message = UserMessage(
                            key = MessageKey.ERROR_SECURITY_VIOLATION,
                            args = listOf(MessageArg.Text(DECISION_RULE_CONTROL_TOKEN_BLOCKED))
                        ),
                        reasonCode = DECISION_RULE_CONTROL_TOKEN_BLOCKED
                    )
                }
                val schemeVerdict = outboundPolicy.inspectRawValueForBlockedSchemes(argVal)
                if (schemeVerdict is OutboundPolicyVerdict.Blocked) {
                    recordAudit(
                        timestampEpochMs = nowMs,
                        toolName = action.toolName,
                        targetId = grant.ruleId,
                        actionSummary = "Background rule '${grant.ruleId}' blocked outbound scheme: ${schemeVerdict.detail}",
                        provenance = DataProvenance.SYSTEM,
                        decision = schemeVerdict.reasonCode
                    )
                    return FirewallDecision.Denied(
                        message = UserMessage(
                            key = MessageKey.ERROR_SECURITY_VIOLATION,
                            args = listOf(MessageArg.Text(schemeVerdict.reasonCode))
                        ),
                        reasonCode = schemeVerdict.reasonCode
                    )
                }
            }
        }

        if (grant.staticActions.any { it.requiresBiometric || isVaultTargetedAction(it) }) {
            recordAudit(
                timestampEpochMs = nowMs,
                toolName = auditToolName,
                targetId = grant.ruleId,
                actionSummary = "Background rule '${grant.ruleId}' degraded to biometric confirmation",
                provenance = DataProvenance.SYSTEM,
                decision = DECISION_RULE_REQUIRES_BIOMETRIC
            )
            return FirewallDecision.RequiresBiometric(
                message = UserMessage(
                    key = MessageKey.ACTION_BIOMETRIC_REQUIRED,
                    args = listOf(MessageArg.Text(grant.ruleId))
                )
            )
        }

        if (grant.requiresInteractiveUpgrade) {
            recordAudit(
                timestampEpochMs = nowMs,
                toolName = auditToolName,
                targetId = grant.ruleId,
                actionSummary = "Background rule '${grant.ruleId}' degraded to interactive confirmation card",
                provenance = DataProvenance.SYSTEM,
                decision = DECISION_RULE_REQUIRES_CONFIRMATION
            )
            return FirewallDecision.RequiresConfirmation(
                message = UserMessage(
                    key = MessageKey.ACTION_CONFIRMATION_REQUIRED,
                    args = listOf(MessageArg.Text(grant.ruleId))
                )
            )
        }

        recordAudit(
            timestampEpochMs = nowMs,
            toolName = auditToolName,
            targetId = grant.ruleId,
            actionSummary = "Authorized unattended background rule '${grant.ruleId}'",
            provenance = DataProvenance.SYSTEM,
            decision = DECISION_RULE_AUTHORIZED
        )
        return FirewallDecision.Authorized
    }

    override suspend fun validateOutboundTarget(
        toolName: String,
        action: String,
        uriOrTarget: Tainted<String>
    ): FirewallDecision {
        val nowMs = clockMs()
        val safeToolName = toolName.ifBlank { "outbound_tool" }
        val safeTargetId = action.ifBlank { "unknown_action" }

        when (val verdict = outboundPolicy.evaluate(action, uriOrTarget.value)) {
            is OutboundPolicyVerdict.Blocked -> {
                recordAudit(
                    timestampEpochMs = nowMs,
                    toolName = safeToolName,
                    targetId = safeTargetId,
                    actionSummary = "Blocked outbound target: ${verdict.detail}",
                    provenance = uriOrTarget.provenance,
                    decision = verdict.reasonCode
                )
                return FirewallDecision.Denied(
                    message = UserMessage(
                        key = MessageKey.ERROR_SECURITY_VIOLATION,
                        args = listOf(MessageArg.Text(verdict.reasonCode))
                    ),
                    reasonCode = verdict.reasonCode
                )
            }

            OutboundPolicyVerdict.Allowed -> {
                if (uriOrTarget.isUntrusted || isVaultSource(uriOrTarget.sourceLabel)) {
                    recordAudit(
                        timestampEpochMs = nowMs,
                        toolName = safeToolName,
                        targetId = safeTargetId,
                        actionSummary = "Outbound target requires user confirmation due to provenance/vault barrier",
                        provenance = uriOrTarget.provenance,
                        decision = DECISION_OUTBOUND_CONFIRMATION_REQUIRED
                    )
                    return FirewallDecision.RequiresConfirmation(
                        message = UserMessage(
                            key = MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE,
                            args = listOf(MessageArg.ProvenanceBadge(uriOrTarget.provenance))
                        ),
                        untrustedHighRiskSlots = setOf(OUTBOUND_TARGET_SLOT_NAME)
                    )
                }

                recordAudit(
                    timestampEpochMs = nowMs,
                    toolName = safeToolName,
                    targetId = safeTargetId,
                    actionSummary = "Authorized outbound target for action '$safeTargetId'",
                    provenance = uriOrTarget.provenance,
                    decision = DECISION_OUTBOUND_AUTHORIZED
                )
                return FirewallDecision.Authorized
            }
        }
    }

    private fun scanArgumentsForOutboundViolations(
        toolCall: ToolCallAst,
        toolMetadata: ToolMetadata
    ): OutboundPolicyVerdict.Blocked? {
        var intentActionValue: String? = null
        var primaryTargetValue: String? = null

        for ((argName, taintedArg) in toolCall.arguments) {
            val declaredField = toolMetadata.fieldByName(argName)
            val effectiveKind = taintedArg.slotKind ?: declaredField?.slotKind
            val displayValue = taintedArg.value.asDisplayString()

            val verdict = outboundPolicy.inspectArgumentValue(
                slotKind = effectiveKind,
                rawValue = displayValue,
                argName = argName
            )
            if (verdict is OutboundPolicyVerdict.Blocked) {
                return verdict
            }

            if (effectiveKind == SensitiveSlotKind.INTENT_ACTION) {
                intentActionValue = displayValue
            } else if (
                primaryTargetValue == null &&
                (
                    effectiveKind == SensitiveSlotKind.EXTERNAL_URI ||
                        effectiveKind == SensitiveSlotKind.PACKAGE_NAME ||
                        effectiveKind == SensitiveSlotKind.RECIPIENT_ADDRESS ||
                        effectiveKind == SensitiveSlotKind.PHONE_NUMBER
                    )
            ) {
                primaryTargetValue = displayValue
            }
        }

        if (intentActionValue != null) {
            val pairVerdict = outboundPolicy.evaluate(
                action = intentActionValue,
                uriOrTarget = primaryTargetValue.orEmpty()
            )
            if (pairVerdict is OutboundPolicyVerdict.Blocked) {
                return pairVerdict
            }
        }

        return null
    }

    private fun computeAggregateProvenance(
        toolCall: ToolCallAst,
        fallback: DataProvenance
    ): DataProvenance {
        var current = fallback
        for (arg in toolCall.arguments.values) {
            current = DataProvenance.worstOf(current, arg.provenance)
        }
        return current
    }

    private fun normalizeForVaultCheck(raw: String): String {
        val nfkc = Normalizer.normalize(raw, Normalizer.Form.NFKC)
        return Gemma4InputSanitizer.stripInvisibleControls(nfkc).trim().lowercase(Locale.ROOT)
    }

    private fun isVaultSource(sourceLabel: String?): Boolean {
        if (sourceLabel.isNullOrBlank()) return false
        return normalizeForVaultCheck(sourceLabel).startsWith(VAULT_SOURCE_PREFIX)
    }

    private fun isVaultTargetedAction(action: RuleActionSpec): Boolean {
        if (normalizeForVaultCheck(action.toolName).contains(VAULT_KEYWORD)) {
            return true
        }
        for ((key, value) in action.staticArguments) {
            if (normalizeForVaultCheck(key).contains(VAULT_KEYWORD)) {
                return true
            }
            val normalizedVal = normalizeForVaultCheck(value)
            if (normalizedVal.contains(VAULT_SOURCE_PREFIX) || VAULT_PATH_REGEX.containsMatchIn(normalizedVal)) {
                return true
            }
        }
        return false
    }

    private fun isOutboundOrSafWriteTool(toolMetadata: ToolMetadata): Boolean {
        if (toolMetadata.category == ToolCategory.COMMUNICATION) return true
        if (toolMetadata.requiredCapability == AtomicCapability.APP_LAUNCH) return true
        if (toolMetadata.requiredCapability == AtomicCapability.MODIFY_DELETE_SEND) return true
        if (
            toolMetadata.category == ToolCategory.NOTES_FILES &&
            toolMetadata.requiredCapability == AtomicCapability.CREATE_DRAFT
        ) {
            return true
        }
        val lowerName = toolMetadata.name.lowercase(Locale.ROOT)
        return lowerName.contains("sms") ||
            lowerName.contains("call") ||
            lowerName.contains("saf") ||
            lowerName.contains("launch") ||
            lowerName.contains("intent")
    }

    private suspend fun recordAudit(
        timestampEpochMs: Long,
        toolName: String,
        targetId: String,
        actionSummary: String,
        provenance: DataProvenance,
        decision: String
    ) {
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = timestampEpochMs,
                toolName = toolName.ifBlank { "unknown_tool" },
                targetId = targetId.ifBlank { "unknown_target" },
                actionSummary = actionSummary,
                provenance = provenance,
                decision = decision
            )
        )
    }

    companion object {
        const val DECISION_AUTHORIZED: String = "AUTHORIZED"
        const val DECISION_REQUIRES_CONFIRMATION: String = "REQUIRES_CONFIRMATION"
        const val DECISION_REQUIRES_CONFIRMATION_TAINTED: String = "REQUIRES_CONFIRMATION_TAINTED"
        const val DECISION_REQUIRES_BIOMETRIC: String = "REQUIRES_BIOMETRIC"
        const val DECISION_PERMISSION_DENIED: String = "PERMISSION_DENIED"
        const val DECISION_TOKEN_MINT_DENIED: String = "TOKEN_MINT_DENIED"
        const val DECISION_TOOL_METADATA_MISMATCH: String = "TOOL_METADATA_MISMATCH"
        const val DECISION_CAPABILITY_TOKEN_DENIED: String = "CAPABILITY_TOKEN_DENIED"
        const val DECISION_RULES_GLOBALLY_PAUSED: String = "RULES_GLOBALLY_PAUSED"
        const val DECISION_RULE_NOT_APPROVED: String = "RULE_NOT_APPROVED"
        const val DECISION_RULE_SEAL_INVALID: String = "RULE_SEAL_INVALID"
        const val DECISION_RULE_CONTROL_TOKEN_BLOCKED: String = "RULE_CONTROL_TOKEN_BLOCKED"
        const val DECISION_RULE_REQUIRES_BIOMETRIC: String = "RULE_REQUIRES_BIOMETRIC"
        const val DECISION_RULE_REQUIRES_CONFIRMATION: String = "RULE_REQUIRES_CONFIRMATION"
        const val DECISION_RULE_AUTHORIZED: String = "RULE_AUTHORIZED"
        const val DECISION_OUTBOUND_AUTHORIZED: String = "OUTBOUND_AUTHORIZED"
        const val DECISION_OUTBOUND_CONFIRMATION_REQUIRED: String = "OUTBOUND_CONFIRMATION_REQUIRED"

        private const val VAULT_SOURCE_PREFIX: String = "vault:"
        private const val VAULT_KEYWORD: String = "vault"
        private const val OUTBOUND_TARGET_SLOT_NAME: String = "uriOrTarget"
        private val VAULT_PATH_REGEX: Regex = Regex("""(?:^|[/\\:])vault(?:[/\\:]|$)""")
    }
}

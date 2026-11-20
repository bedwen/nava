package com.nava.feature.automations.saf

import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.Gemma4InputSanitizer
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.NavaTool
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolCategory
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolResult
import com.nava.domain.tool.ToolSchemaField
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.common.AutomationOutboundActions
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.SafGatewayResult
import com.nava.feature.automations.common.SafPlatformGateway
import com.nava.feature.automations.common.ToolArgumentReader
import com.nava.feature.automations.common.ToolTargetIds

/**
 * Storage Access Framework (SAF) document tree and file automation tools.
 *
 * Security Invariants (PLAN.md 5.4, 5.7):
 * - Restricted strictly to persistable SAF tree URIs explicitly granted by the user via system picker.
 * - `MANAGE_EXTERNAL_STORAGE` is strictly forbidden.
 * - Always verifies persisted URI permissions via [SafPlatformGateway.hasPersistedGrant].
 * - Validates document names against directory traversal (`..`, slashes, control chars) via
 *   [SafPlatformGateway.isSafeDocumentName].
 * - Validates outbound read/write operations via [SecurityFirewallPort.validateOutboundTarget].
 * - Enforces the Outbound Channel taint barrier on SAF writes containing `UNTRUSTED_EXTERNAL`
 *   or vault data by requiring explicit user confirmation.
 * - Tags all read document content and directory listings with [DataProvenance.UNTRUSTED_EXTERNAL].
 * - Appends structured records to [AuditLogPort] for every operation without leaking file contents.
 */
sealed class SafDirectoryTool(
    override val metadata: ToolMetadata,
    protected val safGateway: SafPlatformGateway,
    protected val firewall: SecurityFirewallPort,
    protected val auditLog: AuditLogPort
) : NavaTool {

    protected suspend fun recordSafAudit(
        timestampMs: Long,
        treeUri: String,
        actionSummary: String,
        provenance: DataProvenance,
        decision: String
    ) {
        val targetId = try {
            ToolTargetIds.forSafTree(treeUri)
        } catch (_: Exception) {
            ToolTargetIds.SAF
        }
        auditLog.record(
            AuditLogEntry(
                timestampEpochMs = timestampMs,
                toolName = metadata.name,
                targetId = targetId,
                actionSummary = actionSummary,
                provenance = provenance,
                decision = decision
            )
        )
    }

    /**
     * SAF directory list or document read tool (`saf_read`).
     */
    class Read(
        safGateway: SafPlatformGateway,
        firewall: SecurityFirewallPort,
        auditLog: AuditLogPort
    ) : SafDirectoryTool(
        metadata = ToolMetadata(
            name = AutomationToolNames.SAF_READ,
            displayNameKey = "action_saf_directory_listed",
            description = "Lists documents in a granted SAF directory or reads a specific document",
            category = ToolCategory.NOTES_FILES,
            requiredCapability = AtomicCapability.DATA_READ,
            schemaVersion = 1,
            fields = listOf(
                ToolSchemaField(
                    name = FIELD_TREE_URI,
                    description = "Persisted SAF directory tree URI",
                    required = true,
                    slotKind = SensitiveSlotKind.EXTERNAL_URI,
                    valueType = SlotValueType.STRING
                ),
                ToolSchemaField(
                    name = FIELD_FILE_NAME,
                    description = "Optional document file name to read within the directory",
                    required = false,
                    slotKind = SensitiveSlotKind.FILE_PATH,
                    valueType = SlotValueType.STRING
                )
            ),
            supportsUnattendedRule = true
        ),
        safGateway = safGateway,
        firewall = firewall,
        auditLog = auditLog
    ) {
        override suspend fun execute(
            context: ToolExecutionContext,
            arguments: Map<String, Tainted<SlotValueAst>>
        ): ToolResult {
            val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else System.currentTimeMillis()

            val treeUriTainted = ToolArgumentReader.getString(arguments, FIELD_TREE_URI)
                ?: ToolArgumentReader.getString(arguments, "treeUri")
                ?: ToolArgumentReader.getString(arguments, "uri")
                ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_TREE_URI)

            val rawTreeUri = treeUriTainted.value.trim()
            if (!safGateway.hasPersistedGrant(rawTreeUri, requireWrite = false)) {
                recordSafAudit(
                    timestampMs = nowMs,
                    treeUri = rawTreeUri,
                    actionSummary = "SAF grant missing for tree: $rawTreeUri",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = ToolArgumentReader.ERROR_SAF_GRANT_MISSING
                )
                return ToolResult.Failure(
                    message = UserMessage(
                        key = MessageKey.ERROR_SAF_GRANT_MISSING,
                        args = listOf(MessageArg.Text(rawTreeUri))
                    ),
                    errorCode = ToolArgumentReader.ERROR_SAF_GRANT_MISSING
                )
            }

            val fileNameTainted = ToolArgumentReader.getString(arguments, FIELD_FILE_NAME)
                ?: ToolArgumentReader.getString(arguments, "fileName")
                ?: ToolArgumentReader.getString(arguments, "name")

            val rawFileName = fileNameTainted?.value?.trim()
            val targetUriString = if (!rawFileName.isNullOrEmpty()) "$rawTreeUri/$rawFileName" else rawTreeUri
            val taintedTargetUri: Tainted<String> = if (fileNameTainted != null) {
                treeUriTainted.combineWith(fileNameTainted) { _, _ -> targetUriString }
            } else {
                treeUriTainted.map { targetUriString }
            }

            if (!rawFileName.isNullOrEmpty() && !SafPlatformGateway.isSafeDocumentName(rawFileName)) {
                recordSafAudit(
                    timestampMs = nowMs,
                    treeUri = rawTreeUri,
                    actionSummary = "Unsafe SAF document name or path traversal rejected: $rawFileName",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = ToolArgumentReader.ERROR_INVALID_ARGUMENTS
                )
                return ToolArgumentReader.invalidArgumentsFailure("file_name: unsafe name or traversal sequence")
            }

            val firewallDecision = firewall.validateOutboundTarget(
                toolName = metadata.name,
                action = AutomationOutboundActions.ACTION_SAF_READ,
                uriOrTarget = taintedTargetUri
            )

            val userConfirmed = context.isUserConfirmed && !context.isUnattendedBackground
            val bioApproved = context.isBiometricApproved && !context.isUnattendedBackground
            val hasUntrustedHighRisk = treeUriTainted.isUntrusted || fileNameTainted?.isUntrusted == true

            when (firewallDecision) {
                is FirewallDecision.Denied -> {
                    recordSafAudit(
                        timestampMs = nowMs,
                        treeUri = rawTreeUri,
                        actionSummary = "Denied SAF read target: $targetUriString",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = firewallDecision.reasonCode
                    )
                    return ToolArgumentReader.securityFailure(
                        reasonCode = firewallDecision.reasonCode,
                        message = firewallDecision.message
                    )
                }

                is FirewallDecision.RequiresBiometric -> {
                    if (!bioApproved || (hasUntrustedHighRisk && !userConfirmed)) {
                        recordSafAudit(
                            timestampMs = nowMs,
                            treeUri = rawTreeUri,
                            actionSummary = "Biometric confirmation required for SAF read target: $targetUriString",
                            provenance = ToolArgumentReader.worstProvenance(arguments),
                            decision = "BIOMETRIC_REQUIRED"
                        )
                        return ToolResult.ConfirmationRequired(
                            message = firewallDecision.message,
                            pendingToolName = metadata.name,
                            targetId = ToolTargetIds.forSafTree(rawTreeUri),
                            canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                            requiresBiometric = true,
                            hasUntrustedHighRiskSlot = hasUntrustedHighRisk
                        )
                    }
                }

                is FirewallDecision.RequiresConfirmation -> {
                    if (!userConfirmed) {
                        recordSafAudit(
                            timestampMs = nowMs,
                            treeUri = rawTreeUri,
                            actionSummary = "User confirmation required for SAF read target: $targetUriString",
                            provenance = ToolArgumentReader.worstProvenance(arguments),
                            decision = "CONFIRMATION_REQUIRED"
                        )
                        return ToolResult.ConfirmationRequired(
                            message = firewallDecision.message,
                            pendingToolName = metadata.name,
                            targetId = ToolTargetIds.forSafTree(rawTreeUri),
                            canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                            requiresBiometric = false,
                            hasUntrustedHighRiskSlot = true
                        )
                    }
                }

                FirewallDecision.Authorized -> {
                    val hasUntrusted = treeUriTainted.isUntrusted || fileNameTainted?.isUntrusted == true
                    val hasVault = ToolArgumentReader.hasVaultSourceArgument(arguments)
                    if (hasUntrusted || hasVault) {
                        if (!userConfirmed) {
                            val worst = ToolArgumentReader.worstProvenance(arguments)
                            recordSafAudit(
                                timestampMs = nowMs,
                                treeUri = rawTreeUri,
                                actionSummary = "User confirmation required for SAF read target: $targetUriString",
                                provenance = worst,
                                decision = "CONFIRMATION_REQUIRED"
                            )
                            return ToolResult.ConfirmationRequired(
                                message = UserMessage(
                                    key = MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE,
                                    args = listOf(MessageArg.ProvenanceBadge(worst))
                                ),
                                pendingToolName = metadata.name,
                                targetId = ToolTargetIds.forSafTree(rawTreeUri),
                                canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                                requiresBiometric = false,
                                hasUntrustedHighRiskSlot = true
                            )
                        }
                    }
                }
            }

            // If file_name is omitted: list directory contents
            if (rawFileName.isNullOrEmpty()) {
                return when (val listResult = safGateway.listDocuments(rawTreeUri)) {
                    is SafGatewayResult.Success -> {
                        val entries = listResult.value
                        recordSafAudit(
                            timestampMs = nowMs,
                            treeUri = rawTreeUri,
                            actionSummary = "Listed SAF directory: $rawTreeUri (count=${entries.size})",
                            provenance = DataProvenance.UNTRUSTED_EXTERNAL,
                            decision = "SUCCESS"
                        )
                        ToolResult.Success(
                            message = UserMessage(
                                key = MessageKey.ACTION_SAF_DIRECTORY_LISTED,
                                args = listOf(
                                    MessageArg.Text(rawTreeUri),
                                    MessageArg.Number(entries.size.toLong())
                                )
                            ),
                            outputValues = mapOf(
                                "count" to entries.size.toString(),
                                "documents" to entries.joinToString(",") { Gemma4InputSanitizer.sanitize(it.displayName) }
                            ),
                            outputProvenance = DataProvenance.UNTRUSTED_EXTERNAL
                        )
                    }

                    is SafGatewayResult.GrantMissing -> {
                        recordSafAudit(
                            timestampMs = nowMs,
                            treeUri = rawTreeUri,
                            actionSummary = "SAF grant missing during list: $rawTreeUri",
                            provenance = ToolArgumentReader.worstProvenance(arguments),
                            decision = ToolArgumentReader.ERROR_SAF_GRANT_MISSING
                        )
                        ToolResult.Failure(
                            message = UserMessage(
                                key = MessageKey.ERROR_SAF_GRANT_MISSING,
                                args = listOf(MessageArg.Text(rawTreeUri))
                            ),
                            errorCode = ToolArgumentReader.ERROR_SAF_GRANT_MISSING
                        )
                    }

                    is SafGatewayResult.NotFound -> {
                        ToolArgumentReader.notFoundFailure(rawTreeUri)
                    }

                    is SafGatewayResult.Unavailable -> {
                        recordSafAudit(
                            timestampMs = nowMs,
                            treeUri = rawTreeUri,
                            actionSummary = "SAF directory unavailable: ${listResult.reason}",
                            provenance = ToolArgumentReader.worstProvenance(arguments),
                            decision = ToolArgumentReader.ERROR_PLATFORM_UNAVAILABLE
                        )
                        ToolArgumentReader.platformUnavailableFailure(listResult.reason)
                    }
                }
            }

            // If file_name is specified: read document contents
            return when (val readResult = safGateway.readDocument(rawTreeUri, rawFileName)) {
                is SafGatewayResult.Success -> {
                    val bytes = readResult.value
                    val contentString = Gemma4InputSanitizer.sanitize(bytes.toString(Charsets.UTF_8))
                    val sanitizedFileName = Gemma4InputSanitizer.sanitize(rawFileName)
                    recordSafAudit(
                        timestampMs = nowMs,
                        treeUri = rawTreeUri,
                        actionSummary = "Read SAF document: $rawFileName in $rawTreeUri",
                        provenance = DataProvenance.UNTRUSTED_EXTERNAL,
                        decision = "SUCCESS"
                    )
                    ToolResult.Success(
                        message = UserMessage(
                            key = MessageKey.ACTION_SAF_FILE_READ,
                            args = listOf(MessageArg.Text(sanitizedFileName))
                        ),
                        outputValues = mapOf(
                            FIELD_FILE_NAME to sanitizedFileName,
                            FIELD_CONTENT to contentString,
                            "size_bytes" to bytes.size.toString()
                        ),
                        outputProvenance = DataProvenance.UNTRUSTED_EXTERNAL
                    )
                }

                is SafGatewayResult.NotFound -> {
                    recordSafAudit(
                        timestampMs = nowMs,
                        treeUri = rawTreeUri,
                        actionSummary = "SAF document not found: $rawFileName",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = ToolArgumentReader.ERROR_NOT_FOUND
                    )
                    ToolArgumentReader.notFoundFailure(rawFileName)
                }

                is SafGatewayResult.GrantMissing -> {
                    recordSafAudit(
                        timestampMs = nowMs,
                        treeUri = rawTreeUri,
                        actionSummary = "SAF grant missing during read: $rawTreeUri",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = ToolArgumentReader.ERROR_SAF_GRANT_MISSING
                    )
                    ToolResult.Failure(
                        message = UserMessage(
                            key = MessageKey.ERROR_SAF_GRANT_MISSING,
                            args = listOf(MessageArg.Text(rawTreeUri))
                        ),
                        errorCode = ToolArgumentReader.ERROR_SAF_GRANT_MISSING
                    )
                }

                is SafGatewayResult.Unavailable -> {
                    recordSafAudit(
                        timestampMs = nowMs,
                        treeUri = rawTreeUri,
                        actionSummary = "SAF document read unavailable: ${readResult.reason}",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = ToolArgumentReader.ERROR_PLATFORM_UNAVAILABLE
                    )
                    ToolArgumentReader.platformUnavailableFailure(readResult.reason)
                }
            }
        }
    }

    /**
     * SAF document write tool (`saf_write`).
     */
    class Write(
        safGateway: SafPlatformGateway,
        firewall: SecurityFirewallPort,
        auditLog: AuditLogPort
    ) : SafDirectoryTool(
        metadata = ToolMetadata(
            name = AutomationToolNames.SAF_WRITE,
            displayNameKey = "action_saf_file_written",
            description = "Writes or overwrites a document inside a granted SAF directory",
            category = ToolCategory.NOTES_FILES,
            requiredCapability = AtomicCapability.CREATE_DRAFT,
            schemaVersion = 1,
            fields = listOf(
                ToolSchemaField(
                    name = FIELD_TREE_URI,
                    description = "Persisted SAF directory tree URI",
                    required = true,
                    slotKind = SensitiveSlotKind.EXTERNAL_URI,
                    valueType = SlotValueType.STRING
                ),
                ToolSchemaField(
                    name = FIELD_FILE_NAME,
                    description = "Document display name",
                    required = true,
                    slotKind = SensitiveSlotKind.FILE_PATH,
                    valueType = SlotValueType.STRING
                ),
                ToolSchemaField(
                    name = FIELD_CONTENT,
                    description = "Document content to write",
                    required = true,
                    slotKind = SensitiveSlotKind.TEXT_BODY,
                    valueType = SlotValueType.STRING
                ),
                ToolSchemaField(
                    name = FIELD_MIME_TYPE,
                    description = "Optional MIME type (default text/plain)",
                    required = false,
                    slotKind = SensitiveSlotKind.TEXT_BODY,
                    valueType = SlotValueType.STRING
                ),
                ToolSchemaField(
                    name = FIELD_OVERWRITE,
                    description = "Whether to overwrite an existing document",
                    required = false,
                    slotKind = SensitiveSlotKind.TEXT_BODY,
                    valueType = SlotValueType.BOOLEAN
                )
            ),
            supportsUnattendedRule = true
        ),
        safGateway = safGateway,
        firewall = firewall,
        auditLog = auditLog
    ) {
        override suspend fun execute(
            context: ToolExecutionContext,
            arguments: Map<String, Tainted<SlotValueAst>>
        ): ToolResult {
            val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else System.currentTimeMillis()

            val treeUriTainted = ToolArgumentReader.getString(arguments, FIELD_TREE_URI)
                ?: ToolArgumentReader.getString(arguments, "treeUri")
                ?: ToolArgumentReader.getString(arguments, "uri")
                ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_TREE_URI)

            val fileNameTainted = ToolArgumentReader.getString(arguments, FIELD_FILE_NAME)
                ?: ToolArgumentReader.getString(arguments, "fileName")
                ?: ToolArgumentReader.getString(arguments, "name")
                ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_FILE_NAME)

            val contentTainted = ToolArgumentReader.getRawString(arguments, FIELD_CONTENT)
                ?: ToolArgumentReader.getRawString(arguments, "body")
                ?: ToolArgumentReader.getRawString(arguments, "text")
                ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_CONTENT)

            val rawTreeUri = treeUriTainted.value.trim()
            val rawFileName = fileNameTainted.value.trim()

            if (!SafPlatformGateway.isSafeDocumentName(rawFileName)) {
                recordSafAudit(
                    timestampMs = nowMs,
                    treeUri = rawTreeUri,
                    actionSummary = "Unsafe SAF document name rejected for write: $rawFileName",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = ToolArgumentReader.ERROR_INVALID_ARGUMENTS
                )
                return ToolArgumentReader.invalidArgumentsFailure("file_name: unsafe name or traversal sequence")
            }

            if (!safGateway.hasPersistedGrant(rawTreeUri, requireWrite = true)) {
                recordSafAudit(
                    timestampMs = nowMs,
                    treeUri = rawTreeUri,
                    actionSummary = "SAF write grant missing for tree: $rawTreeUri",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = ToolArgumentReader.ERROR_SAF_GRANT_MISSING
                )
                return ToolResult.Failure(
                    message = UserMessage(
                        key = MessageKey.ERROR_SAF_GRANT_MISSING,
                        args = listOf(MessageArg.Text(rawTreeUri))
                    ),
                    errorCode = ToolArgumentReader.ERROR_SAF_GRANT_MISSING
                )
            }

            val targetDocUriString = "$rawTreeUri/$rawFileName"
            val taintedTargetDocUri: Tainted<String> = treeUriTainted.combineWith(fileNameTainted) { _, _ -> targetDocUriString }

            val firewallDecision = firewall.validateOutboundTarget(
                toolName = metadata.name,
                action = AutomationOutboundActions.ACTION_SAF_WRITE,
                uriOrTarget = taintedTargetDocUri
            )

            val userConfirmed = context.isUserConfirmed && !context.isUnattendedBackground
            val bioApproved = context.isBiometricApproved && !context.isUnattendedBackground
            val hasUntrustedHighRisk = treeUriTainted.isUntrusted || fileNameTainted.isUntrusted

            when (firewallDecision) {
                is FirewallDecision.Denied -> {
                    recordSafAudit(
                        timestampMs = nowMs,
                        treeUri = rawTreeUri,
                        actionSummary = "Denied SAF write target: $targetDocUriString",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = firewallDecision.reasonCode
                    )
                    return ToolArgumentReader.securityFailure(
                        reasonCode = firewallDecision.reasonCode,
                        message = firewallDecision.message
                    )
                }

                is FirewallDecision.RequiresBiometric -> {
                    if (!bioApproved || (hasUntrustedHighRisk && !userConfirmed)) {
                        recordSafAudit(
                            timestampMs = nowMs,
                            treeUri = rawTreeUri,
                            actionSummary = "Biometric confirmation required for SAF write target: $targetDocUriString",
                            provenance = ToolArgumentReader.worstProvenance(arguments),
                            decision = "BIOMETRIC_REQUIRED"
                        )
                        return ToolResult.ConfirmationRequired(
                            message = firewallDecision.message,
                            pendingToolName = metadata.name,
                            targetId = ToolTargetIds.forSafTree(rawTreeUri),
                            canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                            requiresBiometric = true,
                            hasUntrustedHighRiskSlot = hasUntrustedHighRisk
                        )
                    }
                }

                is FirewallDecision.RequiresConfirmation -> {
                    if (!userConfirmed) {
                        recordSafAudit(
                            timestampMs = nowMs,
                            treeUri = rawTreeUri,
                            actionSummary = "User confirmation required for SAF write target: $targetDocUriString",
                            provenance = ToolArgumentReader.worstProvenance(arguments),
                            decision = "CONFIRMATION_REQUIRED"
                        )
                        return ToolResult.ConfirmationRequired(
                            message = firewallDecision.message,
                            pendingToolName = metadata.name,
                            targetId = ToolTargetIds.forSafTree(rawTreeUri),
                            canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                            requiresBiometric = false,
                            hasUntrustedHighRiskSlot = true
                        )
                    }
                }

                FirewallDecision.Authorized -> {
                    // Outbound Channel Taint Barrier: check if arguments contain untrusted or vault content
                    val hasUntrusted = ToolArgumentReader.hasUntrustedArgument(arguments)
                    val hasVault = ToolArgumentReader.hasVaultSourceArgument(arguments)
                    if (hasUntrusted || hasVault) {
                        if (!userConfirmed) {
                            val worst = ToolArgumentReader.worstProvenance(arguments)
                            recordSafAudit(
                                timestampMs = nowMs,
                                treeUri = rawTreeUri,
                                actionSummary = "Taint barrier: SAF write payload contains untrusted or vault content",
                                provenance = worst,
                                decision = "CONFIRMATION_REQUIRED"
                            )
                            return ToolResult.ConfirmationRequired(
                                message = UserMessage(
                                    key = MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE,
                                    args = listOf(MessageArg.ProvenanceBadge(worst))
                                ),
                                pendingToolName = metadata.name,
                                targetId = ToolTargetIds.forSafTree(rawTreeUri),
                                canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                                requiresBiometric = false,
                                hasUntrustedHighRiskSlot = hasUntrustedHighRisk
                            )
                        }
                    }
                }
            }

            val mimeType = ToolArgumentReader.getString(arguments, FIELD_MIME_TYPE)?.value ?: "text/plain"
            val overwrite = ToolArgumentReader.getBoolean(arguments, FIELD_OVERWRITE)?.value ?: true
            val contentBytes = contentTainted.value.toByteArray(Charsets.UTF_8)

            return when (val writeResult = safGateway.writeDocument(
                treeUri = rawTreeUri,
                fileName = rawFileName,
                mimeType = mimeType,
                content = contentBytes,
                overwrite = overwrite
            )) {
                is SafGatewayResult.Success -> {
                    recordSafAudit(
                        timestampMs = nowMs,
                        treeUri = rawTreeUri,
                        actionSummary = "Wrote SAF document: $rawFileName in $rawTreeUri",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = "SUCCESS"
                    )
                    ToolResult.Success(
                        message = UserMessage(
                            key = MessageKey.ACTION_SAF_FILE_WRITTEN,
                            args = listOf(MessageArg.Text(rawFileName))
                        ),
                        outputValues = mapOf(
                            "document_uri" to writeResult.value.documentUri,
                            FIELD_FILE_NAME to writeResult.value.displayName,
                            "size_bytes" to writeResult.value.sizeBytes.toString()
                        )
                    )
                }

                is SafGatewayResult.GrantMissing -> {
                    recordSafAudit(
                        timestampMs = nowMs,
                        treeUri = rawTreeUri,
                        actionSummary = "SAF grant missing during write: $rawTreeUri",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = ToolArgumentReader.ERROR_SAF_GRANT_MISSING
                    )
                    ToolResult.Failure(
                        message = UserMessage(
                            key = MessageKey.ERROR_SAF_GRANT_MISSING,
                            args = listOf(MessageArg.Text(rawTreeUri))
                        ),
                        errorCode = ToolArgumentReader.ERROR_SAF_GRANT_MISSING
                    )
                }

                is SafGatewayResult.NotFound -> {
                    ToolArgumentReader.notFoundFailure(rawFileName)
                }

                is SafGatewayResult.Unavailable -> {
                    recordSafAudit(
                        timestampMs = nowMs,
                        treeUri = rawTreeUri,
                        actionSummary = "SAF document write unavailable: ${writeResult.reason}",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = ToolArgumentReader.ERROR_PLATFORM_UNAVAILABLE
                    )
                    ToolArgumentReader.platformUnavailableFailure(writeResult.reason)
                }
            }
        }
    }

    /**
     * SAF document delete tool (`saf_delete`).
     */
    class Delete(
        safGateway: SafPlatformGateway,
        firewall: SecurityFirewallPort,
        auditLog: AuditLogPort
    ) : SafDirectoryTool(
        metadata = ToolMetadata(
            name = AutomationToolNames.SAF_DELETE,
            displayNameKey = "action_saf_file_deleted",
            description = "Deletes a document from a granted SAF directory",
            category = ToolCategory.NOTES_FILES,
            requiredCapability = AtomicCapability.MODIFY_DELETE_SEND,
            schemaVersion = 1,
            fields = listOf(
                ToolSchemaField(
                    name = FIELD_TREE_URI,
                    description = "Persisted SAF directory tree URI",
                    required = true,
                    slotKind = SensitiveSlotKind.EXTERNAL_URI,
                    valueType = SlotValueType.STRING
                ),
                ToolSchemaField(
                    name = FIELD_FILE_NAME,
                    description = "Document display name to delete",
                    required = true,
                    slotKind = SensitiveSlotKind.FILE_PATH,
                    valueType = SlotValueType.STRING
                )
            ),
            supportsUnattendedRule = false
        ),
        safGateway = safGateway,
        firewall = firewall,
        auditLog = auditLog
    ) {
        override suspend fun execute(
            context: ToolExecutionContext,
            arguments: Map<String, Tainted<SlotValueAst>>
        ): ToolResult {
            val nowMs = if (context.issuedAtEpochMs > 0L) context.issuedAtEpochMs else System.currentTimeMillis()

            if (context.isUnattendedBackground) {
                recordSafAudit(
                    timestampMs = nowMs,
                    treeUri = "unknown",
                    actionSummary = "Security violation: saf_delete attempted in unattended background",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = "SECURITY_VIOLATION"
                )
                return ToolArgumentReader.securityFailure("UNATTENDED_SAF_DELETE_FORBIDDEN")
            }

            val treeUriTainted = ToolArgumentReader.getString(arguments, FIELD_TREE_URI)
                ?: ToolArgumentReader.getString(arguments, "treeUri")
                ?: ToolArgumentReader.getString(arguments, "uri")
                ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_TREE_URI)

            val fileNameTainted = ToolArgumentReader.getString(arguments, FIELD_FILE_NAME)
                ?: ToolArgumentReader.getString(arguments, "fileName")
                ?: ToolArgumentReader.getString(arguments, "name")
                ?: return ToolArgumentReader.invalidArgumentsFailure(FIELD_FILE_NAME)

            val rawTreeUri = treeUriTainted.value.trim()
            val rawFileName = fileNameTainted.value.trim()

            if (!SafPlatformGateway.isSafeDocumentName(rawFileName)) {
                recordSafAudit(
                    timestampMs = nowMs,
                    treeUri = rawTreeUri,
                    actionSummary = "Unsafe SAF document name rejected for delete: $rawFileName",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = ToolArgumentReader.ERROR_INVALID_ARGUMENTS
                )
                return ToolArgumentReader.invalidArgumentsFailure("file_name: unsafe name or traversal sequence")
            }

            if (!safGateway.hasPersistedGrant(rawTreeUri, requireWrite = true)) {
                recordSafAudit(
                    timestampMs = nowMs,
                    treeUri = rawTreeUri,
                    actionSummary = "SAF write grant missing for delete in tree: $rawTreeUri",
                    provenance = ToolArgumentReader.worstProvenance(arguments),
                    decision = ToolArgumentReader.ERROR_SAF_GRANT_MISSING
                )
                return ToolResult.Failure(
                    message = UserMessage(
                        key = MessageKey.ERROR_SAF_GRANT_MISSING,
                        args = listOf(MessageArg.Text(rawTreeUri))
                    ),
                    errorCode = ToolArgumentReader.ERROR_SAF_GRANT_MISSING
                )
            }

            val targetDocUriString = "$rawTreeUri/$rawFileName"
            val taintedTargetDocUri: Tainted<String> = treeUriTainted.combineWith(fileNameTainted) { _, _ -> targetDocUriString }

            val firewallDecision = firewall.validateOutboundTarget(
                toolName = metadata.name,
                action = AutomationOutboundActions.ACTION_SAF_WRITE,
                uriOrTarget = taintedTargetDocUri
            )

            val userConfirmed = context.isUserConfirmed && !context.isUnattendedBackground
            val bioApproved = context.isBiometricApproved && !context.isUnattendedBackground
            val hasUntrustedHighRisk = treeUriTainted.isUntrusted || fileNameTainted.isUntrusted

            when (firewallDecision) {
                is FirewallDecision.Denied -> {
                    recordSafAudit(
                        timestampMs = nowMs,
                        treeUri = rawTreeUri,
                        actionSummary = "Denied SAF delete target: $targetDocUriString",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = firewallDecision.reasonCode
                    )
                    return ToolArgumentReader.securityFailure(
                        reasonCode = firewallDecision.reasonCode,
                        message = firewallDecision.message
                    )
                }

                is FirewallDecision.RequiresBiometric -> {
                    if (!bioApproved || (hasUntrustedHighRisk && !userConfirmed)) {
                        recordSafAudit(
                            timestampMs = nowMs,
                            treeUri = rawTreeUri,
                            actionSummary = "Biometric confirmation required for SAF delete target: $targetDocUriString",
                            provenance = ToolArgumentReader.worstProvenance(arguments),
                            decision = "BIOMETRIC_REQUIRED"
                        )
                        return ToolResult.ConfirmationRequired(
                            message = firewallDecision.message,
                            pendingToolName = metadata.name,
                            targetId = ToolTargetIds.forSafTree(rawTreeUri),
                            canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                            requiresBiometric = true,
                            hasUntrustedHighRiskSlot = hasUntrustedHighRisk
                        )
                    }
                }

                is FirewallDecision.RequiresConfirmation -> {
                    if (!userConfirmed) {
                        recordSafAudit(
                            timestampMs = nowMs,
                            treeUri = rawTreeUri,
                            actionSummary = "User confirmation required for SAF delete target: $targetDocUriString",
                            provenance = ToolArgumentReader.worstProvenance(arguments),
                            decision = "CONFIRMATION_REQUIRED"
                        )
                        return ToolResult.ConfirmationRequired(
                            message = firewallDecision.message,
                            pendingToolName = metadata.name,
                            targetId = ToolTargetIds.forSafTree(rawTreeUri),
                            canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                            requiresBiometric = false,
                            hasUntrustedHighRiskSlot = true
                        )
                    }
                }

                FirewallDecision.Authorized -> {
                    val hasUntrusted = treeUriTainted.isUntrusted || fileNameTainted.isUntrusted || ToolArgumentReader.hasUntrustedArgument(arguments)
                    val hasVault = ToolArgumentReader.hasVaultSourceArgument(arguments)
                    if (hasUntrusted || hasVault) {
                        if (!userConfirmed) {
                            val worst = ToolArgumentReader.worstProvenance(arguments)
                            recordSafAudit(
                                timestampMs = nowMs,
                                treeUri = rawTreeUri,
                                actionSummary = "Confirmation required for SAF delete with untrusted/vault arguments: $targetDocUriString (worstProvenance=$worst)",
                                provenance = worst,
                                decision = "CONFIRMATION_REQUIRED"
                            )
                            return ToolResult.ConfirmationRequired(
                                message = UserMessage(
                                    key = MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE,
                                    args = listOf(MessageArg.ProvenanceBadge(worst))
                                ),
                                pendingToolName = metadata.name,
                                targetId = ToolTargetIds.forSafTree(rawTreeUri),
                                canonicalArguments = ToolArgumentReader.toCanonicalDisplayMap(arguments),
                                requiresBiometric = false,
                                hasUntrustedHighRiskSlot = hasUntrustedHighRisk
                            )
                        }
                    }
                }
            }

            return when (val deleteResult = safGateway.deleteDocument(rawTreeUri, rawFileName)) {
                is SafGatewayResult.Success -> {
                    recordSafAudit(
                        timestampMs = nowMs,
                        treeUri = rawTreeUri,
                        actionSummary = "Deleted SAF document: $rawFileName in $rawTreeUri",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = "SUCCESS"
                    )
                    ToolResult.Success(
                        message = UserMessage(
                            key = MessageKey.ACTION_SAF_FILE_DELETED,
                            args = listOf(MessageArg.Text(rawFileName))
                        ),
                        outputValues = mapOf(
                            FIELD_FILE_NAME to rawFileName,
                            "deleted" to deleteResult.value.toString()
                        )
                    )
                }

                is SafGatewayResult.NotFound -> {
                    recordSafAudit(
                        timestampMs = nowMs,
                        treeUri = rawTreeUri,
                        actionSummary = "SAF document to delete not found: $rawFileName",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = ToolArgumentReader.ERROR_NOT_FOUND
                    )
                    ToolArgumentReader.notFoundFailure(rawFileName)
                }

                is SafGatewayResult.GrantMissing -> {
                    recordSafAudit(
                        timestampMs = nowMs,
                        treeUri = rawTreeUri,
                        actionSummary = "SAF grant missing during delete: $rawTreeUri",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = ToolArgumentReader.ERROR_SAF_GRANT_MISSING
                    )
                    ToolResult.Failure(
                        message = UserMessage(
                            key = MessageKey.ERROR_SAF_GRANT_MISSING,
                            args = listOf(MessageArg.Text(rawTreeUri))
                        ),
                        errorCode = ToolArgumentReader.ERROR_SAF_GRANT_MISSING
                    )
                }

                is SafGatewayResult.Unavailable -> {
                    recordSafAudit(
                        timestampMs = nowMs,
                        treeUri = rawTreeUri,
                        actionSummary = "SAF document delete unavailable: ${deleteResult.reason}",
                        provenance = ToolArgumentReader.worstProvenance(arguments),
                        decision = ToolArgumentReader.ERROR_PLATFORM_UNAVAILABLE
                    )
                    ToolArgumentReader.platformUnavailableFailure(deleteResult.reason)
                }
            }
        }
    }

    companion object {
        const val FIELD_TREE_URI: String = "tree_uri"
        const val FIELD_FILE_NAME: String = "file_name"
        const val FIELD_CONTENT: String = "content"
        const val FIELD_MIME_TYPE: String = "mime_type"
        const val FIELD_OVERWRITE: String = "overwrite"

        fun createReadTool(
            safGateway: SafPlatformGateway,
            firewall: SecurityFirewallPort,
            auditLog: AuditLogPort
        ): NavaTool = Read(safGateway, firewall, auditLog)

        fun createWriteTool(
            safGateway: SafPlatformGateway,
            firewall: SecurityFirewallPort,
            auditLog: AuditLogPort
        ): NavaTool = Write(safGateway, firewall, auditLog)

        fun createDeleteTool(
            safGateway: SafPlatformGateway,
            firewall: SecurityFirewallPort,
            auditLog: AuditLogPort
        ): NavaTool = Delete(safGateway, firewall, auditLog)

        fun createAll(
            safGateway: SafPlatformGateway,
            firewall: SecurityFirewallPort,
            auditLog: AuditLogPort
        ): List<NavaTool> = listOf(
            createReadTool(safGateway, firewall, auditLog),
            createWriteTool(safGateway, firewall, auditLog),
            createDeleteTool(safGateway, firewall, auditLog)
        )
    }
}

typealias SafReadTool = SafDirectoryTool.Read
typealias SafWriteTool = SafDirectoryTool.Write
typealias SafDeleteTool = SafDirectoryTool.Delete

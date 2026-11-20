package com.nava.app.redteam

import com.nava.core.security.crypto.CryptoKeyProvider
import com.nava.core.security.crypto.HmacSha256Engine
import com.nava.core.security.crypto.SecureMemory
import com.nava.core.security.dao.AuditLogDao
import com.nava.core.security.dao.EncryptedNoteDao
import com.nava.core.security.firewall.OutboundChannelPolicy
import com.nava.core.security.firewall.SecurityFirewall
import com.nava.core.security.policy.PermissionProfileManager
import com.nava.core.security.policy.RuleCapabilityGrantManager
import com.nava.core.security.storage.EncryptedRowStorage
import com.nava.core.security.storage.EncryptedSqliteStore
import com.nava.core.security.storage.EncryptedTableSchema
import com.nava.core.security.storage.RawEncryptedRow
import com.nava.core.security.storage.StructuredPayloadCodec
import com.nava.core.security.vault.NavaVault
import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.automation.RoutineExecutionOutcome
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.PermissionProfilePreset
import com.nava.domain.security.RuleActionSpec
import com.nava.domain.security.RuleApprovalState
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.RuleTriggerSpec
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.StoredNote
import com.nava.domain.security.Tainted
import com.nava.domain.security.VaultPort
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolRegistry
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.UserMessage
import com.nava.domain.usecase.ExecutePlanUseCase
import com.nava.feature.automations.alarm.AlarmTimerTool
import com.nava.feature.automations.applaunch.AppLaunchTool
import com.nava.feature.automations.calendar.CalendarTool
import com.nava.feature.automations.call.CallIntentTool
import com.nava.feature.automations.common.AutomationIntentGateway
import com.nava.feature.automations.common.AutomationNotificationBridge
import com.nava.feature.automations.common.AutomationToolNames
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
import com.nava.feature.automations.common.ToolTargetIds
import com.nava.feature.automations.notes.NotesVaultTool
import com.nava.feature.automations.routine.RoutineExecutor
import com.nava.feature.automations.routine.RoutineWorkScheduler
import com.nava.feature.automations.saf.SafDirectoryTool
import com.nava.feature.automations.sms.SmsDraftTool
import java.io.File
import java.nio.file.Files
import java.util.Locale
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Gate 2 Real-Firewall End-to-End Integration Red-Team Suite for Phase 4 (`:app` test scope).
 *
 * Wires the REAL production implementations across `:domain`, `:core-security-data`, and
 * `:feature-automations`:
 * - [SecurityFirewall], [OutboundChannelPolicy], [PermissionProfileManager],
 *   [RuleCapabilityGrantManager], [HmacSha256Engine], [EncryptedSqliteStore], [AuditLogDao],
 *   [EncryptedNoteDao], and [NavaVault].
 * - [ExecutePlanUseCase], [ToolRegistry], and [ToolExecutionContext].
 * - [SmsDraftTool], [CallIntentTool], [CalendarTool], [SafDirectoryTool], [AppLaunchTool],
 *   [NotesVaultTool], [AlarmTimerTool], and [RoutineExecutor].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class Phase4RealFirewallRedTeamTest {

    private val nowMs: Long = 1_760_000_000_000L
    private val nowEpochSec: Long = nowMs / 1000L
    private val safTreeUri: String = "content://com.android.externalstorage.documents/tree/primary%3ADocuments"

    // -------------------------------------------------------------------------
    // Section 1: End-to-End HIGH-2 Verification (Real SecurityFirewall + OutboundChannelPolicy)
    // -------------------------------------------------------------------------

    @Test
    fun high2_calendarModifyUpdate_passesRealFirewallAndOutboundPolicyOnceConfirmed() = runTest {
        withRealHarness { h ->
            h.assignCustomProfile(
                targetId = ToolTargetIds.CALENDAR,
                capabilities = mapOf(
                    AtomicCapability.DATA_READ to ConfirmationLevel.AUTO,
                    AtomicCapability.CREATE_DRAFT to ConfirmationLevel.AUTO,
                    AtomicCapability.MODIFY_DELETE_SEND to ConfirmationLevel.PROMPT_CARD
                )
            )
            h.calendarGateway.seedEvent(
                CalendarEventRecord(
                    eventId = 42L,
                    calendarId = 1L,
                    title = "Initial Sync",
                    startEpochMs = nowMs + 3_600_000L,
                    endEpochMs = nowMs + 7_200_000L
                )
            )

            val token = h.firewall.mintToken(
                requestId = "req-cal-update",
                utteranceProvenance = DataProvenance.USER_UTTERANCE,
                candidateTools = setOf(AutomationToolNames.CALENDAR_MODIFY),
                nowEpochMs = nowMs
            )
            val plan = PlanAst(
                planId = "plan-cal-update",
                calls = listOf(
                    ToolCallAst(
                        toolName = AutomationToolNames.CALENDAR_MODIFY,
                        arguments = mapOf(
                            "operation" to Tainted.fromUserUtterance(
                                SlotValueAst.StringValue("update"),
                                SensitiveSlotKind.TEXT_BODY
                            ),
                            "event_id" to Tainted.fromUserUtterance(
                                SlotValueAst.IntValue(42L),
                                SensitiveSlotKind.EVENT_TITLE
                            ),
                            "title" to Tainted.fromUserUtterance(
                                SlotValueAst.StringValue("Updated Architecture Sync"),
                                SensitiveSlotKind.EVENT_TITLE
                            )
                        ),
                        orderIndex = 0,
                        targetId = ToolTargetIds.CALENDAR
                    )
                )
            )

            val pass1 = h.executePlan(
                plan = plan,
                capabilityToken = token,
                targetId = ToolTargetIds.CALENDAR,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = emptySet()
            )
            assertEquals(1, pass1.size)
            assertTrue(
                "Pass 1 must request confirmation, not deny via OutboundChannelPolicy; got ${pass1[0]}",
                pass1[0] is ToolResult.ConfirmationRequired
            )
            assertEquals(0, h.calendarGateway.updatedEvents.size)

            val pass2 = h.executePlan(
                plan = plan,
                capabilityToken = token,
                targetId = ToolTargetIds.CALENDAR,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = setOf(0)
            )
            assertEquals(1, pass2.size)
            assertTrue(
                "Pass 2 with user confirmation must succeed through real SecurityFirewall + OutboundChannelPolicy; got ${pass2[0]}",
                pass2[0] is ToolResult.Success
            )
            assertEquals(1, h.calendarGateway.updatedEvents.size)
            assertEquals(42L, h.calendarGateway.updatedEvents[0].first)
            assertEquals("Updated Architecture Sync", h.calendarGateway.updatedEvents[0].second.title)
        }
    }

    @Test
    fun high2_calendarModifyDelete_passesRealFirewallAndOutboundPolicyOnceConfirmed() = runTest {
        withRealHarness { h ->
            h.assignCustomProfile(
                targetId = ToolTargetIds.CALENDAR,
                capabilities = mapOf(
                    AtomicCapability.DATA_READ to ConfirmationLevel.AUTO,
                    AtomicCapability.CREATE_DRAFT to ConfirmationLevel.AUTO,
                    AtomicCapability.MODIFY_DELETE_SEND to ConfirmationLevel.PROMPT_CARD
                )
            )
            h.calendarGateway.seedEvent(
                CalendarEventRecord(
                    eventId = 99L,
                    calendarId = 1L,
                    title = "Deprecated Meeting",
                    startEpochMs = nowMs + 3_600_000L,
                    endEpochMs = nowMs + 7_200_000L
                )
            )

            val token = h.firewall.mintToken(
                requestId = "req-cal-delete",
                utteranceProvenance = DataProvenance.USER_UTTERANCE,
                candidateTools = setOf(AutomationToolNames.CALENDAR_MODIFY),
                nowEpochMs = nowMs
            )
            val plan = PlanAst(
                planId = "plan-cal-delete",
                calls = listOf(
                    ToolCallAst(
                        toolName = AutomationToolNames.CALENDAR_MODIFY,
                        arguments = mapOf(
                            "operation" to Tainted.fromUserUtterance(
                                SlotValueAst.StringValue("delete"),
                                SensitiveSlotKind.TEXT_BODY
                            ),
                            "event_id" to Tainted.fromUserUtterance(
                                SlotValueAst.IntValue(99L),
                                SensitiveSlotKind.EVENT_TITLE
                            )
                        ),
                        orderIndex = 0,
                        targetId = ToolTargetIds.CALENDAR
                    )
                )
            )

            val pass1 = h.executePlan(
                plan = plan,
                capabilityToken = token,
                targetId = ToolTargetIds.CALENDAR,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = emptySet()
            )
            assertEquals(1, pass1.size)
            assertTrue(
                "Pass 1 delete must request confirmation, not deny; got ${pass1[0]}",
                pass1[0] is ToolResult.ConfirmationRequired
            )
            assertEquals(0, h.calendarGateway.deletedEventIds.size)

            val pass2 = h.executePlan(
                plan = plan,
                capabilityToken = token,
                targetId = ToolTargetIds.CALENDAR,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = setOf(0)
            )
            assertEquals(1, pass2.size)
            assertTrue(
                "Pass 2 delete with user confirmation must succeed; got ${pass2[0]}",
                pass2[0] is ToolResult.Success
            )
            assertEquals(listOf(99L), h.calendarGateway.deletedEventIds)
        }
    }

    @Test
    fun high2_appLaunchByTier1AppName_passesRealFirewallAndOutboundPolicy() = runTest {
        withRealHarness { h ->
            h.assignAutoSafeProfile(ToolTargetIds.APP_LAUNCH)
            h.intentGateway.appLabelsToPackages["Calculator"] = "com.android.calculator2"

            val token = h.firewall.mintToken(
                requestId = "req-app-launch-calc",
                utteranceProvenance = DataProvenance.USER_UTTERANCE,
                candidateTools = setOf(AutomationToolNames.LAUNCH_APP),
                nowEpochMs = nowMs
            )
            val plan = PlanAst(
                planId = "plan-app-launch-calc",
                calls = listOf(
                    ToolCallAst(
                        toolName = AutomationToolNames.LAUNCH_APP,
                        arguments = mapOf(
                            "app_name" to Tainted.fromUserUtterance(
                                SlotValueAst.StringValue("Calculator")
                            )
                        ),
                        orderIndex = 0,
                        targetId = ToolTargetIds.APP_LAUNCH
                    )
                )
            )

            val results = h.executePlan(
                plan = plan,
                capabilityToken = token,
                targetId = ToolTargetIds.APP_LAUNCH,
                languageTag = "en-US",
                nowEpochMs = nowMs
            )
            assertEquals(1, results.size)
            val success = results[0] as? ToolResult.Success
                ?: fail("Expected ToolResult.Success for Tier 1 app_name='Calculator', got ${results[0]}")
            assertEquals("com.android.calculator2", success.outputValues["package_name"])
            assertEquals(listOf("com.android.calculator2"), h.intentGateway.launchedPackages)
        }
    }

    @Test
    fun high2_appLaunchMaliciousPackageName_hardDeniedEvenWhenConfirmed() = runTest {
        withRealHarness { h ->
            h.assignAutoSafeProfile(ToolTargetIds.APP_LAUNCH)

            val maliciousPackages = listOf(
                "https://evil.com",
                "http://127.0.0.1/exfil",
                "intent:#Intent;action=android.intent.action.VIEW;S.url=https://evil.com;end",
                "javascript:alert(1)",
                "file:///etc/passwd"
            )

            for ((idx, payload) in maliciousPackages.withIndex()) {
                val token = h.firewall.mintToken(
                    requestId = "req-malicious-pkg-$idx",
                    utteranceProvenance = DataProvenance.USER_UTTERANCE,
                    candidateTools = setOf(AutomationToolNames.LAUNCH_APP),
                    nowEpochMs = nowMs
                )
                val plan = PlanAst(
                    planId = "plan-malicious-pkg-$idx",
                    calls = listOf(
                        ToolCallAst(
                            toolName = AutomationToolNames.LAUNCH_APP,
                            arguments = mapOf(
                                "package_name" to Tainted.fromUserUtterance(
                                    SlotValueAst.StringValue(payload),
                                    SensitiveSlotKind.PACKAGE_NAME
                                )
                            ),
                            orderIndex = 0,
                            targetId = ToolTargetIds.APP_LAUNCH
                        )
                    )
                )

                val results = h.executePlan(
                    plan = plan,
                    capabilityToken = token,
                    targetId = ToolTargetIds.APP_LAUNCH,
                    languageTag = "en-US",
                    nowEpochMs = nowMs,
                    confirmedStepIndices = setOf(0),
                    biometricApprovedStepIndices = setOf(0)
                )
                assertEquals(1, results.size)
                val failure = results[0] as? ToolResult.Failure
                    ?: fail("Malicious package_name '$payload' MUST fail, got ${results[0]}")
                assertTrue(
                    "Malicious package_name '$payload' MUST set isSecurityViolation=true",
                    failure.isSecurityViolation
                )
            }
            assertEquals(0, h.intentGateway.launchedPackages.size)
        }
    }

    @Test
    fun high2_appLaunchRogueGatewayResolvingMaliciousUri_hardDeniedAtOutboundBarrierEvenWhenConfirmed() = runTest {
        withRealHarness { h ->
            h.assignAutoSafeProfile(ToolTargetIds.APP_LAUNCH)
            val roguePayloads = listOf(
                "RogueHttpApp" to "https://evil.com/leak",
                "RogueIntentApp" to "intent:#Intent;action=android.intent.action.VIEW;end"
            )

            for ((label, resolvedMaliciousTarget) in roguePayloads) {
                h.intentGateway.appLabelsToPackages[label] = resolvedMaliciousTarget

                val token = h.firewall.mintToken(
                    requestId = "req-rogue-$label",
                    utteranceProvenance = DataProvenance.USER_UTTERANCE,
                    candidateTools = setOf(AutomationToolNames.LAUNCH_APP),
                    nowEpochMs = nowMs
                )
                val plan = PlanAst(
                    planId = "plan-rogue-$label",
                    calls = listOf(
                        ToolCallAst(
                            toolName = AutomationToolNames.LAUNCH_APP,
                            arguments = mapOf(
                                "app_name" to Tainted.fromUserUtterance(
                                    SlotValueAst.StringValue(label)
                                )
                            ),
                            orderIndex = 0,
                            targetId = ToolTargetIds.APP_LAUNCH
                        )
                    )
                )

                val results = h.executePlan(
                    plan = plan,
                    capabilityToken = token,
                    targetId = ToolTargetIds.APP_LAUNCH,
                    languageTag = "en-US",
                    nowEpochMs = nowMs,
                    confirmedStepIndices = setOf(0),
                    biometricApprovedStepIndices = setOf(0)
                )
                assertEquals(1, results.size)
                val failure = results[0] as? ToolResult.Failure
                    ?: fail("Rogue resolved URI '$resolvedMaliciousTarget' MUST be denied, got ${results[0]}")
                assertTrue(
                    "Rogue resolved URI '$resolvedMaliciousTarget' MUST be a security violation",
                    failure.isSecurityViolation
                )
            }
            assertEquals(0, h.intentGateway.launchedPackages.size)
        }
    }

    // -------------------------------------------------------------------------
    // Section 2: End-to-End HIGH-1 Verification (Stage 2 Approval Without Confirmation Deadlock)
    // -------------------------------------------------------------------------

    @Test
    fun high1_smsDraftUntrustedArguments_pass1ConfirmationRequired_pass2SucceedsOnce() = runTest {
        withRealHarness { h ->
            h.assignAutoSafeProfile(ToolTargetIds.SMS)

            val token = h.firewall.mintToken(
                requestId = "req-sms-untrusted",
                utteranceProvenance = DataProvenance.USER_UTTERANCE,
                candidateTools = setOf(AutomationToolNames.CREATE_SMS_DRAFT),
                nowEpochMs = nowMs
            )
            val plan = PlanAst(
                planId = "plan-sms-untrusted",
                calls = listOf(
                    ToolCallAst(
                        toolName = AutomationToolNames.CREATE_SMS_DRAFT,
                        arguments = mapOf(
                            "recipient" to Tainted.fromUntrustedExternal(
                                value = SlotValueAst.StringValue("+15550199"),
                                slotKind = SensitiveSlotKind.PHONE_NUMBER,
                                sourceLabel = "notification:com.example.chat"
                            ),
                            "body" to Tainted.fromUntrustedExternal(
                                value = SlotValueAst.StringValue("See you at 5pm"),
                                slotKind = SensitiveSlotKind.TEXT_BODY,
                                sourceLabel = "notification:com.example.chat"
                            )
                        ),
                        orderIndex = 0,
                        targetId = ToolTargetIds.SMS
                    )
                )
            )

            val pass1 = h.executePlan(
                plan = plan,
                capabilityToken = token,
                targetId = ToolTargetIds.SMS,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = emptySet()
            )
            assertEquals(1, pass1.size)
            val confirm = pass1[0] as? ToolResult.ConfirmationRequired
                ?: fail("Pass 1 untrusted SMS draft MUST require confirmation, got ${pass1[0]}")
            assertTrue("Untrusted phone_number MUST set hasUntrustedHighRiskSlot=true", confirm.hasUntrustedHighRiskSlot)
            assertEquals(0, h.intentGateway.smsDrafts.size)

            val pass2 = h.executePlan(
                plan = plan,
                capabilityToken = token,
                targetId = ToolTargetIds.SMS,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = setOf(0)
            )
            assertEquals(1, pass2.size)
            assertTrue(
                "Pass 2 confirmed SMS draft MUST succeed without confirmation deadlock, got ${pass2[0]}",
                pass2[0] is ToolResult.Success
            )
            assertEquals(1, h.intentGateway.smsDrafts.size)
            assertEquals("+15550199" to "See you at 5pm", h.intentGateway.smsDrafts[0])
        }
    }

    @Test
    fun high1_smsDraftUntrustedBodyOnly_pass1ConfirmationRequired_pass2SucceedsOnce() = runTest {
        withRealHarness { h ->
            h.assignAutoSafeProfile(ToolTargetIds.SMS)

            val token = h.firewall.mintToken(
                requestId = "req-sms-untrusted-body",
                utteranceProvenance = DataProvenance.USER_UTTERANCE,
                candidateTools = setOf(AutomationToolNames.CREATE_SMS_DRAFT),
                nowEpochMs = nowMs
            )
            val plan = PlanAst(
                planId = "plan-sms-untrusted-body",
                calls = listOf(
                    ToolCallAst(
                        toolName = AutomationToolNames.CREATE_SMS_DRAFT,
                        arguments = mapOf(
                            "recipient" to Tainted.fromUserUtterance(
                                value = SlotValueAst.StringValue("+15550188"),
                                slotKind = SensitiveSlotKind.PHONE_NUMBER
                            ),
                            "body" to Tainted.fromUntrustedExternal(
                                value = SlotValueAst.StringValue("Forwarded summary from email"),
                                slotKind = SensitiveSlotKind.TEXT_BODY,
                                sourceLabel = "notification:com.example.mail"
                            )
                        ),
                        orderIndex = 0,
                        targetId = ToolTargetIds.SMS
                    )
                )
            )

            val pass1 = h.executePlan(
                plan = plan,
                capabilityToken = token,
                targetId = ToolTargetIds.SMS,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = emptySet()
            )
            assertEquals(1, pass1.size)
            val confirm = pass1[0] as? ToolResult.ConfirmationRequired
                ?: fail("Pass 1 SMS draft with untrusted body MUST require confirmation, got ${pass1[0]}")
            assertTrue(confirm.hasUntrustedHighRiskSlot)
            assertEquals(0, h.intentGateway.smsDrafts.size)

            val pass2 = h.executePlan(
                plan = plan,
                capabilityToken = token,
                targetId = ToolTargetIds.SMS,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = setOf(0)
            )
            assertEquals(1, pass2.size)
            assertTrue(
                "Pass 2 confirmed SMS draft with untrusted body MUST succeed, got ${pass2[0]}",
                pass2[0] is ToolResult.Success
            )
            assertEquals(1, h.intentGateway.smsDrafts.size)
        }
    }

    @Test
    fun high1_callIntentDialAndPlaceUntrustedNumber_pass1ConfirmationRequired_pass2SucceedsOnce() = runTest {
        withRealHarness { h ->
            h.assignAutoSafeProfile(ToolTargetIds.PHONE)
            h.intentGateway.grantedRuntimePermissions.add("android.permission.CALL_PHONE")

            // DialCallTool (CREATE_DRAFT)
            val dialToken = h.firewall.mintToken(
                requestId = "req-dial-untrusted",
                utteranceProvenance = DataProvenance.USER_UTTERANCE,
                candidateTools = setOf(AutomationToolNames.DIAL_CALL),
                nowEpochMs = nowMs
            )
            val dialPlan = PlanAst(
                planId = "plan-dial-untrusted",
                calls = listOf(
                    ToolCallAst(
                        toolName = AutomationToolNames.DIAL_CALL,
                        arguments = mapOf(
                            "phone_number" to Tainted.fromUntrustedExternal(
                                value = SlotValueAst.StringValue("+15550123"),
                                slotKind = SensitiveSlotKind.PHONE_NUMBER,
                                sourceLabel = "calendar:event-7"
                            )
                        ),
                        orderIndex = 0,
                        targetId = ToolTargetIds.PHONE
                    )
                )
            )

            val dialPass1 = h.executePlan(
                plan = dialPlan,
                capabilityToken = dialToken,
                targetId = ToolTargetIds.PHONE,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = emptySet()
            )
            assertEquals(1, dialPass1.size)
            val dialConfirm = dialPass1[0] as? ToolResult.ConfirmationRequired
                ?: fail("Pass 1 untrusted dial_call MUST require confirmation, got ${dialPass1[0]}")
            assertTrue(dialConfirm.hasUntrustedHighRiskSlot)
            assertEquals(0, h.intentGateway.dialedNumbers.size)

            val dialPass2 = h.executePlan(
                plan = dialPlan,
                capabilityToken = dialToken,
                targetId = ToolTargetIds.PHONE,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = setOf(0)
            )
            assertEquals(1, dialPass2.size)
            assertTrue(
                "Pass 2 confirmed dial_call MUST succeed without deadlock, got ${dialPass2[0]}",
                dialPass2[0] is ToolResult.Success
            )
            assertEquals(listOf("+15550123"), h.intentGateway.dialedNumbers)

            // PlaceCallTool (MODIFY_DELETE_SEND)
            val placeToken = h.firewall.mintToken(
                requestId = "req-place-untrusted",
                utteranceProvenance = DataProvenance.USER_UTTERANCE,
                candidateTools = setOf(AutomationToolNames.PLACE_CALL),
                nowEpochMs = nowMs
            )
            val placePlan = PlanAst(
                planId = "plan-place-untrusted",
                calls = listOf(
                    ToolCallAst(
                        toolName = AutomationToolNames.PLACE_CALL,
                        arguments = mapOf(
                            "phone_number" to Tainted.fromUntrustedExternal(
                                value = SlotValueAst.StringValue("+15550124"),
                                slotKind = SensitiveSlotKind.PHONE_NUMBER,
                                sourceLabel = "notification:com.example.voicemail"
                            )
                        ),
                        orderIndex = 0,
                        targetId = ToolTargetIds.PHONE
                    )
                )
            )

            val placePass1 = h.executePlan(
                plan = placePlan,
                capabilityToken = placeToken,
                targetId = ToolTargetIds.PHONE,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = emptySet()
            )
            assertEquals(1, placePass1.size)
            val placeConfirm = placePass1[0] as? ToolResult.ConfirmationRequired
                ?: fail("Pass 1 untrusted place_call MUST require confirmation, got ${placePass1[0]}")
            assertTrue(placeConfirm.hasUntrustedHighRiskSlot)
            assertEquals(0, h.intentGateway.directCalledNumbers.size)

            val placePass2 = h.executePlan(
                plan = placePlan,
                capabilityToken = placeToken,
                targetId = ToolTargetIds.PHONE,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = setOf(0)
            )
            assertEquals(1, placePass2.size)
            assertTrue(
                "Pass 2 confirmed place_call MUST succeed without deadlock, got ${placePass2[0]}",
                placePass2[0] is ToolResult.Success
            )
            assertEquals(listOf("+15550124"), h.intentGateway.directCalledNumbers)
        }
    }

    @Test
    fun high1_calendarCreateUntrustedArguments_pass1ConfirmationRequired_pass2SucceedsOnce() = runTest {
        withRealHarness { h ->
            h.assignAutoSafeProfile(ToolTargetIds.CALENDAR)

            val token = h.firewall.mintToken(
                requestId = "req-cal-create-untrusted",
                utteranceProvenance = DataProvenance.USER_UTTERANCE,
                candidateTools = setOf(AutomationToolNames.CALENDAR_CREATE),
                nowEpochMs = nowMs
            )
            val plan = PlanAst(
                planId = "plan-cal-create-untrusted",
                calls = listOf(
                    ToolCallAst(
                        toolName = AutomationToolNames.CALENDAR_CREATE,
                        arguments = mapOf(
                            "title" to Tainted.fromUntrustedExternal(
                                value = SlotValueAst.StringValue("External Invite Dinner"),
                                slotKind = SensitiveSlotKind.EVENT_TITLE,
                                sourceLabel = "notification:com.example.mail"
                            ),
                            "start_epoch_ms" to Tainted.fromUntrustedExternal(
                                value = SlotValueAst.IntValue(nowMs + 3_600_000L),
                                slotKind = SensitiveSlotKind.DATE_TIME,
                                sourceLabel = "notification:com.example.mail"
                            ),
                            "end_epoch_ms" to Tainted.fromUntrustedExternal(
                                value = SlotValueAst.IntValue(nowMs + 7_200_000L),
                                slotKind = SensitiveSlotKind.DATE_TIME,
                                sourceLabel = "notification:com.example.mail"
                            )
                        ),
                        orderIndex = 0,
                        targetId = ToolTargetIds.CALENDAR
                    )
                )
            )

            val pass1 = h.executePlan(
                plan = plan,
                capabilityToken = token,
                targetId = ToolTargetIds.CALENDAR,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = emptySet()
            )
            assertEquals(1, pass1.size)
            assertTrue(
                "Pass 1 untrusted calendar_create MUST require confirmation, got ${pass1[0]}",
                pass1[0] is ToolResult.ConfirmationRequired
            )
            assertEquals(0, h.calendarGateway.createdDrafts.size)

            val pass2 = h.executePlan(
                plan = plan,
                capabilityToken = token,
                targetId = ToolTargetIds.CALENDAR,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = setOf(0)
            )
            assertEquals(1, pass2.size)
            assertTrue(
                "Pass 2 confirmed calendar_create MUST succeed without deadlock, got ${pass2[0]}",
                pass2[0] is ToolResult.Success
            )
            assertEquals(1, h.calendarGateway.createdDrafts.size)
            assertEquals("External Invite Dinner", h.calendarGateway.createdDrafts[0].title)
        }
    }

    @Test
    fun high1_safWriteUntrustedArguments_pass1ConfirmationRequired_pass2SucceedsOnce() = runTest {
        withRealHarness { h ->
            val safTargetId = ToolTargetIds.forSafTree(safTreeUri)
            h.assignAutoSafeProfile(safTargetId)
            h.safGateway.grantTree(safTreeUri, writable = true)

            val token = h.firewall.mintToken(
                requestId = "req-saf-write-untrusted",
                utteranceProvenance = DataProvenance.USER_UTTERANCE,
                candidateTools = setOf(AutomationToolNames.SAF_WRITE),
                nowEpochMs = nowMs
            )
            val plan = PlanAst(
                planId = "plan-saf-write-untrusted",
                calls = listOf(
                    ToolCallAst(
                        toolName = AutomationToolNames.SAF_WRITE,
                        arguments = mapOf(
                            "tree_uri" to Tainted.fromUntrustedExternal(
                                value = SlotValueAst.StringValue(safTreeUri),
                                slotKind = SensitiveSlotKind.EXTERNAL_URI,
                                sourceLabel = "saf:external-index"
                            ),
                            "file_name" to Tainted.fromUntrustedExternal(
                                value = SlotValueAst.StringValue("meeting-summary.txt"),
                                slotKind = SensitiveSlotKind.FILE_PATH,
                                sourceLabel = "notification:com.example.chat"
                            ),
                            "content" to Tainted.fromUntrustedExternal(
                                value = SlotValueAst.StringValue("Agenda summary notes"),
                                slotKind = SensitiveSlotKind.TEXT_BODY,
                                sourceLabel = "notification:com.example.chat"
                            )
                        ),
                        orderIndex = 0,
                        targetId = safTargetId
                    )
                )
            )

            val pass1 = h.executePlan(
                plan = plan,
                capabilityToken = token,
                targetId = safTargetId,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = emptySet()
            )
            assertEquals(1, pass1.size)
            val confirm = pass1[0] as? ToolResult.ConfirmationRequired
                ?: fail("Pass 1 untrusted saf_write MUST require confirmation, got ${pass1[0]}")
            assertTrue("Untrusted SAF tree_uri/file_name MUST set hasUntrustedHighRiskSlot=true", confirm.hasUntrustedHighRiskSlot)
            assertEquals(0, h.safGateway.writtenDocuments.size)

            val pass2 = h.executePlan(
                plan = plan,
                capabilityToken = token,
                targetId = safTargetId,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = setOf(0)
            )
            assertEquals(1, pass2.size)
            assertTrue(
                "Pass 2 confirmed saf_write MUST succeed without deadlock, got ${pass2[0]}",
                pass2[0] is ToolResult.Success
            )
            assertEquals(1, h.safGateway.writtenDocuments.size)
            assertEquals("meeting-summary.txt", h.safGateway.writtenDocuments[0].second)
        }
    }

    @Test
    fun high1_appLaunchUntrustedPackageAndAppName_pass1ConfirmationRequired_pass2SucceedsOnce() = runTest {
        withRealHarness { h ->
            h.assignAutoSafeProfile(ToolTargetIds.APP_LAUNCH)
            h.intentGateway.appLabelsToPackages["Calculator"] = "com.android.calculator2"
            h.intentGateway.appLabelsToPackages["com.android.calculator2"] = "com.android.calculator2"

            // Case 1: Untrusted package_name (PACKAGE_NAME high-risk slot)
            val pkgToken = h.firewall.mintToken(
                requestId = "req-launch-untrusted-pkg",
                utteranceProvenance = DataProvenance.USER_UTTERANCE,
                candidateTools = setOf(AutomationToolNames.LAUNCH_APP),
                nowEpochMs = nowMs
            )
            val pkgPlan = PlanAst(
                planId = "plan-launch-untrusted-pkg",
                calls = listOf(
                    ToolCallAst(
                        toolName = AutomationToolNames.LAUNCH_APP,
                        arguments = mapOf(
                            "package_name" to Tainted.fromUntrustedExternal(
                                value = SlotValueAst.StringValue("com.android.calculator2"),
                                slotKind = SensitiveSlotKind.PACKAGE_NAME,
                                sourceLabel = "notification:com.example.chat"
                            )
                        ),
                        orderIndex = 0,
                        targetId = ToolTargetIds.APP_LAUNCH
                    )
                )
            )

            val pkgPass1 = h.executePlan(
                plan = pkgPlan,
                capabilityToken = pkgToken,
                targetId = ToolTargetIds.APP_LAUNCH,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = emptySet()
            )
            assertEquals(1, pkgPass1.size)
            val pkgConfirm = pkgPass1[0] as? ToolResult.ConfirmationRequired
                ?: fail("Pass 1 untrusted launch_app(package_name) MUST require confirmation, got ${pkgPass1[0]}")
            assertTrue(pkgConfirm.hasUntrustedHighRiskSlot)
            assertEquals(0, h.intentGateway.launchedPackages.size)

            val pkgPass2 = h.executePlan(
                plan = pkgPlan,
                capabilityToken = pkgToken,
                targetId = ToolTargetIds.APP_LAUNCH,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = setOf(0)
            )
            assertEquals(1, pkgPass2.size)
            assertTrue(
                "Pass 2 confirmed launch_app(package_name) MUST succeed, got ${pkgPass2[0]}",
                pkgPass2[0] is ToolResult.Success
            )
            assertEquals(1, h.intentGateway.launchedPackages.size)

            // Case 2: Untrusted app_name (resolved via gateway to package)
            val nameToken = h.firewall.mintToken(
                requestId = "req-launch-untrusted-name",
                utteranceProvenance = DataProvenance.USER_UTTERANCE,
                candidateTools = setOf(AutomationToolNames.LAUNCH_APP),
                nowEpochMs = nowMs
            )
            val namePlan = PlanAst(
                planId = "plan-launch-untrusted-name",
                calls = listOf(
                    ToolCallAst(
                        toolName = AutomationToolNames.LAUNCH_APP,
                        arguments = mapOf(
                            "app_name" to Tainted.fromUntrustedExternal(
                                value = SlotValueAst.StringValue("Calculator"),
                                slotKind = SensitiveSlotKind.TEXT_BODY,
                                sourceLabel = "notification:com.example.chat"
                            )
                        ),
                        orderIndex = 0,
                        targetId = ToolTargetIds.APP_LAUNCH
                    )
                )
            )

            val namePass1 = h.executePlan(
                plan = namePlan,
                capabilityToken = nameToken,
                targetId = ToolTargetIds.APP_LAUNCH,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = emptySet()
            )
            assertEquals(1, namePass1.size)
            val nameConfirm = namePass1[0] as? ToolResult.ConfirmationRequired
                ?: fail("Pass 1 untrusted launch_app(app_name) MUST require confirmation, got ${namePass1[0]}")
            assertTrue(nameConfirm.hasUntrustedHighRiskSlot)
            assertEquals(1, h.intentGateway.launchedPackages.size)

            val namePass2 = h.executePlan(
                plan = namePlan,
                capabilityToken = nameToken,
                targetId = ToolTargetIds.APP_LAUNCH,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = setOf(0)
            )
            assertEquals(1, namePass2.size)
            assertTrue(
                "Pass 2 confirmed launch_app(app_name) MUST succeed, got ${namePass2[0]}",
                namePass2[0] is ToolResult.Success
            )
            assertEquals(2, h.intentGateway.launchedPackages.size)
        }
    }

    @Test
    fun high1_vaultTaintedContentToStandardNoteAndSms_pass1ConfirmationRequired_pass2SucceedsOnce() = runTest {
        withRealHarness { h ->
            h.assignAutoSafeProfile(ToolTargetIds.NOTES)
            h.assignAutoSafeProfile(ToolTargetIds.SMS)

            val noteToken = h.firewall.mintToken(
                requestId = "req-vault-to-note",
                utteranceProvenance = DataProvenance.USER_UTTERANCE,
                candidateTools = setOf(AutomationToolNames.NOTES_CREATE),
                nowEpochMs = nowMs
            )
            val notePlan = PlanAst(
                planId = "plan-vault-to-note",
                calls = listOf(
                    ToolCallAst(
                        toolName = AutomationToolNames.NOTES_CREATE,
                        arguments = mapOf(
                            "note_id" to Tainted.fromUserUtterance(SlotValueAst.StringValue("copied-note")),
                            "body" to Tainted.fromUntrustedExternal(
                                value = SlotValueAst.StringValue("recovery-phrase-redacted"),
                                slotKind = SensitiveSlotKind.TEXT_BODY,
                                sourceLabel = "vault:backup_codes"
                            )
                        ),
                        orderIndex = 0,
                        targetId = ToolTargetIds.NOTES
                    )
                )
            )

            val notePass1 = h.executePlan(
                plan = notePlan,
                capabilityToken = noteToken,
                targetId = ToolTargetIds.NOTES,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = emptySet()
            )
            assertEquals(1, notePass1.size)
            assertTrue(
                "Pass 1 vault-sourced content to standard note MUST require confirmation, got ${notePass1[0]}",
                notePass1[0] is ToolResult.ConfirmationRequired
            )
            assertEquals(0, h.noteDao.listNotes().size)

            val notePass2 = h.executePlan(
                plan = notePlan,
                capabilityToken = noteToken,
                targetId = ToolTargetIds.NOTES,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = setOf(0)
            )
            assertEquals(1, notePass2.size)
            assertTrue(
                "Pass 2 confirmed vault-sourced content to standard note MUST succeed, got ${notePass2[0]}",
                notePass2[0] is ToolResult.Success
            )
            assertEquals(1, h.noteDao.listNotes().size)

            val smsToken = h.firewall.mintToken(
                requestId = "req-vault-to-sms",
                utteranceProvenance = DataProvenance.USER_UTTERANCE,
                candidateTools = setOf(AutomationToolNames.CREATE_SMS_DRAFT),
                nowEpochMs = nowMs
            )
            val smsPlan = PlanAst(
                planId = "plan-vault-to-sms",
                calls = listOf(
                    ToolCallAst(
                        toolName = AutomationToolNames.CREATE_SMS_DRAFT,
                        arguments = mapOf(
                            "recipient" to Tainted.fromUserUtterance(
                                SlotValueAst.StringValue("+15550177"),
                                SensitiveSlotKind.PHONE_NUMBER
                            ),
                            "body" to Tainted.fromUntrustedExternal(
                                value = SlotValueAst.StringValue("secret-vault-value"),
                                slotKind = SensitiveSlotKind.TEXT_BODY,
                                sourceLabel = "vault:wifi_password"
                            )
                        ),
                        orderIndex = 0,
                        targetId = ToolTargetIds.SMS
                    )
                )
            )

            val smsPass1 = h.executePlan(
                plan = smsPlan,
                capabilityToken = smsToken,
                targetId = ToolTargetIds.SMS,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = emptySet()
            )
            assertEquals(1, smsPass1.size)
            assertTrue(smsPass1[0] is ToolResult.ConfirmationRequired)
            assertEquals(0, h.intentGateway.smsDrafts.size)

            val smsPass2 = h.executePlan(
                plan = smsPlan,
                capabilityToken = smsToken,
                targetId = ToolTargetIds.SMS,
                languageTag = "en-US",
                nowEpochMs = nowMs,
                confirmedStepIndices = setOf(0)
            )
            assertEquals(1, smsPass2.size)
            assertTrue(smsPass2[0] is ToolResult.Success)
            assertEquals(1, h.intentGateway.smsDrafts.size)
        }
    }

    @Test
    fun high1_blockedSchemesAndTraversal_hardDeniedEvenWhenConfirmedAcrossAllTools() = runTest {
        withRealHarness { h ->
            val safTargetId = ToolTargetIds.forSafTree(safTreeUri)
            h.assignAutoSafeProfile(ToolTargetIds.SMS)
            h.assignAutoSafeProfile(ToolTargetIds.PHONE)
            h.assignAutoSafeProfile(safTargetId)
            h.assignAutoSafeProfile(ToolTargetIds.APP_LAUNCH)
            h.safGateway.grantTree(safTreeUri, writable = true)
            h.intentGateway.grantedRuntimePermissions.add("android.permission.CALL_PHONE")

            data class BlockedCase(
                val label: String,
                val toolName: String,
                val targetId: String,
                val args: Map<String, Tainted<SlotValueAst>>
            )

            val blockedCases = listOf(
                BlockedCase(
                    label = "sms-https",
                    toolName = AutomationToolNames.CREATE_SMS_DRAFT,
                    targetId = ToolTargetIds.SMS,
                    args = mapOf(
                        "recipient" to Tainted.fromUntrustedExternal(
                            SlotValueAst.StringValue("https://evil.example/exfil"),
                            SensitiveSlotKind.PHONE_NUMBER
                        ),
                        "body" to Tainted.fromUserUtterance(SlotValueAst.StringValue("hi"))
                    )
                ),
                BlockedCase(
                    label = "sms-javascript",
                    toolName = AutomationToolNames.CREATE_SMS_DRAFT,
                    targetId = ToolTargetIds.SMS,
                    args = mapOf(
                        "recipient" to Tainted.fromUntrustedExternal(
                            SlotValueAst.StringValue("javascript:alert(1)"),
                            SensitiveSlotKind.PHONE_NUMBER
                        ),
                        "body" to Tainted.fromUserUtterance(SlotValueAst.StringValue("hi"))
                    )
                ),
                BlockedCase(
                    label = "dial-https",
                    toolName = AutomationToolNames.DIAL_CALL,
                    targetId = ToolTargetIds.PHONE,
                    args = mapOf(
                        "phone_number" to Tainted.fromUntrustedExternal(
                            SlotValueAst.StringValue("https://evil.example/exfil"),
                            SensitiveSlotKind.PHONE_NUMBER
                        )
                    )
                ),
                BlockedCase(
                    label = "place-javascript",
                    toolName = AutomationToolNames.PLACE_CALL,
                    targetId = ToolTargetIds.PHONE,
                    args = mapOf(
                        "phone_number" to Tainted.fromUntrustedExternal(
                            SlotValueAst.StringValue("javascript:alert(1)"),
                            SensitiveSlotKind.PHONE_NUMBER
                        )
                    )
                ),
                BlockedCase(
                    label = "saf-write-https-tree",
                    toolName = AutomationToolNames.SAF_WRITE,
                    targetId = safTargetId,
                    args = mapOf(
                        "tree_uri" to Tainted.fromUntrustedExternal(
                            SlotValueAst.StringValue("https://evil.example/exfil"),
                            SensitiveSlotKind.EXTERNAL_URI
                        ),
                        "file_name" to Tainted.fromUserUtterance(
                            SlotValueAst.StringValue("note.txt"),
                            SensitiveSlotKind.FILE_PATH
                        ),
                        "content" to Tainted.fromUserUtterance(SlotValueAst.StringValue("data"))
                    )
                ),
                BlockedCase(
                    label = "saf-write-traversal",
                    toolName = AutomationToolNames.SAF_WRITE,
                    targetId = safTargetId,
                    args = mapOf(
                        "tree_uri" to Tainted.fromUserUtterance(
                            SlotValueAst.StringValue(safTreeUri),
                            SensitiveSlotKind.EXTERNAL_URI
                        ),
                        "file_name" to Tainted.fromUntrustedExternal(
                            SlotValueAst.StringValue("../secret"),
                            SensitiveSlotKind.FILE_PATH
                        ),
                        "content" to Tainted.fromUserUtterance(SlotValueAst.StringValue("data"))
                    )
                ),
                BlockedCase(
                    label = "saf-read-encoded-traversal",
                    toolName = AutomationToolNames.SAF_READ,
                    targetId = safTargetId,
                    args = mapOf(
                        "tree_uri" to Tainted.fromUserUtterance(
                            SlotValueAst.StringValue(safTreeUri),
                            SensitiveSlotKind.EXTERNAL_URI
                        ),
                        "file_name" to Tainted.fromUntrustedExternal(
                            SlotValueAst.StringValue("%2e%2e/secret"),
                            SensitiveSlotKind.FILE_PATH
                        )
                    )
                ),
                BlockedCase(
                    label = "app-launch-https",
                    toolName = AutomationToolNames.LAUNCH_APP,
                    targetId = ToolTargetIds.APP_LAUNCH,
                    args = mapOf(
                        "package_name" to Tainted.fromUntrustedExternal(
                            SlotValueAst.StringValue("https://evil.example/exfil"),
                            SensitiveSlotKind.PACKAGE_NAME
                        )
                    )
                ),
                BlockedCase(
                    label = "app-launch-javascript",
                    toolName = AutomationToolNames.LAUNCH_APP,
                    targetId = ToolTargetIds.APP_LAUNCH,
                    args = mapOf(
                        "package_name" to Tainted.fromUntrustedExternal(
                            SlotValueAst.StringValue("javascript:alert(1)"),
                            SensitiveSlotKind.PACKAGE_NAME
                        )
                    )
                )
            )

            for (case in blockedCases) {
                val token = h.firewall.mintToken(
                    requestId = "req-blocked-${case.label}",
                    utteranceProvenance = DataProvenance.USER_UTTERANCE,
                    candidateTools = setOf(case.toolName),
                    nowEpochMs = nowMs
                )
                val plan = PlanAst(
                    planId = "plan-blocked-${case.label}",
                    calls = listOf(
                        ToolCallAst(
                            toolName = case.toolName,
                            arguments = case.args,
                            orderIndex = 0,
                            targetId = case.targetId
                        )
                    )
                )

                val results = h.executePlan(
                    plan = plan,
                    capabilityToken = token,
                    targetId = case.targetId,
                    languageTag = "en-US",
                    nowEpochMs = nowMs,
                    confirmedStepIndices = setOf(0),
                    biometricApprovedStepIndices = setOf(0)
                )
                assertEquals(1, results.size)
                val failure = results[0] as? ToolResult.Failure
                    ?: fail("Blocked case '${case.label}' MUST fail even when confirmed, got ${results[0]}")
                assertTrue(
                    "Blocked case '${case.label}' MUST set isSecurityViolation=true",
                    failure.isSecurityViolation
                )
            }

            assertEquals(0, h.intentGateway.smsDrafts.size)
            assertEquals(0, h.intentGateway.dialedNumbers.size)
            assertEquals(0, h.intentGateway.directCalledNumbers.size)
            assertEquals(0, h.intentGateway.launchedPackages.size)
            assertEquals(0, h.safGateway.writtenDocuments.size)
            assertEquals(0, h.safGateway.readDocuments.size)
        }
    }

    // -------------------------------------------------------------------------
    // Section 3: Unattended ToolExecutionContext & Real SecurityFirewall + RoutineExecutor
    // -------------------------------------------------------------------------

    @Test
    fun unattendedContext_forbidsInteractiveConfirmationAndBiometricFlags() {
        val validSafeGrant = RuleCapabilityGrant(
            grantId = "grant-safe-1",
            ruleId = "rule-safe-1",
            triggerSpec = RuleTriggerSpec("TIME_DAILY", mapOf("hour" to "7", "minute" to "0")),
            staticActions = listOf(
                RuleActionSpec(
                    toolName = AutomationToolNames.SET_ALARM,
                    requiredCapability = AtomicCapability.CREATE_DRAFT,
                    staticArguments = mapOf("hour" to "7", "minute" to "0")
                )
            ),
            approvalState = RuleApprovalState.APPROVED_ACTIVE,
            sealHmacHex = "a".repeat(64),
            grantedAtEpochSec = nowEpochSec
        )

        assertThrowsIllegalArgument("isUnattendedBackground=true + isUserConfirmed=true") {
            ToolExecutionContext(
                requestId = "routine:rule-safe-1",
                capabilityToken = null,
                ruleGrant = validSafeGrant,
                targetId = ToolTargetIds.ROUTINES,
                languageTag = "en-US",
                issuedAtEpochMs = nowMs,
                isUnattendedBackground = true,
                isUserConfirmed = true,
                isBiometricApproved = false
            )
        }

        assertThrowsIllegalArgument("isUnattendedBackground=true + isBiometricApproved=true") {
            ToolExecutionContext(
                requestId = "routine:rule-safe-1",
                capabilityToken = null,
                ruleGrant = validSafeGrant,
                targetId = ToolTargetIds.ROUTINES,
                languageTag = "en-US",
                issuedAtEpochMs = nowMs,
                isUnattendedBackground = true,
                isUserConfirmed = false,
                isBiometricApproved = true
            )
        }

        assertThrowsIllegalArgument("isUnattendedBackground=true + both flags true") {
            ToolExecutionContext(
                requestId = "routine:rule-safe-1",
                capabilityToken = null,
                ruleGrant = validSafeGrant,
                targetId = ToolTargetIds.ROUTINES,
                languageTag = "en-US",
                issuedAtEpochMs = nowMs,
                isUnattendedBackground = true,
                isUserConfirmed = true,
                isBiometricApproved = true
            )
        }

        val unsafeGrant = validSafeGrant.copy(
            staticActions = listOf(
                RuleActionSpec(
                    toolName = AutomationToolNames.PLACE_CALL,
                    requiredCapability = AtomicCapability.MODIFY_DELETE_SEND,
                    staticArguments = mapOf("phone_number" to "+15550199")
                )
            )
        )
        assertThrowsIllegalArgument("isUnattendedBackground=true + MODIFY_DELETE_SEND grant") {
            ToolExecutionContext(
                requestId = "routine:rule-unsafe",
                capabilityToken = null,
                ruleGrant = unsafeGrant,
                targetId = ToolTargetIds.ROUTINES,
                languageTag = "en-US",
                issuedAtEpochMs = nowMs,
                isUnattendedBackground = true
            )
        }
    }

    @Test
    fun routineExecutor_validHmacSealedSetAlarmRule_executesUnattended() = runTest {
        withRealHarness { h ->
            val ruleId = "rule-morning-alarm"
            h.ruleGrantManager.createPendingRule(
                ruleId = ruleId,
                triggerSpec = RuleTriggerSpec("TIME_DAILY", mapOf("hour" to "7", "minute" to "30")),
                staticActions = listOf(
                    RuleActionSpec(
                        toolName = AutomationToolNames.SET_ALARM,
                        requiredCapability = AtomicCapability.CREATE_DRAFT,
                        staticArguments = mapOf(
                            "hour" to "7",
                            "minute" to "30",
                            "skip_ui" to "true"
                        ),
                        requiresBiometric = false
                    )
                ),
                nowEpochSec = nowEpochSec
            )
            val sealedGrant = h.ruleGrantManager.approveAndSealRule(ruleId, nowEpochSec)
            assertEquals(64, sealedGrant.sealHmacHex.length)
            assertTrue("Real HmacSha256Engine seal MUST verify", h.ruleGrantManager.verifySeal(sealedGrant))

            val outcome = h.routineExecutor.executeRule(
                ruleId = ruleId,
                nowEpochMs = nowMs,
                languageTag = "en-US"
            )
            val executed = outcome as? RoutineExecutionOutcome.Executed
                ?: fail("Expected RoutineExecutionOutcome.Executed for valid HMAC-sealed set_alarm, got $outcome")
            assertEquals(ruleId, executed.ruleId)
            assertEquals(1, executed.stepResults.size)
            assertEquals(1, h.intentGateway.alarmsDispatched.size)
            assertEquals(7, h.intentGateway.alarmsDispatched[0].first)
            assertEquals(30, h.intentGateway.alarmsDispatched[0].second)
            assertEquals(1, h.notificationBridge.completionNotifications.size)
            assertEquals(0, h.notificationBridge.interactiveNotifications.size)
        }
    }

    @Test
    fun routineExecutor_tamperedHmacSeal_deniedWithZeroExecutions() = runTest {
        withRealHarness { h ->
            val ruleId = "rule-tampered-seal"
            h.ruleGrantManager.createPendingRule(
                ruleId = ruleId,
                triggerSpec = RuleTriggerSpec("TIME_DAILY", mapOf("hour" to "6", "minute" to "45")),
                staticActions = listOf(
                    RuleActionSpec(
                        toolName = AutomationToolNames.SET_ALARM,
                        requiredCapability = AtomicCapability.CREATE_DRAFT,
                        staticArguments = mapOf("hour" to "6", "minute" to "45")
                    )
                ),
                nowEpochSec = nowEpochSec
            )
            val approved = h.ruleGrantManager.approveAndSealRule(ruleId, nowEpochSec)

            // Flip one hex character in the persisted HMAC seal directly inside EncryptedSqliteStore
            val flippedChar = if (approved.sealHmacHex.first() == 'a') 'b' else 'a'
            val tamperedGrant = approved.copy(
                sealHmacHex = flippedChar + approved.sealHmacHex.substring(1)
            )
            h.overwritePersistedRuleGrant(tamperedGrant)
            assertFalse(
                "Tampered seal MUST fail constant-time HMAC verification",
                h.ruleGrantManager.verifySeal(tamperedGrant)
            )

            val outcome = h.routineExecutor.executeRule(
                ruleId = ruleId,
                nowEpochMs = nowMs,
                languageTag = "en-US"
            )
            val denied = outcome as? RoutineExecutionOutcome.Denied
                ?: fail("Tampered HMAC seal MUST be Denied, got $outcome")
            assertEquals(SecurityFirewall.DECISION_RULE_SEAL_INVALID, denied.reasonCode)
            assertEquals(0, h.intentGateway.alarmsDispatched.size)
            assertEquals(0, h.notificationBridge.completionNotifications.size)
            assertEquals(0, h.notificationBridge.interactiveNotifications.size)

            // Also verify argument tampering with original seal still fails verification
            val argTamperedGrant = approved.copy(
                staticActions = listOf(
                    approved.staticActions[0].copy(
                        staticArguments = mapOf("hour" to "3", "minute" to "0")
                    )
                )
            )
            h.overwritePersistedRuleGrant(argTamperedGrant)
            val argTamperOutcome = h.routineExecutor.executeRule(
                ruleId = ruleId,
                nowEpochMs = nowMs + 1_000L,
                languageTag = "en-US"
            )
            val argDenied = argTamperOutcome as? RoutineExecutionOutcome.Denied
                ?: fail("Tampered staticArguments under original seal MUST be Denied, got $argTamperOutcome")
            assertEquals(SecurityFirewall.DECISION_RULE_SEAL_INVALID, argDenied.reasonCode)
            assertEquals(0, h.intentGateway.alarmsDispatched.size)
        }
    }

    @Test
    fun routineExecutor_spoofedVaultReadRule_neverRunsUnattendedAndEscalatesWithBiometric() = runTest {
        withRealHarness { h ->
            // Unlock the real NavaVault and store a secret so we prove Vault is NEVER read unattended
            // even when an active session happens to exist.
            val unlockCipher = h.realVault.prepareUnlockCipher()
            h.realVault.unlockWithAuthenticatedCipher(unlockCipher)
            h.realVault.writeNote("master-pin", "9942-secret".toByteArray(Charsets.UTF_8))

            val ruleId = "rule-spoofed-vault-read"
            h.ruleGrantManager.createPendingRule(
                ruleId = ruleId,
                triggerSpec = RuleTriggerSpec("TIME_DAILY", mapOf("hour" to "8", "minute" to "0")),
                staticActions = listOf(
                    // Adversarial spoofing: claims DATA_READ and requiresBiometric=false for vault_read
                    RuleActionSpec(
                        toolName = AutomationToolNames.VAULT_READ,
                        requiredCapability = AtomicCapability.DATA_READ,
                        staticArguments = mapOf("note_id" to "master-pin"),
                        requiresBiometric = false
                    )
                ),
                nowEpochSec = nowEpochSec
            )
            h.ruleGrantManager.approveAndSealRule(ruleId, nowEpochSec)

            val outcome = h.routineExecutor.executeRule(
                ruleId = ruleId,
                nowEpochMs = nowMs,
                languageTag = "en-US"
            )
            val escalated = outcome as? RoutineExecutionOutcome.EscalatedToInteractive
                ?: fail("Spoofed vault_read rule MUST escalate to interactive notification, got $outcome")
            assertTrue("Vault rule escalation MUST set requiresBiometric=true", escalated.requiresBiometric)
            assertEquals(listOf(AutomationToolNames.VAULT_READ), escalated.pendingToolNames)
            assertEquals(0, escalated.completedSteps.size)

            assertEquals(0, h.vaultSpy.readCount)
            assertEquals(0, h.vaultSpy.listCount)
            assertEquals(0, h.notificationBridge.completionNotifications.size)
            assertEquals(1, h.notificationBridge.interactiveNotifications.size)
            assertTrue(h.notificationBridge.interactiveNotifications[0].requiresBiometric)
            assertEquals(
                listOf(AutomationToolNames.VAULT_READ),
                h.notificationBridge.interactiveNotifications[0].pendingToolNames
            )
        }
    }

    @Test
    fun routineExecutor_modifyDeleteSendPlaceCallAndNotesDeleteRules_neverRunUnattendedAndEscalate() = runTest {
        withRealHarness { h ->
            h.intentGateway.grantedRuntimePermissions.add("android.permission.CALL_PHONE")
            h.noteDao.saveNote(
                StoredNote(
                    noteId = "important-note",
                    title = "Important",
                    body = "Keep safe",
                    updatedEpochSec = nowEpochSec
                )
            )

            // 1. Honest MODIFY_DELETE_SEND place_call rule -> firewall degrades to RequiresConfirmation -> EscalatedToInteractive
            val honestCallRuleId = "rule-honest-place-call"
            h.ruleGrantManager.createPendingRule(
                ruleId = honestCallRuleId,
                triggerSpec = RuleTriggerSpec("TIME_DAILY", mapOf("hour" to "9", "minute" to "0")),
                staticActions = listOf(
                    RuleActionSpec(
                        toolName = AutomationToolNames.PLACE_CALL,
                        requiredCapability = AtomicCapability.MODIFY_DELETE_SEND,
                        staticArguments = mapOf("phone_number" to "+15550199"),
                        requiresBiometric = false
                    )
                ),
                nowEpochSec = nowEpochSec
            )
            h.ruleGrantManager.approveAndSealRule(honestCallRuleId, nowEpochSec)

            val callOutcome = h.routineExecutor.executeRule(honestCallRuleId, nowMs, "en-US")
            val callEscalated = callOutcome as? RoutineExecutionOutcome.EscalatedToInteractive
                ?: fail("place_call rule MUST escalate to interactive, got $callOutcome")
            assertFalse(callEscalated.requiresBiometric)
            assertEquals(listOf(AutomationToolNames.PLACE_CALL), callEscalated.pendingToolNames)
            assertEquals(0, h.intentGateway.directCalledNumbers.size)

            // 2. Spoofed capability place_call rule (claims CREATE_DRAFT to bypass RuleCapabilityGrant check)
            val spoofedCallRuleId = "rule-spoofed-place-call"
            h.ruleGrantManager.createPendingRule(
                ruleId = spoofedCallRuleId,
                triggerSpec = RuleTriggerSpec("TIME_DAILY", mapOf("hour" to "9", "minute" to "5")),
                staticActions = listOf(
                    RuleActionSpec(
                        toolName = AutomationToolNames.PLACE_CALL,
                        requiredCapability = AtomicCapability.CREATE_DRAFT,
                        staticArguments = mapOf("phone_number" to "+15550199"),
                        requiresBiometric = false
                    )
                ),
                nowEpochSec = nowEpochSec
            )
            h.ruleGrantManager.approveAndSealRule(spoofedCallRuleId, nowEpochSec)

            val spoofedCallOutcome = h.routineExecutor.executeRule(spoofedCallRuleId, nowMs, "en-US")
            val spoofedCallEscalated = spoofedCallOutcome as? RoutineExecutionOutcome.EscalatedToInteractive
                ?: fail("Capability-spoofed place_call rule MUST STILL escalate, got $spoofedCallOutcome")
            assertEquals(listOf(AutomationToolNames.PLACE_CALL), spoofedCallEscalated.pendingToolNames)
            assertEquals(0, h.intentGateway.directCalledNumbers.size)

            // 3. Honest MODIFY_DELETE_SEND notes_delete rule
            val honestDeleteRuleId = "rule-honest-notes-delete"
            h.ruleGrantManager.createPendingRule(
                ruleId = honestDeleteRuleId,
                triggerSpec = RuleTriggerSpec("TIME_DAILY", mapOf("hour" to "9", "minute" to "10")),
                staticActions = listOf(
                    RuleActionSpec(
                        toolName = AutomationToolNames.NOTES_DELETE,
                        requiredCapability = AtomicCapability.MODIFY_DELETE_SEND,
                        staticArguments = mapOf("note_id" to "important-note"),
                        requiresBiometric = false
                    )
                ),
                nowEpochSec = nowEpochSec
            )
            h.ruleGrantManager.approveAndSealRule(honestDeleteRuleId, nowEpochSec)

            val deleteOutcome = h.routineExecutor.executeRule(honestDeleteRuleId, nowMs, "en-US")
            val deleteEscalated = deleteOutcome as? RoutineExecutionOutcome.EscalatedToInteractive
                ?: fail("notes_delete rule MUST escalate to interactive, got $deleteOutcome")
            assertFalse(deleteEscalated.requiresBiometric)
            assertEquals(listOf(AutomationToolNames.NOTES_DELETE), deleteEscalated.pendingToolNames)

            // 4. Spoofed capability notes_delete rule (claims DATA_READ)
            val spoofedDeleteRuleId = "rule-spoofed-notes-delete"
            h.ruleGrantManager.createPendingRule(
                ruleId = spoofedDeleteRuleId,
                triggerSpec = RuleTriggerSpec("TIME_DAILY", mapOf("hour" to "9", "minute" to "15")),
                staticActions = listOf(
                    RuleActionSpec(
                        toolName = AutomationToolNames.NOTES_DELETE,
                        requiredCapability = AtomicCapability.DATA_READ,
                        staticArguments = mapOf("note_id" to "important-note"),
                        requiresBiometric = false
                    )
                ),
                nowEpochSec = nowEpochSec
            )
            h.ruleGrantManager.approveAndSealRule(spoofedDeleteRuleId, nowEpochSec)

            val spoofedDeleteOutcome = h.routineExecutor.executeRule(spoofedDeleteRuleId, nowMs, "en-US")
            val spoofedDeleteEscalated = spoofedDeleteOutcome as? RoutineExecutionOutcome.EscalatedToInteractive
                ?: fail("Capability-spoofed notes_delete rule MUST STILL escalate, got $spoofedDeleteOutcome")
            assertEquals(listOf(AutomationToolNames.NOTES_DELETE), spoofedDeleteEscalated.pendingToolNames)

            // Verify ZERO side effects occurred and interactive notifications were posted
            assertNotNull("Important note MUST still exist", h.noteDao.findNote("important-note"))
            assertEquals(0, h.intentGateway.directCalledNumbers.size)
            assertEquals(0, h.notificationBridge.completionNotifications.size)
            assertEquals(4, h.notificationBridge.interactiveNotifications.size)
        }
    }

    @Test
    fun routineExecutor_globalPauseRevokedAndInjectedSchemeRules_deniedWithZeroExecutions() = runTest {
        withRealHarness { h ->
            val safeRuleId = "rule-killswitch-alarm"
            h.ruleGrantManager.createPendingRule(
                ruleId = safeRuleId,
                triggerSpec = RuleTriggerSpec("TIME_DAILY", mapOf("hour" to "7", "minute" to "0")),
                staticActions = listOf(
                    RuleActionSpec(
                        toolName = AutomationToolNames.SET_ALARM,
                        requiredCapability = AtomicCapability.CREATE_DRAFT,
                        staticArguments = mapOf("hour" to "7", "minute" to "0")
                    )
                ),
                nowEpochSec = nowEpochSec
            )
            h.ruleGrantManager.approveAndSealRule(safeRuleId, nowEpochSec)

            // 1. Global pause in RuleCapabilityGrantManager enforced by real SecurityFirewall
            h.ruleGrantManager.setGlobalRulesPaused(true)
            val pausedOutcome = h.routineExecutor.executeRule(safeRuleId, nowMs, "en-US")
            val pausedDenied = pausedOutcome as? RoutineExecutionOutcome.Denied
                ?: fail("Globally paused rule MUST be Denied, got $pausedOutcome")
            assertEquals(SecurityFirewall.DECISION_RULES_GLOBALLY_PAUSED, pausedDenied.reasonCode)
            h.ruleGrantManager.setGlobalRulesPaused(false)

            // 2. Revoked rule cannot execute
            h.ruleGrantManager.revokeRule(safeRuleId, nowEpochSec + 10L)
            val revokedOutcome = h.routineExecutor.executeRule(safeRuleId, nowMs + 10_000L, "en-US")
            assertTrue("Revoked rule MUST be Denied, got $revokedOutcome", revokedOutcome is RoutineExecutionOutcome.Denied)

            // 3. Sealed rule smuggling an https:// exfiltration URL in static arguments is hard-denied by SecurityFirewall
            val evilRuleId = "rule-smuggled-https"
            h.ruleGrantManager.createPendingRule(
                ruleId = evilRuleId,
                triggerSpec = RuleTriggerSpec("TIME_DAILY", mapOf("hour" to "7", "minute" to "15")),
                staticActions = listOf(
                    RuleActionSpec(
                        toolName = AutomationToolNames.SET_ALARM,
                        requiredCapability = AtomicCapability.CREATE_DRAFT,
                        staticArguments = mapOf(
                            "hour" to "7",
                            "minute" to "15",
                            "label" to "https://evil.example/exfil"
                        )
                    )
                ),
                nowEpochSec = nowEpochSec
            )
            h.ruleGrantManager.approveAndSealRule(evilRuleId, nowEpochSec)

            val evilOutcome = h.routineExecutor.executeRule(evilRuleId, nowMs, "en-US")
            val evilDenied = evilOutcome as? RoutineExecutionOutcome.Denied
                ?: fail("Rule with smuggled https:// URL MUST be Denied, got $evilOutcome")
            assertEquals(OutboundChannelPolicy.REASON_HTTP_BLOCKED, evilDenied.reasonCode)

            assertEquals(0, h.intentGateway.alarmsDispatched.size)
            assertEquals(0, h.notificationBridge.completionNotifications.size)
            assertEquals(0, h.notificationBridge.interactiveNotifications.size)
        }
    }

    // -------------------------------------------------------------------------
    // Real-Firewall End-to-End Test Harness & Recording Platform Gateways
    // -------------------------------------------------------------------------

    private data class RealHarness(
        val store: EncryptedSqliteStore,
        val profileManager: PermissionProfileManager,
        val ruleGrantManager: RuleCapabilityGrantManager,
        val auditLogDao: AuditLogDao,
        val noteDao: EncryptedNoteDao,
        val realVault: NavaVault,
        val vaultSpy: SpyVaultPort,
        val firewall: SecurityFirewall,
        val toolRegistry: ToolRegistry,
        val executePlan: ExecutePlanUseCase,
        val routineExecutor: RoutineExecutor,
        val intentGateway: RecordingIntentGateway,
        val calendarGateway: RecordingCalendarGateway,
        val safGateway: RecordingSafGateway,
        val notificationBridge: RecordingNotificationBridge,
        val vaultDir: File
    ) {
        suspend fun assignCustomProfile(
            targetId: String,
            capabilities: Map<AtomicCapability, ConfirmationLevel>
        ) {
            val profileId = "custom_${targetId.replace(Regex("[^a-zA-Z0-9_]"), "_")}"
            val profile = PermissionProfile(
                id = profileId,
                name = "Test Profile $profileId",
                preset = PermissionProfilePreset.CUSTOM,
                capabilities = capabilities
            )
            profileManager.saveProfile(profile)
            profileManager.assignTargetToProfile(targetId, profileId)
        }

        suspend fun assignAutoSafeProfile(targetId: String) {
            assignCustomProfile(
                targetId = targetId,
                capabilities = mapOf(
                    AtomicCapability.NOTIFICATION_READ to ConfirmationLevel.AUTO,
                    AtomicCapability.DATA_READ to ConfirmationLevel.AUTO,
                    AtomicCapability.CREATE_DRAFT to ConfirmationLevel.AUTO,
                    AtomicCapability.MODIFY_DELETE_SEND to ConfirmationLevel.PROMPT_CARD,
                    AtomicCapability.APP_LAUNCH to ConfirmationLevel.AUTO
                )
            )
        }

        /**
         * Overwrites a persisted rule grant in [EncryptedSqliteStore] directly to test DB-level
         * HMAC seal tampering against the real [RuleCapabilityGrantManager] and [HmacSha256Engine].
         */
        suspend fun overwritePersistedRuleGrant(grant: RuleCapabilityGrant) {
            val encoded = StructuredPayloadCodec.encode(formatVersion = 1) {
                writeString(grant.grantId)
                writeString(grant.ruleId)
                writeString(grant.triggerSpec.triggerType)
                writeStringMap(grant.triggerSpec.parameters)
                writeInt(grant.staticActions.size)
                for (action in grant.staticActions) {
                    writeString(action.toolName)
                    writeString(action.requiredCapability.name)
                    writeStringMap(action.staticArguments)
                    writeBoolean(action.requiresBiometric)
                }
                writeString(grant.approvalState.name)
                writeString(grant.sealHmacHex)
                writeLong(grant.grantedAtEpochSec)
            }
            SecureMemory.withZeroizedBytes(encoded) { payload ->
                val lookupHmac = store.computeBlindIndex("rule", grant.ruleId)
                store.upsertEncryptedByBlindIndex(
                    tableName = EncryptedTableSchema.TABLE_AUTOMATION_RULES,
                    lookupHmac = lookupHmac,
                    plaintext = payload,
                    epochSec = grant.grantedAtEpochSec.coerceAtLeast(1L),
                    schemaVersion = 1
                )
            }
        }
    }

    private suspend fun TestScope.withRealHarness(block: suspend (RealHarness) -> Unit) {
        val dispatcher = UnconfinedTestDispatcher(testScheduler)
        val storage = TestInMemoryRowStorage()
        val keyProvider = TestSoftwareKeyProvider()
        val hmacEngine = HmacSha256Engine()
        val store = EncryptedSqliteStore(
            storage = storage,
            keyProvider = keyProvider,
            hmacEngine = hmacEngine,
            dispatcher = dispatcher
        )
        val profileManager = PermissionProfileManager(
            store = store,
            clockEpochSec = { nowEpochSec }
        )
        val ruleGrantManager = RuleCapabilityGrantManager(
            store = store,
            keyProvider = keyProvider,
            hmacEngine = hmacEngine
        )
        val auditLogDao = AuditLogDao(store = store)
        val noteDao = EncryptedNoteDao(store = store)
        val outboundPolicy = OutboundChannelPolicy()
        val firewall = SecurityFirewall(
            permissionEvaluator = profileManager,
            ruleGrantManager = ruleGrantManager,
            auditLog = auditLogDao,
            outboundPolicy = outboundPolicy,
            clockMs = { nowMs }
        )

        val vaultDir = Files.createTempDirectory("nava-phase4-redteam-vault").toFile()
        val realVault = NavaVault(
            vaultDir = vaultDir,
            keyProvider = keyProvider,
            clockMs = { nowMs },
            dispatcher = dispatcher
        )
        val vaultSpy = SpyVaultPort(realVault)

        val intentGateway = RecordingIntentGateway()
        val calendarGateway = RecordingCalendarGateway()
        val safGateway = RecordingSafGateway()
        val notificationBridge = RecordingNotificationBridge()
        val scheduler = RecordingRoutineWorkScheduler()

        val calendarTool = CalendarTool(calendarGateway, firewall, auditLogDao, clock = { nowMs })
        val alarmTimerTool = AlarmTimerTool(intentGateway, firewall, auditLogDao, clock = { nowMs })

        val toolRegistry = ToolRegistry(
            initialTools = buildList {
                add(SmsDraftTool(intentGateway, firewall, auditLogDao))
                addAll(CallIntentTool.createAll(intentGateway, firewall, auditLogDao))
                addAll(calendarTool.allTools())
                addAll(SafDirectoryTool.createAll(safGateway, firewall, auditLogDao))
                add(AppLaunchTool(intentGateway, firewall, auditLogDao, clock = { nowMs }))
                addAll(NotesVaultTool.createAll(noteDao, vaultSpy, auditLogDao))
                addAll(alarmTimerTool.allTools())
            }
        )

        val executePlan = ExecutePlanUseCase(
            toolRegistry = toolRegistry,
            securityFirewall = firewall,
            auditLog = auditLogDao
        )
        val routineExecutor = RoutineExecutor(
            ruleGrantPort = ruleGrantManager,
            securityFirewall = firewall,
            toolRegistry = toolRegistry,
            auditLog = auditLogDao,
            notificationBridge = notificationBridge,
            scheduler = scheduler
        )

        val harness = RealHarness(
            store = store,
            profileManager = profileManager,
            ruleGrantManager = ruleGrantManager,
            auditLogDao = auditLogDao,
            noteDao = noteDao,
            realVault = realVault,
            vaultSpy = vaultSpy,
            firewall = firewall,
            toolRegistry = toolRegistry,
            executePlan = executePlan,
            routineExecutor = routineExecutor,
            intentGateway = intentGateway,
            calendarGateway = calendarGateway,
            safGateway = safGateway,
            notificationBridge = notificationBridge,
            vaultDir = vaultDir
        )

        try {
            block(harness)
        } finally {
            realVault.close()
            vaultDir.deleteRecursively()
        }
    }

    private fun fail(message: String): Nothing {
        throw AssertionError(message)
    }

    private fun assertThrowsIllegalArgument(label: String, block: () -> Unit) {
        try {
            block()
            fail("Expected IllegalArgumentException for $label")
        } catch (_: IllegalArgumentException) {
            // Expected security invariant enforcement.
        }
    }

    private class SpyVaultPort(
        private val delegate: NavaVault
    ) : VaultPort {
        var readCount: Int = 0
        var listCount: Int = 0
        var writeCount: Int = 0
        var deleteCount: Int = 0

        override suspend fun isUnlocked(): Boolean = delegate.isUnlocked()

        override suspend fun listNoteIds(): List<String> {
            listCount++
            return delegate.listNoteIds()
        }

        override suspend fun readNote(noteId: String): ByteArray {
            readCount++
            return delegate.readNote(noteId)
        }

        override suspend fun writeNote(noteId: String, content: ByteArray) {
            writeCount++
            delegate.writeNote(noteId, content)
        }

        override suspend fun deleteNote(noteId: String) {
            deleteCount++
            delegate.deleteNote(noteId)
        }

        override suspend fun lock() {
            delegate.lock()
        }
    }

    private class RecordingIntentGateway : AutomationIntentGateway {
        val grantedRuntimePermissions: MutableSet<String> = LinkedHashSet()
        val appLabelsToPackages: MutableMap<String, String> = LinkedHashMap()
        val alarmsDispatched: MutableList<Pair<Int, Int>> = mutableListOf()
        val timersDispatched: MutableList<Int> = mutableListOf()
        val smsDrafts: MutableList<Pair<String, String>> = mutableListOf()
        val dialedNumbers: MutableList<String> = mutableListOf()
        val directCalledNumbers: MutableList<String> = mutableListOf()
        val launchedPackages: MutableList<String> = mutableListOf()

        override fun hasRuntimePermission(permission: String): Boolean {
            return permission in grantedRuntimePermissions
        }

        override fun isNotificationPolicyAccessGranted(): Boolean = true

        override fun isNotificationListenerEnabled(): Boolean = true

        override fun dispatchSetAlarm(
            hour: Int,
            minute: Int,
            label: String?,
            skipUi: Boolean
        ): PlatformDispatchResult {
            alarmsDispatched.add(hour to minute)
            return PlatformDispatchResult.Dispatched("alarm:$hour:$minute")
        }

        override fun dispatchSetTimer(
            durationSeconds: Int,
            label: String?,
            skipUi: Boolean
        ): PlatformDispatchResult {
            timersDispatched.add(durationSeconds)
            return PlatformDispatchResult.Dispatched("timer:$durationSeconds")
        }

        override fun dispatchSmsDraft(recipient: String, body: String): PlatformDispatchResult {
            smsDrafts.add(recipient to body)
            return PlatformDispatchResult.Dispatched("sms:$recipient")
        }

        override fun dispatchDial(phoneNumber: String): PlatformDispatchResult {
            dialedNumbers.add(phoneNumber)
            return PlatformDispatchResult.Dispatched("dial:$phoneNumber")
        }

        override fun dispatchDirectCall(phoneNumber: String): PlatformDispatchResult {
            directCalledNumbers.add(phoneNumber)
            return PlatformDispatchResult.Dispatched("call:$phoneNumber")
        }

        override fun resolveLaunchablePackage(appNameOrPackage: String): String? {
            val trimmed = appNameOrPackage.trim()
            appLabelsToPackages[trimmed]?.let { return it }
            val lower = trimmed.lowercase(Locale.ROOT)
            return appLabelsToPackages.entries.firstOrNull { (k, _) ->
                k.lowercase(Locale.ROOT) == lower
            }?.value
        }

        override fun dispatchLaunchApp(packageName: String): PlatformDispatchResult {
            launchedPackages.add(packageName)
            return PlatformDispatchResult.Dispatched("launch:$packageName")
        }
    }

    private class RecordingCalendarGateway : CalendarPlatformGateway {
        private val events: MutableMap<Long, CalendarEventRecord> = LinkedHashMap()
        private var nextEventId: Long = 1000L
        val createdDrafts: MutableList<CalendarEventDraft> = mutableListOf()
        val updatedEvents: MutableList<Pair<Long, CalendarEventPatch>> = mutableListOf()
        val deletedEventIds: MutableList<Long> = mutableListOf()

        fun seedEvent(record: CalendarEventRecord) {
            events[record.eventId] = record
        }

        override suspend fun queryEvents(
            startEpochMs: Long,
            endEpochMs: Long,
            limit: Int
        ): CalendarGatewayResult<List<CalendarEventRecord>> {
            val matched = events.values
                .filter { it.endEpochMs >= startEpochMs && it.startEpochMs <= endEpochMs }
                .take(limit)
            return CalendarGatewayResult.Success(matched)
        }

        override suspend fun createEvent(draft: CalendarEventDraft): CalendarGatewayResult<Long> {
            createdDrafts.add(draft)
            val id = nextEventId++
            events[id] = CalendarEventRecord(
                eventId = id,
                calendarId = draft.calendarId ?: 1L,
                title = draft.title,
                description = draft.description,
                location = draft.location,
                startEpochMs = draft.startEpochMs,
                endEpochMs = draft.endEpochMs,
                allDay = draft.allDay
            )
            return CalendarGatewayResult.Success(id)
        }

        override suspend fun updateEvent(
            eventId: Long,
            patch: CalendarEventPatch
        ): CalendarGatewayResult<Boolean> {
            val existing = events[eventId] ?: return CalendarGatewayResult.NotFound(eventId)
            updatedEvents.add(eventId to patch)
            events[eventId] = existing.copy(
                title = patch.title ?: existing.title,
                description = patch.description ?: existing.description,
                location = patch.location ?: existing.location,
                startEpochMs = patch.startEpochMs ?: existing.startEpochMs,
                endEpochMs = patch.endEpochMs ?: existing.endEpochMs,
                allDay = patch.allDay ?: existing.allDay
            )
            return CalendarGatewayResult.Success(true)
        }

        override suspend fun deleteEvent(eventId: Long): CalendarGatewayResult<Boolean> {
            events.remove(eventId) ?: return CalendarGatewayResult.NotFound(eventId)
            deletedEventIds.add(eventId)
            return CalendarGatewayResult.Success(true)
        }
    }

    private class RecordingSafGateway : SafPlatformGateway {
        private val grants: MutableMap<String, Boolean> = LinkedHashMap()
        private val files: MutableMap<Pair<String, String>, ByteArray> = LinkedHashMap()
        val readDocuments: MutableList<Pair<String, String>> = mutableListOf()
        val writtenDocuments: MutableList<Pair<String, String>> = mutableListOf()
        val deletedDocuments: MutableList<Pair<String, String>> = mutableListOf()

        fun grantTree(treeUri: String, writable: Boolean) {
            grants[treeUri] = writable
        }

        override fun hasPersistedGrant(treeUri: String, requireWrite: Boolean): Boolean {
            val isWritable = grants[treeUri] ?: return false
            return !requireWrite || isWritable
        }

        override fun listPersistedTreeUris(): Set<String> = grants.keys.toSet()

        override suspend fun listDocuments(treeUri: String): SafGatewayResult<List<SafDocumentEntry>> {
            if (!hasPersistedGrant(treeUri, requireWrite = false)) {
                return SafGatewayResult.GrantMissing(treeUri)
            }
            val entries = files.entries
                .filter { it.key.first == treeUri }
                .map { (key, bytes) ->
                    SafDocumentEntry(
                        documentUri = "$treeUri/${key.second}",
                        displayName = key.second,
                        mimeType = "text/plain",
                        isDirectory = false,
                        sizeBytes = bytes.size.toLong(),
                        lastModifiedEpochMs = 1_760_000_000_000L
                    )
                }
            return SafGatewayResult.Success(entries)
        }

        override suspend fun readDocument(
            treeUri: String,
            fileName: String,
            maxBytes: Int
        ): SafGatewayResult<ByteArray> {
            if (!hasPersistedGrant(treeUri, requireWrite = false)) {
                return SafGatewayResult.GrantMissing(treeUri)
            }
            readDocuments.add(treeUri to fileName)
            val bytes = files[treeUri to fileName] ?: return SafGatewayResult.NotFound(fileName)
            return SafGatewayResult.Success(bytes.copyOf(minOf(bytes.size, maxBytes)))
        }

        override suspend fun writeDocument(
            treeUri: String,
            fileName: String,
            mimeType: String,
            content: ByteArray,
            overwrite: Boolean
        ): SafGatewayResult<SafDocumentEntry> {
            if (!hasPersistedGrant(treeUri, requireWrite = true)) {
                return SafGatewayResult.GrantMissing(treeUri)
            }
            writtenDocuments.add(treeUri to fileName)
            files[treeUri to fileName] = content.copyOf()
            return SafGatewayResult.Success(
                SafDocumentEntry(
                    documentUri = "$treeUri/$fileName",
                    displayName = fileName,
                    mimeType = mimeType,
                    isDirectory = false,
                    sizeBytes = content.size.toLong(),
                    lastModifiedEpochMs = 1_760_000_000_000L
                )
            )
        }

        override suspend fun deleteDocument(
            treeUri: String,
            fileName: String
        ): SafGatewayResult<Boolean> {
            if (!hasPersistedGrant(treeUri, requireWrite = true)) {
                return SafGatewayResult.GrantMissing(treeUri)
            }
            deletedDocuments.add(treeUri to fileName)
            val removed = files.remove(treeUri to fileName) != null
            return if (removed) SafGatewayResult.Success(true) else SafGatewayResult.NotFound(fileName)
        }
    }

    private class RecordingNotificationBridge : AutomationNotificationBridge {
        val completionNotifications: MutableList<CompletionNotificationRequest> = mutableListOf()
        val interactiveNotifications: MutableList<InteractiveNotificationRequest> = mutableListOf()

        override fun postCompletionNotification(request: CompletionNotificationRequest) {
            completionNotifications.add(request)
        }

        override fun postInteractiveConfirmationNotification(request: InteractiveNotificationRequest) {
            interactiveNotifications.add(request)
        }

        override fun cancelNotification(notificationId: Int) = Unit

        override fun createForegroundNotificationSpec(
            taskId: String,
            message: UserMessage
        ): ForegroundNotificationSpec {
            return ForegroundNotificationSpec(
                notificationId = 1,
                channelId = AutomationNotificationBridge.CHANNEL_FOREGROUND_TASK,
                taskId = taskId,
                message = message
            )
        }
    }

    private class RecordingRoutineWorkScheduler : RoutineWorkScheduler {
        override suspend fun schedule(grant: RuleCapabilityGrant) = Unit
        override suspend fun cancel(ruleId: String) = Unit
        override suspend fun cancelAll() = Unit
    }

    private class TestSoftwareKeyProvider : CryptoKeyProvider {
        private val lock = Any()
        private var dbMasterKey: SecretKey? = null
        private var blindIndexKey: SecretKey? = null
        private var vaultBiometricKey: SecretKey? = null

        override fun getOrCreateDbMasterKey(): SecretKey = synchronized(lock) {
            dbMasterKey ?: generateKey("AES").also { dbMasterKey = it }
        }

        override fun getOrCreateBlindIndexKey(): SecretKey = synchronized(lock) {
            blindIndexKey ?: generateKey("HmacSHA256").also { blindIndexKey = it }
        }

        override fun getOrCreateVaultBiometricKey(): SecretKey = synchronized(lock) {
            vaultBiometricKey ?: generateKey("AES").also { vaultBiometricKey = it }
        }

        override fun isStrongBoxBacked(alias: String): Boolean = false

        private fun generateKey(algorithm: String): SecretKey {
            val gen = KeyGenerator.getInstance(algorithm)
            gen.init(256)
            return gen.generateKey()
        }
    }

    private class TestInMemoryRowStorage : EncryptedRowStorage {
        private val lock = Any()
        private val tables: MutableMap<String, MutableList<RawEncryptedRow>> = LinkedHashMap()
        private val sequences: MutableMap<String, Long> = LinkedHashMap()
        private var transactionDepth: Int = 0

        init {
            for (table in EncryptedTableSchema.ALLOWED_TABLES) {
                tables[table] = mutableListOf()
                sequences[table] = 0L
            }
        }

        override fun allocateRowId(tableName: String): Long {
            val validTable = EncryptedTableSchema.validateTableName(tableName)
            return synchronized(lock) {
                val nextId = (sequences[validTable] ?: 0L) + 1L
                sequences[validTable] = nextId
                nextId
            }
        }

        override fun insertRow(tableName: String, row: RawEncryptedRow) {
            val validTable = EncryptedTableSchema.validateTableName(tableName)
            synchronized(lock) {
                val rows = tables.getValue(validTable)
                if (rows.any { it.rowId == row.rowId }) {
                    throw IllegalStateException("Duplicate rowId ${row.rowId} in table '$validTable'")
                }
                rows.add(copyRow(row))
            }
        }

        override fun upsertByLookupHmac(tableName: String, row: RawEncryptedRow) {
            val validTable = EncryptedTableSchema.validateTableName(tableName)
            synchronized(lock) {
                val rows = tables.getValue(validTable)
                rows.removeAll { it.lookupHmac == row.lookupHmac || it.rowId == row.rowId }
                rows.add(copyRow(row))
            }
        }

        override fun findByLookupHmac(tableName: String, lookupHmac: String): RawEncryptedRow? {
            val validTable = EncryptedTableSchema.validateTableName(tableName)
            return synchronized(lock) {
                tables.getValue(validTable)
                    .asSequence()
                    .filter { it.lookupHmac == lookupHmac }
                    .sortedWith(RECENT_ORDER)
                    .firstOrNull()
                    ?.let(::copyRow)
            }
        }

        override fun findByRowId(tableName: String, rowId: Long): RawEncryptedRow? {
            val validTable = EncryptedTableSchema.validateTableName(tableName)
            return synchronized(lock) {
                tables.getValue(validTable).firstOrNull { it.rowId == rowId }?.let(::copyRow)
            }
        }

        override fun listRows(tableName: String): List<RawEncryptedRow> {
            val validTable = EncryptedTableSchema.validateTableName(tableName)
            return synchronized(lock) {
                tables.getValue(validTable).sortedBy { it.rowId }.map(::copyRow)
            }
        }

        override fun listRecent(tableName: String, limit: Int): List<RawEncryptedRow> {
            val validTable = EncryptedTableSchema.validateTableName(tableName)
            if (limit <= 0) return emptyList()
            return synchronized(lock) {
                tables.getValue(validTable).sortedWith(RECENT_ORDER).take(limit).map(::copyRow)
            }
        }

        override fun listRecentByLookupHmac(
            tableName: String,
            lookupHmac: String,
            limit: Int
        ): List<RawEncryptedRow> {
            val validTable = EncryptedTableSchema.validateTableName(tableName)
            if (limit <= 0) return emptyList()
            return synchronized(lock) {
                tables.getValue(validTable)
                    .asSequence()
                    .filter { it.lookupHmac == lookupHmac }
                    .sortedWith(RECENT_ORDER)
                    .take(limit)
                    .map(::copyRow)
                    .toList()
            }
        }

        override fun deleteByLookupHmac(tableName: String, lookupHmac: String): Boolean {
            val validTable = EncryptedTableSchema.validateTableName(tableName)
            return synchronized(lock) {
                tables.getValue(validTable).removeAll { it.lookupHmac == lookupHmac }
            }
        }

        override fun deleteByRowId(tableName: String, rowId: Long): Boolean {
            val validTable = EncryptedTableSchema.validateTableName(tableName)
            return synchronized(lock) {
                tables.getValue(validTable).removeAll { it.rowId == rowId }
            }
        }

        override fun deleteOlderThanMaxCount(tableName: String, maxEntries: Int): Int {
            val validTable = EncryptedTableSchema.validateTableName(tableName)
            require(maxEntries >= 0) { "maxEntries must be non-negative" }
            return synchronized(lock) {
                val rows = tables.getValue(validTable)
                if (rows.size <= maxEntries) return@synchronized 0
                val evictCount = rows.size - maxEntries
                val evictIds = rows.sortedWith(LRU_ORDER).take(evictCount).mapTo(HashSet()) { it.rowId }
                rows.removeAll { it.rowId in evictIds }
                evictIds.size
            }
        }

        override fun touchUpdatedEpochSec(tableName: String, rowId: Long, updatedEpochSec: Long): Boolean {
            val validTable = EncryptedTableSchema.validateTableName(tableName)
            return synchronized(lock) {
                val rows = tables.getValue(validTable)
                val idx = rows.indexOfFirst { it.rowId == rowId }
                if (idx < 0) return@synchronized false
                rows[idx] = rows[idx].copy(updatedEpochSec = updatedEpochSec)
                true
            }
        }

        override fun <T> withTransaction(block: () -> T): T {
            return synchronized(lock) {
                val isOutermost = transactionDepth == 0
                val tableSnap = if (isOutermost) {
                    tables.mapValuesTo(LinkedHashMap()) { (_, v) -> v.mapTo(mutableListOf(), ::copyRow) }
                } else {
                    null
                }
                val seqSnap = if (isOutermost) HashMap(sequences) else null
                transactionDepth++
                try {
                    block()
                } catch (e: Throwable) {
                    if (isOutermost && tableSnap != null && seqSnap != null) {
                        tables.clear()
                        tables.putAll(tableSnap)
                        sequences.clear()
                        sequences.putAll(seqSnap)
                    }
                    throw e
                } finally {
                    transactionDepth--
                }
            }
        }

        override fun close() = Unit

        private fun copyRow(row: RawEncryptedRow): RawEncryptedRow {
            return row.copy(payloadBlob = row.payloadBlob.copyOf())
        }

        companion object {
            private val RECENT_ORDER: Comparator<RawEncryptedRow> =
                compareByDescending<RawEncryptedRow> { it.updatedEpochSec }
                    .thenByDescending { it.rowId }

            private val LRU_ORDER: Comparator<RawEncryptedRow> =
                compareBy<RawEncryptedRow> { it.updatedEpochSec }
                    .thenBy { it.rowId }
        }
    }
}

package com.nava.feature.automations.redteam

import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageArg
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.feature.automations.alarm.AlarmTimerTool
import com.nava.feature.automations.applaunch.AppLaunchTool
import com.nava.feature.automations.calendar.CalendarTool
import com.nava.feature.automations.call.CallIntentTool
import com.nava.feature.automations.common.AndroidAutomationIntentGateway
import com.nava.feature.automations.common.AutomationToolNames
import com.nava.feature.automations.common.SafPlatformGateway
import com.nava.feature.automations.common.ToolTargetIds
import com.nava.feature.automations.saf.SafDirectoryTool
import com.nava.feature.automations.sms.SmsDraftTool
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Gate 2 Adversarial Security Suite 1: Outbound Exfiltration, URI/Scheme Smuggling,
 * Path Traversal, Firewall Enforcement, and Manifest Permission Hygiene.
 */
class OutboundExfiltrationRedTeamTest {

    private val schemeAndInjectionPayloads: List<String> = listOf(
        "http://evil.example/exfil?d=1",
        "https://evil.example/exfil",
        "HTTPS://EVIL.EXAMPLE/leak",
        "ftp://evil.example/drop",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "intent:#Intent;action=android.intent.action.VIEW;S.url=https://evil.example;end",
        "file:///etc/passwd",
        // Fullwidth / NFKC homoglyph schemes and digits
        "\uFF48\uFF54\uFF54\uFF50\uFF1A\uFF0F\uFF0Fevil.example/exfil",
        "\uFF48\uFF54\uFF54\uFF50\uFF53\uFF1A\uFF0F\uFF0Fevil.example/exfil",
        "\uFF11\uFF15\uFF15\uFF15\uFF11\uFF12\uFF13\uFF14",
        // CRLF and null-byte injection
        "+15551234567\r\nBcc:attacker@evil.example",
        "+15551234567\nX-Injected: true",
        "+15551234567\u0000evil",
        // Query-string injection
        "+15551234567?body=stolen_secret",
        "+15551234567&sms_body=stolen_secret",
        // Path traversal variants
        "../secret.txt",
        "%2e%2e%2fsecret.txt",
        "sub\\..\\secret.txt",
        "%252e%252e%252fsecret.txt",
        // Unallowlisted actions
        "android.intent.action.VIEW",
        "ACTION_VIEW",
        "android.intent.action.SEND",
        "ACTION_SEND"
    )

    private val traversalPayloads: List<String> = listOf(
        "../secret.txt",
        "../../etc/passwd",
        "sub/../../secret.txt",
        "sub\\..\\secret.txt",
        "\\windows\\system32\\cmd.exe",
        "%2e%2e%2fsecret.txt",
        "%2E%2E%2Fsecret.txt",
        "%2e%2e%5csecret.txt",
        "%252e%252e%252fsecret.txt",
        "%252e%252e%255csecret.txt",
        "secret%00.txt",
        "secret\u0000.txt",
        "secret\r\n.txt",
        "secret%0d%0a.txt",
        // Fullwidth NFKC homoglyphs for ../ and \
        "\uFF0E\uFF0E\uFF0Fsecret.txt",
        "\uFF0E\uFF0E\uFF3Csecret.txt",
        // Zero-width character splitting ".."
        ".\u200B./secret.txt"
    )

    @Test
    fun smsDraftToolRejectsAllMaliciousUriHomoglyphCrlfQueryAndActionPayloads() = runBlocking {
        val gateway = RecordingIntentGateway()
        val firewall = StrictRedTeamFirewall()
        val audit = RecordingAuditLog()
        val tool = SmsDraftTool(gateway, firewall, audit)
        val ctx = RedTeamContexts.interactive(AutomationToolNames.CREATE_SMS_DRAFT, ToolTargetIds.SMS)

        for (payload in schemeAndInjectionPayloads) {
            val result = tool.execute(
                context = ctx,
                arguments = mapOf(
                    "recipient" to RedTeamContexts.userStr(payload, SensitiveSlotKind.PHONE_NUMBER),
                    "body" to RedTeamContexts.userStr("Hello", SensitiveSlotKind.TEXT_BODY)
                )
            )
            assertTrue(
                "SmsDraftTool MUST reject malicious recipient '$payload', got $result",
                result is ToolResult.Failure
            )
        }
        assertEquals("SmsDraftTool must never dispatch gateway on malicious payloads", 0, gateway.totalDispatchCount())
    }

    @Test
    fun callIntentDialAndPlaceRejectAllMaliciousPayloads() = runBlocking {
        val gateway = RecordingIntentGateway(callPhonePermissionGranted = true)
        val firewall = StrictRedTeamFirewall()
        val audit = RecordingAuditLog()
        val dialTool = CallIntentTool.createDialTool(gateway, firewall, audit)
        val placeTool = CallIntentTool.createPlaceTool(gateway, firewall, audit)
        val dialCtx = RedTeamContexts.interactive(AutomationToolNames.DIAL_CALL, ToolTargetIds.PHONE)
        val placeCtx = RedTeamContexts.interactive(AutomationToolNames.PLACE_CALL, ToolTargetIds.PHONE)

        for (payload in schemeAndInjectionPayloads) {
            val args = mapOf("phone_number" to RedTeamContexts.userStr(payload, SensitiveSlotKind.PHONE_NUMBER))
            val dialResult = dialTool.execute(dialCtx, args)
            assertTrue(
                "DialCallTool MUST reject malicious phone_number '$payload', got $dialResult",
                dialResult is ToolResult.Failure
            )
            val placeResult = placeTool.execute(placeCtx, args)
            assertTrue(
                "PlaceCallTool MUST reject malicious phone_number '$payload', got $placeResult",
                placeResult is ToolResult.Failure
            )
        }
        assertEquals("CallIntentTool must never dispatch gateway on malicious payloads", 0, gateway.totalDispatchCount())
    }

    @Test
    fun appLaunchToolRejectsMaliciousSchemesHomoglyphsAndUnallowlistedActions() = runBlocking {
        val gateway = RecordingIntentGateway()
        val firewall = StrictRedTeamFirewall()
        val audit = RecordingAuditLog()
        val tool = AppLaunchTool(gateway, firewall, audit)
        val ctx = RedTeamContexts.interactive(AutomationToolNames.LAUNCH_APP, ToolTargetIds.APP_LAUNCH)

        val nonPackageMaliciousPayloads = schemeAndInjectionPayloads.filterNot {
            it == "android.intent.action.VIEW" || it == "android.intent.action.SEND"
        }
        for (payload in nonPackageMaliciousPayloads) {
            // Even if a misbehaving resolver returned the raw payload, firewall must hard-deny it.
            gateway.launchablePackages[payload.trim()] = payload.trim()
            val result = tool.execute(
                context = ctx,
                arguments = mapOf("package_name" to RedTeamContexts.userStr(payload, SensitiveSlotKind.PACKAGE_NAME))
            )
            assertTrue(
                "AppLaunchTool MUST reject malicious package_name '$payload', got $result",
                result is ToolResult.Failure
            )
            gateway.launchablePackages.remove(payload.trim())
        }

        // Unallowlisted Android action strings are not installed packages and must fail cleanly.
        for (actionPayload in listOf("android.intent.action.VIEW", "ACTION_VIEW", "android.intent.action.SEND", "ACTION_SEND")) {
            val result = tool.execute(
                context = ctx,
                arguments = mapOf("package_name" to RedTeamContexts.userStr(actionPayload, SensitiveSlotKind.PACKAGE_NAME))
            )
            assertTrue(
                "AppLaunchTool MUST reject unallowlisted action '$actionPayload', got $result",
                result is ToolResult.Failure
            )
        }
        assertEquals("AppLaunchTool must never dispatch gateway on malicious payloads", 0, gateway.totalDispatchCount())
    }

    @Test
    fun appLaunchToolEnforcesFirewallDenialBeforeUntrustedConfirmation() = runBlocking {
        val gateway = RecordingIntentGateway()
        gateway.launchablePackages["https://evil.example/phish"] = "https://evil.example/phish"
        val firewall = StrictRedTeamFirewall()
        val audit = RecordingAuditLog()
        val tool = AppLaunchTool(gateway, firewall, audit)
        val ctx = RedTeamContexts.interactive(AutomationToolNames.LAUNCH_APP, ToolTargetIds.APP_LAUNCH)

        val result = tool.execute(
            context = ctx,
            arguments = mapOf(
                "package_name" to RedTeamContexts.untrustedStr(
                    "https://evil.example/phish",
                    SensitiveSlotKind.PACKAGE_NAME
                )
            )
        )

        assertTrue(
            "Untrusted hard-blocked URI in AppLaunchTool MUST fail with security violation (not prompt ConfirmationRequired); got $result",
            result is ToolResult.Failure && result.isSecurityViolation
        )
        assertEquals(0, gateway.totalDispatchCount())
    }

    @Test
    fun safPlatformGatewayIsSafeDocumentNameRejectsAllTraversalEncodingAndHomoglyphPayloads() {
        for (payload in traversalPayloads) {
            assertFalse(
                "SafPlatformGateway.isSafeDocumentName MUST reject adversarial filename '$payload'",
                SafPlatformGateway.isSafeDocumentName(payload)
            )
        }
        assertTrue(SafPlatformGateway.isSafeDocumentName("notes_2026.txt"))
        assertTrue(SafPlatformGateway.isSafeDocumentName("report-final.pdf"))
    }

    @Test
    fun safDirectoryToolsRejectAllTraversalAndMaliciousTreeUris() = runBlocking {
        val validTree = "content://com.android.externalstorage.documents/tree/primary%3ADocs"
        val gateway = RecordingSafGateway().apply {
            grantedTrees[validTree] = true
            documents[validTree] = mutableMapOf("safe.txt" to "ok".toByteArray(Charsets.UTF_8))
        }
        val firewall = StrictRedTeamFirewall()
        val audit = RecordingAuditLog()
        val readTool = SafDirectoryTool.createReadTool(gateway, firewall, audit)
        val writeTool = SafDirectoryTool.createWriteTool(gateway, firewall, audit)
        val deleteTool = SafDirectoryTool.createDeleteTool(gateway, firewall, audit)

        val readCtx = RedTeamContexts.interactive(AutomationToolNames.SAF_READ, ToolTargetIds.forSafTree(validTree))
        val writeCtx = RedTeamContexts.interactive(AutomationToolNames.SAF_WRITE, ToolTargetIds.forSafTree(validTree))
        val deleteCtx = RedTeamContexts.interactive(AutomationToolNames.SAF_DELETE, ToolTargetIds.forSafTree(validTree))

        for (badName in traversalPayloads) {
            val readRes = readTool.execute(
                readCtx,
                mapOf(
                    "tree_uri" to RedTeamContexts.userStr(validTree, SensitiveSlotKind.EXTERNAL_URI),
                    "file_name" to RedTeamContexts.userStr(badName, SensitiveSlotKind.FILE_PATH)
                )
            )
            assertTrue("SafReadTool MUST reject traversal filename '$badName', got $readRes", readRes is ToolResult.Failure)

            val writeRes = writeTool.execute(
                writeCtx,
                mapOf(
                    "tree_uri" to RedTeamContexts.userStr(validTree, SensitiveSlotKind.EXTERNAL_URI),
                    "file_name" to RedTeamContexts.userStr(badName, SensitiveSlotKind.FILE_PATH),
                    "content" to RedTeamContexts.userStr("data", SensitiveSlotKind.TEXT_BODY)
                )
            )
            assertTrue("SafWriteTool MUST reject traversal filename '$badName', got $writeRes", writeRes is ToolResult.Failure)

            val deleteRes = deleteTool.execute(
                deleteCtx,
                mapOf(
                    "tree_uri" to RedTeamContexts.userStr(validTree, SensitiveSlotKind.EXTERNAL_URI),
                    "file_name" to RedTeamContexts.userStr(badName, SensitiveSlotKind.FILE_PATH)
                )
            )
            assertTrue("SafDeleteTool MUST reject traversal filename '$badName', got $deleteRes", deleteRes is ToolResult.Failure)
        }

        // Also attack tree_uri itself even if erroneously present in grantedTrees
        val maliciousTreeUris = listOf(
            "http://evil.example/tree",
            "https://evil.example/tree",
            "ftp://evil.example/tree",
            "file:///data/data/com.nava/files/vault",
            "javascript:alert(1)",
            "data:text/plain,evil",
            "intent:#Intent;action=android.intent.action.VIEW;end",
            "content://com.android.externalstorage.documents/tree/../vault",
            "content://com.android.externalstorage.documents/tree/%2e%2e%2fvault"
        )
        for (badTree in maliciousTreeUris) {
            gateway.grantedTrees[badTree] = true
            val rRes = readTool.execute(readCtx, mapOf("tree_uri" to RedTeamContexts.userStr(badTree, SensitiveSlotKind.EXTERNAL_URI)))
            assertTrue("SafReadTool MUST reject malicious tree_uri '$badTree', got $rRes", rRes is ToolResult.Failure)

            val wRes = writeTool.execute(
                writeCtx,
                mapOf(
                    "tree_uri" to RedTeamContexts.userStr(badTree, SensitiveSlotKind.EXTERNAL_URI),
                    "file_name" to RedTeamContexts.userStr("a.txt", SensitiveSlotKind.FILE_PATH),
                    "content" to RedTeamContexts.userStr("hi", SensitiveSlotKind.TEXT_BODY)
                )
            )
            assertTrue("SafWriteTool MUST reject malicious tree_uri '$badTree', got $wRes", wRes is ToolResult.Failure)

            val dRes = deleteTool.execute(
                deleteCtx,
                mapOf(
                    "tree_uri" to RedTeamContexts.userStr(badTree, SensitiveSlotKind.EXTERNAL_URI),
                    "file_name" to RedTeamContexts.userStr("a.txt", SensitiveSlotKind.FILE_PATH)
                )
            )
            assertTrue("SafDeleteTool MUST reject malicious tree_uri '$badTree', got $dRes", dRes is ToolResult.Failure)
            gateway.grantedTrees.remove(badTree)
        }

        assertEquals("SAF gateway must never execute on malicious traversal or URI payloads", 0, gateway.totalOperationCount())
    }

    @Test
    fun calendarAndAlarmTimerToolsRejectUnallowlistedActionsAndMaliciousPayloads() = runBlocking {
        val calGateway = RecordingCalendarGateway()
        val intentGateway = RecordingIntentGateway()
        val firewall = StrictRedTeamFirewall()
        val audit = RecordingAuditLog()
        val calendarTool = CalendarTool(calGateway, firewall, audit)
        val alarmTimerTool = AlarmTimerTool(intentGateway, firewall, audit)

        val calModCtx = RedTeamContexts.interactive(AutomationToolNames.CALENDAR_MODIFY, ToolTargetIds.CALENDAR)
        val alarmCtx = RedTeamContexts.interactive(AutomationToolNames.SET_ALARM, ToolTargetIds.CLOCK)
        val timerCtx = RedTeamContexts.interactive(AutomationToolNames.SET_TIMER, ToolTargetIds.CLOCK)

        for (payload in schemeAndInjectionPayloads) {
            val calRes = calendarTool.modifyTool.execute(
                calModCtx,
                mapOf(
                    "operation" to RedTeamContexts.userStr(payload, SensitiveSlotKind.INTENT_ACTION),
                    "event_id" to RedTeamContexts.userInt(42L)
                )
            )
            assertTrue("CalendarModifyTool MUST reject malicious operation '$payload', got $calRes", calRes is ToolResult.Failure)

            val alarmRes = alarmTimerTool.setAlarmTool.execute(
                alarmCtx,
                mapOf("time" to RedTeamContexts.userStr(payload, SensitiveSlotKind.DATE_TIME))
            )
            assertTrue("SetAlarmTool MUST reject malicious time '$payload', got $alarmRes", alarmRes is ToolResult.Failure)

            val timerRes = alarmTimerTool.setTimerTool.execute(
                timerCtx,
                mapOf(
                    "duration_value" to RedTeamContexts.userInt(5L, SensitiveSlotKind.DURATION),
                    "duration_unit" to RedTeamContexts.userStr(payload, SensitiveSlotKind.DURATION)
                )
            )
            assertTrue("SetTimerTool MUST reject malicious duration_unit '$payload', got $timerRes", timerRes is ToolResult.Failure)
        }

        assertEquals(0, calGateway.totalWriteCalls())
        assertEquals(0, intentGateway.totalDispatchCount())
    }

    @Test
    fun firewallDenialPreventsDispatchAndRecordsAuditAcrossAllOutboundTools() = runBlocking {
        val deniedDecision = FirewallDecision.Denied(
            message = UserMessage(MessageKey.ERROR_SECURITY_VIOLATION, listOf(MessageArg.Text("OUTBOUND_POLICY_DENIED"))),
            reasonCode = "OUTBOUND_POLICY_DENIED"
        )
        val validTree = "content://com.android.externalstorage.documents/tree/primary%3ADocs"

        val intentGateway = RecordingIntentGateway(callPhonePermissionGranted = true)
        val calGateway = RecordingCalendarGateway()
        val safGateway = RecordingSafGateway().apply {
            grantedTrees[validTree] = true
            documents[validTree] = mutableMapOf("note.txt" to "secret".toByteArray(Charsets.UTF_8))
        }
        val firewall = StrictRedTeamFirewall(forcedOutboundDecision = deniedDecision)
        val audit = RecordingAuditLog()

        val alarmTimer = AlarmTimerTool(intentGateway, firewall, audit)
        val smsTool = SmsDraftTool(intentGateway, firewall, audit)
        val dialTool = CallIntentTool.createDialTool(intentGateway, firewall, audit)
        val placeTool = CallIntentTool.createPlaceTool(intentGateway, firewall, audit)
        val appLaunchTool = AppLaunchTool(intentGateway, firewall, audit)
        val calendar = CalendarTool(calGateway, firewall, audit)
        val safRead = SafDirectoryTool.createReadTool(safGateway, firewall, audit)
        val safWrite = SafDirectoryTool.createWriteTool(safGateway, firewall, audit)
        val safDelete = SafDirectoryTool.createDeleteTool(safGateway, firewall, audit)

        val invocations: List<Pair<String, suspend () -> ToolResult>> = listOf(
            AutomationToolNames.SET_ALARM to {
                alarmTimer.setAlarmTool.execute(
                    RedTeamContexts.interactive(AutomationToolNames.SET_ALARM, ToolTargetIds.CLOCK),
                    mapOf("hour" to RedTeamContexts.userInt(7), "minute" to RedTeamContexts.userInt(30))
                )
            },
            AutomationToolNames.SET_TIMER to {
                alarmTimer.setTimerTool.execute(
                    RedTeamContexts.interactive(AutomationToolNames.SET_TIMER, ToolTargetIds.CLOCK),
                    mapOf("duration_seconds" to RedTeamContexts.userInt(120))
                )
            },
            AutomationToolNames.CREATE_SMS_DRAFT to {
                smsTool.execute(
                    RedTeamContexts.interactive(AutomationToolNames.CREATE_SMS_DRAFT, ToolTargetIds.SMS),
                    mapOf(
                        "recipient" to RedTeamContexts.userStr("+15551234567", SensitiveSlotKind.PHONE_NUMBER),
                        "body" to RedTeamContexts.userStr("Hello")
                    )
                )
            },
            AutomationToolNames.DIAL_CALL to {
                dialTool.execute(
                    RedTeamContexts.interactive(AutomationToolNames.DIAL_CALL, ToolTargetIds.PHONE),
                    mapOf("phone_number" to RedTeamContexts.userStr("+15551234567", SensitiveSlotKind.PHONE_NUMBER))
                )
            },
            AutomationToolNames.PLACE_CALL to {
                placeTool.execute(
                    RedTeamContexts.interactive(AutomationToolNames.PLACE_CALL, ToolTargetIds.PHONE),
                    mapOf("phone_number" to RedTeamContexts.userStr("+15551234567", SensitiveSlotKind.PHONE_NUMBER))
                )
            },
            AutomationToolNames.LAUNCH_APP to {
                appLaunchTool.execute(
                    RedTeamContexts.interactive(AutomationToolNames.LAUNCH_APP, ToolTargetIds.APP_LAUNCH),
                    mapOf("package_name" to RedTeamContexts.userStr("com.nava.safeapp", SensitiveSlotKind.PACKAGE_NAME))
                )
            },
            AutomationToolNames.CALENDAR_QUERY to {
                calendar.queryTool.execute(
                    RedTeamContexts.interactive(AutomationToolNames.CALENDAR_QUERY, ToolTargetIds.CALENDAR),
                    mapOf(
                        "start_epoch_ms" to RedTeamContexts.userInt(RedTeamContexts.FIXED_NOW_MS),
                        "end_epoch_ms" to RedTeamContexts.userInt(RedTeamContexts.FIXED_NOW_MS + 3_600_000L)
                    )
                )
            },
            AutomationToolNames.CALENDAR_CREATE to {
                calendar.createTool.execute(
                    RedTeamContexts.interactive(AutomationToolNames.CALENDAR_CREATE, ToolTargetIds.CALENDAR),
                    mapOf("title" to RedTeamContexts.userStr("Standup"))
                )
            },
            AutomationToolNames.CALENDAR_MODIFY to {
                calendar.modifyTool.execute(
                    RedTeamContexts.interactive(AutomationToolNames.CALENDAR_MODIFY, ToolTargetIds.CALENDAR),
                    mapOf(
                        "operation" to RedTeamContexts.userStr("delete"),
                        "event_id" to RedTeamContexts.userInt(99L)
                    )
                )
            },
            AutomationToolNames.SAF_READ to {
                safRead.execute(
                    RedTeamContexts.interactive(AutomationToolNames.SAF_READ, ToolTargetIds.forSafTree(validTree)),
                    mapOf(
                        "tree_uri" to RedTeamContexts.userStr(validTree, SensitiveSlotKind.EXTERNAL_URI),
                        "file_name" to RedTeamContexts.userStr("note.txt", SensitiveSlotKind.FILE_PATH)
                    )
                )
            },
            AutomationToolNames.SAF_WRITE to {
                safWrite.execute(
                    RedTeamContexts.interactive(AutomationToolNames.SAF_WRITE, ToolTargetIds.forSafTree(validTree)),
                    mapOf(
                        "tree_uri" to RedTeamContexts.userStr(validTree, SensitiveSlotKind.EXTERNAL_URI),
                        "file_name" to RedTeamContexts.userStr("note.txt", SensitiveSlotKind.FILE_PATH),
                        "content" to RedTeamContexts.userStr("updated")
                    )
                )
            },
            AutomationToolNames.SAF_DELETE to {
                safDelete.execute(
                    RedTeamContexts.interactive(AutomationToolNames.SAF_DELETE, ToolTargetIds.forSafTree(validTree)),
                    mapOf(
                        "tree_uri" to RedTeamContexts.userStr(validTree, SensitiveSlotKind.EXTERNAL_URI),
                        "file_name" to RedTeamContexts.userStr("note.txt", SensitiveSlotKind.FILE_PATH)
                    )
                )
            }
        )

        for ((toolName, runTool) in invocations) {
            val auditBefore = audit.entries.size
            val res = runTool()
            assertTrue(
                "Tool '$toolName' MUST return ToolResult.Failure(isSecurityViolation=true) on FirewallDecision.Denied, got $res",
                res is ToolResult.Failure && res.isSecurityViolation
            )
            assertTrue(
                "Tool '$toolName' MUST record an audit entry when denied by firewall",
                audit.entries.size > auditBefore
            )
        }

        assertEquals("Zero intent dispatches permitted when firewall denies", 0, intentGateway.totalDispatchCount())
        assertEquals("Zero calendar queries permitted when firewall denies", 0, calGateway.queryCalls)
        assertEquals("Zero calendar writes permitted when firewall denies", 0, calGateway.totalWriteCalls())
        assertEquals("Zero SAF operations permitted when firewall denies", 0, safGateway.totalOperationCount())
    }

    @Test
    fun productionGatewayAndToolsNeverEmitActionViewOrHttpHttpsUris() {
        val mainSrcDir = resolveModulePath("src/main/kotlin")
        assertTrue("Production source directory must exist: ${mainSrcDir.absolutePath}", mainSrcDir.isDirectory)

        val ktFiles = mainSrcDir.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        assertTrue("Expected production Kotlin files under feature-automations", ktFiles.isNotEmpty())

        val forbiddenPatterns = listOf(
            Regex("""\bACTION_VIEW\b"""),
            Regex("""android\.intent\.action\.VIEW"""),
            Regex("""\bACTION_SEND\b(?![A-Za-z0-9_])"""),
            Regex("""android\.intent\.action\.SEND(?![A-Za-z0-9_])"""),
            Regex("""\bACTION_WEB_SEARCH\b"""),
            Regex("""https?://""", RegexOption.IGNORE_CASE),
            Regex("""\bjavascript:""", RegexOption.IGNORE_CASE)
        )

        for (file in ktFiles) {
            val codeWithoutComments = stripComments(file.readText(Charsets.UTF_8))
            for (pattern in forbiddenPatterns) {
                assertFalse(
                    "Forbidden outbound action/URI pattern '${pattern.pattern}' found in ${file.name}",
                    pattern.containsMatchIn(codeWithoutComments)
                )
            }
        }

        // Also validate gateway companion validators reject all attack payloads
        for (payload in schemeAndInjectionPayloads) {
            assertFalse(
                "isValidDialableNumber must reject '$payload'",
                AndroidAutomationIntentGateway.isValidDialableNumber(payload)
            )
            if (payload != "android.intent.action.VIEW" && payload != "android.intent.action.SEND") {
                assertFalse(
                    "isValidPackageName must reject '$payload'",
                    AndroidAutomationIntentGateway.isValidPackageName(payload)
                )
            }
        }
    }

    @Test
    fun androidManifestDeclaresZeroForbiddenPermissionsAndProtectsNotificationListener() {
        val manifestFile = resolveModulePath("src/main/AndroidManifest.xml")
        assertTrue("AndroidManifest.xml must exist at ${manifestFile.absolutePath}", manifestFile.isFile)

        val rawXml = manifestFile.readText(Charsets.UTF_8)
        val forbiddenPermissions = listOf(
            "android.permission.INTERNET",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.SEND_SMS",
            "android.permission.READ_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW"
        )
        for (perm in forbiddenPermissions) {
            assertFalse(
                "AndroidManifest.xml MUST NOT declare forbidden permission '$perm'",
                rawXml.contains(perm)
            )
        }

        val factory = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
        val doc = factory.newDocumentBuilder().parse(manifestFile)
        val androidNs = "http://schemas.android.com/apk/res/android"
        val services = doc.getElementsByTagName("service")
        var foundProtectedListener = false

        for (i in 0 until services.length) {
            val node = services.item(i)
            val attrs = node.attributes ?: continue
            val name = attrs.getNamedItemNS(androidNs, "name")?.nodeValue.orEmpty()
            val permission = attrs.getNamedItemNS(androidNs, "permission")?.nodeValue.orEmpty()
            if (name.endsWith("NavaNotificationListenerService")) {
                assertEquals(
                    "NavaNotificationListenerService MUST require BIND_NOTIFICATION_LISTENER_SERVICE",
                    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
                    permission
                )
                foundProtectedListener = true
            }
        }
        assertTrue(
            "AndroidManifest.xml MUST declare NavaNotificationListenerService protected by BIND_NOTIFICATION_LISTENER_SERVICE",
            foundProtectedListener
        )
    }

    private fun resolveModulePath(relativePath: String): File {
        val direct = File(relativePath)
        if (direct.exists()) return direct
        val fromRoot = File("feature-automations", relativePath)
        if (fromRoot.exists()) return fromRoot
        return direct
    }

    private fun stripComments(source: String): String {
        val withoutBlock = source.replace(Regex("""/\*.*?\*/""", setOf(RegexOption.DOT_MATCHES_ALL)), "")
        return withoutBlock.lines().joinToString("\n") { line ->
            val idx = line.indexOf("//")
            if (idx >= 0) line.substring(0, idx) else line
        }
    }
}

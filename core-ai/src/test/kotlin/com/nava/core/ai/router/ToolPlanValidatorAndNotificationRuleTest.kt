package com.nava.core.ai.router

import com.nava.core.ai.locale.AssetLocaleRulePackLoader
import com.nava.core.ai.locale.DirectoryAssetTextReader
import com.nava.core.ai.locale.SeedLocaleNormalizers
import com.nava.core.ai.testing.FakeSecurityFirewallPort
import com.nava.domain.ai.IntentRequest
import com.nava.domain.ai.ResolutionResult
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.locale.DetectedLanguage
import com.nava.domain.locale.GenericTextNormalizer
import com.nava.domain.locale.ScriptFamily
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolCategory
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolSchemaField
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.time.ZoneOffset

class ToolPlanValidatorAndNotificationRuleTest {

    private val assetsRoot: File = run {
        val direct = File("src/main/assets")
        if (direct.exists()) direct else File("core-ai/src/main/assets")
    }

    private val rulePackLoader = AssetLocaleRulePackLoader(DirectoryAssetTextReader(assetsRoot))
    private val normalizer = GenericTextNormalizer(SeedLocaleNormalizers.createRegistry())

    private val summarizeNotificationsMeta = ToolMetadata(
        name = "summarize_notifications",
        displayNameKey = "tool_summarize_notifications_name",
        description = "Summarizes recent notifications captured from permitted applications",
        category = ToolCategory.COMMUNICATION,
        requiredCapability = AtomicCapability.NOTIFICATION_READ,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "package_name",
                description = "Optional package name filter",
                required = false,
                slotKind = SensitiveSlotKind.PACKAGE_NAME,
                valueType = SlotValueType.STRING
            ),
            ToolSchemaField(
                name = "limit",
                description = "Maximum number of notifications to summarize",
                required = false,
                slotKind = SensitiveSlotKind.DURATION,
                valueType = SlotValueType.INTEGER
            )
        )
    )

    private val launchAppMeta = ToolMetadata(
        name = "launch_app",
        displayNameKey = "tool_launch_app",
        description = "Launches an installed application",
        category = ToolCategory.DEVICE_SETTINGS,
        requiredCapability = AtomicCapability.APP_LAUNCH,
        schemaVersion = 1,
        fields = listOf(
            ToolSchemaField(
                name = "package_name",
                description = "Package name",
                required = false,
                slotKind = SensitiveSlotKind.PACKAGE_NAME,
                valueType = SlotValueType.STRING
            )
        )
    )

    @Test
    fun turkishNotificationUtterancesMatchTier1Rule() = runTest {
        val resolver = RuleIntentResolver(
            rulePackLoader = rulePackLoader,
            securityFirewall = FakeSecurityFirewallPort(),
            textNormalizer = normalizer,
            zoneIdProvider = { ZoneOffset.UTC }
        )

        val utterances = listOf(
            "Telefondaki mevcut bildirimi oku",
            "telefondaki bildirimleri oku",
            "cihazdaki gelen bildirimleri ozetle",
            "telefondaki son 5 bildirimi goster"
        )

        for (utterance in utterances) {
            val result = resolver.resolve(
                request = IntentRequest(
                    requestId = "req-$utterance",
                    rawUtterance = utterance,
                    languageHint = DetectedLanguage("tr", 1.0f, ScriptFamily.LATIN),
                    issuedAtEpochMs = 1_760_000_000_000L
                ),
                availableTools = listOf(summarizeNotificationsMeta)
            )
            assertTrue("Expected Tier 1 ResolvedPlan for '$utterance', got $result", result is ResolutionResult.ResolvedPlan)
            val plan = result as ResolutionResult.ResolvedPlan
            assertEquals(ResolutionTier.TIER_1_RULE, plan.tier)
            assertEquals("summarize_notifications", plan.plan.calls.single().toolName)
        }
    }

    @Test
    fun validatorStripsGenericPlaceholderOptionalPackageNameOnlyForNonLaunchTools() {
        val placeholderCall = ToolCallAst(
            toolName = "summarize_notifications",
            arguments = mapOf(
                "package_name" to Tainted.fromUserUtterance(
                    value = SlotValueAst.StringValue("default"),
                    slotKind = SensitiveSlotKind.PACKAGE_NAME
                ),
                "limit" to Tainted.fromUserUtterance(
                    value = SlotValueAst.IntValue(1L),
                    slotKind = SensitiveSlotKind.DURATION
                )
            ),
            orderIndex = 0
        )

        val res = ToolPlanValidator.validateAndNormalizeCalls(
            calls = listOf(placeholderCall),
            prunedByName = mapOf(summarizeNotificationsMeta.name to summarizeNotificationsMeta),
            targetContextId = "system.notifications"
        ) as ToolPlanValidator.ValidationResult.Valid

        val normalizedArgs = res.normalizedCalls.single().arguments
        assertFalse("Placeholder 'default' must be stripped", normalizedArgs.containsKey("package_name"))
        assertEquals(SlotValueAst.IntValue(1L), normalizedArgs["limit"]?.value)

        // Malicious URI scheme must NEVER be stripped so SecurityFirewall rejects it.
        val maliciousCall = placeholderCall.copy(
            arguments = mapOf(
                "package_name" to Tainted.fromUserUtterance(
                    value = SlotValueAst.StringValue("https://evil.example/leak"),
                    slotKind = SensitiveSlotKind.PACKAGE_NAME
                )
            )
        )
        val maliciousRes = ToolPlanValidator.validateAndNormalizeCalls(
            calls = listOf(maliciousCall),
            prunedByName = mapOf(summarizeNotificationsMeta.name to summarizeNotificationsMeta),
            targetContextId = "system.notifications"
        ) as ToolPlanValidator.ValidationResult.Valid
        assertEquals(
            SlotValueAst.StringValue("https://evil.example/leak"),
            maliciousRes.normalizedCalls.single().arguments["package_name"]?.value
        )

        // launch_app must NEVER have package_name stripped even if value is "default".
        val launchCall = ToolCallAst(
            toolName = "launch_app",
            arguments = mapOf(
                "package_name" to Tainted.fromUserUtterance(
                    value = SlotValueAst.StringValue("default"),
                    slotKind = SensitiveSlotKind.PACKAGE_NAME
                )
            ),
            orderIndex = 0
        )
        val launchRes = ToolPlanValidator.validateAndNormalizeCalls(
            calls = listOf(launchCall),
            prunedByName = mapOf(launchAppMeta.name to launchAppMeta),
            targetContextId = "system.app_launch"
        ) as ToolPlanValidator.ValidationResult.Valid
        assertTrue(launchRes.normalizedCalls.single().arguments.containsKey("package_name"))
    }
}

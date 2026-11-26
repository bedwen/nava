package com.nava.core.ai.router

import com.nava.core.ai.engine.LiteRtLlmEngine
import com.nava.core.ai.engine.RuntimeStreamDelta
import com.nava.core.ai.json.SimpleJsonParser
import com.nava.core.ai.lifecycle.DeviceHardwareSnapshot
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.core.ai.locale.AssetLocaleRulePackLoader
import com.nava.core.ai.locale.AssetSupportedLanguageCatalog
import com.nava.core.ai.locale.DirectoryAssetTextReader
import com.nava.core.ai.locale.OnDeviceLanguageDetector
import com.nava.core.ai.locale.SeedLocaleNormalizers
import com.nava.core.ai.testing.CoreAiTestFixtures
import com.nava.core.ai.testing.FakeHardwareStatusProvider
import com.nava.core.ai.testing.FakeLiteRtRuntimeAdapter
import com.nava.core.ai.testing.FakeSecurityFirewallPort
import com.nava.core.ai.testing.InMemoryActionCachePort
import com.nava.domain.ai.IntentRequest
import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.ResolutionResult
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.locale.DetectedLanguage
import com.nava.domain.locale.GenericTextNormalizer
import com.nava.domain.locale.LocaleRulePack
import com.nava.domain.locale.ScriptFamily
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.SlotValueType
import com.nava.domain.tool.ToolCategory
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolSchemaField
import com.nava.domain.ui.MessageKey
import com.nava.domain.usecase.ProcessQueryUseCase
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.time.ZoneOffset
import java.time.ZonedDateTime

class ThreeTierHybridRouterTest {

    private val assetsReader = DirectoryAssetTextReader(CoreAiTestFixtures.resolveAssetsDir())
    private val catalog = AssetSupportedLanguageCatalog(assetsReader)
    private val rulePackLoader = AssetLocaleRulePackLoader(assetsReader)
    private val normalizer = GenericTextNormalizer(SeedLocaleNormalizers.createRegistry())
    private val timeResolver = LocaleTimeResolver()
    private val allTools = CoreAiTestFixtures.canonicalTools()

    private lateinit var tempDir: File
    private lateinit var fakeModelFile: File

    @Before
    fun setUp() {
        tempDir = Files.createTempDirectory("nava_router_test").toFile()
        fakeModelFile = File(tempDir, "gemma-4-E2B-it.litertlm").apply {
            writeBytes(byteArrayOf(1, 2, 3, 4))
        }
    }

    @After
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    @Test
    fun ruleIntentResolverMatchesAllFiftySeedGoldenCasesAndSkipsComplexAndLayerGCases() = runTest {
        val firewall = FakeSecurityFirewallPort()
        val resolver = RuleIntentResolver(
            rulePackLoader = rulePackLoader,
            securityFirewall = firewall,
            textNormalizer = normalizer,
            timeResolver = timeResolver,
            zoneIdProvider = { ZoneOffset.UTC }
        )
        val testResourcesDir = CoreAiTestFixtures.resolveTestResourcesDir()
        val fixedEpochMs = 1_760_000_000_000L
        val fixedNow = ZonedDateTime.ofInstant(java.time.Instant.ofEpochMilli(fixedEpochMs), ZoneOffset.UTC)

        val seedTags = listOf("en", "tr", "ar", "es", "fr")
        var totalTier1Cases = 0

        for (tag in seedTags) {
            val pack = rulePackLoader.loadRulePack(tag)!!
            val corpusFile = File(testResourcesDir, "locale/$tag/golden_utterances.json")
            val root = SimpleJsonParser.parse(corpusFile.readText(Charsets.UTF_8)).asObject()
            val scriptFamily = ScriptFamily.valueOf(root.getValue("scriptFamily").asString())
            val cases = root.getValue("cases").asArray()

            for (caseNode in cases) {
                val obj = caseNode.asObject()
                val caseId = obj.getValue("id").asString()
                val utterance = obj.getValue("utterance").asString()
                val expectedTier = obj.getValue("expectedTier").asString()

                val request = IntentRequest(
                    requestId = caseId,
                    rawUtterance = utterance,
                    normalizedText = normalizer.normalize(utterance, tag),
                    languageHint = DetectedLanguage(tag, 0.95f, scriptFamily),
                    issuedAtEpochMs = fixedEpochMs
                )

                val result = resolver.resolve(request, allTools)
                if (expectedTier == "TIER_1_RULE") {
                    totalTier1Cases++
                    assertTrue("Expected TIER_1_RULE match for $caseId", result is ResolutionResult.ResolvedPlan)
                    val resolved = result as ResolutionResult.ResolvedPlan
                    assertEquals(ResolutionTier.TIER_1_RULE, resolved.tier)

                    val expectedTool = obj.getValue("expectedTool").asString()
                    val call = resolved.plan.calls.single()
                    assertEquals("Tool mismatch for $caseId", expectedTool, call.toolName)

                    val rawExpectedSlots = obj.getValue("expectedSlots").asObject()
                        .mapValues { it.value.asString() }
                    assertCanonicalSlots(caseId, expectedTool, rawExpectedSlots, pack, fixedNow, call)
                } else {
                    assertEquals("Expected NO_MATCH_TIER_1 for $caseId", ResolutionResult.NoMatch, result)
                }
            }
        }

        assertEquals(50, totalTier1Cases)

        val layerGTags = listOf("ru", "el", "he", "hi", "th", "ja", "zh", "ko", "sw")
        for (tag in layerGTags) {
            val corpusFile = File(testResourcesDir, "locale/$tag/golden_utterances.json")
            val root = SimpleJsonParser.parse(corpusFile.readText(Charsets.UTF_8)).asObject()
            val scriptFamily = ScriptFamily.valueOf(root.getValue("scriptFamily").asString())
            val cases = root.getValue("cases").asArray()
            for (caseNode in cases) {
                val obj = caseNode.asObject()
                val utterance = obj.getValue("utterance").asString()
                val req = IntentRequest(
                    requestId = obj.getValue("id").asString(),
                    rawUtterance = utterance,
                    normalizedText = normalizer.normalize(utterance, tag),
                    languageHint = DetectedLanguage(tag, 0.9f, scriptFamily),
                    issuedAtEpochMs = fixedEpochMs
                )
                assertEquals(ResolutionResult.NoMatch, resolver.resolve(req, allTools))
            }
        }
    }

    @Test
    fun tier1RuleIntentResolverMeetsP95UnderTwoMillisecondsBenchmark() = runTest {
        val resolver = RuleIntentResolver(
            rulePackLoader = rulePackLoader,
            securityFirewall = FakeSecurityFirewallPort(),
            textNormalizer = normalizer,
            timeResolver = timeResolver,
            zoneIdProvider = { ZoneOffset.UTC }
        )
        val testResourcesDir = CoreAiTestFixtures.resolveTestResourcesDir()
        val benchmarkRequests = mutableListOf<IntentRequest>()

        for (tag in listOf("en", "tr", "ar", "es", "fr")) {
            val corpusFile = File(testResourcesDir, "locale/$tag/golden_utterances.json")
            val root = SimpleJsonParser.parse(corpusFile.readText(Charsets.UTF_8)).asObject()
            val scriptFamily = ScriptFamily.valueOf(root.getValue("scriptFamily").asString())
            for (caseNode in root.getValue("cases").asArray()) {
                val obj = caseNode.asObject()
                if (obj.getValue("expectedTier").asString() == "TIER_1_RULE") {
                    val utterance = obj.getValue("utterance").asString()
                    benchmarkRequests.add(
                        IntentRequest(
                            requestId = obj.getValue("id").asString(),
                            rawUtterance = utterance,
                            normalizedText = normalizer.normalize(utterance, tag),
                            languageHint = DetectedLanguage(tag, 0.95f, scriptFamily),
                            issuedAtEpochMs = 1_760_000_000_000L
                        )
                    )
                }
            }
        }

        // Warm up JVM JIT and compiled regex cache
        repeat(3) {
            for (req in benchmarkRequests) {
                resolver.resolve(req, allTools)
            }
        }

        val latenciesNs = ArrayList<Long>(benchmarkRequests.size * 5)
        repeat(5) {
            for (req in benchmarkRequests) {
                val startNs = System.nanoTime()
                val res = resolver.resolve(req, allTools)
                val elapsedNs = System.nanoTime() - startNs
                assertTrue(res is ResolutionResult.ResolvedPlan)
                latenciesNs.add(elapsedNs)
            }
        }

        latenciesNs.sort()
        val p95Index = ((latenciesNs.size - 1) * 0.95).toInt()
        val p95Ms = latenciesNs[p95Index] / 1_000_000.0
        assertTrue("Expected Tier 1 p95 < 2.0 ms, measured ${p95Ms} ms", p95Ms < 2.0)
    }

    @Test
    fun skeletonNormalizerAndCacheIntentResolverReplayWithFreshTokenAndSchemaInvalidation() = runTest {
        val skeletonNormalizer = SkeletonNormalizer()
        val cachePort = InMemoryActionCachePort()
        val firewall = FakeSecurityFirewallPort()
        val cacheResolver = CacheIntentResolver(
            actionCachePort = cachePort,
            securityFirewall = firewall,
            textNormalizer = normalizer,
            skeletonNormalizer = skeletonNormalizer
        )

        val admitUtterance = "Remind me at 09:30 with label \"Morning\" and 5"
        val admitNormalized = normalizer.normalize(admitUtterance, "en")
        val admitReq = IntentRequest(
            requestId = "req-admit",
            rawUtterance = admitUtterance,
            normalizedText = admitNormalized,
            languageHint = DetectedLanguage("en", 0.95f, ScriptFamily.LATIN),
            issuedAtEpochMs = 1_000_000L
        )
        val admittedPlan = PlanAst(
            planId = "tier3-plan-1",
            calls = listOf(
                ToolCallAst(
                    toolName = "set_alarm",
                    arguments = mapOf(
                        "time" to Tainted.fromUserUtterance(SlotValueAst.StringValue("09:30"), SensitiveSlotKind.DATE_TIME),
                        "label" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Morning"), SensitiveSlotKind.TEXT_BODY)
                    )
                )
            )
        )

        assertFalse(cacheResolver.admitPlan(admitReq, admittedPlan, allTools, userApproved = false, touchesVault = false, nowEpochSec = 1000L))
        assertFalse(cacheResolver.admitPlan(admitReq, admittedPlan, allTools, userApproved = true, touchesVault = true, nowEpochSec = 1000L))
        val untrustedPlan = PlanAst(
            planId = "tier3-untrusted",
            calls = listOf(
                ToolCallAst(
                    toolName = "set_alarm",
                    arguments = mapOf(
                        "time" to Tainted.fromUntrustedExternal(SlotValueAst.StringValue("09:30"), SensitiveSlotKind.DATE_TIME)
                    )
                )
            )
        )
        assertFalse(cacheResolver.admitPlan(admitReq, untrustedPlan, allTools, userApproved = true, touchesVault = false, nowEpochSec = 1000L))
        assertTrue(cacheResolver.admitPlan(admitReq, admittedPlan, allTools, userApproved = true, touchesVault = false, nowEpochSec = 1000L))

        val replay1Utterance = "Remind me at 14:45 with label \"Afternoon\" and 10"
        val replay1 = cacheResolver.resolve(
            IntentRequest(
                requestId = "req-replay-1",
                rawUtterance = replay1Utterance,
                normalizedText = normalizer.normalize(replay1Utterance, "en"),
                languageHint = DetectedLanguage("en", 0.95f, ScriptFamily.LATIN),
                issuedAtEpochMs = 2_000_000L
            ),
            allTools
        ) as ResolutionResult.ResolvedPlan

        val replay2Utterance = "Remind me at 21:15 with label \"Evening\" and 15"
        val replay2 = cacheResolver.resolve(
            IntentRequest(
                requestId = "req-replay-2",
                rawUtterance = replay2Utterance,
                normalizedText = normalizer.normalize(replay2Utterance, "en"),
                languageHint = DetectedLanguage("en", 0.95f, ScriptFamily.LATIN),
                issuedAtEpochMs = 3_000_000L
            ),
            allTools
        ) as ResolutionResult.ResolvedPlan

        assertEquals(ResolutionTier.TIER_2_CACHE, replay1.tier)
        assertEquals(SlotValueAst.StringValue("14:45"), replay1.plan.calls.single().arguments.getValue("time").value)
        assertEquals(SlotValueAst.StringValue("Afternoon"), replay1.plan.calls.single().arguments.getValue("label").value)
        assertEquals(SlotValueAst.StringValue("21:15"), replay2.plan.calls.single().arguments.getValue("time").value)
        assertNotEquals(replay1.capabilityToken.tokenId, replay2.capabilityToken.tokenId)

        // Schema version bump invalidates cached template
        val bumpedTools = allTools.map { tool ->
            if (tool.name == "set_alarm") tool.copy(schemaVersion = 2) else tool
        }
        val afterBump = cacheResolver.resolve(
            IntentRequest(
                requestId = "req-bump",
                rawUtterance = replay1Utterance,
                normalizedText = normalizer.normalize(replay1Utterance, "en"),
                languageHint = DetectedLanguage("en", 0.95f, ScriptFamily.LATIN),
                issuedAtEpochMs = 4_000_000L
            ),
            bumpedTools
        )
        assertEquals(ResolutionResult.NoMatch, afterBump)
        assertEquals(0, cachePort.size())
    }

    @Test
    fun gemmaIntentResolverHandlesPlansRepliesHallucinationsThoughtAbortsAndThermalSevere() = runTest {
        val gb = 1024L * 1024L * 1024L
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val runtime = FakeLiteRtRuntimeAdapter()
        val engine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime
        )
        val gemmaResolver = GemmaIntentResolver(
            llmEngine = engine,
            lifecycleManager = lifecycle,
            securityFirewall = FakeSecurityFirewallPort()
        )

        // Multi-step plan
        runtime.enqueueDeltas(
            listOf(
                RuntimeStreamDelta(
                    outputDelta = "<|tool_call>call:set_alarm{time:<|\"|>07:30<|\"|>}<tool_call|>" +
                        "<|tool_call>call:save_note{title:<|\"|>Standup<|\"|>,body:<|\"|>Review sprint<|\"|>}<tool_call|>"
                )
            )
        )
        val planRes = gemmaResolver.resolve(
            IntentRequest("r1", "Set alarm for 07:30, and also save a note about standup", issuedAtEpochMs = 100L),
            allTools
        ) as ResolutionResult.ResolvedPlan
        assertEquals(ResolutionTier.TIER_3_GEMMA, planRes.tier)
        assertEquals(2, planRes.plan.calls.size)

        // Direct conversational reply
        runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "It looks like you have no alarms yet.")))
        val replyRes = gemmaResolver.resolve(
            IntentRequest("r2", "What can you help me with?", issuedAtEpochMs = 200L),
            allTools
        ) as ResolutionResult.ConversationalReply
        assertEquals("It looks like you have no alarms yet.", replyRes.replyText)

        // Hallucinated tool rejection
        runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "<|tool_call>call:wipe_device{confirm:true}<tool_call|>")))
        val hallucinated = gemmaResolver.resolve(
            IntentRequest("r3", "Do something unsafe", issuedAtEpochMs = 300L),
            allTools
        ) as ResolutionResult.ClarificationNeeded
        assertEquals(MessageKey.ERROR_CLARIFICATION_NEEDED, hallucinated.message.key)

        // Unclosed thought channel
        runtime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "<|channel>thought\nInfinite reasoning...")))
        val thoughtAbort = gemmaResolver.resolve(
            IntentRequest("r4", "Set alarm for 07:30, then 08:30, and summarize everything for tomorrow morning", issuedAtEpochMs = 400L),
            allTools
        ) as ResolutionResult.ClarificationNeeded
        assertEquals(MessageKey.ERROR_THOUGHT_BUDGET_EXCEEDED, thoughtAbort.message.key)

        // Severe thermal throttling
        hardware.snapshot = DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_SEVERE, 90)
        val severe = gemmaResolver.resolve(
            IntentRequest("r5", "Save a note", issuedAtEpochMs = 500L),
            allTools
        ) as ResolutionResult.ClarificationNeeded
        assertEquals(MessageKey.ERROR_MODEL_UNAVAILABLE, severe.message.key)
    }

    @Test
    fun processQueryUseCaseRoutesAcrossTier1Tier2AndTier3InPriorityOrder() = runTest {
        val gb = 1024L * 1024L * 1024L
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val runtime = FakeLiteRtRuntimeAdapter()
        val engine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime
        )
        val firewall = FakeSecurityFirewallPort()
        val cachePort = InMemoryActionCachePort()
        val tier1 = RuleIntentResolver(rulePackLoader, firewall, normalizer, timeResolver, { ZoneOffset.UTC })
        val tier2 = CacheIntentResolver(cachePort, firewall, normalizer)
        val tier3 = GemmaIntentResolver(engine, lifecycle, securityFirewall = firewall)
        val detector = OnDeviceLanguageDetector(catalog, textNormalizer = normalizer)

        val useCase = ProcessQueryUseCase(
            resolvers = listOf(tier3, tier1, tier2),
            toolRegistry = CoreAiTestFixtures.canonicalToolRegistry(),
            languageDetector = detector,
            textNormalizer = normalizer
        )

        // 1. Tier 1 hit (LLM is never called)
        val t1 = useCase(
            requestId = "u1",
            rawUtterance = "Set an alarm for 07:30",
            appLocaleTag = "en",
            issuedAtEpochMs = 1_000_000L
        ) as ResolutionResult.ResolvedPlan
        assertEquals(ResolutionTier.TIER_1_RULE, t1.tier)
        assertEquals(0, runtime.clonedTurnCalls.size)

        // 2. Tier 3 hit for a novel phrasing not in Layer R, then admit to Tier 2 cache
        val novelUtterance = "Remember to wake me up at 08:15 tomorrow"
        runtime.enqueueDeltas(
            listOf(RuntimeStreamDelta(outputDelta = "<|tool_call>call:set_alarm{time:<|\"|>08:15<|\"|>}<tool_call|>"))
        )
        val t3 = useCase(
            requestId = "u2",
            rawUtterance = novelUtterance,
            appLocaleTag = "en",
            issuedAtEpochMs = 2_000_000L
        ) as ResolutionResult.ResolvedPlan
        assertEquals(ResolutionTier.TIER_3_GEMMA, t3.tier)
        assertEquals(1, runtime.clonedTurnCalls.size)

        val admitReq = IntentRequest(
            requestId = "u2",
            rawUtterance = novelUtterance,
            normalizedText = normalizer.normalize(novelUtterance, "en"),
            languageHint = DetectedLanguage("en", 0.95f, ScriptFamily.LATIN),
            issuedAtEpochMs = 2_000_000L
        )
        assertTrue(tier2.admitPlan(admitReq, t3.plan, allTools, userApproved = true, touchesVault = false, nowEpochSec = 2_000L))

        // 3. Tier 2 cache hit with different time (LLM call count remains 1)
        val t2 = useCase(
            requestId = "u3",
            rawUtterance = "Remember to wake me up at 09:45 tomorrow",
            appLocaleTag = "en",
            issuedAtEpochMs = 3_000_000L
        ) as ResolutionResult.ResolvedPlan
        assertEquals(ResolutionTier.TIER_2_CACHE, t2.tier)
        assertEquals(SlotValueAst.StringValue("09:45"), t2.plan.calls.single().arguments.getValue("time").value)
        assertEquals(1, runtime.clonedTurnCalls.size)
    }

    @Test
    fun cacheIntentResolverRejectsUnparameterizedTemporalLiteralsPreservesTurkishCaseAndIsolatesTargetContext() = runTest {
        val skeletonNormalizer = SkeletonNormalizer()
        val cachePort = InMemoryActionCachePort()
        val firewall = FakeSecurityFirewallPort()
        val cacheResolver = CacheIntentResolver(
            actionCachePort = cachePort,
            securityFirewall = firewall,
            textNormalizer = normalizer,
            skeletonNormalizer = skeletonNormalizer
        )

        // HIGH-4: reject unparameterized ISO_DATE/ISO_TIME/ISO_DATETIME literal (e.g. "tomorrow" -> "2026-11-20")
        val relativeDateUtterance = "Schedule meeting tomorrow"
        val relativeDateReq = IntentRequest(
            requestId = "req-rel-date",
            rawUtterance = relativeDateUtterance,
            normalizedText = normalizer.normalize(relativeDateUtterance, "en"),
            languageHint = DetectedLanguage("en", 0.95f, ScriptFamily.LATIN),
            issuedAtEpochMs = 1_000_000L
        )
        val unparameterizedPlan = PlanAst(
            planId = "plan-rel-date",
            calls = listOf(
                ToolCallAst(
                    toolName = "create_calendar_event",
                    arguments = mapOf(
                        "title" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Meeting"), SensitiveSlotKind.EVENT_TITLE),
                        "date" to Tainted.fromUserUtterance(SlotValueAst.StringValue("2026-11-20"), SensitiveSlotKind.DATE_TIME)
                    )
                )
            )
        )
        assertFalse(
            cacheResolver.admitPlan(
                request = relativeDateReq,
                plan = unparameterizedPlan,
                availableTools = allTools,
                userApproved = true,
                touchesVault = false,
                nowEpochSec = 1000L
            )
        )
        assertEquals(0, cachePort.size())

        // MEDIUM-2: Turkish locale case folding binds quoted "\u0130STANBUL" to $STR_0
        val trAdmitUtterance = "Alarmi 07:30 icin \"\u0130STANBUL\" etiketiyle kur"
        val trAdmitReq = IntentRequest(
            requestId = "req-tr-admit",
            rawUtterance = trAdmitUtterance,
            normalizedText = normalizer.normalize(trAdmitUtterance, "tr"),
            languageHint = DetectedLanguage("tr", 0.95f, ScriptFamily.LATIN),
            issuedAtEpochMs = 1_100_000L
        )
        val trPlan = PlanAst(
            planId = "plan-tr-label",
            calls = listOf(
                ToolCallAst(
                    toolName = "set_alarm",
                    arguments = mapOf(
                        "time" to Tainted.fromUserUtterance(SlotValueAst.StringValue("07:30"), SensitiveSlotKind.DATE_TIME),
                        "label" to Tainted.fromUserUtterance(SlotValueAst.StringValue("\u0130STANBUL"), SensitiveSlotKind.TEXT_BODY)
                    )
                )
            )
        )
        assertTrue(
            cacheResolver.admitPlan(
                request = trAdmitReq,
                plan = trPlan,
                availableTools = allTools,
                userApproved = true,
                touchesVault = false,
                nowEpochSec = 1100L
            )
        )
        val trReplayUtterance = "Alarmi 09:15 icin \"Ankara\" etiketiyle kur"
        val trReplay = cacheResolver.resolve(
            IntentRequest(
                requestId = "req-tr-replay",
                rawUtterance = trReplayUtterance,
                normalizedText = normalizer.normalize(trReplayUtterance, "tr"),
                languageHint = DetectedLanguage("tr", 0.95f, ScriptFamily.LATIN),
                issuedAtEpochMs = 1_200_000L
            ),
            allTools
        ) as ResolutionResult.ResolvedPlan
        assertEquals(SlotValueAst.StringValue("09:15"), trReplay.plan.calls.single().arguments.getValue("time").value)
        assertEquals(SlotValueAst.StringValue("Ankara"), trReplay.plan.calls.single().arguments.getValue("label").value)

        // MEDIUM-3: targetContextId isolation across replays
        val ctxUtterance = "Set alarm at 09:30 labeled \"Morning\""
        val ctxAdmitReq = IntentRequest(
            requestId = "req-ctx-a",
            rawUtterance = ctxUtterance,
            normalizedText = normalizer.normalize(ctxUtterance, "en"),
            languageHint = DetectedLanguage("en", 0.95f, ScriptFamily.LATIN),
            issuedAtEpochMs = 1_300_000L,
            targetContextId = "context-A"
        )
        val ctxPlan = PlanAst(
            planId = "plan-ctx-a",
            calls = listOf(
                ToolCallAst(
                    toolName = "set_alarm",
                    arguments = mapOf(
                        "time" to Tainted.fromUserUtterance(SlotValueAst.StringValue("09:30"), SensitiveSlotKind.DATE_TIME),
                        "label" to Tainted.fromUserUtterance(SlotValueAst.StringValue("Morning"), SensitiveSlotKind.TEXT_BODY)
                    ),
                    targetId = "context-A"
                )
            )
        )
        assertTrue(
            cacheResolver.admitPlan(
                request = ctxAdmitReq,
                plan = ctxPlan,
                availableTools = allTools,
                userApproved = true,
                touchesVault = false,
                nowEpochSec = 1300L
            )
        )
        val ctxReplayUtterance = "Set alarm at 11:45 labeled \"Noon\""
        val ctxReplay = cacheResolver.resolve(
            IntentRequest(
                requestId = "req-ctx-b",
                rawUtterance = ctxReplayUtterance,
                normalizedText = normalizer.normalize(ctxReplayUtterance, "en"),
                languageHint = DetectedLanguage("en", 0.95f, ScriptFamily.LATIN),
                issuedAtEpochMs = 1_400_000L,
                targetContextId = "context-B"
            ),
            allTools
        ) as ResolutionResult.ResolvedPlan
        assertEquals("context-B", ctxReplay.plan.calls.single().targetId)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun gemmaIntentResolverCoalescesStreamingChatDeltasAt35msAndEmitsFinalText() = runTest {
        val gb = 1024L * 1024L * 1024L
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val runtime = FakeLiteRtRuntimeAdapter()
        val engine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = runtime
        )
        var clockMs = 1000L
        val resolver = GemmaIntentResolver(
            llmEngine = engine,
            lifecycleManager = lifecycle,
            securityFirewall = FakeSecurityFirewallPort(),
            monotonicClockMs = {
                val now = clockMs
                clockMs += 10L
                now
            }
        )

        runtime.enqueueDeltas(
            listOf(
                RuntimeStreamDelta(outputDelta = "Hello "),
                RuntimeStreamDelta(outputDelta = "there, "),
                RuntimeStreamDelta(outputDelta = "this "),
                RuntimeStreamDelta(outputDelta = "is "),
                RuntimeStreamDelta(outputDelta = "Nava.")
            )
        )

        val collected = mutableListOf<ChatStreamDelta>()
        val collectJob = launch(UnconfinedTestDispatcher(testScheduler)) {
            resolver.streamingChatDeltas.collect { collected.add(it) }
        }

        val reply = resolver.resolve(
            IntentRequest("chat-stream-1", "How are you doing today?", issuedAtEpochMs = 100L),
            allTools
        ) as ResolutionResult.ConversationalReply

        collectJob.cancel()

        assertEquals("Hello there, this is Nava.", reply.replyText)
        // Throttled intermediate deltas + final completion guarantee
        assertTrue(collected.size in 2..3)
        assertEquals("Hello there, this is Nava.", collected.last().accumulatedText)
    }

    @Test
    fun tier1LayerRRulesMatchScheduleReminderAndSummarizeNotificationsInEnAndTr() = runTest {
        val reminderTool = ToolMetadata(
            name = "schedule_reminder",
            displayNameKey = "tool_schedule_reminder",
            description = "Schedule an offline reminder",
            category = ToolCategory.TIME_CALENDAR,
            requiredCapability = AtomicCapability.CREATE_DRAFT,
            fields = listOf(
                ToolSchemaField("title", "Title", true, SensitiveSlotKind.EVENT_TITLE, SlotValueType.STRING),
                ToolSchemaField("delay_minutes", "Delay min", false, SensitiveSlotKind.DURATION, SlotValueType.INTEGER)
            )
        )
        val notifyTool = ToolMetadata(
            name = "summarize_notifications",
            displayNameKey = "tool_summarize_notifications",
            description = "Summarize recent notifications",
            category = ToolCategory.COMMUNICATION,
            requiredCapability = AtomicCapability.NOTIFICATION_READ,
            fields = listOf(
                ToolSchemaField("limit", "Limit", false, SensitiveSlotKind.DURATION, SlotValueType.INTEGER)
            )
        )
        val extendedTools = allTools + reminderTool + notifyTool
        val firewall = FakeSecurityFirewallPort()
        val resolver = RuleIntentResolver(rulePackLoader, firewall, normalizer, timeResolver, { ZoneOffset.UTC })

        val enRem = resolver.resolve(
            IntentRequest(
                requestId = "en-rem",
                rawUtterance = "Remind me in 15 minutes to call mom",
                normalizedText = normalizer.normalize("Remind me in 15 minutes to call mom", "en"),
                languageHint = DetectedLanguage("en", 0.99f, ScriptFamily.LATIN),
                issuedAtEpochMs = 1_000_000L
            ),
            extendedTools
        ) as ResolutionResult.ResolvedPlan
        assertEquals("schedule_reminder", enRem.plan.calls.single().toolName)
        assertEquals(SlotValueAst.IntValue(15L), enRem.plan.calls.single().arguments.getValue("delay_minutes").value)
        assertEquals(SlotValueAst.StringValue("call mom"), enRem.plan.calls.single().arguments.getValue("title").value)

        val trRem = resolver.resolve(
            IntentRequest(
                requestId = "tr-rem",
                rawUtterance = "10 dakika sonra ilac icmeyi hatirlat",
                normalizedText = normalizer.normalize("10 dakika sonra ilac icmeyi hatirlat", "tr"),
                languageHint = DetectedLanguage("tr", 0.99f, ScriptFamily.LATIN),
                issuedAtEpochMs = 1_000_000L
            ),
            extendedTools
        ) as ResolutionResult.ResolvedPlan
        assertEquals("schedule_reminder", trRem.plan.calls.single().toolName)
        assertEquals(SlotValueAst.IntValue(10L), trRem.plan.calls.single().arguments.getValue("delay_minutes").value)
        assertEquals(SlotValueAst.StringValue("ilac icmeyi"), trRem.plan.calls.single().arguments.getValue("title").value)

        val enNotif = resolver.resolve(
            IntentRequest(
                requestId = "en-notif",
                rawUtterance = "Summarize my unread notifications",
                normalizedText = normalizer.normalize("Summarize my unread notifications", "en"),
                languageHint = DetectedLanguage("en", 0.99f, ScriptFamily.LATIN),
                issuedAtEpochMs = 1_000_000L
            ),
            extendedTools
        ) as ResolutionResult.ResolvedPlan
        assertEquals("summarize_notifications", enNotif.plan.calls.single().toolName)

        val trNotif = resolver.resolve(
            IntentRequest(
                requestId = "tr-notif",
                rawUtterance = "Son 5 bildirimi \u00F6zetle",
                normalizedText = normalizer.normalize("Son 5 bildirimi \u00F6zetle", "tr"),
                languageHint = DetectedLanguage("tr", 0.99f, ScriptFamily.LATIN),
                issuedAtEpochMs = 1_000_000L
            ),
            extendedTools
        ) as ResolutionResult.ResolvedPlan
        assertEquals("summarize_notifications", trNotif.plan.calls.single().toolName)
        assertEquals(SlotValueAst.IntValue(5L), trNotif.plan.calls.single().arguments.getValue("limit").value)

        // Multi-step notification + draft remains NO_MATCH in Tier 1 even with extendedTools
        val complex = resolver.resolve(
            IntentRequest(
                requestId = "en-complex-notif",
                rawUtterance = "Summarize my unread notifications and draft a reply to Alex",
                normalizedText = normalizer.normalize("Summarize my unread notifications and draft a reply to Alex", "en"),
                languageHint = DetectedLanguage("en", 0.99f, ScriptFamily.LATIN),
                issuedAtEpochMs = 1_000_000L
            ),
            extendedTools
        )
        assertEquals(ResolutionResult.NoMatch, complex)
    }

    @Test
    fun processQueryUseCaseRoutesT1ToT2ToT25FunctionGemmaBeforeT3() = runTest {
        val gb = 1024L * 1024L * 1024L
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(8L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val fgRuntime = FakeLiteRtRuntimeAdapter()
        val gemmaRuntime = FakeLiteRtRuntimeAdapter()
        val fgEngine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = fgRuntime
        )
        val gemmaEngine = LiteRtLlmEngine(
            modelPathProvider = { fakeModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = gemmaRuntime
        )
        val firewall = FakeSecurityFirewallPort()
        val cachePort = InMemoryActionCachePort()
        val tier1 = RuleIntentResolver(rulePackLoader, firewall, normalizer, timeResolver, { ZoneOffset.UTC })
        val tier2 = CacheIntentResolver(cachePort, firewall, normalizer)
        val tier25 = FunctionGemmaIntentResolver(
            functionEngine = fgEngine,
            isModelAvailable = { true },
            lifecycleManager = lifecycle,
            securityFirewall = firewall
        )
        val tier3 = GemmaIntentResolver(gemmaEngine, lifecycle, securityFirewall = firewall)
        val detector = OnDeviceLanguageDetector(catalog, textNormalizer = normalizer)

        val useCase = ProcessQueryUseCase(
            resolvers = listOf(tier3, tier25, tier1, tier2),
            toolRegistry = CoreAiTestFixtures.canonicalToolRegistry(),
            languageDetector = detector,
            textNormalizer = normalizer
        )

        fgRuntime.enqueueDeltas(
            listOf(
                RuntimeStreamDelta(
                    outputDelta = "<start_function_call>call:set_alarm{time:<escape>06:30<escape>}<end_function_call>"
                )
            )
        )
        val res25 = useCase(
            requestId = "u-fg",
            rawUtterance = "Wake me up with an alarm at 06:30 please",
            appLocaleTag = "en",
            issuedAtEpochMs = 1_000_000L
        ) as ResolutionResult.ResolvedPlan
        assertEquals(ResolutionTier.TIER_2_5_FUNCTION_GEMMA, res25.tier)
        assertEquals(1, fgRuntime.clonedTurnCalls.size)
        assertEquals(0, gemmaRuntime.clonedTurnCalls.size)

        // When FunctionGemma returns NO_FUNCTION_CALL, falls back to Tier 3 Gemma
        fgRuntime.enqueueDeltas(listOf(RuntimeStreamDelta(outputDelta = "NO_FUNCTION_CALL")))
        gemmaRuntime.enqueueDeltas(
            listOf(RuntimeStreamDelta(outputDelta = "<|tool_call>call:set_dnd{enabled:true}<tool_call|>"))
        )
        val res3 = useCase(
            requestId = "u-t3",
            rawUtterance = "Please activate do not disturb focus mode for me",
            appLocaleTag = "en",
            issuedAtEpochMs = 2_000_000L
        ) as ResolutionResult.ResolvedPlan
        assertEquals(ResolutionTier.TIER_3_GEMMA, res3.tier)
        assertEquals(1, gemmaRuntime.clonedTurnCalls.size)
    }

    private fun assertCanonicalSlots(
        caseId: String,
        expectedTool: String,
        rawExpectedSlots: Map<String, String>,
        pack: LocaleRulePack,
        fixedNow: ZonedDateTime,
        call: ToolCallAst
    ) {
        when (expectedTool) {
            "set_alarm" -> {
                val expectedTime = timeResolver.resolveTime(rawExpectedSlots, pack.timeKeywords, fixedNow)!!
                assertEquals("Time mismatch for $caseId", SlotValueAst.StringValue(expectedTime), call.arguments.getValue("time").value)
                rawExpectedSlots["label"]?.let { expectedLabel ->
                    assertEquals("Label mismatch for $caseId", SlotValueAst.StringValue(expectedLabel), call.arguments.getValue("label").value)
                }
            }

            "set_timer" -> {
                val expectedSeconds = timeResolver.resolveDurationSeconds(rawExpectedSlots, pack.timeKeywords)!!
                assertEquals("Duration mismatch for $caseId", SlotValueAst.IntValue(expectedSeconds), call.arguments.getValue("duration_seconds").value)
                rawExpectedSlots["label"]?.let { expectedLabel ->
                    assertEquals("Label mismatch for $caseId", SlotValueAst.StringValue(expectedLabel), call.arguments.getValue("label").value)
                }
            }

            "set_dnd" -> {
                val expectedEnabled = rawExpectedSlots.getValue("enabled").toBooleanStrict()
                assertEquals("DND mismatch for $caseId", SlotValueAst.BooleanValue(expectedEnabled), call.arguments.getValue("enabled").value)
            }

            "set_volume" -> {
                val expectedLevel = rawExpectedSlots.getValue("level").toLong()
                assertEquals("Volume mismatch for $caseId", SlotValueAst.IntValue(expectedLevel), call.arguments.getValue("level").value)
            }

            "launch_app" -> {
                val expectedApp = rawExpectedSlots.getValue("app_name")
                assertEquals("App name mismatch for $caseId", SlotValueAst.StringValue(expectedApp), call.arguments.getValue("app_name").value)
            }

            else -> error("Unexpected Tier 1 tool in golden corpus: $expectedTool")
        }
    }
}

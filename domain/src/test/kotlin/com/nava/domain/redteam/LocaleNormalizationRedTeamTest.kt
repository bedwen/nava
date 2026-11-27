package com.nava.domain.redteam

import com.nava.domain.ai.IntentRequest
import com.nava.domain.ai.IntentResolver
import com.nava.domain.ai.PlanAst
import com.nava.domain.ai.ResolutionResult
import com.nava.domain.ai.ResolutionTier
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.ai.ToolCallAst
import com.nava.domain.locale.DetectedLanguage
import com.nava.domain.locale.GenericTextNormalizer
import com.nava.domain.locale.LanguageDetector
import com.nava.domain.locale.LocaleNormalizerRegistry
import com.nava.domain.locale.LocaleNormalizerStrategy
import com.nava.domain.locale.ScriptFamily
import com.nava.domain.security.AtomicCapability
import com.nava.domain.security.AuditLogEntry
import com.nava.domain.security.AuditLogPort
import com.nava.domain.security.CapabilityToken
import com.nava.domain.security.ConfirmationLevel
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.FirewallDecision
import com.nava.domain.security.PermissionProfile
import com.nava.domain.security.RuleCapabilityGrant
import com.nava.domain.security.SecurityFirewallPort
import com.nava.domain.security.SensitiveSlotKind
import com.nava.domain.security.Tainted
import com.nava.domain.tool.NavaTool
import com.nava.domain.tool.ToolCategory
import com.nava.domain.tool.ToolExecutionContext
import com.nava.domain.tool.ToolMetadata
import com.nava.domain.tool.ToolRegistry
import com.nava.domain.tool.ToolResult
import com.nava.domain.ui.MessageKey
import com.nava.domain.ui.UserMessage
import com.nava.domain.usecase.ExecutePlanUseCase
import com.nava.domain.usecase.ProcessQueryUseCase
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Gate 2 independent adversarial invariant suite for [GenericTextNormalizer],
 * [LocaleNormalizerRegistry], script-family handling, and language-independence of security checks.
 */
class LocaleNormalizationRedTeamTest {

    private val normalizer = GenericTextNormalizer()

    @Test
    fun `seed languages and all major script families normalize deterministically and idempotently`() {
        val samples = listOf(
            "en-US" to "Set Alarm At 07:30 Tomorrow",
            "tr-TR" to "Saat 07:30 i\u00E7in alarm kur",
            "ar-EG" to "\u0627\u0636\u0628\u0637 \u0627\u0644\u0645\u0646\u0628\u0647 \u0627\u0644\u0633\u0627\u0639\u0629 \u0660\u0667:\u0663\u0660",
            "es-ES" to "\u00BFPon una alarma a las 7:30!",
            "fr-FR" to "R\u00E9veil \u00E0 7h30 demain matin",
            "ru-RU" to "\u041F\u043E\u0441\u0442\u0430\u0432\u044C \u0431\u0443\u0434\u0438\u043B\u044C\u043D\u0438\u043A \u043D\u0430 07:30",
            "el-GR" to "\u0392\u03AC\u03BB\u03B5 \u03BE\u03C5\u03C0\u03BD\u03B7\u03C4\u03AE\u03C1\u03B9 \u03C3\u03C4\u03B9\u03C2 07:30",
            "he-IL" to "\u05E7\u05D1\u05E2 \u05E9\u05E2\u05D5\u05DF \u05DC\u05E9\u05E2\u05D4 07:30",
            "hi-IN" to "\u0938\u0941\u092C\u0939 \u0966\u096D:\u0969\u0966 \u092C\u091C\u0947 \u0905\u0932\u093E\u0930\u094D\u092E",
            "bn-BD" to "\u09B8\u0995\u09BE\u09B2 \u09E6\u09ED:\u09E9\u09E6 \u099F\u09BE\u09DF \u0985\u09CD\u09AF\u09BE\u09B2\u09BE\u09B0\u09CD\u09AE",
            "th-TH" to "\u0E15\u0E31\u0E49\u0E07\u0E19\u0E32\u0E2C\u0E34\u0E01\u0E32\u0E1B\u0E25\u0E38\u0E01 \u0E50\u0E57:\u0E53\u0E50",
            "zh-CN" to "\u660E\u5929\u65E9\u4E0A\u4E03\u70B9\u534A\u95F9\u949F",
            "ja-JP" to "\u660E\u65E5\u306E\u671D\uFF17\u6642\uFF13\uFF10\u5206\u306B\u30A2\u30E9\u30FC\u30E0",
            "ko-KR" to "\uB0B4\uC77C \uC544\uCE68 7\uC2DC 30\uBD84 \uC54C\uB78C"
        )

        for ((tag, utterance) in samples) {
            val first = normalizer.normalize("  $utterance  ", tag)
            val second = normalizer.normalize(first.folded, tag)
            assertEquals("Original must be preserved for $tag", "  $utterance  ", first.original)
            assertEquals("Folded normalization must be idempotent for $tag", first.folded, second.folded)
            assertEquals("MatchKey must be idempotent for $tag", first.matchKey, second.matchKey)
            assertFalse("Tokens must not be empty for $tag", first.tokens.isEmpty())
            assertTrue("All tokens must be non-blank for $tag", first.tokens.all { it.isNotBlank() })
        }

        // Verify ScriptFamily metadata invariants match PLAN.md Section 6.2.
        assertTrue(ScriptFamily.LATIN.allowsDiacriticStrippingForMatchKeys)
        assertTrue(ScriptFamily.CYRILLIC.allowsDiacriticStrippingForMatchKeys)
        assertTrue(ScriptFamily.GREEK.allowsDiacriticStrippingForMatchKeys)
        for (nonStrippable in listOf(
            ScriptFamily.ARABIC,
            ScriptFamily.HEBREW,
            ScriptFamily.DEVANAGARI,
            ScriptFamily.INDIC_OTHER,
            ScriptFamily.THAI,
            ScriptFamily.KHMER_LAO,
            ScriptFamily.CJK,
            ScriptFamily.HANGUL
        )) {
            assertFalse(
                "$nonStrippable must not strip diacritics generically",
                nonStrippable.allowsDiacriticStrippingForMatchKeys
            )
        }
        assertTrue(ScriptFamily.THAI.isSpaceLessScript)
        assertTrue(ScriptFamily.KHMER_LAO.isSpaceLessScript)
        assertTrue(ScriptFamily.CJK.isSpaceLessScript)
        assertFalse(ScriptFamily.HANGUL.isSpaceLessScript)
    }

    @Test
    fun `turkish and azerbaijani case folding preserves dotless i and diverges from en-US`() {
        for (tag in listOf("tr", "tr-TR", "tr_TR", "az", "az-AZ")) {
            val res = normalizer.normalize("\u0130STANBUL ISIK I\u0307ZM\u0130R", tag)
            assertEquals("Failed Turkish/Azeri case folding for tag $tag", "istanbul \u0131s\u0131k izmir", res.folded)
        }

        val english = normalizer.normalize("ISIK \u0130STANBUL", "en-US")
        assertEquals("isik i\u0307stanbul", english.folded)
        assertEquals("isik istanbul", english.matchKey)
    }

    @Test
    fun `unicode decimal digit unification covers all major Nd scripts and mixed-script numbers`() {
        val digitSets = mapOf(
            "Arabic-Indic" to "\u0660\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668\u0669",
            "Eastern Arabic-Indic" to "\u06F0\u06F1\u06F2\u06F3\u06F4\u06F5\u06F6\u06F7\u06F8\u06F9",
            "Devanagari" to "\u0966\u0967\u0968\u0969\u096A\u096B\u096C\u096D\u096E\u096F",
            "Bengali" to "\u09E6\u09E7\u09E8\u09E9\u09EA\u09EB\u09EC\u09ED\u09EE\u09EF",
            "Thai" to "\u0E50\u0E51\u0E52\u0E53\u0E54\u0E55\u0E56\u0E57\u0E58\u0E59",
            "Fullwidth" to "\uFF10\uFF11\uFF12\uFF13\uFF14\uFF15\uFF16\uFF17\uFF18\uFF19",
            "Tamil" to "\u0BE6\u0BE7\u0BE8\u0BE9\u0BEA\u0BEB\u0BEC\u0BED\u0BEE\u0BEF",
            "Myanmar" to "\u1040\u1041\u1042\u1043\u1044\u1045\u1046\u1047\u1048\u1049",
            "Khmer" to "\u17E0\u17E1\u17E2\u17E3\u17E4\u17E5\u17E6\u17E7\u17E8\u17E9",
            "Math Bold" to "\uD835\uDFCE\uD835\uDFCF\uD835\uDFD0\uD835\uDFD1\uD835\uDFD2" +
                "\uD835\uDFD3\uD835\uDFD4\uD835\uDFD5\uD835\uDFD6\uD835\uDFD7"
        )

        for ((scriptName, digits) in digitSets) {
            val normalized = normalizer.normalize(digits, "en-US")
            assertEquals("Digit unification failed for $scriptName", "0123456789", normalized.folded)
            assertEquals("Digit unification matchKey failed for $scriptName", "0123456789", normalized.matchKey)
        }

        // Mixed-script time string combining Arabic-Indic, Devanagari, Thai, and Fullwidth digits.
        val mixedTime = "\u0660\u096D:\u0E53\uFF10"
        assertEquals("07:30", normalizer.normalize(mixedTime, "en").folded)
    }

    @Test
    fun `diacritics strip only on Latin Greek Cyrillic match keys and preserve Indic Thai Arabic Hebrew marks`() {
        // Latin (French & Spanish): folded keeps diacritics, matchKey strips them.
        val french = normalizer.normalize("Caf\u00E9 cr\u00E8me \u00E0 Paris e\u0301", "fr")
        assertEquals("caf\u00E9 cr\u00E8me \u00E0 paris \u00E9", french.folded)
        assertEquals("cafe creme a paris e", french.matchKey)

        val spanish = normalizer.normalize("Ma\u00F1ana \u00E1rbol \u00FCnico", "es")
        assertEquals("ma\u00F1ana \u00E1rbol \u00FCnico", spanish.folded)
        assertEquals("manana arbol unico", spanish.matchKey)

        // Greek: folded keeps tonos/polytonic marks, matchKey strips them.
        val greek = normalizer.normalize("\u03AC\u03BB\u03B1\u03C2 \u1F00\u03BD\u03B8\u03C1\u03C9\u03C0\u03BF\u03C2", "el")
        assertEquals("\u03B1\u03BB\u03B1\u03C2 \u03B1\u03BD\u03B8\u03C1\u03C9\u03C0\u03BF\u03C2", greek.matchKey)

        // Cyrillic: folded keeps \u0439 and \u0451, matchKey strips diacritic marks.
        val cyrillic = normalizer.normalize("\u0439\u043E\u0433\u0443\u0440\u0442 \u0451\u043B\u043A\u0430", "ru")
        assertEquals("\u0439\u043E\u0433\u0443\u0440\u0442 \u0451\u043B\u043A\u0430", cyrillic.folded)
        assertEquals("\u0438\u043E\u0433\u0443\u0440\u0442 \u0435\u043B\u043A\u0430", cyrillic.matchKey)

        // Semantic combining marks MUST be preserved intact in GenericTextNormalizer matchKey:
        val preservedSemanticCases = listOf(
            "hi" to "\u0915\u0947\u0932\u093E \u0928\u092E\u0938\u094D\u0924\u0947", // Devanagari vowel signs & virama
            "bn" to "\u09AC\u09BE\u0982\u09B2\u09BE \u09AC\u09BE\u09B0\u09CD\u09A4\u09BE", // Bengali vowel signs & hasanta
            "th" to "\u0E01\u0E31\u0E19 \u0E15\u0E31\u0E49\u0E07\u0E19\u0E32\u0E2C\u0E34\u0E01\u0E32", // Thai mai han-akat & tone marks
            "ar" to "\u0645\u064E\u0631\u0652\u062D\u064E\u0628\u064B\u0627", // Arabic tashkeel (unless strategy strips)
            "he" to "\u05E9\u05B8\u05C1\u05DC\u05D5\u05B9\u05DD" // Hebrew niqqud in canonical NFD/NFC order
        )
        for ((lang, word) in preservedSemanticCases) {
            val res = normalizer.normalize(word, lang)
            assertEquals("Semantic combining marks stripped unexpectedly for $lang", word, res.matchKey)
        }

        // Japanese halfwidth katakana with dakuten folds to precomposed fullwidth and retains voiced mark.
        val jp = normalizer.normalize("\uFF76\uFF9E\u3063\u3053\u3046", "ja")
        assertEquals("\u30AC\u3063\u3053\u3046", jp.matchKey)

        // Hangul syllables survive NFD->NFC round-trip without losing Jamo components.
        val ko = normalizer.normalize("\uD55C\uAE00 \uC54C\uB78C", "ko")
        assertEquals("\uD55C\uAE00 \uC54C\uB78C", ko.matchKey)
    }

    @Test
    fun `probe mixed-script Latin base followed by Devanagari semantic mark preserves Devanagari mark`() {
        // Adversarial mixed-script string: Latin 'a' immediately followed by Devanagari vowel sign 'e' (U+0947).
        // Diacritic stripping should only strip marks belonging to Latin/Greek/Cyrillic/Inherited, not Devanagari.
        val mixed = "a\u0947"
        val res = normalizer.normalize(mixed, "hi")
        assertTrue(
            "Devanagari semantic vowel sign U+0947 was stripped because previous char was Latin: matchKey='${res.matchKey}'",
            res.matchKey.contains('\u0947')
        )
    }

    @Test
    fun `bidi zero-width controls are stripped and BreakIterator segments space-less scripts`() {
        val obfuscated = "S\u200Bet \u202Ealarm\u202C \u2066for\u2069 \uFEFF07:30\u061C\u00AD"
        val norm = normalizer.normalize(obfuscated, "en-US")
        assertEquals("set alarm for 07:30", norm.folded)
        assertEquals("set alarm for 07:30", norm.matchKey)
        assertTrue(norm.tokens.containsAll(listOf("set", "alarm", "for")))

        // Space-less scripts segmented by BreakIterator.
        // Note: Standard JDK BreakIterator emits non-empty tokens for pure Hanzi Chinese and splits
        // on script/digit boundaries, while Japanese and Thai split multi-word phrases directly.
        val chinese = normalizer.normalize("\u660E\u5929\u65E9\u4E0A\u4E03\u70B9\u95F9\u949F", "zh-CN")
        assertFalse("Expected non-empty segmentation for Chinese", chinese.tokens.isEmpty())
        assertTrue(chinese.tokens.all { it.isNotBlank() })

        val chineseWithDigits = normalizer.normalize("\u660E\u5929\u65E9\u4E0A7\u70B9\u95F9\u949F", "zh-CN")
        assertTrue(
            "Expected digit boundary segmentation for Chinese, got ${chineseWithDigits.tokens}",
            chineseWithDigits.tokens.size >= 3
        )

        val japanese = normalizer.normalize("\u660E\u65E5\u306E\u671D\u306B\u30A2\u30E9\u30FC\u30E0", "ja-JP")
        assertTrue("Expected multi-token segmentation for Japanese, got ${japanese.tokens}", japanese.tokens.size >= 2)

        val thai = normalizer.normalize("\u0E15\u0E31\u0E49\u0E07\u0E19\u0E32\u0E2C\u0E34\u0E01\u0E32\u0E1B\u0E25\u0E38\u0E01", "th-TH")
        assertFalse("Expected non-empty segmentation for Thai", thai.tokens.isEmpty())
        assertTrue(thai.tokens.all { it.isNotBlank() })

        val thaiWithDigits = normalizer.normalize("\u0E15\u0E31\u0E49\u0E07\u0E19\u0E32\u0E2C\u0E34\u0E01\u0E32\u0E1B\u0E25\u0E38\u0E01\u0E50\u0E57:\u0E53\u0E50", "th-TH")
        assertTrue(
            "Expected digit boundary segmentation for Thai, got ${thaiWithDigits.tokens}",
            thaiWithDigits.tokens.size >= 2
        )
    }

    @Test
    fun `LocaleNormalizerRegistry dispatches pluggable strategies without hardcoded branches`() {
        val arabicStrategy = object : LocaleNormalizerStrategy {
            override val languageTags: Set<String> = setOf("ar")
            override fun normalizeMatchKey(text: String, languageTag: String): String {
                return text
                    .replace(Regex("[\u064B-\u065F\u0670\u0640]"), "")
                    .replace('\u0623', '\u0627')
                    .replace('\u0625', '\u0627')
                    .replace('\u0622', '\u0627')
                    .replace('\u0629', '\u0647')
            }
        }
        val frenchStrategy = object : LocaleNormalizerStrategy {
            override val languageTags: Set<String> = setOf("fr")
            override fun normalizeMatchKey(text: String, languageTag: String): String {
                return text.replace(Regex("\\b(?:l|d)'"), "")
            }
        }
        val registry = LocaleNormalizerRegistry(listOf(arabicStrategy, frenchStrategy))
        val customNormalizer = GenericTextNormalizer(registry)

        // Regional tag ar-EG resolves base strategy ar.
        val arNorm = customNormalizer.normalize("\u0623\u064E\u0644\u0652\u063A\u0650\u0640\u064A", "ar-EG")
        assertEquals("\u0627\u0644\u063A\u064A", arNorm.matchKey)

        // Regional tag fr-CA resolves base strategy fr.
        val frNorm = customNormalizer.normalize("R\u00E9gler l'alarme d'\u00E9t\u00E9", "fr-CA")
        assertEquals("regler alarme ete", frNorm.matchKey)
        assertNotNull(registry.findForLanguage("fr_FR"))
    }

    @Test
    fun `probe LocaleNormalizerRegistry matches script-qualified subtag fallback before primary subtag`() {
        val zhHantStrategy = object : LocaleNormalizerStrategy {
            override val languageTags: Set<String> = setOf("zh-Hant")
        }
        val registry = LocaleNormalizerRegistry(listOf(zhHantStrategy))
        assertNotNull(
            "zh-Hant-TW should fall back to zh-Hant strategy before dropping script subtag",
            registry.findForLanguage("zh-Hant-TW")
        )
    }

    @Test
    fun `security invariants are completely independent of LanguageDetector output`() = runBlocking {
        val adversarialTags = listOf("und", "ar", "tr", "zh-CN", "hi", "xx-invalid")

        for (badDetectedTag in adversarialTags) {
            val deceptiveDetector = object : LanguageDetector {
                override suspend fun detect(utterance: String, appLocaleTag: String): DetectedLanguage {
                    return DetectedLanguage(
                        bcp47Tag = badDetectedTag,
                        confidence = 0.0f,
                        scriptFamily = ScriptFamily.OTHER,
                        isAmbiguous = true
                    )
                }
            }

            val smsMeta = ToolMetadata(
                name = "sms.draft",
                displayNameKey = "tool_sms_draft",
                description = "Creates an SMS draft",
                category = ToolCategory.COMMUNICATION,
                requiredCapability = AtomicCapability.CREATE_DRAFT
            )
            var toolExecutions = 0
            val smsTool = object : NavaTool {
                override val metadata = smsMeta
                override suspend fun execute(
                    context: ToolExecutionContext,
                    arguments: Map<String, Tainted<SlotValueAst>>
                ): ToolResult {
                    toolExecutions++
                    return ToolResult.Success(UserMessage(MessageKey.ACTION_SMS_DRAFT_PREPARED))
                }
            }
            val registry = ToolRegistry(listOf(smsTool))

            var resolverCalled = false
            val resolver = object : IntentResolver {
                override val tier = ResolutionTier.TIER_1_RULE
                override suspend fun resolve(
                    request: IntentRequest,
                    availableTools: List<ToolMetadata>
                ): ResolutionResult {
                    resolverCalled = true
                    return ResolutionResult.NoMatch
                }
            }
            val processQuery = ProcessQueryUseCase(
                resolvers = listOf(resolver),
                toolRegistry = registry,
                languageDetector = deceptiveDetector,
                textNormalizer = normalizer
            )

            // 1. UNTRUSTED_EXTERNAL Stage 1 rejection holds regardless of detector output.
            try {
                processQuery(
                    requestId = "req-$badDetectedTag",
                    rawUtterance = "Send SMS to +15550100",
                    appLocaleTag = badDetectedTag,
                    issuedAtEpochMs = 1_000L,
                    provenance = DataProvenance.UNTRUSTED_EXTERNAL
                )
                fail("Expected SecurityException for UNTRUSTED_EXTERNAL with detected tag $badDetectedTag")
            } catch (_: SecurityException) {
                // Expected
            }
            assertFalse(resolverCalled)

            // 2. CapabilityToken mint still strictly rejects UNTRUSTED_EXTERNAL and SYSTEM.
            try {
                CapabilityToken.mint(
                    tokenId = "tok-bad-$badDetectedTag",
                    requestId = "req-$badDetectedTag",
                    allowedTools = setOf("sms.draft"),
                    mintProvenance = DataProvenance.UNTRUSTED_EXTERNAL,
                    issuedAtEpochMs = 1_000L
                )
                fail("Expected SecurityException for CapabilityToken under tag $badDetectedTag")
            } catch (_: SecurityException) {
                // Expected
            }

            // 3. PermissionProfile Default-Deny remains invariant.
            val defaultDeny = PermissionProfile.defaultDeny()
            assertEquals(ConfirmationLevel.DISABLED, defaultDeny.levelFor(AtomicCapability.MODIFY_DELETE_SEND))

            // 4. Tainted high-risk slot cannot auto-execute regardless of detected language tag.
            val auditLog = object : AuditLogPort {
                override suspend fun record(entry: AuditLogEntry) = Unit
                override suspend fun queryRecent(limit: Int) = emptyList<AuditLogEntry>()
            }
            val firewall = object : SecurityFirewallPort {
                override suspend fun mintToken(
                    requestId: String,
                    utteranceProvenance: DataProvenance,
                    candidateTools: Set<String>,
                    nowEpochMs: Long,
                    maxToolCalls: Int
                ): CapabilityToken = CapabilityToken.mint(
                    "tok-$badDetectedTag",
                    requestId,
                    candidateTools,
                    utteranceProvenance,
                    nowEpochMs
                )

                override suspend fun authorizeToolCall(
                    token: CapabilityToken,
                    toolCall: ToolCallAst,
                    toolMetadata: ToolMetadata,
                    targetId: String,
                    nowEpochMs: Long
                ): FirewallDecision {
                    val untrustedSlots = toolCall.arguments.filterValues { it.requiresExplicitConfirmation }.keys
                    return if (untrustedSlots.isNotEmpty()) {
                        FirewallDecision.RequiresConfirmation(
                            UserMessage(MessageKey.WARNING_UNTRUSTED_EXTERNAL_SOURCE),
                            untrustedSlots
                        )
                    } else {
                        FirewallDecision.Authorized
                    }
                }

                override suspend fun authorizeRuleExecution(grant: RuleCapabilityGrant) = FirewallDecision.Authorized
                override suspend fun validateOutboundTarget(
                    toolName: String,
                    action: String,
                    uriOrTarget: Tainted<String>
                ) = FirewallDecision.Authorized
            }
            val executePlan = ExecutePlanUseCase(registry, firewall, auditLog)
            val validToken = CapabilityToken.mint(
                tokenId = "tok-ok-$badDetectedTag",
                requestId = "req-ok-$badDetectedTag",
                allowedTools = setOf("sms.draft"),
                mintProvenance = DataProvenance.USER_UTTERANCE,
                issuedAtEpochMs = 1_000L
            )
            val plan = PlanAst(
                planId = "plan-$badDetectedTag",
                calls = listOf(
                    ToolCallAst(
                        toolName = "sms.draft",
                        arguments = mapOf(
                            "recipient" to Tainted.fromUntrustedExternal(
                                SlotValueAst.StringValue("+15550199"),
                                SensitiveSlotKind.PHONE_NUMBER,
                                "notification:external"
                            )
                        )
                    )
                )
            )
            val results = executePlan(
                plan = plan,
                capabilityToken = validToken,
                targetId = "com.sms",
                languageTag = badDetectedTag,
                nowEpochMs = 1_100L,
                confirmedStepIndices = emptySet()
            )
            assertEquals(0, toolExecutions)
            assertTrue(results.first() is ToolResult.ConfirmationRequired)
            assertTrue((results.first() as ToolResult.ConfirmationRequired).hasUntrustedHighRiskSlot)
        }
    }
}

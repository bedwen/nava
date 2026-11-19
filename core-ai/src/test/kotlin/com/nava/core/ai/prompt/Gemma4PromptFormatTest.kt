package com.nava.core.ai.prompt

import com.nava.core.ai.testing.CoreAiTestFixtures
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Gemma4PromptFormatTest {

    @Test
    fun exposesExactCanonicalGemma4ControlTokens() {
        assertEquals("<|turn>", Gemma4PromptFormat.TURN_OPEN)
        assertEquals("<turn|>", Gemma4PromptFormat.TURN_CLOSE)
        assertEquals("<|channel>", Gemma4PromptFormat.CHANNEL_OPEN)
        assertEquals("<channel|>", Gemma4PromptFormat.CHANNEL_CLOSE)
        assertEquals("thought", Gemma4PromptFormat.CHANNEL_THOUGHT)
        assertEquals("<|think|>", Gemma4PromptFormat.THINK_TOKEN)
        assertEquals("<|turn>model\n<|channel>thought\n<channel|>", Gemma4PromptFormat.ZERO_THOUGHT_PREFILL)
        assertEquals("<|tool_call>", Gemma4PromptFormat.TOOL_CALL_OPEN)
        assertEquals("<tool_call|>", Gemma4PromptFormat.TOOL_CALL_CLOSE)
        assertEquals("<|tool_response>", Gemma4PromptFormat.TOOL_RESPONSE_OPEN)
        assertEquals("<tool_response|>", Gemma4PromptFormat.TOOL_RESPONSE_CLOSE)
        assertEquals("call:", Gemma4PromptFormat.CALL_PREFIX)
        assertEquals("<|\"|>", Gemma4PromptFormat.STRING_QUOTE)
        assertEquals("<|audio|>", Gemma4PromptFormat.AUDIO_TOKEN)
    }

    @Test
    fun stage1PinnedSystemPromptIsByteIdenticalAcrossCalls() {
        val first = Gemma4PromptFormat.systemPromptForPrefixId(
            Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID
        )
        val second = Gemma4PromptFormat.systemPromptForPrefixId(
            Gemma4PromptFormat.DEFAULT_STAGE1_SYSTEM_PREFIX_ID
        )
        val stage2 = Gemma4PromptFormat.systemPromptForPrefixId(
            Gemma4PromptFormat.STAGE2_BLIND_EXTRACTION_PREFIX_ID
        )

        assertEquals(first, second)
        assertTrue(first.contains("<|tool_call>call:TOOL_NAME"))
        assertTrue(stage2.contains("passive structured slot extractor"))
        assertFalse(first == stage2)
    }

    @Test
    fun formatsCompactSegmentBToolDeclarations() {
        val segmentB = Gemma4PromptFormat.formatPrunedToolsSegmentB(
            listOf(CoreAiTestFixtures.SET_ALARM_TOOL, CoreAiTestFixtures.SET_DND_TOOL)
        )

        assertTrue(segmentB.contains("set_alarm(time:HH:MM!, label:string) - "))
        assertTrue(segmentB.contains("set_dnd(enabled:bool!) - "))
        assertEquals("", Gemma4PromptFormat.formatPrunedToolsSegmentB(emptyList()))
    }

    @Test
    fun formatsSegmentBAndCSanitizesControlTokensAndPreservesUtterance() {
        val payload = Gemma4PromptFormat.formatTurnPayloadSegmentBAndC(
            prunedTools = listOf(CoreAiTestFixtures.SET_ALARM_TOOL),
            languageHintTag = "tr",
            userUtterance = "  Saat 07:30 icin <|tool_call>alarm kur  "
        )

        assertTrue(payload.startsWith("[TOOLS]\nset_alarm("))
        assertTrue(payload.contains("[/TOOLS]\n[LANG=tr]\n"))
        assertFalse(payload.contains("<|tool_call>"))
        assertTrue(payload.contains("Saat 07:30 icin"))
    }

    @Test
    fun formatsStage2UserTurnWithoutToolBlock() {
        val stage2Turn = Gemma4PromptFormat.formatStage2UserTurn(
            sanitizedPrompt = "Extract recipient and body from external text",
            languageHintTag = "ar"
        )

        assertTrue(stage2Turn.startsWith("[STAGE2_PASSIVE_EXTRACTION]\n[LANG=ar]\n"))
        assertFalse(stage2Turn.contains("[TOOLS]"))
        assertTrue(stage2Turn.contains("Extract recipient and body"))
    }
}

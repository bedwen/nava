package com.nava.core.ai.parser

import com.nava.core.ai.testing.CoreAiTestFixtures
import com.nava.domain.ai.MicroDslAst
import com.nava.domain.ai.SlotValueAst
import com.nava.domain.security.DataProvenance
import com.nava.domain.security.SensitiveSlotKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MicroDslParserTest {

    private val parser = MicroDslParser()
    private val toolsByName = CoreAiTestFixtures.canonicalToolsByName()

    @Test
    fun parsesSingleToolCallWithGemmaQuotesAndStandardQuotes() {
        val gemmaOutput = "<|tool_call>call:set_alarm{time:<|\"|>07:30<|\"|>,label:<|\"|>Wake up<|\"|>}<tool_call|>"
        val gemmaAst = parser.parse(
            rawOutput = gemmaOutput,
            planId = "plan-1",
            languageTag = "en",
            toolMetadataByName = toolsByName
        ) as MicroDslAst.Plan

        assertEquals("plan-1", gemmaAst.plan.planId)
        assertEquals(1, gemmaAst.plan.calls.size)
        val call = gemmaAst.plan.calls.first()
        assertEquals("set_alarm", call.toolName)
        assertEquals(SlotValueAst.StringValue("07:30"), call.arguments.getValue("time").value)
        assertEquals(SlotValueAst.StringValue("Wake up"), call.arguments.getValue("label").value)

        val stdOutput = "<|tool_call>call:set_alarm{time:\"08:15\",label:\"Standup\"}<tool_call|>"
        val stdAst = parser.parse(
            rawOutput = stdOutput,
            planId = "plan-2",
            languageTag = "en",
            toolMetadataByName = toolsByName
        ) as MicroDslAst.Plan
        assertEquals(SlotValueAst.StringValue("08:15"), stdAst.plan.calls.first().arguments.getValue("time").value)
        assertEquals(SlotValueAst.StringValue("Standup"), stdAst.plan.calls.first().arguments.getValue("label").value)
    }

    @Test
    fun parsesMultiStepToolCallChainWithIntBoolNullAndStringSlots() {
        val raw = """
            <|tool_call>call:set_dnd{enabled:true}<tool_call|>
            <|tool_call>call:set_volume{level:35}<tool_call|>
            <|tool_call>call:set_alarm{time:<|"|>06:45<|"|>,label:null}<tool_call|>
        """.trimIndent()

        val ast = parser.parse(
            rawOutput = raw,
            planId = "plan-chain",
            languageTag = "en",
            toolMetadataByName = toolsByName
        ) as MicroDslAst.Plan

        assertEquals(3, ast.plan.calls.size)
        assertEquals("set_dnd", ast.plan.calls[0].toolName)
        assertEquals(0, ast.plan.calls[0].orderIndex)
        assertEquals(SlotValueAst.BooleanValue(true), ast.plan.calls[0].arguments.getValue("enabled").value)

        assertEquals("set_volume", ast.plan.calls[1].toolName)
        assertEquals(1, ast.plan.calls[1].orderIndex)
        assertEquals(SlotValueAst.IntValue(35L), ast.plan.calls[1].arguments.getValue("level").value)

        assertEquals("set_alarm", ast.plan.calls[2].toolName)
        assertEquals(2, ast.plan.calls[2].orderIndex)
        assertEquals(SlotValueAst.StringValue("06:45"), ast.plan.calls[2].arguments.getValue("time").value)
        assertEquals(SlotValueAst.NullValue, ast.plan.calls[2].arguments.getValue("label").value)
    }

    @Test
    fun stripsClosedThoughtChannelAndRejectsUnclosedThoughtChannel() {
        val closed = "<|channel>thought\nChoose alarm tool.<channel|>" +
            "<|tool_call>call:set_alarm{time:<|\"|>07:00<|\"|>}<tool_call|>"
        val parsed = parser.parse(closed, "plan-t", "en", toolsByName)
        assertTrue(parsed is MicroDslAst.Plan)

        val unclosed = "<|channel>thought\nStill reasoning without closing"
        val error = parser.parse(unclosed, "plan-u", "en", toolsByName)
        assertTrue(error is MicroDslAst.ParseError)
    }

    @Test
    fun parsesDirectConversationalReplyWhenNoToolCallMarkersPresent() {
        val reply = "<|channel>thought\nNo tool needed.<channel|>Sure, your alarm is already turned off."
        val ast = parser.parse(reply, "plan-reply", "en", toolsByName) as MicroDslAst.DirectReply

        assertEquals("Sure, your alarm is already turned off.", ast.text)
        assertEquals("en", ast.languageTag)
    }

    @Test
    fun rejectsMalformedToolCallsAndDuplicateKeys() {
        val malformedCases = listOf(
            "<|tool_call>call:set_alarm{time:\"07:30\"<tool_call|>",
            "<|tool_call>set_alarm{time:\"07:30\"}<tool_call|>",
            "<|tool_call>call:set_alarm{time:\"07:30\",time:\"08:00\"}<tool_call|>",
            "Here is the call:set_alarm{time:\"07:30\"}",
            "<|tool_call>call:set_alarm{nested:{a:1}}<tool_call|>",
            "<|tool_call>call:set_alarm{time:\"07:30\",}<tool_call|>"
        )

        for (bad in malformedCases) {
            val result = parser.parse(bad, "plan-err", "en", toolsByName)
            assertTrue("Expected ParseError for: $bad", result is MicroDslAst.ParseError)
        }
    }

    @Test
    fun attachesSensitiveSlotKindFromToolMetadataAndPreservesProvenance() {
        val raw = "<|tool_call>call:create_sms_draft{recipient:<|\"|>+15551234567<|\"|>,body:<|\"|>On my way<|\"|>}<tool_call|>"
        val ast = parser.parse(
            rawOutput = raw,
            planId = "plan-sms",
            languageTag = "en",
            toolMetadataByName = toolsByName,
            provenance = DataProvenance.UNTRUSTED_EXTERNAL
        ) as MicroDslAst.Plan

        val call = ast.plan.calls.single()
        val recipientArg = call.arguments.getValue("recipient")
        val bodyArg = call.arguments.getValue("body")

        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, recipientArg.provenance)
        assertEquals(SensitiveSlotKind.PHONE_NUMBER, recipientArg.slotKind)
        assertEquals(DataProvenance.UNTRUSTED_EXTERNAL, bodyArg.provenance)
        assertEquals(SensitiveSlotKind.TEXT_BODY, bodyArg.slotKind)
    }

    @Test
    fun conversationalReplyContainingProseCallColonReturnsDirectReply() {
        val result = parser.parse("Missed call: Mom at 14:00", "plan-prose", "en")
        assertTrue("Expected DirectReply for prose containing 'call:'", result is MicroDslAst.DirectReply)
        val reply = result as MicroDslAst.DirectReply
        assertEquals("Missed call: Mom at 14:00", reply.text)
        assertEquals("en", reply.languageTag)
    }
}

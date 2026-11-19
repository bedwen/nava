package com.nava.core.ai.json

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class SimpleJsonParserTest {

    @Test
    fun parsesValidPrimitivesObjectsAndArrays() {
        val raw = """
            {
              "name": "nava",
              "count": 42,
              "negative": -7,
              "ratio": 3.5e-1,
              "active": true,
              "disabled": false,
              "empty": null,
              "tags": ["offline", 1, false, null]
            }
        """.trimIndent()

        val root = SimpleJsonParser.parse(raw).asObject()
        assertEquals("nava", root.getValue("name").asString())
        assertEquals(42, root.getValue("count").asInt())
        assertEquals(-7L, root.getValue("negative").asLong())
        assertEquals(0.35, root.getValue("ratio").asDouble(), 1e-9)
        assertEquals(true, root.getValue("active").asBoolean())
        assertEquals(false, root.getValue("disabled").asBoolean())
        assertEquals(JsonValue.JsonNull, root.getValue("empty"))

        val tags = root.getValue("tags").asArray()
        assertEquals(4, tags.size)
        assertEquals("offline", tags[0].asString())
        assertEquals(1, tags[1].asInt())
        assertEquals(false, tags[2].asBoolean())
        assertEquals(JsonValue.JsonNull, tags[3])
    }

    @Test
    fun parsesUnicodeAndSurrogateEscapesAndRoundTrips() {
        val raw = """{"greeting":"T\u00FCrk\u00E7e \u0639\u0631\u0628\u064A \uD83D\uDE80","escaped":"a\"b\\c\nd"}"""
        val parsed = SimpleJsonParser.parse(raw)
        val obj = parsed.asObject()

        assertEquals("T\u00FCrk\u00E7e \u0639\u0631\u0628\u064A \uD83D\uDE80", obj.getValue("greeting").asString())
        assertEquals("a\"b\\c\nd", obj.getValue("escaped").asString())

        val serialized = SimpleJsonParser.stringify(parsed)
        val reparsed = SimpleJsonParser.parse(serialized)
        assertEquals(parsed, reparsed)
    }

    @Test
    fun rejectsNestingBeyondMaxDepth() {
        val excessiveDepth = SimpleJsonParser.MAX_DEPTH + 2
        val nested = "[".repeat(excessiveDepth) + "1" + "]".repeat(excessiveDepth)
        try {
            SimpleJsonParser.parse(nested)
            fail("Expected IllegalArgumentException for depth > MAX_DEPTH")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message.orEmpty().contains("depth", ignoreCase = true))
        }
    }

    @Test
    fun rejectsDuplicateKeys() {
        val raw = """{"a":1,"b":2,"a":3}"""
        try {
            SimpleJsonParser.parse(raw)
            fail("Expected IllegalArgumentException for duplicate JSON key")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message.orEmpty().contains("Duplicate", ignoreCase = true))
        }
    }

    @Test
    fun rejectsTrailingGarbage() {
        val raw = """{"a":1} trailing"""
        try {
            SimpleJsonParser.parse(raw)
            fail("Expected IllegalArgumentException for trailing characters")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message.orEmpty().contains("trailing", ignoreCase = true))
        }
    }

    @Test
    fun rejectsEmptyAndMalformedNumbers() {
        val invalidInputs = listOf("", "   ", "{\"a\":01}", "{\"a\":1,}", "[1,2,]")
        for (input in invalidInputs) {
            try {
                SimpleJsonParser.parse(input)
                fail("Expected IllegalArgumentException for malformed JSON: $input")
            } catch (_: IllegalArgumentException) {
                // Expected
            }
        }
    }
}

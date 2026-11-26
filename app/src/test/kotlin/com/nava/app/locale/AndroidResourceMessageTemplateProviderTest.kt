package com.nava.app.locale

import com.nava.domain.ui.MessageKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

class AndroidResourceMessageTemplateProviderTest {

    private lateinit var resDir: File
    private lateinit var stringsFile: File
    private lateinit var baseStrings: Map<String, String>
    private val placeholderRegex = Regex("%(?:\\d+\\$)?[a-zA-Z]")

    @Before
    fun setUp() {
        resDir = resolveResDir()
        stringsFile = File(resDir, "values/strings.xml")
        assertTrue("Base strings.xml must exist at ${stringsFile.absolutePath}", stringsFile.exists())
        baseStrings = parseStringsXml(stringsFile)
    }

    @Test
    fun totalMessageKeysCountIsExactly62() {
        assertEquals("MessageKey enum must contain exactly 62 entries", 62, MessageKey.entries.size)
    }

    @Test
    fun all53MessageKeysHaveMatchingCanonicalStringResourceInStringsXml() {
        for (key in MessageKey.entries) {
            val canonicalName = MessageTemplateProvider.canonicalResourceName(key)
            assertTrue(
                "Canonical resource name '$canonicalName' must start with 'msg_'",
                canonicalName.startsWith("msg_")
            )
            assertTrue(
                "strings.xml must contain string resource for key '$canonicalName'",
                baseStrings.containsKey(canonicalName)
            )
            val templateText = baseStrings[canonicalName]
            assertNotNull("Template text for '$canonicalName' must not be null", templateText)
            assertTrue("Template text for '$canonicalName' must not be blank", templateText!!.isNotBlank())
        }
    }

    @Test
    fun all53MessageKeysMapToMatchingRStringResourceFields() {
        val rStringClass = try {
            Class.forName("com.nava.app.R\$string")
        } catch (_: ClassNotFoundException) {
            null
        }

        val provider = AndroidResourceMessageTemplateProvider()

        for (key in MessageKey.entries) {
            val canonicalName = MessageTemplateProvider.canonicalResourceName(key)
            if (rStringClass != null) {
                val field = try {
                    rStringClass.getField(canonicalName)
                } catch (_: NoSuchFieldException) {
                    null
                }
                assertNotNull("R.string must contain field '$canonicalName'", field)
                val expectedResId = field!!.getInt(null)
                val actualResId = provider.stringResFor(key)
                assertEquals(
                    "AndroidResourceMessageTemplateProvider.stringResFor($key) must match R.string.$canonicalName",
                    expectedResId,
                    actualResId
                )
            } else {
                // When R class is not generated in headless pure-JVM mode, verify provider method doesn't throw
                val resId = provider.stringResFor(key)
                assertTrue("Resource ID for $key must be non-zero", resId != 0)
            }
        }
    }

    @Test
    fun all53TemplateStringsContainConsistentPlaceholders() {
        val fallbackProvider = FallbackEnglishMessageTemplateProvider()
        for (key in MessageKey.entries) {
            val canonicalName = MessageTemplateProvider.canonicalResourceName(key)
            val xmlTemplate = baseStrings.getValue(canonicalName)
            val fallbackTemplate = fallbackProvider.templateFor(key)

            val xmlPlaceholders = extractPlaceholders(xmlTemplate)
            val fallbackPlaceholders = extractPlaceholders(fallbackTemplate)

            assertEquals(
                "Placeholder signature in strings.xml for '$canonicalName' must match fallback template",
                fallbackPlaceholders,
                xmlPlaceholders
            )
        }
    }

    @Test
    fun templateProviderResolvesUsingFallbackWhenContextUnavailable() {
        val provider = AndroidResourceMessageTemplateProvider()
        val fallbackProvider = FallbackEnglishMessageTemplateProvider()
        for (key in MessageKey.entries) {
            val resolved = provider.templateFor(key)
            val expectedFallback = fallbackProvider.templateFor(key)
            assertEquals(
                "When context is unavailable, provider must fall back to FallbackEnglishMessageTemplateProvider for $key",
                expectedFallback,
                resolved
            )
        }
    }

    @Test
    fun stringsXmlIsStrictlyAscii() {
        val bytes = stringsFile.readBytes()
        for (b in bytes) {
            assertTrue("strings.xml must be strictly ASCII (byte <= 127)", (b.toInt() and 0xFF) <= 127)
        }
    }

    private fun resolveResDir(): File {
        val candidates = listOf(
            File("src/main/res"),
            File("app/src/main/res"),
            File("../app/src/main/res")
        )
        return candidates.firstOrNull { it.exists() && it.isDirectory }
            ?: error("Could not resolve app/src/main/res directory from ${File(".").absolutePath}")
    }

    private fun parseStringsXml(file: File): Map<String, String> {
        val factory = DocumentBuilderFactory.newInstance()
        val builder = factory.newDocumentBuilder()
        val doc = builder.parse(file)
        val stringNodes = doc.getElementsByTagName("string")
        val result = mutableMapOf<String, String>()
        for (i in 0 until stringNodes.length) {
            val element = stringNodes.item(i) as Element
            val name = element.getAttribute("name")
            val text = element.textContent
            result[name] = text
        }
        return result
    }

    private fun extractPlaceholders(value: String): List<String> {
        return placeholderRegex.findAll(value).map { it.value }.sorted().toList()
    }
}

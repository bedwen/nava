package com.nava.app.assistant

import android.content.Intent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

class AssistantServicesUnitTest {

    private lateinit var manifestFile: File
    private lateinit var manifestXml: String

    @Before
    fun setUp() {
        manifestFile = resolveManifestFile()
        assertTrue("AndroidManifest.xml must exist at ${manifestFile.absolutePath}", manifestFile.exists())
        manifestXml = manifestFile.readText(Charsets.UTF_8)
    }

    @Test
    fun manifestSecurityInvariants_noForbiddenPermissions() {
        val forbiddenPermissions = listOf(
            "android.permission.INTERNET",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.SEND_SMS",
            "android.permission.READ_SMS"
        )
        for (forbidden in forbiddenPermissions) {
            assertFalse(
                "AndroidManifest.xml MUST NOT declare $forbidden (Iron Law 3 & Gate 1)",
                manifestXml.contains(forbidden)
            )
        }
    }

    @Test
    fun manifestSecurityInvariants_requiredPermissionsPresent() {
        val requiredPermissions = listOf(
            "android.permission.USE_BIOMETRIC",
            "android.permission.RECORD_AUDIO"
        )
        for (required in requiredPermissions) {
            assertTrue(
                "AndroidManifest.xml must declare $required",
                manifestXml.contains(required)
            )
        }
    }

    @Test
    fun manifestSecurityInvariants_applicationAttributes() {
        val doc = parseXml(manifestFile)
        val appNodes = doc.getElementsByTagName("application")
        assertEquals("Must have exactly one <application> element", 1, appNodes.length)
        val app = appNodes.item(0) as Element

        assertEquals(".di.NavaApplication", app.getAttribute("android:name"))
        assertEquals("false", app.getAttribute("android:allowBackup"))
        assertEquals("@string/app_name", app.getAttribute("android:label"))
        assertEquals("true", app.getAttribute("android:supportsRtl"))
        assertEquals("@xml/locales_config", app.getAttribute("android:localeConfig"))
        assertEquals("@style/Theme.Nava", app.getAttribute("android:theme"))
    }

    @Test
    fun manifestSecurityInvariants_activityDeclarations() {
        val doc = parseXml(manifestFile)
        val activities = doc.getElementsByTagName("activity")
        val activityMap = mutableMapOf<String, Element>()
        for (i in 0 until activities.length) {
            val el = activities.item(i) as Element
            activityMap[el.getAttribute("android:name")] = el
        }

        // 1. .MainActivity
        val mainActivity = activityMap[".MainActivity"]
        assertNotNull(".MainActivity must be declared in AndroidManifest.xml", mainActivity)
        assertEquals("true", mainActivity!!.getAttribute("android:exported"))
        assertEquals("singleTop", mainActivity.getAttribute("android:launchMode"))

        val mainFilters = mainActivity.getElementsByTagName("intent-filter")
        assertTrue(".MainActivity must have at least one intent-filter", mainFilters.length > 0)
        var hasMainAction = false
        var hasLauncherCategory = false
        for (i in 0 until mainFilters.length) {
            val filter = mainFilters.item(i) as Element
            val actions = filter.getElementsByTagName("action")
            for (j in 0 until actions.length) {
                val act = (actions.item(j) as Element).getAttribute("android:name")
                if (act == "android.intent.action.MAIN") hasMainAction = true
            }
            val categories = filter.getElementsByTagName("category")
            for (j in 0 until categories.length) {
                val cat = (categories.item(j) as Element).getAttribute("android:name")
                if (cat == "android.intent.category.LAUNCHER") hasLauncherCategory = true
            }
        }
        assertTrue(".MainActivity must declare android.intent.action.MAIN", hasMainAction)
        assertTrue(".MainActivity must declare android.intent.category.LAUNCHER", hasLauncherCategory)

        // 2. .assistant.NavaAssistantSheetActivity
        val sheetActivity = activityMap[".assistant.NavaAssistantSheetActivity"]
        assertNotNull(".assistant.NavaAssistantSheetActivity must be declared in AndroidManifest.xml", sheetActivity)
        assertEquals(
            "NavaAssistantSheetActivity must be exported=false so external apps cannot forge intents",
            "false",
            sheetActivity!!.getAttribute("android:exported")
        )
        assertEquals("@style/Theme.Nava.Sheet", sheetActivity.getAttribute("android:theme"))
        assertEquals("true", sheetActivity.getAttribute("android:excludeFromRecents"))
        assertEquals("singleTop", sheetActivity.getAttribute("android:launchMode"))
    }

    @Test
    fun manifestSecurityInvariants_serviceDeclarations() {
        val doc = parseXml(manifestFile)
        val services = doc.getElementsByTagName("service")
        val serviceMap = mutableMapOf<String, Element>()
        for (i in 0 until services.length) {
            val el = services.item(i) as Element
            serviceMap[el.getAttribute("android:name")] = el
        }

        // 1. .assistant.NavaVoiceInteractionService
        val voiceService = serviceMap[".assistant.NavaVoiceInteractionService"]
        assertNotNull(".assistant.NavaVoiceInteractionService must be declared", voiceService)
        assertEquals(
            "android.permission.BIND_VOICE_INTERACTION",
            voiceService!!.getAttribute("android:permission")
        )
        assertEquals("true", voiceService.getAttribute("android:exported"))

        val voiceFilters = voiceService.getElementsByTagName("intent-filter")
        var hasVoiceAction = false
        for (i in 0 until voiceFilters.length) {
            val filter = voiceFilters.item(i) as Element
            val actions = filter.getElementsByTagName("action")
            for (j in 0 until actions.length) {
                if ((actions.item(j) as Element).getAttribute("android:name") ==
                    "android.service.voice.VoiceInteractionService"
                ) {
                    hasVoiceAction = true
                }
            }
        }
        assertTrue("NavaVoiceInteractionService must filter android.service.voice.VoiceInteractionService", hasVoiceAction)

        val metaDataNodes = voiceService.getElementsByTagName("meta-data")
        var hasVoiceMeta = false
        for (i in 0 until metaDataNodes.length) {
            val meta = metaDataNodes.item(i) as Element
            if (meta.getAttribute("android:name") == "android.voice_interaction" &&
                meta.getAttribute("android:resource") == "@xml/nava_voice_interaction_service"
            ) {
                hasVoiceMeta = true
            }
        }
        assertTrue("NavaVoiceInteractionService must declare @xml/nava_voice_interaction_service metadata", hasVoiceMeta)

        // 2. .assistant.NavaVoiceInteractionSessionService
        val sessionService = serviceMap[".assistant.NavaVoiceInteractionSessionService"]
        assertNotNull(".assistant.NavaVoiceInteractionSessionService must be declared", sessionService)
        assertEquals(
            "android.permission.BIND_VOICE_INTERACTION",
            sessionService!!.getAttribute("android:permission")
        )
        assertEquals("false", sessionService.getAttribute("android:exported"))

        // 3. .assistant.NavaQuickSettingsTileService
        val tileService = serviceMap[".assistant.NavaQuickSettingsTileService"]
        assertNotNull(".assistant.NavaQuickSettingsTileService must be declared", tileService)
        assertEquals(
            "android.permission.BIND_QUICK_SETTINGS_TILE",
            tileService!!.getAttribute("android:permission")
        )
        assertEquals("true", tileService.getAttribute("android:exported"))

        val tileFilters = tileService.getElementsByTagName("intent-filter")
        var hasTileAction = false
        for (i in 0 until tileFilters.length) {
            val filter = tileFilters.item(i) as Element
            val actions = filter.getElementsByTagName("action")
            for (j in 0 until actions.length) {
                if ((actions.item(j) as Element).getAttribute("android:name") ==
                    "android.service.quicksettings.action.QS_TILE"
                ) {
                    hasTileAction = true
                }
            }
        }
        assertTrue("NavaQuickSettingsTileService must filter android.service.quicksettings.action.QS_TILE", hasTileAction)
    }

    @Test
    fun manifestSecurityInvariants_pureAscii() {
        val bytes = manifestFile.readBytes()
        for (b in bytes) {
            assertTrue("AndroidManifest.xml must be strictly ASCII (byte <= 127)", (b.toInt() and 0xFF) <= 127)
        }
    }

    @Test
    fun assistantRoleHelper_gatewayDelegation() {
        val testIntent = Intent("android.app.role.action.REQUEST_ROLE")
        val fakeGateway = object : AssistantRoleManagerGateway {
            var available: Boolean = true
            var held: Boolean = false
            override fun isAssistantRoleAvailable(): Boolean = available
            override fun isAssistantRoleHeld(): Boolean = held
            override fun createRequestAssistantRoleIntent(): Intent? =
                if (available) testIntent else null
        }

        val helper = AssistantRoleHelper(fakeGateway)
        assertTrue(helper.isAssistantRoleAvailable())
        assertFalse(helper.isAssistantRoleHeld())
        assertEquals(testIntent, helper.createRequestAssistantRoleIntent())

        fakeGateway.available = false
        assertFalse(helper.isAssistantRoleAvailable())
        assertNull(helper.createRequestAssistantRoleIntent())

        fakeGateway.held = true
        assertTrue(helper.isAssistantRoleHeld())
    }

    @Test
    fun assistantRoleHelper_constantMatchesAndroidSdk() {
        assertEquals("android.app.role.ASSISTANT", AssistantRoleHelper.ROLE_ASSISTANT)
    }

    @Test
    fun voiceInteractionSession_launchSpecInvariants() {
        val spec = NavaVoiceInteractionSession.buildSheetSpec(
            openMode = AssistantOpenMode.QUICK_SHEET,
            packageName = "com.nava.app"
        )
        assertEquals("com.nava.app", spec.packageName)
        assertEquals("com.nava.app.assistant.NavaAssistantSheetActivity", spec.className)
        assertEquals(AssistantIntentContract.ACTION_OPEN_ASSISTANT_SHEET, spec.action)
        assertEquals(AssistantOpenMode.QUICK_SHEET, spec.openMode)
        assertEquals("QUICK_SHEET", spec.stringExtras[AssistantIntentContract.EXTRA_OPEN_MODE])
        assertTrue((spec.flags and Intent.FLAG_ACTIVITY_NEW_TASK) != 0)
        assertTrue((spec.flags and Intent.FLAG_ACTIVITY_SINGLE_TOP) != 0)
    }

    @Test
    fun quickSettingsTile_launchSpecAndPendingIntentInvariants() {
        val spec = NavaQuickSettingsTileService.buildTileLaunchSpec(
            openMode = AssistantOpenMode.QUICK_SHEET,
            packageName = "com.nava.app"
        )
        assertEquals("com.nava.app", spec.packageName)
        assertEquals("com.nava.app.assistant.NavaAssistantSheetActivity", spec.className)
        assertEquals(AssistantIntentContract.ACTION_OPEN_ASSISTANT_SHEET, spec.action)
        assertEquals(1001, NavaQuickSettingsTileService.TILE_REQUEST_CODE)
    }

    private fun resolveManifestFile(): File {
        val candidates = listOf(
            File("src/main/AndroidManifest.xml"),
            File("app/src/main/AndroidManifest.xml"),
            File("../app/src/main/AndroidManifest.xml")
        )
        return candidates.firstOrNull { it.exists() && it.isFile }
            ?: error("Could not resolve AndroidManifest.xml from ${File(".").absolutePath}")
    }

    private fun parseXml(file: File): org.w3c.dom.Document {
        val factory = DocumentBuilderFactory.newInstance()
        val builder = factory.newDocumentBuilder()
        return builder.parse(file)
    }
}

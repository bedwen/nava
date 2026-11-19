package com.nava.core.ai.pruner

import com.nava.core.ai.testing.CoreAiTestFixtures
import com.nava.domain.ai.IntentRequest
import com.nava.domain.tool.ToolCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DynamicToolPrunerTest {

    private val pruner = DynamicToolPruner(minTools = 3, maxTools = 5)
    private val allTools = CoreAiTestFixtures.canonicalTools()

    @Test
    fun selectsThreeToFiveToolsDeterministically() {
        val request = IntentRequest(
            requestId = "req-1",
            rawUtterance = "Set an alarm for 07:30 tomorrow",
            issuedAtEpochMs = 1_000L
        )

        val firstRun = pruner.prune(request, allTools)
        val secondRun = pruner.prune(request, allTools)

        assertEquals(firstRun, secondRun)
        assertTrue(firstRun.size in 3..5)
        assertEquals("set_alarm", firstRun.first().name)
    }

    @Test
    fun ranksRelevantToolsHighestAcrossCategories() {
        val commRequest = IntentRequest(
            requestId = "req-comm",
            rawUtterance = "Send sms draft message to +1 555 234 5678",
            issuedAtEpochMs = 2_000L
        )
        val commTools = pruner.prune(commRequest, allTools)
        assertEquals("create_sms_draft", commTools.first().name)

        val settingsRequest = IntentRequest(
            requestId = "req-settings",
            rawUtterance = "Adjust volume level to 80% and enable do not disturb",
            issuedAtEpochMs = 3_000L
        )
        val settingsTools = pruner.prune(settingsRequest, allTools)
        val topTwoNames = settingsTools.take(2).map { it.name }.toSet()
        assertTrue("set_volume" in topTwoNames)
        assertTrue("set_dnd" in topTwoNames)

        val notesRequest = IntentRequest(
            requestId = "req-notes",
            rawUtterance = "Save a note with title meeting summary",
            issuedAtEpochMs = 4_000L
        )
        val notesTools = pruner.prune(notesRequest, allTools)
        assertEquals("save_note", notesTools.first().name)
    }

    @Test
    fun handlesFewerThanThreeAvailableToolsGracefully() {
        val subset = listOf(CoreAiTestFixtures.SET_ALARM_TOOL, CoreAiTestFixtures.SET_TIMER_TOOL)
        val request = IntentRequest(
            requestId = "req-small",
            rawUtterance = "Set timer for 5 minutes",
            issuedAtEpochMs = 5_000L
        )

        val pruned = pruner.prune(request, subset)
        assertEquals(2, pruned.size)
        assertEquals(emptyList<Any>(), pruner.prune(request, emptyList()))
    }

    @Test
    fun selectCategoryBucketMapsCleanlyToFourKvCacheBuckets() {
        val timeBucket = pruner.selectCategoryBucket(
            IntentRequest("r1", "Set alarm for 07:30", issuedAtEpochMs = 1L),
            allTools
        )
        val commBucket = pruner.selectCategoryBucket(
            IntentRequest("r2", "Send sms message to +1 555 987 6543", issuedAtEpochMs = 1L),
            allTools
        )
        val settingsBucket = pruner.selectCategoryBucket(
            IntentRequest("r3", "Change volume to 50% and launch spotify", issuedAtEpochMs = 1L),
            allTools
        )
        val notesBucket = pruner.selectCategoryBucket(
            IntentRequest("r4", "Save note body for /docs/report.txt", issuedAtEpochMs = 1L),
            allTools
        )

        assertEquals(ToolCategory.TIME_CALENDAR, timeBucket)
        assertEquals(ToolCategory.COMMUNICATION, commBucket)
        assertEquals(ToolCategory.DEVICE_SETTINGS, settingsBucket)
        assertEquals(ToolCategory.NOTES_FILES, notesBucket)
    }
}

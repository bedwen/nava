package com.nava.app.ui.mvi

import com.nava.app.di.AppContainer
import com.nava.app.di.InMemoryPreferencesStorageGateway
import com.nava.app.di.InMemoryTestKeyProvider
import com.nava.app.di.PinnedModelCatalog
import com.nava.app.ui.hub.HubWorkMode
import com.nava.app.ui.hub.NavaHubViewModel
import com.nava.core.ai.engine.LiteRtRuntimeAdapter
import com.nava.core.ai.engine.RuntimeStreamDelta
import com.nava.core.ai.engine.RuntimeTurnConfig
import com.nava.domain.ai.EmbeddingPort
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

@OptIn(ExperimentalCoroutinesApi::class)
class HubWorkModeSplitTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun chatModeBypassesToolsAndUnloadsAddonModelsWhileWorkModePreservesActionHistory() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val modelsDir = tempFolder.newFolder("models")
        val vaultDir = tempFolder.newFolder("vault")
        File(modelsDir, PinnedModelCatalog.FILE_NAME_GEMMA4_E2B).writeBytes(byteArrayOf(1, 2, 3, 4))

        var embeddingUnloadCalls = 0
        var embeddingEmbedCalls = 0
        val spyEmbedding = object : EmbeddingPort {
            override suspend fun isEmbeddingModelAvailable(): Boolean = true
            override suspend fun embedQuery(query: String): FloatArray {
                embeddingEmbedCalls++
                return floatArrayOf(1f, 0f)
            }
            override suspend fun embedDocument(title: String, text: String): FloatArray {
                embeddingEmbedCalls++
                return floatArrayOf(1f, 0f)
            }
            override suspend fun unloadEmbeddingModel() {
                embeddingUnloadCalls++
            }
        }

        val fakeRuntime = object : LiteRtRuntimeAdapter {
            private var loaded = false
            val seenPrefixIds = mutableListOf<String>()

            override fun isLoaded(): Boolean = loaded
            override suspend fun ensureMasterPrefix(
                modelPath: String,
                systemPrefixId: String,
                systemPrompt: String,
                maxNumTokens: Int
            ) {
                loaded = true
                seenPrefixIds.add(systemPrefixId)
            }
            override fun runClonedTurn(
                systemPrefixId: String,
                config: RuntimeTurnConfig
            ): Flow<RuntimeStreamDelta> {
                return flowOf(RuntimeStreamDelta(outputDelta = "Direct Gemma chat reply"))
            }
            override suspend fun resetLiveChatSession() = Unit
            override suspend fun unload() {
                loaded = false
            }
        }

        val container = AppContainer.createForTesting(
            vaultDir = vaultDir,
            modelsDir = modelsDir,
            keyProvider = InMemoryTestKeyProvider(),
            preferencesStorageGateway = InMemoryPreferencesStorageGateway(),
            liteRtRuntimeAdapter = fakeRuntime,
            embeddingPort = spyEmbedding,
            verifyModelSha256OnResolve = false,
            ioDispatcher = dispatcher
        )

        val vm = NavaHubViewModel(
            container = container,
            dispatcher = dispatcher,
            clockMs = { 1_760_000_000_000L }
        )
        advanceUntilIdle()

        assertEquals(HubWorkMode.WORK, vm.uiState.value.workMode)

        // Switch to CHAT mode -> must unload embedding/function add-ons
        vm.setWorkMode(HubWorkMode.CHAT)
        advanceUntilIdle()
        assertEquals(HubWorkMode.CHAT, vm.uiState.value.workMode)
        assertTrue("Expected embedding model unload when switching to CHAT", embeddingUnloadCalls >= 1)

        // Submit an alarm-like utterance in CHAT mode -> must bypass Tier 1/tools and stay in chatHistory
        vm.submitQuery("Set alarm for 07:30")
        advanceUntilIdle()

        assertEquals(0, embeddingEmbedCalls)
        assertEquals(0, vm.uiState.value.actionHistory.size)
        assertEquals(1, vm.uiState.value.chatHistory.size)
        assertEquals("Direct Gemma chat reply", vm.uiState.value.chatHistory.single().conversationalReply)
        assertEquals(vm.uiState.value.chatHistory, vm.uiState.value.activeHistory)

        // Switch back to WORK mode -> actionHistory is separate and clean
        vm.setWorkMode(HubWorkMode.WORK)
        advanceUntilIdle()
        assertEquals(HubWorkMode.WORK, vm.uiState.value.workMode)
        assertEquals(0, vm.uiState.value.activeHistory.size)
    }
}

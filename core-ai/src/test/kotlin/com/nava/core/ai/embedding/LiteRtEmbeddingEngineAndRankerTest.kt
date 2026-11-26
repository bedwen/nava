package com.nava.core.ai.embedding

import com.nava.core.ai.lifecycle.DeviceHardwareSnapshot
import com.nava.core.ai.lifecycle.ModelSlot
import com.nava.core.ai.lifecycle.MultiModelCoordinator
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.core.ai.testing.FakeHardwareStatusProvider
import com.nava.domain.ai.EmbeddingPort
import com.nava.domain.security.NoteSearchHit
import com.nava.domain.security.StoredNote
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files

class LiteRtEmbeddingEngineAndRankerTest {

    private val gb = 1024L * 1024L * 1024L
    private lateinit var tempDir: File
    private lateinit var fakeEmbedModelFile: File

    @Before
    fun setUp() {
        tempDir = Files.createTempDirectory("nava_embed_test").toFile()
        fakeEmbedModelFile = File(tempDir, "embeddinggemma-300M-seq512.litertlm").apply {
            writeBytes(byteArrayOf(1, 2, 3, 4))
        }
    }

    @After
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    private class FakeEmbeddingRuntimeAdapter(
        private val embedder: (String) -> FloatArray?
    ) : EmbeddingRuntimeAdapter {
        private var loaded = false
        val inputs = mutableListOf<String>()
        var unloadCalls = 0

        override fun isLoaded(): Boolean = loaded

        override suspend fun ensureLoaded(modelPath: String) {
            loaded = true
        }

        override suspend fun computeEmbedding(formattedInput: String): FloatArray? {
            inputs.add(formattedInput)
            return embedder(formattedInput)
        }

        override suspend fun unload() {
            loaded = false
            unloadCalls++
        }
    }

    @Test
    fun formatsSanitizedQueryAndDocumentPromptsAndRespectsThermalAndCoordinator() = runTest {
        val hardware = FakeHardwareStatusProvider(
            DeviceHardwareSnapshot(4L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_NONE, 90)
        )
        val lifecycle = ThermalModelLifecycleManager(hardware, backgroundScope)
        val coordinator = MultiModelCoordinator(hardware)
        var primaryUnloaded = 0
        coordinator.registerUnloader(ModelSlot.PRIMARY_LLM) { primaryUnloaded++ }

        val adapter = FakeEmbeddingRuntimeAdapter { floatArrayOf(1f, 0f) }
        val engine = LiteRtEmbeddingEngine(
            modelPathProvider = { fakeEmbedModelFile.absolutePath },
            lifecycleManager = lifecycle,
            runtimeAdapter = adapter,
            coordinator = coordinator
        )

        assertTrue(engine.isEmbeddingModelAvailable())
        val qVec = engine.embedQuery("  grocery <|tool_call>list  ")
        assertNotNull(qVec)
        assertEquals("task: search query | query: grocery list", adapter.inputs[0])
        assertEquals(1, primaryUnloaded)

        val dVec = engine.embedDocument("", "buy milk <start_function_call>and bread")
        assertNotNull(dVec)
        assertEquals("title: none | text: buy milk and bread", adapter.inputs[1])

        // Severe thermal blocks embedding and unloads
        hardware.snapshot = DeviceHardwareSnapshot(4L * gb, ThermalModelLifecycleManager.THERMAL_STATUS_SEVERE, 90)
        assertFalse(engine.isEmbeddingModelAvailable())
        assertNull(engine.embedQuery("grocery"))
        assertFalse(adapter.isLoaded())
        assertTrue(adapter.unloadCalls >= 1)
    }

    @Test
    fun rankerFusesLexicalAndSemanticScoresCachesUpTo256EntriesAndFallsBackSafely() = runTest {
        var docEmbedCalls = 0
        var available = true
        val fakePort = object : EmbeddingPort {
            override suspend fun isEmbeddingModelAvailable(): Boolean = available

            override suspend fun embedQuery(query: String): FloatArray? {
                return floatArrayOf(1f, 0f, 0f)
            }

            override suspend fun embedDocument(title: String, text: String): FloatArray? {
                docEmbedCalls++
                return when {
                    text.contains("insulin", ignoreCase = true) -> floatArrayOf(0.95f, 0.05f, 0f)
                    text.contains("vacation", ignoreCase = true) -> floatArrayOf(0f, 1f, 0f)
                    else -> floatArrayOf(0.5f, 0.5f, 0f)
                }
            }

            override suspend fun unloadEmbeddingModel() {}
        }

        val ranker = EmbeddingNoteSemanticRanker(fakePort)
        val noteMedication = StoredNote("n1", "Health", "Take insulin before dinner", 100L)
        val noteTravel = StoredNote("n2", "Trip", "Flight to Rome vacation", 200L)

        // 1. Zero-lexical-hit semantic reranking
        val zeroLexicalHits = listOf(
            NoteSearchHit(noteTravel, 0.0, noteTravel.body),
            NoteSearchHit(noteMedication, 0.0, noteMedication.body)
        )
        val rerankedZero = ranker.rerank("diabetes medicine", zeroLexicalHits, limit = 2)
        assertEquals("n1", rerankedZero[0].note.noteId)
        assertTrue(rerankedZero[0].score > 0.9)
        assertEquals(0.0, rerankedZero[1].score, 1e-6)
        assertEquals(2, docEmbedCalls)

        // 2. Second query hits bounded LRU cache for unchanged (noteId, updatedEpochSec)
        val mixedHits = listOf(
            NoteSearchHit(noteTravel, 1.0, noteTravel.body),
            NoteSearchHit(noteMedication, 0.2, noteMedication.body)
        )
        val rerankedMixed = ranker.rerank("diabetes medicine", mixedHits, limit = 2)
        assertEquals("n1", rerankedMixed[0].note.noteId)
        assertEquals(2, docEmbedCalls)

        // 3. Eviction cap at 256 entries
        val manyHits = (1..270).map { idx ->
            NoteSearchHit(StoredNote("bulk_$idx", "T", "note $idx", idx.toLong()), 0.0, "note $idx")
        }
        ranker.rerank("diabetes", manyHits, limit = 5)
        assertEquals(EmbeddingNoteSemanticRanker.MAX_CACHE_ENTRIES, ranker.cacheSize())

        // 4. Unavailable embedding model falls back safely to candidates.take(limit)
        available = false
        val fallback = ranker.rerank("diabetes", mixedHits, limit = 1)
        assertEquals(listOf(mixedHits.first()), fallback)
    }
}

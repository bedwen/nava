package com.nava.core.ai.embedding

import android.content.Context
import android.util.Log
import com.google.ai.edge.litertlm.Backend
import com.google.ai.edge.litertlm.EmbeddingEngine
import com.google.ai.edge.litertlm.EmbeddingEngineConfig
import com.google.ai.edge.litertlm.EmbeddingOptions
import com.google.ai.edge.litertlm.InputData
import com.nava.core.ai.engine.AndroidLiteRtRuntimeAdapter
import com.nava.core.ai.lifecycle.ModelSlot
import com.nava.core.ai.lifecycle.MultiModelCoordinator
import com.nava.core.ai.lifecycle.ThermalModelLifecycleManager
import com.nava.domain.ai.EmbeddingPort
import com.nava.domain.ai.ThermalState
import com.nava.domain.security.Gemma4InputSanitizer
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Runtime adapter abstracting `com.google.ai.edge.litertlm.EmbeddingEngine` for deterministic
 * JVM testing without native JNI libraries.
 */
interface EmbeddingRuntimeAdapter {
    fun isLoaded(): Boolean

    suspend fun ensureLoaded(modelPath: String)

    suspend fun computeEmbedding(formattedInput: String): FloatArray?

    suspend fun unload()
}

/**
 * Production Android adapter wrapping `com.google.ai.edge.litertlm.EmbeddingEngine` (EmbeddingGemma 2).
 */
class AndroidLiteRtEmbeddingRuntimeAdapter(
    private val context: Context
) : EmbeddingRuntimeAdapter {

    private val stateMutex = Mutex()

    @Volatile
    private var activeEngine: EmbeddingEngine? = null
    private var loadedModelPath: String? = null

    override fun isLoaded(): Boolean {
        val engine = activeEngine ?: return false
        return runCatching { engine.isInitialized() }.getOrDefault(false)
    }

    override suspend fun ensureLoaded(modelPath: String) {
        withContext(Dispatchers.IO) {
            stateMutex.withLock {
                if (activeEngine != null && isLoaded() && loadedModelPath == modelPath) {
                    return@withLock
                }
                unloadLocked()
                val cacheDir = File(context.noBackupFilesDir, EMBEDDING_CACHE_DIR_NAME).apply {
                    mkdirs()
                }.absolutePath
                val config = EmbeddingEngineConfig(
                    modelPath = modelPath,
                    backend = Backend.CPU(
                        threadCount = AndroidLiteRtRuntimeAdapter.optimalCpuThreadCount()
                    ),
                    cacheDir = cacheDir
                )
                val candidate = EmbeddingEngine(config)
                try {
                    candidate.initialize()
                    activeEngine = candidate
                    loadedModelPath = modelPath
                } catch (ce: CancellationException) {
                    runCatching { if (candidate.isInitialized()) candidate.close() }
                    throw ce
                } catch (t: Throwable) {
                    runCatching { if (candidate.isInitialized()) candidate.close() }
                    throw t
                }
            }
        }
    }

    override suspend fun computeEmbedding(formattedInput: String): FloatArray? {
        return withContext(Dispatchers.IO) {
            stateMutex.withLock {
                val engine = activeEngine ?: return@withLock null
                val response = engine.computeEmbedding(
                    contents = listOf(InputData.Text(formattedInput)),
                    options = EmbeddingOptions(normalize = true)
                )
                response.embedding
            }
        }
    }

    override suspend fun unload() {
        withContext(Dispatchers.IO) {
            stateMutex.withLock {
                unloadLocked()
            }
        }
    }

    private fun unloadLocked() {
        val engine = activeEngine
        activeEngine = null
        loadedModelPath = null
        if (engine != null) {
            runCatching {
                if (engine.isInitialized()) {
                    engine.close()
                }
            }.onFailure { err ->
                Log.w(TAG, "Error closing EmbeddingEngine", err)
            }
        }
    }

    companion object {
        private const val TAG: String = "NavaEmbedding"
        private const val EMBEDDING_CACHE_DIR_NAME: String = "litert_embedding_cache"
    }
}

/**
 * On-device EmbeddingGemma 2 implementation of [EmbeddingPort] integrated with
 * [ThermalModelLifecycleManager] and [MultiModelCoordinator].
 */
class LiteRtEmbeddingEngine(
    private val modelPathProvider: suspend () -> String?,
    private val lifecycleManager: ThermalModelLifecycleManager,
    private val runtimeAdapter: EmbeddingRuntimeAdapter,
    private val coordinator: MultiModelCoordinator? = null
) : EmbeddingPort {

    private val embeddingMutex = Mutex()

    init {
        coordinator?.registerUnloader(ModelSlot.EMBEDDING_ENGINE) {
            if (runtimeAdapter.isLoaded()) {
                unloadEmbeddingModel()
            }
        }
    }

    override suspend fun isEmbeddingModelAvailable(): Boolean {
        if (!lifecycleManager.canRunLlm()) return false
        val path = modelPathProvider() ?: return false
        if (path.isBlank()) return false
        return File(path).let { it.exists() && it.isFile }
    }

    override suspend fun embedQuery(query: String): FloatArray? {
        val cleanQuery = Gemma4InputSanitizer.sanitize(query).trim()
        if (cleanQuery.isEmpty()) return null
        return computeWithLifecycle("task: search query | query: $cleanQuery")
    }

    override suspend fun embedDocument(title: String, text: String): FloatArray? {
        val cleanTitle = Gemma4InputSanitizer.sanitize(title).trim()
        val cleanText = Gemma4InputSanitizer.sanitize(text).trim()
        if (cleanTitle.isEmpty() && cleanText.isEmpty()) return null
        return computeWithLifecycle("title: ${cleanTitle.ifBlank { "none" }} | text: $cleanText")
    }

    override suspend fun unloadEmbeddingModel() {
        embeddingMutex.withLock {
            lifecycleManager.forceUnload(ModelSlot.EMBEDDING_ENGINE) {
                runtimeAdapter.unload()
            }
            coordinator?.markUnloaded(ModelSlot.EMBEDDING_ENGINE)
        }
    }

    private suspend fun computeWithLifecycle(formattedInput: String): FloatArray? {
        if (lifecycleManager.currentThermalState() == ThermalState.SEVERE_OR_HIGHER) {
            unloadEmbeddingModel()
            return null
        }

        val modelPath = modelPathProvider()
        if (modelPath.isNullOrBlank() || !File(modelPath).let { it.exists() && it.isFile }) {
            return null
        }

        coordinator?.onBeforeLoad(ModelSlot.EMBEDDING_ENGINE)

        return embeddingMutex.withLock {
            if (lifecycleManager.currentThermalState() == ThermalState.SEVERE_OR_HIGHER) {
                runtimeAdapter.unload()
                coordinator?.markUnloaded(ModelSlot.EMBEDDING_ENGINE)
                return@withLock null
            }

            try {
                lifecycleManager.onEnsureLoaded(ModelSlot.EMBEDDING_ENGINE) {
                    runtimeAdapter.ensureLoaded(modelPath)
                    coordinator?.markLoaded(ModelSlot.EMBEDDING_ENGINE)
                }
                runtimeAdapter.computeEmbedding(formattedInput)
            } catch (ce: CancellationException) {
                if (!runtimeAdapter.isLoaded()) {
                    coordinator?.markUnloaded(ModelSlot.EMBEDDING_ENGINE)
                }
                throw ce
            } catch (_: Throwable) {
                if (!runtimeAdapter.isLoaded()) {
                    coordinator?.markUnloaded(ModelSlot.EMBEDDING_ENGINE)
                }
                null
            } finally {
                withContext(NonCancellable) {
                    scheduleIdleUnloadLocked()
                }
            }
        }
    }

    /**
     * Arms the per-slot idle unload timer, or unloads immediately on Tier 0, MODERATE thermal
     * state, battery < 15%, or SEVERE (the burst grace applies only under normal conditions).
     * Must be called while holding [embeddingMutex]; the deferred unloader re-acquires
     * [embeddingMutex] before the lifecycle mutex, preserving the
     * `embeddingMutex -> lifecycleManager.mutex` lock ordering.
     */
    private suspend fun scheduleIdleUnloadLocked() {
        if (!runtimeAdapter.isLoaded()) return
        lifecycleManager.onTurnCompleted(
            slot = ModelSlot.EMBEDDING_ENGINE,
            immediateUnloader = {
                runtimeAdapter.unload()
                coordinator?.markUnloaded(ModelSlot.EMBEDDING_ENGINE)
            },
            deferredIdleUnloader = { expectedGen ->
                embeddingMutex.withLock {
                    if (lifecycleManager.consumePendingIdleUnload(ModelSlot.EMBEDDING_ENGINE, expectedGen)) {
                        runtimeAdapter.unload()
                        coordinator?.markUnloaded(ModelSlot.EMBEDDING_ENGINE)
                    }
                }
            },
            minimumIdleTimeoutSec = EMBEDDING_BURST_IDLE_TIMEOUT_SEC
        )
    }

    private companion object {
        /** Grace window keeping the ~300M embedding model resident across a burst of calls. */
        const val EMBEDDING_BURST_IDLE_TIMEOUT_SEC: Int = 15
    }
}

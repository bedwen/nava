package com.nava.spike.phase0

import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import java.io.File

/**
 * Minimal offline launcher activity for running the Phase 0 spike on physical arm64-v8a hardware.
 * Supports either SAF .litertlm import into filesDir/models/ or running directly against an
 * adb-pushed model inside filesDir/models/.
 */
class Phase0SpikeActivity : AppCompatActivity() {

    private lateinit var provisioner: Phase0SafProvisioner
    private lateinit var harness: Phase0SpikeHarness
    private lateinit var logView: TextView
    private lateinit var importBtn: Button
    private lateinit var runGpuBtn: Button
    private lateinit var runCpuBtn: Button
    private var isRunning: Boolean = false

    private val openModelLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) {
            appendLog("SAF picker cancelled.")
            return@registerForActivityResult
        }
        if (isRunning) {
            appendLog("Operation already in flight; ignoring SAF import request.")
            return@registerForActivityResult
        }
        isRunning = true
        setButtonsEnabled(false)
        lifecycleScope.launch {
            try {
                runCatching {
                    appendLog("Starting offline SAF import + SHA-256 verification...")
                    val result = provisioner.importAndVerifyModel(sourceUri = uri)
                    appendLog(
                        "Imported ${result.modelFile.name}: bytes=${result.bytesCopied}, " +
                            "durationMs=${result.durationMs}, sha256=${result.sha256Hex}, " +
                            "availAfter=${result.availableBytesAfter}"
                    )
                }.onFailure { err ->
                    appendLog("SAF import failed: ${err.javaClass.simpleName}: ${err.message}")
                }
            } finally {
                isRunning = false
                setButtonsEnabled(true)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        provisioner = Phase0SafProvisioner(applicationContext)
        harness = Phase0SpikeHarness(applicationContext)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = 32
            setPadding(pad, pad, pad, pad)
        }

        importBtn = Button(this).apply {
            text = "1. Import .litertlm via SAF (SHA-256)"
            setOnClickListener {
                if (!isRunning) {
                    openModelLauncher.launch(arrayOf("*/*"))
                }
            }
        }

        runGpuBtn = Button(this).apply {
            text = "2. Run Phase 0 Benchmark (GPU)"
            setOnClickListener { runLatestModel(useGpu = true, enableMtp = false) }
        }

        runCpuBtn = Button(this).apply {
            text = "3. Run Phase 0 Benchmark (CPU)"
            setOnClickListener { runLatestModel(useGpu = false, enableMtp = false) }
        }

        logView = TextView(this).apply {
            textSize = 12f
            text = "Ready. Models dir: ${provisioner.modelsDirectory().absolutePath}\n" +
                "Device: ${harness.captureDeviceSnapshot()}\n"
        }

        val scroller = ScrollView(this).apply {
            addView(logView)
        }

        root.addView(importBtn)
        root.addView(runGpuBtn)
        root.addView(runCpuBtn)
        root.addView(scroller)
        setContentView(root)
    }

    private fun runLatestModel(useGpu: Boolean, enableMtp: Boolean) {
        if (isRunning) {
            appendLog("Operation already in flight; ignoring duplicate benchmark tap.")
            return
        }
        val modelFile = findModelFile()
        if (modelFile == null) {
            appendLog(
                "No .litertlm file found in ${provisioner.modelsDirectory().absolutePath}. " +
                    "Use button 1 (SAF) or adb push."
            )
            return
        }
        isRunning = true
        setButtonsEnabled(false)
        lifecycleScope.launch {
            try {
                runCatching {
                    appendLog("Running Phase0SpikeHarness on ${modelFile.name} (gpu=$useGpu, mtp=$enableMtp)...")
                    val report = harness.runFullSuite(
                        modelFile = modelFile,
                        useGpuBackend = useGpu,
                        enableMtp = enableMtp
                    )
                    appendLog(formatReport(report))
                }.onFailure { err ->
                    appendLog("Spike run failed: ${err.javaClass.simpleName}: ${err.message}")
                }
            } finally {
                isRunning = false
                setButtonsEnabled(true)
            }
        }
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        importBtn.isEnabled = enabled
        runGpuBtn.isEnabled = enabled
        runCpuBtn.isEnabled = enabled
    }

    private fun findModelFile(): File? {
        return provisioner.modelsDirectory()
            .listFiles { file -> file.isFile && file.name.endsWith(".litertlm") }
            ?.maxByOrNull { it.lastModified() }
    }

    private fun formatReport(report: Phase0SpikeHarness.SpikeSuiteReport): String {
        return buildString {
            append("=== PHASE 0 SPIKE REPORT ===\n")
            append("Model: ").append(report.modelPath).append('\n')
            append("Backend: ").append(report.backendName).append(" | MTP=").append(report.enableMtp).append('\n')
            append("Device Before: ").append(report.deviceBefore).append('\n')
            append("Cold init (ms): ").append(report.coldInitializeMs)
                .append(" | Warm init (ms): ").append(report.warmReinitializeMs).append('\n')
            append("Clone loop native heap growth (bytes): ").append(report.cloneLoopNativeHeapGrowthBytes).append('\n')
            append("Stage 2 decoder emitted tool call: ").append(report.stage2DecoderEmittedToolCall)
                .append(" | Kotlin invariant enforced: ").append(report.stage2KotlinInvariantEnforced).append('\n')
            append("Preface preview: ").append(report.renderedPrefacePreview.take(200)).append('\n')
            append("Injection render preview: ").append(report.renderedInjectionPreview.take(200)).append('\n')
            for (m in report.turnMetrics) {
                append("--- [").append(m.label).append("] ---\n")
                append("  TTFT=").append(m.ttftMs).append("ms, Total=").append(m.totalMs)
                    .append("ms, KVTokens=").append(m.kvTokenCount)
                    .append(", HeapDelta=").append(m.nativeHeapDeltaBytes)
                    .append(", ThoughtChars=").append(m.thoughtCharCount)
                    .append(", ToolCalls=").append(m.toolCallCount).append('\n')
                append("  BenchmarkInfo: ").append(m.nativeBenchmarkSummary).append('\n')
                append("  Output: ").append(m.outputPreview).append('\n')
            }
            append("Device After: ").append(report.deviceAfter).append('\n')
        }
    }

    private fun appendLog(line: String) {
        logView.append("\n$line\n")
    }
}

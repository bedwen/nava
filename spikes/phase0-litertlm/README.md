# Nava Phase 0 LiteRT-LM & Provisioning Spike Harness

Isolated Android spike application validating `com.google.ai.edge.litertlm:litertlm-android` (`0.19.1`) and offline Gemma 4 (`E2B` / `E4B`) `.litertlm` provisioning on physical `arm64-v8a` hardware with **zero `INTERNET` permission** and **zero `MANAGE_EXTERNAL_STORAGE`**.

## 1. Prerequisites

* Physical Android device running **Android 12+ (`API 31+`)** on **`arm64-v8a`**.
* Free internal storage:
  * **For SAF import (`Phase0SafProvisioner`):** Minimum **2x** model size (`~5.4 GB` free for `Gemma 4 E2B` `2.58 GB`; `~7.6 GB` free for `Gemma 4 E4B` `3.65 GB`) until the external download is removed after import.
  * **For `adb push` direct staging:** Minimum `2.8 GB` (`E2B`) or `4.0 GB` (`E4B`) free.
* `.litertlm` weights obtained externally on host (e.g., `litert-community/gemma-4-E2B-it-litert-lm` or `litert-community/gemma-4-E4B-it-litert-lm`) and SHA-256 digest computed on host (`sha256sum gemma-4-E2B-it.litertlm`).

## 2. Build & Install the Standalone Spike APK

Because `spikes/phase0-litertlm` is intentionally kept outside root `settings.gradle.kts`, invoke Gradle directly with `-p spikes/phase0-litertlm`:

```bash
./gradlew -p spikes/phase0-litertlm assembleDebug
adb install -r spikes/phase0-litertlm/build/outputs/apk/debug/phase0-litertlm-debug.apk
```

*(Note: Verify root Gate 1 architecture compliance anytime with `bash scripts/verify_architecture.sh`.)*

## 3. Model Staging Options (Zero `INTERNET`)

### Option A -- Offline SAF Import (End-to-End Provisioning Validation)
1. Push the model onto user-accessible device Downloads:
   ```bash
   adb push gemma-4-E2B-it.litertlm /sdcard/Download/gemma-4-E2B-it.litertlm
   ```
2. Launch `Nava Phase 0 Spike` on the phone.
3. Tap **`1. Import .litertlm via SAF (SHA-256)`**, pick `/sdcard/Download/gemma-4-E2B-it.litertlm`, and verify the logged SHA-256 matches `sha256sum` from host.

### Option B -- Direct `adb push` into App-Private Storage (`run-as`)
For rapid benchmarking without keeping a 2x copy on `/sdcard/Download`:
```bash
adb push gemma-4-E2B-it.litertlm /data/local/tmp/gemma-4-E2B-it.litertlm
adb shell run-as com.nava.spike.phase0 mkdir -p files/models
adb shell run-as com.nava.spike.phase0 cp /data/local/tmp/gemma-4-E2B-it.litertlm files/models/gemma-4-E2B-it.litertlm
adb shell rm /data/local/tmp/gemma-4-E2B-it.litertlm
```

## 4. Running Benchmarks & Collecting Telemetry

1. Reset battery stats before a 100-query test:
   ```bash
   adb shell dumpsys batterystats --reset
   ```
2. Tap **`2. Run Phase 0 Benchmark (GPU)`** and **`3. Run Phase 0 Benchmark (CPU)`** in `Phase0SpikeActivity`.
3. Capture live peak memory (Native PSS + Java Heap) during inference:
   ```bash
   adb shell dumpsys meminfo com.nava.spike.phase0
   ```
4. Capture battery impact after the run:
   ```bash
   adb shell dumpsys batterystats com.nava.spike.phase0
   ```
5. Record all observed values into `docs/spikes/PHASE_0_FEASIBILITY_REPORT.md` to clear the `PENDING_DEVICE_RUN` gates (G0-B1 through G0-B8).

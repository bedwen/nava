# NAVA -- On-Device Gemma 4 Privacy, Security, and Automation Assistant

> **Status: Work in Progress (Active Development)**
>
> Nava is currently under active development and is **not yet production-ready**. All five architectural modules (Phases 1-5, including `:app`) are fully implemented and verified via Gate 1 architecture guards, comprehensive JVM unit and Gate 2 red-team test suites, `:app:assembleDebug`, and `:app:compileDebugAndroidTestKotlin`. Physical `arm64-v8a` device runtime execution (Phase 0 feasibility measurements and on-device `androidTest`) and an independent third-party security audit remain pending.

---

## Overview

**Nava** is a 100% offline Android personal assistant powered by on-device **Gemma 4** (`E2B` / `E4B` via LiteRT-LM) and a multi-tiered deterministic automation engine, designed under a strict **Zero-Trust** security architecture.

Its core goal is to provide fast, private on-device automation without cloud dependencies, without `android.permission.INTERNET`, and without third-party runtime libraries.

---

## Current Implementation Status

| Phase | Scope | Status |
| :--- | :--- | :--- |
| **Phase 0** | On-Device LiteRT-LM & Provisioning Feasibility Spike (`spikes/phase0-litertlm/`) | `SDK_AND_ARCHITECTURE_VERIFIED / ON_DEVICE_RUN_PENDING` |
| **Phase 1** | 5-Module Gradle Skeleton, Gate 1 Guard (`scripts/verify_architecture.sh`), and `:domain` Pure Kotlin Contracts | `COMPLETED` |
| **Phase 2** | `:core-security-data` (Keystore `AES-256-GCM`, `EncryptedSqliteStore`, `Nava Vault`, `PermissionProfile`, `RuleCapabilityGrant`, `AuditLogDao`, `BlindSlotExtractor`, `SecurityFirewall`, Gate 2 red-team suites) | `COMPLETED` |
| **Phase 3** | `:core-ai` (3-Tier Hybrid Router, `LiteRtLlmEngine`, `DynamicToolPruner`, `MicroDslParser`, `ThermalModelLifecycleManager`, SAF SHA-256 model provisioning, `OnDeviceLanguageDetector`, `SupportedLanguageCatalog`, seed Layer R rule packs, Gate 2 red-team suites) | `COMPLETED` |
| **Phase 4** | `:feature-automations` (Atomic `NavaTool` adapters, `NavaNotificationListenerService`, `WorkManager` `RoutineExecutor` & `BackgroundTaskContinuationManager`, Gate 2 real-firewall red-team suites) | `COMPLETED` |
| **Phase 5** | `:app` (`Dual-Core Neural Canvas`, MVI screens & ViewModels, `NavaViewModelFactory`, Default-Deny Onboarding, Action Confirmation Cards, `VoiceInteractionService` / `TileService`, `AppContainer` manual DI, `values-{tr,ar,es,fr}` translations, Gates 1-3 verified) | `COMPLETED` |

---

## Architecture & Core Principles

Nava is structured into **5 Gradle modules** with dependencies pointing strictly inward toward `:domain`:

```
:app                    Presentation (Jetpack Compose, Dual-Core Neural Canvas, MVI, AppContainer DI)
  |-- :feature-automations   Atomic NavaTool adapters (Alarm, Calendar, SMS Draft, Audio/DND, SAF, Routines)
  |-- :core-ai               3-Tier Hybrid Router & on-device Gemma 4 (LiteRT-LM) engine
  |-- :core-security-data    Keystore AES-256-GCM, EncryptedSqliteStore, Nava Vault, SecurityFirewall
  '-- :domain                Pure Kotlin contracts, use cases, and entities (zero Android/AndroidX imports)
```

### Key Design Highlights

* **Zero `INTERNET` Permission:** `android.permission.INTERNET` is forbidden in all `AndroidManifest.xml` files. Model weights (`.litertlm`) are provisioned offline via Storage Access Framework (SAF) with streaming SHA-256 verification.
* **Zero External 3rd-Party Dependencies:** Built exclusively with the Official Android SDK, Kotlin Standard Library / Coroutines, Official Android Jetpack (`androidx.*`), and Google's official on-device `com.google.ai.edge.litertlm:litertlm-android` runtime.
* **3-Tier Hybrid Intent Router:**
  * **Tier 1 (`RuleIntentResolver`):** Deterministic rule engine (`<2 ms`) handling common commands without waking the LLM.
  * **Tier 2 (`CacheIntentResolver`):** `HMAC-SHA256` normalized skeleton cache (`<5 ms`).
  * **Tier 3 (`GemmaIntentResolver`):** On-device Gemma 4 inference via `LiteRtLlmEngine` for complex or chained requests.
* **Default-Deny & 5 Atomic Capability Switches:** Every app, notification source, and directory starts blocked (`DENIED`). Capabilities (`NOTIFICATION_READ`, `DATA_READ`, `CREATE_DRAFT`, `MODIFY_DELETE_SEND`, `APP_LAUNCH`) are evaluated independently via `PermissionProfile`.
* **Plan-Then-Extract & Value Taint Tracking:** Untrusted external data (notifications, messages, files, clipboard) is isolated with `DataProvenance.UNTRUSTED_EXTERNAL` (`Tainted<T>`). Stage 1 mints a `CapabilityToken` strictly from user utterances; Stage 2 (`BlindSlotExtractor`) deterministically rejects any tool call in Kotlin (`SecurityException`), and sensitive slots from untrusted sources cannot auto-execute.
* **Zero-Jank Neural UI:** A single hardware-accelerated `Canvas` backed by pre-allocated primitive `FloatArray` buffers (`0` heap allocations inside `onDraw`, sleeping at `0 FPS` when idle).

---

## Tech Stack & Baseline

* **Language:** Kotlin (`2.4.21`) + Coroutines (`1.9.0`)
* **Build System:** Gradle (AGP `8.7.3`)
* **Target Platform:** Android (`minSdk = 31`, `arm64-v8a`)
* **UI:** Jetpack Compose (`composeBom = 2024.12.01`, Material 3)
* **On-Device AI:** LiteRT-LM (`com.google.ai.edge.litertlm:litertlm-android:0.19.1`)
* **Dependency Injection:** Pure Kotlin Constructor DI (`AppContainer`)

---

## Verification

Nava uses a **Risk-Tiered Verification Pipeline**:

1. **Gate 1 (Deterministic Architecture Guard):** Checks manifest permissions, dependency allowlist, `:domain` purity, Neural Canvas zero-allocation rules, and English/ASCII codebase rules:
   ```bash
   ./gradlew verifyArchitecture
   # or directly:
   bash scripts/verify_architecture.sh
   ```
2. **Gate 2 (Adversarial Red-Team & Invariant Suites):** Security, allocation, and invariant test suites covering prompt injection, `Tainted<T>` escalation, IPC exfiltration, cryptographic `AAD` integrity, multilingual normalization, and Neural Canvas zero-allocation constraints.
3. **Gate 3 (Independent Four-Eyes Review):** Line-by-line architecture, security, lifecycle, and concurrency review against `PLAN.md`.

All five modules (Phases 1-5) are implemented and verified:
```bash
./gradlew test
./gradlew :app:assembleDebug :app:compileDebugAndroidTestKotlin
```

> **Note:** Physical `arm64-v8a` device runtime execution (Phase 0 LiteRT-LM hardware measurements and on-device `androidTest` suites) and an independent third-party security audit remain pending.

---

## Disclaimer & Untested Software Notice

**IMPORTANT -- PLEASE READ CAREFULLY:**

* **Development Status:** While all architectural modules (Phases 1-5, including `:app`) are implemented and verified via Gate 1 architecture guards, JVM unit and Gate 2 red-team suites, `:app:assembleDebug`, and `:app:compileDebugAndroidTestKotlin`, Nava remains under active development and is **not yet production-ready**.
* **Pending Physical Device Runtime Execution & Audit:** The application has **not yet been executed or benchmarked end-to-end on physical `arm64-v8a` Android hardware** (Phase 0 on-device spike measurements and on-device `androidTest` suites remain pending hardware testbed execution), and no independent third-party security audit has been conducted.
* **No Warranty / Use at Your Own Risk:** This software is provided **"AS IS"**, without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, security, or non-infringement. Do **not** rely on this repository in production or for safeguarding critical or sensitive personal data while it remains under active development. In no event shall the authors or copyright holders be liable for any claim, damages, data loss, or other liability arising from the use of this software.

---

## License

This project is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for the full license text.

# NAVA -- On-Device Gemma 4 Privacy, Security, and Automation Assistant

<h2 align="center">PROJECT ON HOLD -- PAUSED NOVEMBER 2026</h2>

<p align="center">
  <b>Development is paused until stronger small on-device language models are available.</b><br>
  This is a one-person project; it is <b>not production-ready</b> and is <b>not</b> under active maintenance.
</p>

> [!CAUTION]
> **Do not rely on this code to protect real personal data.**
> The latest changes (one-tap permissions, personal memory, device controls, routines, UI
> performance, notification watchers) have **not** passed the independent Gate 2 red-team review
> or the Gate 3 principal review. See [Review status](#review-status-of-the-latest-work).

| | |
| :--- | :--- |
| **State** | Paused, not maintained |
| **Builds / tests** | Yes -- `./gradlew verifyArchitecture test` passes (about 1,470 JVM tests) |
| **Runs on a phone** | Yes -- tested on one device (Samsung Galaxy A36, Android 17) |
| **Security review of latest work** | **Not done** (Gate 2 and Gate 3 pending) |
| **Why paused** | Small local models are not yet reliable at tool calling; the review bar is too heavy for one maintainer |
| **Resume plan** | [STATUS.md](STATUS.md) -- exact state, known issues, and next steps |

---

## Why the project is paused

Nava is a one-person project with a demanding goal: a genuinely useful assistant that runs
100% offline, never asks for the `INTERNET` permission, and treats every external input as
hostile. Two things make continuing right now hard:

1. **Today's small local models are the bottleneck.** On a mid-range phone (Samsung Galaxy A36,
   8 GB RAM) Gemma 4 E2B needs about 12 s to load from cold and 4-5 s for an ordinary request.
   More importantly, it is not reliable enough at structured tool calling: it uses typographic
   quotes, invents argument formats, splits one request into several calls, and adds arguments
   that do not exist. Much of the recent work was compensating for model output instead of
   building features. Larger models (E4B and up) are too heavy for the target devices.
2. **The security bar needs more than one person.** Every change that touches permissions,
   taint tracking, or the firewall is supposed to pass an independent red-team review (Gate 2)
   and an independent principal review (Gate 3). Doing that properly for every iteration is a
   lot of work for a single maintainer.

The plan is to resume when small on-device models handle function calling dependably. The
architecture (deterministic Tier 1 rules, a cache, and the LLM only as a last resort) is designed
so that a better model can be dropped in without changing the security model.

---

## What Nava is

**Nava** is an offline Android personal assistant powered by on-device **Gemma 4**
(`E2B` / `E4B` via LiteRT-LM), a **FunctionGemma 270M** router, and **EmbeddingGemma** for
semantic search, built under a strict **Zero-Trust** architecture:

* **No `INTERNET` permission, ever.** Models are imported through the Storage Access Framework
  with streaming SHA-256 verification.
* **No third-party runtime libraries.** Only the Android SDK, Kotlin stdlib/coroutines,
  `androidx.*`, and Google's official LiteRT-LM runtime.
* **Default-Deny.** Every app, notification source, folder, and feature starts blocked. Five
  independent capability switches (`NOTIFICATION_READ`, `DATA_READ`, `CREATE_DRAFT`,
  `MODIFY_DELETE_SEND`, `APP_LAUNCH`) are evaluated per target.
* **Plan-Then-Extract with taint tracking.** Only the user's own words can authorize tool calls.
  Text from notifications, messages, files, or shares is tagged `UNTRUSTED_EXTERNAL` and can
  never trigger tools or auto-execute sensitive actions; this is enforced in Kotlin, not in the
  prompt.
* **3-tier hybrid router.** Tier 1 deterministic rule packs (< 2 ms), Tier 2 HMAC skeleton
  cache, Tier 2.5 FunctionGemma, and Tier 3 Gemma 4 only when needed.
* **Zero-jank Neural Canvas.** One hardware-accelerated canvas, no allocations while drawing,
  0 FPS when idle.

---

## What works today

Measured on a Samsung Galaxy A36 (Android 17) with Gemma 4 E2B on the GPU:

| Area | State |
| :--- | :--- |
| Commands | Alarms, timers, reminders, calendar, notes, encrypted vault, SMS drafts, calls, Do Not Disturb, volume, app launch, folder access, notification summaries, daily briefing |
| New in the last round | Personal memory ("remember that ..."), flashlight, media controls, Wi-Fi/Bluetooth/internet/volume panels, multi-step natural-language routines |
| Languages | Tier 1 rule packs for Turkish, English, Spanish, French, Arabic; UI translated into all five |
| Speed | Common commands resolve instantly in Tier 1; the model starts loading when the input field is focused, so most of the ~12 s cold load overlaps with typing; a warm Tier 3 request takes about 4 s |
| Memory | About 870 MB while the model is resident; the model is unloaded after 180 s idle (back to about 115 MB) |
| Permissions | Plain-language "permission needed" card with one-tap "always allow" / "ask every time", scoped to the single target |
| My Day | Today's calendar, reminders, important notifications, and the list of remembered facts |
| Tests | About 1,470 JVM unit and red-team tests; `./gradlew verifyArchitecture test` passes |

---

## Review status of the latest work

Nava's process has three gates: **Gate 1** (automated architecture guard), **Gate 2**
(independent red-team suites), and **Gate 3** (independent principal review). Not all recent
work has been through all three:

| Change set | Gate 1 | Gate 2 | Gate 3 |
| :--- | :--- | :--- | :--- |
| Phases 1-5 (original implementation) | Passed | Passed | Passed |
| Audit fixes: Stage 1 history taint, per-slot model residency, locked-device key handling, routine anti-rollback seals | Passed | Passed (3 red-team tests still `@Ignore`d) | Passed, but the final remediation round was not re-checked |
| UI performance (lifecycle-aware state, streaming throttle, lazy audit log) | Passed | Not run | **Not run** |
| Notification watcher hardening (sender matching, locked-screen snapshot) | Passed | Not run | **Not run** |
| Speed, one-tap permissions, My Day, personal memory, device controls, routines, token call limit, outbound settings panels | Passed | **Not run** | **Not run** |

**Before anyone relies on this code, the last three rows need Gate 2 and Gate 3**, in
particular: the one-tap permission grant, the personal memory feed into the planner, the
`SETTINGS_PANEL` outbound action, and the change that lets a capability token cover repeated
calls to the same tool.

---

## Architecture

Five Gradle modules with dependencies pointing inward to `:domain`:

```
:app                    Jetpack Compose UI, Neural Canvas, MVI ViewModels, AppContainer DI
  |-- :feature-automations   NavaTool adapters (alarm, calendar, SMS, audio, SAF, memory, routines)
  |-- :core-ai               3-tier router, LiteRT-LM engine, prompt format, parsers, lifecycle
  |-- :core-security-data    Keystore AES-256-GCM, EncryptedSqliteStore, vault, firewall
  '-- :domain                Pure Kotlin contracts and use cases (no Android imports)
```

* **Language / build:** Kotlin `2.4.21`, coroutines `1.9.0`, AGP `8.7.3`
* **Platform:** Android, `minSdk = 31`, `arm64-v8a`
* **UI:** Jetpack Compose, Material 3
* **On-device AI:** LiteRT-LM `0.19.1`
* **DI:** plain constructor injection in `AppContainer`

---

## Building and testing

```bash
./gradlew verifyArchitecture test      # Gate 1 + all JVM unit and red-team suites
./gradlew :app:assembleDebug           # debug APK
```

Models are not shipped with the repository. Import a Gemma 4 `.litertlm` file from the app's
onboarding screen (Storage Access Framework, SHA-256 verified).

---

## Disclaimer

* **Paused and not production-ready.** The app has been run on one physical device only, no
  independent third-party security audit has been performed, and the latest changes have not
  passed Gate 2 or Gate 3.
* **No warranty.** This software is provided **"AS IS"**, without warranty of any kind, express or
  implied, including merchantability, fitness for a particular purpose, security, or
  non-infringement. Do not use it to protect critical or sensitive personal data. In no event
  shall the authors or copyright holders be liable for any claim, damages, data loss, or other
  liability arising from its use.

---

## License

Licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE).

# Nava -- Project Status (paused 2026-11-27)

Snapshot for whoever resumes the project. The README explains why it is paused; this file
records exactly where things stand.

## Branch layout

`master` now contains everything below (fast-forwarded). The topic branches are kept on the
remote for history:

| Branch | Content |
| :--- | :--- |
| `fix/critical-audit-findings` | Audit fixes K1-K3 (Stage 1 history taint, per-slot model residency, locked-device key fallback), Gate 2/3 remediation, defect 5 (routine anti-rollback seals) |
| `perf/ui-compose` | Lifecycle-aware state collection, 50 ms streaming throttle, `LazyColumn` audit log, 30 fps canvas pacing during inference, resource shrinking |
| `feat/notification-watchers` | Watcher sender matching on structured sender metadata, `EXTRA_PEOPLE_LIST` extraction, locked-screen watcher snapshot |
| `test/integration` | Merge of the three branches above (base for the next one) |
| `perf/speed-first-impression` | Speed, permissions, My Day, personal memory, device controls, routines (see below) |

## Last round of work (`perf/speed-first-impression`)

* Model prewarm on input focus, "preparing the model" status, input hints.
* Wider Tier 1 rule packs in tr/en/es/fr/ar; free-text slots keep the user's original spelling.
* Thought mode only for calendar date math.
* One-tap permission grant on the denial card (per-target profile fork; `AUTO` never allowed
  for `MODIFY_DELETE_SEND`; vault/SAF/notification reading keep their own flows).
* Permission screen consistency; My Day "Today" timeline and "What I remember" list.
* Personal memory (`remember_fact`, `recall_facts`, `forget_fact`; encrypted table, DB version 4;
  facts only from `USER_UTTERANCE`, passed to the planner as a bounded `[ABOUT_USER]` block).
* Device controls: flashlight, media keys, settings panels (`SETTINGS_PANEL` outbound action with
  a fixed panel allowlist).
* Multi-step routines (up to 3 actions), tolerant parsing of small-model output, merge of split
  calls from one request.
* Capability tokens now carry the plan's call count (bounded, max 8) so plans that repeat a tool
  are no longer rejected.
* Hardware Enter no longer clicks the audit log button.

## Review debt (must be cleared before relying on the code)

* **Gate 2 and Gate 3 have not run** on `perf/ui-compose`, `feat/notification-watchers`, or
  `perf/speed-first-impression`. Highest-risk items: one-tap grant
  (`ManageProfilesUseCase.setCapabilityForTarget`, `NavaHubViewModel.grantPermissionAndRetry`),
  `[ABOUT_USER]` facts in Stage 1 prompts, `SETTINGS_PANEL` in `OutboundChannelPolicy`,
  `maxToolCalls` in `SecurityFirewall.mintToken`, typographic quotes in `MicroDslParser`, and
  original-span recovery in `RuleIntentResolver`.
* The final defect-5 remediation round was not re-checked by an independent reviewer.
* Three Gate 2 red-team tests are `@Ignore`d pending fixes.

## Known issues

* Gemma 4 E2B tool calling is unreliable: extra or invented arguments (`mode=sleep`,
  `stream=default` in routines), split calls, wrong value formats. Routine actions with invented
  arguments have not been executed end to end yet.
* `NotificationUrgencyClassifier` uses a hardcoded English keyword list; Turkish promotional mail
  is shown as "important". The keywords should move into the locale rule packs.
* Calendar on the test device contains events created from tool descriptions by older builds.
* `LockedDeviceFallbackGate2RedTeamTest.concurrentReadersAndWriters_finalRevocationAlwaysWinsAfterLock`
  failed once under full parallel load and passed on every rerun (likely timing-sensitive).
* Permission denial check still happens after the LLM for Tier 3 requests.
* No contact lookup by design (the owner does not want Nava to read the address book); the
  personal memory can hold the numbers the user chooses to share.

## Device test notes (Samsung Galaxy A36, Android 17)

* Cold GPU engine init about 12 s; warm Tier 3 turn about 4 s; Tier 1 instant.
* PSS about 870 MB with the model resident, about 115 MB after the 180 s idle unload.
* The debug build was signed with `~/.android/debug.keystore` so updates keep app data.

## How to resume

1. Pick a stronger small model and re-run the device checks above (cold load, Tier 3 latency,
   tool-call format accuracy on routines and multi-step commands).
2. Run Gate 2 and Gate 3 over the review-debt items (see `AGENTS.md`, Gate Budget Rules).
3. Then continue with: urgency keywords in locale packs, permission pre-check before the LLM,
   and executing an approved multi-step routine end to end on a device.

Build: `./gradlew verifyArchitecture test` (JDK 21 with `javac` is required).

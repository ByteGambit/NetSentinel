# NS-098 — First-run/feedback polish: acceptance and handoff

Started from verified clean **main**, HEAD = origin/main =
`4846fe9d6427ce8b5b420353f21fad9e1b090425`, 2026-10-06.
Policy: [FIRST_RUN_FEEDBACK.md](FIRST_RUN_FEEDBACK.md). Exact acceptance:
capture/TI separate consent; no raw-history default export; feedback preview;
clear limitations; consistent release docs. Schema **019 → 019**, no migration.
M17 stays IN PROGRESS; NS-099 stays NOT STARTED.

**COMPLETE (2026-10-06).** Full offline **3781 passed, 8 deselected, 332.50s**;
Ruff, configured/direct mypy, diff and privacy review PASS. No release/tag.

## Requested 80-item report

| # | Item | Result / evidence |
|---|---|---|
| 1 | Exact title | NS-098 — First-run/feedback polish |
| 2 | Completion | COMPLETE; exact acceptance and final gates PASS |
| 3 | M17 | IN PROGRESS |
| 4 | Schema before/after | 019 → 019 |
| 5 | Migration | None; config owns UI acknowledgement |
| 6 | Version/state | CURRENT_ONBOARDING_VERSION=1; completed/dismissed integer versions; legacy boolean compatibility |
| 7 | Fresh trigger | Unacknowledged fresh config opens guide before core engine |
| 8 | Existing users | Nonmodal status-bar notice for legacy/older acknowledged guide |
| 9 | Skip | Dismiss current guide version; no completion or permission grant; no repeat launch |
| 10 | Cancel | No save; first run quits/reappears next time, Help just closes |
| 11 | Finish | Reload current settings and atomically complete guide; first-run engine starts once |
| 12 | Reopen | Help reads current settings, never resets or restarts engine |
| 13 | Steps | Six: Visibility first; Local monitoring and capture; Optional external reputation; What evidence can conclude; Privacy, storage and feedback; Current capabilities |
| 14 | Local-first | Exact “NetSentinel does not upload your network history by default.” visible |
| 15 | Capture explanation | Passive observed LAN/classic DNS/broadcast/VLAN metadata, explicit selected-network action |
| 16 | Capture permission | Existing Devices Start passive capture only; no shadow preference or guide toggles |
| 17 | TI explanation | Actual AbuseIPDB selected public IP/manual lookup, source-IP visibility, unknown retention; authentication key required |
| 18 | TI consent | Existing separate provider/data-type settings; default zero requests; Save alone sends nothing |
| 19 | Independence proof | Eight guide Finish/Skip combinations with capture running/stopped and TI consent on/off; unchanged actual consent and capture state, zero starts; existing consent regressions |
| 20 | Npcap absent | Unavailable with manual dependency/access explanation; supported core/saved views remain independent |
| 21 | Notifications | Disabled by default; separate opt-in screen; current preference shown |
| 22 | Storage link | Settings → Storage & Privacy; direct local shortcut in reopened guide |
| 23 | Polling | Short-lived connections can be missed |
| 24 | Process events | Metadata does not mean recorded creation/termination events |
| 25 | Flow bytes | Per-flow upload/download totals unavailable |
| 26 | DNS | Classic DNS where capture sees it; no universal DoH/DoT |
| 27 | Domain attribution | Many-to-many/ambiguous context, not causal proof |
| 28 | Hash | Disk bytes at observation, not process memory integrity |
| 29 | Signer | Signed not safe; unsigned not malicious |
| 30 | TI HIT | Not a malware verdict |
| 31 | TI NO_HIT | Not a safety verdict; stale/error/unknown separate |
| 32 | Baseline | Novel/rare not malicious; insufficient historical coverage explicit |
| 33 | Score | Deterministic review priority, not malware probability; severity/confidence/quality distinct |
| 34 | Incident | Related evidence grouping; ordering not causality or forensic completeness; source expiry disclosed |
| 35 | Response | No automatic blocking; no antivirus replacement |
| 36 | Summary | Activity versus capability, engine/connection/capture/DNS/local storage plus optional preferences |
| 37 | Diagnostics | Readable top summary; existing detailed matrix, privilege, worker and notification counters expandable |
| 38 | Optional disabled | Neutral Disabled by user; unchecked, degraded and unavailable separate; no false green |
| 39 | Feedback | Review fixed categories → full sanitized preview → local Save → manual sharing |
| 40 | Channel | Verified project remote; no dedicated feedback/private-security endpoint defined, explicitly disclosed; project page starts channel discovery |
| 41 | NS-095 reuse | Same dialog in feedback mode, worker, service, allowlist repository and atomic/cancel path |
| 42 | Defaults | App/schema/policy, generated export time, storage aggregates/retention, bounded sanitized alert/incident summaries |
| 43 | Preview | Full immutable sanitized UTF-8 bytes, included/excluded categories, counts, limitations and no-upload statement; Save gated |
| 44 | Redaction | allowlist-v1 unchanged; re-preview clears stale Save state; fixture fields remain excluded |
| 45 | Raw history | Never offered or included by default; no include-all option |
| 46 | Secrets | No key/config/raw exception/path in preview or support export; UI reads no secret backend |
| 47 | Upload | No automatic upload; Save local, browser separate explicit action |
| 48 | Crash upload | No crash client, exception POST or dump uploader |
| 49 | Runtime network | No new automatic request, telemetry dependency or startup/browser launch |
| 50 | Cancellation | Existing worker cancel/temp cleanup; no final file before replace; completed save is not undone |
| 51 | Bounds | Existing 50/category, 100 total, 25-row pages, 64KiB; no export format/policy bump |
| 52 | URL privacy | Fixed https://github.com/ByteGambit/NetSentinel; no query/prefill/attachment; clicked only |
| 53 | Notes path | docs/RELEASE_NOTES.md |
| 54 | Notes limits | 0.1.0 source/pilot preparation, unsigned/manual update, credential/capture/evidence limits; no release/tag or rebuilt binary claim |
| 55 | Screenshot strategy | Actual Qt/offscreen fixtures, fixed synthetic data/clock; five small PNGs following existing docs/images convention |
| 56 | Screenshot paths | docs/images/ns098-{guide,limitations,diagnostics,storage,feedback}-synthetic.png |
| 57 | Screenshot privacy | Synthetic/allowlisted data only; no real history, identity, path, domain, IP, MAC or key; labelled demo, no live sensor claim |
| 58 | 1280×720 | Essential guide/feedback controls fit; footer remains outside scroll body |
| 59 | Larger viewport | 1366×768, 1600×900, 1920×1080 tested; 9/16-point font proxies; guide also 12-point |
| 60 | Keyboard | Tab focus, Space navigation, Enter Finish and Esc cancellation tested |
| 61 | Accessibility | Meaningful names/tooltips for guide, local shortcuts, preview/export and browser action; text states independent of color |
| 62 | Walkthrough | Agent/operator synthetic offscreen walkthrough PASS; no independent novice/native beta usability claim |
| 63 | Added tests | 49 new NS-098 cases + two production-startup regressions (legacy/skipped) = 51 cases |
| 64 | Targeted | 269 passed, 23.86s; GUI/config/consent/export/privacy/packaging/installer dependencies |
| 65 | Full pytest | 3781 passed, 8 deselected, 332.50s |
| 66 | Ruff | src/tests/packaging PASS |
| 67 | Configured mypy | PASS, 36 source files |
| 68 | Direct mypy | PASS, 7 changed source modules including packaging entry |
| 69 | Diff | git diff --check PASS; normal LF/CRLF notices only |
| 70 | Privacy scan | PASS: changed-text secret/crash-client review, actual fixture PNG inspection, schema/dependency diff; reserved synthetic test values only |
| 71 | Added files | NS-098 GUI tests, synthetic renderer, three docs and five PNGs |
| 72 | Modified code | shared/config; onboarding; diagnostics; main_window; app; storage_privacy; packaging/entry; existing capability tests |
| 73 | Modified docs | README, PRODUCT, ARCHITECTURE, SECURITY, ROADMAP, TASKS, RELEASING and STORAGE_PRIVACY |
| 74 | TASKS | NS-098 COMPLETE; M17 IN PROGRESS; NS-099 task remains planned/NOT STARTED |
| 75 | Commit | feat: add first-run and feedback experience; exact ID in final Git handoff |
| 76 | Push | Normal origin/main push only; actual outcome in final Git handoff |
| 77 | HEAD/origin | Actual post-push comparison in final Git handoff |
| 78 | Working tree | Actual final status in final Git handoff |
| 79 | NS-099 | NOT STARTED; no beta gate/response work |
| 80 | Remaining blockers | None for NS-098; owner-defined feedback/security contact, public signer/licensing/audience and NS-099 remain release prerequisites |

## Execution evidence

Targeted dependency run: **269 passed in 23.86s**, using Qt offscreen and the
already approved bundled CPython 3.12.14 with existing repository dependencies.
No dependency installation or Windows security-policy change. Initial new-test
failures were test assumptions: offscreen focus required window activation;
a missing SQLite file initializes normally, so unavailable-storage tests now use
a corrupt synthetic file. A viewport check also identified a missing Cancel
tooltip, which was added. Corrected new-only run: **49 passed in 3.27s**.

Full offline result: **3781 passed, 8 deselected in 332.50s**. Configured mypy
**36** and direct mypy **7** PASS; Ruff and diff checks PASS. The only dependency
warning is existing Scapy/cryptography finite-field DH deprecation. The 80-item
table, documentation links, five image files and 19-migration inventory were
checked. Secret-token/crash-client pattern scan found no introduced credentials
or uploader; changed source/doc review and PNG inspection found no real telemetry.
Dependency manifests, version source, SQLite schema and NS-099 task are unchanged.

Exact command environment, without weakening Application Control:

```powershell
$env:PYTHONPATH = "$PWD\src;$PWD\.venv\Lib\site-packages"
$env:QT_QPA_PLATFORM = 'offscreen'
$env:PYTHONHASHSEED = '0'
$runtimePython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $runtimePython -m pytest tests/gui/test_first_run_feedback.py tests/gui/test_capabilities.py tests/gui/test_storage_privacy.py tests/gui/test_threat_intel_consent.py tests/unit/shared tests/integration/sqlite/test_storage_privacy.py tests/integration/test_packaging_resources.py tests/integration/test_installer_lifecycle.py -q
& $runtimePython -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests packaging
& $runtimePython -m mypy
& $runtimePython -m mypy src/netsentinel/shared/config.py src/netsentinel/presentation/app.py src/netsentinel/presentation/views/diagnostics.py src/netsentinel/presentation/views/main_window.py src/netsentinel/presentation/widgets/onboarding.py src/netsentinel/presentation/widgets/storage_privacy.py packaging/entry.py
& $runtimePython -m tests.fixtures.first_run_feedback_screenshots
git diff --check
```

## Walkthrough record and limits

New standard-user beta persona, using synthetic data and actual Qt widgets:

| Question / action | Observation |
|---|---|
| Is history uploaded by default? | Exact local-first statement on page 1; local sensitivity on page 5 |
| How does capture start? | Page 2 names Devices/current network/Start passive capture; guide zero starts |
| What leaves for TI? | Page 3 identifies AbuseIPDB/manual public IP/auth/source IP; separate consent, backend unavailable |
| Does score mean malware? | Page 4 says review priority, not probability; evidence limits remain accessible later |
| Where are privacy controls? | Settings Storage & Privacy; Help guide shortcuts use existing actions |
| Can optional features stay off? | Finish/Skip tests preserve TI, capture, notification and retention settings |
| Can feedback be reviewed? | Full read-only allowlist preview; Save gated; exact local bytes verified with 12 alerts beyond old sample size |
| Is feedback sent automatically? | No worker request on feedback open; no browser until click; Save reports no upload |
| Can limitations be found later? | Help guide reopens actual settings, no engine restart; no acknowledgement on local navigation |
| Is there a dead end/clipping? | Scrollable pages/body and visible footer at four sizes, keyboard and font proxies pass; save failure retry stays open |

Five generated PNGs were visually inspected: clear text, no clipped essential
controls, sanitized fixture preview and explicit degraded/default states. This
does not assert Windows native DPI, accessibility reader, independent-user
comprehension, installer rebuild or client VM beta acceptance. NS-099 remains
unstarted. No capture, external provider request, public issue, telemetry upload,
certificate purchase, tag, release or update client was performed.

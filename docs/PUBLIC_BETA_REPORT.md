# NS-099 — Final delivery record

Second host sleep diagnostic (2026-10-07): **NOT RUN**, active Mobile Hotspot
SYSTEM/AWAYMODE request with AC Away Mode enabled. Administrator read-only query
succeeded; Legacy Kernel Caller SYSTEM and WebView2 audio EXECUTION also present,
DISPLAY none. No fresh sleep event, app launch or new workload measurements;
no service/power/override change. Prior first-attempt numbers remain historical.
Docs-only evidence is committed/pushed normally; no installer rebuild, tag,
release, VPN retest or NS-100. NS-099 INCOMPLETE/M17 IN PROGRESS, M18 DEFER,
pilot/broad NO_GO. [Blocker and scope](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md#second-attempt--blocker-diagnosis-no-sleep-action-requested).

Physical-host sleep attempt (2026-10-07): **NOT RUN**, actual native transition
not verified despite S3 support and the operator's reported wake. Wall and awake
time both advanced157.72s; no new power event. App PID/session unchanged,
alert/incident delta0/0, notification attempts0 with notifications OFF;
DB grew266,240 bytes by first post-action snapshot, integrity clean. Ordinary
Quit upper bound2.315s, no remaining app. NS-099 INCOMPLETE/M17 IN PROGRESS;
VPN BLOCKED/NOT RUN; pilot/broad NO_GO, M18 DEFER. No runtime change/rebuild,
commit/push/tag/release/NS-100. [Exact scope and evidence](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md).

VPN-only environment attempt (2026-10-07): **NOT RUN**, because Windows
Application Control blocked the hash-verified portable host server before process
creation. Alerts/incidents/notifications/app errors **NOT MEASURED**. No product
change, security bypass or native sleep test. NS-099 INCOMPLETE; M17 IN PROGRESS;
pilot/broad NO_GO; M18 DEFER; NS-100 NOT STARTED; no tag/release.
[Attempt, candidate identity and cleanup](NS099_VPN_ENVIRONMENT_ATTEMPT.md).

NS-099 notification-policy closure (2026-10-07): **policy PASS**, actual Windows
global Notifications OFF/ON in the same Limited-token Session1; application
reports **UNKNOWN**, accepted submission is not visible-delivery proof.
Current unpublished unsigned0.1.0 source `8242868ba79c63ad743c005366ea715b238cf5d0`,
SHA256 `39b14fe844c8aaa150a8b09229e0d63aaaf5ecc98b5bc8c54b419140be7749d9`, 37,559,481 bytes, schema019→019.
Installed1119 hashes/0 mismatches;194 source-matching compiled modules.
Native popup/privacy/click/duplicates/restart PASS in the recorded policy scope.
Human UX remains PASS8/8, layout CLOSED in its evaluator scope. VPN and meaningful
native sleep NOT RUN; NS-099 INCOMPLETE, M17 IN PROGRESS, pilot/broad NO_GO,
M18 DEFER, NS-100 NOT STARTED; tag/release NONE.
[Policy model, native measurements and limitations](NS099_NOTIFICATION_POLICY_CLOSURE.md).

| Current policy candidate / result | Value |
|---|---|
| Runtime commit / source | `8242868ba79c63ad743c005366ea715b238cf5d0` — fix: report notification policy and delivery uncertainty; normal main push succeeded |
| Installer | NetSentinel-0.1.0-Setup.exe,0.1.0,37,559,481 bytes |
| SHA256 | `39b14fe844c8aaa150a8b09229e0d63aaaf5ecc98b5bc8c54b419140be7749d9` |
| Signing / AppId / schema | NotSigned / {62E3BFC6-ACAD-4FC3-94D8-46927D015096} / 019→019, no migration |
| Install | Limited token, exit0,35.763s;1119 files/0 hash mismatches;194 compiled modules matched source |
| Windows detection | Documented balloon policy + native session restrictions; exact global/per-app/DND permission remains UNKNOWN |
| Actual OS disabled | PASS: Settings control verified OFF, adapter accepted1 per case, no popup in bounded native observations, UNKNOWN/null visibility |
| Native counters |7 persisted synthetic alerts,13 intents including6 duplicates;6 eligible/attempted/accepted;2 directly seen ON popups,2 OFF cases without popup,2 exploratory ON visibility NOT MEASURED |
| Native click / restart |1 real click/1 exact-target navigation/0 failures; restart replay0;7 persisted after final fresh-PID restart |
| Final live controlled process |5 intents,2 eligible/attempted/accepted,3 duplicates suppressed;1 seen ON popup/0 OFF popups;1 click/navigation; runtime visibility remains null |
| Human / benign FP / tray | Human8 PASS scoped to evaluator; benign42min0 alerts/0 incidents and tray-context Quit PASS retained in original candidate scope |
| Quality | Final targeted123/21.69s (freeze123/23.48s); full3833/8 deselected/1 warning,91.09%,734.10s; Ruff, configured mypy36/direct6 PASS; final checks below/in operator report |
| Cleanup / OS restore |Probe0, owned tasks0, credentials0; original global ON/DND OFF preserved; evidence and installed candidate retained |
| Final docs commit / Git state |Separate evidence commit and normal push; exact final HEAD in operator report and ignored Git receipt |
| Decision |Policy PASS; NS-099 INCOMPLETE/M17 IN PROGRESS; pilot/broad NO_GO; M18 DEFER; NS-100/tag/release NONE |

## Historical layout delivery record

Historical NS-099 layout follow-up (2026-10-07): runtime/source `bfe531d960aaabd6b61c1701cf7179f7214c5097`,
unsigned0.1.0 candidate SHA256 `74529e4cfa03d466ed365a4b0fe5c65c4399873acf150b0c3472496472bdf4c2`, 37,543,802 bytes, schema019→019.
Incidents/DNS/History layout fixed; fresh Windows11 native layout test-build
captures evaluated by the human. Focused layout recheck **PASS**; overall Human UX
**8 PASS / 0 FAIL**. The previous layout finding is closed. Prior functional/native measurements below keep
their original ae08d7e/14934a52 candidate scope. VPN NOT RUN, native sleep NOT RUN,
effective OS-disabled policy BLOCKED; NS-099 INCOMPLETE, M17 IN PROGRESS,
pilot/broad NO_GO, M18 DEFER, NS-100 NOT STARTED. [Layout record](NS099_LAYOUT_CLOSURE.md).

| Historical layout candidate field | Result |
|---|---|
| Source | `bfe531d960aaabd6b61c1701cf7179f7214c5097` |
| File | NetSentinel-0.1.0-Setup.exe, 37,543,802 bytes |
| SHA256 | `74529e4cfa03d466ed365a4b0fe5c65c4399873acf150b0c3472496472bdf4c2` |
| Signature / AppId / schema | NotSigned / {62E3BFC6-ACAD-4FC3-94D8-46927D015096} / 019→019 |
| Install | Limited token, exit0, 29.650s;1119 hashes checked/0 mismatches; not a Users-only account claim |
| Native layout |15 isolated test-build cases; production PYZ byte-identical;1280 selected rows5/6/8;1366 rows6/6/9;96DPI/1.0 ratio |
| Physical1920 viewport | NOT RUN, VM screen1668×878; offscreen1920 PASS |
| Targeted / full |133 passed/36.55s;3794 passed/8 deselected/1 Scapy warning;91.10% coverage/488.91s |
| Ruff / configured / direct mypy | PASS /36 files PASS /4 files PASS |
| Human | Focused layout recheck PASS, overall8 PASS/0 FAIL; original layout finding closed by evaluator |
| Commit | Runtime `bfe531d960aaabd6b61c1701cf7179f7214c5097` — fix: improve beta list and history layouts; normal main push succeeded |
| Final evidence Git state | Document-bearing evidence commit/push/HEAD state in operator report and ignored Git receipt |
| Decisions | NS-099 INCOMPLETE; M17 IN PROGRESS; pilot/broad NO_GO; M18 DEFER; no tag/release/NS-100 |

## Previous 97-field closure report — historical ae08d7e/14934a52 candidate

All native/FP/notification/tray numbers in the following historical table retain
their original candidate scope; they were not repeated for the layout candidate.

2026-10-06. These 97 fields accompany the [acceptance evidence](PUBLIC_BETA_ACCEPTANCE.md)
and [native checklist](PUBLIC_BETA_CHECKLIST.md). **Required pending evidence keeps
NS-099 INCOMPLETE/M17 IN PROGRESS; no release approval is inferred.**

| # | Requested field | Actual result |
|---|---|---|
| 1 | Exact title | NS-099 — Public beta acceptance gate |
| 2 | Task status | INCOMPLETE |
| 3 | M17 status | IN PROGRESS |
| 4 | Final version | 0.1.0 |
| 5 | Candidate source | Committed runtime ae08d7ef1205f5bd4f0b9b0397075c1f6176f2c4; clean HEAD == origin/main rebuild |
| 6 | Filename | NetSentinel-0.1.0-Setup.exe |
| 7 | Size | 37,556,108 bytes |
| 8 | SHA256 | 14934a527e985dc3f32bb94fb3e721ad87d86b3cee1330de12f2b2af36b46538 |
| 9 | Signature | UNSIGNED / NotSigned, no timestamp |
| 10 | AppId | {62E3BFC6-ACAD-4FC3-94D8-46927D015096} |
| 11 | Schema | 019→019, packaged001–019 |
| 12 | VM Windows | New Windows 11 VMware Workstation VM; Home x64,10.0.26200,full 26200.9457; old VM not used |
| 13 | Cleanliness | Existing OS, fresh A/Unicode B per-user profiles with no app state; encrypted VM snapshot unavailable; not pristine |
| 14 | Standard user | Users-only/not Administrators; install/app standard credentials/no observed UAC; Secondary Logon on existing interactive session 1, not independent sign-in |
| 15 | Python | No actual runtime; Store alias only; packaged app works |
| 16 | Npcap | Service/driver absent; no installation/bundling |
| 17 | Install | Historical A0 wizard/B fresh install retained; closure new-candidate standard-user reinstall exit0/14.717s; all1119 payload hashes matched |
| 18 | Driver missing | Core connection/history working; capture/DNS unavailable/degraded honest; no elevation/driver action. A0 observation + unchanged final capability code |
| 19 | First run | A0 first launch/six pages; final B guide appeared and Skip persisted |
| 20 | Onboarding | Human onboarding PASS; capability page dense but understandable. Layout FAIL on Incidents/DNS upper lists and History right-column squeeze/overflow; exact1280×720/DPI not inferred |
| 21 | Browser | Final ordinary visible Edge isolated profile, three loaded safe HTTPS pages/close/reopen; ≥10min, no attack traffic |
| 22 | Updater | Existing Microsoft-signed EdgeUpdate UA check task executed/result 0; ≥9min observation; no claimed download/version change |
| 23 | VPN | NOT RUN, safe VPN absent; mandatory case not waived |
| 24 | Sleep/resume | NOT RUN, native S3/Modern Standby unsupported; S1-only VM, VMware suspend not substituted; historical A0 S1 observation remains limited |
| 25 | App restart | Final A three quits/relaunches; no guide/ghost, config/defaults/integrity preserved; final Unicode B restart PASS |
| 26 | Windows reboot | NOT RUN extra; auto logonOFF/independent sign-in impractical; no recovery/autostart PASS inferred |
| 27 | Tray | PASS new candidate Hide/X/actual shell icon restore/context Quit1357ms/default X1653ms, no ghosts; human tray intent PASS |
| 28 | Notifications default | OFF in fresh profiles; no accidental consent or unsolicited observed popup |
| 29 | Enabled notifications | PASS scoped production-PYZ native fixture: generic preview actually displayed; private synthetic path/domain/IP absent |
| 30 | Notification count | Synthetic intents10/eligible source events7, sink submissions6; OS deliveries verified3, other3 submissions unmeasured; clicks1/correct navigation1, replay0 |
| 31 | Duplicate count | Duplicate intents suppressed3; one immediate upstream source repeat suppressed; no extra intent/submission |
| 32 | Burden conclusion | Observed benign0/hour retained; synthetic forced qualification separate. Effective OS-disabled policy BLOCKED; no whole burden/native acceptance GO |
| 33 | Native benign alerts | 0 in measured observations |
| 34 | Severity counts | INFO0/LOW0/MEDIUM0/HIGH0; no CRITICAL enum |
| 35 | Tester labels | Useful0/noise0/unresolved0 reviewed alerts, no scientific ground truth |
| 36 | FP metric | 0 noise review demands/hour during measured benign interval |
| 37 | FP threshold | Frozen≤5/30min (10/hour),≤2/scenario, unexplained HIGH0, no duplicate inflation/giant IP-only incident |
| 38 | FP conclusion | Observed benign budget met; current new-candidate alerts/incidents/occurrences0; missing VPN/meaningful sleep and layout FAIL prevent complete gate |
| 39 | Incidents | Native0; offline2 explicit synthetic incidents, separate |
| 40 | Incident quality | No giant native merge observed; zero does not exercise explanation/grouping quality; offline story/caps PASS |
| 41 | Baseline | Native A summaries grew to15/persisted; B4; row counts not coverage proof; learning/gap/scope offline PASS |
| 42 | DNS ambiguity | Native capture unavailable honestly; synthetic direct/CNAME/AMBIGUOUS tests PASS |
| 43 | TI-off requests | Source/fake-provider forbidden-network intended requests0; native app socket snapshot0/0, not continuous trace |
| 44 | Feedback export | Final Unicode B 3702 bytes local Save, exact preview hash PASS; final A 3721-byte preview/Save cancelled; A0 exact3718 separate |
| 45 | Export privacy | Actual files/preview support-export-v1/allowlist-v1/schema 19/records 0; bounded raw-value scan0; not anonymous/backup |
| 46 | Storage/retention | Native settings/preview/Cancel; stale Diagnostics fixed, final immediate OFF/ON PASS; no manual purge confirmed, destruction protection offline |
| 47 | Persistence | Final three A restarts/defaults/SQLite OK, B restart/Skip record; populated incident/occurrence story offline |
| 48 | Guide persistence | A completed-v1; B dismissed-v1, no incorrect repeat after relaunch |
| 49 | Notification replay | PASS populated native production-PYZ fixture restart generated0/submitted0; enabled preference preserved; actual click/navigation1/1. Offline3 restarts also no historical replay |
| 50 | Soak | Final measured42m00.93 from16:53:38.507 to17:35:39.433UTC; A0 separate33m19.07; later VM pauses excluded |
| 51 | DB growth | Final measured subinterval17:04→17:35 DB+299008/WAL+428480 bytes, not whole42min growth; final closed A6438912/B552960 preserved |
| 52 | Resources | Final A working set43.36–82.61MB in snapshots, not peak; CPU137.75→498.78 accumulated sec; restarted/B~156–158MB; no leak/CPU utilization claim |
| 53 | GUI response | Native guide/navigation/settings/Diagnostics/storage/export usable; no latency SLA/human ergonomics PASS |
| 54 | Shutdown | Closure installed app tray Quit1357ms/default X1653ms, no ghost; historical shutdown observations retain original scope |
| 55 | Logs/errors | Collected quick_check OK/log 0 bytes; NetSentinel-matching Application1000/1001/1002 count0 at final A review; helper failures separate |
| 56 | Defaults | Final TI empty/capture not started/notificationsOFF/retentionOFF/QUIT; manual update/no upload/response/elevation; test opt-ins restored |
| 57 | Network audit | Native app TCP/UDP snapshot0/0 at 19:15:14UTC; not continuous wire trace; explicit browser/updater traffic separate; default-zero source/fixtures |
| 58 | Artefact scan | New payload1119 hashes/193 compiled modules matched source; all1119 installed payload hashes matched. Relative application code paths; no development/private/driver payload |
| 59 | Privacy docs | BETA_PRIVACY/SECURITY updated, local sensitivity/consent/export/retention/delete/manual updates and limits disclosed |
| 60 | Support docs | BETA_SUPPORT updated with exact Windows scope, no-driver behavior, unsigned/manual/help/privacy/contact limits |
| 61 | Known limits | Polling misses/metadata access, no per-flow bytes/events, DNS/DoH ambiguity, supporting TI/signer/hash context, explicit incidents/source expiry, no forensic or malware certainty |
| 62 | Unsigned pilot | Conditional NS-097 policy, owner audience/license/channel/contact and remaining functional gate; no publisher authentication |
| 63 | App Control | Prior host4551 block retained; no bypass/promise all Windows policy will allow |
| 64 | Tested Windows | One Windows 11 Home x64 build 26200.9457 VM/fresh profiles |
| 65 | Untested Windows | Other10/11 editions/builds,ARM64/non-x64/server; DPI/scaling not measured; no universal support claim |
| 66 | M11 | Prior ACCEPTED, current telemetry/history/restart regressions preserve; bytes/event-source NO_GO spikes retained |
| 67 | M12 | Prior ACCEPTED, context/DNS/ambiguity/TTL/attribution regressions preserve |
| 68 | M13 | Prior ACCEPTED, learning/warm-up/gap/scope/eviction/restart preserve |
| 69 | M14 | Prior ACCEPTED, explainability/reassessment/suppression/occurrence preserve |
| 70 | M15 | Prior ACCEPTED, default-zero/fake-provider/timeout/stale/consent preserve; live TI not prerequisite |
| 71 | M16 | Prior ACCEPTED, NS-092 accelerated/explicit story/export/restart preserve |
| 72 | M17 exit | Closure table: VPN/meaningful sleep NOT RUN, effective OS-policy BLOCKED, human layout FAIL (other7 PASS); M17 not passed |
| 73 | Targeted | Closure targeted200 passed/67.40s; retention-only99 passed. Earlier276 preserved separately |
| 74 | Full pytest | Closure full offline:3785 passed,8 deselected,1 Scapy warning; coverage91.08% (floor85%);505.82s |
| 75 | Ruff | PASS src/tests/packaging |
| 76 | Configured mypy | PASS, 36 files |
| 77 | Direct mypy | PASS direct mypy12 runtime/build/verifier/GUI/audit/native-fixture files; configured36 also PASS |
| 78 | Diff | PASS final git diff --check, line-ending notices only |
| 79 | Privacy/secrets | PASS closure bounded secret/local-identity scan23 files/0 findings; frozen runtime/hash/size/schema19 consistency true; not exhaustive privacy detection |
| 80 | Rebuild | Clean committed ae08d7e runtime rebuilt via approved PyInstaller/Inno; source193/payload1119 and all1119 installed hashes matched |
| 81 | Provenance | Committed full runtime identity, clean build working tree; old339da4 base+patch historical only |
| 82 | Docs | README; ARCHITECTURE/PRODUCT/SECURITY/ROADMAP/TASKS/RELEASING/RELEASE_NOTES; new BETA_PROTOCOL/BETA_SUPPORT/BETA_PRIVACY/PUBLIC_BETA_ACCEPTANCE/CANDIDATE/CHECKLIST/REPORT/RELEASE_CHECKLIST |
| 83 | Release blockers | Mandatory VPN/meaningful sleep, effective OS-policy BLOCKED, layout FAIL; NS-097 broad signing/distribution and owner prerequisites |
| 84 | Other findings | Retention production fix committed; native wrapper cleanup bug corrected separately; denied privilege escalation not applied; successful shell helper Limited |
| 85 | Limited pilot | NO_GO for now |
| 86 | Broad release | NO_GO |
| 87 | Reasons | Exact functional acceptance incomplete; unsigned/public signer/release gates unresolved; no threshold waiver |
| 88 | M18 | DEFER, later explicit response GO independently required |
| 89 | TASKS | Only NS-099 IN PROGRESS/INCOMPLETE updated, acceptance criteria preserved |
| 90 | Milestone | M17 IN PROGRESS; M1–M16 historical gates preserved |
| 91 | Commit/message | Runtime fix ae08d7ef1205f5bd4f0b9b0397075c1f6176f2c4 — fix: refresh retention diagnostics state; separate document-bearing evidence commit: test: record public beta acceptance closure evidence (INCOMPLETE) |
| 92 | Push | Runtime normal main push succeeded; document-bearing evidence commit normal main push and remote identity checked in final operator report; no force |
| 93 | HEAD/origin | Clean runtime freeze HEAD == origin/main == ae08d7ef1205f5bd4f0b9b0397075c1f6176f2c4; final evidence HEAD/remote identity in operator report and ignored final Git receipt |
| 94 | Working tree | Runtime rebuild clean; acceptance-only evidence commit; final working tree checked in operator report/ignored Git receipt |
| 95 | Tag/release | NONE |
| 96 | NS-100 | NOT STARTED; no M18 work |
| 97 | Remaining blockers | VPN NOT RUN; meaningful native sleep NOT RUN; effective OS-disabled policy BLOCKED; human7 PASS/1 layout FAIL. Tray context Quit closed PASS |

Closure cleanup verified2026-10-06T21:11:48Z: all four temporary scheduled tasks
removed, closure DPAPI credential absent, app/fixture processes0. Prior isolated browser
debug listener cleanup remains recorded in its historical scope. A/B KEEP data/accounts/exports
preserved. Full raw evidence stays in ignored build output, referenced in the
acceptance document; no binaries/native browsing telemetry/screens committed.

## Closure measurement supplement

Runtime fix/source commit ae08d7e; installer14934a52…36b46538/37,556,108 bytes.
Total synthetic test intents10, eligible source events7, sink submissions6,
OS-visible deliveries verified3 (other3 submissions not individually observed),
duplicate intents suppressed3, upstream immediate source repeat suppressed1,
actual click/navigation1/1, restart replay0. The desktop-user registry flag0
experiment still displayed a popup; effective OS-disabled gate remains BLOCKED.
New candidate live benign alerts0/incidents0/occurrences0, schema19/quick_checkOK.
Forced fixture alerts are separate from observed benign FP/notification burden.
Human UX: **FAIL**, seven other criteria PASS; Incidents/DNS upper lists too small, History right columns cramped/overflowing. Human feedback recorded, no layout waiver.

## Focused layout follow-up (2026-10-07)

New runtime/source `bfe531d960aaabd6b61c1701cf7179f7214c5097`, installer SHA256 `74529e4cfa03d466ed365a4b0fe5c65c4399873acf150b0c3472496472bdf4c2`, 37,543,802 bytes,
unsigned/NotSigned, schema019→019. Prior native measurements above retain their
original source/candidate scope. [Layout closure](NS099_LAYOUT_CLOSURE.md).
Human layout recheck PASS, previous finding closed; overall8 PASS/0 FAIL. VPN
NOT RUN, native sleep NOT RUN, OS-policy BLOCKED unchanged. NS-099 INCOMPLETE,
M17 IN PROGRESS, pilot/broad NO_GO, M18 DEFER, NS-100 NOT STARTED.

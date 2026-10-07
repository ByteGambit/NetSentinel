# NS-099 — Public beta acceptance gate

Follow-up host S3 (2026-10-07): Windows sleep/wake fields verify **142.461447s**
after all power-request classes cleared. **NetSentinel sleep/resume NOT RUN**:
the measured candidate had already been quit, with no new application baseline
or active recorder. Stopped DB unchanged; no recovery or burden PASS inferred.
VPN BLOCKED/NOT RUN, NS-099 INCOMPLETE/M17 IN PROGRESS and release decisions unchanged.
[Host S3/application scope](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md#follow-up-verified-host-s3-without-an-application-test).

Third host sleep attempt (2026-10-07): **NOT RUN**. The operator temporarily
disabled Hotspot; elevated query confirmed AWAYMODE none, but USB Audio Device
SYSTEM remained for an active stream. The explicit pre-sleep stop condition was
honored. No sleep action issued; awake-only alerts/incidents delta0/0,
notifications disabled/attempts0; ordinary Quit upper bound2.604s. Hotspot restored
On natively, icssvc Running/Manual. No override/permanent policy/runtime change.
[Third-attempt evidence](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md#third-attempt--hotspot-cleared-usb-audio-system-request-remained).

Second host sleep diagnostic (2026-10-07): **sleep NOT RUN**. Elevated read-only
`powercfg /requests` identified Mobile Hotspot (`icssvc`) SYSTEM/AWAYMODE,
Legacy Kernel Caller SYSTEM and WebView2 audio EXECUTION. Host is AC online with
Away Mode allowed. This provides a current explanation for apparent sleep
without suspend; no historical causation or S3 recovery PASS inferred. No
service/policy/override change or new manual sleep action. VPN BLOCKED/NOT RUN,
NS-099 INCOMPLETE/M17 IN PROGRESS and release decisions unchanged.
[Second diagnostic evidence](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md#second-attempt--blocker-diagnosis-no-sleep-action-requested).

Physical-host sleep attempt (2026-10-07): **native sleep/resume NOT RUN**.
Host supports S3, but after the reported wake no new power event or sleep clock
gap was measured (157.718656s wall / 157.7186565s awake). App/DB remained healthy,
alerts/incidents0 and notifications OFF; ordinary Quit was clean. This is not
native recovery evidence. VPN BLOCKED/NOT RUN, NS-099 INCOMPLETE/M17 IN PROGRESS,
pilot/broad NO_GO and M18 DEFER remain unchanged. No rebuild/source change.
[Host measurements and limits](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md).

VPN environment attempt (2026-10-07): **VPN NOT RUN; provisioning BLOCKED**.
The hash-verified portable host server was prevented from starting by Windows
Application Control. No tunnel/workload measurements; counts NOT MEASURED.
No production change or security bypass; native sleep untouched. NS-099
INCOMPLETE, M17 IN PROGRESS, pilot/broad NO_GO, M18 DEFER, NS-100 NOT STARTED.
[Exact attempt, stop reason and cleanup](NS099_VPN_ENVIRONMENT_ATTEMPT.md).

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

## Current M17 exit table

| Gate / decision | Current result |
|---|---|
| Notification policy | PASS, actual OS OFF; honest UNKNOWN and no observed popup; original ON restored |
| Native notification/privacy/click/duplicates/restart | PASS in current policy fixture scope; visibility counters remain unconfirmed |
| Tray / benign browser/updater / install scenarios | Original candidate-scoped PASS, not unnecessarily repeated |
| Human UX | PASS8/8; original layout finding CLOSED; no new human rating invented |
| Safe VPN | NOT RUN; private host-server provisioning BLOCKED by Windows Application Control; workload counts NOT MEASURED |
| Meaningful native sleep/resume | Application NOT RUN; later host S3 verified for142.46s with requests clear, but measured candidate already quit and no recovery baseline |
| FP / notification burden | Historical benign42min alerts0/incidents0; current synthetic policy measurements scoped separately; required missing cases prevent full M17 exit |
| NS-099 / M17 | INCOMPLETE / IN PROGRESS; exact TASKS criteria preserved |
| Limited pilot / broad release | NO_GO / NO_GO; broad signing/distribution policy still applies |
| M18 / NS-100 / tag-release | DEFER / NOT STARTED / NONE |


## Historical layout follow-up (2026-10-07)

The focused [layout closure](NS099_LAYOUT_CLOSURE.md) changes Incidents/DNS/History
presentation only. The ae08d7e/14934a52 installer and all closure observations
below are historical after that runtime change. Its replacement is source `bfe531d960aaabd6b61c1701cf7179f7214c5097`,
SHA256 `74529e4cfa03d466ed365a4b0fe5c65c4399873acf150b0c3472496472bdf4c2`, 37,543,802 bytes; see the clean rebuild/native layout record. Human
layout recheck is PASS; the original finding is closed and the other seven PASS
observations are preserved. Overall Human UX: **8 PASS / 0 FAIL**.
VPN/sleep NOT RUN and OS-policy BLOCKED remain unchanged; NS-099 INCOMPLETE,
M17 IN PROGRESS, pilot/broad NO_GO, M18 DEFER. NS-100 NOT STARTED.

### Historical layout-time M17 exit update — human layout finding closed

The evaluator accepted the new Incidents/DNS list space and History readability
with horizontal scrolling. [Exact response and current result](NS099_LAYOUT_CLOSURE.md#human-layout-recheck-pass).
The prior seven human PASS observations are preserved; only the layout finding
changes. Historical FAIL tables below describe the superseded candidate.

| Gate / decision | Current result |
|---|---|
| Human UX | PASS, 8 PASS / 0 FAIL |
| Safe VPN | NOT RUN |
| Meaningful native sleep/resume | NOT RUN |
| Effective OS-disabled notification policy | BLOCKED |
| NS-099 / M17 | INCOMPLETE / IN PROGRESS |
| Limited pilot / broad release | NO_GO / NO_GO |
| M18 / NS-100 | DEFER / NOT STARTED |

2026-10-07 closure (native work2026-10-06 UTC). **INCOMPLETE; M17 IN PROGRESS. Limited unsigned pilot NO_GO;
broad public release NO_GO; M18 DEFER; NS-100 NOT STARTED.** Safe native VPN,
meaningful native sleep and effective OS-disabled policy remain open. Human UX is PASS.
TASKS requires all criteria; recording this decision does not complete the task.
Runtime fix committed/pushed; no tag/release/publication. [97-field report](PUBLIC_BETA_REPORT.md),
[scenario checklist](PUBLIC_BETA_CHECKLIST.md), [frozen protocol](BETA_PROTOCOL.md).

## Previous closure pass — historical candidate

Runtime fix **`ae08d7ef1205f5bd4f0b9b0397075c1f6176f2c4`** (`fix: refresh retention diagnostics state`) committed
and pushed normally to main. Review was limited to three presentation files plus
the composed GUI regression. Targeted99 passed; targeted Ruff and direct mypy
passed. Before/after rebuild HEAD = origin/main and working tree clean; pending
acceptance documents/tests were preserved temporarily and restored afterward.

| Current identity | Value |
|---|---|
| Source commit / version | `ae08d7ef1205f5bd4f0b9b0397075c1f6176f2c4` / 0.1.0 |
| Installer / bytes | NetSentinel-0.1.0-Setup.exe / **37,556,108** |
| SHA256 | `14934a527e985dc3f32bb94fb3e721ad87d86b3cee1330de12f2b2af36b46538` |
| Signing / AppId | UNSIGNED, NotSigned / {62E3BFC6-ACAD-4FC3-94D8-46927D015096} |
| Schema / compiler | **019→019**, no migration / Inno Setup6.7.3,35.875s |
| Installed EXE | `daee77e62c48fd639dc903e5918f325762265f3c0449c416cdd14b494afaa62b` |
| Payload |1119 files,193 compiled source-matching application modules |
| New VM install | Installer hash matched; standard-user install exit0,14.717s |
| Installed inventory |**All1119 payload hashes matched**, mismatches0 |

The previous `339da4135a630f085ba640200e464017ab1d724419842caf63a6ffb97f9cdbed` installer is **historical evidence only**. Pre-closure
observations below keep their original hashes and scope; they are not newly
performed tests of this installer. Previously passed unchanged scenarios were
not repeated. All closure native work used the new installer/its exact payload.

| Unresolved gate | Closure result | Evidence and limit |
|---|---|---|
| A VPN | **NOT RUN** | No safe VPN environment; user/per-machine profiles0. Required TASKS case not waived. |
| B native sleep/resume gap | **NOT RUN** | Fresh powercfg /a: S1 only; S3 and S0 Low Power Idle unsupported by firmware. No VMware-suspend PASS and no S1 equivalence claim. |
| C native toast/privacy | **PASS, scoped native fixture** | Real Windows popup captured; fixed severity-only preview, no synthetic path/domain/IP. Exact production PYZ used in isolated native fixture. |
| C toast click | **PASS, scoped native fixture** | Actual popup body clicked; selected UUID equaled expected alert; clicks1/navigation_success1/failure0. No fake messageClicked emission. |
| C duplicates/source cooldown | **PASS, scoped native fixture** | Three repeated persisted intents skipped. Two source writes1s apart produced only one new eligible intent/submission; no count/intent inflation. |
| C restart replay | **PASS, scoped native fixture** | Enabled preference preserved; populated fixture restart generated0/submitted0, no historical replay. |
| C effective OS-disabled/policy | **BLOCKED** | Desktop-user ToastEnabled0 experiment still showed a popup from the secondary-logon fixture. Effective OS-disabled state was not established; registry flag alone is not PASS. Original value absence restored in finally. |
| D tray context Quit | **PASS** | Hide + X retained PID; real overflow-icon click restored same PID; real right-click/Quit exited in1357ms, app processes0. Default QUIT restored and X exited1653ms, no ghost. |
| E human UX | **FAIL:7 PASS/1 FAIL** | Evaluator accepted comprehension/tray/toast/privacy/support; Incidents/DNS lists too small and History right columns cramped/overflowing. |

Reproducible fixture: [native notification probe](../tests/fixtures/beta_native_notifications.py).
It accepts only an isolated NS099Toast directory; production modules come from the
frozen payload. The initially executed wrapper and later guarded/typed probe
share the same production components.

Native notification fixture composes the existing production application,
AlertService/SQLiteAlertRepository, notification controller, real Qt sink and
real tray; only the engine supplies inert health. It uses an isolated synthetic
database/config, no network generation, production DB insertion, injected
runtime code or new production hook. The fixture PYZ and installer PYZ hashes
are identical: `cd442529d090f55005290c30ae7ea11507039d828144511dec9cbe02b71bde05`.
The wrapper executable has a distinct NS099NativeToast.exe display name; this
does not claim installed-executable publisher/OS-registration acceptance.

Notification counts are separated from benign FP: phase1 intents8 (five eligible
source events plus three explicit duplicate intents), disabled1, duplicate skips3,
sink submissions4; phase2 restart intents0/submissions0, then two eligible source
events/submissions2 and one upstream repeat suppressed. **Total test intents10,
eligible source events7, sink submissions6, OS-visible deliveries verified3,
unmeasured submissions3, actual clicks1/correct navigations1, restart replay0**.
One of the three visible popups occurred during the ineffective desktop-user
disable attempt. Submitted is not delivered. Forced synthetic qualification is
not normal benign popup burden; the pre-closure42min benign result remains0.
No complete notification-burden/policy GO is inferred.

The initial wrapper's cleanup-only Quit needed controlled same-user fixture
termination; the wrapper was corrected to request_quit and its later clean exit
was confirmed. This is separate from the installed app's bounded clean shutdown.
An attempted helper privilege increase was rejected by automatic approval review
as outside standard-user scope. It was not applied; file access was corrected
within owned test files and the successful shell helper remained **Limited**.

New candidate's live aggregate at20:56:03UTC: schema19/quick_check OK, history392,
assessments/revisions97, baselines9, **benign alerts0/occurrences0/incidents0**, log0.
Counts include preserved prior-profile data; they are retained counts, not total
produced-cycle counts. Source-harness synthetic alerts are in a separate DB.
Observed benign FP is acceptable for tested activity; missing VPN/sleep, layout FAIL and
effective OS-policy evidence prevent whole-gate acceptance.

| M17 closure exit | Status |
|---|---|
| Committed runtime/candidate/native installed identity | PASS |
| Previously passed install/browser/updater/driver-missing/privacy/storage/restart | PASS in recorded original scope; historical phases kept separate |
| Native tray lifecycle/default QUIT | PASS |
| Native toast/privacy/correct target/duplicates/restart fixture | PASS in component/fixture scope |
| Effective OS-disabled policy / complete notification burden | BLOCKED |
| Mandatory VPN | NOT RUN |
| Mandatory meaningful Windows sleep/resume | NOT RUN |
| Independent human UX | **FAIL**, layout criterion; other7 PASS |
| Overall NS-099 / M17 | **INCOMPLETE / IN PROGRESS** |
| Limited unsigned pilot / broad release / M18 | **NO_GO / NO_GO / DEFER** |

Broad release also remains subject to NS-097 signing/distribution policy.
No tag, release, publication or NS-100/M18 implementation. Closure quality and
acceptance evidence commit/push details are recorded in the final report.

Ignored closure evidence: ns099-closure-provenance.json, installer-build.log,
payload-audit.json, installed-inventory.json, tray-context.png, toast-on.png,
actual-toast-click.png and human-guide pages; native aggregate/control JSONs.
The pre-closure records that follow are historical and retain their identities.

## Closure quality and cleanup

Targeted closure200 passed in67.40s. Full offline3785 passed/8 deselected,
one Scapy warning, coverage91.08% (required85%) in505.82s. Ruff PASS;
configured mypy36 files PASS; direct mypy12 files PASS. Installer verification
INTEGRITY_OK, signature NOT_CHECKED there; independent Authenticode NotSigned.
Payload audit1119 files/193 source-matching modules and installed1119 hashes PASS.
Final diff and bounded privacy/secret/local-identity scan PASS; runtime remains
identical to the committed candidate source; no migration (019→019).

Closure cleanup at2026-10-06T21:11:48Z: four temporary scheduled tasks removed,
DPAPI credential file absent, application/fixture processes0; accounts/data/exports
preserved. Human guide was already closed when cleanup began. Native raw files
remain ignored. This document-bearing acceptance-only commit records valid
INCOMPLETE evidence separately from the runtime fix; its hash, normal push,
HEAD/remote equality and clean-tree verification are in the final operator report
and ignored build/ns099-closure-git-final.json. No tag/release/NS-100.

## Previous native human UX result — historical layout finding

Human evaluator response received2026-10-07 Europe/Istanbul, from the prepared
new Windows11 walkthrough/screens. **Seven PASS, one FAIL; overall UX gate FAIL.**
This is a human observation; automation does not replace the evaluator.

| Criterion | Human result | Evaluator observation |
|---|---|---|
| Onboarding | PASS | General flow understandable; last capability page dense but usable. |
| Optional-disabled versus failure | PASS | Disabled/unavailable/degraded generally distinguishable. |
| Risk/alert language | PASS | Does not read as a definitive malware verdict. |
| Tray Hide/Show/Quit intent | PASS | Intended behavior understandable. |
| Native toast wording/privacy | PASS | Wording and privacy boundary acceptable. |
| Support/feedback | PASS | Flow understandable. |
| Essential controls/layout | **FAIL** | Incidents and DNS upper list areas too small; History right columns cramped/overflowing. Layout polish required. |
| Other pilot-blocking confusion | PASS | No other obvious confusion beyond the reported layout issues. |

The layout finding remains open under NS-099; it was not fixed or quietly waived
in this closure pass. The frozen runtime/candidate remains unchanged. No universal
viewport/DPI acceptance is inferred. VPN/sleep NOT RUN, effective OS-disabled
policy BLOCKED and this layout FAIL preserve INCOMPLETE/NO_GO/M18 DEFER.

## Historical pre-closure candidate and provenance

Started clean main, HEAD = origin/main =
`1d053721733139ab66e0078737fbd19c38e4c679`. Final runtime is that base **plus an
uncommitted three-file presentation patch**, not a clean-HEAD build. Native
retention Save persisted the setting but Diagnostics showed the previous value.
The fix signals successfully saved worker settings to Diagnostics on the Qt
thread. No domain/infrastructure, network, dependency, packaging or migration
change. Two composed GUI cases failed on the original runtime and passed on the
fix; final native OFF/ON display checks passed immediately without restart.

| Field | Frozen final value |
|---|---|
| Version / PE FileVersion / ProductVersion | 0.1.0 / 0.1.0 / 0.1.0 |
| Runtime base commit | `1d053721733139ab66e0078737fbd19c38e4c679` |
| Runtime patch SHA256 | `bd3bf030bbb02196e86a08ad4cad730ea1837a454cd5c1d27a1216527bd44d19` |
| Installer | `dist/NetSentinel-0.1.0-Setup.exe`, ignored |
| Bytes / SHA256 | 37,545,567 / `339da4135a630f085ba640200e464017ab1d724419842caf63a6ffb97f9cdbed` |
| Build completion/file timestamp | 2026-10-06 16:44:48.7324919 UTC / 19:44:48.7324919 Europe/Istanbul |
| AppId | `{62E3BFC6-ACAD-4FC3-94D8-46927D015096}` |
| Schema / compiler | 019→019; migrations 001–019 / Inno Setup 6.7.3, 26.953s compiler phase |
| Signing / timestamp | UNSIGNED, observed NotSigned / no signing timestamp |
| Channel / updates | Unpublished limited unsigned pilot candidate / manual |
| Installed EXE SHA256 | `c4f282a3ae9d8797e9aa62f58212954caf53cb1d4d91ba0571bdde4e336b5c94` |

[Machine-readable identity](PUBLIC_BETA_CANDIDATE.json) includes the three source
hashes. Local patch: `build/ns099-runtime-fix.patch`; Git diff remains reviewable.
This is not a published NS-097 release manifest; no release URL/timestamp invented.

Initial resumed clean-HEAD candidate (**A0**) was 37,546,894 bytes, SHA256
`42b996d4eb7ad29cd4f667ff0aaa2eeb8275744a7fd80c46e1dba938c473edf9`, built at
15:27:01.9468252 UTC (28.578s compiler). It is superseded. A0 observations below
are not attributed to the final hash. Historical NS-096/pre-pause hashes remain
separate; 0.1.1 installer fixture is not a candidate.

Rebuild used approved bundled CPython 3.12.14, locked existing project packages
and `packaging/build_installer.py --use-project-packages --iscc <approved ISCC.exe>`.
No Windows security changes. Final payload audit: **1,119 exact inventory/hash
files, 193 embedded application modules matching current source**, relative
application code filenames, NS-098 modules and 001–019 present; no developer
DB/config/log/export/key/certificate/test/git/driver/reparse content. This audits
builder input/emitted onedir payload, not reverse extraction of compressed Inno.
Final verifier: **INTEGRITY_OK / signature NOT_CHECKED**; separately NotSigned.
Hash matching does not authenticate the publisher.

Final portable smoke PASS: archive SHA256
`eaf2913d5758773836308d61940ee1bcf1ac6a5deb932a05399583f5ee4da7f9`; foreign cwd,
synthetic Unicode directory, isolated data, Qt/icon/SQLite, 19 migrations,
018→019 upgrade, first guide shown/saved, second absent, GUI exits 0, unchanged
install tree. Build-host fixture, separate from installed client acceptance.
Prior host Application Control 4551 remains a distribution limitation.

## Historical pre-closure native environment and results

Only new **Windows 11** VMware Workstation VM; old Windows 11 x64 (2) not used.
Windows 11 Home x64 10.0.26200, full **26200.9457**; Tools running, guest auth and
commands/copy verified. No real Python (Store alias only), no Npcap service/driver.
One up adapter; safe VPN undefined. Actual display **1078×800**; DPI/scaling and
exact 1280×720 unmeasured. A and Unicode B fresh local profiles had no prior
NetSentinel state; Users-only, not Administrators, app/install standard credentials,
no observed UAC. Secondary Logon used existing session 1; not independent
standard-user sign-in/pristine OS. Encrypted-VM snapshot creation unavailable;
no security/encryption changes. Raw usernames/paths/screens/telemetry stay ignored.

MCP performed native operations. Same-user UI Automation/PrintWindow worked;
direct capture was black, keystrokes unavailable. Working-directory/focus/stale
handles, UTF-8 script reading and UTF-8 SQLite interop corrections were confined
to ignored harness code. Temporary approval-review usage-limit failures prevented
three calls; normal MCP calls subsequently worked after user continuation.
No bypass. Old feedback Save failure originated from the harness System32 cwd;
final owned-cwd Unicode export succeeded.

| Scenario | Native evidence and limits |
|---|---|
| A0 clean install / guide | Standard-user wizard/launch without Python/Npcap; distinct roots; six pages Next/Back/Finish and guide v1; no accidental consent. Structure PASS, human understanding PENDING. |
| Missing driver | A0 core connection/history Running; capture unavailable, Devices/DNS/Alerts honestly degraded; no driver install/auto capture/elevation. Unchanged capability code audited in final payload. |
| Final A repair | MCP copy/hash match; exit 0; exact DB/config/external-export preservation; installed EXE matches payload. PASS. |
| Final benign browser | Visible standard-user Edge, isolated profile, three ordinary HTTPS pages loaded, two closures acknowledged, four after reopening; ≥10 min. PASS for observed activity, no attack traffic. |
| Final updater | Existing Microsoft-signed EdgeUpdate UA task guarded /ua /installsource scheduler; result 0 and ≥9 min observation. PASS for check task, no claimed download/version change. |
| VPN | **PENDING / NOT RUN**, no safe environment; synthetic scope/gap evidence is separate, no waiver. |
| Sleep/wake | A0 Windows SetSuspendState S1 returned 0, Kernel-Power 42/107 and Power-Troubleshooter 1; timer did not wake VM, MCP start resumed same app/polling. Recovery observed; full gap/timing acceptance PENDING; no final S1 retest. |
| Final A restarts / X Quit | Three quits/relaunches: 2,036 / 739 / 837ms, no ghosts; guide absent, v1/defaults preserved, SQLite OK, alerts/incidents 0. Final shutdown 1,201ms. PASS for persistence; populated native replay not exercised. |
| Tray | Final Hide + X kept process alive; real shell overflow NetSentinel icon restored same window. Hide/Show PASS; context-menu Quit NOT RUN, human discoverability PENDING. |
| Notifications | Fresh A0/B OFF observed. A explicitly ON, zero qualifying alerts/intents/submissions/failures/drops in observed Diagnostics, zero observed benign popups. Actual OS delivery, privacy preview, correct-ID click/dedup/cooldown/escalation/replay **PENDING / NOT RUN**. |
| Storage/retention | Load/save/preview/Cancel native; confirmed stale Diagnostics fixed and final OFF/ON immediate PASS. No manual purge confirmed; protection/destruction cases offline. |
| Feedback/export | A0 exact 3,718-byte local Save. Final A preview 3,721 bytes, Save attempt not completed/cancelled. Final B **3,702-byte exact preview Save**, support-export-v1/allowlist-v1/schema 19/records 0/private-pattern matches0. Final native export PASS, no upload. |
| Final Unicode B | Fresh standard install exit 0; guide/Skip dismissed-v1 with OFF consent; launch/export/restart (guide absent), quick_check OK. PASS. |
| Final KEEP A/B | Both exit 0; closed DB/config/log and external export exact; program roots/HKCU uninstall entries absent, zero app processes. PASS. Compatible fixture upgrade/DELETE historical NS-096 and current source regressions, not repeated native. |
| Extras / optional | Reboot/sign-out/reconnect NOT RUN (independent sign-in impractical, auto logon OFF); Npcap-present/live TI optional NOT RUN. No assumed autostart/reboot PASS. |

Temporary localhost-only CDP browser profile used no headless/security-disabling
flags. Pages/updater traffic is separate from app uploads. Browser closed,
listener 0; all NS099 scheduled tasks/guest-only DPAPI credential files removed;
app 0. KEEP data/test accounts/external exports remain intentionally preserved.

## Historical pre-closure native metrics and limits

Frozen protocol unchanged: unexplained HIGH0 (no CRITICAL enum), ≤5 noise review
demands/30min (10/hour), ≤2/scenario, no identical occurrence inflation or giant
IP-only merge; notifications OFF0, ON benign ≤3 popups/30min (6/hour), duplicates/
history replay0, 120s monotonic cooldown with genuine escalation/reopen exceptions.
Incomplete required cases still block acceptance.

| Metric | Observed result |
|---|---|
| A0 monitored interval | 15:59:36.897–16:32:55.969 UTC, 33m19.07 before S1; old hash |
| Final A bounded interval | Process start 16:53:38.507–17:35:39.433 UTC, **42m00.93**; later VM pauses/elapsed time excluded |
| Browser/updater windows | Loaded pages 17:10:38, four pages 17:13:05 and 17:35:39; updater 17:04:06.856–17:13:05.627 |
| Final A assessments/revisions | Retained **512/512 at cap**; lifetime produced total unavailable, at least512 |
| Final A history/DNS/baselines | 1,472/0/15 at bounded interval end; separate B later116/0/4 |
| Alerts/occurrences/incidents; severities | 0/0/0; INFO/LOW/MEDIUM/HIGH all0 |
| Useful/noise/unresolved; FP burden | 0/0/0 reviewed alerts; **0 demands/hour**, below frozen budget in observed benign interval, not scientific ground truth |
| Incident quality | No giant merge observed; zero incidents cannot prove explanation/grouping quality |
| Notifications | Observed benign popups0, no duplicate/noisy dismissal observed; genuine enabled fixture NOT RUN; 0/hour, unique actionable denominator 0→N/A |
| A0 DB/WAL growth | 344,064→2,052,096 (+1,708,032); 1,788,112→4,173,592 (+2,385,480) bytes |
| Final A measured DB/WAL subinterval | 17:04:06→17:35:39: DB5,808,128→6,107,136 (+299,008); WAL4,297,192→4,725,672 (+428,480), not exact whole42min growth |
| Closed DB after KEEP | A6,438,912; B552,960 bytes, exact preservation |
| Working set / CPU | Final A82,612,224 at 17:04,43,360,256 at 17:13,71,716,864 at 17:35 bytes; accumulated CPU137.75→498.78125s. Restart/B snapshots ~156–158MB; no peak/leak/utilization claim |
| Poll cycles | Unmeasured; configured 1s interval is not a counted cycle total |
| Integrity/log/OS errors | All collected quick_check OK; app log 0 bytes; Application1000/1001/1002 matching NetSentinel.exe0 at final A review |
| GUI/startup/shutdown | Settings/navigation/preview usable, no latency SLA; relaunch window after ~6s harness wait not exact cold start; bounded exits above, no ghosts/corruption |

Native baseline rows grew/persisted, not proof of complete learning coverage.
Gap/scope/quality and DNS ambiguity are separate offline regressions; native DNS
capture unavailable. Final preferences: TI empty, capture not started,
notifications/retention OFF, QUIT/manual updates/no upload/response/elevation.
App-owned TCP/UDP socket snapshot **0/0 at 19:15:14 UTC**, not continuous tracing.
Source/forbidden-network fixtures prove intended default-zero requests, not universal
native zero egress.

## Pre-closure offline quality and M17 exit

New real-repository/fake-sink replay: 3,600 injected seconds/rounds, two submissions
(one synthetic escalation),100 identical delivery skips,1 cooldown skip,1 disabled
skip, failures/drops/history submissions0 across3 restarts; queue≤32/state≤512.
These are submitted requests, not native popups. Combined baseline/risk/incident/
export story:600 synthetic seconds,601 rounds,1 LOW assessment/alert,2 explicitly
created incidents,3 config/facade restarts, stable explanations/occurrences, allowlist
export, defaultsOFF/QUIT, SQLite OK, DB364,544→364,544 bytes, external calls0 under
forbidden-network fixtures. NS-092 accelerated caps/expiry/query regression is
separate from native soak.

| Check | Final local result |
|---|---|
| Targeted UTF-8 NS-092–098/runtime/release | 276 passed,1 Scapy warning,262.14s |
| New retention GUI tests | Original runtime2 failed; fixed2 passed,2.23s |
| Full post-fix suite / coverage | **3,785 passed,8 deselected,1 Scapy warning,729.43s;91.10%**, gate85% |
| Ruff / configured mypy | PASS src/tests/packaging / PASS, 36 files |
| Direct mypy | PASS seven runtime/build/verifier + audit fixture; PASS three changed GUI modules |
| Dependency audit | PASS28packages, no known vulnerabilities/adverse status (29resolved) |
| Payload / portable / integrity | PASS1,119files/193modules / PASS / INTEGRITY_OK, separately NotSigned |
| Diff / bounded privacy scan | PASS git diff --check; PASS 19 source/doc files, zero bounded private-value/key matches; not exhaustive detection |
| Remote CI / live markers | Not run;8 deselected live cases are not PASS |

Initial mocked installer stdout failures274+2 were UTF-8 environment issues.
Pre-fix full3,783/91.07% is superseded. Harness/cache/OSV/compiler access corrections
did not change frozen thresholds or Windows security. No runtime edit after final build.

| Gate | Exit evidence |
|---|---|
| M11–M12 | Prior ACCEPTED; current telemetry/history/context/DNS/ambiguity/TTL/restart regressions; bytes/event-source NO_GO spikes preserved |
| M13–M14 | Prior ACCEPTED; learning/warm-up/gap/scope/eviction/explainability/reassessment/suppression/occurrence; native aggregate persistence/benign observation |
| M15–M16 | Prior ACCEPTED; default-zero/fake-provider/timeout/consent; NS-092 and combined explicit incident/restart/export |
| M17 install/standard/driver-missing | A0 and final B native PASS; no pristine/all-builds claim |
| M17 repair/upgrade/uninstall | Final repair/KEEP A/B PASS; upgrade/DELETE historical NS-096 + current source tests |
| M17 benign/recovery | Browser/updater/restarts/observed benign budget pass; VPN/full native sleep gap pending |
| M17 notifications/human UX | Actual delivery/click/policy and independent evaluation pending |
| M17 storage/privacy/export | Retention display fix/current Unicode exact Save/KEEP PASS; destructive protection offline |
| M17 signing/support | Unsigned pilot policy retained; public signer/protected release and owner contact/audience/license conditions unresolved |
| M17 overall | **NOT PASSED / IN PROGRESS** |

| Finding | Severity / owner follow-up |
|---|---|
| Stale Diagnostics retention state | Confirmed privacy/readiness defect **fixed**; composed regression + final OFF/ON PASS |
| Safe VPN absent | Required evidence blocker; owner supplies safe authorized environment; no native PASS |
| Enabled notification route | Required evidence blocker; accepted benign fixture without direct DB insertion/new production test hook, then actual OS measurement |
| Human onboarding/tray/toast UX | Human evaluator comprehension/discoverability; automation only structural |
| Full sleep/gap and tray-context Quit | Remaining native evidence; A0 S1 recovery limited, final normal QUIT verified |
| Unsigned/App Control/public signer | Broad distribution blocker; approved pilot audience/channel only, no bypass/purchase |
| Dedicated feedback/private-security contact | Owner prerequisite before recruiting; disclosed, no invented endpoint |
| Polling/DNS/attribution/bytes/TI/incident limits | Disclosed scope limits, no malware certainty/automatic response |

Limited pilot **NO_GO for now**, broad **NO_GO**, M18 **DEFER**. Exact criteria
unmet in this historical phase; the closure section above supersedes its commit/candidate/remaining-gate status. No release/tag/upload/NS-100.

## Local evidence

Ignored `build/`: ns099-runtime-fix.patch, ns099-final-identity.json,
ns099-final-payload-audit.json, ns099-final-portable-smoke.log,
ns099-post-fix-full.log, ns099-targeted-utf8.log, ns099-dependency-audit.log,
ns099-repair-current.json, ns099-final-updater-metrics-{before,after}.json,
ns099-final-soak-end.json, ns099-sleep-result.json, ns099-restart-results-flat.json,
ns099-final-native-review.json, ns099-uninstall-current.json,
ns099-unicode-{install,export-check,metrics,restart,uninstall}.json,
ns099-support-scan.json, ns099-final-cleanup.json, ns099-final-consistency.json, ns099-final-privacy-scan.json. Screens/UI dumps/raw helper paths
stay ignored; no generated installer/raw telemetry committed.
Reusable audit: `python -m tests.fixtures.beta_artifact_audit`.

Harness references: [Windows SetSuspendState](https://learn.microsoft.com/en-us/windows/win32/api/powrprof/nf-powrprof-setsuspendstate),
[wake timer](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-setwaitabletimer),
[Edge DevTools Protocol](https://learn.microsoft.com/en-us/microsoft-edge/devtools/protocol/).

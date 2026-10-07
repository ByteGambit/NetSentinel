# NS-099 — Physical host native sleep attempts (2026-10-07)

**Latest: third attempt — sleep NOT RUN, remaining USB audio SYSTEM request.**
The operator temporarily turned Mobile Hotspot off; its SYSTEM/AWAYMODE requests
cleared, but a USB Audio Device still held SYSTEM for an active audio stream.
The requested pre-sleep stop condition was honored. No sleep action was requested.
Hotspot was restored On through native Windows Settings; startup type Manual
preserved. Each attempt below retains its own measurement scope. VPN remains
BLOCKED / NOT RUN.

## First attempt — unverified host sleep

**Meaningful native sleep/resume: NOT RUN — actual host sleep not verified.**
The operator reported waking after the one requested manual sleep/wake action.
The measured host has S3 capability, but no new Windows sleep/wake event or
sleep-time clock gap was recorded. These observations do not establish a real
S3 transition; the operator report alone is not acceptance evidence. Which
environment received the action was requested as clarification and remains
unconfirmed at this record. No second manual sleep action was requested.

VPN stays NOT RUN / provisioning BLOCKED by Application Control. NS-099 remains
INCOMPLETE; M17 IN PROGRESS; limited pilot/broad release NO_GO; M18 DEFER;
NS-100 NOT STARTED. No waiver, tag or release.

## Capability, candidate and isolation

Physical host `powercfg /a`: S3, Hibernate and Fast Startup available; S0 Low
Power Idle, S1 and S2 unavailable because firmware does not support them;
Hybrid Sleep unavailable because of the hypervisor. **S3 is supported, not
proven exercised.** VMware suspend, process pause and hibernate were not used
as substitutes. No power/security setting was changed and SoftEther was not
retried. `powercfg /requests` required an elevated administrator token; the
current host token could not read it, so a specific sleep blocker is unknown.

Repository HEAD and origin/main at preparation were
`ef05655926739cc791bd65912783e2e8637faad1`, with a clean tracked tree.
Existing unpublished unsigned 0.1.0 candidate was reused without rebuilding:

| Field | Value |
|---|---|
| Runtime source | `8242868ba79c63ad743c005366ea715b238cf5d0` |
| Installer | NetSentinel-0.1.0-Setup.exe, 37,559,481 bytes |
| Installer SHA256 | `39b14fe844c8aaa150a8b09229e0d63aaaf5ecc98b5bc8c54b419140be7749d9` |
| Payload EXE SHA256 | `bfa73e87509d6b2762336a9f0cff87026f31271580a188fa10e81005320a89d4` |
| Payload verification this attempt | 1119 files, 0 hash mismatches against the frozen candidate manifest |
| AppId / schema | `{62E3BFC6-ACAD-4FC3-94D8-46927D015096}` / 019→019, no migration |

The exact payload EXE ran on the physical host as a standard user in a new,
isolated LocalAppData profile under ignored `build/`. Developer data was not
copied or overwritten; no installer registration was performed. The first-run
guide was dismissed explicitly. Notifications and scheduled retention stayed
default OFF, capture stopped, threat intelligence disabled. An existing Edge
binary used a separate test profile for benign HTTPS; no browser was installed.

## Actual observations

| Measurement | Before manual action | After reported wake |
|---|---|---|
| UTC snapshot | 10:11:22.817380 | 10:14:00.536036 |
| App PID / engine sessions | 3220 / 1 | 3220 / 1 |
| Alerts / alert occurrences | 0 / 0 | 0 / 0 |
| Incidents | 0 | 0 |
| Notification intents / eligible / adapter attempts / submitted | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0, native Diagnostics |
| Connection history rows | 842 | 925 (+83) |
| Risk assessments / baseline rows | 338 / 25 | 387 / 28 |
| Main DB bytes | 3,911,680 | 4,177,920 (+266,240) |
| SQLite quick_check / foreign-key violations | ok / 0 | ok / 0 |
| Invalid history timestamps | 0 | 0 |
| Log bytes / collector exceptions | 0 / 0 | 0 / 0 |

Wall-clock elapsed **157.718656 seconds**; Windows awake-time elapsed
**157.7186565 seconds**. Difference is approximately zero, not a 1–2 minute
sleep gap. The five-second recorder continued without a meaningful gap; its
largest adjacent sample interval through the first post-action analysis was
5.077736 seconds, and maximum wall-minus-awake difference was 0.001013 seconds.
The awake clock uses
[QueryUnbiasedInterruptTime](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttime),
which excludes sleep and hibernation. Kernel-Power 42/107/506/507 and
Power-Troubleshooter 1 were read in bounded queries and explicitly filtered to
timestamps after app launch. No matching event occurred in the measured period.
Historical power events were excluded from this acceptance result.

Native Diagnostics showed engine Running, DB Available, history writer Running,
queue 0/2048, DNS writer NotChecked while capture was stopped. Retry and modal
Application behavior controls responded. Tray availability was represented by
the normal Hide/Quit explanation, with default Quit selected; actual tray
restore/context-Quit after real sleep was **NOT RUN**. Notification delivery is
UNKNOWN in the UI; zero attempts while notifications are OFF does not prove
enabled notification replay/delivery behavior across sleep.

Monitoring continued, without an observed crash, engine restart or duplicate
session. Baseline payloads decoded, DB timestamps were ordered, and no alert or
incident was created. **No claim is made about sleep-gap baseline accounting,
connection duration or retention timing**, since no native gap occurred and
scheduled retention remained disabled. Worker health/log observations are not
an exhaustive Windows-wide error count.

Initial benign Edge activity was recorded in history. A later isolated-profile
IANA navigation was launched after the report of wake, but no new browser row or
browser last-seen timestamp was established for that navigation; this part is
**NOT VERIFIED**, not a successful post-resume browsing test. Overall history
continued to 984 rows at 10:16:03.669330 UTC, in the same engine session.

## Clean shutdown and persistence

Native main-window Close exercised the configured Quit behavior. A separate
50 ms process watcher recorded exit at 10:17:05.741934 UTC, **2.314934 seconds
after the UI-action timestamp** (observed upper bound including UI dispatch).
No remaining NetSentinel process was found; the finite recorder was stopped.
Post-close DB had 1000 history rows, 442 risk assessments, 28 baseline rows,
0 alerts/incidents, quick_check ok, 0 foreign-key violations, schema 019.
Main DB was 4,882,432 bytes; WAL/SHM were removed by clean SQLite close. This
checks ordinary shutdown persistence, not sleep recovery or restart replay.

## Evidence and outcome

Raw receipts, read-only DB snapshots, clock samples and the isolated profile
remain local under ignored `build/ns099-native-sleep-20261007/`. Raw paths,
process/domain/IP records, baseline identities and browser history are not
included in tracked evidence. Only acceptance documentation changes are made;
no runtime/test/dependency/schema change, rebuild, commit or push in this turn.
Docs-only `git diff --check` PASS; bounded privacy/secret review of this new
record and added documentation lines PASS (no raw user path, IPv4 address,
credential assignment or private key). Evidence links resolve. The full runtime
suite is not rerun for this documentation-only attempt. Final power-event query
at 10:19:31.9247077 UTC still returned no event after launch. HEAD still equals
origin/main at the same commit; five acceptance/status documents modified and
this new evidence document untracked, deliberately not committed/pushed.
No identifiable test-profile Edge process remained; two other Edge command
lines were unreadable under the current token, and those processes were left
untouched. This does not prove every browser process has exited.

| Gate | Result |
|---|---|
| Host meaningful sleep capability | S3 supported; S0 unsupported |
| Actual native sleep type / duration | NOT VERIFIED / NOT MEASURED |
| Native sleep/resume acceptance | **NOT RUN**, actual transition not verified |
| Ordinary app/worker/DB health and shutdown | Observed healthy in the measured non-sleep interval |
| Safe VPN | **NOT RUN / BLOCKED**, unchanged |
| NS-099 / M17 | **INCOMPLETE / IN PROGRESS** |
| Limited unsigned pilot / broad release | **NO_GO / NO_GO** |
| M18 / NS-100 / tag-release | **DEFER / NOT STARTED / NONE** |

## Second attempt — blocker diagnosis, no sleep action requested

At 10:49:38.7972944 UTC, the standard Windows UAC path launched a one-shot,
read-only `powercfg /requests` helper. Its receipt confirmed Administrator=true
and powercfg exit0. This resolved the first attempt's diagnostic privilege
limitation; sandbox escalation alone had still left the host token at Medium
integrity. No security setting, service, power setting or override was changed.

`powercfg /a` still reports S3 available, S0 unsupported. Actual request output:

| Request class | Observed caller / reason |
|---|---|
| DISPLAY | None |
| SYSTEM | Windows Mobile Hotspot Service (`icssvc`); Legacy Kernel Caller |
| AWAYMODE | Windows Mobile Hotspot Service (`icssvc`) |
| EXECUTION | Microsoft Edge WebView2 (`msedgewebview2.exe`); Playing audio |
| PERFBOOST / ACTIVELOCKSCREEN | None / None |

`icssvc` was Running, startup Manual. Read-only power-plan query showed Balanced,
Allow Away Mode Policy AC=1/DC=0 and Allow Standby States AC=1/DC=1. System power
status confirmed **AC online**, so the enabled Away Mode policy applies. Existing
request override lists were empty; no override was created. Legacy Kernel
Caller does not identify a specific driver in this output. The owner of the
WebView2 audio request was not determined or terminated.

Microsoft documents that an
[Away Mode request on S3 systems](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-powersetrequest)
can replace explicitly requested sleep with a state where the system continues
running and audio/video turn off. Other requests ordinarily terminate on
user-initiated sleep entry; Away Mode is the documented exception. This is a
**concrete current mechanism consistent with the first attempt's black-screen,
no-suspend observations**, not proof that these same requests existed during the
first attempt. A historical cause cannot be asserted from this later snapshot.

A clean S3 attempt was **not initiated** while the active Away Mode request
remained. No second manual action was requested and no NetSentinel process was
launched in this diagnostic-only attempt. Automatically stopping Mobile Hotspot
could interrupt existing network sharing, and is outside the diagnostic-only
change scope. No request override, forced suspend, screen lock, display-off,
VMware suspend or hibernate substitute was used. Removing the active Away Mode
request through its owning feature and rechecking requests is a prerequisite
for a future clean attempt; this record does not prescribe overriding Windows
power or security policy.

| Second diagnostic observation | Value |
|---|---|
| Current UTC / local time | 10:51:46.177280 UTC / 13:51:46.177280 +03:00 |
| Awake-time counter / uptime tick | 356,911.015303s / 378,829.468s |
| NetSentinel PID / monitoring | None / not started this attempt |
| Alert/incident/notification/DB delta | NOT MEASURED this attempt |
| Sleep-entry / resume / duration | NOT RUN / NOT RUN / NOT MEASURED |
| Recovery / GUI/tray / shutdown | NOT RUN this attempt |

Recent System events were read in bounded queries at 10:52:28.9099490 UTC.
Latest Kernel-Power sleep-entry42 was 00:23:03.8533201 UTC, record33944;
latest resume107 was 00:23:11.4556846 UTC, record33947. Latest
Power-Troubleshooter1 was 06:24:31.9107951 UTC, record33974, with sleep/wake fields
00:23:03.6099872 / 06:24:30.8959692 UTC and TargetState6/EffectiveState5.
These historical events precede both attempts, do not establish this attempt's
S3 entry and are not assigned a current acceptance duration.

Raw request paths, diagnostic receipts and power-plan/event queries remain only
in ignored `build/ns099-native-sleep-20261007-second/`. No production/test/schema
or installer change; no rebuild/full runtime suite. First-attempt and second
diagnostic documentation are delivered together in a normal main evidence
commit/push after diff and bounded privacy/secret checks. The first-attempt
uncommitted-delivery description above is historical; no acceptance criterion
or first-attempt result is weakened by committing the evidence.

**Native sleep/resume NOT RUN; prerequisite BLOCKED by an active Away Mode
request. VPN BLOCKED / NOT RUN unchanged. NS-099 INCOMPLETE, M17 IN PROGRESS,
pilot/broad NO_GO, M18 DEFER, NS-100 NOT STARTED; no tag/release.**

## Third attempt — hotspot cleared, USB audio SYSTEM request remained

Preparation reused the same frozen candidate, freshly verified again: installer
SHA256 `39b14fe844c8aaa150a8b09229e0d63aaaf5ecc98b5bc8c54b419140be7749d9`,
37,559,481 bytes; runtime source `8242868ba79c63ad743c005366ea715b238cf5d0`;
1119 payload files/0 hash mismatches, EXE hash unchanged. No rebuild or production
change. Repository HEAD/origin/main at preparation were
`d2ae8cefd3350ea9ce4db6c0aa2a72e0ad80937a`, clean tracked tree.

A separate third-attempt LocalAppData profile was created. Only the first
isolated test profile's default preferences and prior onboarding dismissal were
copied, not developer data or earlier history. Two owned setup processes were
stopped before acceptance measurements: the first-run guide and a process on
the sandbox desktop that the native UI tool could not target. The candidate was
then started outside that private desktop as a standard user on the physical
user desktop. Those setup stops are not clean-shutdown or sleep recovery PASS.
An intentional setup monitoring restart accounts for two persisted sessions and
560 existing gap rows in the pre-action DB. Both remain unchanged in the final
measurement. Final measured process PID8224 started11:03:19.545264 UTC;
active candidate process count1.

Native Diagnostics: engine Running, DB Available, history writer Running,
queue0/2048 after Retry. DNS writer NotChecked with capture stopped. Notifications
and scheduled retention remained default OFF; threat intelligence disabled.
Notification intents/eligible/adapter attempts/submitted0; visible delivery
UNKNOWN. The optional unavailable-adapter counter in Diagnostics is not treated
as a worker/application failure. Native Application behavior showed tray
availability and default Quit; its dialog was canceled without a setting change.
This is pre-sleep GUI/capability evidence, not post-resume tray acceptance.

Before hotspot was disabled, the elevated read-only request snapshot at
10:58:22.8893714 UTC showed icssvc SYSTEM/AWAYMODE, Legacy Kernel Caller SYSTEM,
Brave Playing audio EXECUTION, DISPLAY none. The previously observed WebView2
audio request was absent; no WebView2 or unrelated browser/system process was
killed. An exact benign audio tab/application was not identified, so the user's
existing browser was preserved. A finite five-second clock/DB recorder and
post-action event/DB/process checks were prepared before the manual action.

The operator replied **Hotspot kapalı**. Subsequent UAC launches initially failed
without a result; after the operator explicitly authorized a new local UAC
prompt, the query succeeded at **11:23:25.6094515 UTC**, Administrator=true,
powercfg exit0. `icssvc` was Stopped, startup Manual. Actual post-hotspot output:

| Request class | Result |
|---|---|
| DISPLAY | None |
| SYSTEM | **USB Audio Device — An audio stream is currently in use** |
| AWAYMODE | None |
| EXECUTION | None |
| PERFBOOST / ACTIVELOCKSCREEN | None / None |

Hotspot and Legacy Kernel Caller were no longer listed. The USB device's raw
instance ID is kept out of tracked evidence. The remaining request's owning
application was **not identified**, so no attribution to WebView2, Brave or
NetSentinel is asserted. Following the explicit instruction to stop if another
SYSTEM/AWAYMODE request remained, **no sleep instruction or sleep action was
issued**. No override or permanent power-policy change was made. This is an
environment prerequisite failure, not a NetSentinel sleep-recovery failure.

## Third-attempt measurements — awake interval only

| Measurement | Prepared snapshot | Stop snapshot |
|---|---|---|
| UTC / local timestamp | 11:04:42.706656 / 14:04:42.706656 +03:00 | 11:24:51.269348 / 14:24:51.269348 +03:00 |
| Awake time / uptime tick seconds | 357687.545679 / 379606.000 | 358896.108370 / 380814.562 |
| PID / active processes / recorded sessions | 8224 / 1 / 2 | 8224 / 1 / 2 |
| Alerts / occurrences / incidents | 0 / 0 / 0 | 0 / 0 / 0 |
| Notification intents/eligible/attempts/submitted | 0/0/0/0, disabled | 0/0/0/0, disabled; native UI counters |
| DB bytes | 3,506,176 | 7,798,784 (+4,292,608) |
| History rows / gap rows | 1627 / 560 | 5967 / 560 |
| Baseline rows | 17, decoded | 25, decoded |
| SQLite integrity / foreign-key violations / schema | ok / 0 / 019 | ok / 0 / 019 |
| Invalid history timestamps / log bytes | 0 / 0 | 0 / 0 |

Wall elapsed1208.562692s; awake elapsed1208.5626918s, approximately zero sleep
gap. Across246 samples, collector exceptions0 and largest sample interval
5.113843s. These numbers describe the ordinary waiting/diagnostic interval, not
sleep duration or post-resume workload. Monitoring continued with the same PID
and no new session. No alert/incident storm occurred during this interval.
No sleep-gap duration, baseline accounting, retention scheduling, notification
replay, native tray recovery or post-resume benign-browser claim is made.
The browser-name query does not include Brave and returned0 rows; no dedicated
post-resume navigation was generated because the S3 prerequisite did not pass.
Log/collector observations are a bounded error measure, not an exhaustive system
error count.

No new power event after the measured app launch was found in bounded
Kernel-Power42/107/506/507 and Power-Troubleshooter1 queries; final query was
11:29:23.6937103 UTC. Recorded pre-action latest Kernel-Power42/107 and
Power-Troubleshooter1 IDs/timestamps match the historical events in the second
diagnostic above. Verified sleep entry/resume/type/duration: **NOT RUN / NOT
MEASURED**, with no historical event substituted as current evidence.

Native main-window Close exercised default Quit. A50ms watcher observed exit at
11:25:34.958428 UTC, **2.604428s after the action timestamp**, an upper bound
including UI dispatch. No remaining NetSentinel process/window; recorder stopped.
Post-close DB:8,085,504 bytes,6124 history rows,512 risk assessments,25 baseline
rows,0 alerts/incidents, schema019, integrity ok, foreign-key violations0;
WAL/SHM removed on close. This is ordinary clean shutdown/persistence evidence.

## Third-attempt restoration and delivery

The previously enabled Mobile Hotspot was restored using its native Windows
Settings switch. Native UI independently showed **On** and icssvc returned
**Running / Manual**. Sharing source, band, network properties, credentials and
power-saving setting were not edited. The Settings window opened for restoration
was closed. No service was permanently disabled/uninstalled. Raw request paths,
device identifiers, profile data and screenshots containing private Settings
details were not saved/exported into tracked evidence. Local numeric receipts
and isolated test data remain under ignored
`build/ns099-native-sleep-20261007-third/`.

Docs-only evidence: diff/whitespace and bounded privacy/secret review; normal main
commit/push. No runtime suite rerun, code/schema/dependency change or installer
rebuild. Native sleep **NOT RUN**, prerequisite **BLOCKED by USB audio SYSTEM
request**. VPN **BLOCKED/NOT RUN** unchanged; NS-099 **INCOMPLETE**, M17 **IN
PROGRESS**, pilot/broad **NO_GO**, M18 **DEFER**, NS-100 **NOT STARTED**;
tag/release **NONE**.

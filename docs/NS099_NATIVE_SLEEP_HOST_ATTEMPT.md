# NS-099 — Physical host native sleep attempts (2026-10-07)

**Latest: final prepared native S3 recovery PASS (default optional features OFF).**
The accepted candidate remained running across verified host S3 for 1732.464145s
with the same PID/session. Monitoring/GUI/history writer recovered, benign
browser traffic persisted, and native Quit was clean. Notification counters0
are scoped to notifications OFF; browser OS account association and pre-existing
capacity-loss observations are recorded below. VPN remains BLOCKED / NOT RUN;
NS-099 INCOMPLETE, M17 IN PROGRESS, pilot/broad NO_GO, M18 DEFER.

**Historical follow-up: host S3 observed; NetSentinel sleep/resume NOT RUN.**
After a read-only audio diagnosis and a clean power-request snapshot, the
operator independently reported waking. New Windows events establish host S3
for 142.461447 seconds. The measured candidate had already been cleanly quit;
no application pre-sleep baseline or recorder was prepared for this transition.
This proves host capability, not application recovery. See the follow-up below.
VPN remains BLOCKED / NOT RUN; NS-099 remains INCOMPLETE.

**Third attempt — sleep NOT RUN, remaining USB audio SYSTEM request.**
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

## Follow-up: verified host S3 without an application test

The next task was limited to identifying the audio blocker, with no sleep action
requested by Codex. Read-only Core Audio session/peak queries matched the prior
power-request USB instance through its PnP container to Speakers/Microphone
(2- USB PnP Audio Device). At 11:42:25 UTC, the only observed active session was
Brave render audio: brave.exe PID8252, parent Brave PID17460, Session10,
unmuted, peak0.683202. Subsequent snapshots at 11:43:58 and 11:45:10 were
Inactive/peak0; no application was closed by Codex. An elevated query at
11:45:03.5103398 UTC no longer listed the USB SYSTEM request. Hotspot was still
holding SYSTEM/AWAYMODE because it had been restored after the third attempt.
These observations identify the currently observed stream owner; they do not
retroactively prove the owner at every earlier request timestamp or constitute
a controlled Brave-close experiment. No audio content was recorded.

The operator then turned Hotspot off again. At **11:48:14.1120783 UTC**,
Administrator=true, powercfg exit0: **all six request classes None**, including
SYSTEM/AWAYMODE/EXECUTION. The nearby audio snapshot found no active session.
The icssvc service remained Running/Manual despite no active power request;
service-running state alone was not used to infer Hotspot sharing state. No
override, device disable, driver uninstall or permanent policy write occurred.

After this read-only check the operator independently wrote **Uyandı**. Bounded
System queries since the clean request snapshot returned the following new
events, with no query exceptions:

| Evidence | UTC timestamp / data |
|---|---|
| Kernel-Power42, record34047 | 11:50:48.8184419; TargetState4 / EffectiveState4 |
| Kernel-Power107, record34050 | 11:50:50.4648503; TargetState4 / EffectiveState4 |
| Power-Troubleshooter1, record34067 | Emitted11:53:12.5136308; TargetState4 / EffectiveState4 |
| SleepTime in Power-Troubleshooter1 | **11:50:47.8557455** (local14:50:47.8557455) |
| WakeTime in Power-Troubleshooter1 | **11:53:10.3171929** (local14:53:10.3171929) |
| WakeTime minus SleepTime | **142.461447 seconds** |

State4 is Windows PowerSystemSleeping3/S3. `powercfg /a` still reports S3
available, S0 Low Power Idle unavailable. HiberWriteDuration/HiberReadDuration
were0. The duration above comes from SleepTime/WakeTime, not event107's emission
time or the separate SleepDuration/WakeDuration transition fields. No prepared
pre/post awake-time observation exists for this independently initiated sleep.
The new state and sleep/wake fields establish host S3; no screen-off-only claim
or VMware suspend substitution is used.

**Application acceptance is still NOT RUN.** The final measured candidate was
cleanly quit at 11:25:34.958428 UTC, with its shutdown receipt at11:25:35.045038;
it was not relaunched by Codex for this read-only task. No candidate process was
found at the post-wake query. Its isolated DB remained unchanged from shutdown:
8,085,504 bytes,6124 history rows,25 baseline rows,0 alerts/incidents; last
history observation11:25:32.226193 UTC, integrity ok, foreign-key violations0,
schema019. This is a stopped-file check, not live monitoring/persistence recovery
evidence or a measured zero false-positive/notification burden during sleep.

Monitoring recovery, duplicate engine/session, duration/gap accounting, baseline
and retention timing across sleep, notification replay, GUI/tray usability,
post-resume benign workload and shutdown: **NOT RUN**. Application before/after
alert/incident/notification deltas and error/shutdown duration: **NOT MEASURED**.
No application crash/recovery FAIL is inferred from an intentionally closed
candidate. The host transition removes the earlier hardware/environment doubt;
it does not close the NS-099 application gate.

Sanitized local observation/analysis receipts are under ignored
`build/ns099-native-sleep-unprepared-20261007/`; audio receipts under ignored
`build/ns099-audio-blocker/`. No new manual sleep instruction, application launch,
Hotspot restoration or other setting change was issued in this follow-up; the
operator's latest Hotspot-off choice was preserved. Docs-only evidence receives
diff/privacy checks and normal main commit/push; no rebuild/runtime suite.
VPN **BLOCKED/NOT RUN**, NS-099 **INCOMPLETE**, M17 **IN PROGRESS**, pilot/broad
**NO_GO**, M18 **DEFER**, NS-100 **NOT STARTED**; tag/release **NONE**.

## Final prepared retry: live candidate S3 recovery

**Native sleep/resume: PASS for this prepared physical-host scenario.**
2026-10-07; host build26200.9550, DisplayVersion25H2, standard-user Session10.
This is actual Windows S3, not VMware suspend, hibernate, process pause or screen
off. Previous attempts retain their own NOT RUN results and counters.

### Candidate and preparation

Runtime source `8242868ba79c63ad743c005366ea715b238cf5d0`;
unsigned0.1.0 `NetSentinel-0.1.0-Setup.exe`, 37,559,481 bytes;
SHA256 `39b14fe844c8aaa150a8b09229e0d63aaaf5ecc98b5bc8c54b419140be7749d9`.
1119 payload files freshly verified,0 mismatches; EXE SHA256
`bfa73e87509d6b2762336a9f0cff87026f31271580a188fa10e81005320a89d4`.
No rebuild/production change. Source is distinct from the docs-only repository
HEAD `fa90ecea150573ebf86b9a51fda7d4260a1675a9` at test preparation.

A new isolated LocalAppData profile was used, copying only the prior isolated
test's default preferences/onboarding dismissal, no history or developer data.
Candidate PID19696 started12:03:46.075636 UTC. Native Diagnostics after Retry
showed engine/history writer Running, DB Available, queue0/2048, standard user.
Notifications and scheduled retention OFF; TI disabled; capture Stopped, DNS
writer NotChecked. Optional-disabled/unavailable is not an application failure.
Pre-sleep notification intents/eligible/attempts/submitted/failures0.

Elevated read-only `powercfg /requests` at12:06:28.7127854 UTC returned exit0,
**all six classes None**, including SYSTEM/AWAYMODE/EXECUTION. The operator's
latest Hotspot-off choice was preserved; no service/device/override/power-policy
change was made. No new sleep event since app launch existed at12:07:07.6574476
UTC. Numeric DB/clock snapshots, five-second recorder, post-event/DB checks and
bounded shutdown observer were prepared before the single requested sleep action.

### Actual S3 evidence

| Evidence | UTC / local+03:00 |
|---|---|
| New Kernel-Power42 / record34096 | 12:08:15.0398843; TargetState4 / EffectiveState4 |
| New Kernel-Power107 / record34099 | 12:08:16.8856125; TargetState4 / EffectiveState4 |
| New Power-Troubleshooter1 / record34117 | Emitted12:37:07.3754435; TargetState4 / EffectiveState4 |
| SleepTime | **12:08:13.9440018 / 15:08:13.9440018** |
| WakeTime | **12:37:06.4081465 / 15:37:06.4081465** |
| WakeTime minus SleepTime | **1732.464145s (28min52.464s)** |

The observed sleep was longer than the requested one-to-two minutes. Duration
uses the sleep/wake fields, not Kernel-Power107's emission timestamp or the
separate transition-duration fields. HiberWriteDuration/HiberReadDuration0.
Pre/post wall elapsed1864.228125s, awake elapsed136.613623s; excluded awake-clock
time1727.614502s independently confirms a real suspend gap. Event duration and
excluded time are recorded separately, not asserted equal.

The recorder collected28 pre-sleep samples with0 collector errors; the last at
12:08:11.943775 UTC was2.000226s before SleepTime. Its1800s wall deadline expired
during the longer S3 and it ended on wake, so it produced no automatic post-wake
sample. Explicit post-wake snapshots supplied the independent awake-clock and
application checks; the recorder's maximum adjacent interval is not used as a
sleep gap. Its stderr was empty.

### Application recovery and measurements

| Measurement | Prepared baseline12:06:30.347536 UTC | First post-wake12:37:34.575661 UTC |
|---|---|---|
| PID / process count / monitoring sessions | 19696 / 1 / 1 | 19696 / 1 / 1 |
| Alerts / occurrences / incidents | 0 / 0 / 0 | 0 / 0 / 0 |
| Notification intents / adapter attempts / submitted | 0 / 0 / 0, OFF | 0 / 0 / 0, OFF; native Retry |
| DB bytes | 3,252,224 | 4,177,920 (**+925,696**) |
| History rows | 1085 | 1724 (+639) |
| Baseline rows | 10 | 16 |
| Integrity / foreign-key violations / schema | ok / 0 / 019 | ok / 0 / 019 |
| Invalid history timestamps / log bytes | 0 / 0 | 0 / 0 |

Native Diagnostics after resume and after benign traffic: engine/history writer
Running, queue0/2048, DB Available, GUI responsive. No duplicate process/session,
crash, alert/incident storm or notification intent/replay was observed. Enabled
notifications across sleep are **NOT RUN**; OS visible delivery remains UNKNOWN.
This OFF scenario is not new enabled-toast/click/policy evidence. Existing
notification-policy acceptance remains separately scoped.

Duration sanity: first post-wake maximum history wall span1997.911672s; later
maximum2527.727407s versus app wall age2558.143517s. Invalid timestamps0, no span
beyond application age. History/connection durations are first/last observation
spans and can include suspension; they are not asserted continuous active
coverage. Baseline monitored coverage did not acquire28min of sleep: maximum131s
at first post-wake;13 matched baseline records against the closest pre-sleep
sample showed0 decreases and additions at most10s. No malformed baseline,
future persisted timestamp or sleep-induced baseline reset was found.

The earlier prepared baseline showed one coverage value42s that was24s after
wake. The pre-sleep recorder independently shows50→7 at12:07:26.725937 UTC,
then24 at12:07:56.871525, **before S3**, and24 in the first post-wake snapshot.
This existing counter cycling is not attributed to sleep or hidden as a fix.
All23 later baseline payloads decoded; all carried capacity-loss and22 carried
gap flags. Exact counter-cycling root cause and full baseline learning quality
are not claimed resolved; the across-S3 comparison and conservative loss flags
are the bounded evidence used here.

Scheduled retention remained OFF; timestamps stayed ordered/non-future. Enabled
retention scheduling across sleep was **NOT RUN**, not inferred from DB integrity.
Post-sleep tray context was not repeated; this run verifies responsive GUI and
default native Quit, while earlier tray acceptance retains its recorded scope.

### Benign browser check and shutdown

Existing Edge launched at12:39:54.7213577 UTC with a new test-profile directory
and normal Example Domain/Wikipedia URLs. Native observation confirmed Example
Domain content behind an OS sign-in notice and a Wikipedia tab title. The OS
automatically associated its account with the new profile; the notice was not
accepted, sync/account settings were not changed, and no account identifier or
private screenshot is included in tracked evidence. This was directory isolation,
not proven account/network isolation. No claim of zero browser background egress.

At12:43:44.086914 UTC, history2260→3105 during the browser interval; browser-name
rows2→38, including36 new Edge rows first/last observed after test launch. These
are process-level rows, not definitive domain attribution. Same NetSentinel PID,
one session, alerts/incidents0; no storm. Native engine/writer/queue remained
Running/Running/0 after Retry. The sync modal prevented native browser frame
Close, so only the10 verified test-profile Edge processes were stopped;0 remained.
Other browsers were preserved. No account/privacy setting was edited.

Native NetSentinel Close exercised configured default Quit at12:49:18.298 UTC;
50ms watcher observed exit12:49:21.330945 UTC, **3.032945s upper bound** including
UI dispatch. No remaining NetSentinel process/window. Closed DB:6,311,936 bytes
(**+3,059,712** versus prepared baseline),4259 history rows,23 baseline rows,
alerts/incidents0, integrity ok, foreign-key violations0, schema019; empty WAL
after the overlapping read-only checker, no pending WAL data. This is clean
shutdown/persistence evidence, not a claimed new application restart test.
Application log bytes0, recorder exceptions0; this bounded observation is not an
exhaustive Windows error counter. Diagnostic helper command mistakes were
corrected and are not counted as NetSentinel crashes or worker failures.

### Acceptance and delivery

**PASS:** actual new S3 + live candidate recovery, same process/session,
resumed monitoring, bounded duration/coverage, no alert/incident/notification
storm in the stated OFF scenario, healthy persistence, responsive GUI, benign
browser monitoring and clean Quit. Optional enabled features, post-sleep tray
context, browser account isolation and baseline counter-cycling root cause retain
the explicit limitations above. No production fix, installer rebuild or migration.

Local receipts/profile data remain under ignored
`build/ns099-native-sleep-20261007-final/`; no sensitive raw record is staged.
Docs-only diff/privacy checks and normal main commit/push. VPN **BLOCKED/NOT RUN**
unchanged, so exact TASKS acceptance remains unmet: NS-099 **INCOMPLETE**, M17
**IN PROGRESS**, limited pilot **NO_GO**, broad release **NO_GO** (NS-097 policy
also applies), M18 **DEFER**, NS-100 **NOT STARTED**, tag/release **NONE**.

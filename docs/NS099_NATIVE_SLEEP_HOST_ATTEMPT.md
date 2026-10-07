# NS-099 — Physical host native sleep attempts (2026-10-07)

**Latest: second-attempt diagnostic only — sleep NOT RUN, active Away Mode
request identified.** The first attempt below remains NOT RUN. The second
diagnostic is recorded separately at the end; first-attempt counters are not
reused as second-attempt measurements. VPN remains BLOCKED / NOT RUN.

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

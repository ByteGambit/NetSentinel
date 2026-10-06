# NS-099 — Native candidate checklist

Historical closure checklist candidate (superseded by the layout fix): unsigned0.1.0,37,556,108 bytes, SHA256
`14934a527e985dc3f32bb94fb3e721ad87d86b3cee1330de12f2b2af36b46538`, clean committed runtime `ae08d7ef1205f5bd4f0b9b0397075c1f6176f2c4`.
[Identity](PUBLIC_BETA_CANDIDATE.json), [closure gate table](PUBLIC_BETA_ACCEPTANCE.md).
The scenario table below preserves pre-closure42b996/A0 and339da4 evidence;
its historic install/browser/updater/KEEP rows are not new-candidate repetitions.

Current layout candidate: source `bfe531d960aaabd6b61c1701cf7179f7214c5097`, SHA256 `74529e4cfa03d466ed365a4b0fe5c65c4399873acf150b0c3472496472bdf4c2`, 37,543,802 bytes.
[Layout/native/human recheck](NS099_LAYOUT_CLOSURE.md). Human layout recheck PENDING;
other seven human PASS results preserved; required VPN/sleep/policy gates unchanged.

## Environment

| Field | Actual record |
|---|---|
| VM / access | New Windows 11, VMware Workstation / configured VMware MCP; old VM not used |
| OS | Windows 11 Home x64, 10.0.26200, full build 26200.9457 |
| Accounts/token | A and Unicode B fresh local Users-only/not Administrators; no observed UAC |
| Session/cleanliness | Secondary Logon in existing interactive session 1; fresh app profiles, existing OS; no pristine snapshot |
| Tools/Python/Npcap | Tools running; no actual Python, Store alias only; Npcap service/driver absent |
| Network/VPN | One up adapter; safe VPN undefined, required case PENDING |
| Display | 1078×800 measured; scaling/DPI and exact 1280×720 unmeasured |
| Hash | Final host→guest hash match; installed EXE matches final payload |
| Cleanup | Historical A/B KEEP uninstalls; closure candidate remains installed, app/fixture0, temporary task0/credential-file0; accounts/data/exports preserved. Prior browser listener cleanup historical |

## Pre-closure results (closure overrides below)

NATIVE PASS is limited to the actual subcase described. Offline/historical
evidence cannot fill a required unrun case. Zero observed benign alerts/popups
does not prove enabled notification delivery. Required pending rows prevent GO.

| Scenario | Native result / limits | Separate evidence |
|---|---|---|
| Fresh A standard install | A0 NATIVE PASS wizard/launch/data separation | Final A same-version repair PASS |
| Fresh final Unicode B | NATIVE PASS install/launch/export/restart/KEEP | Historical NS-096 Unicode remains separate |
| First-run guide | A0 six pages Next/Back/Finish PASS; final B appearance/Skip PASS | Guide source unchanged; final payload source audit |
| Human onboarding comprehension | PENDING, no independent evaluator result | Structural/UI automation is not comprehension |
| Observed display/footer | Native guide controls fit1078×800; exact 1280×720/DPI NOT RUN | Supported-viewport/font-size GUI tests PASS |
| Npcap missing | A0 observed core running, capture/DNS honestly unavailable; final driver absent | Unchanged capability source and regression |
| Npcap present / live TI | NOT RUN optional | Fakes only; no driver/credential provisioning |
| Browser≥10min | NATIVE PASS loaded ordinary HTTPS tabs/close/reopen, visible isolated profile | No scientific FP ground truth |
| Updater≥5min | NATIVE PASS existing signed normal EdgeUpdate task result 0, ≥9min | Check executed, no download/version-change claim |
| Safe VPN transition | **PENDING / NOT RUN required** | Synthetic scope/wrong-scope/gap tests only |
| Windows sleep/wake | A0 S1 recovery observed, timer failed/MCP resume; full timing/gap PENDING, final S1 NOT RUN | Injected gaps do not prove native behavior |
| Three app restarts A | NATIVE PASS config/guide/integrity, alerts/incidents remained0, no ghosts | Populated incident/occurrence/notification replay offline |
| Unicode B restart | NATIVE PASS dismissed-v1 guide absent, SQLite OK/defaultsOFF | Harness UTF-8 SQL-path fix separate from app |
| Reboot/sign-out/reconnect | NOT RUN extras, independent sign-in impractical | No autostart/reboot recovery PASS inferred |
| Default X Quit | NATIVE PASS bounded exits, no ghosts | Lifecycle regression |
| Hide / real tray Show | NATIVE PASS same process/window restored from actual shell icon | Human discoverability PENDING |
| Tray-context Quit | NOT RUN | File/default QUIT native passed; context action regression separate |
| Notification defaultOFF | Observed NATIVE PASS OFF/no accidental consent/no unsolicited popup | Default-zero fake sink tests |
| Enabled actual OS toast/privacy/click | **PENDING / NOT RUN required**; no qualifying native alert | Accepted benign fixture route needed, no direct DB insertion/production hook |
| Dedup/cooldown/escalation/replay | NOT RUN native populated fixture | Fake sink submissions2, duplicates100/cooldown1/disabled1, failures0 |
| Benign FP/notification burden | Observed zero alerts/popups in bounded 42min; below budget for observed activity | Missing VPN/delivery prevents overall PASS; actionable ratio N/A |
| Incident quality | Native0, no giant merge seen; explanation quality not exercised | Explicit incident story/source-expiry/caps PASS |
| Baseline learning/restart | Native rows grow/persist; full coverage/quality not inferred | Warm-up/gap/scope/eviction/learning regressions |
| DNS ambiguity | Native DNS capture unavailable honestly | Direct/CNAME AMBIGUOUS fixtures |
| TI OFF/network | Final app socket snapshot0/0; not continuous trace | Source/forbidden-network default-zero tests |
| ≥30min native soak | Final measured42m00.93; retained assessments512, history1472, SQLite OK/log0 | Exact cycle count/peak memory/whole-session DB-growth unknown |
| GUI responsiveness | Native settings/navigation/Diagnostics/preview usable | Human ergonomics/latency SLA not claimed |
| Retention/status | NATIVE PASS final immediate OFF/ON after Save, preferences restoredOFF | Original2 GUI failures/fixed2 passes |
| Purge preview/Cancel | A0 native PASS, no manual purge confirmed | Destructive/reference protection offline only |
| Feedback preview/Save | Final B NATIVE PASS, 3702 bytes exact preview; final A Save attempt cancelled | A0 localSave3718bytes separate |
| Export privacy | Final actual file/preview allowlist scan0 raw-value matches | Bounded scan, not universal anonymity guarantee |
| Final repair | NATIVE PASS exit 0, exact DB/config/export preservation | Same-version repair, not code-version upgrade |
| Compatible upgrade/DELETE | Historical NS-096 only; no new native repetition | Current installer/source compatibility/deletion-safety tests |
| Final KEEP A/B | NATIVE PASS exit 0, exact data/export hashes; program/registration gone | No deletion switch; silent means KEEP |
| Defaults/autostart | Native preferences OFF/QUIT; no capture; manual launch used | Autostart/update/upload/response/elevation source audit; reboot unrun |

For remaining runs, record candidate hash and exact environment once, start/end
times and active minutes, retained versus produced assessments, severity/labels/
review demands, occurrences/incidents, OS-observed popups versus sink submissions,
duplicates/skips/escalations, errors/drops, DB/WAL sizes and resource snapshots.
No raw usernames/paths/IP/domain/MAC/screens or secrets in committed evidence.
Human onboarding/tray/toast review and safe VPN setup require real evaluator/
environment input; no inferred PASS. Resume with a verified candidate after any
runtime change and rerun affected native scenarios.

## Closure overrides

| Gate | Current status |
|---|---|
| Installed new candidate | PASS, installer/EXE/all1119 installed payload hashes matched |
| VPN | NOT RUN, safe environment absent; mandatory |
| Meaningful native sleep/resume | NOT RUN, S3/Modern Standby unavailable; S1/VMware suspend not substituted |
| Real native fixture toast/privacy/click | PASS, identical production PYZ, actual native click selected exact alert |
| Duplicate/source cooldown/restart fixture | PASS, duplicates3; immediate source repeat produced no extra intent; replay0 |
| Effective OS-disabled notification state | BLOCKED, desktop-user registry flag did not suppress secondary-user popup; restored |
| Tray context Quit/default X | PASS,1357/1653ms, no remaining app processes |
| Human UX | **FAIL**,7 PASS/1 layout FAIL; Incidents/DNS small upper lists, History right-column squeeze/overflow |
| NS-099/M17 | INCOMPLETE/IN PROGRESS |
| Pilot/broad/M18 | NO_GO/NO_GO/DEFER |

Counts and fixture limitations are in the authoritative closure table. No NOT RUN is waived.

Human evaluator accepted onboarding/optional-state/risk language/tray/toast/privacy/support
and found no other obvious confusion. Layout criterion FAIL remains open; see
[human evidence](PUBLIC_BETA_ACCEPTANCE.md#native-human-ux-result).

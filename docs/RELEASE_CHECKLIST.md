# NS-099 — Release readiness checklist (unpublished)

Follow-up host S3 verified for142.461447s after requests cleared; **application
sleep/resume NOT RUN** because the measured candidate had already been quit and
no live baseline existed. Host proof grants no recovery waiver or release GO.
VPN BLOCKED/NOT RUN, NS-099 INCOMPLETE/M17 IN PROGRESS, pilot/broad NO_GO;
M18 DEFER, NS-100 NOT STARTED. [Scope](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md#follow-up-verified-host-s3-without-an-application-test).

Third host sleep attempt (2026-10-07): **NOT RUN**, remaining USB audio SYSTEM
request after Hotspot off; stopped before sleep as instructed. Hotspot restored
On/Running/Manual. No sleep-recovery waiver, runtime/power-policy change or
override. VPN BLOCKED/NOT RUN, NS-099 INCOMPLETE/M17 IN PROGRESS, pilot/broad NO_GO,
M18 DEFER, NS-100 NOT STARTED. [Exact scope](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md#third-attempt--hotspot-cleared-usb-audio-system-request-remained).

Second host sleep diagnostic (2026-10-07): **NOT RUN**, active Hotspot Away Mode
request with AC Away Mode allowed; no clean S3 transition or workload measured.
No service/override/power setting changed. Docs-only commit/push creates no
release approval. VPN BLOCKED/NOT RUN, NS-099 INCOMPLETE/M17 IN PROGRESS,
pilot/broad NO_GO, M18 DEFER and NS-100 NOT STARTED remain unchanged.
[Blocker evidence](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md#second-attempt--blocker-diagnosis-no-sleep-action-requested).

Physical-host sleep attempt (2026-10-07): **native sleep/resume NOT RUN**;
S3 available but no verified transition or sleep gap after the reported wake.
Ordinary app/DB/quit observations do not close the gate. VPN BLOCKED/NOT RUN;
NS-099 INCOMPLETE/M17 IN PROGRESS, pilot/broad NO_GO, M18 DEFER unchanged.
No new installer, commit/push/tag/release or NS-100.
[Measured host attempt](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md).

VPN-only attempt (2026-10-07): **NOT RUN; provisioning BLOCKED** by host Windows
Application Control. No tunnel or VPN burden measurements. Candidate/runtime and
release decisions unchanged; native sleep untouched. NS-099 INCOMPLETE/M17 IN
PROGRESS, pilot/broad NO_GO, M18 DEFER; NS-100/tag/release NONE.
[Private endpoint attempt and cleanup](NS099_VPN_ENVIRONMENT_ATTEMPT.md).

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


[Candidate](PUBLIC_BETA_CANDIDATE.json), [acceptance](PUBLIC_BETA_ACCEPTANCE.md),
[native checklist](PUBLIC_BETA_CHECKLIST.md), [frozen protocol](BETA_PROTOCOL.md).
NS-099 **INCOMPLETE**, M17 **IN PROGRESS**, limited pilot **NO_GO**, broad release
**NO_GO**, M18 **DEFER**. This checklist creates no publication/tag or approval.

| Area | Current evidence | Open gate |
|---|---|---|
| Core/context/risk | Prior M11–M14 accepted and offline regressions; native benign browser/updater, driver-missing, restarts | Safe VPN and complete native sleep/gap evidence |
| Incidents/baselines | Prior M13/M16, accelerated caps/explicit story/restarts; native aggregate persistence | Native zero incidents do not exercise narrative quality |
| Notifications | DefaultsOFF and zero-alert benign observation; fake sink policy PASS | Current policy fixture PASS: actual global OFF/ON, UNKNOWN, popup/privacy/click/duplicates/restart; human toastUX/layout PASS retained in evaluator scope |
| Tray | Native Hide/actual icon Show/default X Quit; no ghosts | Prior-candidate tray-context Quit PASS1357ms; human intent PASS |
| Privacy/storage | Committed immediate retention status fix; sanitized Unicode export/KEEP PASS in historical recorded scope | Destructive protection offline; no continuous egress trace |
| Installer | Current policy candidate1119 installed hashes matched, Limited-token install PASS; fresh Unicode/repair/KEEP historical scope | Historical upgrade/DELETE explicitly separate; no pristine OS claim |
| Signing/distribution | Explicit UNSIGNED/NotSigned, manual updates, verified integrity | Broad signer/protected release gate; owner audience/license/channel/contact |
| Onboarding/feedback | A0 six-page walkthrough; final B appearance/Skip/persistence/export; no accidental consent | Human UX8 PASS/0 FAIL, layout finding closed; broader DPI/scaling remains unmeasured |
| Windows matrix | Windows 11 Home x64 build 26200.9457 observed | All other client builds/ARM64/server NOT TESTED |
| Performance/FP | Native42min interval, zero reviewed alerts, SQLite OK/log0, bounded exits; offline caps | Missing scenarios prevent complete burden assessment; no leak/peak/SLA claim |
| Quality | Policy3833/8deselected,91.09%,734.10s; targeted123; Ruff/mypy/audit/integrity PASS; portable historical scope | Remote CI not run; final diff/privacy checks local only |
| Publication | NONE | Future explicit release authorization, final signed hashes/metadata when a release exists |

Future release requires refreshed candidate/hash after runtime edits, affected
native retests, functional M17 exit, and NS-097 owner/distribution gates. If signed,
verify inner/generated-uninstaller/outer signatures and timestamps, then take final
hash. Do not fabricate published_at/tag URLs. M18 independently requires later
explicit response GO; no NS-100 work is authorized by this checklist.

Historical layout source `bfe531d960aaabd6b61c1701cf7179f7214c5097`; candidate SHA256 `74529e4cfa03d466ed365a4b0fe5c65c4399873acf150b0c3472496472bdf4c2`, 37,543,802 bytes.
Prior14934a52/339da4 candidates historical; previous native functional gates retain
their original scope. [Layout/native recheck](NS099_LAYOUT_CLOSURE.md).
Human layout recheck PASS; overall8 PASS/0 FAIL. Original layout finding closed.
Mandatory VPN/meaningful native sleep NOT RUN; no M17 waiver. See authoritative
[closure exit table](PUBLIC_BETA_ACCEPTANCE.md).

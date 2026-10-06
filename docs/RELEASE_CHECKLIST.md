# NS-099 — Release readiness checklist (unpublished)

[Candidate](PUBLIC_BETA_CANDIDATE.json), [acceptance](PUBLIC_BETA_ACCEPTANCE.md),
[native checklist](PUBLIC_BETA_CHECKLIST.md), [frozen protocol](BETA_PROTOCOL.md).
NS-099 **INCOMPLETE**, M17 **IN PROGRESS**, limited pilot **NO_GO**, broad release
**NO_GO**, M18 **DEFER**. This checklist creates no publication/tag or approval.

| Area | Current evidence | Open gate |
|---|---|---|
| Core/context/risk | Prior M11–M14 accepted and offline regressions; native benign browser/updater, driver-missing, restarts | Safe VPN and complete native sleep/gap evidence |
| Incidents/baselines | Prior M13/M16, accelerated caps/explicit story/restarts; native aggregate persistence | Native zero incidents do not exercise narrative quality |
| Notifications | DefaultsOFF and zero-alert benign observation; fake sink policy PASS | Native scoped toast/privacy/click/duplicate/restart fixture now PASS; effective OS-disabled policy BLOCKED, human toastUX PASS; page layout FAIL |
| Tray | Native Hide/actual icon Show/default X Quit; no ghosts | Tray-context Quit now PASS1357ms; human intent PASS |
| Privacy/storage | Committed immediate retention status fix; sanitized Unicode export/KEEP PASS in historical recorded scope | Destructive protection offline; no continuous egress trace |
| Installer | Committed runtime candidate/new installed1119 hashes audited; reinstall PASS; fresh Unicode/repair/KEEP historical scope | Historical upgrade/DELETE explicitly separate; no pristine OS claim |
| Signing/distribution | Explicit UNSIGNED/NotSigned, manual updates, verified integrity | Broad signer/protected release gate; owner audience/license/channel/contact |
| Onboarding/feedback | A0 six-page walkthrough; final B appearance/Skip/persistence/export; no accidental consent | Human comprehension PASS, Incidents/DNS/History layout FAIL; unmeasured DPI/scaling |
| Windows matrix | Windows 11 Home x64 build 26200.9457 observed | All other client builds/ARM64/server NOT TESTED |
| Performance/FP | Native42min interval, zero reviewed alerts, SQLite OK/log0, bounded exits; offline caps | Missing scenarios prevent complete burden assessment; no leak/peak/SLA claim |
| Quality | Closure3785/8deselected,91.08%,505.82s; targeted200; Ruff/mypy/audit/integrity PASS; portable historical scope | Remote CI not run; final diff/privacy checks local only |
| Publication | NONE | Future explicit release authorization, final signed hashes/metadata when a release exists |

Future release requires refreshed candidate/hash after runtime edits, affected
native retests, functional M17 exit, and NS-097 owner/distribution gates. If signed,
verify inner/generated-uninstaller/outer signatures and timestamps, then take final
hash. Do not fabricate published_at/tag URLs. M18 independently requires later
explicit response GO; no NS-100 work is authorized by this checklist.

Closure candidate14934a52…36b46538, clean runtime ae08d7e; previous339da4 historical.
Mandatory VPN/meaningful native sleep NOT RUN; no M17 waiver. See authoritative
[closure exit table](PUBLIC_BETA_ACCEPTANCE.md).

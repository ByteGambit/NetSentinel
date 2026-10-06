# NS-096 native clean Windows client gate

Status (2026-10-06): **NS-096 COMPLETE**. Exact TASKS.md native lifecycle gate
**PASS**, based on
user-supplied Windows VM results. Final automated closure is recorded in
[the acceptance report](INSTALLER_ACCEPTANCE.md). Existing VM, newly created
standard-user profiles; no pristine OS image or pre-existing clean snapshot.
The exact task requires clean-client VM lifecycle smoke and does not explicitly
require a pristine OS baseline. Fresh profiles without NetSentinel/data, Npcap
or a real Python runtime satisfy this per-user lifecycle condition.
Host wizard was blocked by Application Control 4551 and is excluded from
acceptance; Windows security was not disabled/bypassed. Source tests/offscreen
smoke and NS-050's historical portable VM evidence are separate.

## Recorded native evidence

| Case | Result and observation |
|---|---|
| Standard-user install/UAC | PASS: `desktop-iqft4nq\ns096test` not Administrators, non-elevated; no normal-install UAC/admin-password request |
| No Python | PASS: only WindowsApps Store alias; app launched without external runtime |
| No Npcap | PASS: service absent, launch succeeds, no driver bundle/download/install/elevation |
| Fresh install | PASS: program under LocalAppData\Programs\NetSentinel; first launch creates LocalAppData\NetSentinel config/log/SQLite/WAL/SHM |
| Program/data separation | PASS: no config/log/SQLite in install-tree search |
| Repair/reinstall 0.1.0 | PASS: observed config and DB hashes unchanged |
| Upgrade 0.1.0 → 0.1.1 fixture | PASS: direct over-install; config/DB hashes preserved relative to immediate pre-upgrade observation |
| Registration/path | PASS: one HKCU entry, DisplayVersion 0.1.1, same install location/AppId |
| KEEP / reinstall after KEEP | PASS: program removed/data retained; reinstall has program/data paths available |
| DELETE | PASS: program/data removed; LocalAppData parent retained |
| Reinstall after DELETE | PASS: data absent until first launch, then fresh config/log/SQLite created |
| Cancel | PASS: cancellation before destruction leaves program/data paths present |
| Unicode install/launch | PASS: standard-user `desktop-iqft4nq\İzmirçalışma`, profile `C:\Users\İzmirÇalışma`; program/data/config/log/SQLite present |
| Unicode DELETE | PASS: program/data removed; USERPROFILE preserved |
| Host wizard | BLOCKED: Application Control 4551; not used for acceptance |

The 0.1.1 fixture upgrades installer metadata/lifecycle only; application payload
is still 0.1.0. No separate Unicode UAC observation, pristine OS, native migration
fixture run, packet-level offline audit or full native history audit is claimed.
Exact artefact hashes and per-scenario data hashes are in the acceptance report.
Unsigned pilot; no updater, Npcap bundling/download, service/autostart, firewall
rule/Defender exclusion or automatic elevation; no secure-erasure guarantee.

## Broader reproducible checklist

The recipes below are retained for broader coverage. Only scenarios explicitly
recorded above are native PASS. Additional running/tray coordination, silent
flows, copy failure/rollback, deleted-file repair, native old/future-schema
fixtures, external sentinels, long/custom spaced paths and reparse/inventory
tamper scenarios are **NOT RECORDED** in this native session. Some have separate
offline/source/OS-fixture coverage; that is not native wizard evidence. The exact
TASKS.md acceptance controls NS-096 closure; this broader checklist does not
assert that every recipe ran.

## Prepare

- Clean supported Windows 10/11 x64 client VM, snapshot and standard user token.
- No Python, repo, venv, Npcap or WinPcap required; offline initially.
- Approved Inno Setup 6.3+ Unicode build tool on the build host, not the VM.
- Transfer only unsigned pilot Setup.exe and its SHA256/manifest sidecars.
- Verify `Get-FileHash -Algorithm SHA256` against sidecar before any execution.
- Record Windows build, token/elevation, username/path, compiler version,
  artifact/source version/hash, Npcap state, logs and each PASS/FAIL/NOT RUN.
- Record SmartScreen/Application Control blocks as blocks; do not disable/bypass
  security. Installer framework logs may contain user paths; do not publish raw logs.
- For true N→N+1 tests use two actual versioned installer builds; do not pretend
  a current-version repair is a version upgrade. Schema fixtures are separately
  labelled application migration tests, not native installer evidence.

## Fresh install / capabilities / paths

1. Run Setup normally offline. Read pilot/privacy notice. Confirm no UAC/admin
   prompt. Default `%LOCALAPPDATA%\Programs\NetSentinel` and desktop opt-in.
2. Confirm one current-user Windows uninstall entry and a Start Menu shortcut;
   no Registry Run, Startup entry, service, task, firewall rule or exclusion.
3. Before first launch, `%LOCALAPPDATA%\NetSentinel` must not be newly created
   by installation. Bundle contains exe, `_internal`, icons, 001–019 SQL,
   third-party licenses/notices, policy and payload inventory; no local user data.
4. Launch Start Menu from a foreign cwd. Confirm first-run onboarding, visible
   startup, notification/TI/storage defaults OFF and close behavior QUIT.
5. Finish onboarding. Confirm config/SQLite/log only in user data root; inspect
   ledger = 019 with approved external tooling (no Python runtime required to run app).
6. With Npcap absent, Connections/process/history work as supported; Diagnostics
   honestly reports capture unavailable/degraded. Capture never starts implicitly.
7. Confirm tray Hide keeps monitoring and File/tray Quit exits boundedly.
8. Try repair/upgrade and uninstall with visible then hidden running app. Both
   must require Quit. Try starting the app while Setup/uninstall is open; startup
   must refuse before opening DB/config/log. No force kill or restart.

## Repair / upgrade / failure

9. Save representative history, alerts/incidents, profile/trust/preferences,
   notification/tray/storage settings and consent in VM. Copy closed data safely.
10. Quit; delete one **owned** installed runtime file. Rerun same-version installer.
    Confirm file restored; config bytes and DB logical rows/preferences unchanged.
11. Install actual N+1 over N with same AppId. One uninstall entry/shortcut remains;
    owned stale payload files removed; no `.old`/`.tmp` or duplicate runtime payload.
    A separately created sentinel file inside install directory must remain.
12. Relaunch; retained history/config/settings/profile/trust readable. Supported old
    schema fixture (008 and 018 separately) reaches 019 via application startup;
    019 stays unchanged. Future 020 refuses without reset/downgrade/deletion.
13. Exercise install cancellation and simulated copy/start/migration failure in
    snapshot. Record actual framework rollback result; user data must stay. Do not
    claim binary or DB downgrade rollback without evidence.

## Uninstall choices / reinstall / safety

14. Quit. Cancel the first data-choice prompt and second DELETE confirmation in
    separate runs. Verify binaries/shortcuts/registration/data remain unchanged.
15. KEEP (default No): remove owned binaries, shortcuts and registration; hash/copy
    data before/after confirms retained local state. Unrelated install sentinel stays.
16. Reinstall; compatible data and preferences reused, onboarding not reset.
17. Place external export and unrelated AppData sentinel. DELETE Yes + destructive
    OK: owned user data root removed, parent/sentinels/external export unchanged.
18. Reinstall after DELETE; fresh defaults/schema 019 and normal onboarding.
19. Repeat silent `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG="<VM log>"`
    install/repair and silent uninstall. Silent uninstall must always KEEP; there is
    no silent deletion switch. Check exit codes, no dialogs/elevation/reboot.
20. In snapshot only: junction at data root, child and ancestor pointing to a safe
    unrelated sentinel fixture. DELETE must refuse before touching data; KEEP must
    remain usable. Missing/broken helper must abort DELETE and recommend repair/KEEP.
21. Pre-NS-096 portable process also must prevent DELETE (Toolhelp image check).
    Quit any development Python GUI manually before uninstall; it is not a frozen
    process and has no installer marker. Do not test against real daily user data.

## Unicode / spaces / reasonable long paths

22. Repeat all relevant flows with Unicode user `Berke-İzmir Test Kullanıcı` and
    `%LOCALAPPDATA%\Programs\Çalışma Net Sentinel`. Include export Save, restart,
    repair, upgrade, KEEP/reinstall and DELETE/reinstall. Record results separately.
23. Use a reasonably long dedicated folder below LocalAppData\Programs; record
    framework/runtime path limitations without changing Windows security/path policy.
24. Try an install location outside that per-user Programs subtree or containing
    a junction. Expect a clear refusal, not elevation or shared data overwrite.
25. After installation in a snapshot, replace an owned program subtree with a
    junction to an unrelated sentinel fixture. Both uninstall choices must refuse
    before framework file removal. Remove the inventory in a separate fixture;
    uninstall must require repair. Restore fixtures before proceeding.

Use the recorded-results matrix above for actual native outcomes. Do not infer
PASS for unreported recipes. NS-097 remains outside this task.

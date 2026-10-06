# NS-096 final native acceptance / closure — 2026-10-06

**NS-096 — Installer/upgrade/uninstall: COMPLETE.** Native lifecycle acceptance
and final automated closure gates **PASS**. M17 remains
IN PROGRESS; NS-097 is NOT STARTED. No release or tag is created.

## Exact acceptance and clean-client decision

The authoritative NS-096 text in `TASKS.md` is:

> Standard-user policy; Unicode path, fresh/upgrade DB; Npcap/elevation otomatik yok; user data kararı açık.

The specified test method is:

> Clean Windows client VM install/repair/upgrade/uninstall smoke.

The repo does not define this as a pristine OS image, never-used VM, or mandatory
pristine starting snapshot. This per-user installer was exercised in newly
created, never-used standard-user profiles on an **existing Windows VM**.
Initially the test profile had no NetSentinel installation/data, no Npcap service,
and no real Python runtime. This satisfies the clean-client condition for the
exact NS-096 per-user lifecycle acceptance. It does **not** establish a pristine
Windows OS baseline: there was no pristine pre-existing snapshot. Snapshot-based
destructive/adversarial recipes in the broader smoke checklist are not evidence
that such a baseline was used. Exact task criteria and test method remain unchanged.

| Exact gate | Evidence | Result |
|---|---|---|
| Standard-user policy | `desktop-iqft4nq\ns096test` not in Administrators; non-elevated PowerShell; normal install | PASS |
| Unicode path | Separate standard-user `desktop-iqft4nq\İzmirçalışma`, actual profile `C:\Users\İzmirÇalışma`; install/launch/data/delete | PASS |
| Fresh/upgrade DB | Fresh native data creation; upgrade preserves immediate pre-upgrade DB; offline old/current/future compatibility tests | PASS |
| No automatic Npcap/elevation | No Npcap service; successful app launch; normal install has no UAC/admin-password prompt; no driver install/download | PASS |
| Explicit user-data decision | Native KEEP, explicit DELETE, reinstall after each, cancel preserving program/data | PASS |
| VM install/repair/upgrade/uninstall | Recorded native scenarios below; two versioned installer builds, same AppId | PASS |

## Actual native Windows results

These are **user-supplied native observations**, recorded on 2026-10-06; this
closure turn does not claim to rerun the VM UI. Windows OS build and independent
installer-network measurement were not supplied. No missing observation is inferred
from a passing offline/source test. Historical results below remain historical.

| Scenario | Actual observation | Result |
|---|---|---|
| Standard user | `desktop-iqft4nq\ns096test`, not Administrators, normal non-elevated token | PASS |
| UAC/elevation | Fresh normal installer flow asked for neither UAC elevation nor administrator password | PASS |
| No Python runtime | Only `C:\Users\ns096test\AppData\Local\Microsoft\WindowsApps\python.exe` Store execution alias; installed app launched | PASS |
| No Npcap | `Get-Service npcap -ErrorAction SilentlyContinue` returned no service; app launched; no bundle/download/install/elevation | PASS |
| Fresh install | Program at `%LOCALAPPDATA%\Programs\NetSentinel`; app launched successfully | PASS |
| First launch | `%LOCALAPPDATA%\NetSentinel` created with config.json, netsentinel.log, netsentinel.sqlite3 and WAL/SHM | PASS |
| Program/data separation | Install-tree search for `*.sqlite3`, config.json and netsentinel.log found no persistent user-data files | PASS |
| Same-version repair/reinstall | Rerun 0.1.0 over existing 0.1.0; config and DB hashes unchanged in this observation | PASS |
| Installer upgrade | 0.1.1 fixture installed directly over 0.1.0, without uninstall; config/DB hashes equal immediate pre-upgrade values | PASS |
| Product registration | One HKCU uninstall record: `NetSentinel 0.1.1 (unsigned pilot)`, DisplayVersion 0.1.1; original program location retained | PASS |
| KEEP uninstall | Program path False; data path True | PASS |
| Reinstall after KEEP | 0.1.1 fixture: program/data paths True; preserved data root available | PASS |
| DELETE uninstall | Program/data paths False; parent `%LOCALAPPDATA%` True | PASS |
| Reinstall after DELETE | Program exists, data absent before app launch; launch creates fresh config/log/SQLite and WAL/SHM as applicable | PASS |
| Cancel uninstall/delete | Cancelled before destructive completion; program/data paths both True | PASS |
| Unicode install/launch | Standard-user `İzmirçalışma`; profile `C:\Users\İzmirÇalışma`; program/data paths True, config/log/SQLite present | PASS |
| Unicode DELETE uninstall | Program/data paths False; Unicode USERPROFILE True | PASS |
| Host wizard | Windows Application Control 4551 blocked launch; security not disabled or bypassed; excluded from native acceptance | BLOCKED |

The Unicode test did not separately record a UAC observation; the no-UAC result
above belongs to `ns096test`. Cancel evidence establishes path preservation;
separate cancellation at every prompt was not reported. Reinstall-after-KEEP
establishes availability of the retained root, not a full native row-by-row history
audit. All additional, unreported checklist cases remain NOT RECORDED.

Repair observations:

| File | Before and after SHA256 |
|---|---|
| config.json | `4C51D92C566F7ED7286FFB3D712B49A8A7B12DBF6FAFE58614711DB96E599FAB` |
| netsentinel.sqlite3 | `71C0CB5A350A88E9F19587E724823AFA2FF52286B9DC729A14EDAD0CA818A631` |

Upgrade observations (compared to the **immediate pre-upgrade** observation):

| File | Before and after SHA256 |
|---|---|
| config.json | `4C51D92C566F7ED7286FFB3D712B49A8A7B12DBF6FAFE58614711DB96E599FAB` |
| netsentinel.sqlite3 | `B5F5779406FD5DA320E6EAB7CB9DD3337591D817F500BE4DDA9E0F238C7A02A5` |

The DB changed between the repair and later pre-upgrade observations; each
scenario uses its own before/after pair. Byte-identical DB files are not a general
production requirement. Registry InstallLocation was
`C:\Users\ns096test\AppData\Local\Programs\NetSentinel\`; no duplicate
0.1.0 + 0.1.1 registrations were observed.

## Accepted artefacts and fixture limits

Build compiler: Inno Setup **6.7.3** at
`C:\Users\berke\AppData\Local\Programs\Inno Setup 6\ISCC.exe`.
Stable AppId for both installers: `{62E3BFC6-ACAD-4FC3-94D8-46927D015096}`.

| Artefact | Size | SHA256 |
|---|---:|---|
| `C:\Users\berke\NetSentinel\dist\NetSentinel-0.1.0-Setup.exe` | 37,535,265 bytes | `f9c253eea2b605436fc685cdf2334c4d52233a3bb5ac01d6a358b633fae419a7` |
| `C:\Users\berke\NetSentinel\dist\ns096-upgrade-fixture\NetSentinel-0.1.1-Setup.exe` | 37,535,262 bytes | `845eff9b207bb060a50625a4297fa9dc48a8e395596e4383a20b327d4e4dd2c6` |

Both are unsigned pilot artefacts. The temporary fixture has installer version
0.1.1 and installer PE version 0.1.1.0; **its application payload remains 0.1.0**.
It proves installer identity/replacement, single registry product entry, data
preservation and path preservation. It does not prove a functional application
code-version upgrade. The fixture is ignored test output, not a version bump,
release or NS-097 work. Accepted payload/inventory: 1,119 files.

Schema **019 → 019**; no NS-096 migration, no changed SQL resources. Application
migration compatibility: 001 → 019, 008 → 019, 018 → 019, current 019 reopen and
future-schema rejection. Installer/helper do not open or migrate SQLite.
Static source/manifest/payload checks confirm no service, autostart, scheduled
task, firewall rule/cleanup, Defender exclusion, updater, Npcap bundle/download,
automatic elevation or upload hook. These are source/payload confirmations, not
an invented native OS-wide audit. DELETE is ordinary local deletion, with no
secure-erasure guarantee.

## Final automated and Git closure

| Final gate | Result |
|---|---|
| Relevant targeted suite | 121 passed (18.33 s) |
| Installer-only suite | 57 passed (5.30 s) |
| Full offline pytest | 3683 passed, 8 deselected (450.13 s); one existing Scapy FFDH deprecation warning |
| Ruff, `src tests packaging` | PASS |
| Configured mypy | PASS, 36 source files |
| Direct mypy, touched modules/builders | PASS, 8 source files |
| Accepted payload/inventory/ZIP/PE/sidecar verification | PASS, 1,119 files |
| Fixture manifest/PE/sidecar verification | PASS; identical 0.1.0 payload, installer PE 0.1.1.0 |
| `git diff --check` | PASS; line-ending notices only |

Final commands (repo root; default pytest markers exclude live tests):

```powershell
$env:PYTHONPATH = "$PWD\src;$PWD\.venv\Lib\site-packages"
$runtimePython = 'C:\Users\berke\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $runtimePython -m pytest -q tests/integration/test_installer_lifecycle.py tests/integration/test_packaging_resources.py tests/integration/sqlite/test_migrations.py tests/unit/shared/test_config_logging_diagnostics.py tests/unit/shared/test_notification_config.py tests/unit/shared/test_window_close_config.py tests/gui/test_app_lifecycle.py
& $runtimePython -m pytest -q tests/integration/test_installer_lifecycle.py
& $runtimePython -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests packaging
& $runtimePython -m mypy
& $runtimePython -m mypy src/netsentinel/shared/paths.py src/netsentinel/infrastructure/windows_installer.py src/netsentinel/infrastructure/uninstall_data.py src/netsentinel/infrastructure/sqlite/database.py src/netsentinel/bootstrap.py packaging/build_installer.py packaging/installer_payload.py packaging/build_windows.py
& $runtimePython build/ns096_verify.py
git diff --check
```

Approved bundled CPython 3.12.14 uses existing repo venv dependencies for tests
and mypy; Ruff uses venv Python. No Windows security policy/runtime files change.
Artefact verification checks existing builds; this turn does not rebuild them.

Closure began on `main` with **13 modified + 11 untracked** legitimate NS-096
files; HEAD = origin/main = `90a55134850e02ee6722077c09e9e94edf8d0213`.
Existing work preserved; generated binaries/build output/fixtures remain ignored.
All final gates passed; NS-096 alone is marked COMPLETE. Authorized Git closure
uses `feat: add Windows installer lifecycle` and normal `git push origin main`.
The final chat report records the resulting commit/push/HEAD/status after these
operations; no generated installer/fixture or build output is included.

Reviewed scope (24 files): README.md; docs/ARCHITECTURE.md, PRODUCT.md,
RELEASING.md, ROADMAP.md, SECURITY.md, TASKS.md, INSTALLER_ACCEPTANCE.md,
INSTALLER_UPGRADE_UNINSTALL.md, INSTALLER_WINDOWS_SMOKE.md;
packaging/NetSentinel.spec, README.md, build_windows.py, entry.py,
INSTALLER_POLICY.md, NetSentinel.iss, build_installer.py, installer_payload.py;
src/netsentinel/bootstrap.py, infrastructure/sqlite/database.py,
infrastructure/uninstall_data.py, infrastructure/windows_installer.py,
shared/paths.py; tests/integration/test_installer_lifecycle.py.
No SQL resource/version bump/NS-097 implementation or generated artefact belongs
to this commit. Native account paths here are acceptance context; no VM images,
logs, local config/database or secrets are staged.

## Historical implementation and phase 1 evidence

The following sections preserve the earlier implementation/build observations.
Their INCOMPLETE/NOT RUN/no-commit statements describe that earlier phase and
are superseded by the current native and closure sections above.

Initial state verified: branch `main`, clean working tree;
HEAD = origin/main = `90a55134850e02ee6722077c09e9e94edf8d0213`
(`feat: add storage and privacy controls`). Actual SQL manifest 001–019.
Stale portable spec/self-test expectations of 009 were updated to 019.

## Closure phase 1 — actual build and artefact (2026-10-06)

User-installed Inno Setup **6.7.3** exact path:
`C:\Users\berke\AppData\Local\Programs\Inno Setup 6\ISCC.exe`.
`/?` worked outside the sandbox (help returns exit 1); compiler engine reported
6.7.3 in the real build. Compiler Authenticode signature Valid, Pyrsys B.V.
Initial sandbox access denial was a tooling restriction, not an OS-security
bypass. Repo `_ctypes` remains blocked; approved same CPython 3.12.14 used.
Locked packaging dependencies installed with the existing uv workflow; PyInstaller
6.22.3 / hooks 2026.7. No second packaging system or compiler download introduced.

```powershell
uv sync --cache-dir .uv-cache --locked --extra dev --extra packaging
& 'C:\Users\berke\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' packaging/build_installer.py --use-project-packages --iscc 'C:\Users\berke\AppData\Local\Programs\Inno Setup 6\ISCC.exe'
```

The explicit package flag uses only the fixed repo `.venv\Lib\site-packages`
dependency directory with the invoking runtime; it does not change stdlib,
Python prefix, native runtime files or security policy. Build child still removes
ambient PYTHONPATH and narrows DLL PATH. The initial artifact had correct ProductVersion
but Inno's default numeric FileVersion 0.0.0.0. `VersionInfoVersion={#AppVersion}`
now derives both from the one app version source; final real recompile passed.

| Phase 1 requested item | Actual result |
|---|---|
| 1 ISCC | 6.7.3, exact path above |
| 2 Command | Existing build command above, approved-runtime dependency option |
| 3 Build | **PASS**, full fresh PyInstaller → validation → real ISCC → SHA256 |
| 4 Artefact | `C:\Users\berke\NetSentinel\dist\NetSentinel-0.1.0-Setup.exe` |
| 5 Size / timestamp | **37,535,265 bytes**; **2026-10-06 01:48:22 Europe/Istanbul** (2026-10-05T22:48:22.9370427Z) |
| 6 SHA256 | `f9c253eea2b605436fc685cdf2334c4d52233a3bb5ac01d6a358b633fae419a7` |
| 7 Signing | **NotSigned**, verified with Get-AuthenticodeSignature; unsigned pilot |
| 8 Payload | **PASS**: 1,119 payload files / 123,762,673 bytes; compiler input list equals payload + generated inventory |
| 9 Program/data | Separate per-user Programs root vs NetSentinel data root; actual portable smoke install directory unchanged |
| 10 Per-user/admin | Static/compiled PE **PASS**, both setup/app `asInvoker`, uiAccess false; normal wizard UAC observation blocked |
| 11 KEEP/DELETE | Source/Pascal compile PASS; KEEP default and silent KEEP; DELETE explicit choice + destructive confirm + trusted-root helper; native UI NOT RUN |
| 12 Npcap | No Npcap/WinPcap/wpcap.dll/Packet.dll/.sys payload or download; PASS |
| 13 Other hooks | No service/Run/Startup/task/firewall/exclusion/updater/telemetry/network requirement; static PASS |
| 14 Schema | 019→019; no new migration; installer does not open/migrate SQLite |
| 15 Compatibility | Migration tests cover 001→019, 008/018→019, current 019 and future 020 rejection; PASS |
| 16 Local smoke | Final installer launch **BLOCKED: 4551**; temp inner exe blocked, wizard never opened, no installation. Isolated portable smoke PASS |
| 17 Clean VM | **NOT RUN / PENDING**, all native install/repair/upgrade/uninstall/Unicode scenarios |
| 18 Targeted | **121 passed**; final NS-096 new-only **57 passed** |
| 19 Full offline | **3683 passed / 8 deselected**, 403.17s; existing Scapy FFDH deprecation warning only |
| 20 Ruff | PASS, `src tests packaging` |
| 21 Mypy | Configured PASS (36); direct PASS (8, now including portable builder) |
| 22 Diff | PASS; line-ending notices only |
| 23 Task | **INCOMPLETE**, implementation/build finished |
| 24 Remaining gate | Clean Windows client standard-user/offline/no-Python/no-Npcap install, repair, true N→N+1 upgrade, KEEP/DELETE/cancel/reinstall, Unicode/spaces/reparse acceptance |
| 25 NS-097 | NOT started; no signing/update-distribution spike |
| 26 Git | main, HEAD/origin/main unchanged 90a5513; prior work preserved, no reset/revert/stash/commit/push; all generated outputs ignored |

SHA256 sidecar was independently compared with the final executable. Payload
manifest hashes, generated file inventory and every portable ZIP file hash match.
19 exact SQL resources, icon, helper/path/migration modules, Python/Qt runtime and
seven top-level license files are present. Frozen PYZ has 690 modules and no
pytest/development tests. Actual Setup/app PE versions are 0.1.0.0, both manifests
are `asInvoker`/uiAccess false. Setup bootstrap is x86, installed app/runtime x64
(normal Inno x64-compatible installer configuration).

Inspection uses actual files plus compiler compression log; no independent
decompression of the Inno archive or native installation is claimed. No renamed
secret-content scanner or bit-identical rebuild guarantee is claimed.
Ignored evidence: `build/ns096-build.log`, `build/ns096-artefact-verification.json`,
`build/ns096-portable-smoke.log`, `build/smoke-windows/{first,second}.json`.
Native error text was read with the computer-use skill; subsequent window
inventory confirmed no installer window remained. No Windows Security/Application Control
setting was changed and no blocked inner executable was moved/relaunched.

Final portable smoke: two Qt/offscreen GUI sessions, first/second onboarding,
actual SQLite WAL/FK/schema 019, 018→019, icon, orderly exit 0, Unicode/spaces/
foreign cwd and unchanged program directory all PASS. Real-user data untouched;
test data isolated under ignored build directory. This is not clean-VM acceptance.

Framework metadata reference: [Inno VersionInfoVersion](https://jrsoftware.org/ishelp/topic_setup_versioninfoversion.htm).

## Initial implementation evidence (historical)

- Initial targeted run: 3 fixture failures / 101 passed; the fixture used an invalid
  history UUID. Fixed to a valid 36-character UUID; then 104 passed.
- Expanded targeted run: 109 passed (5.49s); final targeted with actual GUI lifecycle
  regressions **116 passed** (12.18s), final new-only **52 passed** (2.60s).
- Full offline suite: **3672 passed / 8 deselected**, 303.65s. One existing Scapy
  cryptography FFDH deprecation warning. This run collected the original 46 new
  NS-096 cases; subsequently added cases were separately verified.
- Ruff `src tests packaging`: PASS. Configured mypy: PASS (36 files).
  Direct mypy: PASS (7 files). `git diff --check`: PASS (line-ending notices only).
- Requested venv runtime `_sqlite3` import was blocked by Windows Application
  Control. Same approved bundled CPython **3.12.14 Windows x64** and existing venv
  packages used for pytest/mypy; Ruff ran with requested venv Python. No OS security
  settings or runtime files changed; no live/capture/provider tests executed.
- Build command: explicit failure before PyInstaller build, missing `ISCC.exe`.
  No current Setup artifact, compiler syntax result, real installer payload/hash
  inspection or native install/repair/upgrade/uninstall/Unicode result exists.
  Source/layout/build-mock tests are not compiler or native acceptance.
- An expanded test invocation referenced nonexistent `tests/gui/test_onboarding.py`;
  pytest ran no tests and returned an error. Corrected invocation uses actual
  `tests/gui/test_app_lifecycle.py`. No failure is counted as a pass.
- No commit/push: user's conditional commit/push applies when acceptance permits
  completion; this task is still incomplete. Changes are reviewable in the working
  tree. No branch/tag/release or NS-097 work was created.

## Requested 104-item report

“Implemented” below describes source behavior, not a claim that compiled Inno or
native VM behavior passed. Native outcomes explicitly remain NOT RUN.

| # | Item | Result |
|---|---|---|
| 1 | Exact title | NS-096 — Installer/upgrade/uninstall |
| 2 | State | INCOMPLETE: build PASS; clean VM gate pending; local installer smoke BLOCKED 4551 |
| 3 | M17 | Active; NS-093/094/095 COMPLETE; NS-097 not started |
| 4 | Technology | Inno Setup 6.3+ Unicode |
| 5 | Choice | Small wrapper over tested PyInstaller; per-user, stable AppId, mutex, Unicode, owned ledger, silent fixtures |
| 6 | Version | 0.1.0 from `src/netsentinel/version.py` |
| 7 | Identity | `{62E3BFC6-ACAD-4FC3-94D8-46927D015096}`, stable across versions |
| 8 | Scope | Per-user only |
| 9 | Standard user | `PrivilegesRequired=lowest`; dedicated current-user Programs subtree |
| 10 | UAC/elevation | No automatic request/helper/runas; native result pending |
| 11 | Program path | `%LOCALAPPDATA%\Programs\NetSentinel` |
| 12 | User data | `%LOCALAPPDATA%\NetSentinel` |
| 13 | Resource path | Existing package APIs; frozen resources under `_internal` |
| 14 | Dev paths | Same per-user data policy, source package resources |
| 15 | Portable paths | Same per-user data, PyInstaller resources |
| 16 | Installed paths | Same per-user data, same PyInstaller payload |
| 17 | Test override | Explicit injected path/LocalAppData fixture; no new production env override |
| 18 | SQLite | `NetSentinel/netsentinel.sqlite3`, WAL/SHM; reputation cache in DB |
| 19 | Config | `NetSentinel/config.json`, all consent/preference settings |
| 20 | Logs | `NetSentinel/netsentinel.log` and existing bounded rotations |
| 21 | Separation | Central resolver never uses executable/cwd/_MEIPASS for data; Unicode tests pass |
| 22 | PyInstaller | Fresh existing onedir build reused for both formats |
| 23 | Contents | Exe/runtime/icons/019 resources, licenses/notices, policy; generated owned inventory |
| 24 | Exclusions | Deny private DB/WAL/SHM/journal/config/log/exports, tests/.git/.env, driver assets and stale temp formats |
| 25 | Secrets | Key/certificate/credential/.env exclusions; no copied build-machine data; no arbitrary renamed-secret detection claim |
| 26 | Licenses | Existing third-party inventory/actual files preserved and required; no invented project EULA |
| 27 | Build command | `python packaging/build_installer.py --iscc <ISCC.exe>` after locked packaging dependencies |
| 28 | Compiler | Explicit prerequisite; missing tool error, no download |
| 29 | Output | Ignored actual Setup.exe, checksum and payload manifest produced; phase 1 table above |
| 30 | SHA256 | Final independent check PASS; phase 1 table above |
| 31 | Fresh | Deploy program files; app creates root/config/DB at first run; native NOT RUN |
| 32 | Offline | Payload self-contained, no installer network hooks; native NOT RUN |
| 33 | No Npcap | Existing capability/degraded flow remains; native NOT RUN |
| 34 | Npcap bundle | Absent; payload exclusion gate |
| 35 | Npcap download | No implementation/download hook |
| 36 | Repair | Same-version reinstallation restores owned files; native NOT RUN |
| 37 | Repair data | Installer never writes/resets data/config/consent; native preservation NOT RUN |
| 38 | Upgrade | Same identity/entry/location, payload replacement and exact obsolete-file pruning; native NOT RUN |
| 39 | Running app | Desktop marker before writers; installer close/retry; no force kill |
| 40 | Hidden tray | Marker independent of window visibility; native tray installer flow NOT RUN |
| 41 | Config | Older missing fields use safe defaults; persisted bytes preserved in migration fixture |
| 42 | Old schema | 008→019 and 018→019 preserve history; actual SQLite fixture PASS |
| 43 | Current schema | 019 reopens unchanged; PASS |
| 44 | Future schema | 020 raises typed DatabaseSchemaTooNew; ledger retained; PASS |
| 45 | Migration owner | Application SQLite migration runner |
| 46 | Installer migration | None; helper never opens SQLite |
| 47 | Schema | 019→019 |
| 48 | New migration | None; existing 001–019 SQL unchanged |
| 49 | KEEP | Inno owned program files/shortcuts/registration removed, data untouched; native NOT RUN |
| 50 | DELETE | Exact owned user root via maintenance-only packaged entry; tests PASS, native NOT RUN |
| 51 | Default choice | KEEP (No, default second button); silent always KEEP |
| 52 | Confirmation | Separate destructive OK/Cancel; examples/local irreversible/secure-erasure wording |
| 53 | Root checks | Trusted Windows folder, exact child, absolute/canonical/ancestor checks; reject broad/malformed root |
| 54 | Links/reparse | User-data ancestor/root/child refusal before mutation; real junction fixtures PASS. Program/inventory preflight implemented, native pending; concurrent hostile swap not atomically prevented |
| 55 | Exports | External export preserved; isolated fixture PASS |
| 56 | Cancel | Inno confirmations before `usUninstall`; native no-mutation verification NOT RUN |
| 57 | Reinstall KEEP | Compatible data policy reused; native scenario NOT RUN |
| 58 | Reinstall DELETE | Fresh config fixture PASS; native scenario NOT RUN |
| 59 | Unicode | Resolver/SQLite/config/build fixtures PASS; native installer NOT RUN |
| 60 | Spaces | Same offline fixture PASS; native installer NOT RUN |
| 61 | Start Menu | Current-user shortcut defined |
| 62 | Desktop | Explicit unchecked opt-in task |
| 63 | Autostart | Absent; no Run/startup/task |
| 64 | Service | Absent |
| 65 | Firewall | No rules/exceptions |
| 66 | Defender | No exclusions/settings modifications |
| 67 | Installer network | No networking/download/run hooks |
| 68 | Telemetry | No install stats/upload |
| 69 | Notifications | Default OFF preserved; config regression PASS |
| 70 | TI | Default-deny/off preserved; no consent rewrite |
| 71 | Close/tray | QUIT_APPLICATION default preserved; config/lifecycle regressions |
| 72 | Storage/privacy | Default retention OFF, opt-in settings preserved |
| 73 | Signing | Unsigned pilot sources; no signature claim |
| 74 | SmartScreen | Possible warning/block documented; no bypass instructions |
| 75 | Updater | Absent |
| 76 | Npcap ownership | User separately installs; installer never removes it |
| 77 | Firewall cleanup | Excluded, no M18 implementation |
| 78 | Checklist | `docs/INSTALLER_WINDOWS_SMOKE.md` |
| 79 | Native clean VM | NOT RUN |
| 80 | Native repair | NOT RUN |
| 81 | Native upgrade | NOT RUN; no true N/N+1 artifacts generated |
| 82 | Native KEEP | NOT RUN |
| 83 | Native DELETE | NOT RUN |
| 84 | Native Unicode | NOT RUN |
| 85 | App Control | Repo runtime SQLite blocked; approved same-CPython test runtime used; current installer/runtime native result unavailable |
| 86 | Added tests | 57 in `tests/integration/test_installer_lifecycle.py`; source/path/schema/content/helper/build/OS coordination fixtures |
| 87 | Added files | paths, Windows coordinator, delete helper; Inno/build/payload/policy; 3 focused docs; test file |
| 88 | Modified files | spec/entry/portable build/readme; DB default/boot paths; README and PRODUCT/ARCHITECTURE/SECURITY/ROADMAP/TASKS/RELEASING |
| 89 | Targeted | 104 then 109 PASS; final with lifecycle 116 PASS, new-only 52 PASS |
| 90 | Full pytest | Phase 1: 3683 passed / 8 deselected, 403.17s; initial implementation run 3672 retained below |
| 91 | Ruff | PASS: `src tests packaging` |
| 92 | Configured mypy | PASS: 36 source files |
| 93 | Direct mypy | Phase 1 PASS: 8 source files |
| 94 | diff check | PASS |
| 95 | Installer build | PASS: real ISCC 6.7.3; metadata corrected and recompiled |
| 96 | Payload inspection | Actual payload, compiler file list, PE resources and ZIP/manifest hashes PASS; no native install/archive extraction claim |
| 97 | Checksum | Final Setup executable SHA256 independently matches sidecar |
| 98 | Migration chain | Fresh 019, 008/018→019, 019 reopen, future rejection PASS |
| 99 | TASKS | INCOMPLETE explicitly; order/scope intact |
| 100 | Docs | policy, native checklist, this report; releasing/product/security/architecture/roadmap/readme updated |
| 101 | Commit | Not created; initial HEAD stays 90a5513 |
| 102 | Push | Not attempted; completion condition unmet |
| 103 | NS-097 | NOT started |
| 104 | Working tree | Implementation/docs changes remain uncommitted on main; no generated artifacts staged |

## Initial implementation commands (historical)

```powershell
# Approved same CPython version, using existing repo packages (no security changes).
$env:PYTHONPATH = "$PWD\src;$PWD\.venv\Lib\site-packages"
$runtimePython = 'C:\Users\berke\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $runtimePython -m pytest -q tests/integration/test_installer_lifecycle.py tests/integration/test_packaging_resources.py tests/integration/sqlite/test_migrations.py tests/unit/shared/test_config_logging_diagnostics.py tests/unit/shared/test_notification_config.py tests/unit/shared/test_window_close_config.py tests/gui/test_app_lifecycle.py
& $runtimePython -m pytest -q tests/integration/test_installer_lifecycle.py
& $runtimePython -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests packaging
& $runtimePython -m mypy
& $runtimePython -m mypy src/netsentinel/shared/paths.py src/netsentinel/infrastructure/windows_installer.py src/netsentinel/infrastructure/uninstall_data.py src/netsentinel/infrastructure/sqlite/database.py src/netsentinel/bootstrap.py packaging/build_installer.py packaging/installer_payload.py
git diff --check
& $runtimePython packaging/build_installer.py
```

The last command demonstrated missing-compiler behavior, not a successful build.
No installer/compiler download, OS security change, live network or VM execution
was performed. Refer to [frozen matrices and limitations](INSTALLER_UPGRADE_UNINSTALL.md).

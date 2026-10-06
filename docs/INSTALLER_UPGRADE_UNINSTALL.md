# NS-096 — Installer/upgrade/uninstall

Status (2026-10-06): **NS-096 COMPLETE**. Implementation/build, exact native
lifecycle acceptance and final automated closure gates **PASS**. Targeted 121,
installer-only 57, full offline 3683 passed/8 deselected; Ruff, configured/direct
mypy and diff checks PASS. Details are in the acceptance report.
Real ISCC 6.7.3 build/payload/SHA256 verification passed. Host installer wizard
was blocked by Application Control 4551; accepted native tests ran in a Windows
VM under fresh standard-user profiles on the existing OS. No pristine OS image
or pre-existing clean snapshot existed. TASKS.md does not explicitly require
that baseline; the clean per-user profiles satisfy its lifecycle test condition.
NS-097 is NOT STARTED; M17 remains IN PROGRESS. Schema 019 → 019; no new migration.

Native PASS: standard-user install without normal-flow UAC/admin prompt, launch
without real Python/Npcap, fresh data creation and program/data separation,
same-version 0.1.0 repair/reinstall, direct 0.1.0 → 0.1.1 installer-fixture upgrade
with config/DB hash preservation, one HKCU uninstall record and retained path,
KEEP/reinstall, explicit DELETE/reinstall, Cancel preserving both roots, Unicode
profile install/launch and DELETE preserving USERPROFILE. Unicode-specific UAC
was not separately recorded. Hashes and actual observations are in
[the final native acceptance report](INSTALLER_ACCEPTANCE.md).

The unsigned temporary 0.1.1 fixture uses the same AppId and PE version 0.1.1.0
but the **application payload remains 0.1.0**. This proves installer lifecycle,
registration/path replacement and data preservation; no functional application
code-version upgrade is claimed. Fixture binaries remain ignored test output.
Broader unreported native checklist recipes are not claimed as PASS.

## Frozen decision and matrices (before implementation)

Use Inno Setup 6 (Unicode) to wrap the existing PyInstaller x64 onedir bundle.
No second Python packaging system. Existing CI has Windows runners and offline
source tests; the compiler is an explicit build prerequisite, never downloaded
by the build script. Inno's non-administrative mode, stable AppId, AppMutex,
owned-file uninstall ledger and silent automation fit this small packaging layer.
No publisher/company, EULA, support URL or signature is invented.

| Install scenario | Expected behavior |
|---|---|
| Fresh standard user | Offline install, no UAC; Start Menu shortcut |
| No Npcap | Install succeeds; app shows existing degraded capture capability |
| Offline | No installer network request or telemetry |
| Unicode/spaces | Program and data paths work without shell interpolation |
| Running/hidden tray app | Close using File/tray Quit; installer waits/aborts; no force kill |
| Missing compiler | Clear error; no automatic download |
| Install failure | Framework rollback of owned files; user data untouched |

| Repair/upgrade scenario | Expected behavior |
|---|---|
| Same version repair | Rerun installer; restore all owned binaries; preserve all user data |
| Earlier app/config | Same AppId/one uninstall entry; replace payload; safe missing-field defaults |
| Schema 008/018 | Application startup applies existing migrations through 019 |
| Current schema 019 | Open unchanged; preserve history, preferences, consent and profiles |
| Future schema | Existing typed safe failure; no downgrade/reset/deletion |
| Running/tray app | Explicit Quit required before replacing files |
| Failed upgrade/start/migration | Data preserved; automatic rollback of migrated DB is not promised |

| Uninstall scenario | Expected behavior |
|---|---|
| KEEP (default, also silent) | Remove installed files/shortcuts/registration; leave data untouched |
| DELETE | Separate opt-in and destructive confirmation before any uninstall; canonical owned root only |
| Cancel | No uninstall/data mutation |
| Unsafe path/reparse/helper failure | Refuse deletion and abort uninstall; repair before retry, or choose KEEP |
| External export | Never delete outside canonical data root |
| Reinstall after KEEP/DELETE | Compatible retained state / new default state on first app start |

| Runtime | Resources | Persistent paths |
|---|---|---|
| Development | Python package resources | `%LOCALAPPDATA%\NetSentinel` (existing policy) |
| Portable | PyInstaller package resources in `_internal` | Same per-user root; never beside exe |
| Installed | Same PyInstaller payload/resources | Same per-user root; installer does not create it |
| Tests | Real package resources or frozen bundle fixture | Explicit path/LocalAppData fixture; never real user data |

No distribution-mode enum/marker is needed: all three already share the same
data policy. Resource APIs (`importlib.resources`/Qt icon resolver) remain separate.
Canonical paths: `netsentinel.sqlite3` (including WAL/SHM and DB-integrated
reputation cache), `config.json` (tray/notification/TI/storage preferences),
`netsentinel.log` and its bounded rotations under that root. Support exports use
the existing user-chosen Save dialog; no new default export/cache/temp directory.

## Identity, installation and build

Version comes only from `src/netsentinel/version.py` (`0.1.0`). Stable product
identity: `{62E3BFC6-ACAD-4FC3-94D8-46927D015096}`; keep it across builds.
Default program path: `%LOCALAPPDATA%\Programs\NetSentinel`; fixed per-user
scope, no system-wide option/elevation. Application remains `asInvoker`.
Start Menu shortcut and Windows uninstall entry; desktop shortcut opt-in.
No startup entry, service, scheduled task, file association or protocol handler.

Use Inno Setup **6.3+ Unicode**, an explicitly installed build prerequisite.
No compiler bootstrap/download is performed. Build command:

```powershell
uv sync --locked --extra dev --extra packaging
.\.venv\Scripts\python.exe packaging\build_installer.py --iscc 'C:\Users\berke\AppData\Local\Programs\Inno Setup 6\ISCC.exe'
```

The command builds fresh PyInstaller payload first, validates the allowlisted
layout/private-data/driver exclusions and license/001–019 presence, writes an
owned-file inventory, invokes ISCC without a shell, requires fresh output, then
emits `dist/NetSentinel-0.1.0-Setup.exe`, `.exe.sha256` and `.exe.manifest.json`.
The portable zip/checksum still ships separately. Version is read from the single
application version file. Output is ignored `dist/`; binaries are not committed.
Exact binary hash reproducibility is not claimed. Real build passed with user-installed
ISCC 6.7.3. Current installer is 37,535,265 bytes, SHA256
`f9c253eea2b605436fc685cdf2334c4d52233a3bb5ac01d6a358b633fae419a7`.
Approved same-version CPython runtime can add `--use-project-packages` to use the
fixed existing repo venv dependencies while retaining its own stdlib/native runtime;
no OS security setting is changed. Exact executed command/results are in the evidence report.
The unsigned pilot installer is not a public beta release. SmartScreen or
Application Control may block it/runtime DLLs; record this without disabling or
bypassing Windows security. Signing/distribution policy belongs to NS-097.

## Data and safety boundaries

Uninstall application and delete local user data are separate decisions. DELETE
includes monitoring history, alerts/incidents, config/preferences, profiles/trust,
reputation cache and local logs. Local deletion cannot be restored by NetSentinel;
secure erasure is not guaranteed. KEEP/reinstall preserves compatible data.
No installer schema manipulation, consent rewriting, backup, cloud upload, updater,
Npcap download/bundle/install/removal, firewall cleanup/rules or Defender exclusion.
Normal app startup owns all DB migrations and existing failure/degraded behavior.
Downgrade is not guaranteed. Copy closed local data before testing upgrades;
sanitized support export is not a history/database backup.

Installation destinations are dedicated folders under the current user's
LocalAppData\Programs, including Unicode/spaces. Outside paths, Program Files,
root paths and reparse ancestors are refused without requesting admin rights.
Install/repair never write/delete user data. Exact obsolete files recorded in the
prior owned inventory are pruned after deployment, comparing the new inventory;
no wildcard recursive install-directory removal. Unrecorded user-created files
are preserved; obsolete empty directories can remain. Inno tracks owned files
across reinstalls via appended uninstall logs. Framework copy rollback is
best-effort; post-install pruning and already-applied schema changes are not
transactional rollback promises.

Uninstall also validates the dedicated program path and every inventory file's
ancestors before framework removal. Unsafe install links or a missing inventory
abort both choices and require repair; a missing deletion helper alone still
allows KEEP. Inventory validation is not a cryptographic tamper-proof ledger.

Frozen startup creates a global desktop mutex before writers. Inno AppMutex
handles visible/hidden tray processes across sessions; inaccessible mutexes
conservatively refuse. SetupMutex prevents desktop startup during Setup; uninstall
creates the same setup marker. A separate short coordination gate protects the
desktop-marker check/creation and is held across data deletion. No app force-kill,
automatic close or restart. Older portable exe images are additionally checked
using a read-only Toolhelp process snapshot before DELETE. Development Python
GUI sessions must be quit manually; no installer marker is added to development.

DELETE invokes the existing packaged exe in a narrow maintenance-only mode before
Inno removes it; it does not import Qt/start writers or open/migrate the DB.
Windows SHGetFolderPathW supplies the current user's trusted LocalAppData;
environment/config/CLI cannot select the deletion path. The shared resolver's
canonical root is checked against that base, including absolute path, exact
NetSentinel child, lexical/resolved equality, every ancestor and all tree entries.
Any symlink/junction/reparse point refuses before mutation. Missing root is
idempotent; non-directory/access/helper/runtime failures abort DELETE/uninstall.
An I/O error during actual deletion can leave partial deletion: no restoration
promise. Whole-tree checks are not an atomic snapshot against hostile same-user
filesystem replacement. Windows `shutil.rmtree` avoids traversing junctions,
but no universal filesystem race protection is claimed.

Silent install/repair can use `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=...`;
silent uninstall always KEEP. DELETE remains interactive with two confirmations.
Cancel occurs before any deletion. A broken executable/helper can be repaired
or uninstalled with KEEP; it cannot silently discard data.

Final automated results, commands, changed-file inventory and all 104 requested
report items are in [NS-096 evidence report](INSTALLER_ACCEPTANCE.md).

See [native Windows checklist](INSTALLER_WINDOWS_SMOKE.md). Automated/source and
offscreen results do not prove native install/repair/upgrade/uninstall acceptance.

Framework references: [non-admin privileges](https://jrsoftware.org/ishelp/topic_setup_privilegesrequired.htm),
[AppMutex](https://jrsoftware.org/ishelp/topic_setup_appmutex.htm),
[uninstall events](https://jrsoftware.org/ishelp/topic_scriptevents.htm).
Deletion behavior reference: [Python 3.12 rmtree](https://docs.python.org/3.12/library/shutil.html#shutil.rmtree).

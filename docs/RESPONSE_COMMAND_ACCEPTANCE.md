# NS-100 acceptance — response command/privilege contract

Date: **2026-10-08 (Europe/Istanbul)**. Baseline `ea20629530b1119e6782bd1d26e0be32847901d6`.
Explicit user **GO NS-100** follows accepted planning and completed M17/NS-099.
**NS-100 COMPLETE.** Full default offline suite **4038 passed / 8 deselected**,
**91.17%** coverage; Ruff, configured/direct mypy, whitespace and bounded privacy
review PASS. M18 remains IN PROGRESS; NS-101–104 NOT STARTED.

## Delivered contract and exact acceptance

| Frozen NS-100 criterion / test | Evidence |
|---|---|
| Target/profile/expiry explicit | Required executable AND literal IP AND TCP/UDP remote port AND one typed profile; outbound BLOCK only, manual lifetime only; no domain/PID-only/IP-only/ranges/ANY/ALL |
| Automatic elevation absent | Read-only privilege protocol; no executor/helper/UAC/COM/shell call, no startup/selection/monitoring wiring; default boundary unavailable |
| Denied/degraded results typed | Fake PRIVILEGE_REQUIRED/ACCESS_DENIED/UAC_CANCELLED/READ_UNAVAILABLE/POLICY_LIMITED/BOUNDARY_UNAVAILABLE/REVALIDATION_REQUIRED; fixed NOT_ATTEMPTED receipts, exception/malformed reply fail closed |
| Ownership boundary documented | Exact originating manifest, unique UUID name, full fresh OS readback; no prefix/group adoption or foreign/modified-rule deletion; external-edit atomicity remains later gate |
| Validation | Unsafe/nonliteral/special/mapped targets, hostile path syntax, Unicode/long paths, exact enums/ints/UUIDs/UTC/file bounds, manual lifetime, immutable values and stale/future source tested |
| Fake privilege denial | CREATE and REMOVE assessed once only after exact confirmation; missing/stale/cancelled review or unavailable creation source makes zero probe calls |
| Scope/command serialization | Canonical deterministic bounded roundtrip; duplicate/unknown/missing fields at every depth, unsupported/future version, malformed/deep/invalid UTF-8 and oversized payload rejected with fixed errors |
| Preview/Undo contract and threat model | [Complete contract](RESPONSE_COMMAND_CONTRACT.md): source/file/generation/action binding, five-minute preview deadline, separate Undo command, cross-instance scope, human confirmation requirements and no traffic-effect verdict |

Two new modules contain no OS/file/network I/O. `ports.py` adds a read-only
protocol and domain imports. Existing desktop execution paths are unchanged.
No storage, migration, dependency, installer, native firewall operation or GUI
implementation is introduced. Current schema remains **019**.

## Verification

| Check | Result |
|---|---|
| Focused new tests | **205 passed**, 1.77s with coverage |
| New module coverage | **98.06%** combined: response domain 99%, review service 93% |
| Repository Ruff (`src tests packaging`) | **PASS** |
| Configured mypy | **PASS — 37 source files** |
| Direct mypy on three changed source modules | **PASS — 3 source files** |
| Full default offline suite + repository coverage | **PASS — 4038 passed, 8 deselected, 561.96s; 91.17%** (85% gate) |
| Whitespace/privacy/scope checks | **PASS — tracked/new-file whitespace; bounded 12-file changed-content scan, zero private-key/provider-token/secret-assignment/personal-path/SID/email findings; only NS-100 changes** |
| Native firewall/elevation | **NOT RUN / outside NS-100** |

The virtual environment's mypy startup was blocked by Windows Application Control
on its `_ctypes` DLL. Type checks and full-suite retry use the existing approved
bundled CPython 3.12.14 with repository `src` and existing `.venv/Lib/site-packages`
on PYTHONPATH. No install, policy change or bypass. Initial full-suite setup failed
on pytest sandbox temporary-directory permissions; that coverage run was stopped.
A `--maxfail=1` diagnostic confirmed the fixture error (97 passed/8 deselected/1
setup error); a fresh, checked-absent basetemp under ignored `build/` resolves it.
The sandboxed basetemp retry then stopped at an existing installer junction
fixture: **1322 passed / 8 deselected / 1 failure in 288.68s**; `mklink /J` was
denied before the deletion assertions. All three root/child/ancestor junction
cases passed outside the filesystem sandbox (**3 passed in 0.65s**), with source,
target and sentinel fixtures confined to a fresh repository `build/` directory.
The final full-suite run used that outside-sandbox execution and a fresh bounded
basetemp. No test expectation was changed or excluded. These earlier attempts
are **not** full-suite passes. Pytest cache is disabled for this run.
The final run passed all default offline tests; one pre-existing Scapy cryptography
deprecation warning remains. The eight live cases retain their normal default
marker exclusions; the failed junction cases were included in the passing run.
Privacy scanning is a bounded heuristic, not exhaustive secret detection.
Test-only endpoints/paths/UUIDs and hostile strings are synthetic fixtures; none
is observed user telemetry and no socket/provider/firewall call was added.

Reproduction using the existing approved runtime:

```powershell
$taskPython = Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
$env:PYTHONPATH = "$PWD\src;$PWD\.venv\Lib\site-packages"
$env:QT_QPA_PLATFORM = 'offscreen'
$env:PYTHONHASHSEED = '0'
& $taskPython -m pytest tests/unit/domain/test_response.py tests/unit/application/test_response_contract.py -p no:cacheprovider -q
& $taskPython -m ruff check src tests packaging
& $taskPython -m mypy --cache-dir .ns100-mypy-cache
& $taskPython -m mypy src/netsentinel/domain/response.py src/netsentinel/application/ports.py src/netsentinel/application/services/response_contract.py --cache-dir .ns100-mypy-cache
# Choose a fresh, nonexistent directory under this repository's ignored build/.
# Do not reuse an existing basetemp: pytest removes its contents.
$ns100BaseTemp = Join-Path $PWD ('build/ns100-offline-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $ns100BaseTemp) { throw 'Existing basetemp' }
& $taskPython -m pytest -p no:cacheprovider --basetemp $ns100BaseTemp -m 'not windows_live and not lab_live and not live_threat_intel' --cov=netsentinel --cov-report=term --cov-fail-under=85 -q --maxfail=1
git diff --check
```

## Remaining gates and delivery boundary

**In-product writes NO_GO.** The user-writable per-user payload/ledger is not a
trusted privileged boundary. Command/confirmation serialization cannot grant
administrator intent or ownership; native mutation and helper deployment need
independent approval/design/acceptance. Metadata/path syntax is not proof of a
safe local file. The full future ownership/OS-DB reconciliation, response GUI,
uninstall and controlled native traffic matrix remain NS-101–104 work.

M18 IN PROGRESS. **NS-101–104 NOT STARTED.** No NS-101 authorization, commit/push,
installer rebuild, signing, tag or release is implied by this implementation.
The accepted M18 planning document is unchanged and remains historical evidence.

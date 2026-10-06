# NS-097 acceptance and delivery evidence — 2026-10-06

**NS-097 — Signing/update distribution spike: COMPLETE as a spike.**
M17 IN PROGRESS. NS-098/099 NOT STARTED. This records an explicit unsigned pilot
policy, not a public-trust signature or authorization to publish.
[Decision and dated official sources](SIGNING_UPDATE_DISTRIBUTION.md).

## Exact task acceptance

TASKS purpose: “Beta artefact trust ve update politikasını karara bağlamak.”
Acceptance: “Signed workflow veya açık pilot policy; key ownership ve network
disclosure; explicit decision ve tamper sonucunun fail-closed olması.”
Test method: “Artefact verification dry-run ve tamper fixtures.”
Non-goals: automatic updater implementation and certificate purchase.

| Required gate | Evidence | Result |
|---|---|---|
| Signed workflow OR explicit pilot policy | Limited unsigned pilot with canonical channel, warning, hash/provenance limits; conditional public audience/license/M17 gate; production target documented | PASS via pilot policy |
| Key ownership | Validated publisher/project owner; role/custody/approval/recovery/renewal/revocation matrix; legal identity and named people explicitly unresolved | PASS design |
| Network disclosure | Zero app update requests; offline installer/integrity script; explicit browser and OS trust networking; TI consent separate; future disclosure | PASS design/source boundary |
| Explicit decision | Immediate limited unsigned/manual pilot; production Artifact Signing if eligible, OV fallback; broad release and self-signed public NO-GO | PASS |
| Fail-closed tamper | Canonical artefact copied; one byte changed at offset 8192; verifier exit 1 HASH_MISMATCH; original unchanged | PASS actual fixture |

## Actual artefact dry-run

Starting clean repository: HEAD = origin/main =
`e22ad5ca6c1bea3b80acbabec018986c23e397cb`,
`feat: add Windows installer lifecycle`. Remote main was also checked via
`git ls-remote` (read-only). No rebuild or signing mutation was performed.

| Check | Observed result |
|---|---|
| Canonical `dist/NetSentinel-0.1.0-Setup.exe` | 37,535,265 bytes |
| SHA256 before / after | Both `f9c253eea2b605436fc685cdf2334c4d52233a3bb5ac01d6a358b633fae419a7` |
| Native FileVersion / ProductVersion | `0.1.0` / `0.1.0` |
| `Get-AuthenticodeSignature` | Status `NotSigned`, SignatureType `None` → UNSIGNED |
| Canonical hash + PE version | INTEGRITY_OK, exit 0; signature_state NOT_CHECKED in offline tool |
| Correct hash/version/small manifest on copy | INTEGRITY_OK, exit 0 |
| Wrong expected hash (`0`×64) | HASH_MISMATCH, exit 1 |
| Expected PE version `0.1.1` | VERSION_MISMATCH, exit 3 |
| Missing artefact | IO_ERROR, exit 4 |
| Malformed manifest `{}` | INVALID_MANIFEST, exit 6 |
| Copy one-byte XOR at offset 8192 | HASH_MISMATCH, exit 1 |
| Tamper copy SHA256 | `0992f2e0cb72424c4c3e8398ed24cd30ab54509aa4178d9404dcae48fec7fc25` |
| Original preserved | Actual before/after hash equals canonical expected hash |

Temporary copy/manifest existed only inside a generated `build/ns097-*` test
directory and were cleaned by TemporaryDirectory. Original was opened read-only.
Ignored local machine-readable result: `build/ns097-evidence.json`; all relevant
observations are copied here so ignored output is not a delivery dependency.

**Signed pipeline execution: NOT RUN.** No public signer was supplied or enrolled;
SignTool was not on PATH and no signtool binary existed under Windows Kits
(only NETFXSDK). No SDK was installed. The documented SHA256/RFC3161/provider
metadata and Inno-generated-program signing sequence were reviewed against
official docs as command/config dry-run only. No self-signed certificate/root/
PFX was created. Public trust, timestamp-chain verification and signed tamper
invalidity are NOT claimed as tested. Exact TASKS permits the pilot alternative.

## Automated checks and boundaries

47 new integration test cases verify correct/wrong/invalid hashes, copy-only
tamper, missing file, no socket/subprocess for hash-only mode, malformed/duplicate/
oversize/missing-field JSON, deterministic schema fields, wrong manifest hash/
size/version/policy/channel/reference, signed assertion refusing trust, changed
file, byte/time bounds, remote UNC path refusal, sanitized CLI/exit and bounded
version subprocess timeout/static-source/path handoff. Real PE version and
UNSIGNED observation are the separate actual dry-run above; synthetic test bytes
are not signed executables. No production test certificate or trust-store change.

| Quality gate | Result |
|---|---|
| New-only tests | 47 passed (1.99 s) |
| New + installer lifecycle + packaging resources | 105 passed (3.17 s) |
| Full offline pytest | 3730 passed, 8 deselected (279.94 s); one existing Scapy FFDH deprecation warning |
| Ruff `src tests packaging` | PASS |
| Configured mypy | PASS, 36 source files |
| Direct mypy verifier + new tests | PASS, 2 source files |
| `git diff --check` | PASS; LF/CRLF informational notices only |
| Diff secret/certificate scan | PASS: no private-key/cert file extensions or credential/private-key content patterns in changed files; no cert created |

Commands at repository root:

```powershell
$env:PYTHONPATH = "$PWD\src;$PWD\.venv\Lib\site-packages"
$env:QT_QPA_PLATFORM = 'offscreen'
$env:PYTHONHASHSEED = '0'
$runtimePython = 'C:\Users\berke\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $runtimePython -m pytest -q tests/integration/test_release_verification.py tests/integration/test_installer_lifecycle.py tests/integration/test_packaging_resources.py
& $runtimePython -m pytest -q -m 'not windows_live and not lab_live and not live_threat_intel'
.\.venv\Scripts\python.exe -m ruff check src tests packaging
& $runtimePython -m mypy
& $runtimePython -m mypy packaging/verify_release.py tests/integration/test_release_verification.py
& $runtimePython packaging/verify_release.py dist/NetSentinel-0.1.0-Setup.exe --sha256 f9c253eea2b605436fc685cdf2334c4d52233a3bb5ac01d6a358b633fae419a7 --expected-version 0.1.0
git diff --check
```

Approved bundled CPython 3.12.14 with existing repo venv dependencies was used,
following NS-095/096's recorded runtime route; no Windows security setting was
changed. Ruff used repo venv Python. No new dependency/uv.lock change.

No `src/`, schema, version, .iss, builders or CI workflow changes. The 19 migration
resources remain 001–019; schema **019 → 019**, no migration or real user DB read/
write by the tool/dry-run. Network evidence is source boundary plus denied socket
fixture, not an OS-wide packet capture; explicit Windows trust queries may use
OS networking. No current application update hook was introduced. Historical
NS-096 VM acceptance is not re-run or repurposed as signed Windows acceptance.

## Requested 64-item report

| # | Requested item | Delivered answer / location |
|---:|---|---|
| 1 | Exact title | NS-097 — Signing/update distribution spike |
| 2 | Completion | COMPLETE as spike via explicit pilot policy |
| 3 | M17 | IN PROGRESS |
| 4 | Current installer | UNSIGNED / NotSigned, actual native query |
| 5 | Options | Unsigned, Artifact Signing, OV, EV, Store, self-signed researched |
| 6 | Current name | Azure Artifact Signing, formerly Trusted Signing |
| 7 | Eligibility | Exact current country/entity list in decision; actual publisher unknown; Türkiye absent |
| 8 | Artifact Signing cost | Basic $9.99/mo/5,000; Premium $99.99/100,000; $0.005 excess/signature |
| 9 | Key custody | Remote managed HSM/digest signing; no export; FIPS doc discrepancy recorded |
| 10 | OV viability | Conditional fallback; organization/country validation not assumed |
| 11 | OV cost | Current official vendor/term/token/cloud examples and conflicting quotes in option matrix |
| 12 | OV storage | Compliant hardware/HSM/cloud signing, no casual exportable PFX |
| 13 | EV | NO-GO premium for current requirements; no instant SmartScreen benefit |
| 14 | Self-signed | Dev/test only; public NO-GO; none created |
| 15 | Store | Deferred; current EXE/PE needs publisher signing; MSIX separate task |
| 16 | SmartScreen | Publisher + file reputation; signing does not guarantee no warning |
| 17 | Immediate beta recommendation | Limited explicit unsigned/manual pilot conditional on remaining release gates |
| 18 | Production recommendation | Artifact Signing Public Trust if eligible; otherwise CA OV managed HSM; individual alternative requires separate issuer validation |
| 19 | Public pilot | CONDITIONAL GO, no publication now |
| 20 | Broad public release | NO-GO until signer/licensing/channel/M17 gates |
| 21 | Key owner | Project owner as validated legal publisher; actual legal name unresolved |
| 22 | Authorization | Explicit reviewed release/protected environment; no ordinary push/PR signing |
| 23 | Key storage | Managed HSM preferred; no repo/.env/plaintext CI PFX/private secret |
| 24 | Rotation | Identity/cert renewal before expiry; recorded publisher/profile transitions; no fixed leaf pin |
| 25 | Revocation | Freeze, disable access, provider/CA revocation, notice, audit, rotate/recover; profile deletion insufficient |
| 26 | Pipeline | Clean source → quality → payload → sign/verify inner → Inno generated + outer signing → verify → final hash → manifest → approval/publish |
| 27 | Inner binary | Sign main owned NetSentinel.exe before packing; helper is same EXE mode; preserve vendor DLLs |
| 28 | Installer | Sign Setup.exe AND generated uninstaller/self-copies using Inno integration |
| 29 | SHA256 | Exact stream hash compare; SHA256 Authenticode file digest |
| 30 | Timestamp | Required RFC3161/SHA256; Microsoft TSA for Artifact Signing; issuer endpoint for OV |
| 31 | Final hash | AFTER final signing/timestamp; current unsigned bytes unchanged |
| 32 | Manifest | Strict 13-field v1 design/example/parser; source SHA; no min-version/updater/crypto bootstrap |
| 33 | Canonical channel | https://github.com/ByteGambit/NetSentinel/releases; accessibility/settings unresolved |
| 34 | Manual update | User visits/downloads/verifies/quits/installs; NS-096 upgrade lifecycle |
| 35 | Automatic updater | NO-GO / not implemented |
| 36 | Update networking | Zero automatic app requests; browser and OS security traffic disclosed separately |
| 37 | Privacy | Source IP/timing/browser context at channel; future app metadata requires prior explicit disclosure; TI consent separate |
| 38 | Downgrade | No automatic/schema downgrade; manual old binary unsupported absent exact compatibility |
| 39 | Rollback | Withdrawal distinct from compatible binary rollback; no automatic data rollback |
| 40 | Bad release | Canonical withdrawn notice, archive evidence, known-good compatible/forward fix, manual recovery preserving data |
| 41 | Commands/tool | Get-FileHash, PE VersionInfo, explicit Get-AuthenticodeSignature/SignTool; offline verify_release.py |
| 42 | Signature states | Conceptual trusted/untrusted/invalid/unsigned/error; timestamp separate; offline script NOT_CHECKED |
| 43 | Dry-run | Actual unsigned integrity PASS; signing commands/config review only, not execution |
| 44 | Tamper | Actual copy XOR one byte → HASH_MISMATCH exit 1 |
| 45 | Canonical unchanged | Same expected SHA256 before/after |
| 46 | Tests added | 47 cases in test_release_verification.py |
| 47 | Targeted | 105 passed; new-only 47 passed |
| 48 | Full pytest | See final quality gate row above |
| 49 | Ruff | PASS |
| 50 | Configured mypy | PASS / 36 files |
| 51 | Direct mypy | PASS / 2 files |
| 52 | Diff check | PASS |
| 53 | Secret/cert scan | See final quality gate row above; no cert generated |
| 54 | Schema | 019 → 019 |
| 55 | Migration | None; existing 001–019 untouched |
| 56 | Docs | New decision + acceptance; updated SECURITY/RELEASING/PRODUCT/ARCHITECTURE/ROADMAP/TASKS/README/packaging README |
| 57 | Sources | 23 dated official source rows, claims and caveats in decision document |
| 58 | Owner decisions | Legal identity/entity/country, signer budget/custody, named backup, license/audience, channel visibility/plan/protections |
| 59 | TASKS | Only NS-097 marked COMPLETE; frozen purpose/criteria unchanged; M17 remains IN PROGRESS |
| 60 | Commit | `feat: add release verification policy`; final immutable commit SHA supplied in delivery chat / `git log -1` |
| 61 | Push | Normal origin main push requested; actual final result supplied in delivery chat |
| 62 | HEAD/origin | Final verified result supplied in delivery chat; starting main equality recorded above |
| 63 | Working tree | Final verified result supplied in delivery chat; binaries/build output ignored |
| 64 | NS-098 | NOT STARTED; task block unchanged |

The commit's own SHA cannot be embedded inside that same commit without changing
it. The final chat records its immutable SHA and actual push/tree observations.
No release/tag/certificate purchase or signing credentials are created.

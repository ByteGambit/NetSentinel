# NS-104 â€” Firewall/uninstall acceptance

Date: 2026-10-09. Scope: **NS-104 only**, final M18 task. **COMPLETE**;
native, installer, quality and final cleanup gates passed in the stated scope.
No commit, push, tag or release is authorized or created.

## Frozen TASKS definition

The following definition is unchanged; its status is updated only after acceptance:

- **AmaÃ§:** GerÃ§ek Windows rule ve uninstall davranÄ±ÅŸÄ±nÄ± doÄŸrulamak.
- **YapÄ±lacaklar:** Owned rule lifecycle, rollback ve installer cleanup iÃ§in explicit VM acceptance ve dokÃ¼man ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** packaging/, docs/RELEASING.md, docs/SECURITY.md, tests/integration/.
- **BaÄŸÄ±mlÄ±lÄ±klar:** NS-096, NS-103.
- **Acceptance criteria:** Unrelated rules untouched; owned cleanup doÄŸrulanÄ±r; yetki yoksa kalan kurallar aÃ§Ä±k listelenir; automatic elevation yok.
- **Test yÃ¶ntemi:** Isolated VM rule lifecycle, upgrade/uninstall ve interrupted-action tests.
- **Kapsam dÄ±ÅŸÄ±:** Ãœretim aÄŸÄ±nda riskli test veya driver geliÅŸtirme.
- **BaÅŸlatma kapÄ±sÄ±:** Do not start before NS-099 and explicit response GO decision; M17 de tamamlanmÄ±ÅŸ olmalÄ±dÄ±r.

M17 and NS-100â€“103 were COMPLETE at entry. This user's explicit NS-104 VM-only
authorization opens this task, without opening NS-103's in-product privileged
write deployment gate. [NS-103 boundary](MANUAL_RESPONSE_UI_ACCEPTANCE.md),
[frozen custody](RESPONSE_LIFECYCLE_ACCEPTANCE.md),
[native adapter](RESPONSE_FIREWALL_ACCEPTANCE.md).

## Dedicated lab and bounded pre-state

Only the existing global VMware MCP was used for guest execution/power/file
transport; no MCP was added. Physical-host firewall APIs were never called.

| Item | Observed |
|---|---|
| Windows guest | Existing dedicated `Windows 11`, VMware, `DESKTOP-B18OKSK` |
| Edition/build | Windows 11 Home 25H2, **26200.9457**, x64 |
| Initial power/network | Windows and Kali stopped; their single NICs NAT |
| Test network | Existing VMnet1 host-only; Windows `192.168.140.128/24`, Kali `.129/24`; no default gateway |
| Controlled endpoint | Kali TCP echo, literal `.129:49191`, deadline 900 seconds, no Internet target |
| Profile | Public (mask4); Domain/Private/Public enabled throughout |
| Initial firewall | **476** rules; NetSentinel matching count **0** |
| Inventory digest | `dd21de4500264cf0e961f11d370631894eb0f8b148ebb21bada4afe9a854bdc1` |
| Existing install | Previous supported 0.1.0 M17 candidate; test-account canonical data root absent |
| Recovery | Existing `NS101-before-native-20261008` snapshot available; no snapshot revert |

The digest covers a sorted, bounded, complete INetFwRule3 getter inventory:
all NS-101 ownership fields including Description, Grouping, application,
addresses/ports, transport, direction/action, enabled/profile, interface,
edge/security and authorization properties. Profile/default policy was compared
separately. Raw unrelated names/descriptions, full inventory and ownership witness
remain guest-local and are removed at cleanup; only count/digest receipts are
retained. All 476 pre-existing rules are unrelated controls, compared in full
after each scenario; independent executable traffic supplies the traffic control.
Rules are excluded from the comparison only by the explicit operator's finite
recorded test IDs. This comparison is never a deletion/adoption authority.

An attempted whole-user-data backup was rejected by automatic approval review
because Public Documents could disclose sensitive existing history. No copy
occurred. A bounded read-only check instead confirmed the test account's original
data root was absent; no backup was necessary.

## Acceptance artifact

| Item | Current candidate |
|---|---|
| Version | **0.1.0**; no version bump or new release |
| Source | Base `7ee0aef71572fb6dc5a257384e6801ed7b6e710b` + uncommitted NS-104 changes |
| File | `dist/NetSentinel-0.1.0-Setup.exe` |
| Size | **37,638,469 bytes** |
| SHA-256 | `b46502c9f5cc7ded621e92edbd75c627915a9b32b62d3f8b8c9f7d654ddeb954` |
| Authenticode | **NotSigned**; not forged, signed or bypassed |
| Compiler | Inno Setup **6.7.3**, fresh PyInstaller payload |
| Schema | Sequential **001â€“020**, packaged migration guard corrected from019 |
| Previous candidate | 0.1.0, base `8242868`, schema019; 37,559,481 bytes; SHA-256 `39b14fe844c8aaa150a8b09229e0d63aaaf5ecc98b5bc8c54b419140be7749d9` |

Payload/inventory/private-data/license guards precede compilation; actual installer
PE, manifest, `.sha256`, size and signature are checked independently. The first
Inno compile exposed the required CreateCustomForm arguments; fixed against the
installed compiler's official example, then actual compilation passed. The
candidate is rebuilt from current source, not the previous M17 installer.

## Minimum uninstall policy implementation

Preserve-by-default follows [M18 section11](M18_RESPONSE_PLANNING.md#11-uninstall-policy-recommendation)
and [NS-096](INSTALLER_UPGRADE_UNINSTALL.md). Interactive uninstall displays a
bounded exact recorded rule/scope list **before** choosing KEEP/DELETE. Silent
uninstall preserves both firewall rules and local data, and writes the same list
to `%LOCALAPPDATA%\NetSentinel\firewall-uninstall-report.txt` when a data root
exists. Report contains sensitive local metadata; it is not a sanitized support
export and is not uploaded.

The per-user installer performs **no firewall mutation**, OS lookup, reconciliation,
migration or elevation. Its consistent read-only schema020 custody decoder reuses
NS-102's complete validated provenance, with bounded1024 operations and strict
links/paths/schema checks. Each unresolved CREATE lists its exact name, executable,
literal IP/port/protocol/profile, FINAL versus PREPARED-only, and historical
status; current OS presence is explicitly UNKNOWN, removal NOT ATTEMPTED. Complete
verified-removal evidence can retire that record from the remaining list. Missing,
edited, duplicate, denied or interrupted-without-receipt never become a successful
cleanup claim. Unknown/corrupt/over-budget custody refuses DELETE.

There is no optional installer Remove button: the shipped asInvoker composition
still lacks NS-100's trusted privileged requester. Adding one would violate the
current deployment boundary. Cleanup occurs **separately**, through explicitly
confirmed native acceptance Undo with retained FINAL + fresh full equality, or
an administrator's exact Windows Firewall inspection. No prefix/group deletion,
delete-anyway override or privileged persistent helper is added.

M18's ledger-loss acknowledgement was a recommendation, not a frozen acceptance
criterion. This implementation conservatively refuses DELETE while any recorded
rule may remain, instead of adding a new orphan-custody flow. KEEP is available.
After verified confirmed cleanup, the existing two-confirmation DELETE behavior
works. Firewall cleanup and local-data deletion remain separate actions; neither
decision implies the other. Installer/data helpers fail closed and retain evidence.

## Native lifecycle results

Test-only operators in `tests/fixtures/ns104/` are not shipped. The original
NS-101 VMware/hardware/name/authorization/network/profile guard remains mandatory.
No CLI supplied path becomes a production privilege or custody authority.
Each invocation starts a fresh process and opens persisted schema020/store UUID.

The controlled block companion uses the existing exact NS-101 lab validation seam
for **one** private literal `.129`, only inside that test process. Production
private-IP rejection is unchanged. Real-install custody tests use literal
`8.8.8.8` with the same exact test executable/TCP49191/Public/OUTBOUND/BLOCK scope;
**no traffic is sent to that public address**. This second specimen keeps the
packaged production custody decoder unchanged. Actual effect is measured by the
private companion, not inferred from Add or claimed for the public target.

| Scenario | Native evidence |
|---|---|
| Clean baseline | No stale rule/custody; exact client and independent control echo succeed |
| CREATE | Durable PREPARED then ATTEMPT/witness independently read from DB **inside the callback before native Add**; fresh full MATCHED readback, version2 FINAL durable; one exact candidate |
| Actual block | New C# fixture flow fails `WSAEACCES10013`; independent Python executable to same endpoint still echoes; rule never broadens |
| Process restart | Exact FINAL recovered, read-only reconciliation EXACT; inventory unchanged; verified CREATE audit count does not grow; no Add/replay |
| Confirmed Undo | FINAL required, distinct explicit confirmed REMOVE; fresh complete equality; native Remove, verified absence, durable rollback; client/control restored |
| External edit | Test operator changes only Description; EXTERNAL_MODIFIED, no adoption/repair/delete; field remains edited |
| Edited-rule test cleanup | Fresh mismatch equals precisely the operator's single recorded edit; operator restores only its own edit, then separately confirmed normal strict Undo; no production delete-anyway |
| External missing | Operator exact-remove after full MATCHED read; EXTERNAL_MISSING, no recreate/Add or false Undo success |
| Interrupted CREATE | Inject at FINAL persistence after native readback: ATTEMPT + exact witnessed OS rule, no FINAL; fresh process safely PROMOTED; no duplicate Add; created_at unknown retained |
| Interrupted REMOVE with receipt | Inject before final rollback commit: durable OS_VERIFIED + native absence; restart finalizes VERIFIED/REMOVED without another Remove |
| Interrupted REMOVE before dispatch | Durable PREPARED REMOVE + exact rule present; restart PENDING_REMOVE, no implicit retry; later new explicit confirmed Undo succeeds |
| Interrupted REMOVE without receipt | Inject immediately after OS absence but before durable readback receipt: ATTEMPT; restart UNKNOWN/ABSENCE_OBSERVED/outcome_unknown, **never successful cleanup** |
| Privilege denied | Actual native REMOVE under a reduced same-account thread token returns typed ACCESS_DENIED; exact owned rule remains; unrelated controls unchanged; original token restored |
| Ambiguous/duplicate | Disabled controlled foreign specimen uses same friendly Name and an independent internal UUID; native DUPLICATE â†’ AMBIGUOUS, no adoption/mutation; report lists original custody and DELETE refuses |
| Duplicate test cleanup | Operator checks the two complete COM inventory rows and fresh native filter scope, then removes only its recorded internal UUID; original exact owned rule remains; all476 controls equal |

The permission test uses Windows CreateRestrictedToken with only
DISABLE_MAX_PRIVILEGE and Administrators SID deny-only, scoped
ImpersonateLoggedOnUser/RevertToSelf. It does not use SANDBOX_INERT, create
credentials, change policy, disable security, raise UAC or launch a service.
IsUserAnAdmin is false during dispatch and the successful identity-restoration
receipt is checked. [Microsoft API](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken).
This is an actual denied effective security context, not a mocked backend result.
Repeated with the real-install schema020 custody: native ACCESS_DENIED, one exact
rule retained, and the same reduced thread's production custody report explicitly
lists that remaining rule and refuses DELETE. After denial the packaged desktop's
Qt/SQLite/GUI self-test still passes; offline NS-103 denied-path/local-trust gates
also pass. A fresh full desktop/monitoring session under a reduced child token is
not claimed, because that child never initialized successfully.
Linked-token and same-account desktop seams were unavailable; a reduced child
process failed DLL initialization before mutation. Security/desktop ACLs were
not changed to force that child to run. Fresh standard-user installer history
remains NS-096 evidence, not a new NS-104 standard-user claim.

Failure injection is deterministic at exact repository persistence events; it
does not kill arbitrary Windows processes. During this long run Windows also
closed unexpectedly several times; bounded VMware logs show clean VIX shutdown
activity but the external cause is unconfirmed. Each restart validated persisted
custody and the unrelated inventory. No VM security setting was relaxed.
One control listener hit its900-second deadline after a verified removal; a fresh
listener and separate verified-absence/restored-connectivity receipt completed
that check. A test harness audit assertion initially inspected only its first100
rows and failed **before Add**; fixed to bounded cursor pagination, with an offline
regression. These failed attempts are not counted as passed native mutations.

## Installer native results

| Scenario | Evidence |
|---|---|
| Current clean install | Old candidate removed KEEP; current candidate installed, native Qt/icon/SQLite/GUI self-test PASS, fresh20 and18â†’20 smoke PASS |
| No-owned KEEP | Actual silent uninstaller removed application; DB SHA-256 `64a022c984579e4573180be9e108e10f9505ab31142762e840020edb9a25e1a1` unchanged; local recovery list honest; reinstall succeeds |
| No-owned DELETE | Actual interactive report â†’ DELETE â†’ destructive OK â†’ Inno program-removal Yes; program and canonical test-data root removed; no cleanup claim or firewall call |
| Supported previous candidate | Fresh previous0.1.0 install opens schema019 self-test; no unsupported020 downgrade attempted |
|019â†’020 upgrade | Controlled history marker in old schema; new candidate replaces old payload; app migrates20; marker preserved, config SHA-256 `cc895f04e163e060c592ecce5fa48257e3fcf26f6eed9c5f80d587f1d5216178` unchanged |
| Repair/upgrade with FINAL | Same-version current candidate replacement preserves complete response store/operations/audit hash `9c5a8fe40aa97211b3faa959f13044c6fa1f062a849b7a5bd42a2c42ccda5e89`; schema20, config/history preserved; no Add/duplicate/removal |
| Packaged restart with FINAL | Real packaged desktop self-test PASS, then separate native reconciliation EXACT; verified CREATE audit count unchanged |
| Owned/modified uninstall KEEP | Actual interactive report/KEEP/program-removal confirmation completes; exact edited rule still present, no repair/deletion; complete custody/audit hash `ef3e4f876859f89fba5544ec072db836822eea2a7b86cfe23060a0b6b0fcdd6a` unchanged; recovery list retained |
| Insufficient cleanup permission | Installer has no privileged cleanup path; real effective-token REMOVE denial leaves rule intact and readable/listed; packaged confirmed DELETE returns1, DB unchanged, no false cleanup |
| Reinstall after owned KEEP | Ledger retained, test operator restores only its exact edit, native reconciliation EXACT, no duplicate CREATE; separately confirmed strict Undo then verifies absence |
| Final no-owned DELETE | After verified native Undo, real interactive DELETE removes program/data; original previous candidate reinstalled without launching, original data-root absence restored |

Installer runs used an **already administrative VMware guest token**. Inno logs
show administrative install mode No, HKCU/per-user installation; no new approval
or elevation is requested. PE/requestedExecutionLevel remains asInvoker and
PrivilegesRequired=lowest. Do not infer fresh standard-user OS acceptance from
these administrative-token observations.

Real UI operator binds to the launched canonical uninstaller's process tree,
checks exact expected captions/buttons, supports this guest's Turkish Windows
MessageBox labels and waits for actual uninstaller termination. Unexpected
dialogs/timeouts fail closed. Early operator attempts missed localized buttons
and the separate built-in program-removal confirmation; cancelled without deleting
data, then rerun with explicit full dialog checks. One old installer invocation
was refused while the completed uninstall confirmation still held its mutex;
closing that confirmation and retrying succeeded. Not counted as an upgrade PASS.

## Verification, cleanup and exit decision

[Bounded actual guest receipts](NS104_ACCEPTANCE_RECEIPTS.json) preserve selected
native scenario/status/count/digest, real dialog decisions and self-test outcomes
with each original receipt's SHA-256. The archive deliberately excludes raw
firewall inventory, Description/witness, DB payloads, command lines and credentials.
Failed operator attempts remain distinguishable from later passing checks.
Installer state hashing initially encountered a SQLite BLOB serialization error;
the test-only encoder was fixed and the full pre/repair/post comparison rerun.
The receipt archive is review evidence, not tamper-proof/forensic custody.

| Quality gate | Final result |
|---|---|
| Targeted installer/custody/schema/packaging | **224 passed**,37.26 s; new NS-104 tests19 |
| Full offline suite | **4711 passed /9 live deselected**,695.35 s; one existing Scapy cryptography deprecation warning |
| Coverage | **91.32%**;28916 statements,2510 missed;85% floor passed |
| Ruff | `src tests tools packaging pyproject.toml --no-cache` PASS |
| Configured mypy | **38 sources PASS**; configuration unchanged |
| Additional mypy | New uninstall report/data/entry **3 sources PASS** |
| Whitespace | `git diff --check` and bounded new-file checks PASS |
| Privacy | Changed/new text filesâ‰¤128 KiB each; credential/private-key/control/raw-custody checks and manual review PASS |
| Package | **1120 payload hashes,0 mismatches**; full manifest/sidecar/policy equality; sequential001â€“020; no private/test/driver payload |
| PE/privilege | Installer **and** application manifests extracted as resources: **asInvoker**; Inno PrivilegesRequired=lowest; Authenticode NotSigned |

Test runs use approved CPython3.12.14 with existing repo dependency packages,
explicit workspace `src` on PYTHONPATH, fresh ignored build basetemp and disabled
pytest cache. Initial invocation/path mistakes failed collection and are not PASS
claims. Windows junction fixtures require an approved unsandboxed test invocation;
only workspace test directories, no live/host firewall tests. The final full suite
excludes windows_live, lab_live and live_threat_intel explicitly.

Final native inventory is **476â†’476**, identical full-getter digest above, identical
profile/default policy, **0 matching/temporary rules**. Fresh fixture/control
connectivity restored. Kali listener stopped only after validating exact PID,
start ticks, command identity and source hash; endpoint absent and listener files
deleted. Windows test root removed only after checking its exact resolved path,
all descendants for reparse points and no remaining test rule. No temporary guest
runtime, scripts, receipts, logs or credentials remain. Original installer0.1.0
restored, canonical data root absent as before, one per-user registration,
app/uninstaller processes0, NetSentinel services/tasks0, autostart absent,
execution policy still Restricted. Both guests gracefully stopped; exactly their
two single NIC connectionType lines restored **hostonlyâ†’nat**. Existing VMnet1
and host firewall/security settings were untouched. Review installer/build logs
and sanitized receipt archive remain local; disposable host transport files removed.

Known limits remain: measured Windows build/Public/TCP and new-flow effect only;
no instant termination of existing flows, other-build/IPv6/VPN/sleep claim, new
fresh standard-user installer claim, security-policy bypass, malicious-local-admin
ownership guarantee or atomic Add/Remove compare operation. A privileged admin can
forge/copy a witness. Add preflight TOCTOU and compare-to-Remove race remain.
Current in-product privileged write deployment is **NO_GO**, unchanged from NS-103.

Frozen criteria passed: unrelated rules untouched, exact owned cleanup verified,
remaining rules explicitly listed under real insufficient effective permission,
no automatic elevation. **NS-104 COMPLETE; M18 COMPLETE.** Limited unsigned pilot
remains **CONDITIONAL_GO** under NS-097 owner/audience/license/distribution gates;
broad public release **NO_GO** (unsigned/signing/distribution gates). Automatic
response remains **deferred/absent**. Helper/service/scheduled task/driver/WFP
development **NONE**. Tag/release and commit/push **NONE**.

Changed files: `packaging/NetSentinel.spec`, `NetSentinel.iss`, `entry.py`,
`INSTALLER_POLICY.md`; infrastructure `uninstall_response.py`, `uninstall_data.py`;
`tests/integration/test_response_uninstall.py`; five test-only operators in
`tests/fixtures/ns104/`; this report/receipt archive, TASKS, RELEASING and SECURITY.

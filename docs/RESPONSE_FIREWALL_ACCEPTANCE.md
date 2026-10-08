# NS-101 acceptance — Windows Firewall adapter

Date: **2026-10-08 (Europe/Istanbul)**. Baseline:
`dc96e906a7095a8e26cc2027ba93eedb55ac184c` (NS-100 ownership handoff).
The user explicitly authorized **NS-101 only**, including a native test only in
the dedicated Windows test VM. **NS-101 COMPLETE: adapter/offline acceptance and
explicit isolated VMware native lifecycle/traffic acceptance PASS; full lab
cleanup verified. Production validation unchanged.** NS-100 COMPLETE;
NS-102–104 NOT STARTED. In-product writes remain NO_GO. Acceptance is approved
for an NS-101-only commit and normal push to main; tag/release NONE.

## Exact task definition used

From `docs/TASKS.md`, unchanged scope and criteria:

> NS-101 — Windows Firewall adapter

- **Amaç:** Dar owned firewall kuralını Windows'ta yönetmek.
- **Yapılacaklar:** Structured COM/typed Windows API ile add/read/remove adapter ve sanitized permission errors ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/infrastructure/, src/netsentinel/application/ports.py, tests/unit/infrastructure/.
- **Bağımlılıklar:** NS-100.
- **Acceptance criteria:** Program/IP/port/profile bounded; shell injection yok; unrelated rule'a dokunmaz; mevcut akışı hemen kesme garantisi verilmez.
- **Test yöntemi:** Fake API ve explicit isolated Windows rule tests.
- **Kapsam dışı:** Custom WFP driver veya process termination.
- **Başlatma kapısı:** Do not start before NS-099 and explicit response GO decision; M17 de tamamlanmış olmalıdır.

Read before implementation: TASKS, M18_RESPONSE_PLANNING,
RESPONSE_COMMAND_CONTRACT, RESPONSE_COMMAND_ACCEPTANCE, domain.response,
application.ports; all NS-100 ownership domain/port tests, plus PRODUCT,
ARCHITECTURE, SECURITY and ROADMAP rules. The historical planning decision does
not override the user's current, narrow NS-101 authorization.

## Files and architecture

| File | Responsibility |
|---|---|
| `src/netsentinel/infrastructure/windows_response_firewall.py` | `ResponseFirewall` implementation, injected API/target guard/UTC clock, caller-held manifest, typed receipts, per-instance mutation lock |
| `src/netsentinel/infrastructure/windows_firewall_com.py` | Lazy native session; detached structured rule construction, full mapping, fresh bounded enumeration, sanitized HRESULTs |
| `src/netsentinel/infrastructure/windows_response_target.py` | Independent local/final-path/reparse/file metadata guard; required trusted ordinary-desktop classifier, held handles |
| `tests/unit/infrastructure/test_windows_response_firewall.py` | Fake port lifecycle, ownership/drift/failure and scope tests |
| `tests/unit/infrastructure/test_windows_firewall_com.py` | Fake COM property/QI/mapping/collision/apartment/HRESULT tests |
| `tests/unit/infrastructure/test_windows_response_target.py` | Fake file/drive/final-path/classifier/handle/identity tests |
| `tests/integration/test_response_firewall_vm.py` | Explicit isolated VM lifecycle harness; doubly live-marked and excluded by default |
| `tests/unit/infrastructure/test_response_firewall_vm_harness.py` | 44 offline lab allowlist, activation, restoration, native mapping/manifest and COM proxy lifetime tests |
| `tests/fixtures/ns101/TcpClient.cs` | Dedicated bounded TCP client, compiled only in the guest with the trusted Framework compiler |
| `tests/fixtures/ns101/tcp_listener.py` | Temporary Linux listener bound only to its configured RFC1918 address/high port |
| `pyproject.toml`, `uv.lock` | Optional Windows-only `firewall` extra, pinned `pywin32==312` with locked wheel hashes |
| `docs/TASKS.md`, `docs/RESPONSE_COMMAND_CONTRACT.md`, this report | Current NS-101 status, implementation boundary and acceptance evidence |

No application/domain API changes were needed. `WindowsResponseFirewall` satisfies
the existing protocol structurally. Callers explicitly inject a factory returning
an operation-local session and an independent target guard. There is no permissive
default guard, no startup/composition/monitoring/UI wiring, worker, global mutable
COM singleton, repository or automatic operation.

The native binding uses **INetFwPolicy2 / INetFwRules / INetFwRule**, requiring
**INetFwRule3** (including Rule2 fields) via explicit QueryInterface. The fixed
policy/rule interface GUIDs come from Microsoft's SDK header. pywin32 dynamic
Automation is infrastructure-only; no generated makepy cache is used. Sessions
balance `CoInitializeEx(COINIT_APARTMENTTHREADED)` / `CoUninitialize` on the calling
thread, release operation-local references, reject cross-thread API use/release,
and refuse an incompatible apartment.
No COM object crosses `ResponseFirewall`; no DLL or dependency is automatically
installed. Normal/default dependency sets and the installed package are unchanged.
[Microsoft Rule3](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule3),
[SDK interface definitions](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/netfw.h),
[pywin32](https://pypi.org/project/pywin32/).

## CREATE and ownership handoff

CREATE requires the exact `FirewallCreateRequest`; fingerprint/UTC age/source
availability are checked before native work. A trusted target guard is required.
The Windows guard checks DRIVE_FIXED before opening components, rejects system/
WindowsApps/self/known shared-host paths, and requires independent ordinary-desktop
classification. It does **not** infer service/package identity from a filename.
A production trusted classifier/privilege boundary remains unavailable; the
isolated harness classifies only its own exact disposable PE fixture bytes.

All ancestors are opened with OPEN_REPARSE_POINT/BACKUP_SEMANTICS, checked for
reparse/type/final-path equality and held against rename/deletion. The final file
is held without write/delete sharing; current volume serial, file index, size and
UTC mtime must equal the preview recipe. Missing/changed/unverifiable targets
refuse creation. The file is never executed, hashed implicitly, loaded as a DLL
or resolved over a network. Handles close on success, refusal and exceptions.
This metadata/handle guard is not loaded-image identity or protection against an
administrator modifying/replacing a target after the operation.

The exact rule is one enabled **OUTBOUND/BLOCK** conjunction of one executable,
one public literal IPv4/IPv6, explicit TCP/UDP, one remote port and one selected
Domain/Private/Public profile. Native values are direction **2**, action **0**,
protocol **6/17**, profile **1/2/4**. No all-program/address/port/profile fallback,
DNS lookup, hostname conversion, subnet expansion or second-family rule exists.
The name is exactly `NetSentinel:<canonical-rule-uuid>`; the description is
`NetSentinel response v1 <uuid>`, grouping empty. No test-specific alteration of
the frozen name/description contract is introduced.

The adapter refuses any existing identity, even an equal rule. It re-enumerates
after target validation. The native API constructs a detached complete rule,
sets protocol before ports, verifies every supported detached property including
unwritten API defaults, and rechecks collision immediately before Add. It invokes
the adapter's current-confirmation callback directly before native mutation,
after potentially slow construction and reads. Add is never a blind upsert.
[Microsoft Add semantics](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrules-add).

After Add, the adapter independently enumerates and reads the OS rule again.
Only one complete equal snapshot produces VERIFIED/PRESENT_ENABLED and the exact
originating `OwnedFirewallRuleManifest` (original request, actual readback,
creation-dispatch/verification UTC times). Context cleanup must succeed before
ownership is handed off. Submission, exception, missing/duplicate/mismatched or
unreadable state produces **no manifest**. There is no automatic cleanup/delete
after an unverified create: ownership was not established.

## READ, normalization and REMOVE

READ requires the caller-held originating manifest and creates a fresh native
session. It never adopts or reconstructs ownership from discovered UUID/name/
prefix/group/description. Enumeration reads all identities up to 16,384 rules;
partial/inconsistent/over-budget enumeration never proves absence. Name matching
also detects case aliases; equality of the actual name remains exact. Duplicate
discovery is reported without fabricating an expected snapshot.

Every unique candidate reads all snapshot fields independently: name, full
program/IP/protocol/port/profile/direction/action spec, description/grouping,
enabled, service, local addresses/ports, ICMP, interfaces/types, edge/options,
package ID, local owner, local/remote user and remote machine authorization, and
secure flags. Missing properties are unsupported; malformed data cannot become
equal. No default is substituted for an unavailable getter. Successfully read
NULL optional BSTRs mean empty text and VT_EMPTY interfaces mean no restriction.
Complete IPv4 /32/full netmask and IPv6 /128 host representations normalize to
one literal host; shorter masks/lists/keywords/ranges refuse support. Unicode,
spaces and valid shell-looking filename characters remain structured Unicode
data. Path case/spelling is never silently normalized or truncated.

MATCHED/MISMATCH carry framework-independent complete snapshots. ABSENT,
DUPLICATE, ACCESS_DENIED, READ_UNAVAILABLE, BACKEND_UNAVAILABLE, UNSUPPORTED and
INVALID_REQUEST remain typed, without COM objects or raw exception details.
Broader/ALLOW/inbound shapes cannot fit the frozen domain snapshot and return
UNSUPPORTED; they are never treated as a partial equality match.

REMOVE requires the exact `FirewallRemoveRequest`, originating manifest and a
separate confirmed command bound to original rule/store/spec/file/source identity.
An expired source or missing executable does not prevent owned Undo. The adapter
performs its **own** fresh full unique read during that call. Every mismatch,
disabled rule, changed restriction/profile/program/IP/protocol/port/action/
direction, missing/foreign/case-alias/duplicate/unsupported state refuses removal.
Caller-cached MATCHED values confer no authority. The adapter reuses NS-100's
`removal_readback_matches` with its own actual read-start/read-completion/current
UTC times; clock reversal or inconsistent read timing refuses dispatch.

The native removal boundary repeats full unique equality, then invokes the
current-confirmation callback and Remove on the exact manifest name. No prefix/
UUID-only/name-only/similarity deletion exists in the adapter. An independent
post-removal enumeration must prove absence before VERIFIED/ABSENT. Initial
absence means EXTERNALLY_MISSING/NOT_ATTEMPTED; repeated Undo does not invent a
successful deletion. Remaining or unreadable poststate stays OUTCOME_UNKNOWN.
[Microsoft Remove semantics](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrules-remove).

## Failure, privilege and security review

| Condition | Behavior |
|---|---|
| Wrong untyped port argument | Fixed TypeError before any API; no fabricated command identity/result |
| Stale confirmation/source/file, target/classification failure | NOT_ATTEMPTED; zero mutation, no fallback |
| COM missing/unregistered, platform/apartment/interface unsupported, service/read unavailable | Distinct typed refusal/read status before dispatch |
| Access denied during pre-read/target validation | NOT_ATTEMPTED/ACCESS_DENIED |
| Definitive native permission/argument/conflict failure after submission starts | FAILED with typed access-denied/operation-failed/ownership-conflict reason |
| Transport/reply loss, generic mutation exception, verification mismatch or unavailable poststate | OUTCOME_UNKNOWN/READBACK_UNAVAILABLE; no ownership or success claim |
| Duplicate/foreign/modified/missing rule | Refuse; no adoption, re-enable, repair, recreate or compensating ALLOW |
| Busy adapter | Nonblocking per-instance lock refusal; no overlapping local mutation |

HRESULT/Automation SCODE classification discards free text and nested native
exception details. A successful submission followed by permission denial during
verification remains OUTCOME_UNKNOWN, rather than mislabelling the mutation as
FAILED. No raw target, exception, command/manifest bytes or rule
inventory is logged/exported by the adapter. The application stays **asInvoker**.
There is no UAC prompt, runas retry, helper, elevated GUI, service or scheduled
task. A real permission denial is returned honestly; security policy is untouched.

Security review: injection absent (no shell/PowerShell/netsh execution or command
construction); collision refusal; bounded hostile selectors; no accidental
wildcard/all-program/all-address/all-profile/inbound rule; exact originating
manifest handoff and full fresh equality; duplicate ambiguity refusal; no foreign
rule deletion by discovery; no privilege grant from confirmation or metadata;
unknown verification remains unknown. Fake tests change every supported ownership
field, including controls beyond the visible selector, and assert zero removal.

**Native external-edit atomicity limit:** COM Add/Remove do not expose atomic
compare-and-add/delete. Preflight and immediate native rechecks reduce races;
a hostile concurrent administrator replacing a rule between the final comparison
and Remove cannot be excluded. A per-instance lock serializes only this adapter,
not other processes/admin tools. The manifest is sensitive caller-held evidence,
not cryptographic provenance or admin authorization: trusted originating custody
is a prerequisite. Forged manifests/exact cloned rules cannot be authenticated by
COM fields alone. No production safety claim is made across this boundary.

Synchronous COM calls have no application-enforced hard cancellation timeout;
enumeration/memory is bounded and no retry/polling worker exists. OS getter
normalizations/defaults/QI and handle behavior still require native VM evidence.
VERIFIED is configured rule state only: not traffic effect, immediate existing-
flow termination, restored connectivity, active profile or GPO/MDM applicability.
There is no local-policy/firewall-enabled/default-rule modification to force effect.

## Local VMware native closure — 2026-10-08

**PASS. NS-101 COMPLETE.** The user explicitly approved the test-only lab seam.
TASKS does not require a public Internet endpoint or VPS. Production
`domain.response._remote_ip`, all production source files, and the production
command/ownership contract remained unchanged during this follow-up.

`ns101_lab_scope` is a function-scoped pytest fixture used only by the opt-in
native test. It verifies authorization/recovery, exact guest name, VMware hardware,
actual on-link local interface/subnet, no interface gateway and active selected
profile before entering `_exact_lab_validation`. Inside `monkeypatch.context()`
only `domain.response._remote_ip` is replaced, accepting exactly the configured
canonical RFC1918 endpoint literal. All other addresses, including other private
and public addresses, names, ranges, subnets and wildcards are rejected by that
exception. No broad `is_private` rule, production config flag, domain type,
runtime composition or user-facing path was added. Command construction and
`dataclasses.replace` during actual COM readback both use the same exact exception;
all other typed/confirmation/file/full-equality/ownership checks remain active.
The fixture remains active through manifest-required removal and verifies original
validator identity and private-IP rejection during teardown. A fresh independent
guest process also rejected the private target while the fixture was active.
The post-pytest runner confirmed restoration and private rejection. Offline tests
cover success and exception restoration. No lab manifest was serialized/persisted.

Current opt-in guest configuration (the later historical public-endpoint example
is superseded):

```text
NETSENTINEL_NS101_VM_NAME=<exact authorized guest computer name>
NETSENTINEL_NS101_VM_AUTHORIZED=YES
NETSENTINEL_NS101_VM_SNAPSHOT_READY=YES
NETSENTINEL_NS101_HOST_ONLY_AUTHORIZED=YES
NETSENTINEL_NS101_LAB_IP=192.168.140.129
NETSENTINEL_NS101_WINDOWS_LAB_IP=192.168.140.128
NETSENTINEL_NS101_LAB_SUBNET=192.168.140.0/24
NETSENTINEL_NS101_LAB_PORT=49191
NETSENTINEL_NS101_PROFILE=public
```

Select only `tests/integration/test_response_firewall_vm.py` with
`-m 'windows_live and lab_live'`, a checked-absent guest basetemp whose parent
exists, and pytest cache disabled. The Linux listener takes its literal address,
port and guest-local receipt path as positional arguments. No lab switch is
read by production code.

The former inert PE was replaced with the dedicated C# TCP client fixture. The
guest's existing Microsoft .NET Framework compiler built one executable with
the validated lab IP and port baked into constants; it accepts no runtime
arguments or other targets. It uses `IPAddress.TryParse` / literal `IPEndPoint`,
one TCP connection and one-byte echo, bounded connect/send/receive timeouts, no
DNS and no other network behavior. Exit 0 means connection/echo succeeded;
exit 3 means Winsock access denied; timeout, other failure and bad input have
distinct nonzero outcomes and cannot satisfy the BLOCK assertion. The existing
independent target guard pinned the exact compiled executable identity and bytes.
The separate guest Python interpreter provided unrelated-program control traffic.

| Native environment | Actual value |
|---|---|
| Windows client | Existing dedicated **Windows 11**, Home build **26200.9457**, VMware20,1 |
| Linux endpoint | Existing Desktop **kali-linux-2026.2-vmware-amd64**, kernel 7.1.5+kali-amd64; guest UID 1000 |
| VMware network | Existing **VMnet1 host-only**, **192.168.140.0/24** |
| Windows lab address | **192.168.140.128/24** |
| Linux lab address / port | **192.168.140.129:49191**, TCP |
| Routing | No default route in either guest while testing; no public inbound, router forwarding or third-party test target |
| Listener | Existing `/usr/bin/python3`, PID **1184**, bound only to the Linux lab IP; script hash `c0ac2b8caaab377a851162c60e3fac6e6c3fc84930df120dc8c6d84ca0fb8b44` |
| Windows privilege | Existing elevated guest token; MpsSvc Running; no UAC request, elevation helper, policy/Defender change or privilege retry |
| Selected profile | **Public** (active mask 4); one profile only |
| API | Native pywin32 312 structured `INetFwPolicy2` / `INetFwRules` / `INetFwRule3` Automation backend and file-handle target guard |
| Source equality | **211** packaged source/config/fixture files hash-verified in guest, including unchanged production implementation |

The existing global VMware MCP was used. Desktop discovery found the usable Kali
VM; no OS/VPS was created or downloaded. Its config entry was registered under
**Kali**, matching the user's PasswordVault account keys, without printing or
copying credentials. The turn's original MCP connection retained its old inventory,
so a temporary client opened a fresh session to the **same configured global MCP
entry point/config**, not a new MCP definition/installation or direct vmrun/SSH
workflow. Existing credential-store handling stayed inside that provider. Both
VMs were normally stopped before temporarily switching only their existing NIC's
connectionType from NAT to host-only. VMnet1 and host firewall settings were untouched.
The existing Windows recovery snapshot remained available. The guest dependency
package reused the approved runtime and uv.lock SHA-256-verified wheels; no host
Firewall COM call or host pywin32 installation was made.

| Required acceptance step | Result |
|---|---|
| PRE connect, same dedicated executable | **PASS**, exit 0 and expected echo |
| CREATE | **VERIFIED**, one exact executable + Linux literal + TCP 49191 + Public + OUTBOUND/BLOCK/enabled |
| Fresh unique readback | **PASS**, complete expected snapshot equality and separate READ MATCHED |
| Originating manifest | **PASS**, returned only with verified CREATE; exact request bound; held in memory only |
| Scoped BLOCK, same executable/endpoint | **PASS**, exit **3**, `NS101_SOCKET_ERROR:10013` (**WSAEACCES**) |
| Unrelated control | **PASS**, separate Python executable received the endpoint echo before/during/after blocking |
| Confirmed REMOVE with originating manifest | **VERIFIED**, adapter's own fresh full equality and native-boundary recheck required |
| Fresh absence / stale duplicates | **PASS**, READ ABSENT; independent fresh enumeration found zero `NetSentinel:*` rules |
| Restored connectivity, same executable | **PASS**, exit 0 / echo after removal |
| Unrelated rules / profile/global policy | **PASS**, full before/during/after inventory and policy equality |
| Validator restoration | **PASS**, original function identity and default private-target rejection after pytest |
| Full cleanup | **PASS**, details below |

The final native run was **1 passed / 1438 deprecation warnings in 14.17s**;
pytest exit 0, with no access-violation diagnostic. Warnings are the pinned
pywin32 `MakeIID` deprecation in full enumerations and backend QI; none were
suppressed and production API code was not changed for this warning. One initial
runner preparation attempt failed on a missing basetemp parent before mutation;
the VM-only runner created that parent for the next attempt. A preliminary full
lifecycle passed but emitted first-chance access-violation diagnostics during WMI
proxy teardown. The test harness now releases its WMI and policy proxies before
`CoUninitialize`; the final native rerun was clean of those diagnostics. A new
offline regression verifies proxies are released while their apartment is alive.
No genuine production adapter defect was found or silently redesigned.

The native firewall inventory hash before and after each complete lifecycle was
`dd21de4500264cf0e961f11d370631894eb0f8b148ebb21bada4afe9a854bdc1`.
Both cycles created and removed one rule each, with no overlapping/stale rule.
There were 476 unrelated rules before and after; the intermediate inventory
contained exactly one additional owned test rule. The listener recorded 12
successful echoes across the two cycles; denied clients did not reach it.

**Cleanup verified:** confirmed manifest-based REMOVE and fresh absence; zero
remaining client fixture executables or NetSentinel prefix rules; 476 rules and
MpsSvc Running on independent final enumeration. The listener's PID, process
start ticks, command path and script hash were checked before normal SIGTERM.
Its receipt reported STOPPED, and the endpoint port was independently no longer
listening. Both guest test folders, copied runtimes/dependencies, raw inventories
and temporary probe files were deleted and absence verified. Windows was powered
off before one cleanup call; it was normally restarted solely to finish/verify
file cleanup. Both VMs were then normally stopped, matching their initial state,
and their exact original NAT connectionType lines restored and re-read. The
pre-existing VMnet1 configuration was retained unchanged. The user-approved Kali
MCP registry/PasswordVault records remain available. No unrelated rule was deleted.

**Limits:** this proves fresh TCP connections for the test executable on IPv4,
one selected Public profile and this guest build/token. It does not promise
immediate termination of existing flows, arbitrary GPO/MDM policy applicability,
other Windows builds or standard-user native writes. IPv6/UDP and denial/failure
branches retain their fake acceptance coverage; they were not additional native
network scenarios. Production writes stay NO_GO pending trusted privilege/custody
and later lifecycle/UI gates; there is no UI/runtime response wiring, auto-block,
elevation helper, persistence or reconciliation. NS-102–104 NOT STARTED.

Fresh quality on the final harness: **599 targeted passed / 1 native deselected,
3.79s** (44 new offline harness tests); configured Ruff PASS; configured mypy PASS
(37 source files). Production source did not change, so the earlier full suite
**4388 passed / 9 deselected, 91.30% coverage** is retained without an unnecessary
rerun. This is not a claim that a new full suite including the 44 tests was run.
Final whitespace and bounded privacy checks **PASS** over all 15 changed/new files,
with zero trailing-whitespace or secret/privacy findings.

## Earlier private-lab validation review/proposal — superseded by closure above

**TASKS does not require a public Internet endpoint or VPS.** Its NS-101 acceptance
requires bounded program/IP/port/profile, no shell injection, no unrelated-rule
changes, and explicit isolated Windows rule tests. The previous report conflated
the shared NS-100 production address contract and the harness's external control
socket with an NS-101 task requirement. A controlled host-only private lab can
satisfy the native rule/traffic acceptance after an explicit test-only fixture is
established. No third-party destination, fabricated public address, router port
forwarding, or production scope expansion is necessary.

The current validation split is **not separate**:

| Boundary | Current implementation |
|---|---|
| Production response spec | `domain.response._remote_ip` requires public global unicast; `ResponseRuleSpec.__post_init__` calls it unconditionally |
| Typed CREATE/REMOVE | Exact `ResponseCommand` / `ResponseRuleSpec` types required; a subclass or alternate lab-spec object is rejected |
| Native readback | `windows_firewall_com.snapshot` reconstructs the actual spec using `dataclasses.replace`, which reruns the same validator; accepting only command construction is insufficient |
| Manifest / ownership | Uses the exact originating request and full expected/readback equality; cannot substitute a different address for evidence |
| Existing native harness | Builds that production spec and opens an unrelated-interpreter socket to the selected address; it has no lab fixture |
| Existing executable fixture | Minimal PE returns zero and is never executed; it cannot establish the requested same-executable block/unblock proof |

Existing domain tests explicitly reject RFC1918 private literals. The review
reran all targeted NS-100/NS-101 offline tests: **555 passed / 1 native deselected,
2.16s**. No production source, contract semantics, or harness was changed. Per
section 7 of the user's current request ("STOP before broadening production
behavior. Propose the smallest explicit test-only seam or fixture mechanism."),
execution stops at this proposal, before any lab network/listener/firewall change.
Fresh configured Ruff (`src tests packaging --no-cache`) PASS; configured mypy
PASS (37 source files). `git diff --check`, new-report whitespace check and bounded
12-file privacy scan PASS with zero findings. No full-suite rerun is required for
this documentation-only review; the earlier 4388-pass / 91.30% result is retained.

**Proposed smallest test-only mechanism; not implemented:**

1. Add a function-scoped pytest fixture exclusively to the opt-in native test
   module. After exact Windows guest identity, virtualization, explicit lab
   authorization, recovery access, and actual host-only endpoint inventory are
   verified, temporarily replace `domain.response._remote_ip` using pytest's
   scoped `monkeypatch.context()` in the dedicated guest test process. The fixture
   accepts only the one canonical literal RFC1918 unicast address actually assigned
   to the controlled Linux endpoint, rejecting every other address, hostname,
   list, subnet, wildcard, loopback, link-local, and special address. Do not use
   the broad `is_private` predicate alone, which also covers special addresses.
   This is an explicit test-process validation exception, not normal production
   contract acceptance. No production environment switch, injected public
   validator, runtime path, exported lab type, or permissive default is added.
2. Keep the fixture active through real adapter CREATE, full unique fresh native
   READ, originating in-memory manifest, confirmed REMOVE and fresh absence
   verification. Preserve every other existing typed command/file/confirmation,
   selector and ownership guard. Do not bypass frozen values with `object.__new__`
   or alter the readback/equality/ownership API. Never serialize or persist the lab
   manifest. Native cleanup must finish before the fixture restores the original
   validator. Check unchanged production private-IP rejection before activation,
   after teardown, and in a separate unpatched process. Add offline fixture tests
   for exact allowlisting, bad targets, guard ordering and restoration on errors.
3. Replace the inert PE with a trusted, dedicated TCP client executable fixture,
   using literal-address connect calls and a bounded timeout, never DNS. Pin and
   classify its exact file identity through the existing target guard. Run fresh
   connections from that same executable before creation, while blocked and after
   verified removal; use a separate executable as an unrelated control. Require
   listener health/control success during the block check so an endpoint failure
   cannot masquerade as scoped blocking. Continue exact rule/profile/global-state
   checks and manifest-only cleanup.
4. Use the existing Windows 11 VM and an existing Linux/Kali VM on one host-only
   VMware segment. Start one temporary high-port TCP listener bound only to the
   Linux lab address; record its address, port and PID. No NAT/routing/public
   endpoint is needed for this topology. Restore only test-created networking
   changes, stop that exact listener, and remove owned rules and test files after
   observing full cleanup. Configuration changes must be reversible and must not
   disturb pre-existing VM networking.

Current VMware MCP discovery lists **Windows 11 only**, currently stopped. No
Linux/Kali VM is registered in the MCP inventory; this does not prove that none
exists outside that inventory. No VM was started or changed in this review, and
no host-only segment, lab addresses, endpoint port/PID or listener was provisioned.
The proposed topology and every native lifecycle/traffic step remain **NOT RUN**.
NS-101 is INCOMPLETE because the explicit lab fixture and execution are pending,
not because TASKS requires a public endpoint. NS-102–104 remain NOT STARTED.

## Earlier native isolated VM preflight result and cleanup

**Native lifecycle: BLOCKED. CREATE / originating manifest / adapter READ / REMOVE
and traffic block/unblock: NOT RUN. NS-101 stays INCOMPLETE.** No physical-host
Firewall COM probe or firewall mutation was performed. The following evidence is
guest preflight only; it is not native adapter lifecycle acceptance.

On 2026-10-08 the already-configured global **VMware MCP** found the exact dedicated
VM **Windows 11**. No new MCP, SSH, or alternate/old VM was used. MCP start, guest
program execution, file copy in both directions and independent SHA-256 equality
all passed.
The copied read-only preflight file had SHA-256
`9f6701412c0aeea7db8c06d3754a902ab2793fc48455c50dee4844b4e66fc43f`.
VMware Tools reported running. A recovery snapshot
`NS101-before-native-20261008` was created and listed successfully after a normal
soft shutdown, then the VM was restarted. The initial running-VM snapshot call
returned encrypted-VM authentication failure; no credentials or security settings
were changed to resolve it.

| Guest preflight evidence | Observed result |
|---|---|
| OS | Windows 11 Home, version 10.0.26200, build **26200.9457** |
| Hardware | VMware, Inc.; VMware20,1 |
| Existing guest token | Administrator membership enabled; no elevation requested |
| Firewall service | MpsSvc Running |
| Firewall profiles | Domain, Private and Public enabled; active profile mask 4 (Public) |
| Existing rules | 476 total; **zero** names matching `NetSentinel:*` before and after preflight |
| API exercised | Guest `HNetCfg.FwPolicy2` read-only Automation enumeration; no Add/Remove |
| Unrelated state | Two enumerations of the harness's ownership property set were byte-equal; profile settings unchanged |
| Basic connectivity | One ICMP check to the VM's existing local NAT gateway succeeded; no third-party endpoint contacted |
| Native mutation / manifest | None attempted / none generated |

The guest-local inventory hashes before and after read-only preflight were both
`3ef71478f613bbe7f755a5946478482bc517e2d9ac48ecc4b88bb072d40c5bb5`.
This equality covers the short read-only observation interval, not a create/remove
cycle. The PowerShell Automation preflight does not exercise the Python COM
factory, explicit Rule3 QueryInterface, snapshot mapper or target handle guard.
It therefore does not prove their native correctness. Raw inventories and guest
credentials are not included in this report.

The user confirmed that no operator-controlled reachable public literal IP/TCP
endpoint is available and expressly prohibited a random third-party IP, router
port forwarding, weaker acceptance, and declaring NS-101 COMPLETE. The current
harness has no independently selectable endpoint-free create/read/remove test:
its command still requires a validated public unicast literal even if connectivity
checks were omitted. No public address assigned to the guest was found. Private,
loopback, documentation or reserved IP substitution would violate the frozen
NS-100 contract. No alternate address, monkeypatch or bypass was used.
Consequently `tests/integration/test_response_firewall_vm.py` was **not invoked**;
the endpoint-dependent lifecycle remains BLOCKED and real traffic block/unblock
remains NOT RUN. No production or test code was changed during this native attempt.

The guest's default PowerShell script policy refused the copied `.ps1` file
(scripts disabled). Read-only preflight used ordinary direct guest program
invocation with `-Command`; no execution-policy override or policy change was made.
The MCP `powershell` shell option also returned an error; its direct guest program
API worked. These are preparation observations, not an adapter permission denial
or a native adapter defect. No native mutation denial, verified CREATE, ownership
handoff or verified REMOVE is claimed.

**Cleanup:** no temporary firewall rule or executable fixture was created, and
fresh guest enumeration confirmed zero NetSentinel-prefixed rules. Removal/absence
verification after a CREATE is NOT RUN. Unrelated inventory/profile equality and
local gateway reachability passed in preflight only. Temporary copied probe files
and local raw probe receipts were removed; the recovery snapshot is retained and
the dedicated VM remains running. No foreign firewall rule was deleted.
Final cleanup observation: zero temporary probe files, zero NetSentinel-prefixed
rules, 476 total firewall rules, MpsSvc Running. The cleanup-proof receipt itself
was then removed successfully.

The harness is `tests/integration/test_response_firewall_vm.py`, marked both
`windows_live` and `lab_live`. Default suite/CI excludes it. Before mutation it
requires Windows, explicit VM name + authorization + recovery/snapshot attestations,
actual computer-name equality and virtualization hardware identity (VMware,
VirtualBox or Hyper-V). It refuses a physical host. Only the authorized guest
operator should configure:

```text
NETSENTINEL_NS101_VM_NAME=<exact authorized guest computer name>
NETSENTINEL_NS101_VM_AUTHORIZED=YES
NETSENTINEL_NS101_VM_SNAPSHOT_READY=YES
NETSENTINEL_NS101_CONTROL_IP=<operator-controlled reachable public literal IP>
NETSENTINEL_NS101_CONTROL_PORT=<explicit TCP port>
NETSENTINEL_NS101_PROFILE=<domain|private|public>
```

Inside that VM, install the locked optional `firewall` extra in its test venv
without changing security policy, then explicitly select only this test with
`-m 'windows_live and lab_live'`. Use a checked-absent basetemp under guest
repository `build/`; pytest removes an existing basetemp. Run with the guest's
already-authorized token. If mutation is denied, record refusal, do not elevate
or retry. This is adapter harness acceptance, not deployment of a trusted helper.

The harness records a complete local pre-inventory and profile policy before
mutation, creates one clearly NetSentinel-prefixed rule targeting only its
disposable `NetSentinel-NS101-temporary-fixture.exe`, verifies full readback and
keeps the manifest in memory. It compares unrelated inventory/policy and a
separate interpreter's TCP connectivity before/during/after, removes only using
the manifest, verifies exact absence and identical poststate, and deletes the
fixture. Raw prestate is a VM-local sensitive receipt, not repository/support
data. It does not run the PE or claim matching-traffic blocking acceptance.
If readback fails and no manifest was granted, the harness refuses blind cleanup
and records exact local operator-recovery context; complete cleanup is unproven
until the operator restores the dedicated VM state. No restart manifest recovery
or unrelated-state wholesale restore code is implemented.

## Offline quality gates

The table below retains the earlier implementation gates before the 44 offline
lab-harness tests were added. The latest follow-up changed tests/fixtures/harness
and documentation only, with no production source change. Its final 599 targeted
tests, native pass, configured Ruff/mypy and 15-file whitespace/privacy checks are
recorded in the closure above. The previous full-suite/coverage result is retained;
the entire offline suite including the new 44 tests was not repeated.

| Check | Result |
|---|---|
| New infrastructure tests | **236 passed**; three-module coverage **96.93%** |
| Targeted NS-100 + NS-101 | **555 passed / 1 native deselected**, 3.35s; combined coverage **97.82%** |
| Full default offline suite | **PASS — 4388 passed / 9 live deselected / 1 warning, 470.09s (7m50s)** |
| Repository coverage | **91.30%**, 27,647 statements / 2,406 missed; existing **85%** gate unchanged |
| Configured Ruff (`src tests packaging --no-cache`) | PASS |
| Configured mypy | PASS — 37 source files |
| Direct infrastructure mypy | PASS — 3 source files |
| Lock consistency (`uv lock --check --offline`) | PASS — 30 packages; no install |
| Whitespace / bounded privacy scan | PASS — git diff check plus exact 12-file tracked/new-file whitespace and bounded secret/privacy scan; zero findings |

The existing approved bundled CPython 3.12.14 uses repository `src` plus existing
`.venv/Lib/site-packages` on PYTHONPATH. Full suite uses the prior accepted
outside-sandbox procedure for existing installer junction fixtures, a fresh
checked-absent ignored `build/` basetemp, offscreen Qt, deterministic hash seed,
and pytest cache disabled. All three live categories remain excluded; no gates
or assertions were weakened. Two earlier full-suite runs were stopped during
review to fix the submitted-versus-postread failure distinction and to bind
removal to NS-100's fresh-read timing guard; neither is a full-suite pass.
Final results concern the restarted run on the final code.
The sandboxed lock update initially lacked DNS;
the authorized outside-sandbox lock update succeeded. No dependency was installed
on the physical host and no firewall operation was performed. The full pass
includes all existing offline installer junction cases and the 236 new fake
infrastructure cases. Eight previous live cases plus the new doubly-marked native
VM test account for the nine exclusions. A bounded privacy heuristic over the
exact 12 changed/new files found zero private-key/token/secret-assignment,
personal-path/SID/email patterns; synthetic fixtures are not observed telemetry.
This is not exhaustive secret detection. `git diff --check`, eight new-file
no-index checks and an explicit 12-file trailing-whitespace scan had zero
diagnostics. The four pre-existing ignored `ns067-mypy-*` permission-warning
directories were untouched. HEAD remains the baseline above.

## Explicit NS-102 boundary and delivery state

NS-101 uses **caller-held manifest only**. There is no SQLite schema/repository,
durable audit, lifecycle storage, restart recovery/adoption, external-change
polling, reconciliation, expiry worker, startup cleanup or uninstall integration.
The existing manifest codec is reused only in fake roundtrip tests; the native
harness holds its ownership evidence in memory. Production writes remain NO_GO
pending trusted privilege/custody and later production lifecycle/UI gates.

**NS-101 COMPLETE** (offline and isolated host-only VMware native acceptance PASS);
**NS-102 NOT STARTED**;
**NS-103–104 NOT STARTED**. UI/runtime response wiring **NO**; auto-block **NO**;
elevation helper **NO**; persistence/reconciliation **NO**.
The user approved an **NS-101-only commit and normal push to main** after
acceptance. Git verification is reported separately; tag/release **NONE**.

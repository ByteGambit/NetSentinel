# NS-100 — Manual response command and privilege contract

Date: **2026-10-08 (Europe/Istanbul)**. User instruction **“GO NS-100”**
authorizes this task after M17/NS-099 completion and acceptance of the
[M18 planning gate](M18_RESPONSE_PLANNING.md). This is contract implementation
only. **NS-101–104 NOT STARTED; no firewall write, elevation, helper, response UI,
installer rebuild, dependency, schema, tag or release.** The original planning
document is retained as the historical review that preceded this authorization.

## Scope and values

`domain/response.py` provides frozen, strictly typed values with no OS or file
access. `ResponseRuleSpec` requires **all** of these dimensions:

| Dimension | Contract v1 |
|---|---|
| Program | One absolute drive-qualified Windows desktop `.exe` path; full value retained, never truncated |
| Destination | One canonical public unicast literal IPv4 **or** IPv6; no domain, list, range, subnet, keyword, local/special address or IPv4-mapped IPv6 |
| Transport and remote port | Explicit TCP or UDP, one integer 1–65535; bool, zero, ANY and absent port rejected |
| Windows profile | Exactly one Domain, Private or Public; no default ALL or implicit current profile |
| Direction/action | Fixed OUTBOUND/BLOCK; no inbound/ALLOW or global policy change |
| Lifetime | Explicit `UNTIL_MANUALLY_REMOVED`; `expires_at` must be absent (`None`) |

Program/IP/transport/port/profile form an AND scope. Local address and local port
are unconstrained. No NIC filter is promised; Windows profile is separate from
NetSentinel's observed network fingerprint. The rule can match other instances
and users at the same path, including a later replacement executable. IP is not
a domain identity; an IPv4 target does not cover another IPv6 address. New traffic
may fail; immediate termination of an existing flow is never promised.

Path validation is **syntax only**: reject relative/UNC/device/extended path
forms, forward-slash forms, environment variables, ADS, wildcard/control/bidi
characters, empty/dot/traversal components, trailing spaces/dots, reserved DOS
components and non-executable suffixes. Maximum path length is 4096 UTF-8 bytes.
Unicode is preserved exactly. Shell-looking characters valid in filenames remain
in structured data; no shell or arbitrary execution interface exists.

An absolute drive can still be a network/mapped drive; a syntactically valid
path can be missing, a reparse point or a system/hosted application. The contract
does **not** claim to establish those facts. Before any future creation a trusted
reader must independently establish local final path, no reparse components,
ordinary desktop class and fresh file identity. Reject Windows/system/service/
packaged/shared-host processes, NetSentinel and its privilege component. Never
execute the file or follow a network path to validate it. Missing/unverifiable
metadata denies creation; never fall back to IP-only or widen the scope.

`ResponseFileIdentity` binds bounded volume serial/file ID/size/UTC mtime to the
preview. These are local metadata, not loaded-image proof or an immutable hash
condition. A future reader must compare current metadata/final path with this
snapshot immediately before creation; any drift requires a new preview. Snapshot
serialization alone proves no check occurred. File replacement after validation
remains a TOCTOU limit. A retained hash can be explained separately; there is no
implicit hashing, DNS resolution or TI lookup.

## Identity, preview and confirmation

`ResponseSource` retains exact nonzero session/lifecycle UUIDs, UTC observation
time, AVAILABLE/EXPIRED/UNAVAILABLE status and COMPLETE/REDUCED/FAILED or unknown
quality. A container incident, PID or name is not a target. Unknown measurement
does not become complete. The review denies CREATE on an expired/unavailable
source or FAILED collection. Removal retains historical provenance even after
source expiry; expiry alone must not prevent later independent owned-rule Undo.
Undo retains the original spec/file snapshot as provenance; it does not require
that the executable still exists. Its fresh validation concerns ownership and
OS rule equality, independently of file/source availability.

`ResponseCommand` contains a nonzero command UUID, rule UUID, originating-store
UUID, CREATE/REMOVE, exact spec/source/file snapshot, UTC preparation time and a
positive selection generation. CREATE allocates one UUID used for both command
and rule. A retry keeps it. REMOVE allocates a distinct command UUID but names
the original rule: `NetSentinel:<canonical-uuid>`. No prefix wildcard, PID reuse,
new target, ALLOW-rule compensation or whole-firewall restore.

The SHA-256 command fingerprint includes **every** serialized field. A local
`ResponseConfirmation` binds that fingerprint and UTC confirmation time. Match
requires preparation ≤ confirmation ≤ current time and a maximum **five-minute
age from preparation**, inclusive. This is a preview deadline, **not rule expiry**.
Changing target, profile, protocol/port, file metadata, source, store, action,
preparation time or selection generation invalidates confirmation. An A→B→A
selection requires a new generation and cannot reuse A's earlier confirmation.
Historical evidence age is separate; no risk threshold or malware verdict is
required for a manual review.

The future UI must show the full program/IP/family/port, single profile and
inactive/unknown profile state, original source/time/quality, manual lifetime,
cross-user/path-replacement/shared-IP collateral, persistence after exit/crash,
and exact Undo/admin requirement. Cancel before dispatch produces no intent,
audit or OS mutation. Close after dispatch cannot promise OS cancellation.
ACK/RESOLVED, trust, mark-normal, TI HIT/NO_HIT and detector thresholds are never
response triggers. NS-103 owns UI implementation; this task adds no widgets.

## Local codec and privacy

The v1 codec emits deterministic sorted-key UTF-8 JSON bytes, bounded at **16 KiB**.
The decoder rejects oversized/non-byte/invalid UTF-8 inputs, missing/unknown fields
at every level, duplicate keys, invalid enums, bool-as-integer, invalid/noncanonical
UUID/UTC times, future versions, unsupported scope and temporary lifetime. Literal
IP syntax is normalized once. Invalid inputs yield one fixed error without echoing
the input or chaining raw parser exceptions. No arbitrary metadata/secret/script
or command-line field is supported.

The codec is **local sensitive transport**, not a support export or log format.
Path/IP/store/source/file metadata and confirmation digests are excluded from
dataclass repr. This reduces accidental exposure; it does not authorize logging
serialized bytes or guarantee redaction of every caller. There is no persistence,
network request, automatic upload or diagnostics hook. Schema stays **019**.

## Privilege contract and explicit deny decision

`application/ports.py` defines only `ResponsePrivilegeProbe.assess(command)`.
It is read-only and must never launch UAC or mutate state. `ResponseContractReview`
checks confirmation before calling that injected port once, then returns a typed
**NOT_ATTEMPTED** result. Missing/cancelled confirmation, stale selection/clock,
invalid source, malformed probe replies and exceptions fail closed. Exceptions
are discarded, never shown in result/error text. No executor method exists.

Privilege statuses: **PRIVILEGE_REQUIRED, ACCESS_DENIED, UAC_CANCELLED,
READ_UNAVAILABLE, POLICY_LIMITED, BOUNDARY_UNAVAILABLE, REVALIDATION_REQUIRED**.
The last means further trusted review is required; it grants no mutation authority.
`UnavailableResponsePrivilege` is the default pure implementation and always
returns BOUNDARY_UNAVAILABLE, including for a correctly fingerprinted command.
These modules are not wired into startup, monitoring, selection, retry, feedback,
expiry, uninstall or any GUI flow. Standard-user monitoring/local trust continue
through their existing paths.

**Current decision: NO_GO for in-product writes.** The per-user writable package/
SQLite cannot authenticate a privileged operation. A command, store UUID,
confirmation hash, DB flag, token indication or UAC approval of a mutable payload
is not trusted exact-target consent. No helper is approved or implemented here.

The conditional future one-operation helper needs protected loaded-code integrity,
requester/session/nonce/command/spec binding and independent trusted plain-text
target confirmation. Separate origin user/store from approving administrator;
different-account UAC cannot redirect the ledger or target. Normal UAC is the only
credential surface; never capture an admin password or restart the GUI elevated.
Helper authority ends with one operation; Undo requires its own human approval.
No service, scheduled task, reusable elevated IPC server, arbitrary shell/script,
driver, security bypass or global policy mutation. Any protected deployment scope
change needs separate approval. These are gates for later work, not implemented
IPC or elevated validation claims. Until resolved, use read-only guidance/manual
Windows administration without claiming NetSentinel-owned success.

## Ownership, rollback and partial outcomes

Rule UUID/name and origin-store ID provide prospective identity, **not ownership
proof**. Before a future CREATE, refuse any foreign collision or duplicate; never
blindly upsert. Before REMOVE, require the originating durable manifest, a unique
exact rule name and fresh equality of **all** relevant OS properties with the
expected full specification. Prefix/group/description alone is insufficient.
Unsupported properties, modified/disabled/missing/renamed/foreign rules, lost
ledger and unknown ownership cannot be adopted, repaired, re-enabled or deleted.
COM external-edit atomicity and full readback proof remain NS-101/102 gates.
There is no durable manifest or reconciliation implementation in NS-100.

`ResponseResult` separates command outcome from current rule state. Known failure,
OUTCOME_UNKNOWN and PARTIAL are not VERIFIED. A VERIFIED receipt requires the
`RULE_READBACK_VERIFIED` reason and correct postcondition: CREATE→PRESENT_ENABLED,
REMOVE→ABSENT. It never claims traffic blocked/restored, safety or malware stopped.
Only test fixtures construct these success receipts now; there is no OS executor.
UAC cancellation after a later durable attempt is FAILED; this read-only preflight
always remains NOT_ATTEMPTED. Denied removal may leave a rule present.

Future sequencing is durable confirmed INTENT → durable ATTEMPT → trusted
validation/confirmation → OS call → independent readback → bounded durable
receipt. No OS write when persistence/reserved Undo capacity fails. OS/DB/IPC
disagreement stays PARTIAL/UNKNOWN; retain recovery provenance, reconcile read-only
and never retry CREATE blindly. Submission/worker cancellation is not verified
postcondition. Restart/profile/VPN/sleep changes do not retarget or authorize writes.
Undo removes only the unchanged owned rule, verifies absence and records a distinct
confirmed action; already-absent discovery is not proof NetSentinel removed it.

Manual lifetime persists across app exit/restart/crash. No timer/app-exit guarantee
is accepted. Future uninstall preserves by default with an exact remaining-rule
list and separate explicit cleanup/data-delete choices; loss of privilege cannot
be labelled cleanup success. NS-102/104 own storage/reconciliation/uninstall work.

## Threat model and acceptance mapping

| Risk / acceptance criterion | NS-100 control and remaining gate |
|---|---|
| Target/profile/expiry explicit | Required AND dimensions, single profile, manual lifetime; no default scope widening |
| Injection/untrusted command | Strict typed bounded codec, exact local path/literal IP, no shell; parser values never authorize execution |
| Stale selection/PID/file replacement | Exact lifecycle and file snapshot, generation/time/fingerprint binding; trusted fresh file checks still required |
| Forged consent/admin boundary | Read-only probe, typed denial, default unavailable, no executor/elevation; helper integrity/authentication unresolved |
| Denied/degraded/partial result | Fixed enums, correct readback postcondition, OS state separate from outcome; traffic effect unmeasured |
| Forged ownership/external edit | Full manifest/unique-name/readback boundary documented; no adoption by prefix or unrelated-rule mutation |
| OS/DB split/crash/lost ledger | Durable intent/receipt and read-only recovery required later; no blind retry, preserve Undo metadata |
| Privacy/collateral | Local sensitive data only, sanitized errors/repr; explain shared IP, profile/NIC and all-instance/path scope |

Validation results are recorded in [NS-100 acceptance](RESPONSE_COMMAND_ACCEPTANCE.md).
M18 remains in progress. Starting NS-101 requires a separate user instruction;
NS-100 completion does not unlock writable response or native tests.

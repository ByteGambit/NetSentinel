# NS-100 — Manual response command and privilege contract

## NS-102 production lifecycle contract — 2026-10-09

The user authorized full **NS-102 only** after the native witness gate passed.
See [current implementation acceptance](RESPONSE_LIFECYCLE_ACCEPTANCE.md#full-ns-102-implementation--2026-10-09).
Earlier review/native sections retain their historical scope. NS-103 UI and
NS-104 uninstall/native acceptance remain NOT STARTED. No runtime response
composition, automatic threat blocking, privilege helper, elevation, background
service or task scheduler is added.

**PreparedFirewallOwnershipClaim** is immutable and framework-independent: original
FirewallCreateRequest (full typed command and exact confirmation), complete
expected snapshot, independent 256-bit witness, UTC preparation time, version1.
new_response_rule_identity allocates UUID4 **before preview/confirmation**; the
coordinator never rewrites a confirmed command. It requires UUID4 and generates
secrets.token_hex(32) before OS mutation. A unique SQLite witness constraint
prevents reuse across retained operations. PREPARED is not ownership and cannot
authorize REMOVE. Strict bounded UTF-8 transport retains Unicode paths and IPv4/IPv6.

The exact native-verified Description is 133 literal ASCII characters/bytes:

> NetSentinel response witness v1 <canonical-uuid> <64 lowercase hex>

Grouping and target semantics remain unchanged. Normal reprs, historical audit
and diagnostics omit witness/Description/path/IP. Sensitive bounded custody
transport remains local. Witness is visible OS metadata, not a password.

CREATE commits PREPARED/audit, then ATTEMPT/audit in a second short transaction.
Only then does the adapter independently validate the target, preflight fresh
exact-identity absence, Add and verify unique complete witnessed readback.
The coordinator commits FINAL and VERIFIED_SUCCESS audit atomically. An adapter
receipt alone is not normal lifecycle success. Final DB failure returns PARTIAL
without granting ownership and retains original durable provenance. Partial Add
does not trigger blind cleanup.

FINAL version2 binds original CREATE, store/rule identity, verified full snapshot,
PREPARED witness/provenance, recorded dispatch-intent time, actual dispatch time
(created_at) when known, verification time and version. Recovery uses created_at
None: it never invents Add time inside an expired confirmation window. Dispatch
intent is a pre-call durable phase, not proof of the instant Windows changed.
Legacy v1 manifests/codecs and their original Description equality remain strict;
v1 gains no witnessed recovery semantics.

Existing-operation replay loads the exact durable request and reconciles first.
Changed request/confirmation/store/revision is refused. CREATE replay never adds
again. PREPARED promotion requires original durable operation, exact unique rule
identity, exact literal witness/Description and every expected field in a fresh
supported OS read. Absence becomes NOT_MATERIALIZED; wrong/missing witness, drift,
disabled state, duplicates and unavailable reads remain unowned/unresolved.
FINAL and RECOVERY_PROMOTION persist atomically. Recovery observes evidence; it
does not manufacture a current CREATE confirmation or execute Add.

REMOVE requires this store's FINAL and a distinct confirmed typed REMOVE, then
the adapter's own fresh unique complete equality including witness/Description,
exact removal and verified absence. The original five-minute action-time
confirmation rule remains unchanged. PREPARED, witness/name/UUID and cached
readback cannot authorize removal. Rollback uses this same explicit path with
separate attempt/success/failure audit; unfinalized partial claims cannot be undone.
Drift, missing state and duplicates refuse normal mutation.

After REMOVE verifies absence, a short transaction stores OS_VERIFIED evidence;
another finalizes VERIFIED_SUCCESS. Finalization failure preserves the durable
OS_VERIFIED receipt pending restart/fresh-absence finalization. Without that
durable receipt, fresh absence is ABSENCE_OBSERVED and UNKNOWN, not proof this
command removed anything. REMOVE replay never removes again. Historical verified
operation results and current reconciliation are separate; prior creation success
is not proof of current presence.

A durable verified removal receipt (including OS_VERIFIED pending finalization)
also tombstones the originating ownership. If the exact old metadata later
reappears, reconciliation records external drift rather than readopting it.
A new REMOVE using that archival manifest is refused; replay of the original
REMOVE still never mutates. This closes stale-manifest resurrection without
weakening NS-101 equality or relying on an adversarial witness interpretation.

Append-only schema020 adds response_store, response_operations and response_audit;
migrations001–019 are unchanged. Custody uses canonical codecs, summary equality,
command fingerprints, unique CREATE identities, local store binding and revision
CAS. Invalid/corrupt/future storage refuses mutations. Requests are bounded32KiB;
claims/manifests16KiB; result512bytes. SQL bounds payload materialization.
Admission limits are **64 installed/unresolved CREATEs** and **1024 retained
operations**; capacity refuses admission without evicting ownership/idempotency.
Reconciliation of verified removal releases active-rule admission capacity.
CREATE admission reserves at least one future cleanup operation for every
installed/unresolved rule. Repeated failed REMOVE requests cannot consume another
rule's reserved first cleanup slot. Finite history still bounds further retries:
when no safe slot remains, mutation is refused and custody retained.
An existing DB opens its persisted store identity without caller memory; missing
store metadata beside retained operations fails closed. Under the store lock,
custody is validated in bounded64-row pages (maximum1024 operations), outside a
write transaction, before any coordinator call. A corrupt unrelated record
cannot be bypassed by submitting a different new CREATE.

Each state transition and typed audit append is one transaction. Audit identifies
sequence, operation/rule/action/time, phase/result and reconciliation. Requested
scope comes from the retained operation, not duplicated free text. Events include
PREPARED, ATTEMPT, readback/verified success, failure, UNKNOWN/PARTIAL,
RECOVERY/PROMOTION, rollback outcomes, external drift/missing and expiry pending.
Replay of an already finalized REMOVE records RECOVERY rather than a new
VERIFIED_SUCCESS/ROLLBACK_SUCCESS. Historical results remain distinct from
current observation and from a pending OS_VERIFIED receipt being finalized.
Oldest audit events are pruned atomically to **8192 rows**; custody/idempotency is
never pruned with audit or NS-095 eligible-history purge. This local finite audit
is neither complete lifetime history nor a tamper-proof forensic log.

Restart/manual reconciliation uses **64-operation maximum UUID cursor pages**
and bounded native enumeration. It classifies exact/promoted, not materialized,
pending CREATE/REMOVE, modified/disabled/missing, ambiguous, expired/expiry pending
and unknown/partial. It never recreates, re-enables, overwrites, adopts foreign
rules or retries writes. A backwards clock cannot establish fresh evidence.

The frozen CREATE lifetime remains UNTIL_MANUALLY_REMOVED, expires_at None;
timed CREATE still fails closed. NS-102 also persists an explicit **confirmed
REMOVE intent with a due time** through schedule_expiry. Due observation invokes
normal strict REMOVE only with FINAL and a still-fresh REMOVE confirmation.
Stale approval remains EXPIRY_PENDING and requires a new distinct confirmed
request. Drift/denied/unknown cleanup stays reported. No synthetic confirmation,
wall-clock expiry guarantee while stopped, 15-minute/hour writable lifetime or
app-exit deletion guarantee is introduced.

A nonblocking OS advisory file lock per DB serializes coordinator CREATE/replay,
REMOVE/REMOVE, reconciliation and expiry across threads/processes. The OS releases
it on crash; it is not a SQLite transaction or privilege grant. Transactions cover
short durable transitions, never COM. Managed callers must use the coordinator.
External administrators are outside this lock: fresh absence preflight plus
UUID4 does not eliminate **preflight-to-Add TOCTOU**. Existing external
compare-to-Remove TOCTOU also remains; Windows COM provides no atomic compare-and-swap.

**Local-admin threat boundary:** a malicious privileged administrator can inspect,
copy or change metadata/witness/custody and forge equivalent state. That adversary
is outside the frozen model. Witness gives no cryptographic anti-admin protection;
it protects accidental equivalent rules, ordinary foreign rules, crash ambiguity
and normal external edits. No DPAPI/key/certificate/broker/service/WFP expansion
is added. In-product privileged-write deployment retains its separate trust gate.

Diagnostics expose finalized currently exact ownership, prepared/pending,
partial/unknown, distinct drifted/missing rules, expiry pending, last reconciliation
time/result and current reconciliation-error count. No witness/target/raw exception
or UI/export field is added.

## Historical native witness closure

**Native witness closure (2026-10-09): NATIVE PASS / GO for resuming NS-102's
PREPARED + witness implementation**, dedicated Windows 11 26200.9457, authorized
individual inline PowerShell under unchanged Restricted policy. Exact 133-character
Description/witness, full fresh equality, ordinary Description drift and complete
cleanup passed (476->476, prefix0, identical inventory hash; guest receipt deleted
and initially stopped VM restored). [Exact evidence and limits](RESPONSE_LIFECYCLE_ACCEPTANCE.md#native-description-round-trip-closure--2026-10-09).
NS-102 remains INCOMPLETE; production promotion/recovery/write authority stays
NO_GO pending full implementation and existing privileged-boundary gates. This
native-only turn did not resume implementation. The earlier spike below retains
its original conditional/native-blocked scope; production REMOVE is unchanged.

## NS-102 OS ownership witness review — 2026-10-09

**Latest decision: witness model is viable in the frozen non-adversarial threat
model, subject to native metadata verification. Full NS-102 remains INCOMPLETE
and has not resumed.** NS-100/101 remain COMPLETE; NS-103/104 NOT STARTED.
The prior PREPARED-only stop below remains historical and correct for that model.

The narrow spike introduces **test fixtures only**. A new CREATE allocates an
independent UUID4 rule/command identity and a **256-bit CSPRNG witness** before
mutation (`secrets.token_hex(32)`). Proposed literal Description encoding:

```text
NetSentinel response witness v1 <canonical-rule-uuid> <64-lowercase-hex-witness>
```

This is 133 ASCII characters, with no `|`, indirect-resource prefix, user label,
path/IP, secret key or credential. The witness is not a UUID, password, MAC or
digital signature; it is a random operation discriminator. Keep it out of logs,
repr, diagnostics/support exports and ordinary user labels. It is observable in
OS metadata and local PREPARED state; privacy minimization is not secrecy against
a privileged inspector.

PREPARED binds complete confirmed CREATE, exact expected snapshot **including
the witness Description**, the independent witness, UTC provenance time and
format version. All operation/rule/store/source/file/scope/confirmation/contract
fields stay in the nested command/request. Atomic storage must precede any
dispatch. PREPARED and witness alone grant **no ownership and no deletion**.

Proposed restart eligibility requires an original durable pre-Add claim, exact
operation/store/rule binding, one fresh complete supported OS candidate, exact
witness and full equality of **every** NS-101 property. Missing, wrong/edited
witness, drift, duplicates, unsupported/incomplete/unavailable readback or missing
claim must remain unresolved, with no adoption/repair/re-enable/Remove. A foreign
rule with equal selectors and an absent/wrong independent witness fails this
proof. Random identity generation is not namespace authentication; never issue
another Add on uncertain replay. Reconciliation records discovery time, not an
invented OS creation time.

The final `OwnedFirewallRuleManifest` remains mandatory for confirmed normal
REMOVE, which performs its own fresh unique full comparison including witness,
exact removal and independent absence verification. This review changes **no
production REMOVE type or code**. Existing v1 expects a different fixed Description
and rejects the spike snapshot: no v1 manifest is synthesized to evade this guard.
A future versioned final evidence model, strict codecs, honest recovery timestamps
and a typed PREPARED inspection boundary need review before actual implementation.
The test eligibility predicate returns a decision, never a production manifest or
privilege grant. No production persistence, nonce allocation, recovery port or
adapter mutation path was added.

**Threat boundary:** [M18 planning](M18_RESPONSE_PLANNING.md#8-ownership-command-identity-and-rollback)
expressly excludes an adversarial-local-admin/tamper-proof ownership guarantee;
[NS-101 acceptance](RESPONSE_FIREWALL_ACCEPTANCE.md#failure-privilege-and-security-review)
likewise disclaims authentication of forged manifests/exact clones. A privileged
administrator or a caller who tampers with the writable ledger can copy the
witness. An exact clone passes equality; tests demonstrate this limitation. The
model protects accidental/unrelated matches and ordinary edits, not malicious
copying, authenticated privileged consent or trusted deployment. Production writes
remain NO_GO at that separate boundary; no key store, DPAPI, signing, broker,
service or driver is introduced.

Microsoft documents [Description as a read/write BSTR, forbidding `|`](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrule-put_description),
but specifies no maximum length or general exact-persistence/localization guarantee
there. The short literal ASCII marker avoids resource references; exact readback
is mandatory on each supported build, never inferred from setter success. NS-101
already sets Description before Add, retrieves it during exhaustive enumeration
and includes it in complete equality. The spike tests that same property mapping
with fakes, including drift.

[INetFwRules::Add](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrules-add)
can overwrite an existing rule with the same identifier. Name is documented as a
[friendly name](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrule-get_name),
not a protected namespace. Preserve NS-101's bounded case-alias enumeration and
zero-match checks before Add, after target validation and immediately at the native
boundary. Never upsert/adopt an existing identity, even if its witness matches.
There remains an external insertion/replacement window between the last check and
Add/Remove; ordinary COM supplies no atomic compare-and-create/delete or
authenticated origin receipt. Witness entropy does not turn those calls atomic.

**Native gate OPEN / NOT RUN:** the authorized dedicated Windows 11 VM's effective
PowerShell execution policy was **Restricted**. The file-based metadata probe was
refused with `PSSecurityException / UnauthorizedAccess` before it executed. No
policy change, bypass, elevation or alternative mutation path was attempted.
Read-only cleanup found zero probe rules; transferred files were deleted and the
initially stopped VM was returned to stopped state. Native Description persistence,
Unicode, length and transformation behavior remain **NOT VERIFIED**, not failed
metadata semantics. Thus no production recovery GO follows this review.

The [complete witness report](RESPONSE_LIFECYCLE_ACCEPTANCE.md#os-ownership-witness-review--2026-10-09)
records tests, the native limitation and all 22 requested delivery items.

## NS-102 PREPARED clarification review — 2026-10-09

The user authorized a two-phase CREATE provenance model and required STOP if
durable pre-mutation provenance plus fresh equality still cannot establish safe
ownership. **NS-100/101 remain COMPLETE; NS-102 INCOMPLETE; NS-103/104 NOT STARTED.**
This review adds no production value, port, adapter recovery or persistence path.

The intended `PreparedFirewallOwnershipClaim` is immutable local provenance:
complete confirmed `FirewallCreateRequest`, exact expected `FirewallRuleSnapshot`,
UTC pre-mutation provenance time and claim version. Command/operation, rule,
store and contract identities remain bound by the nested command. It means
"durably committed to attempting this exact creation", **not** "owns a rule".
It cannot be supplied to REMOVE, rollback or any modification. The final
`OwnedFirewallRuleManifest` remains required for normal removal, with a confirmed
REMOVE, unique full fresh equality, exact removal and verified absence.

NS-102 would own atomic PREPARED storage before dispatch and durable finalized
manifest/audit storage afterwards. NS-101 remains stateless with respect to
persistence. The intended flow is confirmed validation -> PREPARED commit ->
exact CREATE -> fresh full verification -> finalized manifest commit -> owned
VERIFIED_SUCCESS audit. Adapter VERIFIED alone is not durable lifecycle success.
Claim serialization alone cannot prove its commit order or authenticate custody.

**Promotion remains blocked:** after PREPARED, termination before CREATE with an
equal foreign rule, or termination after NS-101 refuses that collision but before
recording refusal, produces the same durable claim and fresh unique complete OS
readback as termination after successful CREATE. Current Rule/Rule2/Rule3 snapshots
and operation identities cannot distinguish those histories. Promoting solely on
the proposed four inputs would turn an explicit NS-101 ownership refusal into
owned authority after restart. This is separate from the already documented
external edit race during Remove; no concurrent Remove is needed.

The user's safety condition therefore stops implementation before adding a
promotion path. PREPARED + mismatch/duplicate/unsupported/missing cannot grant
ownership; exact equality is also insufficient in this demonstrated collision
window. No recovery may invent creation/verification timestamps, deserialize an
expected rule as a finalized manifest, or call CREATE again while the prior
outcome is unknown. A separately reviewed discriminator/custody mechanism or an
explicit acceptance of this additional origin ambiguity is needed; a second
writable journal, dispatch flag or self-declared nonce does not by itself supply
an OS creation receipt.

The complete [NS-102 review and tests](RESPONSE_LIFECYCLE_ACCEPTANCE.md#prepared-contract-clarification-review--2026-10-09)
preserve the initial blocker report and the new decision. The existing v1
contract below remains unchanged. Neither this test-only candidate nor any new
production PREPARED codec/type was introduced into the application.

Date: **2026-10-08 (Europe/Istanbul)**. User instruction **“GO NS-100”**
authorizes this task after M17/NS-099 completion and acceptance of the
[M18 planning gate](M18_RESPONSE_PLANNING.md). This is contract implementation
only. **NS-101 INCOMPLETE / stopped before coding; NS-102–104 NOT STARTED;
no firewall write, elevation, helper, response UI,
installer rebuild, dependency, schema, tag or release.** The original planning
document is retained as the historical review that preceded this authorization.

**NS-100 remains COMPLETE with the scoped ownership handoff clarification
(2026-10-08).** This adds only immutable values, a bounded manifest codec and
an application protocol. It does not resume NS-101 adapter implementation.

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

The privilege preflight in `application/ports.py` remains
`ResponsePrivilegeProbe.assess(command)`.
It is read-only and must never launch UAC or mutate state. `ResponseContractReview`
checks confirmation before calling that injected port once, then returns a typed
**NOT_ATTEMPTED** result. Missing/cancelled confirmation, stale selection/clock,
invalid source, malformed probe replies and exceptions fail closed. Exceptions
are discarded, never shown in result/error text. No executor implementation exists.
The ownership handoff protocol below declares future adapter operations;
it neither implements nor dispatches them.

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
blindly upsert. Before REMOVE, require the originating manifest, a unique
exact rule name and fresh equality of **all** relevant OS properties with the
expected full specification. Prefix/group/description alone is insufficient.
Unsupported properties, modified/disabled/missing/renamed/foreign rules, lost
ledger and unknown ownership cannot be adopted, repaired, re-enabled or deleted.
COM external-edit atomicity and full readback proof remain NS-101/102 gates.
NS-100 now defines the manifest value/handoff, not manifest storage or reconciliation.

### Scoped ownership handoff clarification

The previous gap was an absent typed handoff: NS-101 could neither return its
verified originating creation evidence nor receive it for read/removal without
assuming NS-102 storage existed. The user-authorized division is now explicit:

**NS-101 can complete create/read/remove adapter acceptance using a caller-held
manifest, while durable production ownership across restarts remains unavailable
until NS-102.** Fake tests may hold that manifest in memory. A separately authorized
isolated native NS-101 harness may hold it for create → read → remove. This is not
production persistence or permission to run native tests in this clarification.
After a harness/process restart, no ownership recovery or adoption by OS name is
available. Production writes remain NO_GO; existing privilege/native gates remain.

`OwnedFirewallRuleManifest` is a frozen framework-independent v1 value containing:

| Fields | Why retained |
|---|---|
| Original `FirewallCreateRequest` (command + exact confirmation) | Rule/command/store UUIDs, full spec, file snapshot and source provenance; binds originating intent rather than a name/UUID discovered later |
| Complete `FirewallRuleSnapshot` | Exact supported original OS rule equality, including enabled state and restrictions beyond the visible program/IP selector |
| `created_at`, `verified_at` (UTC) | Creation dispatch time with current confirmation, followed by verified unique full readback; reported adapter evidence, not authenticated timestamps |
| Manifest version | Stable strict transport for later NS-102 persistence; future/unknown versions fail closed |

The snapshot includes name, description, grouping, full `ResponseRuleSpec`
(application path, literal remote address, protocol/remote port, profile,
direction/action), enabled state, service, local addresses/ports, ICMP fields,
interface list/types, edge traversal/options, package ID, local user owner and
local/remote user/machine authorization lists, and security flags. These cover
the documented [INetFwRule](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule),
[INetFwRule2](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule2)
and [INetFwRule3](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule3)
property families without COM objects or native numeric enums in the domain scope.

The supported expected rule is enabled, with exact UUID name and fixed
`NetSentinel response v1 <uuid>` description; grouping is empty (no display-group
authority). Local addresses/ports are `*`, interface list empty/type `All`;
service/ICMP/package/user/IPsec selectors are empty/zero and edge traversal is
false/options zero. They are explicit comparison fields, not omitted defaults.
Description/grouping never establish ownership. An adapter must independently
read every supported property and determine unique identity; unavailable,
malformed, unsupported/broader or future properties cannot be silently replaced
with these defaults. Unsupported spec shapes return UNSUPPORTED instead of a
partial snapshot. Native property normalization/support still requires NS-101
verification; no API binding or property-support claim is implemented here.
Path spelling remains exact as in the accepted command. No case/path normalization,
file access or new target is inferred by the handoff.

`ResponseFirewall` in `application/ports.py` declares only:

- `create(FirewallCreateRequest) → FirewallCreateResult`: exact CREATE command and
  confirmation required. VERIFIED requires the matching originating manifest;
  NOT_ATTEMPTED/FAILED/UNKNOWN/PARTIAL cannot carry an ownership grant. The future
  adapter may produce a manifest only after its own creation and unique full readback.
- `read(OwnedFirewallRuleManifest) → FirewallReadResult`: explicit fresh inspection;
  MATCHED requires a complete equal snapshot. ABSENT, MISMATCH, DUPLICATE, access
  denied, read/backend unavailable, unsupported and invalid request remain distinct.
  No raw COM objects, arbitrary data or infrastructure exceptions escape the port.
- `remove(FirewallRemoveRequest) → ResponseResult`: originating manifest plus a
  distinct confirmed REMOVE command binding the original rule/store/spec/file/source
  identity. Source availability may expire; original observation/quality remain bound.
  The adapter must do its OWN fresh unique full read during this call, compare every
  field, refuse drift/ambiguity/unsupported state, remove that exact unchanged rule,
  then independently verify absence. Caller-cached reads cannot authorize removal.

`removal_readback_matches` is only a pure equality/time/binding guard. It checks
the manifest, MATCHED status, a read performed after this operation's supplied
read-start time/confirmation and before now, and current confirmation validity.
It is not an OS check, authenticated proof or a removal executor. Missing discovery
is not successful Undo; no file-existence requirement is added to removal. Existing
external-edit atomicity limits and unrelated-rule protections remain unchanged.

The manifest codec is canonical sorted-key UTF-8 JSON, bounded to 16 KiB, with
strict field/version/type/time/confirmation/scope validation and duplicate-key
rejection at every depth. Scope is stored once in the original command and bound
to the snapshot on decode. Sensitive path/IP/store/source/file/confirmation and
restriction fields are excluded from repr. Bytes are local sensitive transport,
not logs or support exports. Serialization never authenticates custody or performs
storage; a forged/deserialized manifest alone is not privileged authority.

For future adapter receipts, `ResponseReason` adds INVALID_REQUEST, UNSUPPORTED,
BACKEND_UNAVAILABLE and OPERATION_FAILED. Existing `ResponseOutcome` and privilege
statuses are unchanged: a known operation failure is FAILED, unprovable state is
OUTCOME_UNKNOWN/READBACK_UNAVAILABLE, and OS/DB disagreement is PARTIAL. Invalid or
unsupported requests cannot become verified/partial successes.

Here, **durable** describes a stable serializable type suitable for durable
storage. NS-101 produces/consumes and checks caller-held evidence; it must not
persist, poll or reconcile it. NS-102 supplies actual durable DB custody,
restart recovery/reconciliation and lifecycle/external-change audit. No SQLite
schema/repository/audit table, startup wiring, recovery state machine, Windows
backend, UI or elevation was added by this clarification.

`ResponseResult` separates command outcome from current rule state. Known failure,
OUTCOME_UNKNOWN and PARTIAL are not VERIFIED. A VERIFIED receipt requires the
`RULE_READBACK_VERIFIED` reason and correct postcondition: CREATE→PRESENT_ENABLED,
REMOVE→ABSENT. It never claims traffic blocked/restored, safety or malware stopped.
Only test fixtures construct these success receipts now; there is no OS executor.
UAC cancellation after a later durable attempt is FAILED; this read-only preflight
always remains NOT_ATTEMPTED. Denied removal may leave a rule present.

Future production sequencing is durable confirmed INTENT → durable ATTEMPT → trusted
validation/confirmation → OS call → independent readback → bounded durable
receipt. No production OS write when persistence/reserved Undo capacity fails. OS/DB/IPC
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
NS-101 resumed by explicit user instruction on 2026-10-08: adapter/offline tests
implemented; COMPLETE after explicitly approved test-only lab validation and
isolated Windows 11/Kali VMware native acceptance on 2026-10-08. Production
public-literal validation is unchanged; the private-IP exception exists only
inside the opt-in pytest process and is restored after manifest-based cleanup.
NS-102–104 NOT STARTED. Production writes remain NO_GO; no runtime response
wiring, UI, helper, persistence or reconciliation was added.
[NS-101 implementation, native gate and quality report](RESPONSE_FIREWALL_ACCEPTANCE.md).

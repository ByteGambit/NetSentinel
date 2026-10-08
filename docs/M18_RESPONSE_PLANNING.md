# M18 — Manual response planning gate

Date: **2026-10-08 (Europe/Istanbul)**. Review baseline: **8600d9a**.
Scope: planning / go-no-go review only, covering frozen **NS-100–NS-104**.

**Decision: CONDITIONAL_GO for the proposed M18 design. Implementation is NOT
authorized. NS-100–NS-104 remain NOT STARTED. No production code, firewall state,
installer, dependency, schema, tag or release is changed by this review.**
This records a planning decision separately; it does not satisfy the explicit
user response GO required by TASKS/ROADMAP/SECURITY.

NetSentinel can help a user make a reversible decision from evidence. It cannot
convert concern, novelty, reputation or correlation into a malware verdict.
The viable direction is a manually selected, explicitly confirmed, owned outbound
Windows Firewall rule with durable provenance and Undo. Two unresolved design
gates prevent unconditional GO: a trustworthy action-time privilege boundary
under the current per-user installation, and demonstrable ownership/readback/
rollback behavior across failures and external edits. Native response acceptance
has **NOT RUN**; existing monitoring acceptance does not establish response safety.

## 1. Repository verification and authoritative evidence

The requested commands ran before document creation:

| Command | Observed result |
|---|---|
| `git branch --show-current` | `main` |
| `git status` | Up to date with `origin/main`; working tree clean |
| `git rev-parse HEAD` | `8600d9a1fe3051fafae520461a1712f4289102fa` |
| `git rev-parse origin/main` | `8600d9a1fe3051fafae520461a1712f4289102fa` |
| `git log -8 --oneline` | Listed below |

```text
8600d9a docs: complete public beta VPN acceptance gate
98b2b5a docs: record prepared native S3 recovery acceptance
fa90ece docs: distinguish host S3 evidence from app acceptance
497c27b docs: record native sleep audio blocker
d2ae8ce docs: record native sleep blocker diagnosis
ef05655 docs: record blocked NS-099 VPN environment attempt
b14f74e test: record native notification policy acceptance
8242868 fix: report notification policy and delivery uncertainty
```

`git status` also reported permission warnings for four ignored `ns067-mypy-*`
directories. No access change or cleanup was attempted. Equality with the local
`origin/main` reference was checked; no remote freshness claim or fetch is implied.

Read first: [TASKS](TASKS.md), [ROADMAP](ROADMAP.md), [PRODUCT](PRODUCT.md),
[ARCHITECTURE](ARCHITECTURE.md), [SECURITY](SECURITY.md). Their latest closure
headers supersede earlier historical progress paragraphs; frozen scope remains.

| Accepted evidence read | Consequence for response planning |
|---|---|
| [M14 risk explanation](RISK_EXPLANATION_UI.md) | Score is review priority, not malware probability; exact revision and original observation remain historical truth. Missing explanation is not safety. |
| [M15 TI evidence](THREAT_INTELLIGENCE_EVIDENCE.md) | HIT and NO_HIT are informational supporting context with provenance/freshness; no automatic verdict, response or lookup. Credential unavailability remains an operational limitation. |
| [M16 acceptance/soak](INCIDENT_ACCEPTANCE_SOAK.md), [timeline acceptance](INCIDENT_TIMELINE_ACCEPTANCE.md) | Canonical links, bounded correlation and source-loss semantics exist; no forensic completeness or automatic incident producer is claimed. Incident/alert lifecycle is independent. |
| [M17 beta acceptance](PUBLIC_BETA_ACCEPTANCE.md), [final VPN closure](NS099_VPN_WIREGUARD_CLOSURE.md) | NS-099 and M17 COMPLETE; zero alerts/incidents in measured benign cases, with original candidate and optional-feature limits. IPv4 VPN PASS does not prove IPv6 response behavior. |
| [Native S3 final prepared retry](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md#final-prepared-retry-live-candidate-s3-recovery) | Actual S3 recovery PASS with optional features OFF; prior failed attempts and baseline counter-cycling limits are retained. No rule-expiry acceptance follows. |
| [Notification closure](NS099_NOTIFICATION_POLICY_CLOSURE.md) | Actual OS policy PASS; accepted submission is not visible delivery. Apply the same distinction to firewall submission versus verified rule state versus traffic effect. |
| [Human UX/layout closure](NS099_LAYOUT_CLOSURE.md) | Human UX PASS 8/8 in its evaluator/candidate scope; response confirmation still needs its own human review. |
| [Installer policy](INSTALLER_UPGRADE_UNINSTALL.md), [signing/distribution](SIGNING_UPDATE_DISTRIBUTION.md) | Per-user/asInvoker, KEEP default, explicit DELETE and no automatic elevation. Limited unsigned pilot remains CONDITIONAL_GO under NS-097; broad release remains NO_GO. |

No beta zero-alert observation establishes zero false positives for all workloads,
or justifies automatic blocking. M18 does not alter M17 or NS-097 decisions.
Signing remains a separate distribution gate; response does not require buying
a public signing certificate before NS-100 contract planning. Helper deployment
integrity, however, is a distinct privilege-boundary requirement.

## 2. Exact frozen task definitions

The following section is copied verbatim from `docs/TASKS.md` at the verified
baseline, including status, scope, acceptance criteria and dependencies. The
remainder of this document is a recommendation, not a replacement task definition.

<!-- FROZEN_TASKS_START -->
## M18 — Manual Response & Firewall Integration — CONDITIONAL

**Conditional başlatma kapısı:** M17 tamamlanmış, NS-099 public beta acceptance gate geçmiş ve explicit response GO kararı verilmiş olmalıdır. **Do not start before NS-099 and explicit response GO decision.** NS-100–NS-104 committed next work değildir. Automatic blocking ve automatic elevation kapsam dışıdır.

### NS-100 — Response command/privilege contract

- **Durum:** ⬜ Conditional plan; başlatma kapısı bekleniyor.
- **Amaç:** Manuel blocking için dar, geri alınabilir sözleşmeyi ve yetki UX'ini tasarlamak.
- **Yapılacaklar:** Destination/program rule scope, user preview/confirmation, privilege-denied, ownership ve rollback threat model tanımla.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/, src/netsentinel/application/ports.py, docs/SECURITY.md, tests/unit/.
- **Bağımlılıklar:** NS-082, NS-099 ve explicit response GO kararı.
- **Acceptance criteria:** Target/profile/expiry açık; automatic elevation yok; denied/degraded sonuç typed; rule ownership sınırı kayıtlı.
- **Test yöntemi:** Validation, fake privilege denial, scope/command serialization.
- **Kapsam dışı:** Gerçek rule yazma veya automatic response.
- **Başlatma kapısı:** Do not start before NS-099 and explicit response GO decision; M17 de tamamlanmış olmalıdır.

### NS-101 — Windows Firewall adapter

- **Durum:** ⬜ Conditional plan; başlatma kapısı bekleniyor.
- **Amaç:** Dar owned firewall kuralını Windows'ta yönetmek.
- **Yapılacaklar:** Structured COM/typed Windows API ile add/read/remove adapter ve sanitized permission errors ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/infrastructure/, src/netsentinel/application/ports.py, tests/unit/infrastructure/.
- **Bağımlılıklar:** NS-100.
- **Acceptance criteria:** Program/IP/port/profile bounded; shell injection yok; unrelated rule'a dokunmaz; mevcut akışı hemen kesme garantisi verilmez.
- **Test yöntemi:** Fake API ve explicit isolated Windows rule tests.
- **Kapsam dışı:** Custom WFP driver veya process termination.
- **Başlatma kapısı:** Do not start before NS-099 and explicit response GO decision; M17 de tamamlanmış olmalıdır.

### NS-102 — Owned rules/audit/reconciliation

- **Durum:** ⬜ Conditional plan; başlatma kapısı bekleniyor.
- **Amaç:** Oluşturulan kuralların sahipliğini, expiry ve rollback'i sürdürmek.
- **Yapılacaklar:** UUID manifest, idempotent command, short transaction audit ve OS/DB partial failure reconciliation ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/services/, src/netsentinel/infrastructure/sqlite/, src/netsentinel/shared/diagnostics.py, tests/integration/.
- **Bağımlılıklar:** NS-095, NS-101.
- **Acceptance criteria:** Duplicate/stale/external edit açıklanır; yalnız NetSentinel-owned rules kaldırılır; partial failure recoverable; audit bounded.
- **Test yöntemi:** Fake OS/DB failure, restart, external edit ve expiry testleri.
- **Kapsam dışı:** Başka uygulama/kullanıcı kurallarını değiştirme.
- **Başlatma kapısı:** Do not start before NS-099 and explicit response GO decision; M17 de tamamlanmış olmalıdır.

### NS-103 — Manual response UI

- **Durum:** ⬜ Conditional plan; başlatma kapısı bekleniyor.
- **Amaç:** Kullanıcıya firewall etkisini görüp onaylama ve undo akışı vermek.
- **Yapılacaklar:** Target/profile/expiry/rollback preview, explicit confirm/Cancel, permission sonucunu ve audit'i UI'da göster.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/presentation/, src/netsentinel/application/services/, tests/gui/.
- **Bağımlılıklar:** NS-082, NS-102.
- **Acceptance criteria:** Cancel write yapmaz; admin yokken local trust çalışır; undo accessible; partial result açık.
- **Test yöntemi:** Offscreen denied/success/partial/rollback/Cancel.
- **Kapsam dışı:** Automatic blocking veya silent elevated helper.
- **Başlatma kapısı:** Do not start before NS-099 and explicit response GO decision; M17 de tamamlanmış olmalıdır.

### NS-104 — Firewall/uninstall acceptance

- **Durum:** ⬜ Conditional plan; başlatma kapısı bekleniyor.
- **Amaç:** Gerçek Windows rule ve uninstall davranışını doğrulamak.
- **Yapılacaklar:** Owned rule lifecycle, rollback ve installer cleanup için explicit VM acceptance ve doküman ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** packaging/, docs/RELEASING.md, docs/SECURITY.md, tests/integration/.
- **Bağımlılıklar:** NS-096, NS-103.
- **Acceptance criteria:** Unrelated rules untouched; owned cleanup doğrulanır; yetki yoksa kalan kurallar açık listelenir; automatic elevation yok.
- **Test yöntemi:** Isolated VM rule lifecycle, upgrade/uninstall ve interrupted-action tests.
- **Kapsam dışı:** Üretim ağında riskli test veya driver geliştirme.
- **Başlatma kapısı:** Do not start before NS-099 and explicit response GO decision; M17 de tamamlanmış olmalıdır.
<!-- FROZEN_TASKS_END -->

## 3. Product invariants and minimum response decision

Keep **visibility → context → explainable detection → user response after
evidence/context**. Risk score is not malware probability; TI HIT is not malware;
TI NO_HIT is not safe; signed does not mean safe; unsigned and novelty do not mean
malicious. DNS association can be ambiguous. Polling can miss short-lived flows;
timeline is not forensic completeness; no per-flow byte claim is added.

Every creation and removal begins with a human action and explicit confirmation.
No risk threshold is required for a manual action. A score may be unavailable or
zero while the user still has actionable observed endpoint context. A valid target
and scope are required; an accusation or detector score is not. ACK, RESOLVED,
false-positive feedback, trust and mark-normal never change firewall state.

**Recommended first writable capability, if its entry gates pass:** create one
outbound BLOCK rule for **one validated ordinary desktop executable path AND one
literal remote IP AND one observed TCP/UDP remote port/protocol**, on one explicitly
selected Windows profile, **until manually removed**, with canonical evidence,
collateral warning, an owned rule ID, local audit, readback and accessible Undo.
Do not infer client/outbound intent solely from a TCP established snapshot: if the
flow's initiation direction is unobserved, say so and preview that only outbound
matching traffic is targeted. This is not an exact selected-connection block.

The executable+IP conjunction reduces collateral compared with the proposed
machine-wide IP-only hypothesis. Path safety adds a real gate: if the application
identity cannot be validated, refuse the writable action; **never silently widen
to IP-only**. Start with one rule, no bulk actions or advanced rule editor.
The adapter contract bounds program/IP/port/profile rather than exposing every
Windows Firewall property. UDP is unavailable when the remote endpoint is absent.

| Capability / identity | Recommendation and honest meaning |
|---|---|
| A. Remote IP only | Technically representable, but affects every matching application/user on the machine. Defer first UI exposure because shared/CDN infrastructure increases collateral. Requires a separate explicit broader-scope approval if later added. |
| B. Executable path only | Blocks that path's matching outbound traffic to every destination; too broad for first response. Defer. Path is not hash or immutable application identity. |
| C. Executable + literal IP | Preferred, narrowed further by observed transport/remote port and selected profile. Applies to every instance/user matching that path, not only the selected PID. Reject unresolved or unsafe path. |
| D. Domain | Defer. IP association is not stable domain identity; no DNS resolution or copying an associated domain into an IP field. Modern FQDN features have prerequisites and limits; see section 4. |
| E. PID | Never a durable firewall target. PID/create-time/session help check provenance only. PID reuse or process exit cannot retarget a command. |
| F. Packaged app / service identity | Defer UWP/package identity and service-hosted processes; the selected classic COM path model does not authorize package/service targeting. |
| View owned rules/history | Required, local and read-only; active/inactive/drift/effect status plus exact ID and Undo path. No management of unrelated rules. |
| Undo/remove owned unchanged rule | Required, confirmed and idempotent. Remove exactly the created rule; do not add an ALLOW rule or restore global policy. |
| Disable/re-enable owned rule | Defer separate UI controls. Removal provides one rollback meaning; external disablement is drift. No automatic re-enable. |
| Copy evidence / open process location | Useful manual inspection aids using existing supported affordances, not a new response task. Copy is user-selected local data; open location is explicit, validates local path, and never executes the file. No bulk/raw support export expansion. |
| Terminate process | Reject for M18: explicitly outside NS-101/ROADMAP scope, destroys unsaved work, has PID/TOCTOU hazards and cannot provide meaningful Undo. No kill or kill automation. |
| Automatic firewall blocking | Reject on alert, incident, TI HIT, novelty or risk score. No `risk >= X => block`, background policy engine or automatic retry of a create. |

No Defender/SmartScreen bypass, security exclusions, driver installation, custom
WFP/kernel driver, firewall replacement, mandatory service, hidden scheduled task,
or persistent elevated agent. Local monitoring continues when response is denied.

## 4. Windows backend choice and documented limits

**Choose structured Windows Firewall COM**, `INetFwPolicy2` / `INetFwRules` /
`INetFwRule`, behind a typed application port, as NS-101 specifies. Bindings are
an implementation decision after GO and dependency review; domain/application
must not import COM/Qt/SQL. No shell, interpolated PowerShell, `cmd`, `netsh`
string, user-supplied script, or registry editing in the response backend.
Documented PowerShell may be used by an operator for VM diagnostics, never as
an arbitrary command execution port. No live firewall API was called in this review.

| Documented behavior | Required design response |
|---|---|
| Add returns permission/argument errors, and can overwrite an existing rule with the same identifier | Pre-read and collision refusal; no blind upsert. Read back exact intended fields after a successful call. [Microsoft Add](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrules-add). |
| Remove takes a rule name; missing rule removal has no effect | Never remove by prefix/group/wildcard. Confirm uniqueness and manifest match, then remove exact name and verify absence. [Microsoft Remove](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrules-remove). |
| Rule property changes are committed individually; newly added rules may have application lag | Build a detached complete object before Add; no editing active rules in place. Submission is not instantaneous connection termination. [Microsoft INetFwRule](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule). |
| RemoteAddresses accepts broader lists/ranges/keywords as well as IPs | Portable validation permits exactly one canonical literal unicast IP; reject wildcard, subnet, range, list, hostname and keyword. [Microsoft addresses](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrule-get_remoteaddresses). |
| Profiles are a bitmask; local rule effectiveness can be affected by policy | Initial UI selects one Domain/Private/Public profile, no implicit ALL. Read current modify state and expose unknown/blocked policy. [Microsoft profiles](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrule-get_profiles), [modify state](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_localpolicymodifystate). |
| Block/allow precedence and local policy merge matter | Do not change existing allows/blocks, GPO/MDM merge, firewall enabled state or defaults to make the rule effective. Removal may leave other blockers. [Microsoft rule behavior](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules). |

Proposed allowlisted rule specification: OUTBOUND, BLOCK, enabled; exact canonical
absolute program path, exact remote host IP, explicit TCP or UDP and one remote
port (1–65535), one selected profile. Local address/port unconstrained, no interface
binding, no service/package filter, no edge traversal. These unconstrained fields
must be visible as scope, not inferred from the selected flow. Windows firewall
profile is not NetSentinel's network fingerprint. Current profile is only a
preview candidate; multiple/unknown profiles require explicit selection. A rule
can stay installed while its profile is inactive. Same-profile traffic on another
NIC/VPN can match. Rule is machine-level even though the manifest is per-user.

FQDN blocking is not universally impossible on Windows. Microsoft's dynamic
keyword feature has Defender/Network Protection prerequisites, DNS observation,
DoH/proxy/VPN and restart limitations; it does not supply the stable domain
semantics this product needs. Do not disable DoH or alter Defender configuration
to support it. [Microsoft FQDN requirements and limitations](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/dynamic-keywords).

The reviewed classic COM interface exposes no rule TTL/expiry property. **Planning
inference:** a local expiry timestamp alone cannot guarantee OS removal when the
app is stopped, crashed, asleep or lacks privileges. This is not a claim about all
possible Windows filtering APIs. Dynamic WFP sessions would change the approved
backend/lifecycle model and are not proposed as an expiry workaround.

## 5. Target validation and collateral safety

### Executable path

Obtain the path from the exact canonical connection lifecycle/source, not a
display name, PID-only lookup, free-text inference or newest process with that PID.
At preview and immediately before mutation, recheck process-instance metadata
where still available and the local file identity, final path, file ID/size/mtime;
show missing/stale source separately. A changed target invalidates confirmation.
Missing file, unavailable identity, UNC/network path, device path, relative path,
environment expansion, alternate data stream, symlink/reparse component or an
unverifiable final local path is denied for first release. Never execute/load the
target or perform network path access to validate it.

If a retained local hash/revision exists, display its time and distinguish it from
current file metadata; a detected hash/metadata change invalidates the preview.
No implicit hashing/TI lookup is triggered solely by opening response. A hash is
provenance, not a firewall condition, and does not prove the loaded image is intact.
No absolute TOCTOU guarantee is claimed: path rules can later match replacement
files and all future processes at that path. Moving the executable leaves the
rule pointing to its old path; path reuse can affect a different executable.
Display these limits and any observed drift. Never follow a move, rewrite or
automatically re-enable a rule. Reject Windows/system processes, NetSentinel and
its privilege component, service hosts/shared hosting and packaged apps in the
first UI; do not guess the hosted service from `svchost.exe` or a process name.
Unicode and supported long paths require exact readback tests; unsupported path
forms return typed unavailable instead of truncation or another path.

### Remote IP

Parse with a strict typed IP parser, canonicalize IPv4/IPv6 once, and bind the
confirmation to that exact value. Treat IPv4-mapped IPv6 explicitly; no implicit
dual-family expansion. Reject unspecified, loopback, multicast, broadcast,
link-local/zone-index and other special/non-global targets in the initial writable
UI. Private lab targets may be exercised only through an explicit isolated test
fixture, not a broadened production input policy. Synthetic documentation IPs in
this document are wording examples, not production-eligible targets.

An observed IP may be shared by CDN/cloud tenants or map to multiple domains;
dynamic reassignment can change its meaning later. Show associated DNS names only
with original time, TTL, ambiguity and source status. Never imply domain blocking
or DNS→process certainty. Literal IPv4 blocking does not cover another IPv6 address
or vice versa. The user sees that legitimate app features, updates or authentication
may fail, and that rules can apply across users/instances of the chosen path.

VPN changes, multiple NICs, DHCP, disappearing/reappearing interfaces and
sleep/resume do not authorize retargeting. Preserve the original observed network
context while displaying current Windows profile separately. Refresh or reconnect
does not extend scope or add IPs. VPN enforcement for inner/outer traffic and
IPv6 must be measured; unknown effectiveness is not a successful block.

## 6. Privilege model — unresolved implementation gate

Firewall mutation normally needs administrative rights; actual Add/Remove results
and machine policy remain authoritative. An elevated token alone is not proof of
effective local policy. [Microsoft administration requirement](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/create-inbound-rules-to-support-rpc).

The desktop remains **asInvoker**. Preview, history, evidence and local trust work
without admin. Standard-user mutation returns typed `PRIVILEGE_REQUIRED` /
`ACCESS_DENIED`; read access failure is separately `READ_UNAVAILABLE`. No startup,
selection, detector, retry, expiry timer or uninstall automatically raises UAC.

Candidate for approval during NS-100 design: a **one-operation helper**, launched
only by a separate human choice **“Continue with Windows administrator approval”**
after the exact preview. Normal Windows UAC is the sole credential surface; the
app never requests/stores admin passwords. Main monitoring GUI is never restarted
elevated. UAC cancellation performs no mutation. Helper exit ends its authority;
Undo needs its own explicit approval. Microsoft documents separating privileged
operations from an asInvoker app, using explicit `runas`/COM elevation.
[Microsoft privilege minimization](https://learn.microsoft.com/en-us/windows/win32/secbp/running-with-administrator-privileges).

**This helper is a conditional design candidate, not approved architecture.** The
current `%LOCALAPPDATA%` installer/payload and SQLite are user-writable. Elevating
a caller-supplied script, plugin, Python module, executable or mutable manifest
would make an unprivileged caller a machine-wide policy author. UAC approval of a
binary is not confirmation of its target or immutable dependencies. Require a
trusted deployment/integrity story for the helper and all loaded code, no DLL/
module search through user-controlled locations, and independent privileged
validation plus a plain-text exact-target confirmation in the trusted component.
An administrator entering credentials for a different account must not redirect
the action/audit to that account's LocalAppData or authorize a different target.

The contract must authenticate/bind requester, interactive session, nonce,
action UUID and canonical spec; one request, bounded transport, no reusable admin
IPC endpoint. Never trust a DB row, confirmation flag or command-line argument as
proof of user intent. Helper cannot enumerate/change arbitrary rules, execute
commands, open files as admin, install drivers, change global policy or serve
background clients. Separate originating-user identity from approving-admin
identity; unavailable identity is labelled unknown, not fabricated.

If a trusted bounded helper requires a protected deployment change, explicitly
review that change against NS-096 philosophy and obtain scope approval; do not
silently add a system installer/service. **Until this boundary is resolved,
in-product writes stay disabled.** Reduced fallback is read-only evidence/rule
guidance and a human administrator using Windows Firewall independently. Such
external actions are not labelled NetSentinel-owned or audited successes and do
not satisfy NS-101–104 writable acceptance. If no acceptable route exists, M18
write implementation is **NO_GO**, even though contract planning can proceed.

## 7. Confirmation UX and evidence-rich entry points

First entry: selected **Alert detail** or **Incident timeline's exact selected
evidence/connection entry** → secondary “Review firewall rule…” action. An incident
container does not justify targeting every member/IP; select one canonical source
with sufficient executable/endpoint context. If it lacks that context, inspection
remains available and creation explains why it is unavailable. A selected
Connection detail with timestamp/process/endpoint/quality can offer the same
review without a score threshold. Defer generic process-page/list-row shortcuts,
notification quick-block, Dashboard block and batch incident actions.

Opening this review never mutates state, refreshes TI or resolves a domain. Show:

1. Exact action and rule ID; outbound direction, transport and destination port.
2. Full executable path and literal IP/family; expandable/selectable full values,
   never confirmation against a clipped label. Explain all instances/users and
   unconstrained local address/port.
3. Explicit Domain/Private/Public selection, active/inactive status, observed
   network scope versus current profile, and lifetime **until manually removed**.
4. Original UTC observation, canonical lifecycle/evidence/alert/assessment revision
   or incident-entry pointer, source availability, age, measurement quality/gaps,
   and correlation/DNS uncertainty. Historical evidence may be old; changed
   identity/spec requires a new preview. Missing observation quality stays unknown.
5. Local risk explanation if present, plus optional already-retained TI provenance,
   queried time and freshness; no fresh lookup just to make a block attractive.
6. Expected effect and collateral: matching outbound traffic may fail, shared
   infrastructure may be legitimate, VPN/profiles can change applicability,
   existing connections may continue, neither rule creation nor score is a
   malware verdict.
7. Exact Undo path, admin requirement, persistence through app exit/restart,
   crash/uninstall policy and the fact another rule may still block after Undo.

Illustrative copy with synthetic targets:

> Create an outbound Windows Firewall rule blocking TCP to 203.0.113.10:443 for
> C:\Example\app.exe on the Private profile, until you remove it.

> This IP may be shared by legitimate services. The rule may break this app's
> functionality and affect other instances at this path. Evidence is not a malware
> verdict. Existing connections may not stop immediately. The rule remains after
> NetSentinel closes. Undo requires administrator approval.

Buttons: **Cancel**, **Create firewall rule**, then separate administrator approval
choice if necessary. Undo confirmation names the exact rule and effect. Cancel in
the review before command dispatch writes neither OS state nor response intent/audit;
do not audit mere selection. After confirmed dispatch, UAC cancellation is a failed
attempt recorded against the durable intent, with no OS mutation. Closing the window
after dispatch cannot promise OS cancellation: pending outcome is retained and
reconciled. A denied attempted action is an audit failure.
Keyboard/focus/accessibility names and plain-text hostile strings must be tested.
No “Block malware”, “Block threat”, “Safe now”, “Process isolated” or guessed
domain-block wording. Success UI says **“Rule created and read back; traffic effect
not measured here”**, not “connection blocked”.

## 8. Ownership, command identity and rollback

Allocate a random UUID once per confirmed intent. Stable deterministic name from
that UUID: **`NetSentinel:<canonical-uuid>`**; retry uses the same action/name, not
another rule. UUID is independent of IP, risk score, process name and source alert;
same target does not grant ownership. Store a schema-versioned manifest and exact
canonical expected rule specification/fingerprint. Fixed description marker can
contain version and UUID only; no raw note/path/history. Grouping is only display
metadata, never authority, and its supported encoding is validated in NS-101.

Manifest: action/command UUID, exact OS name, origin store identity/requester when
available, created/confirmed/attempted/verified UTC times, canonical source refs,
target, transport/port, direction, profile, lifetime, expected enabled state,
expected full relevant properties, observed state/time and rollback state.
Name prefix/group/description alone is insufficient. Manifest plus unique exact
OS name plus full relevant readback equality is required before management.
All exposed properties capable of altering scope/effect must participate;
unsupported/future rule types are not assumed equal. Never adopt unmanifested
prefixed rules or rules from another user's store. No privacy-sensitive requester
SID is put in shared display strings; local audit may retain a minimized typed
identifier when justified, otherwise unavailable.

Before Add: enumerate exact matches with bounded scanning; zero allows creation,
one already verified owned match may yield `ALREADY_PRESENT` after reconciliation,
any foreign collision, mismatch or duplicates yields `OWNERSHIP_CONFLICT` and no
write. Before Remove: fresh read and equality check, then exact removal and fresh
absence read. COM offers no compare-and-swap transaction for external edits;
preflight/readback cannot give absolute atomicity. Namespace collision and
concurrent admin edits must be tested. If strict unrelated-rule protection cannot
be maintained for supported conditions, deny writes rather than claiming safety.
No adversarial-local-admin/tamper-proof ownership guarantee is claimed.

Undo removes only that unchanged owned rule. It never deletes unrelated allows,
resets firewall defaults, deletes by group/prefix, kills a process, adds an ALLOW
rule, or restores a stale whole-firewall snapshot. Repeat Undo when verified absent
returns “already absent”; absence first discovered on restart is externally missing
or cause-unknown, not proof NetSentinel undid it. Failure/timeout leaves Undo
pending/unknown; no recreated rule or silent compensation. All Undo attempts are
auditable, separately confirmed, and available after app restart.

## 9. Durable state, audit and failure semantics

Dedicated local response history is the canonical action store. Alerts/incident
details may show separate linked response rows using the exact source pointers;
never mutate observations, assessments, scores, occurrences or lifecycle feedback
to make a response look successful. Incident linkage is a read projection of
response history, not a new correlated security event or incident merge. Source
expiry leaves minimum action provenance and explicit unresolved/expired status.
For a connection without an alert, retain lifecycle/time/endpoint provenance; do
not manufacture an alert to enable response.

Use **three independent dimensions**, retaining append-only bounded events rather
than overwriting historical success:

| Dimension | States / meaning |
|---|---|
| Command | `INTENT` (confirmed, durable), `ATTEMPT` (durable before OS call), `SUCCESS` (exact postcondition read back), `FAILURE` (known failed outcome), `OUTCOME_UNKNOWN` / `PARTIAL` (OS/DB/readback disagreement) |
| Current OS rule | verified present/enabled, inactive profile, externally disabled/modified, `EXTERNALLY_MISSING` (cause unknown unless separately evidenced), read unavailable/unsupported/duplicate |
| Rollback | not requested, requested/attempted, `ROLLED_BACK` (postcondition verified for this Undo), already absent, denied/failed/unknown |

Traffic effectiveness is separate: not measured, policy-limited/unknown, or a
**native lab acceptance result with its own time/scope**. `SUCCESS` means verified
rule creation/removal only; it never means malware stopped or connection terminated.

Sequence: reserve audit/recovery capacity → durable confirmed INTENT with immutable
spec → durable ATTEMPT → privileged revalidation/confirmation → OS call → readback
→ short transaction receipt. DB and OS are not one atomic transaction. If INTENT/
ATTEMPT persistence fails, no OS mutation. If OS succeeds but receipt commit fails,
keep the preexisting intent and recover from exact readback; report partial. The
privileged component needs a bounded trusted pending receipt to bridge lost IPC/
GUI crashes; safe placement/ownership is part of the privilege gate, never an
attacker-editable authorization source. Reconciliation records discovery time,
not an invented earlier completion time. Timeouts never trigger blind create retry.

| Failure / drift | Safe result |
|---|---|
| Access denied / UAC cancel | No automatic retry/elevation; sanitized typed failure, local monitoring/trust continue |
| Duplicate/collision/stale preview | No overwrite or widening; refresh/reconfirm required |
| OS Add accepted, readback unavailable | Outcome unknown, rule may exist; show exact ID and recovery instructions |
| OS/DB partial failure, crash at any boundary | Keep intent/provenance; reconcile read-only, retain unresolved state |
| Remove accepted, readback unavailable | Undo unverified, never report removed solely from call return |
| Rule missing / externally edited or disabled | Show missing/modified/disabled, do not recreate, repair, re-enable or delete |
| Firewall stopped/disabled, policy excludes local rules | No enabling service/firewall or policy change; unavailable/limited result |
| Storage corrupt/full/future schema | Disable new mutations; preserve OS rules, offer external manual inspection/Undo guidance |
| Shutdown while privileged attempt is in progress | Do not equate worker cancellation with OS cancellation; receipt/restart recovery |
| Profile/interface/VPN/sleep/clock changes | No retarget/replay; disclose current applicability and uncertain outcome |

Proposed NS-102 bounds to ratify in NS-100: at most **64 unresolved/installed
manifests**, **1024 total action records**, **8192 audit events**, **16 KiB per
manifest**, **2 KiB per event**, paginated **25 default / 100 maximum**; one mutation
in flight, bounded read work, no unbounded retries. Reserve completion/Undo events
before admitting creates; no eviction of unresolved/installed ownership. If even
rollback audit cannot be safely reserved, disable further managed mutation and
show external manual removal instructions. Terminal-only history cleanup can be
explicit after a documented retention period; proposed 90 days, never delete the
last ownership record for a rule that may remain. Quotas/retention are proposals,
not implemented constants or frozen task changes.

Additive future schema/codec work belongs to NS-102, with strict typed fields,
parameterized SQL, version/corruption handling, short worker-owned transactions
and retention integration. Current schema stays **019**. NS-095 purge/retention
must protect installed/unresolved manifests and explain that deleting history
does not Undo firewall rules. Diagnostics/support export contain aggregate counts
and typed error codes only, no IP/path/hash/SID/provider body/secret/raw exception.
Response audit stays local; no upload, cloud request or provider report because
an action was taken. It is not a signed forensic/tamper-proof log.

## 10. Expiry, crash, restart and external modification

| Lifetime option | Decision |
|---|---|
| Until manually removed | Initial recommendation, clearly persistent across app exit/OS restart; admin Undo and uninstall list mandatory |
| 15 minutes / 1 hour | Bounded lifetime would reduce collateral if reliably enforced. Defer writable UI promise until removal can be guaranteed or an explicitly honest best-effort model is approved. A timestamp/timer alone is insufficient. |
| Until app exit | Defer: crash, forced shutdown and lost privilege can leave a persistent OS rule; app exit is not atomic with removal |

The NS-100 contract should distinguish manual lifetime, requested deadline,
removal due/overdue and actual removed, rather than equating expiry with rollback.
NS-102 fake expiry tests cover unsupported timed requests, due/overdue/clock anomaly,
sleep gaps and failed cleanup; passing them does not unlock advertised temporary
blocking. Any later cleanup must derive from a prior explicit authorized lifetime,
only remove unchanged owned rules and remain honest about failures. Automatic
creation remains forbidden. No timer/service/scheduled task is added here.

Crash policy: OS rule state survives coherently and can be identified by exact
name in Windows Firewall; do not depend on graceful app exit. Keep pending intent
and expose an external removal guide that lists exact ID/scope and admin need.
On restart, bounded read-only reconciliation compares manifest and OS rule; no
automatic creation, re-enable, repair, adoption or destructive compensation.
If the local ledger is missing, do not claim ownership from a prefix. Show
unmanaged markers for inspection only; manual administrator recovery remains.

External modification is authoritative user/firewall-manager state. Detect
property drift, disablement and missing rules where observable. A renamed rule
may be indistinguishable from missing plus another rule; say “cause unknown”.
Do not chase renames or rewrite the expected manifest to adopt the new rule.
Modified rules require the user's Windows Firewall manager for changes; an
in-app “delete anyway” override is deferred. No fighting GPO/MDM or another user.

## 11. Uninstall policy recommendation

Keep existing **per-user, KEEP-by-default** philosophy, with firewall and data
choices separate. Recommend **preserve rules by default with a mandatory clear
list**, plus an explicit **remove unchanged NetSentinel-owned rules** choice before
uninstall. Silent uninstall also preserves; no silent UAC or policy change. This
is a future NS-104 change; the current installer has no firewall cleanup.

The list shows exact rule IDs, scope/profile, drift/unverified state and admin
removal guidance. Optional cleanup uses the same confirmed privileged removal
contract, not special installer authority. Successful cleanup must be read back;
permission denial, externally edited rules and unknown outcomes remain listed.
Never silently remove user-modified rules. “All removed” requires verified absence
of every unchanged manifest-owned rule; other rules are untouched.

KEEP data normally retains the ledger. **DELETE data and rule cleanup are separate
decisions:** before ledger deletion, show that preserved rules remain machine-wide
and ownership/audit will be lost. Require a separate explicit acknowledgement and
offer a local recovery list save (user-selected sensitive metadata, not the generic
sanitized support export). If pending outcomes cannot be enumerated, block DELETE
and offer KEEP; do not erase recovery evidence while claiming cleanup. If the
user explicitly elects to preserve rules and delete the ledger after seeing the
list, reinstall must not automatically adopt those rules. External exports stay
outside automatic deletion. No secure erase claim or hidden protected ledger is
added; ledger-loss recovery is deliberately manual.

## 12. Response threat model

| Threat / trust boundary | Planned control and remaining risk |
|---|---|
| Command/path/rule-name injection | Typed COM, generated UUID names, strict IP/port/profile enums, bounded strings; no shell/scripts. Reject NUL/control/unsupported syntax, plain text in UI. |
| Hostile process/domain/provider text | Never executable code/markup/command; no provider URL fetch or arbitrary description. Long text cannot hide the exact target. |
| Stale PID / lifecycle / evidence | Canonical refs, original time, selection generation and immutable spec; revalidate before action, no PID retarget. Historical evidence age remains visible. |
| File replacement / symlink / path reuse / TOCTOU | Reject unsafe path forms, fresh metadata/final-path checks; disclose ongoing path identity limits. No immutable-app or loaded-image guarantee. |
| Unprivileged API/DB/IPC caller | No DB flag confers admin intent; trusted one-shot component revalidates and independently confirms exact target; authenticated bounded request, no reusable elevated endpoint. Unresolved deployment integrity is a blocker. |
| UAC different account / forged receipt | Bind origin user/store/session/action/spec and approving identity separately; do not load admin's data as origin. Unknown/lost receipt means partial, not success. |
| Attacker induces alert/TI to block benign infrastructure | No auto actions, no thresholds, no prechecked mass targeting; explain uncertainty/shared IP and require exact manual confirmation. Social engineering remains possible. |
| Shared IP, critical infrastructure, VPN/CDN changes | Prefer executable+IP+port/profile, refuse unsafe/system targets, no bulk/global/domain scope; warn legitimate features may fail. Perfect collateral prediction is impossible. |
| Forged ownership / duplicate name / external edit race | Manifest plus full fresh unique readback, refuse mismatch/duplicate, never adopt by prefix; COM lacks atomic compare-and-remove and local admin cannot be constrained by this ledger. |
| OS/DB split / timeout / crash | Durable intent before mutation, pending receipt, read-only reconciliation, no blind retry, explicit unknown/partial; preserve Undo evidence. |
| GPO/MDM/disabled firewall / alternate VPN filters | Read policy where supported, separate configured/effective/effect-tested, no bypass/default/service changes. Native matrix bounds supported claims. |
| Audit/privacy/resource abuse | Local quotas/pagination, reserved rollback capacity, typed diagnostics; no secrets/raw history/upload. Local writable storage is not forensic integrity. |

Security review must challenge trusted confirmation and loaded-code integrity,
not merely test string sanitization. Rejecting a mutation is preferable to acting
on an ambiguous identity, collision, unknown ownership or invalid privilege boundary.

## 13. Offline test plan and dedicated native acceptance

No runtime suite is required for this documentation-only change. The following
tests are **future acceptance requirements, NOT RUN**, and do not start tasks.

Fake ports for privilege, firewall add/read/remove, clock, trusted action receipt
and response repository keep default unit/integration tests offline and harmless.
Fake adapter contract covers: success/readback mismatch, access denied, duplicate,
foreign name collision, missing rule, external edit/disable/rename, rollback and
repeat rollback, timeout/outcome unknown, Add-success/DB-failure, DB-failure/no-Add,
restart at every boundary, queue saturation, malformed/future manifests, unsupported
expiry, IPv4/IPv6/mapped IPv6, hostile strings, Unicode and long executable paths,
changed/moved/missing files, symlink/reparse, stale PID, stale confirmation and
selection A→B→A. OS API calls must fail a default-suite guard rather than alter a
real firewall. Offscreen UI asserts Cancel creates zero intent/audit/OS writes,
denied local trust remains usable, no feedback/TI action triggers response, full
target accessible, explicit partial outcome and confirmed Undo.

**Native NS-101/NS-104 tests only in a dedicated, explicitly authorized Windows VM**
with snapshot/recovery access, isolated data and disposable benign client/server
endpoints. Never on the host development machine for this gate. Pre/post unrelated
rule inventory and policy comparison stay in local ignored receipts; publish only
sanitized aggregate results. Use controlled traffic, no malware/C2 or attacks.

| Native scenario | Required evidence |
|---|---|
| Standard user, admin availability, UAC cancel | Honest privilege/read result, no mutation/cancel writes or auto prompt; monitoring/local trust continue |
| Explicit one-shot approval; different admin account | Same displayed action/spec/store, validated requester/receipt, helper exits; no elevated GUI/service/credential capture |
| Create selected executable+IP+TCP/UDP port/profile | Actual OS fields read independently; controlled matching **new** traffic denied, preexisting flow behavior separately recorded |
| Unrelated executable, destination, port, profile/user | Matching-scope effect as previewed; unrelated traffic/rules unchanged; rule's cross-instance/user effect documented rather than falsely excluded |
| IPv4 and IPv6 | Controlled reachability before rule, denial after and recovery after Undo; no implicit other-family coverage |
| Profile matrix Domain/Private/Public, inactive/multiple | Explicit mask/applicability; policy restriction correctly reported; no “effective” claim from installed rule alone |
| Firewall disabled/service unavailable/local merge restricted | Denied/unknown/limited safely; no global/default/service/security policy mutation |
| Undo and repeat Undo | Exact rule gone, normal fixture traffic restored where no other blocker; unrelated inventory unchanged |
| App crash, exit, OS restart, interrupted Add/Remove/receipt | Rule persistence coherent, discoverable ID, durable intent recovered; no recreate/blind retry or invented completion time |
| External deletion, disablement, scope edit, duplicates/rename | Missing/modified/conflict reported, no re-enable/recreate/delete/adopt |
| VPN connect/disconnect, multiple NICs, DHCP and interface return | Same literal target/spec, inner/outer effect explicitly measured, unrelated traffic unaffected, no retarget |
| Sleep/resume | Supported native VM sleep verified separately from hypervisor suspend; persistent rule/readback/traffic and due-state honesty. Unsupported native sleep is NOT RUN, not PASS. |
| Unicode/long path, move/replace/reparse | Exact path readback or safe unavailable; target drift invalidates confirmation; no silent widen |
| Upgrade/repair and uninstall preserve/remove × data KEEP/DELETE | Default preservation/list, explicit cleanup success/denial/partial, changed rules preserved, recoverable ledger-loss warning; unrelated inventory intact |
| Privacy and privilege tampering | No new cloud/TI/upload, no raw diagnostics, altered DB/IPC/script inputs cannot silently obtain arbitrary elevated operations |

Native block verification uses disposable reachable endpoints and independent
OS/fixture observations; a failed connect alone may be server failure. Record
control success, rule installed/readback, scoped deny, unaffected control, Undo
and restored success. Do not assert all Windows builds/VPNs from one VM. Separate
operator/human confirmation clarity review from offscreen functional checks.

## 14. Frozen dependencies and recommended order

Preserve task order: **NS-100 → NS-101 → NS-102 → NS-103 → NS-104**. Existing
prerequisites are complete, but explicit user response GO is still absent.
Do not ship or expose NS-101 writes without NS-102 recovery/audit and NS-103
confirmation; adapter-only testing stays isolated behind fakes/VM opt-in. This
adds safety gates within the frozen sequence, not task reordering or completion.

| Task / purpose | Exact prerequisites | Future production areas | Persistence / privilege | Native / rollback | Biggest safety risk |
|---|---|---|---|---|---|
| NS-100: narrow response/permission contract | NS-082, NS-099, explicit response GO; M17 complete | `domain/`, `application/ports.py`; SECURITY and unit tests | Pure typed intent/spec/results, no rule writes or migration; specify privilege candidate and denial | No real rule test required; fake denial/serialization; contract must define Undo and partial states | Contract implies immutable app identity or trusts user-writable input as admin consent |
| NS-101: structured Windows adapter | NS-100 | `infrastructure/`, `application/ports.py`, infrastructure tests | Add/read/remove receipts through port; admin mutation, standard-user degraded behavior | Explicit dedicated VM rule tests; exact owned removal/readback, no live default suite | Collision overwrite, shell injection or API-success-as-block claim |
| NS-102: ownership/audit/reconciliation | NS-095, NS-101 | `application/services/`, `infrastructure/sqlite/`, sanitized diagnostics, integration tests | Additive versioned bounded manifest/audit, OS/DB split recovery; no privilege bypass | Fake crash/DB/OS/drift/expiry plus restart VM validation; reserve Undo metadata | Lost ownership after OS success/DB failure or deleting externally edited rules |
| NS-103: confirmed manual UI | NS-082, NS-102 | `presentation/`, application services, GUI tests | Reads/history and immutable confirmed commands; explicit action-time approval only | Offscreen Cancel/denied/success/partial/Undo; native human/UAC acceptance before delivery | Vague scope, stale selection, hidden elevation, treating feedback as firewall action |
| NS-104: real lifecycle/uninstall acceptance | NS-096, NS-103 | `packaging/`, RELEASING/SECURITY docs, integration tests | Ledger retention/DELETE policy and cleanup receipts; no new automatic elevation | Dedicated VM create/effect/Undo/crash/upgrade/uninstall; unrelated rules proven untouched | Uninstall deletes recovery ledger or falsely reports cleanup without permission |

Gate graph:

```text
M17 complete + NS-099 complete + explicit USER response GO (not yet given)
  + NS-082 -> NS-100 -> NS-101 -> NS-102 -> NS-103 -> NS-104
                                  ^          ^          ^
                              NS-095      NS-082      NS-096
Trusted privilege boundary must be resolved before any native mutation.
NS-102 + NS-103 must be ready before exposing writable adapter to users.
NS-104 must pass before calling M18 complete or distributing response capability.
```

## 15. DEFER / reject list

Grounded in TASKS NS-100–104, ROADMAP M18 and SECURITY conditional response:

- All automatic blocking on alerts, TI, risk, novelty or incidents; global
  reputation lists, auto retry/create/re-enable and any risk threshold policy.
- Process termination/manual kill for M18 and all kill automation.
- WFP/kernel/custom packet driver, firewall replacement, driver install,
  persistent elevated agent/service or scheduled task to bypass UAC.
- Domain/FQDN blocking, DNS resolution to manufacture a target, packaged-app and
  service-host/system-process rules, executable-only and machine-wide IP-only UI.
- Bulk blocks, inbound rules, ranges/subnets/wildcards, automatic dual-family
  expansion, interface-tied assumptions and a general firewall editor.
- Guaranteed 15-minute/1-hour/app-exit expiry without a validated removal model;
  background security policy changes and automatic uninstall cleanup.
- Override of externally edited rules, prefix-based adoption/deletion,
  global restore/reset, ALLOW-rule rollback, elevated GUI and arbitrary helper API.
- Cloud response telemetry, provider reporting, automatic history/crash upload,
  new reputation request triggered by response, Defender/SmartScreen/DoH bypass.

## 16. Decision criteria, blockers and NS-100 entry conditions

**Planning result: CONDITIONAL_GO.** Evidence/context architecture supports a
conservative response design. The all-program IP-only hypothesis is reduced to
validated executable+IP+transport/port/profile. Unconditional write readiness is
not established. This plan itself neither grants explicit response GO nor starts
the contract implementation task.

| Gate outcome | Required condition |
|---|---|
| GO for subsequent authorized implementation | User explicitly approves starting NS-100; scope/lifetime/ownership/audit are accepted; credible narrow trusted privilege design fits approved scope; fake/native evidence at each later task passes |
| CONDITIONAL_GO (this review) | Design is useful and consistent, but privilege deployment and collision/partial-failure rollback must be settled and then tested; every task stays NOT STARTED |
| NO_GO for writes | Requires persistent admin service/hidden task/elevation/bypass; cannot own/remove exactly; cannot distinguish submission/readback/effect; collateral cannot be bounded; unsafe command surface; insufficient audit/recovery; unclear uninstall or untrusted privileged deployment |

**Current blockers / open decisions:**

1. Explicit user response implementation GO has not been given; planning-only
   authorization cannot substitute for it.
2. Trusted one-shot action-time privilege boundary under user-writable per-user
   packaging is unresolved. No silent system-install scope expansion is allowed.
3. COM name/identity collision, uniqueness, full property comparison and
   external-edit race behavior require NS-101/102 fake/native proof; no atomic
   compare-and-swap ownership promise is available from the reviewed API.
4. Durable OS/DB/IPC partial-failure recovery and reserved rollback capacity need
   contract review and acceptance before writes are exposed.
5. First lifetime **until manually removed**, explicit profile/transport/port
   scope and preserve-by-default uninstall/ledger DELETE warnings need product
   acceptance. Guaranteed temporary expiry is deferred, not secretly promised.
6. Dedicated response VM, reachable disposable IPv4/IPv6 fixtures, administrative
   approval and recovery/snapshot access must exist before native rule tests.
   No M17 VPN/S3/UX result is re-labelled as firewall acceptance.

**Recommended NS-100 entry conditions:** repository/task state reverified;
M17/NS-099 and NS-082 accepted; explicit user instruction authorizes NS-100 only;
this bounded scope and manual lifetime are accepted; privilege/ownership threat
model reviewed with an explicit deny/reduced-scope outcome if unsolved. NS-100
then defines typed contract, validation, fake denied/degraded results and command
serialization only. It must not write real rules or silently authorize NS-101.
Every later task obeys its frozen dependencies and documented native/rollback
gates; a scope-expanding deployment decision requires separate explicit approval.

## 17. Delivery and validation record

Only `docs/M18_RESPONSE_PLANNING.md` is added. TASKS statuses and frozen definitions
are unchanged; no implementation, migration, installer build, native firewall
operation or runtime test suite is performed. No commit/push is implied by document
creation. Validation: `git diff --check` and the new-file equivalent
`git diff --no-index --check -- NUL docs/M18_RESPONSE_PLANNING.md` PASS. A bounded
scan of this one document found **0** private-key/token/secret-assignment,
personal-path/account-SID/email or non-example IPv4 findings; the single
203.0.113.10 example in the UX copy is synthetic documentation. Manual review found
no raw telemetry or credential. This is a bounded heuristic review, not exhaustive
secret detection. All **16** distinct local document-link targets exist. Frozen
M18 gate and NS-100–104 text match TASKS exactly with line endings normalized for
comparison. Only this new document appears in repository changes. HEAD remains
`8600d9a`; document is uncommitted, with no push, tag or release.

**NS-100: NOT STARTED. NS-101–104: NOT STARTED. Tag/release: NONE.**

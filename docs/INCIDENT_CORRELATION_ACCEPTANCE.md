# NS-089 implementation / acceptance report

2026-10-04; repo `C:\Users\berke\NetSentinel`. Verified starting main HEAD:
`4472bca37065a051ba1a3a07c49f6ef5ef9067aa`; initially clean working tree.
Authoritative task: `docs/TASKS.md`, NS-089.

The [policy freeze](INCIDENT_CORRELATION.md) was written before code. The fixed
UTC cohort boundary is a deliberate conservative policy choice: nearby events
on opposite sides do not attach. This is stricter than a sliding ten-minute
window. Unambiguous supported input sets have order-independent membership;
arbitrary bridging/eviction/late sets do not claim that property.

## Requested report items

| # | Item / result |
|---:|---|
| 1 | **NS-089 — Bounded incident correlator** |
| 2 | **COMPLETE**; all NS-089 acceptance gates passed. |
| 3 | M16 in progress; NS-090–092 remain planned, M16 not COMPLETE. |
| 4 | SQLite supported schema **018**, verified from built-in migration manifest. |
| 5 | **018 → 018**; no migration or SQL resource changed. |
| 6 | Frozen `IncidentInput`, `IncidentObservationRef`, `CorrelatedIncident`, `IncidentRelation`, `IncidentCorrelationResult`, `IncidentPolicy`. |
| 7 | UUID4 runtime incident ID; stable while retained, no durable/replay/restart identity promise. |
| 8 | Typed process/session, connection session/lifecycle, destination, scope, alert UUID and assessment revision pointers. |
| 9 | Existing NS-076 `EvidenceReference`: risk evidence digest, legacy event digest, canonical DNS UUID; no payload/snapshot clone. |
| 10 | Reason enum plus exact matched typed correlation key; isolated seed explicitly FIRST_OBSERVATION. |
| 11 | Strong matrix in policy doc: exact lifecycle, evidence, assessment lineage, alert reference, fully identified process+destination+resolved scope. |
| 12 | IP/domain/app/PID-only/network/time/severity/score/ASN/country/signer/hash/parent alone do not attach. |
| 13 | Priority: lifecycle → evidence → assessment → alert → process+destination. |
| 14 | Same session/lifecycle metadata observations attach within cohort. |
| 15 | Same canonical evidence attaches; identical observation reference/time/kind is duplicate. |
| 16 | Same assessment logical digest attaches distinct revision pointers using original observation time. |
| 17 | Exact process create-time + session + destination port/protocol + equal resolved scope + clean quality + cohort required. |
| 18 | Same process, different destination: separate unless another canonical link connects it. |
| 19 | Different processes, shared IP: separate unless an independent exact canonical link is supplied. |
| 20 | Different processes, shared domain: same conservative behavior; association is not causal proof. |
| 21 | Same application across different process instances: no app key in the correlator. |
| 22 | PID alone never a derived relation key. |
| 23 | Same PID, different create-time: different instance; regression passed. |
| 24 | Unknown process is retained as absent; no fabricated identity. |
| 25 | Partial PID identity retained with session context; cannot make a process+destination key. |
| 26 | Existing NS-056 session/lifecycle UUID semantics retained; polling observations only. |
| 27 | Connection tuple reuse does not imply lifecycle equality; unknown-instance tuple reuse stays separate. |
| 28 | Canonical IPv4 typed destination. |
| 29 | Canonical IPv6 typed destination; interface zones rejected. |
| 30 | DOMAIN and IP are distinct identities; canonical DNS naming reused. |
| 31 | Port retained and compared; absent port disallows the derived key. |
| 32 | TCP/UDP retained and compared; absent protocol disallows the derived key. |
| 33 | Existing EvidenceScope preserves host/resolved/unknown/ambiguous. |
| 34 | UNKNOWN has no fabricated network fingerprint; cannot make a derived key. |
| 35 | AMBIGUOUS stays distinct, also disallows a derived key. |
| 36 | Different resolved fingerprints do not attach by process+destination; exact canonical links may bridge. |
| 37 | Ten-minute UTC-aligned half-open cohorts. |
| 38 | Total incident span bounded by ten minutes. |
| 39 | Upper boundary equality begins new cohort; epsilon inside eligible, epsilon outside separate. |
| 40 | 10:00/10:09/10:18 cannot chain into an eighteen-minute incident. |
| 41 | Caller-supplied UTC event time only; no datetime.now(). |
| 42 | Arrival order does not establish temporal/causal order; relation pointers sorted by observation time. |
| 43 | Ten-minute inclusive lateness; 24 insertion permutations spanning two cohorts give equal unambiguous membership. |
| 44 | Older events return LATE without reopening state; twenty-minute retention horizon. |
| 45 | Existing failed/reduced/loss round markers and NS-076 quality deny derived continuity; exact refs may bridge with limitation. |
| 46 | INITIAL ConnectionOpened maps to connection_observed, never an OS connect claim. |
| 47 | Process identity is observed context; create-time is not converted into an event. |
| 48 | No PROCESS_CREATED/process-start inference or event kind. |
| 49 | Canonical observation kind/reference/time drives retained-state idempotency; wrapper recreation does not duplicate. |
| 50 | Assessment revisions retain separate small pointers within one lineage. |
| 51 | Real offline NS-088 HIT/NO_HIT revision 2 attaches revision 1's incident; original time preserved. |
| 52 | Fingerprint absent from input; exact alert UUID still obeys bounded cohorts. |
| 53 | Alert state/count/time/severity/confidence remain owned by existing pipeline, unchanged by correlation. |
| 54 | Suppressed evidence can be explicitly supplied; suppression is not evaluated/changed here. |
| 55 | Mark-normal/preference state not a correlation identity and not mutated. |
| 56 | Severity/score absent from correlation input and keys. |
| 57 | ASN/country absent from keys. |
| 58 | Signer/hash/artifact context absent from keys. |
| 59 | Parent metadata absent; no ancestry/causality inference. |
| 60 | Strongest reason first, canonical first observation breaks equal-priority ties; ambiguity limitation retained. |
| 61 | No incident union or recursive graph traversal; unmatched aggregates remain unchanged. |
| 62 | Max active incidents **256**. |
| 63 | Max process refs/incident **16**. |
| 64 | Max connection refs/incident **32**. |
| 65 | Max destination refs/incident **32**. |
| 66 | Max evidence refs/incident/input **64**. |
| 67 | Max alert refs/incident **16**. |
| 68 | Max assessment revision pointers/incident **16**. |
| 69 | Max observation relations/incident **128**; reason vocabulary fixed at six. |
| 70 | Max secondary memberships **16,384 global**, **256/incident**; dedup entries count toward global cap. |
| 71 | Atomic CAPACITY_LIMITED admission; rejected pointers not indexed; existing group gets typed limitation, no risk change. |
| 72 | Expire outside twenty-minute horizon first; active-capacity eviction picks earliest last time, first time, canonical first observation. |
| 73 | No random UUID tie-break in admission/eviction; deterministic canonical ordering. |
| 74 | Removal clears all secondary memberships and observation dedup entries; tested directly. |
| 75 | Immutable bounded tuple snapshot; previously returned objects cannot mutate or track later internal changes. |
| 76 | One RLock serializes synchronous in-memory mutation/read; no I/O or callbacks under it. |
| 77 | 64 concurrent identical inputs: one seed + 63 duplicates; distinct concurrent same-process observations attach atomically. |
| 78 | Local IncidentDiagnostics counts active/index/gaps/new/attach/duplicate/out-of-order/late/gap-separation/capacity/eviction/expiry; no desktop wiring. |
| 79 | Diagnostics consist only of integers; counters saturate at signed 64-bit max. |
| 80 | Memory-only; fresh service/restart empty, continuity not claimed. |
| 81 | No incident persistence. |
| 82 | No incident repository. |
| 83 | No ACK/resolve/reopen incident lifecycle implementation. |
| 84 | No GUI. |
| 85 | No timeline. |
| 86 | No forensic graph, graph DB or all-to-all edges. |
| 87 | No network/cloud action or history upload; all acceptance fixtures offline. |
| 88 | NS-090 not implemented. |
| 89 | Added three modules, fixture, four test modules and policy/acceptance docs; list below. |
| 90 | Modified documentation only outside those additions: TASKS, ARCHITECTURE, ROADMAP (final acceptance status). |
| 91 | **140 new tests**; no existing test behavior changed. |
| 92 | Exact targeted command below. |
| 93 | New-only **140 passed**; dependency-targeted **493 passed in 17.63 s**. |
| 94 | Full offline pytest **3039 passed, 8 deselected in 112.53 s (1:52)**. |
| 95 | Ruff src/tests passed. |
| 96 | Workspace `.venv\Scripts\python.exe`; configured mypy 33 source files, direct mypy three new modules passed. |
| 97 | git diff --check passed; final pre-commit check recorded below. |
| 98 | Only NS-089 task acceptance status marked COMPLETE; NS-090 definition unchanged. |
| 99 | Focused INCIDENT_CORRELATION.md contains pre-code policy freeze, scope/gap/time/identity/bounds and future boundary. |
| 100 | Commit on existing main with message `feat: add bounded incident correlator`; exact resulting hash supplied in final chat report. |
| 101 | Explicit target `git push origin main`; verified result supplied in final chat report. |
| 102 | NS-090 NOT started; NS-091/092 NOT started. |
| 103 | Final working tree and remote equality checked after commit/push; result supplied in final chat report. |

## Files

Added:

- `src/netsentinel/domain/incidents.py`
- `src/netsentinel/application/services/incidents.py`
- `src/netsentinel/application/services/incident_inputs.py`
- `tests/fixtures/incidents.py`
- `tests/unit/domain/test_incidents.py`
- `tests/unit/application/test_incident_correlator.py`
- `tests/unit/application/test_incident_inputs.py`
- `tests/integration/test_incident_boundary.py`
- `docs/INCIDENT_CORRELATION.md`
- `docs/INCIDENT_CORRELATION_ACCEPTANCE.md`

Modified: `docs/TASKS.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`.
Existing runtime composition, events, infrastructure, SQL, GUI, scoring and alert
lifecycle code remain unchanged. Explicit synchronous adapters are the integration
boundary; a production event subscription is not part of NS-089.

## Exact validation commands

All executed from the repo in PowerShell with its existing Python environment.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/domain/test_incidents.py tests/unit/application/test_incident_correlator.py tests/unit/application/test_incident_inputs.py tests/integration/test_incident_boundary.py
.\.venv\Scripts\python.exe -m pytest -q tests/unit/domain/test_incidents.py tests/unit/application/test_incident_correlator.py tests/unit/application/test_incident_inputs.py tests/integration/test_incident_boundary.py tests/unit/application/test_connection_tracking.py tests/unit/application/test_observation_quality.py tests/unit/application/test_connection_network_scope.py tests/unit/application/test_dns_association.py tests/integration/sqlite/test_dns_association_persistence.py tests/unit/domain/test_risk_evidence.py tests/unit/domain/test_risk_assessment.py tests/integration/test_risk_alert_pipeline.py tests/integration/sqlite/test_risk_assessments.py tests/unit/application/test_threat_intel_evidence.py tests/integration/test_threat_intel_evidence.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/domain/incidents.py src/netsentinel/application/services/incidents.py src/netsentinel/application/services/incident_inputs.py
git diff --check
```

Full offline result: **3039 passed, 8 deselected in 112.53 s (1:52)**.
Ruff passed; configured mypy 33 source files and direct mypy three new source
files passed; final git diff --check passed. Built-in migration manifest: **018**.
No live markers enabled. NS-089 COMPLETE; M16 in progress, NS-090 not started.

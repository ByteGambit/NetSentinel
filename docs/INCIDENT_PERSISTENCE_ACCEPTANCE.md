# NS-090 — Incident persistence/lifecycle: acceptance report

2026-10-04. Authoritative task: `TASKS.md` NS-090. Initial clean `main` HEAD:
`448392c6eb02d07ae3971092a451d5f233242bfc`. Only NS-090 is delivered.
M16 remains in progress; NS-091/092 are not started. The detailed contract and
pre-implementation matrices are in [INCIDENT_PERSISTENCE.md](INCIDENT_PERSISTENCE.md).

## Requested 125-item report

| # | Requested item | Result / evidence |
|---:|---|---|
| 1 | Exact title | NS-090 — Incident persistence/lifecycle. |
| 2 | Task status | COMPLETE, validated offline as recorded below. |
| 3 | M16 status | In progress; NS-091/092 planned. |
| 4 | Previous/new schema | 018 → 019, verified actual manifest/upgrade. |
| 5 | Migration | `019_incidents.sql`. |
| 6 | Stable ID | UUIDv5 dedicated namespace + immutable v1/window/cohort + canonical seed observation. Random runtime ID discarded; mutable score/severity excluded. |
| 7 | Current-state model | Immutable `IncidentRecord` with bounded `CorrelatedIncident`, current revision/state, separate lifecycle stamps, origin/action and historical policy. |
| 8 | Revision model | Immutable `IncidentRevision` event: ID/number/action/state/origin/time and original observation range. Historical event log, not reconstructable full forensic graph. |
| 9 | Format version | Incident format 1, independent of SQLite 019 and assessment formats 1/2. |
| 10 | Repository port | `application.ports.IncidentRepository`, pure atomic transform contract. |
| 11 | SQLite adapter | `SQLiteIncidentRepository`, scoped caller-owned connections. |
| 12 | Application service | `IncidentPersistenceService`; explicit create_or_get, append, acknowledge, resolve, reopen, observe/get. Bounded list/history/cleanup through repository port. |
| 13 | Create | Validated NS-089 snapshot → stable ID, OPEN, revision 1, original min/max, refs/reasons/limitations/policy. |
| 14 | Create idempotency | Same canonical seed retry returns NO_CHANGE; original subset retry survives later appends. Changed unretained snapshot conflicts. |
| 15 | Append | Canonical `IncidentInput` must attach through NS-089; merge current refs/time range atomically. No implicit lifecycle change. |
| 16 | Append key | Canonical observation pointer/kind/original UTC time; namespaced links use SHA-256 of closed canonical value/relation. No random request UUID. |
| 17 | Duplicate | NO_CHANGE; no revision, timestamp churn, new logical link or occurrence count. Restart and concurrent retries tested. |
| 18 | Relation reasons | Typed reason + matched canonical key persisted exactly in current snapshot/reference links. |
| 19 | Correlation version | Explicit version 1 in current record; full immutable correlation policy persisted. |
| 20 | UTC bucket | Stored cohort + original window; aligned half-open membership retained, never recomputed on read. |
| 21 | States | OPEN, ACKNOWLEDGED, RESOLVED; REOPENED is an action with current OPEN. |
| 22 | OPEN | New/reopened incident requiring review, independent of alerts. |
| 23 | ACK | OPEN → ACKNOWLEDGED; acknowledged_at/updated_at only. |
| 24 | ACK retry | Already ACK with matching expected revision: NO_CHANGE. |
| 25 | RESOLVE | OPEN or ACK → RESOLVED; resolved_at/updated_at only. |
| 26 | RESOLVE retry | Already RESOLVED with matching expected revision: NO_CHANGE. |
| 27 | REOPEN | RESOLVED + new legitimate correlated observation + eligibility → OPEN, one REOPENED revision. Duplicate observation cannot reopen. |
| 28 | Horizon | Default 5 minutes, centralized; configurable down or up to hard 10-minute ceiling. |
| 29 | Exact boundary | `0 <= observation_time - resolved_at <= horizon`; -epsilon/zero/+epsilon around upper boundary tested before/after restart. |
| 30 | Strong relation | Same cohort/span and NS-089 exact canonical key or eligible full process/destination relation required. Unknown continuity disables derived links. |
| 31 | Same IP | Same IP alone cannot attach/reopen; unrelated process and unknown identity rejected. |
| 32 | Beyond horizon | HORIZON_EXCEEDED, no revival. Next-cohort create/observe yields a new stable identity. Archive append to resolved remains resolved; not a reopen. |
| 33 | Matrix | OPEN ACK; OPEN/ACK RESOLVE; RESOLVED REOPEN with input. Repeated ACK/RESOLVE no-op; no ACK→OPEN command. Full matrix in contract. |
| 34 | Invalid transition | Typed INVALID_TRANSITION; no mutation. Outdated revision is CONFLICT. |
| 35 | Origin | Typed MANUAL_USER or SYSTEM_CORRELATION; no free user metadata/note. |
| 36 | Incident/alert separation | No AlertService dependency or SQL touching alerts in incident writes. Real bidirectional lifecycle regression. |
| 37 | Incident ACK → alerts | Zero effect on status/count/notification metadata. |
| 38 | Incident RESOLVE → alerts | Zero effect, tested. |
| 39 | Incident REOPEN → alerts | Zero effect, tested. |
| 40 | Alert ACK → incident | Zero effect, tested. |
| 41 | Alert RESOLVE → incident | Zero effect, tested. |
| 42 | Alert REOPEN → incident | Zero effect, tested through real subsequent occurrence. |
| 43 | First observed | Minimum actual correlated original event time; can decrease on valid out-of-order append. |
| 44 | Last observed | Maximum actual correlated original event time; lifecycle/recalc clock never advances it. |
| 45 | ACK timestamp | Independent acknowledged_at; previous ACK survives in revision event after reopen clears current ACK. |
| 46 | Resolved timestamp | Independent resolved_at; retained as previous resolution context when reopened. |
| 47 | Reopen timestamp | Independent reopened_at, caller UTC command time. |
| 48 | Time axes | Input event time determines observation range/reopen eligibility. Command time determines lifecycle stamps/revision order; backward mutation time rejected. |
| 49 | Assessment revisions | Distinct revision pointers attach by logical lineage, using original observation time; no occurrence counter. |
| 50 | TI revisions | Actual NS-088 HIT/NO_HIT output persisted/restarted; original time, risk semantics and all three alert states preserved. |
| 51 | Revision triggers | Create, unique append, meaningful ACK/RESOLVE/REOPEN. Reads, hydration, lazy expiry and duplicate retry create none. |
| 52 | Monotonicity | 1,2,... under atomic BEGIN IMMEDIATE. Failed transaction does not consume a number. |
| 53 | Revision bound | Newest 32 per incident by default/hard max; reduced policy tested. |
| 54 | Pruning | Oldest revision numbers removed deterministically in the same commit; no overwrite of retained events. |
| 55 | Current survives | Separate current payload/ref rows remain complete; counter never rewinds. Tested with two-event history. |
| 56 | References | Typed process/connection/destination/evidence/assessment/alert/scope/relation vocabulary. Namespaced unique incident+kind+identity PK. |
| 57 | Minimum explanation | Canonical pointers, original UTC observation range/relations, typed matched key/reason, scopes/destinations and limitations. No invented per-input provenance beyond NS-089 snapshot. |
| 58 | AVAILABLE | Lazy exact canonical probes for session+lifecycle, DNS evidence, alert UUID, assessment ID+revision. |
| 59 | SOURCE_EXPIRED | SOURCE_EXPIRED_OR_UNAVAILABLE for missing supported source. Deletion cause is not fabricated; snapshot unchanged. |
| 60 | UNRESOLVED | Sources with no supported durable store/resolver (including standalone generic evidence), process/destination/scope values. |
| 61 | CORRUPT | Invalid assessment source explanation is CORRUPT; separate from absent source. Future assessment format is UNSUPPORTED_VERSION. Incident remains readable. |
| 62 | Source deletion | Real connection/DNS/assessment deletion preserves incident, refs, revision and explanation across restart. |
| 63 | No history pinning | No FK to source tables; only owned references/revisions FK to incidents. |
| 64 | Snapshot size | Current payload 128 KiB; individual source link/event 2 KiB; strict read/write codec and SQL gates. |
| 65 | Total refs | 320 source links per incident, central hard ceiling. |
| 66 | Evidence | 64 canonical evidence refs. |
| 67 | Processes | 16. |
| 68 | Connections | 32. |
| 69 | Destinations | 32. |
| 70 | Alerts | 16. |
| 71 | Assessments | 16 distinct revision pointers. |
| 72 | Relations | 128; scopes 16. No arbitrary graph. |
| 73 | Global disk bound | 1024 parents; derived maxima 327680 links and 32768 revisions. Payload ceilings give ≤832 MiB logical payload ceiling, excluding SQLite indexes/pages/WAL/freelist. Not a physical file-size quota. |
| 74 | Global revisions | 1024 × 32 = 32768, enforced through parent capacity and atomic per-parent pruning. |
| 75 | Capacity | Typed CAPACITY_REACHED; reject atomically, no risk/severity effect, no silent partial drop. |
| 76 | Cleanup | Explicit cutoff/now, old RESOLVED only, strictly outside horizon. No automatic aggressive deletion or storage scheduling. |
| 77 | Chunk | At most 16 incident parents per call, with bounded owned child rows. Reduced chunk tested. |
| 78 | Active protection | OPEN/ACK never deleted by cleanup or automatic capacity eviction. |
| 79 | Restart OPEN | Preserved, tested. |
| 80 | Restart ACK | Preserved, tested. |
| 81 | Restart RESOLVED | Preserved, tested. |
| 82 | Restart REOPEN | Current OPEN + REOPENED action/timestamps preserved. |
| 83 | Restart refs | Canonical pointer/reason/snapshot rows preserved and validated. |
| 84 | Restart revisions | Bounded immutable history and monotonic current counter preserved. |
| 85 | Restart expiry | Derived lazily, no read revision. Snapshot unchanged; deletion/restart test. |
| 86 | Hydration | Private temporary correlator, exact input cohort, no global preload, no event/revision creation. |
| 87 | Hydration bound | 256 candidates maximum; canonical ID ordering. Overflow rejected rather than selecting an unsafe partial match. Live continuity LRU also ≤256. |
| 88 | Startup gap | Unknown restart continuity denies derived process/destination relation. Exact pointers bridge with explicit gap limitations. |
| 89 | Reopen restart | Within horizon strong reference accepted; beyond horizon/bucket rejected; exact boundary tests. |
| 90 | Concurrent same append | Eight independent services/connections: one append, remaining NO_CHANGE, one logical link. |
| 91 | Concurrent different append | All accepted within caps, no lost update, unique monotonic numbers. |
| 92 | Concurrency | BEGIN IMMEDIATE around read/transform/current/ref/event/prune. Lifecycle expected_revision required; append optionally optimistic. |
| 93 | Stale revision | CONFLICT before transform; no overwrite. |
| 94 | Resolve/append race | Same expected revision gives one mutation winner and conflict to stale peer; non-optimistic append merges serialized latest state. |
| 95 | Resolve/reopen race | Same expected revision serializes; already-resolved resolve may no-op, otherwise stale command conflicts. |
| 96 | Atomicity | Trigger-induced failures for create/append/ACK/resolve/reopen leave current, refs and events unchanged. Successful retry uses next contiguous number. |
| 97 | Corrupt incident | Typed CORRUPT for JSON, size, inconsistent counter/ref/event or invalid typed fields. Good list entries survive bad incident. |
| 98 | Unsupported format | Typed UNSUPPORTED_VERSION for future incident format, no fallback/reinterpretation. |
| 99 | List/query | Parameterized ID/state/cohort filters; deterministic keyset paging, ordinary page ≤100, candidate page ≤256. |
| 100 | History query | ≤32 per page; before_revision cursor, newest first, explicit truncation. |
| 101 | Diagnostics | Service exposes only live_continuity_incidents; global diagnostics schema unchanged. No unsolicited worker instrumentation. |
| 102 | Sanitization | Only integer aggregate; no IP/domain/PID/path, refs, exception text or payload. DB failures typed UNAVAILABLE. |
| 103 | Privacy | Local bounded sensitive behavioral/security metadata; no upload, raw source graph, packet/HTTP body or credential. |
| 104 | Forensic claim | Explicitly not tamper-proof or authenticated forensic evidence; no hash chain/signing. |
| 105 | GUI | No incident GUI added. |
| 106 | Timeline | No timeline UI added. Revision history API is backend only. |
| 107 | Process creation | Original observed connection semantics preserved; no process-created event inferred. |
| 108 | Cloud | No cloud/provider call or subscription added. All tests offline. |
| 109 | Firewall | No firewall/response changes. |
| 110 | NS-091 | Not implemented or marked complete. |
| 111 | Added files | Five source/schema files, four test files, contract and acceptance documents, listed below. |
| 112 | Modified files | Port, bounded correlator hydrate, migration manifest, five product/task/architecture/security/roadmap docs; existing schema-version assertions only. List below. |
| 113 | Tests | 151 new domain/application/codec/repository/boundary cases. Existing assertions updated to actual schema 019; custom future-migration probes move to 020. |
| 114 | Targeted commands | Exact PowerShell commands below. |
| 115 | Targeted result | New-only 151 passed (145 + 6); final broad dependency-targeted 526 passed in 29.96 s. |
| 116 | Full result | 3190 passed, 8 deselected in 129.55 s. No live markers enabled. |
| 117 | Ruff | `ruff check src tests`: passed. |
| 118 | mypy | Workspace `.venv/Scripts/python.exe`; configured 34 files + direct five source modules: passed. |
| 119 | Whitespace | `git diff --check`: passed; final pre-commit check also run. |
| 120 | Migrations | Full 001→019 and 018→019, old source preservation, repeat migration, future schema rejection, rollback and resource packaging verified. 001–018 unchanged. |
| 121 | TASKS | Only NS-090 task completion status changed. No M16 COMPLETE/NS-091 implementation. Historical NS-089 acceptance record retained. |
| 122 | Docs | Contract contains lifecycle/append/reopen matrices, bounds, identity, time axes, gap/restart, expiry, privacy and limitations. |
| 123 | Commit | Existing main, `feat: add incident persistence lifecycle`; resulting exact hash reported in final chat. |
| 124 | Push | Explicit `git push origin main`; verified result and remote equality reported in final chat. No force/tag/release/branch. |
| 125 | Working tree | Final post-commit/push status reported in final chat. |

## Files and validation

Added source:

- `src/netsentinel/domain/incident_persistence.py`
- `src/netsentinel/application/services/incident_persistence.py`
- `src/netsentinel/infrastructure/sqlite/incident_codec.py`
- `src/netsentinel/infrastructure/sqlite/incident_repository.py`
- `src/netsentinel/infrastructure/sqlite/schema/019_incidents.sql`

Added tests:

- `tests/unit/domain/test_incident_persistence.py`
- `tests/unit/application/test_incident_persistence_service.py`
- `tests/integration/sqlite/test_incident_persistence.py`
- `tests/integration/test_incident_durable_boundary.py`

Added docs: `docs/INCIDENT_PERSISTENCE.md`, this acceptance report.
Modified implementation: `application/ports.py`, `application/services/incidents.py`
(explicit bounded hydrate only), `infrastructure/sqlite/migrations.py` (manifest only).
Modified docs: `TASKS.md`, `ARCHITECTURE.md`, `PRODUCT.md`, `SECURITY.md`, `ROADMAP.md`.

Existing tests changed only for latest-schema expectations (018→019), contiguous
packaged manifest and future migration probes (019→020):
`test_alert_repository`, `test_baseline_reset_completion`, `test_behavior_baselines`,
`test_connection_repository`, `test_device_profiles`, `test_dns_association_persistence`,
`test_dns_repository`, `test_gateway_baseline_repository`, `test_history_freshness`,
`test_migrations`, `test_preferences`, `test_risk_assessments`, `test_risk_explanation`,
`test_threat_intel_cache`, `test_vlan_repository`, `test_packaging_resources`,
`test_risk_alert_pipeline`, `test_suppression_pipeline`, `test_threat_intel_scheduler`,
`test_abuseipdb`. No runtime alert/risk/TI/presentation/bootstrap behavior changed.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/application/test_incident_persistence_service.py tests/unit/domain/test_incident_persistence.py tests/integration/sqlite/test_incident_persistence.py
.\.venv\Scripts\python.exe -m pytest -q tests/integration/test_incident_durable_boundary.py
.\.venv\Scripts\python.exe -m pytest -q tests/unit/domain/test_incident_persistence.py tests/unit/application/test_incident_persistence_service.py tests/integration/sqlite/test_incident_persistence.py tests/integration/test_incident_durable_boundary.py tests/unit/domain/test_incidents.py tests/unit/application/test_incident_correlator.py tests/unit/application/test_incident_inputs.py tests/integration/test_incident_boundary.py tests/unit/domain/test_risk_assessment.py tests/integration/sqlite/test_risk_assessments.py tests/unit/application/test_alert_service.py tests/integration/sqlite/test_alert_repository.py tests/integration/test_risk_alert_pipeline.py tests/unit/application/test_threat_intel_evidence.py tests/integration/test_threat_intel_evidence.py tests/integration/sqlite/test_migrations.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/domain/incident_persistence.py src/netsentinel/application/services/incident_persistence.py src/netsentinel/application/services/incidents.py src/netsentinel/infrastructure/sqlite/incident_codec.py src/netsentinel/infrastructure/sqlite/incident_repository.py
git diff --check
```

Final full offline validation: **3190 passed, 8 deselected in 129.55 s (2:09)**.
Final dependency-targeted validation: **526 passed in 29.96 s**. Ruff passed;
configured mypy (34 files), direct mypy (five modules) and whitespace checks passed.
All 151 new tests passed. SQLite manifest and full migration chain reach **019**.
NS-090 COMPLETE; M16 in progress; NS-091/092 remain planned.

# NS-091 — Incident timeline GUI: acceptance report

Completed **2026-10-05**, NS-091 **COMPLETE**. Started from clean `main` at `9dc0616f3fcb328cb6d5925acde67b380c1a5f1c`.
Authoritative scope: `TASKS.md` NS-091. Mapping/order freeze is in
[INCIDENT_TIMELINE_UI.md](INCIDENT_TIMELINE_UI.md). M16 remains in progress.
NS-092 is not started. No migration: schema **019 → 019**.

## Requested 113-item report

| # | Requested item | Result / evidence |
|---:|---|---|
| 1 | Exact NS-091 title | NS-091 — Incident timeline GUI. |
| 2 | Status COMPLETE / INCOMPLETE | COMPLETE. Offline acceptance passed; M16 remains in progress. |
| 3 | M16 status | M16 remains in progress; NS-092 remains planned and is not started. |
| 4 | Schema version | 019, verified using the actual built-in migration manifest. |
| 5 | Migration status | 019 → 019; no SQL migration or schema/index changes. |
| 6 | Incident UI surface | Read-only Incidents page: bounded list, selected summary/context, timeline table, selected entry detail and lazy shared risk explanation. |
| 7 | Navigation integration | PageId.INCIDENTS after Alerts and before Diagnostics; existing shell convention and all legacy pages retained. |
| 8 | Incident list model | IncidentTableModel; one page ≤100, default 25; full stable ID, state, original observation bounds, incident revision and reference/limitation counts. |
| 9 | Incident detail model | TimelinePage carries immutable IncidentRecord, limitations and aggregate historical context; GUI shows independent lifecycle/persistence times and policy. |
| 10 | Timeline query service | IncidentTimelineQueryService.lookup and IncidentTimelineRepository read port; concrete SQLite implementation exists only in infrastructure/composition. |
| 11 | Timeline entry model | Immutable TimelineEntry: kind, semantic primary time, observation/assessment/action times, canonical source, state and revision/reference. |
| 12 | Observation entry mapping | Unique persisted relation observations except ASSESSMENT_PRODUCED. Connection observed/updated/no longer observed, DNS/evidence observed, alert observation pointer; no entity timestamp invented. |
| 13 | Inference entry mapping | Each persisted relation: human-readable exact reason, matched identity/current target availability. Seed is labelled isolated first observation; computation time is not recorded. |
| 14 | Assessment entry mapping | Unique incident assessment pointers; exact retained revision, assessed_at, original observation, stored score/severity/confidence/quality; lazy NS-083 contributor detail. Missing time is explicitly unknown. |
| 15 | User-action entry mapping | Retained ACKNOWLEDGED/RESOLVED/REOPENED revisions only; origin displayed. System reopen is explicitly system correlation, not attributed to a human. |
| 16 | Primary timeline timestamp semantics | Observation observed_at; inference original-observation anchor; assessment assessed_at; action changed_at. Missing assessment falls back only for ordering with explicit unknown/anchor wording. |
| 17 | Observation-time behavior | Original canonical observed_at and incident min/max are preserved; no mutable telemetry/cache lookup. |
| 18 | Assessment-time behavior | Exact retained assessed_at is separate. Unknown assessment time is shown before the anchor in the table; no updated_at substitution. |
| 19 | Action-time behavior | Persisted revision changed_at, with origin/state/revision. No observation or assessment time assigned to actions. |
| 20 | Confirmation timestamps are not conflated | Observation, assessment, action and persistence-created/updated times are independent. Dedicated mapping and GUI tests check them. |
| 21 | Deterministic sort key | (primary UTC time, kind priority, canonical source kind, canonical source ID, revision, stable entry ID). |
| 22 | Event-kind priority | Observation 0 → Inference 1 → Assessment 2 → User action 3. |
| 23 | Equal timestamp behavior | Stable total order, including all four kinds at the same timestamp; independent of SQLite natural order and Python hash. |
| 24 | Same-kind tie-break | Canonical source kind/ID, revision and stable entry ID; action revision breaks same-time lifecycle ties. |
| 25 | Ascending/descending UX | Oldest → newest; Load more continues forward. |
| 26 | Incident list ordering | UUID ascending, reusing NS-090 stable keyset semantics. List ordering is explicitly described in the GUI. |
| 27 | Pagination strategy | Bounded application timeline mapping from one coherent repository snapshot, then keyset slicing. List uses SQL UUID keyset. No full-store preload. |
| 28 | Cursor format/semantics | Typed TimelineCursor: incident ID, incident revision, content/source-state SHA-256 token, last total sort key. Invalid cursor is a typed result. |
| 29 | Page size/default/max | Default 25, hard maximum 100. UI retains one list page and up to 256 timeline rows. |
| 30 | Equal-timestamp page-boundary behavior | Cursor uses the full total key; equal-time boundary tests verify no duplicates/missing entries at several page sizes. |
| 31 | New-revision-during-pagination behavior | Changed incident revision returns UPDATED, retains already displayed rows and disables continuation until explicit refresh. |
| 32 | Snapshot consistency | Current record, refs, retained history and exact assessments are read in one SQLite transaction. Token also detects source availability changes between pages. |
| 33 | Load-more behavior | Explicit button; no automatic query storm. Controls disabled while loading and when no continuation remains. |
| 34 | Loaded-row memory bound | One incident list page ≤100, timeline ≤256 rows, ≤41 list cursor positions under 1024-parent store ceiling; changing incident clears previous rows and risk selection. |
| 35 | Process wording | Process observed: PID/session/create-time identity context; process name unavailable when absent. Per-observation entity attribution is explicitly not retained. |
| 36 | Confirmation no process-created inference | No process-created event or inference; identity create-time is technical context only. |
| 37 | Connection wording | Connection observed / connection observation updated / connection no longer observed (polling). |
| 38 | Initial-snapshot wording | INITIAL is connection observed. No exact OS opened/closed/created claim. |
| 39 | Relation-reason display | REASONS maps every NS-089 enum; exact matched identity and source-state explanation are displayed. |
| 40 | Same-connection display | Same connection lifecycle (exact session and lifecycle reference). |
| 41 | Same-evidence display | Same canonical evidence reference. |
| 42 | Same-assessment-lineage display | Same assessment lineage; revisions remain distinct; matched revisions retain individual source status. |
| 43 | Process+destination relation display | Same process instance and destination (port/protocol and resolved network scope); aggregate identity retained, original links may be unresolved. |
| 44 | Same-IP-only regression | No same-IP-only reason is introduced; NS-089 PID reuse/shared IP regressions retained and run. |
| 45 | Source AVAILABLE display | Source available now; availability is a current read attribute, not proof of historical completeness. |
| 46 | SOURCE_EXPIRED display | Original source record is no longer retained or available; cause unknown. Retained incident explanation stays visible. |
| 47 | UNRESOLVED display | Source reference could not be resolved; not labelled expired. Generic evidence/entity context without a supported durable store remains unresolved. |
| 48 | CORRUPT display | Original source corrupt; row and incident explanation survive. Corrupt root incident is a degraded list row; corrupt old history becomes a partial limitation. |
| 49 | Unsupported display if applicable | Distinct unsupported-version wording; exact assessment decoding is reused and unsupported sources do not blank the incident. |
| 50 | Unknown-link explanation | Known reason, canonical matched reference, current unavailable/unresolved state and persisted aggregate context; no fabricated target/name/process. |
| 51 | Minimum snapshot fallback | NS-090 retained observation/relation/process/destination/scope identity. Original telemetry metadata beyond that snapshot is not invented. |
| 52 | Historical truth behavior | Persisted current canonical incident snapshot + retained action revisions + exact retained historical assessments. Current source availability is labelled separately. |
| 53 | Current-data substitution prevention | No live process/baseline/cache data substitution. NS-083 separates current preference context from historical risk; no inference of missing past suppression. |
| 54 | PID reuse display behavior | Session + PID + known/unknown instance create-time shown; process name absent remains unavailable. No PID-only historical lookup. |
| 55 | IPv4/IPv6 behavior | Canonical IPv4/IPv6 destination type/value retained; tests cover both. |
| 56 | Domain behavior | Domain destination remains a distinct typed domain; no DNS lookup or inferred process/domain attribution. |
| 57 | Assessment revision display | Assessment revision is exact and separate from incident revision. Newer assessment does not replace the incident's pointer. |
| 58 | Incident revision display | Current incident revision shown in summary/list and used in pagination token; action entry revision is incident revision. |
| 59 | TI evidence/timeline behavior | TI is stored assessment context only, via selected-row NS-083 explanation. No provider event, causal attack claim or lookup from timeline. |
| 60 | NO_HIT wording | Existing NS-088/083 NO_HIT wording retained through shared explanation; no safety verdict from no-hit. |
| 61 | stale TI wording | Stored TI freshness/stale/refresh-error semantics retained through shared explanation, not refreshed from cache. |
| 62 | Alert-reference behavior | Alert observation pointers/reference counts may be shown. No eager AlertService lookup or lifecycle reconstruction. |
| 63 | Incident-vs-alert lifecycle distinction | Summary/actions explicitly state alert lifecycle is separate; no alert state/count/notification change. |
| 64 | ACK timeline behavior | One retained acknowledged action with actual changed_at and MANUAL_USER/SYSTEM_CORRELATION origin. |
| 65 | RESOLVE timeline behavior | One retained resolved action with actual changed_at and origin. |
| 66 | REOPEN timeline behavior | One retained reopened action with actual changed_at and origin; current OPEN is separate. Real GUI reopen test. |
| 67 | Duplicate-append render behavior | Canonical observation/assessment/action entry IDs deduplicate retry rendering; duplicate append produces no revision or new row/cursor. |
| 68 | Nonsemantic storage-revision behavior | CREATED/APPENDED storage events are excluded as extra timeline rows. Source status is an attribute, not an expiry event. |
| 69 | Worker design | Two daemon latest-slot workers (list/detail); optional independent NS-083 risk worker for selected assessment only. |
| 70 | Confirmation no GUI-thread DB I/O | Factory construction and all repository calls happen on worker threads; Qt result slots run on GUI thread. No SQL in presentation/application mapper. |
| 71 | Query coordinator | IncidentQueryCoordinator follows existing NS-083 Condition/thread/signals pattern; one active and one latest pending request. |
| 72 | Generation guard | Worker generation and GUI generation guard plus selected incident ID guard. Invalidation clears pending requests; queued old signals are rejected. |
| 73 | A→B behavior | Late A cannot replace B; tests verify missing B stays selected and old A remains dropped. |
| 74 | A→B→A behavior | First A result cannot replace new A generation; coalesced latest A query delivers the final selection. |
| 75 | Page cancellation | Active second page invalidated on switch, hide or Cancel; no stale append to another incident. |
| 76 | Refresh behavior | Refresh list resets list paging while preserving selected stable ID/detail where possible; timeline refresh clears cursor/model/risk and starts a fresh generation. |
| 77 | Query dedup | Repeated same selection and Load more while busy are deduplicated by the view; worker storms coalesce to one pending latest query. |
| 78 | Shutdown behavior | Each query worker joins at most 2 seconds by default; stop clears pending/delivery and emits stopped. ApplicationLifecycle includes all new workers in start/rollback/shutdown. |
| 79 | Query failure behavior | Sanitized list/timeline unavailable messages; factory and query exceptions never expose SQL/path/token data. List remains usable after detail failure. |
| 80 | Partial corrupt-source behavior | One corrupt/unsupported assessment is a degraded row; old corrupt action history is a limitation. Root incident integrity failures remain explicit unavailable/corrupt rows. |
| 81 | Restart behavior | Same durable IDs/current snapshot/actions after restart; no preload, no re-correlation and no read-created revision. |
| 82 | Confirmation UI read-only | Page has no incident command buttons; read port exposes only list_summaries/read_snapshot. Reads are verified against all incident/alert/assessment table contents. |
| 83 | Confirmation no incident revision on read | No incident revision allocated by list/select/pagination/refresh/read. |
| 84 | Confirmation no observed-time mutation | No first/last observation mutation on read; lifecycle times remain separate. |
| 85 | Confirmation no incident-state mutation | No incident state mutation from rendering or selection. |
| 86 | Confirmation no alert mutation | No AlertService action; real table-state regression includes alerts. |
| 87 | Confirmation no reassessment | No scorer/reassessment worker submission in this query or page. |
| 88 | Confirmation no TI lookup | No TI scheduler/provider/cache lookup; lazy historical risk read is local. |
| 89 | Accessibility | Keyboard-navigable QTableViews, single row selection, accessible names/text/descriptions/tooltips and accessible controls/read-only detail panels. |
| 90 | Plain-text rendering | QTableView string roles, PlainText labels and QTextEdit.setPlainText; HTML-like snapshot/provider text stays literal. |
| 91 | Color-independent semantics | Kind, state, availability and limitations are text; color is supplemental only. |
| 92 | Diagnostics changes | No shared diagnostics schema or counters changed; avoids introducing unrelated telemetry work. |
| 93 | Diagnostics sanitization | Errors are sanitized; no sensitive identifiers logged or diagnostic dump added. |
| 94 | Privacy/local-only behavior | Local SQLite history only; no networking/upload path added. |
| 95 | Causality disclaimer/wording | Visible help: timeline order shows recorded times and does not prove causality; inference computation time is unknown. |
| 96 | Forensic-integrity non-claim | Visible help calls this local application history, not a tamper-proof forensic record. |
| 97 | Confirmation no graph | No graph canvas, traversal, path finding or causal reconstruction. |
| 98 | Confirmation no process-created wording | New presentation text contains no Process created or Process started; regression tests enforce this. |
| 99 | Files added | New service/read port, SQLite timeline adapter, coordinator, two table models/view, fixture, three test modules and two focused docs (listed below). |
| 100 | Files modified | bootstrap.py, presentation/app.py, main_window.py, assessment_repository.py (optional source-free decode), test_application_shell.py, PRODUCT/ARCHITECTURE/ROADMAP/TASKS docs. |
| 101 | Tests added/changed | 129 new offline cases: 51 application, 12 SQLite integration, 66 offscreen GUI; existing shell test includes Incidents and new PAGE_ORDER parametrization. |
| 102 | Exact targeted commands | Exact validation commands and scopes are recorded below. |
| 103 | Targeted results | Dependency-targeted 657 passed before the final nine additional cases; final current new-only result is recorded below. |
| 104 | Full pytest result | Full offline pytest result is recorded below after completion. |
| 105 | Ruff result | python -m ruff check src tests: passed; final recheck below. |
| 106 | mypy result + execution path | Configured python -m mypy and direct --check-untyped-defs on all five new code modules: passed; execution uses repo .venv/Scripts/python.exe. |
| 107 | git diff --check | git diff --check passed; final gate below. |
| 108 | TASKS.md update | Only NS-091 task state may become COMPLETE after validation; NS-092 definition/state untouched. |
| 109 | Timeline docs | INCIDENT_TIMELINE_UI.md freezes mapping/order/paging/worker/source/bounds before implementation; this file contains the requested acceptance report. |
| 110 | Commit hash/message | Requested commit message: feat: add incident timeline UI. Exact resulting commit hash is given in the final chat/git log; a commit cannot embed its own hash. |
| 111 | Push result | Requested target: origin main, no force/tag/release. Exact push outcome is given in the final chat. |
| 112 | NS-092 NOT started confirmation | NS-092 not started; no soak, automatic producers, notifications, installer, response or graph added. |
| 113 | Working tree status | Final working tree state is reported after commit/push in the final chat. |

## Validation

Execution uses `C:/Users/berke/NetSentinel/.venv/Scripts/python.exe`.
The offline pytest configuration excludes `windows_live`, `lab_live` and
`live_threat_intel`; no external traffic was used. Offscreen layout was inspected
with an explicitly loaded Segoe UI font because the isolated Qt offscreen host
initially had no registered fonts. Native interactive Windows smoke was not run.

Dependency-targeted command (657 passed in 64.64 s before the final nine additions):

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/domain/test_incidents.py tests/unit/domain/test_incident_persistence.py tests/unit/application/test_incident_correlator.py tests/unit/application/test_incident_inputs.py tests/unit/application/test_incident_persistence_service.py tests/integration/test_incident_boundary.py tests/integration/test_incident_durable_boundary.py tests/integration/sqlite/test_incident_persistence.py tests/unit/application/test_risk_explanation.py tests/gui/test_risk_explanation.py tests/gui/test_alerts_view.py tests/gui/test_connections_view.py tests/gui/test_application_shell.py tests/integration/test_risk_explanation_pipeline.py tests/integration/sqlite/test_risk_explanation.py tests/integration/sqlite/test_risk_assessments.py tests/unit/application/test_incident_timeline.py tests/integration/sqlite/test_incident_timeline.py tests/gui/test_incident_timeline.py tests/gui/test_threat_intel_evidence.py tests/integration/test_threat_intel_evidence.py --tb=short
```

Final gates: new-only **129 passed in 38.00 s**; full offline **3320 passed, 8 deselected in 163.14 s**; Ruff passed; configured mypy **34 files** and direct mypy **5 modules** passed; diff whitespace clean.

The full suite preceded final display-only column widths/unknown-time prefix polish; the final current 129-case NS-091 gate includes that polish. No native Windows manual smoke or NS-092 soak is claimed.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/application/test_incident_timeline.py tests/integration/sqlite/test_incident_timeline.py tests/gui/test_incident_timeline.py --tb=short
.\.venv\Scripts\python.exe -m pytest -q --tb=short
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy --check-untyped-defs src/netsentinel/application/services/incident_timeline.py src/netsentinel/presentation/incident_query.py src/netsentinel/presentation/models/incidents.py src/netsentinel/presentation/views/incidents.py src/netsentinel/infrastructure/sqlite/incident_timeline_repository.py
git diff --check
```

## Concrete limits

NS-090 does not store per-observation process/destination envelopes, original
process names, inference computation time or a full historic incident graph.
These are explicitly unavailable/aggregate in the UI. Source expiry can remove
an assessment's precise time/score; only its canonical pointer remains. The
ordering fallback is labelled unknown/anchor and never claims an assessment
occurred at that time. Older action revisions may be pruned. A visible 256-row
cap can hide later retained rows, and explicitly says so. Current source-state
changes force refresh during pagination. No forensic completeness is claimed.

## Files

New: `application/services/incident_timeline.py`,
`infrastructure/sqlite/incident_timeline_repository.py`,
`presentation/incident_query.py`, `presentation/models/incidents.py`,
`presentation/views/incidents.py`, `tests/fixtures/incident_timeline.py`,
`tests/unit/application/test_incident_timeline.py`,
`tests/integration/sqlite/test_incident_timeline.py`,
`tests/gui/test_incident_timeline.py`, `docs/INCIDENT_TIMELINE_UI.md`, this report.
Modified files are listed in item 100. Historic NS-089/090 reports are preserved.

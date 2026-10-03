# NS-079 — Risk-to-AlertService integration

**COMPLETE.** Only NS-079 is implemented. The authoritative definition is `docs/TASKS.md`.
Initial checkout was clean `main`, HEAD
`8a852e612a1c1aedbe5afe7defa5f95665e0a80e`. M14 remains in progress;
NS-080 remains planned. Evidence contract, scoring policy and assessment format
remain **v1**. SQLite changes **015 → 016**.

## Orchestration and normalization (request items 1–12)

`application.services.risk_alerts.RiskToAlertService.process(BehaviorRiskSignal)`
normalizes a bounded bundle, calls the unchanged NS-077 pure scorer, persists
through NS-078 `RiskAssessmentService`, then calls the existing `AlertService`.
It never imports concrete SQLite adapters. Detectors remain SQL-free; the
existing alert repository remains the sole alert lifecycle store.

`application.services.risk_evidence.evidence_from_behavior` is the single M13
adapter. It validates subject/application/revision/network and destination
agreement. Ordinary outputs use OBSERVATION, positive results FINDING, and
insufficient/not-evaluated/resolution-limited outputs LIMITATION. Producer rule,
reason, result, policy version and observation time stay explicit.

| Producer | Preserved interpretation |
|---|---|
| NS-072 | FIRST_SEEN means absent from this retained scoped baseline, never malicious IP. KNOWN is observation history, never safety. RARE remains separate. |
| NS-073 frequency | Observed connection appearance rate, never OS connect count. Unconfirmed/confirmed are distinct; confirmed findings carry moderate statistical confidence, unconfirmed low. |
| NS-073 diversity | Retained destination-window diversity, with overflow/capacity/gap/revision limitations. |
| NS-074 | PERIODIC_CANDIDATE is behavioral regularity, never beacon/C2 attribution. Resolution limitation, polling quantization and BENIGN_SCHEDULE_COMPATIBLE remain typed; NS-077 alone applies mitigation. |

Novelty/periodicity findings carry LOW confidence; quality remains a separate
field. Unsupported or absent evidence never acquires HIGH confidence. The closed
M13 dataclass content is canonical-JSON hashed into an EVIDENCE source reference,
including numeric rate/count/interval changes, without copying measurements into
arbitrary alert details. This pointer is UNRESOLVED by the existing source reader;
the generic evidence snapshot retains the minimal symbolic explanation. Identical
inputs produce identical IDs without clock reads or random IDs. A signal has at
most four M13 outputs; NS-076 additionally enforces its 32-evidence batch cap and
rejects duplicates. Source lifecycle/session references are retained.

## Identity, scope and alert eligibility (items 13–29)

The original NS-078 `RiskAssessmentKey` is supplied by the caller and kept for
recalculation: kind `connection_behavior`, typed subject/scope, canonical
ConnectionLifecycleId, session context and original observation UTC time.
Assessment logical ID uses the unchanged key factory; policy/evidence changes
create revisions of the original logical occurrence, never a new occurrence.
NS-056 IDs are reused; timestamp alone is not an identity.

Stable alert fingerprint is SHA-256 of a canonical object containing:

- family `connection_behavior`;
- canonical application key and executable revision digest;
- canonical IPv4/IPv6 destination;
- typed scope (including UNKNOWN versus AMBIGUOUS);
- session for unresolved network/provisional or unknown application context;
- fallback process identity for non-stable applications; when the instance is
  unknown/PID-only, the lifecycle reference additionally prevents unproven merge.

It excludes score, severity, confidence, assessment ID/revision, policy version,
assessed time, occurrence timestamp, evidence/contributor count and DB identity.
Stable applications deliberately group instances of the same executable/revision
and destination on the same resolved network. PID/name is never a persistent
application key; unknown/provisional instances do not gain that grouping.
Different application, known artifact revision, network or destination produces
a different alert fingerprint. A revision becoming known changes the semantic
application scope. Unresolved scopes require a session and store SQL NULL for
network fingerprint. No fake LAN fingerprint is created. IPv6 is retained in
assessment subject, never forced into legacy IPv4 ARP `AlertEvidence.ip_address`.

| Assessment result | New alert |
|---|---|
| UNKNOWN, missing effective severity, exclusively excluded/limitation evidence | No |
| INFO, no positive applied contributor, zero points | No |
| LOW/MEDIUM/HIGH + AVAILABLE/PARTIAL + positive eligible applied contributor | Yes |
| Normal/insufficient recalculation of an existing current occurrence | Refresh its reference/context; never create a normal/safe alert |

Effective severity is copied from NS-077; no thresholds/weights are reimplemented.
Reported confidence is copied. If an existing assessment becomes UNKNOWN, the
legacy alert transport requires `info`/`low`; the assessment snapshot preserves
UNKNOWN and unreported confidence. These transport values are not a safe verdict.
Current v1 first-seen/rare/unconfirmed findings can yield LOW review alerts;
confirmed frequency can yield MEDIUM, periodic-only remains LOW. The orchestrator
uses scorer correlation/quality/severity caps rather than accumulating weights.
NS-077 supports only policy v1. A synthetic stored historical v2 snapshot tests
pointer/fingerprint stability without adding a v2 scoring policy.

## Persistence, retries and lifecycle (items 30–42)

`AlertEvidence.assessment` is an optional typed `AlertAssessmentReference` with
logical assessment ID, revision and network status (None denotes host scope).
The existing bounded evidence JSON stores this small reference, not a copied
assessment snapshot. It can outlive assessment retention; no FK pins sources.
Legacy constructors and JSON without this field remain readable.

`AlertWriteIntent.OCCURRENCE` is the legacy default;
`AlertService.update_assessment` explicitly uses REASSESSMENT. The existing
repository handles both within its original short alert transaction. A retained
same-assessment ID is also detected on an OCCURRENCE retry, so mode alone cannot
accidentally count a recalculation twice.

| Request | Count / last_seen / status |
|---|---|
| Original T1 | 1 / T1 / OPEN |
| Exact T1 retry | 1 / T1 / unchanged |
| T1 revision 2 | 1 / T1 / unchanged; current severity/confidence/reference refresh |
| Later genuine T2 under same fingerprint | 2 / T2 / existing ACK stays; RESOLVED reopens |
| Equal/older observation with another source ID | Existing conservative legacy watermark: no increment or time update |
| Reassessment of an older non-current occurrence | Historical assessment persists; current alert is not rewound |
| Replay of a retained older revision | Cannot replace a newer alert reference |

Reassessment preserves first_seen/count/last_seen/ACK/RESOLVED, and does not
reopen. Its reference replaces the current occurrence's evidence slot instead
of consuming another occurrence slot. Severity/confidence updates are separate
from occurrence mutation. Reassessment may initialize a first alert at the
original observation time if no alert existed and the revised result becomes
eligible. Idempotency applies to retained NS-078 content (eight revisions per
assessment); evicted/pruned content follows NS-078's documented retention bounds.

| Failure point | Typed result and durable effects |
|---|---|
| Normalization invalid/duplicate/mismatched | NORMALIZATION_FAILED; no writes or intent |
| Scorer failure | SCORING_FAILED; no writes or intent |
| Valid UNKNOWN/zero result | Persist explanation; NO_ALERT, no new alert |
| Assessment write failure | ASSESSMENT_PERSISTENCE_FAILED; no alert or intent |
| Assessment committed, alert write fails | ASSESSMENT_PERSISTED_ALERT_FAILED; assessment stays, no intent |
| Explicit retry after partial commit/crash | Same retained assessment revision; alert occurrence recorded once |
| Alert committed, subscriber fails | Both records stay; PublishReport.failed reports isolated failure |

Operational adapter failures are converted to statuses without exception text.
Assessment and alert are two separate transactions, not a distributed atomic
write. A crash between them is recoverable by an explicit original-signal retry.

## Intent and runtime ownership (items 43–56)

`application.events.AlertNotificationIntent` carries alert UUID/fingerprint,
assessment pointer, severity, occurrence/reassessment intent and alert persistence
timestamp. It is emitted only after both repository commits return successfully,
and only when `AlertService` returns its notification-eligibility bool.
Exact retries produce no intent. Current-occurrence severity/confidence changes
reuse the repository's change-eligibility rule; an ACK remains ACK, while a
RESOLVED reassessment never generates reopen/notification. No desktop hysteresis
or notification delivery adapter is implemented.

The existing exact-type, synchronous `EventDispatcher` isolates subscriber
exceptions. This event is process-local eligibility, not desktop delivery proof.
A crash after alert commit but before publish can lose the intent. Retrying the
committed occurrence does not force a second intent. No durable event store or
notification queue is invented.

Production `create_desktop_engine` composes `BehaviorRiskPipeline` and
`RiskAlertWorker`. The optional engine path works without Qt and does not use GUI
bridge/coalescing as detection input. The minimal connection-only engine remains
optional/dormant as before. Per round:

1. Filter OBSERVED opens of the same monitoring session; INITIAL/update/close are
   not behavioral occurrences. Capture PRE-MUTATION baseline and evaluate NS-072.
2. Apply the existing NS-070 accumulator and NS-071 learning contribution once.
3. Evaluate NS-073 from POST-MUTATION current features, with the retained bucket
   envelope and pre-mutation reference. Evaluate once per behavior scope/round.
   Clean normal independent windows seed at most the policy's finite reference
   count, then freeze; unavailable/reset reference clears range/confirmation state.
4. NS-074 receives every round (including empty/failing rounds to break continuity),
   but only COMPLETE OBSERVED appearances enter its sequence. Match returned
   evidence by exact scope/process/endpoint/protocol.
5. Hand off one bounded typed signal per eligible occurrence. Normalization,
   scoring, assessment and alert SQL run on `netsentinel-risk-worker`.

There are at most 128 prepared signals/round, 128 pending signals + one active,
128 scope states in each existing M13 stateful detector and at most four outputs
per signal. Queue saturation returns SATURATED; stopped/unavailable returns
UNAVAILABLE. No unbounded backlog, automatic retry loop or historical replay.
Aggregate worker diagnostics expose pending/processed/failed/rejected/dropped;
the pipeline separately counts preparation drops. No IP/path/evidence/SQL dump
or new diagnostics GUI is added. Existing engine error diagnostics are sanitized.

Shutdown closes acceptance, drains up to the configured deadline, drops/counts
remaining pending work on timeout and reports failure. An already active blocking
call or subscriber cannot be forcibly killed; it may finish later. A live prior
worker prevents restart. Startup starts an empty queue and never re-emits old
assessments/alerts as observations. Worker/service construction opens no database.

## Compatibility, schema and excluded scope (items 57–76)

Legacy ARP/DNS/VLAN/broadcast retain their detector paths, fingerprints, occurrence
watermark, dedup, ACK/resolve/reopen and notification eligibility behavior. Legacy
ARP is not silently routed through NS-077. There is no second alert repository,
table or lifecycle. The reassessment branch is an additive operation in the same
alert transaction/service, not another ACK/reopen/count implementation.

`016_alert_risk_scope.sql` is required because schema 015's alerts column was
NOT NULL: unresolved scopes could not be stored without an invented network ID.
The migration transaction rebuilds the same `alerts` table with a nullable
network fingerprint, copies all original columns byte-equivalently and restores
its two indexes. No assessment column/snapshot is duplicated. Migrations 001–015
are unchanged (static LF-normalized hash regressions); old rows retain their
values and lifecycle. Model validation still rejects a legacy NULL-network row
without a typed risk assessment reference.

No risk explanation GUI, suppression, trust/mark-normal, threat intelligence,
cloud/network request, desktop notification delivery, response/firewall,
dependency change, tag, release or new branch is added. The existing alert view
has one nullable-network display guard for compatibility; NS-083 UI remains
planned. Assessment storage quotas/cleanup contracts remain NS-078's.

## Verification and delivery (items 77–91)

Tests are offline/synthetic and use temporary DBs;
no capture, live attacks, provider requests or firewall changes are performed.

**71 new test cases**, in `tests/integration/test_risk_alert_pipeline.py` and
`tests/unit/application/test_behavior_risk_runtime.py`, with synthetic fixtures
in `tests/fixtures/behavior_risk.py`. Existing regression cases remain intact;
schema expectations change to 016 and synthetic next/future migrations to 017.
Coverage includes actual engine pre/post ordering, failed/reduced/INITIAL/long-lived
rounds, queue capacity/shutdown, strict references/corruption, semantic scope/PID
reuse, same-score numeric changes, historical policy pointer, SQL rollback,
concurrency, duplicate/retry, partial failures and post-commit intent isolation.

All commands ran from `C:\Users\berke\NetSentinel` using its existing venv:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/application/test_behavior_risk_runtime.py tests/integration/test_risk_alert_pipeline.py tests/unit/application/detectors/test_destination_novelty.py tests/unit/application/detectors/test_frequency_diversity.py tests/unit/application/detectors/test_periodicity.py tests/unit/domain/test_risk_evidence.py tests/unit/domain/test_risk_scoring.py tests/unit/domain/test_risk_assessment.py tests/integration/sqlite/test_risk_assessments.py tests/unit/application/test_alert_service.py tests/integration/sqlite/test_alert_repository.py tests/integration/test_arp_alert_pipeline.py tests/unit/application/test_events.py tests/unit/application/test_engine.py tests/integration/test_connection_monitor.py tests/integration/sqlite/test_migrations.py tests/gui/test_alerts_view.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/application/services/risk_alerts.py src/netsentinel/application/services/risk_worker.py src/netsentinel/application/services/behavior_risk.py src/netsentinel/application/services/risk_evidence.py src/netsentinel/application/services/alerts.py src/netsentinel/application/events.py src/netsentinel/application/engine.py src/netsentinel/infrastructure/sqlite/alert_repository.py src/netsentinel/domain/alert_risk.py
git diff --check
```

| Final check | Result |
|---|---|
| Targeted | **709 passed, 1 deselected; 16.75 s** |
| Full pytest | **1917 passed, 7 deselected; 71.36 s** |
| Ruff | All checks passed |
| Configured mypy | 27 source files, success |
| Direct mypy | 9 files above, success |
| Migration hashes/legacy copy | 001–015 unchanged; 015→016 preserves original alert columns/values |
| Git diff whitespace | Passed |

A supplementary direct `python -m mypy src/netsentinel/bootstrap.py` check reports
three pre-existing argument-type errors at the unrelated
`DnsHistoryWriter(**writer_options)` call. The same three errors were reproduced
against the original HEAD's bootstrap source with `MYPYPATH` pointing to `src`;
no new integration type error was reported. The configured gate excludes
bootstrap, and the required direct new-service/events check above passes. This
existing annotation issue was kept outside NS-079 scope.

Added files:

- `src/netsentinel/application/services/behavior_risk.py`
- `src/netsentinel/application/services/risk_alerts.py`
- `src/netsentinel/application/services/risk_worker.py`
- `src/netsentinel/domain/alert_risk.py`
- `src/netsentinel/infrastructure/sqlite/schema/016_alert_risk_scope.sql`
- `tests/fixtures/behavior_risk.py`
- `tests/integration/test_risk_alert_pipeline.py`
- `tests/unit/application/test_behavior_risk_runtime.py`
- `docs/RISK_ALERT_INTEGRATION.md`

Modified implementation: `application/engine.py`, `application/events.py`,
`application/services/alerts.py`, `application/services/risk_evidence.py`,
`bootstrap.py`, `domain/alerts.py`, `infrastructure/sqlite/alert_repository.py`,
`infrastructure/sqlite/migrations.py`, and the existing null-network display guard
in `presentation/views/alerts.py`.

Modified documentation: `docs/ARCHITECTURE.md`, `docs/PRODUCT.md`,
`docs/SECURITY.md`, and **only NS-079 status** in `docs/TASKS.md`.

Existing schema/resource expectations modified in
`tests/integration/sqlite/test_alert_repository.py`,
`test_baseline_reset_completion.py`, `test_behavior_baselines.py`,
`test_connection_repository.py`, `test_device_profiles.py`,
`test_dns_association_persistence.py`, `test_dns_repository.py`,
`test_gateway_baseline_repository.py`, `test_history_freshness.py`,
`test_migrations.py`, `test_risk_assessments.py`, `test_vlan_repository.py`,
and `tests/integration/test_packaging_resources.py`.

Delivery targets the user's existing `main` with commit message
`feat: integrate risk assessments with alert lifecycle` and ordinary
`git push origin main`. Commit hash, actual push outcome and final working-tree
status are returned in the completion message. No force-push/tag/release/new branch
is requested or created. NS-080 is NOT started; M14 is NOT complete.

# NS-078 — Versioned assessment persistence

**COMPLETE (2026-10-03).** NS-078 stores historical risk explanations independently of observation and alert
lifecycle. The authoritative acceptance criteria are in `TASKS.md`. Initial checkout
was clean `main`, HEAD `95badf2bb5b79e6dec6c39cbc1aba93b8b7a4de0`.
SQLite **014 → 015**, snapshot format **1**, input evidence contract **1**,
scoring policy **1**. NS-079 remains planned; M14 is not complete.

## Identity and revision contract

`RiskAssessmentKey` is an immutable canonical kind, typed subject/scope, original
observation reference and UTC observation time. Its SHA-256 is the logical
assessment ID, independent of DB rows, scoring policy, evidence content and
revision number. The caller must keep that original identity for recalculation;
prefer canonical connection lifecycle/session or original source reference.
Unknown/ambiguous scopes keep their explicit status without invented fingerprints.
PID-only process identities retain a session; controlled application identity and
executable revision use the existing NS-076 validation. This is an occurrence
reference, not an occurrence counter. No alert lifecycle fields exist here.

`RiskAssessmentRevision` keeps key, local revision number, explicit UTC
`assessed_at`, immutable `AssessmentSnapshot` and format version. Both observation
and assessment timestamps reject naive/non-UTC inputs. Observation time is never
updated. Assessment time comes from the caller, not a hidden domain clock; wall
clock reversal does not rewind revision numbering. Reads use stored results and
never invoke today's scorer. Policy and evidence contract versions are preserved
as bounded positive historical values; the snapshot does not require today's
scoring policy to support an old version.

Content fingerprint is SHA-256 over closed canonical JSON of the snapshot.
It includes versions, evidence identity/context/freshness, score/severity/context,
contributors and adjustments; excludes assessment time, DB identity and current
source availability. Collections have deterministic ordering. Identical retained
content returns its existing revision (`created=False`), preserving its original
assessment time; replaying an older retained request does not make it latest.
Evidence/contributor/freshness changes create a new revision even with equal score.
Policy change is also meaningful. Removed evidence is reflected in the new snapshot.

## Minimum explanation and format

Evidence snapshots contain evidence ID, contract version, source, rule/reason/result
codes, producer policy version, role, typed subject/scope, quality/limitations,
confidence, original evidence observation time, assessment-time freshness and
bounded canonical references. ARP adds expected MAC; observed MAC/IP and reason
remain in the typed subject/codes. No legacy event/correlation object graph is copied.

Contributor snapshots contain evidence ID, scoring policy version, family,
direction, raw/applied points, eligibility, reason and typed adjustments, including
excluded facts, correlation supersession and family/global/mitigation caps. The
correlation group and SHA-256 of its canonical NS-077 key preserve shared-fact
identity without copying the application/path context for each contributor.
This fingerprint is an identity relation, not a resolvable source pointer.

Result snapshots contain exact NS-077 score, positive subtotal, raw/applied
mitigation, score severity, effective severity, severity-cap reasons, confidence,
measurement quality and availability. Totals must reconcile with contributors;
integer bounds, enum types, unique IDs, contributor links and versions validate.
There is no probability, safe/clean verdict or interpretation by current policy.

The format-1 codec decodes only a closed dataclass vocabulary with exact keys,
typed primitives, enums, UUIDs and UTC timestamps. Arbitrary details dictionaries,
extension dataclasses, duplicate JSON fields, NaN/inf and malformed collections
are rejected. SQL applies payload size gates before transfer into Python. Content
fingerprint is checked on read; this detects inconsistency, not forensic tamper
proofing. A future format returns `UNSUPPORTED_VERSION`. Invalid JSON, time,
enum, version, counter, identity, oversized payload or mismatched content returns
`CORRUPT`. Latest never silently falls back to an earlier row. Bounded history
returns per-entry status so valid historical entries survive one corrupt revision.
An absent logical assessment is `NOT_FOUND`; DB failure is `UNAVAILABLE`.

## Schema, atomicity and ownership

Additive migration `015_risk_assessments.sql` contains:

| Table | Columns |
|---|---|
| `risk_assessments` | assessment_id, original_observed_at, identity_payload, last_revision |
| `risk_assessment_revisions` | assessment_id, revision, format_version, assessed_at, content_fingerprint, snapshot |

Policy/contract versions, scores and explanation values are in the strict bounded
snapshot rather than duplicate SQL columns. Parent identity payload has the exact
typed semantic context. A retention index covers original observation time/ID;
an additive partial history session index supports canonical source probes.
Primary key `(assessment_id, revision)` and unique `(assessment_id,
content_fingerprint)` enforce allocation/idempotency. Only the logical parent
counter is updated; committed revisions are append-only via the repository API.

`RiskAssessmentRepository` is the application port. `RiskAssessmentService` exposes
explicit persist/latest/history/cleanup operations and copies a supplied scoring
result. `SQLiteAssessmentRepository` uses a scoped connection on its calling
worker, WAL and the existing bounded busy timeout. No connection is shared across
threads. Every save uses a short `BEGIN IMMEDIATE` transaction for dedup, parent,
revision allocation, append and retention; races cannot allocate two revision 1s.
Any failure rolls back all writes, including eviction. Persistence failures raise
sanitized `AssessmentPersistenceError`; scoring results exist independently.
There is no writer queue, coalescing or background scheduler in this task; callers
must run these blocking operations on an owning worker. Runtime engine/GUI wiring
belongs to later tasks. Read transactions give a consistent revision/source view.

## Source retention and storage budget

Reference states are read separately from immutable historical snapshots:

| State | Meaning |
|---|---|
| AVAILABLE | Canonical DNS history or connection lifecycle/session source exists |
| SOURCE_EXPIRED_OR_UNAVAILABLE | Supported source absent: retention or never successfully persisted; neither cause is invented |
| UNRESOLVED | Generic evidence/legacy ARP digest has no canonical source repository to probe |

Assessment sources have no FK to connection/DNS/baseline/alert rows. Their cleanup
neither pins source history nor cascades into assessments. The only FK is revision
→ its own logical assessment, for intentional assessment retention. Source deletion
does not create a revision, change score/freshness or erase explanation. Evidence
freshness means the status used at assessment time, not current source age.

Budgets are centralized in immutable `AssessmentStoragePolicy` and domain constants:

| Limit | Default / hard maximum |
|---|---|
| Evidence snapshots | 32 |
| Contributor snapshots | 64 |
| References per evidence | 8 (NS-076) |
| Limitations per evidence | 16 (NS-076) |
| Identity payload | 8192 bytes |
| Revision snapshot | 65536 bytes |
| Revisions per assessment | 8 |
| Logical assessments | 512 |
| Total retained revisions | 4096 (512 × 8) |
| Age | 30 days default; policy can select 1–365 days |
| Cleanup call | at most 128 revision rows, with at most 16 default-policy parents |
| History query | at most 8 returned rows plus one lookahead |
| Latest query | LIMIT 1 |
| Startup loading | none |

Policies may lower row/revision budgets, never exceed hard caps. Collection caps
do not exempt a snapshot from the byte quota: unusually large controlled identity
contexts can be rejected. At most 256 MiB revision payload + 4 MiB parent payload
is retained; SQLite indexes/page/WAL overhead is separate from this logical budget,
and deleted pages are reusable rather than guaranteed to shrink the physical file.
No unlimited history/tombstone collection is maintained.

Per-assessment pruning removes oldest revision numbers and preserves the parent
high-water mark. History reports `truncated` when older revisions were removed or
the caller requested fewer rows. At global capacity, the oldest original
observation (ID tie-break) is evicted as a complete assessment in the same save
transaction. If a fully evicted/purged identity is later saved again it begins a
new retained history at revision 1; no unlimited counter tombstones remain.
Idempotency applies to retained revisions; replaying content already pruned can
create a new revision. Explicit cleanup removes expired whole assessments in one
bounded chunk, with no clock-jump loop. Backward clocks retain newer observations.
Age cleanup is caller-triggered; no runtime schedule was installed.

## Compatibility, privacy and verification

Migrations 001–014 are byte-equivalent (LF-normalized) to the previous HEAD, with
hash regression tests that also work in shallow CI. Migration 014→015 and the full
chain preserve legacy alerts/history, without fabricating generic assessments.
Existing AlertRepository/AlertService read, dedup, occurrence, last_seen,
acknowledge, resolve, reopen and notification semantics remain unchanged. Assessment
save never calls AlertService or emits notification eligibility/events.

Storage is local behavioral/security metadata. Only existing canonical controlled
application identity, process identity, IP/MAC/scope and bounded explanation
references are kept. Raw packets/DNS payload, process environment, command line,
executable bytes, full process/source objects, secrets and free-form details are
excluded. No diagnostics counters, event dumps or new upload path are added.
NS-079, GUI, suppression, trust, TI, detector runtime wiring and a second alert
lifecycle are not implemented. M14 remains incomplete.

Tests cover duplicate replay, same-score changes, policy/context versions,
concurrent same/different writes, transaction rollback/retry and rollback of quota
eviction; source expiry; maximum counts/bytes; migration/legacy compatibility;
restart; deterministic history/caps/age chunks; corrupt/future snapshots and
independent valid rows; explicit no re-score and domain/application boundaries.
Existing migration/resource tests only update the expected latest schema and
synthetic next/future migration number.

Exact validation commands use `C:\Users\berke\NetSentinel\.venv\Scripts\python.exe`
from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/domain/test_risk_assessment.py tests/integration/sqlite/test_risk_assessments.py tests/unit/domain/test_risk_evidence.py tests/unit/domain/test_risk_scoring.py tests/unit/application/test_alert_service.py tests/integration/sqlite/test_alert_repository.py tests/integration/sqlite/test_migrations.py tests/integration/test_arp_alert_pipeline.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/application/services/risk_assessments.py src/netsentinel/infrastructure/sqlite/assessment_repository.py src/netsentinel/infrastructure/sqlite/assessment_codec.py
git diff --check
```

Targeted: **311 passed, 10.20 s**. Full pytest: **1846 passed, 7 deselected,
67.13 s**. Ruff: **All checks passed**. Configured mypy: **26 source files**,
including the new domain/port. Direct service/repository/codec mypy:
**3 source files**, successful. **90 new test cases** were added.
`git diff --check` passed. Only NS-078 is marked complete in TASKS;
NS-079 remains planned, M14 incomplete. No branch, tag or release is created.

Added files:

- `src/netsentinel/domain/risk_assessment.py`
- `src/netsentinel/application/services/risk_assessments.py`
- `src/netsentinel/infrastructure/sqlite/assessment_codec.py`
- `src/netsentinel/infrastructure/sqlite/assessment_repository.py`
- `src/netsentinel/infrastructure/sqlite/schema/015_risk_assessments.sql`
- `tests/fixtures/risk_assessments.py`
- `tests/unit/domain/test_risk_assessment.py`
- `tests/integration/sqlite/test_risk_assessments.py`
- `docs/RISK_ASSESSMENT_PERSISTENCE.md`

Modified files: application `ports.py`, SQLite `migrations.py`,
`docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/TASKS.md`; integration schema
expectations in `test_alert_repository.py`, `test_baseline_reset_completion.py`,
`test_behavior_baselines.py`, `test_connection_repository.py`,
`test_device_profiles.py`, `test_dns_association_persistence.py`,
`test_dns_repository.py`, `test_gateway_baseline_repository.py`,
`test_history_freshness.py`, `test_migrations.py`, `test_vlan_repository.py`,
and `tests/integration/test_packaging_resources.py`. No existing domain/scorer,
detector, AlertService, presentation, bootstrap or dependency file was changed.

# NS-095 — Storage/privacy controls

Policy freeze, 2026-10-06, before implementation. TASKS.md is authoritative.
Initial main/HEAD/origin/main: 71eb116; clean checkout; schema 019.
No migration is needed: retention is retryable and deferred on every restart;
no durable cursor or new store is necessary. M17 continues; NS-096 is not started.

## Inventory and classification

B = historical telemetry, C = current security state, D = user preference/trust,
E = explanatory snapshot, F = regeneratable cache. All are local and potentially
sensitive. Table counts and approximate DB/WAL bytes are safe support metadata;
values, identities and activity times are excluded from support exports.

| Store / repository owner | Class | Existing bound / behavior | NS-095 policy / protection | References / sensitivity |
|---|---|---|---|---|
| connection_history / history writer | B/C | manual 30 days, 100000, 500/chunk | same age/count plus 100000 admission cap; completed or observation-gap rows only | lifecycle/session sources; IP, process, path, time |
| dns_history / DNS writer | B | manual 30 days, 100000 | same age/count plus 100000 admission cap; replay remains idempotent | evidence sources; domain/IP/time |
| dns_associations / DNS association writer | F/B | 100000, 1-hour TTL, manual 30 days; unbounded overflow trim | expired TTL first, 100000; write trim <=128, larger overflow rolls back | no source FK; domain/IP |
| devices / inventory worker | C/B | no global quota | 90 days, 4096 goal; profile members protected | binding/profile FK; MAC/scope |
| device_bindings / inventory worker | B | no global quota | 90 days, 16384 maintenance/admission cap; profile member and recent bindings protected | device FK; IP/time |
| device_profiles / profile worker | D | bounded fields, no global quota | preserve, 4096 admission quota | user labels/notes/trust |
| device_profile_members / profile worker | D | one per device | preserve, bounded by devices/profile admission | device/profile FK |
| gateway_baselines / gateway worker | C/D | one per network | preserve, 4096 admission quota | gateway/MAC/user verification |
| gateway_baseline_changes / gateway worker | B | no global quota | 90 days, 16384 admission/maintenance cap | parent FK; MAC/time |
| vlan_summaries / VLAN worker | C/D | default 64 scopes (configurable <=4096), oldest eviction | preserve, default 64 admission cap; reject instead of evicting | interface/scope/user verification |
| vlan_id_summaries / VLAN worker | C | 128 IDs/scope | preserve, default <=8192 total | parent cascade; VLAN/time |
| behavior_baselines / baseline writer | C | 512 rows, 16KiB, 90 days, 64/chunk | only expired (>90 days), never unexpired READY/LEARNING | exact-scope reset stays in existing UI; path/scope |
| behavior_baseline_storage / baseline writer | C | singleton | preserve | capacity-loss marker |
| risk_assessments / risk worker | E | 512 parents, 30 days | preserve any alert-linked assessment; latest active connection assessment protected | identity payload/path/scope |
| risk_assessment_revisions / risk worker | E | 8/parent, 64KiB | same bound; retained alert-linked revision cannot be pruned | cascade; minimum evidence snapshots |
| alerts / alert workers | C/E | evidence <=8KiB, no global quota | resolved >90 days or 10000 goal; OPEN/ACK protected; admission cap 10000 | assessment references in evidence; IP/MAC/evidence |
| incidents / explicit incident worker | C/E | 1024 parents, 128KiB | RESOLVED >90 days/outside 5-minute reopen horizon; OPEN/ACK protected | source-independent explanation |
| incident_revisions / incident worker | E | 32/parent, 2KiB | parent cleanup charges actual cascaded rows | immutable action/time |
| incident_references / incident worker | E | 320/parent, 2KiB | parent cleanup charges actual cascaded rows | sources expire lazily; no source FK |
| threat_intel_cache / TI workers | F | 1024, 4KiB, 128/chunk; HIT 24h+24h / NO_HIT 1h+24h | reuse existing cleanup/purge API | IP/domain/hash; normalized facts only |
| scoped_preferences + revisions / preference worker | D | 1024/256 active/64 per entity/16384 audit | never automatically delete, no generic purge | suppression/mark-normal/reasons/path |
| notification state / notification service | A/C | memory queue 32, 512 subjects; existing alert watermark | no new durable store; watermark retained with active alerts | no historical replay |
| config / shared config | D | 16KiB atomic JSON | preserve unrelated consent/tray/notification settings | export never reads config or secrets |
| diagnostic logs / shared logging | A | configured rotation, default 1MiB x4 | unchanged; not read by export | redacted logs |

Historical quotas are also admission caps for normal new writes; existing
oversized databases use bounded maintenance toward the quota. Quotas never
promise that protected data will be destroyed. Protected-only pressure is
reported (including a full protected store at its cap). Admission limits stop new
legacy current entities rather than evicting user/current state. Existing
oversized installations remain readable and require bounded maintenance;
no mass cleanup runs on upgrade. At a cap, new persistence fails via the existing
typed repository/worker failure diagnostics; updates/replay to existing records
remain possible. Live monitoring remains available; unavailable source states
make missing persistence explicit. SQLite pages/WAL can remain large after deletion.

## Retention and purge matrix

Typed central policy uses store enum, immutable rules, age/count/chunk bounds,
UTC cutoffs and typed results. Connection/DNS use the existing strict-before
cutoff (equality retained); baseline expiry uses strictly older than 90 days.
Cache uses its existing inclusive expiry. Resolved alert age uses updated time,
incident uses resolved time; neither may purge inside the 5-minute reopen window.
Candidate order is timestamp then primary key. Child rows count against budgets.

Opt-in scheduling: disabled by default, deferred 60 seconds after start/enable,
then 3600 seconds from completion. No engine polling subscription. A single
application worker owns all maintenance operations; no thread per request.
One queued/active operation, no backlog; conflicts reject. Runtime budget 2s,
16 chunks/run, 2048 physical deletes/run. Chunk ceilings: telemetry 128,
baseline 64, cache 128, assessment/incident 512 (including cascades).
Busy and connection-setup lock timeout 100ms; SQL progress handler bounds long scans. Each chunk is a
separate BEGIN IMMEDIATE transaction; failure rolls back that chunk, previous
commits remain. Stop/cancel is checked before each chunk. Shutdown join <=2s.
Summary and export queries share a 2s query deadline.

Purge scopes: completed connection history, DNS history, reputation cache,
resolved alerts, resolved incidents, expired baselines, eligible device history,
all eligible history. Confirmation presents exact scope, estimated eligible and
protected counts, reference consequences and irreversible local deletion.
Counts can change: execution rechecks protection inside the write transaction.
All-history excludes profiles/trust, preferences, recent device observations, current gateway/VLAN, unexpired
baselines and active state. No generic baseline reset or user preference purge:
existing exact-scope controls remain authoritative. Cache purge leaves consent
unchanged. Cancel before confirmation writes nothing; cancellation between chunks
reports partial committed deletion. A bounded run may require another confirmed
run to clear large history. No automatic broad purge or automatic VACUUM.

Source removal leaves incident relation/snapshot and assessment snapshot intact;
existing lazy SOURCE_EXPIRED_OR_UNAVAILABLE is truthful after restart. Generic
evidence without a durable source remains UNRESOLVED. Incident links do not pin
full telemetry indefinitely. Retained alert links protect assessment explanation;
incident assessment links have retained minimum context and may expire.

## Export matrix and bounds

`support-export-v1` JSON, allowlist only. Manifest: app/schema/format/redaction
versions, generated UTC time, categories and limitations. Default categories:
storage aggregate counts/approximate bytes, retention policy, bounded alert
severity/status and incident state/revision summaries. Other categories (raw
connections/DNS/baseline/TI/preferences/capabilities/logs) are excluded; their
aggregate store counts remain included. No raw ID/IP/domain/MAC/path/hash/notes,
source/evidence/provider responses, config, credentials or exception strings.
No pseudonymization or anonymous-data claim. Enum fields are validated before
projection so a corrupt DB value cannot become an export channel.

Maximum 50 alerts + 50 incidents, 100 records total, SQL LIMIT pagination at 25,
preview sample 10 per category, JSON <=64KiB, preview <=64KiB. Preview is the exact
immutable bytes to be saved; Save does not query again or change policy.
User chooses destination with Save dialog after seeing sanitized preview.
Worker writes a same-directory temporary file, flush/fsync, checks cancellation,
then atomic replace; failure/cancel removes temp and preserves existing target.
No final file on Cancel. No upload, HTTP, email or cloud destination selection.

Deletion is local and irreversible from NetSentinel; secure erasure is not
guaranteed (SQLite/WAL/filesystem remnants). DB encryption is not guaranteed.
Exports remain on the user's computer until the user shares them manually.

Implementation and validation evidence will be recorded in STORAGE_PRIVACY_ACCEPTANCE.md.
After cleanup, a deadline-limited aggregate read reports capacity pressure and
per-store protected counts. If no time remains, counts are explicitly unavailable;
committed deletion receipts remain valid. Source-expired counts are not invented:
lazy source states are resolved when the retained explanation/timeline is read.
Legacy assessment cleanup keeps its revision-count return contract while charging
parent rows as well to its physical transaction bound. Revision pruning preserves
each retained alert's exact referenced revision; unreferenced older revisions can
be removed. Fully pinned capacity fails with a sanitized typed storage error.

OS connection/file/fsync operations and thread termination are best-effort;
the worker checks its 2s deadline between chunks and interrupts long SQLite
queries. Shutdown joins for at most 2s and reports failure if the worker remains.

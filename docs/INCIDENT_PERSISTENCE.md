# NS-090 — Incident persistence/lifecycle

## Pre-implementation policy freeze

This is an explicit blocking application boundary, called on an owning worker.
It does not subscribe to the engine or add a GUI. NS-089 remains an in-memory
correlator. SQLite 018 → 019 is additive; incident snapshot format is 1.

Stable UUIDv5 identity uses a dedicated incident namespace, policy v1/window, the fixed UTC cohort
and the canonical FIRST_OBSERVATION pointer (including its original event time).
Runtime random UUIDs, score, severity, PID alone, IP alone and assessment revision
do not independently identify an incident. Once stored, ID never changes.

| Current | Command | Result | Revision | Time effect |
|---|---|---|---|---|
| OPEN | ACK | ACKNOWLEDGED | yes | acknowledged_at / updated_at |
| ACKNOWLEDGED | ACK | no change | no | none |
| OPEN / ACKNOWLEDGED | RESOLVE | RESOLVED | yes | resolved_at / updated_at |
| RESOLVED | RESOLVE | no change | no | none |
| RESOLVED | REOPEN + new correlated input | OPEN | yes | reopened_at / updated_at, input min/max |
| OPEN / ACKNOWLEDGED | REOPEN | INVALID_TRANSITION | no | none |
| RESOLVED | ACK | INVALID_TRANSITION | no | none |

REOPENED is a revision action, not a fourth current state. Reopen needs both
NS-089 membership (same fixed cohort, bounded span, strong canonical relation or
eligible process/destination relation) and **0 ≤ observed_at − resolved_at ≤ 5
minutes**. Equality is eligible; one microsecond outside is HORIZON_EXCEEDED.
Observation before resolution is rejected. A duplicate observation cannot reopen.
Reopen never overrides a bucket boundary. Explicit caller create of the next
cohort yields a new stable incident; an old cohort cannot be revived indefinitely.
Append to RESOLVED is an explicit archive append and does not reopen it.

New canonical observations or additional assessment revision pointers create one
APPENDED revision; duplicates do not change any timestamp or revision. Assessment
and TI refresh use original observation time. Canonical observation identity plus
reference kind/value determines link uniqueness; random request IDs are absent.
Create retries cannot change a retained relation/snapshot (IDENTITY_CONFLICT).
Append follows NS-089 observation-pointer dedup: a retained observation never
overwrites its relation. Introducing previously unretained entity/evidence fields
under that same pointer returns IDENTITY_CONFLICT; already-retained aggregate
context is a NO_CHANGE retry. The NS-089 snapshot does not encode per-observation
input envelopes, and this boundary does not invent that provenance.
Out-of-order append uses min/max actual event times. Lifecycle times
are separate UTC timestamps, cannot precede the last lifecycle update, and never
change observation times. Origins are MANUAL_USER or SYSTEM_CORRELATION.
Every incident command has zero effect on alert state/count/notification; alert
commands have zero effect on incident state. No occurrence counter is added.

Current state is read directly; immutable bounded revision events record action,
origin, revision, lifecycle times and observation range (not a full historical
graph). Newest 32 events are retained by default, oldest removed deterministically;
the monotonic counter and complete current explanation remain. All writes and
pruning share a short BEGIN IMMEDIATE transaction. Expected revisions detect
stale user commands; absent expected revision on append serializes and merges.
Failures roll back state, references, revision allocation and pruning together.

Central hard ceilings: 1024 incidents, 32 revisions/incident (32768 globally),
16 processes, 32 connections, 32 destinations, 64 evidence, 16 alert pointers,
16 assessment pointers, 16 scopes and 128 relations per incident; 320 source
links per incident. Current snapshot ≤128 KiB, source link ≤2 KiB, revision
event ≤2 KiB. Policies can reduce ceilings. Capacity rejects atomically with a
typed CAPACITY_REACHED result; it is not a security signal. No automatic active
eviction. Explicit cleanup removes at most 16 old RESOLVED incidents, ordered
resolved time/ID, strictly before a caller-selected cutoff and outside reopen
eligibility. No invented aggressive retention age; OPEN/ACK are protected.

Sources have no foreign keys to history stores. Only incident-owned rows cascade
when explicitly cleaning the incident. Typed canonical pointers, UTC observation
and relation reason, matched identity, scopes, destinations and limitations form
the minimum local explanation. No arbitrary details, source object, path, raw
packet, HTTP body or secret is copied. Availability is derived lazily on read:
AVAILABLE, SOURCE_EXPIRED_OR_UNAVAILABLE, UNRESOLVED, CORRUPT, UNSUPPORTED_VERSION.
Absence from a supported source store does not prove that retention was the cause.
Generic evidence without its own durable source store remains UNRESOLVED. Source
expiry never changes the historical relation or removes the explanation.

Restart matching queries only the input's exact cohort, at most 256 candidates;
overflow fails conservatively. It never preloads history. Rehydration does not
produce revisions or observations. Across service restart/unknown continuity,
derived process/destination matching is disabled; exact canonical keys may bridge
with MONITORING_GAP/CANONICAL_GAP_BRIDGE limitations. Reads preserve historical
policy version/window and never apply future membership policy. Local current
read, list and history use SQL size gates, finite limits and per-row errors;
one corrupt row does not suppress good list entries. No cloud calls occur.

This local behavioral/security history is sensitive and is not a tamper-proof
forensic log. No hash chain/authenticity guarantee, GUI, timeline, process-created
inference, desktop notification, firewall or response is introduced. NS-091 and
NS-092 remain planned; M16 stays in progress.

# NS-080 — Scoped preference/suppression storage

**COMPLETE.** Implementation and acceptance report, 2026-10-04. Authoritative task: `docs/TASKS.md`.
Initial checkout: clean `main`, HEAD `99bdf2e518b79c4a22812a255ad95fe953aa42a0`.
SQLite **016 → 017**, preference format **v1**. Evidence contract, scoring policy
and assessment format remain **v1**. M14 remains in progress; NS-081 is not started.

## Immutable domain and selector contract

`PreferenceDefinition` contains a `PreferenceSelector`, explicit
`PreferenceLifetime`, bounded reason and `NOTIFICATION_SUPPRESSION` effect.
`ScopedPreference` is a frozen/slots revision snapshot with nonzero UUID logical
ID, positive revision, original creation time/origin, action time/origin,
CREATE/EDIT/REVOKE action and persisted ACTIVE/REVOKED status. Creation origin
never changes. No device trust, observed baseline, risk evidence or safety verdict
is represented by these values. No arbitrary metadata dictionary is accepted.

| Selector dimension | Persisted and matching semantics |
|---|---|
| Application | NS-069 stable `ApplicationIdentity`, canonical `winpath:v1:` key, at most 4096 UTF-8 bytes; compare exact canonical key |
| Application revision | Optional known `ApplicationRevision` SHA-256; requires stable application; exact digest; absent/unknown hash never matches a known selector |
| Destination | Typed IPV4/IPV6 `PreferenceDestination`, canonical `ipaddress` output; no interface zone, DNS name, ASN, country, subnet or domain selector |
| Network | Exact canonical lower-case 64-character fingerprint, representing resolved scope only |
| Rule | NS-076 symbolic lower-case ASCII convention, 1–64 characters; exact ID, no regex, glob, prefix or substring |

All specified dimensions use **AND**. Omitted dimensions are wildcards. Empty
all-wildcard selectors are rejected by domain and SQLite CHECK. Application-only
preferences span revisions of the same stable application; an explicit revision
narrows them. PID, process name, provisional instance and monitoring session are
not persistent policy keys. Same process name at a different path cannot match.

`PreferenceMatchContext(rule_id, subject: EvidenceSubject, scope: EvidenceScope)`
and pure `selector_matches` are scope primitives only. They do not evaluate
preference effect, lifetime, precedence, alert eligibility or notifications.
Network-specific selectors match only NETWORK/RESOLVED with the same fingerprint.
HOST, UNKNOWN and AMBIGUOUS never acquire a guessed fingerprint; omitting the
network can match those contexts when the other dimensions match. Expanded/full
and compressed IPv6 match after canonicalization. IPv4 and IPv4-mapped IPv6
remain distinct. An IP never expands to its domain, ASN or network neighbors.

## Lifetime, reason and origin

`PreferenceLifetimeKind.PERMANENT` explicitly forbids `expires_at`.
`EXPIRES_AT` explicitly requires it. No default lifetime kind exists;
missing expiry cannot become permanent. UTC-aware datetimes are required;
naive/non-UTC timestamps are rejected and persisted with six fractional digits.
Domain and repository do not read the clock; commands and `status_at(now)` take
caller-supplied UTC time. Audit time cannot rewind behind the latest revision.

`status_at(now)` returns REVOKED first, otherwise EXPIRED when `now >= expires_at`,
otherwise ACTIVE. Permanent preferences never expire through time. EXPIRED is a
derived state, not a revision/audit action, and expiration deletes nothing. Create
and meaningful edits of timed preferences require a future expiry. An expired
preference can be explicitly extended or made permanent by EDIT; identical
expired content is NO_CHANGE. Revoke of an expired preference is still an
audited REVOKE. Historical lifetime values remain readable.

Reason is nonempty, single-line **plain text**, at most **512 characters** (up to
2048 UTF-8 bytes). Blank-only input, C0/C1 controls, DEL and Unicode line/paragraph
separators are rejected. No rich text renderer or HTML interpretation exists;
ordinary punctuation and literal markup remain text. Reasons are not trimmed
or silently truncated. Origin is the small typed `MANUAL_USER` enum; there is no
account, credential, actor path, automatic-trust or authentication subsystem.
Every action records its reason and origin. REVOKE records its new reason in a
new snapshot; the earlier reason remains in history.

## Commands, revisions and concurrency

`application.ports.ScopedPreferenceRepository` exposes `create`, `edit`,
`revoke`, `get_current`, `get_history` and `list_current` using domain results.
`ScopedPreferenceService` is an explicit blocking facade for an owning worker;
it imports no SQLite or Qt and creates no preference at construction. Caller
retains an optional UUID for retry; otherwise an explicit create call generates
UUID4. This user policy ID is separate from DB row IDs and observation IDs.

| Operation | Result and audit |
|---|---|
| Create | Stable UUID, revision 1, CREATE/ACTIVE; explicit definition, origin and UTC time |
| Same-ID create retry | NO_CHANGE only while revision 1 has the same definition and creation origin; current snapshot returned, no new audit |
| Same-ID different create | CONFLICT; no overwrite |
| Distinct-ID identical definitions | Separate user decisions; both retained within quotas; no selector-based merging |
| Edit | Requires exact `expected_revision`; append next full EDIT/ACTIVE snapshot; original ID/time/origin retained |
| Identical edit | NO_CHANGE, no audit spam; stale expected revision still conflicts |
| Restore earlier values | New EDIT revision; historical content fingerprint is not a uniqueness constraint |
| Revoke | Requires expected revision and bounded explicit reason; append REVOKE/REVOKED; never DELETE |
| Revoke retry | ALREADY_REVOKED for current revision or immediately preceding expected revision; no additional revision |
| Older stale revoke | CONFLICT |
| Edit revoked | INVALID with current revision, or CONFLICT for a stale expected revision; create a new policy for new intent |

Content SHA-256 covers only canonical selector, lifetime, reason and effect.
ID, revision, audit/creation timestamps and action are excluded. It supports
integrity checks and no-op content semantics, not identity or forensic authenticity.
Two simultaneous edits against N yield one N+1 and one CONFLICT. Simultaneous
revoke retries yield one REVOKED and one ALREADY_REVOKED. Concurrent same-ID
creation yields one CREATED and one NO_CHANGE.

`PreferenceResultStatus`: CREATED, UPDATED, NO_CHANGE, REVOKED, ALREADY_REVOKED,
CONFLICT, NOT_FOUND, INVALID, UNAVAILABLE, CAPACITY_REACHED, FOUND, CORRUPT and
UNSUPPORTED_VERSION. Fixed typed statuses contain no raw exception/SQL/path/note.
Invalid constructed domain values raise at construction; invalid command
arguments return INVALID. Invalid read IDs/cursors/limits raise ValueError before
opening storage, following existing bounded read-port conventions.

## Schema, ownership and atomicity

Append-only migration **`017_scoped_preferences.sql`** is registered in the
explicit manifest. Existing **001–016 SQL files are unchanged**; tests freeze
their original hashes and verify old rows/schema survive the upgrade. Migration
creates no preferences and never converts trusted device profiles.

| Table | Purpose |
|---|---|
| `scoped_preferences` | Logical UUID primary key, original creation time/origin and current revision pointer |
| `scoped_preference_revisions` | Complete typed selector/effect/lifetime/reason/audit snapshots; composite primary key `(preference_id, revision)` |

Typed columns replace arbitrary JSON. CHECKs constrain nonempty selector,
destination kind/value pairs, explicit lifetime/expiry pairs, rule/digest/lengths,
positive integer revisions/format, and action/status agreement. The logical
current pointer has a deferred composite FK to its revision; revision rows point
back to their parent. The parent PK supports ordered current pages; the revision
PK supports ordered history pages. `idx_scoped_preference_status` supports status
counting. No FK connects preferences to device trust, risk or source records.

`SQLiteScopedPreferenceRepository` uses the existing component-owned
`SQLiteDatabase.connection()` pattern and short `BEGIN IMMEDIATE` transactions.
Validation happens before mutation. Revision insertion and guarded current-pointer
update commit together; any insert/pointer/commit failure rolls back. No global
writer redesign or runtime wiring is added. GUI integration must dispatch these
blocking commands to a worker in its future task.

All user values are SQL parameters. Dynamic column text comes exclusively from
fixed internal schema vocabularies, never selector/note input. Reopening the DB
preserves exact current/history, origin, expiry and revision semantics. Unavailable
DB/schema/transactions yield typed UNAVAILABLE. Reads do not change policy.

## Explicit budgets and retention

Central domain constants and immutable `PreferenceStoragePolicy` hold these
default/hard upper bounds; tests can choose smaller quotas:

| Budget | Bound |
|---|---:|
| Unrevoked logical preferences | 256 |
| All logical preferences, including revoked | 1024 |
| Revisions per logical preference | 64 |
| Global revision/audit rows | 16384 |
| Reason | 512 characters |
| Current page | 100; default 100 |
| History page | 64; default 32 |
| Rule ID / application key / IP value | 64 chars / 4096 UTF-8 bytes / 45 chars |

The unrevoked budget conservatively includes expired ACTIVE rows: expiry is
derived and never silently frees audit capacity. Total quota includes revoked
preferences. Counts are serialized with writes. One final per-preference revision
and one global row per unrevoked preference are reserved for revocation. Capacity
returns CAPACITY_REACHED instead of deleting user decisions or old audit records.
The smallest revision quota is two (create plus revoke).

There is **no cleanup, pruning, automatic age retention, purge or cleanup chunk**
in NS-080. Active/permanent policies cannot disappear through time or eviction.
This deliberately finite store may stop accepting new policies/edits when full;
NS-095 can design an explicit user-controlled purge later. No source retention is
pinned by these policies. Logical/revision/text bounds limit normal store growth;
they are not a filesystem-byte quota or forensic integrity guarantee.

Current pages sort by canonical UUID with optional `after_id`, fetching limit+1
to expose truncation. History pages sort descending by revision, with optional
`before_revision` to reach earlier snapshots. No unlimited query is exposed.
Each page entry has its own read status. Malformed text is size/type-gated in SQL
before transfer, then decoded through domain validation and content-integrity
checks. Inconsistent pointers/missing revision history return CORRUPT. A future
positive format returns UNSUPPORTED_VERSION and is never reinterpreted. One bad
policy does not hide or crash reads of other valid policies. Corrupt historical
entries can coexist with readable current and other history entries.

## Isolation and privacy

Legacy DeviceProfile read/write/update, device detector behavior and persistence
remain separate and unchanged. No trust migration or automatic preference creation
exists. Suppression preference storage does not mean application/destination safety,
observed-normal baseline, negative score or evidence removal. No AlertService,
notification eligibility, scorer, assessment snapshot, GUI, mark-normal command,
TI/cloud, firewall or response behavior is changed. NS-081 is not implemented.

Reason and selector metadata can reveal user security decisions and remain in
the local database. Controlled application keys may contain local paths; no extra
path/credential/secret/payload fields, upload, network request or sensitive
diagnostics dump is introduced. Sensitive selector/destination/reason fields are
excluded from their dataclass repr. No diagnostics counters/runtime diagnostics
changes are needed for this storage-only task. Security documentation states the
local sensitivity boundary; existing redacted diagnostics remain unchanged.

## Files and acceptance commands

Added production files:

- `src/netsentinel/domain/preferences.py`
- `src/netsentinel/application/services/preferences.py`
- `src/netsentinel/infrastructure/sqlite/preference_repository.py`
- `src/netsentinel/infrastructure/sqlite/schema/017_scoped_preferences.sql`

Added tests and documentation:

- `tests/fixtures/preferences.py`
- `tests/unit/domain/test_preferences.py`
- `tests/unit/application/test_preference_service.py`
- `tests/integration/sqlite/test_preferences.py`
- `docs/SCOPED_PREFERENCES.md`

Modified production interfaces: `application/ports.py`, SQLite `migrations.py`.
Modified documentation: `ARCHITECTURE.md`, `SECURITY.md`, `PRODUCT.md`, and only the
NS-080 status in `TASKS.md`. Existing tests below change only expected current
schema version; migration tests additionally move synthetic next/future/failing
probes from 017 to 018:

- `tests/integration/sqlite/test_alert_repository.py`
- `tests/integration/sqlite/test_baseline_reset_completion.py`
- `tests/integration/sqlite/test_behavior_baselines.py`
- `tests/integration/sqlite/test_connection_repository.py`
- `tests/integration/sqlite/test_device_profiles.py`
- `tests/integration/sqlite/test_dns_association_persistence.py`
- `tests/integration/sqlite/test_dns_repository.py`
- `tests/integration/sqlite/test_gateway_baseline_repository.py`
- `tests/integration/sqlite/test_history_freshness.py`
- `tests/integration/sqlite/test_migrations.py`
- `tests/integration/sqlite/test_risk_assessments.py`
- `tests/integration/sqlite/test_vlan_repository.py`
- `tests/integration/test_packaging_resources.py`
- `tests/integration/test_risk_alert_pipeline.py`

Commands from the repo root, using
`C:\Users\berke\NetSentinel\.venv\Scripts\python.exe`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/domain/test_preferences.py tests/unit/application/test_preference_service.py tests/integration/sqlite/test_preferences.py tests/integration/sqlite/test_migrations.py tests/integration/sqlite/test_device_profiles.py tests/integration/sqlite/test_device_profile_ui_command.py tests/unit/application/detectors/test_device_identity.py tests/unit/application/detectors/test_arp_identity.py tests/unit/application/detectors/test_arp_anomaly.py tests/unit/application/test_alert_service.py tests/integration/sqlite/test_alert_repository.py tests/integration/test_risk_alert_pipeline.py tests/integration/test_arp_alert_pipeline.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/domain/preferences.py src/netsentinel/application/services/preferences.py src/netsentinel/infrastructure/sqlite/preference_repository.py src/netsentinel/application/ports.py
git diff --check
```

Targeted acceptance: **297 passed, 15.51 seconds**. It covers domain/service/new
SQLite policies plus device trust, ARP and NS-079 regression. All data is offline
and synthetic. Tests cover every selector dimension/combination, exact unknown
and revision behavior, IPv6, malformed selectors/lifetimes/reasons, expiry boundary,
full revision history, restore/no-op/retries, concurrent changes, bounds and revoke
reservation, SQL constraints/parameterization, 016 upgrade, restart, corruption,
future format, DB unavailable and transaction rollback. A paired risk pipeline
test proves stored/edit/revoked policies cannot alter existing scores, assessment
history, alerts or notification intents. The three new test modules add **159
test cases**. Full suite: **2076 passed, 7 deselected, 73.93 seconds**.
Ruff: **All checks passed**. Configured mypy: **28 source files**, direct mypy:
**4 source files**, both successful. Direct mypy explicitly covers the service
and SQLite repository outside configured scope. `git diff --check` passed.
Only NS-080 is marked COMPLETE; NS-081 remains planned and M14 is not marked
complete. Delivery uses the requested commit message
`feat: add scoped suppression preference storage` on `main`, followed by
`git push origin main`; the final chat report supplies the exact commit and
verified push/working-tree result.

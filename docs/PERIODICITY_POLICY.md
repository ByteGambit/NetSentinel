# NS-074 — Periodicity evidence detector

Rule ID `observed_appearance_periodicity`, immutable `PeriodicityPolicy` version
**1**. `PeriodicityEvidence` is behavioral context with **low security
significance**, not an alert, risk severity, safety verdict or malware probability.
Regular updates, telemetry, sync and reconnects can all produce the same evidence.
No “beacon confirmed”, C2 identification, payload/TLS inspection or long-lived
flow heartbeat inference exists.

## Observation and scope contract

`PeriodicityService.observe_round` consumes every NS-056 tracker round in order,
including empty, FAILED and REDUCED rounds. The caller explicitly supplies the
round's `now_monotonic` observation time and the actual polling cadence at service
construction. There is no hidden clock call. UTC is reference/display metadata;
forward/backward UTC changes do not affect intervals, expiry or quality gates.
Runtime monotonic values are finite, non-negative and bounded to 1e12 seconds.

Only `ConnectionOpened(origin=OBSERVED)` in a COMPLETE, loss-free round adds an
appearance. This means a new lifecycle **observed by polling**, not a precise OS
connection-open event. INITIAL, update, close, wrong-session events, missing remote
endpoints and repeated observations of an existing flow add nothing. A TCP socket
seen in 300 polls remains zero new appearances. A later OBSERVED lifecycle can add
one appearance. FAILED/reduced visibility never becomes presumed benign inactivity.

Exact key:

`BehaviorScopeKey(application_key, identity_quality, revision_digest,
network_status, network_token)` + `ProcessIdentity(PID, UTC create_time)` +
canonical remote `Endpoint(IP, port)` + `TransportProtocol`.

The NS-069 resolver and NS-071 pure canonical scope validator are reused without
I/O. Stable canonical Windows executable paths are required; name/PID alone
cannot merge different executables. Known revisions A/B and explicit unknown
revision are separate. Unknown revision can build its own sequence and always
carries `revision_unverified`. Hash/signature lookup is not performed here; the
caller can inject a resolver using already available, matching artifact metadata.

Network scope must be NS-057 RESOLVED with its exact fingerprint. Unknown or
ambiguous network and provisional/unknown applications are not evaluated. They
cannot borrow a resolved sequence. This fingerprint remains local-address context,
not proof of a physical network or route. Known process create-time is required;
different PIDs/create-times have separate runtime sequences, including concurrent
instances and application restarts. Stable application identity does not imply
timestamp continuity. ApplicationScope's instance must match the event instance.

IPv4/IPv6 endpoints use the existing canonical Endpoint model; port and TCP/UDP
are part of the key. Missing, unspecified or IPv6 zone-ID destinations are not
evaluated. Private and loopback IPs follow the same mathematical policy and gain
no safety interpretation. Different CDN IPs stay separate: there is no DNS/domain,
ASN or inferred-service merging, hostname assertion or service periodicity baseline.

## Versioned default policy and arithmetic

| Policy | Default / hard limit | Semantics |
|---|---:|---|
| Minimum intervals | 5 | Six distinct accepted appearances; inclusive |
| Retained interval cap | 32 | At most 33 timestamps per scope |
| Tracked scopes | 128 | Global hard cap, including process and endpoint subdivisions |
| Period range | 10–3600 s | Inclusive median base-period bounds |
| Absolute jitter | 1 s | Inclusive tolerance |
| Relative jitter | 0.05 | Inclusive tolerance |
| Resolution factor | 3 | Base <= 3 × polling cadence is resolution-limited |
| Maximum multiple | 3 | Only 1×, 2× and 3× are considered |
| Inactivity expiry | 10800 s | Expire when elapsed since last accepted appearance is strictly greater |
| Retained horizon | 86400 s | Remove timestamps older than this monotonic horizon |
| Recent lifecycle IDs | 33 | Policy interval cap + 1; no unbounded dedup map |
| Input events per round | 8192 | Two times NS-056's default active capacity: full opens + closes |

Typed policy permits minimum intervals 5–32, interval cap 5–32, scopes 1–128,
period endpoints 1–3600 s, absolute tolerance 0–1 s, relative tolerance 0–0.1,
resolution factor 3–10 and multiple cap 1–3. Inactivity cannot exceed 10800 s or
be shorter than maximum multiple × maximum period. Horizon cannot exceed 86400 s
or be shorter than minimum intervals × maximum period. Thresholds reject bool,
non-finite and inconsistent values; version other than 1 is unsupported. Actual
polling cadence is explicit, positive, finite and at most 3600 s; no fixed cadence
assumption is embedded in the detector.

For accepted monotonic appearances `t0..tn`, intervals are `di = ti - t(i-1)`.
Zero/negative/NaN/inf intervals are rejected by the public sequence contract.
Runtime clock regression resets all sequences and rejects that round. Distinct
same-timestamp appearances reset that endpoint sequence and keep only one new
anchor; concurrent connections cannot manufacture zero intervals or silently
preserve an earlier periodic classification. Small positive burst intervals remain
in the sequence and fail the constant-period gate rather than being filtered away.

Reference `b = median(raw retained intervals)`. No mean-only fit, hidden period
search or inferred subharmonic is used. Tolerance `T = max(1 s, 0.05 × b)` under
default policy. For each interval, choose `m` in 1..maximum_multiple minimizing
`abs(di / m - b)`; ties choose the smaller m. Maximum deviation
`D = max(abs(di / mi - b))`, normalized jitter `D / b`. Multiple deviations are
expressed in base-period units: 126 s compared to a 60 s base has 3 s deviation
when m=2. Every interval must satisfy `D <= T`, and a strict majority must select
m=1. This majority gate prevents a sequence dominated by gaps from fitting an
invented short period. Random, rising 10/20/30/40/50 and burst-group intervals
do not qualify. Out-of-range bases are gated before division, including subnormal
positive values; no NaN/inf can escape into computed evidence.

`INSUFFICIENT_DATA` until five intervals, `IRREGULAR` for out-of-range period,
excess jitter or no direct majority; otherwise `RESOLUTION_LIMITED` if base is
<= three poll intervals, or `PERIODIC_CANDIDATE`. These are mathematical
classifications over a recent observed sequence, not confirmation of intent.

## Polling, aliasing and missed appearances

Every result carries `polling_quantized_exact_timer_not_inferred`. Polling can
quantize 58/62 s differences into apparent 60 s intervals; zero measured jitter
does not establish a perfect underlying timer. A 5 s cadence with observed 10/15 s
periods is resolution-limited. A 60 s period at 5 s cadence can be a candidate but
retains the limitation. The interval estimate describes polling appearances,
not a process timer, packet heartbeat or exact network connect time.

With clean monitoring coverage, 60/60/120/60/60 or 60/60/180/60/60 can be a
candidate with `missed_multiple_compatible_not_proven`, a compatible interval
count and separate reason. Nothing says an event was definitely missed. A 4×,
17× or larger gap is not silently interpreted as missing appearances; it exceeds
the bounded multiple policy. The count is for retained compatible intervals,
not a count of reconstructed connections. `maximum_multiple=1` disables this
compatibility. Failed monitoring coverage always resets instead of applying it.

## Gaps, resets, restart and capacity

FAILED resets active interval sequences. REDUCED is also a quality break and its
appearances are not added. Discarded rows/capacity drops reset with `capacity_loss`.
No interval bridges these rounds. More than two actual polling cadences between
successive rounds is a monitoring gap, including sleep/wake or an unreported
collection delay. Equality at two cadences remains allowed. Recovery starts a
fresh anchor and must rebuild five intervals. Repeated FAILED rounds cannot
backfill elapsed time. This differs from a compatible 2×/3× appearance interval
across continuously clean polling rounds.

The last typed reset (`monitoring_gap`, `reduced_quality`, `capacity_loss`,
`session_changed`, `clock_regression`, `inactivity`, `concurrent_appearances`)
remains in evidence even after a clean sequence rebuilds. A prior reset is context,
not an interval included in the new sample. Session UUID change clears all state
and the monotonic epoch. New service / NetSentinel restart starts empty. Separate
process-instance keys prevent bridging application restarts. No persisted
baseline/history/DNS records reconstruct monotonic intervals. `reset(scope)` drops
only that exact runtime scope; future baseline-reset orchestration must explicitly
call it, as there is no composition integration in this task.

Scope order is oldest accepted appearance touch; deterministic tracker ordering
breaks same-round ties. Duplicate deliveries do not refresh recency. At capacity,
evict the oldest scope before admitting a new one. An evicted scope returns fresh
and insufficient. A single session-wide sticky history-unavailable flag marks new
scopes after any eviction/expiry, without unlimited per-key tombstones. Existing
retained scopes are unaffected. This limitation is conservative and does not
claim that a particular returned key was previously seen. Inactivity expiry is
checked on every round, including empty ones, so old process/endpoint scopes
cannot be kept alive solely by unrelated polling. A scope at the inclusive
inactivity boundary still exists; it expires just beyond that boundary.

Dropping the oldest timestamp because of interval cap or horizon sets
`recent_bounded_sequence_only` until reset. A recent sequence can still be a
candidate but makes no long-term regularity claim. Retained count is not a
lifetime observation count. Memory is bounded by 128 keys, 4224 timestamps,
4224 recent UUIDs and constant-size per-scope metadata; transient output catalogs
also have the scope bound. Round input iteration stops at 8193 with a capacity
reset and no partial candidate output. There is no unlimited event materialization.

The tracker and synchronous EventDispatcher normally deliver a lifecycle once
to each consumer. The additional per-scope recent-ID cache ignores accidental
duplicates in the retained cache, including after a quality reset. IDs do not
survive eviction, expiry, explicit reset or session change. This contract is not
a durable replay/idempotency guarantee for arbitrary ancient redelivery; an owner
must not replay historical events as fresh monotonic observations. Invalid/wrong
session events add nothing. RLock makes round mutation and snapshots atomic;
the caller still owns ordered round delivery and resolver metadata freshness.

## Evidence and subsystem boundaries

Immutable portable evidence carries rule ID, full policy/version, classification,
reason, exact scope, session UUID, retained interval count, median base, maximum
deviation, normalized jitter, tolerance, min/max raw interval, compatible-multiple
count, actual polling cadence, typed limitations, last reset and UTC reference time.
Insufficient sequences carry counts/min/max but no fitted estimate or confidence.
No raw timestamp/interval history dump is emitted. Ineligible events return no
evidence and create no state. Snapshot is a read of current state with the caller's
latest round reference; expiry advances only through observe_round, never a hidden
clock. The pure detector requires an eligible clean sequence from its runtime owner.

All results carry benign-schedule-compatible and behavioral-only-low-security-
significance limitations. There is no high-confidence security classification,
probability, severity, notification, AlertService call or alert DB write.
NS-072 destination novelty, NS-073 frequency/diversity and NS-074 interval
periodicity remain independent contributors. Combining/scoring is M14 work.

Only a minimal application service and pure detector are added. There is no
engine/dispatcher/bootstrap subscription, GUI change, diagnostics/config change,
thread/worker creation, DB/file/network/DNS/hash/signer I/O or new dependency.
SQLite schema remains **014**, NS-071 summary format **1**, feature policy **1**,
NS-072 policy **1** and NS-073 policy **1**. No monotonic sequence is persisted.
NS-075 remains unstarted; M13 is not complete.

## Offline validation

`tests/unit/application/detectors/test_periodicity.py` has 109 tests with explicit
fake monotonic/UTC times and no sleep/network/admin requirements. It covers
startup and long-lived tracker flows, periodic/jitter/random/trend/burst sequences,
numeric/typed policy bounds, polling aliasing/resolution, compatible multiples,
FAILED/REDUCED/loss/delayed/recovery rounds, clock/session/application restart,
duplicate/concurrent appearances, exact app/revision/network/endpoint isolation,
IPv4/IPv6/private/loopback, expiry/horizon/eviction/caps, regular benign scheduler
context and deterministic immutable output. Existing NS-058/070/073 regressions
are run without changing their implementations or test files.

Exact targeted command:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/application/detectors/test_periodicity.py tests/unit/application/test_behavior_features.py tests/unit/application/test_connection_tracking.py tests/unit/application/test_observation_quality.py tests/integration/sqlite/test_history_freshness.py tests/unit/application/detectors/test_frequency_diversity.py
```

Targeted result: **249 passed** (1.67 s).

Requested full command `.\.venv\Scripts\python.exe -m pytest -q` fails during
collection because Windows Application Control blocks repo Python's `_overlapped`:
`ImportError: DLL load failed while importing _overlapped: An Application Control
policy has blocked this file.` The second collection error is the consequent
partial asyncio import `NameError: name 'base_events' is not defined`. The same
two parser-test collection failures were reproduced on an untouched ZIP export
of baseline commit `9bd6c27e87d2fa6613f88d0874f3cc2560894212`, using repo venv Python
and that export's source path. No security policy or blocked module was changed.

Repo and existing Codex runtime both report **Python 3.12.14**, MSC v.1944 64-bit.
The already available Codex runtime imports asyncio normally. Full validation
uses this runtime with the exact repo venv site-packages (no dependency installs):

```powershell
$ns074PriorPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = 'C:\Users\berke\NetSentinel\.venv\Lib\site-packages;C:\Users\berke\NetSentinel\src'
    & 'C:\Users\berke\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q
} finally {
    $env:PYTHONPATH = $ns074PriorPath
}
```

Final full result: **1499 passed, 7 deselected, 1 warning (53.91 s)**. The warning
is existing Scapy/cryptography FFDH deprecation. Opt-in windows_live/lab_live tests
were not run.

```powershell
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/domain/periodicity.py src/netsentinel/application/detectors/periodicity.py src/netsentinel/application/services/periodicity.py
git diff --check
```

Ruff passed. Standard mypy: **23 source files**, no issues. Direct mypy: **3
source files**, no issues. Both used standard repo venv `-m mypy`, no alternate
launcher. `git diff --check` passed.

Added files: the domain model, pure detector, bounded runtime service, 109-test
detector test module and this policy document. Modified files: ARCHITECTURE.md
and only NS-074's completion status in TASKS.md. Existing NS-058/070/073 source
and test files, NS-075 status, ROADMAP milestone statuses, presentation,
infrastructure/schema and configuration remain unchanged.

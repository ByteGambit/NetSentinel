# NS-092 — Incident acceptance/soak

2026-10-05. Authoritative scope: `TASKS.md`, NS-092. Initial clean `main` HEAD:
`d44bcc6ce2eac05bfff0203dba09b5df654d8fde`. Schema **019 → 019**; no migration,
production behavior change, new detector, provider or engine subscription.
This is acceptance-only. **NS-092 COMPLETE; M16 COMPLETE.** Final validation and
the M16 decision are recorded below. NS-093/M17 implementation is not started.

## Offline story and composition

`test_incident_end_to_end_story` uses `tests/fixtures/incident_acceptance.py`.
The injected UTC and monotonic clocks advance independently. A real
`ConnectionTrackingService` feeds 601 consecutive one-second observation rounds
to `BehaviorFeatureAccumulator` and `BehaviorBaselineService`: twenty later
observed appearances and 600 seconds of actual clean monitored coverage. INITIAL
visibility does not count as a new appearance. The actual baseline writer loads,
checkpoints and drains against temporary SQLite, with Event synchronization.
No impossible READY baseline is constructed.

At 10:00 UTC a new public destination is observed. The actual
`BehaviorRiskPipeline.prepare` reads the pre-mutation READY baseline and produces
FIRST_SEEN novelty. After accumulator/baseline mutation, `finish` submits to the
real `RiskAlertWorker`. Existing evidence normalization, scoring policy v1,
assessment persistence and `AlertService` create score 20, assessment revision 1
and one alert occurrence. The original generic novelty evidence is normalized
through the same public adapter, including canonical lifecycle and session refs;
its digest is asserted equal to the persisted minimum evidence snapshot.

The explicit incident application boundary receives connection, RiskEvidence,
assessment and alert observations. Exact lifecycle and assessment references join
one stable UUIDv5 incident. No wrapper record ID or alert fingerprint is used as
a relation key. Application services cross real repository ports into SQLite;
the timeline query crosses the read port into the coherent batch source resolver.
GUI list/detail factories and queries run on their existing owning workers.

DNS uses a completed synthetic transaction for `example.test` CNAME → `edge.test`
and a direct A answer sharing the destination. Canonical evidence UUID 9000 is
asserted through both association provenance paths and persisted history. TTLs
20/60, observation time, network/client scope and AMBIGUOUS result survive.
**DNS is independent destination context, not DNS→process attribution.** Its
canonical observation has a separate isolated incident. No unsupported relation
is invented to force DNS into the behavioral incident. Current production has no
DNS-risk adapter and no automatic incident producer; explicit service composition
is the tested seam. This is the existing frozen product boundary, not a new feature.

The story ACKs and resolves the behavioral incident. Child alert remains OPEN;
alert ACK leaves incident RESOLVED. Original observation is 10:00:00, assessment
10:00:02, ACK 10:00:03 and RESOLVE 10:00:04. All four timeline kinds appear with
their semantic times and deterministic total keys. The two owning workers drain
before restart; repository calls scope/close every connection. Rebuilding all
facades/services reads the same ID/state/snapshot/revision/order. Canonical replay
has no revision, timestamp, reference or occurrence churn.

Existing history restart reconciliation sets a gap without a close time or
invented downtime observation. Deleting connection and DNS source records retains
incident identity/explanation and changes only lazily resolved source status.
A second facade restart preserves those statuses and readable timeline rows.

The new tests prohibit socket connect/connect_ex/sendto/create_connection and DNS
resolution. All data is synthetic, clocks/failure inputs are bounded, temporary
stores are local, and TI results use normalized fake outcomes. There are **zero
uncontrolled external requests**, credentials, Npcap/admin requirements, live
C2/attack traffic, packet injection, malware execution, firewall operations,
upload, notifications, tray, package rebuild or NS-093 work.

## Identity, window, loss and lifecycle acceptance

| Scenario | Expected / observed result | Evidence |
|---|---|---|
| Same process + exact lifecycle | Connection/evidence/assessment/alert attach using typed refs | Full story |
| PID reused, create time A/B | Different instance; no same-IP derived merge | Real tracker test, weak reopen, shared-IP soak |
| Tuple removed then reappears | Same tuple, different lifecycle UUID | Real tracker test |
| Unknown or PID-only process | Separate groups, no fabricated process | Parametric identity tests, storm |
| Different resolved network | No derived merge or reopen | Weak reopen, scope storm |
| DNS direct/CNAME shared IP | AMBIGUOUS; evidence/provenance/TTL preserved; no process attribution | Full story; NS-062–064 regressions |
| Same UTC bucket | Expected exact-key grouping | Forward/reverse bucket matrix |
| 10:09:59.999999 / 10:10:00 | Separate half-open UTC buckets, by design | Boundary matrix |
| 10:00 → 10:09 → 10:18 | Two groups; no sliding chain bridge | Forward/reverse matrix |
| Reversed supported input | Same expected bucket membership | Reverse matrix; NS-089 regression |
| Arbitrary bridge input / eviction | Global order-independent graph partition is not claimed | NS-089 frozen limitation retained |

| Gap/loss scenario | Expected behavior | Observed behavior |
|---|---|---|
| FAILED round | No coverage, invented closure or risk signal | Real story pipeline prepares no signal; DB unchanged; active lifecycle retained |
| REDUCED + discarded rows | Derived matching remains conservative | Separate incident for only process/destination; typed gap persists |
| COMPLETE + discarded rows | Loss marker still applies | Same conservative result |
| Exact reference crosses gap | Allowed with explicit limitation | MONITORING_GAP + CANONICAL_GAP_BRIDGE retained after persistence/restart |
| App downtime | No synthetic observations or continuity | Source reconcile changes gap only; incident rows/order unchanged |
| Gap marker overflow | Finite state, conservative matching | 256 retained markers; further admission fails |

Loss is neither benign nor an attack finding. Incident correlation does not write
any risk/alert table; the real FAILED-round story leaves assessment/alert tables
unchanged. No confidence or score inflation is introduced for induced loss.

| Reopen scenario | Expected / observed result |
|---|---|
| 4m59.999999s after resolution | CHANGED → OPEN, same ID, if correlated |
| 5m exactly | CHANGED → OPEN, inclusive |
| 5m + 1µs | HORIZON_EXCEEDED, no revival |
| Wrong process / unknown / PID-only / wrong scope, same IP | NOT_CORRELATED |
| Strong lifecycle after restart, eligible horizon | Reopens with gap/canonical-bridge limitation |
| Strong lifecycle after restart, outside horizon | HORIZON_EXCEEDED |
| Next UTC bucket | Cannot override cohort membership; new explicit seed is separate |
| Repeated resolve/reopen | 80 changes on one lineage; newest 32 immutable events retained |

OPEN/ACKNOWLEDGED/RESOLVED and REOPENED action remain NS-090 semantics.
Incident commands never own alert lifecycle. Existing concurrent/idempotency and
expected-revision/failure-injection regressions are included in broad/full gates.

## Source retention, TI and timeline acceptance

| Source scenario | Expected / observed result |
|---|---|
| Supported source AVAILABLE | Exact connection/DNS/assessment/alert source resolves |
| Connection/DNS source deleted | SOURCE_EXPIRED_OR_UNAVAILABLE, same incident explanation/ID |
| Generic evidence or aggregate entity without store | UNRESOLVED, not expired |
| One malformed assessment | CORRUPT row; rest of story renders |
| One future assessment format | UNSUPPORTED_VERSION row; rest renders |
| Assessment removed | Time unknown, explicit observation anchor for ordering |
| Restart after expiry | Same current status and deterministic readable entries |
| Incident cleanup | Explicit resolved-only chunks ≤16; OPEN/ACK protected |

Absence does not prove retention caused it. Sources have no FK that pins source
history or cascades source deletion into incident deletion. Retained context is
not cryptographic forensic evidence and correlation is not causality.

| Fake TI scenario | Expected / observed result |
|---|---|
| HIT | Supporting context, assessment revision 2, same incident lineage, score 20 |
| NO_HIT | Informational; no safe verdict or mitigation; score 20 |
| STALE HIT | Stored freshness remains STALE; explicit historical provenance |
| Provider unavailable | No context/revision injected; complete local story still works |
| Replayed TI assessment | NO_CHANGE append; original observed_at unchanged |
| Every result | Alert count/time/fingerprint/state unchanged; no auto block |

The test maps fake normalized scheduler outcomes through NS-088 and calls the
real risk enrichment boundary; it does not test HTTP or need an AbuseIPDB key.
Scheduler/provider protocol fakes and consent/default zero-request cases are
also exercised in broad/full M15 regressions. Dormant desktop composition creates
no DB or provider request. NS-083 query shows stored provider provenance; timeline
retains exact assessment revision pointers rather than copying current TI cache.

| Timeline scenario | Expected / observed result |
|---|---|
| OBSERVATION | Original observation time; connection observed/polling semantics |
| INFERENCE | Original anchor, exact relation reason; computation time not fabricated |
| ASSESSMENT | Exact retained assessed_at separate from observed_at |
| USER_ACTION | Persisted action UTC time/origin, separate incident revision |
| Equal timestamp | Canonical total order across page sizes 1/2/3/5/25/100 and restart |
| Process wording | “Process observed”; no creation/start inference from create time |
| Expired / unresolved | Explicit separate warnings with retained explanation |
| Long timeline | 257 backend rows, 11 pages; no duplicate/missing row |
| GUI cap | Exactly 256 unique sorted loaded rows, visible display-limit message |
| Query count | Exactly 5 SELECT/page for the long source shape; 55 for 11 pages |
| A→B / late page / Cancel / destroy | Old page cannot replace selection; no stale append/crash |
| 1,000 requests while page blocked | One active + one latest pending slot; at most three executed reads |
| Open/paging/refresh | Incident/ref/revision/alert/assessment table contents unchanged |

## Policy extraction and measured resource budget

These policies were extracted before writing soak from `IncidentPolicy`,
`IncidentStoragePolicy`, NS-089/090/091 contracts and timeline/coordinator constants.
They are the existing policies, not duplicated configurable product settings.

| Policy | Configured limit | Observed max / result | Gate |
|---|---:|---:|---|
| Runtime incident state | 256 | 256 | PASS |
| Processes / incident | 16 | 16, overflow atomic | PASS |
| Connections / incident | 32 | 32, overflow atomic | PASS |
| Destinations / incident | 32 | 32, overflow atomic | PASS |
| Evidence refs / incident | 64 | 64, overflow atomic | PASS |
| Alert refs / incident | 16 | 16, overflow atomic | PASS |
| Assessment refs / incident | 16 | 16, overflow atomic | PASS |
| Scope refs / incident | 16 | 16, overflow atomic | PASS |
| Observation relations / incident | 128 | 128, overflow atomic | PASS |
| Secondary key memberships / incident | 256 | 65; global admission asserted | PASS |
| Global index memberships | 16,384 | 16,383; next 2-member input rejected | PASS |
| Gap markers | 256 | 256; overflow rejected | PASS |
| Persisted parents | 1024 | 1024; next parent rejected | PASS |
| Retained events / parent | 32 | 32; current monotonic revision 81 | PASS |
| Global retained events | 32,768 | 1,077 | PASS |
| Source links / parent | 320 | 132 in main soak; typed ref limits independently reached | PASS |
| Current record payload | 131,072 bytes | 55,526 bytes | PASS |
| Link payload | 2,048 bytes | 423 bytes | PASS |
| Revision payload | 2,048 bytes | 294 bytes | PASS |
| Cleanup transaction | 16 parents | 16 then 5; 21 total | PASS |
| Hydration/continuity LRU | 256 | 256; cohort overflow rejected | PASS |
| Query page | 25 default / 100 maximum | Both exercised; finite pagination | PASS |
| GUI timeline loaded rows | 256 | 256 | PASS |
| Query worker handoff | 1 active + 1 pending / worker | Blocked read + 1 latest pending | PASS |
| Query join | 2 s default / worker | Existing bounded shutdown/cancel regressions | PASS |
| Window/lateness/expiry | 10m fixed / 10m inclusive / 20m | Boundary/order/cleanup regressions | PASS |
| Reopen | 5m inclusive, plus cohort membership | Boundary matrix, before/after restart | PASS |

Structural counts are the primary memory/storage gate. Row/revision/ref counts
and encoded sizes avoid SQLite WAL/page-size ambiguity. No fragile RSS or
microbenchmark threshold was introduced. CPU work is bounded by the existing
incident/index/reference/candidate and query mapping ceilings; finite workload
elapsed time is informational, not a hardware-independent throughput guarantee.
Long query SQL count proves batch resolution for that supported source shape;
assessment-bearing stories have their own bounded exact-source query shape.

## Accelerated workload and validation

`performance` remains included in default pytest, following NS-049 policy.
No test uses `time.sleep` for correctness or runs hours of wall time.

Main soak: 320 distinct shared-destination inputs across a small reused PID set,
unknown processes and three scopes; 4,096 runtime duplicates; 128 relations plus
one overflow; 128 durable canonical replays; 80 resolve retries; 80 material
resolve/reopen changes; 1,024 persisted parents with overflow/hydration rejection;
resolved-only cleanup; complete timeline pagination/restart. A separate evidence
storm saturates global indexes and 256 gap markers. Seven additional tests hit
every per-incident typed ref cap and assert durable rejection has no partial write.

Final main soak metrics:

| Metric | Measured |
|---|---:|
| Synthetic mutation/admission submissions | 5,859 |
| Duplicate submissions | 4,303 (4,096 runtime + 128 append + 79 resolve) |
| Shared-IP runtime groups created | 320 |
| Independent durable parents created | 1,024 |
| Combined creation count across those workloads | 1,344 |
| Max active runtime groups / max continuity LRU | 256 / 256 |
| Max observation relations / max durable links per parent | 128 / 132 |
| Persisted parents before cleanup | 1,024 |
| Logical source links before cleanup | 4,306 |
| Retained revision events before cleanup | 1,077 |
| Max current snapshot / link / revision bytes | 55,526 / 423 / 294 |
| Backend timeline rows / pages queried | 257 / 11 |
| Expired-source timeline rows | 256 |
| GUI rows / pages / SELECTs | 256 / 11 / 55 |
| Runtime capacity evictions | 64 |
| Cleanup parents / transaction sizes | 21 / 16 then 5 |
| Main admission capacity rejections | 3 |
| Main accelerated soak elapsed | 68.761 s (final repeat; informational) |
| Index storm peak / per-incident keys / gap markers | 16,383 / 65 / 256 |
| Index/gap storm capacity rejections | 66 |
| Runtime expired groups after 21-minute fake clock advance | 127 |

The index storm submits 8,192 evidence observations, 258 gap markers and one
expiry observation. Per-type cap tests are separate smaller deterministic
workloads. Runtime aggregate diagnostics after the main shared-IP storm:
active=256, indexes=973, new=320, duplicates=4096, evictions=64; attachments,
gap/late/out-of-order/expiry/capacity counters are zero in that specific workload.
Other workloads explicitly exercise those limits; diagnostic fields contain only
nonnegative bounded integers, no subject, raw reference, SQL, secret or error body.

Input counts are submissions, not OS events. Runtime groups and durable parents
are separate workloads and their combined creation count is not a claim of unique
cross-store product incidents. State/count metrics must match repeat runs;
elapsed time may vary.

Exact commands from repo root (existing `.venv/Scripts/python.exe`):

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/integration/test_incident_acceptance.py tests/gui/test_incident_acceptance.py --tb=short -s
.\.venv\Scripts\python.exe -m pytest -q -s tests/performance/test_incident_soak.py --tb=short
.\.venv\Scripts\python.exe -m pytest -q tests/unit/application tests/integration tests/gui --tb=short
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy --check-untyped-defs tests/fixtures/incident_acceptance.py tests/integration/test_incident_acceptance.py tests/performance/test_incident_soak.py tests/gui/test_incident_acceptance.py
git diff --check
```

Normal selection excludes `windows_live`, `lab_live`, `live_threat_intel` (eight
cases). Migration tests cover the full 001→019 chain; no SQL file is edited.
Repeat/flakiness gates include soak, equal timestamps and concurrent/idempotent
incident operations. Targeted story + GUI: **36 passed in 21.55 s**. Broad M11–M16
application/integration/GUI regression: **2277 passed, 8 deselected in 223.49 s**.
Soak-only: **9 passed in 119.07 s**, main measured 105.891 s while broad checks
also ran. Final soak + equal-time/concurrent/idempotency repeat: **14 passed in
90.27 s**, main 68.761 s; all persisted/resource counts match. A bookkeeping
correction counts both explicit durable creates in the final 5,859 submissions;
no workload behavior changed for that correction. No arbitrary sleep/flakiness
was observed. Final full suite: **3365 passed, 8 deselected in 306.73 s**.
All 45 new cases are included in that run, including the accelerated soak.

Exact repeat command:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -s tests/performance/test_incident_soak.py tests/gui/test_incident_acceptance.py::test_real_story_equal_time_paging_and_restart_has_total_order tests/unit/application/test_incident_correlator.py::test_concurrent_duplicate_and_distinct_inputs_serialize_and_snapshots_do_not_leak tests/integration/sqlite/test_incident_persistence.py::test_concurrent_append_serializes_refs_and_revisions tests/integration/sqlite/test_incident_persistence.py::test_concurrent_create_retries_allocate_one_stable_parent --tb=short
```

Ruff passes; configured mypy **34 files** and direct mypy **4 new modules** pass.
`git diff --exit-code -- src/netsentinel/infrastructure/sqlite/schema src` is
clean, preserving all migrations and production source. Whitespace checks pass;
the staged check and clean working-tree receipt are verified before/after the
requested commit and reported in the final chat.

## M16 exit decision

Exact ROADMAP criterion:
> Dedup/reopen/restart/retention testleri geçer; process creation telemetry yoksa
> “process observed” denir; ilişki nedenleri/unknown görünür.

| Exit criterion | Evidence | Final decision |
|---|---|---|
| Window | Fixed UTC bucket, boundary, reversed input, no chain bridge | PASS |
| Scope | Process/create-time/session, scope, unknown and shared-IP storm | PASS |
| Dedup | Runtime 4,096, durable replay, UI unique rows/read purity | PASS |
| Reopen | Inclusive 5m matrix and restarted exact-key eligibility | PASS |
| Restart | Full facade reconstruction, stable UUIDv5; no downtime continuity | PASS |
| Evidence expiry | Source deletion, distinct unresolved/corrupt, second restart | PASS |
| Honest timeline | Four kinds, semantic times, process observed, relation/unknown wording | PASS |

**All frozen exit gates pass: NS-092 COMPLETE and M16 COMPLETE.** TASKS marks only
NS-092 and the M16 summary COMPLETE; ROADMAP preserves the exact exit criterion
and marks M16 complete. NS-093 remains planned and is not started.

## Limitations and requested report index

This validates existing explicit subsystem composition; it does not install
automatic engine→incident persistence. DNS ambiguity is independent context;
there is no DNS-process causal claim. Known NS-089 multi-match/order limits remain;
gap markers must precede dependent inputs. Restart disables derived matching.
Generic evidence has no durable source store. Historic action revisions can prune,
assessment expiry removes exact assessed time, and the GUI deliberately displays
only 256 rows. This is local application history, not a tamper-proof forensic log.
No native Windows live/manual beta, portable packaging or provider HTTP test is
claimed. These remain separate product/task gates.

The user's requested final items map to this report as follows:

| Requested items | Recorded result |
|---|---|
| 1–7 | Exact title/header, final decision, schema 019→019, no migration/production fix |
| 8–12 | Offline story, layer boundaries, fixture strategy and network denial |
| 13–25 | Identity/DNS/baseline/risk/AlertService/incident/timeline story above |
| 26–38 | Conservative identity/window/dedup/restart matrices |
| 39–47 | State/reopen table; independent alert lifecycle |
| 48–54 | Source table, retained explanation and revision occurrence invariants |
| 55–60 | Fake TI table, historical provenance, no score/count inflation |
| 61–78 | Four-kind/timestamp/source/order/UI/cancel/read-only/query table |
| 79–103 | Workload, policy/configured/observed resource table, aggregate diagnostics |
| 104–120 | Exact commands, final results/repeat, migration chain/immutability |
| 121–130 | M16 exit matrix and TASKS/ROADMAP final status updates |
| 131–134 | This file and inventory below |
| 135–138 | Commit/push/clean-tree receipt in final chat; a commit cannot include its own hash; NS-093 untouched |

Added: `tests/fixtures/incident_acceptance.py`,
`tests/integration/test_incident_acceptance.py` (30 cases),
`tests/performance/test_incident_soak.py` (9 cases),
`tests/gui/test_incident_acceptance.py` (6 cases), this report.
Existing test files and production source remain unchanged. Final status notes
are updated in ARCHITECTURE, PRODUCT, ROADMAP and TASKS only after passing gates.

# NS-089 — Bounded incident correlator

## Policy freeze (before implementation)

An incident is a local, bounded grouping of canonical observations, assessment
revisions and alert references. It is neither an alert lifecycle nor proof of
causality, compromise or forensic integrity. NS-089 is an explicit synchronous
application boundary; it is not automatically subscribed to every detector.

### Relation matrix and priority

All relations require the same UTC event-time cohort and a total span no greater
than the policy window. References are namespaced by their canonical types.

| Priority / reason | Required identity | Scope | Known gap | Attach |
|---|---|---|---|---|
| 1 same connection lifecycle | exact session + lifecycle UUID | canonical link may bridge scopes | explicit identity may bridge; limitation retained | yes |
| 2 same canonical evidence | exact NS-076 evidence digest, legacy event digest or NS-063 DNS UUID | canonical link may bridge scopes | same as above | yes |
| 3 same assessment lineage | exact logical assessment digest; revisions remain distinct pointers | canonical link may bridge scopes | same as above | yes |
| 4 same alert observation | exact alert UUID (never fingerprint) | canonical link may bridge scopes | same as above | yes |
| 5 same process instance and destination | session + PID + known create-time + exact typed destination including port/protocol | equal resolved network fingerprint only | denied if gap/reduced/unknown quality | yes |
| first observation | no match | retain actual scope | retain limitation | isolated seed |

Same IP, DNS name/ambiguous association, application/path, PID without create-time,
network, severity, score, time proximity, ASN/country, signer/hash or best-effort
parent metadata alone **never attach**. Same process with another destination also
does not attach without a stronger canonical reference. Unknown/partial process,
unknown/ambiguous network and missing destination are retained without fabrication.
Exact canonical references can connect different process instances or destinations;
coincidence cannot. Monitoring-session references alone are not evidence links.
TI HIT/NO_HIT is context, not a relation key. Supplied exact evidence references
can relate observations; the service never derives a link from provider verdicts.

### Event time, order and gap policy

Policy v1 uses **10-minute UTC-aligned half-open cohorts** `[start, start + 10m)`.
This is deliberately stricter than a sliding pairwise window: two nearby events
on opposite cohort sides stay separate. Equality at the upper boundary starts a
new cohort; one microsecond inside remains eligible. Total incident span is also
checked and can never exceed 10 minutes. Fixed cohorts prevent sliding bridges
(10:00 → 10:09 → 10:18), and give order-independent membership for unambiguous
shared-key input sets. No hidden wall clock is read.

An event-time high-water mark permits lateness of **10 minutes inclusive**.
Older inputs return a typed LATE result without reviving state. Expiry uses a
**20-minute** horizon (window + lateness); equality is retained. Capacity eviction
chooses earliest latest-observation, then first-observation, then canonical first
observation reference. Random runtime UUIDs do not decide eviction.
Replay dedup only covers retained state; restart/eviction intentionally ends it.

`ConnectionRoundObservation` supplies known failed/reduced/loss round markers.
Caller must supply markers before dependent observations; late markers cannot
retroactively undo earlier attachments. Gap checks use event-time intervals,
not arrival order. A marker between first and last observation denies a derived
process/destination link, while an exact reference may bridge with an explicit
limitation. NS-076 quality/monitoring-gap limitations also deny derived links.
Markers expire with the event-time horizon. Marker overflow fails conservatively:
derived links are disabled until the overflow timestamp leaves the horizon.

Multi-match selects priority first and then the canonical first observation reference;
ambiguity is explicit and incidents are never unioned. Arbitrary bridging inputs,
capacity eviction and late input beyond the supported horizon can depend on
arrival order. This online boundary does not claim global order-independent graph
partitioning. References from rejected inputs are never indexed.

### Central immutable bounds

| Resource | Default / hard maximum |
|---|---:|
| active incidents | 256 |
| process refs per incident | 16 |
| connection refs per incident | 32 |
| destinations per incident | 32 |
| evidence refs per incident/input | 64 |
| alert refs per incident | 16 |
| assessment revision pointers per incident | 16 |
| scope refs per incident | 16 |
| observation relations per incident | 128 |
| secondary index memberships, globally | 16,384 |
| secondary key memberships per incident | 256 |
| gap markers globally | 256 |
| diagnostic counters | saturate at signed 64-bit maximum |

Policies can reduce these bounds, never expand them. Input evidence tuples are
validated before processing. Admission is atomic: exceeding a reference, relation
or index bound returns CAPACITY_LIMITED and marks the incident; it never stores a
partial input or widens correlation. Eviction is not resolution or suspicious
evidence. Every incident removal cleans its index memberships.

### Domain and integration boundary

Immutable input, typed observation/entity/evidence pointers, explicit reason and
matched key, min/max UTC time, limitations and immutable snapshots form the public
contract. Canonical NS-076 `EvidenceReference` and NS-079
`AlertAssessmentReference` are reused. Destination adds a minimal typed domain
case to canonical IP endpoint semantics; DNS name and IP never collapse.
Connection tuple reuse is not lifecycle identity. Runtime IDs are random UUIDs,
stable while retained; this task promises no durable or cross-restart identity.

Application adapters accept existing connection lifecycle events, generic evidence
and historical assessment revisions. Reassessment uses original observation time,
not assessment/provider refresh time. The input contains no score, severity,
fingerprint, application name/path, provider payload or alert status, so correlation
cannot overwrite ACK/RESOLVED, suppression, mark-normal or risk decisions.

ConnectionOpened INITIAL means **connection observed**, not OS connect or process
creation. Process create-time is identity context only; no process-created event,
timeline or causal process tree is generated.

The synchronous service serializes short in-memory mutations and snapshots with
one lock; no dispatcher callback occurs under that lock. Diagnostics expose only
bounded aggregate counts. There is no SQL, incident repository, lifecycle storage,
GUI, timeline, worker, cloud action or history upload. SQLite remains **018 → 018**;
no migration. Memory disappears on restart. NS-090 persistence/lifecycle, NS-091
GUI and NS-092 end-to-end/soak remain future work; M16 is not complete.

## Validation

2026-10-04: **NS-089 COMPLETE**. New-only 140 passed; dependency-targeted 493
passed; full offline **3039 passed, 8 deselected in 112.53 s**. Ruff src/tests,
configured mypy (33 files), direct mypy (three new modules) and diff whitespace
checks passed. The built-in migration manifest reports **018**; no SQL resource
changed. Exact commands, files and all 103 requested report items are in the
[acceptance report](INCIDENT_CORRELATION_ACCEPTANCE.md).

Known limits: fixed-cohort boundary separation, caller-supplied gap ordering,
retained-state-only dedup and no global partition guarantee for arbitrary bridge
inputs. These are conservative correlation limits, not risk findings. M16 remains
in progress; NS-090 has not started.

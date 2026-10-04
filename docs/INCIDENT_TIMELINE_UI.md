# NS-091 — Incident timeline GUI

## Pre-implementation mapping freeze

This local, read-only page presents persisted NS-090 history. It does not run
correlation, mutate incidents/alerts, reassess risk, query TI, or subscribe new
engine producers. NS-090 remains an explicit persistence boundary; an empty
store is a valid page. Schema remains 019; NS-092 is not started.

| Kind | Persisted input | Primary time / wording |
|---|---|---|
| Observation | Each unique relation observation except ASSESSMENT_PRODUCED | Original observed_at; connection observed/updated/no longer observed, evidence/DNS evidence observed, alert observation reference |
| Inference | Each relation, including the isolated seed | Original observation anchor; correlation computation time is not recorded. Human-readable reason and exact matched identity; ordering is not causality |
| Assessment | Unique assessment pointers in the incident | Exact retained assessed_at, original observation separately. If missing/corrupt/unsupported, assessment time is unknown; original observation is an explicitly labelled ordering fallback, never presented as assessment time |
| User action | Retained ACKNOWLEDGED, RESOLVED, REOPENED revisions | changed_at; origin is displayed (reopen can be system correlation). CREATED/APPENDED storage revisions are not extra events |
| Context / limitations | Aggregate process/destination/scope refs, incident limitations, source availability, truncated revision history | No fabricated event time. Per-observation entity attribution is not retained by NS-090; aggregate context is labelled accordingly |

Process identity/create-time is technical instance context, never a creation
event. No current PID/name/cache data replaces missing historical information.
Polling INITIAL is connection observed; disappearance does not prove a TCP FIN.
Incident and assessment revisions are separate. Alert pointers are not alert
lifecycle events. TI remains assessment context with NS-083 explanation semantics.

## Ordering and pagination freeze

Oldest first total key: `(primary UTC time, kind priority, canonical source kind,
canonical source ID, revision, stable entry ID)`. Priority is Observation=0,
Inference=1, Assessment=2, User action=3. Canonical IDs and revision break ties,
including equal timestamps across page boundaries; no SQL natural order/hash.

Application pages default to 25 rows, maximum 100. Typed keyset cursor binds
incident ID, incident revision, content/source-state token and the last total
key. A changed revision or source state yields an explicit refresh-required
result, never mixed pages. Invalid cursors yield a typed invalid-cursor result.
The repository reads one coherent transaction: bounded canonical current
snapshot, up to 32 revisions, up to 16 exact assessments and batch source states.
There is no per-timeline-row source query. Mapping is bounded by NS-090 ceilings.
Incident list reuses UUID ascending repository keyset order and a single visible
page. Timeline retains at most 256 displayed rows; the cap is visibly explained.

## Worker, rendering and availability freeze

Separate list/detail latest-slot workers each have one active and one coalesced
pending request, with factory creation and all DB work off the GUI thread.
Generation plus immutable request guard protects A→B→A, pagination and refresh.
Cancel invalidates delivery; shutdown clears pending work and bounds each join
to two seconds. Tables use models, plain text and textual kind/status roles;
selected row exposes semantic times, UTC and canonical IDs. Local display follows
the existing timestamp formatter and is explicitly labelled local.

AVAILABLE means source available now. SOURCE_EXPIRED_OR_UNAVAILABLE means the
original supported source is no longer retained/available; it does not prove
retention caused absence. UNRESOLVED means no supported resolution, not expired.
CORRUPT and UNSUPPORTED_VERSION have distinct degraded wording. The retained
incident explanation survives source loss. Availability is a current attribute,
never a new observation. Failures are sanitized; no SQL/exception details or
sensitive diagnostics are exposed. There are no graph, causal reconstruction,
forensic integrity, process-created events or incident command buttons.

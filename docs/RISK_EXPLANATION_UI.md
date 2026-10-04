# NS-083 — Risk explanation UI

**NS-088 update (2026-10-04):** The shared query/panel now adds External reputation
context from immutable format-2 snapshots. Historical freshness is explicit;
provider score is separate from confidence and never malware probability. The
widget permits 8 detail sections plus Summary. Read-only exact-linked Alerts and
lifecycle-latest Connections remain; no read starts a lookup. [NS-088 current contract](THREAT_INTELLIGENCE_EVIDENCE.md).

Authoritative definition: [TASKS.md](TASKS.md#ns-083--risk-explanation-ui).
Starting checkout: clean `main`, HEAD
`74a4d062c555e59f386c7e089b49b40c5efaa8ed`.
SQLite **017 → 017**; no migration, dependency or diagnostics change.

**COMPLETE (2026-10-04). M14 COMPLETE.** Final full suite: **2348 passed,
7 deselected, 94.11 s**. Ruff, configured/direct mypy and whitespace checks pass.

## Surfaces and wording

Alerts → Selected alert → **Risk explanation** and Connections → Selected
connection → **Risk explanation** share one application read model and widget.
Legacy alert evidence remains in its original detail fields, inside a scrollable
Alert evidence tab. The risk tab is hidden for legacy alerts without an assessment
pointer. Connections without a retained assessment show an explicit unavailable
message, never a safety conclusion. Refresh risk details is an explicit read.

Summary shows **Concern score: N / 100** with visible
**Deterministic review-priority score; not a malware probability.** It also shows
effective and raw severity, availability, confidence, measurement quality,
assessment revision, scoring policy, observation/assessment times, suppression
state and a short contributor explanation. Zero with UNKNOWN availability is
rendered **Unavailable / insufficient evidence**, not as a numeric verdict.
INFO/LOW/MEDIUM/HIGH are stored severity values, not recalculated thresholds.

The remaining sections explain applied policy contributions, zero/excluded
contributors, measurement/severity limitations, evidence/source freshness,
baseline context at assessment time, suppression/preferences and technical
identity. Raw/applied points and stored correlation/family/global/mitigation
adjustments are explained without duplicating scoring rules. Negative points are
mitigating context, not trust. Related evidence is grouped to avoid double-counting.

## Read boundary and revisions

`RiskExplanationQueryService` returns frozen `RiskExplanationViewModel` values:
typed read status, bounded summary fields and explanation sections. Presentation
never formats repository graphs, executes SQL, scores or writes policy/audit.
The service accepts an explicit UTC query time. Absolute timestamps are shown
with their UTC offset and UTC label; no relative age/freshness is inferred.

For Alerts, the last attached `AlertAssessmentReference` is read **exactly** by
`(assessment_id, revision)`. An absent/pruned/corrupt/future linked revision does
not fall back to latest. Identity, revision and network status are checked.
Connections carry their canonical NS-056 lifecycle UUID in the existing table
read model. The query finds the latest retained revision for **that lifecycle**,
never by IP/PID/process name. No pointer is inferred for INITIAL observations.
Revision describes a re-evaluation of the same observation, not another occurrence.

The SQLite adapter adds two read methods. Exact revision uses the existing
composite primary key. Connection lookup scans only size-gated identity payloads
from at most 512 parents; it does not hydrate every revision or snapshot. Overflow,
ambiguous same-lifecycle assessments and unreadable identity metadata are
conservatively CORRUPT. The selected latest revision/source states are decoded in
the same scoped transaction. Existing 001–017 migrations are unchanged.

Stored freshness is independent of current reference availability. AVAILABLE,
SOURCE_EXPIRED_OR_UNAVAILABLE and UNRESOLVED retain NS-078's exact distinction:
absence cannot distinguish retention from a source that was never persisted;
an unsupported pointer does not establish expiry. Minimum historical evidence
still renders. Repository corruption/future format/query failure gives sanitized
text with no previous score left behind and no raw adapter exception.

## Historical data limits and preference truth

Format v1 persists baseline rule/result/reason/limitations, **not** the numeric
M13 count/rate/coverage/reference/interval object. Only the stored classifications
are explained. First-seen means not previously observed in the retained scoped
baseline. Frequency means observed appearance frequency; diversity means retained
destination diversity. Capacity loss forbids an exact-total inference. Periodic
timing is a polling observation and does not establish an exact timer or cause.
Missing historical metrics are explicitly disclosed. Today's learned baseline
remains in the separate NS-075 Behavior baseline tab.

NS-081 suppression is process-local, not part of a persisted assessment snapshot.
The existing `RiskAlertWorker` now retains at most **32** exact assessment/revision
evaluation results for explanation. It stores only the immutable suppression
contract, under its existing lock; it adds no event subscription, write, replay,
timer or scoring path. Reads do not update the cache. Restart clears it. An entry
is labelled **last runtime evaluation in this session**, with its actual evaluation
time, rather than being attributed to the assessment's original saved time.

Full/partial/no suppression, not applicable, incomplete and unavailable evaluation
use their stored dispositions. Fail-open is explicit; unknown evaluation is not
a no-match claim. Matched preference ID/revision, scope, lifetime, reason and
limitations remain available. Evidence/score are retained and alert eligibility
is not proof of notification delivery. If the runtime result was evicted or the
application restarted, the UI says historical suppression was not recorded.

A separate read of **current matching preferences** uses the existing NS-080
candidate query/exact matcher at the supplied query time. It displays current
active/expired/revoked policy, scope, revision, expiry/permanent and plain-text
reason, without evaluating historical alert eligibility. Revoke can therefore
coexist with an older applied runtime result without rewriting it. Candidate
corruption/future format/truncation/failure remains explicit. No USED record,
audit revision or command is issued by opening/refreshing detail.

## Bounds, lifecycle and accessibility

Each surface owns one `RiskQueryCoordinator`: **one active read + one replaceable
latest pending request**. Factories and queries run on `netsentinel-risk-query`,
with SQLite's one-second busy timeout in composition. Generation guards in both
worker and widget reject A→B and A→B→A late results. Same-selection live row updates
and alert page refresh preserve the panel and deduplicate reads. Explicit Refresh
coalesces while pending. Each worker waits at most two seconds at shutdown, drops
pending work and suppresses delivery; an active read may finish after that deadline.
Destroyed QObject emissions are guarded. Application startup/failure/shutdown own
both workers; presentation introduces no infrastructure imports.

Limits: 32 evidence, 64 contributors, 8 references/evidence, 16 limitations/evidence,
100 decoded current policy candidates, 32 displayed distinct preferences per
runtime/current section. Text is capped at 700 characters with an explicit truncation
marker; long application identities are separately shortened so destination,
revision and network constraints remain readable. The widget independently caps
13 summary fields, 7 detail sections and 1536 lines/section. Contributor/evidence
ordering follows the immutable stored contract; matched references preserve the
NS-081 specificity/UUID ordering. No refresh creates hundreds of widgets: sections
use a bounded number of read-only text views.

Labels explicitly use PlainText; rich user text is never interpreted. Evidence
editors use setPlainText and standard keyboard/select/copy behavior. Tabs, fields,
status, refresh and sections have accessible names; severity/suppression always
have text and do not depend on color. Canonical IPv4/IPv6 values and typed
unknown/ambiguous network states are preserved. Artifact hashes identify files,
not reputation; PID/name are not promoted to persistent application identity.

## Validation

All commands run in `C:\Users\berke\NetSentinel` using the existing
`.\.venv\Scripts\python.exe`; no environment installation or dependency upgrade.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/application/test_risk_explanation.py tests/integration/sqlite/test_risk_explanation.py tests/integration/test_risk_explanation_pipeline.py tests/gui/test_risk_explanation.py tests/integration/sqlite/test_risk_assessments.py tests/integration/test_risk_alert_pipeline.py tests/unit/application/test_behavior_risk_runtime.py tests/unit/application/test_suppression.py tests/integration/test_suppression_pipeline.py tests/gui/test_mark_normal.py tests/gui/test_baseline_detail.py tests/gui/test_alerts_view.py tests/gui/test_connections_view.py tests/gui/test_app_lifecycle.py tests/gui/test_application_shell.py tests/unit/domain/test_risk_scoring.py tests/unit/domain/test_risk_assessment.py tests/integration/test_arp_alert_pipeline.py tests/integration/test_dns_config_alert_pipeline.py tests/integration/test_vlan_pipeline.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/application/services/risk_explanation.py src/netsentinel/application/services/risk_worker.py src/netsentinel/infrastructure/sqlite/assessment_repository.py src/netsentinel/presentation/risk_query.py src/netsentinel/presentation/widgets/risk_explanation.py
git diff --check
```

Final targeted: **597 passed, 39.09 s**. Final full: **2348 passed, 7 deselected,
94.11 s**. Ruff: **All checks passed**. Configured/direct mypy: **29 / 5 files
passed**. `git diff --check` passed. The first broad targeted run
passed **591** tests, and the first full run passed **2342, 7 deselected** (99.82 s).
Six additional cap/exclusion/quota tests then passed with the affected GUI/model
regressions (**131 passed**). The final full and targeted runs include these cases.
The final parser/runtime-explanation failure checks were then verified with all
new NS-083 tests: **101 passed, 3.42 s**, plus Ruff and direct mypy. Malformed
optional runtime context cannot hide stored score; deeply nested corrupt identity
data returns a typed corruption result.

Configured mypy passed (29 files), and direct new query/presentation/modified
worker/repository mypy passed (5 files). A supplementary existing-GUI check of
alerts/details/connections/model/viewmodels remains outside the configured gate:
**33 pre-existing Qt annotation errors** (optional header/selection/viewport APIs,
legacy roleNames bytes/QByteArray annotation and one loop variable). The starting
HEAD files were extracted to a temporary package and checked with the same
interpreter; they reproduce these diagnostics plus existing optional-model issues
(49 total). The touched model access is now narrowed and nullable alert scope is
handled. No suppression/query module type error remains. This task does not expand
into a general GUI typing refactor. Supplemental exact command:

```powershell
.\.venv\Scripts\python.exe -m mypy src/netsentinel/presentation/views/alerts.py src/netsentinel/presentation/widgets/connection_details.py src/netsentinel/presentation/views/connections.py src/netsentinel/presentation/models/connections.py src/netsentinel/presentation/viewmodels.py
```

Tests are offline/synthetic, including real temporary SQLite and production risk
worker paths. Mixed ARP/behavior evidence preserves legacy expected/observed MAC,
confidence and correlation breakdown. Opening/refreshing detail compares all SQL
tables before/after: no risk revision, occurrence, baseline or policy/audit mutation.
Offscreen summary was rendered and visually inspected using a local Windows font.
No live capture/network traffic or manual end-user desktop smoke is claimed.

## M14 exit evidence

| Frozen exit requirement | Evidence |
|---|---|
| Contributor/evidence/confidence/quality/source-freshness/policy visible | NS-083 shared summary/detail and mixed/unknown/stale/source-state tests |
| Assessment revision visible; old snapshot not overwritten | Exact-linked versus latest/restart/pruning/corruption tests; NS-078 regression |
| Recalculation does not change occurrence/original observation time | NS-079 reassessment/lifecycle regression; NS-083 read-only table comparison |
| Legacy alert readability and dedup | Existing ARP/DNS/VLAN/Alerts regression plus mixed legacy detail test |
| Scoped, expiring, revocable preference | NS-080/081/082 scope/expiry/revoke/restart/Cancel regression |
| Probability/suppression/mark-normal invariants | Pure scoring tests; unchanged score/evidence under suppression; no global trust |

NS-076–NS-082 already completed; NS-083 completes M14 with the passing final gates.
NS-084/M15 is not started. No incident timeline, cloud/TI consent, desktop
notification delivery, response/firewall, branch, tag or release is included.

## Requested completion report (items 1–101)

| # | Item | Result |
|---|---|---|
| 1 | Exact title | NS-083 — Risk explanation UI |
| 2 | NS-083 status | COMPLETE (2026-10-04) |
| 3 | M14 status | COMPLETE; frozen exit criteria passed |
| 4 | Surfaces | Alerts and Connections selected detail tabs |
| 5 | Alerts integration | Last attached pointer; exact revision read |
| 6 | Connections integration | Canonical lifecycle; latest retained revision |
| 7 | Query/read model | RiskExplanationQueryService / RiskExplanationViewModel |
| 8 | Linked versus latest | Never silently substitute latest for an alert pointer |
| 9 | Revision | Visible summary field |
| 10 | Policy version | Visible stored vN |
| 11 | Score wording | Concern score: N / 100 |
| 12 | Probability | Explicit visible non-probability explanation |
| 13 | Zero/unknown | Numeric zero hidden when availability UNKNOWN |
| 14 | Severity | Stored text INFO/LOW/MEDIUM/HIGH or unknown |
| 15 | Raw/effective | Separate fields plus stored cap explanation |
| 16 | Confidence | Separate stored value or Unknown / not reported |
| 17 | Measurement quality | Separate complete/reduced/failed/unreported |
| 18 | Confidence versus quality | Explicit inference-support versus coverage/loss text |
| 19 | Observed at | Original observation UTC timestamp |
| 20 | Assessed at | Stored revision UTC timestamp |
| 21 | Applied contributors | Rule name, linked evidence ID, explanation |
| 22 | Points | Stored signed raw/applied policy points |
| 23 | Correlation | Grouped to avoid double-counting |
| 24 | Caps | Stored family/global adjustments explained |
| 25 | Mitigation | Negative context and mitigation cap explained; no trust verdict |
| 26 | Excluded contributors | Not used in score tab, including zero/correlated rows |
| 27 | Exclusion reasons | Typed stale/expired/quality/conflict/version/rule/limitation reasons |
| 28 | Evidence | Bounded rule/result/reason/role/time/identity/quality/reference snapshots |
| 29 | Source | ARP, baseline novelty/frequency/diversity, polling timing provenance |
| 30 | Freshness | Stored CURRENT/STALE/EXPIRED/UNKNOWN |
| 31 | Current source availability | Separate resolver state from historical freshness |
| 32 | Expired source | Expired-or-unavailable, retained minimum snapshot |
| 33 | Unresolved source | No resolver, distinct from evidence of expiry |
| 34 | Baseline context | Persisted classifications/limitations only |
| 35 | Novelty | Retained scoped baseline; first-seen/rare/known |
| 36 | Frequency | Observed appearance frequency |
| 37 | Diversity | Retained diversity; capacity limitation visible |
| 38 | Periodicity | Regular observed appearance timing; no cause verdict |
| 39 | Polling resolution | Explicit no exact-timer inference |
| 40 | Historical/current baseline | Separate risk historical tab and NS-075 learned baseline |
| 41 | Suppression | Last retained runtime evaluation, historical-unrecorded fallback |
| 42 | Full | All alert-driving evidence suppressed for alerting |
| 43 | Partial | Remaining independent/correlated support explained |
| 44 | Fail-open | Incomplete/unavailable distinct from no-match |
| 45 | Scope/expiry | Rule/app/revision/destination/network; timed/permanent; reason |
| 46 | Score under suppression | Preserved |
| 47 | Evidence under suppression | Preserved |
| 48 | Legacy ARP details | Expected/observed MAC, confidence, breakdown remain |
| 49 | ARP scoring/context | Original correlation score retains its label/meaning |
| 50 | DNS legacy | Existing detail retained; no generic panel without pointer |
| 51 | VLAN legacy | Existing detail retained |
| 52 | Broadcast legacy | Existing detail retained |
| 53 | Mixed evidence | Shared generic explanation plus legacy context |
| 54 | Unknown network | Explicit unknown/no fingerprint |
| 55 | Ambiguous network | Explicit ambiguous/no fingerprint |
| 56 | IPv4 | Canonical exact destination |
| 57 | IPv6 | Canonical full destination, no endpoint truncation inference |
| 58 | Application | Typed stable/provisional/unknown identity; bounded key |
| 59 | Artifact revision | Stored digest prefix or explicit unknown |
| 60 | Hash meaning | File identity, not reputation |
| 61 | Missing assessment | No retained assessment, no safety verdict |
| 62 | Corrupt | Typed unavailable/corrupt text |
| 63 | Future version | Typed unsupported version text |
| 64 | Unknown rule | Canonical ID plus no display mapping available |
| 65 | Bounds | Domain quotas plus independent widget/text/preference bounds |
| 66 | Ordering | Stored deterministic evidence/contributor and match order |
| 67 | Async | Two surface workers, all factory/DB reads off GUI |
| 68 | Generation | Worker and widget reject stale A→B→A results |
| 69 | Dedup | Same request preserved; pending manual refresh coalesced |
| 70 | Shutdown | 2 seconds/worker, no stale delivery, destroyed QObject guarded |
| 71 | Plain text | QLabel PlainText; QTextEdit setPlainText |
| 72 | Accessibility | Named summary/status/refresh/tabs/sections; standard keyboard controls |
| 73 | Color | Severity/suppression text; no color-only semantics |
| 74 | Read-only open | SQL table equality verified |
| 75 | Reassessment on open | None |
| 76 | Occurrence mutation | None |
| 77 | Preference/audit mutation | None |
| 78 | UI scoring logic | None; application mapping only |
| 79 | Historical re-score | None; stored old policy/result retained |
| 80 | Incident timeline | None |
| 81 | Cloud/TI consent | None |
| 82 | Desktop delivery | None |
| 83 | Schema | 017 → 017 |
| 84 | Migration file | None; 001–017 unchanged |
| 85 | Diagnostics | No new fields/logging/dumps |
| 86 | Added files | Listed below |
| 87 | Modified files | Listed below |
| 88 | Tests | New fixture and 4 test files; 101 new cases |
| 89 | Targeted commands | Exact command in Validation |
| 90 | Targeted result | 597 passed, 39.09 s |
| 91 | Full pytest | 2348 passed, 7 deselected, 94.11 s |
| 92 | Ruff | All checks passed |
| 93 | Mypy/path | Existing repo venv; configured 29 + direct 5 pass; supplementary legacy errors disclosed |
| 94 | Diff check | Passed; staged files also checked before commit |
| 95 | TASKS | NS-083 + M14 status only, acceptance text unchanged |
| 96 | ROADMAP | M14 completion; M15 remains planned |
| 97 | M14 exit | Matrix above and final gate results below |
| 98 | Commit | Actual SHA/message reported in final Git response |
| 99 | Push | Actual origin main result reported in final Git response |
| 100 | NS-084 | Not started |
| 101 | Working tree | Verified after commit/push in final Git response |

Added: `application/services/risk_explanation.py`, `presentation/risk_query.py`,
`presentation/widgets/risk_explanation.py`, `tests/fixtures/risk_explanations.py`,
`tests/unit/application/test_risk_explanation.py`,
`tests/integration/sqlite/test_risk_explanation.py`,
`tests/integration/test_risk_explanation_pipeline.py`,
`tests/gui/test_risk_explanation.py`, this document.

Modified: `application/services/risk_worker.py`, `bootstrap.py`,
`infrastructure/sqlite/assessment_repository.py`, `presentation/app.py`,
`presentation/models/connections.py`, `presentation/viewmodels.py`,
`presentation/views/alerts.py`, `presentation/views/connections.py`,
`presentation/views/main_window.py`, `presentation/widgets/connection_details.py`,
`docs/TASKS.md`, `docs/ROADMAP.md`, `docs/PRODUCT.md`, `docs/ARCHITECTURE.md`,
`docs/SECURITY.md`. Existing tests and migrations are unchanged.

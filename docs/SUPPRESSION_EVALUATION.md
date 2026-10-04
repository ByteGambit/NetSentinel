# NS-081 — Suppression evaluation integration

**COMPLETE (2026-10-04).** Authoritative scope: [TASKS.md](TASKS.md#ns-081--suppression-evaluation-integration).
Starting main HEAD: `b9807dfa0dffec01486cd84b2cadd9c943b1948c`;
schema **017 → 017**, evidence/scoring/assessment contracts **v1** unchanged.
Only NS-081 is completed. NS-082 remains planned; M14 remains incomplete.

Suppression expresses an explicit user's scoped alerting preference. It does not
classify a process/destination as safe, trusted or normal. It never deletes risk
evidence, changes score/severity/confidence, feeds the scorer, mutates baselines,
or rewrites historical assessment snapshots.

## Ownership and ordering

The existing `RiskAlertWorker` owns the complete blocking operation:

```text
M13 behavior signal → NS-076 evidence → NS-077 pure scoring
→ NS-078 assessment commit → current preference lookup/evaluation
→ NS-079 eligibility → existing AlertService commit → notification intent
```

`SuppressionEvaluationService` uses the `ScopedPreferenceRepository` port.
Its pure `evaluate_suppression` function reuses NS-080 `selector_matches` and
`ScopedPreference.status_at`. No SQLite import appears in the evaluator or
orchestrator. Bootstrap wires the existing SQLite policy repository into that
worker; construction is dormant. Monitoring callbacks and the GUI perform no
preference SQL. No new worker, cache, expiry timer or dependency is introduced.

`RiskAlertResult.suppression` adds a frozen typed current-policy explanation tied
to `AlertAssessmentReference`: assessment ID, stored revision and typed network
status. Evaluation uses **caller-supplied UTC `BehaviorRiskSignal.assessed_at`**,
including when persistence returns an older duplicate assessment revision. The
historical revision's time is not substituted. Naive/non-UTC times are rejected;
pure matching/evaluation has no wall-clock read. The result is process-local,
not a persisted suppression usage log. Future NS-083 can consume this contract;
no explanation GUI/read-model implementation is included here.

## Matching and precedence

Specified selector fields are exact AND constraints; omitted fields impose no
constraint. Match context comes from the normalized evidence's rule/subject/scope:

| Dimension | Contract |
|---|---|
| Rule | Exact typed ID; no substring, prefix, regex or wildcard |
| Application | NS-069 stable identity; no persistent PID/name or provisional key |
| Revision | Exact available digest; unknown/different revision cannot match a specified digest |
| Application without revision | Does not constrain artifact revision |
| Destination | NS-080 canonical IPv4/IPv6 equality; no IP/domain/ASN expansion |
| Network | Exact resolved fingerprint; UNKNOWN/AMBIGUOUS do not match resolved-network selectors |
| Host-wide | Omitting network permits UNKNOWN/AMBIGUOUS if all other constraints match |

All supported preference effects are suppression. **Any effective active match
is sufficient** for that evidence. Primary explanation order is descending count
of specified typed dimensions (application, revision, destination, network, rule),
then lexical UUID ascending. Current revisions alone participate; audit revisions
are not competing policies. Duplicate logical IDs in a port reply are corrupt
and excluded, rather than arbitrarily choosing one revision.

| Matching selectors | Primary explanation | Semantic effect |
|---|---|---|
| rule-only / application-only / destination-only / network-only | Lowest lexical UUID among one-dimension matches | Any active match suppresses |
| application + destination, versus application-only | Two-dimension selector | Same suppression effect |
| application + network, versus application-only | Two-dimension selector | Same suppression effect |
| rule + application + destination + network, versus its broader subsets | Four-dimension selector | Same suppression effect |
| application + exact revision, versus application-only | Two-dimension selector | Same suppression effect |
| Incomparable scopes with unequal dimension counts | Greater count, for explanation only | No security/allow/deny override |
| Incomparable scopes with equal dimension counts | Lexical UUID | Both retained within the bound |

A strict superset of matching constraints always precedes its broader subset.
The count/UUID ordering for incomparable selectors is an explanatory convention,
not an invented security priority. Input order does not affect the result.

## Evidence, correlation and eligibility

The unchanged NS-079 gate requires availability other than UNKNOWN, severity
LOW/MEDIUM/HIGH and an eligible positive contributor with applied points > 0.
For each correlation key with such a seed, every eligible raw-positive evidence
in that same group is supporting evidence, including superseded contributors
with zero applied points. A group remains alert-eligible if **any support is not
affirmatively suppressed**. Only suppressing every support removes the group.
An independent capped-to-zero group is not promoted; scoring budgets are not
redistributed. Negative/neutral/excluded contributors never become alert support.
The same evidence may have a negative mitigation contributor; its historical
mitigation remains untouched and cannot perversely raise the score.

`EvidenceSuppression` retains evidence ID and typed match context, disposition,
bounded matches and observed active/expired/revoked counts. `MatchedPreference`
retains policy ID/revision, selector, lifetime, manual origin and bounded reason;
`primary` and `dimensions` provide deterministic explanation. `AlertDrivingGroup`
retains original correlation key, all support IDs and remaining IDs.
`SuppressionEvaluation` exposes `suppressed_evidence_ids`,
`unsuppressed_evidence_ids`, `alert_eligible`, typed limitations and symbolic
`reason_code`. Uncertain support appears among remaining IDs because it stays
eligible for alerting; it is not classified safe or definitively policy-free.

| Original gate | Driving support / active matches | Evaluation | Eligibility and AlertService | Intent |
|---|---|---|---|---|
| Eligible | One evidence, no active match, complete query | NOT_SUPPRESSED | Normal NS-079 path | Existing post-commit eligibility |
| Eligible | One evidence, active match | SUPPRESSED | No AlertService call | None |
| Eligible | Two independent supports, one matched | PARTIALLY_SUPPRESSED | Remaining group maintains eligibility; original score/severity used | Existing post-commit eligibility |
| Eligible | Two correlated supports, one matched | PARTIALLY_SUPPRESSED | Remaining support maintains the same group | Existing post-commit eligibility |
| Eligible | All driving supports matched | SUPPRESSED | No AlertService call | None |
| Eligible | No valid match, truncated/corrupt/future candidates | INDETERMINATE | Unknown supports fail-open | Existing post-commit eligibility |
| Eligible | Lookup/evaluation unavailable | UNAVAILABLE | Unknown supports fail-open | Existing post-commit eligibility |
| Ineligible | UNKNOWN/INFO/no applied positive support | NOT_APPLICABLE | No new alert; existing NS-079 reassessment behavior retained | Existing NS-079 behavior only |

The six dispositions distinguish not applicable, proven no effective match,
full/partial suppression, incomplete evaluation and unavailable evaluation.
Aggregate suppression is validated against every group's remaining support;
references cannot point to missing evidence, drop uncertain support or justify
suppression with nonmatching/expired policies.

## Expiry and failure matrices

| Current preference | Effective state at explicit evaluated_at |
|---|---|
| ACTIVE/PERMANENT | Effective until explicit revoke |
| ACTIVE/TIMED, now < expires_at | Effective |
| ACTIVE/TIMED, now = expires_at | Expired, ineffective |
| ACTIVE/TIMED, now > expires_at | Expired, ineffective |
| REVOKED, permanent or timed | Revoked, ineffective even before future expiry |

Expired and revoked matches have distinct bounded counts. They remain in NS-080
storage/audit; evaluation appends no revision or USED record. Create/edit/revoke,
clock advancement and restart never automatically replay past assessments.
The next genuine signal evaluates current policy. An explicit caller-requested
reassessment still uses NS-079's existing semantics: existing count/last_seen/state
are preserved, and first-alert initialization for an assessment with no prior
alert remains possible. This is not an automatic policy-change replay; no original
occurrence/time is fabricated or changed.

| Failure/order | Result |
|---|---|
| Assessment persistence fails | No evaluation, alert operation or intent |
| Assessment committed, lookup unavailable | UNAVAILABLE + LOOKUP_UNAVAILABLE, normal eligibility continues |
| Evaluation raises / malformed port response | UNAVAILABLE + EVALUATION_UNAVAILABLE, normal eligibility continues |
| Evaluator omitted by a legacy caller | UNAVAILABLE + EVALUATOR_NOT_CONFIGURED, normal eligibility continues |
| Corrupt/future candidate, no valid matching active policy | INDETERMINATE with typed limitation; uncertain support remains |
| Valid active match plus corrupt/future candidate | Affirmative suppression remains valid; limitation retained |
| Candidate set truncated, no match | INDETERMINATE; never claim a complete no-match result |
| Candidate set truncated, valid active match | Match is effective; omitted candidates explicitly limited |
| Full suppression after assessment commit | NO_ALERT with assessment and suppression; zero AlertService calls |
| Partial suppression | Existing AlertService runs only because remaining original support is eligible |
| Alert persistence fails | Assessment and evaluation retained in result; no intent |
| Intent subscriber fails | Existing dispatcher isolation; committed alert stays committed |

Raw adapter exceptions never enter the result. Reasons, selectors, network/IP/path
context and correlation key are bounded local explanation data, hidden from their
dataclass repr and not added to diagnostics/export/logging. No new diagnostic
sink, arbitrary exception string or full source object graph is introduced.

## Bounds and candidate query

| Object/query | Hard bound |
|---|---|
| Evidence summaries / correlation groups | 32 each, from NS-076 contributor quota |
| Match references | 8 per evidence; at most 256 total |
| Candidate contexts | 1–32, deduplicated by service; no lookup for no driving support |
| Current candidate policies | At most 100 decoded; limit+1 (101) size-gated rows fetched to prove truncation |
| Observed active/expired/revoked count | Each 0–100, reflects examined candidates only |
| Limitations | Unique tuple from seven fixed enum values |
| Policy reason | NS-080 bound: 512 single-line characters |

`find_candidates` uses one short read transaction and the existing logical policy
primary key/current revision composite primary key. A connection-local deterministic
SQLite predicate receives only size/type-gated selector fields, reconstructs the
NS-080 selector and calls the same exact matcher. Valid unrelated selectors are
filtered before hydration. Malformed/future selectors and missing current revision
pointers are conservatively admitted as candidates and reported by the decoder.
Full decode also checks format, revision history and content fingerprint.

The query orders effective active rows before expired/revoked rows, then dimension
count and stable UUID. Effective ordering uses the same supplied UTC time; many
revoked rows cannot crowd a valid active match out of the page. Primary explanation
is selected again among decoded valid active matches; with truncation it refers
only to the examined bounded candidates.

The predicate scans bounded selector metadata for NS-080's at most 1024 logical
policies and up to 32 contexts; it does **not hydrate all 1024 policy/audit objects
per event**. No selector index, migration or complex cache is introduced. Existing
keys support current-revision joins and history integrity checks. SQL values are
parameterized; composed column vocabulary is fixed. No preference/audit usage
write or device trust operation occurs.

## Lifecycle and scope

Full suppression returns before even reading an alert through AlertService. For
OPEN/ACKNOWLEDGED/RESOLVED alerts, occurrence_count, first/last_seen, updated_at,
state, reopen fields and last_notified_at stay identical. Suppression never ACKs
or resolves a record. It emits no intent and consumes no notification rate window.
After expiry/revoke, the next real eligible occurrence uses existing count,
ACK/reopen and cooldown rules. The real 120-second AlertService cooldown continues
to apply. Detector windows/cooldowns and observed baseline learning run upstream
as before; a production-worker regression verifies that evaluation SQL runs on
`netsentinel-risk-worker`, and an engine regression verifies pre/post-mutation
behavior inputs continue while alerting is suppressed.

Fingerprint calculation is unchanged and independent of preference ID/revision,
disposition, score, scoring policy and assessment revision. Legacy ARP/device trust,
DNS, VLAN and broadcast paths remain outside generic suppression. No presentation,
detector, scoring, assessment serialization, AlertService lifecycle, migration
001–017, ROADMAP, dependency or version file is modified. No NS-082 command,
mark-normal/automatic trust, TI/cloud, firewall/response, desktop notification
delivery, new branch, tag or release is added.

## Files and validation

Added:

- `src/netsentinel/domain/suppression.py`
- `src/netsentinel/application/services/suppression.py`
- `tests/fixtures/suppression.py`
- `tests/unit/domain/test_suppression_contract.py`
- `tests/unit/application/test_suppression.py`
- `tests/integration/test_suppression_pipeline.py`
- `docs/SUPPRESSION_EVALUATION.md`

Modified:

- `src/netsentinel/application/ports.py`
- `src/netsentinel/application/services/risk_alerts.py`
- `src/netsentinel/infrastructure/sqlite/preference_repository.py`
- `src/netsentinel/bootstrap.py`
- `docs/ARCHITECTURE.md`, `docs/PRODUCT.md`, `docs/SECURITY.md`
- `docs/TASKS.md`: only NS-081 status updated

**107 new test cases**; existing test files are unchanged. Tests use synthetic
inputs and temporary local SQLite databases, without live capture/network actions.
All commands ran in `C:\Users\berke\NetSentinel` using the existing venv:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/domain/test_suppression_contract.py tests/unit/application/test_suppression.py tests/integration/test_suppression_pipeline.py
.\.venv\Scripts\python.exe -m pytest -q tests/unit/domain/test_suppression_contract.py tests/unit/application/test_suppression.py tests/integration/test_suppression_pipeline.py tests/unit/domain/test_preferences.py tests/unit/application/test_preference_service.py tests/integration/sqlite/test_preferences.py tests/integration/test_risk_alert_pipeline.py tests/unit/application/test_behavior_risk_runtime.py tests/unit/application/test_alert_service.py tests/unit/domain/test_risk_scoring.py tests/unit/domain/test_risk_assessment.py tests/integration/sqlite/test_risk_assessments.py tests/integration/test_device_security_pipeline.py tests/integration/test_device_identity_pipeline.py tests/integration/sqlite/test_device_profiles.py tests/unit/application/detectors tests/integration/test_arp_alert_pipeline.py tests/integration/test_dns_config_alert_pipeline.py tests/integration/test_dns_pipeline.py tests/integration/test_vlan_pipeline.py tests/performance/test_broadcast_burst.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/domain/suppression.py src/netsentinel/application/services/suppression.py src/netsentinel/application/services/risk_alerts.py src/netsentinel/infrastructure/sqlite/preference_repository.py src/netsentinel/application/ports.py
.\.venv\Scripts\python.exe -m mypy src/netsentinel/bootstrap.py
git diff --check
```

| Check | Observed result |
|---|---|
| New domain/service/pipeline tests | **107 passed, 7.39 s** |
| Targeted plus NS-080/079/scoring/assessment/legacy regressions | **961 passed, 32.35 s** |
| Full pytest | **2183 passed, 7 deselected, 86.18 s** |
| Ruff | All checks passed |
| Configured mypy | Success, 29 source files |
| Direct domain/service/orchestrator/repository/port mypy | Success, 5 source files |
| Supplementary bootstrap mypy | Three pre-existing DnsHistoryWriter argument-type errors |
| Schema | Latest migration 017, actual temporary DB 017, frozen 017 hash unchanged |
| Whitespace | `git diff --check` passed; staged new files also checked before commit |

The optional bootstrap check reports three errors at line 201 in the unrelated
`DnsHistoryWriter(**writer_options)` call (int/float/Callable expectations).
The original `b9807dfa...` bootstrap source was extracted with `git show` to a
temporary file and checked by this same `.venv\Scripts\python.exe -m mypy`, with
`MYPYPATH=C:\Users\berke\NetSentinel\src`: it reproduces exactly those three errors
at original line 198. No new integration error was reported. The configured gate
excludes bootstrap and passes; this existing issue remains outside NS-081 scope.

## Requested completion report (items 1–84)

| Item | Outcome |
|---|---|
| 1. Exact title | NS-081 — Suppression evaluation integration |
| 2. Status | COMPLETE |
| 3. Domain model | Frozen SuppressionEvaluation/EvidenceSuppression/MatchedPreference/AlertDrivingGroup |
| 4. Dispositions | NOT_APPLICABLE, NOT_SUPPRESSED, SUPPRESSED, PARTIALLY_SUPPRESSED, INDETERMINATE, UNAVAILABLE |
| 5. Evaluator | Application service + pure evaluation function, port-only storage access |
| 6. Query boundary | One bounded current-revision lookup, ≤100 decoded policies |
| 7. Clock | Explicit UTC signal.assessed_at; naive/non-UTC rejected; no hidden clock |
| 8. Rule | Exact rule ID |
| 9. Application | Stable identity; same name/different path does not match |
| 10. Revision | Exact available digest; unknown/different cannot match constrained revision |
| 11. IPv4 | Canonical exact address |
| 12. IPv6 | Canonical exact address; no mapped-family expansion |
| 13. Network | Exact resolved fingerprint |
| 14. UNKNOWN | Does not match a resolved-network constraint |
| 15. AMBIGUOUS | Does not match a resolved-network constraint |
| 16. Host-wide | Network omitted; other exact constraints can match unresolved scope |
| 17. AND | All specified fields must match |
| 18. Multiple matches | Any effective active match suppresses; references retained within cap |
| 19. Match bound | 8/evidence, 32 evidence, ≤256 references overall |
| 20. Precedence | Descending specified typed dimension count; strict subsets follow supersets |
| 21. Tie-break | Lexical UUID ascending; explanatory only for incomparable scopes |
| 22. Timed | Effective before expiry, inactive at/after exact boundary |
| 23. Permanent | No time expiry, explicit revoke remains effective |
| 24. Revoked | Always inactive, including future-expiry policies |
| 25. Corrupt | Typed limitation; no match → indeterminate; valid other match survives |
| 26. Repository failure | UNAVAILABLE with typed lookup/evaluation limitation |
| 27. Fail-open | Uncertain support retains normal alert eligibility |
| 28. Suppressed evidence | IDs plus typed bounded policy/context explanation |
| 29. Unsuppressed evidence | Remaining original alert-driving IDs, including uncertain support |
| 30. Partial | Any remaining original group/support maintains eligibility |
| 31. Full | Every support suppressed; bypass every AlertService call |
| 32. Correlation | Superseded raw-positive support retained; capped unrelated group not promoted |
| 33. Negative | Never alert support; historical mitigation unchanged |
| 34. Score | NS-077 result unchanged |
| 35. Severity | Historical and alert candidate risk severity unchanged |
| 36. Evidence | Same batch/evidence IDs; no removal |
| 37. Assessment | Committed before evaluation; same historical snapshot |
| 38. Separation | Historical risk vs current scoped policy decision |
| 39. Explanation | Additive RiskAlertResult.suppression with assessment reference |
| 40. Integration | Before NS-079 eligibility and AlertService operations |
| 41. AlertService | Single existing service; full suppression invokes none of its methods |
| 42. Occurrence | Suppressed signal cannot increment count |
| 43. last_seen | Suppressed signal cannot change it |
| 44. ACK | Suppression preserves ACKNOWLEDGED |
| 45. Resolved | Suppression preserves RESOLVED |
| 46. Reopen | Suppression/expiry/revoke do not reopen; next real occurrence uses existing rules |
| 47. Intent | Full suppression emits none; partial/unsuppressed use normal eligibility |
| 48. Ordering | Assessment and alert commits precede eligible intent |
| 49. Cooldown | Existing AlertService and detector policies unchanged |
| 50. Consumption | Fully suppressed signal leaves last_notified_at untouched |
| 51. After expiry | Next real signal sees inactive policy; no background action |
| 52. After revoke | Next real signal sees inactive policy; no replay |
| 53. Retroactive replay | None from preference operations/time/restart |
| 54. Fingerprint | Existing function unchanged |
| 55. Policy identity | Preference ID/revision/disposition excluded from fingerprint |
| 56. Reassessment | Existing NS-079 count/time/state semantics; explicit evaluation uses current time |
| 57. Detector state | Learning/windows and detector cooldown run upstream unchanged |
| 58. No deletion | Confirmed by immutable result and exact control snapshot regression |
| 59. No score change | Confirmed by scorer equality/partial/full/negative regressions |
| 60. No automatic trust | No preference writes or trust commands |
| 61. No mark-normal | NS-082 not implemented |
| 62. Device semantics | No detector/trust modifications; legacy regression suite passed |
| 63. GUI | Presentation unchanged |
| 64. TI/cloud | No provider/network request added |
| 65. Firewall/response | None |
| 66. Desktop delivery | Existing intent only, no delivery adapter |
| 67. Schema | 017 |
| 68. Migration | None; 001–017 unchanged |
| 69. Diagnostics | No new sink/fields; private context/reason hidden from repr, exceptions sanitized |
| 70. Added files | Seven, listed above |
| 71. Modified files | Eight, listed above |
| 72. Tests | 107 new cases in three files plus fixtures; existing cases unchanged |
| 73. Targeted commands | Exact commands recorded above |
| 74. Targeted results | 107 new; 961 including regressions, all passed |
| 75. Full pytest | 2183 passed, 7 deselected |
| 76. Ruff | Passed |
| 77. mypy/path | Existing project venv; configured 29/direct 5 passed; baseline bootstrap issue documented |
| 78. Diff check | Passed; staged check included new files |
| 79. TASKS | Only NS-081 status changed to COMPLETE |
| 80. Commit | Delivery message: feat: integrate scoped suppression evaluation; actual hash in completion message |
| 81. Push | Delivery target: ordinary git push origin main; actual outcome in completion message |
| 82. NS-082 | NOT started |
| 83. M14 | Incomplete, NS-082/083 remain planned |
| 84. Working tree | Post-commit/push verification returned in completion message |

Git delivery metadata is reported after commit/push, rather than storing a
self-referencing commit hash in its own source commit. No force push is used.

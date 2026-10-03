# NS-077 — Pure explainable scoring policy

**COMPLETE (2026-10-03).** Only NS-077 is completed by this change.

## Frozen v1 decisions

Score is integer **0..100**, a policy review priority / concern level, never
malware, compromise, C2 or confidence probability. Scoring policy **1** is
separate from evidence contract **1** and producer policy **1**. No dynamic
weights, I/O, clock, ML, persistence, alerts, preferences or UI are involved.
SQLite remains **014**; NS-078 is not started. M14 remains in progress.

Input is `RiskScoringInput(RiskEvidenceBatch, freshness)` plus an explicit
immutable `RiskScoringPolicy`. Freshness is a bounded tuple of typed evidence-ID
statuses: CURRENT, STALE, EXPIRED, UNKNOWN. Missing status is UNKNOWN; the scorer
never infers age from a clock. Duplicate input IDs are rejected by NS-076.
Unsupported contract versions are rejected at that contract boundary.

One immutable result contains score, pre-cap totals, availability, confidence,
measurement quality, score severity, final severity, severity-cap reasons, and
bounded explained contributors. Each contributor keeps its original evidence,
family, typed correlation key, policy version, rule explanation, raw and applied
points, and typed adjustments. No arbitrary details dictionary or assessment ID.

## Positive mapping

All M13 rows require exact source/rule/result and producer version 1. Positive
rows require FINDING role; ordinary known/normal/irregular rows require
OBSERVATION and contribute zero, never safety or mitigation. Insufficient,
not-evaluated and resolution-limited results are excluded as unknown context.

| Source / rule | Result | Points | Correlation family |
|---|---|---:|---|
| novelty / destination_ip_novelty_rarity | rare | 10 | activity |
| novelty / destination_ip_novelty_rarity | first_seen | 20 | activity |
| frequency / observed_appearance_frequency | elevated_unconfirmed | 15 | activity |
| frequency / observed_appearance_frequency | elevated_confirmed | 35 | activity |
| diversity / destination_window_diversity | elevated_unconfirmed | 10 | activity |
| diversity / destination_window_diversity | elevated_confirmed | 25 | activity |
| periodicity / observed_appearance_periodicity | periodic_candidate | 15 | periodicity |
| legacy ARP / ip_mac_conflict | original context | 30; corroborated 45 | identity |
| legacy ARP / gateway_mac_change | learned conflict | 35; corroborated 50 | identity |
| legacy ARP / gateway_mac_change | verified conflict | 45; corroborated 60 | identity |

ARP requires original validated legacy context, reason and unreported producer
version. Corroborated means original NS-027 correlation has MODERATE confidence;
legacy score/breakdown/severity are retained context, not additional points.
Generic missing measurement quality remains UNKNOWN and caps generic severity
at LOW. Original detector/AlertCandidate/AlertService semantics are unchanged.

## Correlation matrix (defined before implementation)

| A | B | Relationship in matching context | Stacking |
|---|---|---|---|
| novelty | diversity | partially correlated destination expansion | max |
| novelty | frequency | partially correlated appearance burst | max |
| frequency | diversity | partially correlated appearance burst | max |
| periodicity | frequency | independent timing regularity / volume | sum with family caps |
| periodicity | novelty | independent timing regularity / novelty | sum with family caps |
| legacy IP-MAC mismatch | gateway change | same identity transition if IP/expected/observed MAC match | max |
| any activity | legacy identity | independent behavior / LAN identity | sum with family caps |

Activity key: scope + application identity/revision/session (stable application
ignores process/lifecycle/IP, so window and destination facts meet). Without an
application, use exact subject identity conservatively. Periodicity adds
destination IP; contract v1 has no endpoint port/protocol, so no inferred service
identity. Identity uses scope + IP + expected/observed MAC; gateway/device kind
and event timestamps do not multiply the same transition. References stay in
the evidence explanation; absent/shared references never imply different facts.
Batch owner supplies a bounded assessment horizon; scorer does not invent it.

Every matching key keeps the largest eligible positive contribution; ties use
evidence ID. All batches and output contributors have deterministic ordering.
Contradictory CURRENT novelty classifications with the same scope, subject and
observation timestamp are all excluded as CONFLICT. No latest-source guessing.
Stale or otherwise ineligible facts cannot supersede current facts. Repeated
timestamps/references or correlation revisions cannot multiply a same-key fact.

Global family caps: activity **40**, periodicity **30**, identity **70**.
Group maxima are summed per family then capped (rather than separate novelty /
frequency caps), preserving positive monotonicity. Allocation is strongest first,
then evidence ID, with every cap/superseded explanation retained. Independent
keys/families can stack. Final positive subtotal caps at **100**.

## Mitigation

Only eligible PERIODIC_CANDIDATE with explicit typed
`BENIGN_SCHEDULE_COMPATIBLE` limitation proposes a separate **-3** contributor.
This is a small calibration for a pattern compatible with scheduled benign
workloads, not confirmation of a benign cause. Limitation-only evidence never
scores. Only the winning periodicity evidence gets the discount; correlated
copies cannot multiply it. No signer, country/ASN, device trust, known destination,
normal frequency, irregularity, user suppression or future preference is input
to mitigation. Periodicity's other limitations, including polling quantization,
remain available in its evidence explanation.

Total reduction is at most **min(5, positive_subtotal // 4)** and at most the
applied periodicity points supporting it. Negatives cannot erase strong evidence,
cross below zero or create safe/trusted/clean verdicts. At most two contributors
per evidence, therefore output hard bound **64** for NS-076's 32-evidence batch.
No explanation history is accumulated. Changes to these choices need a new
scoring policy version.

## Availability, quality, confidence and severity matrix

| Score band | Raw severity | Requirement / final cap |
|---|---|---|
| 0..9 | INFO | CURRENT recognized eligible observation/finding required |
| 10..29 | LOW | no safety verdict |
| 30..59 | MEDIUM | COMPLETE or REDUCED measurement, MODERATE/HIGH confidence |
| 60..100 | HIGH | COMPLETE measurement and MODERATE/HIGH confidence |
| any | UNKNOWN (no severity) | no eligible current recognized evidence |

Confidence is the weakest reported confidence among eligible evidence;
PASSIVE_OBSERVATION/LOW remains LOW-level context, never numeric. Unreported
confidence stays None. Any excluded evidence makes availability PARTIAL and
confidence at most LOW, without subtracting risk points. Empty/all-excluded is
UNKNOWN with no confidence or severity. Explicit capacity loss, monitoring gap,
reduced observation or prior-history loss caps confidence at LOW, without
rewriting reported measurement quality. A resolution-limited qualifier excludes
a candidate even if its result code claims a periodic candidate.
Quality summary covers all provided
measurements: FAILED dominates, otherwise unreported dominates, then REDUCED,
otherwise COMPLETE; empty is unreported. This describes measurement, not risk.

Reduced measurement caps severity at MEDIUM without lowering raw points.
Missing/FAILED measurement or missing/PASSIVE/LOW confidence caps severity at
LOW. Excluded stale/unknown evidence never creates high-confidence output.
COMPLETE is not HIGH confidence. HIGH impact and LOW confidence remain separate
in raw severity and final capped severity. No CRITICAL band is added to the
existing info/low/medium/high vocabulary.

Validation will freeze every mapping row and every severity boundary (-1/exact/
+1), positive and negative monotonicity, family/global/mitigation caps, conflicts,
fresh/stale mixtures, quality/confidence separation, unknown versions/rules,
32-evidence bounds, immutable equality, unchanged legacy context, and purity.

## Offline verification and delivery

Actual initial checkout: clean `main`, HEAD
`883d73cf6ccad2816bcabd7b84bb74ee8b0fc5b5`. No branch, tag, release, migration,
runtime wiring or dependency change was made. Scorer has no random result ID,
occurrence count, repository entity, preference or suppression hook. Frozen,
hashable results reconcile exactly with applied contributor totals. Complete
quality permits full points; reduced quality retains points and limits severity;
FAILED is limitation-only and cannot produce points. Unreported quality remains
None. Unsupported producer versions propose zero points; future evidence
contract versions are rejected by the unchanged NS-076 boundary.

Excluded reasons: unknown freshness, stale, expired, unsupported rule/version,
missing legacy context, limitation-only, insufficient data/quality, not evaluated,
resolution-limited, role mismatch, conflicting novelty. Correlated supersession,
family/global score cap and mitigation cap are typed contributor adjustments.
Input duplicates reject; different content IDs describing the same correlation
fact remain explained but cannot multiply that fact. Independent positive
additions and stronger supported replacements cannot lower score; adding only
the explicit mitigation qualifier cannot raise score. All result/source order
permutations are deterministic. Neutral/limitation/unknown inputs subtract no
points; no safe, clean or trusted assessment value exists.

Added files: `src/netsentinel/domain/risk_scoring.py`,
`tests/unit/domain/test_risk_scoring.py`, `docs/RISK_SCORING_POLICY.md`.
Modified files: `docs/ARCHITECTURE.md` (pure boundary/semantics),
`docs/TASKS.md` (only NS-077 status). **108 new test cases**; existing tests
unchanged. Tests are synthetic/offline, including unchanged legacy device-trust
detector regression tests and legacy SQLite alert repository/pipeline tests.

Exact commands run from repository root with the existing venv interpreter
`C:\Users\berke\NetSentinel\.venv\Scripts\python.exe`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/domain/test_risk_scoring.py tests/unit/domain/test_risk_evidence.py tests/unit/application/detectors/test_arp_identity.py tests/unit/application/detectors/test_arp_anomaly.py tests/unit/application/test_alert_service.py tests/unit/application/detectors/test_destination_novelty.py tests/unit/application/detectors/test_frequency_diversity.py tests/unit/application/detectors/test_periodicity.py tests/unit/application/detectors/test_device_identity.py tests/integration/sqlite/test_alert_repository.py tests/integration/test_arp_alert_pipeline.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/domain/risk_scoring.py
git diff --check
```

Targeted: **517 passed, 3.66 s**. Full pytest: **1756 passed, 7 deselected,
56.52 s**. Ruff: **All checks passed**. Configured mypy: **25 source files**;
direct scorer mypy: **1 source file**, both successful. `git diff --check`
passed. Schema remains **014**, AlertService/dedup/fingerprint/notification
eligibility and GUI remain unchanged. No probability output, ML, I/O, TI, cloud,
active network action, persistence or automatic response was added. NS-078
remains planned; M14 is not marked complete.

# NS-088 — TI evidence ve assessment/UI integration

Implementation date: **2026-10-04** (Europe/Istanbul). Authoritative acceptance:
[TASKS.md](TASKS.md#ns-088--ti-evidence-ve-assessmentui-integration).
Starting checkout: clean `main`, HEAD
`75af270e82cdc6c67a1209df45da921029089c92`.

**NS-088 COMPLETE. M15 COMPLETE.** All frozen exit gates passed. NS-089 remains
planned and untouched. Final working tree/commit/push receipt is reported in the
final Git response.

## Frozen decisions and mapping

**Numeric NS-077 scoring policy does not change: v1.** External reputation is
supporting context, not a malware verdict. Both HIT and NO_HIT are informational
OBSERVATION evidence with zero raw/applied points and no generic confidence or
measurement-quality claim. No provider vote, risk reduction or safety conclusion.
The saved local score, availability, confidence, quality, severity and contributors
stay intact. The unchanged scorer also excludes a standalone unsupported TI rule.

| Input | Evidence / revision | Visible meaning |
|---|---|---|
| FRESH HIT | Generic informational evidence + typed provider snapshot | Provider reports/context present; no attack or malware conclusion |
| FRESH NO_HIT | Same, zero positive/negative points | No reports/context in queried lookback; does not establish safety |
| STALE HIT | Same, explicit per-provider STALE | Old supporting context, not a fresh hit |
| STALE NO_HIT | Same, explicit STALE NO_HIT | Old absence of reports, never current clearance |
| STALE + refresh ERROR | Stale context and typed refresh error together | Refresh failed; stale remains stale |
| ERROR only | Operational UI status; no evidence/revision | Timeout, rate limit, unavailable or credential failure; local detection continues |
| EXPIRED / unusable cache only | No current evidence | Never promoted to fresh; prior historical snapshots stay readable |
| OFFLINE_DEFERRED | Pending operational status, cached stale context if available | No network probe; scheduler can resume under NS-087 policy |
| Cancelled consent/shutdown | No attachment | Cancellation context is not a current reputation result |
| Subject mismatch / unsupported subject | Typed mapping failure, no attachment | No guessed destination, domain or process identity |

`ThreatIntelEvidenceAdapter` centralizes scheduler/provider/cache mapping.
`evidence_for_context` creates source **THREAT_INTELLIGENCE** and stable rule
**threat_intelligence_reputation_context**. Reason codes are
`provider_reports_present` / `provider_no_reports`; result codes HIT / NO_HIT.
Provider is separate provenance, never a source enum or an alert fingerprint.
Generic evidence contains an EVIDENCE digest reference to its closed provenance.
No provider-specific mapping is spread across Qt or the risk orchestrator.

## Provenance, format and historical truth

The existing generic envelope cannot encode provider, fetch/query times or typed
metrics. Therefore the existing assessment snapshot adds a small closed
`ThreatIntelEvidenceContext`: linked evidence ID, exact cache key, minimum cached
result, assessment-time NS-085 freshness, optional refresh error and cache-write
limitation. It carries canonical provider ID, subject kind/value, data type,
result contract v2, request reference, UTC queried/fetched time and typed facts.
Evidence adapter v1 is fixed; AbuseIPDB metric mapping v1 is preserved.

SQLite **018 → 018**, no migration or table. Old migrations 001–018 are unchanged.
Local-only snapshots still write **format 1** with byte-for-byte original canonical
vocabulary and fingerprints. TI snapshots write **format 2** into the existing
snapshot column. v1 reads remain supported; a v1 row containing TI fields, a v2
row missing TI, bad link/freshness/subject or malformed content is CORRUPT. Future
format 3+ is UNSUPPORTED_VERSION. Format vocabulary is exact, byte/collection
bounded and type validated; no arbitrary metadata dictionary is introduced.

Each revision stores its own immutable context. It never re-reads the mutable TI
cache to explain the past and never executes today's scorer on a saved revision.
Historical UI labels **freshness at assessment time**, explicitly distinguishing
this from current cache freshness. Cache replacement, expiry or purge does not
rewrite historical evidence. Opening historical Alerts/Connections needs no network.
Latest local reassessment of the same observation retains independent TI context
without feeding it into scoring. If the generic 32-evidence bound leaves no room,
local scoring/persistence takes priority; older historical TI revisions remain.

## Revisions, alert lifecycle and failure boundary

The selected immutable target is **canonical lifecycle UUID + exact queried IP**.
The risk worker resolves only that lifecycle's existing assessment and verifies
canonical IP equality. It reuses its original RiskAssessmentKey and UTC observation
time. Different processes sharing an IP are never selected by destination alone.
No target means cache/UI context only; no fabricated behavior observation or alert.
Connection closure/navigation does not manufacture a replacement identity.

NS-078 `RiskAssessmentService.persist_snapshot` and the existing repository own
durable append/dedup. NS-079 `RiskAlertWorker` serializes TI enrichment with local
risk work in its existing 128-pending + one-active FIFO. The GUI receives a bounded
completion Future, never waits for it and claims integration only after commit.
Rejected/dropped work returns a sanitized unavailable/saturated completion.

| Change | Result |
|---|---|
| Exact cached result/provenance repeated | Existing retained content; no new revision |
| New queried/fetched observation, even same metrics | Materially fresher provenance; new revision |
| HIT ↔ NO_HIT, changed metrics or freshness/error context | New semantic revision when not an exact retained duplicate |
| Older fetched result arrives late | Does not replace newer per-provider provenance |
| Provider error after HIT without stale fallback | UI limitation only; historical HIT is not replaced with “clean” |
| No existing assessment | No assessment, occurrence or alert created |
| Assessment write failure | Lookup/cache remains available; no alert write |
| Assessment committed, alert update failed | Typed partial failure; retry deduplicates assessment and occurrence |
| Retry of retained older content | NS-078 historical no-op; no rewind of current alert |

Existing alerts use only **AlertService.update_assessment / REASSESSMENT**.
Occurrence count, first_seen, last_seen, original observed_at, fingerprint,
ACK/RESOLVED state and severity/confidence are preserved. TI alone never reopens
RESOLVED or clears ACK, never initializes a new alert and emits no notification
intent. Genuine later observations keep the original NS-079 occurrence behavior.
An older occurrence's assessment can persist without rewinding the current alert.
Suppression is not replayed or mutated by informational TI enrichment.

## Shared UI, explicit consent and privacy

Connections → Selected connection → **External reputation** provides a named
provider selector and **Check reputation** action. Eligible public IPv4/IPv6 only;
private/local/special/invalid IPs are disabled. No production domain/hash lookup is
advertised. Startup, connection observation, alert creation, row selection,
detail/page opening and consent Save submit **zero** lookup requests.

The action submits only through NS-087. Current memory consent is checked by the
scheduler, with missing consent explaining the Settings path. No implicit grant.
The production secret backend remains unavailable; explicit lookup reports
**credential unavailable** and performs zero HTTP. A reviewed injectable secret
port can support successful lookup; no key textbox, normal config/SQLite key,
plaintext file or production environment fallback was added.

One 200 ms Qt timer polls memory-only shared tickets for at most **8** captured user
actions. No per-request worker or busy loop. Selection epoch + lifecycle + subject
guards A→B and A→B→A late rendering. Old targets still complete/integrate independently
of the selected panel. A pre-commit risk query is superseded by a bounded post-commit
refresh; no stale pre-commit read is left displayed. Close/shutdown stops the timer,
clears pending UI state and suppresses delivery; scheduler caching follows NS-087.

`context_lines` is the shared application view mapper for both lookup and NS-083
stored explanations. Alerts continue reading the exact attached revision; a held
historical pointer is never silently substituted with latest. Connections show
the latest retained revision for that lifecycle. Alert list refresh exposes its
updated linked pointer. Existing legacy ARP/DNS/VLAN/broadcast details remain.

Visible AbuseIPDB labels:

- **AbuseIPDB abuse confidence score: N / 100** — provider metric, not NetSentinel
  confidence or malware probability.
- **Reports in provider lookback window** and explicit 30-day lookback.
- **Distinct reporting users**; optional **Last reported at** in UTC.
- Whitelist context explicitly does not imply trust or reduce risk.

Unknown provider metrics are omitted from display, while bounded stored facts stay
typed. Independent provider rows retain independent status/freshness and deterministic
provider-ID order; no averaging or malicious-provider vote. Display names/labels are
plain text, QTextEdit uses setPlainText, status is textual and accessible, and standard
keyboard/select/copy controls remain. The shared panel now allows 8 detail sections
plus Summary. Existing text/line caps remain.

Hard caps: 16 TI providers per assessment, 32 generic evidence, 64 contributors,
8 references/evidence, 16 limitations/evidence, 64 KiB assessment snapshot, 8 retained
revisions/assessment and 512 assessments. Metrics are the existing fixed 7-field
ThreatIntelIpFacts model, no unbounded metric collection. Lookup results contain at
most 16 constant-size lines/context plus operational status. The widget retains at
most 8 pending tickets/receipts. Existing aggregate risk-worker processed/failed/
rejected/dropped diagnostics include TI work; no new subject/metric log or diagnostic
dump, exception text, raw body/HTTP or credential is stored.

Automatic suppression/trust, device trust, file/process/path/history upload, blocking,
firewall, process kill, second production provider and incident timeline are absent.
Only AbuseIPDB remains production; fake second providers are tests. NS-089 is not started.

## Verification

All commands run in `C:\Users\berke\NetSentinel` with
`C:\Users\berke\NetSentinel\.venv\Scripts\python.exe`. Tests are offline, synthetic,
temporary SQLite and offscreen Qt. No live provider/network/capture is exercised.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/application/test_threat_intel_evidence.py tests/integration/test_threat_intel_evidence.py tests/gui/test_threat_intel_evidence.py tests/unit/domain/test_risk_assessment.py tests/unit/domain/test_risk_evidence.py tests/unit/domain/test_risk_scoring.py tests/integration/sqlite/test_risk_assessments.py tests/integration/test_risk_alert_pipeline.py tests/unit/application/test_risk_explanation.py tests/integration/sqlite/test_risk_explanation.py tests/integration/test_risk_explanation_pipeline.py tests/gui/test_risk_explanation.py tests/unit/domain/test_threat_intelligence.py tests/unit/domain/test_threat_intel_cache.py tests/unit/application/test_threat_intel_service.py tests/unit/application/test_threat_intel_cache_service.py tests/unit/application/test_threat_intel_scheduler.py tests/unit/infrastructure/test_abuseipdb.py tests/integration/sqlite/test_threat_intel_cache.py tests/integration/test_threat_intel_scheduler.py tests/gui/test_threat_intel_consent.py tests/gui/test_threat_intel_scheduler.py tests/gui/test_connections_view.py tests/gui/test_alerts_view.py tests/gui/test_app_lifecycle.py tests/gui/test_application_shell.py tests/integration/test_arp_alert_pipeline.py tests/integration/test_dns_config_alert_pipeline.py tests/integration/test_vlan_pipeline.py
.\.venv\Scripts\python.exe -m pytest -q tests/unit/domain/test_risk_assessment.py tests/unit/application/test_threat_intel_evidence.py tests/integration/test_threat_intel_evidence.py tests/gui/test_threat_intel_evidence.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/application/services/threat_intel_evidence.py src/netsentinel/application/services/risk_alerts.py src/netsentinel/application/services/risk_worker.py src/netsentinel/application/services/risk_assessments.py src/netsentinel/application/services/risk_explanation.py src/netsentinel/infrastructure/sqlite/assessment_codec.py src/netsentinel/infrastructure/sqlite/assessment_repository.py src/netsentinel/presentation/widgets/threat_intel_lookup.py src/netsentinel/presentation/widgets/risk_explanation.py
.\.venv\Scripts\python.exe -m mypy src/netsentinel/presentation/app.py
git diff --check
```

Broad targeted: **992 passed, 44.01 s**. After additional snapshot semantic
validation, focused adapter/persistence/GUI/domain: **102 passed, 6.87 s**.
Final startup/GUI optional-composition regression: **81 passed, 5.61 s**.
Final full offline suite: **2899 passed, 8 deselected, 110.55 s**. The first full
run identified three startup fakes lacking the optional behavior_risk field; the
composition now degrades gracefully, and the final full run is clean. The initial
targeted test-call typo was corrected before final targeted validation.
Offscreen STALE + timeout + metric layout was rendered with Segoe UI and visually
inspected; no end-user desktop/live provider smoke is claimed.
Ruff, configured mypy (32 source files), direct application/codec/query/presentation
mypy (9 files) and additional app composition mypy (1 file) pass. `git diff --check`
passes. Execution path is the existing repo venv, CPython 3.12.14.

## M15 exit verification

| Frozen ROADMAP gate | Evidence |
|---|---|
| Fresh install zero requests | NS-084/087 startup/consent/selection tests; real NS-088 GUI flow asserts zero before click |
| Fake provider abstraction | Independent A HIT / B NO_HIT; A STALE / B FRESH, no voting |
| Offline and TI-disabled local detection | NS-087 deferred/offline/optional-start-failure; unchanged local risk pipeline and unavailable/persistence-failure tests |
| Timeout / 429 / TTL / stale | NS-085–087 fake cache/provider regression; NS-088 operational/stale+refresh-error UI |
| NO_HIT versus failure | NO_HIT informational and never safe; ERROR operational, no security evidence |
| Supporting evidence / provenance | Generic source/rule + format-2 typed history + shared UI mapping |
| Recalculation occurrence invariant | Real SQLite count/time/ACK/RESOLVED/older occurrence/retry tests |

## Requested completion report, items 1–111

| Items | Result |
|---|---|
| 1–5 | Exact title above; final status below; schema 018; no migration |
| 6–9 | Central ThreatIntelEvidenceAdapter; THREAT_INTELLIGENCE / threat_intelligence_reputation_context; separate provider ID/mapping/time/reference; exact canonical IP |
| 10–18 | Fresh HIT/NO_HIT informational; NO_HIT ≠ safe; stale explicit for both; expired excluded; ERROR operational; offline deferred/local continues; stale+refresh error preserved |
| 19–26 | Typed AbuseIPDB score/reports/distinct-users/last-report/whitelist; labels above; whitelist no trust; metrics ≠ NS confidence and ≠ malware probability |
| 27–32 | No raw response/secret; immutable format-2 minimum provenance; historical freshness distinct from current cache; mutable cache not assessment history |
| 33–40 | Same logical key; append revision; exact cache duplicate no-op; newer fetch meaningful; HIT↔NO_HIT/metric changes semantic; ERROR only cannot clear HIT |
| 41–48 | Count/last_seen/observed_at/ACK/RESOLVED/fingerprint unchanged; existing update_assessment path; no TI notification intent |
| 49–53 | Numeric policy unchanged v1; scoring ceilings/weights not added; independent providers/no vote; unchanged scorer excludes standalone TI |
| 54–64 | Connections External reputation / explicit Check reputation; consent Settings explanation; credential unavailable/no HTTP; private/special disabled; domain/hash unsupported; fresh/stale cache visible; offline/rate-limit/timeout operational |
| 65–70 | Nonblocking 200 ms bounded memory polling; NS-087 shared ticket; selection epoch; immutable lifecycle/IP; closed connection never gets fabricated identity |
| 71–75 | No target: cache/UI only; persist failure retains lookup; alert failure typed partial commit; restart stored v1/v2 readable without network; historical TI section |
| 76–80 | Shared NS-083 query/panel; exact-linked Alerts and lifecycle-latest Connections; legacy ARP/DNS/VLAN/broadcast regression preserved |
| 81–85 | Accessible names/plain text/text status; explicit bounds above; existing aggregate worker diagnostics; no secret/raw/subject logging or new upload |
| 86–95 | Zero default/startup/connection/alert/selection/history lookups; no auto suppression/trust/block/firewall; no second production provider or incident timeline |
| 96–98 | File/test inventory below; 75 new offline cases; existing future-format fixture advances from 2 to 3 |
| 99–104 | Exact commands and measured results in Verification / final gate record |
| 105–107 | TASKS/ROADMAP M15 status and frozen gate verification updated only after final passing checks |
| 108–109 | Actual commit SHA/message and origin main push receipt are reported in final Git response |
| 110–111 | NS-089 untouched; actual final working tree is verified after commit/push |

Added: `domain/threat_intel_evidence.py`, `application/services/threat_intel_evidence.py`,
`presentation/widgets/threat_intel_lookup.py`, `tests/fixtures/threat_intel_evidence.py`,
`tests/unit/application/test_threat_intel_evidence.py`,
`tests/integration/test_threat_intel_evidence.py`, `tests/gui/test_threat_intel_evidence.py`,
this document.

Modified: application `ports.py`, risk_assessments/risk_alerts/risk_worker/risk_explanation
services; domain risk_evidence/risk_assessment; SQLite assessment_codec/repository;
presentation app, Connections/MainWindow, connection_details/risk_explanation widgets;
existing `tests/integration/sqlite/test_risk_assessments.py` future-version fixture;
TASKS/ROADMAP/ARCHITECTURE/PRODUCT/SECURITY and persistence/UI documentation update notes.

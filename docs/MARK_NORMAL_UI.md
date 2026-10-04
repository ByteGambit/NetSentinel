# NS-082 — Trust/mark-normal commands ve UI

## Frozen decisions (2026-10-04)

Connections → Selected connection → Behavior baseline contains a separate User
preference section. The user explicitly selects one canonical behavior rule;
this is a future pattern selection, not a claim that detector evidence exists.
No score or contributor explanation UI is added (NS-083 remains planned).

| Available context | Offered scopes / default | Unavailable explanation |
|---|---|---|
| No selected rule or no stable application | None | PID/name/provisional identity cannot persist |
| Stable application, selected rule | Exact available dimensions; default first | Empty/global scope never offered |
| Known revision | Exact revision by default; explicit across-revisions choice | Unknown revision: exact binary revision unavailable |
| Destination IPv4/IPv6 | Canonical destination by default; explicit any-destination choice | Missing destination: no destination selector |
| Resolved network | Exact fingerprint by default; explicit any-network choice | Fingerprint describes observed context, not proven routing |
| Unknown/ambiguous network | Explicit host-wide scope for selected rule/application only | No fake fingerprint or “this network” choice |

Only curated progressively broader combinations are offered. Every combination
retains stable application AND exact rule. Broader scope requires explicit
selection and a preview warning. Process display name is not identity.

| Lifetime | Behavior |
|---|---|
| No choice (default) | Preview/Save disabled |
| Explicit 24 hours | Freeze absolute UTC expiry at preview; no timer restart |
| Explicit permanent | No expiry; never selected by default |
| Expired/revoked current policy | Inactive text; no silent reactivation |

Reason is required, nonempty, single-line plain text, maximum 512 characters.

| Command result | UI effect |
|---|---|
| Invalid preview / Cancel create or revoke | No command, write or audit |
| Created / equivalent definition NO_CHANGE | Refresh relevant policies |
| Capacity / unavailable / unexpected failure | Sanitized text, no raw error |
| Revoke conflict | Refresh; never overwrite current revision |
| Revoke success | Refresh; audit preserved; no replay |

Preview is immutable and Save consumes that exact snapshot and retry ID.
User preference changes future matching alert/notification eligibility through
NS-081. It never declares safety, resets baseline, mutates evidence/score/history,
changes current alert count/status, changes device trust or writes firewall rules.
No automatic trust, signer trust, TI/cloud or desktop delivery is added.
Schema stays **017**, no migration; diagnostics fields are unchanged.

## Implementation and verification

`behavior_context` derives an immutable `PreferenceMatchContext` from the
NS-075 selected connection and explicitly selected rule. `scope_choices` is the
single scope factory; the UI never branches on individual rule IDs. Application
and rule are retained in every curated choice. `MarkNormalCommandService`
delegates through `ScopedPreferenceService` and its port; presentation imports
no SQLite adapter. An opt-in create flag deduplicates exact active definitions
inside the existing write transaction. Default NS-080 distinct-ID decisions
remain distinct; expired/revoked definitions never silently reactivate.

`PreferenceCommandCoordinator` owns reads and writes on one daemon worker:
8 pending commands, one active command, one latest coalesced query. Queries
use generation checks at worker and widget boundaries; command completions use
a selection epoch (including A→B→A). Save always consumes the immutable preview,
even if selection changes inside a modal confirmation. No destroyed-widget
callback is attached to command Futures. Stop waits at most two seconds,
rejects/drains queued work and invalidates query results. An already active
transaction may finish after a shutdown timeout; shutdown cannot undo a commit.

The existing candidate query reuses the NS-080 matcher and hydrates at most
32 policies, including matching expired/revoked current revisions. Truncation
and unavailable/corrupt state are visible. This is a selected-context surface,
not a global preference manager; edit UI and detailed risk explanation are absent.

Added files:

- `src/netsentinel/application/services/mark_normal.py`
- `src/netsentinel/presentation/preference_commands.py`
- `src/netsentinel/presentation/widgets/mark_normal.py`
- `tests/fixtures/mark_normal.py`
- `tests/unit/application/test_mark_normal.py`
- `tests/integration/test_mark_normal_commands.py`
- `tests/gui/test_mark_normal.py`
- `docs/MARK_NORMAL_UI.md`

Modified files:

- `src/netsentinel/application/ports.py`
- `src/netsentinel/application/services/preferences.py`
- `src/netsentinel/infrastructure/sqlite/preference_repository.py`
- `src/netsentinel/bootstrap.py`
- `src/netsentinel/presentation/app.py`
- `src/netsentinel/presentation/views/connections.py`
- `src/netsentinel/presentation/views/main_window.py`
- `src/netsentinel/presentation/widgets/connection_details.py`
- `src/netsentinel/presentation/widgets/baseline_detail.py`
- `docs/PRODUCT.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/TASKS.md`

64 new offline cases cover canonical scope/revision/address mapping, explicit
lifetime, invalid reasons, no-write previews/cancellations, Save/revoke/restart,
atomic duplicate confirmations, failures, stale results, immutable command
identity, thread ownership, queue bounds, shutdown and accessibility. Real SQLite
integration compares every non-policy table before/after query/Save/revoke,
including a retained baseline and risk/alert history. Future real fixture signals
exercise NS-081 matching, nonmatching dimensions, expiry/revoke and no replay.
No existing tests are changed. Synthetic Qt screenshots of the options and
Connections detail were inspected at the existing 1080×680 window size.

Exact targeted command (PowerShell, repository root):

```powershell
$env:QT_QPA_PLATFORM='offscreen'
.\.venv\Scripts\python.exe -m pytest -q tests/unit/application/test_mark_normal.py tests/integration/test_mark_normal_commands.py tests/gui/test_mark_normal.py tests/unit/domain/test_preferences.py tests/unit/application/test_preference_service.py tests/integration/sqlite/test_preferences.py tests/unit/domain/test_suppression_contract.py tests/unit/application/test_suppression.py tests/integration/test_suppression_pipeline.py tests/integration/test_risk_alert_pipeline.py tests/gui/test_baseline_detail.py tests/gui/test_device_profile.py tests/unit/application/test_alert_service.py --tb=short
```

Full validation commands:

```powershell
.\.venv\Scripts\python.exe -m pytest -q --tb=short
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/application/services/mark_normal.py src/netsentinel/application/services/preferences.py src/netsentinel/presentation/preference_commands.py src/netsentinel/presentation/widgets/mark_normal.py
git diff --check
```

Results: targeted **451 passed**; full **2247 passed, 7 deselected** (90.89s).
Deselected tests are the repository's opt-in live markers. Ruff passed; configured
mypy passed (29 files), direct mypy passed (4 files), diff check passed.
All commands use the repository's `.venv\Scripts\python.exe`; no alternate
interpreter, dependency update or environment installation was needed.

## Requested completion checklist

| # | Report item | Result |
|---|---|---|
| 1 | Exact title | NS-082 — Trust/mark-normal commands ve UI |
| 2 | Status | COMPLETE |
| 3 | UI location | Connections → Selected connection → Behavior baseline → User preference |
| 4 | Action wording | Mark this behavior as normal… |
| 5 | Semantics | Explicit preference for future matching behavior eligibility |
| 6 | Global trust | Never created |
| 7 | Application boundary | MarkNormalCommandService → ScopedPreferenceService → port |
| 8 | Preview | Immutable MarkNormalPreview with definition/context/retry UUID |
| 9 | Preview vs Save | Pure preview; separate explicit Save confirmation |
| 10 | Scope derivation | Central behavior_context and scope_choices |
| 11 | Default scope | App + rule + every available revision/destination/network dimension |
| 12 | Broader options | Explicit progressively omitted revision, network, destination; warning |
| 13 | Rule | One of four canonical M13 behavior rule IDs selected explicitly |
| 14 | Application | Canonical stable Windows path identity |
| 15 | PID/process name | Display context only; never persistent keys |
| 16 | Provisional app | Action unavailable with explanation |
| 17 | Revision | Known digest exact by default; any-revision choice explicit |
| 18 | Destination | Canonical selected IP; omitted destination means Any destination |
| 19 | IPv4 | Canonical typed destination supported |
| 20 | IPv6 | Canonical typed destination supported; no domain inference |
| 21 | Network display | Status, fingerprint, interface and observed-context limitation |
| 22 | UNKNOWN network | No fake scope; explicitly visible host-wide rule/app preference |
| 23 | AMBIGUOUS network | Ambiguity visible; no this-network choice |
| 24 | No valid selector | No action; no fallback global selector |
| 25 | Lifetime choices | Explicit 24 hours or permanent |
| 26 | Permanent | Explicit opt-in, no expiry |
| 27 | Timed expiry | Absolute UTC expiry frozen at preview |
| 28 | Default lifetime | Unselected; Preview/Save unavailable |
| 29 | Reason | Required nonempty single-line plain text, max 512 |
| 30 | Effect preview | Future-only eligibility; safety/history/baseline/firewall limits explicit |
| 31 | Evidence/history | Preserved; all non-policy stores compared in integration |
| 32 | Score | Historical score/severity unchanged |
| 33 | Baseline reset | Separate button/command; never invoked by preference |
| 34 | Current alert | Unchanged |
| 35 | Create | One definition/revision audit via existing NS-080 storage |
| 36 | Duplicate | NS-082 opt-in atomic exact-active-definition NO_CHANGE |
| 37 | Cancel create | No preference/audit/suppression change; restart remains empty |
| 38 | Capacity | Typed CAPACITY_REACHED, safe text |
| 39 | DB failure | Typed UNAVAILABLE; no raw exception |
| 40 | Preference display | Up to 32 relevant entries; status/lifetime/revision/reason/scope |
| 41 | Revoke | Captured preference ID + expected revision; audit appended |
| 42 | Revoke confirmation | Scope/revision/lifetime/reason and no-past-alert-replay text |
| 43 | Cancel revoke | No write or audit |
| 44 | Revoke conflict | Safe conflict message and refresh; no silent overwrite |
| 45 | Expired | Inactive EXPIRED text; no silent reactivation |
| 46 | Restart | Fresh service/UI reads persisted state |
| 47 | Permanent restart | Active state preserved |
| 48 | Timed restart | Same absolute expiry; active/expired correctly derived |
| 49 | Revoked restart | Revoked revision preserved |
| 50 | Matching future signal | Eligibility suppressed through NS-081 |
| 51 | Nonmatching future signal | App/rule/revision/destination/network mismatch does not suppress |
| 52 | Expiry integration | Next real signal resumes normal eligibility |
| 53 | Revoke integration | Next real signal resumes normal eligibility |
| 54 | Retroactive replay | None |
| 55 | Occurrence impact | Preference command changes no occurrence count |
| 56 | ACK/RESOLVED | Preserved; NS-081 lifecycle regressions pass |
| 57 | Suppression integration | Existing evaluator/matcher/pipeline reused |
| 58 | Preference vs baseline | Separate state, section and command |
| 59 | Preference vs device trust | Separate tables/contracts; device regression passes |
| 60 | Stale-result protection | Worker/query generation and widget selection epoch |
| 61 | Preview TOCTOU | Save consumes immutable A even after selection B |
| 62 | Double click | Pending actions disabled; retry ID and atomic definition dedup |
| 63 | Threading | Factory/read/create/revoke on dedicated worker, never GUI |
| 64 | Shutdown | Two-second wait; queue drained; active command may finish after timeout |
| 65 | Accessibility | Named/described controls; keyboard Preview/Cancel; text status |
| 66 | Plain text | All context/reason/status/confirmation labels explicitly PlainText |
| 67 | Automatic trust | None |
| 68 | Signer auto-trust | None |
| 69 | Everything normal | Empty/global selector impossible; app+rule always retained |
| 70 | Firewall | None |
| 71 | Response | None |
| 72 | TI/cloud | None |
| 73 | Desktop notification delivery | None; eligibility only |
| 74 | NS-083 implementation | None |
| 75 | Schema | 017 → 017 |
| 76 | Migration | None; existing numbered migrations unchanged |
| 77 | Diagnostics | No new fields; no sensitive logging |
| 78 | Added files | Enumerated above |
| 79 | Modified files | Enumerated above |
| 80 | Tests | Four new test/fixture files, 64 cases; existing tests unchanged |
| 81 | Targeted commands | Exact command above |
| 82 | Targeted result | 451 passed |
| 83 | Full pytest | 2247 passed, 7 deselected |
| 84 | Ruff | All checks passed |
| 85 | Mypy/path | Repository .venv interpreter; 29 configured + 4 direct files passed |
| 86 | Diff check | Passed |
| 87 | TASKS.md | Only NS-082 status updated; acceptance text preserved |
| 88 | Commit | feat: add scoped mark-normal commands and UI; actual SHA in final Git report |
| 89 | Push | origin main requested; actual result in final Git report |
| 90 | NS-083 started | No |
| 91 | M14 | Incomplete; NS-083 still planned |
| 92 | Working tree | Final Git report verifies post-commit/push state |

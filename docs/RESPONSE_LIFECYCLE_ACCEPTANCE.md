# NS-102 — ownership lifecycle acceptance

## Full NS-102 implementation — 2026-10-09

**Current status: NS-102 COMPLETE.** User GO followed the recorded native
Windows26200.9457 witness PASS. This resume uses injected fake firewall APIs and
temporary SQLite only. Native firewall mutation this resume **NO**; physical
host untouched. NS-103 UI and NS-104 native/uninstall NOT STARTED; automatic
threat blocking/elevation helper/background service NONE; git publication NONE.
Earlier reports below retain their original model/measurement scope.

Exact [TASKS NS-102 definition](TASKS.md#ns-102--owned-rulesauditreconciliation):

- **Amaç:** Oluşturulan kuralların sahipliğini, expiry ve rollback'i sürdürmek.
- **Yapılacaklar:** UUID manifest, idempotent command, short transaction audit ve OS/DB partial failure reconciliation ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/services/, src/netsentinel/infrastructure/sqlite/, src/netsentinel/shared/diagnostics.py, tests/integration/.
- **Bağımlılıklar:** NS-095, NS-101.
- **Acceptance criteria:** Duplicate/stale/external edit açıklanır; yalnız NetSentinel-owned rules kaldırılır; partial failure recoverable; audit bounded.
- **Test yöntemi:** Fake OS/DB failure, restart, external edit ve expiry testleri.
- **Kapsam dışı:** Başka uygulama/kullanıcı kurallarını değiştirme.
- **Başlatma kapısı:** Do not start before NS-099 and explicit response GO decision; M17 de tamamlanmış olmalıdır.

See [production contract](RESPONSE_COMMAND_CONTRACT.md#ns-102-production-lifecycle-contract--2026-10-09)
for behavior/limits. Earlier witnessless-PREPARED STOP counterexamples remain
valid and unchanged; they do not describe this implementation.

| Failure phase / evidence | Implemented result |
|---|---|
| PREPARED transaction fails/rolls back | No OS call; no partial intent/audit row |
| PREPARED committed, ATTEMPT fails/crash before Add | Fresh absence => NOT_MATERIALIZED; no replay Add |
| Add denied/definitely fails | FAILURE audit, preserve provenance, reconcile |
| Add unknown/crashes after materialization | Exact unique witnessed fresh state => FINAL/PROMOTION; otherwise unresolved |
| Add verified, FINAL DB failure | PARTIAL without returned ownership; original PREPARED supports witnessed recovery |
| FINAL commit acknowledgement lost | Conservative partial return; load existing durable result on replay |
| Wrong/missing witness, Description/scope drift, disabled, duplicate | No promotion/normal mutation; external/ambiguous classification |
| REMOVE intent/ATTEMPT fails/rolls back | No OS remove; retain committed intent |
| Remove denied/fails/unknown | Failure/unknown audit; no blind retry |
| OS remove succeeds, absence receipt write fails/crash | Fresh absence => ABSENCE_OBSERVED/UNKNOWN; cause not invented |
| OS_VERIFIED receipt committed, finalization fails/crashes | Pending receipt; fresh absence can finalize verified removal |
| Crash after FINAL commit | Existing final result plus current fresh reconciliation |
| External missing/modified/disabled | Discovery only; no repair/recreate/re-enable |
| Exact old metadata reappears after a durable verified removal receipt | Tombstoned archival manifest; external drift, no readoption/new REMOVE |
| Expiry due with fresh confirmed REMOVE and FINAL | Normal strict remove/equality/absence, audited |
| Overdue/stale approval or drift | Pending/refused; no synthetic approval or stopped-app guarantee |
| Concurrent same-store coordinator | Nonblocking store lock refusal; crash releases OS lock; no SQLite transaction over COM |

### Files changed

Production:

- src/netsentinel/domain/response.py: PREPARED value/codec, v2 FINAL/dispatch binding, typed PREPARED readback; v1 retained.
- src/netsentinel/domain/response_lifecycle.py: bounded typed lifecycle/audit/diagnostics/errors.
- src/netsentinel/application/response_ports.py: typed witness firewall and durable custody boundaries.
- src/netsentinel/application/response_lifecycle_service.py: explicit create/remove/replay/recovery/rollback/expiry coordinator.
- src/netsentinel/infrastructure/windows_response_firewall.py: witnessed construction/readback, existing strict target/REMOVE guards.
- src/netsentinel/infrastructure/sqlite/response_repository.py: short transactions/CAS/store binding/process lock/retention/diagnostics.
- src/netsentinel/infrastructure/sqlite/migrations.py and schema/020_response_lifecycle.sql: append-only020.

New implementation tests: tests/integration/test_response_lifecycle.py.
Existing tests/integration/sqlite/test_migrations.py and test_storage_privacy.py
advance supported/future schema assertions to020/021 without weakening checks.
Packaging entry/payload schema guards now require migrations001–020 and report
schema020; no build, installer release, uninstall behavior or NS-104 acceptance
was added. The schema-only compatibility changes also update these existing tests:

- packaging/entry.py; packaging/installer_payload.py.
- tests/gui/test_tray_lifecycle.py; tests/unit/infrastructure/test_abuseipdb.py.
- tests/integration/test_installer_lifecycle.py; test_desktop_notifications.py; test_risk_alert_pipeline.py; test_threat_intel_scheduler.py; test_suppression_pipeline.py; test_public_beta_acceptance.py; test_packaging_resources.py.
- tests/integration/sqlite/test_alert_repository.py; test_behavior_baselines.py; test_baseline_reset_completion.py; test_device_profiles.py; test_dns_association_persistence.py; test_dns_repository.py; test_gateway_baseline_repository.py; test_history_freshness.py; test_incident_persistence.py; test_incident_timeline.py; test_preferences.py; test_risk_assessments.py; test_threat_intel_cache.py; test_risk_explanation.py; test_vlan_repository.py; test_connection_repository.py.

Retained earlier uncommitted review files: tests/fixtures/ns102/__init__.py,
ownership_witness.py, witness_metadata_probe.ps1, inline_metadata_roundtrip.py;
tests/integration/test_response_prepared_claim_review.py,
test_response_ownership_witness_review.py;
tests/unit/infrastructure/test_ns102_inline_metadata_probe.py.
Docs: this report, RESPONSE_COMMAND_CONTRACT.md, SECURITY.md; TASKS.md status
changes only after full acceptance.

### Final report and quality gates

| # | Requested item | Result |
|---|---|---|
| 1 | Exact task | Quoted above unchanged |
| 2 | Files | Listed above, including retained review fixtures |
| 3 | Schema | **020**, append-only;001–019 unchanged |
| 4 | PREPARED | Immutable typed version1; persisted before Add; not ownership/REMOVE |
| 5 | Witness | UUID4 before confirmation; independent secrets.token_hex(32), unique256bits |
| 6 | Description | Exact native-proven133-byte literal ASCII; target unchanged |
| 7 | FINAL | Version2 full original request/state/witness/time binding; strict legacy v1 preserved |
| 8 | CREATE | Validated→PREPARED→ATTEMPT→OS/fresh verify→atomic FINAL/success audit |
| 9 | Promotion | Original durable claim + exact unique witnessed fresh read; unknown Add time stays None |
| 10 | Foreign/wrong witness | No promotion/ownership/removal |
| 11 | REMOVE/rollback | Final custody + distinct confirmed REMOVE + fresh full equality/exact removal/verified absence |
| 12 | Idempotency | Durable operation/request/store/CAS; reconcile first; no blind Add/Remove replay |
| 13 | Partial failures | Matrix above; absence without durable REMOVE receipt stays unknown |
| 14 | Reconciliation |64-operation cursor pages; exact/promotion/pending/expiry/external/ambiguous/unknown |
| 15 | External edits/missing | Discovery/audit only; no repair/recreate/re-enable |
| 16 | Duplicates | Ambiguous; no adoption/normal mutation |
| 17 | Expiry | Manual CREATE preserved; explicit confirmed REMOVE due intent; stale approval pending |
| 18 | Audit | Atomic phase/event/outcome/reconciliation; scope from retained operation |
| 19 | Retention |8192 audit rows;1024 operations;64 active/unresolved; custody protected; first cleanup capacity reserved |
| 20 | Diagnostics | Ownership/pending/partial/drift/expiry/last reconciliation/current errors; no witness |
| 21 | Concurrency | OS store lock across threads/processes, crash-released; short DB CAS, no COM transaction |
| 22 | Local admin | Privileged forgery outside frozen model; no cryptographic anti-admin claim |
| 23 | TOCTOU | Preflight→Add/external compare→Remove remain non-atomic |
| 24 | SQLite tests | Fresh/019→020/idempotency, Unicode/IPv4/IPv6/claim/manifest/witness, restart/rollback/retention/corruption |
| 25 | Targeted | **774 passed**,40.64s;126 production lifecycle cases included |
| 26 | Full offline | **4638 passed /9 live deselected**,513.34s(8m33s); no failures |
| 27 | Coverage | **91.21%**,28335 statements/2491 missed;85% gate unchanged |
| 28 | Ruff | **PASS** across src/tests/tools/packaging/pyproject.toml |
| 29 | mypy | **PASS** configured38 files; expanded production42 files |
| 30 | Whitespace | **PASS** git diff check plus all49 changed-file whitespace/control checks |
| 31 | Privacy scan | **PASS** bounded49-file/128KiB-per-file heuristic plus manual review; one exact reviewed negative fixture |
| 32 | Real firewall mutation this resume | **NO** |
| 33 | UI added | **NO** |
| 34 | Automatic blocking added | **NO** |
| 35 | Elevation helper added | **NO** |
| 36 | NS-102 | **COMPLETE** |
| 37 | NS-103 | **NOT STARTED** |
| 38 | NS-104 | **NOT STARTED** |
| 39 | Commit/push | **NONE** |
| 40 | Tag/release | **NONE** |

Quality procedure: targeted first, then full offline with offscreen Qt,
PYTHONHASHSEED0, pytest cache disabled and a fresh checked-absent workspace build
directory. Existing installer junction fixtures require the previously accepted
outside-sandbox procedure described in RESPONSE_FIREWALL_ACCEPTANCE.md; this uses
the current token, not a new elevation/helper. All three live categories remain
excluded. Early full runs were interrupted for stale-manifest/audit/custody review
or schema019 expectation updates; they are not full-suite passes. A sandboxed
schema regression run passed618 before its existing mklink/J fixture was denied;
no test was skipped or weakened to hide that failure. Final full results below
must come from the restarted run on final production code.

Final run: **4638 passed,9 live deselected,513.34s**;85% coverage requirement
passed at91.21%. It includes every existing offline installer junction case,
all schema020 compatibility regressions and126 new production lifecycle cases.
No native firewall test was run. Coverage measured28335 statements with2491
missed; prior gate configuration unchanged. Configured Ruff PASS; configured
mypy38 files PASS and expanded42-file production check PASS. No dependency/lock
update or installation was needed. Baseline HEAD remains
865a23680d22804b72676a09e0dfa3083c58b97e; working tree is uncommitted for review.

Bounded privacy review covers the exact changed UTF-8 text files at128KiB/file,
credential/private-key/personal-path/SID/email/control-character/trailing-space
heuristics and manual witness/logging review. The existing native-probe test's
explicit rejected host.json path is one reviewed negative fixture (never opened);
only that exact fixture is allowlisted. Native test-only witness evidence retained
from the earlier authorized VM closure is not a production secret. This is a
bounded heuristic, not exhaustive secret detection.

## Historical native-only closure and earlier reviews

**Latest native-only follow-up (2026-10-09): OS-resident witness metadata =
NATIVE PASS.** Dedicated Windows 11 **26200.9457**, individually authorized inline
PowerShell under unchanged **Restricted** policy: exact 133-character marker,
witness, fresh full readback and Description drift PASS. Exact cleanup, stale0,
476->476 inventory/hash equality, receipt deletion and original stopped VM state
verified. **GO to resume full NS-102 with PREPARED + witness**, not completion or
production-write authorization. This turn performed only native metadata testing;
no full NS-102 implementation resumed. See the [native closure](#native-description-round-trip-closure--2026-10-09).

**Historical witness review (2026-10-09):** independent OS-resident witness resolves
the accidental equal-selector ambiguity in focused fakes under the existing
non-adversarial threat boundary. **Native metadata verification remains OPEN**:
the dedicated VM refused the probe under effective Restricted execution policy;
no native rule mutation occurred. See the [witness review](#os-ownership-witness-review--2026-10-09).
No full NS-102 implementation/promotion resumed. Earlier stop reports below keep
their exact original model and measurement scope.

**Historical PREPARED-only follow-up (2026-10-09):** user authorized the PREPARED/FINAL model.
Its required promotion safety condition fails the deterministic collision
counterexample below. **STOP remains in effect; NS-102 INCOMPLETE.** The new
[clarification review](#prepared-contract-clarification-review--2026-10-09)
records 12 added contract-review tests / 235 targeted passes. The original
pre-clarification report below is preserved as historical evidence; its
files-changed/test counts describe that earlier pass, not the current follow-up.

Date: **2026-10-09 (Europe/Istanbul)**. Baseline:
`865a23680d22804b72676a09e0dfa3083c58b97e` (accepted NS-101).
The user authorized **only NS-102** and explicitly required STOP if crash recovery
would need weaker NS-100/101 ownership evidence. This is a blocker report, not
implementation acceptance. **NS-102 INCOMPLETE; NS-103/104 NOT STARTED.**
`TASKS.md` is unchanged; no completion or gate waiver is recorded.

## Exact authoritative task

From [TASKS.md, NS-102](TASKS.md#ns-102--owned-rulesauditreconciliation):

- **Amaç:** Oluşturulan kuralların sahipliğini, expiry ve rollback'i sürdürmek.
- **Yapılacaklar:** UUID manifest, idempotent command, short transaction audit ve OS/DB partial failure reconciliation ekle.
- **Acceptance criteria:** Duplicate/stale/external edit açıklanır; yalnız NetSentinel-owned rules kaldırılır; partial failure recoverable; audit bounded.
- **Test yöntemi:** Fake OS/DB failure, restart, external edit ve expiry testleri.
- **Bağımlılıklar:** NS-095, NS-101.
- **Kapsam dışı:** Başka uygulama/kullanıcı kurallarını değiştirme.

The current instruction authorizes work after M17 and NS-100/101 completion.
Historical NOT STARTED summaries in older documents do not invalidate that
authorization. The stop here is an ownership/atomicity issue, not missing GO.

## Exact blocking window

The accepted [ownership contract](RESPONSE_COMMAND_CONTRACT.md) requires the
**originating verified creation manifest**, unique exact identity, complete fresh
OS equality and verified exact removal/absence. An expected specification,
confirmed intent, UUID, name or equal discovered rule cannot replace originating
creation evidence.

`ResponseFirewall.create(request)` returns a manifest only after Add, unique full
readback and successful context cleanup. `read(manifest)` and `remove(request)`
already require that originating manifest. There is no pending-receipt recovery
or durable creation-evidence handoff in this port.

The relevant interruption sequence is:

1. An NS-102 coordinator could durably store INTENT/ATTEMPT and the full request.
2. NS-101 executes OS Add. The rule now survives application termination.
3. NS-101 reads back and constructs the manifest **in memory**.
4. The adapter returns the verified receipt, still **in memory**.
5. Only then could the coordinator commit the manifest to SQLite.

A crash between steps 2 and 5 can leave a rule without any durable originating
manifest. A failed/uncertain final DB commit has the same risk if the caller loses
the receipt before a successful durable retry. While the process remains alive,
retaining and retrying persistence of the exact returned manifest could help;
that does not bridge termination or prove that a commit succeeded.

After restart, intent plus a fully equal discovered rule is still insufficient:
that observation cannot distinguish this process's creation from a foreign exact
collision/replacement. Constructing `OwnedFirewallRuleManifest` from expected
properties and invented creation/verification times would grant ownership without
the accepted evidence. The contract expressly prohibits that recovery.

Adding SQLite tables, a lock, audit capacity or a second writable journal cannot
make OS Add and durable evidence capture atomic. Holding a DB transaction across
COM also cannot roll back the OS mutation on process termination. Persisting a
returned receipt in a callback can narrow the later window, but does not close the
Add-to-readback window; a pre-Add expected manifest is not verified evidence.

The safe residual result is **unresolved, no ownership grant, no replayed Add and
no managed Remove**. This preserves safety but cannot satisfy full recoverable
owned-rule rollback for the required crash windows. Per the user's explicit STOP
rule, no incomplete coordinator/schema was implemented or marked accepted.

## Evidence and limits

The existing fake suite already tests:

- Add changes the fake OS state and then loses its reply: OUTCOME_UNKNOWN, no
  manifest, rule remains (`test_unknown_exception_after_successful_mutation_stays_unknown`).
- Context cleanup fails after creation/readback: no manifest is handed out
  (`test_missing_backend_and_cleanup_exception_do_not_grant_ownership`).
- Even a completely equal existing identity cannot be adopted
  (`test_create_refuses_existing_identity_even_full_equal_never_adopts`).
- Full ownership field drift, duplicates, missing rules and stale confirmation
  refuse removal.

An additional **one-off, non-persisted fake probe** used these existing fixtures:

| Injection | State after creating a new adapter over retained fake OS state | Replay | Add calls | Remove calls |
|---|---|---|---|---|
| `BaseException` immediately after fake Add | One rule, zero durable manifests | NOT_ATTEMPTED / OWNERSHIP_CONFLICT, no manifest | 1 | 0 |
| Discard verified receipt before any durable handoff | One rule, zero durable manifests | NOT_ATTEMPTED / OWNERSHIP_CONFLICT, no manifest | 1 | 0 |

This probe simulates the lost handoff and new service instance. It does **not**
claim a persistent SQLite restart test, an implemented lifecycle state machine,
native Windows evidence or completed NS-102 acceptance. No OS backend was loaded.

## Failure matrix at the stopped boundary

These are design implications, not implemented NS-102 behavior:

| Case | Accepted safe interpretation / remaining work |
|---|---|
| DB intent fails before OS | No dispatch; coordinator not implemented |
| Intent durable, known OS create failure | Record known failure; no ownership |
| OS create verified, manifest commit fails | Retain exact in-memory receipt if available; after loss, unresolved ownership gap |
| OS create UNKNOWN | No manifest; no blind retry/adoption/removal |
| DB commit uncertain | Inspect durable state with bounded validated reads; no assumed success |
| Crash after intent only | ATTEMPT/intent cannot prove whether Add happened; no blind retry |
| Crash after OS Add/readback, before durable manifest | Blocking gap described above |
| OS Remove succeeds, final DB commit fails | Persisted originating manifest could support fresh absence discovery, but absence alone cannot prove this command removed it |
| Removal intent durable, OS Remove fails | Keep manifest and failed/unknown removal state; no success claim |

Persisted valid originating manifests would allow read-only reconciliation to
classify matching, missing, modified/disabled and duplicate rules. They would not
authorize repair, recreation, re-enable, adoption or deletion of drifted rules.
Unmanifested pending creates must remain unresolved. A DB failure cannot be
treated as permission to delete by name.

## Expiry and other preserved boundaries

NS-100 v1 accepts only `UNTIL_MANUALLY_REMOVED` with `expires_at=None`.
Timed/exit lifetime is rejected by `ResponseLifetime` and the strict codec.
The [planning expiry section](M18_RESPONSE_PLANNING.md#10-expiry-crash-restart-and-external-modification)
calls for unsupported/deadline/clock/failed-cleanup fake tests without unlocking
temporary blocking. NS-102 must not silently change that accepted scope or
manufacture a new REMOVE confirmation when an expiry timestamp is reached.
No expiry scheduler or guaranteed wall-clock cleanup was added.

Existing adapter locks cover one instance only. COM has no atomic compare-and-
remove against an external administrator; exact cloning/replacement and external
edit races remain documented NS-101 limitations. A user-writable manifest/SQLite
row is not authenticated privileged authority, even when structurally valid.
No protected receipt storage, privileged helper or new security boundary was
introduced as a workaround. Production writes remain NO_GO.

Before implementation can resume, the ownership/recovery contract must explicitly
resolve this window: either accept permanently unresolved pre-manifest operations
as the required recovery outcome, or approve a separately reviewed evidence and
custody mechanism. Neither an expected manifest nor a post-restart OS match may
silently become originating evidence. This report makes no claim that an ordinary
journal alone can guarantee atomic OS/DB recovery.

## Delivery checklist (requested final report)

| # | Item | Result |
|---|---|---|
| 1 | Exact NS-102 definition | Quoted above without modifying acceptance criteria |
| 2 | Files changed | Only `docs/RESPONSE_LIFECYCLE_ACCEPTANCE.md` |
| 3 | Migration/schema | **019 -> 019**; no migration, existing SQL untouched |
| 4 | Owned-rule persistence | Not implemented; stopped at contract blocker |
| 5 | Manifest persistence | Existing strict 16 KiB v1 codec retained; no durable repository |
| 6 | Lifecycle states | No new values; intended UNKNOWN/PARTIAL must not grant ownership |
| 7 | Idempotency | No durable implementation; existing replay refuses collisions |
| 8 | Audit model | Not implemented |
| 9 | Audit bound/retention | Not implemented; planning quotas remain proposals |
| 10 | CREATE coordination | Not implemented; precise handoff gap documented |
| 11 | REMOVE/rollback | Existing NS-101 manifest/fresh equality/absence contract preserved |
| 12 | Partial-failure machine | Not implemented; matrix above documents safe limits |
| 13 | Restart reconciliation | Not implemented; two fake receipt-loss probes confirm blocker |
| 14 | External edit/missing | Existing refusal semantics retained; no durable reconciliation |
| 15 | Duplicate/ambiguous | Existing refusal retained; no guessing/removal |
| 16 | Expiry | Existing manual-only contract preserved; no expiry removal |
| 17 | Diagnostics | No new signals or raw data |
| 18 | Concurrency | Existing per-adapter nonblocking mutation lock unchanged |
| 19 | Security/races | Lost evidence window, writable-ledger trust and external edit/clone race documented |
| 20 | Targeted tests | **223 passed** (existing ownership/adapter/port tests); one pytest cache permission warning |
| 21 | SQLite integration | NOT RUN; no NS-102 schema/repository exists |
| 22 | Full offline suite | NOT RUN on this stop/documentation pass; no new acceptance claim |
| 23 | Coverage | NOT MEASURED; prior NS-101 evidence is not a current measurement |
| 24 | Ruff | **PASS**; four preexisting inaccessible temporary directories reported as traversal warnings |
| 25 | mypy | **PASS**, configured 37 source files |
| 26 | Whitespace | **PASS**, tracked diff check plus new-document trailing-whitespace check |
| 27 | Bounded privacy scan | **PASS**, new document limited to 128 KiB; secret patterns/control characters plus manual privacy review |
| 28 | Real firewall mutation performed | **NO** |
| 29 | UI added | **NO** |
| 30 | Automatic threat blocking added | **NO** |
| 31 | Elevation helper added | **NO** |
| 32 | NS-102 | **INCOMPLETE / STOP** |
| 33 | NS-103 | **NOT STARTED** |
| 34 | NS-104 | **NOT STARTED** |
| 35 | Commit/push | **NONE** |
| 36 | Tag/release | **NONE** |

Targeted command:

```powershell
& .\.venv\Scripts\python.exe -m pytest tests/unit/infrastructure/test_windows_response_firewall.py tests/unit/domain/test_response_ownership.py tests/unit/application/test_response_ownership_port.py -q
```

The sole warning reports inability to write the existing pytest cache; all 223
tests passed. No source, test, dependency, packaging, runtime or task-status file
was changed. Full implementation quality gates cannot be claimed from this
pre-implementation blocker review.

Additional checks: `python -m ruff check --no-cache .`,
`python -m mypy --no-incremental --cache-dir=nul` and `git diff --check` passed.
The new untracked document was checked separately for trailing whitespace and
bounded private-key/token/credential patterns, control characters and accidental
raw sensitive data. Ruff's four traversal warnings concern existing inaccessible
temporary directories; no lint errors were reported.

## PREPARED contract clarification review — 2026-10-09

The user chose two-phase pre-mutation provenance, with a conditional promotion
rule: durable PREPARED + exact operation identity + fresh unique OS readback +
complete equality may become final ownership **only if this is strong enough with
the current adapter/OS semantics**. The user expressly required STOP otherwise.
The PREPARED/FINAL distinction is accepted as the intended design. Promotion is
not implemented because the following required safety condition fails.

### Remaining blocker: indistinguishable creation and collision refusal

The new test uses **file-backed temporary SQLite**, a committed complete candidate,
fresh independent connections on restart and the existing NS-101 fake backend:

| Observation | History A: NetSentinel created | History B: foreign collision |
|---|---|---|
| Before dispatch | Commit complete PREPARED claim | Commit identical complete PREPARED claim |
| OS mutation | Adapter Add creates exact expected rule | Foreign exact rule exists; application Add count is zero |
| Interruption | Crash after Add, or lose verified receipt before final commit | Crash before calling adapter, or lose explicit OWNERSHIP_CONFLICT refusal before recording it |
| Durable restart row | Same complete claim bytes and operation identity | Same complete claim bytes and operation identity |
| Fresh complete OS read | Exactly one fully equal rule | Exactly one fully equal rule |
| Proposed four-input promotion | Would grant ownership | Would also grant ownership to the foreign rule |

Both pre-dispatch interruption and lost-refusal cases pass this equivalence test.
There is no heuristic mismatch to detect and no second rule making the state
visibly ambiguous. Unique equality alone does not reveal **historical origin**.
This uses the existing adapter's normal collision refusal, not a new hypothetical
privilege or a change to Windows behavior.

Even a durable ATTEMPT flag before dispatch is the same in both histories. Moving
such a flag inside the adapter does not close the before-Add-to-durable-receipt
window. The native COM snapshot has no authenticated operation-origin receipt;
all fields in the supported expected snapshot can be identical for both rules.
A new self-declared marker would require separate semantic review and would not
by itself authenticate who performed Add. No helper, protected ledger, backend
scope change or alteration of the expected native rule was introduced.

Consequently the requested **"exact single OS match can finalize ownership"**
positive test cannot safely be satisfied for both supported histories. Adding it
as a passing test would encode foreign-rule adoption. Per the user's explicit STOP
condition, no production `PreparedFirewallOwnershipClaim`, promotion function,
repository or recovery port was introduced. This does not reject durable
PREPARED bookkeeping; it identifies why that bookkeeping alone cannot meet the
promised ownership recovery.

### Candidate fields tested (not production values)

`_ProposedPreparedClaim` is a frozen test-only candidate with:

- `creation: FirewallCreateRequest`: full immutable CREATE command and bound
  confirmation. Nested command retains command/operation UUID, generated rule UUID,
  store UUID, full spec/lifetime, source/file identities, preparation time,
  selection generation and contract version. Nested confirmation retains the
  fingerprint and UTC confirmation time.
- `expected_rule: FirewallRuleSnapshot`: every supported expected ownership
  property, including the complete spec and Rule/Rule2/Rule3 restrictions.
- `prepared_at: datetime`: UTC pre-mutation provenance time, **not actual OS
  creation or final verification time**.
- `claim_version: int = 1`: candidate format version.

The test writes all fields as a complete structured payload with parameterized
SQL and commits before CREATE; an independent connection inside fake Add verifies
visibility of that commit. It is not a production strict codec/schema migration,
does not prove privileged authorization, and cannot grant ownership or deletion.
The existing REMOVE constructor rejects the candidate, bytes, name and UUID.

### CREATE, replay and nonmatching states

The proposed lifecycle ordering is validated confirmation -> atomic PREPARED
commit -> exact NS-101 CREATE -> fresh unique full verification -> final manifest
commit -> owned VERIFIED_SUCCESS audit. Only final committed evidence could
support normal owned lifecycle. The blocked step is **restart promotion from
PREPARED without a final receipt**, not normal persistence of a returned manifest.

Missing, modified, disabled or duplicate fake rules never satisfy unique exact
equality; no test performs a mutation to repair/adopt them. Unsupported/unavailable
readback must likewise remain unresolved under existing NS-101 semantics.
For missing OS state, CREATE_NOT_PRESENT could record discovery; it cannot assert
that Add never happened or silently dispatch again. Replay retains the original
operation identity. In both exact-match histories, current NS-101 refuses replay
with OWNERSHIP_CONFLICT and no manifest. Tests verify one total Add for History A,
zero Add for History B, and zero Remove in both. No production durable idempotency
or reconciliation coordinator is claimed by this test harness.

### REMOVE gap analyzed independently

Finalized ownership evidence is already durable before a future REMOVE. A durable
REMOVE intent can support read-only restart reconciliation without creating new
ownership. Exact present state permits only the existing confirmed/fresh-checked
removal path; expired confirmation needs a new approval, not automatic retry.
Absent state can be recorded as **verified current absence at reconciliation time**.
It does not establish whether this command or an external administrator removed
the rule; do not fabricate an earlier completed audit event or success time.
Drift/disabled/duplicate/unsupported state refuses mutation. This CREATE review
changes neither the REMOVE request type nor its fresh equality/absence checks.

### Focused test results

New persistent tests cover pre-dispatch crash, durable commit ordering, lost Add
receipt, lost VERIFIED receipt, lost collision refusal, fresh complete equality
of indistinguishable origins, nonmatching/missing/disabled/duplicate OS state,
safe replay and rejection of candidate/name/UUID/bytes for REMOVE.

**12 new tests; 235 total targeted passed in 1.16 s.** Command:

```powershell
& .\.venv\Scripts\python.exe -m pytest tests/integration/test_response_prepared_claim_review.py tests/unit/infrastructure/test_windows_response_firewall.py tests/unit/domain/test_response_ownership.py tests/unit/application/test_response_ownership_port.py -q -p no:cacheprovider --basetemp <fresh-workspace-build-directory>
```

The initial run's eight tmp_path setups failed because the sandbox's default
temporary pytest directory was inaccessible (227 passed / 8 setup errors).
Re-running with a new unique workspace `build/` temporary directory resolved the
environment issue: 235 passed, zero warnings/errors. No real firewall was loaded
or mutated; SQLite files contain only synthetic test data. No existing tests or
gates were weakened. Full offline suite/coverage deferred as expressly allowed
for this clarification; no production contract/code path changed.

### Clarification delivery report (17 items)

| # | Requested item | Current result |
|---|---|---|
| 1 | PREPARED closes crash gap? | **NO** for safe ownership recovery; bookkeeping survives, origin ambiguity remains |
| 2 | Exact claim fields | Four candidate fields above; nested identities/versions preserved; test-only, no production type |
| 3 | Why not ownership | Durable intention proves neither Add nor origin; constructor rejects candidate for REMOVE |
| 4 | CREATE state machine | Proposed phases documented; no coordinator/migration implemented |
| 5 | Restart promotion proof | Proposed inputs identical for successful creation and foreign collision; unsafe promotion stopped |
| 6 | Mismatch/ambiguity | No adoption, repair or deletion; intended PARTIAL/UNRESOLVED |
| 7 | REMOVE contract unchanged | **YES** |
| 8 | Idempotency | Replay tests keep same identity and make no duplicate Add; no production idempotency store |
| 9 | Files changed | This report, `docs/RESPONSE_COMMAND_CONTRACT.md`, `tests/integration/test_response_prepared_claim_review.py` |
| 10 | Targeted tests | **235 passed** including 12 new; initial temp setup issue resolved |
| 11 | Ruff | **PASS**, `src tests tools packaging pyproject.toml`, no warnings |
| 12 | mypy | **PASS**, configured 37 source files; production source unchanged |
| 13 | Whitespace/privacy | **PASS**, tracked diff plus all three changed files (128 KiB/file bound, secret/control/trailing-whitespace checks, manual synthetic-data review) |
| 14 | NS-102 | **INCOMPLETE / STOP**; TASKS unchanged; schema019 unchanged |
| 15 | NS-103/104 | **NOT STARTED** |
| 16 | Commit/push | **NONE** |
| 17 | Tag/release | **NONE** |

NS-100/101 remain COMPLETE. No real firewall mutation, UI, automatic blocking,
elevation helper, privileged service, scheduled task or runtime wiring was added.

## OS ownership witness review — 2026-10-09

Scope: only the requested ownership-witness spike; **do not resume full NS-102**.
The accepted baseline remains NS-101 `865a23680d22804b72676a09e0dfa3083c58b97e`.
The production domain, port, adapter, schema019, runtime and task statuses remain
unchanged. Previous PREPARED-only counterexamples remain valid, not weakened or
deleted. All code added here lives under test fixtures/tests.

### Decision and threat boundary

**Conditional model viability, native gate unresolved.** Adding an independent
256-bit witness to the expected OS state makes an equal-selector foreign rule
without that exact witness observably different. Promotion eligibility now requires
more than semantic selectors/UUID/name or an expected command. Fresh full-state
equality includes that random discriminator, backed by pre-Add durable provenance.
No collision probabilities are presented as absolute safety guarantees.

The frozen planning contract says: "No adversarial-local-admin/tamper-proof
ownership guarantee is claimed." The accepted NS-101 review also states that COM
fields cannot authenticate forged manifests or exact clones. Accordingly, malicious
privileged copying is **outside** this witness's protection. A local administrator
can inspect state and reproduce the token; the test deliberately shows an exact
clone is eligible. A writable SQLite claim also cannot authenticate requester
consent or privileged authority. Those existing production integrity gates remain
NO_GO. No new credential/key hierarchy, signing, broker, service or WFP driver is
needed or introduced for this review. Witness is correlation evidence, not a MAC,
signature or secret access credential.

### Candidate representation and proof

Test-only `WitnessPreparedCandidate` has five fields:

| Field | Bound content |
|---|---|
| `creation: FirewallCreateRequest` | Full command, operation/rule/store identity, spec/lifetime, source/file provenance, command version/generation/time and exact confirmation/fingerprint |
| `expected_rule: FirewallRuleSnapshot` | Every original supported ownership field; only Description differs from production v1 to embed the witness |
| `witness: str` | Independent `secrets.token_hex(32)`, 256 random bits / 64 canonical lowercase hex digits |
| `prepared_at: datetime` | UTC pre-mutation provenance timestamp, not claimed actual OS creation time |
| `claim_version: int = 1` | Test-candidate format version, not a production schema/manifest version |

Each new operation also allocates a UUID4 CREATE command/rule identity before
mutation. Replay reuses the decoded persisted operation, never allocates another
identity/witness. The local strict prototype codec has a 16 KiB bound, canonical
JSON, duplicate/unknown field rejection, supported version/type/time checks and
complete expected-state/confirmation binding. Unicode command paths remain in the
existing codec; the actual OS marker is ASCII only and exactly **133 characters**:

```text
NetSentinel response witness v1 <canonical-rule-uuid> <64-lowercase-hex-witness>
```

Candidate, rule Description and serialized witness stay out of repr/error/log
output. Synthetic test SQLite stores original command bytes and witness locally;
no telemetry/export path is added. Its unique operation/witness constraints are
review scaffolding, not an NS-102 production migration or retention implementation.

The proposed sequencing is generate/confirm exact identity+witness -> atomic
PREPARED commit -> original NS-101-style preflight -> Add exact witnessed rule ->
fresh unique full readback -> versioned final manifest commit -> bounded verified
audit. A callback's independent SQLite connection verifies commit visibility before
fake Add. A restart's new connection restores the identical candidate; fresh
enumeration and eligibility do not invoke a second Add.

Required eligibility combines original durable claim, exact operation/store/rule
identity, exactly one fresh complete supported candidate, exact witness, every
ownership field and a valid fresh read timestamp. Missing/wrong witness or edited
Description rejects the equal-selector foreign rule. Every snapshot field is
independently drift-tested. Missing, duplicate, disabled, unsupported/unavailable,
untyped read, mismatched durable operation and clock reversal/future read cannot
be proof. No auto repair/re-enable/adopt/delete follows any mismatch.

**Eligibility is not finalization or REMOVE authority.** The test-only predicate
does not authenticate that a caller's bytes came from a pre-Add commit or that
supplied snapshots came from a trusted fresh reader. The harness establishes those
facts in tests; production custody/repository/inspection must enforce them later.
Only a final committed manifest may authorize normal lifecycle, subject to separate
privileged confirmation. Production v1 rejects the new Description. A future
versioned contract must include witness and recovered evidence/discovery time,
preserve legacy decode without weakening removal, and provide PREPARED inspection
without pretending an expected snapshot is already a finalized manifest. Do not
invent an actual created_at timestamp after a receipt-losing crash, including when
the original CREATE confirmation has expired. A one-day-later test establishes
read-only eligibility but cannot construct a fictitious v1 creation receipt.

### Windows semantics and native attempt

Primary Microsoft sources checked on 2026-10-09:

- [Description setter](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrule-put_description) and [getter](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrule-get_description): read/write BSTR, optional, `|` prohibited. These pages do not specify a maximum length or guarantee exact storage/localization behavior.
- [INetFwRules::Add](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrules-add): an existing same-identifier rule may be overwritten. Do not equate an Add success receipt with exclusive creation.
- [Name getter](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrule-get_name): required friendly name, `|` prohibited; not a secure namespace.
- [Grouping getter](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrule-get_grouping): explicitly supports indirect resource strings. The spike selects literal Description instead; it does not infer that all Description forms/builds avoid transformations.

NS-101's `TEXT_PROPERTIES` maps Description directly to complete enumeration
readback; `ComFirewallApi.add` sets it before Add and tests detached full state.
The offline spike exercises that actual mapping with an injected COM fake and
verifies exact witnessed Description and all ownership fields. This is not native
Windows persistence evidence.

Native exactness was judged necessary because the documentation alone does not
prove round-trip of persisted metadata. The existing dedicated **Windows 11** VM
was initially stopped and was started headless using the existing VMware provider.
Observed computer identity: **DESKTOP-B18OKSK**. No credentials were read/output.
The reviewed probe is parameter-guarded to that exact computer plus VMware hardware
and an existing administrator token; it never elevates. It would create one
**disabled** outbound rule targeting a unique nonexistent fixture path and one
bounded program/IP/TCP-port/Private-profile scope, with no socket or executable
launch. Planned vectors: 133-character ASCII witness; empty/one-character strings;
Unicode text; 4096 ASCII characters (application bound, not assumed OS maximum).
It would independently enumerate, compare every getter, detect metadata changes,
remove only its own fully equal specimen and verify identical unrelated inventory.

**Actual native result: NOT RUN / BLOCKED by effective Restricted PowerShell
execution policy.** File execution returned failure without a result receipt;
an explicit diagnostic returned `System.Management.Automation.PSSecurityException`
and `UnauthorizedAccess`. `Get-ExecutionPolicy` reported `Restricted`; all listed
policy scopes were Undefined. No bypass, ExecutionPolicy change, elevation, VM
security change or alternative mutation mechanism was used. The probe body did
not run. Therefore Description persistence, allowed native lengths, Unicode,
normalization/localization and mutation detection are **NOT VERIFIED**; this is
not evidence that Description is unstable or unsuitable.

Read-only native cleanup enumeration found **zero**
`NetSentinel:NS102-metadata-spike:*` rules. The transferred script and VMware-created
temporary file were deleted. No result/diagnostic output file existed. The initially
stopped VM was returned to stopped state with a normal soft shutdown. No guest
fixture executable was created, native rule added or physical-host firewall touched.
The retained host probe is review material only; its syntax was checked locally.
No native acceptance PASS or native OS build claim is made.

### Collision, drift and residual races

The fixture verifies NS-101's final native-boundary preflight rejects a matching
identity whether or not its witness is equal; no Add or pre-submit callback runs.
Existing NS-101 initial/post-target checks remain untouched. The documented
same-identifier overwrite semantics mean these checks must never be removed or
turned into upsert. Case aliases/duplicates remain conservative refusal conditions;
Name is not asserted to be Windows' authenticated internal identifier.

An administrator/process can still insert or replace a rule after final enumeration
and before Add/Remove. COM supplies no compare-and-swap protection; per-instance
locks cannot coordinate outside processes. Random identity+witness reduce accidental
collision, not atomicity. A privileged observer can copy both. Exact cloned metadata
cannot authenticate origin. If protection against such an attacker becomes required,
ordinary metadata is insufficient and needs a separate architectural decision.

Ordinary external Description/witness changes are drift: no restoration, deletion
or re-adoption. Confirmed REMOVE remains finalized manifest -> its own fresh unique
complete equality including witness -> exact deletion -> fresh absence. Existing
production request/adapter implementations are unchanged. Candidate/witness/name/
UUID alone are rejected; production v1 cannot be tricked into accepting the spike
snapshot. No unlinking of source or reconstruction of timestamps is added.

### Witness delivery report (22 items)

| # | Item | Result |
|---|---|---|
| 1 | Closes accidental/foreign-selector ambiguity | **YES in the non-adversarial fake model**, assuming original pre-Add custody and exact native metadata; production/native GO not granted |
| 2 | Metadata field | Literal `Description`, exact 133-character ASCII encoding |
| 3 | Native round-trip reliability | **NOT VERIFIED**; file probe blocked before execution |
| 4 | Nonce size/generation | 256 bits, `secrets.token_hex(32)`, independent per operation; UUID4 identity allocated separately |
| 5 | PREPARED fields | Five fields above; complete nested command/confirmation and expected snapshot |
| 6 | Promotion proof | Pre-Add durable provenance + exact identity + fresh unique complete readback + witness + all fields; eligibility only |
| 7 | Equivalent foreign-rule result | Missing/wrong witness -> ineligible, no manifest/Remove authority |
| 8 | Forged/local-admin | Exact cloning passes; frozen threat model excludes malicious-admin proof; writable-ledger privilege gates remain |
| 9 | Same-identifier overwrite | Documented Add risk; no namespace or atomicity claim |
| 10 | Preflight collision | Existing API refuses equal-name candidate with/without witness, zero Add |
| 11 | TOCTOU | Outside insertion/replacement can race Add/Remove; no COM atomic comparison |
| 12 | REMOVE unchanged | **YES**, no production change; final manifested evidence still required |
| 13 | Files changed this review | Two docs, `tests/fixtures/ns102/__init__.py`, `ownership_witness.py`, `witness_metadata_probe.ps1`, `tests/integration/test_response_ownership_witness_review.py`; prior PREPARED review test retained unchanged |
| 14 | Targeted tests | **392 passed / 1.88 s**, including **61 new witness cases**; prior counterexamples retained |
| 15 | Native metadata test | BLOCKED / NOT RUN, no mutation; cleanup verified, VM restored stopped |
| 16 | Ruff | **PASS**, `src tests tools packaging pyproject.toml --no-cache` |
| 17 | mypy | **PASS**, configured 37 source files |
| 18 | Whitespace/privacy | **PASS**, git diff plus seven changed files at 128 KiB/file bound, secret/control/trailing-whitespace scan and manual synthetic-data review; PowerShell probe syntax PASS |
| 19 | NS-102 | **INCOMPLETE**, full implementation not resumed; schema019 unchanged |
| 20 | NS-103/104 | **NOT STARTED** |
| 21 | Commit/push | **NONE** |
| 22 | Tag/release | **NONE** |

No broad production code/contract path changed. Full suite/coverage deferred as
explicitly permitted for the spike. NS-100/101 remain COMPLETE. The review does
not add response UI, threat triggers, secrets infrastructure, privilege helpers,
services/tasks, active traffic tests, dependency changes or runtime wiring.

Final targeted command: the earlier focused test command plus
`tests/integration/test_response_ownership_witness_review.py` and
`tests/unit/infrastructure/test_windows_firewall_com.py`, using a fresh checked-absent
workspace `build/` basetemp and `-p no:cacheprovider`. The initial development run
had three new-test assertion errors (marker length 131 vs actual 133 and incorrect
fake collection attribute); those assertions were corrected. The final expanded
392-case run passed after the source-validity/unavailable/timestamp cases were added.
No accepted tests or production code were weakened.

Quality commands: `python -m ruff check --no-cache src tests tools packaging
pyproject.toml`, configured `python -m mypy --no-incremental --cache-dir=nul`,
`git diff --check`, and explicit scans of tracked and new files. Git reports its
normal LF-to-CRLF notice for the changed tracked Markdown file; no whitespace
errors. The seven-file scan includes the unchanged prior PREPARED test from the
current uncommitted worktree. Ruff and the final tests reported no warnings.

## Native Description round-trip closure — 2026-10-09

The user explicitly authorized **native Description round-trip only**, using the
existing dedicated Windows 11 VMware VM, with inline PowerShell permitted if the
existing Python/pywin32 test runtime was unavailable. No execution-policy change,
`.ps1` execution, Unblock-File, encoded script, security bypass, Defender/Application
Control change, privilege escalation or host-firewall mutation was authorized or
performed. The earlier blocked file-based attempt remains historical; this closes
only its native metadata gate.

### Runtime and preflight

| Measured item | Native result |
|---|---|
| Initial/final VM state | Stopped -> started headless -> normal soft shutdown -> stopped |
| Exact authorized VM/computer | VMware **Windows 11** / **DESKTOP-B18OKSK** |
| Hardware | **VMware, Inc. / VMware20,1**, physical-host guard required |
| Windows | Version **10.0.26200**, build **26200**, UBR **9457** |
| Existing token | Administrator membership enabled; no elevation requested |
| Execution policy | **Restricted** before/after; complete scope-list serialization equal |
| Firewall rule count before Add | **476** |
| Existing witness-test prefix count | **0**, required before mutation |
| Python preference check | No native test interpreter found in checked Local Programs/Desktop/Temp runtime directories or registered PythonCore install paths; only WindowsApps `python.exe` alias found |
| Execution method | **Individual inline PowerShell `-Command` calls**, via existing VMware MCP `guest_run_command` with cmd shell; no `.ps1` file executed |
| Native API | `HNetCfg.FwPolicy2` / `INetFwRules` / `HNetCfg.FWRule` Automation, including all Rule/Rule2/Rule3 getters used by NS-101 |

The installed NetSentinel application directory is not a general test interpreter;
it was not launched or modified. No Python/pywin32 installation was performed.
The fallback does not claim Python adapter/QI acceptance; it proves actual Windows
Automation metadata persistence/readback for the selected witness field. Extended
getters such as EdgeTraversalOptions, LocalAppPackageId, user/machine authorization
lists and SecureFlags were successfully included in complete snapshots.

Two pre-mutation PREPARE attempts stopped on a malformed optional UBR registry
path in the new test command builder (backslashes lost while writing the fixture).
There was no Add and no persisted receipt. The path was corrected, a regression
assertion added, and all snippets passed local PowerShell syntax parsing. The final
prepared operation below used a **new** identity/witness and recorded the actual
UBR. This was a probe-construction error, not a Windows metadata/security failure.

### Exact temporary rule and originating test evidence

The final accepted probe allocated one UUID4 and an independent 32-byte witness
with `System.Security.Cryptography.RandomNumberGenerator` before any OS mutation.
It persisted a **test-only JSON data receipt**, including full expected detached
snapshot and inventory/policy fingerprints, before Add. This receipt is not a
production PREPARED type, strict production codec, privilege grant or manifest.

| Test-only field | Exact accepted value |
|---|---|
| Identity | `b332949e-db1a-4cd6-9479-803c58533717` |
| Native unique Name | `NetSentinel:NS102-metadata-spike:b332949e-db1a-4cd6-9479-803c58533717` |
| Witness (explicitly authorized test evidence) | `08178e8d91364b0f6567b494a45bc3a1d498b6f1c5c593e910bd514319476d53` |
| Description | `NetSentinel response witness v1 b332949e-db1a-4cd6-9479-803c58533717 08178e8d91364b0f6567b494a45bc3a1d498b6f1c5c593e910bd514319476d53` |
| Description length | **133 UTF-16 characters / 133 UTF-8 bytes**, literal ASCII |
| Program | One unique nonexistent guest Temp `NetSentinel-NS102-metadata-fixture-<identity>.exe` path; no file created/executed |
| Scope | One literal **8.8.8.8**, **TCP/443**, **Private profile only**, **OUTBOUND/BLOCK** |
| Enabled | **False** throughout; this is a metadata-only specimen, no active traffic rule |

No remote selector was broadened. Unconstrained local address/port and interface
defaults are the existing NS-100/101 expectation, not an IP-only/global rule. No
socket, DNS, connectivity test, packet capture or executable fixture was launched.
The test-only name is clearly prefixed, with the exact proposed production
Description format carrying its canonical generated UUID and witness. This does
not claim native acceptance for enabled traffic blocking or the production target
guard; those remain the earlier NS-101 scope.

### Native execution and results

Five separately reviewable inline operations are generated by
`tests/fixtures/ns102/inline_metadata_roundtrip.py`. They have exact VM/hardware/
existing-token guards, bounded fresh enumeration (16384 maximum), complete getter
mapping, literal validated JSON receipt path, explicit no-replayed-Add stage checks
and no script/policy-bypass commands. The JSON receipt is read as data with
ConvertFrom-Json, never executed or passed to Invoke-Expression.

| Operation | Actual observed result |
|---|---|
| PREPARE | New identity/witness and complete expected state committed; exact intended identity absent; prefix0; count476 |
| CREATE | One Add attempt; count477; fresh unique1; complete equality true; Disabled preserved |
| Independent READ | New PowerShell process/new policy collection; Name exact; Description ordinal string equality true; UTF-8 byte equality true; exact canonical witness marker true; full equality true |
| Metadata shape | 133 characters/bytes preserved; no observed truncation, normalization, escaping or transformation |
| Existing-name collision guard | Candidate count1 after creation means existing identity would be refused; no second Add issued and no unrelated rule overwritten |
| DRIFT | Only Description appended with ` changed`; fresh state exactly matches this planned edit; all other fields equal |
| Original ownership comparison | Original full snapshot false; original canonical witness Description binding false; external-modified classification; production Remove authority false |
| CLEANUP | Known exact test rule removed under test-only full-state cleanup procedure; independently absent; prefix0; count476; inventory and policy equal |

The drift changed the canonical Description while retaining its original token
substring. The reported false `original_witness_equal` means **exact canonical
witness marker binding** failed, not that the random token bytes themselves were
replaced. This directly verifies Description drift defeats full ownership equality;
the earlier fake cases separately cover wrong/replaced witness values. Only the
native Description was edited; no selector, enabled flag, profile or other policy
was changed.

### Explicit test-only cleanup and inventory proof

The user authorized this harness's cleanup after its deliberate metadata edit.
Cleanup loaded the original test receipt and performed fresh exhaustive enumeration.
It refused duplicates or any full snapshot outside the **original exact state** or
the **explicitly pre-recorded Description-only test edit**. This is not deletion
authorized by UUID/name alone or a production re-adoption policy. It then removed
that exact temporary name, independently enumerated absence and compared the
complete unrelated rule inventory fingerprint. Production REMOVE remains unchanged:
finalized originating manifest, confirmed REMOVE, fresh unique full equality,
exact removal and independently verified absence.

| Cleanup evidence | Actual result |
|---|---|
| Exact removal performed | **YES** |
| Exact absence verified | **PASS** |
| Remaining witness-test prefix rules | **0** |
| Total rule count | **476 -> 477 -> 476** |
| Before/after inventory SHA256 | `807f60caaab00390db626255f5a65be9ca5f5074134a33ad34ccfb9cd180739b` |
| Complete getter inventory equality | **True** (sorted canonical snapshots of all enumerated rules; raw unrelated inventory never exported) |
| Effective policy and all scope settings | **Unchanged**, Restricted |
| Temporary guest receipt | Exact `NS102-native-8c00920d922740eebb3b251dd4370a10.json` deleted; guest file existence **false** verified |
| Guest probe scripts/executables | No file-based script copied/executed; no executable fixture created |
| VM restoration | Normal soft shutdown returned the initially stopped VM to stopped state |

### Native decision and remaining limits

**OS-resident witness metadata = NATIVE PASS. Witness model native decision = GO**
for this exact Description format/build and non-adversarial threat scope. The user
conditionally authorized resuming full NS-102 using PREPARED + witness once this
gate passes; that prerequisite is now satisfied. **NS-102 remains INCOMPLETE** and
full implementation was not resumed in this native-only turn. No production
promotion/recovery, manifest version change or in-product firewall-write permission
is claimed. Future implementation still needs durable custody, versioned final
evidence, honest reconciliation timestamps, bounded audit/idempotency and full
NS-102 failure/restart/expiry acceptance.

This measured short ASCII Description is reliable on **26200.9457** in the actual
Automation calls used here. It is not proof of arbitrary native length/Unicode
behavior, all Windows builds, firewall GUI localization, enabled-rule traffic
effects, trusted requester consent or protected privilege deployment.

The local-admin limitation remains unchanged: a privileged attacker can inspect
and clone the witness/complete state; ordinary metadata is not a cryptographic
origin receipt. The frozen threat model excludes adversarial-admin/tamper-proof
ownership guarantees. [Microsoft Add semantics](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrules-add)
still permit overwriting an existing same-identifier rule. This probe used fresh
high-entropy identity, repeated absence checks and refused pre-existence; it did
not intentionally test overwriting any existing rule. Name is a friendly public
property, not a protected namespace or asserted authenticated internal identifier.
An external insertion/replacement can still race the final read and Add/Remove;
COM has no atomic compare-and-create/delete. The witness does not eliminate that
TOCTOU or authenticate malicious copying. No production REMOVE safeguard changed.

### Native-only final report

| Requested item | Result |
|---|---|
| Execution policy unchanged | **YES**, effective Restricted and scope-list equal |
| Method | **Individual inline PowerShell**, no .ps1 execution |
| Windows build | **26200.9457** |
| Native rule mutation performed | **YES, dedicated VM only**, one disabled metadata specimen |
| Description exact round-trip | **PASS**, ordinal string and UTF-8 byte equality |
| Witness exact round-trip | **PASS**, exact canonical marker |
| Marker length | **133 characters / 133 bytes** |
| Description drift detection | **PASS**, all other fields preserved |
| Collision preflight | Exact identity absent/prefix0 before Add; existing identity would be refused; Add attempts1 |
| Cleanup | **PASS**, exact full-state test-only removal, absence and guest receipt deletion verified |
| Stale rule count | **0** |
| Inventory consistency | **PASS**, 476->476 and identical full-getter fingerprint |
| Relevant targeted tests | **399 passed / 1.92 s**, including seven new inline-command safeguards; no warnings |
| Whitespace/privacy | **PASS**, tracked diff plus nine current changed files, 128 KiB/file bound, secret/control/trailing-whitespace scan and manual privacy review |
| Witness native decision | **GO / NATIVE PASS**, resumes NS-102 gate only |
| NS-102 | **INCOMPLETE** |
| NS-103/104 | **NOT STARTED** |
| Commit/push | **NONE** |
| Tag/release | **NONE** |

Files added in this turn: inline native command builder and seven offline safeguard
tests. This acceptance report updated; the command-contract summary links the new
native closure. All changes remain uncommitted. Existing production/domain/ports/
SQLite/GUI/installer source, schema019 and dependency configuration are unchanged.
No full suite required for this explicit probe/docs/test-only scope.

Final targeted selection: the seven-test inline safeguard module, witness review,
PREPARED-only review, fake COM/firewall adapter, domain ownership and ownership port
modules; a fresh checked-absent ignored workspace `build/` basetemp, pytest cache
disabled. Ruff (`src tests tools packaging pyproject.toml --no-cache`) also passed.
All five individual snippets passed local AST syntax parsing. The first new
safeguard assertion incorrectly matched read-only Get-ExecutionPolicy as the
forbidden parameter; it was corrected to match actual parameter tokens. No accepted
test or production behavior was weakened. The current privacy scan deliberately
permits only the explicitly requested disposable test witness recorded above;
it found no credential/token/private-key patterns, raw unrelated inventory or raw
native errors. Configured mypy's prior 37-source PASS remains historical; no
production source changed in this native-only turn, and no new full-suite/coverage
claim is made.

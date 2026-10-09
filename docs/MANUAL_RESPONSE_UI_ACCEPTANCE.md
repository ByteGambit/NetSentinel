# NS-103 — Manual response UI acceptance

Date: **2026-10-09 (Europe/Istanbul)**. Baseline:
`0a2edf9bdab9fd88f2c57cff4e22eab4a63e55bd` (NS-102).
Initial `git status`: clean; no EOF cleanup remained. The four existing ignored
`ns067-mypy-*` permission-warning directories were untouched.

Status: **NS-103 COMPLETE (offline UI/service acceptance)**. Production privileged
write deployment remains **NO_GO** under the unchanged contract. **NS-104 NOT
STARTED**. No commit/push/tag/release.

## Exact authoritative task

From [TASKS NS-103](TASKS.md#ns-103--manual-response-ui), unchanged:

- **Amaç:** Kullanıcıya firewall etkisini görüp onaylama ve undo akışı vermek.
- **Yapılacaklar:** Target/profile/expiry/rollback preview, explicit confirm/Cancel, permission sonucunu ve audit'i UI'da göster.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/presentation/, src/netsentinel/application/services/, tests/gui/.
- **Bağımlılıklar:** NS-082, NS-102.
- **Acceptance criteria:** Cancel write yapmaz; admin yokken local trust çalışır; undo accessible; partial result açık.
- **Test yöntemi:** Offscreen denied/success/partial/rollback/Cancel.
- **Kapsam dışı:** Automatic blocking veya silent elevated helper.
- **Başlatma kapısı:** Do not start before NS-099 and explicit response GO decision; M17 de tamamlanmış olmalıdır.

The current user instruction explicitly authorizes NS-103 only following accepted
NS-100–102. Frozen contracts take precedence over historical planning proposals.

## Entry, availability and deployment boundary

**Connections → Selected connection → Manual firewall response** is the only
entry. There is no global block control, alert/incident container action, risk
threshold, domain targeting or process termination. Existing Connection, risk,
DNS/context, TI and feedback tabs remain the evidence inspection surfaces.
Alerts/Incidents do not always supply an exact executable/transport/remote-port
source, so no ambiguous response action was added there.

The model retains actual connection-event session/lifecycle IDs and observation
time. Missing executable, endpoint, provenance, unsupported path/public literal
IP/protocol/port, expired/unavailable source or FAILED quality shows an explicit
unavailable reason. Missing measurement quality stays **unknown**: connection
events do not carry collection-round quality. No default profile, DNS resolution,
hash, reputation lookup, endpoint inference or fallback to IP-only is performed.

**The frozen in-product privileged-write trust gate remains NO_GO.** Normal
desktop composition injects only a worker-owned local custody repository into
`ResponseUiService`, with no firewall executor or permissive executable identity
reader. A target review reports `BOUNDARY_UNAVAILABLE` when trusted preview file
identity is unavailable. Retained ownership/audit remains readable. Even a fully
formed preview cannot dispatch without an explicitly injected lifecycle executor;
default confirmation returns typed NOT_ATTEMPTED/BOUNDARY_UNAVAILABLE and writes
no intent/audit. Retained Undo review likewise reports that boundary honestly.
Administrator status alone never unlocks the unresolved deployment gate.

Create/remove success acceptance uses **explicit injected fake infrastructure**,
the unchanged NS-102 coordinator, real temporary SQLite020 and the unchanged
NS-101 strict adapter with fake sessions. This is UI/service preparation, not
approval or a claim that shipped asInvoker UI can mutate the native firewall.
No helper, service, scheduled task, runas, security-policy change or automatic
elevation was introduced. Response failure cannot disable independent local
monitoring, risk/evidence, device trust or mark-normal. The offscreen shell test
verifies connection viewing and successful persisted mark-normal after response
boundary denial.

## Exact review and confirmation

Before dispatch the scrollable plain-text review contains:

- Exact rule name, requested CREATE/REMOVE, full executable and literal IP/family.
- TCP/UDP, one remote port, one explicitly selected Domain/Private/Public profile.
- Outbound direction, block action, unrestricted local address/port and no NIC filter.
- Until manually removed; no expiry; persistence through exit/crash/OS restart.
- Connection source session/lifecycle, original UTC observation, availability and quality.
- Preview UTC/five-minute confirmation deadline; current profile activity/policy
  effectiveness **unknown**, VPN/network applicability caveat.
- DNS/flow/disk attribution limits, retained risk/TI context inspection, shared
  cloud/CDN collateral, all instances/users and future file replacement scope.
- Exact Undo meaning, finalized ownership/equality and administrator requirement.

Profile starts at **Select one profile…**, no implicit ALL or current-profile
assumption. Manual lifetime is the only exposed option. NS-102's explicit due
REMOVE intent does not become an advertised timer or stopped-app cleanup guarantee.

The application service allocates UUID4 before preview, retains its immutable
command and custody privately, and consumes its preview once. Human Confirm binds
the command fingerprint/time; command generation and the frozen inclusive
five-minute preparation deadline are checked before any lifecycle call. A→B→A,
profile/observation/target changes, newer custody revision, risk/TI/DNS/signer
evidence updates and reused previews require a fresh review. Optional context
is not copied into or allowed to broaden the frozen command codec. The adapter
still independently validates current executable metadata before CREATE.

Cancel is the default focused button; Confirm Create and Confirm Undo have
distinct names. Escape and window close reject the review. Cancel/invalidation
before dispatch creates **zero firewall calls, zero response operation, zero
PREPARED/ATTEMPT audit**. Constructing/opening the local repository may initialize
its singleton store identity; that is neither an action intent nor an attempt.
After explicit dispatch, changing/closing the view cannot promise OS cancellation:
the original exact action finishes, its durable outcome remains in local custody,
and stale completion cannot overwrite a newer selected target.

## Results, audit and Undo

Text separates SUCCESS/verified rule readback, DENIED/UNAVAILABLE with typed
reason, FAILURE/NOT_ATTEMPTED, UNKNOWN/PARTIAL and pending reconciliation.
OS_VERIFIED awaiting final DB custody is explicitly partial, never normal success.
Traffic effect/connection termination/restored connectivity are never claimed.
Unknown/partial instructs inspection/reconciliation and warns against blind retry.

Read history replaces one bounded **64-operation** UUID page and one
**100-event** sequence page, with explicit Next controls. Selected operation
shows requested action/time/target, historical receipt, lifecycle/current recorded
reconciliation, and last reconciliation time. Audit shows sequence, UTC, action,
rule ID, event, status, reconciliation and outcome. It is finite/local/not
tamper-proof. Historical success is separate from current recorded state; this
UI read does not perform native reconciliation or dispatch overdue expiry work.
External missing/modified/disabled, ambiguous, pending, expiry-pending and removed
states remain explicit typed text from the existing model.

Witness, Description, ownership payload, file IDs, confirmation fingerprint,
internal tokens and raw exceptions are never rendered/logged/exported. Full
manifest custody stays in the application service/repository. Local path/IP/source
display is user-selected sensitive context, not support export or network upload.

Undo is keyboard reachable only for a finalized CREATE with retained manifest,
VERIFIED lifecycle, last EXACT/PROMOTED reconciliation and no durable removal
tombstone. It is not dependent on current source/file existence or a risk threshold.
A fresh REMOVE preview names the original exact rule/target and requires separate
human confirmation. The service rereads original custody/revision before calling
NS-102 `rollback`; NS-101 then does its own fresh unique complete equality,
exact remove and absence verification. External drift refuses removal; missing,
unfinalized, tombstoned, partial/unknown or unresolved ownership disables Undo.
No delete-anyway, repair, adoption or automatic compensation exists.

## Threading and accessibility

`ResponseCommandCoordinator` owns one worker/service, at most one pending handoff
and one active job; globally serialized work is stricter than per-target exclusion.
Duplicate submit is refused while busy. Widgets disable pending controls and use
queued Qt completion signals. No widget imports COM/SQLite, constructs SQL or
reconstructs manifests. Selection generations and request serials reject stale
results. Dropped queued work has deterministic completion; shutdown stops admission,
invalidates pending work and joins for at most two seconds. An active action may
finish after timeout; it is not labelled cancelled or rolled back.

Names, keyboard mnemonics, explicit tab order, focused default Cancel, safe Esc,
selectable full preview/detail text and color-independent status are tested.
Qt role-name values use the expected QByteArray type, including the new provenance
role; no domain/GUI/infrastructure boundary is relaxed.

## Synthetic layout evidence

Renderer: `python -m tests.fixtures.response_ui_screenshots`, using the same
renderer-only Segoe UI catalog load as NS-098. No live sensors/native API.

- [Exact confirmation](images/ns103-preview-synthetic.png)
- [Owned rule and Undo](images/ns103-owned-synthetic.png)
- [Unknown/partial](images/ns103-partial-synthetic.png)

The 720×620 confirmation shows complete scope/warnings with scroll support and
clear distinct buttons. History/detail/audit have their own readable text areas
inside the existing scrolling detail page. Screens were inspected in this task.
No malware-certainty copy, scary automatic protection claims or color-only result.
This is synthetic/offscreen evidence, not independent native screen-reader/DPI
or human novice acceptance.

## Quality and final boundaries

Changed files:

- Application: `src/netsentinel/application/services/response_ui.py`;
  read-only composition: `src/netsentinel/bootstrap.py`.
- Qt worker/widget: `src/netsentinel/presentation/response_commands.py`,
  `widgets/manual_response.py`.
- Existing Qt integration: `presentation/app.py`, `viewmodels.py`,
  `models/connections.py`, `views/connections.py`, `views/main_window.py`,
  `widgets/connection_details.py`, `widgets/risk_explanation.py`.
- Tests: `tests/integration/test_response_ui.py`,
  `tests/gui/test_manual_response.py`, `tests/fixtures/response_ui.py`,
  `tests/fixtures/response_ui_screenshots.py`.
- Documentation: this report, TASKS/PRODUCT/SECURITY/ROADMAP current summaries;
  three `docs/images/ns103-*-synthetic.png` images.

No existing domain/NS-100 command/NS-101 adapter/NS-102 lifecycle/custody schema
code was changed. No new dependency or migration.

Final quality results:

| Check | Result |
|---|---|
| New NS-103 application/UI integration | **28 passed**, real temporary SQLite + fake infrastructure |
| New GUI/offscreen | **26 passed**: denied/success/failure/unknown/partial, rollback success/denied/partial/drift, Cancel/Esc/close, evidence/selection/profile invalidation, stale deadline, duplicate prevention, heartbeat/thread affinity, queued cancellation, restart read, accessibility, standard-user mark-normal, bounded shutdown |
| Targeted response/application/GUI/regression | **295 passed**,35.30s |
| Full offline | **4692 passed /9 live deselected**,541.21s (9m01s),1 warning |
| Coverage | **91.31%**;28816 statements/2504 missed; unchanged85% gate PASS |
| Ruff | PASS: src/tests/tools/packaging/pyproject.toml |
| Configured mypy | PASS:38 portable files |
| Expanded mypy | PASS:11 changed production files, including Qt integration and bootstrap |
| Whitespace | PASS: git diff check plus all changed/new UTF-8 files |
| Bounded privacy scan | PASS:20 changed/new text files,128KiB/file plus3 synthetic PNGs; zero heuristic findings and manual custody/logging review |

The approved bundled CPython3.12 runtime uses repository src and existing venv
site-packages. Offscreen Qt, deterministic hash seed0 and disabled pytest cache
were used. Each basetemp was a fresh checked-absent ignored workspace build path.
The full suite used the existing outside-sandbox procedure for installer junction
fixtures under the current token; no UAC/elevation or native firewall tests.
The default sandbox temp-directory denial was resolved by workspace basetemp.
Earlier
failing fixture/API-name checks and the interrupted pre-evidence-invalidation
full run are not acceptance passes. No test or coverage threshold was weakened.

Requested final report mapping:

| # | Item | Result |
|---|---|---|
|1| Exact NS-103 TASKS definition | Quoted above; unchanged criteria/scope/dependencies |
|2| Files changed | Listed above;23 files including3 images |
|3| Entry | Selected Connections detail only |
|4| Availability | Exact supported path/public literal IP/TCP-or-UDP/port/source + explicit profile + trusted file preview; default trusted boundary unavailable |
|5| Preview | Exact rule/action/executable/IP/family/protocol/port/profile/outbound/block/lifetime/source/time/quality/warnings/Undo/permission |
|6| Profile/lifetime | Explicit one Domain/Private/Public; until manually removed only |
|7| Confirmation binding | Immutable command fingerprint/generation/deadline; single-use; evidence/selection changes invalidate |
|8| Cancel | Zero firewall write/calls, zero lifecycle intent/ATTEMPT/audit |
|9| Privilege denied | Typed sanitized denied/unavailable; no false ownership; independent local trust works |
|10| Async/threading | Single bounded I/O owner; no widget COM/SQL; duplicate refusal; deterministic queued completion; stale result guard |
|11| Result UX | Verified success/absence separate from denied/failure/unknown/partial/pending and current state |
|12| Audit |64 ownership/100 event page; exact selected scope/time and typed lifecycle; no witness/token/raw exception |
|13| Undo | Persisted FINAL/permitted state/tombstone check; exact confirmed strict NS-102 rollback |
|14| External drift | Fresh full equality refusal; no remove/repair/adoption; clear recorded drift/missing/disabled state |
|15| Accessibility | Keyboard/tab order/names/focus/safe default Cancel/Esc/text status; accessible Undo |
|16| Attribution/collateral | DNS/flow/disk uncertainty; shared/cloud/CDN/all-user/path-replacement and legitimate behavior warning |
|17| Automatic blocking | **NO** |
|18| Elevation helper | **NO** |
|19| Process termination | **NO** |
|20| Real firewall mutation | **NO** |
|21| Targeted tests | **295 PASS** |
|22| GUI/offscreen tests | **26 new PASS**, included in targeted/full |
|23| Integration tests | **28 new PASS**, create/denied/partial/Undo/drift/restart/read |
|24| Full offline suite | **4692 PASS /9 live deselected** |
|25| Coverage | **91.31%;85% gate PASS** |
|26| Ruff | **PASS** |
|27| mypy | **PASS** configured38/expanded11 |
|28| Whitespace | **PASS** |
|29| Privacy scan | **PASS**, bounded20-text/3-image review |
|30| NS-103 | **COMPLETE**, offline UI/service acceptance; production-write deployment still NO_GO |
|31| NS-104 | **NOT STARTED** |
|32| Commit/push | **NONE** |
|33| Tag/release | **NONE** |

**NS-104 NOT STARTED**: no native lifecycle, installer/uninstall cleanup,
upgrade/interrupted-native-action acceptance, package rebuild or distribution.
Schema **020** unchanged; dependencies and asInvoker packaging unchanged.
Automatic blocking **NO**, elevation helper **NO**, process termination **NO**,
real firewall mutation **NO**, commit/push **NONE**, tag/release **NONE**.

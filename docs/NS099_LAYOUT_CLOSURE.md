# NS-099 — focused layout closure

2026-10-07 Europe/Istanbul. NS-099 **INCOMPLETE**, M17 **IN PROGRESS**.
Limited pilot/broad release **NO_GO**, M18 **DEFER**, NS-100 **NOT STARTED**.
VPN **NOT RUN**, meaningful native sleep/resume **NOT RUN**, effective
OS-disabled notification policy **BLOCKED** remain unchanged.

## Scope and behavior

Only Incidents, DNS and History production views change. Domain, queries,
repositories, pagination/lifecycle semantics, other pages, dependencies and
packaging are unchanged. Schema **019→019**, no migration.

- Incidents: font/row/header/scrollbar-derived five-row table minimum; protected
  splitter children; selected detail starts at a 3:2 list/detail balance. Hidden
  risk-tab size hints cannot crush the list. Empty selection retains only the
  status line. Timeline, summary tabs, Load more and Refresh remain accessible.
- DNS: six-row minimum with the same measured chrome allowance; empty details
  collapse to their status. Selection starts with a 3:2 balance. One detail
  scrollbar reaches the form and Questions/Answers; text documents use existing
  natural-height editors without nested vertical scrollbars. Values wrap.
- History: content-sized columns across the bounded 50-row page, pixel horizontal
  scrolling, no stretching/shrinking all columns to fit and no text elision.
  Process/PID/protocol/endpoints/state/timestamps retain their intrinsic widths.
  The shared endpoint-table widget and Connections view are unchanged.

Splitter proportions initialize only on empty→selected transitions; selecting
another row does not discard the user's splitter adjustment. Both tables retain
local row scrolling and horizontal overflow. Minimum heights derive from row/font
and Qt chrome metrics, rather than arbitrary viewport-specific pixel constants.

## Viewport checks

The real MainWindow shell was exercised at 1280×720,1366×768,1920×1080 with
empty, twelve-row and selected-detail states, including long process/IPv6 values,
microsecond timestamps and sixteen DNS answers. Offscreen Windows Segoe UI9pt
font was explicitly loaded for meaningful glyph metrics and removed after each
focused test so unrelated pages retain their test environment.

| Window viewport | Incidents selected full rows | DNS selected full rows | History full rows |
|---|---:|---:|---:|
|1280×720|5|6|8|
|1366×768|7|7|9|
|1920×1080|15|13|10|

These are complete rows from the table viewport; partially visible rows are not
counted. Empty-selection lists receive more space. The probe preserves the actual
requested window dimensions. Exact desktop DPI/scaling matrices are not inferred.

Focused regressions cover minimum rows after extreme splitter adjustment, resize,
pagination/control bounds, timeline/detail reachability, long text, keyboard Down
selection, full History cell widths and scrolling to every timestamp column.
DNS has one selected-detail scroll area; Questions/Answers have no local vertical
scrollbars. Incidents has no added scroll area, History retains its existing page
scroll and table scroll. Existing semantic/pagination/worker tests remain in scope.

## Candidate and native recheck

The prior runtime ae08d7ef1205f5bd4f0b9b0397075c1f6176f2c4 and installer
14934a527e985dc3f32bb94fb3e721ad87d86b3cee1330de12f2b2af36b46538 are historical
after this production change. The committed replacement identity and native receipt are recorded below.

Native probe: [isolated layout entrypoint](../tests/fixtures/beta_layout_probe.py),
using the exact candidate production PYZ in Windows11. It supplies only synthetic
display/query DTOs in an isolated NS099Layout directory, not live monitoring or
production-profile data. Synthetic rows for alternate incident IDs are display
fixtures, not asserted backend incidents. No network generation or new product
insertion hook exists. Its unavailable/inactive backend controls do not constitute
native functional acceptance; real worker/pagination tests validate behavior.

Human recheck is limited to **“Temel kontroller kesilmeden okunabiliyor mu?”**.
The preceding seven UX PASS results are preserved. The original layout FAIL is
historical evidence; the human accepted fresh native images and closed it below.
This PASS comes from the evaluator, rather than automation.

The new candidate/native/quality results below come from the committed rebuild;
no tag/release or NS-100 work is implied.

## Quality before runtime freeze

Targeted133 passed in36.55s (including the prior UI-hotfix contracts updated only
for History's new overflow policy); full offline **3794 passed/8 deselected**,
one Scapy warning, **91.10% coverage**,488.91s. Ruff PASS; configured mypy36 files
PASS; direct mypy three changed views plus native probe (4 files) PASS.
Staged diff check and bounded secret/local-identity scan PASS. Schema019→019.
The initial full run identified obsolete History endpoint-stretch assumptions;
those expectations were replaced with content-width/horizontal-access checks.
Connections checks and production code were preserved. The final full run passed.

## Committed candidate/native result

Runtime layout/source commit `bfe531d960aaabd6b61c1701cf7179f7214c5097`, version0.1.0, unsigned/NotSigned,
installer NetSentinel-0.1.0-Setup.exe, **37,543,802 bytes**, schema019→019.
SHA256 `74529e4cfa03d466ed365a4b0fe5c65c4399873acf150b0c3472496472bdf4c2`. Clean committed rebuild; no tag/release.

Installer transferred through VMware MCP; Limited-token install and all payload
hashes verified. Native test-build PYZ matches the installed candidate production
PYZ byte-for-byte. Raw source/installer/payload hashes and receipts stay ignored.

The VM desktop was locked. Fresh **native guest Qt window captures** are used,
not presented as visible/unlocked desktop screenshots. This evaluates layout,
not physical click delivery or any unrelated acceptance scenario.

| Native window case | Full list rows |
|---|---:|
|incidents-1280-empty (1280×720)|13|
|incidents-1280-rows (1280×720)|13|
|incidents-1280-selected (1280×720)|5|
|dns-1280-empty (1280×720)|10|
|dns-1280-rows (1280×720)|10|
|dns-1280-selected (1280×720)|6|
|history-1280-empty (1280×720)|8|
|history-1280-rows (1280×720)|8|
|history-1280-selected (1280×720)|8|
|incidents-1366-selected (1366×768)|6|
|dns-1366-selected (1366×768)|6|
|history-1366-selected (1366×768)|9|
|history-1280-right (1280×720)|8|
|dns-1280-questions (1280×720)|6|
|dns-1280-answers (1280×720)|6|

Native Windows measurements: 96 logical DPI/1.0 device ratio, 1668×878 screen.
At 1280×720 selected lists show Incidents5/DNS6/History8 full rows; at
1366×768 they show6/6/9. Native1920×1080 physical fit is NOT RUN (screen limit);
1920 offscreen checks passed. Resize preserves the existing selected splitter
position, so native1366 counts differ slightly from freshly initialized offscreen
cases. Fifteen native cases include empty/rows/selection, History rightward
overflow and DNS Questions/Answers scrolling.

Human focused recheck received: **PASS**. Original layout finding closed;
seven other PASS observations preserved, overall **8 PASS / 0 FAIL**.
No VPN/sleep/policy gate waiver.

Native cleanup: probe process0; all three temporary layout/install/wake tasks
removed; newly installed candidate preserved. No credential requested or created.
The installer source is the runtime commit above; this later evidence commit
changes only documentation and the isolated probe entrypoint to use modules
already present in the candidate production PYZ. Runtime/packaging remain equal
to the installer source. No additional production build is implied by that
standalone test-harness adjustment.

Final Ruff and direct mypy4 files were repeated after that probe-only adjustment,
both PASS; the adapted fixture also repeated all27 offscreen cases successfully.
The full suite preceded runtime freeze; production/tests under pytest did not
change afterward, so that3794-case result remains applicable.

## Human layout recheck PASS

2026-10-07 Europe/Istanbul. Evaluator response to the single focused question,
using fresh Windows11 native test-build captures:

> Temel kontroller kesilmeden okunabiliyor mu? PASS — Yeni yerleşimde Incidents ve DNS listeleri yeterli görünür alan kazanmış. History sütunları okunabilir ve gerektiğinde yatay kaydırmayla erişilebilir. Önceki yerleşim bulgusu giderildi; pilotu engelleyen bir layout sorunu görmüyorum.

Incidents/DNS list space and History column readability/horizontal access are
accepted. Only the original essential-controls/layout finding is closed;
the earlier seven human PASS observations remain unchanged. Overall Human UX
**PASS (8 PASS / 0 FAIL)**. This does not assert other Windows/DPI coverage.

| Remaining gate / decision | Current result |
|---|---|
| Human UX | PASS |
| VPN | NOT RUN |
| Meaningful native sleep/resume | NOT RUN |
| Effective OS-disabled notification policy | BLOCKED |
| NS-099 | INCOMPLETE |
| M17 | IN PROGRESS |
| Limited pilot / broad release | NO_GO / NO_GO |
| M18 / NS-100 | DEFER / NOT STARTED |

This follow-up changes documentation only. Runtime/source, installer hash,
size, signing state and schema stay unchanged. No rebuild/native retest or
test rerun is needed for recording the evaluator response. Diff and bounded
privacy/secret checks are repeated before the normal documentation push.

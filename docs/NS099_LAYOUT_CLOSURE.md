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
after this production change. New installer identity must be recorded only after
the layout fix is committed and rebuilt from a clean committed HEAD.

Native probe: [isolated layout entrypoint](../tests/fixtures/beta_layout_probe.py),
using the exact candidate production PYZ in Windows11. It supplies only synthetic
display/query DTOs in an isolated NS099Layout directory, not live monitoring or
production-profile data. Synthetic rows for alternate incident IDs are display
fixtures, not asserted backend incidents. No network generation or new product
insertion hook exists. Its unavailable/inactive backend controls do not constitute
native functional acceptance; real worker/pagination tests validate behavior.

Human recheck is limited to **“Temel kontroller kesilmeden okunabiliyor mu?”**.
The preceding seven UX PASS results are preserved. The original layout FAIL is
historical evidence; it remains unresolved until the human evaluates fresh native
images. Automation alone does not promote human UX to PASS.

Current new candidate/native/quality results are recorded in this section after
the committed rebuild; no tag/release or NS-100 work is implied.

## Quality before runtime freeze

Targeted133 passed in36.55s (including the prior UI-hotfix contracts updated only
for History's new overflow policy); full offline **3794 passed/8 deselected**,
one Scapy warning, **91.10% coverage**,488.91s. Ruff PASS; configured mypy36 files
PASS; direct mypy three changed views plus native probe (4 files) PASS.
Staged diff check and bounded secret/local-identity scan PASS. Schema019→019.
The initial full run identified obsolete History endpoint-stretch assumptions;
those expectations were replaced with content-width/horizontal-access checks.
Connections checks and production code were preserved. The final full run passed.

# Monitoring UI hotfix acceptance — 2026-10-05

This is unnumbered maintenance after NS-093, not a roadmap task. NS-094 was not
started. TASKS.md, ROADMAP.md and M17 state remain unchanged. SQLite stays **019 →
019**; no migrations, domain, persistence, detectors, capture/DNS behavior, tray
lifecycle, notifications or Active Connections metric semantics changed.

## Starting Git state

`git branch --show-current`, `git status`, `git log -1 --oneline` returned main,
clean working tree, and `c618999 feat: add tray application lifecycle`. Main was
already one commit ahead of origin/main. The authorized push therefore publishes
that existing NS-093 commit as well as this UI hotfix; the hotfix commit contains
only the files listed below.

## Connections and History

Before: vertical splitters allocated space to tables and detail panels; metadata,
destination evidence and baseline content had separate small scrolling viewports.

After: each page has one outer MonitoringPageScroll containing its headings,
filters, table, pagination (History) and naturally sized detail. The table's own
row scrolling and horizontal scrolling remain available. Wheel over native
detail content scrolls the outer page. Bottom DNS/context/signature and baseline
reset/feedback controls are reachable. No nested QScrollArea remains in either
detail tree. Connection/Behavior baseline/Risk explanation/External reputation
tabs are preserved and size to their active content; wrapped async baseline and
full risk/reputation text participates in page height. Shared risk widgets in
Alerts and Incidents retain their existing layout through an opt-in page_flow
mode. Keyboard/filter/selection regressions passed.

Table height derives from the viewport, font and row/header/scrollbar metrics:
6–10 rows, with outer page scrolling when the content does not fit. Automated
tests verified these rows at 1280×720, 1366×768, 1600×900 and 1920×1080. Native
default window inspection also showed several rows without detail compression.

Both headers use ResizeToContents for PID, protocol, state and duration; History
timestamps also use ResizeToContents, preserving complete microseconds/offsets.
Process uses Interactive with an initial font-relative width. Local and Remote
remain Interactive with a font-relative IPv4-plus-port minimum and share spare
viewport width on resize. Narrow History windows use horizontal scrolling for
later date columns; Remote IP stays visible at the tested widths. Long IPv6 and
manually widened columns can use the table's horizontal scrollbar. No page-wide
horizontal scrollbar was introduced.

## Process-created presentation

The psutil adapter can supply Unix zero as an aware UTC datetime; SQLite preserves
the value. A shared presentation formatter now renders absent, naive/invalid,
unrepresentable, or UTC Unix epoch-and-earlier creation values as Not available.
This includes zero epoch and old OS sentinels such as 1601. Comparison occurs
before local timezone conversion, so epoch rendered as 1970-01-01 03:00 +0300 is
also unavailable. It applies to every PID, both process and parent creation,
and the History display mapper. Valid timestamps retain the existing local-time
format, microseconds and UTC offset. Missing access-denied/not-found reasons and
unverified/absent parent explanations remain explicit. Parent observation times
are unaffected. No identity or persisted timestamp is mutated.

Native History selection of an actual System Idle Process / PID 0 record showed
**Process created: Not available**. Its observed parent was absent and rendered
No parent reported. Parent epoch equivalence was also tested with fixtures.

## Theme and visual regressions

Root cause: system dark palette foregrounds mixed with fixed white/light card
backgrounds and fixed dark navy headings. There was no shared application theme
helper for these elements. The new shared styles use native Qt palette roles:
alternate-base card backgrounds, window-text foregrounds/headings and mid borders.
Styles are scoped to named Dashboard cards; they do not restyle the light sidebar.

Broadcast/ARP captions, values, quality, thresholds and capture/stale text were
readable in native dark mode. VLAN scope, observations, empty state and visibility
limitations were readable. Dashboard health and metric cards use the same paired
roles. Status wording remains explicit. Connections, History, Devices, DNS,
Alerts and Incidents headings now use shared palette foregrounds. The light
branding/navigation section stayed intact. Dark/light offscreen checks require
at least 4.5:1 text contrast for card labels and headings and validate VLAN editor
text/base roles. Devices opened with existing saved data and capture controls;
DNS, Alerts and Incidents retained readable, honest empty states without fake data.

## Automated validation

27 new parametrized hotfix cases in tests/gui/test_ui_hotfix.py cover four sizes,
row height, page/detail scroll structure, wheel handling, reachable controls,
selection updates, active and async tabs, endpoint width growth, larger fonts,
process/parent sentinels, valid timestamp precision, native dark/light roles,
sidebar isolation and navigation through all pages.

Initial targeted regression: 141 passed (10.65 s). New-only hotfix: 27 passed
(5.67 s). Final targeted command:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/gui/test_ui_hotfix.py tests/gui/test_connections_view.py tests/gui/test_connection_history.py tests/gui/test_process_context.py tests/gui/test_dashboard.py tests/gui/test_broadcast_dashboard.py tests/gui/test_vlan_dashboard.py tests/gui/test_baseline_detail.py tests/gui/test_risk_explanation.py tests/gui/test_threat_intel_evidence.py tests/gui/test_accessibility.py tests/gui/test_devices_view.py tests/gui/test_dns_view.py tests/gui/test_alerts_view.py tests/gui/test_incident_timeline.py
```

**309 passed in 38.85 s**. Includes the existing independent 2× DPI smoke.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/presentation/widgets/page_flow.py src/netsentinel/presentation/theme.py src/netsentinel/presentation/process_context.py src/netsentinel/presentation/models/history.py src/netsentinel/presentation/views/connections.py src/netsentinel/presentation/views/history.py src/netsentinel/presentation/views/dashboard.py src/netsentinel/presentation/views/devices.py src/netsentinel/presentation/views/dns.py src/netsentinel/presentation/views/alerts.py src/netsentinel/presentation/views/incidents.py src/netsentinel/presentation/widgets/connection_details.py src/netsentinel/presentation/widgets/baseline_detail.py src/netsentinel/presentation/widgets/risk_explanation.py src/netsentinel/presentation/widgets/threat_intel_lookup.py
git diff --check
```

Full offline suite: **3428 passed, 8 deselected in 288.22 s**. Ruff: all checks
passed. Configured mypy: no issues in 34 source files. Direct mypy: no issues in
all 15 changed production modules. Qt ownership type narrowing in touched views
also makes their existing optional-return stubs pass direct mypy. Diff whitespace
check passed. TASKS/ROADMAP and schema diff are empty.

## Native visual smoke

Launched `.\.venv\Scripts\python.exe -m netsentinel --gui` in the native Windows
desktop and inspected real local monitoring/history. The sandbox launch exposed
only first-run onboarding on its isolated desktop; native launch used the existing
user configuration. Windows Computer Use supplied screenshots and wheel/click
input. Native dark Dashboard, Connections, History (actual PID 0), Devices, DNS,
Alerts and Incidents passed visual checks. Connections and History wheel over
detail scrolled the outer page and reached the bottom. Baseline text, reset and
feedback controls were reached without nested detail scrolling. Capture stayed
off and no reputation/signature/reset/feedback action was invoked. Live engine
degraded/error status was displayed as reported by the existing monitoring engine;
this hotfix does not change its telemetry or health behavior.

The four requested viewport sizes were verified offscreen; native visual smoke
used the application's default window size on the user's desktop. These are
separate checks, not a claim of native coverage for every size.

## Changed files

Production (15), all under src/netsentinel/presentation:

- theme.py (new) and widgets/page_flow.py (new)
- process_context.py and models/history.py
- views/connections.py, history.py, dashboard.py, devices.py, dns.py, alerts.py,
  incidents.py
- widgets/connection_details.py, baseline_detail.py, risk_explanation.py,
  threat_intel_lookup.py

Tests: tests/gui/test_ui_hotfix.py (new). Documentation: this acceptance report.
Commit, push result and final working-tree state are recorded in the delivery
response after validation; no numbered task or milestone completion is added.

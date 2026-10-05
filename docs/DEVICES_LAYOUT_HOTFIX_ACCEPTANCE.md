# Devices layout hotfix acceptance — 2026-10-05

Unnumbered maintenance after NS-093. Starting state: clean main at f68048a,
matching origin/main. NS-094 was not started. TASKS.md, ROADMAP.md, M17 state,
domain/application/infrastructure code and SQLite schema remain unchanged:
**019 → 019**, with no migration.

## Layout and sizing

The vertical QSplitter shared the remaining page height between the devices
table, Selected device and User-saved profile. The panels' minimum sizes could
leave only two or three visible table rows, independently of device count.

Devices now reuses the existing MonitoringPageScroll from Connections/History:
headings, filters/actions, status, table, selected-device details and saved
profile form one outer page flow. The shared helper is unchanged. Its table
height is recalculated on resize using row height max(28, font height + 10),
35% of the outer viewport height, and header/frame/scrollbar metrics. The row
target is clamped to 6–10; it is not a constant 500px allocation and does not
depend on the number of observations.

The splitter was removed. Detail and profile panels use horizontal Expanding
and vertical Maximum policies so their natural content height does not absorb
spare space. A final layout stretch takes spare space after the panels.
Interface and binding text wrap; longer detail/profile text grows the page
without squeezing the table. There are no nested detail/profile QScrollAreas.
Small windows scroll the whole page vertically to reach profile buttons.
The table retains its own row and horizontal scrolling, using ScrollPerPixel.

MAC, Last observed IPv4, First seen and Last seen use ResizeToContents. The last
Network / interface column uses Interactive plus stretchLastSection and an
initial font-relative readable width. It takes spare width and preserves table
horizontal access when columns do not fit. Outer horizontal scrolling stays off.

Empty and one-device lists retain the same usable table allocation as many-device
lists. Capture OFF still shows saved observations with unchanged wording;
synthetic Capture ON snapshots use the same layout. No automatic capture start,
discovery, ARP, profile/trust semantics or alert behavior was changed.

## Verification

Added tests/gui/test_devices_layout_hotfix.py: 31 cases covering 0, 1 and 32
devices in both capture states at 1280×720, 1366×768, 1600×900 and 1920×1080;
6–10-row capacity; selection and last-row scrolling; outer scrolling and button
reachability; absence of nested detail scroll areas; long binding/interface/note
content; column growth and horizontal access; larger fonts; keyboard selection;
fixture-backed profile creation, reload and related-alert navigation. Existing
Devices/profile/UI/accessibility tests remain unchanged.

- Targeted Devices/layout/profile/UI-hotfix/accessibility: **95 passed in 16.85s**.
- Full pytest: **3459 passed, 8 deselected in 309.13s**.
- Ruff src tests: passed.
- Configured mypy: passed, 34 source files.
- Direct mypy for presentation/views/devices.py: passed, 1 source file.
- git diff --check: passed.

Native Windows smoke used .venv/Scripts/python.exe -m netsentinel --gui.
With three actual saved observations and Capture OFF, the normal window retained
approximately eight row slots; the maximized window retained approximately nine.
Columns and selected-device values were readable. Wheel input over details
scrolled the whole page to the profile buttons. Create profile opened its editor;
it was cancelled without saving, and Reload profile retained the selected device.
The wider window gave Network / interface spare width. Capture was not started
and no native profile/trust data was saved. Profile save and related-alert behavior
were exercised only against the test fixture repository. The smoke app was quit
through File → Quit NetSentinel.

The hotfix changes only Devices presentation, its new regression test file and
this acceptance note. Commit/push evidence is reported in the final response.

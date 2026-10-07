# NS-099 — notification policy closure

2026-10-07 Europe/Istanbul. Scope: notification policy only. Human UX remains
PASS (8/8), layout finding CLOSED. VPN and meaningful native sleep remain NOT RUN.
NS-099 INCOMPLETE, M17 IN PROGRESS, pilot/broad NO_GO, M18 DEFER; no NS-100,
tag or release. Native policy gate remains BLOCKED until the new candidate is
installed and the affected native scenario has actually been measured.

## Previous BLOCKED root cause

The earlier test changed a desktop-user ToastEnabled registry value while a
secondary-logon fixture submitted from another user context. A popup still
appeared; the setting did not establish effective notification suppression for
that fixture. The original absence was restored. That experiment is historical
evidence, rather than OS-disabled acceptance or an application failure.

The current preflight independently found that an MCP command ran in Session0,
while the desktop and Limited-token helper ran in Session1. Their native shell
notification states differed. The desktop initially returned QUNS_NOT_PRESENT;
after the operator unlocked it, the same Limited helper returned
QUNS_ACCEPTS_NOTIFICATIONS. All actual UI/policy/notification tests must share the
interactive user's context. No password/secret was requested.

## Windows/Qt boundary

The installed Qt/PyQt version is6.11.0. Its Windows showMessage implementation
uses Shell_NotifyIcon with NIF_INFO, without returning that call's result to
Python. supportsMessages checks legacy balloon support, rather than exposing
per-app/global toast permission or visible delivery. [Qt6.11 Windows source](https://github.com/qt/qtbase/blob/6.11/src/plugins/platforms/windows/qwindowssystemtrayicon.cpp).
Qt documents that system/user settings can prevent a message from appearing.
[QSystemTrayIcon documentation](https://doc.qt.io/qt-6/qsystemtrayicon.html#showMessage).

ToastNotifier.Setting describes a registered WinRT toast notifier. It is not
assumed to describe an unregistered Qt legacy sender; Qt's generated shell app
identity is not scraped or guessed. [Microsoft explanation](https://devblogs.microsoft.com/oldnewthing/20200810-00/?p=104058/).

The new read-only Windows adapter uses SHQueryUserNotificationState for native
session restrictions, including locked/not-present, busy, presentation/fullscreen,
quiet-time and Store-app states. It does not claim comprehensive Do Not Disturb,
global or per-app permission coverage. Even ACCEPTS_NOTIFICATIONS maps to
DELIVERY_UNKNOWN. Missing APIs, errors or future enum values also map to UNKNOWN.
[Microsoft API](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shqueryusernotificationstate),
[native states](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ne-shellapi-query_user_notification_state).

One positive configured restriction is read: the exact HKCU REG_DWORD
TaskbarNoNotification=1 under Software/Microsoft/Windows/CurrentVersion/Policies/Explorer.
This is the documented Taskbar.admx user-policy mapping, rather than speculative
registry scraping. Absence/0 does not prove permission. Wrong type, unsupported
value or access failure yields UNKNOWN. Production never writes the registry.
The UI says the balloon policy is **configured off**, rather than claiming
independently verified OS enforcement. The documented CSP edition matrix does
not include Home; effective Home enforcement must be measured separately.
[Microsoft policy and mapping](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-taskbar#taskbarnonotification).

## Policy and submission model

| State | Meaning |
|---|---|
| DISABLED_BY_APP | NetSentinel preference OFF; optional feature, not application failure |
| DISABLED_BY_OS | Documented balloon user policy positively configured off; no submission |
| SESSION_RESTRICTED | Native shell currently advises against notifications; no submission |
| UNAVAILABLE | Qt tray/message platform unavailable; no submission |
| DELIVERY_UNKNOWN | Permission or display unverified; a future intent may be submitted |
| FAILED | Status/submission failure, reported separately from disabled/unknown |

Diagnostics separately count committed intents seen, those passing the frozen
local delivery rules, adapter attempts, accepted adapter submissions, OS/session
skips, duplicates/cooldown and navigation. Qt showMessage attempts are separately
measurable at the native adapter. Accepted submission increments delivery_unknown;
visible_delivery_confirmed remains null/UNKNOWN because Qt supplies no display
confirmation. Actual native screenshots/observations belong to acceptance
evidence, not an invented runtime delivery counter. Clicks and exact alert
navigation are separate counters; neither changes the persisted alert.

Malformed adapter results and exceptions become sanitized failure outcomes.
Policy skips do not advance the accepted-submission cooldown/high watermark.
Attempt identities remain consumed to prevent tight retries. A known restriction
discards the pending queue; re-enable does not replay it. Only a genuinely future
eligible alert can be submitted. Frozen dedup/cooldown120s, hysteresis/escalation,
queue32/session512 bounds, privacy preview and default OFF remain unchanged.

Settings show current optional-off, configured restriction, session restriction,
unavailable, failure or unknown state. Diagnostics explicitly label submissions
as display-unconfirmed and show the last adapter result. No monitoring, detector,
alert repository or persistence logic changes. Schema019→019, no migration,
dependency, driver, network, notification-listener permission or new backend.

## Regression and candidate freeze

Focused tests exercise default/app OFF, positive OS policy, native session
restriction, unavailable, failure/invalid result, unknown, re-enable/backlog,
dedup/cooldown/escalation, restart replay0, exact click navigation, unchanged
persisted alerts and unchanged monitoring lifecycle. Native fixture data is
isolated and synthetic, uses the production PYZ, and records its supplied
candidate identity rather than a hard-coded historical source.

Final targeted123 PASS (23.48s); full offline3833 PASS /8 deselected /1 warning
(734.10s),91.09% coverage. Ruff PASS, configured mypy36 PASS, direct mypy6 PASS.
Final diff/privacy checks and committed rebuild identity are recorded after the
runtime freeze. The isolated native fixture also exposes Diagnostics/Settings
for screenshots; its onboarding is explicitly completed for this policy-only
exercise and notification defaults remain OFF.

## Native scenario plan and status

Windows11 Home x64 build26200 VM, existing desktop user, Limited-token Session1.
Actual Settings UI was opened through MCP; UI Automation read the global
Notifications toggle ON and Do Not Disturb OFF. The prior shell-generated fixture
sender was also listed ON. No raw user names or app identity numbers are committed.
No effective disabled result is inferred from these enabled observations.

After the committed runtime build: verify all installed payload hashes; run the
isolated exact-PYZ fixture with default OFF, enable/new eligible alert, actual
OS notification toggle OFF, duplicate/restart checks, restore original OS setting,
then a new alert/click. Measure policy state, submissions and actual desktop
visibility independently. If the backend cannot observe a confirmed disabled
setting, report UNKNOWN honestly. Native gate PASS requires an actual disabled
scenario and honest application behavior; otherwise BLOCKED/NOT RUN remains.

# NS-099 — notification policy closure

2026-10-07 Europe/Istanbul. Scope: notification policy only. Human UX remains
PASS (8/8), layout finding CLOSED. VPN and meaningful native sleep remain NOT RUN.
NS-099 INCOMPLETE, M17 IN PROGRESS, pilot/broad NO_GO, M18 DEFER; no NS-100,
tag or release. **Notification-policy gate PASS**: the newly installed candidate
was tested against the actual Windows global Notifications control in the same
interactive context, with honest UNKNOWN reporting and native screen evidence.
This closes only the policy gate; it does not waive the remaining TASKS criteria.

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

PyQt and its compile-time Qt version are6.11.0; the bundled Qt runtime is6.11.2.
The Windows showMessage implementation
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

Runtime freeze targeted123 PASS (23.48s); full offline3833 PASS /8 deselected /1 warning
(734.10s),91.09% coverage. Ruff PASS, configured mypy36 PASS, direct mypy6 PASS.
Final diff/privacy checks and committed rebuild identity are recorded after the
runtime freeze. The isolated native fixture also exposes Diagnostics/Settings
for screenshots; its onboarding is explicitly completed for this policy-only
exercise and notification defaults remain OFF.

## Native setup

Windows11 Home x64 build26200 VM, existing desktop user, Limited-token Session1.
Actual Settings UI was opened through MCP; UI Automation read the global
Notifications toggle ON and Do Not Disturb OFF. The prior shell-generated fixture
sender was also listed ON. No raw user names or app identity numbers are committed.
No effective disabled result is inferred from these enabled observations.

The installer was rebuilt from clean main==origin/main after runtime commit
`8242868ba79c63ad743c005366ea715b238cf5d0` and normal push. Version0.1.0,
NetSentinel-0.1.0-Setup.exe,37,559,481 bytes, SHA256
`39b14fe844c8aaa150a8b09229e0d63aaaf5ecc98b5bc8c54b419140be7749d9`.
UNSIGNED/NotSigned; unchanged AppId{62E3BFC6-ACAD-4FC3-94D8-46927D015096},
schema019. Limited-token install exit0,35.763s,1119 payload hashes checked,
0 mismatches. Installed EXE SHA256
`bfa73e87509d6b2762336a9f0cff87026f31271580a188fa10e81005320a89d4`.
194 compiled application modules matched source. Fixture and production PYZ
were byte-identical: SHA256
`fca552e60dfc82fb13ae7cf36196701511a246d6cacc4714acc83965d1f2b8a9`.
The74529e4c layout installer is historical; it was preserved before overwrite.

## Native measurements — PASS

Windows11 Home/Core26200.9457, existing desktop account with a Limited token,
Session1. This is not a newly created Users-only account or pristine OS claim.
VMware MCP copied/installed/verified the candidate and executed the test helpers.
The isolated fixture invokes production AlertService and notification/UI code;
its engine is inert, rather than a new live benign-network workload.

The exact native Settings control was
`SystemSettings_Notifications_ShowAppNotifications_ToggleSwitch`.
UI Automation verified ON→OFF and OFF→ON in Session1. No credential was requested
or created; no registry policy flag, unrelated security control, random VPN or
notification backend was added. Do Not Disturb remained OFF. Original global ON
was restored in a finally block after each test. The final transition was OFF→ON
at2026-10-07T08:38:43.5806087Z.

| Measurement | Actual result |
|---|---|
| Default OFF |1 persisted synthetic alert,0 eligible submissions/adapter attempts; DISABLED_BY_APP |
| Explicit enable, OS ON |1 adapter/showMessage call; real generic low-severity popup observed; DELIVERY_UNKNOWN/visible confirmation null |
| Actual OS OFF, first case |1 new persisted alert,1 adapter/showMessage call; accepted submission, UNKNOWN; no visible popup in the recorded desktop observation |
| First duplicates |3 suppressed; no additional adapter/showMessage call |
| Restart while OS OFF |3 alerts persisted,0 new intents/attempts/submissions/replay |
| Re-enabled, final live case |New future alert,1 adapter/showMessage call; native popup captured at4.5s, then physical click |
| Native click |1 click,1 successful navigation,0 navigation failures; selected UUID exactly matched the newly generated target UUID |
| Actual OS OFF, final live case |New future alert,1 accepted adapter/showMessage call; UNKNOWN/null visibility; no popup at0/1.5/3/4.5/6s in native desktop samples |
| Final duplicates |3 suppressed,0 additional calls; local alerts7, fixture engine still RUNNING |
| Final restart after OS restore |Fresh PID/time report;7 alerts persisted,0 generated/eligible/attempted/submitted/replay; preference ON, UNKNOWN |
| Cleanup |Fixture processes0, owned tasks0, credentials created0; installed candidate and evidence/data preserved |

The final live process independently measured5 intents (2 new alerts+3 duplicate
intents),2 eligible adapter/showMessage calls,2 accepted submissions,
delivery_unknown2, duplicate_skipped3, clicks1/navigation_success1. One of those
two calls produced the observed ON popup; the OFF call produced none in the
sampled six-second window. Runtime visible_delivery_confirmed remained null in
both cases. A native observation never becomes a fictitious Qt delivery counter.

Across all live fixture processes:7 unique synthetic alerts,13 eligible-marked
intents including6 duplicates,6 adapter/showMessage calls and accepted submissions,
6 duplicates suppressed,2 directly observed ON popups,2 observed OFF cases with
no popup,1 confirmed click, restart replay0. Two earlier exploratory ON calls
were not captured at the right time; their visibility is **NOT MEASURED**, not
counted as delivered or failed. Eligible-for-delivery after local rules was6;
the default-OFF intent and duplicates were excluded. No sink failure/unavailable
or detected OS-policy skip was recorded: this global toggle is not observable by
the chosen runtime API, so production correctly remained UNKNOWN.

### Observation limitations and corrected harness checks

UI Automation did not expose the native popup's title in its text tree. Its
zero-match samples are not used as proof of hidden delivery. A short-lived popup
also defeated the initial window lookup. The final observer therefore captured
actual Session1 desktop frames through native screen-copy calls executed via
MCP, before a real mouse click; MCP also captured static screens. This avoids
inferring delivery from adapter return values or a missed automation selector.
No edited/generated images are used as evidence. The observed VM viewport was
1001×484; overlapping Settings obscured part of the notification dialog screenshot.
Readable state wording is additionally covered by composed GUI tests.

Some exploratory restart commands reached an already stopped fixture and left a
pending control file. Those attempts are excluded from acceptance. The harness
now reports PID/time and supports genuinely future synthetic identities. Its own
pending command was archived/cleared before restart; liveness and a fresh startup
report were verified. The final restart was also checked against a fresh PID,
zero new intents and unchanged persisted count. This is a test-harness repair,
with no further production or installer change. The late fixture additions are
validated by native execution, Ruff/direct mypy and the final targeted run;
the full offline run covers the frozen production fix and regression tests.

Policy PASS follows the user's native acceptance rule: the actual OS-disabled
condition was programmatically verified, and NetSentinel reported submission and
unknown visibility honestly. This does not claim comprehensive per-app/DND
permission detection or universal suppression timing. Positive documented balloon
policy/session restriction, unavailable and failure paths are additionally fake/API
tested; Home enforcement of an injected Taskbar policy is not claimed.

Raw installer, receipts, native frames and test logs remain local under ignored
build/ns099-policy-*; only sanitized evidence/metadata are committed.

## Current exit decisions

| Gate | Result |
|---|---|
| Notification policy / current native popup/privacy/click/duplicates/restart | PASS, scope and limits above |
| Human UX | PASS8/8 on recorded layout/evaluator scope; layout CLOSED; no new human score invented |
| Safe native VPN | NOT RUN, unchanged; no safe environment |
| Meaningful native sleep/resume | NOT RUN, unchanged; VMware suspend is not accepted |
| Benign/FP | Historical42min observation: alerts0/incidents0; not repeated on the policy candidate; synthetic alerts are not benign FP evidence |
| Tray context Quit | Historical scoped PASS; not unnecessarily repeated |
| NS-099 / M17 | INCOMPLETE / IN PROGRESS; exact TASKS criteria unchanged |
| Limited unsigned pilot / broad public release | NO_GO / NO_GO; broad still subject to NS-097 |
| M18 / NS-100 / publication | DEFER / NOT STARTED / tag-release NONE |

Final post-native targeted123 PASS (21.69s), Ruff PASS, configured mypy36 PASS, direct mypy6 PASS, diff check PASS, bounded privacy/secret scan26 files/0 findings/schema19. Full offline3833/8/91.09% applies to the frozen production fix; subsequent changes are native fixture instrumentation and sanitized evidence only.

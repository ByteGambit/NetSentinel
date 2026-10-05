# NS-094 — Desktop notifications

## Frozen policy v1 (2026-10-05)

Before implementation: default **disabled**, LIMITED preview only. Cooldown is
120 seconds per alert, using an injected monotonic clock. Persistence commits
before a process-local intent is published. No startup scan or backlog replay.
SQLite 019 already deduplicates unchanged occurrences/revisions across restart;
`last_notified_at` is an eligibility watermark, never submission/display proof.
No durable delivery ledger or migration is necessary for this no-replay model.

| State / transition | Decision |
|---|---|
| New eligible OPEN | Submit |
| Identical persisted occurrence / revision | Duplicate skip, even after cooldown |
| New same-severity occurrence within 120 s | Cooldown skip |
| New same-severity occurrence after 120 s | Submit |
| LOW → MEDIUM, LOW → HIGH, MEDIUM → HIGH | Submit, bypass cooldown |
| Decrease | Skip; retain highest submitted severity until genuine reopen |
| Score/confidence-only reassessment | Skip |
| ACKNOWLEDGED / RESOLVED | Skip; cancel pending intent |
| RESOLVED → OPEN via persisted new occurrence | New lifecycle, submit |
| Suppressed / ineligible | Skip |
| Disabled / quitting | Reject; clear pending queue |
| Sink unavailable / failed / exception | Typed failure; no successful submission state |
| Historical record read at startup | No intent, zero submissions |

INFO observations are skipped. LOW/MEDIUM/HIGH use the existing RiskSeverity
enum; numeric risk/provider scores are never popup inputs. Failed identities are
remembered separately to prevent tight retries; only a genuinely newer intent
can try again. No retry scheduler. State capacity exhaustion is a typed policy
skip, never a security verdict.

## Contracts and delivery

`PersistedNotificationIntent` is a validated portable event derived from a
committed alert. Legacy AlertService producers (DNS configuration and passive
inventory) use the same engine dispatcher. RiskToAlertService publishes after
assessment and alert persistence plus NS-081 suppression/eligibility evaluation.
The old NS-079 AlertNotificationIntent remains an eligibility event, never proof.
No detector calls a sink. Alert ACK/RESOLVE commands cancel pending delivery;
incident lifecycle remains independent. Suppression leaves existing evidence,
assessment and alert history intact.

`DesktopNotificationRequest`, `DesktopNotificationSink`, immutable
`NotificationDeliveryPolicy` and `NotificationDeliveryService` contain no Qt or
platform dependency. Typed outcomes: POLICY_SKIPPED, QUEUED, QUEUE_COALESCED,
QUEUE_FULL, SUBMITTED_TO_SINK, SINK_UNAVAILABLE, SINK_FAILED. SUBMITTED means only
that the adapter accepted a request. It does not prove OS display or that a person
saw it. Sink failure/exception does not advance the submitted clock/high watermark.
Identical failed attempts are not retried; a future eligible intent may try again.

Stable identity: alert UUID + policy v1 + original observation watermark +
occurrence count + severity. Score, provider details, confidence and random
notification UUIDs are excluded. Older intents cannot rewind runtime state.
New same-severity occurrences may notify after cooldown; unchanged intent cannot.
Highest submitted severity prevents HIGH→MEDIUM→HIGH reassessment oscillations.
Genuine persisted reopen starts a new lifecycle and resets cooldown/hysteresis.

## Restart and settings

Production starts with no subscriptions replaying stored data and no historical
notification scan. Repository occurrence/revision watermarks prevent unchanged
retries from creating another eligible intent after restart. A genuine later
occurrence, reopen or severity escalation can produce a new intent. The submitted
clock/high watermark is session-only; no durable delivery/display claim is made.
SQLite schema remains 019; migrations 001–019 are unchanged.

Settings → Desktop notifications offers one Enable checkbox and explains limited
preview and lock-screen visibility. Default disabled is conservative because the
existing product had no OS disclosure consent. Save uses the existing atomic
config writer and preserves unrelated preferences; runtime changes only after
successful persistence. Cancel writes nothing. Missing/invalid setting or malformed
file defaults disabled. Disable clears pending delivery; Enable applies to future
eligible intents without scanning/replaying history. No detailed-preview mode.

## Bounds and threading

Producer callbacks only append to a locked portable queue; no Qt call or per-event
queued Qt callback. The GUI controller has one 1000 ms QTimer and drains at most
one intent per tick. Queue capacity 32, coalesced by stable alert ID. Overflow
rejects the new distinct intent with QUEUE_FULL and aggregate queue_dropped.
Coalescing preserves the initial lifecycle baseline and freshest occurrence.
Pending ACK/RESOLVED/suppressed/ineligible alerts cancel the pending slot.

State capacity 512 alert subjects per session: one most recent attempted identity,
highest submitted severity and monotonic submitted timestamp per subject. No
eviction permits replay of an old subject; once full, new subjects get a typed
POLICY_SKIPPED plus capacity_skipped until restart. Existing subjects still work.
This operational resource limit is visible in Diagnostics, not a security verdict.
Counters saturate at signed 64-bit maximum; no per-subject diagnostics history.

QUITTING closes the subscription and sink before worker shutdown, clears the
queue/state, stops timers, rejects new intents and ignores late click callbacks.
ApplicationLifecycle owns shutdown; the notification adapter owns no monitoring.

## Privacy mapper

Title: `NetSentinel security alert`

Example body: `High severity network security alert detected. Open NetSentinel to review details.`

Only LOW/MEDIUM/HIGH from the existing RiskSeverity enum are mapped to fixed plain
text. INFO observations do not notify. Title is fixed (25 characters); body maximum
160 characters (current longest 84). The request constructor rejects any title or
body that differs from this mapper. No alert entity, IP, domain/DNS name, executable
path, command line, MAC, hash, username, provider metadata, raw payload or evidence
can enter the preview. Detailed evidence remains inside the application.

OS notifications may be visible to others and on lock screens depending on OS
settings. Disable notifications in Settings if OS surfaces are unsuitable.

## Qt platform boundary and exact click identity

QtDesktopNotificationSink checks tray availability and supportsMessages, then
uses showMessage. Qt does not provide delivery acknowledgement or a message token
on messageClicked. Reusing one tray icon and replacing a latest-alert pointer
would be unsafe for delayed A/B clicks. Instead each accepted request has its own
temporary QSystemTrayIcon source and immutable alert ID. No source is repurposed.
At most **8** handles/icons live for **600 seconds** each. A single expiry timer
disconnects, hides and deletes expired sources; capacity is SINK_UNAVAILABLE.
Expired/quit callbacks are ignored. The usual NS-093 tray menu stays independent.
Temporary notification icons can appear in Windows' tray; this deliberate v1
tradeoff provides exact source identity without another dependency or native toast
registration. Click handling is limited to a running app and retained handles,
not Action Center activation after exit or expiry. OS may suppress, group, defer
or replace messages; timeout is a hint, not a display guarantee.

[Qt QSystemTrayIcon documentation](https://doc.qt.io/qt-6/qsystemtrayicon.html)
documents plain text, configuration-dependent display, parameterless click signal
and Windows tray-icon activation behavior. Native Windows shell behavior still
requires the manual smoke below; offscreen tests are not native shell proof.

Click → immutable alert UUID → ApplicationController show/restore → Alerts page
→ existing bounded AlertQueryCoordinator worker → AlertService.get(UUID) → exact
single-row reveal/detail. Filters/profile scope reset; offset/page 1 is never
searched for the target. Refresh returns to normal browsing. Generation and one
pending query prevent delayed A/B replies selecting another alert. Deleted target
shows `Alert is no longer available.`; query failure shows a safe unavailable
message. Opening performs no ACK/resolve, occurrence change, reassessment or TI
lookup. Legacy and generic risk alerts use the same path.

## Diagnostics and tests

Aggregate-only NotificationDiagnostics includes intents_seen, submitted_to_sink,
duplicate_skipped, cooldown_skipped, escalation_notifications, suppression_skipped,
disabled_skipped, sink_unavailable, sink_failure, queue_coalesced, queue_dropped,
lifecycle_skipped, hysteresis_skipped, capacity_skipped, shutdown_skipped, clicks,
navigation_success and navigation_failure. Diagnostics UI shows delivery failures,
queue/capacity and navigation counts, explicitly calling display unconfirmed.
No alert IDs, IPs, names, paths, preview body or exception strings are logged.

Offline FakeNotificationSink supports requests/attempt count, unavailable/failed
outcomes, exception injection, pre-submit commit verification and delayed A/B clicks.
Portable matrix, actual SQLite restart/failure/suppression/storm, offscreen shell
and fake Qt-icon mapping tests require no Windows shell, network or capture.
See [acceptance and validation report](DESKTOP_NOTIFICATIONS_ACCEPTANCE.md).

## Windows manual smoke — NOT EXECUTED

1. Launch normal Windows GUI; startup visible and no historical popup.
2. Settings → Desktop notifications → Enable → Save.
3. Use a safe local/synthetic committed LOW/MEDIUM/HIGH alert (no attack traffic).
4. Verify generic limited-preview notification with no sensitive metadata.
5. Hide to tray; generate another eligible alert; check notification appears.
6. Click it: window restores, Alerts opens, exact ID/detail appears.
7. Submit A then B; click retained A and verify A, then B and verify B.
8. Repeat with minimized and visible window; monitoring starts only once.
9. Check target hidden by filters and target outside current page; exact reveal.
10. Repeat same occurrence within cooldown: no spam; escalate severity: eligible.
11. ACK/RESOLVED/suppression produce no popup; genuine reopen follows policy.
12. Disable, accumulate alerts, enable: no backlog flood. Restart: zero replay.
13. Check OS notification-disabled/Focus Assist/lock-screen settings and tray loss;
    app/local alerts remain usable even if OS suppresses messages.
14. Check temporary-icon/handle expiry and late clicks never open a different alert.
15. Quit from tray; pending delivery cancelled; no orphan popup/click callback.

NS-095 not started. No retention scheduling/purge/export, installer, signing,
service/autostart, firewall, automatic elevation, provider upload or release/tag.

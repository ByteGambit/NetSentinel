# NS-094 kabul ve teslim raporu

2026-10-05. Authoritative task: **NS-094 — Desktop notifications**.
Frozen policy: [DESKTOP_NOTIFICATIONS.md](DESKTOP_NOTIFICATIONS.md).
Offline acceptance is separate from native Windows shell smoke.

| # | İstenen rapor alanı | Sonuç / kanıt |
|---:|---|---|
| 1 | Exact title | NS-094 — Desktop notifications |
| 2 | COMPLETE / INCOMPLETE | COMPLETE; frozen offline acceptance geçti; native smoke ayrı ve çalıştırılmadı |
| 3 | M17 | Devam ediyor; yalnız NS-094 teslimi |
| 4 | Schema before/after | 019 → 019; real SQLite restart ve migration regression |
| 5 | Migration | Yok; 001–019 SQL dosyaları değişmez |
| 6 | Application contract | Portable PersistedNotificationIntent, DesktopNotificationRequest, immutable policy, service ve sink Protocol |
| 7 | Delivery service | Locked bounded enqueue; GUI-thread drain; typed outcomes |
| 8 | Sink contract | submit → typed outcome; set_click_handler(UUID); close |
| 9 | Qt adapter | QtDesktopNotificationSink; capability + showMessage + immutable per-source click target |
| 10 | Fake sink | FakeNotificationSink: outcome/exception injection, request/attempt count, commit hook, delayed click |
| 11 | Policy version | Frozen v1 |
| 12 | Intent source | Committed AlertService legacy state; risk after assessment + alert commit and suppression |
| 13 | Persistence before delivery | Separate read in intent subscriber and fake pre-submit hook verifies committed row |
| 14 | Intent versus delivery | Existing bool/last_notified_at only eligibility; SUBMITTED_TO_SINK never display/user-seen proof |
| 15 | Identity | Alert stable UUID + policy v1 + original observation watermark + count + severity |
| 16 | Dedup | Unchanged attempted identity skipped even after cooldown; old intents cannot rewind |
| 17 | Cooldown | 120 seconds per alert |
| 18 | Clock | Injected monotonic runtime clock; repository UTC eligibility watermark remains separate |
| 19 | Hysteresis table | Exact frozen matrix in policy document and parametrized portable tests |
| 20 | Same severity | Identical skip; future occurrence inside cooldown skip; outside cooldown eligible |
| 21 | Escalation | LOW→MEDIUM/HIGH, MEDIUM→HIGH bypass cooldown |
| 22 | De-escalation | No popup; highest submitted severity retained until reopen |
| 23 | Score-only | Revision/confidence/provider/numeric changes alone never popup |
| 24 | ACK | No notification; committed status event cancels pending intent |
| 25 | RESOLVED | No notification; pending cancelled |
| 26 | REOPEN | Genuine new occurrence reopens persisted alert; resets lifecycle cooldown/hysteresis |
| 27 | Suppression | NS-081 respected; pending cancelled; existing alert/evidence/assessment retained |
| 28 | Setting | desktop_notifications_enabled: typed bool, default false |
| 29 | Disable / re-enable | Pending cleared; enable applies only to future intents |
| 30 | Historical replay | No query/scan/submission at startup |
| 31 | Restart dedup | Real DB: unchanged retry emits no intent; future occurrence/escalation still works |
| 32 | Durable state | Existing occurrence/revision/eligibility watermarks; no durable submitted/display ledger |
| 33 | Failure | SINK_FAILED, no submitted-time/high-watermark advancement; raw error excluded |
| 34 | Retry | No scheduler/tight retry; identical failed intent skipped, genuine future intent may try |
| 35 | Unavailable | SINK_UNAVAILABLE; local detection/navigation independent |
| 36 | Queue model | One locked OrderedDict slot per alert ID, no per-event Qt callbacks |
| 37 | Queue bound | 32; one GUI timer drains at most one per second |
| 38 | Coalescing | Same ID pending coalesced; initial lifecycle baseline and freshest occurrence retained |
| 39 | Overflow | QUEUE_FULL + queue_dropped; state-capacity POLICY_SKIPPED + capacity_skipped |
| 40 | Shutdown | Subscription detached/sink closed before workers; timer/queue/state cleared; late callbacks ignored |
| 41 | Preview | LIMITED only; default opt-in; fixed severity text |
| 42 | Example | NetSentinel security alert / High severity network security alert detected. Open NetSentinel to review details. |
| 43 | Excluded fields | IP/domain/DNS/path/MAC/hash/username/command-line/provider/raw payload/evidence; constructor rejects arbitrary preview |
| 44 | Body max | 160 characters hard policy; current maximum 84 |
| 45 | Plain text | Fixed plain strings; no HTML or arbitrary metadata |
| 46 | Settings | Settings → Desktop notifications; atomic field-only Save; Cancel no write |
| 47 | Malformed fallback | Missing/non-bool field or malformed/unreadable file defaults disabled; write failure preserves old config/runtime |
| 48 | Click identity | Immutable alert UUID per retained message source; no latest-alert pointer or row-index target |
| 49 | Visible click | Offscreen shell pass; exact detail; engine starts once |
| 50 | Hidden click | NS-093 Show restores then navigates exact ID |
| 51 | Minimized click | Minimized flag removed; exact detail |
| 52 | Alerts navigation | Existing alert worker direct get(UUID), single-row reveal/detail |
| 53 | Pagination | Test with 121 stored records; old target outside first 50 retrieved directly |
| 54 | Filters | Reset/reveal exact target; pending filtered page query superseded by generation |
| 55 | Deleted alert | Alert is no longer available.; no selection of another row/crash |
| 56 | Legacy / risk | Both committed sources and exact navigation covered; risk reference/detail tab preserved |
| 57 | A/B | Submit A then B, click B then delayed A; both portable fake and Qt-source mapping tests |
| 58 | Click mutation | Row before/after identical; no ACK/resolve/count/reassessment/TI lookup; exact read only |
| 59 | Diagnostics | Aggregate-only immutable counters; selected operational totals in Diagnostics UI |
| 60 | Diagnostics privacy | Counters only; no alert ID, IP/domain/path/body/exception string in normal diagnostics/logs |
| 61 | Startup zero | Adapter construction has zero showMessage calls; historical shell startup zero submissions |
| 62 | No backlog | Disabled→enabled and restart covered with actual persistence |
| 63 | Hide/show duplicate | Repeated restore/drain starts engine once, sink submission once |
| 64 | Firewall | None |
| 65 | Service / autostart | None; no Registry Run, Task Scheduler or elevation |
| 66 | Windows checklist | Policy document, 15 explicit safe local/synthetic steps |
| 67 | Native smoke | NOT EXECUTED; offscreen/fake-icon evidence is not native Windows shell acceptance |
| 68 | Added files | application/services/notifications.py; presentation/notifications.py; widgets/notification_settings.py; fixture + 4 test modules; 2 notification docs |
| 69 | Modified files | AlertService/risk_alerts/alert_query; bootstrap; presentation app/alert_query/Alerts/MainWindow/Diagnostics; shared config; PRODUCT/ARCHITECTURE/SECURITY/ROADMAP/TASKS |
| 70 | Tests | Portable matrix, actual SQLite failure/restart/storm/suppression, offscreen shell, fake Qt-icon mapping, config atomic/default/malformed |
| 71 | Targeted | Exact commands/results recorded below |
| 72 | Full pytest | Exact result recorded below |
| 73 | Ruff | src tests; exact result recorded below |
| 74 | Configured mypy | Default project targets; exact result recorded below |
| 75 | Direct mypy | 12 changed service/presentation/composition modules; exact result recorded below |
| 76 | Diff check | git diff --check; result recorded below |
| 77 | TASKS | Only NS-094 marked complete after validation; NS-095–099 remain planned |
| 78 | Docs | DESKTOP_NOTIFICATIONS.md and this acceptance report; core product/security/architecture/roadmap records updated |
| 79 | Commit | feat: add privacy-aware desktop notifications; verified SHA supplied in final delivery message |
| 80 | Push | origin main, no force/tag/release/branch; verified result supplied in final delivery message |
| 81 | NS-095 | Not started; no retention scheduling/quota/purge/export added |
| 82 | Working tree | Final git status and HEAD/origin/main verification supplied with commit/push result |

Additional explicit resource limits: 512 retained alert subject states per session,
8 temporary Qt notification icon handles with 600-second lifetime, one settings
dialog and one pending exact-navigation target/query. At 512 new subjects are
rejected until restart; no eviction silently enables replay. At 8 active Qt handles
new requests are unavailable; no icon is reused for another alert. Expired callbacks
are ignored; post-exit Action Center activation is outside this v1 Qt adapter.
Temporary notification icons may be visible in the tray. Native display is subject
to OS settings, as documented by [Qt](https://doc.qt.io/qt-6/qsystemtrayicon.html).

## Validation

All commands use `.\.venv\Scripts\python.exe` from the repository root:

| Check | Command | Result |
|---|---|---|
| Final new-only | `-m pytest -q tests/unit/application/test_notifications.py tests/integration/test_desktop_notifications.py tests/gui/test_desktop_notifications.py tests/unit/shared/test_notification_config.py` | **84 passed**, 13.19 s |
| Dependency-targeted | Above notification modules plus `tests/gui/test_app_lifecycle.py tests/gui/test_tray_lifecycle.py tests/gui/test_alerts_view.py tests/integration/test_suppression_pipeline.py tests/integration/test_risk_alert_pipeline.py` | **225 passed**, 44.52 s; before final six malformed/stale-intent edge cases, which the final new-only/full runs include |
| Full offline | `-m pytest -q` | **3543 passed, 8 deselected**, 254.29 s |
| Ruff | `-m ruff check src tests` | All checks passed |
| Configured mypy | `-m mypy` | Success, **34 source files** |
| Direct mypy | `-m mypy` plus the 12 modules listed below | Success, **12 source files** |
| Whitespace | `git diff --check` | Clean; normal Windows LF/CRLF informational warnings only |

Direct mypy modules: application/services/{notifications,alerts,risk_alerts,alert_query}.py;
presentation/{notifications,alert_query,app}.py;
presentation/widgets/notification_settings.py;
presentation/views/{alerts,main_window,diagnostics}.py; bootstrap.py.
Shared config is included in configured mypy. MainWindow received narrow type
annotations/optional Qt guards so this direct check also passes its previously
unchecked snapshot/navigation hooks; no unrelated feature was added.

No live attack, capture, Windows elevation, native shell smoke or external
provider is used. M17 continues; NS-095 is not started. Git commit/push/clean
status are reported from verified command results in the final delivery message.

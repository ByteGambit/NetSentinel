# M19 / M20 — Localization, guided onboarding and full-system validation

Date: **2026-10-09 (Europe/Istanbul)**. Frozen planning baseline:
`97e214a270a5153d1ffd234cc50707ce52083f7f`, local `main`, SQLite **020**.
Historical frozen planning baseline: at plan creation this was **PLANNING ONLY**,
and NS-105–NS-120 were **PLANNED / NOT STARTED**. The later explicit NS-105 request
completed only the localization foundation with runtime **NO_GO / whole-app
restart required**. [Current acceptance](LOCALIZATION_ACCEPTANCE.md) and TASKS
carry current status; NS-106–120 remain NOT STARTED. The frozen requirements below
remain unchanged.
Implementation, translations, migrations, installer builds, VM execution,
attack execution, commit/push and tag/release are not authorized by this plan.

## 1. Current post-M18 state and inspected sources

M1–M18 and NS-001–NS-104 are complete in their recorded acceptance scopes.
Limited unsigned pilot remains **CONDITIONAL_GO**; broad public release and
asInvoker in-product privileged firewall writes remain **NO_GO**. Automatic
blocking/elevation, persistent service/helper/task/driver/WFP and release: NONE.
Local HEAD was verified; no remote fetch or remote freshness claim is implied.
Initial tracked working tree was clean; four ignored `ns067-mypy-*` directories
produced existing permission warnings and were left alone.

Authoritative reading: [TASKS](TASKS.md), [ROADMAP](ROADMAP.md),
[PRODUCT](PRODUCT.md), [ARCHITECTURE](ARCHITECTURE.md), [SECURITY](SECURITY.md),
[RELEASING](RELEASING.md). Older status paragraphs in these documents retain
their historical candidate scopes; TASKS NS-104 and
[response/uninstall acceptance](RESPONSE_UNINSTALL_ACCEPTANCE.md) establish
the current M18 closure. This plan adds milestones without rewriting history.

| Inspected implementation/evidence | Planning consequence |
|---|---|
| `presentation/views/main_window.py`, `app.py`, `models/`, `widgets/`, `tray.py`, `notifications.py` | Hand-built PyQt6 widgets; eight stable PageIds: Dashboard, Connections, History, Devices, DNS, Alerts, Incidents, Diagnostics. Settings is a menu of dialogs, not a ninth page. Labels, headers and presentation mappers currently contain English literals. |
| `shared/config.py`, `shared/paths.py` | Local bounded JSON, field validation, atomic replace; legacy completion boolean plus completed/dismissed guide versions. Any damaged config currently disables TI consents; preserve this fail-closed rule. |
| `widgets/onboarding.py`, [M17 guide](FIRST_RUN_FEEDBACK.md), `tests/gui/test_first_run_feedback.py` | Existing six-page informational guide, Next/Back/Skip/Finish, Help replay and separate consents. Fresh guide precedes engine start; Esc currently quits fresh startup. Build on it, avoid a second competing first-run state. |
| `packaging/NetSentinel.iss`, `.spec`, `build_installer.py`, `installer_payload.py`, `entry.py`, `pyproject.toml` | Inno Setup per-user `PrivilegesRequired=lowest`, PyInstaller onedir/asInvoker, no installer language catalog/selection. Custom English safety text and policy file. Package currently includes SQL001–020/icon, no app translation resources. |
| Repository search for QTranslator/QLocale/LanguageChange/retranslate/translation catalogs | No existing app localization system found. NS-105 owns extraction and source-string conversion, not a dependency on a nonexistent `.ui`/retranslateUi generator. |
| `bootstrap.py`, incident services and [incident soak](INCIDENT_ACCEPTANCE_SOAK.md) | Incident read UI and explicit correlation/persistence APIs exist; no automatic desktop incident producer. Empty Incidents is an honest expected runtime outcome. |
| TI composition, [TI evidence](THREAT_INTELLIGENCE_EVIDENCE.md), [local dataset](LOCAL_DESTINATION_DATASET.md) | AbuseIPDB manual public-IP only; desktop secret backend unavailable, no key-entry UI. ASN/country defaults to no dataset; local user-supplied dataset is supported. |
| Detector implementations and domain policies; network-scope/VPN tests | ARP identity/correlation, device identity, DNS server-set, traffic rate, VLAN, novelty/rarity, appearance frequency/diversity, periodicity exist. No dedicated TCP port-scan/UDP attack/DNS-content malware detector. |
| `tests/conftest.py`, GUI layout/accessibility tests, screenshot fixtures | Offscreen default; actual synthetic Qt screenshots already exist. These prove widget behavior, not native Windows DPI, Narrator or visible toast delivery. |
| `test_connection_monitor.py`, `test_windows_network_context.py`, `test_scapy_capture.py`, `sqlite/test_device_inventory.py`, `test_response_firewall_vm.py`, `tests/fixtures/ns101/`, `ns102/`, `ns104/` | Reuse bounded loopback/capture and strict Windows/Kali firewall harnesses; current RFC1918 firewall seam is pytest-only and cannot authorize production private-IP writes. |
| [beta protocol](BETA_PROTOCOL.md), [native VPN](NS099_VPN_WIREGUARD_CLOSURE.md), [sleep](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md), [notification policy](NS099_NOTIFICATION_POLICY_CLOSURE.md), installer acceptance | Prior evidence is candidate-scoped. Reuse procedures/topology, repeat affected native gates against the final M19 candidate. |

## 2. User goals and requirement ownership

M19: **Localization & Guided Onboarding**. M20: **Full-System VMware Validation**.
M19 is a usability milestone, never a declaration that NetSentinel is finished.

| Requirement | Owning task(s) / acceptance |
|---|---|
| Turkish, English fallback, approximately 18 offline languages | NS-105/107/110; language registry and catalog gates below |
| First-launch language question, persistence, repeated Settings changes | NS-106/109/110; S51/S54/S56 |
| Honest runtime/restart behavior, open dialogs/tray/notifications/accessibility | NS-105/106/109/110; S34/S48/S54/S55 |
| Beginner guide: purpose/meaning/actions, all major areas, safe Skip/Next/Back/Finish | NS-108/110; S56 |
| Never-shown/skipped/completed/versioning/upgrade and Settings replay | NS-108/109/110; S52/S56 |
| Complete product inventory, positive and benign native evidence | NS-111–120; F01–F64, S01–S56, C01–C36 |
| VMware isolation, privileges, observability and cleanup | NS-111, each execution task, NS-120 |
| Stability/privacy/installer/response/localization completion | NS-116–120; final gate below |
| Separate functional completion from signing/distribution | NS-120; release NO_GO retained |

## 3. Localization architecture decisions

**Choose Qt QTranslator with UTF-8 Qt Linguist `.ts` sources and compiled `.qm`
application catalogs**, not runtime JSON dictionaries, gettext or online APIs.
Canonical English source text and explicit context/disambiguation are the keys.
Do not use dynamically translated text as identity, fingerprint, rule, sort key,
SQL field or config enum. Domain/application store typed codes/evidence/UTC;
presentation maps them to translated descriptions. Technical evidence remains
verbatim. Already persisted free text is historical evidence, not rewritten.

Qt provides catalog loading and language-change events; widgets must explicitly
update their text. These are framework capabilities, **not proof this application
already switches correctly**. Sources:
[QTranslator](https://doc.qt.io/qt-6/qtranslator.html) and
[dynamic widget translation](https://doc.qt.io/qt-6/i18n-source-translation.html#prepare-for-dynamic-language-changes).
Display formatting can use [QLocale](https://doc.qt.io/qt-6/qlocale.html).
The following integration design is a repository-specific decision.

### Extraction, resources and formatting

- NS-105 creates a complete surface inventory and presentation translation
  facade using extractable literal `tr` / `QCoreApplication.translate` calls.
  Import-time PAGE_LABELS and text tuples must become source descriptors rendered
  at use time. F-strings/concatenation are not translation keys. Proposed sources:
  `src/netsentinel/presentation/i18n/`, runtime catalogs under
  `src/netsentinel/assets/i18n/`, translator policy under `docs/LOCALIZATION.md`.
- Use `pylupdate6` for Python extraction, Qt `lrelease` for compilation and Qt
  Linguist for editing. NS-105 verifies actual locked PyQt/Qt tooling support,
  comments, plural extraction and deterministic catalog output. A missing
  compiler requires a reviewed build-tool dependency, not a runtime Qt-tools
  bundle or a silent replacement with another resource system. No tool install
  or dependency change occurs during this planning task.
- English is default/fallback and available without a translated catalog. Keep
  an English source/plural catalog where needed to handle English numerus forms;
  failure must still yield readable English singular/plural, never raw keys or
  empty safety text. Missing/unfinished translations fall back to source English
  and fail catalog acceptance; removed/obsolete keys are excluded from `.qm`.
- Use Qt numerus `%n`, with required locale plural forms, not `count == 1`
  language logic. Parameterized messages use validated named placeholders after
  translating a whole literal sentence; exact placeholder multiset, type and
  escaping must match. No evaluated template/code, rich markup from evidence,
  or English sentence fragments. NS-105 freezes one substitution convention.
- UI language selects an explicit QLocale for displayed date/time/counts.
  UTC remains stored; display shows local time with timezone/offset where useful.
  Locale formatting does not change time filters' raw values or numerical sort.
  Durations retain unambiguous units. IP/port/protocol, paths, MAC, hashes,
  executable/publisher names and raw technical evidence are not localized.
- Machine reports/logs/export JSON keep schema keys, status codes, ISO UTC,
  numeric values and canonical evidence; localize only surrounding preview/help
  labels. Existing support-export-v1/allowlist-v1 remains unchanged. CLI/self-test
  machine receipts and firewall recovery evidence remain canonical English/codes;
  document these exceptions. No new human report feature is implied.
- Ship trusted, reviewed catalogs offline in wheel and PyInstaller inventory;
  validate language manifest, catalog sizes/digests and package completeness.
  Load only allowlisted bundled paths. No arbitrary user catalogs, downloads,
  external translation API or runtime extraction. Include licensed compatible
  Qt widget catalogs where available, with explicit standard-dialog coverage;
  otherwise document/test the OS or English fallback.

### Dynamic retranslation and switching contract

**Preferred design: safe runtime retranslation for application-owned surfaces.**
NS-105 must pass a narrow fake/pseudo-language feasibility gate before NS-106
commits to the runtime path: preserve selection/filter/focus, unsaved input,
command target/confirmation semantics, query generations and existing workers
while switching LTR→RTL→LTR and updating a live dialog. Existing hand-built Qt
widgets need explicit `retranslate()`/`changeEvent(LanguageChange)` handling;
QTranslator alone does not regenerate constructor literals.

One GUI-owned locale manager holds strong translator references and a monotonic
locale generation. Models retain raw records, then invalidate DisplayRole,
headers, tooltips and accessibility roles; numeric sorting/IDs remain stable.
Render cached detail/status/error text again from typed data on locale change.
Workers return language-neutral data; late results use the **current** locale,
not text computed in the old generation. Keep selection/query generations
separate from locale generation; a switch must not discard a committed command.

Settings → Language shows current and pending language using autonym plus
English name, independent of whichever language the user currently understands.
Selection previews text/direction; **Apply** persists, Cancel writes nothing.
Stage and verify the new app/Qt catalogs before atomically saving a reload/merge
of current config, then publish the GUI generation at a safe event-loop boundary.
Save failure leaves old language/config intact. Load failure does not persist the
failed selection; offer/use English fallback with a sanitized reason. Startup
with invalid/removed/missing resource uses effective English; display the invalid
requested preference honestly until a valid explicit Apply replaces it.
Catalog failure alone is not a privacy-consent operation. Existing damaged-config
fail-closed TI policy remains independently in force.

Open informational/settings dialogs retranslate in place and keep input. A live
destructive confirmation or executing command defers Apply until its critical
step closes; never change what was confirmed, auto-confirm, replay or silently
close it. Guide preserves current step. Tray QAction labels/tooltips update.
Future notifications use current language when submitted; already delivered
Windows notifications stay in their original language and are not replayed.
OS shell/security prompts and native file dialogs can follow Windows language;
close/reopen them for refreshed app captions. Installer language stays English.

If NS-105 cannot establish safe dynamic updates, **freeze a restart-required
mode for the whole app** before NS-106: Settings explicitly says language applies
on next launch, shows pending/current language, saves without forcing restart,
and keeps the current session coherent. Repeated changes and cancellation remain
possible. NS-110 must record the tested mode; partial/mixed-language runtime
support must not be advertised. Thus runtime switching is a planned capability
with a mandatory decision gate, not an unsupported promise.

## 4. M19 scope and task breakdown

Full task definitions (objective, exact work, files, dependencies, criteria,
tests, exclusions and gates) are appended in [TASKS](TASKS.md). These IDs were
unused at baseline. All sixteen records remain **PLANNED / NOT STARTED**.

| ID | Frozen title | Dependency / specific gate |
|---|---|---|
| NS-105 | Localization architecture & source extraction | NS-104; future explicit M19 implementation authorization; decide runtime/restart mode |
| NS-106 | First-launch language selection & persistence | NS-105; loader/config/switching contract with fake catalogs |
| NS-107 | Reviewed translation packs & offline packaging | NS-106; four independently accepted catalog waves |
| NS-108 | Page-aware first-run guided tour | NS-106, NS-098; extend current guide, preserve permissions |
| NS-109 | Settings language/replay & surface integration | NS-107, NS-108; complete tray/dialog/model coverage |
| NS-110 | Localization/onboarding acceptance gate | NS-105–109; full matrix, packaged native UX gate |

The proposed ID allocation is retained. Boundaries are refined: extraction and
runtime feasibility belong to NS-105; NS-107 is bounded by four quality waves;
NS-108 replaces/extends M17 guide rather than duplicating it; NS-109 completes
all surface integration and exposes replay under actual Settings menu architecture.
No detector/privilege deployment/schema change is part of M19.

## 5. Language strategy and translation quality

**Freeze 18 UI languages, including English; 17 target translation packs.** This
is a supported target set subject to each pack's acceptance, not a claim of
already available translations. Reach rationale is qualitative audience coverage,
not fabricated market-share research. Turkish is mandatory and English fallback.

| Persisted BCP-47 ID | Language / autonym | Reach and QA rationale |
|---|---|---|
| en | English / English | Canonical source, broad interoperability, fallback |
| tr | Turkish / Türkçe | Mandatory primary user need; İ/ı/Ş/ş/Ğ/ğ/Ç/ç/Ö/ö/Ü/ü and case handling |
| de | German / Deutsch | European reach; long compound labels and expansion stress |
| fr | French / Français | European and wider francophone reach; accents/spacing |
| es | Spanish / Español | Cross-region reach; neutral vocabulary, no region claim |
| it | Italian / Italiano | European audience; inflection and expansion |
| pt-BR | Portuguese (Brazil) / Português (Brasil) | Explicit single regional pack to bound maintenance; pt-PT is not claimed |
| nl | Dutch / Nederlands | European audience; compact pack but expansion still tested |
| pl | Polish / Polski | Central European reach; diacritics and plural QA |
| ru | Russian / Русский | Cyrillic reach; plural and long-string stress |
| uk | Ukrainian / Українська | Distinct Cyrillic language; do not substitute Russian |
| ar | Arabic / العربية | Broad Arabic audience; explicit RTL, shaping and mixed-direction evidence |
| ja | Japanese / 日本語 | East Asian reach; glyph/fallback/wrapping QA |
| ko | Korean / 한국어 | East Asian reach; Hangul glyph/fallback/wrapping QA |
| zh-Hans | Simplified Chinese / 简体中文 | Script-specific pack; no silent conversion from Traditional |
| zh-Hant | Traditional Chinese / 繁體中文 | Separate script pack and reviewer; regional terminology checked |
| id | Indonesian / Bahasa Indonesia | Southeast Asian reach; avoids widening into unreviewed regional packs |
| cs | Czech / Čeština | Central European coverage; diacritics/plural validation |

The candidate list survives evaluation with **Portuguese narrowed to pt-BR** and
Chinese made script-explicit. All fit Qt Unicode/locale design; actual fonts and
tool plural behavior must be measured, not assumed. No installer translations
are added. Additional regional variants increase translation/review costs and
are deferred. Names/IDs are a manifest, never localized config values.

Arabic mirrors appropriate navigation/layouts and action placement, preserving
logical keyboard order; technical evidence cells/fields use explicit LTR and
plain text. Test punctuation, IPv6, path/hash copy and bidi edge cases. Do not
inject direction characters into persisted/exported evidence. CJK/Arabic must
validate actual Windows fallback glyphs/font metrics offline. If fonts are absent,
record a blocker or approved licensed packaging decision; no automatic font
download or assumption Segoe UI covers every script. German/Russian and a
non-shipping expansion pseudo-locale stress 30–50% expansion and wrapping.

NS-107 waves: **A** English plural/source + Turkish + German; **B** French,
Spanish, Italian, pt-BR, Dutch, Polish, Czech; **C** Russian, Ukrainian,
Indonesian; **D** Arabic, Japanese, Korean, zh-Hans, zh-Hant. Each wave has an
inventory hash, load/placeholder/plural completeness check, screenshots and
review receipt before proceeding; D requires RTL/CJK native evidence. NS-108 can
use English/pseudo resources before all catalogs finish. NS-107 accepts its own
frozen source-inventory revision; NS-109 owns re-extraction and every pack's
guide/Settings delta translation/review after integration. Thus NS-107 does not
depend on future NS-109 completion. Every pack must cover the final inventory
before NS-110.

Quality model:

- English wording is canonical, including explicit unknown/limitation/consent
  language. TS context and translator comments explain ambiguity, technical
  terms, parameters, units, privacy and destructive effects.
- CI diff checks extracted inventory, unique context/source/comment keys,
  required locale registry, unfinished/missing/obsolete strings, plural forms,
  placeholders, Unicode/control characters, accelerator conflicts and trusted
  package resources. Source edits mark translations stale and require review;
  never silently preserve an obsolete safety translation.
- A static user-visible sink scan covers setText/window title/menu/action/header/
  tooltip/accessibility and presentation mappers; reviewed allowlist records
  protocol names, IDs, technical values, historical evidence, machine exports
  and OS language surfaces. Neither regex alone nor English words in evidence
  prove a localization defect. Pair scan with representative UI assertions.
- AI drafts may assist, but are not acceptance. Every target pack needs a
  language-competent human reviewer for all consent, safety, uncertainty,
  firewall/Undo/purge text and guide steps, plus navigation/status/error/number
  spot-checks. Reviewers sign a bounded locale/inventory receipt; independent
  second check for Turkish/English and destructive language. Missing reviewer
  leaves the pack unaccepted, not silently production-quality.
- Offline tests/compilation on final resources plus manual native spot-checks;
  review wording for unsupported malware/safety promises. No runtime service or
  automatic machine-translation fallback. Maintainer owns re-extraction and
  stale-string triage for every future UI change.

## 6. Installer versus first-launch language decision

**Installer remains the current minimal English Inno Setup wrapper; the first
application launch asks language before explanatory app text/tour.** This meets
the user's installation OR initial-launch requirement without a second eighteen-
language safety-text system. Inno custom KEEP/DELETE/custody text and policy file
are explicitly English; translating those later is a separate reviewed scope.
No installer-to-config handoff, command-line language write or consent coupling.

First launch shows all autonyms/English names; supported OS UI language can be a
suggestion, with English preselection if no exact supported mapping. No decision
is silently accepted. Continue/Use English explicitly confirms choice; X/Esc at
this bootstrap exits without recording choice, so the next launch asks again.
Existing users with no confirmed language get one language-only question at next
launch, default English, preserving data and acknowledged guide state. Reinstall
KEEP/upgrade retains choice; confirmed DELETE resets it.

Persist proposed `ui_language` and `ui_language_confirmed` in existing config,
not SQLite. Explicit mapping connects BCP-47 IDs to QLocale/Qt catalog names;
bounded aliases may normalize regional OS suggestions but never confuse Chinese
scripts or substitute an unaccepted pack. Unknown/removed preferences use English
and a nonmodal Settings notice; no recurring forced chooser for an acknowledged
returning user. Preserve current file budget/atomic save and concurrent settings.

## 7. Guided-tour architecture and first-run state

**Choose dedicated welcome/language bootstrap plus a nonmodal, page-aware coach
panel with optional widget highlights.** Reuse existing informational guide
content/consent explanations; no full-screen click-blocking overlay. MainWindow
PageIds and objectName/semantic target registry locate widgets. Bind after layout,
map widget rects at resize/DPI change, never hardcode screen coordinates. A missing
selection/disabled capability/hidden target yields text-only explanation and an
honest unavailable reason. Do not fabricate telemetry or click real commands.

After explicit language confirmation, show MainWindow and start core monitoring
once through existing lifecycle; the guide runs alongside it. This deliberate
change from M17's hidden-window/pre-engine guide needs NS-108 lifecycle tests.
Capture, TI, notifications and retention stay separate opt-ins. Tour navigation
only selects pages/sections; it never Starts capture, queries reputation, Saves a
profile/preference, purges data, confirms firewall actions or changes privacy.

Planned steps explain purpose, interpretation and available action for:
welcome/local-first; Dashboard (including broadcast/VLAN limitations);
Connections/process/destination; History and observation gaps; Devices/passive
capture/trust; DNS/association ambiguity; risk/baseline/mark-normal; Alerts and
notifications; Incidents/timeline/empty-state limits; TI consent/credential status;
manual firewall preview/Undo/NO_GO; Diagnostics; Settings/storage/language/replay.
No data selection is required to finish. No network request is needed.

Next/Back, immediately available Skip and Finish, keyboard focus, readable progress,
plain accessible text, resize/scroll and safe Esc are mandatory. **Esc/X on the
running tour is Skip**, exits without blocked navigation; app close performs
normal configured shutdown. Save failure shows sanitized retry state and allows
closing the panel to continue the session; acknowledgement remains unsaved and
may reappear next launch. Return focus to originating control; navigating away
updates the context or pauses guidance safely. Replay is explicit from Settings
and existing Help. It never restarts monitoring or resets preferences.

State uses existing `onboarding_completed_version`,
`onboarding_dismissed_version`, legacy `onboarding_completed`; planned tour version
**2**. Derive never-shown when no legacy/version acknowledgement exists; skipped
when current dismissed version exceeds completed version; completed when current
completion exists (completion wins a same-version tie). Finish updates completed;
Skip updates dismissed, preserving historical completion. Counters never decrease,
including unknown future versions. No partial step persistence required.

Legacy/version1 acknowledged users get a nonmodal version2 availability notice,
**never a forced new tour**. Never-acknowledged users get the first tour. A new
version only offers optional replay; future forced retraining requires a separate
explicit product decision. Replay does not erase previous acknowledgement on
entry; cancel/Skip of replay cannot undo a completed version. Update only guide
fields after reloading current config. All copy follows effective UI language.

## 8. M19 acceptance gate — NS-110

| Dimension | Required evidence |
|---|---|
| Clean first run / existing upgrade / KEEP reinstall | First language question exactly once; old consent/data/guide acknowledgement preserved; declined bootstrap records no choice |
| Turkish + English | Complete critical copy, Turkish case/characters, English source/plural fallback and readable missing-key behavior |
| All 18 configured languages | Final inventory load/compile/placeholder/plural/reviewer receipt; all app pages/dialogs smoke-tested |
| Persistence and repeated switching | At least ten Apply operations including tr→en→de→ar→ja→zh-Hant→tr; restart; Cancel; save/load failure; no accumulated translators/workers or mixed stale text |
| Missing/malformed/removed pack | Safe English, sanitized explanation, no corrupt preference/consent; malformed binary tested in bounded child process, not untrusted production loader |
| German/Russian + pseudo expansion | Navigation, headers, detail/status/help/error/guide and critical buttons wrap/remain accessible, stable selection |
| Arabic | RTL/LTR changes, keyboard order, mixed technical values/copy, dialogs and mirrored resize |
| CJK | Japanese/Korean/both Chinese scripts glyphs, fallback fonts, wrapping and native offline readability |
| Windows scaling | 100/125/150/200%, realistic 1280×720/1366×768/1920×1080; minimum logical 760×480 shell and effective viewport recorded; scroll allowed, no unreachable controls |
| Tour | Next/Back from boundaries; immediate Skip/Esc; Finish; missing target/data/capability; resize/navigation; Settings/Help replay; restart/version1/legacy/future state |
| Surfaces | Open dialogs, tray, future notifications, status/tooltips/accessibility names, columns/filters/details, generated export surrounding text and canonical machine exceptions |
| Accessibility | Keyboard-only completion and language recovery; focus/restoration, native Narrator spot-check of progress/critical controls; translated names and no focus trap |
| Beginner usability | At least one independent beginner walks the guide and can explain area purpose, uncertainty and action effects; language-competent Turkish/English spot checks, bounded findings and remediation receipt |
| Safety | No capture/TI/notification/retention consent from chooser/tour/replay; no elevation/firewall write/network access |

Extend synthetic screenshot fixtures/offscreen pytest-qt model/geometry and
stale-result assertions; record locale, viewport, font, Qt platform, scaling,
inventory digest and synthetic-data provenance. Screenshots cover every locale's
shell/tour/settings and stress-locale critical dialogs. Run packaged Windows
matrix for all scaling and RTL/CJK classes; native rendering and human language
review cannot be replaced by offscreen PASS. Restart-mode fallback, if chosen,
tests pending-language UX in place of runtime assertions. No M19 exit with an
unreviewed pack, broken critical translated action or missing mandatory native
UX evidence. M19 completion authorizes neither M20 execution nor release.

## 9. M20 lab architecture and start gates

Primary topology: **owned Kali VM ↔ VMware VMnet1 host-only ↔ owned Windows 11
VM running final M19 packaged NetSentinel**. Reuse NS-101/104's proven host-only
configuration, resolving current addresses/interface IDs afresh. Offensive
phases have one lab NIC per VM, no default route, bridged NIC, public target or
forwarding. Host itself is not a test target. Snapshot/recovery and data root must
be verified before changes; fresh test profile is not a pristine OS snapshot.

Use a separate benign NAT phase for installer/offline comparison and existing
private WireGuard topology (Windows→Kali→VMware NAT), with explicit forwarding
scope, no public inbound mapping and no attacks during NAT. Prefer controlled
local browser/download/update-like fixtures; any actual vendor update check or
public benign browsing needs an explicit approved destination list and is not
attack authorization. Restore original NIC/route/DNS/VPN state and stop VMs after
each phase. Do not resurrect prior tunnel keys/credentials in docs.

NS-111 starts only after NS-110 COMPLETE and **future explicit M20 VM execution
authorization**. It freezes candidate source/payload/catalog/installer hashes,
VM identity/build/tools/Npcap/token/profile, cleanliness, topology, stimulus caps,
timing, budgets and receipt oracle before scenarios. NS-112–119 need this freeze
and scenario-specific opt-in. No networking or VM work occurs in this plan.

Default tests exclude `windows_live`, `lab_live`, `live_threat_intel` as current
pyproject specifies. Passive tests retain `NETSENTINEL_LAB_CAPTURE` plus exact
interface/subnet. Firewall tests retain strict VM-name/virtualization/snapshot/
host-only/profile/literal-target guard in `test_response_firewall_vm.py` and its
pytest-only validation seam. New active harness gates must be distinct from
passive capture opt-in: exact owned VM pair/target, operator authorization,
duration/rate/packet cap and stop/cleanup receipt. Never weaken a production IP
policy or assume a passive marker authorizes injection. No default CI live run.

Native privileges are explicit: standard-user app always; separately confirmed
operator administration for firewall harness, Windows DNS/NIC test configuration,
Npcap installation if separately authorized, and Kali raw-frame send/VPN setup.
No automatic elevation, Defender/App Control disabling, service/helper deployment
or credential copying into receipts. Lab tools are temporary, bounded fixtures.

## 10. Complete observable feature inventory

**64 acceptance units** enumerate current M1–M18 surfaces/behaviors plus the
explicitly **planned M19** additions F60–F64. Count does not claim M19 exists.
Columns record source/user value; native stimulus; telemetry and service oracle;
UI and persistence oracle; negative control; existing native evidence and new M20
need. `P:` is expected persisted state; `none` explicitly means no new store.
All rows require fresh candidate evidence. Existing evidence codes: **H** historical
native scoped evidence, **O** offline/synthetic only, **N** new planned behavior.
H never substitutes for current-candidate native PASS. S numbers refer to §11.

| ID | Source / user value | Stimulus | Expected telemetry → detector/service | Expected UI; persistence | Control | Prior / remaining M20 evidence |
|---|---|---|---|---|---|---|
| F01 | Dashboard/statistics: activity overview | S01/13/49 | Actual snapshot/event/window counts; no bandwidth fiction | Counts/health/windows; P: underlying histories only | C01 | H beta; current counters/soak |
| F02 | psutil Connections TCP IPv4/IPv6 | S01 | Held owned sockets visible within polling; lifecycle refs | Endpoints/state; P: history/session refs | C01 | H loopback; owned peer IPv6 if supported |
| F03 | UDP endpoint visibility | S02 | Local endpoint, optional remote; no UDP session claim | UDP/unavailable remote; P: history | C02 | O; native socket |
| F04 | Connections models/filter/pause/sort | S01/49 | Engine continues; stable row/raw sort keys | Selection/filters/paused view; P: no UI-only filter writes | C03 | O; native interaction under churn |
| F05 | Process name/path/availability | S04 | Best-effort fields/denied codes, bounded reads | Plain text/reasons; P: historical snapshot | C04 | H beta; field-specific comparison |
| F06 | Parent observed context | S04 | Validated parent identity or absent/denied/reused | Observed qualifier; P: parent snapshot | C04 | O; own parent-child and exit race |
| F07 | Instance/PID/lifecycle identity | S05 | PID+create-time and new lifecycle; no merge by PID | Stable correct selected process; P: separate refs | C05 | O; native restart, deterministic reuse supplement |
| F08 | Path-based application/revision identity | S06 | Same-name paths separate; replacement invalidates revision | Scope/unknown; P: baseline revision scope | C06 | O; local copies/replacement |
| F09 | On-demand hash | S06 | Bounded disk bytes/read failure/cache invalidation | SHA-256/context limits; P: existing baseline revision only where supported | C06 | O; native local file proof |
| F10 | Offline signer | S07 | Embedded/catalog/unsigned/unknown, revocation not_checked | No safe/malware verdict; P: signer not persisted | C07 | H signer spike; final on-demand UI |
| F11 | Conservative network scope | S44/45 | Exact IPv4 local-address match or unknown/ambiguous | Honest scope; P: supported current history scope | C08 | H VPN; fresh transition/readback |
| F12 | History checkpoints/restart gaps | S01/47 | Last actual observation; no invented close/coverage | Gap/legacy/duration; P: session/checkpoint | C09 | H restart; long socket/crash recovery |
| F13 | History pagination/query generation | S49 | Bounded worker reads; stale page ignored | Filters/pages/details stable; P: read-only | C03 | O; large native fixture UI |
| F14 | Devices explicit passive capture | S08/51 | Selected current interface, bounded queue, no implicit start | Start/Stop/capability; P: normalized metadata only | C10 | H passive lab; current start/stop/change |
| F15 | Device/binding history & discovery | S08 | Warm-up excludes initial import; new network+MAC info | New/known/last-seen; P: device/bindings | C11 | H M4; new/known native control |
| F16 | Device label/note/trust/expected identity | S09 | User profile separate from observations | Save/Cancel/local trust; P: profiles/expected members | C12 | O; native edits/restart |
| F17 | Device identity/churn rules | S09 | Unexpected MAC/IP rules, DHCP/private MAC conservative | Explained profile alert; P: alert/evidence | C12 | O; controlled identity stimuli |
| F18 | Gateway baseline/verification | S10 | Current context exact gateway, learned/pending/verified | Baseline qualifier; P: gateway baseline/change | C13 | O; owned isolated gateway context |
| F19 | Gateway MAC-change detector | S10 | Repeated conflicting sender; scope/confidence limits | Suspected anomaly only; P: alert | C13 | O; header stimulus, no interception |
| F20 | IP-MAC conflict | S11 | Same scoped IP conflicting MAC in policy window | Conflict/reason; P: alert/binding evidence | C14 | O; bounded owned-LAN frames |
| F21 | ARP correlation/risk | S12 | Independent related signals; no fabricated MITM proof | Severity/confidence/evidence; P: alert context | C15 | O; native signal combination |
| F22 | Broadcast/multicast classification/metrics | S13 | Correct categories/no double count/window/quality | Dashboard rates/window; P: no raw payload | C16 | O; bounded frame observation |
| F23 | Broadcast/ARP rate/hysteresis | S13/14 | Threshold/confirmation/cooldown/recovery | Rate alert then recovery; P: alert lifecycle | C17 | O; native full windows |
| F24 | VLAN parser/summary/baseline | S15 | Single tag/untagged/QinQ/malformed qualifiers | VID/count/offload limit; P: aggregates | C18 | O; native visibility preflight + fixture fallback |
| F25 | VLAN anomaly/verification | S16 | Verified baseline unexpected tag/device switch/diversity | Explicit limits; P: baseline/alert | C18 | O; conditional native tag delivery |
| F26 | Classic DNS transactions | S17 | Query/matched/orphan/timeout A/AAAA/CNAME metadata | Status/latency/answers; P: canonical DNS refs/history | C19 | O; controlled resolver |
| F27 | DNS config detector | S18 | Repeated Windows server-set change scoped; reorder neutral | Link to server-change alert; P: alert, existing config state | C20 | O; operator config/restore |
| F28 | DNS table/filter/detail | S17/19 | Bounded query/filter generations | Pages/query/response/limitations; P: read-only | C19 | O; native resolver UI |
| F29 | Domain association/ambiguity | S19 | Network/client/TTL/CNAME candidates; many-to-many | Correlated/ambiguous, not process attribution; P: associations/source IDs | C21 | O; native shared answer |
| F30 | DNS expiry/restart/encryption limits | S20/21 | TTL expiry, no DoH content inference | Unknown/expired/unobservable; P: retained source context | C22 | O; native expiry/restart |
| F31 | Local ASN/country dataset | S22 | Default not_configured; licensed synthetic prefix lookup | Source/version, not physical location; P: config path, no new report | C23 | O; native presentation + injected public lookup |
| F32 | Baseline accumulator/coverage | S23/49 | INITIAL/gaps excluded; monitored-time and hard caps | Learning/quality/features; P: bounded aggregates | C24 | H VPN baselines; measured learning |
| F33 | Baseline persistence/stale/version | S23/47 | Restart warm-up/reference, no downtime window | Honest reference freshness; P: baseline | C24 | O/H restart; stale/version supplements |
| F34 | Novelty/rarity | S24 | Pre-mutation READY check, eligibility/reason | Explained concern only; P: assessment/eligible alert | C25 | O; native controlled destinations |
| F35 | Frequency/diversity | S25/26 | Comparable coverage/reference/confirmation gates | Observed appearances, not OS connect count; P: assessment | C26 | O; real timed windows |
| F36 | Periodicity | S27 | ≥5 eligible intervals, polling/gap limits | Candidate not C2 verdict; P: supported assessment | C27 | O; native periodic fixture |
| F37 | Baseline scoped reset | S28 | Confirm selected learned scope only | Reset/Cancel/pending; P: scoped reference reset | C28 | O; native action/readback |
| F38 | Explainable risk/revisions | S30 | Policy/contributors/quality, commit then alert, no double count | Historical revision/freshness; P: assessment versions | C25 | O; actual runtime risk + revision seam |
| F39 | Mark-normal/preferences/audit | S29 | Narrow stable application/rule, expiry/revoke, fail-open errors | Preview/lifetime/explanation; P: prefs/audit | C29 | O; native Save/Cancel/restart |
| F40 | Suppression vs risk/trust | S29/30 | Eligibility changes, evidence/score retained | Current preference vs historical assessment; P: existing evidence remains | C29 | O; native matched/unmatched scopes |
| F41 | Alert list/details/lifecycle | S31 | Dedup fingerprint/count, ACK/RESOLVE/reopen policy | Filters/evidence/commands; P: alert rows | C30 | O/H beta; positive native lifecycle |
| F42 | Notification eligibility/visible popup | S34 | Committed eligible intent; cooldown; OS may suppress | Generic privacy text/click exact alert; P: enable preference, no replay | C31 | H native ON/OFF; translated candidate |
| F43 | Incidents correlation boundary | S32 | Normal desktop no producer; explicit API groups exact refs | Empty valid / test-seeded explained group; P: incident only in explicit seam | C32 | O; native empty + labelled seam |
| F44 | Incident lifecycle/persistence | S32/33 | Separate ACK/RESOLVE/reopen/dedup lineage | Lifecycle independent of alert; P: incident revisions | C32 | O; native read, explicit service supplement |
| F45 | Incident timeline/source expiry | S33 | Observation/assessment/action times distinct, bounded pages | Unresolved/expired/read-only timeline; P: retained explanation | C32 | O; seeded native UI + source-expiry seam |
| F46 | TI consent/manual/private-IP guard | S35/36 | Default zero; Save/selection no lookup; private rejected | Sent-data/credential status; P: consent | C33 | O/H default; native tracing scope |
| F47 | TI cache/scheduler/provider states | S37/38 | HIT/NO_HIT/stale/offline/429/revoke bounded | Supporting context/errors; P: bounded cache | C33 | O; labelled injected transport native UI |
| F48 | TI assessment enrichment | S37 | Revision context only; numeric v1/occurrence unchanged | Historical TI provenance; P: revision pointers | C33 | O; controlled service seam, no real API needed |
| F49 | Diagnostics/capability/retry/degraded | S04/51/49 | Available vs Running, queue/loss/errors sanitized | Readable summary/technical expansion; P: bounded log only | C04 | H beta; native driver/token cases |
| F50 | Retention/purge/protected records | S50 | Opt-in bounded cleanup; active/trust/custody protected | Preview/confirm/cancel/source expiry; P: eligible deletion | C34 | H beta scoped; detailed current readback |
| F51 | Sanitized support/feedback export | S50 | Full immutable preview/atomic Save, allowlist/64KiB | Local Save; no Send/upload; P: chosen local sanitized file | C34 | H beta; current privacy/bytes compare |
| F52 | Offline/privacy/config/logging | S35/50 | Bounded config/rotation, zero default TI/update traffic | Honest disabled/unknown; P: local config/logs/DB | C33 | H/O; measured offline and secret scan |
| F53 | Tray/close/recovery/quit | S48 | Hide continues, unavailable tray restores/quit | Show/Hide/Quit/current language; P: close preference | C35 | H beta; final candidate native |
| F54 | VPN/network disconnect/sleep | S44–47 | Conservative scope, gaps, no fabricated coverage | Recovery/quality; P: true observed checkpoints | C08 | H VPN + physical S3; VM/current evidence required |
| F55 | Backpressure/soak/shutdown | S49 | Config caps, losses explicit, bounded stop | Responsive navigation/diagnostics; P: healthy stores | C03 | O/H scoped; sustained native measurement |
| F56 | Per-user installer/repair/upgrade | S51/52 | Verified packaged resources/asInvoker/data separation | Wizard + first launch; P: preserved config/DB | C36 | H NS-104; M19 resource candidate |
| F57 | Uninstall KEEP/DELETE/custody | S43/53 | KEEP default, unresolved custody refuses DELETE | Exact local recovery/English installer; P: KEEP or confirmed safe deletion | C36 | H NS-104; repeat current candidate |
| F58 | Manual response UI/deployment limit | S39 | Explicit preview/Cancel/typed NO_GO; no runtime write | Collateral/privilege/Undo limits; P: read custody | C29 | O; native asInvoker denial path |
| F59 | Adapter ownership/audit/reconcile/Undo | S40–43 | Exact full manifest/witness equality; partial/denied no false success | Current custody/audit; P: schema020 lifecycle | C30 | H NS-104; test-only native adapter, no shipped-write claim |
| F60 | Planned language bootstrap | S51/56 | Explicit first-language action only | Autonyms/English recovery; P: confirmed language | C36 | N; NS-110 + current M20 native |
| F61 | Planned 18 catalogs/fallback | S54/55 | Allowlisted offline resources, locale generation | All text/format/script readable; P: language ID only | C36 | N; catalog review + native classes |
| F62 | Planned repeated Settings switching | S54 | Atomic preference/load/retranslation or tested restart mode | Current/pending/no stale language; P: independent preference | C29 | N; repeated/open-dialog native |
| F63 | Planned interactive guide | S56 | Read-only page-aware steps, safe unavailable targets | Next/Back/Skip/Finish/keyboard; P: acknowledged state only | C10 | N; beginner/native UX |
| F64 | Planned guide replay/versioning | S52/56 | Legacy no force, future version preserved, no consent reset | Settings/Help replay/current language; P: completed/dismissed versions | C36 | N; upgrade/restart/replay |

No silent exclusions: per-flow bytes, exact DNS→process causality, universal
DoH/DoT visibility, process event telemetry, dedicated scan/malware verdict,
automatic incident production, default dataset coverage and usable desktop TI
credentials are **not current capabilities**. Their unknown/unavailable/no-claim
behavior is tested rather than implementing them. Parent/signature/source race
and local-admin tampering cannot be universally proven; alternative deterministic
fixtures document those limits. No new feature is authorized to close a test gap.

## 11. Native/adversarial matrix and benign controls

**56 scenario families** S01–S56, each instantiated with bounded receipts.
These include adversarial-shaped metadata, benign lifecycle and native UI cases;
they are not 56 promised attack detectors. Modes: **N** actual native final-product
behavior; **A** isolated native adapter/service test composition; **X** deterministic
supplement for uncontrollable races/transport/time; **V** native visibility gate.
Each family records these modes separately. Test-seeded DB/UI results are A/X,
never proof normal installed runtime produced them. All scenarios are NOT RUN now.

Every receipt inherits verified candidate/topology/config, before/after storage,
expected alert/incident semantics, referenced control and explicit cleanup.
Unless specified, no new alert/incident is promised; query-only UI must not mutate
state. Actual detector prerequisites and thresholds are extracted in NS-111, not
changed to manufacture PASS. Native packet visibility must be proven first.

| Scenario / task | Bounded stimulus and preconditions | Expected telemetry/service/alert and UI/persistence oracle | Mode / control |
|---|---|---|---|
| S01 / NS-112 | Owned held TCP listeners, IPv4 and supported lab IPv6, long-lived plus close/reopen | Poll observation/current row/history lifecycle and ≥30s checkpoint; no exact connect/FIN or per-flow bytes claim | N; C01/C09 |
| S02 / NS-112 | Own UDP bind/send/close | UDP local endpoint optional remote visible, no invented session/attack alert | N; C02 |
| S03 / NS-112 | Capped Kali→Windows TCP probe pattern and Windows→Kali outgoing churn, separated directions | Incoming scan need not appear as outgoing process rows; no dedicated scan verdict. Outgoing observed rate only if baseline gates hold | N; C03/C26 |
| S04 / NS-112 | Owned parent-child clients; parent exit and read-restricted process | Fields/identity/availability versus OS fixture; no historical lineage or raw errors | N+X race; C04 |
| S05 / NS-112 | Client restarts; bounded PID churn | New create-time/lifecycle, stable path identity; actual reuse if observed, otherwise native NOT OBSERVED + deterministic reuse proof | N+X; C05 |
| S06 / NS-114 | Same-name local harmless executables at different paths, stopped-file replacement, hash reread | Distinct app scopes/revision invalidation, digest agrees with fixture; no executing arbitrary downloaded binary | N; C06 |
| S07 / NS-114 | Known Windows signed/catalog executable and harmless unsigned fixture; access-denied file | Signer states/revocation limits, no safety score by signature; no provider network needed | N+X API faults; C07 |
| S08 / NS-113 | Explicit capture, initial inventory then owned new MAC observation | Initial import neutral; new-device warm-up info only; device/binding persistence and Stop cleanup | N; C10/C11 |
| S09 / NS-113 | Save expected owned identity; bounded unexpected MAC/IP observations and restart | Profile independent, device identity/churn rule evidence, normal DHCP/random MAC no unsupported HIGH | N; C12 |
| S10 / NS-113 | Isolated virtual gateway role on Kali/no forwarding; repeated different sender MAC for owned gateway IP | Actual gateway context/baseline/pending/verified and MAC-change evidence, suspected signal not confirmed interception | N+V; C13 |
| S11 / NS-113 | Small owned-IP/MAC conflict frame sequence within detector window | Scoped conflict evidence, dedup/count/readable alert after actual capture | N; C14 |
| S12 / NS-113 | Related gateway/conflict sequences vs unrelated/single signals | Correlation confidence/reasons; no fabricated independent signals/MITM proof | N; C15 |
| S13 / NS-113 | Capped broadcast/multicast at baseline then sustained above existing threshold | Correct metrics/category; confirmed rate/hysteresis/cooldown/recovery alert and Dashboard | N; C16/C17 |
| S14 / NS-113 | Capped ARP rate full windows then recovery | ARP rate rule/drops/quality shown; no storm, recovery policy preserved | N; C17 |
| S15 / NS-113 | Few tagged/untagged/QinQ/malformed synthetic frames across owned NIC pair | Observe actual delivered tag or record offload/VMware gap; summary/no guessed tag | V+X; C18 |
| S16 / NS-113 | After supported verified baseline, bounded new VID/device tag/diversity | Existing VLAN rule only when capture and policy prerequisites hold; fixtures supplement missing native transport | V+X; C18 |
| S17 / NS-114 | Controlled Kali DNS answers A/AAAA/CNAME and delayed/missing/orphan responses | Transaction statuses/latency/canonical IDs, pagination/detail; no invented DNS malware alert | N; C19 |
| S18 / NS-114 | Operator changes lab DNS set, repeated polls; reorder/transient read control; restore | Existing dns_server_set_change evidence only after confirmation; link in DNS/Alerts | N+X transient; C20 |
| S19 / NS-114 | Two `.test` names same owned IP, bounded CNAME, distinct client | CORRELATED/AMBIGUOUS exact scope/TTL/provenance, no PID causality | N; C21 |
| S20 / NS-114 | Short TTL, restart and retained source query | Expired/unknown association, source history retained according to policy; no resurrected TTL | N; C21 |
| S21 / NS-114 | Controlled encrypted-DNS-shaped HTTPS / cached DNS comparison | Socket observable where held; no classic DNS payload claim; no need to decrypt/disable TLS | N+X precise encryption limit; C22 |
| S22 / NS-114 | Default no dataset, approved synthetic local prefix file, malformed reload | Native not_configured/private not_applicable; injected public lookup matches source/version, failed load safe | N+A; C23 |
| S23 / NS-115 | Stable client path/scope, ≥20 observed appearances and ≥600s clean coverage; restart | Real learning/READY/quality/persisted reference, INITIAL/gap not training samples | N; C24 |
| S24 / NS-115 | Known/new/rare controlled peer destinations after READY; rarity ≥100 samples policy | Pre-mutation novelty/rarity reasons, persisted assessment and eligible alert, not malware | N; C25 |
| S25 / NS-115 | Controlled rate increase after full independent reference/current windows | Appearance rate policy: current ≥120s/20 appearances, reference/confirmation/cooldown extracted; explain qualified result | N; C26 |
| S26 / NS-115 | Bounded ≤configured cap destinations/owned address aliases, independent reference windows | Diversity gates (default ≥10 current destinations, ≥3 reference windows) and quality; no Internet scan to meet counts | N; C26 |
| S27 / NS-115 | Harmless scheduled client ≥5 intervals at supported period, jitter/gap comparison | Periodic candidate/limited/irregular evidence; no confirmed beacon/C2, no repeated count for held socket | N; C27 |
| S28 / NS-115 | Baseline reset preview/Cancel then confirmed one scope | Only learned reference reset, unrelated trust/preferences/history preserved | N; C28 |
| S29 / NS-115 | Mark-normal preview/Cancel/Save/expiry/revoke, other scope control | Audit/policy persistence, matched eligibility only; risk evidence preserved; denied/failure typed | N+X expiry/fault; C29 |
| S30 / NS-115 | Real qualified behavior signal then explicit supported reassessment | Contributors/quality/policy/revisions; no occurrence/time/ACK overwrite; legacy ARP remains | N+A revision; C25/C30 |
| S31 / NS-115 | Repeat same qualified signal, ACK/RESOLVE/reopen conditions and restart | Exact fingerprint lifecycle/count policy, no replay increments; UI evidence readback | N+X boundary times; C30 |
| S32 / NS-115 | Observe normal installed Incidents, then separate explicit API composition with native-derived refs | Normal empty state valid; A records exact relations, not same-IP causal fiction; incident lifecycle independent | N+A; C32 |
| S33 / NS-115 | Explicit incident story, source purge/expiry, long timeline pages/restart | Retained explanation, unknown/expired status, time-kind/order and pagination; no GUI write side effects | A+X; C32/C34 |
| S34 / NS-115 | Native eligible alert or clearly labelled safe alert fixture, OFF→ON, duplicate/escalation/click/OS suppression | Counts distinguish intent/submit/delivered/click; generic translated text, exact alert target, no historical replay | N+A fixture; C31 |
| S35 / NS-116 | TI OFF, offline adapters, startup/details/consent UI across real local stimuli | Zero default provider requests; local detection continues, no updater/history upload | N+X network-denial assertions; C33 |
| S36 / NS-116 | Enable consent then explicit selected lookup in normal desktop; private/local guard | Save sends nothing; unavailable credential shown, no pretend HIT/live success; private target rejected | N; C33 |
| S37 / NS-116 | Separate injected normalized HIT/NO_HIT/stale/conflicting fake provider results | Scheduler/cache/UI/provenance and revision seam; numeric policy unchanged, no safe/malware/auto-block claim | A; C33 |
| S38 / NS-116 | Fake transport offline/timeout/429/oversize/redirect, duplicate pending, revoke | Budget/backoff/redaction/typed states, revoke prevents pending requests; no real public API or secret | A+X; C33 |
| S39 / NS-117 | Installed asInvoker response preview/Cancel/Confirm and Undo unavailable state | No native privileged write; typed NO_GO/denied and local trust still works, no automatic UAC | N; C29 |
| S40 / NS-117 | Separate explicitly elevated test-only exact host-only adapter harness create/read/effect/confirmed Undo | Owned scoped rule blocks new target traffic, independent executable unaffected, manifest/audit readback/removal; not shipped UI write proof | A; C30 |
| S41 / NS-117 | Operator edit/missing/duplicate matching test rule | Full fresh equality/ownership refuses unsafe Undo/adoption; unrelated inventory exact | A; C30 |
| S42 / NS-117 | Interrupt test-owned CREATE/REMOVE stages, DB/COM faults, restart, genuine restricted token | PREPARED/FINAL/UNKNOWN/PARTIAL/ACCESS_DENIED honest; no false cleanup; bounded reconciliation | A+X faults; C30 |
| S43 / NS-117 | Uninstall with unresolved recorded rule/unknown custody then verified explicit cleanup | Recovery list local, DELETE refused, KEEP safe; no installer firewall dispatch/elevation | N+A rule setup; C36 |
| S44 / NS-118 | Separate authorized benign private WireGuard NAT phase; connect/disconnect | Actual route/handshake/peer counters, conservative scope/DNS, no false high or baseline merge | N; C08 |
| S45 / NS-118 | Disconnect/reconnect/change owned lab NIC/context | Loss/gap/retry, no fake closure/coverage, capture selection freshness, restored data | N; C08/C09 |
| S46 / NS-118 | Genuine supported Windows guest sleep/resume with live monitor | Power-event/timing proof + same/recovered app/queues/history; VMware pause is not S3 | N+V; C09 |
| S47 / NS-118 | Three app restarts, controlled abrupt app loss and one Windows reboot | Config/consent/baseline/history/custody retained, gap semantics, no autostart or replay | N; C05/C09 |
| S48 / NS-118 | Default X Quit, opt-in Hide, Show, tray Quit/unavailable tray | Hidden monitoring continues; translated actions, bounded exit/no ghost | N+X unavailable; C35 |
| S49 / NS-118 | ≥2h bounded native session incl ≥30min steady benign, ≥30min capped churn, return to idle | Queue/capacity/loss/CPU/RSS/DB/WAL/heartbeat samples, no unbounded retained state/corruption; recovery/restart | N+X saturation; C03 |
| S50 / NS-116 | Storage summary, opt-in retention/purge, Cancel, support/feedback preview→Save, faults | Protected active/trust/audit/custody and retained explanations; exact sanitized bytes/64KiB/atomic cleanup, no upload | N+X failure; C34 |
| S51 / NS-119 | Fresh standard profile, verified installer offline, Npcap absent then separately approved present environment | Correct payload/catalog/schema020/asInvoker/data roots; language question/defaults/degraded honest | N; C10/C36 |
| S52 / NS-119 | Supported pre-M19 schema019/020 upgrade and repair, Unicode/space path, old config | Append-only migration/data/config/guide/language/custody preserved; resources/inventory match final artifact | N; C36 |
| S53 / NS-119 | KEEP, reinstall, explicit DELETE without unresolved custody, external export control | Data preserved on KEEP; confirmed bounded DELETE only owned data, outside export safe, no secure erase claim | N; C36 |
| S54 / NS-119 | All languages load; repeated Apply/Cancel/restart, open dialogs/late result, invalid/missing pack | Tested runtime or restart-mode contract; coherent generation/fallback/formatting/persistence, no permission changes | N+X broken pack; C29/C36 |
| S55 / NS-119 | tr/en/de/ru/ar/ja/ko/zh scripts + all-locale smoke at supported scaling | RTL/LTR technical evidence, glyphs/wrapping/focus/accessible controls; tray/future popup language | N; C31/C36 |
| S56 / NS-119 | Never-shown/legacy/v1/v2/future versions, Next/Back/Skip/Esc/Finish/Settings replay, missing target | Localized guide, preserved acknowledgements, immediate exit, no repeated force/permission changes, restart proof | N; C10/C36 |

### Benign/false-positive controls — 36 distinct control families

Each C row produces its own observed result/receipt and is paired above; shared
controls are not multiplied into fictitious counts. Ordinary traffic may produce
explainable low concern: acceptance checks unjustified claims/burden, not a blanket
promise that benign equals zero alerts.

| ID | Benign/negative stimulus | Expected control result |
|---|---|---|
| C01 | Normal browser to owned web endpoint and held TCP | Correct rows; no bandwidth/malware inference |
| C02 | Ordinary owned UDP DNS/echo endpoint | No guaranteed remote/session/UDP-attack finding |
| C03 | Small benign burst, view pause/filter and idle | Monitoring continues, responsive UI, no invented storm |
| C04 | Ordinary child + absent/denied metadata | Unknown/observed honest, no security escalation by absence |
| C05 | Same client restart vs new instance | History separate, baseline path continuity only where eligible |
| C06 | Unchanged harmless file/read | Stable digest/revision/cache, no false replacement |
| C07 | Signed and unsigned harmless files | Neither signature state yields safety/malware certainty |
| C08 | Normal VPN/network-context transition | No cross-scope contamination/unjustified HIGH |
| C09 | Long-held TCP across checkpoint/downtime | No fake reconnect, FIN time or downtime coverage |
| C10 | Fresh guide/capture OFF/missing driver | No passive socket until explicit Start, usable supported core |
| C11 | Initial/imported/known device ARP repeat | No spurious new-device rediscovery |
| C12 | One DHCP renewal + expected randomized MAC | No unjustified MAC/HIGH spoofing conclusion |
| C13 | Stable gateway/gratuitous refresh/new scope | Baselines scoped, no single-frame interception claim |
| C14 | Stale/out-of-order or different-scope MAC observation | No false same-scope conflict |
| C15 | Single/unrelated ARP signals | No inflated independent correlation/confidence |
| C16 | Ordinary multicast/LAN discovery | Correct category; no broadcast double count |
| C17 | Short normal ARP/broadcast burst then idle | No sustained-rate confirmation/storm |
| C18 | Stable tagged/untagged traffic/driver-stripped tag | No invented VID/offload attack certainty |
| C19 | Ordinary controlled browsing DNS A/AAAA | Correct transaction, no DNS-malware detector invention |
| C20 | DNS server order-only change/new interface | No same-context server-set change false positive |
| C21 | Same DNS evidence repeat/TTL=0/shared IP | No fake uniqueness, causality or expired active association |
| C22 | Cache hit/encrypted browsing | Classic DNS absence not fabricated zero queries or threat |
| C23 | Private/unknown address and no local dataset | not_applicable/not_configured, no physical-location claim |
| C24 | Cold/INITIAL/insufficient/gapped baseline | No READY/high-confidence training from missing coverage |
| C25 | Established destination and normal CDN-like owned alias | Explainable familiarity/novelty, no malware verdict |
| C26 | Bursty benign updater-like client/file download | Policy gates hold; no scan/C2 label from burst alone |
| C27 | Harmless periodic updater and irregular client | Candidate with benign caveat, no confirmed beacon |
| C28 | Reset Cancel and unrelated baseline scope | No write on Cancel; other reference/trust unchanged |
| C29 | Preference/language/response Cancel, unmatched rule scope | No mutation/overbroad suppression/consent coupling |
| C30 | Canonical replay and unrelated firewall executable/rule | No duplicate occurrence, lifecycle corruption or collateral write |
| C31 | Notifications OFF/duplicate/restart/OS suppression | Zero OFF popups/replay; submit not visible-delivery proof |
| C32 | Same-IP unrelated process/no explicit incident producer | No causal/same-IP merge; empty normal list valid |
| C33 | TI disabled/offline/no secret/revoke/private IP | No unauthorized request, local detector remains operational |
| C34 | Purge/export Cancel and protected active/trust/custody | Protected records/file remain; no secret/raw-history leak |
| C35 | Normal visible launch/tray unavailable | Reachable window or clean Quit, no hidden orphan |
| C36 | Existing acknowledged config/KEEP/external export/language Cancel | Upgrade/replay preserves data/state and outside-root files |

## 12. M20 task breakdown and dependency graph

| ID | Frozen title | Dependencies |
|---|---|---|
| NS-111 | Lab topology, feature inventory & frozen acceptance matrix | NS-110, NS-104; explicit future M20 authorization |
| NS-112 | Core telemetry & process end-to-end validation | NS-111 |
| NS-113 | LAN / ARP / broadcast / VLAN validation | NS-112 |
| NS-114 | DNS / destination / executable context validation | NS-112 |
| NS-115 | Baseline / risk / alerts / incidents / notifications validation | NS-113, NS-114 |
| NS-116 | TI / privacy / storage / offline validation | NS-115 |
| NS-117 | Manual response / firewall / custody validation | NS-112, NS-104 |
| NS-118 | Lifecycle / VPN / recovery / native stability validation | NS-112 |
| NS-119 | Installer / localization / onboarding full acceptance | NS-116, NS-117, NS-118 |
| NS-120 | Final adversarial & benign product completion gate | NS-111–119 |

NS-111 must cover all F rows after M19, adding any newly exposed behavior before
matrix freeze. NS-112 owns S01–05, NS-113 S08–16, NS-114 S06–07/S17–22,
NS-115 S23–34, NS-116 S35–38/S50, NS-117 S39–43, NS-118 S44–49,
NS-119 S51–56. NS-120 aggregates, does not rerun everything without cause.
VLAN/notifications/storage/stability are explicit additions to the proposed titles;
no numbering changes. Dependency edges only point to earlier tasks; no cycle.
Full exact work/files/criteria/tests/exclusions/gates are in appended TASKS records.

## 13. Evidence/receipt model and performance budgets

Every native scenario/control has a **bounded structured receipt** (proposed
`m20-receipt-v1`) and an artifact index. Required fields:

```text
scenario_id, feature_ids, task_id, candidate_source_hash, installer_sha256,
payload_inventory_digest, catalog_inventory_digest, evidence_mode,
environment (OS/build, token class, Qt/Npcap, viewport/scaling, topology alias),
preconditions, stimulus (owned aliases, rate/count/duration caps),
expected_telemetry, expected_detector_service, expected_alert,
expected_incident, expected_ui, expected_persistence, negative_control_ids,
observed_result (bounded counters/status/time ranges), assertion_results,
result (PASS/FAIL/NOT_RUN/BLOCKED/NOT_APPLICABLE), limitations,
evidence_refs (sanitized hashes/query IDs/screenshots), cleanup_result
```

No result field is prefilled PASS. NOT_APPLICABLE needs a frozen feature/scope
reason; unavailable environment is BLOCKED/NOT_RUN, not N/A. Receipt ≤64KiB;
arrays ≤100 entries each, strings ≤2048 characters. Split oversized evidence into
bounded indexed receipts; no huge logs, packet dumps, credentials, keys, raw
provider responses, unnecessary hostnames/usernames/process paths or real browsing
history. Exact sensitive rule recovery remains VM-local. Shared evidence uses
fixture aliases/counts/digests. Inspect before saving/sharing; no automatic upload.

Use explicit typed DB/repository readback (table/record/ref/revision/count/UTC),
structured diagnostics/read models, known fixture process identity and socket
state, UI selected IDs/widget texts/roles, screenshot geometry/glyph proof and
full unrelated firewall inventory comparison. UI observation alone cannot prove
DB writes, zero network requests, rule ownership or cleanup. Correlate before/after
OS+DB+UI. Read a coherent backup/snapshot or read-only connection; no direct
production DB fabrication. Separate operational browsing from synthetic UI assets.

Network zero-request proof pairs native process-scoped observation where
available with deterministic forbidden-network assertions; document observation
blind spots and OS background traffic separately. Signer cryptsvc traffic is not
assumed measured from adapter flags alone. Native popup proof requires actual
delivery/click evidence, not accepted sink submission. Current HASH/signature
checks do not prove running-memory integrity.

Performance protocol derives from [NS-049 budgets](ARCHITECTURE.md),
[incident soak](INCIDENT_ACCEPTANCE_SOAK.md) and [beta protocol](BETA_PROTOCOL.md):

- Freeze current configured hard caps before stimulus: capture1024, history/DNS
  queues2048 each/batch64, Qt bridge1024, risk128 pending+1 active, notification
  queue32/state512/sink handles8, baseline512 stored/128 loaded (verify candidate
  values), timeline256 loaded rows, worker-specific coalesced query slots and
  schema020 response audit quotas. Measure admission/drop/health rather than
  claiming every observed socket must be retained under overload.
- Native ≥2h S49, actual timestamps/active monitored duration and ≤60s sample
  spacing for RSS/private bytes/CPU/DB/WAL/queues; UI heartbeat also during load,
  then drain/idle/restart. Repeated cycles must not accumulate owned workers,
  translators, handles or retained state beyond caps. Flat RSS is not promised;
  unexplained sustained growth or loss without diagnostics blocks acceptance.
- DB growth can be legitimate with retention default OFF; report logical rows
  and main/WAL bytes separately. With explicit retention ON, eligible cleanup
  obeys its configured limits; protected active data remains. No universal disk
  cap or secure erase/shrink guarantee. Native CPU/throughput are descriptive;
  no fabricated FPS/CPU-percent/RSS SLA. NS-111 freezes environment-specific
  responsiveness review criteria before results using baseline samples; stalls
  and unbounded queues remain objective failures regardless of CPU benchmark.
- Existing shutdown joins/timeouts and queue caps remain primary criteria;
  synthetic NS-049 3.5s combined guard is not a universal native SLA. Record native
  elapsed shutdown/pending jobs/no ghost; typed timeout must be visible and safe.
- Preserve beta false-positive review budget: zero unexplained HIGH or malware
  certainty; ≤5 benign/noise review demands per30min and ≤2 per individual
  benign scenario. Notifications OFF zero; ON ≤3 benign popups per30min, no
  duplicate/historical replay, existing120s cooldown with documented exceptions.
  Controlled positive fixtures are a separate population; don't count them as
  organic benign FP. Unresolved findings require classification before exit.

## 14. Safety boundaries and cleanup

Only isolated owned VMs and declared fixture targets; no public/third-party
attacks, exploit/credential attacks, malicious binaries, persistence or traffic
interception. ARP/MITM scenarios emit bounded header evidence for owned identities,
not an actual forwarding/poisoning campaign. Gateway fixture is disconnected from
external routes. NS-111 defines conservative rate/duration/stop caps; ceilings
come from detector windows and lab capacity, never flood-to-pass. Stop on escape
route, unexpected target, instability, policy block or cleanup uncertainty.

Restore NIC, route, DNS, neighbor/baseline fixtures and VPN to recorded prestate;
remove exact test-owned rules only after verified provenance/full equality,
listeners/temp files/keys, command processes and transient lab configuration.
Compare unrelated rule inventory/profile policies before/after. No prefix/group
delete or disabling Defender/App Control/Npcap security to pass. Failed cleanup
blocks subsequent mutation and final acceptance; retain local recovery evidence.
Admin actions are operator-reviewed separate test harness steps, never automatic
app elevation. Snapshot restore is a last resort only on the exact disposable VM
with verified ownership and approval, not blanket deletion of host/user data.

## 15. NS-120 final completion gate

Aggregate every receipt/control, feature coverage, candidate hashes, unresolved
failures, product limitations, FP/burden, stability/privacy/installer/localization/
response findings and cleanup. Record three independent decisions: functional
acceptance; in-product privileged deployment (still NO_GO); public distribution
(still NO_GO unless separate signing/distribution gate is authorized and passed).

| Decision | Criteria / consequence |
|---|---|
| **PASS** | NS-110 and NS-111–119 exact required criteria pass on final candidate; every F row has native evidence or the narrowly predefined alternative for an inherently unavailable capability, all required controls pass, critical localization reviewed, no unresolved blocker/major/required evidence gap, budgets met, cleanup proven. NS-120 may mark functional completion only in declared Windows/lab scope. |
| **CONDITIONAL_PASS** | No known critical defect/privacy loss/unsafe cleanup, but a required native environment, reviewer or measurable feature gap remains, or a bounded minor issue needs a named owner/condition/date. List exact conditions; keep NS-120 incomplete and **do not declare NetSentinel functionally finished** until conditions close and PASS is recorded. |
| **FAIL** | Any corruption/destructive upgrade/KEEP loss, protected/custody deletion, secret/raw-data leak, unauthorized request/write/elevation, unrelated firewall change, unsupported security certainty, unbounded storm/growth, essential guide/Settings/Quit inaccessibility, failed required behavior or unsafe cleanup. Fix in a separately scoped task, rebuild if payload changes, retest affected paths. |

Acceptable predefined alternatives are limited to: uncontrollable PID/TOCTOU races
(native ordinary restart + deterministic fault/reuse fixtures); VMware/NIC VLAN
tag stripping (native visibility limitation + full synthetic pipeline, no native
VLAN-detection PASS claim); production incident creation absent (native empty/read
UI + explicit labelled API persistence story); default TI secret backend absent
(native unavailable + injected fake transport); public ASN matches unreachable
without public targets (native not_configured + injected local dataset lookup).
These are known capability boundaries, not post-failure waivers. If actual
observability is worse than this frozen scope, raise a finding.

Genuine sleep: attempt supported guest sleep with OS event/timing proof. VMware
pause/resume is a separate transport case. If guest power model cannot exercise
real sleep, an explicitly authorized owned Windows physical fallback with current
candidate may supply native sleep evidence; otherwise S46 remains required/pending
and only CONDITIONAL_PASS is possible. Old host S3 evidence alone is not fresh
product proof. No waiver invented after failed tests.

Code/catalog/packaging changes during future validation invalidate affected hashes
and require new build identity/affected retests. A final gate does not authorize
new detectors or silently relax thresholds. Passing tests alone is insufficient.
Functional PASS is **not broad public release GO** and never opens privileged
desktop writes. M19 alone cannot close the project.

## 16. Deferred and out-of-scope

Automatic blocking/elevation, privileged persistent service/helper, WFP/custom
driver, malicious-local-admin protection, process termination, auto updater,
broad-release certificate/signing/distribution approval; additional detectors,
ETW/flow bytes/definitive DNS attribution, automatic incident producer, credential
backend/key-entry UI, online font/catalog/dataset updates, multilingual installer
and extra regional language variants. Defect remediation is separately scoped;
M20 is acceptance, not permission to expand production functionality.

## 17. Open implementation/environment decisions and planning checks

Frozen now: 18 IDs, first-launch rather than installer selection, Qt catalogs,
page-aware optional tour, existing config guide state, task ownership/dependency
graph, lab isolation, capability exclusions, completion versus release gates.

Open at the named gate (do not conceal as implemented): NS-105 toolchain versions/
placeholder extraction and runtime versus coherent restart mode; NS-107 reviewers,
Arabic terminology/CJK fallback fonts and redistribution license if bundling is
needed; NS-110 native Narrator/font/scaling availability; NS-111 exact VM snapshot,
Npcap/token, lab addresses/rates/timers, guest sleep capability/approved physical
fallback and current-candidate performance baseline. NS-117 test admin scope
remains explicit and does not resolve shipped-write NO_GO. Release signing and
maintainer distribution contacts remain separate owner decisions.

Planning validation must check unique NS-105–120 records, backward-only acyclic
dependencies, all eight task fields and start gates, requirement and F/S/C mapping,
Markdown table structure/links/counts, `git diff --check` and bounded changed-doc
privacy/secret scan. No full suite is required for this docs-only edit. NS-105
remains NOT STARTED; no implementation/native execution/build/commit/push/tag/release.

### Planning validation result — 2026-10-09

- NS-105–120: 16 unique sequential records, all PLANNED / NOT STARTED; all nine
  definition fields including start gate present. Dependencies reference existing
  earlier IDs only: acyclic. NS-107/109 inventory delta ownership avoids a hidden
  translation-review dependency cycle.
- Inventory: 59 current acceptance units + 5 planned M19 additions =64; 56
  scenario families,36 distinct controls (all paired),18 locale IDs. Requirement
  ownership and feature/scenario/explicit-alternative coverage reviewed.
- Local document links and Markdown table column consistency PASS.
- Bounded scan of this new file and TASKS/ROADMAP additions: no credential/token/
  private-key/JWT or raw personal user-path/IP/MAC matches; manual privacy review
  found only public source identity, fixture descriptors and policy text.
- `git diff --check` and new-file `git diff --no-index --check -- NUL
  docs/M19_M20_PLANNING.md`: PASS. Git's configured LF→CRLF notices are informational.
- Only three planning/docs files changed. Production source, migrations,
  translations, dependencies, tests, installers and VM state unchanged. Full
  suite not run for this docs-only request. NS-105 NOT STARTED; implementation,
  commit/push and tag/release NONE.

# NS-106 — First-launch language selection & persistence

Implementation review snapshot, 2026-10-10. Exact authority:
[TASKS NS-106](TASKS.md#ns-106--first-launch-language-selection--persistence),
including `ui_language` / `ui_language_confirmed`, language-only bootstrap before
the guide, autonym + English names, explicit Continue / Use English, X/Esc exit,
atomic reload/merge, failed-load/save rollback and current/pending restart mode.
NS-105's whole-application restart **NO_GO for live switching** stays frozen.

Checkpoint approval, 2026-10-10: the user approved NS-106 acceptance and authorized
committing only the reviewed NS-106 files and a normal push to `main`. The
commit/push NONE and unchanged HEAD entries below are the historical pre-checkpoint
review snapshot. Recorded test receipts remain unchanged; NS-107–120 are NOT
STARTED and tag/release remain NONE.

## Product and startup

Production `run_application` opts into language bootstrap in `create_application`:
QApplication → English bootstrap → bounded config load → chooser when
`ui_language_confirmed` is false → explicit stage/validate/save → effective locale
activation → seal → MainWindow, models, tray and coordinators → existing M17 guide
or normal lifecycle. Engine/services may be composed earlier but monitoring is not
started by language selection. No network, capture, permission probe, elevation,
consent, guide replay or automatic process restart is caused by the chooser.
`create_application` without bootstrap remains an internal embedding/test API;
tests opt in explicitly using temporary paths, never the real user profile.

Fresh profiles and pre-M19 users without confirmed preference get the question.
Legacy completed/dismissed/future guide acknowledgement is preserved; acknowledged
users receive only the language question. X/Esc/Cancel writes nothing and exits
bootstrap before normal window construction or lifecycle start; another launch
asks again. Selecting/highlighting a row writes nothing. Continue/Use English
validates and confirms. A new profile can suggest an exactly mapped, available OS
locale; legacy profiles default to English. No automatic language acceptance.

## Metadata, catalogs and recovery

`shared.locales` is the single Qt-free immutable metadata source: 18 stable BCP-47
IDs, Qt mappings, autonyms, English names and Arabic RTL flag. Read-only
`LanguageOption` values add validated catalog status and selectable state. All
18 names appear; unreviewed/missing/corrupt catalogs are visibly unavailable and
disabled. English is always selectable, has no QM requirement and is reachable
through a separate Use English button. NS-106 ships **zero non-English production
translations**; current production availability is **English only**. Real pseudo
QM injection is restricted to tests. Future NS-107 availability comes from the
existing allowlisted bundled manifest/digest/size checks and Qt loader, never
from a duplicate widget list or filesystem-derived locale name.

Unsupported/malformed/removed config values use English and bounded config issue
codes. A confirmed invalid preference does not force another bootstrap question;
startup displays a sanitized English-fallback notice. Missing/corrupt catalogs
retain a valid requested ID and confirmation on disk, use effective English and
report fallback. There is no automatic repair/write: a later explicit valid Apply
can replace the preference, or a restored pack can work on the next launch. This
avoids repeated modal failures while preserving the user's valid request.
Invalid unsupported raw values are not reflected into GUI text or diagnostics.

## Persistence and transactions

The existing per-user `%LOCALAPPDATA%/NetSentinel/config.json` holds typed
`ui_language` (allowlisted ID, default `en`) and `ui_language_confirmed` (strict
bool, default false). No second settings file or DB migration. Schema **020 →
020**. Upgrade and KEEP reinstall retain these fields with user data, independently
of onboarding, TI/privacy, notifications, storage, firewall custody and telemetry.

Apply stages a real catalog without installing it, reloads current config,
changes only language fields, and uses existing bounded tempfile + flush + fsync +
atomic replace. A settings write completed while the dialog was open is preserved.
Unknown forward fields are retained for this merge, while the existing loader's
unknown/invalid-field TI fail-closed policy still applies. No consent is restored
from a damaged document. Unparseable/unreadable/oversized root documents are not
overwritten by the language operation. Write failure leaves original file and
selected/effective state intact; temporary files are cleaned up.

There is no new global locking architecture. Two independent instances each
reload immediately before saving; successful atomic replacement is last-writer
wins. Same-field decisions from another instance appear on restart/reopen, not
as live translation. Simultaneous read/replace races have the existing settings
architecture's lost-update limit; atomicity protects complete documents, not
cross-process serializability. Neither machine restart nor application upgrade
changes the per-user persistence model.

Failed catalog validation never persists the failed choice. Save failure displays
only sanitized text and keeps bootstrap open for retry or Cancel. Bootstrap also
offers an explicit Continue in English without saving recovery action: no false
saved acknowledgement, no corrupt document rewrite, English session continues,
and next launch asks again. Settings Apply never changes the live translator;
Cancel closes without applying highlighted input. A prior successful Apply stays
saved if the dialog is subsequently cancelled.

## Current/pending state and accessibility

`LanguagePreferences.selected_locale` is the successfully persisted next-launch
choice. `effective_locale` comes from the sealed manager for this launch.
`restart_required` is their inequality. The reusable Apply/Cancel window displays
both names and explicitly requests user-controlled restart. Repeated Apply keeps
UI text, generation, direction, focus and widgets coherent in the current language;
no silent restart, MainWindow recreation or partial retranslation. NS-109 will
wire this foundation into Settings; no Settings/replay integration was added.

Immutable diagnostics expose selected/effective IDs, catalog outcome, fallback,
restart-required and invalid-preference flags only: no paths, raw config, secrets
or exception messages. Config loading keeps existing bounded issue codes.

The chooser uses Qt layouts, a scrollable Unicode list, plain-text wrapped status,
resizable logical-pixel geometry, accessible control names/descriptions, arrow
selection, explicit list→confirm→English→Cancel Tab order, Enter/default confirm
and safe Esc/window close. No flags, custom fonts, fixed screen coordinates or
network fonts. Offscreen tests verify representative Unicode names and compact
layout; native Windows DPI, glyph/shaping and Narrator acceptance stay NS-110.
Direction metadata is ready for Arabic; no full RTL redesign/acceptance claimed.

## Verification and remaining work

Changed deliverable files:

| Files | Responsibility |
|---|---|
| `shared/locales.py`, `shared/config.py` | Single 18-locale metadata, typed fields, validation, durable reload/merge |
| `presentation/i18n/manager.py`, `preferences.py` | Non-mutating catalog staging, current/pending state, bounded diagnostics, bootstrap |
| `presentation/widgets/language_settings.py`, `presentation/app.py` | Dedicated accessible chooser, reusable Apply/Cancel, startup/exit order |
| `tests/unit/shared/test_language_config.py`, `tests/gui/test_language_selection.py` | Fresh/legacy/future/invalid, persistence, Unicode/keyboard, failure and restart fixtures |
| `tests/gui/test_localization.py`, `tests/gui/test_capabilities.py` | Preserve NS-105 gates with injected availability; explicitly confirm the new bootstrap in existing production-startup tests |
| `translations/netsentinel_en.ts` | 19 additional English source keys; 1,932 strings / 120 contexts / 3 plural keys total |
| `docs/PRODUCT.md`, `ARCHITECTURE.md`, `LOCALIZATION.md`, this report | Behavior, boundaries, failure policies and measured acceptance |
| `docs/TASKS.md`, `ROADMAP.md`, `M19_M20_PLANNING.md` | NS-106 COMPLETE receipt/status only; frozen task requirements unchanged |

Verification uses installed Python **3.12.10** with the existing locked `.venv`
dependencies via `PYTHONPATH=src;.venv/Lib/site-packages`. The original uv Python
3.12.14's `_sqlite3`/`_overlapped` imports were blocked by Windows Application
Control, before test collection; no security policy was changed. Temporary test,
wheel and pip build paths are isolated under ignored `build/`. Pip's default
sandbox temporary path was unwritable; redirecting TEMP/TMP to `build/ns106-tmp`
allowed the same offline, no-dependency, no-build-isolation wheel build.

Targeted receipts: **169 passed** (new language/config, existing localization,
config, first-run feedback, extraction tooling and packaging resources);
**89 passed** after adding explicit language confirmation to the existing
production-startup test and verifying the final fallback-state correction.
An initial full run was interrupted when the old production-startup harness
waited for the newly required language choice. Its original QApplication/engine/
capture assertions remain, with language-before-guide assertions added.

Ruff configured source/tests/packaging/tooling: PASS. Configured mypy **41 files**:
PASS; direct i18n/language widget mypy **7 files**: PASS. Extraction/check: **1,932
strings, 120 contexts, 3 numerus keys, 87 unchanged reviewed exceptions**. Wheel
ZIP resource import: PASS, manifest empty, English-only availability, 18 metadata
entries, SQL001–020, no TS/pseudo QM/compiler. Final bounded privacy/secret scan:
**18 task text files**, PASS including documentation/status updates.
`git diff --check`: PASS.

Full offline receipt: **4,810 passed, 3 failed, 9 live deselected, 982.88 s**.
All three failures were the unchanged installer-junction fixture's sandbox
`cmd mklink /J` creation, before its guard assertions. The exact three cases
passed **3/3 in 1.38 s** outside the sandbox under automatically reviewed execution,
in a fresh, checked `build/tests-ns106-junction-native` root. Links and sentinel
targets stayed inside the workspace. Post-run audit: zero remaining reparse
points, three unchanged `unrelated` sentinels. All **4,813 selected cases verified**;
this is not represented as one all-green sandbox run. No skip/test/installer
change or live-marker bypass was added for these failures.

Coverage **91.43%**, configured **85%** gate retained and passed. NS-106 is
**COMPLETE** in its exact offline acceptance scope; no test/coverage gate weakened.
NS-107 production packs, NS-108 guide, NS-109 Settings/replay integration,
NS-110 native multilingual acceptance and NS-111–120 M20 work are **NOT STARTED**.
Pre-checkpoint review snapshot: commit/push/tag/release **NONE**.

## Requested final-report checklist

| # | Item | Result |
|---|---|---|
| 1 | Exact frozen definition | TASKS NS-106: typed ui_language/ui_language_confirmed, atomic reload/merge, language before guide, explicit confirmation, restart-mode current/pending and failed-load/save recovery; full quoted authority is linked above. |
| 2 | Files changed | Deliverable file table above; no infrastructure, domain, SQL or installer changes. |
| 3 | Persistence | Existing per-user config.json; allowlisted stable ID plus explicit confirmation bool. |
| 4 | Schema still 020 | YES; SQL001–020 retained. |
| 5 | First-launch detection | ui_language_confirmed false; independent of DB, catalogs, consent and guide. |
| 6 | Fresh flow | Language-only chooser → explicit confirmation → validated atomic save → activation/seal → normal UI/guide. |
| 7 | Existing-user upgrade | One language question; all acknowledged legacy/current/future guide states and valid independent settings preserved. |
| 8 | Language model | Frozen Qt-free metadata plus immutable LanguageOption/LanguageDiagnostics. |
| 9 | Planned count | 18 total, 17 future target packs. |
| 10 | Available/selectable | All names shown; only validated packs enabled. Production English only. |
| 11 | English fallback | Always available, no QM needed, separate recovery button. |
| 12 | selected_locale | Successfully persisted next-launch preference. |
| 13 | effective_locale | Current sealed manager locale for this session. |
| 14 | Restart contract | Pending/current shown; Apply does not activate, replace widgets, change direction/generation or restart processes. |
| 15 | Startup order | QApplication → language/config/chooser → activate/seal → MainWindow/models/tray/coordinators → onboarding/lifecycle. |
| 16 | Chooser | Dedicated resizable QDialog, Unicode scroll list, wrapped plain text, three primary actions. |
| 17 | Confirmation | Continue/Use English only; highlighted row never persists. |
| 18 | Cancel/close | X/Esc/Cancel exits bootstrap with no choice write; subsequent launch asks again. |
| 19 | Invalid preference | Safe English + bounded invalid flag/notice; no raw invalid value reflected or automatic accepted repair. |
| 20 | Missing/corrupt pack | Effective English; retain valid requested ID/confirmation; explicit valid Apply repairs. |
| 21 | Persistence failure | Previous file/state intact; sanitized retry; explicit unsaved English continuation in bootstrap. |
| 22 | Onboarding | Follows language resolution, never consented/reset/replayed by language choice. |
| 23 | RTL/Unicode | Arabic direction metadata and representative autonyms tested; OS/Qt fonts, no bundled font/full native RTL claim. |
| 24 | Accessibility | Named/described controls, arrow selection, Tab chain, Enter, Esc, compact layout; native Narrator/DPI/font gate remains NS-110. |
| 25 | Diagnostics | Selected/effective IDs, last catalog validation/activation outcome, fallback, restart-required, invalid flag; no paths/secrets/raw config. |
| 26 | Production translations added | NO. |
| 27 | Runtime live switching added | NO. |
| 28 | Targeted tests | 169 passed; final startup/config/GUI delta 89 passed. |
| 29 | GUI/offscreen | Included in targeted receipts and full-suite run; keyboard/layout/confirmation/recovery verified. |
| 30 | Upgrade/restart | Temporary legacy/future configs, atomic/concurrent update/failure, actual modal once, 12 pending Apply operations and next-launch real QM fixture. |
| 31 | Full offline suite | 4,810 passed, 3 sandbox junction-creation failures, 9 live deselected; exact 3/3 outside-sandbox retry PASS, all 4,813 selected cases verified. |
| 32 | Coverage | 91.43%; configured 85% gate retained and passed. |
| 33 | Ruff | PASS. |
| 34 | mypy | PASS, configured 41 + direct 7 files. |
| 35 | Whitespace | git diff --check PASS. |
| 36 | Privacy scan | PASS, bounded task text files including final documentation/status updates; no real user configuration read. |
| 37 | Extraction/resources | PASS, 1,932 strings / 120 contexts / 3 plurals / 87 unchanged exceptions; actual offline wheel ZIP resource smoke. |
| 38 | NS-106 | COMPLETE, exact offline acceptance; native multilingual gate remains NS-110. |
| 39 | NS-107 | NOT STARTED. |
| 40 | NS-108–120 | NOT STARTED. |
| 41 | Pre-checkpoint commit/push | NONE; review HEAD ad2ae6b6cf003b2ca372161c86efc191bdac8974 unchanged. Later checkpoint authorization is recorded above. |
| 42 | Tag/release | NONE. |

Reproduce with existing dependencies (no network or real user config):

```powershell
$env:PYTHONPATH = "$PWD\src;$PWD\.venv\Lib\site-packages"
python -m pytest tests/gui/test_language_selection.py tests/unit/shared/test_language_config.py tests/gui/test_capabilities.py -q --basetemp=build/tests-ns106-review -o cache_dir=build/pytest-cache-ns106
python -m pytest -q --cov=netsentinel --cov-report=term --cov-fail-under=85 --basetemp=build/tests-ns106-review-full -o cache_dir=build/pytest-cache-ns106
python -m ruff check src tests packaging tools/localization.py
python -m mypy
python -m mypy src/netsentinel/presentation/i18n src/netsentinel/presentation/widgets/language_settings.py
python tools/localization.py check
git diff --check
```

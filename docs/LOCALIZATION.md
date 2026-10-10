# NS-105 — Localization architecture & source extraction

English is the canonical source and fallback. The frozen architecture is
PyQt6 `QTranslator`, Qt Linguist `.ts` sources and offline compiled `.qm`
resources. **Runtime switching: NO_GO; whole-application restart required.**
No production translation pack, chooser, preference, new tour or installer
language change is added. Schema stays 020. This document defines the NS-105
foundation; [acceptance and measured results](LOCALIZATION_ACCEPTANCE.md) and
[surface inventory](localization/surface-inventory.md) record its verification.

## Composition and lifetime

`presentation.app.create_application` creates/reuses QApplication, constructs
one GUI-owned `LocalizationManager`, activates the initial locale, then seals
the manager **before constructing any window, dialog, model or worker**. Its
`initial_locale` argument is an internal composition/test API; normal bootstrap
passes English. There is no saved language field or selector.

The manager owns the translator and its backing bytes, resolves only bundled
resources, installs/removes translators on the GUI thread and applies QLocale
and application layout direction. A successful activation publishes a locale
generation. That generation is separate from existing query/selection/command
generations. Main-window destruction removes the owned translator. Close is
idempotent. Widgets never manipulate QTranslator.

Before sealing, outcomes are `english`, `applied`, `unsupported`,
`missing_catalog` or `invalid_catalog`. Unsupported, missing, malformed,
oversized, unreadable, digest-mismatched or Qt-invalid catalogs produce English
with no translator installed. Failures return bounded semantic codes without
paths, exception text or catalog contents. Missing keys use Qt's English source
fallback; malformed named placeholders also fall back to the complete source.
Normal UX never displays missing-translation markers.

After sealing, every activation request returns `restart_required` and leaves
current/requested locale, generation, translator, direction and live UI state
unchanged. It does not save a preference, restart automatically or rebuild domain
state. The current shippable-language list is English only; planned metadata
is explicitly separate from availability. NS-106/107 will connect accepted
catalog availability to the future chooser.

## Locale identity

The frozen BCP-47 IDs below are independent of translated display names. Qt
locale forms are an internal mapping. No automatic OS-language choice exists.

| ID | Planned language | Qt locale | Direction |
|---|---|---|---|
| en | English | en_US | LTR |
| tr | Turkish | tr_TR | LTR |
| de | German | de_DE | LTR |
| fr | French | fr_FR | LTR |
| es | Spanish | es_ES | LTR |
| it | Italian | it_IT | LTR |
| pt-BR | Brazilian Portuguese | pt_BR | LTR |
| nl | Dutch | nl_NL | LTR |
| pl | Polish | pl_PL | LTR |
| ru | Russian | ru_RU | LTR |
| uk | Ukrainian | uk_UA | LTR |
| ar | Arabic | ar_EG | RTL |
| ja | Japanese | ja_JP | LTR |
| ko | Korean | ko_KR | LTR |
| zh-Hans | Simplified Chinese | zh_CN | LTR |
| zh-Hant | Traditional Chinese | zh_TW | LTR |
| id | Indonesian | id_ID | LTR |
| cs | Czech | cs_CZ | LTR |

## Keys, descriptors and evidence

Presentation calls use explicit deterministic contexts and literal English:
`translate('MainWindow', 'Dashboard')`. The thin facade calls
`QCoreApplication.translate`; it is not a dictionary translation system.
Contexts follow surface/module names (`Devices`, `ConnectionDetails`,
`ConnectionsModel`, etc.). Enum contexts include a display style, such as
`AlertStatus.raw` or `PreferenceStatus.upper`. Preserve contexts and source
wording during unrelated refactors. Qt disambiguation is available when needed.

Import-time header/label containers use deferred `TranslationSequence` or
`TranslationMapping` factories, so imports do not freeze English before startup
activation. Stable keys, object names, PageIds, roles and selection IDs remain
canonical; only container display values are translated. Onboarding link keys
and capability names retain their original lookup identities.

The six existing application read/preview services now return Qt-free
`SourceText`/`SourceMessage` descriptors marked by the Linguist-compatible
`QT_TRANSLATE_NOOP(context, literal)` helper. They retain canonical `str`
compatibility for existing pure contracts and carry named raw values until GUI
rendering. Concatenation/joining preserves recipes; bounds apply again after
translation. Rendering accepts descriptors only: arbitrary strings, old stored
explanations and user notes never become translation keys. Immutable recipes
can cross worker boundaries without choosing a language. Domain and application
import neither Qt nor presentation.

`shared.enum_sources` holds explicit extractable **display sources**, never
target-language translations. Persisted enum values are unchanged. Risk,
confidence, alert/incident state, trust, network scope, preference, signer,
response lifecycle/permission and baseline/TI status displays use mappings.
Unknown enum displays retain the previous canonical formatting. Technical
diagnostics deliberately show bounded raw status codes beside translated labels.

No schema, detector/scoring, evidence, firewall ownership or consent contract
changes. Timeline cursor hashing converts only its UI descriptor fields back to
exact canonical strings before the unchanged closed domain encoder. Its stable
IDs, sort tuple and token therefore do not depend on locale. The persisted
preference-revocation audit reason remains an exact raw canonical string.

## Parameters and plurals

Use complete literal templates with **simple named Python format fields** and
named values. `format_text` renders nested descriptors before formatting.
Domain values are passed as raw parameters. Do not put an f-string inside a Qt
lookup. Technical notation without words can remain an ordinary f-string.

Catalog validation compares the multiset of field names, occurrences, conversion
flags and format specifications. It rejects renamed/dropped/duplicated fields,
positional/nested/attribute/index fields, damaged escaped braces, empty finished
translations and dropped `%n`. Runtime validation retains readable English for
invalid named placeholders. Compilation rejects unfinished/obsolete entries.
Translations remain plain text on existing safety/evidence text surfaces.

Three representative count messages use Qt numerus: observed devices, dropped
UI events and VLAN frames. Call `translate(context, source, None, count)`, keeping
`%n` in the literal so pylupdate extracts `numerus="yes"`. Qt chooses forms, not
an English `count == 1` conditional. English without a translator uses readable
`device(s)`, `event(s)` and `frame(s)` wording with the numeric count. No duplicate
English QM is needed. Non-grammatical diagnostic counters and labels such as
`queue depth/capacity` keep named numeric parameters. NS-107 must validate each
target language's actual form count and linguistic correctness; English pseudo
fixtures have two forms and prove 0/1/2/19 behavior only.

## Dates, numbers and exports

Dashboard aggregate integers use QLocale formatting. The presentation helpers
support locale-aware integers/decimals and timezone-aware short dates with an
explicit numeric UTC offset; Devices' ordinary observed-time columns use them.
Naive date input is rejected. Storage timestamps are never changed.

History/DNS/incident/process evidence retains its ISO-style local timestamp
with explicit offset and existing precision. Assessment/response/audit timing
retains UTC/ISO wording and precision; filter input contracts remain ISO.
Hashes, IP/MAC/domain/path/process strings, protocols, IDs, rule IDs, schema and
diagnostic keys, exact time/duration/byte/risk evidence and database values stay
stable. Translator-controlled labels wrap these values without translating them.

There is no human report renderer to replace: support-export-v1/allowlist-v1
JSON, logs, CLI/self-test receipts, release/firewall recovery manifests and
installer policy output keep canonical keys/codes/English/ISO machine formats.
The application preview's surrounding controls and warnings are extracted;
the sanitized export bytes are displayed verbatim. Installer, native file chooser
captions/buttons and OS notification chrome retain OS or English language. All
app-owned standard QMessageBox/QDialogButtonBox labels are extracted separately.

## Catalogs and reproducible offline tools

| Location | Purpose | Shipped |
|---|---|---|
| `translations/netsentinel_en.ts` | Extracted unfinished canonical source inventory | No |
| `presentation/i18n/` | Manager, facade, standard buttons, notification renderer | Yes |
| `shared/source_text.py`, `shared/enum_sources.py` | Qt-free source recipes/display descriptors | Yes |
| `assets/i18n/manifest.json` | Version 1 bundled catalog allowlist/digests | Yes |
| `assets/i18n/netsentinel_<BCP-47-id>.qm` | Future reviewed compiled catalogs | None yet |
| `tests/fixtures/i18n/pseudo.ts` and `.qm` | 59-message test-only real QM fixture | No |
| `build/i18n/` | Generated full pseudo/compile outputs | No; ignored |
| `tools/localization.py` | Extract/check/pseudo/compile commands | No |

The app's runtime dependency stays PyQt6. Verified extraction uses locked
PyQt6 6.11.0's Python pylupdate module (Qt compiled 6.11.0, runtime 6.11.2).
The executable launcher is unnecessary. A separate optional **build-only**
`i18n-build` dependency pins `PySide6-Essentials==6.11.0` for its native
Qt 6.11.0 lrelease executable. No PySide6/shiboken import or alternate runtime
binding is used. The isolated compiler installation below needs no Python
binding dependencies because only the native binary is executed.

Install dependencies once (cached/offline installs are possible afterwards):

```powershell
uv sync --locked --extra dev
uv pip install --python .venv/Scripts/python.exe --target build/i18n-tools --no-deps PySide6-Essentials==6.11.0
build/i18n-tools/PySide6/lrelease.exe -version
```

Developer commands after installation require no network:

```powershell
.venv/Scripts/python.exe tools/localization.py extract
.venv/Scripts/python.exe tools/localization.py check
.venv/Scripts/python.exe tools/localization.py pseudo
.venv/Scripts/python.exe tools/localization.py compile --catalog build/i18n/pseudo.ts --output build/i18n/pseudo.qm
.venv/Scripts/python.exe tools/localization.py compile --catalog tests/fixtures/i18n/pseudo.ts --output build/i18n/fixture.qm
```

An alternate compiler path can be supplied with `--lrelease`; for a normal
`uv sync --locked --extra dev --extra i18n-build` install it is
`.venv/Lib/site-packages/PySide6/lrelease.exe`. Compile always validates the
finished TS before invoking `lrelease -nounfinished ... -qm ...`. Outputs must be
explicit: it never implicitly writes a production pack. Source extraction sorts
contexts/messages and normalizes relative file locations without line numbers.
NS-107 creates target TS catalogs next to the source, performs reviewer/plural
gates, compiles, and records each QM's SHA-256 in the manifest. Do not compile
the unfinished English inventory into a fake completed pack.

The manifest is currently `{"version":1,"catalogs":{}}`. Future entries look
like `"tr":{"sha256":"<64 lowercase hex characters>"}`. Filenames are derived
from the allowlisted locale, never a manifest path. Runtime reads are bounded
to 16 KiB manifest and 4 MiB catalog and checked before Qt parses bytes. Digest
checks provide bundled integrity, not publisher authentication.

Wheel package-data and the PyInstaller spec include the manifest and QM files.
The spec validates exact inventory/IDs/digests before bundling and excludes
PySide6/shiboken. `check` performs the same resource validation. Source TS,
compiler, test fixture and generated files are excluded from the app payload.
NS-105 verifies a wheel ZIP resource lookup; it does not rebuild the acceptance
installer or claim a new native installer acceptance.

## Runtime feasibility decision: NO_GO

The isolated **unsealed test probe** changes English→pseudo Arabic metadata
(RTL)→English (LTR). It keeps page, filter text, selection, focus, raw row ID,
query generation and evidence intact. However, constructor-created navigation,
buttons, dialog text, cached dashboard/detail snapshots and a11y strings do not
all handle LanguageChange. On-demand model headers can return the new language
while navigation still says Dashboard. This mixed UI is a concrete blocker.
There are no complete per-surface retranslate handlers/headerDataChanged
notifications or a globally coordinated cached-presentation refresh. A partial
live API must not be exposed.

Production composition therefore seals before construction. Open settings keep
unsaved choice/input and focus; destructive confirmations keep their text,
target, Cancel default and command generation throughout. Locale requests during
a worker leave the current session language and existing result guards unchanged.
Qt-free worker recipes render at completion in the effective GUI language,
including an isolated late-result test whose probe changes locale after dispatch.
Neither old pretranslated worker text nor persisted history is relocalized.

Tray menus/tooltips resolve during startup. Notifications resolve their approved
title/body from raw severity at **submission time**. Locale activation has no
delivery/replay hook; an already shown notification stays as submitted, and no
persisted event is rewritten. Models resolve headers and display-only mappings
when constructed/read; accepted locale changes recreate the whole application
on next launch, rather than resetting security records inside the current model.
Accessibility follows that same startup/restart contract.

The frozen NS-106/109 contract is:

1. The user selects a language.
2. The selection is validated and persisted atomically.
3. The UI explicitly states that an application restart is required.
4. The running UI retains its current language without partial retranslation.
5. The selected language becomes active on the next application launch.

NS-106/109 must implement explicit current/pending language and Apply/Cancel,
with user-controlled restart. First-launch selection must
occur before activation/seal and before the guide. Do not switch only a page,
recreate an open confirmation or silently discard unsaved dialog input. Native
switching and full UX remain gated by NS-110.

## RTL, CJK and bounded detection

Qt box/grid layouts inherit application direction. Obvious fixed left/right
presentation alignment became AlignLeading/AlignTrailing; navigation padding
is symmetric. No absolute positioning or manual overlays were found in the
presentation inventory. Protocol arrows/endpoint strings and icon semantics
remain raw evidence and need mixed-direction scrutiny in NS-107/110. No bidi
characters are injected into stored/exported evidence.

Remaining RTL/expansion risks: sidebar 180–300 logical-pixel width; dashboard
two-column card layouts; font-metric table sizing; fixed maximum heights in note,
profile, list, preview panels; horizontal evidence scrollers; ellipsis/truncation;
long translated menu/action/button text and Arabic mnemonic collisions. The
offscreen direction probe demonstrates Qt inheritance, not Arabic shaping or
native screen-reader acceptance.

Production does not force a font family or load a font binary; it uses the
QApplication/Windows font and Qt fallback. Styles change size/weight only. Tests
may temporarily load a host Segoe UI font for legacy layout checks. Offscreen Qt
reports its missing bundled font directory on this host; that is not proof of
Windows CJK availability. NS-107/110 must inspect actual Windows Japanese,
Hangul, Simplified/Traditional Chinese and Arabic glyph fallback, shaping,
wrapping, DPI 100/125/150/200%, installed/font availability and license evidence.
No font is redistributed by NS-105.

`tools/localization.py check` re-extracts exact keys, validates fields/numerus,
checks bundled resources, and AST-scans direct UI sinks and prose in the source
set. [Exact reviewed exceptions](localization/literal-exceptions.json) document
87 file/string pairs; stale exceptions fail too. A unit test proves a new
untranslated setText literal fails. CI runs the check explicitly. This bounded
scanner is not full data-flow analysis: dynamic strings, single words outside
known sinks and presentation text newly generated in other services still need
manual review and inclusion in SOURCES. It does not flag every technical value.
The full accent/expansion pseudo output preserves fields and Qt numerus, stresses
coverage, and is never an available production locale or human-review substitute.

Remaining work: NS-106 chooser/persistence/restart; NS-107 seventeen reviewed
target packs plus English plural review/resource availability; NS-108 new
page-aware guide; NS-109 Settings/replay and final string delta; NS-110 complete
native multilingual/RTL/CJK/accessibility acceptance. NS-106–120 remain not
started; VMware M20 and release work are outside this task.

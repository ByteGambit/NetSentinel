# NS-105 acceptance — localization architecture & source extraction

Precommit acceptance snapshot, 2026-10-09. Starting/acceptance HEAD:
`6545832c31c0065a4afc44418b5d6c0d78642369`. The commit/push NONE entries below
describe that snapshot. On 2026-10-10 the user approved acceptance and authorized
the reviewed NS-105 checkpoint commit/push to main; no later task was authorized.
**Runtime switching NO_GO: whole-app restart mode.**
**NS-105 COMPLETE** in the frozen offline/restart-mode scope; M19 IN PROGRESS.
NS-106–120 remain NOT STARTED. Native multilingual acceptance remains NS-110.

## Exact frozen task used

The NS-105 definition from `docs/TASKS.md` at the starting HEAD was used;
its implementation/acceptance scope is unchanged:

> **NS-105 — Localization architecture & source extraction**
>
> **Amaç:** Mevcut hand-built PyQt6 UI için offline Qt localization sözleşmesini ve dürüst runtime/restart davranışını kurmak.
>
> **Yapılacaklar:** QTranslator/.ts/.qm, canonical English/context, allowlisted language manifest, extraction/compiler ve placeholder/numerus sözleşmesini uygula; presentation string inventory çıkar ve literal çağrılara dönüştür; domain/application typed codes ile UI metnini ayır. GUI-owned locale generation, raw-record re-render, model header/DisplayRole/accessibility güncellemesi ve açık dialog/late-result sınırını tanımla. English/pseudo/fake catalog ile runtime feasibility gate çalıştır; başarısızsa tüm app için explicit restart-required contract dondur. Date/number display QLocale; UTC/technical evidence/machine export formatlarını koru; hardcoded-string scanner ve reviewed exceptions oluştur.
>
> **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/presentation/i18n/ (yeni), presentation/views/, widgets/, models/, viewmodels.py, process_context.py; tests/gui/, tests/unit/; pyproject.toml/uv.lock yalnız gerekli build-tool kararı; docs/LOCALIZATION.md (yeni).
>
> **Bağımlılıklar:** NS-104.
>
> **Acceptance criteria:** Domain/application Qt translation import etmez; stable IDs/sort/selection/evidence değişmez; English missing/plural fallback okunabilir; extraction inventory ve placeholders doğrulanır; araç sürümü/build-only dependency açık; load failure sanitized. Açık settings dialog, unsaved input, delayed result, LTR→RTL→LTR feasibility kanıtıyla runtime veya coherent restart mode seçilmiş ve belgelenmiştir; destructive confirmation dili ortasında değişmez. No network/API/external catalog.
>
> **Test yöntemi:** Fake translator/load errors, plural/placeholder/extraction fixtures; offscreen selection/filter/focus/dialog/query-generation ve pseudo expansion/RTL; static sink scan/exception review. Native güvenli switching için sonraki NS-110 gate korunur.
>
> **Kapsam dışı:** Gerçek target-language çevirileri, SQLite migration, installer rebuild, detector/privacy policy değişimi.
>
> **Başlatma kapısı:** NS-104 COMPLETE ve kullanıcıdan gelecekte açık M19 implementation yetkisi; mevcut planning isteği uygulama yetkisi değildir.

The present explicit NS-105 request supplies the implementation authorization;
the quoted planning request was historical. All six authoritative documents and
the complete presentation tree/composition/bootstrap/tests/resource/build paths
were reviewed. [Contract](LOCALIZATION.md) and [file/context inventory](localization/surface-inventory.md)
explain the exact restart-mode alternative accepted by this frozen definition.

## Acceptance evidence

| Criterion | Evidence / result |
|---|---|
| Qt-free domain/application | AST layer-import test; descriptors have no Qt lookup/import. Configured mypy 40 files; direct i18n/tooling check 8 files. |
| Stable identity/evidence | Raw roles/PageId/filter/selection/focus/row ID checks; internal AlertStatus values unchanged; incident sort/cursor remains canonical; raw domain/path/IP/hash/time data never looked up. |
| English fallback | No translator, unsupported IDs/path-shaped input, missing/invalid catalog, load exception and rejected install; absent key; invalid placeholder; real numerus 0/1/2/19. |
| Offline extraction/toolchain | 1,913 exact keys, 119 contexts, 3 numerus; real PyQt pylupdate and Qt 6.11.0 lrelease; no runtime API/network/external path. |
| Catalog integrity | Bounded resources, strict filename/locale inventory, SHA-256 corruption/invalid manifest tests; ZIP/wheel resource load smoke. |
| Restart decision | Isolated unsealed LTR→RTL→LTR probe exposes old navigation/new header mixed language. Production sealed requests leave all current state unchanged. |
| Open settings/destructive confirmation | Pseudo startup dialog/buttons/a11y; unsaved control state and dialog stay open across rejected changes; exact confirmation target/text and Cancel default preserved. |
| Async boundary | Real blocked RiskQueryCoordinator returns a source recipe after probe change and renders at completion; sealed change keeps English and original query generation. |
| Tray / notifications | Real Qt tray caption test and fake native icon submission seam; future title/body translated, past notification never replayed, DTO unchanged. |
| Models / accessibility / guide | Source-marked/deferred headers and enum display; navigation/page/widget/a11y and existing M17 guide/action link proof. No live header refresh claim in restart mode. |
| Safety / regression | Full offline suite and existing 85% coverage gate; no detector/persistence/firewall/consent/response identity change or migration. |

Two conversion regressions were caught and corrected: SourceText could not be
passed into the unchanged strict incident cursor encoder, and a persisted
revocation audit reason must remain an exact raw str. Original enum underscore
display formatting was also retained. Their existing regression tests passed;
neither domain codec nor tests were weakened.

## Required final report (1–43)

| # | Requested item | Result |
|---:|---|---|
| 1 | Exact NS-105 definition | Quoted above verbatim for objective/work/acceptance/test/scope/gate; original status PLANNED / NOT STARTED. |
| 2 | Files changed | [Complete changed-file list](localization/changed-files.md); [per-module source inventory](localization/surface-inventory.md). |
| 3 | Architecture | Central GUI-owned QTranslator; Qt-free source recipes; explicit literal contexts; sealed startup/restart contract. |
| 4 | Canonical/fallback | English, no English translator/QM needed; safe canonical source fallback. |
| 5 | Locale IDs | en, tr, de, fr, es, it, pt-BR, nl, pl, ru, uk, ar, ja, ko, zh-Hans, zh-Hant, id, cs. Planned metadata only; shippable English. |
| 6 | Resources | translations/*.ts source; assets/i18n manifest/future QM; tests fixture; ignored build/i18n outputs. |
| 7 | Extraction | `.venv/Scripts/python.exe tools/localization.py extract`; locked PyQt pylupdate, normalized deterministic keys/locations. |
| 8 | Compilation | `tools/localization.py compile --catalog <finished.ts> --output <file.qm>`; pinned build-only native Qt 6.11.0 lrelease, placeholder/form validation and -nounfinished. |
| 9 | Packaging | Wheel/package-data and validated PyInstaller inventory include manifest/QM; compiler/test/source catalogs excluded. Actual wheel ZIP resource lookup PASS; installer not rebuilt. |
| 10 | Strings/contexts | 1,913 unique keys / 119 contexts / 3 numerus keys. |
| 11 | Hardcoded conversion count | 1,187 existing presentation literal occurrences in two audited conversion passes; current 1,214 presentation literal source callsites. Counts are occurrences, not unique TS keys; later enum/helper additions are included in current inventory. |
| 12 | Technical exclusions | Raw IP/MAC/domain/hash/path/process/protocol, IDs/enums/schema/keys, ISO UTC/evidence, QSS, persisted history/audit/user text and canonical machine exports. 87 exact scanner exceptions. |
| 13 | Enum/display | Extractable canonical display descriptors separated from persisted codes; response/permission, risk, alert/incident, network/trust, baseline/preference/TI/signer/status mappings. |
| 14 | Placeholders | Exact named field/spec/conversion multiset and brace validation; no positional/evaluated fields; runtime English fallback. |
| 15 | Plurals | Qt `%n`/numerus real QM 0/1/2/19 proof; readable English `(s)` fallback; target plural review deferred to NS-107. |
| 16 | Date/time/number | QLocale aggregate numbers/ordinary Devices display with explicit offset; raw UTC, ISO evidence precision/filter/export contracts unchanged. |
| 17 | Pseudo | Test-only accent/expansion; full generator plus 59-message real fixture; absent from manifest/language list/app payload. |
| 18 | Hardcoded detection | Exact extracted-key comparison plus bounded AST sink/prose scanner; reviewed/stale exception gate; CI; dynamic/out-of-source limitations documented. |
| 19 | Runtime decision | **NO_GO**; restart required for the entire application. Mixed static/new header probe is the concrete blocker. |
| 20 | Open dialogs | Effective session language fixed; unsaved input/focus/target/default preserved. No dialog rebuild on rejected change. |
| 21 | Async | Source recipes translated in GUI at render/completion; query/selection generations unchanged; stale semantic result guards retained. |
| 22 | Tray | Startup-localized menu/tooltip; fixed session language; normal controller diagnostics stay machine codes. |
| 23 | Notifications | Approved raw severity rendered at submission; no replay/event rewrite; existing OS chrome unchanged. |
| 24 | Models | Deferred/source headers and display enums; raw roles/sort/record IDs unchanged. No live headerDataChanged guarantee; next launch creates coherent current-locale surfaces. |
| 25 | Accessibility | Owned names/descriptions/standard buttons/source guide text localized at startup; fixed session language. Native screen reader acceptance remains NS-110. |
| 26 | RTL | Qt direction inheritance probe PASS; logical alignment/symmetric padding; remaining sizing/mixed-evidence/mnemonic risks inventoried. |
| 27 | CJK/fonts | OS/Qt fallback retained, no forced production family/font binary; native fallback/shaping/DPI/font/license acceptance pending NS-107/110. |
| 28 | Production translations added | **NO**. |
| 29 | Schema still 020 | **YES**; SQL001–020, no migration/domain codec change. |
| 30 | Targeted tests | **52 passed** (localization GUI + tooling); incident targeted54, baseline52, mark-normal/service38 during regression fixes. |
| 31 | GUI/offscreen | **697 passed** (all GUI plus localization tooling), 157.22s. |
| 32 | Full offline suite | 4,760 passed, 3 sandbox fixture-creation failures, 9 live deselected in 630.60s; all three unchanged Windows junction tests then PASS outside sandbox in isolated workspace fixtures (0.58s). All 4,763 selected cases verified; no skips/test changes. |
| 33 | Coverage | **91.40%** (26,798 / 29,321 statements), configured fail-under85 retained and passed. |
| 34 | Ruff | PASS: configured src/tests/packaging plus tools/localization.py. |
| 35 | mypy | PASS: configured40; direct new i18n/shared/tooling8 (subsequent i18n/tooling6 also PASS). |
| 36 | Whitespace | Configured `git diff --check` PASS. |
| 37 | Privacy scan | **PASS: 75 task text files** after removing line-ending-only noise; bounded changed/untracked scan for known key/token/private-key/personal-path patterns, no profile/secret reads. |
| 38 | Extraction check | PASS: source keys/placeholders/plural, 87 exact exceptions, resource integrity. |
| 39 | NS-105 | **COMPLETE**; exact restart-mode alternative accepted; native multilingual gate still pending NS-110. |
| 40 | NS-106 | **NOT STARTED**. |
| 41 | NS-107–120 | **NOT STARTED**. |
| 42 | Commit/push | **NONE**. |
| 43 | Tag/release | **NONE**. |

## Reproduction and receipts

```powershell
.venv/Scripts/python.exe -m pytest tests/gui/test_localization.py tests/unit/test_localization_tooling.py -q
.venv/Scripts/python.exe -m pytest tests/gui tests/unit/test_localization_tooling.py -q
.venv/Scripts/python.exe -m pytest -q --cov=netsentinel --cov-report=term --cov-fail-under=85
.venv/Scripts/python.exe -m ruff check src tests packaging tools/localization.py
.venv/Scripts/python.exe -m mypy
.venv/Scripts/python.exe -m mypy src/netsentinel/presentation/i18n src/netsentinel/shared/source_text.py src/netsentinel/shared/enum_sources.py tools/localization.py
.venv/Scripts/python.exe tools/localization.py check
git diff --check
```

This host uses distinct ignored `build/tests-ns105-*` basetemp directories and
`-o cache_dir=build/pytest-cache-ns105` because its default temporary-directory
permissions can fail. No tests/markers/budgets were relaxed. Offline defaults
exclude windows_live/lab_live/live_threat_intel. Tool dependencies were installed
before running offline commands; the optional compiler download is not app
network behavior.

Full-suite environmental failures were exclusively `cmd mklink /J` fixture
creation in the existing installer lifecycle rejection tests. All targets were
fresh isolated `build/tests-ns105-*` workspace directories. Automatic approval
allowed only the three-test retry outside the sandbox; each asserted refusal to
traverse the junction and preservation of the external sentinel, then removed
the junction itself. **3/3 PASS**. The full run's initial failures are recorded
honestly above rather than presented as a single all-green run. No installer
code/test or sandbox-related skip was added.

Verified fixture recompilation is byte-identical with SHA-256
`6662f69503fb59bdbb83136d221a83460a240f52ae2d66f296875114e3639294`.
Real full pseudo compilation validated all source messages. Wheel resource
smoke loads the manifest through importlib.resources inside the ZIP, confirms
SQL001–020, and confirms no `.ts`, test `.qm` or compiler in the payload.
Ignored local test logs/coverage/build products live under `build/`; no generated
installer or release asset is a deliverable. No native multilingual, Arabic/CJK
font, new installation or VMware acceptance is claimed.

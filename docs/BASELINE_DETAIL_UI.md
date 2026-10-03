# NS-075 — Baseline detail ve reset UI

2026-10-03. Authoritative acceptance: `TASKS.md` NS-075. Başlangıç main HEAD:
`5b3fd30ac514a8f30af428004b823feaf9fc2561` (`feat: add connection periodicity evidence`);
başlangıç çalışma ağacı temizdi. Değişiklik yalnız NS-075 ve M13 completion'dır.

## Uygulama ve kabul raporu (istenen 1–55 maddeler)

| No | Konu | Sonuç |
|---|---|---|
| 1 | Exact title | NS-075 — Baseline detail ve reset UI |
| 2 | NS-075 | COMPLETE; authoritative acceptance kriterleri karşılandı. |
| 3 | M13 | COMPLETE; NS-069–075 tamamlandı, aşağıdaki exit matrisi doğrulandı. |
| 4 | Surface | Connections → Selected connection → Behavior baseline sekmesi; History/top-level page eklenmedi. |
| 5 | Selected scope | Canonical application identity + exact known/unknown revision + resolved local network fingerprint. |
| 6 | Application | Display name, canonical path key ve identity quality; PID/name persistent identity değildir. |
| 7 | Revision | Unknown artifact revision veya bounded SHA-256 context. Desktop otomatik hash yapmadığından live unknown olabilir; typed request known revision destekler. Hash reputation değildir. |
| 8 | Network | Resolved fingerprint/status gösterilir. Unknown/ambiguous/provisional scope persistent reference ödünç almaz ve reset disabled'dır. |
| 9 | LEARNING | Açık text state ve yeni öğrenme açıklaması. |
| 10 | READY | Yeterli observed baseline data; safety verdict değildir. |
| 11 | INSUFFICIENT_DATA | Sample/monitored coverage eksikliği ayrı açıklanır. |
| 12 | INSUFFICIENT_QUALITY | Reduced visibility, unknown destination veya capacity loss ayrı açıklanır. |
| 13 | STALE | Eski last-observed reference evaluation için kullanılmaz. |
| 14 | EXPIRED | Expired text, READY değildir. |
| 15 | CLOCK_ANOMALY | Clock değişimi freshness'i güvenilir değerlendirmeyi engeller. |
| 16 | CORRUPT/UNAVAILABLE | Safe explanation; unsupported-version ve policy-mismatch de ayrı state'tir. Raw DB exception gösterilmez. |
| 17 | Sample progress | Current/required eligible appearance count. |
| 18 | Duration progress | Current/required monitored seconds; policy config'den gelir, UI constant değildir. |
| 19 | Coverage wording | Monitored coverage / observed active coverage; uptime veya offline duration değildir. |
| 20 | Appearance wording | Observed connection appearances; OS connection creation sayısı değildir. |
| 21 | Destinations | Retained count + en fazla 8 deterministic IP/count preview. |
| 22 | Ports | Retained count + en fazla 8, sayısal sıralı preview. |
| 23 | Protocols | Retained count + en fazla 2 sorted protocol. |
| 24 | Overflow/capacity | Açık capacity-loss metni ve destination/port/protocol unretained appearance sayaçları; retained diversity exact total unique değildir. |
| 25 | Novelty | Typed evidence varsa classification/reason/count/coverage/limitations. First seen yalnız retained scoped knowledge, known yalnız familiarity. |
| 26 | Frequency | Observed appearance rate, current/reference per monitored minute, confirmation ve quality. NORMAL yerine Within observed reference range açıklaması. |
| 27 | Diversity | Current/reference retained destination diversity; capacity-loss/gap görünür. |
| 28 | Periodicity | Typed classifications, retained interval/base interval/polling resolution; process instance ve endpoint/protocol exact match. |
| 29 | Polling limit | Timing is derived from polling observations and does not prove an exact application timer. |
| 30 | Neutral context | Updater/synchronization compatible açıklaması; beacon/C2 verdict veya korkutucu palette yok. |
| 31 | Runtime/reference | Learned cumulative reference RAM tail içerebilir; current memory window ayrı. Persistence timestamp current tail'in durable kaydı değildir. NS-072–074 engine pipeline'ı bağlı olmadığından desktop evidence absence gösterir; query detector observation uydurmaz. |
| 32 | Preference separation | Observed learning user trust/preferences'ten açıkça ayrılır; preference UI eklenmez. |
| 33 | Reset action | Reset learned baseline… |
| 34 | Confirmation | Application, exact revision, network; learned data silinir, trust/preferences/history/current window değişmez. Default/Escape Cancel. |
| 35 | Reset scope | NS-071 exact-scope API; application B, network B ve revision B korunur. |
| 36 | Cancel | Command/write/dirty mutation yok; fake service diagnostics comparison ve keyboard dialog testi. |
| 37 | Accepted/durable | Queue acceptance bekleme metnidir; typed receipt yalnız writer transaction sonucunda tamamlanır. Coalescing/sequence regression testleri var. |
| 38 | Success | Yeni query; cached READY yerine fresh LEARNING/no reference gösterilir. Already absent da idempotent success'tir. |
| 39 | Failure | Failed/unavailable/unconfirmed text; accepted dirty reset retry olabilir. SQLite/raw exception GUI'ye dump edilmez. |
| 40 | Async query | Bir worker existing destination coordinator convention'ını reuse eder; restore edilmiş bellek snapshot'ını okur. |
| 41 | Stale protection | Generation + immutable request + logical selection ID; A→B→A late result düşer. |
| 42 | Selection stability | Aynı logical row model refresh'inde selected row korunur; baseline query tekrar üretilmez. |
| 43 | Bounds | 1 active + 1 latest pending query; unresolved query varken yeni poll yok. Visible 5-second refresh + explicit Refresh. Receipt map ≤ configured scope cap, default 128. |
| 44 | Plain text | Detail/confirmation QLabel/QMessageBox PlainText; name/path/key/fingerprint/evidence HTML olarak yorumlanmaz. |
| 45 | Accessibility | Accessible name/description, text keyboard selection, tab order, keyboard Reset ve Escape Cancel. Reset/Refresh scroll dışında erişilebilir. |
| 46 | Threading | Worker portable results, Qt signals; widget mutation GUI thread'inde. Reset submission bellek API'sidir. |
| 47 | Shutdown | 2-second default worker join; pending query invalidated, timers stopped; active reset timeout unconfirmed UNAVAILABLE. Destroyed widget'a late callback yok. |
| 48 | DB ownership | Yalnız mevcut NS-071 writer repository/SQLite connection owner'ıdır. |
| 49 | Persistence | Yeni store/raw history yok; yalnız existing scoped reset completion receipt eklenmiştir. |
| 50 | Schema | 014. |
| 51 | Migration | Yeni migration yok; summary/feature policy 1/1. |
| 52 | Risk score | Eklenmedi. |
| 53 | Mark normal | Eklenmedi; automatic/user trust değişikliği yok. |
| 54 | AlertService | Yeni entegrasyon yok. |
| 55 | Cloud/network | Yeni lookup/upload/active network işlemi yok. |

## Dosyalar ve testler (56–58)

Yeni production dosyaları:

- `src/netsentinel/application/services/baseline_detail.py`
- `src/netsentinel/presentation/baseline_query.py`
- `src/netsentinel/presentation/widgets/baseline_detail.py`

Değişen production dosyaları:

- `src/netsentinel/application/services/behavior_baseline.py`
- `src/netsentinel/bootstrap.py`
- `src/netsentinel/presentation/app.py`
- `src/netsentinel/presentation/views/connections.py`
- `src/netsentinel/presentation/views/main_window.py`
- `src/netsentinel/presentation/widgets/connection_details.py`

Yeni test dosyaları (69 yeni test case):

- `tests/gui/test_baseline_detail.py` (52): lifecycle, progress, capacity/preview,
  revisions/network/application limits, evidence mapper, real keyboard Cancel,
  exact-scope confirm, accepted/durable/failure, real writer refresh, rapid
  selection, query storm/coalescing, thread ownership, lifecycle/shutdown.
- `tests/integration/sqlite/test_baseline_reset_completion.py` (8): temp SQLite
  app/network/known/unknown revision isolation, idempotency/schema, blocked writer,
  failure/rejection, coalesced newer learning, stale sequence, pending shutdown.
- `tests/unit/application/test_baseline_detail.py` (9): portable exact scope/read
  model, current/reference separation, unavailable storage, display bound ve reset
  application boundary.

Dokümanlar: bu rapor yeni; `TASKS.md`, `ROADMAP.md`, `ARCHITECTURE.md`,
`PRODUCT.md`, `SECURITY.md`, `README.md` ilgili capability/completion için güncellendi.

## Validation (59–65)

Repo kökünden exact targeted command:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/application/test_baseline_detail.py tests/gui/test_baseline_detail.py tests/integration/sqlite/test_baseline_reset_completion.py tests/integration/sqlite/test_behavior_baselines.py tests/unit/application/test_behavior_features.py tests/unit/application/detectors/test_destination_novelty.py tests/unit/application/detectors/test_frequency_diversity.py tests/unit/application/detectors/test_periodicity.py tests/gui/test_connections_view.py tests/gui/test_app_lifecycle.py
```

Son kodda **467 passed**. Ayrıca control/scroll layout değişimi sonrasında ilgili
GUI/application/reset subset'i **92 passed**.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/application/services/baseline_detail.py src/netsentinel/application/services/behavior_baseline.py src/netsentinel/presentation/baseline_query.py src/netsentinel/presentation/widgets/baseline_detail.py --follow-imports=silent
git diff --check
```

Runtime: repository `.venv\Scripts\python.exe`, Python **3.12.14**, MSC v.1944
AMD64. Windows Application Control / `_overlapped` hatası oluşmadı; alternatif
runtime kullanılmadı ve security policy değiştirilmedi. Qt offscreen; tüm data
sentetik, temp SQLite, fake clock/service, Event synchronization; explicit sleep,
network, Npcap, ETW/admin/cloud yok.

İlk full koşu: **1 failed, 1557 passed, 7 deselected**, unrelated
`test_device_identity.py::test_merge_single_logical_profile_and_bounded_eviction`.
Bu test ve detector için `git diff --exit-code HEAD -- ...` temizdi; aynı unchanged
test isolated rerun **1 passed**. Sonraki full koşu **1567 passed, 7 deselected**;
NS-075 kapsamında unrelated test/eviction policy değiştirilmedi. Son production
layout/progress düzenlemesinden sonra full gate tekrar **1567 passed, 7 deselected
in 57.78s** verdi.

Ruff: all checks passed. Project mypy: **23 source files**, success. Yeni
application/presentation ve completion modüllerine direct mypy: **4 source
files**, success; configured mypy kapsamı genişletilmedi. Diff whitespace gate
temiz; Git'in Windows LF→CRLF bilgilendirmeleri hata değildir.

Offscreen visual QA: sentetik learning state'te Connections baseline sekmesi
render edildi; lifecycle/progress önce, scrollable plain-text explanation ve
erişilebilir fixed Refresh/Reset controls. Offscreen runtime'ın font bulamaması
yalnız QA script'inde mevcut `C:\Windows\Fonts\segoeui.ttf` okunarak giderildi;
production font policy değişmedi.

## M13 exit verification (66–68)

TASKS NS-069–074 önceki COMPLETE kayıtları korundu; NS-075 COMPLETE ve M13 summary
row COMPLETE yapıldı. ROADMAP exact exit criterion korunur:

> Warm-up/gap/eviction/restart testleri geçer; eksik gözlem high-confidence
> anomali üretmez; memory/disk bounds belgelenir.

| Exit evidence | Doğrulama |
|---|---|
| LEARNING / READY / INSUFFICIENT_QUALITY | NS-071 real policy + NS-075 offscreen bütün state/progress matrix. |
| Novelty/rarity explanation | NS-072 cold-start/rare/new/capacity/revision/network/pre-mutation tests + NS-075 mapper classifications. |
| Frequency/diversity explanation | NS-073 quality/reference/independent-window/confirmation tests + NS-075 current/reference wording. |
| Periodicity explanation | NS-074 deterministic interval/jitter/aliasing/updater/gap tests + NS-075 neutral classifications/polling wording. |
| Deterministic clock/warm-up/gap | NS-070/071/073/074 fake clocks; monitored coverage offline duration eklemez. |
| Restart | NS-071 persistence/reconstruction; current evidence/poll sequences restore edilmez. |
| Capacity/eviction | NS-070 memory caps, NS-071 load/retention/quota/write races; NS-075 explicit capacity loss and hard preview. |
| Bounds | 64 app/128 runtime scope, 64 IP/32 port/2 protocol; disk 512 row × ≤16 KiB summary; query 1 active + 1 latest pending; receipt ≤128. |

## Git teslimi (69–72)

Yalnız NS-075/M13 dosyaları `main` üzerinde
`feat: add behavioral baseline detail and reset UI` commit mesajıyla teslim edilir;
commit hash, `git push origin main` sonucu ve final working-tree status son kullanıcı
raporunda kaydedilir. Force push, tag, release veya yeni branch yoktur.
**NS-076/M14 implementation başlatılmadı.**

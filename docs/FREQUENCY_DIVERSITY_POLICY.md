# NS-073 — Frequency/diversity rules

İki distinct rule ID: `observed_appearance_frequency` ve
`destination_window_diversity`. Ortak immutable `BehaviorDeviationEvidence`
contract'ı ayrı contributor/reason taşır; combined score veya verdict yoktur.
Policy **1**; NS-071 summary **1**, feature policy **1**, SQLite schema **014**.

## Current ve historical reference

`BehaviorWindow` NS-070 post-mutation snapshot, tracker session UUID, UTC time,
current round quality ve explicit monotonic retained bucket envelope taşır.
Owner başlangıcı en eski tutulan bucket başlangıcından seçer; sınır en fazla
60 × 12 = 720 saniyedir. Kısa startup pencereleri mümkündür. Her refresh'te
başlangıcı ilerletmek veya round delta'yı pencere diye sunmak geçerli değildir.
Başka accumulator horizon'ı v1'e sessizce uyarlanmaz. Caller snapshot alma
sırasını serialize etmelidir; contract bu sıralamayı tek başına kanıtlayamaz.

Envelope elapsed time denominator değildir. Rate paydası yalnız NS-070
`monitored_seconds`: aynı session/exact scope görünürken kaliteli ardışık
turların coverage'ı. Poll sayısı sample değildir. INITIAL, update, close ve
long-lived repeated polls appearance eklemez. Yeni lifecycle OBSERVED appearance
ekleyebilir. FAILED, gap ve restart offline süresi coverage değildir. REDUCED
appearance accumulator'da korunur; NS-073 güçlü comparison'a kabul etmez.
Terminoloji **observed connection appearances per monitored minute**'tır;
gerçek OS connection creation, packet rate veya byte rate değildir.

Frequency reference NS-071 historical `observed_appearances / monitored_seconds`
mean'idir. Yeterli comparable reference window varsa bunların en yüksek rate'i
ve historical mean'in maksimumu upper reference olur. Summary'de olmayan
variance/percentile uydurulmaz. Yalnız persisted mean varsa frequency bununla
çalışabilir; historical burst distribution'ın bilindiği iddia edilmez.

Diversity NS-071 lifetime unique count ile karşılaştırılmaz.
`BehaviorRangeLearner` explicit reference-training aşamasında aynı READY scope
ve session'ın clean, non-overlapping pencerelerinden en fazla sekiz aggregate
tutar: envelope, monitored seconds, appearance count, retained destination count.
IP listesi/raw event yoktur. `learn()` training komutudur; evaluation bunu
otomatik çağırmaz. Owner training dönemini belirler, evaluation öncesi reference'ı
dondurur ve anomaly'yi kendi reference'ına otomatik normalleştirmez.

Diversity reference current'den önce bitmiş, aynı scope/session/policy/baseline
compatibility key'e sahip en az üç window gerektirir. Her reference current ile
aynı minimum sample/coverage gate'ini geçer. Coverage band:
`abs(reference_seconds - current_seconds) * 100 <= current_seconds * 20`.
Comparable window'ların retained IP / monitored minute maksimumu upper range'dir.
Bu model lifetime unique IP rate değildir; comparable bounded horizons kullanır.
Reference age current end'den en çok 86400 monotonic saniyedir. Uygun reference
yoksa diversity insufficient_data; frequency historical mean'le devam edebilir.
Supplied başka scope/session, future/overlapping reference iki kuralı da engeller.

Supplement **memory-only/session-only**'dir. Restart'ta historical frequency mean
NS-071'den gelebilir; diversity reference yeniden öğrenilmelidir. Persisted
summary extension, migration, evidence/cooldown persistence ve engine integration
yoktur. Bu kısıt baseline'a sahip olunmasına rağmen diversity warm-up gerektirir.

## Versioned default policy v1

| Alan | Değer | Sınır semantiği |
|---|---:|---|
| Baseline samples / coverage | 20 / 600 s | READY ve quality ayrıca gerekir |
| Current samples / coverage | 20 / 120 s | Inclusive minimum |
| Frequency multiplier | 3 | Rate strictly > 3 × reference |
| Frequency absolute floor | 10/min | Current rate >= floor |
| Reference frequency minimum | 1/min | Zero/low → insufficient_data, ratio yok |
| Diversity multiplier | 3 | Normalized diversity strictly > 3 × reference |
| Diversity absolute floor | 10 IP | Daha düşük count elevated olmaz |
| Reference count / cap | 3 / 8 | Clean independent windows |
| Coverage tolerance | %20 | Yukarıdaki explicit band |
| Reference maximum age | 86400 s | Session monotonic age |
| Confirmation count | 2 | Non-overlapping elevated current windows |
| Confirmation maximum gap | 1440 s | Envelope'lar arası daha büyük gap count'u sıfırlar |
| Cooldown | 600 s | Son eligible emission'dan monotonic süre |
| Scope hard cap | 128 | Her memory service için |

Typed immutable policy eşikleri bounded'dır; reference tüm policy değeriyle
eşleşmelidir. Relative cutoff'lar exact `Fraction` aritmetiğidir. Açıklama rate
ve ratio bounded finite float'tır. Zero/low reference sonsuz ratio üretmez.
Invalid current NaN/inf numeric değer evidence'da `None` ve current_invalid
sonucudur; normal hüküm verilmez.

## Scope, lifecycle ve quality

NS-071 owner güncel lifecycle/config compatibility sağlar. LEARNING ve
INSUFFICIENT_DATA → insufficient_data; INSUFFICIENT_QUALITY → insufficient_quality;
STALE/EXPIRED/CLOCK_ANOMALY/CORRUPT/UNSUPPORTED_VERSION/POLICY_MISMATCH/UNAVAILABLE
→ not_evaluated. READY'de canonical summary, scope, version, UTC, minimum
sample/coverage ve quality tekrar kontrol edilir. Future UTC baseline
clock_anomaly olur. Storage AVAILABLE olmalı; previous_unavailable/session_only
origin güçlü reference değildir.

Key canonical application path + exact SHA-256 veya explicit unknown revision +
resolved network fingerprint'tir. Same name farklı path, revision A/B/unknown ve
network A/B reference/cooldown paylaşmaz. Provisional/unknown application veya
unknown/ambiguous network not_evaluated. Unknown revision kendi scope'unda çalışır
ve `revision_unverified` limitation taşır.

Current/historical overflow/capacity loss iki comparison'ı engeller. Retained N ve
other_destinations exact total unique iddiası değildir. Unknown destination,
reduced appearance, saturated count veya non-COMPLETE current quality güçlü
comparison değildir. Current gap_seen insufficient_quality olur: eksik turda
gözlenebilen appearance ile conservative coverage'ın tam karşılaştırılabilirliği
garanti edilmez. NS-070 gap marker'ı scope lifetime'ında sticky'dir; yalnız yeni
kaliteli tur bunu temizlemez. Fresh accumulator/scope gerekir. Historical gap
tek başına NS-071 mean'i geçersiz yapmaz; offline süre coverage'a eklenmemiştir.

## Confirmation, cooldown ve bounds

Saf detector state/clock/I/O okumaz; normal/elevated_unconfirmed/insufficient/
not_evaluated evidence verir. `FrequencyDiversityService.evaluate` explicit
`now_monotonic` alır. Her rule için count yalnız current start >= previous
accepted end olduğunda artar. Same/overlapping rolling windows ve UI refresh
confirmation veya emission artırmaz. Normal/quality/lifecycle gate pending count'u
kırar; count required limitte saturate olur. Session veya baseline compatibility
key değişimi yeni state başlatır.

Confirmed deviation cooldown sırasında elevated_confirmed kalır; emission_eligible
False ve cooldown_active nedeni taşır. Evidence silinmez. UTC clock cooldown'u
etkilemez; monotonic regression clock_anomaly ve no emission/count ilerlemesi
verir. Süre dolduktan sonra yalnız yeni independent window eligible olur.
Bu emission eligibility'dir, AlertService dedup veya notification delivery değildir.

Her servis ayrı lock ve 128 scope hard cap taşır. Learner scope başına 8 aggregate
(toplam 1024), emission service scope başına 2 rule state (toplam 256) tutar.
Oldest accepted independent scope deterministik evict edilir; duplicate refresh
recency artırmaz. Evicted scope yeniden unconfirmed başlar. Eviction cooldown
history'sini de bırakır; sonraki doğrulamaya karşı suppression garantisi değildir.
Explicit `reset(scope)` dar kapsamlıdır. Future NS-071 reset owner hem learner hem
emission state'ini reset etmelidir; aynı policy altında reset generation'ını
mevcut NS-071 snapshot tek başına kanıtlamaz. Yeni service instance restart state'i
taşımaz; raw event/window history saklanmaz.

## Evidence ve future ordering

Evidence ayrı rule ID, full policy/version, classification/reason, exact scope ve
baseline scope/state/origin/storage/policy key, current appearance/coverage/retained/
overflow/reduced/unknown/gap/capacity/quality, reference rate/count/coverage/max IP/
end, historical mean/sample/coverage/UTC time, ratio, confirmation count, emission
eligibility ve current UTC time içerir. İki contributor birlikte elevated olabilir.

Future serialized owner sırası: previous learned reference + pre-mutation baseline
snapshot → NS-072 novelty → NS-070 update → NS-073 post-mutation current window
vs prior reference → NS-071 learning/checkpoint mutation. Current pencere kendi
reference'ına eklenmez. Bu task atomic engine/composition integration uygulamaz.

GUI, alerts/notifications, risk/severity/malware score, TI, packet/byte feature,
ML/time-of-day, config ve diagnostics değişikliği yoktur. NS-074 başlatılmadı;
M13 tamamlanmadı.

## Offline tests

Sentetik stable/burst/browser-CDN/updater; minimum/equality/absolute floor;
zero/low/finite rate; lifecycle/quality/scope/version; comparable coverage/reference
age; duplicate/overlap/confirmation/cooldown/eviction/reset testleri detector
test dosyasındadır. Gerçek tracker→accumulator→NS-073 testi INITIAL/long-lived/
close/reappearance ve iki FAILED/REDUCED tur sonrası no-backfill recovery'yi
doğrular. Explicit fake monotonic/UTC kullanılır; network/admin/driver/cloud yoktur.

2026-10-03 son doğrulama:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/application/detectors/test_frequency_diversity.py tests/unit/application/test_behavior_features.py tests/integration/sqlite/test_behavior_baselines.py tests/unit/application/detectors/test_destination_novelty.py
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/domain/frequency_diversity.py src/netsentinel/application/detectors/frequency_diversity.py src/netsentinel/application/services/frequency_diversity.py
git diff --check
```

Targeted **266 passed**; Ruff passed; normal mypy **22 source files**, direct
mypy **3 source files**, no issues. Yeni detector test dosyası 85 test, gerçek
accumulator dosyasına iki parametrized senaryo eklendi. Existing NS-071/072
regression testleri aynı targeted koşuda geçti.

İstenen `.\.venv\Scripts\python.exe -m pytest -q` collection'da Application
Control'ın repo Python `_overlapped` DLL'ini engellemesiyle iki hata verdi.
Güvenlik politikası/engellenen DLL değiştirilmedi. Codex'in mevcut, aynı sürüm
**Python 3.12.14** runtime'ında asyncio importu başarılıydı. Aynı repo site-packages
ve source path ile tam offline suite çalıştırıldı:

```powershell
$ns073PriorPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = 'C:\Users\berke\NetSentinel\.venv\Lib\site-packages;C:\Users\berke\NetSentinel\src'
    & 'C:\Users\berke\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -q
} finally {
    $env:PYTHONPATH = $ns073PriorPythonPath
}
```

Final full result **1390 passed, 7 deselected, 1 warning (57.00 s)**. Warning
existing Scapy/cryptography FFDH deprecation'dır. Opt-in live/lab testleri
çalıştırılmadı. Normal ve direct mypy repo venv Python'ıyla standart `-m mypy`
çalıştı; özel mypy launcher gerekmedi. `git diff --check` geçti.

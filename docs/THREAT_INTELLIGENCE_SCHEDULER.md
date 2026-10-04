# NS-087 — Bounded lookup scheduler

NS-087 application worker, NS-085 local cache ve NS-086 tek-attempt provider
portunu birleştirir. M15 devam eder; NS-088 başlamaz. SQLite **018 → 018**;
yeni migration, durable queue veya request replay yoktur.

**Status: COMPLETE (2026-10-04).** Full offline acceptance geçti.

Başlangıç: temiz `main`, HEAD `eca4aa563252342749536b7cb188608fd1405c30`.
Tarih: **2026-10-04** (Europe/Istanbul). TASKS.md acceptance authoritative'dir.

## Dondurulan runtime policy v1

| Bütçe | Default / hard üst sınır |
|---|---|
| Global outstanding jobs / dedup entries | 64 / 64, active dahil |
| Global fixed workers / active I/O | 4 / 4 |
| Provider outstanding jobs | 16 / 64, active/delayed/cache dahil |
| Provider eşzamanlı port çağrısı | 1 / 4 |
| Provider yerel minimum çağrı aralığı | 1 s, positive; configurable en çok 300 s |
| Denemeler | İlk + iki retry = 3, configurable en çok 8 |
| Exponential backoff | 1 s başlangıç, 30 s default cap |
| Retry-After cap | 300 s; daha uzun normalized hint typed clamp flag taşır |
| Yeni iş/retry fairness | En çok 2 yeni port dispatch sonrası hazır retry öncelikli |
| Completed polling retention | En çok 64 outcome, 300 s monotonic TTL |
| Shutdown join | Tüm pool için toplam en çok 2 s, tek ortak gerçek monotonic deadline |
| Waiter/subscriber listesi | Yok: duplicate ortak ticket paylaşır |

Policy ve provider budgets immutable validated application modelleridir.
Yerel minimum interval AbuseIPDB plan entitlement/quota varsayımı değildir.
Worker sayısı istek sayısıyla artmaz. Tek Condition deadline wait vardır;
per-request thread/Timer, hidden jitter veya caller sleep yoktur.
Mevcut RiskAlertWorker farklı risk/SQL/drain sözleşmesine sahip olduğundan
doğrudan reuse edilmez; aynı fixed daemon worker/Condition/bounded join convention
uygulanır. Yeni genel executor framework'ü veya dependency eklenmez.

## API, dedup ve completion

`ThreatIntelLookupScheduler.submit(ThreatIntelQuery) -> ThreatIntelSubmission`
yalnız memory validation, consent, bounded admission/dedup yapar. Provider sonucu,
SQLite/cache factory veya config dosyası beklemez. Typed submission states:
ACCEPTED, COALESCED, REJECTED_POLICY (+ denial), CAPACITY_REACHED, STOPPED, INVALID.
Request ID caller provenance'dir; logical iş ayrı UUID ticket taşır.

`poll(ticket) -> ThreatIntelScheduledOutcome | None` memory-only immutable
snapshot verir. `terminal` completion'ı ayırır. Pending state QUEUED/IN_FLIGHT/
DELAYED/OFFLINE_DEFERRED; terminal FRESH_CACHE/PROVIDER_RESULT/PROVIDER_ERROR/
CANCELLED_CONSENT/CANCELLED_SHUTDOWN'dır. Outcome, cache lookup/freshness, typed
provider result/error, attempts, cache mutation, clamp ve in-flight revoke flag'ini
ayrı tutar. `None`, expired/evicted/unknown ticket demektir. Sonuç cache put'tan
sonra terminal yapılır; persistence failure provider HIT/NO_HIT'i kaybettirmez.

Dedup key: NS-085 `ThreatIntelCacheKey(provider, data type, canonical subject,
hash algorithm, result contract version)` + trigger + query policy version +
consent UUID. UUID submission identity dedup key değildir; consent UUID revoke/
regrant epoch'larını ayırır. Mapping v1/result contract v2 mevcut cache key'ini
kullanır; normalization değişikliği NS-086 kuralına göre contract/key bump ister.

Pending veya in-flight duplicate aynı ticket/outcome paylaşır. Yeni logical job,
HTTP çağrısı veya waiter oluşturmaz. Shared provider result ilk admitted query'nin
request ID ve consent provenance'ını korur; her coalesced query için yeni result
üretilmez. 10k duplicate yalnız transient submission nesneleri üretir; scheduler
tek işi saklar. Distinct storm provider/global capacity'de typed reject olur.
Admission concurrency lock'u hiçbir network/SQLite I/O boyunca tutulmaz.

Completion bir kez terminal polling snapshot olarak saklanır. Callback/event
subscribe API eklenmediğinden subscriber failure ve disposed-widget callback
problemi yoktur; Future.result caller yolu veya unbounded subscriber registry yoktur.
Retention max/TTL cleanup submit değil poll/diagnostics/finish sırasında lazy'dir;
idle storage en çok 64'tür, expired outcome okunmaz. Restart retention'ı temizler.

## Cache davranışı

Cache factory ve read/write worker'a aittir. Cache-first aşaması network offline,
provider rate-limit veya budget delay sırasında da çalışır.

| Cache read | Sonuç |
|---|---|
| FRESH HIT / FRESH NO_HIT | FRESH_CACHE completion, sıfır provider/HTTP |
| STALE HIT / STALE NO_HIT | Cache stale görünür kalır; admitted explicit refresh planlanır |
| MISS / EXPIRED | Eligible provider attempt |
| CORRUPT / UNSUPPORTED / CLOCK_ANOMALY / UNAVAILABLE | Typed limitation korunur, eligible provider attempt devam edebilir |
| Factory/read exception | Sanitized UNAVAILABLE, provider engellenmez |
| HIT / NO_HIT provider | NS-085 put → mutation receipt → terminal outcome |
| ERROR provider | Cache write yok; stale fallback + refresh ERROR birlikte korunur |
| Put failure | Provider sonucu + typed failed mutation; eski stale entry fresh yapılmaz |

FRESH ve STALE NS-085 UTC TTL semantiğidir; runtime delay/retention monotonic'tir.
Outcome.cache refresh öncesi snapshot'tır; başarılı refresh outcome.result ve
cache_write'dadır. Sonraki explicit submit yeni cache read ile fresh row'u görür.
NO_HIT safe/clean/trusted değildir; HIT malware hükmü değildir.

## Rate limit, retry ve fairness

Retryable enum'lar: **TIMEOUT, NETWORK_ERROR, UNAVAILABLE (adapter 5xx), RATE_LIMITED**.
Diğerleri terminal: AUTHENTICATION (401/403), CREDENTIAL_UNAVAILABLE,
SUBSCRIPTION_RESTRICTED (402), INVALID_REQUEST (422), INVALID_RESPONSE
(malformed/mismatch), UNSUPPORTED, HTTP_ERROR, REDIRECT_REJECTED,
TRANSPORT_SECURITY_ERROR, RESPONSE_TOO_LARGE. Port exception sanitized UNAVAILABLE;
untyped veya wrong-query return INVALID_RESPONSE. Raw exception taşınmaz.

Attempt n sonrası delay `min(max_backoff, initial_backoff * 2^(n-1))`.
Hard attempt cap overflow ve unlimited retry'ı önler. RATE_LIMITED'da normalized
Retry-After varsa `max(backoff, min(hint, retry_after_cap))`; zero hint dahi immediate
storm yaratmaz. Absent/malformed hint backoff'a düşer. NS-086 zaten numeric header'ı
0..86400 clamp eder; scheduler bu hint'i en çok 300'e indirir ve flag'i saklar.
Raw HTTP-date parsing scheduler'da yapılmaz; NS-086 date/malformed header None olur.

429 provider-wide monotonic next-call deadline'ını uzatır; son attempt'te de
diğer provider işlerini korur. Aynı provider işleri bounded DELAYED kalır.
Provider A backoff B'yi durdurmaz. Minimum interval rezervasyonu ve concurrency
sayacı aynı lock'ta tutulur; retry de normal local budget kullanır. In-flight
çağrılar sonradan gelen 429 ile geri alınamaz.

Provider round-robin; hazır yeni iş/retry sınıflarında stable FIFO uygulanır.
İki yeni dispatch'ten sonra hazır retry önce değerlendirilir; ready olmayan
provider/job diğerlerini engellemez. Retry kuyruğu yeni manuel işleri, bir
provider storm'u diğer provider'ın admitted işlerini kalıcı olarak aç bırakmaz.
Global saturation durumunda başka provider'a admission garantisi yoktur;
provider capacity yerel share ve bounded rejection sağlar.

## Consent, offline ve privacy

Admission, execution hemen öncesi ve her retry güncel **memory consent snapshot**
üzerinden pure NS-084 policy'yi doğrular. Bootstrap startup'ta config'i bir kez
okur; Settings Save/current (yeniden açma dahil) snapshot'ı günceller. Tek bounded
notification slot scheduler.wakeup'ı çağırır ve revoked pending/delayed işleri
hemen iptal eder. External config file değişiklikleri otomatik watched değildir;
current/reopen ile refresh edilir. Config read failure snapshot'ı default-deny yapar.
Custom injected read_consents callable memory-only olmalı; caller disk I/O yapmaz.

Cache read sürerken revoke job'ı cancellation için işaretler; provider'a gidilmez.
In-flight HTTP geri alınamaz. Completion CANCELLED_CONSENT +
consent_revoked_during_flight verir; diagnostic cancellation sayılır ve retry yoktur.
Sonuç cancellation context'inde kalabilir; revoke observed old job'ı regrant dahi
canlandırmaz. Yeni consent UUID ile explicit yeni submit ayrı bounded job'dır.
Revoke cache purge değildir. Aktif cache transaction revoke/stop'tan önce başladıysa
tamamlanabilir; revoke existing cache'i silmez.

Connectivity default unknown/allowed'dır; **set_network_available(bool)** explicit
memory input'tur. DNS/ping/HTTP connectivity probe yoktur. Known offline'da fresh
cache complete, stale görünür OFFLINE_DEFERRED, miss OFFLINE_DEFERRED olur; HTTP
sıfırdır. Pending bounded slot tutar. Online signal, lifetime içindeki consent-valid
işi normal budgets ile devam ettirir; catch-up storm oluşturmaz. NETWORK_ERROR
global offline state üretmez. Native OS connectivity watcher bu taska eklenmez.

Scheduler credential value'yu çözmez/görmez/loglamaz; yalnız provider portu bilir.
AbuseIPDB adapter SecretStore'u yönetir. Bootstrap explicit secrets/providers
injection sunar; desktop default secret store None döndürür. Credential backend ve
key UI henüz yoktur; default admitted miss terminal CREDENTIAL_UNAVAILABLE üretir,
sıfır HTTP ve retry. Bu sınır yeni secret persistence sistemiyle genişletilmez.

**NetSentinel does not upload your network history by default.** Subjects yalnız
bounds içindeki runtime jobs/cache/outcomes'ta bulunur; diagnostics repr ticket,
subject, credential veya exception içermez. No history enumeration/batch API.

## Composition, diagnostics ve shutdown

Bootstrap consent/cache registry/AbuseIPDB scheduler'ı compose eder; construction
DB/secret/HTTP erişmez (consent config load ayrı). ApplicationShell scheduler'ı
explicit API için tutar. ApplicationLifecycle start/quit bir kez worker start/stop
çağırır. Optional initialization/start failure local engine'i durdurmaz; diagnostic
running=False/absent kalır. Consent dialog yalnız consent metnini günceller; lookup
button veya TI result view yoktur. Startup, engine events, connection selection ve
consent dialog open/save: **0 lookup**. Engine constructor/poll pipeline'a scheduler
hook eklenmez. GUI Qt event loop slow provider sırasında çalışmaya devam eder.

Shared immutable `ThreatIntelSchedulerDiagnostics`, current running/online,
outstanding/active/delayed/offline/retained ve aggregate admission/coalescing/cache/
port attempts/retry/429/cancel/completion/failure counters taşır.
collect_diagnostics/capability factory optional scheduler snapshot'ını ekler;
yeni scheduler detail UI veya per-job diagnostics history yoktur. provider_calls
port attempts sayar; missing credential dahil HTTP yapmayan adapter result'ı da
port attempt'tir. Diagnostics log/network upload yapmaz.

Stop admission'ı kapatır; queued/cache-ready/offline/delayed işleri typed shutdown
cancel eder; active işler dönünce CANCELLED_SHUTDOWN tamamlanır, yeni retry yoktur.
Pool toplam 2 saniye join bekler; timeout False/degraded döner. Python thread zorla
öldürülmez. NS-086 socket/body bound 8 saniyedir; **OS DNS çözümü için wall-clock
üst sınır garantisi yoktur**. Bu yüzden bütün worker'ların mutlaka 8 saniyede
çıktığı iddia edilmez. Bounded olan shutdown'ın bekleme süresidir; daemon worker
geç tamamlanabilir. Live eski worker varken restart reddedilir. Test gates finally
release edilir ve tüm worker'lar join edilir; immortal test worker yoktur.

Restart runtime queue/completions/rate state replay etmez; fresh persistent cache
network'i engellemeyi sürdürür. Backoff yeniden başlatmada reset olabilir.
No scheduler DB migration; 001–018 SQL değişmez. NS-088 RiskEvidence, assessment
revision, AlertService integration, provider voting/scoring, firewall ve result UI
eklenmez. M15 COMPLETE yapılmaz.

## Kabul doğrulaması ve teslim envanteri

Yeni dosyalar:

- `src/netsentinel/application/services/threat_intel_scheduler.py`
- `tests/unit/application/test_threat_intel_scheduler.py`
- `tests/integration/test_threat_intel_scheduler.py`
- `tests/gui/test_threat_intel_scheduler.py`
- `docs/THREAT_INTELLIGENCE_SCHEDULER.md`

Değişen dosyalar: `src/netsentinel/application/services/threat_intelligence.py`,
`src/netsentinel/bootstrap.py`, `src/netsentinel/presentation/app.py`,
`src/netsentinel/presentation/widgets/threat_intel_consent.py`,
`src/netsentinel/shared/diagnostics.py`, `tests/unit/infrastructure/test_abuseipdb.py`,
`docs/{ARCHITECTURE,SECURITY,PRODUCT,THREAT_INTELLIGENCE_CONSENT,
THREAT_INTELLIGENCE_CACHE,TASKS,ROADMAP}.md`.

NS-086 structural regression, artık composition root'ta adapter olmamasını değil
yalnız scheduler composition ve engine'de adapter/synchronous lookup olmamasını
doğrular; fixture secret/redaction/adapter endpoint assertions korunur. Direct
mypy'ın ortaya çıkardığı mevcut bootstrap DNS kwargs typing ve app loop-variable/
optional narrowing sorunları yalnız type annotations/local names ile düzeltilir;
bu alanlarda runtime davranış değişmez. Consent UI'daki eski "production provider
yok" metni consent-only davranışı doğru anlatır; NS-088 controls eklenmez.

**98 yeni offline case**: fake monotonic boundaries, bütün operational error enum
retry matrisi, 10k duplicate/1000 distinct storm, canonical IPv6, cache states/write
ordering/failures/restart, A/B concurrency/rate/fairness/isolation, offline→online,
proactive ve execution-only revoke/regrant, bounded stop/partial start failure,
production AbuseIPDB port + fake HTTP + gerçek SQLite, main-thread Qt tick ve
engine'in slow provider sırasında ikinci poll'u. Event gates/Condition synchronization
kullanılır; arbitrary sleep correctness koşulu yoktur. Bütün provider gates finally
release ve workers join edilir. HTTP fixtures/fakes; gerçek key veya provider request yok.

Exact komutlar, repo executable:
`C:\Users\berke\NetSentinel\.venv\Scripts\python.exe`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/application/test_threat_intel_scheduler.py tests/integration/test_threat_intel_scheduler.py tests/gui/test_threat_intel_scheduler.py
.\.venv\Scripts\python.exe -m pytest -q tests/unit/application/test_threat_intel_scheduler.py tests/integration/test_threat_intel_scheduler.py tests/gui/test_threat_intel_scheduler.py tests/unit/domain/test_threat_intelligence.py tests/unit/domain/test_threat_intel_cache.py tests/unit/application/test_threat_intel_service.py tests/unit/application/test_threat_intel_cache_service.py tests/unit/infrastructure/test_abuseipdb.py tests/unit/infrastructure/test_threat_intel_http.py tests/integration/sqlite/test_threat_intel_cache.py tests/unit/shared/test_threat_intel_config.py tests/gui/test_threat_intel_consent.py tests/gui/test_app_lifecycle.py tests/gui/test_application_shell.py tests/integration/test_runtime_diagnostics.py tests/unit/shared/test_config_logging_diagnostics.py tests/unit/application/test_engine.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/application/services/threat_intel_scheduler.py src/netsentinel/application/services/threat_intelligence.py src/netsentinel/bootstrap.py src/netsentinel/presentation/app.py src/netsentinel/presentation/widgets/threat_intel_consent.py
git diff --check
```

Hedefli geniş regression: **533 passed in 24.37 s**. Son beş yeni race/fairness case
eklendiğinde scheduler-only command **98 passed in 1.88 s**. Ruff **All checks
passed**; configured mypy **31 source file**, direct mypy **5 source file** temiz.
Full offline suite: **2824 passed, 8 deselected in 106.48 s**. Default marker
policy Windows/lab/live TI testlerini dışladı; uncontrolled external provider
request yapılmadı. NS-088 task entry değişmedi; M15 devam ediyor.
`git diff --check` exit 0; schema SQL dosyalarında değişiklik yoktur.

İlk regression run yalnız NS-086'ın tarihsel "bootstrap adapter compose etmez"
assertion'ında başarısızdı; assertion NS-087 scheduler-only sınırına güncellendi.
İlk yeni test iterasyonlarında repo schema API/Qt page accessor beklentileri
düzeltildi ve yeni iş/retry sıralaması fairness bütçesiyle tamamlandı.

İstenen final rapor alanlarının eşlemesi:

| # | Sonuç / yukarıdaki sözleşme karşılığı |
|---|---|
| 1–5 | Exact NS-087 — Bounded lookup scheduler; COMPLETE; M15 devam ediyor; schema 018→018, migration yok |
| 6–10 | Application scheduler/policy/budget/query/submission/ticket/outcome; memory-only submit/poll; deterministic cache key + trigger/policy/consent epoch |
| 11–13 | Pending/in-flight duplicates aynı shared ticket; 0 subscriber/waiter listesi |
| 14–19 | Global outstanding64/workers4; provider outstanding16/concurrent1/local minimum interval1s; ayrı provider budgets/deadlines |
| 20–23 | 3 attempts; initial1s/max30s backoff; Retry-After clamp300s |
| 24–30 | Explicit retryable/nonretryable matrix; 429 provider-wide deadline, numeric hint/backoff fallback; A backoff B'yi engellemez; fake B aynı port/core |
| 31–32 | Runtime deadlines/retention injectable monotonic; manual fake advance+wakeup; UTC cache TTL ayrı; joins gerçek monotonic |
| 33–43 | Fresh HIT/NO_HIT 0 HTTP; stale status+refresh error birlikte; miss/provider, corrupt/unavailable typed context; write fail provider result korunur; ERROR hiç cache put yapmaz |
| 44–51 | Admission/dispatch/retry snapshot gate; proactive pending/delayed cancel, execution-only recheck; in-flight cannot unsend/no retry; regrant resurrection yok; cache purge yok |
| 52–56 | Explicit bool availability input, no probe; offline fresh complete, stale/miss deferred; online normal budget ile bir execution |
| 57–62 | 10k same-key single job; distinct typed capacity reject; round-robin/fresh-burst fairness; validated static registry, unsupported unknown provider; real AbuseIPDB + fake B core test |
| 63–65 | Secret adapter-owned injected port; scheduler value'yu görmez; NS-085 exact result key2/mapping1; future mapping contract-version bump ister |
| 66–69 | Port returns→put→terminal poll outcome; write failure included; terminal bir kez; event/subscriber API yok; retention64/300s |
| 70–74 | Sanitized shared immutable aggregate diagnostics/optional composition; startup0lookup; optional init/start failure local engine'e yayılmaz; secret backend default unavailable |
| 75–80 | Engine slow provider sırasında ikinci poll yapar; Qt tick çalışır; automatic engine/selection/history/batch path yok |
| 81–88 | Reject after stop; pending/delayed cancel; active result shutdown-typed; toplam join2s; DNS caveat; old live worker restart denied; runtime no replay, persistent fresh cache 0 HTTP; durable queue yok |
| 89–94 | RiskEvidence/revision/AlertService/provider vote/firewall/NS-088 result UI eklenmedi |
| 95–99 | Yukarıdaki added/modified inventory, 98 new cases, exact commands; geniş targeted533 + son scheduler98 pass |
| 100–103 | Full pytest2824 passed/8 deselected; Ruff/configured31+direct5 mypy temiz; diff check exit0 |
| 104–105 | Yalnız NS-087 newly COMPLETE; NS-088 task entry unchanged; focused scheduler doc ve current architecture/security/product notes |
| 106–109 | `feat: add bounded threat intelligence scheduler`; full hash/push/tree final mesajda; NS-088 başlamadı |

Commit hash/push receipt final teslim mesajında verilir; belge kendi commit hash'ini
kendine yazmaz.

# NS-085 — Reputation cache ve freshness

**NS-087 güncellemesi (2026-10-04):** Local cache service scheduler worker'larında
lazy compose edilir; fresh result sıfır provider call, stale+refresh error ayrı
korunur. Cache mutation completion'dan önce olur; failure provider sonucunu
kaybettirmez. Consent revoke purge yapmaz. Key/result/codec **2**, schema **018**
değişmez. [Runtime sözleşmesi](THREAT_INTELLIGENCE_SCHEDULER.md).

**NS-086 güncellemesi (2026-10-04):** Aşağıdaki v1 kayıtları NS-085 teslimatını
belgeler. Güncel result contract/key ve payload codec **2**'dir. Optional typed
`ip_facts`: mapping_version=1, lookback_days, abuse_confidence_score,
total_reports, distinct_users, last_reported_at ve is_whitelisted. Dict/blob/free
text alanı yoktur. Rate-limit metadata/cache errors saklanmaz. Version 1 key'leri
UNSUPPORTED; güncel key yalnız kendi version 2 row'unu okur. Mapping değişikliği
result contract key version bump gerektirir. Schema **018**, SQL/migration
değişmez; mevcut 4 KiB/1024 row/chunk/TTL/error-skip sınırları korunur.
[NS-086 karar ve kabul raporu](THREAT_INTELLIGENCE_PROVIDER_ABUSEIPDB.md).

## Sözleşme ve sürümler

Bu task yalnız yerel cache backend'idir. Domain `ThreatIntelCacheKey`,
`ThreatIntelCachedResult`, `ThreatIntelCacheEntry`, `ThreatIntelCacheLookup`,
`ThreatIntelCacheFreshness`, `ThreatIntelCachePolicy` ve typed mutation receipt
sağlar. Application `ThreatIntelCacheService` ve `ThreatIntelCacheRepository`
portu concrete SQLite/codec'ten ayrıdır. Desktop/engine composition değişmez;
servis blocking olduğu için ileride component-owned worker'da çağrılmalıdır.
Construction DB açmaz, tüm cache'i restore/preload etmez.

Başlangıç HEAD `e5938833b09a516c8e7efa51d94d28d1f9cb8ad2`, main ve temiz
çalışma ağacı doğrulandı. Schema **017 → 018**: append-only
`018_threat_intel_cache.sql`. 001–017 SQL dosyaları değişmez. Manifest ve güncel
schema bekleyen regression testleri 018'e taşınır; eski data/lifecycle/hash
kontrolleri korunur. M15 devam eder; NS-086–088 başlamaz.

Exact primary key:

`provider_id × data_type × subject_kind × canonical_subject × hash_algorithm × result_version`.

- Provider A ve B aynı subject için farklı kayıt taşır. Sonuçlar birleştirilmez.
- Data type mevcut NS-084 subject kind ile uyuşmalıdır; IP/domain/hash çapraz
  kullanılamaz. String IP domain subject olarak da kabul edilmez.
- Canonicalization tamamen NS-084 `ThreatIntelSubject` kullanır: IPv4 canonical
  address, IPv6 compressed address, ASCII lowercase/trailing-dot domain ve
  lowercase 64 karakter SHA-256. İkinci canonicalizer veya validator yoktur.
- Hash algorithm açık `sha256` key boyutudur; IP/domain için boş string'dir.
- **Result contract version 1**, uygulamanın normalize edilmiş HIT/NO_HIT/ERROR
  sözleşmesinin sürümüdür (`TI_RESULT_CONTRACT_VERSION`). Consent policy version
  değildir. NS-084 provider dataset/adapter mapping version sunmaz; uydurulmaz.
  Future result version ayrı key'dir ve mevcut repository UNSUPPORTED döndürür.
- Consent/current grants, trigger ve request UUID cache identity değildir.
  Consent revoke cache key değiştirmez veya otomatik purge yapmaz.
- Payload format **1** ayrı storage codec sürümüdür. Future format UNSUPPORTED;
  malformed format CORRUPT olur. Future format bugünkü modele yorumlanmaz.

## Minimum snapshot

Key yanında yalnız NS-084 result status, request UUID, original `queried_at`,
`received_at`, trigger ve query policy version tutulur. Cache completion/fetch time
**received_at**'tır. Bu, local TTL başlangıcıdır; provider dataset güncelliği
garantisi değildir. `fresh_until` ve `stale_until` absolute UTC olarak saklanır.
Read sırasında güncel TTL policy ile eski kayıt yeniden hesaplanmaz.

`ThreatIntelCachedResult` minimum immutable projection'dır; orijinal query/consent
object graph'ını persist etmez, authorization olarak kullanılamaz. Read doğrulaması
NS-084 query/result validator'larını consent olmadan reuse eder. NO_HIT ve HIT
aynen round-trip olur. NS-084 başka normalized provider metadata sunmadığından
raw response, arbitrary keys, free text, score, vote veya provider blob alanı yoktur.

Codec JSON exact allowlist, strict field types, duplicate rejection, deterministic
sorted serialization, finite values, byte bound ve read validation uygular.
Timestamp columns ile payload completion time eşleşmelidir. Unknown field,
malformed/oversize/deep JSON, invalid enum/UUID/UTC/horizon CORRUPT olur. SQL önce
payload byte length ve numeric timestamp types kontrol eder; bozuk büyük value
Python'a hydrate edilmez. Exact key read PRIMARY KEY index + tek `fetchone` kullanır.

## TTL ve sonuç matrisi

Değerler tek immutable `ThreatIntelCachePolicy` içinde sabittir; config/UI eklenmez.
Policy/repository ve service farklı değerlerle oluşturulamaz.

| Provider sonucu | Fresh TTL | Stale grace | Yazma |
|---|---:|---:|---|
| HIT | 24 saat | 24 saat | Normalized snapshot |
| NO_HIT | 1 saat | 24 saat | Negative cache: provider kaydı yok |
| ERROR (timeout dahil) | Yok | Yok | ERROR_SKIPPED, SQL yok |

HIT→NO_HIT ve NO_HIT→HIT yeni fetch ile replacement'tır; history/revision tutulmaz.
NO_HIT **clean/safe/benign/trusted değildir**. ERROR hiçbir zaman NO_HIT değildir.
ERROR; empty, fresh HIT/NO_HIT veya stale HIT/NO_HIT cache'ini değiştirmez.
Refresh error ileride ayrı operational context'te, önceki stale snapshot ile
birlikte açıklanabilir; NS-085 scheduler veya error-cache/backoff kurmaz.

| Cache state | Caller semantiği |
|---|---|
| FRESH | Entry + provider HIT/NO_HIT görünür, local TTL içinde |
| STALE | Entry + provider HIT/NO_HIT görünür, current truth değildir |
| EXPIRED | Kullanılabilir entry yok; geçici physical row kalabilir |
| MISS | Kayıt yok; provider NO_HIT iddiası yok |
| CORRUPT | Kullanılabilir entry yok; diğer kayıtlar bağımsız okunur |
| UNSUPPORTED | Provider/capability/result version/format desteklenmiyor |
| UNAVAILABLE | Storage failure; provider error veya NO_HIT değildir |
| CLOCK_ANOMALY | Küçük backward UTC shift; sonuç fresh olarak sunulmaz |

Freshness ve provider status iki ayrı eksendir. Yalnız FRESH/STALE lookup entry
taşır; diğer state'lerde entry verilmesi constructor tarafından reddedilir.

Exact boundaries: `now < fresh_until` FRESH; `now == fresh_until` ve
`fresh_until < now < stale_until` STALE; `now >= stale_until` EXPIRED.
Grace sıfırsa fresh boundary doğrudan EXPIRED olur. Okuma/touch TTL uzatmaz.

## UTC, restart ve saat anomalisi

Tüm API'ler caller-supplied UTC-aware `now` alır. Pure freshness içinde hidden
clock yoktur. Restart için integer UTC epoch microseconds + normalized UTC JSON
timestamps kullanılır; monotonic zaman persist edilmez. Yeni repository/service
aynı kaydı elapsed UTC'ye göre FRESH, STALE veya EXPIRED okur.

Future completion timestamp yazımda reddedilir (INVALID). Read sırasında
`now < received_at` için fark en çok **5 dakika** ise CLOCK_ANOMALY, daha büyükse
CORRUPT; sonuç verilmez, negatif age/freshness uzatılması yoktur. Bu durum row'u
otomatik silmez; saat düzelince yeniden okunabilir. Büyük forward jump direkt
EXPIRED olur; loop/timer/refresh başlatılmaz. Datetime uç sınırları taşmadan
değerlendirilir. Corrupt timestamp/horizon tek kayıtla sınırlı kalır.

## Kaynak bütçeleri ve eviction

| Kaynak | Bound |
|---|---:|
| RAM front-cache entries | **0**, front cache yok |
| Registry | NS-084 en çok 16 descriptor |
| Normalized snapshot | **4.096 UTF-8 byte** hard upper bound |
| Disk entries | **1.024** total, key/text lengths ayrıca bounded |
| Cleanup/purge transaction | **128** silinen satır |
| Read | Tek size-gated row; tüm store hydrate edilmez |
| Normal put | Bir row + en çok bir quota eviction |

Policy daha küçük test/deployment bütçesi seçebilir, hard bounds'ı yükseltemez.
Normalized payload toplamı en çok 4 MiB; bounded keys ve indexes ayrıca sabit
ek maliyet taşır. Bu **logical TI store quota**'dır; paylaşılan SQLite file/WAL
boyutu veya diğer store'ların quota'sı değildir. Freed pages tekrar kullanılır;
purge/write otomatik VACUUM veya shared database quota redesign yapmaz.
Python state cache size ile büyümez; SQLite connection'ın mevcut bounded engine
buffers/convention'ı kullanılır. Persistent LRU/access timestamp yazımı yoktur.

Quota eviction deterministic: önce EXPIRED, ardından STALE, ardından zorunluysa
FRESH; her group'ta oldest `received_at`, sonra tüm key dimensions lexical sıradır.
Bu local cache eviction'dır; malware/no-hit/novelty üretilmez, sonraki lookup MISS'tir.
Global quota gerektiğinde başka provider'ın en eski kaydını evict edebilir;
per-provider/per-type quota yoktur. Exact-key upsert ve scoped purge başka
provider'ı değiştirmez. Provider sonuçları veya subjects merge edilmez.

Store yeniden açıldığında daha küçük capacity seçilirse explicit `cleanup(now)`
expired-first en çok 128 row siler ve `remaining` bildirir. Büyük mevcut overflow
put sırasında tek chunk'ta giderilemiyorsa put rollback + INVALID olur; caller
chunk cleanup tamamlayabilir. Constructor/read bulk cleanup başlatmaz.

## Atomiklik, sıralama ve hata

Component-scoped connection, mevcut WAL/busy timeout ve `BEGIN IMMEDIATE` transaction
reuse edilir; global writer redesign yoktur. Conditional upsert + quota deletion
tek transaction'dır. Daha yeni received_at kazanır; older late result NO_CHANGE.
Equal received_at'ta canonical payload lexical greater kazanır; aynı payload
NO_CHANGE'dir. Tie güvenlik önceliği değildir; repeat/concurrent ordering'den
bağımsız deterministik sonuç içindir. Same-key concurrent writes tek row bırakır.

DB open/busy/migration/read/write/commit/delete failure typed UNAVAILABLE olur;
raw SQL/path/exception caller'a taşınmaz. Başarısız update veya eviction, eski
snapshot'ı korur ve partial insert/delete commit etmez. Corrupt/unsupported read
row'u fresh veya provider NO_HIT'e dönüştürmez; caller sonraki consent-controlled
provider işini storage failure'dan ayrı değerlendirebilir.

## Purge, consent ve gizlilik

`purge(key=...)`, `purge(provider=...)` veya `purge()` yalnız TI tablosunu siler.
Key/provider aynı komutta birleştirilemez; IDs typed'dır. Receipt PURGED,
`affected` ve `remaining` taşır. En çok 128 row/transaction; all/provider scope'u
tam temizlemek için caller `remaining=False` olana kadar explicit chunk çağırır.
Silinecek collection Python'a yüklenmez. Purge removed/unknown provider için de
mümkündür. Assessment, alert, DNS/connection history, baseline, device trust,
preference ve audit tablolarına dokunulmaz. GUI purge controls eklenmez.

Local read cloud consent istemez ve veri göndermez. Consent revoke future
provider lookup'ı NS-084'te reddeder; mevcut cache ayrı explicit purge ile silinir.
Provider registry boş/removed ise service UNSUPPORTED döner, startup crash olmaz.
Production registry boş kalır. Cache service provider port/secret store çağırmaz.

Canonical IP/domain/SHA-256 ve normalized result provenance yerel hassas davranış/
güvenlik metadata'sı olabilir. API key/secret/secret reference, executable path,
file content, command line, user note, raw packet/HTTP response veya history bundle
cache key/payload'da yoktur. Subject/entry repr'de gizlidir. Diagnostics/log field
değişimi, subject dump veya yeni aggregate counter registry eklenmez; typed
receipts yalnız bounded status/count taşır. Yerel DB forensic authenticity sağlamaz.

## Kapsam dışı

Real HTTP/provider adapter, networking dependency, automatic refresh, retry/rate
limiter/scheduler, history/file upload veya batch-history API yoktur. Cache HIT
RiskEvidence oluşturmaz, assessment/revision/scoring veya AlertService çağırmaz.
Malware votes, provider consensus, automatic blocking ve result GUI eklenmez.
Cache-aware provider orchestration helper eklenmedi; bütün get işlemleri yalnız
yerel I/O'dur. NS-086, NS-087 ve NS-088 ayrı tasklar olarak planlı kalır.

## Kabul doğrulaması

New test files:

- `tests/unit/domain/test_threat_intel_cache.py`: saf identity/UTC/horizon/policy.
- `tests/unit/application/test_threat_intel_cache_service.py`: lazy local boundary.
- `tests/integration/sqlite/test_threat_intel_cache.py`: fake UTC boundaries,
  positive/negative/error matrix, canonical subjects, provider/type/version isolation,
  restart, no touch, future/backward/forward clocks, late/tie/concurrent upsert,
  schema/codec corruption, SQL size gates, quotas/eviction/rollback, scoped chunk
  purge, unaffected other stores, registry removal, privacy ve migration/index.

New implementation files: domain/cache, application/services/cache,
infrastructure/sqlite/cache_codec, cache_repository ve schema/018. Modified code:
NS-084 result-version constant, application ports ve migration manifest. Mevcut
SQLite/packaging/pipeline testlerinde yalnız current schema expectations ve
synthetic next-migration probes güncellenir; product behavior/refactor yoktur.

**Status COMPLETE**, M15 devam ediyor. 82 yeni cache test case; NS-084 ve migration
regressions ile hedefli **220 passed**. Full offline suite **2547 passed,
7 deselected** (111.23 saniye). Ruff temiz; configured mypy 31 source file,
direct mypy üç application/infrastructure file temiz. Domain/configured port
configured mypy kapsamındadır. `git diff --check` temiz; 001–017 SQL değişmez.

Kullanılan executable bütün komutlarda repo içindeki
`C:\Users\berke\NetSentinel\.venv\Scripts\python.exe`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/domain/test_threat_intel_cache.py tests/unit/application/test_threat_intel_cache_service.py tests/integration/sqlite/test_threat_intel_cache.py tests/integration/sqlite/test_migrations.py tests/unit/domain/test_threat_intelligence.py tests/unit/application/test_threat_intel_service.py tests/unit/shared/test_threat_intel_config.py tests/gui/test_threat_intel_consent.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/application/services/threat_intel_cache.py src/netsentinel/infrastructure/sqlite/threat_intel_cache_codec.py src/netsentinel/infrastructure/sqlite/threat_intel_cache_repository.py
git diff --check
```

İlk full run yalnız 11 historical current-schema expectation nedeniyle başarısız
oldu; beklentiler 018'e/synthetic next probe 019'a güncellendikten sonra bütün
suite geçti. Old migration hash/data/lifecycle assertions kaldırılmadı. Tests
offline'dır; 7 live test varsayılan marker policy ile dışarıda kalır.

`docs/TASKS.md` yalnız NS-085'i yeni COMPLETE yapar; M15 summary/ROADMAP current
status günceldir. ARCHITECTURE/SECURITY cache boundary'yi açıklar. Commit message:
`feat: add bounded threat intelligence cache`; main'e normal push istenir,
force/tag/release/new branch yoktur. Commit hash/push sonucu final teslim raporunda
verilir; belge commit'in kendi hash'ini içine yazmaz.

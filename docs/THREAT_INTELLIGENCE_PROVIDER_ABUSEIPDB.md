# NS-086 — İlk provider adapter

## Karar ve resmi kaynak incelemesi

Review date: **2026-10-04** (Europe/Istanbul). Provider: **AbuseIPDB LLC**.
İncelenen resmi sayfaların erişim snapshot'ı bu tarihtir; tam sayfa kopyası
saklanmaz. Terms ve Privacy sayfalarının gösterdiği Last Updated: **3/15/2023**.
API docs ve pricing sayfalarında ayrı revision tarihi gösterilmedi.

- [API v2 documentation](https://docs.abuseipdb.com/): CHECK tek IPv4/IPv6
  sorgular; default lookback 30 gündür. Verbose raporları büyütür. Key özel
  credential'dır; header kullanımı önerilir. Kotalar plana bağlıdır; 429 ve
  Retry-After/X-RateLimit headers belgelenmiştir. Whitelist action temeli değildir.
- [Terms / Legal](https://www.abuseipdb.com/legal): Yetkili API kullanımı
  otomasyon kısıtının istisnasıdır. Hesap sorumluluğu ve quota aşmak için çoklu
  hesap yasağı vardır. Free ticari amaçla kullanılamaz; commercial kullanım için
  Basic veya üstü Paid Plan gerektirir. Şartlar değişebilir; kullanımdan önce
  yeniden incelenmelidir. Bu teknik review legal clearance değildir.
- [Privacy Policy](https://www.abuseipdb.com/privacy): Kullanım/teknik veri ve IP
  toplanabilir; ABD dahil AB dışı işleme ve hizmet sağlayıcılarla paylaşım
  açıklanır. PII, toplama amaçları ile hukuki/muhasebe/raporlama gereksinimleri
  için gerekli süre tutulur; yükümlülükler, uyuşmazlıklar ve sözleşme uygulaması
  için de saklanabilir. CHECK sorguları için kesin retention süresi belirtilmez;
  sıfır retention veya silme garantisi çıkarılmaz.
- [API Plans & Pricing](https://www.abuseipdb.com/pricing): Business subscription
  planları sunulur. Bu gözlem ürünün veya belirli kullanıcının lisans/hukuk
  uygunluğu hakkında garanti vermez; fiyat/kota kodda sabitlenmez.

Seçim gerekçesi: tek seçili IP, IPv4/IPv6, küçük non-verbose summary, açık rate
limit davranışı ve header credential, selected-destination modeliyle uyumludur.
Domain/hash soyutlaması korunur; ilk provider yalnız IP_REPUTATION ilan eder.

## Uygulama öncesi dondurulan plan

- Sabit `https://api.abuseipdb.com/api/v2/check`, GET, Accept application/json;
  query yalnız canonical ipAddress ve maxAgeInDays=30. **verbose gönderilmez**.
- Policy/mapping **1**. Synchronous infrastructure adapter ve injected HTTP
  transport. HTTP dependency yok; Python stdlib tercih edilir, yeni paket yok.
- Timeout **8 s**, body **65,536 byte**; oversized Content-Length okumadan
  reddedilir, streaming cap + monotonic read deadline kullanılır. Platform DNS
  çözümü stdlib socket timeout tarafından tam wall-clock sınırlanmaz; scheduler
  shutdown garantisi bu taskta kurulmaz. TLS default certificate verification;
  redirects follow edilmez, 3xx error. Proxy/environment URL override yoktur.
- Başarılı response yalnız HTTP 200 + application/json (charset parametresi
  kabul edilir); missing/wrong MIME ve content encoding reddedilir. Strict JSON:
  byte cap, UTF-8, duplicate keys/NaN/deep malformed rejection, expected dict shape.
- Minimum required fields: IP/isPublic/ipVersion, integer score 0..100,
  totalReports/numDistinctUsers 0..2^31-1, lastReportedAt null veya aware ISO UTC
  dönüşümü. IP/version/request eşleşmesi zorunlu. Whitelist yok/null/bool context.
  ISP/domain/hostname/individual reports/unknown metadata map edilmez.
- NO_HIT: totalReports=0 ve lastReportedAt=null. Score tek başına NO_HIT değildir.
  Nonzero reports veya timestamp => HIT. NO_HIT safe/benign/trusted değildir;
  HIT malware kanıtı değildir. Score provider metriğidir, NetSentinel risk score
  veya saldırı/malware olasılığı değildir. Whitelist risk azaltmaz.
  totalReports yalnız 30 günlük lookback içindeki rapor sayısıdır.
- Result completion clock infrastructure'da injectable UTC callable'dır;
  query timestamp caller'dan gelir, domain hidden clock yoktur.
- Secret yalnız NS-084 get_secret(provider). Empty/whitespace, >4096 veya HTTP
  header'a uygun olmayan control/non-ASCII değerler credential unavailable;
  provider key format regex'i yok. Missing secret => sıfır HTTP. Repr/header/body
  ve raw exceptions üst katmana/log/diagnostics taşınmaz.
- 401/403 AUTHENTICATION, 402 SUBSCRIPTION_RESTRICTED, 422 INVALID_REQUEST,
  429 RATE_LIMITED, 5xx UNAVAILABLE, diğer 4xx HTTP_ERROR, 3xx REDIRECT_REJECTED.
  Timeout TIMEOUT, network NETWORK_ERROR, TLS TRANSPORT_SECURITY_ERROR,
  malformed INVALID_RESPONSE, oversize RESPONSE_TOO_LARGE.
- Error body yalnız bounded JSON errors array şekli olarak incelenir; detail
  hiç kopyalanmaz. HTTP status authoritative. Typed rate metadata: numeric
  Retry-After 0..86400 (büyük değer clamp); limit/remaining <=2^31-1,
  reset epoch <=253402300799. Malformed/negative/huge header None; sleep yok.
- NS-084 result contract **2**, cache codec **2**: optional typed IP facts ve
  operational metadata. Cache yalnız facts/provenance taşır; rate metadata ve
  ERROR cache edilmez. Key result_version=2 mapping v1 semantics'i sabitler;
  ileride mapping değişirse result contract/version key de bump edilir. Eski
  version key/codec yorumlanmaz. SQLite **018 → 018**, migration gerekmez.
- Descriptor/adapter yalnız açık caller composition ile kullanılabilir;
  desktop registry/engine/GUI/bootstrap henüz compose etmez. Consent service
  current grant'i kontrol eder; adapter de eligible/manual/query consent
  dimensions'ı savunma amaçlı doğrular. Construction/consent/selection network yok.
- Live test marker `live_threat_intel`; default ve CI dışı. Explicit enable,
  public selected IP ve secret gerekir; live test bu teslimatta çalıştırılmaz.

## Privacy ve kapsam

Gönderilen: yalnız seçili eligible public IP, lookback query, API key header ve
normal HTTP metadata. Kullanıcının public source IP'si provider tarafından
görülür. Connection/DNS history, process name/path/command line, executable,
hash/file contents, alerts/evidence/assessment, notes, network fingerprint, MAC,
local ASN/country context gönderilmez. Raw provider body saklanmaz.

Yalnız CHECK; REPORT/reports/blacklist/check-block/bulk-report/clear-address,
upload, retry, scheduler (NS-087), risk evidence/assessment/AlertService/scoring
(NS-088), firewall ve multiple production adapters kapsam dışıdır. M15 devam eder.
Release öncesi resmi terms/privacy/plan bilgileri tekrar incelenmelidir.

## Kabul ve teslim raporu

**COMPLETE — 2026-10-04.** Başlangıç full HEAD, main ve gerçek uzak
origin/main: `c3eb2603a72a64137fbf4cf2405d5598d0eab16b`. Çalışma ağacı başlangıçta
temizdi. `git ls-remote origin refs/heads/main` salt okunur ağ erişimiyle doğrulandı.

İstenen final rapor alanlarının karşılıkları:

| # | Alan | Sonuç |
|---|---|---|
| 1 | Exact title | NS-086 — İlk provider adapter |
| 2 | Status | COMPLETE |
| 3–9 | Provider, gerekçe, sources/date, terms/privacy/business | Yukarıdaki resmi inceleme; legal clearance yok |
| 10 | Capability | IP_REPUTATION; IPv4/IPv6 |
| 11 | Domain/hash | Service UNSUPPORTED_DATA_TYPE; direct adapter UNSUPPORTED; sıfır HTTP |
| 12–14 | API, endpoint, fixed security | v2, GET, yalnız fixed api.abuseipdb.com /api/v2/check |
| 15 | HTTPS/TLS | Verified default ssl context; insecure bypass yok |
| 16 | Redirect | 3xx body okumadan döner, adapter REDIRECT_REJECTED; hiçbir host'a Key forward yok |
| 17–19 | Request/lookback/verbose | ipAddress canonical + maxAgeInDays=30, verbose yok |
| 20–23 | Secret | get_secret(provider); missing/invalid CREDENTIAL_UNAVAILABLE ve 0 HTTP; yalnız Key header, URL/query yok |
| 24 | Timeout | 8 saniye finite socket timeout + monotonic body read deadline; OS DNS wall-clock caveat yukarıda |
| 25 | Body | 65536 byte; oversized length önce, stream cap+1 sentinel; exact cap kabul edilir |
| 26 | MIME | HTTP 200 yalnız application/json; charset kabul, missing/HTML/other subtype/encoding reddedilir |
| 27 | JSON | UTF-8 bounded parse; duplicate/nonfinite/deep/malformed/wrong shape reddedilir |
| 28–30 | HIT / NO_HIT / safety | Reports>0 veya timestamp HIT; reports=0 + timestamp null NO_HIT; safe verdict yok |
| 31 | Zero score + reports | HIT korunur |
| 32 | Score | 0..100 provider-specific abuse_confidence_score; NS risk/probability değil |
| 33 | Whitelist | Optional null/bool context; safe veya risk reduction yok |
| 34 | Reports | Sabit 30 günlük lookback içindeki reports |
| 35 | lastReportedAt | Aware ISO → UTC; null kabul; invalid/naive/future timestamp reddedilir |
| 36–38 | Subject, IPv4/IPv6 | Canonical requested IP, public flag ve exact numeric version eşleşir; mismatch INVALID_RESPONSE |
| 39–42 | 401/403/402/422 | AUTHENTICATION / AUTHENTICATION / SUBSCRIPTION_RESTRICTED / INVALID_REQUEST |
| 43 | 429 | ERROR RATE_LIMITED; body sorunu NO_HIT yaratmaz; oversized error body status'u gizlemez |
| 44 | Retry-After | Numeric seconds; 86400 clamp; malformed/date/negative None; sleep yok |
| 45 | Rate headers | Typed optional bounded limit/remaining/reset; absent/invalid None |
| 46 | 5xx | UNAVAILABLE |
| 47–49 | Timeout/network/TLS | TIMEOUT / NETWORK_ERROR / TRANSPORT_SECURITY_ERROR; operational ERROR |
| 50–52 | Malformed/oversize/missing fields | INVALID_RESPONSE / RESPONSE_TOO_LARGE / INVALID_RESPONSE; partial HIT yok |
| 53–54 | Raw body/bounded result | Body/detail/ISP/domain/hostnames/reports persist veya result'a map edilmez; typed constant-size summary |
| 55 | Mapping version | 1; result/key contract 2 ile freeze; future normalization key-version bump gerektirir |
| 56–57 | Cache compatibility/error | HIT/NO_HIT typed facts restart round-trip; ERROR_SKIPPED önceki sonucu korur |
| 58 | Registry/composition | Explicit adapter constructor; desktop registry boştur; production secret backend eklenmedi |
| 59–61 | Startup/consent/selection | Provider/transport construction 0 HTTP; bootstrap/engine/GUI wiring yok; mevcut offscreen regressions geçti |
| 62 | Live marker/gating | live_threat_intel + NETSENTINEL_LIVE_THREAT_INTEL=1 + public test IP + environment secret test port |
| 63 | Offline CI | Default ve CI marker'ı live testi dışlar; fake HTTP/connection; bu çalışmada external provider request yok |
| 64–68 | CHECK-only, reporting/list/block/upload/retry | GET CHECK dışında endpoint yok; write/file upload yok; hata dahil tek çağrı, retry yok |
| 69–74 | Scheduler/risk/revision/alert/score/firewall | Hiçbiri eklenmedi; NS-087/088 başlamadı |
| 75–76 | Schema/migrations | 018→018; 001–018 SQL dosyaları değişmedi; new migration yok |
| 77 | Diagnostics | Değişmedi; provider/IP/key/body log veya diagnostics yok |
| 78 | Security/privacy docs | Bu belge + SECURITY/ARCHITECTURE/PRODUCT + consent/cache güncelleme notları |
| 79–81 | Files/tests | Aşağıdaki envanter; 179 yeni offline case + optional live case; yalnız gereken contract expectation değişiklikleri |
| 82–83 | Targeted commands/results | Aşağıdaki exact komut; 378 passed in 8.05s |
| 84 | Full pytest | 2726 passed, 8 deselected in 109.41s |
| 85 | Ruff | All checks passed |
| 86 | mypy/path | Repo .venv python; configured 31 ve direct 4 source file temiz |
| 87 | diff check | git diff --check exit 0; whitespace error yok |
| 88 | TASKS | Yalnız NS-086 newly COMPLETE; NS-087 entry değişmez; M15 summary güncel |
| 89–90 | Commit/push | feat: add AbuseIPDB threat intelligence adapter; full commit hash ve gerçek push receipt final mesajda |
| 91–93 | NS-087/M15/tree | NS-087 başlamadı; M15 devam ediyor; commit/push sonrası gerçek tree durumu final mesajda |

Exact validation commands (executable:
`C:\Users\berke\NetSentinel\.venv\Scripts\python.exe`):

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/infrastructure/test_abuseipdb.py tests/unit/infrastructure/test_threat_intel_http.py tests/integration/sqlite/test_threat_intel_cache.py tests/unit/domain/test_threat_intelligence.py tests/unit/domain/test_threat_intel_cache.py tests/unit/application/test_threat_intel_service.py tests/unit/application/test_threat_intel_cache_service.py tests/unit/shared/test_threat_intel_config.py tests/gui/test_threat_intel_consent.py
.\.venv\Scripts\python.exe -m pytest -q -m live_threat_intel tests/integration/test_abuseipdb_live.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/infrastructure/abuseipdb.py src/netsentinel/infrastructure/threat_intel_http.py src/netsentinel/infrastructure/sqlite/threat_intel_cache_codec.py src/netsentinel/application/services/threat_intel_cache.py
git diff --check
```

Live marker testi enable koşulu olmadan **1 skipped in 0.24s**. Live provider
verisi veya gerçek ağ/TLS handshake bu çalışmada ölçülmedi; transport security
kuralları fake connection ve default verified context assertions ile doğrulandı.
İlk hedefli run'da test assertions eski result field listesi ve substring check
nedeniyle düzeltildi; son hedefli ve full run temizdir.

Eklenen dosyalar:

- `src/netsentinel/infrastructure/abuseipdb.py`
- `src/netsentinel/infrastructure/threat_intel_http.py`
- `tests/unit/infrastructure/test_abuseipdb.py`
- `tests/unit/infrastructure/test_threat_intel_http.py`
- `tests/integration/test_abuseipdb_live.py`
- `tests/fixtures/abuseipdb/{hit_ipv4,hit_ipv6,no_hit,error}.json` ve `README.md`
- `docs/THREAT_INTELLIGENCE_PROVIDER_ABUSEIPDB.md`

Değiştirilen dosyalar:

- `src/netsentinel/domain/{threat_intelligence,threat_intel_cache}.py`
- `src/netsentinel/infrastructure/sqlite/threat_intel_cache_codec.py`
- `src/netsentinel/application/ports.py`
- `tests/integration/sqlite/test_threat_intel_cache.py` (future version probes 3)
- `tests/unit/application/test_threat_intel_service.py` (typed optional fields allowlist)
- `pyproject.toml`, `.github/workflows/ci.yml` (live marker exclusion)
- `docs/{TASKS,ROADMAP,ARCHITECTURE,SECURITY,PRODUCT,THREAT_INTELLIGENCE_CACHE,THREAT_INTELLIGENCE_CONSENT}.md`

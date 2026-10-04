# NS-084 — TI port ve consent policy

**NS-087 güncellemesi (2026-10-04):** Desktop registry AbuseIPDB IP capability'sini
sunar; consent Save/current tek notification slot ile memory snapshot'ı günceller.
Scheduler submit/dispatch/retry disk I/O olmadan bu snapshot'ı kontrol eder;
pending/delayed revoke iptal edilir. Default secret backend unavailable'dır.
Startup/selection/consent Save hiçbir lookup başlatmaz. Aşağıdaki önceki teslimat
kayıtları tarihseldir. [Güncel scheduler](THREAT_INTELLIGENCE_SCHEDULER.md).

**NS-086 güncellemesi (2026-10-04):** Aşağıdaki NS-084 v1 teslimat kaydı korunur.
Güncel optional typed IP facts ve bounded operational rate hints result contract
**2**'dir; query/consent policy **1** değişmez. AbuseIPDB descriptor yalnız
IP_REPUTATION ilan eder ve mevcut secret portunu kullanır. Default desktop
registry hâlâ boştur; consent Save/selection/startup network tetiklemez.
[Provider review ve adapter politikası](THREAT_INTELLIGENCE_PROVIDER_ABUSEIPDB.md).

**Status: COMPLETE (2026-10-04).** NS-084 provider-independent port, subject/result ve açık veri izni sınırını kurar.
Production provider registry boştur. Consent vermek bir lookup talebi değildir;
startup, connection seçimi, detail açılması ve consent Save hiçbir provider çağrısı
yapmaz. **NetSentinel does not upload your network history by default.**

M15 devam eder; NS-085–088 bu teslimatın kapsamı değildir. SQLite schema **017 →
017**, migration yoktur. Başlangıç HEAD `2af47b7ecbf5377cbe1af666b0d821c035619696`,
branch `main`, çalışma ağacı temizdi.

## Sözleşme ve katmanlar

| Sınır | Sözleşme |
|---|---|
| Provider kimliği | Immutable `ThreatIntelProviderId`: 1–64 lower-case ASCII symbolic karakter; URL/endpoint değildir. |
| Capability | `ThreatIntelProviderDescriptor`: ID, bounded plain-text display name, typed immutable supported-data-type set; retention yalnız `unknown`. Registry en çok 16 provider, unique ID. Gerçek terms/privacy review NS-086'da yapılacak. |
| Subject | `ThreatIntelSubject`: yalnız kind, canonical value ve hash için explicit `HashAlgorithm.SHA256`. Arbitrary metadata/payload/path/file yok. |
| Query | `ThreatIntelQuery`: UUID request ID, provider, subject, data type, trigger, exact consent reference/context, UTC queried_at, policy version 1. URL, headers ve credential yok. |
| Result | `ThreatIntelResult`: exact query provenance, HIT/NO_HIT/ERROR, UTC received_at ve yalnız ERROR için typed operational error. Raw response/headers/universal safety verdict yok. |
| Provider port | `ThreatIntelligenceProvider.descriptor` ve `query(request) -> result`; NS-084 yalnız test fakes sağlar. |
| Secret port | `ThreatIntelSecretStore.get_secret(provider_id) -> str | None`; provider ID referanstır. Gelecek adapter bu portu kullanır. Production backend, API key alanı veya UI credential view model yok. |
| Application lookup | `ThreatIntelLookupService.lookup_selected`: güncel consent'i okuyup pure policy'yi kontrol eder; yalnız ALLOW sonrasında tek port çağrısı. Desktop/engine bu service'i compose etmez. |
| Consent commands | `ThreatIntelConsentService`: registry capability ile current/save; provider portu ve secret portu bilmez. Read/save hiçbir query üretmez. |
| Config boundary | Composition root read/save callable'larını sağlar; shared config bounded JSON'u okur ve atomik yazar. Save mevcut config'i tekrar okuyarak onboarding ve diğer ayarları korur. |
| Presentation | Settings → Threat intelligence / reputation consent. Application consent service'ini kullanır; doğrudan network/DB/secret erişimi yok. |
| Domain/detectors | Pure typed policy mevcut domain canonicalizer'larını kullanır; config dosyası, provider portu ve network bağımlılığı yok. Detector/risk/alert code değiştirilmez. |

Secret değeri normal config, query/result, evidence, assessment, diagnostics,
log, export ve UI'ya taşınamaz. NS-084'te secret backend/resolution yoktur. Provider
exception metni tutulmaz veya loglanmaz; operational enum'a dönüştürülür. Portun
gizli değerini güvenli tutmak gelecek adapter'ın da zorunlu sınırıdır.

## Canonicalization ve dış subject politikası

| Subject | Canonicalization | Dış lookup eligibility |
|---|---|---|
| IPv4 / IPv6 | Mevcut `Endpoint(value, 0).address` / Python `ipaddress`; equivalent textual IPv6 forms aynı kimlik. Scoped IPv6 ve invalid input reddedilir. | `is_global` zorunlu; multicast/reserved/unspecified/loopback/link-local ayrıca dışlanır. RFC1918, CGNAT, ULA, TEST-NET ve IPv6 documentation/special adresleri dışlanır. IPv4-mapped IPv6 reserved olduğundan konservatif dışlanır. Override yok. |
| Domain | Mevcut `canonical_dns_name`: ASCII, lower-case, trailing dot, mevcut name/label bounds. Unicode IDNA expansion yapılmaz; ASCII punycode korunur. TI ayrıca hostname label syntax ister; root, underscore, edge hyphen ve IP literal reddedilir. | Single-label hostname, `.local`, `.localhost` dışlanır. DNS resolve yapılmaz; kalan syntax eligibility bir domain'in internette var olduğunu veya güvenli olduğunu kanıtlamaz. Geniş suffix blacklist yok. |
| SHA-256 | Explicit algorithm; uppercase hex lower-case'e çevrilir ve mevcut `ExecutableHash` digest doğrulaması kullanılır. 64 hex zorunlu. | Ayrı hash consent gerektirir. Contract dosya okumaz; file/path/filename/parent/command line subject değildir. |

Invalid subject model oluşturulurken TypeError/ValueError üretir; invalid raw
query application girişinde reddedilir. Provider çağrısı sıfırdır. Syntax geçerli
local subject ayrı typed `LOCAL_SUBJECT` policy denial olur.

## Consent karar tablosu

Consent UUID + provider + data type + trigger + policy version taşır. Fresh config
boş tuple'dır. Grant ve query'deki consent exact eşleşmelidir; eski/revoked grant
kimliği veya başka provider/type/trigger izni kabul edilmez.

| Kontrol sırası | Sonuç | Provider calls |
|---|---|---:|
| Subject/query typed ve geçerli değil | Constructor / input validation failure | 0 |
| Provider registry'de yok veya ID eşleşmiyor | UNSUPPORTED_PROVIDER | 0 |
| Provider data type desteklemiyor | UNSUPPORTED_DATA_TYPE | 0 |
| Subject external-eligible değil | LOCAL_SUBJECT | 0 |
| Trigger AUTOMATIC | TRIGGER_NOT_SUPPORTED | 0 |
| Güncel exact provider/type/manual grant yok veya config read invalid | NO_CONSENT | 0 |
| Tüm kontroller geçiyor | ALLOW (denial=None) | 1 |

| Tek mevcut grant: A / IP / MANUAL_SELECTED | Karar |
|---|---|
| A / IP / manual public subject | ALLOW |
| A / domain / manual | DENY |
| A / hash / manual | DENY |
| B / IP / manual | DENY |
| A / IP / automatic | DENY |
| A / IP / manual local subject | DENY |

Automatic enum yalnız reserved contract değeridir. Automatic consent config'e
kaydedilemez ve policy tarafından her zaman reddedilir. History enumeration,
engine hook, GUI lookup button veya batch API yoktur. Revocation sonrası her yeni
explicit service talebi güncel izin kontrolünden geçer; queue olmadığı için queued
job cancellation bu taskta yoktur.

## Sonuç semantiği

| Durum | Anlamı |
|---|---|
| Policy denial | Provider çalışmadı; provider result yok. |
| HIT | Provider kayıt döndürdü; malicious/malware veya safe hükmü değildir. |
| NO_HIT | Provider bu subject için kayıt döndürmedi. Safe, clean, trusted veya benign değildir. |
| ERROR | Unavailable/timeout/authentication/rate-limited/invalid-response operational failure; NO_HIT'e çevrilmez ve riski artıran security verdict değildir. |

Application outcome ya denial ya provider result taşır. Yanlış request provenance
ile dönen response `INVALID_RESPONSE` olur; provider exception `UNAVAILABLE` olur.
TTL/stale/negative cache, normalized provider-specific details, retries ve 429
işlemleri sonraki tasklardır.

## Persistence ve kullanıcı açıklaması

Config'in `threat_intel_consents` alanı typed immutable tuple'dır. JSON kaydı explicit
Save sonrası atomik temp-file/fsync/replace kullanır; loader'ın 16,384 karakter
sınırını aşan serialized config yazılmaz. Maksimum 48 grant vardır; duplicate
dimension/identity, unknown version, automatic trigger, malformed/extra fields
TI bölümünü tamamen kapatır. Başka config validation issue da izinleri kapatır.
Missing/old/malformed/unreadable/oversized config izin üretmez. Unknown provider
entry registry'de filtrelenir, random port yaratmaz. Restart exact saved choices
ve UUID'leri geri yükler. Revoke future-only ve anlıktır.

Dialog'da tüm yeni seçenekler OFF'tur. Provider display name/ID ve her data type
ayrı görünür; tek global cloud checkbox yoktur. Görünür açıklamalar şunları kapsar:
manual selected trigger, public source IP'nin provider/network path tarafından
görülebileceği, selected public IP/canonical domain/SHA-256 örnekleri, provider
retention unknown, history/DNS bundle gönderilmeyeceği ve dosya/file path/filename
gönderilmeyeceği. Checkbox değişimi persistence veya lookup yapmaz. Cancel/close
yazmaz; Save yalnız exact choices'ı saklar. Failure plain-text sanitized mesaj
gösterir ve yeni izni uygulamaz. Production registry boşken “No providers
configured” görünür ve Save kapalıdır; test providers production'a eklenmez.

DiagnosticsSnapshot veya TI counter eklenmez. Yalnız mevcut config validation
akışına `disabled_due_to_config_issue` safe code eklenir; log allowlist bu kodu
kabul eder. Subject/key/path/raw exception loglanmaz. Test fake'leri dışında
query kayıtları tutulmaz.

## Doğrulama

Tüm komutların çalışma dizini `C:\Users\berke\NetSentinel`; Python execution path
`.\.venv\Scripts\python.exe` (CPython 3.12.14). Live provider/attack traffic yoktur;
Windows/lab live testler default deselected kalır.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/domain/test_threat_intelligence.py tests/unit/application/test_threat_intel_service.py tests/unit/shared/test_threat_intel_config.py tests/unit/shared/test_config_logging_diagnostics.py tests/gui/test_threat_intel_consent.py tests/gui/test_application_shell.py tests/gui/test_capabilities.py tests/gui/test_risk_explanation.py tests/gui/test_connections_view.py tests/gui/test_destination_context.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/domain/threat_intelligence.py src/netsentinel/application/services/threat_intelligence.py src/netsentinel/presentation/widgets/threat_intel_consent.py src/netsentinel/shared/config.py
git diff --check
```

Targeted: **249 passed**. Ruff ve configured mypy (30 source files), yeni TI
modules direct mypy (4 source files) başarılı. Direct kapsam application service
ve dialog'u da içerir; bunlar configured mypy kapsamı dışındadır. Offscreen dialog
yerel Segoe UI fontuyla ayrıca render edilip disclosure/wrapping incelendi; uzun
checkbox metinleri kısaltıldı. Final full suite: **2465 passed, 7 deselected in
98.95s**. `git diff --check` başarılı; yalnız NS-084 COMPLETE olarak işaretlendi.

Testler consent matrix, IPv4/IPv6 private/special/documentation/global fixtures,
ASCII DNS/punycode/invalid/local domain, SHA-256 normalize/invalid bytes/path,
default no-request, two independent fake providers, capability/identity/trigger
isolation, exact request provenance, NO_HIT vs ERROR, provider exception redaction,
revocation, structural secret/payload absence, config restart/corruption/atomic
failure/size bounds ve GUI Save/Cancel/default/disclosure/startup/selection yollarını
kapsar. Mevcut config, onboarding, shell, destination ve M14 UI regresyonları hedefli
ve full pakette doğrulanır.

## Kapsam dışı

Gerçek HTTP, provider seçimi/adapter/API call, reputation cache/TTL/staleness,
negative cache, retry/rate limiting/scheduler/background lifecycle, automatic
lookup, history/file upload, RiskEvidence conversion, assessment revision,
AlertService/notification integration, malware verdict, auto block ve firewall
eklenmedi. NS-085 başlatılmadı; M15 COMPLETE değildir.

## Dosya envanteri

Eklenen dosyalar:

- `src/netsentinel/domain/threat_intelligence.py`
- `src/netsentinel/application/services/threat_intelligence.py`
- `src/netsentinel/presentation/widgets/threat_intel_consent.py`
- `tests/fixtures/threat_intelligence.py`
- `tests/unit/domain/test_threat_intelligence.py`
- `tests/unit/application/test_threat_intel_service.py`
- `tests/unit/shared/test_threat_intel_config.py`
- `tests/gui/test_threat_intel_consent.py`
- `docs/THREAT_INTELLIGENCE_CONSENT.md`

Değiştirilen dosyalar:

- `src/netsentinel/application/ports.py`
- `src/netsentinel/bootstrap.py`
- `src/netsentinel/shared/config.py`
- `src/netsentinel/shared/logging.py`
- `src/netsentinel/presentation/app.py`
- `src/netsentinel/presentation/views/main_window.py`
- `docs/ARCHITECTURE.md`, `docs/PRODUCT.md`, `docs/SECURITY.md`
- `docs/ROADMAP.md`, `docs/TASKS.md`

Mevcut test dosyaları değiştirilmedi; regresyonlar mevcut paket üzerinden çalıştı.
Geçici UI render dosyası teslimata eklenmez. Commit/push kimliği final raporda
bildirilir; branch/tag/release/force push oluşturulmaz.

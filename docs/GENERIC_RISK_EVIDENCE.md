# NS-076 — Generic risk evidence contract

## Durum ve sınır

**COMPLETE (2026-10-03).** Contract **1** uygulanmıştır. NS-076 yalnız additive domain modelleri, legacy
ARP translation, application handoff protocol ve offline testleri içerir.
NS-077 başlatılmadı; M14 tamamlanmadı. SQLite **014 → 014**.
Scoring weights/severity mapping/probability, generic assessment, SQL/repository,
TI adapter, AlertService/engine entegrasyonu ve GUI değişikliği yoktur.

## Sözleşme ve kimlik

`RiskEvidence(source, rule_id, reason_code, observed_at, scope, subject, quality,
role, policy_version, result_code, confidence, references, legacy_arp,
contract_version)` frozen/slots domain value'dur. Tuple collection kullanır;
hashable ve deterministic equality sağlar. `evidence_id` init sırasında canonical
JSON encoding'in SHA-256'ından hesaplanır; encoding yalnız allowlisted domain
dataclass/enum/UTC/UUID/primitive tiplerini içerir. Arbitrary serialization input
veya JSON payload alanı sunulmaz. Ek dataclass fields ile hassas veri eklenemez.

ID, versioned content/observation summary kimliğidir; random UUID, DB row ID,
alert ID, assessment ID veya issue dedup key değildir. Equivalent field values
ve collection sırası aynı ID verir. UTC zaman, subject, scope, policy veya
correlation değişimi farklı summary ID verir. Legacy issue fingerprint korunur;
generic ID mevcut dedup yoluna verilmez. Encoding'e yeni alan/semantik eklemek
contract version uyumluluğu bakımından ayrıca değerlendirilmelidir.

`EvidenceSource`: `arp_identity`, `destination_novelty`, `frequency_diversity`,
`periodicity`. Source bir verdict değildir. Producer namespace'inde rule/reason/
optional result kodu 1–64 karakter symbolic lower-case ASCII olur. Policy version
optional pozitif integer (1–1,000,000), contract version'dan ayrıdır. Free-form
summary metni yoktur; future explanation rule/reason anahtarını ve typed
subject/reference/context'i kullanır. Unknown producer policy `None` kalır.

## Subject, scope ve quality

| Alan | Anlam / doğrulama |
|---|---|
| Subject kind | Network, application, process, connection, destination, device, gateway; ilgili defining identity zorunlu |
| Application | NS-069 `ApplicationIdentity`; stable key canonical ve en çok 4096 UTF-8 byte, unknown key `None` |
| Revision | Ayrı optional `ApplicationRevision`; bilinen SHA-256 veya explicit unknown; application gerektirir |
| Process | Aynı NS-056 `ProcessIdentity(pid, create_time)`; PID Windows uint32 sınırında; create-time yoksa session zorunlu |
| Provisional application | Known process instance gerektirir; NS-069 instance key exact process ile eşleşir |
| Session / lifecycle | Ayrı canonical UUID; PID, display name veya SQLite row ID yerine kullanılmaz |
| IP / MAC | `ipaddress` ile IPv4/IPv6 canonical; zone ID reddedilir; existing `MacAddress` |
| Host scope | Network gerektirmez, network status/fingerprint içermez |
| Network scope | `RESOLVED` + canonical 64-char SHA-256 fingerprint; interface/route atfı uydurulmaz |
| Unknown scope | `UNKNOWN` veya ayrı `AMBIGUOUS`; fingerprint zorunlu değil, aksine yasak |
| Measurement | `ObservationQuality.COMPLETE/REDUCED/FAILED` veya unreported `None` |
| Limitations | Ayrı typed enum tuple: gap/capacity/revision/IP-only/reduced/resolution/polling/benign schedule/missed multiple/truncated/prior history |
| Confidence | Ayrı optional `passive_observation/low/moderate/high`; quality değildir |
| Role | Observation/finding/limitation; FAILED yalnız limitation rolünde geçerli |
| Time | UTC-aware datetime; naive/non-UTC reddedilir, normalize edilir; runtime monotonic timestamp alanı yok |

Process ve destination network-only ARP için zorunlu değildir. Unknown scope,
unknown application/revision veya missing metadata zararsızlık/zararlılık kanıtı
değildir. Limitation, positive finding gibi sunulmaz.

## References ve contributors

`EvidenceReference(kind, value)` yalnız aşağıdaki target biçimlerini kabul eder:

| Kind | Value |
|---|---|
| `connection_lifecycle` | NS-056 lifecycle UUID |
| `monitoring_session` | NS-056 session UUID |
| `dns_evidence` | NS-063 canonical DNS evidence UUID |
| `evidence` | Generic evidence content SHA-256 |
| `legacy_arp_event` | Existing NS-026 issue fingerprint SHA-256 |

Process/application identity subject'te typed taşınır. Baseline/alert/DB row
reference veya opaque string target bu taskta eklenmez. Reference bir pointer'dır;
target availability, persistence, retention veya automatic resolution garanti
etmez. Üretici referenced source'un ownership'ini ayrıca sağlamalıdır.

Hard caps merkezi constant'lardır: **8 references/evidence**, **16 limitations/
evidence**, **32 evidence contributors/batch**. Empty tuple valid; cap+1 ve
duplicate reddedilir, silent truncate yoktur. References `(kind, value)`,
limitations enum value, flat batch evidence ID sırasına normalize edilir.
`RiskEvidenceBatch` evidence taşıyan düz collection'dır; score contributor
modeli değildir. Nested children/evidence tree yoktur. Correlated facts'in
gelecek scoring sırasında double-count değerlendirmesi NS-077'ye aittir.

`application.ports.RiskEvidenceConsumer.consume(RiskEvidenceBatch)` yalnız
minimal local handoff protocol'üdür. Consumer implementation, repository,
worker/queue veya bootstrap wiring eklenmemiştir.

## Legacy ARP mapping

`application.services.risk_evidence.evidence_from_arp` typed
`ArpIdentityConflictDetected | ArpRiskAssessment` alır. Legacy detector,
correlator, AlertCandidate, AlertService ve fingerprint hesapları değiştirilmez.

| Legacy alan | Generic temsil |
|---|---|
| Rule / reason | `rule_id` / `reason_code`, exact enum values |
| Subsystem | `source=arp_identity`; identity discrepancy, MITM hükmü değil |
| Network fingerprint | `scope=network/RESOLVED`, aynı fingerprint |
| IP / observed MAC | Subject IP/MAC; IP-MAC conflict `device`, gateway change `gateway` |
| Expected MAC / expected-last-seen / baseline status | `legacy_arp.source.evidence`, original typed object |
| Original event time | `legacy_arp.source.observed_at`; uncorrelated envelope aynı zamanı taşır |
| Event fingerprint / entity ID | Original source korunur; fingerprint ayrıca `legacy_arp_event` reference |
| Source confidence / severity | Original source aynen korunur; envelope confidence exact current/source confidence |
| Correlation times/count | Original `legacy_arp.correlation`; envelope `observed_at=last_observed_at` |
| Legacy score / breakdown / confidence / severity | Original correlation aynen; yeni generic score veya weight alanı yok |
| Measurement / policy version | Legacy bildirmediği için `None`; COMPLETE veya v1 uydurulmaz |

Generic envelope rule/reason/scope/subject/time/confidence/reference/role eşlemesi
validate edilir. Legacy correlation mutable breakdown kabul etmez; en çok 8
component, count en çok 1,000,000,000, component points en çok 1,000,000,000.
Bu translation boundary bounds'ıdır; legacy detector policy değiştirilmez.
Round-trip original typed source/correlation object üzerinden kayıpsızdır.
Legacy severity generic standardlaştırma veya new scoring input değildir.

## M13 temsil kapsamı

TASKS.md NS-076 yalnız legacy ARP production adapter ister. NS-072/073/074
production adapters ve runtime pipeline eklenmedi. Gerçek detector çıktıları
ile contract construction örnekleri unit testlerde doğrulanır; mevcut detailed
M13 metrics/policy nesneleri kendi typed modellerinde kalır. Bu örnekler tüm
detector fact'lerinin persistence conversion'ı veya source-reference resolver
değildir. Future integration ayrı taskın sorumluluğudur.

- NS-072: FIRST_SEEN retained scoped baseline'da gözlenmemiş destination'dır;
  `destination_not_previously_observed` reason, reduced observation/IP-only/
  revision limitations ve policy 1 korunabilir. INSUFFICIENT_DATA limitation
  rolünde temsil edilir, finding'e yükseltilmez.
- NS-073: `observed_appearance_frequency` ve `destination_window_diversity`
  ayrı rule'lar olarak NORMAL observation/ELEVATED_UNCONFIRMED finding temsili
  alır. Observed appearance OS connection creation rate değildir. Emission
  eligibility veya future confidence uydurulmaz.
- NS-074: PERIODIC_CANDIDATE C2/beacon değildir. RESOLUTION_LIMITED limitation
  rolündedir. COMPLETE observation ile polling quantization, benign schedule
  compatibility ve low security significance limitations birlikte taşınabilir.
  Producer policy 1 ve source reason/classification değiştirilmez.

## Gizlilik ve değişen dosyalar

Arbitrary details dict, payload/metadata/Any, raw packet/DNS bytes, executable
contents, auth token/cookie, command line, native object ve recursive children
alanları yoktur. Application key mevcut controlled local reference'dır; path
ayrı açıklama/reference-string alanına kopyalanmaz. IP/MAC/path/hash hâlâ hassas
metadata'dır; bu contract hiçbir I/O, diagnostics dump, upload veya fetch yapmaz.

Eklenen: `domain/risk_evidence.py`, `application/services/risk_evidence.py`,
`tests/unit/domain/test_risk_evidence.py`, bu belge.
Değişen: `application/ports.py`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`,
`docs/TASKS.md` (yalnız NS-076 durum satırı).
Existing test dosyaları, presentation/infrastructure, SQLite migrations,
README/ROADMAP ve NS-077 tanımı değiştirilmez.

## Offline doğrulama (2026-10-03)

Komutlar repo root'tan `.\.venv\Scripts\python.exe` ile çalıştırılır:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/domain/test_risk_evidence.py tests/unit/application/detectors/test_arp_identity.py tests/unit/application/detectors/test_arp_anomaly.py tests/unit/application/test_alert_service.py tests/unit/application/detectors/test_destination_novelty.py tests/unit/application/detectors/test_frequency_diversity.py tests/unit/application/detectors/test_periodicity.py
.\.venv\Scripts\python.exe -m pytest -q tests/integration/sqlite/test_alert_repository.py tests/integration/test_arp_alert_pipeline.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/domain/risk_evidence.py src/netsentinel/application/services/risk_evidence.py src/netsentinel/application/ports.py
git diff --check
```

Targeted: **387 passed** (81 yeni contract validation örneği dahil).
Legacy SQLite repository/pipeline: **9 passed**.
Ruff: **All checks passed**. Configured mypy: **24 source files**, direct mypy:
**3 source files**, ikisi de başarılı; adapter configured kapsam dışında olduğu
için ayrıca direct command çalıştırıldı. Full pytest: **1648 passed, 7 deselected,
67.96 saniye**. `git diff --check` başarılı. Testler offline/synthetic; live capture, attack traffic veya network
lookup yapılmadı.

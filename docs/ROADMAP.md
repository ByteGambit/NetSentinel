# Yol haritası

NS-105 (2026-10-09): yalnız localization foundation **COMPLETE**; M19 **IN PROGRESS**,
NS-106–120 **PLANNED / NOT STARTED**, M20 **PLANNED**. Canonical English,
offline QTranslator/TS/QM ve kaynak envanteri; runtime switching **NO_GO**,
whole-app restart required. Schema020; production translation/chooser/new tour/
installer rebuild/VM/commit/push/tag/release NONE. [Kabul](LOCALIZATION_ACCEPTANCE.md).
Önceki planning baseline aşağıda tarihseldir; frozen task kapsamı korunur.

## Post-M18 planning baseline — 2026-10-09

M1–M18 / NS-001–NS-104 **COMPLETE** in their recorded acceptance scopes;
current planning HEAD `97e214a270a5153d1ffd234cc50707ce52083f7f`, schema020.
[NS-104 closure](RESPONSE_UNINSTALL_ACCEPTANCE.md) and TASKS are authoritative;
the earlier progress entries below retain their historical scope. Limited
unsigned pilot **CONDITIONAL_GO**, broad public release **NO_GO**, asInvoker
in-product privileged writes **NO_GO**. Automatic blocking/elevation and
service/helper/task/driver/WFP NONE; tag/release NONE.

The authorized post-M18 work is **planning only**. M19/20 are appended below;
NS-105–120 **PLANNED / NOT STARTED**, implementation and VMware validation not
started. [Frozen scope, inventory, matrix and completion gate](M19_M20_PLANNING.md).

NS-103 (2026-10-09): explicit user GO for manual response UI only; Connections
review/confirmation/Cancel, bounded audit, typed denied/partial and strict
confirmed Undo **COMPLETE (offline UI/service acceptance)**: targeted295,
full4692/9 live deselected, coverage91.31%; Ruff/mypy/whitespace/privacy PASS.
NS-100–102 remain COMPLETE; **NS-104 NOT STARTED**. In-product privileged writes
retain their separate **NO_GO** trust boundary; normal runtime reads custody,
injected fakes exercise writes. No native/uninstall acceptance, helper/elevation,
automatic blocking, process termination, commit/push/tag/release.
[NS-103 acceptance](MANUAL_RESPONSE_UI_ACCEPTANCE.md). Older milestone notes
below are historical.

NS-100 (2026-10-08): explicit user **GO NS-100** authorizes only the contract
task; **NS-100 COMPLETE** (205 new tests, full4038/8/91.17%, Ruff/mypy37/direct3/
whitespace/privacy PASS). M17/NS-099 remain COMPLETE. M18 is IN PROGRESS with
**in-product writes NO_GO** pending the trusted privilege boundary and later
ownership/native acceptance. **NS-101–104 NOT STARTED**, separate user instruction
required; no adapter/helper/firewall/UI/schema/installer/tag/release change.
[NS-100 contract](RESPONSE_COMMAND_CONTRACT.md), [acceptance](RESPONSE_COMMAND_ACCEPTANCE.md).
The following NS-099 and earlier summaries retain their historical scope.

NS-099 final environment closure (2026-10-08): **private native WireGuard VPN PASS**.
NS-099 **COMPLETE**, M17 **COMPLETE**; accepted8242868 runtime unchanged,
unsigned0.1.0 candidate SHA256 `39b14fe844c8aaa150a8b09229e0d63aaaf5ecc98b5bc8c54b419140be7749d9`,
37,559,481 bytes, schema019→019. Fresh installed1119 hashes/0 mismatches.
Real tunnel/HTTPS/scope/disconnect/restart and baseline/DB persistence PASS;
alerts/incidents0 throughout, notifications OFF/intents0, bounded app errors0.
Native S3 PASS, notification policy PASS and human UX8/8 retain their recorded scope.
Limited unsigned pilot **CONDITIONAL_GO** subject to NS-097 owner/distribution gates;
broad release **NO_GO** (unsigned/signing gates). M18 **GO FOR PLANNING ONLY**,
no explicit response implementation GO; NS-100 **NOT STARTED**; tag/release **NONE**.
[VPN measurements, limitations and cleanup](NS099_VPN_WIREGUARD_CLOSURE.md).

Earlier acceptance summaries below are historical; product/security rules remain in force.

NS-099 notification-policy closure (2026-10-07): **policy PASS**, actual Windows
global Notifications OFF/ON in the same Limited-token Session1; application
reports **UNKNOWN**, accepted submission is not visible-delivery proof.
Current unpublished unsigned0.1.0 source `8242868ba79c63ad743c005366ea715b238cf5d0`,
SHA256 `39b14fe844c8aaa150a8b09229e0d63aaaf5ecc98b5bc8c54b419140be7749d9`, 37,559,481 bytes, schema019→019.
Installed1119 hashes/0 mismatches;194 source-matching compiled modules.
Native popup/privacy/click/duplicates/restart PASS in the recorded policy scope.
Human UX remains PASS8/8, layout CLOSED in its evaluator scope. VPN and meaningful
native sleep NOT RUN; NS-099 INCOMPLETE, M17 IN PROGRESS, pilot/broad NO_GO,
M18 DEFER, NS-100 NOT STARTED; tag/release NONE.
[Policy model, native measurements and limitations](NS099_NOTIFICATION_POLICY_CLOSURE.md).

## Previous layout follow-up — historical candidate

NS-099 layout follow-up (2026-10-07): current runtime/source `bfe531d960aaabd6b61c1701cf7179f7214c5097`,
unsigned0.1.0 candidate SHA256 `74529e4cfa03d466ed365a4b0fe5c65c4399873acf150b0c3472496472bdf4c2`, 37,543,802 bytes, schema019→019.
Incidents/DNS/History layout fixed; fresh Windows11 native layout test-build
captures evaluated by the human. Focused layout recheck **PASS**; overall Human UX
**8 PASS / 0 FAIL**. The previous layout finding is closed. Prior functional/native measurements below keep
their original ae08d7e/14934a52 candidate scope. VPN NOT RUN, native sleep NOT RUN,
effective OS-disabled policy BLOCKED; NS-099 INCOMPLETE, M17 IN PROGRESS,
pilot/broad NO_GO, M18 DEFER, NS-100 NOT STARTED. [Layout record](NS099_LAYOUT_CLOSURE.md).

The earlier closure summary below retains its historical candidate scope.

## Yol haritası ilkeleri

- Milestone'lar sırayla uygulanır; ancak aynı milestone içindeki bağımsız tasklar, bağımlılıkları izin veriyorsa paralel yürütülebilir.
- Bir milestone, yalnızca kod yazıldığı için değil; acceptance criteria, test ve gerekli dokümantasyon tamamlandığında biter.
- Her aşama önceki aşamanın public sözleşmelerini mümkün olduğunca korur.
- Packet capture gerektirmeyen çekirdek bağlantı görünürlüğü ilk kullanılabilir dikey dilimdir.
- Güvenlik detector'ları önce gözlem ve baseline güvenilir hale geldikten sonra eklenir.

## M1 — Core Connection Monitor

**Amaç:** GUI ve persistence olmadan, Windows connection snapshot'larını normalize eden ve açılma/kapanma değişikliklerini üreten test edilebilir engine çekirdeği.

**Kapsam:**

- Proje/paket/test iskeleti
- Connection ve process domain modelleri
- psutil TCP/UDP collector adapter'ı
- Process metadata zenginleştirme
- Snapshot diff ve connection lifecycle
- Engine yaşam döngüsü ve in-process event dağıtımı

**Çıkış ölçütü:** Fixture ve adapter testleri geçen; kontrollü biçimde başlayıp duran; yeni/kapanan bağlantı olaylarını GUI'den bağımsız üreten çekirdek.

**Tasklar:** NS-001–NS-007

## M2 — PyQt6 GUI

**Amaç:** Engine'i bloke etmeden canlı bağlantıları ve temel sağlık/istatistik bilgisini gösteren masaüstü kabuğu.

**Kapsam:**

- Uygulama kabuğu ve navigasyon
- Thread-safe Qt bridge
- Connections tablo modeli, filtre ve detay görünümü
- Basit dashboard
- Headless GUI testleri ve temel erişilebilirlik

**Çıkış ölçütü:** Uygulama canlı bağlantıları güncellerken UI responsive kalır; engine hata/stop durumu kullanıcıya görünür.

**Tasklar:** NS-008–NS-013

## M3 — Persistence

**Durum:** ✅ Tamamlandı (NS-014–NS-018, 2026-09-21)

**Amaç:** Connection history ve ilerideki modüllerin kullanacağı güvenilir SQLite altyapısını oluşturmak.

**Kapsam:**

- Migration sistemi ve başlangıç şeması
- Repository portları ve SQLite implementasyonu
- Tek writer queue ve batch transaction
- Retention ve veri yaşam döngüsü
- Geçmiş sorgulama görünümü

**Çıkış ölçütü:** Uygulama yeniden başlatıldığında bağlantı geçmişi korunur; migration, concurrency ve retention testleri geçer.

**Tasklar:** NS-014–NS-018

## M4 — LAN Device Monitor

**Durum:** ✅ Tamamlandı (NS-019–NS-024, 2026-09-23)

**Amaç:** Yerel ağ bağlamını ve pasif ARP gözlemlerini kullanarak cihaz envanteri oluşturmak.

**Kapsam:**

- Windows interface/subnet/gateway bağlamı
- Güvenli packet capture sınırı
- ARP parser
- Device registry ve IP-MAC binding geçmişi
- Yeni cihaz olayı
- Devices ekranı ve kontrollü lab testi

**Çıkış ölçütü:** Seçili ağda gözlenen cihazlar ve kimlikleri kalıcı/okunabilir biçimde gösterilir; yeni cihaz olayı deterministik çalışır.

**Tasklar:** NS-019–NS-024

## M5 — MITM Detection & Alerts

**Durum:** ✅ Tamamlandı (NS-025–NS-029, 2026-09-23)

**Amaç:** Gateway ve ARP kimliği değişimlerinden açıklanabilir, deduplicate edilmiş güvenlik alert'leri üretmek.

**Kapsam:**

- Ağ bağlamına özgü gateway baseline
- IP-MAC çakışma tespiti
- ARP sinyali korelasyonu ve confidence
- Genel alert yaşam döngüsü
- Alert kanıt/detay ekranı

**Çıkış ölçütü:** Sentetik ARP senaryoları doğru alert'leri üretir; normal DHCP/ağ geçişleri kontrollü biçimde ele alınır; alert storm oluşmaz.

**Tasklar:** NS-025–NS-029

## M6 — DNS Monitoring

**Durum:** ✅ Tamamlandı (NS-030–NS-034, 2026-09-24).

**Amaç:** Klasik DNS trafiği ve Windows DNS yapılandırması için görünürlük sağlamak.

**Kapsam:**

- DNS query/response parser
- Transaction korelasyonu ve timeout
- DNS server değişikliği tespiti
- DNS history persistence
- DNS ekranı

**Çıkış ölçütü:** Desteklenen DNS paketleri güvenle parse edilir, işlemler korele edilir ve DNS sunucusu değişimleri kanıtla alert üretir.

**Tasklar:** NS-030–NS-034

## M7 — Broadcast Monitoring

**Durum:** ✅ Tamamlandı (NS-035–NS-038, 2026-09-26).

**Amaç:** Broadcast ve ARP yoğunluğunu bounded rolling window'larla ölçmek ve beklenmeyen artışları raporlamak.

**Kapsam:**

- Broadcast sınıflandırma
- Rolling sayaçlar ve baseline
- Threshold/rate detector ve alert deduplication
- Dashboard istatistikleri

**Çıkış ölçütü:** Burst ve sürekli yüksek trafik ayrıştırılır; bellek sınırlı kalır; kullanıcı ölçüm penceresi ve eşiği görebilir.

**Tasklar:** NS-035–NS-038

Sınıflandırma, bounded rolling oran/baseline ve açıklanabilir yoğunluk alert'i
mevcut pasif consumer'a bağlıdır. Dashboard portable metrikleri gösterir;
işaretli sentetik yük testi queue, kalite ve kapanma sınırlarını doğrular.

## M8 — Device Security

**Durum:** ✅ Tamamlandı (NS-039–NS-042, 2026-09-26).

**Amaç:** Bilinen cihaz profilleri ile gözlenen ağ kimliği arasındaki şüpheli değişimleri tespit etmek.

**Kapsam:**

- Device profile ve trust modeli
- MAC/IP kimlik değişimi kuralları
- Profil/trust yönetimi
- False-positive odaklı testler

**Çıkış ölçütü:** Kullanıcı cihazı adlandırıp beklenen kimlikleri doğrulayabilir; beklenmeyen değişiklikler açıklanabilir alert üretir.

**Tasklar:** NS-039–NS-042

NS-042 sentetik device-identity karar matrisi, ARP → profil → detector → alert
→ SQLite entegrasyonu, servis yeniden kurulumu ve offscreen profil/alert
görünümüyle M8 çıkış ölçütünü doğruladı. Kural ve yanlış pozitif sınırları
[karar tablosunda](DEVICE_SECURITY_DECISIONS.md) belgelenmiştir.

## M9 — VLAN Monitoring

**Durum:** ✅ Tamamlandı (NS-043–NS-046, 2026-09-27).

**Amaç:** Capture'da mevcut 802.1Q etiketlerini gözlemek ve ağ bağlamına göre şüpheli VLAN değişimlerini bildirmek.

**Kapsam:**

- 802.1Q parser
- VLAN baseline
- Yeni/beklenmeyen VLAN ve değişim detector'ı
- Özet persistence ve UI görünümü

**Çıkış ölçütü:** Tagged/untagged ve malformed fixture'lar doğru işlenir; NIC offload sınırlaması kullanıcıya gösterilir.

**Tasklar:** NS-043–NS-046

NS-046, portable VLAN adaylarını mevcut AlertService kalıcılığına bağladı.
Dashboard seçili ağ/interface için kayıtlı VID özetini ve capture görünürlük
sınırını gösterir; Alerts ekranı bounded kanıtı sunar. Fake capture ile parser
→ özet → doğrulama → detector → alert persistence ve restart dedup zinciri
varsayılan test suite'inde doğrulanır.

## M10 — Packaging, Hardening & Test

**Durum:** M10 tamamlandı (NS-047–NS-051). Tanımlı M1–M10 milestone'ları ve NS-001–NS-051 taskları tamamlandı; 1.0 release/tag oluşturulmadı.

NS-047 typed config fallback, yalnızca sabit alanlı dönen log ve mevcut
health/storage snapshot'larını birleştiren diagnostics sözleşmesini ekledi.
NS-048 ilk açılış rehberi, capability matrix, worker üzerinden Retry ve
driver/izin/interface/storage eksikliğinde kademeli çalışma görünümü ekledi.
NS-049 sentetik mixed packet burst, iki writer overload, alert/log storm,
start/stop döngüleri ve hızlandırılmış state/heap soak kontrollerini mevcut
`performance` marker'ıyla doğruladı; CI/default ve yerel bütçeler mimari
belgesinde kayıtlıdır.
NS-050 PyInstaller `onedir` Windows GUI artefact'ını, 001–009 SQL/ikon package
resource'larını, sürüm metadata'sını, lisans envanterini ve SHA-256 zip'i
üretti. Artefact yerel Windows'ta farklı cwd ve boşluk/Türkçe karakterli
çıkarma yoluyla; fresh DB, 008→009, ilk/sonraki açılış ve kapanış için geçti.
SHA-256 değeri doğrulanan aynı artefact, Npcap bulunmayan temiz Windows VM'de
standart kullanıcıyla açıldı: degraded onboarding, bağımsız Connections/engine,
LocalAppData veri yolu, temiz kapanış ve sonraki açılış doğrulandı. Paketlenmiş
tanı modu VM'de migration 001–009 ve 008→009 yükseltmesini geçti. Kaldırma
sonrası kullanıcı verisinin korunması kararı paketleme rehberinde açıklanır.
NS-051'in PR kalite kapıları, GitHub PR #1'de Windows 2022 ve 2025 offline
test/coverage işleri ile lint/type/dependency audit işinin geçmesiyle
doğrulandı. Varsayılan CI live/lab capture testlerini dışlar; release checklist
güvenlik, izin, migration ve paketleme kontrollerini kapsar.

**Amaç:** Uygulamayı farklı Windows yetki/capture koşullarında güvenli, gözlemlenebilir ve dağıtılabilir hale getirmek.

**Kapsam:**

- Merkezi config/logging/diagnostics
- Capability ve permission onboarding
- Performans, backpressure ve dayanıklılık
- Windows paketleme ve temiz makine doğrulaması
- CI test matrisi ve release kontrol listesi

**Çıkış ölçütü:** Temiz Windows ortamında kurulum/çalıştırma doğrulanır; düşük yetki ve capture yokluğu anlaşılır biçimde degrade olur; kalite kapıları geçer.

**Tasklar:** NS-047–NS-051

## Sürümleme önerisi

- **0.1:** M1–M3, bağlantı görünürlüğü ve history
- **0.2:** M4–M5, cihaz görünürlüğü ve ARP/MITM sinyalleri
- **0.3:** M6–M9, DNS/broadcast/device/VLAN güvenlik modülleri
- **1.0:** M10 tamamlanmış, belgelenmiş ve Windows smoke testleri geçen sürüm

Bu sürüm hedefleri bağlayıcı tarih değil, kapsam kapılarıdır.

## Yeni faz: M11–M16 tamamlandı; M17 devam ediyor, M18 conditional

**Durum:** M1–M17 tamamlandı; NS-001–NS-099 COMPLETE (2026-10-08). Son required private WireGuard VPN gate PASS; native S3/policy/human UX ve önceki candidate-scoped acceptance korunur. Limited unsigned pilot CONDITIONAL_GO, broad release NO_GO under NS-097; unsigned/manual dağıtım için owner audience/license/channel/contact ve açık dağıtım onayı gerekir. M18 yalnız GO FOR PLANNING; explicit response GO ve kullanıcı uygulama onayı olmadan NS-100–NS-104 başlatılmaz. [Final evidence](NS099_VPN_WIREGUARD_CLOSURE.md). Önceki milestone kayıtları tarihsel kapsamını korur.

Ana ürün sorusu: “Bilgisayarım şu anda kimlerle konuşuyor, bunu hangi process yapıyor, bu davranış normal mi ve neden şüpheli olabilir?” Öncelikler visibility, context, explainable detection. Task kabul kriterleri [TASKS.md](TASKS.md) içindedir.

### M11 — Process & Connection Telemetry Foundations

- **Durum:** ✅ COMPLETE (NS-052–NS-061; NS-059, NS-060 ve NS-061 belgelenmiş NO-GO spike sonuçları).
- **Amaç:** Connection'ı yapan process'i ve gözlemin sınırlarını daha güvenilir göstermek.
- **Ana teslimatlar:** Executable path, best-effort parent context, field-level availability; observation/lifecycle identity, telemetry quality, conservative network scope, history freshness/restart gap semantics. NS-059 per-flow bytes, NS-060 DNS-process attribution, NS-061 process/connection event-source ölçümlü spike'ları.
- **Açık kapsam dışı:** Per-flow bytes release requirement değildir; production ETW/WFP collector, byte UI, genel risk ve firewall yoktur. Spike sonucu production taskını otomatik eklemez.
- **Çıkış ölçütü:** PID-reuse/connection davranışı korunur; eksik alanlar ve gap görünür; bounded quality/state ve restart testleri geçer. Üç spike'ın her biri kontrollü ölçüm, sınırlama ve explicit GO/NO-GO kararıyla tamamlanır; belgelenmiş NO-GO başarılı sonuçtur.

### M12 — Local Destination Context & Attribution

- **Durum:** ✅ COMPLETE (2026-10-02; NS-062–NS-068). NS-067 GO kararıyla conditional NS-068 adapter uygulandı.
- **Amaç:** Destination hakkında yerel kanıt sağlarken belirsizliği korumak.
- **Ana teslimatlar:** Bounded DNS/domain association, canonical reference; UI'da directly observed/correlated/ambiguous/unknown; source/version içeren yerel ASN/country context; bounded on-demand executable hash; offline signer spike ve olumluysa conditional adapter.
- **Açık kapsam dışı:** Kesin DNS→process→connection nedenselliği, cloud reputation, otomatik dataset download, TLS inspection.
- **Çıkış ölçütü:** Shared IP/CDN, multiple domain, TTL, restart ve ambiguity testleri geçer; UI kesin hostname iddiasında bulunmaz; local source/version görünür.

### M13 — Deterministic Behavioral Baseline

- **Durum:** ✅ COMPLETE (NS-069–NS-075, 2026-10-03). Learning/ready/insufficient-quality, novelty/rarity, frequency/diversity ve periodicity explanation sözleşmeleri; deterministic clock, warm-up/gap/eviction/restart/capacity testleri ve bounded memory/disk kuralları doğrulandı. NS-075 observed learning UI ve confirmed scoped reset tamamlandı; [exit doğrulaması](BASELINE_DETAIL_UI.md). NS-072–074 runtime detector pipeline'ı henüz engine'e bağlı değildir; UI bulunmayan evidence'ı açık gösterir, snapshot'tan geçmiş observation kanıtı üretmez. M14/NS-076 başlatılmadı.
- **Amaç:** Uygulama davranışındaki yeniliği measurement quality ile açıklamak.
- **Ana teslimatlar:** Instance'dan ayrı cross-run application identity; destination IP/port, protocol, observed appearance frequency ve destination diversity için bounded deterministic baseline; ASN varsa ek context; novelty/frequency/diversity/periodicity evidence; learning/quality UI.
- **Açık kapsam dışı:** ML/AI anomaly model, ilk sürümde time-of-day alert, byte-derived behavior, kesin beacon hükmü.
- **Çıkış ölçütü:** Warm-up/gap/eviction/restart testleri geçer; eksik gözlem high-confidence anomali üretmez; memory/disk bounds belgelenir.

### M14 — Explainable Risk & User Feedback

- **Durum:** ✅ COMPLETE (NS-076–NS-083, 2026-10-04). Generic evidence/scoring/revision/persistence/AlertService ve scoped preference/mark-normal zinciri, Alerts/Connections risk explanation ile tamamlandı. Frozen çıkış kriterleri offline full suite ve legacy/lifecycle/suppression regression ile doğrulandı; [NS-083 kabul ve M14 exit raporu](RISK_EXPLANATION_UI.md). SQLite 017; M15/NS-084 başlatılmadı.
- **Amaç:** Riskin nedenini ve feedback etkisini gösterip yanlış pozitifleri azaltmak.
- **Ana teslimatlar:** Generic typed risk evidence, pure/versioned scoring policy, assessment revisions, AlertService entegrasyonu, dar/expiring suppression, mark-normal ve explanation UI.
- **Açık kapsam dışı:** Malware probability iddiası, cloud bağımlılığı, automatic response, process name/PID ile kalıcı suppression.
- **Çıkış ölçütü:** Contributor/evidence/confidence/measurement quality/source-freshness/policy version görünür; recalculation occurrence veya original observation time'ı değiştirmez, önceki assessment'ı overwrite etmez; legacy alert dedup korunur.

### M15 — Optional Threat Intelligence Evidence

- **Durum:** ✅ COMPLETE (NS-084–NS-088, 2026-10-04). Explicit Connections lookup → bounded scheduler/cache/AbuseIPDB → supporting evidence → existing assessment revision → Alerts/Connections historical explanation tamamlandı. Default zero requests, fake second-provider abstraction, offline/timeout/429/TTL/stale, NO_HIT/failure ayrımı ve local detection continuation frozen çıkış kriterleri geçti. Numeric policy v1, schema 018; migration yok. Credential backend unavailable kalır ve açık operational sonuç verir. Full offline 2899 passed, 8 deselected; [NS-088 kabul ve M15 exit raporu](THREAT_INTELLIGENCE_EVIDENCE.md). NS-089 başlatılmadı.
- **Amaç:** Kullanıcı onayıyla destekleyici destination reputation evidence sağlamak.
- **Ana teslimatlar:** Provider port/adapter, provider/subject/data consent, local TTL/stale cache, bounded rate-limited/offline scheduler ve risk revision/UI entegrasyonu.
- **Açık kapsam dışı:** Varsayılan reputation request, toplu IP/domain/hash history upload, provider verdict'inden malware hükmü veya automatic blocking.
- **Çıkış ölçütü:** Yeni kurulumda sıfır request; fake provider ve offline/timeout/429/stale testleri; no-hit/failure ayrımı; TI kapalıyken local detection çalışır.

### M16 — Incident Correlation & Timeline

- **Durum:** ✅ COMPLETE (2026-10-05; NS-089–NS-092). Offline gerçek servis/repository hikâyesi, source retention/restart/dedup/loss, fixed UTC buckets, inclusive reopen, offscreen salt-okunur timeline ve ölçülmüş runtime/storage/query bütçeleri geçti. 45 yeni test; broad 2277 passed/8 deselected, full 3365 passed/8 deselected. Production değişikliği ve migration yok; SQLite 019. [NS-092 kabul/soak ve M16 exit raporu](INCIDENT_ACCEPTANCE_SOAK.md). NS-093 başlatılmadı; önceki [correlation](INCIDENT_CORRELATION_ACCEPTANCE.md), [persistence](INCIDENT_PERSISTENCE_ACCEPTANCE.md), [timeline](INCIDENT_TIMELINE_ACCEPTANCE.md) kabul kayıtları korunur.
- **Amaç:** Ayrı observation, assessment ve alert'ler arasındaki sınırlı olay hikayesini göstermek.
- **Ana teslimatlar:** Typed references, bounded correlation window, incident lifecycle/persistence, timeline GUI ve offline acceptance/soak.
- **Açık kapsam dışı:** Alert'in yerine geçme, aynı IP'den otomatik incident merge, olmayan process creation event'i, forensic integrity garantisi.
- **Çıkış ölçütü:** Dedup/reopen/restart/retention testleri geçer; process creation telemetry yoksa “process observed” denir; ilişki nedenleri/unknown görünür.

### M17 — Public Beta & Product Usability

- **Durum:** IN PROGRESS. NS-093–NS-098 ✅ COMPLETE (2026-10-06). [Tray](TRAY_APPLICATION_LIFECYCLE.md), [notifications](DESKTOP_NOTIFICATIONS_ACCEPTANCE.md), [storage/privacy](STORAGE_PRIVACY_ACCEPTANCE.md), [installer native lifecycle/Unicode](INSTALLER_ACCEPTANCE.md) ve [signing/manual pilot](SIGNING_UPDATE_ACCEPTANCE.md) kabul kayıtları korunur. NS-098 altı sayfalı versioned guide/Help reopen, separate capture/TI consent, readable Diagnostics ve aynı NS-095 full sanitized preview/local Save ekler; beş synthetic UI asset, operator walkthrough ve [pilot notes](RELEASE_NOTES.md) hazırdır. Schema 019→019; 51 yeni case, targeted 269 ve full offline 3781 passed/8 deselected; Ruff/configured/direct mypy/diff/privacy PASS. [Frozen policy ve artifacts](FIRST_RUN_FEEDBACK.md), [80-item kabul](FIRST_RUN_FEEDBACK_ACCEPTANCE.md). Native Windows DPI/screen-reader/independent novice kabulü iddia edilmez. NS-098 teslimatında installer rebuild/release/tag yoktu; NS-099 IN PROGRESS / INCOMPLETE; committed ae08d7e runtime'dan installer rebuilt; yeni Windows 11 VM standard/Unicode install/repair/browser/updater/restart/export/KEEP PASS, required VPN/meaningful native sleep NOT RUN, native toast/click/tray Quit scoped PASS, effective OS-policy PASS (same-context actual global OFF/ON; honest UNKNOWN, current8242868 policy evidence); focused human layout recheck PASS, overall8 UX PASS; [NS-099 report](PUBLIC_BETA_ACCEPTANCE.md).
- **Amaç:** Günlük kullanım ve gerçek kullanıcı geri bildirimi için hazır olmak.
- **Ana teslimatlar:** Tray, privacy-aware desktop notification, storage/privacy controls, installer/upgrade/uninstall, signing/update kararı, first-run/feedback ve NS-099 beta gate.
- **Açık kapsam dışı:** Automatic blocking/elevation, otomatik crash/history upload, custom WFP driver.
- **Çıkış ölçütü:** NS-099 normal browser/updater, VPN, sleep/wake, restart, Npcap missing, standard user, notification/false-positive burden, clean install, upgrade, uninstall ve privacy/storage senaryolarını doğrular; client Windows VM ve offline kalite kapıları geçer.

### M18 — Manual Response & Firewall Integration — CONDITIONAL

- **Durum:** IN PROGRESS (2026-10-08), explicit user GO for NS-100 only; NS-100 contract COMPLETE, NS-101–NS-104 NOT STARTED. In-product writes NO_GO until privilege/ownership/native gates pass. [Contract](RESPONSE_COMMAND_CONTRACT.md), [acceptance](RESPONSE_COMMAND_ACCEPTANCE.md).
- **Başlatma kapısı:** **M17 tamamlanmış, NS-099 geçmiş ve explicit response GO kararı verilmiş olmalıdır. Bu üç koşuldan önce NS-100–NS-104 başlatılmaz.**
- **Amaç:** İncelenmiş davranış için dar, geri alınabilir manuel Windows Firewall eylemleri.
- **Ana teslimatlar:** Explicit user action → preview → confirmation → yalnız NetSentinel-owned narrow firewall rule → audit → undo/expiry; permission UX ve uninstall reconciliation.
- **Açık kapsam dışı:** Automatic blocking, automatic elevation, process termination, unrelated user/system rules'a müdahale, custom WFP driver.
- **Çıkış ölçütü:** Ownership/idempotency/rollback/izin reddi testleri geçer; unrelated rules korunur; kaldırılamayan owned rules açıkça bildirilir.

## M19 — Localization & Guided Onboarding

- **Durum:** IN PROGRESS (2026-10-09); NS-105 COMPLETE, NS-106–NS-110 PLANNED / NOT STARTED.
- **Amaç:** Turkish mandatory/English fallback dahil 18 offline UI dili, kalıcı first-launch/Settings dil tercihi ve mevcut M17 rehberinden geliştirilen erişilebilir beginner tour.
- **Ana teslimatlar:** Qt TS/QM extraction/review/packaging; first-launch language chooser (English Inno installer minimal kalır); coherent runtime retranslation veya NS-105 feasibility gate sonrası explicit restart-required mode; page-aware optional guide/Settings replay/legacy state preservation; RTL/CJK/long-string ve Windows100/125/150/200% acceptance.
- **Başlatma kapısı:** NS-104 COMPLETE; explicit NS-105 yetkisi yalnız foundation/restart-mode kapsamını kapattı. NS-106 ve sonraki tasklar ayrıca kullanıcı yetkisi gerektirir; NS-110 native gate korunur.
- **Açık kapsam dışı:** Yeni detectors, consent değişimi, privileged deployment, installer translations, runtime translation APIs, broad release/signing.
- **Çıkış ölçütü:** NS-110 frozen matrix ve final18 catalog/reviewer/native UX/resource/state/safety gates PASS; tested switching mode açık. **M19 bitişinde NetSentinel finished ilan edilmez.**

## M20 — Full-System VMware Validation

- **Durum:** PLANNED / NOT STARTED (2026-10-09); NS-111–NS-120.
- **Amaç:** Installation→telemetry→detection→UI→persistence→lifecycle/uninstall zincirini real owned Windows11/Kali native lab ve benign controls ile doğrulamak.
- **Ana teslimatlar:** Frozen feature inventory (64 acceptance units, M19 additions planned),56 scenario families/36 benign control families; primary VMware host-only/no-route lab, separate benign NAT/private VPN phase; bounded structured receipts/OS+DB+UI oracles; all actual LAN/DNS/VLAN/process/baseline/risk/alerts/incidents/TI/privacy/response/stability/localization/installer areas.
- **Başlatma kapısı:** NS-110 COMPLETE ve gelecekte explicit M20 VM execution authorization; NS-111 exact owned environment/hash/caps/oracles freeze'i ve scenario-specific opt-ins. Bu plan attack/VM/build çalıştırmaz.
- **Açık kapsam dışı:** Yeni detector/automatic incident producer/credential backend, automatic blocking/elevation, privileged persistent service/helper/WFP/driver, malicious-local-admin protection, process termination/updater, public/third-party attacks veya signing/distribution GO.
- **Çıkış ölçütü:** NS-120 PASS yalnız all required current-candidate receipts/controls/budgets/cleanup ve frozen justified capability alternatives ile. CONDITIONAL_PASS pending conditions bırakır ve işlevsel completion değildir; FAIL defects/unsafe evidence gerektirir. Required missing native evidence PASS sayılamaz. **Functional completion yalnız final M20 PASS sonrası; broad public release ve in-product privileged writes ayrı NO_GO kapılarıdır.**

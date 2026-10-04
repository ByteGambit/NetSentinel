# Yol haritası

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

## Yeni faz: M11–M14 tamamlandı; M15–M17 planlandı, M18 conditional

**Durum:** M1–M14 tamamlandı. M15–M17 planlandı ve henüz uygulanmadı; NS-084 başlatılmadı. M18, M17 tamamlanıp NS-099 public beta acceptance gate geçmeden ve açık response GO kararı verilmeden başlatılamayan conditional roadmap'tir. Yukarıdaki ve önceki teslimatlardaki tarihsel milestone kayıtları değişmez.

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

- **Durum:** ⬜ Planlandı (NS-084–NS-088); kullanıcı için varsayılan kapalı.
- **Amaç:** Kullanıcı onayıyla destekleyici destination reputation evidence sağlamak.
- **Ana teslimatlar:** Provider port/adapter, provider/subject/data consent, local TTL/stale cache, bounded rate-limited/offline scheduler ve risk revision/UI entegrasyonu.
- **Açık kapsam dışı:** Varsayılan reputation request, toplu IP/domain/hash history upload, provider verdict'inden malware hükmü veya automatic blocking.
- **Çıkış ölçütü:** Yeni kurulumda sıfır request; fake provider ve offline/timeout/429/stale testleri; no-hit/failure ayrımı; TI kapalıyken local detection çalışır.

### M16 — Incident Correlation & Timeline

- **Durum:** ⬜ Planlandı (NS-089–NS-092).
- **Amaç:** Ayrı observation, assessment ve alert'ler arasındaki sınırlı olay hikayesini göstermek.
- **Ana teslimatlar:** Typed references, bounded correlation window, incident lifecycle/persistence, timeline GUI ve offline acceptance/soak.
- **Açık kapsam dışı:** Alert'in yerine geçme, aynı IP'den otomatik incident merge, olmayan process creation event'i, forensic integrity garantisi.
- **Çıkış ölçütü:** Dedup/reopen/restart/retention testleri geçer; process creation telemetry yoksa “process observed” denir; ilişki nedenleri/unknown görünür.

### M17 — Public Beta & Product Usability

- **Durum:** ⬜ Planlandı (NS-093–NS-099).
- **Amaç:** Günlük kullanım ve gerçek kullanıcı geri bildirimi için hazır olmak.
- **Ana teslimatlar:** Tray, privacy-aware desktop notification, storage/privacy controls, installer/upgrade/uninstall, signing/update kararı, first-run/feedback ve NS-099 beta gate.
- **Açık kapsam dışı:** Automatic blocking/elevation, otomatik crash/history upload, custom WFP driver.
- **Çıkış ölçütü:** NS-099 normal browser/updater, VPN, sleep/wake, restart, Npcap missing, standard user, notification/false-positive burden, clean install, upgrade, uninstall ve privacy/storage senaryolarını doğrular; client Windows VM ve offline kalite kapıları geçer.

### M18 — Manual Response & Firewall Integration — CONDITIONAL

- **Durum:** ◇ Conditional plan (NS-100–NS-104); committed next work değildir.
- **Başlatma kapısı:** **M17 tamamlanmış, NS-099 geçmiş ve explicit response GO kararı verilmiş olmalıdır. Bu üç koşuldan önce NS-100–NS-104 başlatılmaz.**
- **Amaç:** İncelenmiş davranış için dar, geri alınabilir manuel Windows Firewall eylemleri.
- **Ana teslimatlar:** Explicit user action → preview → confirmation → yalnız NetSentinel-owned narrow firewall rule → audit → undo/expiry; permission UX ve uninstall reconciliation.
- **Açık kapsam dışı:** Automatic blocking, automatic elevation, process termination, unrelated user/system rules'a müdahale, custom WFP driver.
- **Çıkış ölçütü:** Ownership/idempotency/rollback/izin reddi testleri geçer; unrelated rules korunur; kaldırılamayan owned rules açıkça bildirilir.

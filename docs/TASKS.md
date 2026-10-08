# Uygulama taskları

Bu belge planlanan uygulama işlerinin kaynak kaydıdır. Tasklar geliştirme sırasına göre numaralandırılmıştır. Bir taskın “tamamlandı” sayılması için acceptance criteria'nın tamamı karşılanmalı, belirtilen testler geçmeli ve davranış değiştiyse ilgili doküman güncellenmelidir.

## Ortak tamamlanma kuralları

- Kod type hint içerir; domain ve application katmanları framework bağımsız kalır.
- Yeni davranış pozitif, negatif ve hata senaryolarıyla test edilir.
- Canlı ağ veya yönetici yetkisi gerektiren testler varsayılan suite'e dahil edilmez; açık marker kullanır.
- Ham paket payload'ı, secret veya gereksiz kişisel veri loglanmaz.
- Worker'lar bounded kaynak kullanır ve deterministik biçimde durdurulabilir.
- Task kapsamı dışı refactor veya yeni özellik ayrıca planlanır.

---

## M1 — Core Connection Monitor

### NS-001 — Python proje ve test iskeleti

- **Durum:** ✅ Tamamlandı (2026-09-18)
- **Amaç:** Sonraki taskların üzerinde çalışacağı minimal, paketlenebilir `src` layout ve kalite altyapısını kurmak.
- **Yapılacaklar:** `pyproject.toml`, `src/netsentinel`, `tests` alt dizinleri ve pytest yapılandırmasını oluştur; runtime/dev bağımlılık gruplarını ayır; boş uygulama giriş noktasını yalnızca import edilebilirlik için tanımla.
- **Etkilenecek muhtemel dosyalar:** `pyproject.toml`, `src/netsentinel/__init__.py`, `src/netsentinel/__main__.py`, `tests/conftest.py`, `.gitignore`.
- **Bağımlılıklar:** Yok.
- **Acceptance criteria:** Temiz sanal ortamda proje kurulabilir; `netsentinel` import edilir; test discovery hata vermeden çalışır; uygulama özelliği eklenmez.
- **Test yöntemi:** Temiz ortamda editable install, `python -m netsentinel --help` smoke kontrolü ve `pytest` discovery.

### NS-002 — Connection domain modelleri

- **Durum:** ✅ Tamamlandı (2026-09-18)
- **Amaç:** TCP/UDP endpoint, process ve connection yaşam döngüsü için immutable, framework bağımsız veri sözleşmelerini tanımlamak.
- **Yapılacaklar:** Protokol/durum enum'ları, `Endpoint`, `ProcessIdentity`, `ConnectionKey`, `ConnectionSnapshot` ve connection event tiplerini oluştur; eksik remote endpoint ve erişilemeyen process bilgisini açıkça modelle; UTC doğrulaması ekle.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/domain/connections.py`, `src/netsentinel/domain/observations.py`, `tests/unit/domain/test_connections.py`.
- **Bağımlılıklar:** NS-001.
- **Acceptance criteria:** Modeller PyQt6/psutil/Scapy import etmez; eşitlik/hash davranışı tanımlıdır; IPv4, IPv6, UDP ve eksik değerler temsil edilir; naive timestamp reddedilir veya belgeli biçimde normalize edilir.
- **Test yöntemi:** Parametrik unit testlerle oluşturma, validasyon, equality/hash ve serialization-safe alan kontrolü.

### NS-003 — psutil connection collector adapter'ı

- **Durum:** ✅ Tamamlandı (2026-09-18)
- **Amaç:** Windows'taki TCP/UDP connection bilgisini psutil'den alıp domain snapshot'larına normalize etmek.
- **Yapılacaklar:** Collector portunu tanımla; `psutil.net_connections` satırlarını IPv4/IPv6, TCP/UDP ve boş remote endpoint durumlarında dönüştür; erişim reddi ve yarış koşullarını typed adapter hatalarına çevir.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/ports.py`, `src/netsentinel/infrastructure/psutil_connections.py`, `tests/unit/infrastructure/test_psutil_connections.py`.
- **Bağımlılıklar:** NS-002.
- **Acceptance criteria:** Desteklenen psutil satırları normalize edilir; tek bozuk/eksik satır tüm snapshot'ı düşürmez; permission hatası capability kaybı olarak ayırt edilir; collector UI veya DB bilmez.
- **Test yöntemi:** Monkeypatch edilmiş psutil sonuçlarıyla IPv4/IPv6/TCP/UDP, empty remote, denied ve process-race testleri.

### NS-004 — Process metadata resolver

- **Durum:** ✅ Tamamlandı (2026-09-18)
- **Amaç:** Connection PID'lerini güvenli biçimde process adı ve create-time bilgisiyle zenginleştirmek.
- **Yapılacaklar:** Resolver portu ve psutil implementasyonu ekle; kısa ömürlü process, PID reuse, `AccessDenied`, `NoSuchProcess` ve PID'siz connection davranışını tanımla; snapshot turu içinde sınırlı cache kullan.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/ports.py`, `src/netsentinel/infrastructure/psutil_connections.py`, `src/netsentinel/application/services/processes.py`, `tests/unit/application/test_process_resolver.py`.
- **Bağımlılıklar:** NS-002, NS-003.
- **Acceptance criteria:** Erişilebilir PID zenginleştirilir; erişilemeyen bilgi açık bir availability durumu taşır; PID reuse create-time ile ayrıştırılır; hata polling turunu sonlandırmaz.
- **Test yöntemi:** Fake process provider ile başarı, cache, PID reuse, process'in arada kapanması ve erişim reddi unit testleri.

### NS-005 — Connection snapshot diff ve lifecycle tracker

- **Durum:** ✅ Tamamlandı (2026-09-18)
- **Amaç:** Ardışık snapshot'lar arasından yeni, güncellenen ve kapanan connection olaylarını deterministik üretmek.
- **Yapılacaklar:** `ConnectionTrackingService` yaz; kararlı anahtar/eşleme kuralını uygula; first/last seen ve status değişimini tut; UDP “kaybolma” semantiğini belgeleyen close reason kullan.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/services/connections.py`, `src/netsentinel/domain/connections.py`, `tests/unit/application/test_connection_tracking.py`.
- **Bağımlılıklar:** NS-002, NS-004.
- **Acceptance criteria:** İlk snapshot doğru open olayları, sonraki snapshot doğru update/close olayları üretir; aynı snapshot tekrarı idempotenttir; PID reuse yanlış eşleşmez; çıktı sırası testlerde kararlıdır.
- **Test yöntemi:** Fake clock ve tablo temelli snapshot dizileriyle lifecycle, kısa değişim, UDP ve PID reuse testleri.

### NS-006 — Engine yaşam döngüsü ve event dispatcher

- **Durum:** ✅ Tamamlandı (2026-09-18)
- **Amaç:** Polling, tracking ve event dağıtımını GUI'den bağımsız, güvenli başlayıp duran bir monitoring engine altında birleştirmek.
- **Yapılacaklar:** `MonitoringEngine`, interval scheduler, cancellation ve typed dispatcher oluştur; subscriber hatalarını izole et; health/capability snapshot'ı üret; üst üste polling çalışmasını engelle.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/engine.py`, `src/netsentinel/application/events.py`, `src/netsentinel/shared/diagnostics.py`, `src/netsentinel/bootstrap.py`, `tests/unit/application/test_engine.py`.
- **Bağımlılıklar:** NS-003, NS-005.
- **Acceptance criteria:** `start/stop` idempotenttir; stop sınırlı sürede tamamlanır; yavaş tur overlap yaratmaz; subscriber hatası diğer subscriber'ları durdurmaz; health son hatayı görünür kılar.
- **Test yöntemi:** Fake collector/clock/dispatcher ile lifecycle ve hata izolasyonu unit testleri; kısa süreli thread leak smoke testi.

### NS-007 — M1 entegrasyon ve Windows smoke testleri

- **Durum:** ✅ Tamamlandı (2026-09-18)
- **Amaç:** Core connection monitor'ün gerçek adapter sınırında beklenen davranışını doğrulamak.
- **Yapılacaklar:** Katman contract testleri, işaretlenmiş Windows smoke testleri ve kontrollü local socket fixture'ı ekle; bilinen psutil kısıtlarını test notlarında belirt.
- **Etkilenecek muhtemel dosyalar:** `tests/integration/test_connection_monitor.py`, `tests/fixtures/connections.py`, `pyproject.toml`, `docs/ARCHITECTURE.md`.
- **Bağımlılıklar:** NS-001–NS-006.
- **Acceptance criteria:** Varsayılan suite ağ/yönetici yetkisi istemez; Windows marker'lı test local TCP socket'i en az bir snapshot'ta gözler; suite sonunda worker/socket kalmaz.
- **Test yöntemi:** `pytest` unit/integration çalıştırması ve Windows'ta opt-in `windows_live` smoke testi.

---

## M2 — PyQt6 GUI

### NS-008 — PyQt6 uygulama kabuğu ve navigasyon

- **Durum:** ✅ Tamamlandı (2026-09-18)
- **Amaç:** Dashboard, Connections, Devices, DNS ve Alerts için genişletilebilir masaüstü kabuğu kurmak.
- **Yapılacaklar:** `QApplication`, ana pencere, sol navigasyon ve placeholder sayfaları oluştur; uygulama kapanışını composition root'a bağla; ekran üretimini ayrı view sınıflarında tut.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/presentation/app.py`, `src/netsentinel/presentation/views/main_window.py`, `src/netsentinel/presentation/views/*.py`, `src/netsentinel/bootstrap.py`.
- **Bağımlılıklar:** NS-001, NS-006.
- **Acceptance criteria:** Tüm planlanan sayfalar arasında geçiş yapılır; pencere kapanırken engine stop istenir; view'lar psutil/Scapy/SQLite import etmez.
- **Test yöntemi:** Offscreen Qt smoke testi, sayfa geçişi ve close event testi.

### NS-009 — Thread-safe Qt engine bridge

- **Durum:** ✅ Tamamlandı (2026-09-18)
- **Amaç:** Engine event'lerini Qt ana thread'ine güvenli ve batch'li biçimde taşımak.
- **Yapılacaklar:** `QtEngineBridge` ve immutable view event tiplerini ekle; bounded handoff queue/queued signal uygula; overflow ve engine health durumunu UI'ya aktar.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/presentation/bridge.py`, `src/netsentinel/application/events.py`, `tests/gui/test_engine_bridge.py`.
- **Bağımlılıklar:** NS-006, NS-008.
- **Acceptance criteria:** Worker callback'i widget'a erişmez; event'ler GUI thread'inde işlenir; burst batch'lenir; queue overflow görünür health metriği üretir; bridge detach edilebilir.
- **Test yöntemi:** Fake engine'den worker thread üzerinde event yayınlayan Qt testi; thread affinity, ordering ve overflow kontrolü.

### NS-010 — Connections tablo modeli

- **Durum:** ✅ Tamamlandı (2026-09-19)
- **Amaç:** Aktif connection verisini tam tablo reseti yapmadan gösteren test edilebilir Qt modelini oluşturmak.
- **Yapılacaklar:** `QAbstractTableModel` tabanlı model ve connection view model mapper'ı ekle; stable row ID, kolonlar, display/raw roller ve incremental insert/update/remove uygula.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/presentation/models/connections.py`, `src/netsentinel/presentation/viewmodels.py`, `tests/gui/test_connections_model.py`.
- **Bağımlılıklar:** NS-002, NS-009.
- **Acceptance criteria:** Protokol, state, local/remote endpoint, PID, process ve süre alanları gösterilir; eksik alanlar güvenli placeholder alır; row kimliği sıralamada korunur; gereksiz model reset yoktur.
- **Test yöntemi:** Model tester, fake event dizileri ve insert/update/remove sinyal testleri.

### NS-011 — Connections ekranı, filtreleme ve detay

- **Durum:** ✅ Tamamlandı (2026-09-19)
- **Amaç:** Canlı bağlantıları aranabilir, sıralanabilir ve açıklanabilir bir ekranda sunmak.
- **Yapılacaklar:** Table view, proxy filter/sort, TCP/UDP ve state filtreleri, detay paneli ve paused-view davranışı ekle; boş/yetkisiz/hata durumlarını tasarla.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/presentation/views/connections.py`, `src/netsentinel/presentation/widgets/connection_details.py`, `tests/gui/test_connections_view.py`.
- **Bağımlılıklar:** NS-010.
- **Acceptance criteria:** Arama process/IP/port üzerinde çalışır; filtreler birleşebilir; seçim stable ID ile korunur; unavailable process ve degraded monitoring açıkça görünür.
- **Test yöntemi:** Fake model ile filtre/sort/seçim testleri ve offscreen screenshot dışı widget assertions.

### NS-012 — Dashboard ve temel canlı istatistikler

- **Durum:** ✅ Tamamlandı (2026-09-19)
- **Amaç:** Aktif connection sayısı, protokol dağılımı, yeni/kapanan olay sayısı ve engine health'i özetlemek.
- **Yapılacaklar:** Bounded `StatisticsService`, dashboard read model ve kart/widget'ları ekle; kısa rolling window tanımla; “paket byte trafiği” ile “connection sayısı”nı karıştırmayan etiketler kullan.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/services/statistics.py`, `src/netsentinel/presentation/models/dashboard.py`, `src/netsentinel/presentation/views/dashboard.py`, `tests/unit/application/test_statistics.py`.
- **Bağımlılıklar:** NS-006, NS-009.
- **Acceptance criteria:** Sayaçlar event dizilerinden deterministik hesaplanır; pencere dışı veriler atılır; health/degraded durumu görünür; UI “bandwidth” iddiasında bulunmaz.
- **Test yöntemi:** Fake clock ile rolling window unit testleri ve fake read model ile GUI testi.

### NS-013 — GUI lifecycle, erişilebilirlik ve regresyon testleri

- **Durum:** ✅ Tamamlandı (2026-09-19)
- **Amaç:** M2 arayüzünün temel kullanılabilirlik ve kapanış davranışını güvenceye almak.
- **Yapılacaklar:** Klavye navigasyonu, accessible name, yüksek DPI varsayımları, boş/loading/error state ve kapanış testlerini ekle; hızlı event burst altında responsiveness ölçümü tanımla.
- **Etkilenecek muhtemel dosyalar:** `tests/gui/test_app_lifecycle.py`, `tests/gui/test_accessibility.py`, `tests/gui/test_event_burst.py`, ilgili `presentation` dosyaları.
- **Bağımlılıklar:** NS-008–NS-012.
- **Acceptance criteria:** Kritik kontroller accessible name taşır; tab sırası kullanılabilir; kapanışta engine durur; burst sırasında event loop smoke eşiğini aşmaz; testler offscreen çalışır.
- **Test yöntemi:** pytest-qt/offscreen Qt testleri ve ölçülü event-loop heartbeat testi.

---

## M3 — Persistence

### NS-014 — SQLite bağlantısı, migration sistemi ve başlangıç şeması

- **Durum:** ✅ Tamamlandı (2026-09-19)
- **Amaç:** Sürümlenebilir, güvenli ve ilerletilebilir yerel veri tabanı temelini oluşturmak.
- **Yapılacaklar:** DB path politikası, connection factory, WAL/busy timeout, transaction helper ve sıralı migration runner ekle; connection history ve migration tablolarını oluştur.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/infrastructure/sqlite/database.py`, `src/netsentinel/infrastructure/sqlite/migrations.py`, `src/netsentinel/infrastructure/sqlite/schema/*.sql`, `tests/integration/sqlite/test_migrations.py`.
- **Bağımlılıklar:** NS-001, NS-002.
- **Acceptance criteria:** Boş DB en son şemaya çıkar; migration tekrar çalıştırıldığında idempotenttir; yarım migration rollback olur; daha yeni bilinmeyen şema yazma modunda açılmaz.
- **Test yöntemi:** Geçici DB üzerinde fresh, incremental, rollback, corrupt/unsupported version entegrasyon testleri.

### NS-015 — Connection history repository

- **Durum:** ✅ Tamamlandı (2026-09-19)
- **Amaç:** Connection yaşam döngüsünü SQL ayrıntısını application katmanına sızdırmadan saklamak ve sayfalı sorgulamak.
- **Yapılacaklar:** Repository portu, SQLite mapping ve time/process/endpoint filtreli query nesnesi ekle; parameterized SQL ve kararlı pagination uygula.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/ports.py`, `src/netsentinel/infrastructure/sqlite/repositories.py`, `src/netsentinel/domain/connections.py`, `tests/integration/sqlite/test_connection_repository.py`.
- **Bağımlılıklar:** NS-005, NS-014.
- **Acceptance criteria:** Open/update/close bilgisi kaybolmadan round-trip olur; sorgular limit gerektirir; injection benzeri filtreler veri değiştirmez; aynı timestamp'te pagination kayıt atlamaz.
- **Test yöntemi:** Geçici DB ile round-trip, filter, ordering, pagination ve rollback testleri.

### NS-016 — Asenkron history writer ve backpressure

- **Durum:** ✅ Tamamlandı (2026-09-21)
- **Amaç:** Monitoring worker'larını SQLite I/O'dan ayıran tek yazıcılı, bounded persistence hattı kurmak.
- **Yapılacaklar:** Persistence queue, batch boyutu/zamanı, retry sınırı, flush-on-stop ve health metriklerini uygula; event'leri repository komutlarına map et.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/services/history.py`, `src/netsentinel/infrastructure/sqlite/writer.py`, `src/netsentinel/application/engine.py`, `tests/integration/sqlite/test_writer.py`.
- **Bağımlılıklar:** NS-006, NS-015.
- **Acceptance criteria:** Producer DB beklemez; tek writer connection kullanılır; stop mevcut batch'i timeout içinde flush eder; dolu queue veri kaybı metriği/health uyarısı üretir; sınırsız retry yoktur.
- **Test yöntemi:** Yavaş/failing fake repository ve gerçek geçici SQLite ile batching, ordering, overflow, retry ve shutdown testleri.

### NS-017 — Retention ve yerel veri yaşam döngüsü

- **Durum:** ✅ Tamamlandı (2026-09-21)
- **Amaç:** History'nin kontrolsüz büyümesini engellemek ve kullanıcıya anlaşılır saklama politikası sunmak.
- **Yapılacaklar:** Yapılandırılabilir gün/row politikası, chunked cleanup, DB boyutu diagnostics ve manuel güvenli temizleme command'ı ekle; aktif veriyi silme sınırını tanımla.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/services/retention.py`, `src/netsentinel/infrastructure/sqlite/repositories.py`, `src/netsentinel/shared/config.py`, `tests/integration/sqlite/test_retention.py`, `docs/SECURITY.md`.
- **Bağımlılıklar:** NS-014–NS-016.
- **Acceptance criteria:** Eşik öncesi kayıtlar chunk'lar halinde silinir; sınırdaki kayıt korunur; cleanup kesilirse DB tutarlıdır; varsayılan retention belgelenir; ham payload saklanmaz.
- **Test yöntemi:** Fake clock ve çok tarihli geçici DB ile boundary, transaction ve interrupted cleanup testleri.

### NS-018 — Connection history ekranı ve M3 entegrasyonu

- **Durum:** ✅ Tamamlandı (2026-09-21)
- **Amaç:** Kalıcı connection geçmişini UI'da sayfalı ve filtreli göstermek.
- **Yapılacaklar:** History read service, async query bridge, tablo modeli, tarih/process/endpoint filtreleri ve detay görünümü ekle; uzun sorgu iptalini destekle.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/services/history.py`, `src/netsentinel/presentation/models/history.py`, `src/netsentinel/presentation/views/connections.py`, `tests/gui/test_connection_history.py`.
- **Bağımlılıklar:** NS-011, NS-015–NS-017.
- **Acceptance criteria:** Büyük veri seti GUI thread'ini bloklamadan sayfalanır; yeni filtre eski sorgu sonucuyla ezilmez; restart sonrası kayıtlar görünür; retention sonucu UI ile tutarlıdır.
- **Test yöntemi:** Seed edilmiş geçici DB ve fake slow query ile pagination, cancellation, restart ve GUI responsiveness testleri.

---

## M4 — LAN Device Monitor

### NS-019 — Windows network context adapter'ı

- **Durum:** ✅ Tamamlandı (2026-09-21)
- **Amaç:** Interface, subnet, gateway ve DNS bilgisini ağ bağlamına dönüştürmek.
- **Yapılacaklar:** `NetworkContextProvider` portu ve Windows adapter'ı ekle; IPv4 öncelikli ilk kapsamı, çoklu interface, VPN/loopback ve ağ değişimini modelle; kararlı context fingerprint üret.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/domain/devices.py`, `src/netsentinel/application/ports.py`, `src/netsentinel/infrastructure/windows_network.py`, `tests/unit/infrastructure/test_windows_network.py`.
- **Bağımlılıklar:** NS-001.
- **Acceptance criteria:** Aktif interface'ler normalize edilir; loopback varsayılan capture adayı olmaz; gateway/DNS eksik olabilir; aynı ağ kararlı fingerprint alır; komut çıktısı metnine kırılgan parse minimumda tutulur.
- **Test yöntemi:** Fixture tabanlı adapter contract testleri ve opt-in Windows network context smoke testi.

### NS-020 — Packet capture portu ve güvenli Scapy worker

- **Durum:** ✅ Tamamlandı (2026-09-21)
- **Amaç:** Scapy'yi application katmanından ayıran, seçili interface ve filtreyle sınırlı capture sınırı oluşturmak.
- **Yapılacaklar:** Capture portu, capability probe, start/stop lifecycle, bounded output queue ve minimal metadata envelope ekle; driver/yetki/interface hatalarını sınıflandır.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/ports.py`, `src/netsentinel/infrastructure/scapy_capture.py`, `src/netsentinel/domain/observations.py`, `tests/unit/infrastructure/test_scapy_capture.py`.
- **Bağımlılıklar:** NS-006, NS-019.
- **Acceptance criteria:** Capture kendiliğinden başlamaz; interface açıkça seçilir; stop bounded sürede biter; callback DB/UI çağırmaz; queue overflow ölçülür; ham payload loglanmaz.
- **Test yöntemi:** Fake sniffer ile lifecycle/overflow/error testleri; canlı capture yalnızca `lab_live` marker'ıyla.

### NS-021 — Güvenli ARP parser

- **Durum:** ✅ Tamamlandı (2026-09-22)
- **Amaç:** Scapy paketlerinden yalnızca gerekli ARP alanlarını doğrulanmış domain observation'a çevirmek.
- **Yapılacaklar:** Ethernet/ARP alan kontrolü, MAC/IP normalizasyonu, opcode desteği ve malformed paket reddi ekle; parser'ı state/detector mantığından ayrı tut.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/infrastructure/parsers/arp.py`, `src/netsentinel/domain/observations.py`, `tests/unit/infrastructure/parsers/test_arp.py`, `tests/fixtures/packets/`.
- **Bağımlılıklar:** NS-020.
- **Acceptance criteria:** Request/reply doğru parse edilir; eksik, fazla uzun veya geçersiz alan güvenli biçimde reddedilir; payload domain'e geçmez; parser exception capture worker'ı durdurmaz.
- **Test yöntemi:** Sentetik Scapy packet fixture'ları ve malformed/fuzz-benzeri sınır testleri.

### NS-022 — Device registry ve IP-MAC binding geçmişi

- **Durum:** ✅ Tamamlandı (2026-09-23)
- **Amaç:** ARP observations içinden ağ bağlamına özgü cihaz ve zaman aralıklı kimlik eşleşmesi oluşturmak.
- **Yapılacaklar:** `DeviceIdentity`, `IdentityBinding`, registry service, device/binding migration ve repository ekle; first/last seen ile vendor dışı temel kimliği tut.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/domain/devices.py`, `src/netsentinel/application/services/devices.py`, `src/netsentinel/infrastructure/sqlite/schema/*.sql`, `src/netsentinel/infrastructure/sqlite/repositories.py`, `tests/unit/application/test_device_registry.py`.
- **Bağımlılıklar:** NS-014, NS-019, NS-021.
- **Acceptance criteria:** Aynı MAC tekrarında last-seen güncellenir; IP değişimi geçmişi ezmez; farklı network context kayıtları karışmaz; multicast/broadcast/zero MAC cihaz sayılmaz.
- **Test yöntemi:** Fake clock/context ile registry unit testleri ve SQLite round-trip entegrasyon testi.

### NS-023 — Yeni cihaz detector'ı

- **Durum:** ✅ Tamamlandı (2026-09-23)
- **Amaç:** Belirli ağ bağlamında ilk kez görülen cihazı güvenilir ve deduplicate edilmiş olay olarak üretmek.
- **Yapılacaklar:** `NewDeviceDetector`, warm-up davranışı ve restart sonrası known-device yüklemesi ekle; ilk kurulum import'u ile gerçekten yeni cihazı ayır.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/detectors/new_device.py`, `src/netsentinel/application/services/devices.py`, `src/netsentinel/domain/alerts.py`, `tests/unit/application/detectors/test_new_device.py`.
- **Bağımlılıklar:** NS-022.
- **Acceptance criteria:** Cihaz/context başına bir new-device olayı üretilir; restart tekrar alert yaratmaz; warm-up davranışı yapılandırılmış ve açıklanmıştır; sahte/invalid ARP girdi sayılmaz.
- **Test yöntemi:** Boş/seed edilmiş registry, farklı context ve tekrar observation senaryoları ile unit test.

### NS-024 — Devices ekranı ve M4 lab doğrulaması

- **Durum:** ✅ Tamamlandı (2026-09-23)
- **Amaç:** Cihaz envanteri, IP-MAC geçmişi ve capture capability durumunu anlaşılır biçimde göstermek.
- **Yapılacaklar:** Devices read model/table/detail, first/last seen, interface/context ve binding geçmişi ekle; capture yok/yetki yok hallerini belirt; kontrollü pasif lab test prosedürü yaz.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/presentation/models/devices.py`, `src/netsentinel/presentation/views/devices.py`, `tests/gui/test_devices_view.py`, `docs/SECURITY.md`.
- **Bağımlılıklar:** NS-009, NS-020, NS-022, NS-023.
- **Acceptance criteria:** Liste restart sonrası yüklenir ve canlı güncellenir; device detail binding geçmişini gösterir; capture kapalıyken yanlış “cihaz yok” mesajı verilmez; lab testi izinli ağ şartını içerir.
- **Test yöntemi:** Fake registry/capability ile GUI testleri ve opt-in, pasif `lab_live` smoke testi.

---

## M5 — MITM Detection & Alerts

### NS-025 — Gateway identity baseline

- **Durum:** ✅ Tamamlandı (2026-09-23)
- **Amaç:** Her network context için beklenen gateway IP-MAC kimliğini güvenli biçimde öğrenmek ve saklamak.
- **Yapılacaklar:** Baseline modeli/repository'si, öğrenme penceresi, Windows context ile ARP gözlemi korelasyonu ve kullanıcı doğrulama durumunu ekle.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/domain/devices.py`, `src/netsentinel/application/services/baselines.py`, `src/netsentinel/infrastructure/sqlite/schema/*.sql`, `tests/unit/application/test_gateway_baseline.py`.
- **Bağımlılıklar:** NS-019, NS-022.
- **Acceptance criteria:** Baseline network context'e özgüdür; tek unsolicited observation doğrulanmış baseline'ı sessizce değiştirmez; ağ değişimi ayrı kayıt açar; geçmiş değişiklik zamanı korunur.
- **Test yöntemi:** Fake context/clock ile ilk öğrenme, tekrar, conflict, kullanıcı onayı ve ağ değişimi testleri.

### NS-026 — IP-MAC conflict ve gateway değişim detector'ları

- **Durum:** ✅ Tamamlandı (2026-09-23)
- **Amaç:** Aynı IP için çelişkili MAC ve beklenen gateway MAC değişimini yapılandırılmış güvenlik olayı olarak tespit etmek.
- **Yapılacaklar:** İki detector, rule ID, evidence ve severity/confidence kuralları ekle; gratuitous ARP, DHCP/ağ geçişi ve warm-up için istisnaları tanımla.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/detectors/arp_identity.py`, `src/netsentinel/domain/alerts.py`, `tests/unit/application/detectors/test_arp_identity.py`.
- **Bağımlılıklar:** NS-021, NS-025.
- **Acceptance criteria:** Çelişki doğru entity/context için olay üretir; aynı MAC tekrarında üretmez; evidence eski/yeni MAC ve gözlem zamanını içerir; ağ geçişi doğrudan yüksek confidence sayılmaz.
- **Test yöntemi:** Normal ARP, gratuitous ARP, conflict, gateway failover ve context switch fixture dizileriyle unit test.

### NS-027 — ARP sinyal korelasyonu ve risk puanlama

- **Durum:** ✅ Tamamlandı (2026-09-23)
- **Amaç:** Tek paket yerine tekrar, hedef, zaman ve baseline bağlamını birleştirerek MITM şüphesini daha açıklanabilir kılmak.
- **Yapılacaklar:** Bounded rolling ARP state, tekrar/çakışma/gateway ağırlıkları ve confidence hesaplama ekle; kesin saldırı dili kullanmayan sonuç sözleşmesi tanımla.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/detectors/arp_anomaly.py`, `src/netsentinel/application/services/statistics.py`, `tests/unit/application/detectors/test_arp_anomaly.py`.
- **Bağımlılıklar:** NS-026.
- **Acceptance criteria:** Puanlama deterministiktir; state zamanla temizlenir ve sınırlıdır; güçlü birleşik sinyal tekil sinyalden yüksek confidence alır; rule breakdown evidence'ta görünür.
- **Test yöntemi:** Fake clock ile burst, seyrek normal trafik, conflict kombinasyonu ve state expiry testleri.

### NS-028 — Genel alert yaşam döngüsü ve persistence

- **Durum:** ✅ Tamamlandı (2026-09-23)
- **Amaç:** Tüm detector'lar için ortak deduplication, durum ve kalıcılık hattı kurmak.
- **Yapılacaklar:** `Alert`, fingerprint, open/acknowledged/resolved durumları, tekrar sayacı, evidence şeması/repository ve `AlertService` ekle; rate limit tanımla.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/domain/alerts.py`, `src/netsentinel/application/services/alerts.py`, `src/netsentinel/infrastructure/sqlite/schema/*.sql`, `src/netsentinel/infrastructure/sqlite/repositories.py`, `tests/unit/application/test_alert_service.py`.
- **Bağımlılıklar:** NS-014, NS-016, NS-023, NS-026.
- **Acceptance criteria:** Aynı fingerprint pencere içinde tek alert'i günceller; tekrar sayısı/last-seen artar; ack state restart sonrası korunur; farklı context/entity birleşmez; evidence bounded'dır.
- **Test yöntemi:** Fake clock/repository ile dedup, lifecycle, rate limit, restart round-trip ve evidence size testleri.

### NS-029 — Alerts ekranı ve MITM senaryo testleri

- **Durum:** ✅ Tamamlandı (2026-09-23)
- **Amaç:** Güvenlik alert'lerini önem, güven, durum ve kanıtlarıyla inceletmek ve M5'i uçtan uca doğrulamak.
- **Yapılacaklar:** Alert table/filter/detail, acknowledge command ve rule açıklaması ekle; sentetik normal/spoof-benzeri ARP pcap/packet senaryoları oluştur.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/presentation/models/alerts.py`, `src/netsentinel/presentation/views/alerts.py`, `tests/gui/test_alerts_view.py`, `tests/integration/test_arp_alert_pipeline.py`, `tests/fixtures/packets/`.
- **Bağımlılıklar:** NS-009, NS-027, NS-028.
- **Acceptance criteria:** UI saldırı kesinliği iddia etmez; evidence eski/yeni kimliği ve context'i gösterir; acknowledge kalıcıdır; normal fixture yüksek severity alert üretmez; spoof-benzeri fixture beklenen rule ID'yi üretir.
- **Test yöntemi:** Fake alert service ile GUI; packet fixture'dan DB/UI read model'e entegrasyon testi.

---

## M6 — DNS Monitoring

### NS-030 — DNS query/response parser

- **Durum:** ✅ Tamamlandı (2026-09-23)
- **Amaç:** Klasik UDP/TCP DNS paketlerinden güvenli ve sınırlı observation üretmek.
- **Yapılacaklar:** Query/response, transaction ID, question ve desteklenen A/AAAA/CNAME/PTR cevaplarını parse et; isim/record sayısı ve uzunluk sınırı uygula; mDNS'i ayrı sınıflandır.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/infrastructure/parsers/dns.py`, `src/netsentinel/domain/dns.py`, `tests/unit/infrastructure/parsers/test_dns.py`, `tests/fixtures/packets/`.
- **Bağımlılıklar:** NS-020.
- **Acceptance criteria:** Desteklenen UDP/TCP fixture'ları parse edilir; compression/malformed giriş uygulamayı düşürmez; sınırsız record/name tutulmaz; payload saklanmaz; DoH/DoT görünmezliği belgelenir.
- **Test yöntemi:** Sentetik normal, truncated, multi-answer, mDNS ve malformed DNS packet testleri.

### NS-031 — DNS transaction korelasyonu

- **Durum:** ✅ Tamamlandı (2026-09-23)
- **Amaç:** Query ve response observations'ı yön/endpoints/transaction ID ile eşleyip süre ve sonuç üretmek.
- **Yapılacaklar:** `DnsTrackingService`, outstanding query bounded map, timeout, duplicate/retry ve unmatched response davranışı ekle; monotonic süre kullan.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/services/dns.py`, `src/netsentinel/domain/dns.py`, `tests/unit/application/test_dns_tracking.py`.
- **Bağımlılıklar:** NS-030.
- **Acceptance criteria:** Normal işlem doğru korele edilir; transaction ID çakışması endpoint ile ayrılır; timeout state'i temizler; unmatched response gözlem olarak korunabilir; bellek bounded'dır.
- **Test yöntemi:** Fake clock ile success, NXDOMAIN, retry, collision, timeout, out-of-order ve overflow unit testleri.

### NS-032 — DNS sunucusu değişikliği detector'ı

- **Durum:** ✅ Tamamlandı (2026-09-23)
- **Amaç:** Windows yapılandırmasındaki DNS server seti değişimini network context'e göre algılamak.
- **Yapılacaklar:** DNS config polling/notification adapter'ı, baseline ve detector ekle; VPN/interface geçişi, sıralama farkı ve geçici boş sonuç davranışını tanımla.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/infrastructure/windows_network.py`, `src/netsentinel/application/detectors/dns_config.py`, `src/netsentinel/application/services/baselines.py`, `tests/unit/application/detectors/test_dns_config.py`.
- **Bağımlılıklar:** NS-019, NS-025, NS-028.
- **Acceptance criteria:** Set değişimi eski/yeni server evidence'ıyla olay üretir; yalnızca sıra değişimi üretmez; context switch ayrı baseline kullanır; tek transient read yüksek confidence alert yaratmaz.
- **Test yöntemi:** Fixture context/config dizileriyle stable, reorder, add/remove, VPN switch ve transient failure testleri.

### NS-033 — DNS history repository ve retention

- **Durum:** ✅ Tamamlandı (2026-09-23)
- **Amaç:** Sınırlandırılmış DNS transaction metadata'sını yerel history için saklamak.
- **Yapılacaklar:** Migration, repository, writer mapping, normalize edilmiş ad/cevap alanları ve DNS'e özel retention uygula; sorgu text uzunluğu sınırı koy.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/infrastructure/sqlite/schema/*.sql`, `src/netsentinel/infrastructure/sqlite/repositories.py`, `src/netsentinel/application/services/history.py`, `tests/integration/sqlite/test_dns_repository.py`.
- **Bağımlılıklar:** NS-016, NS-017, NS-031.
- **Acceptance criteria:** Transaction round-trip olur; timeout/unmatched durumu korunur; filtre ve pagination bounded'dır; retention çalışır; raw payload DB'ye yazılmaz.
- **Test yöntemi:** Geçici DB ile round-trip, query filter, length limit, pagination ve retention testleri.

### NS-034 — DNS ekranı ve M6 entegrasyonu

- **Durum:** ✅ Tamamlandı (2026-09-24)
- **Amaç:** DNS sorgu/cevap geçmişini, gecikmeyi ve DNS config alert'lerini açıklanabilir biçimde sunmak.
- **Yapılacaklar:** DNS table/model/detail, status/type/name/server/time filtreleri ve capability açıklaması ekle; parser'dan persistence/read model'e entegrasyon fixture'ı oluştur.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/presentation/models/dns.py`, `src/netsentinel/presentation/views/dns.py`, `tests/gui/test_dns_view.py`, `tests/integration/test_dns_pipeline.py`.
- **Bağımlılıklar:** NS-009, NS-032, NS-033.
- **Acceptance criteria:** Query/response/timeout ayrılır; cevaplar bounded listelenir; DoH/DoT sınırlaması görünür; filtre GUI'yi bloklamaz; config change alert'e linklenebilir.
- **Test yöntemi:** Seed DB/fake service GUI testleri ve sentetik packet-to-history entegrasyon testi.

---

## M7 — Broadcast Monitoring

### NS-035 — Broadcast/multicast sınıflandırıcı

- **Durum:** ✅ Tamamlandı (2026-09-25)
- **Amaç:** L2 ve desteklenen L3 broadcast trafiğini ARP ve multicast'ten doğru ayırmak.
- **Yapılacaklar:** Ethernet broadcast, IPv4 limited/directed broadcast ve ARP sınıflarını tanımla; multicast'i ayrı kategori yap; yalnızca gerekli metadata'yı observation'a dönüştür.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/infrastructure/parsers/broadcast.py`, `src/netsentinel/domain/observations.py`, `tests/unit/infrastructure/parsers/test_broadcast.py`.
- **Bağımlılıklar:** NS-020, NS-021.
- **Acceptance criteria:** Broadcast/multicast/unicast fixture'ları doğru ayrılır; malformed paket atlanır; ARP double-count kuralı açıktır; payload tutulmaz.
- **Test yöntemi:** Ethernet/IPv4/ARP/multicast packet fixture'larıyla parametrik parser testleri.

### NS-036 — Rolling broadcast/ARP metrikleri ve baseline

- **Durum:** ✅ Tamamlandı (2026-09-25)
- **Amaç:** Interface/context/protokol başına sınırlı zaman pencerelerinde paket oranı ölçmek.
- **Yapılacaklar:** Bucket tabanlı rolling counter, paket/saniye ve baseline özeti ekle; context warm-up, idle expiry ve clock davranışını tanımla.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/services/traffic_metrics.py`, `src/netsentinel/application/services/baselines.py`, `tests/unit/application/test_traffic_metrics.py`.
- **Bağımlılıklar:** NS-027, NS-035.
- **Acceptance criteria:** Sayaç belleği trafik süresinden bağımsız bounded kalır; pencere sınırları deterministiktir; context'ler karışmaz; dropped capture metriği ölçüm güvenine yansır.
- **Test yöntemi:** Fake monotonic clock ile burst, idle, rollover, context switch ve overflow confidence testleri.

### NS-037 — Broadcast/ARP yoğunluk detector'ı

- **Durum:** ✅ Tamamlandı (2026-09-25)
- **Amaç:** Mutlak eşik ve öğrenilmiş baseline sapmasını kullanarak anormal yoğunluk alert'i üretmek.
- **Yapılacaklar:** Yapılandırılabilir threshold, minimum örnek, hysteresis, cooldown ve recovery kuralı ekle; evidence'a pencere/sayaç/baseline değerlerini koy.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/detectors/traffic_rate.py`, `src/netsentinel/shared/config.py`, `tests/unit/application/detectors/test_traffic_rate.py`.
- **Bağımlılıklar:** NS-028, NS-036.
- **Acceptance criteria:** Kısa normal burst ile sürekli yoğunluk ayrılır; cooldown alert storm'u engeller; recovery resolved durumu üretir; eksik capture verisi confidence'ı düşürür.
- **Test yöntemi:** Fake metric stream/clock ile below/above threshold, hysteresis, cooldown, recovery ve dropped-data testleri.

### NS-038 — Broadcast dashboard ve M7 yük testi

- **Durum:** ✅ Tamamlandı (2026-09-26)
- **Amaç:** Broadcast/ARP oranlarını görünür kılmak ve burst altında kaynak kullanımını doğrulamak.
- **Yapılacaklar:** Dashboard kart/trend read model'i, pencere/eşik açıklaması ve health göstergesi ekle; yüksek hacimli sentetik observation performans testi oluştur.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/presentation/models/dashboard.py`, `src/netsentinel/presentation/views/dashboard.py`, `tests/gui/test_broadcast_dashboard.py`, `tests/performance/test_broadcast_burst.py`.
- **Bağımlılıklar:** NS-012, NS-037.
- **Acceptance criteria:** Gösterilen oran ve pencere aynı read model'den gelir; UI batch güncellenir; sentetik yükte queue/memory sınırı korunur; kayıp veri kullanıcıya görünür.
- **Test yöntemi:** Fake metric GUI testi ve belgeli eşiklerle işaretlenmiş performans testi.

---

## M8 — Device Security

### NS-039 — Device profile ve trust persistence

- **Durum:** ✅ Tamamlandı (2026-09-26)
- **Amaç:** Kullanıcının cihazı adlandırmasını, beklenen kimlikleri ve güven durumunu ağ gözleminden ayrı saklamak.
- **Yapılacaklar:** `DeviceProfile`, trust enum, not/label sınırları, migration/repository ve merge kuralları ekle; kullanıcı verisi ile observed state'i ayır.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/domain/devices.py`, `src/netsentinel/infrastructure/sqlite/schema/*.sql`, `src/netsentinel/infrastructure/sqlite/repositories.py`, `tests/integration/sqlite/test_device_profiles.py`.
- **Bağımlılıklar:** NS-022.
- **Acceptance criteria:** Profil round-trip olur; observation kullanıcı etiketini ezmez; label/not uzunluğu sınırlıdır; trust değişiminin zamanı korunur; cihaz merge kayıp yaratmaz.
- **Test yöntemi:** Geçici DB ile CRUD, validation, concurrent observation update ve merge testleri.

### NS-040 — Device identity change detector'ı

- **Durum:** ✅ Tamamlandı (2026-09-26)
- **Amaç:** Bilinen cihaz profilinin beklenen MAC/IP davranışından şüpheli sapmaları tespit etmek.
- **Yapılacaklar:** Beklenmeyen MAC, aynı MAC'in uygunsuz context'te görünmesi ve IP churn kurallarını ekle; DHCP toleransı ve locally administered MAC davranışını tanımla.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/detectors/device_identity.py`, `src/netsentinel/application/services/devices.py`, `tests/unit/application/detectors/test_device_identity.py`.
- **Bağımlılıklar:** NS-028, NS-039.
- **Acceptance criteria:** Normal DHCP IP değişimi tek başına yüksek alert üretmez; beklenmeyen MAC evidence'la işaretlenir; context ve profil geçmişi değerlendirilir; confidence gerekçesi görülebilir.
- **Test yöntemi:** Stabil cihaz, DHCP churn, private/randomized MAC, cloned identity ve context switch scenario testleri.

### NS-041 — Device profile/trust yönetimi UI

- **Durum:** ✅ Tamamlandı (2026-09-26)
- **Amaç:** Kullanıcının cihazı tanımlayıp beklenen kimliği doğrulamasını ve değişiklik alert'ini bağlam içinde incelemesini sağlamak.
- **Yapılacaklar:** Edit dialog/controller, validation, trust açıklaması, expected identity seçimi ve ilişkili alert bağlantıları ekle; destructive merge/silme davranışını kapsam dışı tut.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/presentation/views/devices.py`, `src/netsentinel/presentation/widgets/device_profile.py`, `src/netsentinel/presentation/models/devices.py`, `tests/gui/test_device_profile.py`.
- **Bağımlılıklar:** NS-024, NS-039, NS-040.
- **Acceptance criteria:** Profil kaydetme/iptal doğru çalışır; trust değişimi gözlem verisini silmez; expected identity kullanıcıya açıkça gösterilir; validation hatası eyleme dönüktür.
- **Test yöntemi:** Fake profile service ile edit/cancel/validation/trust ve alert-link GUI testleri.

### NS-042 — Device security uçtan uca ve false-positive testleri

- **Durum:** ✅ Tamamlandı (2026-09-26)
- **Amaç:** Profil, observation, detector, alert ve UI akışının normal ağ değişimlerinde gereksiz alarm üretmediğini doğrulamak.
- **Yapılacaklar:** Senaryo fixture'ları, restart testi ve rule decision table oluştur; random MAC ve DHCP örneklerini kapsa; ürün/güvenlik belgelerini sınırlarla güncelle.
- **Etkilenecek muhtemel dosyalar:** `tests/integration/test_device_security_pipeline.py`, `tests/fixtures/devices/`, `docs/PRODUCT.md`, `docs/SECURITY.md`.
- **Bağımlılıklar:** NS-040, NS-041.
- **Acceptance criteria:** Her rule için pozitif/negatif fixture vardır; restart duplicate alert üretmez; normal DHCP senaryosu yüksek severity üretmez; doküman kesin saldırı iddiasında bulunmaz.
- **Test yöntemi:** Parametrik scenario matrix ve geçici DB ile uçtan uca entegrasyon testi.

---

## M9 — VLAN Monitoring

### NS-043 — 802.1Q VLAN parser

- **Durum:** ✅ Tamamlandı (2026-09-26)
- **Amaç:** Yakalanan Ethernet frame'lerindeki tekli 802.1Q tag bilgisini güvenli biçimde gözleme dönüştürmek.
- **Yapılacaklar:** VLAN ID, PCP, DEI ve kapsüllenmiş protokol parse'ı ekle; tagged/untagged/malformed ayrımı yap; stacked tag'i gözlenebilir ama ilk kapsam dışı durum olarak işaretle.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/infrastructure/parsers/vlan.py`, `src/netsentinel/domain/vlan.py`, `tests/unit/infrastructure/parsers/test_vlan.py`, `tests/fixtures/packets/`.
- **Bağımlılıklar:** NS-020.
- **Acceptance criteria:** Geçerli VID 0/normal/4095 semantiği doğru sınıflanır; untagged paket false tag üretmez; malformed/stacked trafik güvenli ele alınır; NIC offload sınırlaması belgelenir.
- **Test yöntemi:** Sentetik 802.1Q, priority-tagged, reserved VID, untagged, QinQ ve malformed fixture testleri.

### NS-044 — VLAN observation baseline ve özetler

- **Durum:** ✅ Tamamlandı (2026-09-26)
- **Amaç:** Network context/interface için görülen VLAN kimliklerinin bounded özetini ve öğrenme durumunu tutmak.
- **Yapılacaklar:** VLAN baseline modeli/service/repository, first/last seen, count ve warm-up ekle; raw frame yerine aggregate sakla.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/services/vlan.py`, `src/netsentinel/application/services/baselines.py`, `src/netsentinel/infrastructure/sqlite/schema/*.sql`, `tests/unit/application/test_vlan_baseline.py`.
- **Bağımlılıklar:** NS-025, NS-043.
- **Acceptance criteria:** Context/interface'ler karışmaz; aggregate bounded'dır; baseline tek gözlemle verified olmaz; restart sonrası özet devam eder; untagged count açıkça ayrıdır.
- **Test yöntemi:** Fake context/clock ile warm-up, repeated tag, multiple VLAN, context switch ve DB round-trip testleri.

### NS-045 — Şüpheli VLAN davranışı detector'ı

- **Durum:** ✅ Tamamlandı (2026-09-27)
- **Amaç:** Yeni/beklenmeyen VLAN, cihaz için tag değişimi ve kısa sürede olağandışı VLAN çeşitliliğini raporlamak.
- **Yapılacaklar:** Rule'lar, minimum sample, confidence ve dedup fingerprint ekle; capture/offload belirsizliğini confidence'a yansıt.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/detectors/vlan_anomaly.py`, `src/netsentinel/domain/alerts.py`, `tests/unit/application/detectors/test_vlan_anomaly.py`.
- **Bağımlılıklar:** NS-028, NS-044.
- **Acceptance criteria:** Verified baseline dışı tag event üretir; warm-up doğrudan yüksek severity üretmez; çeşitlilik penceresi bounded'dır; evidence VID/context/interface ve sınırlama bilgisini taşır.
- **Test yöntemi:** Stable VLAN, new tag, device tag switch, burst diversity, offload-unknown ve context switch testleri.

### NS-046 — VLAN görünümü, persistence ve M9 entegrasyonu

- **Durum:** ✅ Tamamlandı (2026-09-27)
- **Amaç:** VLAN özetlerini ve ilişkili alert'leri UI'da göstermek, parser-to-alert akışını doğrulamak.
- **Yapılacaklar:** Dashboard/diagnostics VLAN bölümü, filtreli özet read model'i ve sentetik packet pipeline testi ekle; ayrı büyük ekran yerine mevcut görünümlere entegre et.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/presentation/models/vlan.py`, `src/netsentinel/presentation/views/dashboard.py`, `src/netsentinel/presentation/views/alerts.py`, `tests/integration/test_vlan_pipeline.py`.
- **Bağımlılıklar:** NS-009, NS-043–NS-045.
- **Acceptance criteria:** Görülen VID/count/first-last seen görüntülenir; alert kanıta gider; untagged ile capture'da tag görünmemesi karıştırılmaz; sentetik yeni VLAN beklenen alert'i üretir.
- **Test yöntemi:** Fake baseline GUI testi ve tagged fixture'dan alert persistence'a uçtan uca test.

---

## M10 — Packaging, Hardening & Test

### NS-047 — Merkezi config, logging ve diagnostics

- **Durum:** ✅ Tamamlandı (2026-09-27)
- **Amaç:** Tüm modüllerin ayar, sağlık ve güvenli log davranışını tek bir sözleşmede toplamak.
- **Yapılacaklar:** Typed config yükleme/validasyon, güvenli varsayılanlar, rotating structured log, redaction ve diagnostics snapshot ekle; bozuk config fallback'ini tanımla.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/shared/config.py`, `src/netsentinel/shared/logging.py`, `src/netsentinel/shared/diagnostics.py`, `src/netsentinel/bootstrap.py`, `tests/unit/shared/`.
- **Bağımlılıklar:** NS-006, NS-020, NS-028.
- **Acceptance criteria:** Geçersiz ayar alan bazlı hata verir; secret/payload loglanmaz; log rotasyonu bounded'dır; diagnostics worker/queue/capability/DB durumunu içerir; varsayılanlar SECURITY.md ile uyumludur.
- **Test yöntemi:** Config property/boundary testleri, log capture redaction/rotation testleri ve fake component diagnostics testi.

### NS-048 — Permission/capability onboarding ve degraded mode

- **Durum:** ✅ Tamamlandı (2026-09-27)
- **Amaç:** Yönetici yetkisi, capture driver ve interface durumunu kullanıcıya açıkça gösterip desteklenen özelliklerle çalışmaya devam etmek.
- **Yapılacaklar:** Capability matrix, startup checks, first-run/onboarding UI ve yeniden dene akışı ekle; elevation talebini otomatik olmayan yönlendirme olarak tasarla.
- **Etkilenecek muhtemel dosyalar:** `src/netsentinel/application/services/capabilities.py`, `src/netsentinel/presentation/views/diagnostics.py`, `src/netsentinel/presentation/widgets/onboarding.py`, `tests/gui/test_capabilities.py`.
- **Bağımlılıklar:** NS-020, NS-024, NS-034, NS-047.
- **Acceptance criteria:** Driver yok/yetki yok/interface yok ayrılır; core connection monitor mümkünse çalışır; UI sessizce elevation yapmaz; retry state'i yeniler; her özellik için available/degraded/unavailable nedeni vardır.
- **Test yöntemi:** Fake capability provider ile tüm matrix kombinasyonları ve Windows'ta admin/non-admin opt-in smoke testi.

### NS-049 — Performans, backpressure ve dayanıklılık paketi

- **Durum:** ✅ Tamamlandı (2026-09-27)
- **Amaç:** Uzun çalışma ve trafik burst'lerinde CPU/bellek/queue davranışının sınırlarını doğrulamak.
- **Yapılacaklar:** Connection churn, packet burst, slow DB, UI burst, malformed input ve shutdown senaryoları ekle; ölçüm bütçelerini belgele; leak/tracemalloc kontrolü kur.
- **Etkilenecek muhtemel dosyalar:** `tests/performance/`, `tests/integration/test_resilience.py`, `docs/ARCHITECTURE.md`, `pyproject.toml`.
- **Bağımlılıklar:** NS-018, NS-029, NS-034, NS-038, NS-046.
- **Acceptance criteria:** Tüm queue'lar konfigüre limite uyar; overload health metriği üretir; shutdown timeout bütçesinde kalır; uzun sentetik çalışmada kontrolsüz büyüme gözlenmez; bütçeler CI/local ayrımıyla belgelenir.
- **Test yöntemi:** İşaretlenmiş deterministic load testleri, tracemalloc örneklemesi ve failure-injection entegrasyon testleri.

### NS-050 — Windows paketleme ve temiz ortam doğrulaması

- **Durum:** ✅ Tamamlandı (2026-09-28). SHA-256 doğrulanmış artefact, Npcap bulunmayan temiz Windows VM'de ilk/ikinci açılış ve degraded-mode kabul testini geçti.
- **Amaç:** NetSentinel'i belgeli bağımlılık ve lisanslarla Windows masaüstü artefact'ı olarak üretmek.
- **Yapılacaklar:** Paketleyici config'i, uygulama metadata/icon, data path, version bilgisi, dependency/license inventory ve temiz VM kurulum/kaldırma prosedürü ekle; Npcap'i otomatik gömmeme kararını uygula.
- **Etkilenecek muhtemel dosyalar:** `packaging/`, `pyproject.toml`, `src/netsentinel/version.py`, `README.md`, `docs/SECURITY.md`.
- **Bağımlılıklar:** NS-047–NS-049.
- **Acceptance criteria:** Artefact temiz Windows ortamında açılır; kullanıcı verisi install dizinine yazılmaz; eksik capture driver degraded onboarding gösterir; lisans envanteri üretilir; uninstall kullanıcı verisi kararını açıklar.
- **Test yöntemi:** Temiz Windows VM smoke checklist, checksum doğrulama ve paket içeriği incelemesi.

### NS-051 — CI kalite kapıları ve release checklist

- **Durum:** ✅ Tamamlandı (2026-09-28). PR #1'de Windows 2022/2025 offline test ve coverage işleri ile lint/type/dependency audit işi geçti.
- **Amaç:** Projenin test, stil, tip, güvenlik ve release doğrulamasını tekrarlanabilir hale getirmek.
- **Yapılacaklar:** Windows CI matrix, unit/integration/offscreen GUI testleri, lint/type check, dependency audit, coverage tabanı ve release checklist ekle; live/lab testleri CI'dan ayır.
- **Etkilenecek muhtemel dosyalar:** `.github/workflows/ci.yml`, `pyproject.toml`, `docs/RELEASING.md`, `README.md`, `docs/ROADMAP.md`.
- **Bağımlılıklar:** NS-001–NS-050.
- **Acceptance criteria:** PR kalite kapıları deterministik çalışır; live capture testi varsayılan CI'da yoktur; release checklist güvenlik/permission/migration/packaging kontrollerini kapsar; 1.0 kapsamı belgelerle eşleşir.
- **Test yöntemi:** CI'ı temiz branch'te çalıştırma, bilinçli failing test/lint ile gate doğrulama ve dry-run release checklist.

---

## Task özeti

| Milestone | Task aralığı | Task sayısı |
|---|---:|---:|
| M1 Core Connection Monitor | NS-001–NS-007 | 7 |
| M2 PyQt6 GUI | NS-008–NS-013 | 6 |
| M3 Persistence | NS-014–NS-018 | 5 |
| M4 LAN Device Monitor | NS-019–NS-024 | 6 |
| M5 MITM Detection & Alerts | NS-025–NS-029 | 5 |
| M6 DNS Monitoring | NS-030–NS-034 | 5 |
| M7 Broadcast Monitoring | NS-035–NS-038 | 4 |
| M8 Device Security | NS-039–NS-042 | 4 |
| M9 VLAN Monitoring | NS-043–NS-046 | 4 |
| M10 Packaging, Hardening & Test | NS-047–NS-051 | 5 |
| **Toplam** | **NS-001–NS-051** | **51** |

## Yeni faz taskları — M11–M12 tamamlandı, M13–M17 planlandı, M18 conditional

NS-001–NS-051 kayıtları ve yukarıdaki tarihsel özet değiştirilmez. Yeni taskların hepsi başlangıçta ⬜ Planlandı durumundadır. Bütün yeni işlerde domain framework bağımsız, application ports/adapters ayrımı korunur; queue/state/storage bounded, persisted zaman UTC-aware, runtime rolling window monotonic, SQL parameterized, GUI thread blocking I/O içermez. Davranış testleri default offline/deterministic; gerçek Windows/capture/admin testleri yalnız explicit marker ve yetkili ortamla çalışır. Yeni migration 009 sonrasına append-only eklenir.

## M11 — Process & Connection Telemetry Foundations

### NS-052 — Executable path ve alan bazlı availability

- **Durum:** ✅ Tamamlandı.
- **Amaç:** Bağlantıyı yapan executable'ı best-effort tanımlamak.
- **Yapılacaklar:** ProcessInfo, resolver portu ve psutil adapter'ına optional executable path ile alan bazlı availability ekle; mevcut ProcessIdentity key'ini koru.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/connections.py, src/netsentinel/application/ports.py, src/netsentinel/application/services/processes.py, src/netsentinel/infrastructure/psutil_processes.py, tests/unit/.
- **Bağımlılıklar:** NS-004.
- **Acceptance criteria:** Path reddi name/create-time bilgisini kaybettirmez; key değişmez; path bounded/validated; raw exception sızmaz.
- **Test yöntemi:** Fake process success, access denied, exit race, empty/invalid path ve mevcut resolver regression testleri.
- **Kapsam dışı:** DB, UI, parent, hash, signer, ETW.

### NS-053 — Best-effort parent metadata

- **Durum:** ✅ Tamamlandı.
- **Amaç:** Connection process'inin elde edilebilen parent context'ini sağlamak.
- **Yapılacaklar:** Parent PID, optional parent instance/name, observed-at ve availability durumlarını typed resolver sonucuna ekle; PID reuse ve kapanmış parent için conservative sonuç ver.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/connections.py, src/netsentinel/application/ports.py, src/netsentinel/infrastructure/psutil_processes.py, tests/unit/.
- **Bağımlılıklar:** NS-052.
- **Acceptance criteria:** Parent bulunamadı/reused/denied açık ayrılır; tam tarihsel lineage iddiası yok; lookup bounded.
- **Test yöntemi:** Fake parent exit, PID reuse, denied ve mismatched identity testleri.
- **Kapsam dışı:** Process creation event'leri, sınırsız ancestry.

### NS-054 — Process metadata persistence

- **Durum:** ✅ Tamamlandı (2026-09-30).
- **Amaç:** Process context'ini geçmiş kayıtlarında güvenle korumak.
- **Yapılacaklar:** Connection history mapping'ini veya küçük metadata snapshot'ını additive migration ile genişlet; eski kayıtları okunur bırak.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/connections.py, src/netsentinel/infrastructure/sqlite/, src/netsentinel/application/services/history.py, tests/integration/sqlite/.
- **Bağımlılıklar:** NS-052, NS-053.
- **Acceptance criteria:** Legacy kayıt okunur; path/parent/availability round-trip geçer; yeni metadata eski gözlemi yanlış göstermez; 001–009 değişmez.
- **Test yöntemi:** Fresh DB, 009→new upgrade, null/corrupt/legacy ve idempotency testleri.
- **Kapsam dışı:** Genel process inventory veya event store.

### NS-055 — Process context detail UI

- **Durum:** ✅ Tamamlandı.
- **Amaç:** Path, parent ve eksik alanların nedenini kullanıcıya göstermek.
- **Yapılacaklar:** Connections/History detail read model ve worker query sınırını genişlet; plain-text rendering uygula.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/presentation/, src/netsentinel/application/services/history_query.py, tests/gui/.
- **Bağımlılıklar:** NS-054.
- **Acceptance criteria:** Identity/selection stabil; unavailable açık; GUI thread DB/file I/O yapmaz; path dış servise gönderilmez.
- **Test yöntemi:** Offscreen full/partial/denied/history ve selection testleri.
- **Kapsam dışı:** Risk, reputation veya signer UI.

### NS-056 — Typed observation identity ve quality

- **Durum:** ✅ Tamamlandı.
- **Amaç:** Baseline/incident için örnekleme olaylarının anlamını korumak.
- **Yapılacaklar:** Session/lifecycle reference, initial snapshot, incomplete/gap/quality sözleşmesi ve bounded round state'i tracker/engine/typed events'e ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/connections.py, src/netsentinel/application/services/connections.py, src/netsentinel/application/engine.py, src/netsentinel/application/events.py, src/netsentinel/shared/diagnostics.py, tests/unit/.
- **Bağımlılıklar:** NS-052.
- **Acceptance criteria:** İlk snapshot gerçek connect sayılmaz; capacity loss görünür; eksik round sahte close üretmez; PID reuse korunur.
- **Test yöntemi:** Duplicate, metadata upgrade, overflow, collector failure, gap ve fake-clock testleri.
- **Kapsam dışı:** Durable bütün-event journal veya ETW replacement.

### NS-057 — Connection network scope

- **Durum:** ✅ Tamamlandı.
- **Amaç:** Connection'ın ait olduğu network context'i ancak yeterli kanıtla belirtmek.
- **Yapılacaklar:** Local endpoint/current context eşleştirmesi ve typed unique/unknown/ambiguous scope ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/connections.py, src/netsentinel/application/services/, src/netsentinel/infrastructure/windows_network.py, tests/unit/.
- **Bağımlılıklar:** NS-056.
- **Acceptance criteria:** Unique match ayrılır; wildcard, IPv6, VPN ve multiple-match sahte fingerprint üretmez; fiziksel ağ kesinliği iddia edilmez.
- **Test yöntemi:** Multi-interface, same-subnet, wildcard, loopback ve context-switch fixtures.
- **Kapsam dışı:** Kesin route tracing veya legacy fingerprint rewrite.

### NS-058 — History freshness ve restart gaps

- **Durum:** ✅ Tamamlandı.
- **Amaç:** Uzun yaşayan bağlantının güncelliğini ve gözlem boşluğunu doğru anlatmak.
- **Yapılacaklar:** Coalesced last-seen checkpoint, monitoring-session gap ve startup reconciliation'ı history worker/repository/read model'e ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/services/history.py, src/netsentinel/infrastructure/sqlite/, src/netsentinel/presentation/views/history.py, src/netsentinel/shared/diagnostics.py, tests/integration/.
- **Bağımlılıklar:** NS-054, NS-056, NS-057.
- **Acceptance criteria:** Unchanged connection last-seen bounded write hızıyla güncellenir; eski açık kayıt gap olarak açıklanır; gerçek close zamanı uydurulmaz.
- **Test yöntemi:** Restart/crash gap, long-lived connection, slow DB ve checkpoint coalescing testleri.
- **Kapsam dışı:** Her poll'u kalıcı journal'a yazmak; FIN/RST garantisi.

### NS-059 — Per-flow byte telemetry spike

- **Durum:** ✅ Tamamlandı.
- **Amaç:** TCP/UDP flow-byte ölçümünün privilege, doğruluk ve maliyetini karara bağlamak.
- **Yapılacaklar:** TCP EStats, ETW ve WFP seçeneklerini kontrollü PoC/matrisle değerlendir; ölçüm anlamını ve GO/NO-GO kararını belgele.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/infrastructure/ research harness, tests/fixtures/, docs/ARCHITECTURE.md, docs/SECURITY.md.
- **Bağımlılıklar:** NS-003.
- **Acceptance criteria:** TCP/UDP, IPv4/IPv6, loopback, late attach, loss/retransmission, overhead ve shutdown ölçülür; limitations ve explicit decision vardır. A documented NO-GO is a valid successful spike outcome.
- **Test yöntemi:** Offline decoder fixtures; yalnız explicit Windows standard/admin kontrollü testler.
- **Kapsam dışı:** Production collector, Connections byte UI veya driver kurulumu; olumlu sonuç otomatik production taskı değildir.

### NS-060 — DNS-process attribution spike

- **Durum:** ✅ Tamamlandı.
- **Amaç:** DNS event PID'sinin caller/process ilişkisindeki gerçek anlamını ölçmek.
- **Yapılacaklar:** Windows provider/schema, cache hit, resolver service, custom resolver ve DoH/DoT kapsamını araştır; typed unknown sınırı öner.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/infrastructure/ research harness, tests/fixtures/, docs/ARCHITECTURE.md, docs/SECURITY.md.
- **Bağımlılıklar:** NS-030–NS-034.
- **Acceptance criteria:** Kontrollü ölçüm, PID semantiği, eksikler ve explicit decision belgelenir; desteklenmeyen ilişki unknown kalır. A documented NO-GO is a valid successful spike outcome.
- **Test yöntemi:** Fake/recorded metadata fixtures ve explicit Windows doğrulama.
- **Kapsam dışı:** Kesin DNS→connection sebebi veya production ETW; olumlu sonuç otomatik production taskı değildir.

### NS-061 — Process/connection event-source spike

- **Durum:** ✅ Tamamlandı (2026-10-01; [NO-GO araştırma kararı](research/NS-061-process-connection-event-sources.md)).
- **Amaç:** Polling dışı lifecycle kaynağının maliyet ve doğruluğunu belirlemek.
- **Yapılacaklar:** Process ETW start/end/rundown ile network event schema/permission/loss/session ownership incele; production boundary kararı üret.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/infrastructure/ research harness, src/netsentinel/domain/ contract proposal, tests/fixtures/, docs/ARCHITECTURE.md.
- **Bağımlılıklar:** NS-056.
- **Acceptance criteria:** Provider/version/privilege, PID reuse, loss/recovery, startup rundown ve session ownership ölçülür; limitations ve explicit decision vardır. A documented NO-GO is a valid successful spike outcome.
- **Test yöntemi:** Offline event sequences; explicit bounded Windows testleri.
- **Kapsam dışı:** Service, command-line collection veya production event collector; olumlu sonuç otomatik production taskı değildir.

## M12 — Local Destination Context & Attribution

### NS-062 — Bounded DNS association service

- **Durum:** ✅ Tamamlandı (2026-10-01).
- **Amaç:** Domain/IP ilişkisini connection'a belirsizliği koruyarak bağlamak.
- **Yapılacaklar:** Many-to-many TTL associations, source/time/network/client evidence ve bounded state için application service/port tanımla.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/, src/netsentinel/application/services/, src/netsentinel/application/ports.py, tests/unit/.
- **Bağımlılıklar:** NS-056, NS-057.
- **Acceptance criteria:** Aynı IP'nin birden fazla domain adayı korunur; directly observed DNS ile correlated/ambiguous/unknown ayrılır; bounds/expiry vardır.
- **Test yöntemi:** CDN/shared-IP, CNAME, TTL=0, stale, multiple clients ve loss testleri.
- **Kapsam dışı:** Kesin process-domain attribution veya PTR causality.

### NS-063 — Association persistence ve canonical DNS IDs

- **Durum:** ✅ Tamamlandı (2026-10-01).
- **Amaç:** Association reference'larını restart sonrası izlenebilir tutmak.
- **Yapılacaklar:** DNS result ID'sini origin'den writer/consumer'a taşı; bounded SQLite repository ve retention/ref semantics ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/services/dns.py, src/netsentinel/application/services/dns_history.py, src/netsentinel/infrastructure/sqlite/, src/netsentinel/bootstrap.py, tests/integration/.
- **Bağımlılıklar:** NS-058, NS-062.
- **Acceptance criteria:** Aynı result bütün tüketicilerde aynı ID; idempotent writes, restart ve legacy/expired source açıklaması.
- **Test yöntemi:** DNS→association→DB, restart, duplicate, expiry ve migration testleri.
- **Kapsam dışı:** Genel packet/event store.

### NS-064 — Destination context UI

- **Durum:** ✅ Tamamlandı (2026-10-01).
- **Amaç:** Belirsiz domain association'ı kullanıcıya açıklamak.
- **Yapılacaklar:** Connections/History detail'e candidate/source/TTL/age ve local enrichment read model'i ekle; worker sorgusu kullan.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/presentation/, src/netsentinel/application/services/history_query.py, tests/gui/.
- **Bağımlılıklar:** NS-055, NS-063, NS-065.
- **Acceptance criteria:** Multiple candidates ve unknown görünür; DNS observation connection hostname'i gibi kesin sunulmaz; GUI bloke olmaz.
- **Test yöntemi:** Offscreen ambiguous/stale/no-data/selection testleri.
- **Kapsam dışı:** Kesin hostname ya da cloud lookup.

### NS-065 — Local ASN/country enrichment

- **Durum:** ✅ Tamamlandı.
- **Amaç:** Cloud kullanmadan destination hakkında ek context vermek.
- **Yapılacaklar:** Source/version/lisans bilgili local dataset port/adapter ve bounded cache tanımla; public/private/unknown ayrımı yap.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/, src/netsentinel/application/ports.py, src/netsentinel/infrastructure/, src/netsentinel/shared/diagnostics.py, tests/unit/.
- **Bağımlılıklar:** NS-057.
- **Acceptance criteria:** IPv4/IPv6 prefix lookup versioned ve bounded; country yalnız context; local/private unknown; lisans kararı kayıtlı.
- **Test yöntemi:** Synthetic prefix dataset, malformed/version mismatch, overlap ve offline testleri.
- **Kapsam dışı:** Otomatik dataset download veya ülkeye göre maliciousness.

### NS-066 — Bounded executable hashing

- **Durum:** ✅ COMPLETE.
- **Amaç:** Dosya kimliğini local/on-demand zenginleştirmek.
- **Yapılacaklar:** Ayrı worker/port, SHA-256 ve file-identity keyed cache ekle; path race/UNC policy uygula.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/ports.py, src/netsentinel/application/services/, src/netsentinel/infrastructure/, src/netsentinel/shared/diagnostics.py, tests/unit/.
- **Bağımlılıklar:** NS-052, NS-056.
- **Acceptance criteria:** Polling/GUI bloke olmaz; değişen dosya cache'i geçersiz kılar; size/time/queue bounded; UNC varsayılan kapsam dışı.
- **Test yöntemi:** Temporary files, mutation, denied, duplicate job ve cancellation testleri.
- **Kapsam dışı:** File upload, loaded memory doğrulaması veya bütün executable'ları tarama.

### NS-067 — Offline Authenticode spike

- **Durum:** ✅ Tamamlandı — [GO kararı, sınırlamalar ve doğrulama](research/NS-067-offline-authenticode.md).
- **Amaç:** Signer lookup'ın offline ve izin davranışını belirlemek.
- **Yapılacaklar:** WinTrust/catalog/revocation/timestamp/caching/timeout matrix'i kontrollü Windows harness ile ölç.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/infrastructure/ research harness, tests/fixtures/, docs/SECURITY.md.
- **Bağımlılıklar:** NS-052.
- **Acceptance criteria:** Embedded/catalog/unsigned/unknown ve network retrieval kapatma doğrulanır; limitations ve explicit GO/NO-GO kararı kayıtlıdır.
- **Test yöntemi:** Fake API outcomes ve explicit Windows fixture binaries.
- **Kapsam dışı:** Production signer veya signed=trusted kuralı.

### NS-068 — Signer adapter — conditional

- **Durum:** ✅ COMPLETE (2026-10-02; NS-067 GO sonrası offline adapter ve detail UI).
- **Amaç:** Olumlu spike sonrası offline signer context sağlamak.
- **Yapılacaklar:** Yalnız NS-067 GO ile typed WinTrust adapter/worker/cache ve detail UI ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/infrastructure/, src/netsentinel/application/ports.py, src/netsentinel/presentation/, tests/unit/, tests/gui/.
- **Bağımlılıklar:** NS-066, NS-067 GO kararı.
- **Acceptance criteria:** Offline/network retrieval kapalı; unknown korunur; bounded cache/job; imza safety hükmü değildir. NO-GO halinde adapter uygulanmaz ve M12 exit bloke olmaz.
- **Test yöntemi:** Adapter fixtures, cancellation, partial status ve offline integration.
- **Kapsam dışı:** Online revocation veya cloud lookup; zorunlu milestone gate değil.

## M13 — Deterministic Behavioral Baseline

### NS-069 — Stable application identity policy

- **Durum:** ✅ COMPLETE (2026-10-02; typed path-known application scope, conservative unknown ve artifact revision policy).
- **Amaç:** Process instance'dan farklı cross-run baseline scope'u tanımlamak.
- **Yapılacaklar:** Canonical path-known application key, unknown/revision policy ve typed identity comparison oluştur.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/, src/netsentinel/application/services/, tests/unit/.
- **Bağımlılıklar:** NS-052, NS-056.
- **Acceptance criteria:** PID/name tek başına farklı executable'ları merge etmez; path unavailable conservative unknown; instance key değişmez.
- **Test yöntemi:** Same-name/different-path, restart, path denial ve revision testleri.
- **Kapsam dışı:** Global software inventory veya signer trust.

### NS-070 — Bounded behavior feature accumulator

- **Durum:** ✅ COMPLETE.
- **Amaç:** Process behavior için ölçüm kalitesine bağlı deterministic özet toplamak.
- **Yapılacaklar:** Destination IP/port, protocol, observed appearance frequency ve diversity için monotonic bucket/capacity accumulator ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/, src/netsentinel/application/services/, src/netsentinel/shared/diagnostics.py, tests/unit/.
- **Bağımlılıklar:** NS-056, NS-057, NS-069.
- **Acceptance criteria:** Scope/entity/feature hard caps; overflow other/unknown; initial snapshot/gap counts şişirmez; monitored-time denominator açıktır.
- **Test yöntemi:** Fake monotonic/UTC clocks, churn, burst, eviction, sleep/gap sequences.
- **Kapsam dışı:** ML, byte-derived features veya time-of-day alert.

### NS-071 — Baseline persistence/lifecycle

- **Durum:** ✅ Tamamlandı (2026-10-03). Summary/feature policy v1 ve append-only 014 migration; bounded cumulative learning, 20 sample + 600 monitored saniye warm-up, 30/90 gün stale/expiry, scoped reset ve coalesced worker checkpoint. Restart gap/monotonic reconstruction, corrupt/version/policy mismatch, retention/quota, startup/reset/write yarışları ve failure semantics offline testlerle doğrulandı.
- **Amaç:** Learning state'i restart sonrasında bounded korumak.
- **Yapılacaklar:** Versioned aggregate repository, warm-up/minimum samples, expiry/reset ve disk limitleri ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/, src/netsentinel/application/services/, src/netsentinel/infrastructure/sqlite/, tests/integration/sqlite/.
- **Bağımlılıklar:** NS-058, NS-070.
- **Acceptance criteria:** Restart gap'ten window uydurulmaz; corrupt/version mismatch typed; bounded storage; migration append-only.
- **Test yöntemi:** Restart/stale/corrupt version, retention ve clock-change tests.
- **Kapsam dışı:** Raw tüm event'leri kalıcı saklama.

### NS-072 — Novelty/rarity rules

- **Durum:** ✅ COMPLETE (2026-10-03). Saf scoped IP detector ve immutable typed evidence/policy v1; READY + minimum 20 sample/600 monitored saniye, rarity için 100 sample + en fazla 2 appearance/%1. Lifecycle, capacity/overflow/eviction, revision/network isolation, IPv4/IPv6, INITIAL/REDUCED/FAILED ve pre-mutation snapshot semantics offline testlerle doğrulandı; CDN/service attribution conservative. Engine/alert/risk/UI/persistence entegrasyonu yok.
- **Amaç:** İlk görülen/seyrek destination için açıklanabilir sinyal üretmek.
- **Yapılacaklar:** Typed evidence veren küçük detector'lar ve minimum sample/quality policy ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/detectors/, src/netsentinel/domain/alerts.py, tests/unit/application/detectors/.
- **Bağımlılıklar:** NS-071.
- **Acceptance criteria:** Yetersiz/evicted state yüksek risk sayılmaz; sample/baseline nedeni görünür; CDN değişimi conservative.
- **Test yöntemi:** Cold start, known/rare/new, eviction ve shared destination matrix.
- **Kapsam dışı:** Malware verdict veya genel risk score.

### NS-073 — Frequency/diversity rules

- **Durum:** ✅ Tamamlandı (2026-10-03). İki ayrı pure typed rule, versioned threshold/quality gate, bounded reference learner ve independent-window confirmation/monotonic cooldown tamamlandı; [policy ve doğrulama](FREQUENCY_DIVERSITY_POLICY.md).
- **Amaç:** Observed appearance rate ve destination diversity sapmasını açıklamak.
- **Yapılacaklar:** Confirmation, quality gate, bounded scope/cooldown ile iki ilgili detector kuralı ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/detectors/, src/netsentinel/domain/alerts.py, tests/unit/application/detectors/.
- **Bağımlılıklar:** NS-071.
- **Acceptance criteria:** Polling appearance gerçek connect sayısı gibi sunulmaz; minimum sample/confirmation ve measurement quality gerekir.
- **Test yöntemi:** Stable/burst/normal browser-updater/missing-round testleri.
- **Kapsam dışı:** Packet bytes veya bütün baseline detector'larını tek taska toplama.

### NS-074 — Periodicity evidence detector

- **Durum:** ✅ COMPLETE (2026-10-03). Pure typed interval/jitter detector ve bounded runtime appearance service, policy v1; monitoring gap/reduced/session reset, polling aliasing/resolution ve conservative missed-multiple semantics offline testlerle doğrulandı. Updater yalnız düşük güvenlik anlamlı context; [policy ve doğrulama](PERIODICITY_POLICY.md). Engine/UI/alert/risk/persistence entegrasyonu yok.
- **Amaç:** Düzenli observed connection appearances için interval/jitter kanıtı üretmek.
- **Yapılacaklar:** Minimum interval ve bounded sequence kullanan detector ekle; gap/reset davranışını tanımla.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/detectors/, src/netsentinel/domain/alerts.py, tests/unit/application/detectors/.
- **Bağımlılıklar:** NS-058, NS-070.
- **Acceptance criteria:** Monitoring gap state'i sıfırlar; updater örnekleri düşük güvenli; “beacon confirmed” hükmü yok.
- **Test yöntemi:** Fake clock periodic/jitter/random, aliasing ve missing sample testleri.
- **Kapsam dışı:** Payload/C2 tespiti veya uzun yaşayan socket'i tekrar connect sayma.

### NS-075 — Baseline detail ve reset UI

- **Durum:** ✅ COMPLETE (2026-10-03). Connections detayında worker-backed Behavior baseline sekmesi; exact application/revision/network scope, lifecycle/warm-up/coverage/quality ve bounded retained feature preview. Confirm/Cancel ve scoped durable reset completion, generation/coalescing, selection stability ve bounded shutdown offline testlerle doğrulandı; [uygulama ve kabul raporu](BASELINE_DETAIL_UI.md). M13 tamamlandı; M14/NS-076 başlatılmadı.
- **Amaç:** Öğrenme/coverage/features'i kullanıcıya göstermek ve reset sağlamak.
- **Yapılacaklar:** Worker-backed read model, scoped explicit reset command ve learning/ready/insufficient UI ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/presentation/, src/netsentinel/application/services/, tests/gui/.
- **Bağımlılıklar:** NS-071–NS-074.
- **Acceptance criteria:** Warm-up/quality/overflow görünür; reset yalnız seçili scope ve onayla; gözlem ve tercih karışmaz.
- **Test yöntemi:** Offscreen warm-up/ready/overflow/reset/Cancel testleri.
- **Kapsam dışı:** Risk score UI veya otomatik mark-normal.

## M14 — Explainable Risk & User Feedback

**Durum:** ✅ COMPLETE (2026-10-04; NS-076–NS-083). Çıkış kriterleri ve son
offline doğrulama [NS-083 kabul raporunda](RISK_EXPLANATION_UI.md) kayıtlıdır.
Önceki task durumlarındaki sonraki-task/milestone notları, o teslimat anının tarihsel kaydıdır.

### NS-076 — Generic risk evidence contract

- **Durum:** ✅ COMPLETE (2026-10-03). Contract v1, immutable typed process/application/IPv4/IPv6 evidence, explicit host/resolved/unknown/ambiguous scope, ayrı quality/confidence, 8 reference/32 flat contributor hard cap ve semantics-preserving legacy ARP adapter tamamlandı. Legacy dedup/persistence regression ve M13 contract temsilleri offline doğrulandı; [contract ve kabul raporu](GENERIC_RISK_EVIDENCE.md). SQLite 014 değişmedi; NS-077 başlatılmadı, M14 tamamlanmadı.
- **Amaç:** Process/IPv6/generic kaynaklar için bounded typed kanıt tanımlamak.
- **Yapılacaklar:** Legacy ARP adapter, source/quality/reference ve explicit host/network/unknown scope için additive modeller ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/alerts.py, src/netsentinel/domain/, src/netsentinel/application/ports.py, tests/unit/domain/.
- **Bağımlılıklar:** NS-056.
- **Acceptance criteria:** Legacy ARP evidence/fingerprint semantiği korunur; IPv6/unknown scope; bounded contributors/references; arbitrary details dump yok.
- **Test yöntemi:** Legacy/new validation, IPv6, scope, limits ve sensitive-field testleri.
- **Kapsam dışı:** Scoring weights, SQL veya TI adapter.

### NS-077 — Pure explainable scoring policy

- **Durum:** ✅ Tamamlandı (2026-10-03).
- **Amaç:** Deterministic contributor ve severity mapping oluşturmak.
- **Yapılacaklar:** Versioned pure domain policy; correlated facts, negative contributor ve quality rules tanımla.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/, tests/unit/domain/.
- **Bağımlılıklar:** NS-076.
- **Acceptance criteria:** Her assessment contributor'larıyla açıklanır; same fact çift sayılmaz; missing/stale unknown; trust güçlü kanıtı sınırsız silemez; score malware probability değildir.
- **Test yöntemi:** Table-driven monotonicity, caps, conflicting sources ve negative contributors.
- **Kapsam dışı:** I/O, UI, ML veya malware probability.

### NS-078 — Versioned assessment persistence

- **Durum:** ✅ Tamamlandı (2026-10-03). Stable logical identity, append-only revision ve minimum bounded snapshot; schema 015, retention-safe source states ve typed corruption/restart/legacy regression testleri tamamlandı. [Sözleşme ve doğrulama](RISK_ASSESSMENT_PERSISTENCE.md). NS-079 başlatılmadı.
- **Amaç:** Risk assessment'ı original gözlemden ayrı revision olarak tutmak.
- **Yapılacaklar:** Assessment/revision repository, minimum bounded evidence snapshot ve legacy read mapping ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/, src/netsentinel/application/ports.py, src/netsentinel/infrastructure/sqlite/, tests/integration/sqlite/.
- **Bağımlılıklar:** NS-058, NS-076.
- **Acceptance criteria:** Recalculation occurrence artırmaz/original observation time değiştirmez; eski revision overwrite edilmez; evidence source expiry açıklanır.
- **Test yöntemi:** Duplicate revision, expired source, migration, restart/corrupt data testleri.
- **Kapsam dışı:** İkinci alert repository veya lifecycle.

### NS-079 — Risk-to-AlertService integration

- **Durum:** ✅ Tamamlandı. M13 normalizer + bounded worker, NS-077→NS-078→AlertService orchestration, explicit reassessment ve commit sonrası typed notification intent uygulanmıştır. Schema 016 unresolved alert scope'u NULL ile taşır; 001–015 değişmez. Offline full suite, lifecycle/retry/legacy regression ve statik kontroller geçer; [rapor](RISK_ALERT_INTEGRATION.md). NS-080 başlatılmamıştır; M14 tamamlanmış değildir.
- **Amaç:** Baseline evidence'ı mevcut alert yaşam döngüsüne bağlamak.
- **Yapılacaklar:** Normalized candidate/assessment orchestration ve persisted sonrası notification intent event'i ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/services/alerts.py, src/netsentinel/application/events.py, src/netsentinel/bootstrap.py, tests/integration/.
- **Bağımlılıklar:** NS-072–NS-074, NS-077, NS-078.
- **Acceptance criteria:** Detector SQL yazmaz; stable fingerprint; ack/reopen/dedup korunur; typed failure; eligibility delivery proof değildir.
- **Test yöntemi:** Signal→assessment→AlertService→DB, duplicate/retry/legacy alert pipeline.
- **Kapsam dışı:** Desktop delivery veya response.

### NS-080 — Scoped preference/suppression storage

- **Durum:** ✅ COMPLETE (2026-10-04). Immutable typed selector/lifetime, explicit permanent, manual reason/origin, append-only CREATE/EDIT/REVOKE audit, optimistic concurrency ve bounded SQLite repository/service tamamlandı. Schema 016→017; 001–016 değişmedi. Legacy device trust ayrı; eligibility evaluation/runtime/GUI yok. [Contract ve kabul raporu](SCOPED_PREFERENCES.md). NS-081 başlatılmadı; M14 tamamlanmadı.
- **Amaç:** Kullanıcı tercihini gözlemden ayrı saklamak.
- **Yapılacaklar:** Application/destination/network/rule selector, expiry, reason, origin ve audit repository oluştur.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/, src/netsentinel/application/ports.py, src/netsentinel/infrastructure/sqlite/, tests/integration/sqlite/.
- **Bağımlılıklar:** NS-069, NS-076.
- **Acceptance criteria:** Dar selector'lar; permanent yalnız explicit tercih; legacy device trust ayrı; edit/revoke auditable; PID/name kalıcı key değil.
- **Test yöntemi:** Scope matching, migration, expiry ve malformed selector testleri.
- **Kapsam dışı:** GUI, automatic trust veya evaluation.

### NS-081 — Suppression evaluation integration

- **Durum:** ✅ COMPLETE (2026-10-04). Immutable bounded current-policy evaluation, NS-080 exact matcher/expiry/revoke reuse ve assessment commit sonrası NS-079 eligibility entegrasyonu tamamlandı. Evidence/score/severity korunur; partial/correlated support, deterministic primary explanation, typed fail-open ve lifecycle/cooldown regression testleri geçer. Schema 017; migration yok. [Contract ve kabul raporu](SUPPRESSION_EVALUATION.md). NS-082 başlatılmadı; M14 tamamlanmadı.
- **Amaç:** Risk/alert notification eligibility'yi kullanıcı policy'siyle değerlendirmek.
- **Yapılacaklar:** Application service policy evaluation ve assessment'ta suppression explanation ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/services/, src/netsentinel/domain/, tests/unit/application/.
- **Bağımlılıklar:** NS-079, NS-080.
- **Acceptance criteria:** Evidence silinmez; expiry/revoke etkili; notification suppression ile risk sonucu ayrı; bounded suppressed summary.
- **Test yöntemi:** Rule/app/destination/network, precedence, expiry ve cooldown testleri.
- **Kapsam dışı:** Device detector trust semantiğini değiştirme.

### NS-082 — Trust/mark-normal commands ve UI

- **Durum:** ✅ COMPLETE (2026-10-04). Connections → Behavior baseline içinde ayrı selected-behavior preference UI; immutable preview, explicit 24h/permanent lifetime, Save/Cancel/Revoke ve restart persistence tamamlandı. Stable application + exact rule, narrow default ve visible network scope; PID/name/provisional selector yok. Bounded worker/generation/selection epoch, optimistic revoke conflict ve opt-in atomic equivalent-definition dedup doğrulandı. Evidence/score/baseline/alert history korunur; future-only NS-081 suppression. SQLite 017, migration yok; [kararlar ve kabul raporu](MARK_NORMAL_UI.md). NS-083 başlatılmadı; M14 tamamlanmadı.
- **Amaç:** Dar davranış feedback'i için kullanıcı akışı sağlamak.
- **Yapılacaklar:** Preview/expiry/revoke ile scoped application/destination/behavior command ve offscreen UI ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/presentation/, src/netsentinel/application/services/, tests/gui/.
- **Bağımlılıklar:** NS-075, NS-081.
- **Acceptance criteria:** PID/name permanent key olmaz; seçili behavior scope açık; Cancel write yapmaz; restart persistence var.
- **Test yöntemi:** Offscreen save/cancel/revoke, permission ve restart tests.
- **Kapsam dışı:** Firewall veya global “everything normal”.

### NS-083 — Risk explanation UI

- **Durum:** ✅ COMPLETE (2026-10-04). Alerts ve Connections ortak worker-backed risk explanation read model/panel; exact alert-linked revision, canonical connection lifecycle latest read, contributors/exclusions, quality/confidence/freshness/source availability, policy/revision ve açık current-vs-runtime suppression context tamamlandı. Legacy ARP details korunur; skor review priority olarak açıklanır, unknown/stale safety sonucu değildir. Schema 017; migration yok. Offscreen mixed/legacy/unknown/stale/suppressed/revision, read-only ve lifecycle testleri geçti; [uygulama ve kabul raporu](RISK_EXPLANATION_UI.md). M14 tamamlandı; NS-084 başlatılmadı.
- **Amaç:** Assessment'ın nedenini ve preference etkisini göstermek.
- **Yapılacaklar:** Alerts/Connections detail read model'ine contributors, freshness, quality, version, revision ve suppression ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/presentation/views/alerts.py, src/netsentinel/presentation/views/connections.py, src/netsentinel/presentation/models/, tests/gui/.
- **Bağımlılıklar:** NS-055, NS-079, NS-081.
- **Acceptance criteria:** Skor tek başına/probability gibi gösterilmez; legacy ARP details korunur; unknown/stale açık.
- **Test yöntemi:** Offscreen mixed evidence, legacy, unknown, stale, suppressed ve revision tests.
- **Kapsam dışı:** Incident timeline veya cloud consent UI.

## M15 — Optional Threat Intelligence Evidence

### NS-084 — TI port ve consent policy

- **Durum:** ✅ COMPLETE (2026-10-04). Provider-independent IP/domain/SHA-256 query/result, pure default-deny consent policy, ayrı secret port ve Settings consent UI tamamlandı. Provider/data-type/manual trigger izolasyonu, private/local subject dışlaması, atomic JSON persistence, bozuk config fail-closed ve iki fake provider contract doğrulandı. Startup/selection/consent Save sıfır request; gerçek provider/HTTP yok. SQLite 017, migration yok. Full offline suite: 2465 passed, 7 deselected; [tasarım ve kabul raporu](THREAT_INTELLIGENCE_CONSENT.md). M15 devam ediyor; NS-085 başlatılmadı.
- **Amaç:** Provider-independent reputation query ve açık veri iznini tanımlamak.
- **Yapılacaklar:** IP/domain/SHA-256 subject, result, provider ve sent-data sözleşmesini; default-disabled config/consent UI'ı kur.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/, src/netsentinel/application/ports.py, src/netsentinel/shared/config.py, src/netsentinel/presentation/, tests/unit/.
- **Bağımlılıklar:** NS-076.
- **Acceptance criteria:** Temiz kurulumda sıfır request; provider/subject/data type açık; no-hit/error ayrı; private/local address varsayılan dışı; secret ayrı port.
- **Test yöntemi:** Consent matrix, no-request default, invalid subject ve fake two-provider contract testleri.
- **Kapsam dışı:** Gerçek HTTP veya toplu network history upload.

### NS-085 — Reputation cache ve freshness

- **Durum:** ✅ COMPLETE (2026-10-04). Provider/data-type/canonical subject/algorithm/result-contract-version keyed local SQLite cache, explicit fresh/stale/expired/corrupt/unsupported/unavailable/clock states, separate HIT/NO_HIT status ve ERROR skip policy tamamlandı. Lazy tek-row read; 1024 disk row, 4 KiB snapshot, 128-row chunk cleanup/purge, deterministic expired→stale→oldest-fresh eviction ve atomic newest-fetch/tie upsert doğrulandı. Schema 017→018; 001–017 değişmedi. Fake UTC boundary/restart/corruption/eviction/concurrency/purge ve NS-084 regressions: 220 passed; full offline suite 2547 passed, 7 deselected. [Contract ve kabul raporu](THREAT_INTELLIGENCE_CACHE.md). M15 devam ediyor; NS-086 başlatılmadı.
- **Amaç:** Reputation sonucunu local ve kaynak/güncellik sınırıyla tutmak.
- **Yapılacaklar:** Provider/subject/version keyed TTL/stale/negative cache, bounded repository ve purge ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/services/, src/netsentinel/infrastructure/sqlite/, src/netsentinel/shared/diagnostics.py, tests/integration/sqlite/.
- **Bağımlılıklar:** NS-084.
- **Acceptance criteria:** Bounded memory/disk; stale/no-hit/failure farklı; timeout temiz verdict sayılmaz; provider isolation ve purge var.
- **Test yöntemi:** Fake clock TTL/stale/restart/corrupt/eviction tests.
- **Kapsam dışı:** Provider networking veya aggregate malware vote.

### NS-086 — İlk provider adapter

- **Durum:** ✅ COMPLETE (2026-10-04). AbuseIPDB API v2 IP-only CHECK adapter, official terms/privacy/pricing review, fixed HTTPS/verified TLS/no redirect, 8 s timeout/64 KiB streaming cap ve normalized HIT/NO_HIT/429/error tamamlandı. Secret ayrı port/header-only, no retry/runtime composition. Typed minimum IP facts + rate hints; result/key ve cache codec v2, schema 018→018. Fake transport/fixtures/consent/cache/redaction: 378 passed; full offline suite 2726 passed, 8 deselected; live gating 1 skipped. Ruff/configured ve direct mypy/diff check temiz. [Provider kararı ve kabul raporu](THREAT_INTELLIGENCE_PROVIDER_ABUSEIPDB.md). NS-087 başlamadı; M15 devam ediyor.
- **Amaç:** Seçilen provider'ı typed reputation portuna bağlamak.
- **Yapılacaklar:** Terms/privacy review sonrası sabit endpoint, bounded HTTP ve normalized response adapter'ı ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/infrastructure/, src/netsentinel/application/ports.py, tests/unit/infrastructure/.
- **Bağımlılıklar:** NS-084 ve açık provider seçimi.
- **Acceptance criteria:** Timeout/body/redirect bounds, 429/error/no-hit ayrımı, redacted secrets; yalnız izin verilen subject gönderilir.
- **Test yöntemi:** Fake transport/response fixtures; live provider test default dışı.
- **Kapsam dışı:** Multiple production adapters veya file upload.

### NS-087 — Bounded lookup scheduler

- **Durum:** ✅ COMPLETE (2026-10-04). Memory-only explicit submit/shared pollable ticket; cache-first fixed 4-worker scheduler, 64 global/16 per-provider outstanding bounds ve 1 call/1 s local provider budget tamamlandı. Pending/in-flight dedup, 3-attempt bounded retry/1–30 s backoff/300 s Retry-After clamp, A/B isolation, explicit offline defer, consent snapshot/revoke cancellation ve 2 s toplam shutdown join doğrulandı. Startup/selection/engine/consent Save sıfır lookup; optional bootstrap/lifecycle/aggregate diagnostics, secret port injection ve default unavailable credential korunur. Schema 018→018, migration yok. Geniş targeted 533 passed; son scheduler 98 passed; full offline 2824 passed, 8 deselected; Ruff/configured ve direct mypy/diff temiz. [Scheduler sözleşmesi ve kabul raporu](THREAT_INTELLIGENCE_SCHEDULER.md). M15 devam ediyor; NS-088 başlatılmadı.
- **Amaç:** Opt-in network sorgularını monitoring/GUI'den ayırmak.
- **Yapılacaklar:** Dedup, concurrency, rate limit, bounded retry/backoff, offline ve consent revoke için application worker kur.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/services/, src/netsentinel/shared/diagnostics.py, src/netsentinel/bootstrap.py, tests/unit/application/.
- **Bağımlılıklar:** NS-085, NS-086.
- **Acceptance criteria:** Provider budget ve Retry-After; revoke pending jobs'u durdurur; engine/GUI beklemez; shutdown bounded.
- **Test yöntemi:** Fake clock/network, duplicate/storm/429/offline/shutdown testleri.
- **Kapsam dışı:** Tüm history'yi batch sorgulama.

### NS-088 — TI evidence ve assessment/UI integration

- **Durum:** ✅ COMPLETE (2026-10-04). Central TI→generic supporting evidence adapter, bounded typed provenance, v1-compatible assessment format 2 ve existing risk worker/AlertService reassessment tamamlandı. Numeric policy v1 değişmez; HIT malware ve NO_HIT safe hükmü değildir. Stale/refresh-error, independent providers, exact lifecycle/IP, count/time/ACK/RESOLVED/fingerprint invariants ve durable retry/restart doğrulandı. Connections explicit lookup, shared ticket/selection epoch ve NS-083 historical UI; default zero requests, credential unavailable/local continuation korunur. Schema 018→018, migration yok. Broad targeted 992 passed; final semantic core 102 passed; startup/GUI 81 passed; full offline 2899 passed, 8 deselected; Ruff/configured/direct mypy/diff temiz. [NS-088 kabul ve M15 exit raporu](THREAT_INTELLIGENCE_EVIDENCE.md). M15 ✅ COMPLETE; NS-089 başlatılmadı.
- **Amaç:** Reputation sonucunu yalnız destekleyici risk evidence yapmak.
- **Yapılacaklar:** Provider source/freshness bilgisini assessment revision ve detail UI'a bağla.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/services/, src/netsentinel/domain/, src/netsentinel/presentation/, tests/integration/, tests/gui/.
- **Bağımlılıklar:** NS-078, NS-083, NS-087.
- **Acceptance criteria:** Blacklist→malware yok; stale/no-hit açık; occurrence değişmez; provider unavailable local detection'ı durdurmaz.
- **Test yöntemi:** Fake TI→revision→GUI, conflicting/stale providers ve offline tests.
- **Kapsam dışı:** Automatic blocking veya provider verdict tek başına saldırı hükmü.

## M16 — Incident Correlation & Timeline

### NS-089 — Bounded incident correlator

- **Durum:** ✅ COMPLETE (2026-10-04). Immutable typed incident/reference/reason contract, synchronous locked memory correlator ve existing connection/evidence/assessment adapters tamamlandı. Canonical lifecycle/evidence/assessment/alert priority; tam process instance + destination port/protocol + resolved scope dışında weak merge yok. Central 10-minute UTC cohort/span, inclusive lateness, gap/quality, atomic capacity ve index cleanup; no process-created inference. 140 yeni test, dependency-targeted 493 passed ve full offline 3039 passed/8 deselected; Ruff/configured/direct mypy/diff temiz. Schema 018→018, migration/persistence/GUI yok. [Policy freeze](INCIDENT_CORRELATION.md), [103 maddelik kabul raporu](INCIDENT_CORRELATION_ACCEPTANCE.md). M16 devam ediyor; NS-090 başlatılmadı.
- **Amaç:** Observation/assessment/alert arasındaki ilişkiyi typed reason ile kurmak.
- **Yapılacaklar:** Process/lifecycle/destination identity, correlation window ve bounded relation graph service tanımla.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/, src/netsentinel/application/services/, src/netsentinel/application/events.py, tests/unit/.
- **Bağımlılıklar:** NS-056, NS-063, NS-076, NS-079.
- **Acceptance criteria:** Same IP farklı process'leri merge etmez; unknown conservative; bounded window/entities; process creation çıkarımı yok.
- **Test yöntemi:** PID reuse, shared IP, scope/gap, duplicate/out-of-order testleri.
- **Kapsam dışı:** Persistence veya forensic graph.

### NS-090 — Incident persistence/lifecycle

- **Durum:** ✅ COMPLETE (2026-10-04). Typed additive durable contract, IncidentRepository port, explicit blocking service ve worker-owned SQLite repository tamamlandı. Canonical seed/policy/cohort UUIDv5, independent OPEN/ACK/RESOLVED ve REOPENED action, idempotent bounded append, 5-minute inclusive UTC reopen horizon + NS-089 membership, atomic expected-revision commands ve immutable newest-32 revisions vardır. Retention-safe refs/source states, 1024 parent/320 refs bound, explicit resolved-only chunk cleanup ve conservative bounded restart matching doğrulandı. Schema 018→019 (`019_incidents.sql`), 001–018 değişmez. 151 yeni test; targeted 526 passed; full offline 3190 passed/8 deselected; Ruff/configured/direct mypy/diff temiz. [Persistence sözleşmesi](INCIDENT_PERSISTENCE.md), [125 maddelik kabul raporu](INCIDENT_PERSISTENCE_ACCEPTANCE.md). Alert lifecycle değişmez; GUI/timeline yok. M16 devam ediyor; NS-091/092 başlatılmadı.
- **Amaç:** Incident open/ack/resolved/reopen ve evidence append'i saklamak.
- **Yapılacaklar:** Typed repository, stable incident ID, horizon ve retention-safe reference ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/, src/netsentinel/application/ports.py, src/netsentinel/infrastructure/sqlite/, tests/integration/sqlite/.
- **Bağımlılıklar:** NS-078, NS-089.
- **Acceptance criteria:** Append idempotent; reopen horizon explicit; restart-safe; bounded evidence/revisions; expired source görünür.
- **Test yöntemi:** Restart, duplicate append, expiry/reopen, migration tests.
- **Kapsam dışı:** Alert lifecycle'ını incident ile birebir eşitleme.

### NS-091 — Incident timeline GUI

- **Durum:** ✅ COMPLETE (2026-10-05). Read-only Incidents navigation/list/detail/timeline, typed application query ve coherent worker-owned SQLite read adapter tamamlandı. Original observation, exact assessment, inference anchor ve lifecycle action time ayrıdır; deterministic total key + revision/source-state cursor mixed pages'i önler. Batch source states, retained context, expired/unresolved/corrupt/unsupported fallback, lazy NS-083 risk panel, 25/default–100/max page ve 256 loaded-row cap vardır. Process observed dili, generation/A→B→A/page cancellation, bounded shutdown ve read-only invariants doğrulandı. 129 yeni test; dependency-targeted 657 passed; full offline 3320 passed/8 deselected; final new-only 129 passed; Ruff/configured/direct mypy/diff temiz. Schema 019→019, migration yok. [Timeline sözleşmesi](INCIDENT_TIMELINE_UI.md), [113 maddelik kabul raporu](INCIDENT_TIMELINE_ACCEPTANCE.md). M16 devam ediyor; NS-092 başlatılmadı.
- **Amaç:** İlişkili olayları kaynak/zaman belirsizliğiyle okunur göstermek.
- **Yapılacaklar:** Paginated worker query, observation/assessment time ayrımı ve relation reason'lı timeline model/view ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/presentation/, src/netsentinel/application/services/, tests/gui/.
- **Bağımlılıklar:** NS-083, NS-090.
- **Acceptance criteria:** Deterministic ordering; unknown links ve expired reference açık; GUI DB/network bloklamaz; process creation yoksa “process observed” dili.
- **Test yöntemi:** Offscreen long timeline, equal timestamp, expired reference, cancellation tests.
- **Kapsam dışı:** Olmayan process creation event'i göstermek.

### NS-092 — Incident acceptance/soak

- **Durum:** ✅ COMPLETE (2026-10-05). Acceptance-only: actual polling/accumulator/baseline → risk worker/evidence/assessment/AlertService → explicit incident persistence → timeline/offscreen GUI hikâyesi doğrulandı. DNS ambiguity ayrı context kalır; yeni producer/detector/provider yoktur. Stable UUIDv5/restart/dedup, typed loss/source expiry/corruption, 10-minute fixed UTC bucket ve 5-minute inclusive reopen korunur. Soak 256 runtime/1024 durable parent, 128 relations/32 revisions, 16.383 index memberships, 256 GUI row ve 11 page/55 SELECT ölçtü; source/ref/snapshot/cleanup bounds geçti. 45 yeni test; story/GUI 36 passed; soak 9 passed ve critical repeat 14 passed; broad 2277 passed/8 deselected; full offline 3365 passed/8 deselected (306.73 s). Ruff/configured/direct mypy/diff temiz. Schema 019→019, migration veya production behavior change yoktur. [NS-092 raporu ve M16 exit matrisi](INCIDENT_ACCEPTANCE_SOAK.md). M16 ✅ COMPLETE; NS-093 başlatılmadı.
- **Amaç:** Incident zincirini bounded uçtan uca doğrulamak.
- **Yapılacaklar:** Sentetik connection+DNS+baseline+risk+optional fake TI story, restart/dedup/loss/retention acceptance ve resource budget ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** tests/integration/, tests/performance/, tests/gui/, docs/ARCHITECTURE.md.
- **Bağımlılıklar:** NS-091; NS-088 entegreyse onun fake evidence yolu.
- **Acceptance criteria:** Olay hikayesi ve limitation görünür; bounded CPU/memory/storage; no live attack traffic.
- **Test yöntemi:** Offline end-to-end, accelerated soak ve offscreen GUI.
- **Kapsam dışı:** Canlı C2/attack trafiği veya cloud provider önkoşulu.

## M17 — Public Beta & Product Usability

### NS-093 — Tray ve application lifecycle

- **Durum:** ✅ COMPLETE (2026-10-05). Qt tray adapter/controller, Show/Hide/Quit, File Quit ve typed persisted close preference mevcut lifecycle'a bağlandı. Visible startup ve opt-in HIDE_TO_TRAY; unavailable/init failure quit fallback, runtime tray loss visible recovery; hidden monitoring/alert/risk/incident continuity, tek actual stop ve bounded shutdown doğrulandı. Fatal startup/finally aynı idempotent guard'ı kullanır. 36 yeni test; targeted 198 passed, new-only 36 passed; full offline 3401 passed/8 deselected (235.24 s). Ruff/configured/direct lifecycle mypy/diff temiz. Schema 019→019, migration yok. [Frozen policy, lifecycle kabul matrisi ve Windows smoke checklist](TRAY_APPLICATION_LIFECYCLE.md). Native Windows manual smoke çalıştırılmadı; offscreen kanıt native shell acceptance değildir. M17 devam ediyor; NS-094 başlatılmadı.
- **Amaç:** Günlük background kullanımda görünür start/stop ve quit davranışı sağlamak.
- **Yapılacaklar:** PyQt tray, show/hide/quit ve close preference'ı mevcut lifecycle'a bağla.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/presentation/app.py, src/netsentinel/presentation/views/main_window.py, src/netsentinel/shared/config.py, tests/gui/.
- **Bağımlılıklar:** NS-055.
- **Acceptance criteria:** Hide monitoring'i yanlışlıkla durdurmaz; Quit bounded shutdown; tray unavailable fallback; startup policy explicit.
- **Test yöntemi:** Offscreen/fake tray lifecycle ve Windows manual smoke.
- **Kapsam dışı:** Windows service veya default autostart.

### NS-094 — Desktop notifications

- **Durum:** ✅ COMPLETE (2026-10-05). Commit sonrası portable intent/policy/service/sink, bounded Qt delivery ve exact-ID worker navigation tamamlandı. Default disabled/LIMITED preview; 120 s monotonic cooldown, severity escalation bypass, dedup/decrease/score-only/ACK/RESOLVED/reopen/suppression policy doğrulandı. Queue 32, subject state 512/session, immutable Qt click sources 8/600 s; failure/overflow typed ve aggregate diagnostics; startup/re-enable/restart backlog replay yoktur. Existing SQLite occurrence/revision watermark yeterli: schema 019→019, migration yok. 84 yeni test; dependency-targeted 225 passed, final new-only 84 passed; full offline 3543 passed/8 deselected (254.29 s). Ruff/configured mypy (34)/direct mypy (12)/diff temiz. [Frozen policy ve Windows smoke](DESKTOP_NOTIFICATIONS.md), [82 maddelik kabul/teslim raporu](DESKTOP_NOTIFICATIONS_ACCEPTANCE.md). Native Windows manual smoke çalıştırılmadı; temporary Qt icon/expiry ve OS display sınırları açık. M17 devam ediyor; NS-095 başlatılmadı.
- **Amaç:** Persisted alert intent'ini privacy-aware desktop bildirime çevirmek.
- **Yapılacaklar:** Delivery adapter/port, dedup/cooldown/hysteresis ve click navigation kur.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/services/, src/netsentinel/infrastructure/, src/netsentinel/presentation/, tests/gui/.
- **Bağımlılıklar:** NS-079, NS-081, NS-093.
- **Acceptance criteria:** Eligibility delivery proof sayılmaz; sensitive preview sınırlı; escalation/duplicate yönetilir; click doğru alert'i açar.
- **Test yöntemi:** Fake notification sink, restart/storm/failure ve offscreen navigation.
- **Kapsam dışı:** Raw payload/path'i varsayılan preview yapmak.

### NS-095 — Storage/privacy controls

- **Durum:** ✅ COMPLETE (2026-10-06). Typed central policy, opt-in deferred/hourly single maintenance worker, bounded cleanup/admission quotas, confirmed scoped purge ve allowlist support-export-v1 preview/atomic Save tamamlandı. 2s/16 chunks/2048 physical deletes, 100ms busy/setup timeout; current/reference/user data korunur, source-expiry snapshot/timeline restart-safe kalır. Profile/trust/preferences generic purge dışındadır; no upload/VACUUM/secure erase/encryption claim. 83 yeni test; dependency-targeted 487 passed, final changed-path targeted 221 passed; full offline 3626 passed/8 deselected (290.41 s). Ruff/configured mypy (35)/direct mypy (16)/diff temiz. Requested venv SQLite/ctypes DLL'leri Windows Application Control ile engellendi; aynı CPython 3.12.14 bundled runtime + mevcut repo venv packages ile doğrulandı. Schema 019→019, migration yok. [Store/policy matrisi](STORAGE_PRIVACY.md), [98 maddelik kabul/teslim raporu](STORAGE_PRIVACY_ACCEPTANCE.md). M17 devam ediyor; NS-096 başlatılmadı.
- **Amaç:** Yerel veri yaşam döngüsünü kullanıcı kontrolüne almak.
- **Yapılacaklar:** Bounded retention scheduling, store quota, scoped purge ve sanitized export preview ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/services/retention.py, src/netsentinel/infrastructure/sqlite/, src/netsentinel/shared/config.py, src/netsentinel/presentation/, tests/integration/.
- **Bağımlılıklar:** NS-071, NS-078, NS-090.
- **Acceptance criteria:** Chunk cleanup bounded; active/reference veri açıklanır; yeni store'lar quota taşır; destructive purge confirmed; export preview redacted.
- **Test yöntemi:** Time/size/busy DB, source expiry, Cancel ve restart tests.
- **Kapsam dışı:** Silent purge veya automatic upload.

### NS-096 — Installer/upgrade/uninstall

- **Durum:** ✅ COMPLETE (2026-10-06). Inno Setup 6.7.3 per-user/offline installer, ortak AppData path service, KEEP-default/confirmed DELETE helper, running/tray mutex coordination, payload inventory/checksum ve 001–019 packaging düzeltmesi tamamlandı. Native VM: standard-user/no-UAC, no-Python/no-Npcap, fresh install/data separation, repair, direct 0.1.0→0.1.1 installer-fixture upgrade/config-DB preservation/single HKCU entry, KEEP/DELETE/reinstall/Cancel ve Unicode install/launch/delete PASS. Mevcut VM'de yeni standart kullanıcı profilleri kullanıldı; pristine OS snapshot yoktu. Exact task pristine OS baseline'ını zorunlu tanımlamadığından temiz per-user profile lifecycle kabulü yeterlidir. Fixture app payload'ı 0.1.0 kaldı; app code-version upgrade iddiası yok. Host wizard App Control 4551 ile blocked, kabul VM'de yapıldı. Son targeted 121, installer-only 57; full offline 3683 passed/8 deselected (450.13 s); Ruff/configured mypy (36)/direct mypy (8)/diff PASS. Schema 019→019, migration yok; 001/008/018→019, current/future compatibility PASS. [Final kabul ve sınırlar](INSTALLER_ACCEPTANCE.md), [lifecycle policy](INSTALLER_UPGRADE_UNINSTALL.md), [native sonuçlar/checklist](INSTALLER_WINDOWS_SMOKE.md). M17 IN PROGRESS; NS-097 NOT STARTED.
- **Amaç:** Portable paketi kontrollü dağıtım akışına taşımak.
- **Yapılacaklar:** Installer build, data-path/preserve/delete kararı ve clean upgrade/uninstall kılavuzu ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** packaging/, docs/RELEASING.md, README.md, tests/integration/.
- **Bağımlılıklar:** NS-093, NS-095.
- **Acceptance criteria:** Standard-user policy; Unicode path, fresh/upgrade DB; Npcap/elevation otomatik yok; user data kararı açık.
- **Test yöntemi:** Clean Windows client VM install/repair/upgrade/uninstall smoke.
- **Kapsam dışı:** Npcap bundling, updater veya firewall cleanup henüz yok.

### NS-097 — Signing/update distribution spike

- **Durum:** ✅ COMPLETE (2026-10-06), research/security-design spike. Limited explicit unsigned pilot + canonical GitHub Releases/manual update conditional GO; broad distribution signer/licensing/kalan M17 gate olmadan NO-GO. 23 current official source; Artifact Signing eligibility/cost/HSM, conditional OV fallback, EV/self-signed/Store kararları, key ownership/CI approval/rotation/revocation, inner/Inno-generated/outer signing order, final-hash-after-signing, timestamp, network disclosure ve downgrade/rollback frozen. Küçük offline integrity/manifest/PE-version verifier signature trust iddia etmez; signed manifest ayrı Authenticode gate ister. Actual 0.1.0 hash/version PASS, NotSigned; copy-only one-byte tamper/wrong hash/version/missing/malformed fail-closed; canonical installer değişmedi. Public signed run yapılmadı; pilot alternative exact acceptance'ı karşılar. 47 yeni test; targeted 105 passed; full offline 3730 passed/8 deselected (279.94 s), Ruff/configured mypy (36)/direct mypy (2)/diff/secret scan PASS. Schema 019→019, migration/runtime network/updater/certificate purchase/release/tag yok. [Frozen policy ve sources](SIGNING_UPDATE_DISTRIBUTION.md), [dry-run ve 64-item teslim raporu](SIGNING_UPDATE_ACCEPTANCE.md). M17 IN PROGRESS; NS-098/099 NOT STARTED.
- **Amaç:** Beta artefact trust ve update politikasını karara bağlamak.
- **Yapılacaklar:** Certificate/key/cost/channel, manual update ve verification/downgrade/rollback matrisi üret.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** packaging/, docs/RELEASING.md, docs/SECURITY.md, tests/integration/.
- **Bağımlılıklar:** NS-050, NS-051.
- **Acceptance criteria:** Signed workflow veya açık pilot policy; key ownership ve network disclosure; explicit decision ve tamper sonucunun fail-closed olması.
- **Test yöntemi:** Artefact verification dry-run ve tamper fixtures.
- **Kapsam dışı:** Automatic updater implementation veya certificate satın alma.

### NS-098 — First-run/feedback polish

- **Durum:** ✅ COMPLETE (2026-10-06). Config'te version 1 completed/dismissed state, legacy nonmodal upgrade notice, altı informational page ve Help reopen/current settings eklendi. Finish/Skip capture/TI/notification izni vermez; Cancel/Back write yoktur. Diagnostics readable activity/capability ve expandable details; production credential unavailable açık. Help Feedback & Support aynı NS-095 worker/allowlist-v1/support-export-v1/100 records/64KiB/atomic cancel yolunu kullanır; full sanitized preview → local Save, zero auto upload. Dedicated feedback/security endpoint tanımlı değil; actual project page yalnız click ile/query-prefill olmadan açılır. Evidence limitations, 0.1.0 source/pilot notes, beş actual synthetic Qt screenshot ve operator usability walkthrough PASS. 51 yeni case; targeted 269 passed; full offline 3781 passed/8 deselected (332.50s); Ruff/configured mypy (36)/direct mypy (7)/diff/privacy review PASS. Approved bundled CPython + mevcut deps, security bypass yok. Schema 019→019, migration/new dependency/network/crash client/tag/release/installer rebuild yok. [Frozen policy ve UI artifacts](FIRST_RUN_FEEDBACK.md), [80-item acceptance](FIRST_RUN_FEEDBACK_ACCEPTANCE.md), [pilot notes](RELEASE_NOTES.md). M17 IN PROGRESS; NS-099 NOT STARTED. Native DPI/screen-reader/independent novice/client beta acceptance iddiası yoktur.
- **Amaç:** Yeni privacy/detection sınırlarını kullanıcıya anlatmak.
- **Yapılacaklar:** Onboarding, sanitized user-controlled feedback export, detection docs, screenshot/release-note hazırlığı.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/presentation/widgets/onboarding.py, src/netsentinel/presentation/views/diagnostics.py, docs/, README.md, tests/gui/.
- **Bağımlılıklar:** NS-083, NS-084, NS-091, NS-095.
- **Acceptance criteria:** Capture/TI ayrı consent; raw history default export yok; feedback preview; limitation açık; release docs tutarlı.
- **Test yöntemi:** Offscreen onboarding/consent states, redaction/export fixtures, usability walkthrough.
- **Kapsam dışı:** Automatic crash upload veya public issue'ya gerçek telemetry.

### NS-099 — Public beta acceptance gate

- **Durum:** ✅ COMPLETE (2026-10-08). Final required private WireGuard VPN native gate PASS: accepted8242868 runtime/current39b14fe8 unsigned candidate, fresh installed1119 hashes/0 mismatch, Limited-token Windows11 → existing Kali → VMware NAT. Real handshake/routed benign HTTPS/second honest scope/disconnect normal route+DNS/restart/persistence/cleanup PASS. Alerts/incidents0; notifications OFF/native intents0; bounded app errors0; healthy schema019→019,13 baselines retained. Native host S3 PASS, notification-policy/native ON fixture PASS, human UX8/8/layout CLOSED and prior browser/updater/install/upgrade/uninstall/Npcap-missing/standard-user/privacy/tray candidate scopes retained. Exact acceptance criteria unchanged; optional/other-build/native visibility limitations remain explicit. Frozen runtime quality123 targeted/3833 offline/8 deselected/Ruff/configured mypy36/direct6 retained; this closure docs-only, no production/rebuild/migration. M17 COMPLETE; limited unsigned pilot CONDITIONAL_GO under NS-097 owner/distribution gates; broad NO_GO (unsigned/signing gates); M18 GO FOR PLANNING ONLY, explicit response implementation GO absent, NS-100 NOT STARTED; tag/release NONE. [VPN evidence/exit decision](NS099_VPN_WIREGUARD_CLOSURE.md).
- **Historical notification-policy status:** 🔄 IN PROGRESS / INCOMPLETE (2026-10-07). Notification-policy closure PASS: dar5 runtime dosya fix `8242868ba79c63ad743c005366ea715b238cf5d0` normal main commit/push; temiz committed runtime'dan unsigned0.1.0 installer rebuilt, SHA256`39b14fe844c8aaa150a8b09229e0d63aaaf5ecc98b5bc8c54b419140be7749d9`, 37,559,481 bayt, AppId/schema019→019 unchanged. Windows11 Limited-token install exit0,1119 hash/0 mismatch;194 compiled module source-match. Aynı Session1 gerçek global Notifications OFF/ON doğrulandı; Qt submission görünür delivery değildir, runtime honest UNKNOWN/null. Native privacy popup/gerçek click exact UUID/duplicate/restart replay0 PASS;7 sentetik alert,6 adapter attempt/accepted,6 duplicate suppression,2 doğrudan gözlenen ON popup;2 exploratory ON visibility NOT MEASURED. OS eski ON ve DND OFF korunmuş, probe/task/credential0. Human UX8 PASS/0 FAIL ve layout CLOSED eski evaluator scope'ta korunur. Safe VPN BLOCKED/NOT RUN; final prepared native host S3 recovery PASS (default optional features OFF); önceki42min benign alert/incident0 ve tray Quit yalnız özgün aday kapsamındadır. Exact acceptance tamamlanmadığı için limited pilot NO_GO, broad public NO_GO, M17 IN PROGRESS, M18 DEFER. Targeted123, full offline3833/8deselected/91.09%, Ruff/configured mypy36/direct6/diff/privacy; [policy/native limitations](NS099_NOTIFICATION_POLICY_CLOSURE.md), [report](PUBLIC_BETA_REPORT.md). Acceptance kriterleri aynen korunur; migration/dependency/packaging/network change, tag/release/NS-100 yok.
- **VPN environment attempt (2026-10-07):** NOT RUN; host Application Control hash-verified portable local server launch engelledi. VPN workload/counts NOT MEASURED; safe tunnel kurulmadı. Security bypass/production change/sleep test yok; NS-099 INCOMPLETE/M17 IN PROGRESS ve release kararları değişmez. [Attempt/stop/cleanup](NS099_VPN_ENVIRONMENT_ATTEMPT.md).
- **Physical-host sleep attempt (2026-10-07):** NOT RUN; host S3 supports sleep, but operator wake report was not corroborated by a new power event or sleep-time gap (157.72s wall/awake). Same app PID/session, alerts/incidents0, notifications OFF/attempts0, DB integrity healthy; ordinary Quit upper bound2.315s with no remaining app. No native recovery PASS, source change/rebuild/commit/push or gate waiver. VPN BLOCKED/NOT RUN, NS-099 INCOMPLETE/M17 IN PROGRESS and release decisions unchanged. [Host measurements/limitations](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md).
- **Second host sleep diagnostic (2026-10-07):** NOT RUN; elevated read-only powercfg /requests succeeded: Mobile Hotspot icssvc SYSTEM/AWAYMODE, Legacy Kernel Caller SYSTEM, WebView2 audio EXECUTION; DISPLAY none. AC online/Away Mode AC enabled. Clean S3 action not initiated with this active request; no service/power/override change, app launch or new burden measurement. Docs-only evidence normal main commit/push, no rebuild/tag/release/NS-100. VPN BLOCKED/NOT RUN, NS-099 INCOMPLETE/M17 IN PROGRESS unchanged; exact criteria preserved. [Blocker diagnosis](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md#second-attempt--blocker-diagnosis-no-sleep-action-requested).
- **Third host sleep attempt (2026-10-07):** NOT RUN; operator temporarily disabled Hotspot, AWAYMODE cleared but USB Audio Device SYSTEM stream request remained. Explicit stop-before-sleep honored; no sleep action or recovery PASS. Awake-only alert/incident delta0/0, notifications OFF/attempts0, DB integrity healthy; ordinary Quit upper bound2.604s, no remaining app. Hotspot restored On via native UI, icssvc Running/Manual; no override/permanent power-policy/production change/rebuild. Docs-only normal main commit/push; VPN BLOCKED/NOT RUN, NS-099 INCOMPLETE/M17 IN PROGRESS unchanged. [Third-attempt scope](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md#third-attempt--hotspot-cleared-usb-audio-system-request-remained).
- **Follow-up host S3 (2026-10-07):** Windows events verify142.461447s of actual S3 after all request classes cleared. Application sleep/resume NOT RUN: measured candidate already quit, no prepared baseline/active recorder; stopped DB unchanged does not establish recovery or zero burden. No new sleep instruction, code/rebuild/override; VPN BLOCKED/NOT RUN, NS-099 INCOMPLETE/M17 IN PROGRESS, pilot/broad NO_GO and M18 DEFER preserved. [Host proof/application limitation](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md#follow-up-verified-host-s3-without-an-application-test).
- **Final prepared native sleep retry (2026-10-07):** PASS for accepted8242868 candidate/default optional OFF scope; verified S3 sleep12:08:13.9440018/wake12:37:06.4081465 UTC,1732.464145s. Same PID19696/one session, Running engine/writer/queue0, alert/incident/notification delta0/0/0 with notifications OFF, healthy schema019 DB;36 new Edge history rows, clean native Quit3.033s/no ghost. Browser OS account association and pre-sleep capacity-loss counter cycling explicitly documented; no account/settings/code change or rebuild. VPN BLOCKED/NOT RUN still prevents exact completion: NS-099 INCOMPLETE/M17 IN PROGRESS, pilot/broad NO_GO, M18 DEFER, NS-100 NOT STARTED. [Prepared S3/recovery evidence](NS099_NATIVE_SLEEP_HOST_ATTEMPT.md#final-prepared-retry-live-candidate-s3-recovery).
- **Amaç:** Gerçek kullanıcı koşullarında release ve response öncesi kaliteyi değerlendirmek.
- **Yapılacaklar:** Client Windows VM, offline kalite ve manuel beta senaryo/FP/notification burden checklist'i çalıştır.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** tests/, docs/RELEASING.md, docs/PRODUCT.md, docs/SECURITY.md.
- **Bağımlılıklar:** NS-092–NS-098 ve zorunlu M11–M15 exit kriterleri; NS-068 conditional.
- **Acceptance criteria:** Normal browser, updater, VPN, sleep/wake, restart, Npcap missing, standard user, notification/FP burden, clean install, upgrade, uninstall ve privacy/storage sonuçları belgelenir; gate açıkça pass/fail.
- **Test yöntemi:** Offline suite + explicit clean client VM/manual beta acceptance.
- **Kapsam dışı:** Automatic response veya conditional signer/bytes özelliğini zorunlu kılma.

## M18 — Manual Response & Firewall Integration — CONDITIONAL

**Conditional başlatma kapısı:** M17 tamamlanmış, NS-099 public beta acceptance gate geçmiş ve explicit response GO kararı verilmiş olmalıdır. **Do not start before NS-099 and explicit response GO decision.** 2026-10-08 user **GO NS-100** yalnız NS-100 contract taskını yetkilendirir; NS-101–NS-104 NOT STARTED ve ayrı kullanıcı talimatı bekler. In-product writes NO_GO pending trusted privilege/ownership/native gates. Automatic blocking ve automatic elevation kapsam dışıdır.

### NS-100 — Response command/privilege contract

- **Durum:** ✅ COMPLETE (2026-10-08), explicit user GO NS-100. Pure frozen scope/command/source/file identity/confirmation/result values, 16KiB strict local codec and read-only privilege review/default unavailable boundary implemented; no actual write/elevation/helper/adapter/UI/schema/installer change.205 new tests; full offline4038 passed/8 deselected (561.96s), coverage91.17%; Ruff/configured mypy37/direct3/whitespace/bounded privacy PASS. In-product writes NO_GO pending trusted privilege/ownership/native gates; NS-101–104 NOT STARTED. [Contract/threat model](RESPONSE_COMMAND_CONTRACT.md), [acceptance](RESPONSE_COMMAND_ACCEPTANCE.md).
- **Amaç:** Manuel blocking için dar, geri alınabilir sözleşmeyi ve yetki UX'ini tasarlamak.
- **Yapılacaklar:** Destination/program rule scope, user preview/confirmation, privilege-denied, ownership ve rollback threat model tanımla.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/domain/, src/netsentinel/application/ports.py, docs/SECURITY.md, tests/unit/.
- **Bağımlılıklar:** NS-082, NS-099 ve explicit response GO kararı.
- **Acceptance criteria:** Target/profile/expiry açık; automatic elevation yok; denied/degraded sonuç typed; rule ownership sınırı kayıtlı.
- **Test yöntemi:** Validation, fake privilege denial, scope/command serialization.
- **Kapsam dışı:** Gerçek rule yazma veya automatic response.
- **Başlatma kapısı:** Do not start before NS-099 and explicit response GO decision; M17 de tamamlanmış olmalıdır.

### NS-101 — Windows Firewall adapter

- **Durum:** ⬜ Conditional plan; başlatma kapısı bekleniyor.
- **Amaç:** Dar owned firewall kuralını Windows'ta yönetmek.
- **Yapılacaklar:** Structured COM/typed Windows API ile add/read/remove adapter ve sanitized permission errors ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/infrastructure/, src/netsentinel/application/ports.py, tests/unit/infrastructure/.
- **Bağımlılıklar:** NS-100.
- **Acceptance criteria:** Program/IP/port/profile bounded; shell injection yok; unrelated rule'a dokunmaz; mevcut akışı hemen kesme garantisi verilmez.
- **Test yöntemi:** Fake API ve explicit isolated Windows rule tests.
- **Kapsam dışı:** Custom WFP driver veya process termination.
- **Başlatma kapısı:** Do not start before NS-099 and explicit response GO decision; M17 de tamamlanmış olmalıdır.

### NS-102 — Owned rules/audit/reconciliation

- **Durum:** ⬜ Conditional plan; başlatma kapısı bekleniyor.
- **Amaç:** Oluşturulan kuralların sahipliğini, expiry ve rollback'i sürdürmek.
- **Yapılacaklar:** UUID manifest, idempotent command, short transaction audit ve OS/DB partial failure reconciliation ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/application/services/, src/netsentinel/infrastructure/sqlite/, src/netsentinel/shared/diagnostics.py, tests/integration/.
- **Bağımlılıklar:** NS-095, NS-101.
- **Acceptance criteria:** Duplicate/stale/external edit açıklanır; yalnız NetSentinel-owned rules kaldırılır; partial failure recoverable; audit bounded.
- **Test yöntemi:** Fake OS/DB failure, restart, external edit ve expiry testleri.
- **Kapsam dışı:** Başka uygulama/kullanıcı kurallarını değiştirme.
- **Başlatma kapısı:** Do not start before NS-099 and explicit response GO decision; M17 de tamamlanmış olmalıdır.

### NS-103 — Manual response UI

- **Durum:** ⬜ Conditional plan; başlatma kapısı bekleniyor.
- **Amaç:** Kullanıcıya firewall etkisini görüp onaylama ve undo akışı vermek.
- **Yapılacaklar:** Target/profile/expiry/rollback preview, explicit confirm/Cancel, permission sonucunu ve audit'i UI'da göster.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** src/netsentinel/presentation/, src/netsentinel/application/services/, tests/gui/.
- **Bağımlılıklar:** NS-082, NS-102.
- **Acceptance criteria:** Cancel write yapmaz; admin yokken local trust çalışır; undo accessible; partial result açık.
- **Test yöntemi:** Offscreen denied/success/partial/rollback/Cancel.
- **Kapsam dışı:** Automatic blocking veya silent elevated helper.
- **Başlatma kapısı:** Do not start before NS-099 and explicit response GO decision; M17 de tamamlanmış olmalıdır.

### NS-104 — Firewall/uninstall acceptance

- **Durum:** ⬜ Conditional plan; başlatma kapısı bekleniyor.
- **Amaç:** Gerçek Windows rule ve uninstall davranışını doğrulamak.
- **Yapılacaklar:** Owned rule lifecycle, rollback ve installer cleanup için explicit VM acceptance ve doküman ekle.
- **Etkilenecek muhtemel dosyalar/alt sistemler:** packaging/, docs/RELEASING.md, docs/SECURITY.md, tests/integration/.
- **Bağımlılıklar:** NS-096, NS-103.
- **Acceptance criteria:** Unrelated rules untouched; owned cleanup doğrulanır; yetki yoksa kalan kurallar açık listelenir; automatic elevation yok.
- **Test yöntemi:** Isolated VM rule lifecycle, upgrade/uninstall ve interrupted-action tests.
- **Kapsam dışı:** Üretim ağında riskli test veya driver geliştirme.
- **Başlatma kapısı:** Do not start before NS-099 and explicit response GO decision; M17 de tamamlanmış olmalıdır.

## Yeni faz task özeti

| Milestone | Task aralığı | Sayı | Durum |
|---|---:|---:|---|
| M11 Process & Connection Telemetry Foundations | NS-052–NS-061 | 10 | ✅ COMPLETE |
| M12 Local Destination Context & Attribution | NS-062–NS-068 | 7 | ✅ COMPLETE; NS-067 GO ve NS-068 conditional adapter tamamlandı |
| M13 Deterministic Behavioral Baseline | NS-069–NS-075 | 7 | ✅ COMPLETE |
| M14 Explainable Risk & User Feedback | NS-076–NS-083 | 8 | ✅ COMPLETE |
| M15 Optional Threat Intelligence Evidence | NS-084–NS-088 | 5 | ✅ COMPLETE (2026-10-04); kullanıcı için default disabled |
| M16 Incident Correlation & Timeline | NS-089–NS-092 | 4 | ✅ COMPLETE (2026-10-05) |
| M17 Public Beta & Product Usability | NS-093–NS-099 | 7 | COMPLETE; NS-093–NS-099 COMPLETE — private native VPN PASS, native S3 PASS, OS-policy PASS, human UX8/8; recorded candidate/optional limitations retained |
| M18 Manual Response & Firewall Integration | NS-100–NS-104 | 5 | **IN PROGRESS; NS-100 COMPLETE after user GO; NS-101–104 NOT STARTED; in-product writes NO_GO** |
| **Yeni faz toplamı** | **NS-052–NS-104** | **53** | **48 M11–M17 taskı (NS-068 GO koşullu) + 5 M18 conditional** |

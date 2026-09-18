# Mimari

## 1. Mimari hedefler

NetSentinel mimarisi şu nitelikleri korumalıdır:

- Monitoring engine, GUI olmadan test edilebilmeli ve çalıştırılabilmelidir.
- Domain modelleri PyQt6, psutil, Scapy ve SQLite'a bağımlı olmamalıdır.
- İşletim sistemi ve kütüphane ayrıntıları adapter sınırlarında tutulmalıdır.
- Ağdan gelen güvenilmeyen veri kontrollü, sınırlı ve gözlemlenebilir bir akışla işlenmelidir.
- Uzun süren veya blocking işler GUI ana thread'ini engellememelidir.
- Tespit kuralları deterministik fixture'larla test edilebilmelidir.
- Paket yakalama olmadan bağlantı izleme gibi düşük yetkili özellikler çalışabilmelidir.

## 2. Katmanlar ve bağımlılık yönü

```text
presentation (PyQt6) ───────┐
                            v
application / engine ───> domain
          ^                 ^
          │                 │
infrastructure adapters ────┘
  (psutil, Scapy, SQLite, Windows)
```

Bağımlılık kuralları:

1. `domain` hiçbir dış framework veya I/O kütüphanesini import etmez.
2. `application` domain tiplerini ve kendi port/protokol arayüzlerini kullanır; somut adapter bilmez.
3. `infrastructure` application portlarını uygular ve domain tiplerine normalize eder.
4. `presentation` engine'in read model/command API'sini kullanır; doğrudan psutil, Scapy veya SQLite çağırmaz.
5. Composition root, somut bileşenleri birleştiren tek yerdir.

## 3. Önerilen klasör yapısı

Bu yapı plan niteliğindedir; `NS-001` uygulanana kadar kaynak kod klasörleri oluşturulmayacaktır.

```text
NetSentinel/
├── AGENTS.md
├── README.md
├── docs/
│   ├── PRODUCT.md
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md
│   ├── ROADMAP.md
│   └── TASKS.md
├── pyproject.toml
├── src/
│   └── netsentinel/
│       ├── __main__.py
│       ├── bootstrap.py
│       ├── domain/
│       │   ├── connections.py
│       │   ├── devices.py
│       │   ├── dns.py
│       │   ├── alerts.py
│       │   ├── observations.py
│       │   └── vlan.py
│       ├── application/
│       │   ├── engine.py
│       │   ├── events.py
│       │   ├── ports.py
│       │   ├── services/
│       │   └── detectors/
│       ├── infrastructure/
│       │   ├── psutil_connections.py
│       │   ├── scapy_capture.py
│       │   ├── windows_network.py
│       │   ├── sqlite/
│       │   │   ├── database.py
│       │   │   ├── migrations.py
│       │   │   └── repositories.py
│       │   └── clock.py
│       ├── presentation/
│       │   ├── app.py
│       │   ├── bridge.py
│       │   ├── models/
│       │   ├── views/
│       │   └── widgets/
│       └── shared/
│           ├── config.py
│           ├── logging.py
│           └── diagnostics.py
└── tests/
    ├── unit/
    ├── integration/
    ├── gui/
    ├── fixtures/
    └── performance/
```

## 4. Temel domain kavramları

Domain tipleri mümkün olduğunca immutable veri nesneleri olarak tasarlanır. Zaman damgaları UTC ve timezone-aware tutulur; kullanıcı arayüzünde yerel saate çevrilir.

### Bağlantı

- `Endpoint`: IP adresi ve port. UDP veya dinleme durumlarında eksik remote endpoint'i temsil edebilir.
- `ProcessIdentity`: PID ve varsa UTC process create-time ile bir process instance'ını tanımlar; process adı kimliğin parçası değildir.
- `ProcessInfo`: Process kimliği, adı ve metadata'nın kullanılabilirlik durumunu birbirinden ayırır.
- `ConnectionKey`: Bir bağlantıyı snapshot'lar arasında eşlemek için protokol, local/remote endpoint ve `ProcessIdentity` değerinden oluşan anahtar; state ve process metadata'sı anahtara dahil edilmez.
- `ConnectionSnapshot`: Bir adapter gözleminin normalize edilmiş, framework bağımsız hali.
- `TrackedConnection`: ilk görülme, son görülme, durum ve process metadata'sı bulunan yaşam döngüsü.
- `ConnectionOpened`, `ConnectionUpdated`, `ConnectionClosed`: tracker tarafından üretilen domain olayları.

PID yeniden kullanımına karşı process create-time bilgisi mümkün olduğunda anahtara eklenir. Create-time erişilemiyorsa yalnızca PID ile eşleme yapıldığı ve PID reuse ayrımının garanti edilemediği kabul edilir. UDP'nin bağlantısız doğası ve Windows API sınırlamaları nedeniyle “closed” olayı, snapshot'ta artık görülmeme anlamına gelir; gerçek protokol kapanışı olduğu iddia edilmez.

#### Snapshot diff semantiği

`ConnectionTrackingService` her girdiyi eksiksiz bir gözlem turu kabul eder. İlk turda görünür olan tüm bağlantılar `ConnectionOpened` üretir. Sonraki turlarda `ConnectionKey` eşleşmesi korunurken state veya process availability/name metadata'sı değişirse `ConnectionUpdated`; önceki turda bulunup yeni turda bulunmayan anahtar için `ConnectionClosed(reason=NOT_OBSERVED)` üretilir. Yalnızca observation timestamp'i ilerleyen, diğer gözlemlenebilir alanları aynı kalan bağlantı event üretmez; buna rağmen `last_seen` ilerletilir.

Aynı `ConnectionKey` bir turda birden fazla kez gelirse en yeni `observed_at` seçilir. Timestamp eşitliğinde daha kullanılabilir process metadata'sı, ardından kanonik state/metadata sırası tercih edilir. Böylece duplicate çözümü ve event sırası input sırasından bağımsızdır. Process adı ve availability kimlik değildir; bunların değişimi update'tir. PID ile birlikte create-time değişirse `ProcessIdentity` ve dolayısıyla `ConnectionKey` değişir; eski anahtar görünmedi olarak kapanır ve yenisi açılır.

Event'ler `OPENED`, `UPDATED`, `CLOSED` grupları halinde ve her grup içinde kanonik `ConnectionKey` sırasıyla döner. Open/update olayları kaynak snapshot'ın observation timestamp'ini korur. Close zamanı yeni gözlem turunun zamanıdır; bu olay TCP FIN/RST gözlemlendiğini veya UDP oturumunun protokol seviyesinde kapandığını iddia etmez.

### Paket gözlemi

- `PacketObservation`: ortak capture metadata'sı; interface, capture zamanı, link/network katmanı özeti ve yakalanan uzunluk.
- `ArpObservation`: opcode, sender/target IP ve MAC bilgileri.
- `DnsObservation`: transaction ID, yön, soru ve normalize edilmiş cevap kayıtları.
- `BroadcastObservation`: L2/L3 broadcast türü ve sayaç sınıflandırması.
- `VlanObservation`: 802.1Q VLAN ID, öncelik alanları ve kapsüllenmiş protokol bilgisi.

Ham Scapy paketleri domain/application sınırını geçmez ve varsayılan olarak kalıcılaştırılmaz.

### Cihaz ve ağ kimliği

- `DeviceIdentity`: kararlı dahili ID, gözlenen MAC/IP kümeleri, ilk/son görülme ve kullanıcı profili referansı.
- `DeviceProfile`: kullanıcı etiketi, beklenen kimlikler ve güven durumu.
- `NetworkContext`: interface, subnet, gateway, DNS sunucuları ve ağ profili için normalize edilmiş bağlam.
- `IdentityBinding`: belirli ağ bağlamında zaman aralığıyla IP-MAC ilişkisi.

### Güvenlik olayı

- `SecurityEvent`: detector çıktısı olan gözlemlenebilir güvenlik sinyali.
- `Alert`: kullanıcıya sunulan; kategori, severity, confidence, durum, ilk/son görülme, tekrar sayısı ve kanıt içeren kayıt.
- `Evidence`: mümkün olduğunca yapılandırılmış ve hassas veri içeriği sınırlandırılmış dayanak.

Alert severity ile confidence ayrı tutulur. Örneğin gateway MAC değişimi yüksek etkili olabilir ancak ağ değişiminden hemen sonra confidence düşük olabilir.

## 5. Modüller ve sorumluluklar

### `domain`

Veri modelleri, value object'ler, enum'lar ve framework bağımsız kurallar. I/O, thread, SQL, Qt sinyali veya paket nesnesi içermez.

### `application.events`

Process-içi typed event dağıtımı. Olay sırasını ve hata izolasyonunu tanımlar. Subscriber hatası producer'ı durdurmaz; hata diagnostics kanalına gider.

### `application.engine`

`MonitoringEngine` yaşam döngüsünü yönetir: `start`, `stop`, capability durumu ve worker koordinasyonu. Collector'ları, tracker'ları ve detector'ları port arayüzleri üzerinden kullanır.

### `application.services`

- `ConnectionTrackingService`: snapshot diff ve yaşam döngüsü
- `DeviceRegistryService`: IP-MAC gözlemlerinden cihaz durumu
- `DnsTrackingService`: sorgu/cevap korelasyonu
- `HistoryService`: kalıcılık için olayları kuyruklama
- `AlertService`: deduplication, severity/confidence ve alert yaşam döngüsü
- `StatisticsService`: sınırlı rolling counter ve UI read model'leri

### `application.detectors`

Her detector küçük, state'i açık ve fixture ile beslenebilir olmalıdır:

- `NewDeviceDetector`
- `GatewayMacChangeDetector`
- `IpMacConflictDetector`
- `ArpRateDetector`
- `DnsServerChangeDetector`
- `BroadcastRateDetector`
- `DeviceIdentityChangeDetector`
- `VlanAnomalyDetector`

Detector doğrudan GUI veya veritabanı çağırmaz; `SecurityEvent` döndürür/yayınlar.

### `infrastructure`

- psutil bağlantı snapshot'ı ve process metadata adaptasyonu
- Scapy capture yaşam döngüsü ve protokol parser'ları
- Windows interface, route/gateway ve DNS yapılandırması okuma
- SQLite migration ve repository implementasyonları
- Sistem saati ve logging adaptörleri

### `presentation`

PyQt6 uygulama kabuğu, ekranlar, tablo modelleri ve kullanıcı komutları. UI, domain nesnelerini doğrudan değiştirmez; immutable view model/read model kullanır.

## 6. Veri akışı

### Bağlantı izleme

```text
psutil adapter
  -> normalize snapshot
  -> ConnectionTrackingService (önceki snapshot ile diff)
  -> ConnectionOpened/Updated/Closed
  -> event dispatcher
       -> in-memory read model -> Qt bridge -> Connections/Dashboard
       -> persistence queue -> SQLite writer
       -> statistics service
```

### Paket tabanlı izleme

```text
Scapy capture worker
  -> minimal packet parser
  -> bounded observation queue
  -> protocol services (ARP/DNS/Broadcast/VLAN)
  -> registry/baseline/detectors
  -> SecurityEvent
  -> AlertService
       -> Alerts read model -> Qt bridge -> Alerts UI
       -> persistence queue -> SQLite writer
```

### Kullanıcı komutları

```text
PyQt view
  -> presentation controller/command
  -> application service
  -> domain state + event
  -> read model refresh
```

Örnek komutlar cihazı adlandırma, güven durumunu değiştirme, alert'i onaylama ve güvenli capture başlatma/durdurmadır.

## 7. Threading ve zamanlama tasarımı

İlk sürümde `asyncio` ile Qt event loop'unu birleştirmek yerine sınırlı sayıda worker thread ve bounded queue kullanılır. Bu tercih psutil, SQLite ve paket yakalama gibi blocking API'lerle daha basit ve öğretici bir yaşam döngüsü sağlar.

### Thread'ler

- **GUI main thread:** Yalnızca Qt event loop ve widget/model güncellemeleri.
- **Connection poller:** Yapılandırılabilir aralıkla psutil snapshot'ı alır. Önceki tur bitmeden yeni tur başlatmaz.
- **Capture worker:** Seçili interface'te Scapy capture çalıştırır ve yalnızca normalize edilmiş gözlemleri kuyruğa yollar.
- **Analysis worker:** Packet observation kuyruğunu tüketir ve detector'ları çalıştırır. Başlangıçta tek consumer deterministik sıralama sağlar.
- **SQLite writer:** Tek yazıcı bağlantısıyla batch transaction işler. GUI/read tarafı ayrı read-only bağlantı kullanır.

### Güvenli iletişim

- Kuyruklar bounded olur; limit aşılırsa uygulama sessizce bellek büyütmek yerine drop sayacı ve health olayı üretir.
- Stop işlemi cancellation event, capture stop ve sınırlı join timeout ile yapılır.
- Worker istisnaları yutulmaz; health/diagnostics durumu ve yapılandırılmış log üretir.
- Qt nesnelerine worker thread'den doğrudan erişilmez.
- `QtEngineBridge`, engine event'lerini GUI thread'ine queued signal veya kısa aralıklı queue drain ile taşır.
- UI güncellemeleri olay başına widget değiştirmek yerine batch uygulanır.

Thread sayısı ve batching, performans testlerinden sonra değişebilir; public portlar korunduğu sürece domain tasarımı etkilenmez.

## 8. GUI ile monitoring engine ayrımı

`MonitoringEngine` bir `QApplication` veya widget referansı almaz. Engine aşağıdaki dar yüzeyleri sunar:

- Yaşam döngüsü: başlat, durdur, sağlık/capability durumu
- Read model snapshot'ları: aktif bağlantılar, cihazlar, DNS işlemleri, alert'ler ve istatistikler
- Kullanıcı komutları: filtre dışı olmayan kontrollü state değişiklikleri
- Event stream: yeni veriler için typed application event'leri

PyQt6 katmanı:

- Engine'i doğrudan yaratmak yerine `bootstrap.py` composition root'undan alır.
- Domain olaylarını Qt sinyallerine `bridge.py` üzerinden çevirir.
- Tablo verilerini `QAbstractTableModel` türevlerinde tutar.
- Sıralama/filtreleme için proxy model kullanır; monitoring işini view içine koymaz.
- Engine durduğunda son read model'i gösterebilir ve yetenek kaybını açıkça belirtir.

Bu sınır sayesinde detector ve tracker testleri GUI açmadan, GUI testleri ise fake engine ile çalıştırılabilir.

## 9. Persistence tasarımı

SQLite tek yerel veri deposudur. İlk planlanan tablolar:

- `schema_migrations`
- `connection_history`
- `devices`
- `device_bindings`
- `device_profiles`
- `dns_transactions`
- `security_events`
- `alerts`
- `alert_evidence`
- `network_baselines`
- `vlan_observations` (özet/retention kontrollü)

İlkeler:

- Şema yalnızca sıralı migration'larla değişir.
- WAL modu ve busy timeout kullanılır; tek writer modeli korunur.
- Repository'ler SQL satırlarını domain/read model tiplerine map eder.
- Ham paket payload'ı saklanmaz.
- Liste ekranlarında zaman aralığı, limit ve pagination zorunludur.
- Retention politikası tablo türüne göre yapılandırılabilir ve güvenli transaction ile uygulanır.
- Veritabanı bozulması veya migration hatası uygulamayı anlaşılmaz biçimde çökertmez; diagnostics ve kurtarma yönlendirmesi sunulur.

## 10. Detection yaklaşımı

Detectors üç girdiyi ayırır:

1. **Observation:** Ağdan veya işletim sisteminden doğrudan ölçülen veri.
2. **Baseline/context:** Öğrenilmiş veya kullanıcı tarafından doğrulanmış beklenen durum.
3. **Rule:** Observation ile baseline arasındaki farkı değerlendiren deterministik mantık.

Her çıktı en az rule ID, zaman, ilgili entity ID, severity, confidence ve yapılandırılmış evidence taşır. Aynı semptom kısa sürede tekrarlandığında alert storm yaratmamak için fingerprint tabanlı deduplication ve tekrar sayacı kullanılır.

Baseline ağ bağlamına özgüdür. Örneğin farklı Wi-Fi ağlarındaki gateway MAC adresleri birbirine karıştırılmaz. Ağ değişiminden sonra öğrenme/ısınma penceresi uygulanır.

## 11. Hata, saat ve kimlik stratejisi

- Persist edilen tüm zamanlar UTC'dir; interval ölçümü için monotonic clock kullanılır.
- DB entity'leri için UUID; tekrarlanabilir detector çıktıları için kararlı fingerprint kullanılır.
- Yetki reddi, interface kaybı, process'in snapshot sırasında kapanması ve malformed packet beklenen hata sınıflarıdır.
- Bir adapter hatası ilgili capability'yi degraded yapar; mümkünse diğer monitoring modülleri devam eder.
- Kullanıcıya gösterilen hata mesajı eyleme dönük, teknik log ise ayrıntılı olur.

## 12. Test stratejisi

- **Unit:** Domain, diff, parser, baseline ve detector kuralları; fake clock ile deterministik zaman.
- **Integration:** psutil çıktısı adaptasyonu, geçici SQLite DB ve migration/repository davranışı.
- **Packet fixtures:** Küçük, sentetik ve anonimleştirilmiş ARP/DNS/broadcast/VLAN paketleri.
- **GUI:** Fake engine ile table model, filtreleme, lifecycle ve smoke testleri.
- **Performance:** Event burst, queue backpressure, uzun history pagination ve shutdown süresi.
- **Windows smoke:** Yetkili ve yetkisiz mod, capture driver var/yok kombinasyonları.

Canlı ağ erişimi gerektiren testler varsayılan test suite'inde çalışmaz; açık marker ve kontrollü lab gerektirir.

### M1 Windows live smoke testi

`windows_live` marker'ı gerçek `psutil` adapter sınırını yalnızca açıkça istendiğinde
çalıştırır. Varsayılan `python -m pytest` komutu bu marker'ı dışlar; M1 smoke testi
Windows üzerinde `python -m pytest -m windows_live` ile seçilir. Test external bir
hosta bağlanmaz, yönetici yetkisi istemez ve yalnızca `127.0.0.1` üzerinde işletim
sisteminin atadığı geçici bir portu kullanır. Listener ve bağlantının iki ucu test
boyunca kontrollü biçimde açık tutulur; teardown tüm socket'lerin kapandığını,
engine stop kontrolleri de poller worker'ının kalmadığını doğrular.

Smoke testi endpoint, TCP protokolü, normalize portlar, PID/process enrichment ve
en az bir `ConnectionOpened` olayını gerçek composition root üzerinden denetler.
Sabit bir uykuya dayanmak yerine event sinyalleri ve bounded timeout kullanır.
System-wide connection tablosu Windows politikası tarafından tamamen reddedilirse
test kontrollü skip olur; bu ortam kısıtı yönetici yetkisini test önkoşulu yapmaz.

## 13. Bilinen teknik sınırlamalar

- psutil snapshot tabanlı polling, iki tur arasında açılıp kapanan çok kısa bağlantıları kaçırabilir.
- Windows ve psutil, standart kullanıcıya bazı system-wide connection satırlarının
  PID bilgisini göstermeyebilir veya tablo erişimini tamamen reddedebilir.
- Process adı/create-time sorgusu izin nedeniyle kısıtlanabilir ya da process'in
  snapshot ile metadata sorgusu arasında kapanması sonucu unavailable olabilir;
  bu durum connection görünürlüğünü düşürmeden degraded metadata olarak modellenir.
- UDP satırları gerçek bir “oturum” değil, işletim sistemi endpoint görünümüdür.
- Paket ile PID/process arasında her durumda güvenilir bire bir ilişki kurulamaz.
- Capture sonucu kullanılan driver, interface ve Windows güvenlik politikasına bağlıdır.
- Switch'li ağda bilgisayara ulaşmayan unicast trafik gözlenemez.
- VLAN tag'leri NIC offload/driver nedeniyle capture noktasında kaldırılmış olabilir.
- Şifreli DNS (DoH/DoT) klasik DNS parser'ıyla içerik düzeyinde görünmez.

Bu sınırlamalar UI ve kullanıcı dokümantasyonunda saklanmaz; yanlış güven hissi yaratmamak ürün gereksinimidir.

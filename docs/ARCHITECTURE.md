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
- `HistoryRetentionService`: tamamlanmış history için senkron, bounded manuel cleanup
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

### NS-008 uygulama kabuğu ve yaşam döngüsü

`presentation.app`, `QApplication` oluşturma/yeniden kullanma, `MainWindow`
oluşturma ve engine yaşam döngüsünü bir araya getirir. Engine somut bağımlılıkları
yalnızca `bootstrap.py` composition root'undan alınır. Uygulama çalıştırıldığında
engine event loop öncesinde başlatılır; pencere kapanışı, Qt `aboutToQuit` sinyali
ve event loop çıkışı aynı idempotent lifecycle controller üzerinden tek bounded
`engine.stop()` isteğine indirgenir.

`MainWindow`, Dashboard, Connections, Devices, DNS ve Alerts view örneklerinin
composition sorumluluğunu taşır. Sol `QListWidget` kararlı `PageId` değerleriyle
bir `QStackedWidget` içeriğini seçer; varsayılan sayfa Dashboard'dur ve aynı
sayfanın tekrar seçilmesi idempotenttir. NS-008 view'ları yalnızca profesyonel
placeholder içerir. Engine event bridge'i, connection modelleri ve canlı
istatistikler sırasıyla NS-009 ve sonraki taskların kapsamındadır.

### NS-009 Qt engine bridge ve thread sınırı

```text
MonitoringEngine connection poller worker
  -> EventDispatcher synchronous callback
  -> QtEngineBridge bounded handoff queue
  -> coalesced queued Qt signal
  -> Qt main-thread batch drain
  -> views/models (NS-010 ve sonrası)
```

`QtEngineBridge` presentation katmanında oluşturulur; application veya domain
katmanına PyQt6 bağımlılığı taşımaz ve engine içine Qt bilgisi eklemez. Dispatcher
callback'i widget/model erişimi, sıralama, formatlama veya render yapmaz. Yalnızca
portable `ConnectionOpened`, `ConnectionUpdated` ve `ConnectionClosed` olayını
kilitli ve bounded handoff queue'ya ekler. Boş queue için yalnızca bir queued
drain planlanır; böylece event başına thread oluşturulmaz ve yoğun burst Qt event
queue'sunda gereksiz wake-up çoğaltmaz. Qt thread'indeki her drain sınırlı bir
batch alır; kalan iş bir sonraki event-loop turuna bırakılır.

Queue dolduğunda bekleyen eski sırayı korumak için yeni event düşürülür. Toplam
drop sayısı, queue kapasitesi ve mevcut queue derinliği immutable bridge health
snapshot'ında; mevcut `EngineHealthSnapshot` ile birlikte `health_changed`
sinyalinden sunulur. Engine health yeni bir worker/poller yerine presentation
seviyesindeki `QTimer` ile mevcut `health_snapshot()` API'sinden okunur.

Application composition bridge'i engine başlamadan önce attach eder. Kapanışta
önce bridge detach edilir, pending handoff temizlenir ve daha sonra bounded engine
stop istenir. Attach/detach idempotenttir. Her attachment bir generation ile
korunur; eski queued drain'ler yeniden attach sonrasında event yayımlayamaz.
Dispatcher callback'i bridge'e yalnızca weak reference taşır. Açık stop yoluna ek
olarak QObject destruction ve Python finalization subscription'ları temizler;
publish sırasında alınmış eski subscriber snapshot'ları inactive state'i görüp
no-op olur.

### NS-010 Connections tablo modeli

```text
QtEngineBridge events_ready / lifecycle signals
  -> ConnectionsTableModel (Qt ana thread, incremental state)
  -> QTableView + proxy/detail katmanı (NS-011)
```

`ConnectionsTableModel`, insertion sırasını koruyan immutable `ConnectionRow`
değerleri ile `ConnectionRowId -> row index` haritası tutar. Row ID, domain
`ConnectionKey` alanlarından türetilir; process create-time mevcut olduğunda PID
reuse yeni bir kimlik üretir. OPENED satır ekler, UPDATED aynı index'te
`dataChanged` yayar ve CLOSED yalnızca eşleşen satırı kaldırır. Normal lifecycle
akışında model reset kullanılmaz. Duplicate/stale OPENED güvenli no-op veya aynı
satırda ileri güncellemedir; kaçırılmış OPENED sonrasındaki bilinmeyen UPDATED
upsert ile toparlanır, bilinmeyen CLOSED no-op'tur.

Display değerleri presentation mapper'ında üretilir; IPv6 endpoint portları
köşeli parantezle ayrılır ve eksik process/remote endpoint değerleri güvenli bir
placeholder alır. Raw roller gelecekteki NS-011 filtre/sort katmanına protokol,
state, process, PID, endpoint parçaları, stabil row ID ve sayısal süreyi sunar.
Süre timer ile ilerletilmez; modele ulaşan son lifecycle observation zamanı ile
satırın ilk görülme zamanı arasındaki negatif olmayan snapshot süresidir.

### NS-011 Connections ekranı, filtreleme ve detay

```text
QtEngineBridge connection_opened / connection_updated / connection_closed
  -> ConnectionsTableModel (Qt ana thread, incremental lifecycle mutation)
  -> ConnectionsFilterProxyModel (raw-role search/filter + semantic sort)
  -> ConnectionsView (QTableView + stable-ID selection + detail panel)
```

`MainWindow`, tek `ConnectionsTableModel` örneğini oluşturur ve bridge'in üç
lifecycle sinyalini modelin karşılık gelen handler'larına bir kez bağlar. View,
engine, dispatcher, worker veya infrastructure adapter'ına abone olmaz. Bridge
health sinyali de yalnızca portable snapshot olarak view'a aktarılır; unavailable
connection monitoring ve kısıtlı process metadata kullanıcıya açıkça gösterilir.

Proxy araması process adı, PID ve local/remote address/port raw rollerinden
oluşturulur; display endpoint text'i parse edilmez. Protocol ve portable state
filtreleri exact raw value ile birleşir. PID, endpoint portları ve duration sayısal;
IP adresleri adres ailesi ve sayısal adres; protocol/state ise tanımlı enum sırası
ile karşılaştırılır. Filtre veya sort değişikliği source modeli resetlemez.

Seçim `ConnectionRowId` ile izlenir. Proxy sırası değiştiğinde görünür row yeniden
bulunur; update seçili detayı tazeler. Filtre seçimi gizlerse veya CLOSED source
satırını kaldırırsa seçim ve detay paneli temizlenir, komşu satırın detayına
yanlışlıkla geçilmez. Pause yalnızca view painting ve kontrollerini dondurur;
model lifecycle eventlerini almaya devam eder ve resume güncel state'i gösterir.

### NS-012 Dashboard ve canlı istatistikler

```text
QtEngineBridge lifecycle signals
  -> ConnectionsTableModel (tek aktif-connection source of truth)
  -> DashboardViewModel -> Dashboard connection kartları

QtEngineBridge events_ready
  -> bounded StatisticsService (60 saniyelik opened/closed olay penceresi)
  -> DashboardViewModel -> recent event kartları

QtEngineBridge health_changed
  -> EngineHealthSnapshot + bridge drop sayacı
  -> DashboardViewModel -> kullanıcı dostu health/capability/diagnostic metni
```

Dashboard yeni snapshot toplamaz ve `MonitoringEngine`, psutil ya da başka bir
infrastructure adapter'ına erişmez. Anlık total/TCP/UDP/listening/unique remote
host değerleri `MainWindow` tarafından Connections ekranıyla paylaştırılan tek
`ConnectionsTableModel` örneğinin immutable presentation satırlarından bir
geçişte hesaplanır. Model insert/remove/update/reset sinyalleri kartları Qt ana
thread'inde günceller; canonical remote address kullanılır ve display endpoint
metni parse edilmez.

Framework-bağımsız `StatisticsService` yalnızca bridge'in batch lifecycle
eventlerinden kısa pencere içindeki opened/closed olay sayılarını tutar. State'i
hem zaman hem kapasite bakımından bounded'dır. Dashboard network polling timer'ı
oluşturmaz; rolling pencerenin sona ermesi için yalnızca tek-shot presentation
timer'ı kullanır. Health mapping portable enum ve diagnostic code'larından
üretilir; raw exception/traceback metni presentation state'ine taşınmaz.

### NS-013 GUI lifecycle, erişilebilirlik ve responsiveness doğrulaması

Kritik pencere, navigasyon, filtre, tablo, detay ve health öğeleri açık
`accessibleName` değerleri taşır. Connections sayfasındaki temel focus zinciri
Qt'nin doğal keyboard davranışı korunarak sidebar, arama, protokol/state
filtreleri, pause ve tablo sırasına bağlanır. Sayfa değişimi, focus'u gizlenen bir
widget üzerinde bırakmaz. Sidebar genişliği ve satır yükseklikleri tek bir sabit
geometriye kilitlenmez; test suite'i ayrıca `QT_SCALE_FACTOR=2` ile bağımsız bir
offscreen smoke süreci çalıştırır.

Lifecycle regresyonları window close, `QApplication.aboutToQuit`, önceden
detach edilmiş bridge, tekrarlı shutdown, queued event ve aktif burst sırasında
kapanışı bounded sürelerle doğrular. Bridge detach sonrası dispatcher callback'i
kalmaz; eski queued drain generation kontrolü nedeniyle model/widget mutate
edemez. Responsiveness testi gerçek ağ kullanmadan fake dispatcher'a sentetik
burst yayınlar. Sıfır aralıklı `QTimer` heartbeat'in bounded batch drain'leri
arasında çalışması ve tüm kabul edilen eventlerin 5 saniyelik geniş CI smoke
eşiği içinde tamamlanması beklenir; bu eşik bir performans benchmark'ı değildir.

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

### NS-014 SQLite temeli ve katman sınırı

```text
application / domain
        ↓
ConnectionHistoryRepository port
        ↓
SQLiteConnectionHistoryRepository adapter
        ↓
ordered migrations / versioned schema
```

Domain ve application katmanları `sqlite3`, connection nesnesi, SQL veya şema
ayrıntısı bilmez. NS-014 yalnızca infrastructure katmanındaki bağlantı ve şema
temelini sağlar; repository mapping'i, lifecycle event yazımı ve async writer
NS-015/NS-016 kapsamındadır.

Production veritabanı Windows kullanıcı profilinin Local Application Data
dizinindeki `NetSentinel/netsentinel.sqlite3` dosyasıdır. Test ve composition
kodları açık bir path enjekte edebilir. Path çözümü import sırasında dizin veya
dosya oluşturmaz; parent dizin ilk bağlantıda hazırlanır. Bağlantılar
`foreign_keys=ON`, `journal_mode=WAL` ve 5000 ms `busy_timeout` ile açılır.
Autocommit yalnızca transaction dışındaki işlemler içindir; yazma blokları açık
`BEGIN IMMEDIATE`/commit/rollback helper'ı kullanır. Connection threadler arasında
paylaşılmaz ve sahibi tarafından kapatılır. Bu ayarlar NS-016'daki kısa batch ve
tek-writer modeline hazırlıktır; writer thread/queue bu taskta oluşturulmaz.

Migration manifest'i package içindeki numaralı SQL kaynaklarını explicit sırayla
yükler; filesystem sırasına güvenmez. Her migration kendi transaction'ında DDL'i
ve `schema_migrations` ledger kaydını birlikte yazar. Hata ikisini de rollback
eder. Uygulamanın desteklediğinden yüksek version yazma modunda
`DatabaseSchemaTooNew` ile reddedilir; otomatik downgrade veya destructive
kurtarma yapılmaz. Bozuk metadata ve adapter hataları raw SQLite mesajını üst
katmanlara taşımayan typed infrastructure hatalarıdır.

`connection_history` başlangıç şeması UUID metin kimliği; protocol, endpoint,
process identity/availability/name, portable connection state, first/last seen
ve nullable close time/reason alanlarını içerir. Domain'in nullable remote/process
semantiği ve lifecycle zaman sırası `CHECK` constraint'leriyle korunur. Zamanlar
UTC Unix epoch mikrosaniye olarak signed SQLite `INTEGER` içinde saklanır; bu
seçim float dönüşümünü önler ve timezone-aware domain değerleri için deterministik,
mikrosaniye hassasiyetli NS-015 round-trip sözleşmesi sağlar. Zaman/kararlı ID ve
process filtreleri için iki başlangıç index'i bulunur; ek query index'leri gerçek
repository sorguları ölçülmeden eklenmez.

### NS-015 connection history repository

`application.ports.ConnectionHistoryRepository`, lifecycle yazımı ile bounded
history sorgusunu SQLite ve filesystem tiplerinden bağımsız tanımlar. Immutable
`ConnectionHistoryRecord` DB UUID kimliğini, en son portable snapshot'ı,
first/last seen zamanlarını ve nullable kapanış bilgisini taşır. Bu UUID,
snapshot'lar arası eşleme yapan `ConnectionKey` değildir; aynı endpoint/PID daha
sonra yeniden açıldığında yeni lifecycle kaydı oluşturulabilir. Process
create-time mevcutsa key eşlemesine katıldığı için PID reuse kayıtları birleşmez.

`SQLiteConnectionHistoryRepository`, her senkron operasyon için sahibi olduğu
tek migrated connection açar ve scope sonunda kapatır. OPENED aynı key ve
first-seen ile tekrarlandığında mevcut kaydı döndürür; UPDATED aktif kaydın
first-seen değerini koruyarak son snapshot'ı ilerletir; CLOSED close time/reason
alanlarını atomik yazar ve aynı close eventinin tekrarını no-op olarak döndürür.
Tüm write operasyonları NS-014 `transaction` helper'ını kullanır. Adapter thread,
queue, batching veya background writer oluşturmaz; bunlar NS-016 kapsamındadır.

History query `limit` gerektirir (1–500), negatif offset'i reddeder ve
first-seen zaman aralığı, protocol, process name/PID ve local/remote endpoint IP
filtrelerini parametre binding ile uygular. Sonuçlar
`first_seen_utc_us DESC, id DESC` ile kararlıdır; aynı timestamp'e sahip kayıtlar
sayfalar arasında atlanmaz. SQLite row/exception nesneleri port sınırını geçmez;
bozuk enum veya unsupported persisted değer kontrollü `HistoryDataCorrupt`,
adapter/transaction sorunları sanitize edilmiş `HistoryRepositoryError` olur.
UTC zaman mapping'i float kullanmadan epoch mikrosaniye `INTEGER` üzerinden tam
round-trip yapar ve naive/non-UTC datetime değerlerini reddeder.

### NS-016 asenkron history writer ve backpressure

```text
MonitoringEngine lifecycle events
        ↓ synchronous subscriber / put_nowait
ConnectionHistoryPersistence
        ↓
ConnectionHistoryWriter (bounded FIFO, varsayılan 2048)
        ↓ tek worker, küçük bounded batch (varsayılan 64 / 100 ms)
ConnectionHistoryWriteSession
        ↓ tek writer-owned connection + batch transaction
SQLiteConnectionHistoryRepository mapping
        ↓
SQLite connection_history
```

Producer tarafı yalnızca portable `ConnectionOpened`, `ConnectionUpdated` ve
`ConnectionClosed` eventlerini `put_nowait` ile kuyruğa kabul etmeyi dener; DB
I/O, retry veya connection açma poller thread'inde yapılmaz. Queue doluyken yeni
event düşürülür, bekleyen eski FIFO sırası korunur. Drop yalnızca bounded
counter ve son typed diagnostic snapshot'ını günceller; raw exception, SQL veya
DB path üst katmana taşınmaz. Varsayılan capacity 2048'dir ve composition'da
yapılandırılabilir.

Writer her çalışma döneminde yalnızca bir daemon worker oluşturur. SQLite write
session ve migrated connection worker thread içinde açılır, threadler arasında
paylaşılmaz ve worker çıkarken kapatılır. Kabul edilen eventler FIFO batch'e
alınır; her batch tek transaction'da OPENED → `record_opened`, UPDATED →
`record_updated`, CLOSED → `record_closed` olarak map edilir. Repository'nin
idempotency kuralları writer'da yeniden uygulanmaz. Sanitize edilmiş repository
hatasında varsayılan iki bounded retry ve artan, bounded kısa backoff uygulanır.
Batch kalıcı olarak başarısızsa eventler orijinal sırada tek tek izole edilir;
bir bozuk event sonraki eventleri veya uzun ömürlü worker'ı öldürmez.

Portable persistence health snapshot'ı lifecycle state, queue depth/capacity,
accepted/persisted/dropped/failed/retry/batch sayaçları, son başarılı write zamanı
ve son typed diagnostic'i taşır. Snapshot lock altında kopyalanır; lock tutulurken
DB I/O yapılmaz. Overflow diagnostic'i dışarıya event başına log/sinyal spam'i
üretmez; son durum ve toplam sayaç üzerinden gözlemlenir.

Production composition `create_desktop_engine` içinde yapılır; engine SQLite,
path veya concrete repository bilmez. Start sırasında writer önce başlatılır ve
dispatcher'a her lifecycle tipi için bir kez subscribe edilir. GUI shutdown sırası:

```text
Qt bridge detach
  -> MonitoringEngine poller cancellation/join
  -> persistence subscriber detach
  -> writer acceptance close
  -> bounded queue drain / writer session close
```

Normal stop kabul edilmiş kuyruğu flush eder. Stop timeout aşılırsa producer'a
kapı kapalı kalır, henüz in-flight olmayan queue item'ları drop sayacına eklenir
ve `persistence_shutdown_timeout` görünür olur; devam eden SQLite çağrısı zorla
iptal edilmez, döndüğünde daemon worker kaynaklarını kapatır. `start`/`stop`
idempotenttir; tamamen durmuş writer yeniden başladığında yeni bir worker-owned
session açar. Presentation view'ları writer/repository referansı almaz.

### NS-017 retention ve yerel veri yaşam döngüsü

```text
HistoryRetentionConfig (varsayılan 30 gün / 100.000 toplam satır / 500 chunk)
        ↓
HistoryRetentionService.run_cleanup() (senkron manuel command)
        ↓ HistoryRetentionRepository portu
SQLiteHistoryRetentionRepository
        ↓ her çağrıda ayrı connection + kısa BEGIN IMMEDIATE transaction
bounded completed-only DELETE → connection_history
```

Application servisi SQL, `sqlite3`, DB path veya filesystem bilmez; SQLite
adapter'ı writer'ın connection'ını paylaşmaz ve her operasyon için çağıran
thread'e ait ayrı migrated connection açıp kapatır. Retention writer'a periyodik
iş olarak bağlanmaz ve yeni scheduler/worker oluşturmaz. WAL ve 5000 ms busy
timeout davranışı NS-014 connection factory'sinden aynen alınır.

Gün politikası lifecycle'ın `closed_at_utc_us` zamanını kullanır. Fake/injected
UTC saatinden `now - retention_days` cutoff'u hesaplanır; yalnızca
`closed_at_utc_us < cutoff` kayıtları eligible'dır, tam cutoff mikrosaniyesindeki
kayıt korunur. `closed_at_utc_us IS NULL` aktif lifecycle demektir ve hem gün
hem row query'sinde açıkça seçim dışındadır.

Row politikası age cleanup tamamlandıktan sonra çalışır. `max_history_rows`
aktif ve tamamlanmış tüm lifecycle satırlarını sayar; limit aşılırsa
`first_seen_utc_us ASC, closed_at_utc_us ASC, id ASC` sırasındaki en eski
tamamlanmış kayıtlar silinir. Aktif kayıtlar kapasiteyi kullanır fakat asla
silinmez. Aktif kayıt sayısı tek başına limiti aşarsa tüm completed kayıtlar
temizlenebilir ve kalan toplam zorunlu olarak limitin üstünde olabilir.

Her adapter çağrısı en fazla `cleanup_chunk_size` ID'yi deterministik alt
sorguyla seçip aynı kısa transaction içinde siler. `DELETE ... LIMIT` SQLite
uzantısına güvenilmez; değerler parameter binding ile verilir. Stop predicate
yalnızca chunk sınırlarında değerlendirilir. Kesintide tamamlanmış chunk'lar
kalıcıdır, aktif transaction hata halinde rollback olur ve aynı command daha
sonra idempotent biçimde devam edebilir.

Portable diagnostics ana DB dosyasının ve mevcutsa `-wal` dosyasının ölçüm
anındaki gerçek byte boyutlarını, ayrıca active/completed/toplam satır sayılarını
verir; filesystem path taşımaz. WAL yoksa `wal_bytes=0` olur. Cleanup otomatik
`VACUUM` çalıştırmaz; bu nedenle silme sonrasında dosya boyutunun hemen küçülmesi
beklenmez.

### NS-018 connection history okuma ve GUI akışı

```text
HistoryView (Qt main thread)
  -> HistoryQueryCoordinator (latest-generation, capacity-one handoff)
  -> one persistent query worker
  -> ConnectionHistoryQueryService
  -> ConnectionHistoryRepository port
  -> SQLiteConnectionHistoryRepository (query-owned connection)
```

History ekranı SQLite, DB path veya concrete adapter bilmez. Presentation yalnızca
`ConnectionHistoryQuery`, `ConnectionHistoryPage` ve immutable domain kayıtlarıyla
çalışır. Production composition, query worker içinde yaratılan application service
ve repository için bir factory sağlar. Repository her sorguda yalnızca o worker
thread'ine ait, kısa ömürlü bir read connection açar; NS-016 writer connection'ı
ile paylaşım yapılmaz. WAL ve busy timeout davranışı ortak `SQLiteDatabase`
factory'sinden gelir.

Sayfa boyutu 50'dir. Application service repository'den yalnızca bir look-ahead
satırı daha ister; böylece tüm tabloyu veya `SELECT *` ile count sonucu yüklemeden
`has_next` hesaplanır. Query limit'i her zaman NS-015 üst sınırının altındadır ve
offset kararlı repository sırasına uygulanır. Retention mevcut sayfayı boşaltırsa
view önceki geçerli sayfaya bounded sorgularla geri döner.

Coordinator uygulama çalışması boyunca tek daemon worker kullanır ve pending
istek kuyruğunu bir öğeyle sınırlar. Yeni filtre mevcut cancellation token'ını
işaretler, bekleyen eski isteği değiştirir ve yeni generation üretir. SQLite
adapter `set_progress_handler` üzerinden portable cancellation callback'ini
gözler. İptal gecikse bile yalnızca en yeni generation sonucu Qt queued signal
ile görünür state'i değiştirebilir. Signal payload'larında SQLite connection,
row veya exception bulunmaz.

Kapanışta önce yeni history query kabulü kapatılır, current/pending istekler iptal
edilir ve query worker bounded join ile durdurulur; ardından mevcut Qt engine
bridge detach ve monitoring/persistence shutdown sırası devam eder. Hata sinyali
yalnızca request ID taşır ve UI sabit, sanitize edilmiş mesaj gösterir. Timestamp
değerleri repository sınırına UTC-aware gider; kalıcı mikrosaniye hassasiyeti
korunur ve presentation bunları sistemin yerel timezone'unda formatlar.

## 10. NS-019 Windows network context sınırı

```text
Windows IP Helper API / GetAdaptersAddresses (read-only)
  -> WindowsNetworkAdapterSnapshot (infrastructure DTO)
  -> WindowsNetworkContextProvider (NetworkContextProvider portu)
  -> immutable NetworkContext (domain)
```

`NetworkContext`, ilk M4 kapsamı gereği yalnızca aktif IPv4 bağlamını taşır:
kararlı interface kimliği/index'i, güvenilmeyen display adı, portable interface
türü, canonical host adresi/subnet, nullable gateway, sıralanmış ve tekilleştirilmiş
DNS sunucuları ile UTC-aware observation zamanı. Bir Windows adapter'ında birden
fazla IPv4 adres varsa adres/subnet çifti başına bir context üretilir. IPv6 bu
taskta kasıtlı olarak kapsam dışıdır.

Fingerprint, versioned SHA-256 ile interface kimliği, canonical subnet ve nullable
gateway üzerinden türetilir. Güncel DHCP host adresi, interface display adı, DNS
seti ve observation zamanı fingerprint'e katılmaz; böylece aynı interface/ağ için
adres yenilemesi, ad değişimi veya DNS sıralaması context baseline'ını bölmez.
Subnet, gateway veya interface kimliği değişimi yeni ağ bağlamı üretir. Fingerprint
bir secret veya adli bütünlük imzası değildir.

Adapter her `get_contexts()` çağrısında Windows IP Helper API'yi yeniden okur;
cache, poller, worker, queue veya import-time I/O oluşturmaz. Yalnızca operasyonel
olarak `UP` interface'ler normalize edilir. Loopback context görünür kalır fakat
`is_default_capture_candidate=False` olur. PPP/tunnel ve bilinen VPN adları VPN;
bilinen Hyper-V/VMware/VirtualBox adları virtual olarak işaretlenir, ancak bu
sınıflandırma interface'i sessizce dışlamaz. Disconnected adapter'lar ve malformed
adresler atlanır; tek bozuk kayıt diğer context'leri düşürmez. Whole-read permission
ve platform hataları application katmanındaki sanitize edilmiş typed hatalara
dönüşür. Gateway ve DNS'in bulunmaması geçerli degraded metadata'dır.

Production source yerelleştirilmiş `ipconfig`, PowerShell veya netsh metni parse
etmez. Sadece `GetAdaptersAddresses` kullanır; socket, reverse DNS, paket capture,
aktif discovery, ARP gönderimi ya da yönetici yükseltmesi yoktur. NS-019 provider'ı
henüz `MonitoringEngine` veya presentation yaşam döngüsüne bağlanmaz. Capture
worker NS-020'nin; ARP/device registry ve UI ise sonraki M4 tasklarının kapsamıdır.

## 11. NS-020 packet capture sınırı

```text
NetworkContextProvider.get_contexts() (her start/probe öncesi güncel okuma)
  -> explicit PacketCaptureRequest(NetworkContext + bounded BPF filter)
  -> ScapyCaptureWorker
       -> ScapyCaptureBackend (lazy import, selected interface, promisc=False)
       -> one AsyncSniffer worker / store=False
       -> infrastructure-only raw packet callback
       -> immutable PacketObservation metadata
       -> bounded FIFO output queue (varsayılan 1024)
  -> future protocol parser/analysis consumer (NS-021 ve sonrası)
```

`application.ports.PacketCapture`, Scapy, Npcap, socket veya raw packet tipi
bilmeden capability probe, explicit start/stop, bounded drain ve portable health
snapshot sözleşmesini tanımlar. `PacketCaptureRequest` bir NS-019
`NetworkContext` nesnesi ve boş olmayan, kontrol karakteri içermeyen, en fazla
256 karakterlik filtre ister. Adapter interface veya subnet keşfetmez; provider'ı
her probe/start çağrısında yeniden okur. Aynı interface/fingerprint bulunamazsa
interface disappeared ve network changed ayrı sonuçtur. DHCP host adresinin aynı
fingerprint içinde değişmesi geçerlidir ve observation güncel context metadata'sı
ile üretilir. Loopback LAN capture için reddedilir; VPN ve virtual context'ler
yalnızca açık seçimle kullanılabilir.

Construction dormant'tır: Scapy importu, network read, socket ve worker yoktur.
Production backend Scapy'yi lazy yükler, Windows'ta Npcap/libpcap capability'sini
kontrol eder ve capture socket'ini explicit start yolunda senkron açar; böylece
driver, permission ve interface hataları worker thread içinde kaybolmadan typed,
sanitize edilmiş capability durumuna dönüşür. Backend Scapy 2.7 `AsyncSniffer`
yaşam döngüsünü `start`, non-blocking stop isteği, bounded join ve owned socket
close ile sarar. `start`/`stop` idempotenttir; stopping/running durumda ikinci
worker yaratılamaz. Stop önce callback kabulünü generation ile kapatır; eski veya
stop sonrası callback observation üretemez. Timeout sağlık durumunda görünürdür ve
worker gerçekten bitmeden restart yapılmaz.

Callback ham paketi hiçbir üst katmana taşımaz. Yalnızca interface kimliği/index'i,
network fingerprint, UTC-aware zaman, captured/original length, sınırlı link-layer
ve network-layer enum özeti üretir. Raw payload/body saklanmaz veya loglanmaz.
Malformed paket sayılır ve atlanır; sonraki paketler işlenmeye devam eder. Queue
dolduğunda en yeni observation `put_nowait` semantiğiyle düşürülür; capture thread'i
DB/UI/analysis beklemez. Duplicate observation'lar kasıtlı olarak korunur çünkü
ilerideki oran metriklerinde packet multiplicity anlamlıdır. FIFO sırası arrival
sırasıdır; worker restart'ında eski context'e ait drain edilmemiş observation'lar
sayaca eklenerek atılır ve context'ler karışmaz.

Capability nedenleri `permission_denied`, `dependency_unavailable`,
`interface_unavailable`, `network_changed` ve `transient_failure` olarak ayrılır.
Raw exception mesajı health/port/presentation sınırına geçmez. NS-020 henüz
`MonitoringEngine`, Qt bridge, DB, parser, device registry veya detector'a
bağlanmaz; bu task yalnızca güvenli capture sınırını kurar.

## 12. NS-021 güvenli ARP parser sınırı

```text
Scapy raw packet (yalnızca infrastructure callback scope'u)
  + NS-019 güncel NetworkContext
  -> NS-020 PacketObservation ortak metadata'sı
  -> defensive ARP parser
  -> PacketObservation.arp = immutable ArpObservation
  -> mevcut tek bounded capture queue
```

Parser yalnızca Ethernet üzerinde IPv4 ARP request/reply (`op=1/2`) kabul eder.
EtherType, hardware/protocol type, mevcutsa hardware/protocol adres uzunlukları,
sender/target MAC ve IPv4 alanları doğrulanır. MAC değerleri küçük harfli iki
nokta formatına, IP değerleri canonical IPv4 metnine çevrilir. Zero, broadcast,
multicast ve locally-administered MAC değerleri observation olarak korunur;
bunların cihaz kimliği veya güvenlik anlamı parser tarafından yorumlanmaz.

ARP detayları NS-020 ortak envelope'u içinde interface kimliği/index'i, network
fingerprint, UTC observation zamanı ve observation source ile birlikte taşınır.
Ham Scapy nesnesi, frame bytes veya payload domain/application sınırına geçmez.
Non-ARP paket parser açısından unsupported olup mevcut genel metadata akışını
sürdürür. Eksik, fazla uzun, geçersiz veya desteklenmeyen ARP alanı yalnızca o
paketi malformed sayar; capture worker mevcut diagnostic/sayaç yoluyla devam eder.
Parser state, device identity, registry, detector, persistence veya UI mantığı
içermez. Yeni worker veya ikinci queue oluşturulmaz.

## 13. NS-022 cihaz ve binding kayıtları

`DeviceRegistryService`, yalnızca NS-019 `NetworkContext` ile eşleşen NS-021
`PacketObservation.arp` sender alanlarını tüketir. ARP request/reply target alanı
cihaz kimliği sayılmaz; `0.0.0.0` probe sender'ı, zero/broadcast/multicast MAC
ve cihaz olmayan IPv4 sender adresleri kayıt oluşturmaz. Locally administered
unicast MAC geçerli gözlemdir. Uyumsuz interface/index/fingerprint typed hata
olarak reddedilir. Servis yeni worker, queue veya capture lifecycle oluşturmaz.

`DeviceIdentity` kimliği network fingerprint + canonical MAC'ten kararlı UUID
olarak türetilir; IP kimliğin parçası değildir. `IdentityBinding` aynı scope/MAC
ve sender IP için ayrı kararlı kimlik taşır. Farklı IP eski binding'i silmez;
aynı IP'nin farklı MAC ile gözlenmesi iki ayrı gözlem kaydı oluşturur ve bu
aşamada güvenlik hükmü üretmez. İlk kabul edilen gözlemin `first_seen` değeri
sabit kalır; `last_seen` yalnızca ileri UTC zamanla güncellenir. Eski paketler
state'i geriye götürmez. Public listeler MAC ve sayısal IPv4 sırasındadır.

`DeviceRepository` portunu `SQLiteDeviceRepository` uygular. Migration 003,
`devices` ve `device_bindings` tablolarını, scope/binding unique anahtarlarını
ve foreign key'i ekler. Her observation tek kısa transaction içinde iki upsert
yapar. Repository çağrı başına kendi migrated connection'ını açıp kapatır;
monitoring engine poller, UI veya capture callback'i içinde DB çağrısı
başlatılmaz. NS-024 inventory worker'ı bu servisi açıkça çağırır; NS-023
dedektörü de aynı servis üzerinden çalışır.

### NS-023 yeni cihaz olayı

`NewDeviceDetector`, mevcut `DeviceRegistryService` üzerinden portable ARP
observation tüketir. İlk kez açılan, kayıtlı cihazı olmayan her network
fingerprint için ilk **geçerli sender** ile monotonic saatli warm-up başlar
(varsayılan 60 saniye; `NewDeviceConfig` ile değişir). Bu sürede görülen
cihazlar mevcut repository'ye kaydedilir ve başlangıç envanteri sayılır; olay
üretmez. Süre dolduktan sonra ilk kez görülen canonical MAC için o fingerprint
içinde tek `NewDeviceDetected` üretilir. Sıfır saniye seçimi öğrenme penceresini
bilinçli olarak kapatır. Süreye packet timestamp'i değil, işleme anındaki
monotonic saat yön verir; eski/out-of-order observation state'i geri götürmez.

Detector bir context'e ilk erişiminde kayıtlı cihaz kimliklerini yükler.
Restart sonrası bunlar tekrar olay yaratmaz; kayıtlı cihazı olan context'te
ilk kurulum warm-up'ı yeniden başlamaz. Başlangıç import'u sırasında uygulama
yeniden başlarsa o ana dek kaydedilmiş cihazlar bilinir; henüz görülmemiş bir
sender yeni cihaz olarak değerlendirilebilir. Bu olay yalnızca doğrulanmamış
pasif gözlem (`severity=info`, `confidence=passive_observation`) anlamına gelir;
ARP spoofing/MITM veya kötü niyet hükmü değildir. Event fingerprint'i
rule/device ID'den türetilir; IP binding ve timestamp dedup kimliği değildir.
Olayın alert lifecycle/persistence'ı NS-028 kapsamındadır.

Invalid sender ve bağlam uyuşmazlığı registry'nin NS-022 kurallarıyla ele alınır.
Detector yeni worker, queue, capture başlangıcı, migration veya GUI bağlantısı
eklemez; mevcut tek consumer akışında açıkça çağrılır. Repository hatası typed
olarak yukarı çıkar ve kimlik detector'da biliniyor işaretlenmez.

### NS-024 Devices veri akışı

Composition root, `NetworkContextProvider`, `DeviceRepository` ve dormant
`PacketCapture` portlarını bir `DeviceInventoryService` factory'sinde birleştirir.
`DeviceInventoryCoordinator` tek worker thread'de bu servisi oluşturur. Worker
başlangıçta ve periyodik olarak aktif context'leri, kayıtlı cihazları ve her
cihazın en güncel en fazla 20 binding'ini okur. Pasif capture yalnızca kullanıcı
seçili ağda **Start passive capture** komutunu verdiğinde `arp` filtresiyle
başlar; worker mevcut bounded capture queue'sunu tüketir. `NewDeviceDetector`
aynı consumer içinde çalışır ve 60 saniyelik warm-up'ın tek sahibidir.

Worker yalnızca immutable `DeviceInventorySnapshot` ve portable info event'lerini
Qt sinyaliyle GUI thread'ine taşır. `DevicesTableModel`, network fingerprint +
canonical MAC'den türetilmiş cihaz ID'siyle satırları günceller; IP identity
değildir. Context değişiminde görünür tablo sıfırlanır, kaybolan context'in
cihazları güncel ağda gösterilmez. Seçim ve detay aynı stable ID ile eşlenir.
SQLite, Scapy ve Windows API çağrıları widget/model içinde yoktur. Kapanışta
koordinatörün komut kabulü durur, capture durdurulur ve worker bounded join ile
beklenir; gecikmiş Qt sinyalleri yaşam döngüsü kapanışından sonra işlenmez.

### NS-025 gateway identity baseline

Mevcut Devices inventory consumer'ı aynı bounded capture queue'dan gelen portable
`PacketObservation.arp` değerini `GatewayBaselineService`'e de verir. Servis
seçili `NetworkContext`'in interface/index/fingerprint bilgisini güncel
`NetworkContextProvider` sonucuyla karşılaştırır. Yalnızca context'in gateway
IP'sini sender olarak bildiren, zero/multicast olmayan unicast MAC gözlemi
baseline'a adaydır. Gateway IP yalnızca Windows context değerinden gelir;
ARP target alanından veya bağımsız discovery'den türetilmez.

`GatewayBaseline`, cihaz/binding geçmişinden ayrı bir beklenen kimlik
kaydıdır. İlk aday `learning` durumunda ve fingerprint kapsamında açılır. UTC
işleme saatiyle ölçülen varsayılan 60 saniyelik pencere ve en az iki uyumlu
observation sonrasında, arada çelişki yoksa `learned` olur. Bu otomatik durum
kullanıcı onayı değildir. Öğrenme sırasında farklı MAC görülürse otomatik
ilerleme durur. Öğrenilmiş veya doğrulanmış MAC tek farklı gözlemle değişmez;
farklı MAC `pending` aday olarak kalır. Yalnızca açık
`GatewayBaselineService.confirm` çağrısı gözlenmiş mevcut veya pending MAC'i
`verified` yapar. Bu task detector, alert, GUI komutu veya yeni worker eklemez.

`GatewayBaselineRepository` portunu `SQLiteGatewayBaselineRepository` uygular.
Migration 004, fingerprint başına tek baseline ve ilk gözlem/kullanıcı onayı
geçişlerinin UTC zamanlı geçmişini tutar. Her save kısa bir transaction'dır;
ilk görülme ve son görülme eski observation ile geriye gitmez. Restart'ta
öğrenme başlangıcı, çelişki, pending aday ve doğrulama durumu yüklenir.
Raw frame/payload veya Scapy nesnesi bu tablolara geçmez. Repository hatası
mevcut inventory consumer'ında izole edilir ve observation health sorununa
dönüşür; cihaz envanteri okunmaya devam eder.

### NS-026 IP-MAC ve gateway kimlik uyuşmazlığı

Mevcut inventory consumer'ı yeni sender binding'i kaydetmeden önce
`IpMacConflictDetector` ile aynı fingerprint/IP için en son kalıcı binding'i
okur. Aynı MAC, ilk 60 saniyelik binding ısınması, 120 saniyeden eski
binding, out-of-order observation, yanlış/güncelliğini yitirmiş context ve
gratuitous ARP olay üretmez. Gateway IP bu genel kuraldan hariçtir.
`GatewayMacChangeDetector`, NS-025'in güncel `GatewayBaselineService.get`
sonucunu kullanır: `learning` karar vermez; `learned` ve `verified` beklenen
MAC'leri farklı pasif sender MAC ile karşılaştırır. Pending aynı MAC tekrar
görülürse olay yinelenmez; beklenen MAC yeniden gözlendikten sonraki anlamlı
geçiş yeniden olay olabilir. Baseline değişimi hâlâ yalnızca NS-025
`confirm` komutuyla gerçekleşir.

İki detector da immutable `ArpIdentityConflictDetected` döndürür. Rule/reason,
fingerprint, IP, eski/yeni MAC, eski son görülme ve yeni gözlem UTC zamanı,
severity ve confidence taşınır. Tekil uyuşmazlığın confidence değeri `low`;
IP veya learned gateway severity `low`, verified gateway severity en fazla
`medium` olur; locally administered aday için `low` kalır. Bu bir saldırı
atfı değildir. Olaylar yalnızca `DeviceInventorySnapshot.identity_events`
alanında geçicidir; NS-028 öncesinde alert yaşam döngüsü veya kalıcılığı yoktur.
Yeni worker/queue/schema, packet payload veya GUI alert sunumu eklenmez.

### NS-027 ARP sinyal korelasyonu

`ArpAnomalyCorrelator`, aynı inventory consumer'ında NS-026 olaylarını ve
sonraki doğrulanmış ARP sender metadata'sını değerlendirir. Event fingerprint
ve network fingerprint sınırları korunur. İlk kimlik çelişkisi 2 puan alır;
aynı sender'ın pencere içindeki üç farklı UTC gözlemi 1, verified gateway
bağlamı 1, farklı hedeflerde gateway ve IP çelişkisi birleşimi 2 puan ekler.
Tekil verified gateway gözlemi bile `low` confidence kalır. Tekrar veya
birleşim `moderate` confidence üretir; severity kaynak NS-026 olayından alınır.
`ArpRiskAssessment`, kaynak olayı, puanı, her kuralın katkısını, sayısı en fazla
3 olan gözlem özetini ve UTC zamanlarını taşır; saldırı hükmü veya alert değildir.

Pencere 120 saniyedir. Monotonlaştırılmış UTC clock ile expired sinyaller
temizlenir; en fazla 512 sinyal ve sinyal başına son 3 zaman metadata'sı tutulur.
Kapasite dolarsa en eski sinyal atılır ve sayaç artar. Out-of-order/duplicate
UTC gözlemleri state'i geriye götürmez. Yeni bir çelişki veya confidence
geçişinde sonuç üretilir; her tekrar için sonuç üretilmez. Sonuçlar yalnızca
`DeviceInventorySnapshot.arp_assessments` içinde geçicidir. Yeni worker, queue,
SQLite tablo, GUI görünümü veya raw packet saklama eklenmez.

### NS-028 genel alert yaşam döngüsü

Mevcut inventory consumer'ı NS-023 `NewDeviceDetected` ve NS-027
`ArpRiskAssessment` çıktılarını `AlertService`'e verir. Assessment'ın severity,
confidence ve rule breakdown değerleri değiştirilmeden bounded `AlertEvidence`
olarak saklanır. NS-026 detector veya NS-027 korelatör yeniden çalıştırılmaz.
Ortak `AlertCandidate` portu MAC taşımayan sonraki detector'lar için de kısa,
yapılandırılmış kanıt alanlarını kabul eder; hassas/raw alan adları reddedilir.
Alert persistence başarısızlığı `DeviceInventoryProblem.ALERT_UNAVAILABLE`
olarak izole edilir; envanter ve detection devam eder.

Migration 005 `alerts` tablosunu ekler. Deterministik UUID, detector'ın
fingerprint'inden türetilir; `fingerprint` unique'dir. Kısa `BEGIN IMMEDIATE`
transaction aynı issue için yarışan yazıları seri hale getirir. Daha yeni
assessment son görülmeyi ve tekrar sayacını ilerletir; eski veya aynı UTC
timestamp tekrar sayılmaz ve yeni state'i ezmez. En çok son 8 kanıt özeti
saklanır. `open`, `acknowledged`, `resolved` kalıcıdır; yeniden gözlenen
resolved issue aynı kayıt üzerinde open olur. Onay, gateway baseline doğrulaması
veya detection confidence değişimi değildir. İlk olay ve confidence/severity
değişimi bildirim üretir; diğer güncellemeler 120 saniyelik rate limit'e uyar.
Alert sorguları üst sınırı 100 olan sayfalar ve parametreli typed filtrelerle
çalışır. SQLite bağlantıları her çağrıda açılıp kapatılır ve inventory worker'a
aittir; capture callback veya GUI thread'inde DB yazımı yoktur. NS-028 yeni
writer/queue, alert retention veya Alerts GUI eklemez.

### NS-029 Alerts ekranı

`AlertsView -> AlertsTableModel -> AlertQueryCoordinator -> AlertQueryService
-> AlertService -> AlertRepository port -> SQLiteAlertRepository` akışı yalnızca
kalıcı portable alert kayıtlarını okur. Sorgu servisi 50 görünür satır için
bir ek satır alarak `has_next` belirler; tabloyu veya `COUNT(*)` sonucunu
tümüyle yüklemez. Durum, önem, güven ve rule filtreleri typed `AlertQuery`
üzerinden parametreli SQL'e gider. Deterministik alert UUID, tablo satırının ve
seçimin kararlı kimliğidir; refresh sonrasında aynı kayıt seçili kalır.

Tek alert worker'ı bir pending sorgu ve en çok sekiz bekleyen kullanıcı komutu
tutar. Yeni sorgu önceki sorgunun cancellation token'ını işaretler; SQLite
progress handler iptali görür, generation kontrolü gecikmiş sonucu da dışlar.
Worker servis/repository'yi kendi thread'inde oluşturur; her SQLite çağrısı
bağlantısını orada açıp kapatır. Acknowledge komutu da aynı worker'da
`AlertService` üzerinden yürür ve başarı sonrası sayfa yenilenir. Kapanışta
yeni istekler reddedilir, pending işler temizlenir ve bounded join uygulanır.
Envanter snapshot'ındaki yeni cihaz veya risk assessment çıktısı yalnızca
yenileme tetikler; GUI detector veya puanlama yapmaz. Kanıt en son sekiz portable
özet olarak, yerel saat ve düz metinle sunulur; raw paket taşınmaz.

## 14. Detection yaklaşımı

Detectors üç girdiyi ayırır:

1. **Observation:** Ağdan veya işletim sisteminden doğrudan ölçülen veri.
2. **Baseline/context:** Öğrenilmiş veya kullanıcı tarafından doğrulanmış beklenen durum.
3. **Rule:** Observation ile baseline arasındaki farkı değerlendiren deterministik mantık.

Her çıktı en az rule ID, zaman, ilgili entity ID, severity, confidence ve yapılandırılmış evidence taşır. Aynı semptom kısa sürede tekrarlandığında alert storm yaratmamak için fingerprint tabanlı deduplication ve tekrar sayacı kullanılır.

Baseline ağ bağlamına özgüdür. Örneğin farklı Wi-Fi ağlarındaki gateway MAC adresleri birbirine karıştırılmaz. Ağ değişiminden sonra öğrenme/ısınma penceresi uygulanır.

## 15. Hata, saat ve kimlik stratejisi

- Persist edilen tüm zamanlar UTC'dir; interval ölçümü için monotonic clock kullanılır.
- DB entity'leri için UUID; tekrarlanabilir detector çıktıları için kararlı fingerprint kullanılır.
- Yetki reddi, interface kaybı, process'in snapshot sırasında kapanması ve malformed packet beklenen hata sınıflarıdır.
- Bir adapter hatası ilgili capability'yi degraded yapar; mümkünse diğer monitoring modülleri devam eder.
- Kullanıcıya gösterilen hata mesajı eyleme dönük, teknik log ise ayrıntılı olur.

## 16. Test stratejisi

- **Unit:** Domain, diff, parser, baseline ve detector kuralları; fake clock ile deterministik zaman.
- **Integration:** psutil çıktısı adaptasyonu, geçici SQLite DB ve migration/repository davranışı.
- **Packet fixtures:** Küçük, sentetik ve anonimleştirilmiş ARP/DNS/broadcast/VLAN paketleri.
- **GUI:** Fake engine ile table model, filtreleme, lifecycle ve smoke testleri.
- **Performance:** Event burst, queue backpressure, uzun history pagination ve shutdown süresi.
- **Windows smoke:** Yetkili ve yetkisiz mod, capture driver var/yok kombinasyonları.

Canlı ağ erişimi gerektiren testler varsayılan test suite'inde çalışmaz; açık marker ve kontrollü lab gerektirir.

### NS-019 Windows network context smoke testi

Varsayılan suite yalnızca injected adapter fixture'larıyla active/disconnected,
çoklu interface, loopback, VPN/virtual, eksik gateway/DNS, malformed kayıt,
deterministik sıralama, fingerprint ve typed hata davranışını test eder. Opt-in
`windows_live` testi yalnızca yerel Windows IP Helper yapılandırmasını salt-okur;
socket veya paket üretmez, dış hosta erişmez ve yönetici yetkisini önkoşul yapmaz.

### NS-020 packet capture test sınırı

NS-020 capture lifecycle testleri yalnızca fake context provider, fake backend,
fake sniffer ve sentetik metadata packet nesneleriyle lifecycle, duplicate/FIFO,
overflow, malformed isolation, stale context, capability sınıfları ve bounded
shutdown'ı doğrular; bu testler Scapy import etmez. Tam varsayılan suite içindeki
NS-021 parser testleri yalnızca in-memory sentetik Scapy packet'ları oluşturur;
gerçek network, capture socket'i, Npcap veya yönetici yetkisi gerekmez.
Opt-in `lab_live` testi yalnızca Windows ve açık `NETSENTINEL_LAB_CAPTURE=1`
onayıyla güncel default-candidate context üzerinde pasif filtered start/stop yapar.
Packet göndermez, ARP/ping/port taraması yapmaz ve trafik gözlenmesini beklemez.

### NS-021 ARP parser test sınırı

Varsayılan suite sentetik Scapy request/reply packet'ları ve küçük fuzz-benzeri
field fixture'ları kullanır. MAC/IP canonicalization, eksik/fazla uzun/geçersiz
alanlar, unsupported opcode/protocol, payload sınırı ve parser hatasından sonraki
paketin işlenmesi doğrulanır. Testler capture socket'i açmaz; Npcap, canlı LAN,
yönetici yetkisi, packet injection veya ayrı bir worker gerektirmez.

### NS-030 DNS parser sınırı

Mevcut NS-020 callback'i DNS'yi yalnızca infrastructure içinde okur ve aynı
bounded `PacketObservation` kuyruğuna immutable `DnsObservation` ekler. NS-019
network fingerprint'i ve UTC capture zamanı envelope'da kalır. Parser UDP/TCP
53 ve ayrı mDNS 5353 trafiğini, en fazla 4 soru ve bölüm başına 16 kayıtla
sınırlar; yalnızca A/AAAA/CNAME/PTR cevap metadata'sını taşır. Yakalanmış DNS
wire görüntüsü compression pointer ve uzunluk doğrulaması için callback içinde
incelenir, üst katmana veya veritabanına geçmez. Hatalı mesaj mevcut malformed
sayaç/typed diagnostic ile düşürülür; sonraki paket işlenir. NS-031 korelasyonu,
NS-033 kalıcılığı ve NS-034 ekranı bu parser'a dahil değildir. Varsayılan testler
yalnızca in-memory sentetik Scapy paketleri ve fake capture backend kullanır.
TCP için yalnızca capture'da tek parça ve uzunluğu tutarlı DNS mesajı parse edilir;
TCP stream reassembly bu taskın kapsamında değildir.

### NS-031 DNS transaction korelasyonu

`DnsTrackingService`, yalnızca `PacketObservation.dns` içindeki NS-030 portable
metadata'sını tüketir; Scapy veya DNS wire formatını tekrar işlemez. Klasik
DNS için anahtar network fingerprint, UDP/TCP transport, query yönünden
client/server IP ve portları, transaction ID ve canonical soru tuple'ıdır.
NS-030 soru modelinde qclass bulunmadığından anahtara eklenmez. mDNS bu
unicast işlem state'inden ayrı tutulur ve korelasyona alınmaz.

Tek consumer servis pending sorguları ve yakın tamamlanma izlerini ayrı,
konfigüre edilebilir sınırlar içinde tutar (varsayılan her biri 1024). İlk
query gözlem zamanı korunur; aynı veya daha eski timestamp duplicate sayılır,
daha yeni pending query retry sayacını artırır ve monotonic timeout'u yeniler.
Yanıt ilk uygun pending query'yi tamamlar; tamamlanan yanıtın aynı/eski
timestamp'li tekrarları kısa süreli iz ile bastırılır. Bu izden daha yeni
query yeni işlem açabilir. Soru bilgisi olmayan query korelasyon dışıdır;
soru bilgisi olmayan response unmatched olarak korunur.

Timeout ve latency işleme anındaki monotonic saatle hesaplanır; UTC packet
timestamp'i yalnızca sonuç metadata'sıdır. Yanıt timestamp'i query'den eskiyse
yanıt unmatched kalır ve pending state değişmez. Expiry için deadline heap'i,
kapasite için en eski pending ekleme sırası kullanılır; önce expired kayıtlar
temizlenir. Retry kaynaklı eski heap girdileri periyodik yeniden kurularak
bounded kalır. `completed`, `timed_out`, `evicted` ve `unmatched_response`
immutable sonuçları çağıran consumer'a senkron döner. Servis worker, socket,
SQLite veya GUI nesnesi oluşturmaz; DNS history entegrasyonu NS-033 kapsamıdır.

### NS-032 Windows DNS sunucusu seti değişimi

`WindowsNetworkContextProvider.get_contexts()` mevcut read-only
`GetAdaptersAddresses` adapter'ından her engine turunda güncel, canonical
IPv4 DNS setini sağlar. `DnsConfigMonitoringService` bu portu mevcut engine
worker'ında poll eder; ayrı thread, timer, socket veya paket yakalama başlatmaz.
Whole-read veya alert storage hatası sanitize `DNS_CONFIG_UNAVAILABLE`
diagnostic'ine dönüşür, connection poll devam eder.

`DnsServerBaselineService` network fingerprint başına memory-only state tutar.
İlk set iki sıralı okumayla öğrenilir. Yeni setin iki ardışık, ileri UTC ve
monotonic zamanlı okumada görünmesi `DnsServerChange` kanıtı üretir. Boş,
başarısız veya çelişkili snapshot pending doğrulamayı keser; DNS sırası zaten
`NetworkContext` sınırında canonical set'e dönüşür. Stale/out-of-order okuma
state'i ilerletmez. En çok 256 context tutulur; en eski kullanım kapasite
dolunca atılır, 24 saat kullanılmayan state temizlenir. Context fingerprint'i
interface/subnet/gateway değişiminde ayrılır; eski context tekrar gelirse
aynı baseline kullanılabilir. Tek boş okuma beklenen seti silmez.

`DnsConfigChangeDetector` yalnızca doğrulanmış portable değişimi mevcut
`AlertCandidate` ve bounded `AlertEvidence.details` alanlarına çevirir. Rule
`dns_server_set_change`, severity `low`, confidence `moderate` olur; eski/yeni
set, ilk görülme, interface türü ve tekrar kanıtı taşınır. `AlertService`
mevcut SQLite dedup/lifecycle hattını kullanır; DNS baseline, query history,
raw packet veya payload kalıcılaştırılmaz. Alert yazımı başarısızsa baseline
değişimi commit edilmez ve sonraki poll yeniden denenebilir. NS-030/NS-031
DNS packet/transaction hattı bu config detector'ına girdi değildir.

### NS-033 DNS history repository ve retention

`DnsTrackingService` tarafından üretilen immutable `DnsTransaction`, UUID kayıt
kimliğiyle `DnsHistoryRecord` içine alınır. Application portu SQL bilmez.
`DnsHistoryWriter.submit` sabit kapasiteli FIFO kuyruğa `put_nowait` uygular;
tek writer worker kendi SQLite bağlantısını açıp bounded batch transaction'ları
yazar. Batch başarısızsa kayıtlar tek tek denenir; retry sayısı sınırlıdır ve
sağlık sayacında drop/failed/retry görünür. Capture consumer DB için beklemez.

Migration 006 yalnızca klasik DNS transaction metadata'sını saklar. İlk soru adı
ayrı indekslenir; tüm sorular (en çok 4) ve desteklenen cevaplar (en çok 16)
bounded JSON alanlarında canonical biçimde kalır. Query sözleşmesi zorunlu
`limit <= 500`, offset, UTC event zamanı, ağ fingerprint'i, qname, DNS sunucusu,
durum ve transport filtrelerini destekler; sıralama `event_at_utc_us DESC,
id DESC` ile deterministiktir. Event zamanı sorgu zamanı, eşleşmeyen yanıtta
yanıt zamanıdır. Timestamp'ler UTC Unix mikrosaniyesidir; latency mikrosaniye
integer olarak yazılır. Aynı UUID ve aynı içerik yeniden yazılırsa no-op;
farklı UUID'ler aynı DNS transaction ID'yi paylaşsa da ayrı kayıttır.

DNS'e özel manuel retention önce tam cutoff'tan eski kayıtları, sonra toplam
satır limitini aşan en eski kayıtları 500 veya yapılandırılmış daha küçük
chunk'larla temizler. Her chunk ayrı kısa transaction'dır; pending correlation
state'i restart'ta restore edilmez. Repository read ayrı bağlantı açar.
NS-034 DNS ekranı ve canlı akış bağlantısı aşağıdaki akıştır.

### NS-034 DNS ekranı ve M6 akışı

```text
Kullanıcının Devices üzerinde başlattığı pasif capture (arp or port 53)
  -> NS-030 portable DNS observation -> NS-031 DnsTrackingService
  -> NS-033 DnsHistoryWriter bounded nonblocking queue -> SQLite DNS history
  -> DnsHistoryRepository port -> DnsHistoryQueryService (50 + 1)
  -> DnsQueryCoordinator tek worker -> Qt ana thread -> DnsTableModel/DnsView
```

M6 canlı hattı mevcut tek inventory/capture consumer'ını paylaşır. Yalnızca
klasik DNS transaction sonucu writer'a verilir; query henüz sonuç üretmez,
completed/timeout/evicted/unmatched sonuçları aynı servis semantiğiyle saklanır.
Writer worker kendi SQLite bağlantısını açar ve inventory kapanışında capture
durduktan sonra bounded biçimde kapanır. DNS görünümü capture kapalıyken de
kalıcı geçmişi okuyabilir. Writer persisted sayacı değiştiğinde en fazla
inventory snapshot hızıyla coalesced refresh yapılır; paket başına sorgu yoktur.

Sorgu worker'ı tek capacity-one pending istek, generation ve cooperative SQLite
progress cancellation kullanır. Sorgu/SQLite/UI hata ayrıntıları Qt signal'ına
taşınmaz. Sayfalama `event_at_utc_us DESC, id DESC` sırasını kullanır;
`DnsHistoryRecord.id` seçim kimliğidir. İlk soru türü `questions_json` üzerinde
parametreli JSON extract ile filtrelenir; status, ad, sunucu ve UTC-aware zaman
filtreleri de repository'de uygulanır. Detay yalnızca bounded portable metadata
gösterir. DNS config değişimi bağlantısı, NS-032'nin mevcut Alerts rule filtresine
gider. İlk açılıştaki eşzamanlı DB worker'ları için WAL kurulumu ve migration
kontrolü süreç içinde serileştirilir; sorgu bağlantıları worker'a aittir.

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

## 17. Bilinen teknik sınırlamalar

- psutil snapshot tabanlı polling, iki tur arasında açılıp kapanan çok kısa bağlantıları kaçırabilir.
- Windows ve psutil, standart kullanıcıya bazı system-wide connection satırlarının
  PID bilgisini göstermeyebilir veya tablo erişimini tamamen reddedebilir.
- Process adı/create-time sorgusu izin nedeniyle kısıtlanabilir ya da process'in
  snapshot ile metadata sorgusu arasında kapanması sonucu unavailable olabilir;
  bu durum connection görünürlüğünü düşürmeden degraded metadata olarak modellenir.
- UDP satırları gerçek bir “oturum” değil, işletim sistemi endpoint görünümüdür.
- Paket ile PID/process arasında her durumda güvenilir bire bir ilişki kurulamaz.
- Capture sonucu kullanılan driver, interface ve Windows güvenlik politikasına bağlıdır.
- Capture capability probe socket açmadığı için gerçek permission/driver açma hatası
  explicit `start` sırasında kesinleşebilir; bu hata yine typed degraded duruma çevrilir.
- NS-019 ağ fingerprint'i interface/subnet/gateway metadata'sına dayanır; aynı
  interface üzerinde bu üç değeri de paylaşan farklı fiziksel ağları tek başına
  kesin ayırt etme garantisi vermez. IPv6 network context ilk M4 kapsamı dışındadır.
- Switch'li ağda bilgisayara ulaşmayan unicast trafik gözlenemez.
- VLAN tag'leri NIC offload/driver nedeniyle capture noktasında kaldırılmış olabilir.
- Şifreli DNS (DoH/DoT) klasik DNS parser'ıyla içerik düzeyinde görünmez.

Bu sınırlamalar UI ve kullanıcı dokümantasyonunda saklanmaz; yanlış güven hissi yaratmamak ürün gereksinimidir.

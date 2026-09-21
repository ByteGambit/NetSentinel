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

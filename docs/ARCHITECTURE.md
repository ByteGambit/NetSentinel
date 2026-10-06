# Mimari

NS-099 native kabulde retention Save sonrası Diagnostics'in eski preference
göstermesi düzeltildi. StoragePrivacyDialog, yalnız successful worker sonucu için
Qt signal yayınlar; composition bunu Diagnostics'in cached immutable config'ini
yenilemesine bağlar. Dialog kapanışında deleteLater kullanılır. Domain, repository,
storage worker, network ve schema değişmez; GUI thread'ine DB/file işi taşınmaz.
Committed runtime fix, temiz build provenance ve native OFF/ON retest
[kabul raporunda](PUBLIC_BETA_ACCEPTANCE.md).

NS-098 onboarding acknowledgement config'tedir: bounded completed/dismissed
version, legacy bool compatibility, atomic save ve current-settings reload.
Presentation yalnız informational pages, existing capability coordinator,
stable PageId/actions ve NS-095 StoragePrivacyDialog feedback mode ekler.
Export service/repository/allowlist/bytes aynı kalır; Qt full sanitized bytes'ı
plain text gösterir. DB/file export ve cancellation mevcut tek worker'ındadır.
Credential readiness composition'dan sanitized status olarak gelir; rehber
secret/providera erişmez. Yalnız explicit project-button browser navigation vardır.
Domain/infrastructure/dependency/migration değişmez; SQLite 019→019.
[Sözleşme](FIRST_RUN_FEEDBACK.md).

NS-097 yalnız packaging/release security design ve standalone offline
`packaging/verify_release.py` ekler; `src/` katmanlarına import/call/network hook
eklemez. Streaming SHA256, strict bounded final-release manifest validation ve
optional bounded Windows PE-version subprocess vardır. Integrity ve signature
trust ayrıdır: script signature NOT_CHECKED, signed assertion ayrı verification
gerektirir. Build/sign/publish separation, generated Inno program signing ve
final-hash-after-signing future release target'tır; current builder unsigned kalır.
Schema 019→019, migration yok. [Dağıtım sözleşmesi](SIGNING_UPDATE_DISTRIBUTION.md).

NS-096 ortak `shared.paths.user_data_paths` SQLite/config/log için mevcut
per-user AppData politikasını merkezileştirir. Resource lookup package API'lerinde
kalır; dev/portable/installed aynı veri kökünü kullanır. Packaging entry Windows
mutex adapter'ını writer'lardan önce başlatır; maintenance-only uninstall helper
Qt/domain/SQLite başlatmaz. Inno offline/per-user program deploy ve owned-file
inventory prune yapar; schema/consent/config yazmaz. DELETE trusted Windows user
folder + canonical root + reparse preflight ve stopped-desktop gate gerektirir.
Schema 019→019. ISCC 6.7.3 gerçek build/payload/PE/SHA256 doğrulaması geçti;
native per-user lifecycle/Unicode VM kabulü ve son kalite kapıları PASS, task COMPLETE.
Mevcut VM'de yeni standart profiller kullanıldı; pristine OS snapshot yoktu.
0.1.1 installer fixture payload'ı 0.1.0 kaldı. Host wizard App Control 4551 ile blocked;
[sözleşme ve sınırlar](INSTALLER_UPGRADE_UNINSTALL.md).

NS-095 typed StorageRetentionPolicy/StoreRetentionRule → blocking
StoragePrivacyService → StorageMaintenanceRepository → SQLite adapter sınırını
ekler. Tek portable worker, bir pending veya active komut, coarse opt-in timer,
scoped confirmation token ve immutable sanitized export preview kullanılır.
Bootstrap lazy worker compose eder; ApplicationLifecycle start/2s stop sağlar.
Settings → Storage & Privacy Future sonuçlarını Qt timer ile alır; DB/config/file
işleri GUI dışında kalır. Her cleanup BEGIN IMMEDIATE altında protection'ı
yeniden değerlendirir, gerçek owned cascade satırlarını budget'a dahil eder.
2s runtime/16 chunks/2048 deletes, 100ms busy/setup-lock timeout ve SQL progress
handler vardır; store failure izole, committed chunk receipt korunur. Final
counts deadline içinde okunamazsa unavailable, protected-only pressure açık olur.
Alert reference set'i uncorrelated JSON projection; active lifecycle probe mevcut
index'i kullanır. Parent/revision quota eviction aynı guard'ı kullanır. Baseline
ve VLAN capacity artık current/user state'i körlemesine evict etmez.
No global writer redesign, schema 019→019, migration yok. Raw support export,
network/upload veya generic trust/preference reset yoktur.
[Store/retention/purge/export matrisi](STORAGE_PRIVACY.md).

NS-094 commit sonrası portable `PersistedNotificationIntent` → immutable policy
ve `NotificationDeliveryService` → Qt thread sink → stable-ID worker query
navigation akışını ekler. Legacy AlertService ve risk/suppression pipeline aynı
engine dispatcher'ına bağlanır. Producer yalnız portable locked queue'ya yazar;
bir GUI timer saniyede bir intent drain eder. Queue 32, subject state 512/session,
Qt immutable click sources 8/600 s; overflow/failure typed ve aggregate'dir.
Runtime cooldown 120 s monotonic; severity yükselişi bypass, düşüş/skor/ACK/resolve
skip. Default disabled/LIMITED, no startup/backlog replay; SQLite 019 ve eski
migration'lar değişmez. Exact ID detail query mevcut alert worker'ında, filtre ve
pagination'dan bağımsızdır. `last_notified_at` intent watermark'dır, submission
veya OS display proof değildir. [Frozen policy ve adapter tradeoff](DESKTOP_NOTIFICATIONS.md).

NS-093 `ApplicationController` yalnız window visibility/close policy/Qt quit ve
tray cleanup koordine eder; engine/worker ownership `ApplicationLifecycle`'da
kalır. `QtTrayAdapter` QSystemTrayIcon capability/menu/activation sınırını
kapsüller; offscreen fake adapter aynı sınırı kullanır. X hide event'i ignore
eder ve shutdown çağırmaz. Tray unavailable/init failure quit fallback, runtime
capability loss visible recovery yapar. Qt Quit event'i closeEvent'ten önce
quitting flag'i koyar; aboutToQuit/finally aynı guarded shutdown yoludur.
Fatal engine start rollback de aynı shutdown guard'ını kullanır; shutdown sonrası
start yoktur. Shared typed config dışında domain/infrastructure değişmedi,
SQLite 019 aynı kaldı. [Frozen policy, lifecycle ve smoke](TRAY_APPLICATION_LIFECYCLE.md).
Aşağıdaki teslimat kayıtları tarihseldir.

NS-092 acceptance-only doğrulaması M16'yı tamamlar. Gerçek polling/feature/baseline
→ risk worker/assessment/AlertService → explicit incident persistence → worker
timeline/GUI sınırları offline sentetik hikâyeyle test edilir. DNS ambiguity ayrı
context kalır; otomatik incident producer veya DNS-process attribution eklenmez.
Restart/dedup/loss/retention, inclusive reopen ve fixed UTC bucket semantics
korunur. Accelerated soak 256 runtime/1024 durable parent, 128 relation, 32 retained
revision, 16.383/16.384 index membership ve 256 GUI row sınırını ölçer; long query
11 sayfada 55 SELECT yapar. Şema **019 → 019**, production değişikliği yoktur.
Full offline 3365 passed/8 deselected; [ölçümler, sınırlamalar ve M16 exit](INCIDENT_ACCEPTANCE_SOAK.md).
NS-093 başlatılmadı. Aşağıdaki önceki task teslimat kayıtları tarihseldir.

NS-091 `IncidentTimelineQueryService` / `IncidentTimelineRepository` read port,
`SQLiteIncidentTimelineRepository` coherent read transaction ve Incidents GUI
sayfasını ekler. Ayrı list/detail latest-slot workers DB reads/factory'yi GUI
dışında çalıştırır; selected assessment yalnız gerektiğinde NS-083 risk paneline
bağlanır. Original observation, exact assessment, lifecycle action ve persistence
times ayrıdır; inference computation time kayıtlı değilse observation anchor
olarak açıklanır. UUID list keyset, semantic total-order timeline cursor ve
revision/source-state token mixed pages'i önler. Source resolution batch; default
25/max 100 page, one list page ve 256 loaded timeline row sınırı vardır. Unknown,
expired/unavailable, corrupt ve unsupported source açıklaması retained snapshot
ile kalır; process/destination context per-observation ilişki gibi uydurulmaz.
Read-only: engine subscription, commands, reassessment, TI lookup, graph veya
process-created inference eklenmedi. Schema **019 → 019**, migration yok.
[Timeline sözleşmesi](INCIDENT_TIMELINE_UI.md),
[NS-091 kabul raporu](INCIDENT_TIMELINE_ACCEPTANCE.md). M16 devam ediyor;
NS-092 başlatılmadı. Aşağıdaki önceki teslimat kayıtları tarihseldir.

NS-090 `IncidentPersistenceService` / `IncidentRepository` / `SQLiteIncidentRepository`
explicit worker-owned blocking boundary ile stable incident UUIDv5, independent
OPEN/ACKNOWLEDGED/RESOLVED lifecycle, bounded append ve immutable revision events
saklar. Reopen action → OPEN; 5-minute inclusive UTC horizon ve NS-089 fixed-cohort
membership birlikte gerekir. Short atomic transactions, expected revision,
128 KiB current snapshot, 2 KiB reference/event, 1024 incidents/32 revisions ve
retention-safe lazy source states vardır. Restart matching en fazla 256 exact-cohort
candidate okur; unknown continuity derived links'i durdurur. Engine subscription,
GUI/timeline veya alert cascade eklenmedi. SQLite **018 → 019**; 001–018 değişmez.
[Persistence sözleşmesi](INCIDENT_PERSISTENCE.md),
[NS-090 kabul raporu](INCIDENT_PERSISTENCE_ACCEPTANCE.md). M16 devam ediyor;
NS-091/092 planlandı. Aşağıdaki NS-089 teslimat kaydı tarihseldir.

NS-089 `IncidentCorrelator`, explicit synchronous application boundary olarak
canonical observation/entity/evidence pointers ile bounded memory grouping sağlar.
Tek lock; immutable snapshot; 10-minute UTC cohort/span, inclusive lateness,
typed gap/quality ve atomic reference/index caps vardır. Same IP/PID-only/app
tek başına relation değildir; process-created inference yoktur. Connection,
generic evidence ve historical assessment adapters existing IDs/original time'ı
korur; engine/detector subscription veya worker eklenmedi. Persistence/lifecycle,
GUI/timeline ve forensic graph yoktur; schema 018 değişmez. NS-090 başlamadı.
[Policy freeze](INCIDENT_CORRELATION.md), [NS-089 kabul raporu](INCIDENT_CORRELATION_ACCEPTANCE.md).

NS-088 `ThreatIntelEvidenceAdapter`, explicit scheduler sonucunu generic
THREAT_INTELLIGENCE / threat_intelligence_reputation_context evidence ve küçük
typed provenance'a dönüştürür. HIT/NO_HIT informational, sıfır puanlıdır; numeric
scoring policy v1 değişmez. Mevcut RiskAlertWorker, canonical lifecycle + exact IP
ile yalnız mevcut assessment'a revision ekler; AlertService REASSESSMENT count,
last_seen, observed_at, ACK/RESOLVED ve fingerprint'i korur. No target → cache/UI
context only. Yeni worker/table/migration yoktur; SQLite 018. TI snapshots mevcut
kolonda format 2, local-only format 1; v1 canonical hashes/reads korunur.
Connections explicit action memory ticket'ı bounded Qt timer ile okur; selection
epoch late render'ı düşürür. NS-083 shared query/panel tarihi provider/freshness
snapshot'ını cache/network okumadan gösterir. Credential backend unavailable kalır.
[NS-088 mapping, privacy ve kabul raporu](THREAT_INTELLIGENCE_EVIDENCE.md).
Aşağıdaki önceki NS teslimat kayıtları kendi teslim tarihinin kapsamını anlatır.

NS-087 `ThreatIntelLookupScheduler`, single explicit query admission → worker
cache-first → provider port → bounded retry/put → shared pollable completion
yolunu kurar. 64 outstanding job, 4 worker; provider başına 16 job/1 call/1 s local
interval, en çok 3 attempt ve 300 s Retry-After. Consent memory snapshot Save/current
sonrasında revoke bildirimiyle güncellenir; her dispatch/retry tekrar kontrol eder.
Bootstrap dormant AbuseIPDB/cache/consent composition sağlar; ApplicationLifecycle
optional start/2 s toplam join ile stop eder. Secret backend default unavailable,
explicit port injection mümkündür. Startup/selection/engine/consent Save lookup
üretmez. Shared diagnostics yalnız aggregate counters taşır; GUI/engine I/O
beklemez. Schema **018**, migration yok; NS-088 risk/UI başlamadı.
[Scheduler sözleşmesi ve kabul raporu](THREAT_INTELLIGENCE_SCHEDULER.md).

NS-086, explicit composition için synchronous AbuseIPDB API v2 CHECK adapter'ı
ve bağımsız injected HTTP transport ekler. IP-only descriptor; mevcut application
consent/secret portları korunur. Fixed HTTPS, verified TLS, redirect/retry yok,
8 s socket timeout ve 64 KiB response cap vardır. Typed IP facts ve rate hints
result contract **2**'dir; SQLite cache codec **2** yalnız minimum facts'i saklar,
operational metadata/errors'ı saklamaz. Schema **018** değişmez. Cache key'deki
result_version mapping v1'i izole eder; v1 key/codec yeniden yorumlanmaz.
NS-086 teslimatında desktop composition değişmedi; güncel scheduler yukarıdaki NS-087'dir.
[Provider kararı, privacy ve sınırlar](THREAT_INTELLIGENCE_PROVIDER_ABUSEIPDB.md).

NS-085 local reputation cache backend'ini ekler: immutable canonical
provider/data-type/subject/algorithm/result-version key, ayrı provider status ve
cache freshness, absolute UTC horizons, blocking application port/service ve
lazy SQLite adapter. Schema **018**, append-only `018_threat_intel_cache.sql`;
001–017 değişmez. RAM front cache/preload yoktur; 1024 row/4 KiB snapshot ve
128-row cleanup/purge transaction bounds vardır. Conditional newest-fetch upsert
ve expired→stale→oldest-fresh eviction atomiktir. Runtime provider/scheduler/UI
ve risk integration eklenmez; [NS-085 sözleşmesi](THREAT_INTELLIGENCE_CACHE.md).

NS-084 provider-independent TI contract ve pure consent policy'yi ekler. Application
single-subject lookup service yalnız current provider/data-type/manual consent ve
external-eligible subject sonrası provider portunu çağırabilir; desktop/engine bu
service'i henüz compose etmez. Ayrı secret port yalnız gelecekteki adapter içindir.
Settings consent dialog'u yalnız local JSON config okuma/kaydetme boundary'sini
kullanır; dialog provider, secret veya network erişmez. NS-084 teslimatında production
registry boştu; NS-087 desktop registry AbuseIPDB IP descriptor'ını ilan eder.
[Port tasarımı ve karar tabloları](THREAT_INTELLIGENCE_CONSENT.md).

NS-083 Alerts/Connections ortak `RiskExplanationQueryService` → immutable bounded
read model → plain-text panel yolunu ekler. İki yüzeyde ayrı latest-slot query
worker, factory/SQL reads'i GUI dışında çalıştırır; generation ve aynı-seçim dedup
geciken sonuç/query storm'u engeller. Alert exact linked revision; connection exact
lifecycle için latest retained revision kullanır. SQLite adapter mevcut PK ile
exact read, en çok 512 size-gated identity ile lifecycle lookup yapar; migration yok.
Stored score/freshness/policy asla yeniden hesaplanmaz. Current source availability
ayrıdır. Risk worker en çok 32 session-only suppression explanation tutar; cache
salt-okunur query'de güncellenmez ve restart'ta temizlenir. Historical suppression
olmaması ile current matching preferences ayrı ve açık gösterilir; baseline numeric
metrics format v1'de yoksa uydurulmaz. Her worker bounded shutdown ve destroyed-widget
guard taşır. Şema 017, diagnostics değişmez. [NS-083 ve M14 exit](RISK_EXPLANATION_UI.md).

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

NS-048, `onboarding_completed` bool değerini merkezi config sözleşmesinde
alan bazlı doğrular ve Finish sırasında atomik dosya değişimiyle saklar.
İlk açılışta tek QApplication/MainWindow composition oluşturulur; MainWindow
rehber bitene kadar gizlidir ve `ApplicationLifecycle.start()` yalnız Finish
sonrası çağrılır. Tek `CapabilityCoordinator` worker'ı NS-020 salt-okunur probe,
NS-019 context ve NS-047 diagnostics snapshot'ını toplar; Qt'ye yalnız portable
matrix sinyali yollar. Retry istekleri generation ile birleştirilir, eski
sonuçlar atılır. DB ölçümü GUI thread'inde yapılmaz; yeni SQLite migration
veya otomatik capture yolu yoktur.

NS-047 `shared.config` içinde immutable, bounded runtime ayarları ve alan bazlı
yükleme sonucu sağlar. Composition root bu değerleri mevcut engine, capture,
history ve DNS writer'larına geçirir. Log biçimleyici yalnızca izinli dört
alanı serileştirir; serbest metin veya exception'ı hiç işlemez. Merkezi
`DiagnosticsSnapshot`, mevcut portable sağlık snapshot'larını ve history
storage diagnostics sonucunu birleştirir. Bu toplama eşzamanlı DB ölçümü
içerdiğinden GUI thread'inde çağrılmaz; yeni worker, queue veya DB şeması
oluşturmaz. Capture başlatma hâlâ kullanıcının açık eylemine bağlıdır.

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

`ConnectionTrackingService` bir turu `COMPLETE` veya `REDUCED` quality ile işler; collector/engine hatası `FAILED` round gözlemi üretir ve active state'i değiştirmez. İlk tam tura kadar görülen bağlantıların `ConnectionOpened.origin` değeri `INITIAL` olur: bunlar monitoring sırasında açıldığı iddiasını taşımaz ve yeni bağlantı istatistiğine girmez. İlk tam turdan sonra ilk kez görülenler `OBSERVED` olur. `ConnectionKey` eşleşmesi korunurken state veya process metadata'sı değişirse `ConnectionUpdated`; yalnızca tam turda yokluğu doğrulanan anahtar için `ConnectionClosed(reason=NOT_OBSERVED)` üretilir. Eksik turda yokluk close kanıtı değildir. Yalnızca observation timestamp'i ilerleyen, diğer gözlemlenebilir alanları aynı kalan bağlantı event üretmez; buna rağmen `last_seen` ilerletilir.

NS-056: Her monitoring run bir UUID session ID, her izlenen connection occurrence ayrı UUID lifecycle ID taşır. Bu kimlikler `ConnectionKey` veya SQLite record ID değildir; NS-058 ile yeni history satırlarında kalıcı yazılır. Restart'ta tracker session/state sıfırlanır. Psutil adapter atlanan satırları `REDUCED` kalite ve aggregate kayıp sayısı olarak bildirir. Tracker en fazla 4096 active key tutar; kapasite dolduğunda mevcut lifecycle'lar önceliklidir, yeni adaylar kanonik key sırasıyla seçilir. Kayıp veya eksik turda unutulan key kapandı varsayılmaz. `ConnectionRoundObservation` yalnız session, UTC round zamanı, quality ve sayıları taşır; exception metni veya bağlantı metadata'sı taşımaz. Engine health reduced/gap/loss sayaçlarını ve sanitize edilmiş diagnostic kodunu sunar. Close `occurred_at`, gap sonrası ilk tam gözlem zamanıdır; gerçek kapanma anı iddiası değildir. Rolling poll süresi monotonic clock ile ölçülür.

Aynı `ConnectionKey` bir turda birden fazla kez gelirse en yeni `observed_at` seçilir. Timestamp eşitliğinde daha kullanılabilir process metadata'sı, ardından kanonik state/metadata sırası tercih edilir. Böylece duplicate çözümü ve event sırası input sırasından bağımsızdır. Process adı ve availability kimlik değildir; bunların değişimi update'tir. PID ile birlikte create-time değişirse `ProcessIdentity` ve dolayısıyla `ConnectionKey` değişir; eski anahtar görünmedi olarak kapanır ve yenisi açılır.

Event'ler `OPENED`, `UPDATED`, `CLOSED` grupları halinde ve her grup içinde kanonik `ConnectionKey` sırasıyla döner. Open/update olayları kaynak snapshot'ın observation timestamp'ini korur. Close zamanı yeni gözlem turunun zamanıdır; bu olay TCP FIN/RST gözlemlendiğini veya UDP oturumunun protokol seviyesinde kapandığını iddia etmez.

### Paket gözlemi

- `PacketObservation`: ortak capture metadata'sı; interface, capture zamanı, link/network katmanı özeti ve yakalanan uzunluk.
- `ArpObservation`: opcode, sender/target IP ve MAC bilgileri.
- `DnsObservation`: transaction ID, yön, soru ve normalize edilmiş cevap kayıtları.
- `BroadcastObservation`: L2/L3 broadcast türü ve sayaç sınıflandırması.
- NS-035 `BroadcastObservation`, mevcut `PacketObservation.broadcast` alanında
  Ethernet frame'i başına tek bir sınıf taşır: ARP, L2 broadcast, IPv4 limited/
  seçili subnet'e directed broadcast, multicast veya unicast. ARP frame'i L2
  broadcast olsa da sayaç sınıfı yalnızca ARP'dir; ek `ethernet_broadcast`
  bayrağı gözlemi açıklar fakat ayrı bir sayım anlamına gelmez. Sınıflandırıcı
  Scapy callback'inde mevcut ARP/DNS parser'larının yanında çalışır; aynı
  bounded queue, interface, network fingerprint ve UTC zamanını kullanır.
  NS-036 bu portable sınıfı mevcut consumer içinde oran/baseline servisine verir;
  detector ve dashboard sonraki tasklardadır.
- `VlanObservation`: 802.1Q VLAN ID, öncelik alanları ve kapsüllenmiş protokol bilgisi.

NS-043 `ScapyCaptureWorker` callback'inde Ethernet için aynı `PacketObservation`
zarfına immutable `vlan` alanı ekler. `untagged` yalnızca capture'da görünen
Ethernet frame'ini belirtir; Ethernet dışı input `vlan=None` kalır. Tekli 802.1Q
etikette VID 0 priority-only, 1–4094 normal, 4095 reserved olarak ayrılır.
`stacked` yalnızca dış etiketin VID/PCP/DEI ve iç etiket EtherType'ını taşır;
iç tag parse edilmez. Etiketli frame'ler, untagged EtherType varsayan mevcut
ARP/DNS/broadcast parser'larına gönderilmez. Malformed tag mevcut capture
malformed sayacı ve sanitized diagnostic yoluyla tek frame olarak düşürülür.
NS-043 parser aşaması yeni worker, queue, state, repository veya alert hattı eklemez.
NS-044 aggregate ve SQLite baseline'ı, NS-045 detector'ı, NS-046 UI entegrasyonunu ekler.
NIC offload/driver VLAN tag'ini capture öncesi kaldırabilir ve BPF filtreleri
tagged frame'i dışlayabilir; tag yokluğu güvenilir ağ yokluğu ölçümü değildir.

### NS-044 VLAN gözlem özeti

Mevcut inventory consumer, `PacketObservation.vlan` alanını senkron
`VlanSummaryService`'e verir. Kapsam fingerprint + casefold interface ID +
interface index'tir. Her görülen frame tam bir kez sayılır; tekrar eden aynı
değer gerçek paket çokluğunu temsil eder. İlk/son UTC gözlem zamanı sırasız
paketlerde min/max ile korunur. `untagged`, normal `tagged`, VID 0
`priority_tagged`, VID 4095 `reserved` ve `stacked` ayrı sayaçlardır.
Yalnızca normal VID 1–4094 için per-VID count ve ilk/son görülme tutulur.

Varsayılan 60 saniyelik ısınma, servis UTC saatiyle ölçülür; en az iki normal
tag gözlemi olmadan durum `learning` kalır. Öğrenme anında en az iki kez
görülen VID'ler sabit `learned` setine alınır. Sonraki yeni VID özet içinde
görünür, referans setine kendiliğinden girmez. Bu pasif, gözlenen davranış
referansıdır; kullanıcı doğrulaması veya güvenilir switch konfigürasyonu
değildir. Rolling pencere/rate bu taskta yoktur.

SQLite migration 008, scope başına toplam sayaçları ve en çok 128 normal VID
aggregate'ini saklar. Yeni VID kapasite aşımında `overflow_count` artar;
en çok 64 scope tutulur ve kapasitede son gözlemi en eski olan scope
deterministik anahtar sırasıyla tahliye edilir. Yazma mevcut inventory worker'ında
kısa transaction ile yapılır; yeni thread/queue eklenmez. Restart sonrası
özet ve öğrenme durumu sürer. Varsayılan capture filtresi `vlan` trafiğini de
kapsar; untagged sayaç yalnızca filtrenin diğer kollarından görülen Ethernet
frame'lerini sayar. Bu sayılar tüm ağ trafiğinin veya switch VLAN envanterinin
eksiksiz ölçümü değildir. NS-044 alert, GUI ve inner QinQ parse etmez.

Ham Scapy paketleri domain/application sınırını geçmez ve varsayılan olarak kalıcılaştırılmaz.

### NS-045 portable VLAN detector

Inventory consumer, NS-044 `observe` kaydı başarıyla döndükten sonra aynı
portable `PacketObservation.vlan` ve `VlanSummarySnapshot` çiftini
`VlanAnomalyDetector`'a verir. NS-044 `learning` ve pasif `learned` durumları
korunur; ayrı `verified` durumu yalnızca açık `verify_baseline` application
komutuyla oluşur. Migration 009, scope için `verified_at_utc_us` ekler; 008
değiştirilmez. Repository doğrulama geçişini tek transaction'da yapar ve sonraki
pasif gözlemler doğrulama zamanını veya donmuş learned VID kümesini değiştirmez.
`learning`, doğrulanmamış `learned`, normal olmayan VID kategorileri veya
`overflow_count > 0` karar üretmez. Kabul edilmiş setteki
normal VID bilinir; dışındaki normal VID, 120 saniye içinde farklı ileri UTC
zamanlı iki gözlemle düşük önem/düşük güvenli sinyal olur. 60 saniyede üç ayrı
doğrulanmış yeni VID, orta önem/düşük güvenli çeşitlilik sinyali oluşturur.
Tek frame veya yalnızca `untagged` görünümünden saldırı çıkarımı yapılmaz.

Infrastructure callback'i görülen Ethernet kaynak MAC'ini mevcut `MacAddress`
tipine normalize edip `PacketObservation.ethernet_source_mac` alanına koyar;
geçersiz alan `None` olur, raw frame taşınmaz. Detector geçerli unicast MAC ile
mevcut `DeviceIdentity(network fingerprint, MAC)` UUID sözleşmesini kullanır;
VLAN frame'inden ARP device registry tablosuna kayıt yazmaz ve packet başına
device SQLite sorgusu yapmaz. İlk VID geçici cihaz referansıdır; aynı scope ve
cihazın farklı VID'si iki ileri gözlemle doğrulanınca cihaz tag değişimi sinyali
oluşur. Kaynak kimliği yoksa yalnız global kurallar değerlendirilir. Detector
ikinci kalıcı VLAN baseline veya SQLite store tutmaz; network fingerprint +
normalize interface ID + index + rule/VID/cihaz kapsamında toplam en fazla 512
geçici state tutar. 600 saniye idle expiry ve eşitlikte anahtar
sıralı deterministik tahliye kullanır. Sinyaller bounded `AlertCandidate`
olarak inventory snapshot'ında taşınır; bu aşamada `AlertService`, alert
persistence, GUI, yeni worker/queue veya recovery yoktur. NS-046 bu portable
çıktının kalıcı alert ve görünüm entegrasyonunu üstlenir.

NS-046, aynı inventory worker'ında üretilen portable adayları mevcut
`AlertService.record` çağrısına verir. Yazma başarısızlığı VLAN aggregate'ini
geri almaz; en çok 512 teslim edilmemiş aday aynı worker belleğinde sonraki
inventory yenilemesinde yeniden denenir. Alert fingerprint ve durum yaşam
döngüsü NS-028 repository'sinde kalır. Her inventory yenilemesinde yalnızca
seçili network/interface özeti worker'da okunur ve portable snapshot ile Qt
thread'ine taşınır; GUI SQLite çağırmaz. Dashboard bu scope'u gösterir,
capture kapalıyken önceki gözlemleri belirtir. Alerts ekranı mevcut genel
kanıt detayını ve NS-028 sorgu worker'ını kullanır.

### NS-036 rolling broadcast/ARP metriği

`TrafficMetricsService` mevcut tek pasif capture consumer'ında senkron çalışır.
Yalnızca `PacketObservation.broadcast.kind` değerini okur: `ARP` ayrı sayaçtır;
Ethernet, IPv4 limited ve seçili subnet'e directed broadcast tek broadcast
sayacıdır. Multicast/unicast dışarıda kalır. Consumer filtresi ARP, Ethernet/IP
broadcast ve mevcut DNS history etkinse port 53 trafiğini kapsar. BPF'nin
yakalayamadığı trafik sayılmaz; ölçüm tüm LAN trafiğini temsil etmez.

Scope, network fingerprint + case-insensitive interface ID + interface index'tir.
Varsayılan 60 saniyelik rolling pencere, monotonic saatten türetilen 60 adet
birer saniyelik bucket içerir. Bucket `[n, n+1)` sınırına sahiptir; `n+60`
anında eski bucket çıkar. Paket/saniye `penceredeki paket / 60` olur; ilk,
seyrek ve boş dönemde de payda tam penceredir. UTC packet zamanı yalnızca
observation metadata'sıdır; eski UTC zamanı rolling state'i geriye götürmez.

Baseline her protokol için ayrı, ilk health/gözlem tick'inden başlayan tam ve
kayıpsız 60 saniyelik pencereler üzerinden öğrenilir. Varsayılan üç pencerenin
en az ikisi dolu ve toplamda en az
üç paket varsa median pencere oranı `learned` olur. Bir packet baseline kurmaz.
Öğrenilen değer 600 saniye observation gelmeyip scope silinene kadar sabittir;
sonraki burst referansı hemen yükseltmez. Bu öğrenme yalnızca ölçüm referansıdır,
saldırı/normal davranış hükmü değildir. SQLite, alert ve GUI değişimi yoktur.

Capture health'in cumulative `dropped_observations` farkı aynı scope'un
rolling bucket'ına yazılır. Kayıp varsa `MeasurementConfidence.REDUCED` olur ve
ilgili tamamlanmış pencere baseline'a alınmaz. İlk health okuması mevcut kaybı
konservatif olarak o scope'a bağlar; context switch'te yeni cursor kurulur.
Varsayılan en fazla 64 scope ve scope başına 60 bucket tutulur; önce 600 saniye
idle scope'lar, sonra en eski gözlenen scope (eşitlikte scope key) tahliye edilir.
Uzun zaman sıçraması yalnızca mevcut bucket'ları temizler. Sonuç immutable,
aggregate `TrafficMetricsSnapshot` değeridir; ham paket, payload, kaynak adres
listesi, worker, socket veya yeni queue taşımaz.

### NS-037 broadcast/ARP yoğunluk detector'ı

`TrafficRateDetector`, aynı consumer'ın NS-036 `TrafficMetricsSnapshot` çıktısını
alır; packet parse etmez ve ikinci rolling counter/baseline tutmaz. Öğrenilmiş
ARP ve broadcast referanslarını ayrı değerlendirir. Varsayılan tetik koşulu,
ilgili mutlak paket/saniye eşiğinin (broadcast 5, ARP 2) ve baseline'ın 3 katının
üstündeki orandır. Tam pencere boyunca eşit aralıklı üç yüksek snapshot gerekir;
tek kısa burst böylece doğrulanmaz. Aktif sinyalde 120 saniyelik cooldown ve
tetik eşiğinin yarısına iki ayrı temiz ölçümle dönüş, sırasıyla tekrar yazımını
sınırlar ve recovery üretir. `UNKNOWN` kalite ve öğrenme durumu karar üretmez;
`REDUCED` kalite alert güvenini `low` yapar ve recovery için kullanılmaz.
Tetik eşiğinin iki katını aşan doğrulanmış oran `medium`, diğer tetikler `low`
severity alır; kayıpsız ölçümün confidence değeri `moderate` olur.

State network fingerprint + normalize interface ID + index + protocol için
bellekte tutulur; en fazla 128 kayıt, 600 saniye idle expiry ve deterministik
tahliye vardır. UTC duplicate/eski snapshot state'i ilerletmez; monotonic saat
confirmation/cooldown içindir. Portable karar, mevcut `AlertService` üzerinden
SQLite'a kaydedilir veya çözülür. Fingerprint kural ve scope için sabittir;
evidence yalnızca bounded aggregate oran/sayaç, baseline, eşik, pencere ve kalite
bilgilerini içerir. Bu anomali saldırı hükmü değildir. Yeni worker/queue/GUI yoktur.

### NS-038 Dashboard read model ve sentetik yük

`DeviceInventoryService` aynı worker'da NS-036 snapshot'ını ve NS-037 policy
değerlerini `DeviceInventorySnapshot` içinde taşır. Mevcut coordinator yaklaşık
bir saniyelik refresh ritmiyle tek portable snapshot'ı Qt ana thread'ine iletir.
Dashboard presentation modeli yalnızca bu snapshot'ı formatlar; packet parse,
rate/baseline/threshold kararı ve uzun süreli history tutmaz. Eşdeğer snapshot
widget güncellemesi üretmez. Ağ fingerprint/interface uyuşmazlığında metrik
gösterilmez; capture kapalıysa son değerler stale olarak etiketlenir. Detector
alert yazma veya çözme işlemi başarılı olduğunda mevcut Alerts sorgusu yenilenir.
Küçük capture queue'larında consumer drain sınırı bildirilen kapasiteyle
sınırlanır. İşaretli `performance` testi fake backend ile 2.048 sentetik frame
ve 32 öğelik queue kullanır; producer için 15 saniyelik geniş timeout,
capture stop için 1 saniyelik bounded timeout uygular. Queue 32'yi ve metric
bucket sayısı pencere boyunu aşmamalı, dropped counter `REDUCED` kaliteye
geçmeli ve offscreen Qt heartbeat burst sırasında ilerlemelidir. Bunlar hız
benchmark'ı değil davranış sınırlarıdır; gerçek LAN, Npcap, yönetici yetkisi
veya internet kullanılmaz.

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
- **SQLite writer (M3 history tasarımı):** History kuyruğunun kendi worker-owned yazıcı bağlantısı batch transaction işler. Bu, tüm uygulamada tek global writer olduğu anlamına gelmez; NS-033 DNS history ayrı writer bağlantısına, diğer kısa repository write işlemleri ilgili worker bağlantılarına sahiptir. GUI/read tarafı ayrı bağlantıyla worker üzerinde sorgular.

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
engine event loop öncesinde başlatılır; gerçek quit, Qt `aboutToQuit` sinyali
ve event loop çıkışı aynı idempotent lifecycle controller üzerinden tek bounded
`engine.stop()` isteğine indirgenir.
NS-093 hide/close-to-tray bu shutdown yolunu çağırmaz; explicit close preference
ve tray capability yalnız presentation davranışını belirler.

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
- WAL modu ve busy timeout kullanılır; her asenkron writer kendi bağlantısının tek sahibi olur. SQLite kısa transaction ile eşzamanlı writer girişlerini serileştirir; uygulama genelinde tek writer thread yoktur.
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

### NS-039 kullanıcı cihaz profili

`DeviceProfile`, gözlenen `DeviceIdentity` ve `IdentityBinding` kayıtlarından
ayrı immutable kullanıcı verisidir. Ağ fingerprint'i ile scope edilir; kararlı
profil UUID'si bir veya daha çok gözlenen cihaz UUID'sine
`device_profile_members` üzerinden bağlanır. Profil etiketini (128 karakter),
notunu (1024 karakter), açık `unknown/trusted/untrusted` durumunu, son güven
değişimi UTC zamanını ve en çok 32'şer beklenen canonical MAC/IPv4 kimliğini
taşır. Beklenen kimlikler gözlemden otomatik türetilmez. `DeviceProfileRepository`
application portunu `SQLiteDeviceProfileRepository` uygular; SQL ve bağlantı
yalnızca infrastructure içindedir.

Migration 007, profil ve membership tablolarını mevcut migration manifest'ine
ekler. Kullanıcıya ait create/update/delete/merge komutları kısa transaction
ve çağrıya ait SQLite bağlantısı kullanır. NS-022 `record_binding` yalnızca
observed tablolarına yazar; profil alanlarını değiştirmez. Update eski UTC
timestamp ile state'i geri götürmez, eşit zamanda farklı içerik reddedilir;
güven değişimi `trust_changed_at = updated_at` ile saklanır. Merge yalnızca
aynı network fingerprint içindeki gözlenen cihazları birleştirir. Beklenen
kimlik kümeleri birleşir; boş etiket/not tamamlanır; çelişen dolu kullanıcı
metni veya açık güven durumu atomik olarak reddedilir. Kaynak profil
`merged_into` alias'ı olarak okunabilir kalır, observed cihaz/binding geçmişi
silinmez. Bu işlem güvenlik kararı, alert veya capture davranışı üretmez.

### NS-040 cihaz kimliği sapması

Mevcut inventory worker, açıkça başlatılmış pasif capture sırasında seçili
fingerprint için aktif profil/membership ve son beş dakikalık observed binding
snapshot'ını refresh başına tek SQLite okumasıyla alır. Snapshot en çok 512
profil, 2048 üye ve 4096 yakın binding ile sınırlıdır; detector her profil için
en çok 20 yakın binding ve toplam 512 sinyal durumu tutar. Kullanıcı update/merge
sonraki refresh'te görünür; beklenen kimlik veya trust değişimi eski detector
durumunu geçersiz kılar. Etiket/not alert fingerprint'ine girmez. Kaynak veri
NS-039 repository'sidir; snapshot ikinci kalıcı profil deposu değildir.

`DeviceIdentityChangeDetector`, NS-023'ün tek registry yazısından dönen observed
cihaz/binding'i kullanır. Profil üyesinin MAC'i beklenen kümenin dışındaysa veya
beklenen IP'de yeni MAC görülürse `device_mac_identity_change` adayı üretir.
Beklenen MAC başka profil için ayrılmış IP'de görülürse düşük güvenli
`device_identity_context_mismatch` sinyali üretir. Beklenen MAC'in aynı ağda
beş dakikada üç farklı beklenmeyen IP'ye bağlanması düşük önemli
`device_ip_churn` sinyalidir; tek DHCP yenilemesi değildir. Boş beklenen liste,
başka fingerprint, eski/out-of-order observation ve eski binding karşılaştırma
dayanağı olmaz. Yakın beklenen binding MAC sinyalinin confidence gerekçesidir;
locally administered yeni MAC severity'yi yükseltmez. Bu kurallar saldırı
atfetmez ve güven durumunu değiştirmez.

Çıktı mevcut `AlertCandidate -> AlertService -> AlertRepository` hattına gider.
Fingerprint kural, profil UUID'si, ağ fingerprint'i ve ilgili beklenmeyen
kimlikten türetilir; zaman, etiket ve not içermez. Yazma başarısızlığında
detector sinyali teslim edildi saymaz; sonraki observation ile yeniden dener.
Hata registry/capture/DNS akışından izole edilir. Ek worker, queue, migration,
GUI profil düzenleyici veya packet payload yoktur.

### NS-041 profil düzenleme sınırı

Devices ekranında seçili observed `DeviceIdentity` UUID'si, ağ fingerprint'i ve
son görülen MAC/IPv4 yalnızca bağlam olarak kullanılır. Ayrı profil UUID'si
`DeviceProfileService` tarafından açık Save komutunda oluşturulur; gözlenen
değerler beklenen listeye ancak kullanıcı ayrı ekleme düğmesine bastığında
girer. Dialog Cancel hiçbir yazma başlatmaz. Etiket/not/trust/beklenen kimlik
doğrulaması domain sınırlarıyla uyumludur; trust kullanıcı işaretidir, doğrulama
veya güvenlik garantisi değildir.

`DeviceProfileCoordinator`, SQLite işlemlerini tek bounded worker'da sırayla
yürütür. Seçim bazlı okumalar generation ile korunur; seçili UUID değişince
eski sonuç GUI'ye uygulanmaz. Update, okunmuş `updated_at` değerini aynı
transaction içinde karşılaştırır; stale edit reddedilir ve son profil yeniden
yüklenir. Save sonrası profil ve inventory yenilenir; NS-040 detector sonraki
inventory refresh'te repository snapshot'ını yeniden alır. Alert bağlantısı
profil UUID'si ve ağ fingerprint'iyle mevcut Alerts query'sine gider; profile
edit doğrudan alert lifecycle değiştirmez. SQL, DB yolu, not, ham paket ve
payload GUI hata mesajına veya alert bağlantısına taşınmaz. Merge/silme GUI'si
yoktur.

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

### NS-049 sentetik dayanıklılık bütçeleri

`python -m pytest -m performance` mevcut NS-038 ve NS-049 işaretli testleri
seçer. Mevcut pytest yapılandırmasında bu marker varsayılan suite'ten
çıkarılmaz. Tüm girdiler fake capture, bellek içi sentetik frame, fake saat,
geçici SQLite ve offscreen Qt kullanır; ağ paketi gönderilmez. Aşağıdaki
eşikler hız skoru değil, ölçülebilir kaynak sözleşmesidir:

| Ölçüm | CI/default suite için deterministik sınır | Yerel performance çalışması |
|---|---|---|
| Capture burst | NS-038: 2.048 frame/32 queue; NS-049: 320 geçerli + 40 bozuk frame/32 queue, tam kuyrukta 288 drop | Aynı fixture; makineye göre packets/s vaadi yok |
| Persistence overload | History ve DNS için ayrı ayrı 8 pending; 500 ek submit'te 492 drop ve overload health | Aynı sınır; gerçek SQLite ownership/poison izolasyonu mevcut entegrasyon testleriyle kontrol edilir |
| Uzun çalışma | 4.000 ilerletilmiş saniye + 500 ısınma iterasyonu; 24 context dolaşımında en çok 8 metric scope, scope başına 60 bucket ve en çok 16 DNS pending/recent; ayrıca 500 detector örneğinde rate/VLAN state en çok 8 | Aynı hızlandırılmış soak; gerçek saatlerce çalışma garantisi değil |
| Python heap | Isınma sonrası `tracemalloc` farkı < 1 MB; yapısal state sınırları birincil kontrol | Ortam gürültüsü nedeniyle RSS için sabit MB sınırı yok |
| Kapanış | Capture 1 s + DNS writer 2 s konfigüre süre; birleşik sentetik stop için 3,5 s geniş guard; yavaş writer failure-injection için 50 ms isteği | Aynı timeout sözleşmesi; in-flight blocking DB çağrısı zorla iptal edilemez |
| UI | NS-038 sıfır aralıklı Qt heartbeat burst sırasında ilerler; NS-013/038 model güncellemesi coalesce edilir | Görsel akıcılık veya kesin frame süresi garantisi değil |
| CPU/throughput | Sayısal ürün hedefi tanımlı değil; nonblocking producer ve bounded state doğrulanır | Donanıma bağlı throughput raporlanabilir, pass/fail eşiği yapılmaz |

NS-049 testleri ayrıca aynı mantıksal alert'in 256 tekrarda tek row ve en çok
sekiz evidence tutmasını, farklı IP kapsamının ayrı row kalmasını, log storm'da
rotasyon/redaction sınırlarını ve beş engine start/stop döngüsünde owned worker
kalmazlığını kontrol eder. Bunlar sentetik workload gözlemleridir; sistemin
her ortamda sızıntısız veya sabit CPU kullanımlı olduğunu kanıtlamaz.

Production queue sınırları mevcut `AppConfig` ile capture 1.024, connection
history 2.048 ve DNS history 2.048'dir; history/DNS batch varsayılanı 64'tür.
Qt bridge 1.024, inventory komut handoff'u 8, History/DNS query pending
handoff'ları birer öğe ve Alerts query pending handoff'u bir öğe + en çok
sekiz kullanıcı komutudur. NS-049 yük fixture'ları daha küçük kapasite
vererek overflow'u deterministik üretir; production ayarlarını değiştirmez.
Profile load/save ve capability Retry pending işleri de tek slot/generation
ile birleştirilir. Bu presentation sınırlarının stale sonuç koruması mevcut
offscreen GUI regresyonlarında doğrulanır.

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

## 18. Yeni faz mimari sözleşmesi — M11–M17 planlandı, M18 conditional

Bu bölüm mevcut M1–M10 implementasyonunu tarif eden bölümlere eklenen ileriye dönük tasarımdır. NS-052–NS-058 uygulanmıştır; sonraki model, servis, tablo ve adapter'lar plan aşamasındadır. Eski bölüm 3'ün erken taslak tablo isimleri bugünkü 001–011 şemasıyla eşit kabul edilmez: connection_history, devices/bindings, gateway baselines/changes, alerts, dns_history, device_profiles/members ve vlan summaries/verification tabloları vardır. Yeni şema append-only migration ile eklenir; legacy kayıtlar okunabilir kalır.

### 18.1 Kimlik, gözlem ve kapsam

Mevcut `ProcessIdentity(pid, create_time)` process **instance** identity olarak kalır. PID tek başına kalıcı değildir; executable path, hash ve signer bu key'e eklenmez. M13 cross-run **application identity** ayrı typed kavramdır: canonical executable path biliniyorsa kullanılabilir; yalnız process name ile farklı executable'lar merge edilmez; path yoksa conservative unknown kalır. Artifact/hash/signature sonucu uygulama kimliği için revision/context olabilir, process instance yerine geçmez.

NS-052, `ProcessInfo`/resolver portuna optional executable path ve name/create-time/path için ayrı `ProcessInfoStatus` alanları ekler. Eski `status` ve `ProcessIdentity(pid, create_time)` sözleşmeleri korunur. `psutil.Process.exe()` her PID için gözlem turunda en çok bir kez best-effort okunur; reddedilen veya kapanma yarışı yaşayan path, daha önce elde edilen ad ve create-time bilgisini silmez. Path en fazla 4096 karakterdir; boş, kontrol karakterli veya daha uzun değerler `UNAVAILABLE` olur. Path canonicalize edilmez, dosya okunmaz ve log/diagnostics'e aktarılmaz. NS-053 `ProcessInfo.parent` içinde immutable `ParentProcessInfo` sağlar: gözlenen PID, doğrulanabilirse parent `ProcessIdentity`/ad, UTC observation zamanı, alan bazlı availability ve observed/absent/denied/not-found/reused/unavailable sonuçları. Parent PID tek başına instance identity değildir. Adapter child PPID'sini ve parent create-time'ını tekrar okuyarak tutarlılığı sınar; parent çıkarsa, PID tekrar kullanılırsa veya create-time doğrulanamazsa parent kimliği/adını sunmaz. Bu bilgi yalnız mevcut snapshot'ta gözlenen context'tir, tarihsel yaratılış kaydı değildir; `ConnectionKey` değişmez. Per-round child PID cache'i parent lookup'ını da sınırlar; recursive ancestry, path, dosya, hash veya signer okuması yapılmaz. Parent observation zamanının tek başına ilerlemesi lifecycle update üretmez. Hash/signature hesaplaması poller ve GUI thread dışında bounded worker ile yapılır.

NS-054 migration 010, `connection_history` satırına nullable executable path, process alan availability değerleri ve parent observation/status/alan availability değerlerini ekler. 009 ve eski satırlarda yeni NULL kolonlar bilinmeyen metadata anlamındadır; eski PID, create-time, name ve global status korunur. Yeni satırlarda `NULL` path ile `executable_path_status` birlikte okunur: sorgulanıp kısıtlanan alanın status'u `access_denied`, eski veya sonucu bilinmeyen alanın status'u `unavailable` olur. Parent `NULL` status eski kayıtta gözlem yok demektir; `absent` ayrı bir gözlem sonucudur. Repository yalnız mevcut lifecycle open/update/close event'inde snapshot'ı yazar; kapalı eski satırlar bugünkü process verisiyle yeniden zenginleştirilmez. Parent metadata doğrulanmış yaratılış soyu değildir; path kimliğe girmez. Satırlar mevcut history retention sınırlarına tabidir.

NS-055, Connections detayına runtime `ProcessInfo`, History detayına worker üzerinden okunan kalıcı snapshot `ProcessInfo` taşır. Ortak presentation mapper alan availability ve parent observation durumlarını ayrı kullanıcı metinlerine çevirir; parent adı yalnız doğrulanmış gözlemde görünür. Detay etiketleri Qt plain text kullanır, path link veya dosya açma eylemi değildir. History sayfa sonucu mevcut generation/cancellation sınırından geçer; aynı kayıt ID'si yenilenen sayfada kalırsa seçim geri yüklenir. Metadata connection key veya kayıt ID'sini değiştirmez.

Bugünkü `ConnectionKey` tuple + optional `ProcessIdentity` içerir; `ConnectionOpened` polling snapshot'ında görünme demektir, TCP connect event'i değildir. History UUID repository'de üretilir ve dispatcher'ın ortak event ID'si değildir. M11, session, observation ve lifecycle reference'ları application sınırında typed/immutable biçimde tanımlar. İlk poll'da zaten açık olan bağlantılar, eksik/overflow snapshot ve monitoring gap gerçek open/close/frequency kanıtı gibi sayılmaz. Aynı tuple daha sonra yeni lifecycle olabilir; metadata quality upgrade sahte churn üretmemelidir. Aktif tracker ve yeni event/state bütçeleri açık hard cap, loss/gap diagnostic'i ve conservative degradation taşır.

NS-057, her başarılı connection turunda güncel IPv4 `NetworkContext` envanterini bir kez okur. `ConnectionSnapshot.network_scope` immutable `resolved`/`unknown`/`ambiguous` sonuç taşır. Yalnız local endpoint IP'si tek bir mantıksal interface/context'in atanmış IPv4 adresiyle **tam eşleşirse** `local_address_match` yöntemiyle fingerprint, interface ID ve index verilir. Bu, route kararı veya fiziksel ağ kanıtı değildir. Aynı adres birden fazla context'te varsa `ambiguous`; eşleşme yoksa, wildcard/loopback/IPv6 ise veya provider hata verirse `unknown` olur. Subnet üyeliği tek başına kanıt sayılmaz; VPN/virtual/physical ayrımı eşleşme önceliğini değiştirmez. 4096 context sınırı aşılırsa tüm tur `unknown` kalır; tarihsel context cache'i tutulmaz. Scope `ConnectionKey`'e girmez, değişimi aynı lifecycle üzerinde update'tir ve önceki snapshot scope'unu geriye dönük değiştirmez. Collection round quality ayrı kalır. Mevcut fingerprint interface/subnet/gateway türetimidir, fiziksel ağ veya Windows Firewall profile kimliği değildir. NS-057 bu scope'u SQLite history'ye yazmaz; eski network-fingerprint-zorunlu alert sözleşmesi değişmez.

NS-058, değişmeyen ancak gerçekten yeniden gözlenen connection'ları yapılandırılabilir 30 saniyelik varsayılan aralıkla checkpoint eder. Due hesabı monotonic clock kullanır; satırdaki `last_seen` UTC gözlem zamanıdır. Writer kuyruğunda lifecycle başına tek bekleyen checkpoint tutulur ve yenisi eskisini değiştirir. Checkpoint, OPEN/UPDATE/CLOSE olay sayısını veya lifecycle kimliğini değiştirmez; SQLite update yalnız aynı lifecycle hâlâ açıkken uygulanır. FAILED tur checkpoint üretmez; REDUCED turda yalnız gerçekten görülen anahtar güncellenir. Yeni 011 şeması monitoring session/lifecycle ID ve `observation_gap` işaretini ekler. Writer başlangıcı eski açık satırları 256 satırlık transaction'larla gap durumuna geçirir; `closed_at` boş ve `last_seen` son gerçek gözlem olarak kalır. Restart'ta aynı tuple yeni INITIAL lifecycle olur, continuity varsayılmaz. History UI gap/open/legacy unknown ayrımını ve süreyi gözlenen aralık olarak gösterir; gap satırları tamamlanmış satırlar gibi retention'a girer. Scope kalıcılığı bu taskın parçası değildir.

### 18.2 DNS association ve destination enrichment

Bugünkü klasik DNS parser/tracker network-scoped observation sağlar; PID ya da connection sebebi sağlamaz. M12 DNS result ID'sini event origin'den writer ve association consumer'a aynı şekilde taşır. Directly observed DNS domain → answer IP evidence ile process → connection → remote IP gözlemi ayrı tutulur. Bounded `DomainAssociation` multi-to-multi adayları network/client/time/TTL ve source reference üzerinden ilişkilendirir. Directly observed DNS evidence, correlated association, ambiguous association ve unknown UI/modelde ayrılır; shared IP/CDN/multiple-domain adayları kaybolmaz. PTR sonucu tek başına forward causality değildir. DNS-process attribution yalnız NS-060 spike sonucuna göre ayrı planning pass'te düşünülür.

NS-062 runtime servisi mevcut `DnsTrackingService` sonucundaki yalnız eşleşmiş,
başarılı, truncated olmayan klasik DNS response'larını tüketir. A/AAAA answer
owner doğrudan kanıttır; CNAME üzerinden query adına taşınan aday ayrı
`cname_derived` provenance, bounded zincir ve zincirin minimum TTL'sini taşır.
PTR ve negatif/orphan response association üretmez. Her aday network fingerprint
ve DNS client IP ile scope edilir; lookup yalnız `RESOLVED` connection network
scope ve explicit client IP için exact eşleşme yapar. `UNKNOWN`/`AMBIGUOUS`
scope'tan ağ tahmini yapılmaz. Lookup `CORRELATED`/`AMBIGUOUS`/`UNKNOWN` ve
0..N aday döndürür; connection hostname ya da process ilişkisi iddia etmez.
TTL=0 gözlem olarak dönse de aktif cache'e girmez. Runtime expiry monotonic'tir;
UTC response zamanı kanıt olarak kalır. Varsayılan retention üst sınırı 3600 s,
global 2048, scope başına IP 32 ve domain 32 adaydır. Süre dolanlar önce
temizlenir, kapasitede en eski/yenilenmemiş aday deterministik tahliye edilir.
Duplicate yeni observation time ile coalesce olur; DNS server kimlik değildir,
son gözlemin resolver provenance'ı tutulur. Kapasite kaybı sticky,
sanitize aggregate service stats içinde görünür. Transaction alanları DNS wire
bağlamıdır; kalıcı source reference NS-063'te `DnsEvidenceId` ile sağlanır.

### NS-063 Association persistence ve canonical DNS IDs

`DnsEvidenceId`, bir normalized klasik DNS transaction sonucunun UUID kimliğidir;
domain, IP, resolver, process veya association kimliği değildir. Tracker ilk
pending query kabulünde bir ID oluşturur ve retry'de korur. Matched response,
timeout veya eviction bu pending ID ile tek sonuç üretir; completed response
replay'i yeni sonuç üretmez. Unmatched response için sonuç anında ID oluşturulur;
aynı timestamp'li replay yakın completion penceresinde bastırılır. Daha sonraki
gerçek sorgu/yanıt, içerik aynı olsa bile yeni ID alır. Parser, history writer,
repository ve UI ID üretmez.

DNS history'nin UUID `id` kolonu storage row kimliği olarak kalır. Migration 012
nullable ve unique `evidence_id` ekler. Eski satırlarda `NULL` pipeline origin'i
bilinmediği anlamına gelir; migration backfill yapmaz. Aynı evidence ID ile
writer retry'si yeni row açmaz, farklı içerik kimlik çakışması olarak reddedilir.
`source_status` mevcut kaynak, legacy unknown ve artık bulunamayan kaynak
(retention veya yazma hatası olabilir) durumlarını ayırır.

`dns_associations` her DNS result'taki ayrı domain/IP/provenance/CNAME zinciri
için source `evidence_id` ve result içi bounded sıra taşır. Aynı result iki A cevabı verirse iki association
satırı aynı evidence ID'ye bağlanır. Semantic key'e resolver girmez; farklı
resolver'dan sonraki gerçek gözlem ayrı source ID ile saklanır, runtime aday
güncelliği coalesce edilir. DNS writer'ın bounded kuyruğu ve worker-owned
bağlantısı history ile association'ları aynı transaction'da yazar; capture,
dispatcher ve GUI callback'lerinde DB I/O yoktur. Association yazısı başarısızsa
runtime gözlem korunur, writer'ın sanitized failure sayacı/kodu artar.

Association satırları yalnız bounded canonical metadata, DIRECT/CNAME provenance,
en çok 9 elemanlı CNAME zinciri, network/client scope, UTC observed/expiry ve
gözlenen TTL taşır. Monotonic deadline DB'ye yazılmaz. Restart'ta worker en
fazla 2048 fresh satırı UTC üzerinden okur; geçmişe kaymış wall clock ve süresi
geçmiş/TTL=0 satırlar aktif olmaz. Kalan süre yeni monotonic deadline'a çevrilir;
memory'nin 2048 global ve 32 scope/IP/domain sınırları korunur. Restore hatası
capacity loss olarak işaretlenir. Association tablosu writer transaction'ında
100.000 row hard cap uygular; manuel DNS retention 30 gün/100.000 row/500
chunk politikasını association'lara da uygular. Source history ile association
arasında FK/cascade yoktur: source silinince ilerideki reference lookup
`source_unavailable` olur, kaynak sonsuza kadar tutulmaz. Read API source ID ile
512, scope+client+IP için semantic olarak coalesced en çok 32 aday ve restart
için 2048 satırla sınırlıdır.

Destination IP/domain canonical value object'leri ile local ASN/country enrichment source, dataset version, lookup subject, freshness ve unknown taşır. Ülke/ASN maliciousness verdict değildir. Executable hash local, on-demand, bounded file I/O'dur. NS-068 signer adapter NS-067 GO sonucuyla eklenmiştir; signed=trusted veya unsigned=malicious kuralı kurulmaz. Cloud reputation M15'te ayrıca user-controlled port/adapter sınırıdır; hiçbir yerel path, raw history veya payload bu sınırdan kendiliğinden çıkmaz.

NS-066 `ExecutableHashService` yalnız açık `ProcessInfo` isteğinde iş planlar; poller,
dispatcher ve Qt thread'i dosya okumaz. `ExecutableHasher` portunun yerel adapter'ı
tek daemon worker üzerinde SHA-256'yı 1 MiB parçalarla hesaplar. En fazla 64
benzersiz path bekler, bir aktif iş yürütür ve aynı path'in bekleyen isteklerini
tek future'a birleştirir. Yeni istekler queue dolduğunda `saturated` olur.
1 GiB boyut ve 5 saniyelik kooperatif süre sınırı vardır; shutdown beklemesi
en fazla 2 saniyedir. Cache 128 girişli deterministik LRU'dur; anahtar filesystem
device/file ID, size ve mtime_ns içerir (file ID yoksa path de kullanılır).
Windows creation-time alanının yeni dosya açılışında değişebildiği gözlendiği
için anahtara dahil edilmez. Worker pre-stat, açık handle fstat ve post-stat
karşılaştırır; değişim başarı olarak yayımlanmaz. UNC ve symlink varsayılan
kapsam dışıdır. Metadata eşitliği atomik snapshot veya yüklenmiş process image'ı
kanıtlamaz; cache yalnız redundant işi azaltır. İstek token'ı doğrulanabilir
PID+create_time ve path snapshot'ı taşır; create_time yoksa process'e bağlı
hash isteği `unavailable` olur. Tüketici sonucu güncel metadata ile eşleştirmelidir.
Hash ne process identity ne de güvenlik kararıdır. NS-066 DB, history ve UI
şemasını değiştirmez; otomatik executable taraması yapmaz.

NS-068 `ExecutableSignerService` yalnız Connections detail içindeki açık kullanıcı
isteğiyle çalışır. `ExecutableSignerVerifier` portu blocking Windows çağrılarını
tek daemon worker'a taşır; 64 benzersiz pending path, bir aktif iş ve 2 saniye
bounded shutdown beklemesi vardır. Aynı pending/active path istekleri tek
future'ı paylaşır. Windows adapter'ın cache'i 128 girişli LRU ve en fazla 60
saniyelik TTL kullanır; key device/file ID, size, mtime_ns ve ID yoksa path
içerir. Catalog/trust store değişiklikleri TTL bitene kadar sonucu etkileyebilir.
Dosya açılmadan önce, açık handle ve doğrulamadan sonra metadata eşleştirilir;
değişim sonucu yayımlanmaz. Metadata çakışması veya doğrulama sonrası mutation
için atomik garanti yoktur. Process PID+create_time/path token'ı seçili aktif
satırla yeniden eşleşmeden GUI sonucu göstermez. Geçmiş kayıtların imzası
bugünkü aynı path'ten yeniden türetilmez; DB migration yoktur.

Infrastructure `WinVerifyTrust` embedded yolunu ve Windows catalog admin/SIP
hash yolunu ayrı kullanır. Catalog member hash NS-066 raw SHA-256 değildir.
`WinTrust` state, catalog/admin context ve Python file handle native sınırda
kapanır. Portable sonuç kind, validation, local trust, revocation (bu policy'de
daima `not_checked`), signer subject/issuer/certificate SHA-256 ve yalnız
counter-signer presence kanıtı taşır. Timestamp zamanı veya timestamp validity
çıkarılmaz. Primary signer raporlanır; secondary signature enumeration ve
expired+timestamped fixture doğrulaması bu taskta yapılmadı. Bunlar mevcut
sonucu evrensel signer/trust kanıtına dönüştürmez.

NS-065 temelinde `DestinationContextResolver` public IP'yi local `DestinationContextProvider` portuna yönlendirir; private/special adresler portu çağırmadan `not_applicable` olur. Yerel TSV adapter sınırlandırılmış dosyayı açık yükleme çağrısında IPv4/IPv6 prefix indeksine çevirir; runtime lookup yalnız bellek kullanır ve en uzun prefix'i seçer. Sonuç kaynak adı/sürümü/lisansı ve UTC yükleme zamanını taşır. En fazla 4096 IP için cache dataset generation değişince temizlenir. Varsayılan dataset yoktur; dosya hatası typed/sanitized diagnostic üretir. Yükleme `create_destination_context_resolver` çağrısında yapılır ve GUI worker'ında çağrılmalıdır; NS-064 UI entegrasyonu ayrı kalır. Format, limitler ve lisans kararı [local dataset sözleşmesinde](LOCAL_DESTINATION_DATASET.md) kayıtlıdır.

NS-064, Connections ve History seçimine iki ayrı read-only bölüm bağlar: observed DNS associations ile current local ASN/country context. Her yüzeyin tek bounded worker kuyruğu ve generation kontrolü vardır; SQLite sorgusu ve dataset yüklemesi Qt thread'inde yapılmaz. DNS adayları exact network fingerprint ve DNS client IP ile, en çok 32 satır ve deterministik sırayla okunur; `unknown`/`ambiguous` scope'ta DNS sorgusu yapılmaz. Association provenance, observed age, effective TTL ve canonical source status kullanıcıya gösterilir; correlation hiçbir zaman connection hostname'i veya DNS→process iddiası değildir. Source kaybı evidence yokluğundan ayrılır. History'de canonical ID'si olmayan eski DNS kayıtları için ayrı, en çok 128 satırlık exact scope/client/IP/time probe yalnız legacy limitation durumunu gösterir; eski kayıttan yeni canonical ID veya kesin hostname türetilmez. Country yalnız dataset eşleşmesidir, fiziksel konum veya risk hükmü değildir.

History'de NS-064 migration 013 yalnız connection'ın en son gözlenen network scope'unu ve bu scope'un başladığı UTC zamanı ekler. Eski satırlar `unknown` kalır; local IP'den geriye dönük scope çıkarılmaz. Aynı lifecycle içinde scope değişirse son scope'un başlangıç zamanı ileri alınır. Historical DNS sorgusu `[scope_since, last_seen]` aralığıyla örtüşen, bundan sonra gözlenmemiş ve bu aralıkta süresi dolmamış evidence'i kullanır. Current local dataset geçmiş ASN snapshot'ı gibi sunulmaz. DNS association schema 012 değişmez.

### 18.3 Baseline, risk ve incident

M13 baseline process instance yerine cross-run application identity ve açık network/unknown scope ile çalışır. İlk feature'lar destination IP, destination port, protocol, **observed connection appearance** frequency ve destination diversity'dir; ASN varsa ek context olabilir. State/entity/window caps, monotonic runtime windows, UTC-aware persisted checkpoints, sample coverage, learning/warm-up, eviction ve restart-gap semantiği gerekir. Başlangıç snapshot'ı ve telemetry loss novelty/beacon alarmını şişiremez. ML/AI, time-of-day alert ve byte-derived behavior ilk sürümde yoktur.

NS-069 application scope policy'si yalnız gözlenen executable path'i lexical Windows kurallarıyla (`ntpath.normpath`/`normcase`, filesystem erişimi olmadan) canonical hale getirir. Mutlak drive/UNC path için `winpath:v1:` key restart-stable'dır; aynı ad veya PID uygulama key'i değildir. Path yoksa doğrulanmış `ProcessIdentity` (PID + create time) ile `instance:v1:` geçici key üretilir; create time da yoksa key yoktur. Geçici key baseline persistence için cross-run identity değildir. Raw display path ile canonical key ayrıdır ve path/key yalnız yerel process metadata gizlilik kurallarına tabidir. On-demand, eşleşen request token'ına bağlı SHA-256 ayrı artifact revision kanıtıdır; hash yokluğu veya hata yeni revision kanıtı değildir. Aynı path'te iki bilinen farklı hash revision değişimidir, farklı path'lerde aynı hash application merge etmez. Typed comparison metadata upgrade/loss, path değişimi ve hash değişimini ayırır; önceki baseline verisini yalnız aynı stable path ve doğrulanmış aynı hash durumunda güvenle taşınabilir sayar. Bu, disk dosyasının process'te yüklenmiş image'ı doğruladığı iddiası değildir. Signer identity key'ine katılmaz.

NS-070 `BehaviorFeatureAccumulator`, engine'in tracker turundan sonra elde ettiği immutable round observation, lifecycle event'leri ve o turda gerçekten görülen snapshot'ları tek çağrıda, bellek içinde toplar. Scope anahtarı application identity key + biliniyorsa artifact SHA-256 revision + NS-057 network status/token'dır. Resolved token network fingerprint'tir; unknown/ambiguous token yalnız o monitoring session ve local IP içinde geçerlidir, restart-stable ağ kimliği değildir. Bilinen farklı hash'ler ayrı scope olur; hash yokluğu revision değişimi sayılmaz, ancak bilinmeyen revizyonun bilinen hash'e güvenle baseline carry yaptığı iddia edilmez. Engine otomatik hash okumaz; servis NS-069 resolver'ından sağlanan kanıtı kabul edebilir. Path'i ve process create-time'ı olmayan unknown application için ortak scope kurulmaz. Provisional instance key restart boyunca taşınmaz.

Yalnız `ConnectionOpened(origin=OBSERVED)` bir **observed connection appearance** sayılır; polling gerçek TCP connect zamanı/sayısı değildir. INITIAL yalnız sıfır sayımlı scope oluşturabilir; update, close ve her turda yeniden görülen aynı lifecycle appearance artırmaz. Remote endpoint varsa kanonik IPv4/IPv6, remote port (0–65535) ve mevcut TCP/UDP enum'u ayrı sayaçlardır. Remote endpoint yoksa destination/port yerine typed unknown sayacı kullanılır; DNS association, byte, zaman dilimi, risk veya detector sonucu üretilmez. Diversity, elde tutulan farklı destination/port/protocol anahtarlarının sayısıdır; taşma sonrası gerçek toplam distinct cardinality iddiası değildir.

Varsayılan monotonic pencere 60 saniyelik 12 bucket, toplam 12 dakikadır. Eski bucket'lar her tur/query sırasında topluca atılır; büyük sleep/jump boş bucket tahsis etmez. En fazla 64 application key, application başına 4 scope, toplam 128 scope, scope başına pencere içinde 64 destination, 32 port ve 2 protocol anahtarı tutulur. Bunlar `BehaviorCapacity` immutable policy değerleridir. Her feature cap sonrası yeni değer, bounded `other_*` appearance sayacına gider ve capacity loss işaretlenir; var olan değerler sayılmaya devam eder. Scope dolunca en eski görülen scope (eşitlikte lexical key) atılır; application cap dolunca en eski application'ın scope'ları atılır. Global evicted scope sayısı snapshot'ta kalır. Snapshot'lar immutable ve sıralıdır; `capacity_loss` silinmiş veya taşmış bilginin “never observed” diye yorumlanmasını önler.

Monitored-time paydası UTC farkı veya uygulamanın wall-clock çalışma süresi değildir. Aynı scope iki ardışık COMPLETE turda gerçekten görünürse monotonic farkın en fazla bir polling interval'i kadarı eklenir; 2 interval'i aşan gecikme, FAILED/REDUCED tur veya session değişimi continuity'yi keser. Bu konservatif payda yalnız **scope'un gözlenen etkin olduğu kaliteli aralıkları** kapsar; idle uygulama/ağ için kapsam uydurmaz. REDUCED turda gerçekten görülen OBSERVED appearance sayılabilir ama monitored-time eklenmez; reduced appearance ve gap ayrı işaretlenir. FAILED tur feature ve coverage eklemez. Kaybolan satır/capacity drop capacity-loss işaretler. UTC yalnız upstream observation metadata'sıdır, bucket/rate hesabını değiştirmez. Servis lock ile atomik güncelleme/snapshot sağlar; DB, GUI, dosya veya ağ I/O'su yapmaz. NS-071 persistence ve warm-up policy'si ayrı tasktır.

M14'te detector typed, bounded `RiskEvidence` üretir; pure domain scoring policy contributor'ları normalize edip versioned `RiskAssessment` hesaplar. Risk score malware probability değildir. Assessment evidence, confidence, measurement quality, source/freshness ve policy version'la yeniden açıklanabilir olmalıdır. Eksik kanıt “normal” değildir. ARP'ye özgü mevcut score/evidence ve legacy alerts korunur. Assessment recalculation yeni revision üretir: eski revision overwrite edilmez, alert occurrence artırılmaz, original observation time değişmez. Alert persistence ve lifecycle yalnız `AlertService` üzerinden gider; detector SQL yazmaz. Alert severity ve risk score ayrı policy alanlarıdır; score değişimi fingerprint/dedup kimliğine girmez. Reputation evidence bir contributor olabilir, tek başına malware veya blocking sonucu vermez.

M16 `Incident` ile observation/assessment/alert references arasındaki ilişkiyi açıklar; `Alert`in yerine geçmez. Correlation window, process/lifecycle/destination identity ve relation reason typed/bounded olur. Aynı remote IP tek başına merge sebebi değildir. Open/ack/resolved/reopen ve evidence append idempotent, restart-safe ve retention-aware olmalıdır. GUI timeline observation time ile assessment time'ı ayırır. Mevcut process creation telemetry yoktur: yalnız `process observed` gibi gözleme uygun dil kullanılabilir.

#### NS-071 — Baseline persistence/lifecycle

NS-071, NS-070 rolling snapshot'ından fark almaz. Accumulator her tracker
turunda yalnız o turun eligible appearance ve monitored coverage katkısını
immutable, bounded snapshot olarak döndürür. `BehaviorBaselineService` bunları
bir kez kümülatif learning aggregate'e ekler. Poll sayısı sample değildir;
INITIAL appearance eklemez, FAILED sample/coverage eklemez, REDUCED yalnız
gerçek OBSERVED appearance ekler. Lifetime aggregate ve 60 × 12 runtime bucket
ayrıdır; bucket, monotonic tick, polling round veya raw event SQLite'a yazılmaz.

Migration **013 → 014**, `014_behavior_baselines.sql`, yalnız
`behavior_baselines` ve tek satırlık `behavior_baseline_storage` ekler.
Application key, known SHA-256 revision veya explicit unknown için boş SQL
sentinel, resolved network fingerprint ve version/time/policy kolonları
normalized'dır. Payload deterministic, exact alanlı bounded JSON feature
aggregate'idir; arbitrary object dump değildir. Summary format **1** ve feature
policy **1**, SQLite schema version 014'ten ayrıdır. Compatibility key ayrıca
NS-070 kapasite/window değerleri, polling interval, warm-up ve stale/expiry
policy'sini içerir. Değişen anlam sessizce yeniden yorumlanmaz.

Kalıcı kapsam yalnız canonical NS-069 `winpath:v1:` stable identity + resolved
NS-057 fingerprint'tir. PID/ad kalıcı identity değildir. Known hash A, B ve
unknown revision ayrı scope'tur; unknown known'a taşınmaz. Provisional instance
ve unknown/ambiguous session network bellekte `session_only` kalır. Scope query
ve reset application + revision + network exact anahtarını kullanır.

`BehaviorBaselineConfig` varsayılan warm-up eşiği **20 eligible appearance +
600 monitored saniye**dir. Hiç sample/coverage yoksa `learning`, eşiklerden biri
eksikse `insufficient_data` olur. Capacity/overflow loss, reduced appearance
ve unknown destination `insufficient_quality` üretir. READY yalnız iki eşik ve
bu quality koşulları sağlandığında mümkündür; risk, trust veya normal hükmü
değildir. `gap_seen` korunur; gap'in kendisi historical öğrenmeyi silmez, gap
aralığı coverage'a eklenmez. Kalite kaybı olan aggregate explicit reset ile
yeniden öğrenilir; key listeleri eksiksiz historical knowledge sayılmaz.

Son gerçek UTC gözlemden **30 gün** sonra `stale`, **90 gün** sonra `expired`
olur. Negatif age veya persisted time'ın gelecekte görünmesi `clock_anomaly`
üretir. Gözlem/query/checkpoint ile saptanan stale/expired/clock anomaly runtime
içinde sticky'dir; yeni gözlem eski referansı kendiliğinden READY yapmaz, reset
gerektirir. Büyük ileri sıçrama O(1) age karşılaştırmasıdır. Gelecek summary
version `unsupported_version`, feature/config uyuşmazlığı `policy_mismatch`,
malformed/impossible veri `corrupt` döner; bunlar restore edilmez veya otomatik
onarılıp overwrite edilmez. Scope bile geçersizse read sonucu scope taşımadan
CORRUPT döner ve eksik knowledge conservative unavailable kalır.

Restart'ta en fazla **128** yakın summary worker'da yüklenir; NS-070 default
memory sınırları (64 app, app başına 4 scope, toplam 128; scope başına 64 IP,
32 port, 2 protocol) korunur. Startup I/O sırasında gelen live katkılar bir
kez merge edilir; o sırada kabul edilmiş reset eski restore'u engeller.
Geçerli historical aggregate ve monitored duration korunur, gap işaretlenir.
Yeni accumulator boş bucket ve fresh monotonic continuity ile başlar. Sekiz
saat offline olmak sekiz saat coverage veya empty/normal window üretmez.
Same-process stop/start da persisted sample'ı tekrar toplamaz. Pre-014 history
ve DNS satırlarından baseline türetilmez.

`BaselineRepository` blocking portunu yalnız **netsentinel-baseline-writer**
daemon worker çağırır; SQLite bağlantısı bu worker'da açılır/kapanır. Constructor,
engine/GUI producer ve snapshot/reset API'si DB I/O yapmaz. Monotonic schedule
varsayılan **30 saniye** checkpoint üretir; persisted checkpoint UTC'dir.
Scope başına latest summary coalesce edilir; **128 pending scope + 1 active**
iş vardır. Queue dolarsa producer beklemez, dirty summary sonraki checkpoint
için kalır; reset enqueue kabul edilmezse memory reset uygulanmaz.

Service lock checkpoint/reset submission sırasını belirler. Monoton artan
sequence eski pending checkpoint'i reddeder; reset bayrağı coalescing'de
korunur. Worker önce delete, ardından varsa reset sonrası yeni aggregate'i
yazar. Önceki active write resetten önce biter; resetten sonra eski state'i
diriltemez. Scoped reset idempotenttir ve diğer revision/network/app'a dokunmaz.
Bool başarı **queue acceptance** anlamındadır; durable completion için dirty
count ve storage state izlenir. Write failure reset/summary retry'ını dirty
tutar. Reset mark-normal/trust değildir; GUI NS-075'e bırakılmıştır.

Disk hard cap **512 summary row**, application key en fazla **4096 UTF-8 byte**,
payload en fazla **16 KiB**dir (en çok 8 MiB payload; bounded kolonlar ve SQLite
page/WAL overhead ayrıca). SQL CHECK ve insert quota trigger bunu korur.
Repository load limit 1–128'dir; size SQL'de de sınırlandırılıp parse öncesi
kontrol edilir. Sayaçlar 63-bit, monitored aggregate 1e12 saniye sınırını
aşacaksa katkı reddedilip capacity loss işaretlenir. IP, port, enum, distinct
map kapasitesi/diversity, sample totals, identity, revision ve UTC doğrulanır.

Retention worker başlangıcında, her write sonrasında ve idle iken 30 saniyede
bir, **en fazla 64 row/transaction** siler. 90 günlük expired rows ve quota
fazlası deterministic oldest-observation/key sırasıyla temizlenir. Quota'da bir
yeni scope normalde bir eski scope'u tahliye eder. Tek bounded metadata satırı
retention/eviction loss'u restart boyunca korur; unlimited tombstone yoktur.
Eksik/atlanmış scope `unavailable`/`previous_unavailable` olur, “never seen”
kanıtı sayılmaz. Elde tutulan geçerli scope'un kendi quality'si korunur; explicit
reset sonrası yeniden öğrenilmiş scope sonraki restart'ta taşınabilir.

Graceful shutdown dirty summary için final flush dener; worker join varsayılan
**2 saniye** ile sınırlıdır. Timeout queued işi bırakır; in-flight SQLite çağrı
zorla kesilmez ve dönünce daemon kapanır. Yaşayan worker'ın yerine ikincisi
başlatılmaz. Crash/final flush yokluğunda son committed checkpoint geri gelir;
kayıp RAM tail gözlenmiş inactivity sayılmaz. DB/load/write failure NS-070 veya
connection dispatch'i durdurmaz; storage availability boş baseline'dan ayrıdır.
`BaselineDiagnostics` yalnız aggregate loaded/dirty/pending/checkpoint/failure/
rejection/invalid/cleanup/reset/loss sayılarını taşır; path, hash, IP, features,
SQL veya raw exception içermez. NS-071 detector, risk/alert ve GUI eklemez.

#### NS-072 — Novelty/rarity rules

`evaluate_destination_novelty`, `DestinationNoveltyInput` ve immutable
`DestinationNoveltyPolicy` alıp `DestinationNoveltyEvidence` döndüren saf
application detector'ıdır. Rule ID `destination_ip_novelty_rarity`, policy
version **1**'dir. Domain sözleşmesi framework bağımsızdır. Baseline service'ten
alınan **güncel, observation eklenmeden önceki** `BaselineSnapshot`, mevcut
`BehaviorScopeKey`, remote IP, UTC observation time ve origin/quality kullanılır.
Detector I/O yapmaz, clock okumaz, state/occurrence/dedup tutmaz ve öğrenmez.
Freshness ve config compatibility NS-071 lifecycle owner'ının sorumluluğudur;
detector eski bir READY snapshot'ını kendiliğinden yeniden tarihlendirmez.

Scope stable canonical application path + exact revision (unknown dahil) +
resolved network fingerprint ile eşleşmelidir. Farklı path, revision veya
network snapshot'ı ödünç alınmaz; provisional/unknown application ve
unknown/ambiguous network `not_evaluated` olur. Shared IP başka application'ın
history'sini paylaşmaz. Unknown revision kendi ayrı scope'unda çalışabilir;
evidence `revision_unverified` limitation taşır. Canonical IPv4/IPv6 remote IP
kimliktir; port, DNS adı, ASN veya country novelty key'i değildir. Eksik/geçersiz,
unspecified veya zone-ID içeren remote değerlendirilmez. Private/loopback IP
aynı familiarity policy'sine tabidir; güvenli kabul edilmez.

Yalnız eligible `OBSERVED` appearance değerlendirilir. INITIAL ve FAILED
girdiler defensive `not_evaluated` sonucu verir. REDUCED turda gerçekten
gözlenen appearance, READY reference varsa değerlendirilebilir; current quality
ve `reduced_current_observation` limitation korunur. Baseline'ın reduced
history'si yeniden yorumlanmaz. LEARNING/INSUFFICIENT_DATA
`insufficient_data`, INSUFFICIENT_QUALITY `insufficient_quality` verir;
STALE/EXPIRED/CLOCK_ANOMALY/CORRUPT/UNSUPPORTED_VERSION/POLICY_MISMATCH/UNAVAILABLE
`not_evaluated` verir. READY tek başına verdict değildir: summary version,
feature policy, scope, bounded summary invariants, future timestamps ve quality
ayrıca doğrulanır; detector bir lifecycle engelini READY'ye yükseltemez.

Policy v1 minimum **20 eligible appearance + 600 monitored saniye** ister.
Bu süre NS-070/071 kaliteli gözlenen etkin coverage'dır; wall-clock app age veya
poll sayısı değildir. Eksiksiz READY reference'ta count **0** `first_seen`
(`destination_not_previously_observed`) olur: yalnız retained scoped baseline'da
gözlenmemiş IP demektir, OS first-ever connection değildir. Count **1–2**,
baseline en az **100** appearance ve destination payı en fazla **%1** ise `rare`
olur. Her iki rare sınırı inclusive'dir; oran integer cross multiplication ile
hesaplanır. Count 1–2 ve denominator 100'den küçükse rarity için
`insufficient_data`; diğer pozitif sayımlar `known` olur. KNOWN yalnız retained
observation familiarity'dir, safe değildir. Eşikler bounded typed policy
üzerinden değişebilir; evidence kullanılan policy'nin tamamını ve version'ını
taşır, global AppConfig büyütülmez.

Capacity loss, destination `other` overflow, unknown/reduced baseline samples,
63-bit counter saturation veya `previous_unavailable`/`session_only` history
READY girdide bile normal classification üretmez. Evicted/missing scope için
NS-071 unavailable/loss işaretleri korunur; absent entry “never observed” diye
yorumlanmaz. Gap tek başına history'yi geçersiz yapmaz; coverage eklemeden
evidence'da kalır. Storage status ayrıca taşınır; geçerli memory history yalnız
checkpoint storage hatasından dolayı silinmez. Evidence exact destination
appearance count, baseline sample count (total eligible appearances ile aynı),
monitored duration, scope, lifecycle/origin/storage, compatibility key,
quality/loss/gap, observation time ve typed classification/reason taşır.
Geçersiz/uyuşmayan summary'den açıklama count'u ödünç alınmaz.

Her sonuç `ip_only_service_not_inferred` limitation taşır. CDN/address rotation
yeni IP oluşturabilir; FIRST_SEEN yeni service/domain veya suspicious/malware
iddiası değildir. NS-071 domain baseline içermediğinden hidden domain history
ve DNS candidate girdisi eklenmez. NS-062–064 association'ları ileride ayrı
context olarak kalır; correlated veya ambiguous aday kesin hostname olamaz.

NS-072 engine'e bağlanmaz. Gelecekteki pipeline owner'ı exact scoped snapshot →
evaluation → baseline mutation sırasını **seri/atomik** yürütmelidir; bağımsız
service çağrıları arasında detector transaction sağlamaz. Aynı immutable
girdiyle concurrent veya tekrar evaluation aynı sonucu verir ve state artırmaz.
Service snapshot ile ilk appearance'ın FIRST_SEEN, mutation sonrasındaki
appearance'ın artık FIRST_SEEN olmadığı offline test edilir. Yeni persistence,
migration, UI, AlertService, risk/severity/malware verdict, diagnostics veya
network lookup eklenmez. SQLite schema **014**, baseline summary ve feature
policy **1** kalır. NS-074/075 ve M14 entegrasyonları ayrı tasklardır.

#### NS-073 — Frequency/diversity rules

`evaluate_frequency_diversity` iki ayrı rule evidence üreten saf detector'dır:
`observed_appearance_frequency`, `destination_window_diversity`, policy **1**.
Appearance rate eligible OBSERVED samples / NS-070 monitored coverage'dır;
gerçek OS connect-event count değildir. Frequency reference NS-071 historical
mean ve varsa comparable independent window upper range'idir. Diversity lifetime
unique IP toplamından türetilmez: `BehaviorRangeLearner` aynı scope/session'da
en çok sekiz clean independent reference window aggregate'i tutar. Bu supplement
memory-only'dir; restart diversity reference warm-up gerektirir. Summary format
**1**, feature policy **1**, SQLite schema **014** değişmez.

READY lifecycle, exact application/revision/resolved-network scope, quality/loss
gates, 120 s current coverage ve 20 current appearance gerekir. Frequency strict
3× + >=10/min absolute floor; diversity strict 3× + >=10 retained IP ve en az üç
comparable reference kullanır. Gap/reduced/loss current window güçlü comparison
sayılmaz. `FrequencyDiversityService` explicit monotonic clock ile iki bağımsız
elevated window'da confirmation ve 600 s scoped cooldown sağlar. Duplicate veya
overlapping window count/emission artırmaz. Her servis 128 scope hard cap taşır;
learner scope başına 8 sample, emission scope başına 2 rule state tutar.
Eviction oldest accepted independent scope'tur; yeni scope unconfirmed başlar.

Engine/composition integration yoktur. Future owner NS-072 pre-mutation novelty,
NS-070 update, NS-073 post-mutation window vs prior learned reference sırasını
serialize eder. Evidence persistence, GUI, AlertService, risk/score, packet/byte,
ML/time-of-day veya diagnostics/config değişikliği yoktur. Tam threshold, quality,
restart/reset ve caller sınırları [NS-073 policy](FREQUENCY_DIVERSITY_POLICY.md)
belgesindedir. NS-074/075 ve M14 ayrı tasklardır.

#### NS-074 — Periodicity evidence detector

`evaluate_periodicity` bounded immutable sequence üzerinden saf interval/jitter
evidence üretir; `PeriodicityService` her tracker turunda explicit monotonic time
ile yalnız COMPLETE/loss-free OBSERVED open appearance'larını toplar. Key NS-069
canonical application + exact revision + resolved network scope, known process
instance (PID/create-time) ve canonical remote IP/port/protocol'dür. INITIAL,
update, close ve long-lived poll'lar appearance değildir. FAILED/REDUCED/loss,
delayed round ve session/clock epoch kırılması sequence'i reset eder; recovery
minimum interval'ı yeniden oluşturur. Restart monotonic history restore etmez.

Policy **1**: minimum 5, retained maximum 32 interval, global 128 scope; raw median
base, max normalized residual ve max(1 s, %5) jitter tolerance. En fazla 3× missed
multiple uyumu için strict direct-interval majority gerekir; missed event kanıtı
değildir. Polling quantization/aliasing limitation her sonuçta kalır; base <= 3×
polling cadence resolution-limited olur. Updater/telemetry/sync davranışı yalnız
düşük güvenlik anlamlı context'tir; beacon/C2 veya güvenlik verdict'i yoktur.

Oldest accepted-touch scope eviction, bounded recent lifecycle dedup, 10800 s
inactivity ve 86400 s horizon explicit'tir. RLock altında memory-only state;
engine/composition, UI, persistence, risk/alert, config/diagnostics veya I/O
entegrasyonu yoktur. NS-072/073 ayrı contributor kalır. SQLite **014**, summary
ve feature policy **1** korunur; NS-075 başlamaz, M13 tamamlanmaz. Contract,
threshold/reset/quality/aliasing sınırları ve doğrulama
[NS-074 policy](PERIODICITY_POLICY.md) belgesindedir.

#### NS-075 — Baseline detail ve reset UI

Connections detayındaki **Behavior baseline** sekmesi application
`BaselineDetailService` read modelini kullanır. `BaselineQueryCoordinator` aynı
destination query pattern'ine göre bir daemon worker ve en çok bir pending/latest
request tutar; result/failure Qt signal ile GUI thread'ine gelir. NS-071 zaten
worker'da restore edilmiş baseline snapshot'ını sağlar; NS-075 ayrı SQLite read
veya write bağlantısı açmaz. Composition root mevcut baseline/feature owner'larını
paylaşır. History ve top-level navigation genişletilmez.

Read model canonical application identity + exact known/unknown revision +
resolved network fingerprint kullanır. Unknown/provisional application ve
unknown/ambiguous network için persistent reference ödünç alınmaz; reset disabled
kalır. GUI resolver metadata'yı I/O yapmadan kullanır: desktop otomatik hash
hesaplamadığından mevcut live revision unknown olabilir. Typed request known
revision'ı ayrı scope olarak destekler. PID/ad persistent identity değildir.

Tüm NS-071 lifecycle states, policy-derived warm-up progress, observed connection
appearances, monitored coverage ve quality/gap/loss görünür. Learned reference,
uncommitted RAM tail içerebilen cumulative aggregate'tir; current accumulator
window ayrı memory-only bölümdür. Persistence timestamp current tail'in durable
kaydı gibi sunulmaz. Destination/port preview en çok **8**, protocol preview en
çok **2** değer tutar; sıra deterministic, portlar sayısal sıralıdır. Retained
diversity exact lifetime unique total değildir. Kapasite/overflow ve reduced/
unknown appearance ayrı açıklanır.

Typed novelty/frequency/diversity/periodicity evidence mapper exact scope,
destination ve periodicity için process instance + remote port/protocol eşleşmesini
korur. NS-072–074 engine'e bağlı olmadığı için default provider evidence üretmez.
Query, sonradan öğrenilmiş snapshot'tan geçmiş FIRST_SEEN veya runtime timing
kanıtı uydurmaz. Absent evidence normal/irregular hükmü değildir; polling
resolution ve benign updater/sync sınırları görünür. Pipeline/alert/risk integration
bu taska eklenmez.

Selection request ve logical row identity birlikte izlenir. A→B→A eski sonucu
generation + immutable request karşılaştırması eler. Aynı logical row model
refresh'inde query tekrar edilmez. En fazla bir unresolved query ve bir coalesced
pending request vardır; görünür panel 5 saniyede bir memory snapshot yeniler,
ayrıca explicit Refresh bulunur. DB polling storm yoktur. Qt widgets yalnız GUI
thread'inde değişir; coordinator stop generation invalidation yapar, widget
timer'larını durdurur ve varsayılan 2 saniyelik join ile late result'ı düşürür.

Reset dialog exact application/revision/network'i ve silinen learned reference'i
açıklar; trust/preferences, connection history ve current runtime observations
ayrı kalır. Cancel varsayılan/Escape sonucudur ve command üretmez. Command yalnız
NS-071 memory API'sine submit olur. `reset_with_result` acceptance yanında typed
completion Future verir; receipt yalnız reset bayraklı writer transaction'ının
başarı/hatasında tamamlanır. Coalesced newer learning summary reset'i taşıyabilir;
eski reset sequence daha yeni receipt'i tamamlayamaz. Aynı pending scope duplicate
aynı receipt'i paylaşır; receipt map en fazla scope capacity (default 128) tutar.
Queue reject state'i sıfırlamaz. Failure dirty retry'ı korur; shutdown/timeout
unconfirmed receipt'i UNAVAILABLE yapar. Başarı sonrası panel yeniden query eder,
cached READY'yi tutmaz. Repository owner hâlâ yalnız NS-071 writer'dır.

Yeni schema, raw event storage, diagnostics dump, network/cloud lookup, risk UI,
mark-normal, AlertService veya automatic reset yoktur. SQLite **014**, summary ve
feature policy **1** kalır. [Kabul ve test raporu](BASELINE_DETAIL_UI.md).

#### NS-076 — Generic risk evidence contract

`domain.risk_evidence` additive, framework/I/O bağımsız contract **1** sağlar.
Immutable `RiskEvidence`; bounded source enum, producer'a ait 64 karakterlik
symbolic rule/reason/result kodları, optional producer policy version, UTC
observation time, typed subject/scope/quality/confidence ve references taşır.
Subject mevcut `ProcessIdentity`, `ApplicationIdentity`, `ApplicationRevision`,
session/lifecycle UUID, canonical IPv4/IPv6 ve `MacAddress` kullanır. PID-only
process kimliği session gerektirir; application adı veya PID kalıcı key olmaz.
Path yalnız bounded canonical NS-069 identity key'inde bulunabilir; process
metadata, command line veya ayrı free-path alanı yoktur.

Scope `host`, resolved `network` veya `unknown` olur; sonuncusu NS-057
`UNKNOWN` ve `AMBIGUOUS` durumlarını ayrı korur, fingerprint içermez.
`EvidenceScope.from_connection` interface/route kesinliği eklemez. Observation
quality `COMPLETE/REDUCED/FAILED` veya unreported `None`; inference limitations
ve confidence ayrı alanlardır. FAILED yalnız limitation rolünde taşınabilir.
Finding, observation ve limitation güvenlik verdict'i değildir. Reason/result
kodları producer policy namespace'inde açıklama anahtarlarıdır, serbest kullanıcı
metni değildir; açıklama için subject/reference veya legacy typed context kullanılır.

Evidence başına en fazla **8** typed UUID/digest reference, **16** typed
limitation; düz `RiskEvidenceBatch` başına **32** evidence contributor vardır.
Tuple dışı collection, duplicate ve cap aşımı reddedilir; references/limitations
ve contributor sırası normalize edilir. Recursive evidence tree ve arbitrary
details/metadata/payload yoktur. `evidence_id`, contract version dahil canonical
validated content'in SHA-256 değeridir: summary occurrence/content kimliğidir,
DB row/alert/assessment ID veya legacy issue dedup fingerprint'i değildir.
UTC observation time veya correlation context değişimi yeni content ID verir.
Contract-version ve producer-policy-version farklıdır; bilinmeyen legacy version
uydurulmaz. Referans, target'ın hâlâ saklandığını veya resolve edilebildiğini
garanti etmez; persistence/retention çözümleme NS-078'e aittir.

`application.services.risk_evidence.evidence_from_arp`, mevcut typed NS-026
event/NS-027 correlation sonucunu taşır. `LegacyArpContext` kaynak nesneyi ve
varsa correlation'ı, eski severity/confidence/score/breakdown/count/zamanlarıyla
aynen korur; generic yeni score/severity hesaplamaz. Envelope-source mapping
validate edilir, eski issue fingerprint typed reference olarak kalır.
`RiskEvidenceConsumer` yalnız bounded local handoff protocol'üdür; runtime
consumer veya engine/AlertService bağlantısı yoktur. NS-072/073/074 contract
temsilleri test edilir; detector-specific ölçümler kendi mevcut typed
modellerinde kalır, production M13 adapter/pipeline bu taskta eklenmez.
Evidence **assessment veya score değildir**; schema **014** değişmez. Mapping,
bounds ve test raporu: [NS-076 contract](GENERIC_RISK_EVIDENCE.md).

#### NS-077 — Pure explainable scoring policy

`domain.risk_scoring` contract v1 `RiskEvidenceBatch` ve explicit typed freshness
ile immutable policy **1** alır: evidence → explained contributor → pure result.
Skala **0..100 integer** review priority/concern düzeyidir; malware probability
değildir. Score severity, capped severity, confidence, measurement quality ve
availability ayrı alanlardır. Eksik freshness/stale/expired/unsupported evidence
unknown/not-scored kalır; empty result severity veya safety verdict üretmez.
Quality eksik/FAILED veya confidence eksik/low generic severity'yi LOW, REDUCED
measurement MEDIUM ile sınırlar; evidence puanını benign diye azaltmaz.

Typed correlation keys aynı application/revision/network activity burst'ünün
novelty/frequency/diversity katkılarını max ile birleştirir; timing regularity
ayrı family olarak stack eder. Aynı IP/expected/observed MAC geçişi ARP/gateway
rule'larında max sayılır. Activity/periodicity/identity toplam cap'leri 40/30/70,
global positive cap 100'dür. Same-time contradictory novelty unknown olur;
duplicate evidence NS-076 tarafından reject edilir. Allocation ve explanations
deterministic sıralıdır; bağımsız positive evidence score'u düşürmez.

Yalnız explicit periodicity `BENIGN_SCHEDULE_COMPATIBLE` qualifier küçük -3
calibration önerir; benign nedenin doğrulanması değildir. Global reduction en
çok **min(5, positive subtotal // 4)** ve destekleyen applied periodicity points
ile sınırlıdır. Trust/signer/country/ASN/known destination/suppression mitigation
olmaz. Limitation-only evidence puan üretmez. Her contributor original typed
evidence, raw/applied points, family/key, reason/adjustments ve policy version
taşır; batch 32, result en çok 64 immutable contributor ile bounded'dır.

Scorer DB/files/network/config/clock/Qt/AlertService çağırmaz. Legacy ARP
severity/confidence/score/fingerprint context'i aynen kalır, runtime path'e
bağlanmaz. Persistence, revisions, UI ve preferences eklenmedi; SQLite **014**.
Frozen mapping/correlation/severity decisions: [NS-077 policy](RISK_SCORING_POLICY.md).

#### NS-078 — Versioned assessment persistence

`RiskAssessmentKey` original observation reference/time ve typed scope/subject'ten
stable logical ID üretir. `RiskAssessmentRevision`, explicit UTC assessment time
ve minimum immutable explanation snapshot taşır; revision occurrence değildir.
Evidence contract, producer/scoring policy, freshness, score/severity, quality,
confidence, applied/excluded contributors ve adjustment nedenleri tarihsel kalır.
Read mevcut scorer'ı çalıştırmaz. Canonical content fingerprint timestamp'ten
bağımsız duplicate no-op sağlar; retained eski içeriğin retry'si latest'i değiştirmez.

Schema **015** additive logical assessment/revision tablolarını ekler. Scoped
worker-owned connection'da kısa `BEGIN IMMEDIATE` append/dedup/retention atomiktir;
yerel monotonik revision numarası per-assessment pruning sonrası korunur.
Source tablolarına FK yoktur; source erişimi snapshot'tan ayrı typed
available/expired-or-unavailable/unresolved olarak okunur. Legacy alert read ve
lifecycle korunur; generic assessment uydurulmaz. 8 revision/assessment, 512
assessment, 64 KiB snapshot, 30 gün explicit cleanup ve 128 revision/chunk sınırı
vardır. NS-079/runtime/GUI/queue entegrasyonu eklenmez. Format/corruption, retention
ve ownership ayrıntıları: [NS-078 persistence](RISK_ASSESSMENT_PERSISTENCE.md).

### 18.4 Kullanıcı tercihleri, persistence ve I/O ownership

NS-079 `BehaviorRiskPipeline`, production desktop engine'de OBSERVED appearance
için pre-mutation NS-072 → accumulator/baseline mutation → post-mutation NS-073
→ COMPLETE-only NS-074 sırasını kurar. Qt bridge detection kaynağı değildir.
128 pending + bir active kapasiteli `RiskAlertWorker`, normalization/scoring ve
assessment/alert SQL işlemlerinin sahibidir. `RiskToAlertService`, NS-078 commit
sonrası mevcut AlertService'i çağırır; başarılı alert commit ve notification
eligibility bool sonrası exact-type `AlertNotificationIntent` yayınlar.
Dispatcher process-local'dır; delivery/outbox garantisi yoktur.

Assessment key original lifecycle/session/time bağlamını korur. Alert fingerprint
application/revision/destination/typed scope'tan türetilir; scoring policy, score
ve revision içermez. Explicit reassessment, aynı repository transaction'ında
yalnız current occurrence severity/confidence/reference'ını değiştirir; count,
last_seen, ACK/RESOLVED korunur ve reopen olmaz. Legacy occurrence watermark ve
dedup değişmez. UNKNOWN/AMBIGUOUS scope için `016_alert_risk_scope.sql` mevcut
alerts tablosunda network fingerprint'i nullable yapar; 001–015 değişmez.
Evidence JSON yalnız küçük typed assessment reference taşır. Failure/eligibility,
queue/shutdown, retention ve crash sınırları:
[NS-079 integration](RISK_ALERT_INTEGRATION.md). NS-083 ve desktop
delivery uygulanmamıştır; M14 tamamlanmış değildir.

NS-080 immutable scoped preference modelleri, explicit permanent/timed lifetime,
manual origin/reason ve CREATE/EDIT/REVOKE snapshot audit sağlar. Schema 017 iki
ayrı policy tablosu ekler; device trust veya observed/risk stores'a dönüşüm yapmaz.
`ScopedPreferenceRepository` portu ve blocking `ScopedPreferenceService`, worker
sahipli kısa SQLite transaction kullanır. Expected revision stale edit'i engeller;
revoke için audit kapasitesi ayrılır. Merkezi sınırlar 256 revoke edilmemiş/1024
toplam preference, 64 revision/preference, 16384 audit row ve 100/64 list/history
page'dir. Audit/aktif policy otomatik silinmez; doluluk typed CAPACITY_REACHED olur.
Pure selector matcher exact AND scope primitive'idir.
[NS-080 contract ve kabul raporu](SCOPED_PREFERENCES.md).

NS-081 aynı risk worker içinde NS-078 assessment commit → current scoped policy
lookup/evaluation → eligibility → mevcut AlertService → commit sonrası notification
intent sırasını uygular. `SuppressionEvaluationService`, NS-080 matcher/status
primitive'lerini reuse eder; explicit UTC `signal.assessed_at` kullanır.
`RiskAlertResult.suppression`, assessment reference'ına bağlı immutable current-policy
açıklamasıdır; historical risk snapshot'a yazılmaz, score/severity/evidence korunur.
Alert-driving positive correlation gruplarında bir unsuppressed support bile
eligibility'yi korur. Tam suppression AlertService'e hiç çağrı yapmaz; count,
last_seen, ACK/RESOLVED ve notification cooldown değişmez. Policy değişimi/expiry
otomatik replay başlatmaz. Lookup/evaluation failure typed limitation ile alerting
için fail-open olur. Tek candidate query mevcut current-revision primary key'lerini
kullanır; en çok 100 policy hydrate edilir, evidence başına 8 match, toplam 32 evidence
ve 32 group taşınır. NS-080'in en çok 1024 logical policy metadata'sı üzerinde size-gated
predicate exact matcher'ı uygular; selector index veya migration eklenmez. GUI/monitoring
callback SQL, cache, yeni worker ve preference write eklenmez. Schema **017** kalır.
[NS-081 sözleşmesi ve kabul raporu](SUPPRESSION_EVALUATION.md).

NS-082 `behavior_context` / `scope_choices` mapping'i NS-075 selected connection
context'i ve explicit canonical behavior rule'dan dar selector üretir. Stable
application ve rule her seçenekte korunur; known revision/destination/resolved
network varsayılan olarak dahil edilir. `MarkNormalPreview` immutable definition,
absolute UTC expiry, reason ve retry ID taşır. Preview saf, Save ayrı explicit
confirmation'dır. `MarkNormalCommandService` NS-080 service/port'unu kullanır;
baseline/risk/alert state mutation yapmaz. NS-082 create'da opt-in `deduplicate`
aynı active definition için transaction içinde NO_CHANGE döndürür; NS-080 default
distinct-ID semantics korunur. `PreferenceCommandCoordinator` tek I/O owner,
8 pending command + 1 active ve 1 coalesced latest query taşır; query generation
ve widget selection epoch stale result'ı engeller. Shutdown en çok 2 saniye
bekler, pending commands typed UNAVAILABLE olur; active commit timeout sonrası
tamamlanabilir. Widget callbacks yerine immutable Future/result kullanılır.
Relevant list en çok 32 preference hydrate eder; mevcut NS-081 matcher/current
candidate query reuse edilir (expired/revoked state dahil). SQLite **017**,
migration ve diagnostics field değişimi yoktur. [Scope/lifetime kararları ve
kabul raporu](MARK_NORMAL_UI.md). NS-083 başlatılmamıştır.

Observed telemetry, learned baseline, user feedback, trust, suppression ve notification eligibility ayrı state'tir. DeviceProfile trust ağ/device kapsamlı mevcut kullanıcı verisidir; process/destination preference aynı tabloya yüklenmez. Yeni suppression selector application, destination, application+destination, rule ve network scope için typed/previewable/expiring olur; PID veya process name kalıcı key olmaz. Permanent suppression yalnız açık kullanıcı tercihiyle; evidence silinmeden policy sonucu açıklanır. Notification eligibility delivery proof değildir; tray/desktop delivery ayrı M17 adapter ve cooldown gerektirir.

Bugünkü uygulamada history writer bounded batch queue ve kendi SQLite bağlantısını kullanır; DNS history writer ayrı queue/bağlantıya sahiptir. Device/gateway/VLAN/alert gibi kısa repository işlemleri ilgili worker'da transaction açar. Global tek writer thread yoktur. Yeni high-volume servisler kendi açık owner/queue/batch/backpressure bütçesini belirler; SQLite WAL/busy timeout altında contention, shutdown ve retention testleri gerekir. GUI thread DB, network, hash, signer veya OS event session I/O yapmaz. Typed dispatcher synchronous/in-process'tir, durable bus değildir; subscriber'lar ağır işi bounded queue'ya devreder. Qt bridge drop/coalescing baseline truth source olamaz. Persisted times UTC-aware, rolling runtime windows monotonic olur. Yeni tablolar için row/byte/age quotas, paginated query, source-reference expiry ve local purge contract gerekir. SQLite SQL parameterized; schema migration append-only.

Diagnostics yeni process field coverage, association ambiguity, baseline learning/loss, TI offline/cache ve ileride OS source health'ini sanitized gösterecek; readiness, actual permission ve running health karıştırılmayacak. Config consent/capacity/retention'ı typed default ve bounded dosya kuralları içinde saklayacak; API key ayrı secret port ile yönetilecek.

### 18.5 Windows adapter karar kapıları

NS-059 TCP EStats/ETW/WFP per-flow bytes; NS-060 DNS-process attribution; NS-061 process/connection event sources için ölçümlü research/spike'tır. Belgelenmiş GO da NO-GO da başarılı task çıktısıdır. Production ETW/WFP collector, privileged helper, flow-byte model veya UI ancak spike sonrası **ayrı planning pass ve yeni task** ile eklenebilir. M11 per-flow bytes gerektirmez. psutil per-connection upload/download sağlamaz: interface counter'ı flow counter gibi gösterilmez, ölçüm yoksa `unknown` gösterilir, `0` değil.

NS-059 araştırmasının [NO-GO kararı](research/NS-059-per-flow-byte-telemetry.md), varsayılan standard-user modda EStats enable yetkisi ve UDP kapsamı yokluğu ile ETW/WFP doğruluk ve bakım sınırlarına dayanır. Bu karar production adapter veya ürün contract'ı eklemez.

NS-061 [event-source araştırmasının NO-GO kararı](research/NS-061-process-connection-event-sources.md) mevcut standard-user ürün için polling-only mimarisini korur. Bu hostta ilgili ETW oturum başlatma denemeleri access denied oldu; classic process/TCP-IP event teslimi ve elevated davranış doğrulanmadı. Gelecekte ayrıca yetkilendirilmiş bir çalışma ancak hybrid event evidence + psutil reconciliation yaklaşımını değerlendirebilir. NS-056 session/lifecycle UUID'leri, `INITIAL` ve `COMPLETE`/`REDUCED`/`FAILED` sözleşmesi ETW `connid` veya event arrival order ile değiştirilmez; üretim portu/collector eklenmedi.

M18 response ancak M17/NS-099 tamamlanıp explicit response GO kararı verilince başlar. İlk akış explicit action → preview → confirmation → narrow NetSentinel-owned firewall rule → audit → undo/expiry'dir. Automatic blocking/elevation ve unrelated rule değişimi yoktur.

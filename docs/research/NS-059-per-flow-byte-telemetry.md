# NS-059 — Per-flow byte telemetry spike

**Tarih:** 2026-10-01. **Karar: NO-GO** (mevcut ürün kapsamına production per-flow upload/download eklenmesin). Bu, `docs/TASKS.md` NS-059 için olumlu araştırma sonucudur; NS-060/061 veya production uygulama kararı değildir.

## Soru ve karar ölçütü

NetSentinel, Windows'ta mevcut `ConnectionKey`/monitoring session/lifecycle ID ile güvenilir biçimde her TCP ve UDP flow'un gönderilen ve alınan byte miktarını gösterebilir mi? Hedef varsayılan standard-user, passive ve local-first çalışma; otomatik elevation, driver, firewall/filter, paket enjeksiyonu ve kalıcı sistem ayarı yoktur. Eksik veri `0` veya interface toplamı olarak gösterilemez.

**Sonuç:** Hayır. TCP EStats teknik olarak IPv4/IPv6 TCP data-octet counter sağlar, fakat Data collection varsayılan kapalıdır ve açmak elevated administrator ister. Geç açma, kısa ömürlü akışlar, kapanma yarışı ve psutil tuple ile lifecycle eşleme kapsamı kırar. UDP için EStats yoktur. ETW şemaları her iki protokol ve aile için paket `size`, PID, endpoint ve `connid` taşır, ancak canlı session/privilege, boyut anlamı, loopback, event loss ve mevcut lifecycle'a güvenilir bağlama bu spike'ta doğrulanmadı. WFP user-mode API hazır flow-byte counter değildir; custom callout/driver ürün hedefi için orantısızdır. Bu koşullarda iki yönde güvenilir “uploaded/downloaded” göstermek mümkün olduğu kanıtlanmadı.

## Mevcut sınır

`PsutilConnectionCollector.collect_round()` `psutil.net_connections(kind="inet")` ile TCP/UDP, IPv4/IPv6 snapshot alır. Adapter'ın normalize ettiği alanlar family, type, local/remote endpoint, TCP status ve PID'dir. `ConnectionKey` protocol + tuple + optional `ProcessIdentity` içerir; create-time yoksa PID reuse korunamaz. NS-056 UUID lifecycle/session kimlikleri yalnız NetSentinel gözlemleridir: `INITIAL` ilk tam poll'da zaten mevcut bağlantı, `OBSERVED` sonraki ilk görünme; gerçek SYN/FIN zamanı değildir. `REDUCED` eksik row, `FAILED` başarısız round, capacity 4096. NS-058 restart gap'i gerçek close zamanı uydurmadan saklar. UDP row genellikle remote endpoint içermez ve aynı socket çok hedefe datagram gönderebilir. Mevcut engine stop bounded'dır; yeni kaynak eklemek ayrıca owned resource lifecycle gerektirir.

## Kontrollü ölçüm

Bu host: Windows, Python `.venv`, psutil 7.2.2, **medium integrity / unelevated**. 2026-10-01 tarihinde tek süreç içinde yalnız `127.0.0.1` TCP listen/client/accept ve bound UDP socket açıldı; dış ağa trafik, packet capture veya ETW session açılmadı. İkinci tek kullanımlık kendi IPv4 TCP flow'unda yalnız `TcpConnectionEstatsData` enable denendi; Windows `ERROR_ACCESS_DENIED` döndürdü, ardından read ile state'in kapalı kaldığı doğrulandı. Başka flow'a dokunulmadı; kalıcı OS configuration değişmedi. `finally` tüm socket'leri kapattı. Shell içindeki geçici Python snippet'leri repo artifact'i değildir.

| Ölçüm | Gözlem | Sınır |
|---|---|---|
| psutil `net_connections(kind="inet")`, 10 ardışık çağrı | 201 row; 1.103 / 1.252 / 1.817 ms min/median/max wall time; loopback test portlarını içeren 3 row | Tek host ve düşük yük. Psutil enumeration maliyeti, EStats/ETW maliyeti değildir. CPU, kernel CPU ve memory ölçülmedi. |
| psutil row alanları | `fd, family, type, laddr, raddr, status, pid`; sent/received bytes yok | Interface `net_io_counters()` bağlantı metriği değildir. |
| `GetTcpTable` + `GetPerTcpConnectionEStats(TcpConnectionEstatsData)` **read-only**, kendi IPv4 loopback established row'u | 1 matching row, API status `NO_ERROR` (0), `EnableCollection=FALSE` (0) | `Rod` okunmadı: collection off iken Microsoft'a göre undefined. IPv6, başka process, late attach veya counter delta ölçülmedi. |
| Kendi ayrı ephemeral IPv4 loopback flow'unda 1024 byte local send sonrası `SetPerTcpConnectionEStats(Data, EnableCollection=TRUE)`; ardından read | Set status `ERROR_ACCESS_DENIED` (5); Get status `NO_ERROR` (0), collection hâlâ false | Unelevated yetki sınırının bir gözlemi. Enable başarılı olmadığından byte counter, başlangıç ve retransmission canlı ölçülmedi. Socket kapanışı state cleanup'ı sağladı. |

100/500/1000+ flow polling CPU/memory/event-rate benchmark yapılmadı: kontrollü gerçek flow örneği ve ETW consumer yok. 201-row psutil süresini bu sayılara lineer extrapolate etmek geçerli değildir. Bu eksiklik NO-GO'yu zayıflatmaz: varsayılan standard-user için EStats enable sınırı ve UDP kapsam boşluğu API sözleşmesinde kesin. Etkinleştirme veya kernel tracing gerektiren performans kararı gelecekte ayrı yetkili VM testidir. Offline decoder fixture eklenmedi; production'a aday event/counter decoder seçilmediği için sentetik fixture API semantiğini doğrulayamaz. Repo'nun mevcut offline lifecycle testleri bu taskta değiştirilmedi.

## Teknoloji bulguları

### psutil

[psutil network API](https://psutil.io/api/) connection row'larını ve ayrı interface-level `net_io_counters` değerlerini tanımlar. Bu host'taki row şekli de byte alanı olmadığını doğruladı. Interface toplamını bir veya birden çok connection'a dağıtmak, loopback/VPN/offload, eşzamanlı flows ve PID belirsizliğinde yanlış atıf üretir.

### TCP EStats

`GetPerTcpConnectionEStats` bir mevcut `MIB_TCPROW`, `GetPerTcp6ConnectionEStats` bir mevcut `MIB_TCP6ROW` alır. `TcpConnectionEstatsData` için `TCP_ESTATS_DATA_RW_v0.EnableCollection` varsayılan false; data ROD ancak true iken anlamlıdır. `SetPerTcp[6]ConnectionEStats` enable/disable işlemi elevated Administrators token ister; yalnız Administrators grubunda olmak UAC filtrelenmiş token için yeterli değildir. Get ve Set ayrıdır. Başka uygulama collection'ı önceden açmış olabilir; yalnız enabled state'i okumak ownership sağlamaz. NetSentinel bunu asla kapatmamalı veya resetlememelidir. Microsoft, bazı eski Windows sürümlerinde disable/re-enable ile counter reset olabildiğini de belirtir. [Data RW](https://learn.microsoft.com/en-us/windows/win32/api/tcpestats/ns-tcpestats-tcp_estats_data_rw_v0), [IPv4 Get](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getpertcpconnectionestats), [IPv6 Get](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getpertcp6connectionestats), [IPv4 Set](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-setpertcpconnectionestats), [IPv6 Set](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-setpertcp6connectionestats).

`DataBytesOut` gönderilen segmentlerin **TCP data octet** sayısıdır; retransmitted data dahil, TCP header hariç. `DataBytesIn` alınan segmentlerin data octet sayısıdır; retransmitted data dahil, TCP header hariç. Bunlar application'ın benzersiz payload byte'ı, IP/Ethernet wire byte'ı veya interface toplamı değildir. Örneğin aynı 1 MB data'nın 0.2 MB'si tekrar iletilirse outbound counter 1.2 MB olabilir; gerçek artış OS'nin segment olaylarına bağlıdır. Inbound da tekrarı içerebilir. [Microsoft Data ROD semantics](https://learn.microsoft.com/en-us/windows/win32/api/tcpestats/ns-tcpestats-tcp_estats_data_rod_v0).

Late attach için collection kapalı bağlantıda önceden geçen byte'lar geri elde edilemez. Başka collector önceden enable etmişse counter başlangıcı NetSentinel'in başlangıcı değildir ve exact origin bilinmez. Enable edilen andan önceki kapsamı `unknown` tutmak gerekir; `INITIAL` lifecycle'a tüm connection toplamı yazılamaz. Kapanmış row `ERROR_NOT_FOUND` verebilir; son counter'ı yakalama garantisi yoktur. `MIB_TCPROW` tuple tabanlı olduğundan close/reopen ve tuple reuse iki poll arasında ayırt edilemez; process create-time EStats row'unda değildir. 64-bit counter düşüşünü otomatik wrap saymak güvenli değildir: reset, başka collector'ın state değişimi, tuple reuse veya API race olabilir. Sadece doğrulanmış aynı flow ve bilinen wrap koşulunda modulo delta düşünülebilir; aksi halde coverage gap.

### ETW TCP/IP

Resmi kernel TCP/IP MOF sınıfları IPv4/IPv6 TCP send/receive/retransmit ve UDP send/receive event türlerini tanımlar. v2 event data'da PID, `size`, source/destination IP ve port, `connid` vardır. `size` dokümanda “size of the packet” olarak geçer; bunun application payload, TCP data octet, IP total length veya offload sonrası wire byte olduğuna dair yeterli sözleşme yoktur. Send + retransmit eventlerini körlemesine toplamak double count riski taşır. Event header PID yerine event data PID kullanılmalıdır; Microsoft bazı eventlerin başka thread'de loglandığını söyler. `connid` eventler arasında korelasyon sağlar, fakat psutil/NS-056 lifecycle UUID ile ortak kimlik değildir. UDP `connid` TCP benzeri persistent peer lifecycle kanıtı değildir. MOF version ve property layout kontrolü/TDH gerekir. [TCP provider](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip), [TCP IPv4 send schema](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip-sendipv4), [TCP IPv6 schema](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip-typegroup3), [UDP provider](https://learn.microsoft.com/en-us/windows/win32/etw/udpip), [UDP IPv4 schema](https://learn.microsoft.com/en-us/windows/win32/etw/udpip-typegroup1), [UDP IPv6 schema](https://learn.microsoft.com/en-us/windows/win32/etw/udpip-typegroup2), [MOF version parsing](https://learn.microsoft.com/en-us/windows/win32/etw/retrieving-event-data-using-mof).

Bu olaylar system/kernel trace kapsamındadır. NT Kernel Logger tekil global session'dır; `ERROR_ALREADY_EXISTS` başkasının session'ını durdurma yetkisi vermez. Modern Windows ayrı SystemTraceProvider session destekler ama privilege/ACL gereksinimleri vardır; standard-user erişimi varsayılamaz. Classic provider oturum çatışması başka tüketiciyi etkileyebilir. Canlı ETW session burada başlatılmadı; standard/admin exact kapsam, loopback, event rate, buffer pressure ve stop latency **UNKNOWN**. Gelecekte yalnız benzersiz NetSentinel-owned session handle/GUID tutulmalı, `StartTrace` başarıyla oluşturulmadıysa `ControlTrace(STOP)` çağrılmamalı, mevcut aynı isimli session asla sahiplenilmemeli. Crash sonrası stale sanılan session yalnız ad eşleşmesiyle silinmemeli; güvenli ownership kanıtı yoksa degraded kalmalı. Consumer thread bounded cancel/join, buffer drain ve timeout sonucu gerektirir. [Kernel logger](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-the-nt-kernel-logger-session), [system session](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session), [session control](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew), [lost events](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing).

ETW real-time consumer yavaş kalırsa event/buffer loss mümkündür; session stats ile `EventsLost`/`BuffersLost` ve lost-event bildirimleri izlenebilir. Kayıp tespit edilen zaman aralığında ilgili flow byte toplamı kesin değildir; her etkilenen flow bilinmeyebilir. Event geç gelmesi, sıra değişimi, duplicate, PID/tuple reuse ve `connid` reuse/visibility başlangıcı ayrı state gerektirir. Session açılmadan önceki trafik geri gelmez. `size` semantiği ve offload/loopback davranışı canlı kalibrasyon olmadan UI sayısı olamaz.

### WFP

User-mode WFP management API layers/filters/net events sağlar; mevcut flow için hazır iki yönlü byte counter okuma API'si değildir. Akış veya packet accounting için uygun filtering layer'da custom kernel callout ve flow context gerekir; Microsoft örnekleri driver, filter ekleme ve administrator gerektirir. WFP stream `missedBytes` gibi ayrıntılar bile accounting kalite sınırı doğurur. Bu, service/driver kurulum ve bakım, signing, OS uyumluluk, farklı layer/offload/loopback semantiği ve system-wide filter güvenlik yüzeyi demektir. NS-059 için filter/driver kurulmadı; kernel sürücüsü yalnız byte kolonları için önerilmiyor. [WFP architecture](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-architecture-overview), [basic operation](https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation), [stream callout](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-a-callout-for-deep-inspection-of-stream-data), [Microsoft sample privilege](https://learn.microsoft.com/en-us/samples/microsoft/windows-driver-samples/windows-filtering-platform-msn-messenger-monitor-sample/).

## Karşılaştırma matrisi

`SUPPORTED` = API dokümanında açık yetenek; **bu hostta uçtan uca doğrulandı demek değildir**. `PARTIAL` = alan/olanak var fakat hedef contract veya kapsam eksik. `UNKNOWN` = resmi kaynak ve bu ölçüm kesin karar vermiyor. `NOT SUPPORTED` = yaklaşım bu ihtiyacı sağlamıyor. `RESEARCH NEEDED` = gelecekte ayrı canlı/VM deneyi gerekli. Her hücre kararın *per-flow NetSentinel telemetry* bağlamındadır.

| Gereksinim | EStats | ETW | WFP |
|---|---|---|---|
| TCP IPv4 | PARTIAL (enable/identity) | PARTIAL (size/identity) | RESEARCH NEEDED (driver) |
| TCP IPv6 | PARTIAL (enable/identity) | PARTIAL (size/identity) | RESEARCH NEEDED (driver) |
| UDP IPv4 | NOT SUPPORTED | PARTIAL (events; UDP association) | RESEARCH NEEDED (driver) |
| UDP IPv6 | NOT SUPPORTED | PARTIAL (events; UDP association) | RESEARCH NEEDED (driver) |
| Loopback | UNKNOWN (IPv4 read disabled observed) | UNKNOWN | UNKNOWN |
| PID attribution | PARTIAL (join separate table) | PARTIAL (event PID) | PARTIAL (layer dependent) |
| Flow identity ↔ NS lifecycle | PARTIAL (tuple race) | PARTIAL (`connid` not shared) | RESEARCH NEEDED |
| Sent bytes | SUPPORTED (TCP data octets, retransmits) | PARTIAL (`size` unclear) | RESEARCH NEEDED |
| Received bytes | SUPPORTED (TCP data octets, retransmits) | PARTIAL (`size` unclear) | RESEARCH NEEDED |
| Late attach/full lifetime | NOT SUPPORTED unless pre-enabled (origin unknown) | NOT SUPPORTED before session | NOT SUPPORTED before callout |
| Retransmission semantics | SUPPORTED (included) | PARTIAL (separate events; counting unclear) | UNKNOWN (layer dependent) |
| Event/counter loss | PARTIAL (poll close/reset race) | PARTIAL (loss stats, flow impact unknown) | UNKNOWN |
| Standard user | PARTIAL (read enabled state; cannot enable) | UNKNOWN/RESEARCH NEEDED (ACL) | NOT SUPPORTED for callout deployment |
| Administrator | PARTIAL (EStats enable) | PARTIAL (kernel session control) | PARTIAL (deployment still driver) |
| Polling/runtime overhead | UNKNOWN (Get per flow not benchmarked) | UNKNOWN (event rate not measured) | UNKNOWN (driver cost) |
| Shutdown ownership | PARTIAL (do not disable others' state) | PARTIAL (owned session only) | RESEARCH NEEDED (driver/filter lifecycle) |
| Implementation complexity | PARTIAL (native FFI + races) | PARTIAL (session + TDH + buffers) | PARTIAL (kernel callout) |
| Maintenance burden | PARTIAL (Windows API/version) | PARTIAL (provider/version/privilege) | PARTIAL (signing/driver/OS) |

## Privilege ve kalite önerisi (gelecek çalışma için, uygulanmadı)

| Bağlam | EStats | ETW | WFP |
|---|---|---|---|
| Standard user | Var olan enabled TCP state salt-okunur denenebilir; default kapalı, byte coverage yok | Kernel trace başlatma hakkı varsayılmaz; ACL/privilege araştırılmalı | Custom callout kuramaz |
| Elevated administrator | TCP v4/v6 collection enable edebilir; state değişikliği ve ownership riski | Session başlatma mümkün olabilir; sürüm, ACL, provider çatışması ve loss test edilmeli | Filter/callout deployment için gerekli ama tek başına yeterli değil |
| Service | Ayrı güvenlik sınırı/IPC/izin tasarımı gerekir | Owned service session tasarımı gerekir | Driver/service deployment gerekir |
| Kernel driver | EStats için gerekmez | ETW consumer için gerekmez | Custom per-flow accounting callout için gerekir |

Gelecekte herhangi bir adapter değerlendirilirse `source`, `protocol`, `address_family`, `counter_semantics`, `coverage_start`, `coverage_end`, `lifecycle_ref`, `correlation_confidence`, `quality` ayrı taşınmalı. Olası quality: `COMPLETE` yalnız gerçekten full lifetime kanıtlanırsa; `PARTIAL`, `STARTED_LATE`, `EVENT_LOSS`, `UNSUPPORTED`, `UNKNOWN`. `REDUCED` connection polling turunun kalitesi byte coverage ile eşitlenmemeli. Enabled state yoksa veya eşleme ambiguous ise byte değeri `unknown`, sıfır değil. Counter azalması wrap olarak otomatik normalize edilmemeli; reset/reuse/gap sınıfına girmeli. PID create-time, tuple, IPv6 scope, UDP wildcard, geç event ve close yarışında yalnız unique eşleme yapılmalı. Application port'u ancak ayrı onaylı task ile açılır; infrastructure kaynak API'sini normalize eder, domain Windows bağımlılığı almaz, GUI blocking I/O yapmaz.

**Future action:** Varsayılan üründe per-flow byte telemetry planlanmasın. Ürün önceliği daha sonra değişirse ayrı task ile disposable, açıkça yetkili Windows VM'de TCP v4/v6 EStats enable/delta/late attach/close/loopback ve ETW v2 schema/size/retransmit/loss/privilege/stop ölçülsün; 100/500/1000+ flow load ve standard/elevated token ayrı raporlansın. Bu araştırma yeni feature veya izin vermez.

## Doğrulama

Yerel probelar PowerShell here-string ile `.\.venv\Scripts\python.exe -` komutuna verildi; yalnız kendi loopback socket'leri kullanıldı ve `finally` ile kapatıldı. Salt-okunur psutil/Get probe ile ayrı, yalnız kendi ephemeral flow'unda Set privilege-denial probe sonuçları yukarıdaki tabloda yer alır. ETW, WFP, IPv6 EStats ve elevated Windows live tests **not executed**. Uygulama runtime'ına kod veya harness eklenmedi.

| Komut | Sonuç |
|---|---|
| `.\.venv\Scripts\python.exe -m pytest -q tests\unit\application\test_observation_quality.py tests\unit\application\test_connection_tracking.py` | 37 passed |
| `.\.venv\Scripts\python.exe -m pytest -q` | 1022 passed, 5 deselected |
| `.\.venv\Scripts\python.exe -m ruff check src tests` | All checks passed |
| `.\.venv\Scripts\python.exe -m mypy` | 14 source files, no issues |
| `git diff --check` | exit 0 |

# NS-060 — DNS-process attribution spike

**Karar: NO-GO (varsayılan NetSentinel için production DNS→process attribution).**
Tarih: 2026-10-01. Bu karar araştırmanın başarılı tamamlanmasıdır; production
adapter veya DNS→connection servisi için izin değildir. Bu hostta DNS Client
provider manifesti incelendi, standart kullanıcı ETW session yetkisi ölçüldü ve
kontrollü resolver çağrıları yapıldı. DNS event'indeki `ClientPID` ile gerçek
caller process instance'ı canlı event üzerinde doğrulanamadı. Bu ilişki
`unknown` kalır. Üstelik sistem resolver'ını kullanmayan kaynaklar kapsam dışıdır.

## 1. Soru ve kabul sınırı

NS-060'ın sorusu DNS event PID'sinin çağıran process ile gerçek ilişkisi,
cache, resolver service, custom resolver ve DoH/DoT kapsamıdır. Kanıtlanmamış
bir DNS→connection neden ilişkisi kurulamaz. `SUPPORTED` aşağıdaki matriste
yalnız kaynak şeması veya mevcut uygulama sözleşmesiyle desteklenir; canlı
doğrulama anlamına gelmez. `PARTIAL` kapsam, kimlik veya semantik eksiği;
`UNKNOWN` mevcut kanıtla karar verilememesi; `NOT SUPPORTED` kaynağın o
bilgiyi taşımaması; `NOT TESTED` canlı senaryo çalıştırılmamasıdır.

## 2. Mevcut NetSentinel yeteneği ve pasif DNS bulgusu

`domain/dns.py` ve `infrastructure/parsers/dns.py` klasik UDP/TCP 53 için
transaction ID, client/server IP ve port, soru adı/türü, response code,
truncated flag ve en çok 16 A/AAAA/CNAME/PTR cevap değerini ve TTL'sini
taşır. mDNS 5353 ayrı sınıflanır ve klasik transaction history'ye girmez.
`PacketObservation` capture UTC zamanı, interface ve network fingerprint'i
ekler. `DnsTrackingService` network+transport+endpoint+transaction ID+soru
anahtarıyla en çok 1024 pending işlemi eşler; tamamlanma, timeout, eviction,
unmatched response, retry ve latency sonuçlarını üretir. DNS writer yerel
SQLite'a sınırlı metadata yazar; query portu en çok 500 kayıt döndürür. DNS
ekranı bu geçmişi ve capture durumunu gösterir. Capture yalnız kullanıcının
Devices ekranındaki açık eylemiyle başlar; mevcut DNS parser, transaction,
repository ve GUI yollarında PID, process create-time veya caller alanı yoktur.

Pasif capture **DNS paketinin** client IP/port'unu bilir; DNS API caller'ını
bilmez. Aynı anda `GetExtendedUdpTable`/`GetExtendedTcpTable` veya psutil socket
row'u ile source tuple eşlemesi bile yalnız **heuristic** olur: UDP socket kısa
ömürlü olabilir; capture/OS enumeration asenkron ve yarışlıdır; port/tuple
yeniden kullanılabilir; shared Dnscache socket'i service PID'sini gösterebilir;
bir socket birçok sorguyu taşıyabilir. Row yokluğu caller yokluğu değildir.
[Windows UDP owner-PID table](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable),
[TCP owner-PID table](https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable).

## 3. Windows aday kaynakları ve resmi dayanaklar

| Kaynak | Şema/kanıt | Temel sınır |
|---|---|---|
| `Microsoft-Windows-DNS-Client` ETW, GUID `{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}` | Bu hostun `Get-WinEvent -ListProvider` manifesti; Microsoft [3008 Query Completed](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection) örneği | Event header PID caller kanıtı değildir; `ClientPID` payload'ı ve versiyonu ayrıca doğrulanmalı. |
| DNS Client resolver cache | [Resolver akışı](https://learn.microsoft.com/en-us/windows-server/networking/dns/queries-lookups), [cache API](https://learn.microsoft.com/powershell/module/dnsclient/get-dnsclientcache) | Cache entry caller veya gerçek kullanım amacı taşımaz. |
| UDP/TCP owner-PID tabloları | Yukarıdaki Windows API'leri | Anlık socket ownership, DNS API caller veya query identity değildir. |
| Security 5156 (ayrı audit policy) | [Event 5156](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156) | Process/endpoint bağlantı kanıtı olabilir; DNS query adı yoktur. Bu spike'ta açılmadı. |

Microsoft'un [ETW tanımı](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
controller/provider/consumer rollerini ve event/buffer loss sayaçlarını
tanımlar. [Header açıklaması](https://learn.microsoft.com/en-us/archive/msdn-magazine/2009/september/core-os-events-in-windows-7-part-1)
PID/TID'nin event'i yazan thread bağlamından geldiğini açıklar. Header PID'yi
caller PID diye adlandırmak geçersizdir. `ThreadID` de caller kimliği değildir.

## 4. Yerel provider şeması: event ID, version ve korelasyon

Bu host Windows NT `10.0.26200.0` üzerinde `Get-WinEvent -ListProvider
Microsoft-Windows-DNS-Client` ile okunan **yerel** manifest özetidir. Başka
Windows build'leri aynı sürümü/alanı garanti etmez.

| Event | Version | Önemli payload | Yorum |
|---|---|---|---|
| 3006 query called | 0 | `QueryName`, `QueryType`, `QueryOptions`, `IsNetworkQuery`, `NetworkQueryIndex`, `InterfaceIndex`, `IsAsyncQuery` | Caller PID yok. |
| 3008 query completed | 0 | `QueryName`, `QueryType`, `QueryStatus`, `QueryResults` | Sonuç adresleri metin olabilir; TTL alanı yok, caller PID yok. |
| 3009 network initiated | 0/1/2 | `QueryName`, network/interface; v1+ `ClientPID`; v2 pointer blob'lar | `ClientPID` anlamı canlı doğrulanmadı. |
| 3010 wire sent | 0/1 | `QueryName`, `QueryType`, DNS server; v1 `ClientPID` | Yalnız network path; cache hit kanıtı değil. |
| 3011 response received | 0/1/2 | `ResponseStatus`; v1+ `ClientPID`; v2 pointer blob'lar | Raw answer/TTL alanı yok. |
| 3016 cache lookup | 0/1/2 | `QueryName`, `QueryType`; v1+ `ClientPID`; v2 pointer blob | Lookup çağrısı hit anlamına gelmez. |
| 3018 cache lookup returned | 0/1/2 | `Status`, `QueryResults`; v1+ `ClientPID`; v2 pointer blob | Hit/miss kodları ve caller semantiği canlı doğrulanmadı. |
| 3019 wire called | 0/1/2 | `QueryName`, `QueryType`; v1+ `ClientPID`; v2 pointer blob | Caller varsayımı test bekliyor. |
| 3020 wire response | 0/1/2 | `Status`, `QueryResults`; v1+ `ClientPID`; v2 pointer blob | Payload sonucu TTL/provenance sözleşmesi değil. |

Provider manifestinde DNS start/end opcode'ları ve v2 `QueryBlob` gibi alanlar
bulunsa da pointer değerleri kalıcı/portatif correlation ID olarak
belgelenmemiştir. Bu spike, event 3006↔3008 veya 3016↔3018 için tekil,
çakışmasız, public correlation ID doğrulamadı. Aynı isim/tür/PID/zamanla
eşleme concurrent, duplicate ve out-of-order çağrılarda kesin değildir.
ETW `ActivityID`/`RelatedActivityID` her event XML'inde anlamlı veya eşleşen
olarak doğrulanmadı; kesin start/end join yapılamaz. `QueryResults` adından
A/AAAA ayrıştırılabilir varsayımı production sözleşmesi değildir. `ClientPID`
`ProcessIdentity(pid, create_time)` oluşturacak create-time taşımaz.

## 5. Deney düzeni ve ölçülenler

Host: Windows NT 10.0.26200.0; token medium integrity, Administrators veya
Performance Log Users üyeliği görünmedi; **standard user**. DNS Client
service `Running`. `Microsoft-Windows-DNS-Client/Operational` logu `IsEnabled:
False`; değiştirilmedi. Raw event, IP, query history veya ETL saklanmadı.

| Kontrollü deneme | Sonuç | Kanıt sınırı |
|---|---|---|
| `wevtutil gp Microsoft-Windows-DNS-Client /ge:true` ve `Get-WinEvent -ListProvider Microsoft-Windows-DNS-Client` | Yukarıdaki ID/version/alanlar mevcut | Manifest varlığı event emission/caller semantiği değildir. |
| `wevtutil gl Microsoft-Windows-DNS-Client/Operational` | `enabled: false` | Existing event logdan yeni query okunamaz. Log açılmadı. |
| Benzersiz `logman start NS060-DNS-Research-<random> -p Microsoft-Windows-DNS-Client 0xffffffffffffffff 5 -o <TEMP> -ets` | `Access is denied`, exit `-2147024891`; session oluşmadı | Bu token'da session control yok. Otomatik elevation veya başka session stop edilmedi. Temp ETL bırakılmadı. |
| Python `socket.getaddrinfo('example.com',443,AF_INET)` iki kez | 2 sonuç; ~62 ms ve ~0 ms | İlk çağrının cache miss, ikincinin cache hit olduğu **kanıtlanmaz**. ETW/capture yok. Süre yalnız uygulama çağrısıdır. |
| Ayrı child process `getaddrinfo('example.com',443)` | Başarılı; child PID gözlendi | DNS event `ClientPID` ile karşılaştırılamadı. |
| Python `getaddrinfo('example.com',443,AF_INET6)` | `gaierror` | Host resolver sonucu; IPv6 provider coverage kararı değildir. |
| Python `getaddrinfo('localhost',443)` | Başarılı | Yerel resolution; classical network DNS varsayılmaz. |
| `Get-DnsClientCache -Entry example.com` | `PermissionDenied` | Cache içeriği ve hit/miss doğrulanmadı. Önceki sessiz cache count çıktısı geçersizdir. |

NXDOMAIN, process'in query sonrası hemen kapanması, direct custom UDP/TCP 53,
native DoH, browser/application DoH, DoT, IPv6 DNS answer, canlı packet
capture, elevated admin trace, event throughput/CPU/loss/shutdown ve gerçek
`ClientPID` karşılaştırması **NOT TESTED**. Operasyonel log kapalı ve standart
kullanıcı trace açamadığı için gözlenemeyen eventleri yok kabul etmedik.
Sistem cache'i temizlenmedi; DNS yapılandırması değiştirilmedi. Direct custom
resolver testinin gözlemlenebilir bir ETW/capture çıktısı olmayacağından bu
hostta gereksiz harici sorgu üretilmedi. Geçerli controlled measurement:
provider şeması, disabled log ve standard-user session denial. Event-rate,
CPU ve queue pressure sayısı **UNKNOWN**; 0 olarak raporlanmaz.

## 6. Resolver, cache, custom resolver, DoH ve DoT

[Microsoft resolver açıklaması](https://learn.microsoft.com/en-us/windows-server/networking/dns/queries-lookups)
DNS Client service'in önce cache/hosts içeriğine baktığını, miss halinde
server'a sorgu gönderebildiğini belirtir. Bu nedenle klasik port-53 packet
capture cache hit'i kaçırır. Manifestte 3016/3018 cache lookup olayları
bulunsa da bu hostta etkin event akışı olmadığı için hit, miss, negative cache,
`ClientPID`, result ve packet farkı ölçülmedi. 3008'in header PID'si service
PID'si mi caller mı; 3016/3018'in payload `ClientPID`si çağıran child mı;
**UNKNOWN**. Aynı query'nin birden çok process tarafından shared service/cache
üzerinden yanıtlanması ayrıca test gerektirir.

Windows DNS Client API'sini atlayıp kendi UDP/TCP 53 socket'ini kullanan
uygulama networkte klasik DNS paketini üretebilir; provider'ın resolver API
eventleri için coverage'ı **UNKNOWN**, varsayılan olarak yok kabul edilmeli.
Packet capture sorguyu görebilir ama caller PID'yi taşımaz. Windows native
DoH, [Microsoft'un DoH client akışına](https://learn.microsoft.com/en-us/windows-server/networking/dns/doh-client-support)
göre DNS Client path'inde şifreli HTTPS taşıma kullanır; passive 53 parser
göremez. DNS Client ETW'nin query adı/`ClientPID`yi bu path'te hangi event ve
version ile verdiği canlı doğrulanmadı: **UNKNOWN**. [Firefox'un kendi DoH
açıklaması](https://support.mozilla.org/en-US/kb/firefox-dns-over-https)
OS resolver'ını atlayan browser path'ini örnekler; uygulamaya özgü HTTPS
resolver da aynı ayrımı gerektirir. Encrypted payload'a bakmadan domaini
çıkaramayız. Fallback olursa yalnız görünen klasik sorgu kaydedilebilir;
"DoH yoktu" sonucu çıkarılamaz. DoT için encrypted TLS flow query adını
göstermez. Windows native DoT provider kapsamı ve sürüm bağımlılığı bu hostta
**UNKNOWN**; third-party DoT için DNS Client attribution varsayılmaz.

Hosts, localhost, mDNS, LLMNR ve NetBIOS klasik DNS 53 transaction'ı değildir.
DNS Client provider'ı NetBIOS 3012–3014 de içeriyor; bu eventlerin varlığı
onları DNS response gibi kaydetme izni vermez. Local çözümleme, network DNS
yokluğu ve packet visibility sınırı ayrı belirtilmelidir.

## 7. Caller PID, process instance ve privilege

Header `Execution.ProcessID` event'i **yazan** context'tir; `ClientPID`
payload'ı ise bazı event version'larında ayrıca bulunur. Alan adı caller
kanıtı sayılmamalı. Gerekli doğrulama: aynı isim için parent/child ayrı
PID'leri, Dnscache service PID'si, cache miss/hit, eşzamanlı çağrılar ve hemen
exit eden child ile event ID/version/header PID/payload `ClientPID`yi yan yana
karşılaştırmak. Event TID için de benzer şekilde caller thread iddiası yoktur.

`ProcessIdentity(pid, create_time)` semantiğinde PID tek başına process
instance'ı değildir. ETW payload create-time vermez. Event geldiği anda OS
process query başarılı, `create_time <= event time` ve aynı PID için lifecycle
çakışması yoksa **best-effort** instance kanıtı elde edilebilir. Olay gecikirse
process kapanmış veya PID reuse olmuş olabilir; restricted process metadata
ve saat hizalama hatası olabilir. O durumda `pid_only`/`unknown`, farklı
process'e otomatik join yok. NS-056 `MonitoringSessionId` ve
`ConnectionLifecycleId` UUID'leri DNS event identity'si veya resolver
correlation ID'si değildir. NS-057 `ConnectionNetworkScope` local-address
kanıtıdır, route/DNS causal identity değildir. NS-058 freshness/gap bilgisi
stale connection'a attribution güvenini düşürmelidir.

| Token/kaynak | Bu host gözlemi | Production çıkarımı |
|---|---|---|
| Standard user, mevcut pasif capture | Capture ayrı Npcap/interface yeteneğine bağlı; burada başlatılmadı | PID yok; capture açık olsa da DNS→process çıkarılamaz. |
| Standard user, DNS Client Operational log | Kapalı; salt-okunur metadata erişildi | Açmak system state değiştirir; varsayılan açık varsayılmaz. |
| Standard user, kendi DNS Client ETW trace'i | `Access is denied` | Varsayılan kullanıcıda kullanılabilir kabul edilemez. [ETW session controller yetkisi](https://learn.microsoft.com/en-us/windows/win32/etw/controlling-event-tracing-sessions) elevated admin/Performance Log Users/service hesaplarını belirtir. |
| Elevated admin / Performance Log Users | NOT TESTED | Provider enable, event delivery ve loss ayrı controlled VM testi ister. |
| DNS cache read | `PermissionDenied` | Cache'yi canlı doğrulayan alternatif kaynak burada yok. |

## 8. DNS→IP ve DNS→connection anlamı

Dört ayrı önerme korunmalı: **A** process P DNS sorgusu yaptı; **B** DNS
yanıtında domain D→IP X görüldü; **C** process P'nin connection'ı X'e
gözlendi; **D** connection'ın amaçlanan hostname'i D idi. A+B+C doğrulansa
bile D çıkmaz. Bu spike'ta A da doğrulanmadı. Pasif DNS ile B için yalnız
görülen response ve bounded parse kanıtı vardır; yanıtın sonra application
tarafından kullanıldığı bilinmez. Packet kaybı veya unmatched response daha
da sınırlar.

Aynı X birçok D'ye (CDN/shared IP), aynı D birçok A/AAAA X'e gidebilir:
**many-to-many** aday saklanmalı, IP→tek domain map yasak. DNS cevabının TTL'si
kanıtın ne kadar taze olduğunu sınırlar; TTL içinde bile D'yi kanıtlamaz,
TTL=0/stale daha zayıftır. Query A'dan, X bağlantısı B process'inden ise
process association yapılmaz. Caller belirsizse DNS yalnız network-scoped
evidence olabilir; NS-057 scope `UNKNOWN`/`AMBIGUOUS` ise farklı network
context'ler birleştirilmez. Browser prefetch/speculative query, delayed
connection, pool reuse (HTTP/2, HTTP/3), long-lived socket, proxy, shared
resolver, negative result ve çoklu answer sıralaması query→new connection
ilişkisini bozar. Proxy arkasındaki hedef remote IP'den çıkarılamaz. En fazla
"bu adres, bu bağlantı zamanına yakın D için DNS cevabında gözlendi" denebilir.

Gelecek evidence ayrımı: `DIRECTLY_OBSERVED` yalnız gerçek DNS query/answer
veya connection gözlemine; `PROCESS_ASSOCIATED` ancak caller payload ve
instance doğrulanırsa; `IP_ASSOCIATED` aynı IP/zaman/ağ adayına;
`AMBIGUOUS` çoklu aday veya çelişkiye; `UNKNOWN` görünmeyen/kanıtsız alana.
Bunlar ayrı gözlem türlerinin provenance'ı ve confidence'ı olarak tutulmalı;
tek bir "connection hostname" alanına terfi ettirilmemeli. Typed unknown
ayrıca reason (`NOT_OBSERVED`, `UNSUPPORTED_PATH`, `EVENT_LOSS`, `PID_RACE`,
`NETWORK_SCOPE_UNKNOWN`) taşıyabilir; production model bu taskta eklenmedi.

## 9. Loss, kalite, performans, gizlilik

ETW session stats `EventsLost`/`BuffersLost` izlenebilir; event yokluğu sorgu
yokluğu değildir. Gelecekte DNS source quality için `COMPLETE` yalnız ölçülen
path ve intervalde loss yoksa; `PARTIAL` geç başlama veya eksik event;
`LOSS_DETECTED`, `UNSUPPORTED`, `UNKNOWN` ayrı düşünülebilir. Bunlar NS-056'nın
connection poll `COMPLETE/REDUCED/FAILED` kalitesiyle aynı metrik değildir;
iki kaliteyi birleştirip connection confidence yükseltmemek gerekir.
Application tarafında bounded queue, dedup, max event/domain/IP aday sayısı,
TTL expiry, eviction ve overflow sayaçları; stop için bounded drain/join;
yalnız NetSentinel-owned session'ı kapatma gerekir. `ERROR_ALREADY_EXISTS`
başkasının session'ını sahiplenme gerekçesi değildir. Bu hostta event sayısı,
CPU, memory, queue pressure, loss ve stop latency **NOT TESTED**.

DNS adları, process path+domain çifti ve zaman çizelgesi hassastır. Gelecekte
raw DNS history local kalmalı; cloud'a varsayılan gönderim, query adını
log/diagnostics'e basma, command line/environment toplama olmamalı. Event
payload'ındaki gereksiz SID/blob/adapter metadata portable boundary'ye
taşınmamalı. Araştırma yalnız `example.com`/`localhost` controlled adını ve
aggregate sonuçları yazar; gerçek IP veya üçüncü taraf query history kaydetmez.

## 10. Capability matrix

`Diğer Windows source` = salt-okunur resolver cache, owner-PID socket table
veya ayrı audit policy gerektiren 5156; tek birleşik garantili sensor değildir.
`NOT TESTED` çoğunlukla canlı event/privilege kapsamının ölçülmediğini belirtir.

| Capability | Passive packet DNS | DNS Client ETW | Diğer Windows source |
|---|---|---|---|
| Query name | SUPPORTED (53) | SUPPORTED (şema) | PARTIAL (cache) |
| Query type | SUPPORTED | SUPPORTED (şema) | PARTIAL (cache) |
| Answers | SUPPORTED (A/AAAA/CNAME/PTR bounded) | PARTIAL (`QueryResults` metni) | PARTIAL (cache state) |
| TTL | SUPPORTED (wire answer) | NOT SUPPORTED (incelenen event alanları) | PARTIAL (cache kalan TTL) |
| Caller PID | NOT SUPPORTED | PARTIAL (`ClientPID` yalnız bazı version'lar; semantik unknown) | PARTIAL (socket owner PID, query caller değil) |
| Verified ProcessIdentity | NOT SUPPORTED | NOT SUPPORTED (create-time yok) | PARTIAL (anlık OS lookup; race) |
| Cache miss | NOT SUPPORTED | PARTIAL (lookup/wire ayrımı şemada) | UNKNOWN |
| Cache hit | NOT SUPPORTED | PARTIAL (3016/3018 aday; canlı doğrulanmadı) | PARTIAL (entry varlığı hit olayı değil) |
| NXDOMAIN/failure | PARTIAL (response code gözlenirse) | PARTIAL (`QueryStatus`/`Status`; canlı doğrulanmadı) | PARTIAL (negative cache mümkün) |
| Custom resolver | PARTIAL (görünen plain 53, PID yok) | UNKNOWN | PARTIAL (socket owner heuristic) |
| Native DoH | NOT SUPPORTED (53 parser) | UNKNOWN | NOT SUPPORTED (cache/caller join) |
| Browser/application DoH | NOT SUPPORTED | NOT SUPPORTED (OS resolver bypass path) | NOT SUPPORTED (query name) |
| DoT | NOT SUPPORTED | UNKNOWN (native path/version) | NOT SUPPORTED (query name) |
| IPv4 | SUPPORTED (wire) | SUPPORTED (`QueryType`/results şeması; event canlı değil) | PARTIAL (socket/cache) |
| IPv6 | SUPPORTED (wire) | SUPPORTED (`QueryType`/results şeması; event canlı değil) | PARTIAL (socket/cache) |
| Standard user | PARTIAL (Npcap/interface yetkisi ayrı) | NOT SUPPORTED (bu hostta session start denied) | PARTIAL (cache read de bu hostta denied) |
| Admin requirement | PARTIAL (capture config'e bağlı) | PARTIAL (elevated/admin veya Perf Log Users; admin canlı test yok) | PARTIAL (audit policy için yetki) |
| Loss visibility | PARTIAL (capture queue counters) | PARTIAL (ETW session stats; canlı test yok) | UNKNOWN |
| Correlation ID | PARTIAL (wire transaction ID tuple scope) | UNKNOWN (documented unique ID doğrulanmadı) | NOT SUPPORTED |
| Timestamp quality | PARTIAL (capture UTC; scheduling delay) | PARTIAL (ETW timestamp; delivery delay) | PARTIAL (snapshot/audit timing) |
| Process exit race | NOT SUPPORTED (PID yok) | PARTIAL (PID var olabilir, create-time yok) | PARTIAL (row/process disappear) |
| Production complexity | PARTIAL (mevcut capture + unsafe join) | PARTIAL (session/TDH/version/loss/privacy) | PARTIAL (audit config + racing joins) |

## 11. Gelecek mimari, karar ve explicit next actions

**NO-GO:** Varsayılan standard-user NetSentinel için güvenilir
DNS-process attribution production implementation önerilmiyor. 3009/3016/
3018/3019/3020 `ClientPID` adayları umut vericidir ama caller semantiği ve
cache coverage canlı doğrulanmadı; session bu token'da açılamadı. Klasik
pasif DNS B kanıtını sürdürebilir; PID türetmeye veya DNS→connection hostname
iddiasına dönüştürülmez. Production recommendation **no**.

Eğer ürün önceliği sonra değişirse ayrı, açık yetkili disposable Windows VM
çalışması yapılmalı: aynı build ve farklı build'de standard/admin token;
owned bounded ETW session; manifest event ID/version; parent/child/service
PID karşılaştırması; first/repeat/negative cache, process exit, A/AAAA,
direct UDP/TCP 53, native DoH, browser DoH, DoT; event loss/overhead/cleanup.
Event header ve payload PID'leri kaydedilse bile ham domainler repo/log'a
alınmamalı. Yalnız bu doğrulama olumluysa ayrı onaylı task ile infrastructure
adapter → typed application port → domain evidence sınırı tasarlanabilir.
NS-062'nin many-to-many association tasarımı, bu NO-GO'dan bağımsız olarak
pasif DNS kanıtını yalnız correlated/ambiguous/unknown biçiminde ele alabilir.
NS-061'e başlanmadı.

Bu araştırma için production code, migration, GUI, decoder ve test harness'i
eklenmedi. Gerçek event örneği/semantiği yokken sentetik decoder fixture'ı
yanlış güven yaratır. Şu **sentetik metadata karar fixture'ları** gelecek
decoder testinin beklenen konservatif sonucunu tarif eder; gerçek ETW emission
kanıtı değildir:

| Metadata girdisi | Beklenen attribution |
|---|---|
| 3008 v0, yalnız header PID ve `QueryResults` | Caller `UNKNOWN`; domain→answer ayrı gözlem. |
| 3018 v0, `ClientPID` yok | Caller `UNKNOWN`; cache hit olduğu yalnız event adından çıkarılmaz. |
| 3018 v1, `ClientPID=42`, process lookup kapanmış | PID-only evidence; `ProcessIdentity` doğrulanmamış. |
| 3018 v2, `ClientPID=42`, OS create-time mevcut ama event timestamp'inden sonra | PID reuse/race; caller `UNKNOWN`. |
| 3018 v2 + 3020 v2 aynı ad/tür, iki concurrent caller, benzersiz correlation ID yok | Join `AMBIGUOUS`; tek caller/answer ilişkisi uydurulmaz. |
| Aynı IP için iki domain cevabı, tek process connection'ı | İki IP-associated aday; connection hostname `UNKNOWN`. |
| Event loss veya geç başlatılmış session | Eksik aralık `PARTIAL`/`LOSS_DETECTED`; no-query sonucu yok. |

Repo offline kalite kapıları ayrıca çalıştırıldı; sonuçlar commit öncesi
doğrulamada kaydedildi:

| Komut | Sonuç |
|---|---|
| `.\.venv\Scripts\python.exe -m pytest -q` | 1022 passed, 5 deselected |
| `.\.venv\Scripts\python.exe -m ruff check src tests` | All checks passed |
| `.\.venv\Scripts\python.exe -m mypy` | 14 source files, no issues |
| `git diff --check` ve staged `git diff --cached --check` | Whitespace error yok |

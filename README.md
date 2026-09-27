# NetSentinel

NetSentinel, Windows üzerinde çalışan, GlassWire benzeri görünürlük sağlayan ancak ağ güvenliği sinyallerine odaklanan öğretici bir masaüstü uygulaması olarak tasarlanmıştır.

Proje; aktif TCP/UDP bağlantılarını ve süreçlerini izlemeyi, bağlantı geçmişi tutmayı, yerel ağ cihazlarını tanımayı ve ARP, DNS, broadcast ve VLAN gözlemlerinden açıklanabilir güvenlik uyarıları üretmeyi hedefler.

> Durum: NS-001–NS-049 tamamlandı; M8 ve M9 tamamlandı, M10 sürüyor. TCP/UDP connection pipeline'ı ve PyQt6 canlı görünümüne ek olarak connection lifecycle metadata'sı bounded tek-writer hattıyla yerel SQLite'a kaydedilir. Manuel retention servisi varsayılan olarak 30 günden eski tamamlanmış kayıtları ve toplam 100.000 satır sınırını aşan en eski tamamlanmış kayıtları 500 satırlık transaction chunk'larıyla temizler; aktif kayıtları silmez. History ekranı kalıcı kayıtları filtreli, sayfalı ve GUI thread'ini bloklamayan ayrı bir query worker üzerinden gösterir. NS-019, aktif Windows IPv4 interface/subnet/gateway/DNS bağlamını read-only IP Helper API üzerinden normalize eder. NS-020, açıkça seçilen güncel context ve zorunlu capture filtresiyle çalışan, otomatik başlamayan güvenli Scapy sınırını sağlar. NS-021, bu capture callback'i içinde Ethernet/IPv4 ARP request ve reply alanlarını doğrular; canonical MAC/IP değerlerini payload taşımayan immutable observation'a dönüştürür. NS-024, pasif gözlemleri kalıcı Devices ekranında gösterir.

## Tasarım ilkeleri

- Monitoring engine, PyQt6 arayüzünden bağımsız çalışır.
- Domain kuralları; PyQt6, psutil, Scapy ve SQLite ayrıntılarını bilmez.
- Pasif gözlem varsayılandır; aktif keşif açık kullanıcı onayı ve tanımlı kapsam gerektirir.
- Uyarılar tek bir pakete değil, kanıt ve bağlama dayanır.
- Windows'ta sınırlı yetkiyle çalışmak desteklenir; eksik yetenekler arayüzde açıkça gösterilir.
- Her milestone küçük, bağımsız ve test edilebilir tasklara bölünür.

## Dokümantasyon

| Belge | İçerik |
|---|---|
| [Ürün tanımı](docs/PRODUCT.md) | Amaç, kullanıcı senaryoları, özellikler ve kapsam dışı konular |
| [Mimari](docs/ARCHITECTURE.md) | Katmanlar, modüller, veri akışı, concurrency ve klasör planı |
| [Güvenlik](docs/SECURITY.md) | Yetkiler, packet capture riskleri, veri güvenliği ve güvenli kullanım |
| [Yol haritası](docs/ROADMAP.md) | M1-M10 milestone'ları ve tamamlanma koşulları |
| [Task listesi](docs/TASKS.md) | NS-001'den başlayan uygulanabilir işler, bağımlılıklar ve test yöntemleri |

## Hedef teknoloji seti

- Python
- PyQt6
- psutil
- Scapy (yalnızca paket düzeyi gözlem gereken modüllerde)
- SQLite
- pytest

Teknik kararlar ve task sırası için dokümantasyon kaynak kabul edilir.

## Windows taşınabilir paket (NS-050)

Python 3.12+ ve `uv` kurulu bir Windows x64 makinede repo kökünden:

```powershell
uv sync --extra dev --extra packaging
.\.venv\Scripts\python.exe packaging\build_windows.py
.\.venv\Scripts\python.exe packaging\smoke_windows.py
```

Çıktı `dist\NetSentinel\NetSentinel.exe` ve dağıtım için
`dist\NetSentinel-<version>-windows-x64.zip` dosyasıdır. Zip'in SHA-256
değeri yanındaki `.sha256` dosyasında bulunur. Zip klasörü bütünüyle
çıkarılmalıdır; tek başına exe kopyalanarak çalıştırılmaz. `onedir` GUI
uygulaması geliştirme Python'u, `.venv` veya repo çalışma dizini gerektirmez.
İlk açılışta rehber görünür; **Finish** sonrasında tercih korunur. Paket
smoke testi gerçek ağ yakalama/aktif tarama yapmadan farklı çalışma dizini ve
boş kullanıcı verisiyle Qt, SQLite 001–009 migration, 008→009 yükseltme,
ilk/sonraki açılış ve kapanışı sınar. Gerçek temiz Windows VM kontrol adımları
[paketleme kılavuzunda](packaging/README.md) yer alır.

Veri, config ve sınırlı loglar `%LOCALAPPDATA%\NetSentinel` altında kalır;
exe/zip klasöründe oluşturulmaz. Npcap pakete dahil değildir ve otomatik
kurulmaz. Sürücü veya izin yoksa onboarding/Diagnostics durumu açıklar;
core bağlantı izleme ve kayıtlı veriler mümkün olduğu ölçüde kullanılabilir.
Uygulama yönetici yetkisi istemez. Paket imzalanmamıştır; Windows SmartScreen
uyarısı görülebilir. Bağımlılık ve lisans envanteri paket içindeki
`THIRD_PARTY_NOTICES.md` ve `licenses\` dizinindedir. Özellikle PyQt6 ve
Scapy lisanslarının dağıtım koşulları ayrıca incelenmelidir.

## Geliştirme ortamı

NS-047 merkezi çalışma ayarları, kullanıcıya ait `%LOCALAPPDATA%\NetSentinel\config.json`
dosyasından isteğe bağlı okunur. Eksik veya bozuk dosya güvenli varsayılanlara
döner; geçersiz alanlar ayrı kodlarla raporlanır ve diğer geçerli alanlar
korunur. Pasif capture ayarla otomatik başlamaz. Yapılandırılmış, dönen log
`%LOCALAPPDATA%\NetSentinel\netsentinel.log` dosyasına yalnızca UTC zaman,
seviye, bileşen ve sabit olay kodu yazar. Paket/payload, kullanıcı girdisi,
exception metni, SQL ve DB yolu loglanmaz. Diagnostics snapshot'ı mevcut engine,
history writer, capture ve DNS writer sağlık değerleriyle yerel DB durumunu
birleştirir; DB kontrolü çağıranın worker thread'inde yapılmalıdır.

Python 3.12 veya daha yeni bir sürümle, repository kökünde:

İlk GUI açılışında NS-048 rehberi pasif gözlem ve yerel veri sınırlarını açıklar.
Kullanıcı **Finish** demeden tamamlanma yazılmaz. Bu tercih merkezi
`config.json` içindeki `onboarding_completed` alanında saklanır; bozuk config
güvenli varsayılanla rehberi yeniden gösterir. Diagnostics sayfasındaki
**Retry check** capability durumunu worker'da yeniler. Kontrol capture socket'i
açmaz; paket yakalama yalnız Devices ekranındaki açık eylemle başlar. Npcap
veya interface erişimi eksikse kayıtlı görünümler ve çekirdek bağlantı izleme
mümkün olduğu ölçüde çalışır. Capability/health bir güvenlik hükmü değildir.

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --editable ".[dev]"
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\python -m netsentinel --help
.\.venv\Scripts\python -m netsentinel --gui
```

`python -m netsentinel --gui` composition root üzerinden monitoring engine'i, thread-safe Qt bridge'i ve PyQt6 masaüstü kabuğunu başlatır. Dashboard aktif bağlantı özetini ve monitoring health/capability durumunu canlı gösterir; sayaçlar byte/bandwidth ölçümü değildir. Connections sayfası normal Windows kullanıcısının görebildiği aktif TCP/UDP bağlantılarını canlı olarak listeler; process metadata'sı izin nedeniyle alınamazsa güvenli bir `—` placeholder gösterir. Arama process, PID ve endpoint alanlarını kapsar; protocol/state filtreleri birlikte kullanılabilir. Bridge engine başlamadan önce event dispatcher'a attach edilir; pencere kapatıldığında önce detach edilir ve engine için tek, bounded bir stop isteği yapılır. NS-003 ile psutil, NS-008 ile PyQt6 runtime bağımlılığı; geliştirme/test için pytest ve pytest-qt kullanılır. GUI testleri varsayılan olarak Qt'nin `offscreen` platformunda çalışır ve ekran, canlı ağ ya da yönetici yetkisi gerektirmez.

Sidebar'daki **History** sayfası yerel SQLite'ta saklanan connection lifecycle kayıtlarını 50 satırlık bounded sayfalar halinde gösterir. Process adı, PID, protocol, local/remote IP ve isteğe bağlı yerel tarih-saat aralığı filtreleri kullanılabilir; filtre değişikliği ilk sayfaya döner. **Refresh** mevcut filtre ve sayfayı yeniler. Bir satır seçildiğinde portable metadata, yerel saatler, snapshot süresi ve kapanma nedeni gösterilir; “No longer observed” metni gerçek TCP FIN/RST gözlemi iddiası değildir.

Windows network context sağlayıcısı çağrı başına güncel aktif IPv4 bağlamlarını okur. Loopback görünür kalır ancak varsayılan capture adayı değildir; VPN ve sanal interface türleri portable metadata ile ayrılır. Gateway ve DNS bulunamayabilir. Bu senkron sağlayıcı arka plan thread'i açmaz, ağ paketi göndermez ve canlı ağa bağlanmaz; güvenli capture sınırı NS-020'de eklenmiştir.

Packet capture composition sırasında yalnızca dormant bir adapter oluşturur. Capture,
bir NS-019 `NetworkContext` değeri ve boş olmayan BPF filtresi verilmeden başlamaz;
start öncesinde interface/fingerprint tekrar doğrulanır. Callback ham Scapy paketini
saklamadan interface, fingerprint, UTC zaman, uzunluk ve küçük protokol özetinden
oluşan immutable metadata'ya indirger. Bounded queue dolduğunda yeni observation
beklemeden düşürülür ve sayaç/typed diagnostic güncellenir. Loopback LAN capture
için reddedilir; VPN ve virtual adapter yalnızca açık seçimle kullanılabilir.

Windows packet capture, Scapy'ye ek olarak Npcap ve seçilen interface için uygun
yetki gerektirebilir. Eksik bağımlılık, permission denied, interface kaybı, network
değişimi ve transient driver hataları birbirinden ayrılan sanitized capability
durumlarıdır; core connection monitor bu yüzden capture'a bağımlı değildir. Canlı
capture testi varsayılan suite'te yoktur. Yalnızca izinli bir lab ağında açıkça
`NETSENTINEL_LAB_CAPTURE=1` ayarlanarak
`python -m pytest -m lab_live` ile pasif ve packetsiz smoke doğrulaması yapılır.

NS-024 Devices ekranı aktif IPv4 ağ bağlamını seçtirir; kayıtlı cihazları açılışta
yükler ve seçili ağda açıkça başlatılan pasif ARP capture sırasında canlı yeniler.
Tablo canonical MAC, son gözlenen IPv4, ilk/son görülme ve interface/subnet'i
gösterir. Detayda en güncel 20 IP-MAC binding görüntülenir; daha eski kayıtlar
silinmez. Capture kapalı veya kullanılamazken liste yalnızca kayıtlı gözlemleri
temsil eder. Yeni cihaz bildirimi bilgi düzeyindedir ve 60 saniyelik öğrenme
penceresini uygulama detector'ı yönetir. Bu ekranda aktif keşif yapılmaz.

NS-022, doğrulanmış ARP sender bilgilerini ağ fingerprint'ine özgü cihaz ve
IP-MAC binding geçmişine kaydeder. Cihaz kimliği IP yerine canonical MAC ve ağ
bağlamına dayanır; IP değişimi eski binding'i silmez. İlk görülme korunur, son
görülme yalnızca ileri UTC zamanla ilerler. Bu kayıtlar alarm üretmez; Devices
ekranı bu portable state'i gösterir.

NS-023, ilk kez boş görülen ağ bağlamı için varsayılan 60 saniyelik öğrenme
penceresinde başlangıç cihazlarını sessizce envantere alır. Pencere sonrasında
yeni bir network fingerprint + MAC kimliği için bilgi amaçlı, tek bir olay
üretir. Yeniden başlatmada bilinen cihazlar mevcut SQLite repository'sinden
yüklenir; IP değişimi yeni cihaz sayılmaz. Bu olay saldırı hükmü değildir;
Devices ekranı yeni cihaz olayını yalnızca bilgi olarak gösterir.

NS-025, seçili ağdaki mevcut pasif ARP akışından yalnızca Windows
`NetworkContext.gateway` IP'sinin sender gözlemlerini gateway identity
baseline'ına kaydeder. Her network fingerprint ayrı tutulur. İlk aday en az iki
uyumlu gözlem ve 60 saniyelik öğrenme penceresi sonunda, çelişki yoksa
`learned` olur; bu durum kullanıcı doğrulaması değildir. Farklı MAC gözlemi
beklenen kimliği kendiliğinden değiştirmez, aday olarak saklanır. Açık
`GatewayBaselineService.confirm` komutu gözlenmiş adayı doğrular; değişim
zamanları SQLite'ta korunur. Bu aşama güvenlik alert'i veya yeni GUI kontrolü
üretmez.

ARP parser yalnızca mevcut capture callback sınırında çalışır. Desteklenen Ethernet/
IPv4 ARP request ve reply alanları doğrulanır; MAC adresleri küçük harfli iki nokta
formatına, IPv4 adresleri canonical metne çevrilir. Sonuç, NS-019 interface ve
network fingerprint'i ile NS-020 UTC packet metadata'sını taşıyan aynı bounded
queue içinde kalır. Eksik, fazla uzun veya geçersiz ARP alanı yalnızca ilgili
paketi düşürür; raw frame, payload veya Scapy nesnesi domain/application'a geçmez.

NS-026, aynı pasif consumer içinde yakın geçmişteki IP-MAC binding'i ve NS-025
gateway baseline'ını mevcut ARP sender kimliğiyle karşılaştırır. Farklı kimlik
gözlemi fingerprint, eski/yeni MAC ve UTC zamanları içeren geçici güvenlik olayıdır;
saldırgan atfı değildir. IP kuralı 60 saniyelik ilk binding ısınması ve 120
saniyelik yakınlık penceresi kullanır. Gratuitous ARP tek başına karar üretmez.
Gateway `learning` durumunda olay yoktur; `learned` ve `verified` farklı
değerlendirilir. Tekil kanıtın confidence değeri düşüktür. NS-027, bu olayları
aynı consumer içinde sınırlı 120 saniyelik ARP sinyal penceresinde tekrar ve
farklı hedeflerle birlikte puanlar. Kaynak olayın önem düzeyi korunur;
birleşik veya tekrarlanan kanıt `moderate` confidence üretebilir. NS-028 bu
assessment'ları ve yeni cihaz olaylarını fingerprint bazında deduplicate
edilen, bounded kanıt taşıyan yerel alert kayıtlarına dönüştürür.
Onay/çözüm durumu SQLite'ta korunur. Alerts ekranı kalıcı uyarıları önem,
güven, durum ve kanıtlarıyla 50 satırlık sayfalarda gösterir; durum, önem,
güven ve kural filtreleri sunar. Seçili açık uyarı worker üzerinden onaylanır.
Yeni cihaz veya ARP risk sinyali geldiğinde liste yenilenir; tekil paket başına
yeniden sorgulama yapılmaz. Bu gözlemler kesin saldırı veya trafik ele geçirilmesi
hükmü değildir.

NS-030, açıkça başlatılmış ve DNS trafiğini kapsayan capture filtresinden gelen
klasik UDP/TCP port 53 DNS mesajlarını sınırlı, immutable metadata'ya indirger.
mDNS port 5353 ayrı sınıflandırılır. Query/response, transaction ID, soru ve
A/AAAA/CNAME/PTR cevapları gözlenir; bilinmeyen cevap içeriği ile raw payload
tutulmaz. Bu aşamada transaction eşleme, DNS geçmişi, alert veya DNS ekranı
oluşturulmaz. Şifreli DNS (DoH/DoT) içeriği bu parser tarafından görülemez.

NS-031, portable DNS gözlemlerini ağ fingerprint'i, transport, yönlendirilmiş
client/server uçları, transaction ID ve canonical soru bilgisiyle bellek içinde
eşler. Timeout ve latency monotonic saatle ölçülür; pending sorgular ve yakın
zamandaki tamamlanma izleri sınırlandırılır. Eşleşmeyen cevaplar, timeout ve
kapasite tahliyesi portable sonuç olarak döner. mDNS klasik DNS işlemiyle
eşlenmez. DNS history, alert ve ekran henüz bu aşamada yoktur.

NS-032, Windows IP Helper API'den gelen güncel DNS sunucusu setlerini mevcut
engine worker'ında okur. Ağ fingerprint'i başına iki tutarlı okuma ile baseline
kurar; sonraki set değişimini iki ardışık okumayla doğrular. Sıra farkı, tek
geçici/boş okuma ve VPN/interface geçişi alert üretmez. Doğrulanan değişim,
eski/yeni sunucuları ve network context'i içeren düşük önem/orta güvenli bir
yapılandırma gözlemi olarak mevcut AlertService üzerinden kaydedilir. Bu,
DNS trafiği anomalisine veya kötü niyete ilişkin hüküm değildir. DNS history ve
DNS ekranı sonraki taskların kapsamındadır.

NS-033, NS-031'in portable `DnsTransaction` sonuçlarını ayrı UUID kimlikli,
bounded DNS geçmişine kaydeder. Soru ve desteklenen cevap metadata'sı canonical
biçimde yerel SQLite'ta tutulur; raw paket/payload kaydedilmez. Bounded writer
kuyruğu capture tüketicisini SQLite için bekletmez. Geçmiş sorguları zorunlu
limit ve sayfalama kullanır; DNS'e özel manuel retention varsayılan 30 gün,
100.000 kayıt ve 500 satırlık chunk uygular.

NS-034 DNS ekranı, yerel SQLite'taki klasik DNS geçmişini 50 kayıtlık sayfalarda
gösterir. Durum, ilk soru adı/türü, DNS sunucusu ve yerel tarih-saat aralığıyla
filtrelenebilir; seçimde en çok dört soru ve on altı desteklenen cevap, yanıt
kodu, gecikme ve retry bilgisi görünür. DNS yapılandırma değişimi uyarılarına
Alerts ekranından bağlantı vardır. Devices ekranında kullanıcı tarafından
başlatılan pasif capture, ARP ile birlikte port 53 DNS gözlemlerini de mevcut
bounded consumer içinde işler; sonuçlar SQLite writer'a nonblocking iletilir.
Capture kapalı olsa da kayıtlı geçmiş okunur. mDNS geçmişe dahil değildir;
DoH/DoT'nin şifreli içeriği görülemez. Raw DNS packet/wire/payload saklanmaz.

NS-035, mevcut pasif capture callback'inde Ethernet frame'lerini ARP, Ethernet
broadcast, seçili yerel subnet için IPv4 limited/directed broadcast, multicast
ve unicast olarak tek bir sınıfa indirger. ARP frame'i Ethernet broadcast MAC'i
taşısa bile yalnızca ARP sınıfına sayılır. Kategori, mevcut network fingerprint
ve UTC metadata zarfında taşınır; raw frame/payload tutulmaz. Metrik ve baseline
NS-036'da; alert ve dashboard sonraki taskların kapsamındadır.

NS-036, kullanıcı tarafından başlatılmış aynı pasif capture consumer'ında ARP ve
broadcast sınıflarını ayrı, birer saniyelik bucket'lardan oluşan 60 saniyelik
rolling pencerelerde sayar. Paket/saniye, pencere süresine bölünen gözlenen
paket sayısıdır; tüm trafik hacmi veya byte oranı değildir. Fingerprint ve
interface kimliği/index'i başına bellek içi baseline, en az üç tamamlanmış temiz
pencere ve iki dolu pencere/üç gözlemden sonra median oranı öğrenir; idle expiry'ye
kadar sabit tutar. Capture queue kaybı ölçüm güvenini azaltır ve kayıplı pencere
öğrenilmez. Bu baseline bir saldırı veya normal trafik garantisi değildir.
NS-036 metrik/baseline aşaması alert veya dashboard eklemez.

NS-037, öğrenilmiş ağ/interface baseline'ı hazır olduğunda NS-036'nın 60 saniyelik
ARP ve broadcast paket/saniye özetlerini ayrı kurallarla değerlendirir. Mutlak
eşik ve baseline'ın 3 katı birlikte aşılmalı; üç yüksek örnek tam pencereye
yayılmalıdır. Eşik altına kalıcı dönüş alert'i `resolved` yapar. Capture kaybı
confidence'ı düşürür; kalite bilinmiyorsa karar verilmez. Bu sinyal saldırı kanıtı
değildir. Yalnızca aggregate sayaç/eşik metadata'sı saklanır, raw paket/payload
saklanmaz. Görsel metrik kartları NS-038 kapsamındadır.

NS-038 Dashboard'u aynı portable inventory snapshot'ındaki gözlenen broadcast
ve ARP paket/saniye oranlarını, 60 saniyelik rolling pencereyi, öğrenilmiş
baseline durumunu, detector eşik politikasını ve ölçüm kalitesini gösterir.
`Learning baseline` normal trafik hükmü değildir. `Reduced`, capture kuyruğundan
observation düştüğünü ve oranın eksik olabileceğini bildirir; capture kapalıysa
son oranlar stale olabilir. Uyarılar Alerts ekranındadır. İşaretli sentetik
burst testi yerel ağa paket göndermez: `python -m pytest -m performance`.
Gerçek lab capture testi yalnızca mevcut `NETSENTINEL_LAB_CAPTURE=1` kapısıyla
pasif gözlem yapar.

NS-039, gözlenen cihaz/binding kayıtlarından ayrı kullanıcı `DeviceProfile`
kalıcılığı ekler. Profil, ağ fingerprint'i kapsamında etiket, not, açık güven
durumu ve en çok 32 beklenen MAC/IP kimliği taşır. Pasif ARP gözlemi bu alanları
değiştirmez. Aynı ağdaki cihazlar tek profile bağlanabilir; çatışan kullanıcı
etiketleri/notları veya güven durumları veri kaybı olmadan merge'i reddeder.
Birleştirilen eski profil kayıtları okunabilir kalır. Profil düzenleme arayüzü
NS-041, Devices ekranındaki seçili gözlenen cihaz için açık kullanıcı eylemiyle
profil oluşturma/düzenleme ekler. Etiket, not, `unknown/trusted/untrusted`
güven etiketi ve beklenen MAC/IPv4 listeleri yalnızca Save ile kaydedilir;
Cancel hiçbir profil değişikliği yapmaz. Gözlenen MAC/IP'nin beklenen listeye
alınması ayrı düğmeye bağlıdır. “Trusted” kullanıcı işaretidir; kimlik doğrulama
veya güvenli/zararsız olma garantisi değildir. Pasif gözlem profili değiştirmez.
Profil düzenlemeleri ayrı bounded worker üzerinden SQLite'a gider; ham paket
veya payload tutulmaz. İlgili kimlik uyarıları Alerts ekranında profil ve ağ
kapsamıyla açılır. Merge/silme arayüzü bu taskın kapsamı dışındadır.

NS-040, seçili ağın profil ve son binding geçmişini inventory worker'ında her
refresh için bir kez sınırlı olarak okur. Beklenmeyen MAC, beklenen MAC'in başka
bir profil için beklenen IP'de görülmesi ve beş dakikada üç farklı beklenmeyen
IP'den oluşan churn, mevcut AlertService'e açıklanabilir sinyal gönderir. Tek
DHCP IP değişimi alarm üretmez; locally administered MAC tek başına saldırı
kanıtı değildir. Beklenen kimlikler ve güven durumu yalnızca kullanıcıya aittir;
pasif gözlemler bunları değiştirmez. Alert'e kısa kimlik/bağlam kanıtı gider,
profil notu ve ham paket/payload gitmez. Bu sinyaller kesin saldırı hükmü değildir.

NS-043, mevcut pasif capture callback'inde görülen Ethernet frame'lerini
`untagged`, tekli 802.1Q için `priority_tagged` (VID 0), `tagged` (VID 1–4094),
`reserved` (VID 4095) veya iç içe etiket için `stacked` olarak normalize eder.
Yalnızca dış etiketin VID, PCP, DEI ve kapsüllenmiş EtherType bilgisi taşınır;
iç etiket ve payload tutulmaz. Bu aşamada VLAN baseline, alert, SQLite kaydı
veya UI görünümü yoktur. NIC/driver offload etiketi capture noktasından önce
çıkarabilir; bu nedenle `untagged` gözlemi ağda VLAN bulunmadığını kanıtlamaz.
Mevcut capture filtresi VLAN frame'lerini kapsamıyorsa parser bu trafiği görmez.

NS-044, yalnızca bu portable VLAN gözleminden fingerprint ve interface başına
kalıcı, bounded SQLite özeti oluşturur. `untagged` ve etiket türleri ayrı
sayılır; normal VID 1–4094 için count ve ilk/son görülme saklanır. En az 60
saniye ve iki normal etiket gözleminden sonra, en az iki kez görülen VID'ler
pasif `learned` baseline'a alınır. Sonradan gelen VID özette görünür ama
baseline'ı otomatik değiştirmez. Bu liste güvenilir switch konfigürasyonu
değildir; NIC offload ve capture filtresi görünürlüğü sınırlar.

NS-045, pasif `learned` kümenin açık `verify_baseline` application komutuyla
kabul edilmesini ayrı `verified` durumunda saklar. Bu kabul switch
konfigürasyonunu veya ağdaki VLAN'ların tamamını doğrulamaz. Yalnızca bu durum
hazırken yeni normal VID iki ayrı ileri zamanlı gözlemle 120 saniye içinde
sinyal üretir; üç doğrulanmış yeni VID 60 saniyede çeşitlilik sinyali olur.
Capture adapter'ı Ethernet kaynak MAC'ini canonical, payload içermeyen portable
metadata'ya indirger. Aynı ağ/interface kapsamındaki gözlenen cihazın önceki
normal VID'sinden farklı VID'ye iki kez geçişi düşük güvenli cihaz tag değişimi
sinyalidir. Kaynak kimliği yoksa bu kural çalışmaz. Sonuçlar geçici portable
adaydır; AlertService kaydı, kalıcı alert ve GUI bağlantısı NS-046'ya aittir.
Tek `untagged`, VID 0, VID 4095 veya QinQ gözlemi yeni normal VID sayılmaz.
NIC offload ve BPF görünürlüğü sınırlar; sinyaller VLAN hopping kanıtı değildir.
Aktif VLAN probing/injection yoktur.

NS-046, VLAN detector adaylarını mevcut AlertService yaşam döngüsüne bağlar.
Dashboard seçili ağ/interface için kayıtlı VLAN özetini, normal VID başına sayım
ve ilk/son görülmeyi, ayrı etiket kategorilerini ve pasif öğrenme durumunu
gösterir. `learned` kullanıcı kabulü değildir; `verified`, yalnızca açık
`verify_baseline` komutuyla donmuş gözlenen referansın kabulüdür, switch
yapılandırması veya kriptografik doğrulama değildir. Yeni VID sinyali VLAN
hopping kanıtı değildir. `untagged` gözlemi VLAN yokluğunu kanıtlamaz; NIC/driver
offload ve capture filtresi tag görünürlüğünü sınırlayabilir. İç QinQ tag'i
parse edilmez. Capture kapalıyken ekran önceki kayıtları gösterir. Ham frame
ve payload saklanmaz.

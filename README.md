# NetSentinel

NetSentinel, Windows üzerinde çalışan, GlassWire benzeri görünürlük sağlayan ancak ağ güvenliği sinyallerine odaklanan öğretici bir masaüstü uygulaması olarak tasarlanmıştır.

Proje; aktif TCP/UDP bağlantılarını ve süreçlerini izlemeyi, bağlantı geçmişi tutmayı, yerel ağ cihazlarını tanımayı ve ARP, DNS, broadcast ve VLAN gözlemlerinden açıklanabilir güvenlik uyarıları üretmeyi hedefler.

> Durum: NS-001–NS-036 tamamlandı; M6 tamamlandı, M7 sürüyor. TCP/UDP connection pipeline'ı ve PyQt6 canlı görünümüne ek olarak connection lifecycle metadata'sı bounded tek-writer hattıyla yerel SQLite'a kaydedilir. Manuel retention servisi varsayılan olarak 30 günden eski tamamlanmış kayıtları ve toplam 100.000 satır sınırını aşan en eski tamamlanmış kayıtları 500 satırlık transaction chunk'larıyla temizler; aktif kayıtları silmez. History ekranı kalıcı kayıtları filtreli, sayfalı ve GUI thread'ini bloklamayan ayrı bir query worker üzerinden gösterir. NS-019, aktif Windows IPv4 interface/subnet/gateway/DNS bağlamını read-only IP Helper API üzerinden normalize eder. NS-020, açıkça seçilen güncel context ve zorunlu capture filtresiyle çalışan, otomatik başlamayan güvenli Scapy sınırını sağlar. NS-021, bu capture callback'i içinde Ethernet/IPv4 ARP request ve reply alanlarını doğrular; canonical MAC/IP değerlerini payload taşımayan immutable observation'a dönüştürür. NS-024, pasif gözlemleri kalıcı Devices ekranında gösterir.

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

## Geliştirme ortamı

Python 3.12 veya daha yeni bir sürümle, repository kökünde:

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

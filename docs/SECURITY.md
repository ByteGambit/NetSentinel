# Güvenlik ve güvenli kullanım

## 1. Güvenlik yaklaşımı

NS-047 yerel config dosyasını en çok 16 KiB olarak okur. Geçersiz alanlar
güvenli varsayılana döner; okuma/parsing hatası tüm varsayılanları kullanır.
Config, pasif capture'ı veya yetki yükseltmeyi otomatik başlatamaz. Dönen log
dosyası varsayılan olarak 1 MiB ve üç yedekle sınırlıdır. Log kaydı yalnızca
UTC zaman, seviye, sabit bileşen ve olay kodu içerir; free-form mesaj,
exception/traceback, secret, payload, SQL, DB yolu veya kullanıcı notu
serileştirilmez. Diagnostics DB yolu veya raw hata taşımaz; DB hatası yalnızca
`unavailable` olarak görünür. Log yazma hatası monitoring akışını durdurmaz.

NetSentinel savunma, görünürlük ve eğitim amacıyla tasarlanır. Uygulama mümkün olan en düşük yetkiyle çalışmalı; ek yetenek gerektiren her işlem için kullanıcıya nedenini ve kapsamını açıkça göstermelidir.

Uygulama bir güvenlik sınırı veya kesin saldırı tespit sistemi değildir. Uyarılar incelenmesi gereken belirtilerdir; yanlış pozitif ve eksik görünürlük mümkündür.

NS-048 onboarding tamamlanmadan capture başlatmaz, aktif paket göndermez ve
yetki yükseltmez. Capability kontrolü uygun bir interface için NS-020 probe
kullanır; bu işlem driver/interface varlığını inceleyebilir ancak capture
socket'i açmadığı için erişim iznini kesin doğrulamaz. Gerçek izin reddi ancak
kullanıcı Devices ekranında açıkça capture başlattığında görülebilir. Eksik
Npcap/Scapy, interface veya izin ayrı sanitized nedenler olarak gösterilir;
otomatik driver kurulumu ya da elevation yoktur. İlk açılış metni yerel bounded
connection/device/DNS/alert metadata saklanabileceğini, kullanıcı notunun
yalnız açık Save ile yazıldığını, raw packet payload ve credential
saklanmadığını anlatır. Capability veya diagnostics bir güvenlik hükmü değildir.

## 2. Yetki modeli

### Standart kullanıcıyla hedeflenen işlemler

- psutil'in izin verdiği ölçüde TCP/UDP connection snapshot'ı alma
- Erişilebilen PID/process metadata'sını okuma
- Mevcut kullanıcıya ait ayar, log ve SQLite verisini yazma
- History ve UI ekranlarını kullanma
- Windows API'lerinin standart kullanıcıya sunduğu interface, gateway ve DNS bilgisini okuma

NS-019 network context adapter'ı bu son işlemi Windows IP Helper API üzerinden
salt-okunur yapar. Yerelleştirilmiş komut çıktısı çalıştırılmaz veya parse edilmez;
socket açılmaz, DNS lookup yapılmaz, paket gönderilmez ve yetki yükseltme istenmez.
Erişim reddi ile geçici platform hatası typed capability kaybı olarak ayrılır.

Bazı sistem process'lerinin adı, executable yolu veya sahibi standart kullanıcıya kapalı olabilir. Bu durum hata değil, `unavailable/restricted` metadata olarak modellenir.

### Yönetici yetkisi veya capture driver gerektirebilen işlemler

- Scapy ile belirli interface'lerde promiscuous veya düşük seviye packet capture
- Npcap kurulumu, onarımı veya capture interface'lerine erişim
- Tüm kullanıcıların/process'lerin ayrıntılı connection/process bilgisini okuma
- Aktif ARP keşfi gibi ham paket gönderme işlemleri
- Bazı ağ yapılandırması ve route ayrıntılarını sorgulama

Uygulama baştan sona zorunlu olarak administrator çalıştırılmamalıdır. Bunun yerine capability detection yapılır; düşük yetkide desteklenen modüller çalışır, eksik özellikler “degraded” olarak görünür. Yetki yükseltme otomatik ve sessiz gerçekleşmez.

## 3. Aktif ağ işlemleri

Varsayılan davranış pasiftir. Aktif keşif veya gelecekte eklenebilecek güvenlik testi ancak şu koşullarla yapılabilir:

- Kullanıcı özelliği açıkça etkinleştirir.
- Hedef interface/subnet kullanıcıya gösterilir ve kapsam sınırlandırılır.
- İşlem yalnızca kullanıcının sahibi olduğu, yönettiği veya test izni aldığı ağda yapılır.
- Paket/sorgu hızı güvenli bir üst sınırla rate-limit edilir.
- İşlem durdurulabilir ve audit log'a kaydedilir.

İnternet geneline tarama, exploit çalıştırma, credential saldırısı, trafik bozma, ARP poisoning, deauthentication veya başka bir sisteme zarar verebilecek aktif eylemler ürün kapsamı dışındadır.

## 4. Packet capture riskleri

Packet capture aşağıdaki riskleri taşır:

- DNS adları, IP adresleri, cihaz kimlikleri ve iletişim metadata'sı kişisel/hassas veri olabilir.
- Payload; token, cookie, parola veya özel içerik barındırabilir.
- Yüksek trafik bellek, CPU ve disk tüketimine yol açabilir.
- Malformed paketler parser hatalarını veya üçüncü taraf kütüphane açıklarını tetikleyebilir.
- Capture driver kurulumu ve yüksek yetkili çalışma saldırı yüzeyini büyütür.

Azaltımlar:

- Yalnızca gerekli protokol başlıkları parse edilir; ham payload varsayılan olarak tutulmaz ve loglanmaz.
- Capture filtreleri ve seçili interface ile veri hacmi daraltılır.
- Packet boyutu, queue kapasitesi ve işleme oranı sınırlandırılır.
- Parser girdileri güvenilmeyen veri kabul edilir; uzunluk/tür kontrolleri yapılır.
- Capture callback'i ağır analiz veya DB yazımı yapmaz.
- Hatalı paket uygulamanın tamamını düşürmeden ölçümlenir ve atlanır.
- Scapy/Npcap ve diğer bağımlılıklar sabitlenmiş, desteklenen sürümlerde tutulur.

NS-020 capture sınırı composition sırasında Scapy import etmez, interface okumaz,
socket açmaz veya worker başlatmaz. Capture ancak güncel NS-019 `NetworkContext`
değeri, açık interface kimliği ve boş olmayan en fazla 256 karakterlik filtre ile
başlatılabilir. Start öncesi provider yeniden okunur; kaybolan interface, değişen
network fingerprint ve loopback LAN capture isteği socket açılmadan reddedilir.
VPN ve virtual interface'ler otomatik seçilmez ancak kullanıcı/üst katman açıkça
seçtiğinde sessizce dışlanmaz.

Production Scapy backend seçili interface'te `promisc=False`, `store=False` ve
bounded output queue ile çalışır. Callback DB, UI, DNS lookup veya detector çağırmaz;
ham Scapy nesnesini ve payload'ı saklamadan yalnızca interface/fingerprint, UTC
capture zamanı, captured/original length ve küçük link/network protokol özetini
portable observation'a dönüştürür. Queue dolduğunda producer beklemez; yeni kayıt
düşürülür ve bounded sayaç ile typed overflow diagnostic'i güncellenir. Stop yeni
observation kabulünü önce kapatır, Scapy stop/join işlemini timeout ile sınırlar ve
başarılı kapanışta capture socket'ini kapatır. Timeout worker'ı görünür `stopping`
durumunda bırakır; ikinci worker başlatılmaz.

Scapy paketi veya Npcap bulunmaması, permission denied, interface unavailable,
network changed ve transient capture failure raw exception metni taşımayan ayrı
capability nedenleridir. Eksik capture yeteneği connection monitoring'i durdurmaz.
NS-020 capture lifecycle testleri Scapy importu, Npcap, canlı network veya
yönetici yetkisi gerektirmeyen fake backend kullanır. NS-021'in varsayılan parser
testleri Scapy ile yalnızca in-memory sentetik paket oluşturur; capture socket'i
açmaz. `lab_live` smoke testi ayrıca
`NETSENTINEL_LAB_CAPTURE=1` onayı ister, yalnızca pasif start/stop yapar; packet
inject etmez, subnet taramaz ve observation gelmesini zorunlu tutmaz.

### NS-024 kontrollü M4 lab doğrulaması

Bu prosedür yalnızca sahibi olduğunuz veya açıkça test izni aldığınız yerel
ağda uygulanır. Önce seçilecek interface/subnet'i doğrulayın; aynı makinedeki
VPN veya sanal adapter'ı yanlışlıkla seçmeyin. Windows'ta Npcap ve interface
erişimi yoksa capability mesajını kaydedip testi geçin; sessiz yetki yükseltme
yapmayın. Yetkili lab için PowerShell'de `NETSENTINEL_LAB_CAPTURE=1`,
`NETSENTINEL_LAB_INTERFACE_NAME` ve `NETSENTINEL_LAB_SUBNET` değerlerini
seçtiğiniz tek aktif bağlama göre açıkça ayarlayıp
`python -m pytest -m lab_live tests/integration/sqlite/test_device_inventory.py`
çalıştırın. Test yalnızca seçili interface'te `arp` filtresiyle yarım saniyelik
pasif capture yapar, geçici SQLite veritabanı kullanır ve `finally` bloğunda
capture'ı durdurur. Gözlem gelmesi zorunlu değildir. Paket enjeksiyonu, aktif
tarama, spoofing veya ağdaki diğer cihazlara gönderim yapılmaz. Normal test
suite'i bu marker'ı dışlar ve gerçek LAN, Npcap veya yönetici yetkisi istemez.

NS-021 ARP parser'ı raw Scapy paketini yalnızca aynı infrastructure callback
scope'unda inceler. Ethernet/ARP header alanları sabit tür ve uzunluk sınırlarıyla
doğrulanır; yalnızca IPv4 request/reply metadata'sı canonical MAC/IP değerlerine
indirgenir. Frame bytes, padding ve payload kopyalanmaz, loglanmaz veya domain'e
taşınmaz. Malformed/unsupported bir ARP paketi diğer paketleri ya da capture
worker'ını durdurmaz; mevcut bounded malformed sayacı ve sanitize diagnostic ile
izole edilir. Parser paket göndermez, ARP keşfi/poisoning yapmaz ve gözlemden
saldırı kararı üretmez.

NS-043 802.1Q parser'ı yalnızca açıkça başlatılmış mevcut pasif capture
callback'inde çalışır. Frame ve payload saklamadan, görülen dış VLAN etiketinin
VID/PCP/DEI/EtherType alanlarını bounded immutable metadata'ya indirger;
stacked trafikte iç etiket okunmaz. Bozuk etiket tek frame'i düşürür ve mevcut
sanitized malformed diagnostic'ini günceller. VLAN etiketi gözlenmemesi
etiket bulunmadığı anlamına gelmez: NIC/driver offload capture öncesi etiketi
çıkarabilir; capture filtresi de tagged trafiği dışlayabilir. Bu parser ağ
paketi göndermez, VLAN anomali kararı veya alert üretmez.

NS-044 aynı portable `PacketObservation.vlan` bilgisinden ağ/interface kapsamlı
aggregate üretir. SQLite'da yalnızca tür sayıları, normal dış VID için sınırlı
count/ilk-son UTC zamanları ve pasif öğrenme durumu saklanır; frame, payload,
iç QinQ etiketi ve kaynak cihaz kimliği saklanmaz. VID 0 priority tag ve
VID 4095 reserved normal öğrenilmiş VLAN listesine alınmaz. Öğrenilen liste
gözlenen davranıştır, güvenilir/eksiksiz ağ yapılandırması değildir. NIC/driver
offload etiketi capture öncesi çıkarabilir; seçili BPF filtresi de görünürlüğü
sınırlar. Bu yüzden `untagged` sayacı ağda VLAN olmadığını veya switch port
modunu kanıtlamaz. Bu aşama alert veya aktif ağ işlemi üretmez.

NS-045 pasif `learned` normal VID kümesini yalnızca açık application komutuyla
kabul edilmiş `verified` durumda portable VLAN gözlemiyle karşılaştırır.
`verified`, kullanıcının gözlenen referansı kabul ettiğini belirtir; switch
yapılandırması, yetkilendirme veya ağdaki bütün VLAN'ların eksiksiz listesi
değildir. Pasif gözlemler verification zamanını değiştirmez. En az iki ileri zamanlı
gözlemden gelen yeni VID sinyali de VLAN hopping veya saldırı kanıtı değildir.
`untagged` görünüm, NIC VLAN offload veya capture filtresinden etkilenebilir;
tek başına tag kaybı veya switch port değişimi sayılmaz. VID 0, reserved 4095
ve iç etiketi okunmayan QinQ normal yeni VID kuralına girmez. Özet kapasitesi
aşıldığında eksik referanstan güçlü karar çıkmaz. Detector'ın geçici kanıtı
yalnızca bounded kategori, VID, kapsam, sayım, UTC zaman ve görünürlük notudur;
raw frame/payload veya kimlik bilgisi taşımaz. Infrastructure yalnızca canonical
Ethernet kaynak MAC'ini portable gözleme kopyalar; detector mevcut ağ kapsamlı
gözlenen cihaz UUID sözleşmesini kullanır ve MAC'i alert kanıtına yazmaz. Zero,
broadcast ve multicast kaynak cihaz sayılmaz; locally administered unicast MAC
pasif gözlenen kimlik olabilir. Cihaz kimliği yoksa cihaz tag değişimi atfedilmez.
Aktif VLAN sorgulama, injection veya switch etkileşimi yoktur.

NS-046 Dashboard, yalnızca seçili ağ/interface için kalıcı aggregate metadata
gösterir. `learned` pasif referanstır; `verified`, kullanıcının gözlenen donmuş
seti açıkça kabul etmesidir, switch konfigürasyonu veya kriptografik doğrulama
değildir. Yeni VID uyarısı VLAN hopping kanıtı değildir. Untagged görünüm VLAN
yokluğunu kanıtlamaz; NIC/driver offload ve capture filtresi tag'leri
gizleyebilir. İç QinQ etiketi parse edilmez. Alert kanıtı VID, kapsam, sayım
ve sınırlama ile bounded kalır; raw frame/payload saklanmaz. Uyarı yazma
hatasında bounded bellek retry'si diğer pasif gözlem yollarını durdurmaz.

NS-035 Ethernet/IPv4 broadcast sınıflandırması da aynı pasif capture callback'i
içinde yapılır. Header türü/adresi doğrulanır; bozuk frame mevcut malformed
sayacı ve sanitized diagnostic ile atlanır. Portable sonuç yalnızca tekil
kategori ve L2 broadcast bayrağı taşır; frame, adres/payload, Scapy nesnesi
veya ek kalıcı kayıt taşımaz. Directed broadcast yalnızca seçili güncel
`NetworkContext.subnet` için tanınır. Bu sınıflandırma saldırı hükmü veya
otomatik capture başlatma davranışı oluşturmaz.

NS-036, aynı açıkça başlatılmış capture consumer'ında yalnızca NS-035'in portable
ARP/broadcast sınıfını sayar. Bellekte fingerprint/interface kapsamında en fazla
64 context ve context başına 60 bucket tutulur; 600 saniye gözlemsiz context
temizlenir. Snapshot yalnızca aggregate paket sayısı/oranı, baseline öğrenme
özeti ve capture queue kaybı/güven durumunu taşır. Source MAC/IP listesi, raw
frame/payload, credential veya DNS içerikleri tutulmaz; SQLite'a yazılmaz.
Kayıplı capture ölçüm güvenini düşürür. Öğrenilmiş baseline ve yüksek oran,
tek başına saldırı hükmü değildir; NS-036 alert üretmez.

NS-030 DNS parser'ı yalnızca açıkça seçilmiş capture filtresinde görülen klasik
UDP/TCP port 53 ve ayrı sınıflandırılan mDNS port 5353 mesajlarını işler.
Transaction ID, endpoint, sınırlı soru ve A/AAAA/CNAME/PTR cevap metadata'sı
immutable observation'a geçer; cevaplar 16, sorular 4, DNS mesajı 65535 byte
ile sınırlıdır. Raw wire/payload, bilinmeyen record içeriği ve Scapy nesnesi
saklanmaz veya loglanmaz. Compression döngüsü, bozuk uzunluk ve malformed kayıt
yalnızca ilgili paketi düşürür. DoH/DoT şifreli içeriği bu parser tarafından
görülemez; görünmemesi güvenli DNS kullanıldığına veya kullanılmadığına dair
bir hüküm değildir. NS-030 DNS alert'i veya kalıcılık üretmez.

NS-031 korelasyonu yalnızca bu sınırlanmış DNS metadata'sını memory-only
state'te tutar. Varsayılan en fazla 1024 pending işlem ve 1024 yakın
tamamlanma izi, monotonic timeout ile temizlenir; raw DNS wire, packet,
payload, kimlik bilgisi veya SQLite kaydı tutulmaz. Eşleşmeyen yanıtlar
uydurma query oluşturmadan portable observation sonucu olur. Yanıt kodu ve
truncated flag saldırı hükmü veya alert'e çevrilmez.

NS-032, DNS trafiği veya packet capture kullanmadan yalnızca yerel Windows DNS
yapılandırmasını salt-okunur izler. Fingerprint başına en çok 256, 24 saat idle
expiry'li memory-only baseline tutulur; tek boş/geçici okuma beklenen seti
değiştirmez. Doğrulanan set değişimi düşük önem ve orta güvenli yapılandırma
gözlemidir; DNS hijacking veya saldırı hükmü değildir. Alert kanıtı en çok
8 canonical IPv4 sunucunun eski/yeni setini ve kısa metadata'yı taşır. DNS
baseline/history tablosu, raw paket, payload, hostname veya sorgu içeriği
eklenmez. Poll mevcut engine worker'ında yürür ve ağ trafiği üretmez.

NS-033 DNS history, yalnızca NS-031'in klasik DNS `DnsTransaction` sonucunu
yerel SQLite'a kaydeder: ağ fingerprint'i, UDP/TCP, canonical client/server
IP ve portları, 16-bit DNS transaction ID, en çok 4 canonical soru adı/türü,
query/response UTC zamanları, mikrosaniye latency, response code, durum,
truncated bayrağı, retry sayısı ve en çok 16 desteklenen canonical cevap
adı/türü/değeri/TTL. Ayrı UUID record ID kullanılır. mDNS transaction
korelasyonuna dahil olmadığından DNS history'ye yazılmaz. Raw packet/frame,
DNS wire/payload, Scapy nesnesi veya diğer application verisi tutulmaz.
Hostname'ler hassas gezinti metadata'sıdır. Sorgu adı uzunluğu NS-030 sınırına
tabidir; query API en fazla 500 satır döndürür ve SQL parametreleri kullanır.
Writer kuyruğu varsayılan 2048 kayıt kapasitelidir; taşma ve hata yalnızca
typed sayaç/kod olarak görünür. DNS'e özel manuel retention varsayılan 30 gün,
100.000 satır ve 500 satırlık transaction chunk'ları uygular; otomatik VACUUM
yoktur. Kapanıp açılınca geçmiş okunur, canlı pending correlation restore
edilmez. DNS history kaydı tek başına alert üretmez.

NS-034 DNS ekranı aynı yerel, sınırlandırılmış metadata'yı gösterir; yeni DNS
alanı veya raw payload toplamaz. Sorgu adı/sunucu/zaman/durum/tür filtreleri
repository'nin parametreli sorgusuna gider. Kullanıcı tarafından Devices
ekranında başlatılan pasif capture klasik port 53 DNS'yi mevcut bounded akışta
izler; otomatik capture veya yetki yükseltme yoktur. Capture kapalıyken kayıtlı
geçmiş yine okunur. Ekran DoH/DoT ve mDNS görünürlük sınırını açıkça bildirir.
DNS adları hassas gezinti metadata'sı olabilir; kayıtlar yerel SQLite retention
politikasına tabidir. Hata ekranı SQL, DB yolu veya traceback göstermez.

NS-063 DNS result'a origin'de canonical UUID verir; history storage UUID'si
ayrıdır. Yerel association tablosu yalnız canonical domain/IP, bounded CNAME
zinciri, provenance, network/client scope, UTC observed/expiry ve TTL tutar.
PID, process adı/path, connection hostname, raw packet ve payload eklenmez.
Resolver semantic association key değildir. Tablo yazma sırasında 100.000
satır hard cap, manuel DNS retention'da 30 gün/100.000 satır sınırı kullanır;
sorgular zorunlu limit taşır. Eski history satırındaki NULL evidence ID gerçek
origin kanıtıymış gibi doldurulmaz. Source retention veya write failure sonrası
eksik kaynak, DNS observation yokluğu şeklinde yorumlanmaz. Hata diagnostics'i
domain/IP/DB yolu/SQL içermez; veri yerel SQLite dışına gönderilmez.

NS-064, yeni connection history kayıtlarında yalnız exact network scope
status/fingerprint/interface ID/index/method ve son scope'un başlangıç UTC
zamanını yerel SQLite'a ekler. Eski kayıtların scope'u tahmin edilmez. Detail
worker'ları scoped DNS association ve mevcut local ASN/country dataset'ini
okur; en çok 32 candidate ve legacy göstergesi için en çok 128 kayıt inceler.
GUI DNS verisini hostname veya process attribution olarak sunmaz; IP/domain
cloud servisine, tarayıcıya veya clipboard'a gönderilmez.

## 5. Veri gizliliği ve saklama

NetSentinel'in topladığı IP, hostname, DNS ve process bilgileri hassas olabilir.

- Veriler varsayılan olarak yalnızca yerel makinede tutulur.
- Telemetry veya bulut aktarımı varsayılan değildir; ilk kapsamda yoktur.
- Ham paket payload'ı ve DNS cevap payload'ının gereksiz bölümleri saklanmaz.
- Process command line toplanmaz; NS-052 executable path'i yalnız yerel, best-effort process metadata olarak okur. NS-054 path'i en çok 4096 karakterlik connection history snapshot'ında yerel olarak saklar; path log/diagnostics'e veya dış servise gönderilmez. Yerel DB şifreli varsayılmaz.
- Network context yalnızca interface kimliği/görünen adı ve türü, IPv4 adres/subnet,
  isteğe bağlı gateway/DNS adresleri, UTC gözlem zamanı ve türetilmiş fingerprint
  taşır. MAC, packet payload, hostname veya kullanıcı verisi NS-019'da toplanmaz
  ve bu bağlam bu task kapsamında kalıcılaştırılmaz.
- Loglarda sırlar, payload, tam hata dump'ı veya gereksiz kullanıcı yolu bulunmamalıdır.
- Retention süresi yapılandırılabilir; temizlik transaction'lı ve testli olmalıdır.
- Connection history için varsayılan politika 30 gün, tüm active/completed
  lifecycle kayıtları birlikte sayıldığında en fazla 100.000 satır ve transaction
  başına en fazla 500 silmedir. Önce 30 günlük age politikası, ardından row
  politikası uygulanır; ayarlar pozitif integer olmalıdır.
- Yalnızca tamamlanmış (`closed_at_utc_us IS NOT NULL`) lifecycle kayıtları
  retention'a uygundur. Aktif (`closed_at_utc_us IS NULL`) kayıtlar ne age ne row
  politikasıyla silinir; aktif satırlar row kapasitesini kullansa da güvenlik
  sınırı olarak korunur. Tam age cutoff mikrosaniyesindeki kayıt da korunur.
- Manuel cleanup aynı güvenli kuralları kullanır, bounded chunk'lar arasında
  durdurulabilir ve önceki commit'leri korur. Retention otomatik `VACUUM`
  çalıştırmaz; SQLite/WAL dosyaları silme sonrasında hemen küçülmeyebilir.
- Storage diagnostics yalnızca ana DB ve varsa WAL dosyasının byte boyutlarını
  ve lifecycle satır sayılarını taşır; DB path, SQL, payload veya raw exception
  içermez. WAL dosyası yoksa boyutu sıfır raporlanır.
- UI, hassas alanların kopyalanması veya dışa aktarılması ileride eklenirse kullanıcıyı kapsam konusunda bilgilendirmelidir.
- SQLite dosyası `%LOCALAPPDATA%/NetSentinel/netsentinel.sqlite3` altında kullanıcı
  profiline uygun izinlerle yerel tutulur; repository/install/current-working
  directory içine production verisi yazılmaz. Disk şifreleme işletim sisteminin
  sorumluluğundadır; ürün bunu varmış gibi varsaymaz.
- Connection history yalnızca lifecycle metadata'sı saklar; ham paket veya payload
  kolonu içermez.
- NS-022 cihaz tabloları yalnızca network fingerprint, canonical sender MAC/IP ve
  ilk/son UTC görülme zamanlarını saklar. ARP target, raw frame, payload ve Scapy
  nesnesi kalıcılaştırılmaz. Cihaz/binding state'i saldırı veya güven kararı değildir.
- NS-039 kullanıcı profilleri ayrı SQLite tablolarında etiket (en çok 128
  karakter), not (en çok 1024 karakter), açık güven durumu/zamanı ve en çok
  32'şer beklenen canonical MAC/IPv4 kimliği saklar. Bunlar hassas kullanıcı
  girdileridir; pasif ARP gözlemi profili oluşturmaz veya değiştirmez. Merge
  aynı ağ fingerprint'iyle sınırlıdır; çelişen kullanıcı değerleri transaction
  içinde reddedilir, eski profil alias olarak saklanır. Profil verisi raw
  packet, payload, secret, process veya DNS içeriği taşımaz. Bu adımlar capture
  başlatmaz ve güven/kimlik sapması alert'i üretmez.
- NS-040 beklenen MAC/IP ve trust değerlerini yalnızca kullanıcıya ait beklenti
  olarak okur; pasif gözlem bu alanları, etiketi, notu veya trust değişim zamanını
  yazmaz. Ağ fingerprint'i dışındaki profiller karşılaştırılmaz. Tek DHCP IP
  yenilemesi alert üretmez; locally administered MAC tek başına malicious
  sayılmaz. Beklenmeyen kimlik veya IP churn şüpheli gözlem sinyalidir, kesin
  spoofing/saldırı kanıtı değildir. Alert yalnızca kısa profil etiketi/UUID,
  canonical MAC/IP, ağ bağlamı, güven gerekçesi ve UTC zamanı saklar. Kullanıcı
  notu, ham ARP paket/frame ve payload alert'e veya detector state'ine kopyalanmaz.
- NS-041 profil arayüzü gözlenen MAC/IP'yi ancak açık kullanıcı eylemiyle
  beklenen kimliğe ekler. `trusted`, kullanıcı tarafından verilen bir etikettir;
  kimlik doğrulama, kriptografik güvence veya zararsızlık anlamına gelmez.
  Save/Cancel ayrıdır; profil notu yalnızca seçili profil detayında gösterilir,
  alert'e ve tanılama kaydına taşınmaz. İşlemler yerel SQLite worker'ında
  yürür, pasif capture başlatmaz ve raw packet/payload saklamaz.
- NS-042'nin sentetik senaryoları tek DHCP adres yenilemesinde MAC mismatch
  veya yüksek önem alert'i oluşmadığını, üç farklı beklenmeyen IP'nin beş
  dakikalık pencerede düşük önem churn sinyali ürettiğini doğrular. Beklenen
  locally administered MAC normal kimliktir; yeni randomized/private MAC tek
  başına saldırı hükmü veya önem yükseltme nedeni değildir. Aynı mantıksal
  kimlik uyarısı uygulama yeniden kurulduğunda NS-028'in kalıcı fingerprint/UUID
  kaydına birleşir. Alert'e kullanıcı notu, ham ARP frame'i veya payload
  aktarılmaz. [Karar tablosu](DEVICE_SECURITY_DECISIONS.md) gözlem ile
  kullanıcı beklentisinin ayrımını ve sinyal sınırlarını gösterir.
- NS-023 yeni cihaz olayı yalnızca warm-up sonrasında ilk kez gözlenen network
  fingerprint + MAC kimliği için bilgi amaçlıdır. İlk envanter import'u alert
  üretmez; restart'ta bilinen cihazlar repository'den yüklenir. Pasif ARP
  gözlemi cihazın güvenilirliğini veya saldırı olup olmadığını doğrulamaz.
- NS-025 gateway baseline'ı yalnızca güncel Windows context gateway IP'siyle
  eşleşen portable ARP sender IP/MAC değerini kullanır. İlk gözlem veya tek
  çelişki doğrulanmış kimliği değiştirmez. `learned` otomatik adaydır;
  `verified` yalnızca açık kullanıcı komutudur. Farklı MAC pending aday olarak
  saklanır ve tek başına saldırı kanıtı sayılmaz. SQLite yalnızca fingerprint,
  gateway IP, canonical MAC, sınırlı durum/sayaç ve UTC zamanları tutar;
  ARP target, raw frame, packet payload ve Scapy nesnesi tutulmaz.
- NS-026 iki pasif kimlik uyuşmazlığı kuralı kullanır. Olay, MITM veya trafik
  ele geçirilmesi hükmü değildir; tekil gözlemin güveni düşük tutulur.
  Gratuitous ARP, stale/out-of-order veri ve ağ geçişi tek başına yüksek
  confidence oluşturmaz. Olay evidence'ı yalnızca canonical IP/MAC,
  fingerprint, baseline durumu ve UTC zamanlarından oluşur; raw paket/payload
  veya exception text içermez. Olaylar bu aşamada kalıcılaştırılmaz.
- NS-027 korelasyonu bu portable kimlik olaylarını 120 saniyelik, fingerprint'e
  özgü ve bellek sınırı olan state içinde tekrar ve farklı hedef kanıtlarıyla
  puanlar. Tekil olay `low` confidence kalır; yalnızca tekrar veya birleşik
  kanıt `moderate` olur. Kaynak severity yükseltilmez. Sonuçlar geçicidir ve
  yalnızca rule breakdown, canonical kimlik, sayaç ve UTC zaman metadata'sı
  taşır; raw paket, payload, saldırgan atfı veya alert kalıcılığı içermez.
- NS-028 alert kayıtları yalnızca canonical IP/MAC, network fingerprint,
  detector rule/assessment sonucu, sınırlı score breakdown, UTC zamanlar,
  durum ve tekrar sayısı saklar. Kanıt en son 8 özetle sınırlıdır; raw frame,
  payload, kimlik bilgisi, Scapy nesnesi veya exception text veritabanına
  geçmez. Aynı issue kalıcı fingerprint ile birleşir; onay kullanıcı eylemidir,
  gateway kimliğinin doğrulanması veya saldırı kanıtı değildir. Yalnızca
  confidence/severity geçişi veya 120 saniye aralığı yeni bildirim üretir.
  Alert saklama süresi/temizliği bu task kapsamında tanımlanmaz.
- NS-037 yoğunluk kararı yalnızca NS-036'nın öğrenilmiş ARP/broadcast baseline'ı
  ve aggregate rolling oranlarıyla verilir. Öğrenme ve ölçüm kalitesi bilinmeyen
  durumlarda karar yoktur; capture queue kaybı confidence'ı düşürür ve kayıplı
  ölçüm recovery sayılmaz. Ani oran artışı saldırı veya DoS kanıtı değildir.
  Alert evidence'ı bounded pencere/sayaç/eşik/kalite metadata'sıyla sınırlıdır;
  raw frame, packet payload, kaynak listesi veya credential tutulmaz.
- NS-038 Dashboard yalnızca seçili ağ/interface için aggregate oran, baseline,
  eşik politikası ve kayıp observation sayısını gösterir. Öğrenilmiş baseline
  saldırı veya normal trafik hükmü değildir; `REDUCED` eksik örnekleme anlamına
  gelir. Sentetik yük testi fake backend kullanır ve ağa trafik göndermez.
  Opt-in gerçek lab testi yalnızca izinli interface'te pasif capture yapar;
  flood veya packet injection içermez.
- NS-029 Alerts ekranı yalnızca bu kalıcı, bounded kanıt özetlerini gösterir.
  Eski/yeni MAC ile ağ bağlamını açıklar; tek gözlemden kesin saldırı veya
  trafik ele geçirilmesi sonucu çıkarmaz. Onay, kullanıcı inceleme durumudur;
  gateway baseline doğrulaması değildir. Sorgu ve onay SQLite erişimini tek
  arka plan worker'ında yapar; hata metni, SQL, DB yolu ve raw paket UI'ya geçmez.
- Connection history persistence kuyruğu portable lifecycle metadata'sıyla ve
  yapılandırılabilir sabit kapasiteyle sınırlıdır. Queue dolduğunda monitoring
  thread'i DB için beklemez; yeni event kontrollü düşürülür ve toplam drop sayısı
  ile typed overflow diagnostic'i görünür olur.
- Persistence retry ve shutdown drain süreleri bounded'dır. Diagnostic'ler raw
  SQL, DB path, exception mesajı, stack trace veya process secret taşımaz; yalnızca
  kararlı hata kodu, component, severity ve UTC zaman içerir.
- Connection history sorgularındaki zaman, process, PID, protocol ve endpoint
  filtreleri yalnızca SQLite parameter binding ile uygulanır; process/IP girdisi
  SQL metnine eklenmez. Sonuçlar zorunlu ve üst sınırı olan pagination ile okunur.
- History GUI sorgu hatalarını sabit kullanıcı mesajına dönüştürür; raw SQLite
  exception, SQL metni, traceback veya DB path widget/signal payload'ına taşınmaz.
  Hızlı filtre değişiklikleri capacity-one query handoff ve cooperative cancellation
  ile sınırlandırılır; eski request sonucu daha yeni görünür state'i değiştiremez.
- Uygulamanın bildiğinden yeni schema version'ı yazma modunda reddedilir. Otomatik
  downgrade, tablo silme veya version geri çekme uygulanmaz.

### NS-071 yerel davranış öğrenme verisi

Behavior baseline yalnız yerel SQLite'ta versioned, bounded summary olarak
tutulur. Stable canonical executable key, varsa SHA-256 revision, resolved
network fingerprint, en çok 64 destination IP/32 port/2 protocol aggregate'i,
sample/coverage/quality sayaçları ve UTC zamanlar hassas metadata'dır. PID/ad
kalıcı application identity değildir; provisional ve unresolved session scope
restart boyunca saklanmaz. Raw event/poll/bucket/payload history, cloud isteği
ve history upload eklenmemiştir.

En fazla 512 row ve row başına 16 KiB feature payload vardır; 90 günlük expiry
cleanup en çok 64 row transaction'larla ilerler. 30 günlük stale reference veya
clock anomaly READY sayılmaz. Corrupt/version/policy mismatch otomatik trusted
restore veya repair edilmez. Retention/eviction geçmişin eksik olduğunu gösterir;
eksik baseline “never seen” veya zararsızlık kanıtı değildir. Offline/restart gap
monitored süreye çevrilmez. Scoped reset yalnız learning reference'i temizler,
trust/mark-normal değildir; backend queue kabulü durable delete garantisi değildir,
write failure/dirty completion izlenmelidir. NS-075 Connections detayındaki
explicit confirmation yalnız gösterilen application + revision + network scope'u
sıfırlar. Cancel command, DB write veya dirty-state mutation üretmez. Completion
receipt, reset bayrağını taşıyan exact-scope writer transaction'ının sonucunu
bildirir; eski sequence yeni reset'i tamamlanmış gösteremez. UI storage failure'ı
typed/sanitized gösterir; accepted/failure sonrası backend retry olabileceğini
açıklar. Raw exception, feature listesi, path veya hash loglanmaz. Text plain text
ve bounded preview'dır; trust, mark-normal veya automatic allowlist eklenmez.

Diagnostics yalnız aggregate sayı ve typed storage/lifecycle durumu taşır;
executable key/path, IP, hash, feature değerleri ve raw SQL/exception loglanmaz.
Bu learning state güvenlik verdict'i veya forensic bütünlük garantisi değildir.

## 6. Güven sınırları ve tehditler

### Güvenilmeyen girdiler

- Yakalanan tüm Ethernet/IP/ARP/DNS/VLAN alanları
- Hostname ve DNS text değerleri
- Process adları ve dosya yolları
- Interface adları
- SQLite'tan okunan eski veya bozulmuş kayıtlar
- Kullanıcı tarafından girilen cihaz adları/notları

Bu değerler SQL parametreleriyle işlenir, UI'da markup olarak yorumlanmaz, log injection'a karşı normalize edilir ve uzunluk sınırlarıyla tutulur.

### Yerel saldırgan ve bütünlük

Standart kullanıcı hesabına veya veritabanına yazma erişimi olan bir saldırgana karşı adli bütünlük garantisi verilmez. Alert kayıtları kanıt yardımcılarıdır; imzalı/append-only forensic log değildir. Bu sınır kullanıcıya açıkça belirtilmelidir.

### Ayrıcalıklı süreç riski

Yönetici yetkili süreçte GUI, dosya açma veya geniş eklenti yüzeyi çalıştırmak risklidir. İlk sürüm tek süreçli olsa bile elevated kullanım minimize edilir. İleride ayrı capture helper tasarlanırsa dar IPC sözleşmesi, input validation ve kimlik doğrulaması ayrı tehdit modeliyle ele alınmalıdır.

## 7. Alert güvenliği

- Tek observation kesin saldırı olarak sunulmaz.
- Alert'te observation, baseline, rule ID, confidence ve zaman bilgisi bulunur.
- Deduplication/rate limiting alert storm ve kaynak tüketimini sınırlar.
- Ağ değişimi, DHCP yenileme, NIC uyku/uyanma ve VPN bağlanması gibi normal nedenler hesaba katılır.
- Kullanıcının “trusted” işareti veriyi silmez; suppression kararı izlenebilir olmalıdır.
- Detector başarısızlığı “güvenli” sonucu üretmez; capability/health eksikliği olarak görünür.

## 8. Bağımlılık ve dağıtım güvenliği

NS-050 taşınabilir Windows paketi standart kullanıcı bağlamında (`asInvoker`)
çalışır; Npcap'i bundle etmez, indirmez veya kurmaz, otomatik UAC/elevation
başlatmaz. Paket açılışında capture otomatik başlamaz. Capture yokken
Diagnostics/ilk rehber kısıtlı yeteneği gösterir; kayıtlı yerel veri ve core
bağlantı izleme mümkün olduğu ölçüde sürer. DB/config/log yalnızca
`%LOCALAPPDATA%\NetSentinel` altında tutulur; kurulum veya geçici açma
dizinine yazılmaz. Loglar aynı bounded ve redacted sözleşmeyi kullanır;
raw packet/payload saklanmaz. Paket imzasızdır ve SmartScreen uyarısı çıkabilir.
Paketin `THIRD_PARTY_NOTICES.md` envanteri ve `licenses/` içeriği dağıtım
öncesi lisans incelemesinin yerini tutmaz.

- Bağımlılıklar desteklenen sürüm aralıklarıyla sabitlenir ve düzenli taranır.
- Paketleme çıktısı temiz ortamda ve tekrarlanabilir komutlarla oluşturulur.
- Npcap gibi sistem sürücüleri uygulama paketine lisans ve güvenlik incelemesi olmadan gömülmez.
- İndirilen binary veya driver doğrulanmadan çalıştırılmaz.
- Release artefact'ları için checksum ve mümkün olduğunda code signing planlanır.
- Debug log ve geliştirme seçenekleri production paketinde hassas veri açığa çıkarmamalıdır.

## 9. Lab ve yetkilendirme politikası

Aktif güvenlik testleri yalnızca:

- kullanıcının kendi sistemlerinde,
- açıkça izin verilmiş ağlarda veya
- izole eğitim/lab ortamlarında

yürütülür. Bir özelliğin teknik olarak mümkün olması yetkilendirme anlamına gelmez. NetSentinel kullanıcıyı kapsamı doğrulamaya yönlendirir ve yetkisiz kullanımı kolaylaştıracak otomatik saldırı özellikleri sağlamaz.

## 10. Güvenlik açığı bildirme

Genel bir issue açmadan önce repository sahibiyle özel iletişim kanalı belirlenmelidir. Repository public hale geldiğinde bu bölüm güvenlik bildirim adresi, desteklenen sürümler ve koordineli açıklama süreciyle güncellenecektir. Gerçek capture içeriği, kişisel IP/DNS verisi veya secret içeren örnekler issue'lara eklenmemelidir.

## 11. Yeni faz threat/privacy modeli — planlanan özellikler

Bu bölüm M11–M17 tasarım gereksinimleridir. NS-052 executable path metadata'sı, NS-066 on-demand local executable hash ve NS-068 offline signer evidence uygulanmıştır; reputation provider, incident ve firewall henüz uygulanmamıştır. NS-067 [offline Authenticode araştırması](research/NS-067-offline-authenticode.md) ve GO kararıdır. Mevcut paket otomatik elevation yapmaz; bu kural gelecek fazlarda da korunur.

### Yerel metadata ve veri minimizasyonu

Process path kullanıcı adı/kurulum düzeni içerebilir; DNS/IP/connection history ve incident timeline kişisel davranış gösterebilir. Hash dosyanın içeriği değildir ama executable kimliğini ifşa edebilir. Bu veriler, device trust, baseline, user preference, suppression ve reputation cache varsayılan olarak yerel kalır. **NetSentinel does not upload your network history by default.** Yerel DB'nin adli bütünlük garantisi yoktur; saklama süresi, bounded disk kullanımı, açık export/purge ve evidence-reference expiry tanımlanır. Diagnostics/feedback/export yalnız kullanıcıya önizletilmiş, seçilmiş sanitized metadata taşır; path, domain, IP, hash, provider key, raw exception, payload ve notların redaction sınırları test edilir. Otomatik crash/history upload yoktur.

Executable hashing on-demand bounded worker'da yapılır; dosya çalıştırılmaz, değişen dosyanın sonucu yeniden kullanılmaz, UNC/network path ve symlink varsayılan olarak okunmaz. Hash diskte okunan dosya byte'larının fingerprint'idir; process'in yüklenmiş image bütünlüğünü veya güvenliğini kanıtlamaz. Worker 1 GiB/5 saniye, 64 pending path, tek aktif iş ve 128 cache girişiyle sınırlıdır. Cache file ID, size ve mtime metadata'sına dayanır; metadata çakışması ve okuma sonrası dosya değişimi nedeniyle mutlak TOCTOU garantisi vermez. Hash/path/dosya içeriği diagnostics veya network'e çıkmaz. NS-068 signer doğrulaması da yalnız açık detail isteğinde tek bounded worker'da çalışır; UNC/symlink okunmaz, hedef yürütülmez veya DLL olarak yüklenmez. WinTrust `WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE` kullanır: online revocation yapılmaz, sonuç `not_checked` kalır. Catalog membership hash'i Windows API hesaplar; NS-066 raw SHA-256 kullanılmaz. Metadata kontrolü mutation'ı saptamaya çalışır ama atomik file snapshot veya loaded image kanıtı değildir. Cache en fazla 128 giriş/60 saniye tutulur; trust store/catalog değişimi TTL boyunca görünmeyebilir. Signature, local Windows policy trust, publisher string ve certificate SHA-256 güvenlik veya malware hükmü değildir. Standard user ile erişilebilir yerel dosyada çalışır, elevation istemez. NS-067 ağ trafiğini paket düzeyinde ölçmedi; NS-068 de bu ortamda bağımsız cryptsvc trafiğini ölçmedi. Signer metadata'sı yalnız GUI'de gösterilir, DB/diagnostics/cloud'a yazılmaz. Signed olmak güvenli, unsigned olmak zararlı anlamına gelmez.

### Threat intelligence ve dış sınır

M15 reputation özelliği **default DISABLED**; temiz başlangıçta hiçbir reputation request yoktur. Consent provider, subject type (public IP/domain/SHA-256) ve gönderilen veri bazında ayrı açık eylemdir. Tüm IP/domain/hash history topluca gönderilmez; file bytes, executable path, command line, raw packet, user note veya secret gönderilmez. Private/local adresler varsayılan dışlanır. Provider'ın kendi log/retention politikasının güvenilir olduğu varsayılmaz; seçim öncesi terms/privacy ve rate-limit incelenir. Provider verdict destekleyici evidence'dır; tek başına malware veya automatic blocking kararı üretmez. No-hit, offline, stale, timeout, 429 ve provider failure ayrı durumlar olarak görünür.

API key normal config, DB evidence, log, diagnostics, export veya UI error text'ine girmez; ayrı secret-storage port gerekir. Adapter yalnız sabit/allowlisted provider endpoints'e bağlanır. Evidence içindeki URL/host keyfi fetch tetikleyemez; response body, redirect, concurrency, timeout, retry ve queue boyutları bounded olur. Consent geri alındığında henüz başlamamış sorgular durur; cache purge ayrı kullanıcı kontrolüdür. DNS/IP reputation network isteği provider'a konu veriyi ve bağlantının source IP'sini gösterebilir; kullanıcı bunu önceden görür.

### Windows telemetry privilege ve güven sınırı

NS-059–061 kontrollü spike'ları Windows EStats/ETW privilege, session ownership, buffer/loss, rate ve shutdown etkilerini ölçer. Kernel ETW veya TCP EStats enable işlemleri yüksek yetki gerektirebilir; read-only oldukları varsayılmaz. Uygulama otomatik admin elevation, service/driver installation veya kullanıcı grup üyeliği değişikliği yapmaz. ETW event'lerinin command line/UserSID gibi gereksiz alanları portable boundary'ye taşınmaz. WFP custom callout varsayılan çözüm değildir. Spike GO sonucu production izin veya implementasyon yetkisi sayılmaz; ayrı plan ve threat model gerekir. Per-flow ölçüm yoksa `unknown` gösterilir, sıfır veya interface toplamı connection'a atfedilmez.

NS-059 [araştırma kararı](research/NS-059-per-flow-byte-telemetry.md) NO-GO'dur. Salt-okunur EStats probe bile collection'ın kapalı olduğunu gösterebilir; `SetPerTcp[6]ConnectionEStats` bir sistem state değişimidir ve NetSentinel başka uygulamanın etkinleştirdiği collection'ı kapatmaz. Bu task ETW session, WFP filter veya driver oluşturmadı.

NS-061 [event-source araştırma kararı](research/NS-061-process-connection-event-sources.md) mevcut ürün için NO-GO'dur. Bu hostun medium-integrity standart kullanıcı token'ı ile üç sınırlı ETW session denemesi access denied oldu; başarıyla açılmış session, canlı payload veya elevated doğrulama yoktur. NetSentinel otomatik elevation yapmaz; gelecekteki event kaynağı ancak ayrı task ve yetki/gizlilik incelemesiyle ele alınır. Command line, UserSID ve raw ETW payload varsayılan portable telemetry veya diagnostics'e girmez. Yalnız doğrulanmış NetSentinel-owned session kapatılabilir.

### M18 conditional response ve rollback

M18, **M17 tamamlanmadan, NS-099 gate geçmeden ve explicit response GO kararı verilmeden başlatılamaz.** Automatic blocking ve automatic elevation yasaktır. Gelecekte ilk model explicit user action → target/scope/profile/expiry preview → confirmation → dar NetSentinel-owned Windows Firewall rule → audit → undo/expiry'dir. Program path kuralı PID veya hash engeliymiş gibi; destination IP kuralı domain/CDN engeliymiş gibi gösterilmez. Yetki yoksa degraded sonuç açıkça görünür; supported local monitoring/trust devam eder.

NetSentinel yalnız kendi oluşturduğu rule ID/manifest üzerinde ownership iddia eder. Duplicate, stale, externally edited ve partial failure durumları reconcile edilir; rollback yalnız owned rules'a uygulanır. Uninstall sırasında yetki yoksa kural kaldırıldı varsayılmaz: kalan owned rules kullanıcıya açıkça listelenir. Unrelated user/system rules hiçbir durumda değiştirilmez. Response audit gizli veri veya raw history yüklemez. Gerçek rule etkisi ancak explicit isolated Windows lab/VM testleriyle doğrulanır.

### Public beta ve güncelleme

M17, standard user ve Npcap missing koşullarında temiz install/upgrade/uninstall, VPN, sleep/wake, normal browser/updater, notification/false-positive burden ve storage/privacy davranışını doğrular. Signing/update kararı ayrı spike'tır; otomatik update check veya download varsayılan olarak başlamaz. Gelecekteki update mekanizması artefact bütünlüğünü/imzasını ve downgrade/rollback politikasını doğrulamadan çalıştırmaz; ağ isteği ve gönderilen version/channel bilgisi kullanıcıya açıklanır.

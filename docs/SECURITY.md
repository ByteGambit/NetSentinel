# Güvenlik ve güvenli kullanım

## 1. Güvenlik yaklaşımı

NetSentinel savunma, görünürlük ve eğitim amacıyla tasarlanır. Uygulama mümkün olan en düşük yetkiyle çalışmalı; ek yetenek gerektiren her işlem için kullanıcıya nedenini ve kapsamını açıkça göstermelidir.

Uygulama bir güvenlik sınırı veya kesin saldırı tespit sistemi değildir. Uyarılar incelenmesi gereken belirtilerdir; yanlış pozitif ve eksik görünürlük mümkündür.

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

## 5. Veri gizliliği ve saklama

NetSentinel'in topladığı IP, hostname, DNS ve process bilgileri hassas olabilir.

- Veriler varsayılan olarak yalnızca yerel makinede tutulur.
- Telemetry veya bulut aktarımı varsayılan değildir; ilk kapsamda yoktur.
- Ham paket payload'ı ve DNS cevap payload'ının gereksiz bölümleri saklanmaz.
- Process command line varsayılan olarak toplanmaz; executable path ancak ürün için gerekliyse ve açıkça belgelenerek eklenir.
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

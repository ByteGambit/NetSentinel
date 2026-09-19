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

## 5. Veri gizliliği ve saklama

NetSentinel'in topladığı IP, hostname, DNS ve process bilgileri hassas olabilir.

- Veriler varsayılan olarak yalnızca yerel makinede tutulur.
- Telemetry veya bulut aktarımı varsayılan değildir; ilk kapsamda yoktur.
- Ham paket payload'ı ve DNS cevap payload'ının gereksiz bölümleri saklanmaz.
- Process command line varsayılan olarak toplanmaz; executable path ancak ürün için gerekliyse ve açıkça belgelenerek eklenir.
- Loglarda sırlar, payload, tam hata dump'ı veya gereksiz kullanıcı yolu bulunmamalıdır.
- Retention süresi yapılandırılabilir; temizlik transaction'lı ve testli olmalıdır.
- UI, hassas alanların kopyalanması veya dışa aktarılması ileride eklenirse kullanıcıyı kapsam konusunda bilgilendirmelidir.
- SQLite dosyası `%LOCALAPPDATA%/NetSentinel/netsentinel.sqlite3` altında kullanıcı
  profiline uygun izinlerle yerel tutulur; repository/install/current-working
  directory içine production verisi yazılmaz. Disk şifreleme işletim sisteminin
  sorumluluğundadır; ürün bunu varmış gibi varsaymaz.
- Connection history yalnızca lifecycle metadata'sı saklar; ham paket veya payload
  kolonu içermez.
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

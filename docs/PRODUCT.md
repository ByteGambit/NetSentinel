# Ürün tanımı

## Ürünün amacı

NetSentinel, Windows kullanıcısına bilgisayarının ve bağlı olduğu yerel ağın davranışını anlaşılır biçimde gösteren, yerel çalışan bir network security monitoring uygulamasıdır. Amaç yalnızca trafik göstermek değil; bağlantı, süreç, cihaz kimliği ve temel ağ protokolleri arasındaki ilişkiyi açıklayarak kullanıcının networking ve cybersecurity bilgilerini geliştirmesine yardımcı olmaktır.

Ürün, GlassWire benzeri bir masaüstü görünürlüğünü aşağıdaki güvenlik sorularına odaklar:

- Bilgisayarım şu anda hangi uzak sistemlerle iletişim kuruyor?
- Bu bağlantıyı hangi process oluşturdu ve bağlantı ne zaman açılıp kapandı?
- Yerel ağda hangi cihazlar var, hangileri yeni veya kimlik değiştirmiş görünüyor?
- Gateway veya başka bir IP için MAC eşleşmesi beklenmedik biçimde değişti mi?
- ARP, broadcast, DNS veya VLAN gözlemlerinde açıklanması gereken bir anormallik var mı?
- Bir uyarı hangi kanıtlara dayanıyor ve kullanıcı bunu nasıl yorumlamalı?

NetSentinel bir öğrenme aracı olarak, ham gözlemi, türetilmiş olayı ve güvenlik uyarısını birbirinden ayırır. Uyarıların açıklaması ve dayanak verisi kullanıcıya sunulur; tek başına “kötü niyetli” hükmü verilmez.

## Hedef kullanıcılar

- Networking ve cybersecurity öğrenen geliştiriciler
- Kendi Windows bilgisayarında ağ davranışını anlamak isteyen teknik kullanıcılar
- Yetkili ev ağı veya izole lab ortamında savunma odaklı gözlem yapan öğrenciler
- Küçük bir ağda temel görünürlük isteyen ancak kurumsal SIEM/NDR işletmeyen kullanıcılar

## Temel kullanım senaryoları

### 1. Canlı bağlantı görünürlüğü

Kullanıcı aktif TCP/UDP bağlantılarını; durum, local/remote endpoint, PID, process adı ve gözlem zamanı ile görür. Yeni ve kapanan bağlantılar ekranda güncellenir.

### 2. Geçmiş inceleme

Kullanıcı daha önce açılmış bağlantıları zaman, process veya endpoint üzerinden inceler. Uygulamanın yeniden başlatılmasından sonra geçmiş korunur ve yapılandırılmış saklama süresine göre temizlenir.

### 3. Yerel ağ envanteri

Uygulama pasif ARP gözlemleriyle cihazları, IP-MAC eşleşmelerini ve son görülme zamanlarını kaydeder. Kullanıcı isterse yalnızca sahibi olduğu veya açıkça izinli bir ağda sınırlı aktif keşfi ayrıca etkinleştirir.

### 4. MITM/ARP şüphesi inceleme

Gateway MAC değişikliği, aynı IP için çelişkili MAC gözlemi veya olağandışı ARP davranışı tespit edildiğinde uygulama kanıt içeren ve önem seviyesi belirlenmiş bir uyarı üretir.

### 5. DNS görünürlüğü

Kullanıcı DNS sorgu ve cevaplarını, mümkün olduğunda sorgu-cevap korelasyonunu ve sistem DNS sunucusu değişikliklerini görür.

### 6. Broadcast ve VLAN farkındalığı

Uygulama broadcast/ARP yoğunluğunu zaman pencereleri içinde ölçer; yakalanan trafikteki 802.1Q etiketlerini gösterir ve öğrenilmiş tabana göre şüpheli değişiklikleri raporlar.

## Planlanan özellikler

### Bağlantılar

- Aktif TCP ve UDP bağlantılarını listeleme
- PID ve process bilgisiyle ilişkilendirme
- Local/remote IP ve portları gösterme
- Yeni, güncellenen ve kapanan bağlantıları gerçek zamanlı algılama
- Connection history ve basit trafik/olay istatistikleri

### Yerel ağ ve cihazlar

- LAN cihazlarını ve IP-MAC eşleşmelerini takip etme
- Yeni cihaz algılama
- Bilinen cihaz profilleri, kullanıcı etiketi ve güven durumu
- Cihazın MAC/IP kimliğindeki şüpheli değişiklikleri saptama

### Güvenlik gözlemleri

- Gateway MAC değişikliği ve IP-MAC çakışması algılama
- ARP spoofing/MITM belirtilerini kanıtlarla raporlama
- Broadcast ve ARP yoğunluğu için zaman pencereli anomali tespiti
- DNS sorgu/cevap görünürlüğü ve DNS sunucusu değişikliği algılama
- 802.1Q VLAN tag okuma ve beklenmeyen VLAN davranışı uyarıları
- Önem seviyesi, yaşam döngüsü, deduplication ve kanıt alanları olan alert sistemi

### Kullanıcı arayüzü ve veri

- PyQt6 dashboard
- Connections, Devices, DNS ve Alerts ekranları
- SQLite tabanlı yerel history/log saklama
- Yetkinlik ve izin durumunu açıklayan diagnostics görünümü

## Ürün ilkeleri ve sınırlar

- **Yerel ve savunma odaklı:** Veriler varsayılan olarak yerelde kalır.
- **Açıklanabilir:** Her alert; zaman, kaynak, önem seviyesi ve kanıt içerir.
- **Kademeli yetenek:** Yönetici yetkisi olmadan mümkün olan özellikler çalışmaya devam eder.
- **Pasif varsayılan:** Paket üretmek veya aktif tarama yapmak kendiliğinden başlamaz.
- **Yanlış pozitif farkındalığı:** Anomali bir saldırı kanıtı olarak değil, incelenmesi gereken sinyal olarak sunulur.
- **Öğretici:** Protokol alanları ile çıkarımlar birbirinden ayrılır ve kullanıcıya anlaşılır bağlam verilir.

M8 cihaz profili, gözlenen cihaz/binding geçmişinden ayrı kullanıcı verisidir.
Beklenen MAC/IP listeleri ve `trusted` işareti yalnızca kullanıcının açık
seçimidir; `trusted` kriptografik doğrulama veya cihazın güvenli olduğu anlamına
gelmez. Tek bir normal DHCP IP yenilemesi veya randomized/locally administered
MAC tek başına saldırı kanıtı değildir. Kimlik uyuşmazlığı uyarısı da kesin
spoofing hükmü değildir. [NS-042 karar tablosu](DEVICE_SECURITY_DECISIONS.md)
bu sınırları ve false-positive senaryolarını açıklar.

## Kapsam dışı özellikler

İlk ana sürüm kapsamında şunlar yoktur:

- Firewall kuralı yazma, bağlantı engelleme veya process sonlandırma
- IDS/IPS imza motoru ya da tam paket içerik/DPI sınıflandırması
- Otomatik karşı saldırı, exploit çalıştırma, parola deneme veya yetkisiz aktif test
- Uzak sistemleri izinsiz tarama; internet geneline yönelik port/vulnerability scanning
- TLS şifre çözme, sertifika yerleştirme veya MITM proxy oluşturma
- VPN, proxy, packet forwarding veya ağ geçidi işlevi
- Kurumsal çok-agent yönetimi, merkezi SIEM, bulut senkronizasyonu veya çok kullanıcılı RBAC
- Her Windows sürümü ve her capture sürücüsü için kusursuz paket yakalama garantisi
- Bir paketi kesin olarak belirli bir process ile eşleme garantisi; Windows ve yakalama katmanı sınırlamaları açıkça gösterilir
- Saldırı olduğuna dair hukuki/adli kesinlik; NetSentinel yardımcı gözlem aracıdır

Bu maddeler daha sonra ayrıca ürün kararı verilmeden task kapsamına eklenmez.

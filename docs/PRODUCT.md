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

## Yeni fazın ürün yönü (M11–M14 tamamlandı; M15–M17 planlandı)

NS-080 scoped preference/suppression storage yerel backend olarak uygulanmıştır:
application/destination/network/rule için dar typed selector, explicit expiry veya
permanent lifetime, reason/origin ve auditable edit/revoke saklanır. Kullanıcı
tercihi observed baseline, device trust ve risk evidence'dan ayrıdır.
[Storage contract ve sınırlar](SCOPED_PREFERENCES.md).
NS-081 current scoped preference'ı generic risk/alert pipeline'da eligibility'ye
uygular. Risk score, severity ve evidence history korunur; suppression kullanıcı
tercihini açıklar, uygulama/hedef için güvenli veya trusted hükmü vermez. Tam
suppression alert lifecycle ve notification cooldown'a dokunmaz; storage/evaluation
failure alerting için typed fail-open olur. Current policy açıklaması application
result'ta bounded biçimde görünür. NS-082 Connections → Behavior baseline içinde
ayrı User preference bölümüyle selected behavior preview/expiry/save/cancel/revoke
akışını sağlar. Kalıcı application identity ve exact rule korunur; PID/name veya
provisional kimlik kabul edilmez. Baseline reset veya application safety verdict
değildir. NS-083 Alerts/Connections risk explanation tamamlandı; score, confidence,
measurement quality, source freshness, policy/revision ve preference etkisi ayrı
görünür. [NS-083 açıklama ve veri sınırları](RISK_EXPLANATION_UI.md), [NS-082 akışı](MARK_NORMAL_UI.md),
[evaluation contract](SUPPRESSION_EVALUATION.md).

Ana kullanıcı sorusu: **“Bilgisayarım şu anda kimlerle konuşuyor, bunu hangi process yapıyor, bu davranış normal mi ve neden şüpheli olabilir?”**

Öncelik sırası **visibility → context → explainable detection**. Yeni faz; process/connection correlation, yerel destination context, bounded deterministic behavioral baseline, evidence ile açıklanan risk, incident timeline ve yanlış pozitif kontrolüne odaklanır. Threat intelligence yalnızca kullanıcı tercihiyle destekleyici evidence sağlar. M18 manuel firewall response ayrı ve conditional karardır; automatic blocking erken varsayılan değildir.

**Mevcut ile planı ayırma:** M1–M10'da TCP/UDP polling görünürlüğü, erişilebilen PID/process adı/create-time, connection history, pasif LAN/DNS/VLAN gözlemleri, özel detector'lar, kanıtlı alert'ler, device trust ve portable Windows paketleme vardır. NS-052 ile executable path, NS-053 ile mevcut snapshot'ta erişilebilen best-effort parent context process metadata olarak okunur; NS-054 bu context'i connection history snapshot'ında yerel olarak saklar. NS-055 Connections ve History detaylarında bu alanları ve eksiklik nedenlerini gösterir; parent bilgisi yalnız gözlenen bağlamdır. NS-064 Connections ve History'de DNS association kanıtını kesin hostname iddiası olmadan, local ASN/country context'inden ayrı gösterir. NS-069–075 observed baseline ve detail/reset UI uygulanmıştır. NS-076–079 generic evidence, pure scoring, versioned assessment ve mevcut alert lifecycle entegrasyonu yerel backend olarak uygulanmıştır. Risk explanation UI, kesin domain–connection attribution, incident timeline, reputation request, tray/desktop notification, installer ve firewall bugün uygulanmış değildir. Polling “opened/closed” gerçek TCP connect/FIN zamanını garanti etmez; per-flow upload/download yoktur.

Ürün ilkeleri:

NS-069–075 observed behavior baseline artık uygulanmıştır. Connections → Selected
connection → Behavior baseline sekmesi exact application/revision/network scope,
learning state, policy'den alınan sample/monitored coverage eşikleri, retained
destination/port/protocol özeti ve quality/capacity sınırlarını gösterir. READY
yeterli gözlenmiş veri demektir; uygulamanın güvenliği veya kullanıcı tercihi
hakkında hüküm değildir. Reset, açık scope confirmation ile yalnız learned
reference'i siler; trust/preferences veya connection history'yi değiştirmez.
Kümülatif reference ve current memory window ayrıdır. NS-072–074 typed detector
evidence modelleri NS-079 ile production engine pipeline'ına bağlıdır. Backend
assessment ve mevcut alert lifecycle yerel worker'da işler. NS-083 seçili Alerts
ve Connections detayında kayıtlı sonucu açıklar; bugünkü learned baseline ile
geçmiş assessment context'i karıştırmaz. Numeric baseline metrics ve historical
suppression snapshot format v1'de kayıtlı değilse UI bunu açık söyler. M14 tamamlandı.

- **Local-first:** Connection/DNS/IP/process history varsayılan olarak yerel kalır. **NetSentinel does not upload your network history by default.** Reputation sorgusu başlangıçta kapalıdır; provider, subject type ve gönderilen veri için açık kullanıcı tercihi gerekir.
- **Belirsizlik görünür:** Directly observed DNS evidence, correlated association, ambiguous association ve unknown ayrılır. DNS domain → IP gözlemi, process'in o domain'e bağlandığının kesin kanıtı değildir.
- **Açıklanabilir risk:** Kayıtlı assessment contributor, evidence, confidence, measurement quality, source/freshness, policy version ve revision gösterir. Concern score yanında non-probability açıklaması ve contributor context bulunur; eksik evidence “normal” sonucu değildir.
- **False-positive control:** Observed telemetry, baseline, user feedback, trust, suppression ve notification eligibility ayrı kalır; dar selector ve açık expiration tercih edilir.
- **Aşamalı response:** Önce detection ve M17 public beta. M18 ancak NS-099 sonrası açık response GO kararıyla başlar; automatic blocking ve automatic elevation kapsam dışıdır.

Aşağıdaki kullanım senaryoları mevcut M1–M10 ürününü anlatır; bu yeni faz bölümü uygulanmış feature listesi değildir.

## Hedef kullanıcılar

- Networking ve cybersecurity öğrenen geliştiriciler
- Kendi Windows bilgisayarında ağ davranışını anlamak isteyen teknik kullanıcılar
- Yetkili ev ağı veya izole lab ortamında savunma odaklı gözlem yapan öğrenciler
- Küçük bir ağda temel görünürlük isteyen ancak kurumsal SIEM/NDR işletmeyen kullanıcılar

## Temel kullanım senaryoları

### 1. Canlı bağlantı görünürlüğü

Kullanıcı aktif TCP/UDP bağlantılarını; durum, local/remote endpoint, PID, process adı ve gözlem zamanı ile görür. Yeni ve kapanan bağlantılar ekranda güncellenir.

### 2. Geçmiş inceleme

Kullanıcı daha önce açılmış bağlantıları zaman, process veya endpoint üzerinden inceler. Uygulamanın yeniden başlatılmasından sonra geçmiş korunur; mevcut retention servisi temizliği manuel komutla uygular, otomatik zamanlanmış temizleme henüz yoktur.

### 3. Yerel ağ envanteri

Uygulama pasif ARP gözlemleriyle cihazları, IP-MAC eşleşmelerini ve son görülme zamanlarını kaydeder. Sınırlı aktif keşif mevcut uygulamada yoktur; gelecekte ancak sahibi olunan veya açıkça izinli ağ için ayrı ürün kararıyla değerlendirilebilir.

### 4. MITM/ARP şüphesi inceleme

Gateway MAC değişikliği, aynı IP için çelişkili MAC gözlemi veya olağandışı ARP davranışı tespit edildiğinde uygulama kanıt içeren ve önem seviyesi belirlenmiş bir uyarı üretir.

### 5. DNS görünürlüğü

Kullanıcı DNS sorgu ve cevaplarını, mümkün olduğunda sorgu-cevap korelasyonunu ve sistem DNS sunucusu değişikliklerini görür.

### 6. Broadcast ve VLAN farkındalığı

Uygulama broadcast/ARP yoğunluğunu zaman pencereleri içinde ölçer; yakalanan trafikteki 802.1Q etiketlerini gösterir ve öğrenilmiş tabana göre şüpheli değişiklikleri raporlar.

## Mevcut M1–M10 yetenekleri

### Bağlantılar

- Aktif TCP ve UDP bağlantılarını listeleme
- PID ve process bilgisiyle ilişkilendirme
- Local/remote IP ve portları gösterme
- Yeni, güncellenen ve kapanan bağlantıları gerçek zamanlı algılama
- Connection history ve basit trafik/olay istatistikleri
- Connection gözleminde, local IPv4 adresi güncel tek bir interface context'iyle tam eşleşiyorsa yerel network scope; eşleşme belirsizse `unknown` veya `ambiguous`. Bu kapsam fiziksel ağ ya da gerçek route kimliği değildir ve henüz history'ye kaydedilmez.

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

NS-048 ilk açılış rehberi bağlantı görünürlüğünün kapsamını, pasif capture'ın
yalnızca Devices ekranından açıkça başlatıldığını ve yerel metadata saklama
kurallarını anlatır. Packet capture dependency/driver veya interface erişimi
eksikse ilgili canlı özellikler sınırlı görünür; kaydedilmiş History, DNS,
Devices ve Alerts verisi yerel veritabanı erişilebildiği ölçüde okunabilir.
Diagnostics ekranındaki `available/degraded/unavailable` bir güvenlik skoru
değil, özellik kullanılabilirliğidir. Çalışan worker sağlığı ayrıca gösterilir.

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

# NetSentinel

NetSentinel, Windows üzerinde çalışan, GlassWire benzeri görünürlük sağlayan ancak ağ güvenliği sinyallerine odaklanan öğretici bir masaüstü uygulaması olarak tasarlanmıştır.

Proje; aktif TCP/UDP bağlantılarını ve süreçlerini izlemeyi, bağlantı geçmişi tutmayı, yerel ağ cihazlarını tanımayı ve ARP, DNS, broadcast ve VLAN gözlemlerinden açıklanabilir güvenlik uyarıları üretmeyi hedefler.

> Durum: NS-001–NS-020 ve M3 Persistence tamamlandı; M4 LAN Device Monitor sürüyor. TCP/UDP connection pipeline'ı ve PyQt6 canlı görünümüne ek olarak connection lifecycle metadata'sı bounded tek-writer hattıyla yerel SQLite'a kaydedilir. Manuel retention servisi varsayılan olarak 30 günden eski tamamlanmış kayıtları ve toplam 100.000 satır sınırını aşan en eski tamamlanmış kayıtları 500 satırlık transaction chunk'larıyla temizler; aktif kayıtları silmez. History ekranı kalıcı kayıtları filtreli, sayfalı ve GUI thread'ini bloklamayan ayrı bir query worker üzerinden gösterir. NS-019, aktif Windows IPv4 interface/subnet/gateway/DNS bağlamını read-only IP Helper API üzerinden normalize eder. NS-020, açıkça seçilen güncel context ve zorunlu capture filtresiyle çalışan, otomatik başlamayan güvenli Scapy sınırını sağlar; ARP parse, cihaz envanteri ve Devices UI entegrasyonu sonraki tasklardadır.

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

Windows network context sağlayıcısı çağrı başına güncel aktif IPv4 bağlamlarını okur. Loopback görünür kalır ancak varsayılan capture adayı değildir; VPN ve sanal interface türleri portable metadata ile ayrılır. Gateway ve DNS bulunamayabilir. Bu senkron sağlayıcı arka plan thread'i açmaz, ağ paketi göndermez ve canlı ağa bağlanmaz; güvenli capture sınırı NS-020'de eklenmiştir, ARP işlemleri sonraki taskların kapsamındadır.

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

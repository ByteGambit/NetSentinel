# NetSentinel

NetSentinel, Windows üzerinde çalışan, GlassWire benzeri görünürlük sağlayan ancak ağ güvenliği sinyallerine odaklanan öğretici bir masaüstü uygulaması olarak tasarlanmıştır.

Proje; aktif TCP/UDP bağlantılarını ve süreçlerini izlemeyi, bağlantı geçmişi tutmayı, yerel ağ cihazlarını tanımayı ve ARP, DNS, broadcast ve VLAN gözlemlerinden açıklanabilir güvenlik uyarıları üretmeyi hedefler.

> Durum: NS-001–NS-009 tamamlandı. TCP/UDP connection pipeline'ı; process enrichment, lifecycle tracking, typed event dağıtımı ve kontrollü engine yaşam döngüsüyle çalışıyor. PyQt6 masaüstü kabuğu; Dashboard, Connections, Devices, DNS ve Alerts sayfaları arasında genişletilebilir navigasyon sağlıyor. Bounded `QtEngineBridge`, portable engine eventlerini Qt ana thread'ine güvenli ve batch'li biçimde taşıyor.

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

`python -m netsentinel --gui` composition root üzerinden monitoring engine'i, thread-safe Qt bridge'i ve PyQt6 masaüstü kabuğunu başlatır. Bridge engine başlamadan önce event dispatcher'a attach edilir; pencere kapatıldığında önce detach edilir ve engine için tek, bounded bir stop isteği yapılır. NS-003 ile psutil, NS-008 ile PyQt6 runtime bağımlılığı; geliştirme/test için pytest ve pytest-qt kullanılır. GUI testleri varsayılan olarak Qt'nin `offscreen` platformunda çalışır ve ekran, canlı ağ ya da yönetici yetkisi gerektirmez.

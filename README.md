# NetSentinel

NetSentinel, Windows üzerinde çalışan, GlassWire benzeri görünürlük sağlayan ancak ağ güvenliği sinyallerine odaklanan öğretici bir masaüstü uygulaması olarak tasarlanmıştır.

Proje; aktif TCP/UDP bağlantılarını ve süreçlerini izlemeyi, bağlantı geçmişi tutmayı, yerel ağ cihazlarını tanımayı ve ARP, DNS, broadcast ve VLAN gözlemlerinden açıklanabilir güvenlik uyarıları üretmeyi hedefler.

> Durum: NS-001 proje/test iskeleti tamamlandı. Henüz networking veya GUI özelliği uygulanmadı.

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
```

Runtime bağımlılıkları, ilgili özellik taskı uygulanırken eklenecektir. NS-001 aşamasında yalnızca geliştirme/test bağımlılığı olarak pytest kullanılır.

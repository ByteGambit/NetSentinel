# Yol haritası

## Yol haritası ilkeleri

- Milestone'lar sırayla uygulanır; ancak aynı milestone içindeki bağımsız tasklar, bağımlılıkları izin veriyorsa paralel yürütülebilir.
- Bir milestone, yalnızca kod yazıldığı için değil; acceptance criteria, test ve gerekli dokümantasyon tamamlandığında biter.
- Her aşama önceki aşamanın public sözleşmelerini mümkün olduğunca korur.
- Packet capture gerektirmeyen çekirdek bağlantı görünürlüğü ilk kullanılabilir dikey dilimdir.
- Güvenlik detector'ları önce gözlem ve baseline güvenilir hale geldikten sonra eklenir.

## M1 — Core Connection Monitor

**Amaç:** GUI ve persistence olmadan, Windows connection snapshot'larını normalize eden ve açılma/kapanma değişikliklerini üreten test edilebilir engine çekirdeği.

**Kapsam:**

- Proje/paket/test iskeleti
- Connection ve process domain modelleri
- psutil TCP/UDP collector adapter'ı
- Process metadata zenginleştirme
- Snapshot diff ve connection lifecycle
- Engine yaşam döngüsü ve in-process event dağıtımı

**Çıkış ölçütü:** Fixture ve adapter testleri geçen; kontrollü biçimde başlayıp duran; yeni/kapanan bağlantı olaylarını GUI'den bağımsız üreten çekirdek.

**Tasklar:** NS-001–NS-007

## M2 — PyQt6 GUI

**Amaç:** Engine'i bloke etmeden canlı bağlantıları ve temel sağlık/istatistik bilgisini gösteren masaüstü kabuğu.

**Kapsam:**

- Uygulama kabuğu ve navigasyon
- Thread-safe Qt bridge
- Connections tablo modeli, filtre ve detay görünümü
- Basit dashboard
- Headless GUI testleri ve temel erişilebilirlik

**Çıkış ölçütü:** Uygulama canlı bağlantıları güncellerken UI responsive kalır; engine hata/stop durumu kullanıcıya görünür.

**Tasklar:** NS-008–NS-013

## M3 — Persistence

**Durum:** ✅ Tamamlandı (NS-014–NS-018, 2026-09-21)

**Amaç:** Connection history ve ilerideki modüllerin kullanacağı güvenilir SQLite altyapısını oluşturmak.

**Kapsam:**

- Migration sistemi ve başlangıç şeması
- Repository portları ve SQLite implementasyonu
- Tek writer queue ve batch transaction
- Retention ve veri yaşam döngüsü
- Geçmiş sorgulama görünümü

**Çıkış ölçütü:** Uygulama yeniden başlatıldığında bağlantı geçmişi korunur; migration, concurrency ve retention testleri geçer.

**Tasklar:** NS-014–NS-018

## M4 — LAN Device Monitor

**Durum:** ✅ Tamamlandı (NS-019–NS-024, 2026-09-23)

**Amaç:** Yerel ağ bağlamını ve pasif ARP gözlemlerini kullanarak cihaz envanteri oluşturmak.

**Kapsam:**

- Windows interface/subnet/gateway bağlamı
- Güvenli packet capture sınırı
- ARP parser
- Device registry ve IP-MAC binding geçmişi
- Yeni cihaz olayı
- Devices ekranı ve kontrollü lab testi

**Çıkış ölçütü:** Seçili ağda gözlenen cihazlar ve kimlikleri kalıcı/okunabilir biçimde gösterilir; yeni cihaz olayı deterministik çalışır.

**Tasklar:** NS-019–NS-024

## M5 — MITM Detection & Alerts

**Durum:** ✅ Tamamlandı (NS-025–NS-029, 2026-09-23)

**Amaç:** Gateway ve ARP kimliği değişimlerinden açıklanabilir, deduplicate edilmiş güvenlik alert'leri üretmek.

**Kapsam:**

- Ağ bağlamına özgü gateway baseline
- IP-MAC çakışma tespiti
- ARP sinyali korelasyonu ve confidence
- Genel alert yaşam döngüsü
- Alert kanıt/detay ekranı

**Çıkış ölçütü:** Sentetik ARP senaryoları doğru alert'leri üretir; normal DHCP/ağ geçişleri kontrollü biçimde ele alınır; alert storm oluşmaz.

**Tasklar:** NS-025–NS-029

## M6 — DNS Monitoring

**Durum:** ✅ Tamamlandı (NS-030–NS-034, 2026-09-24).

**Amaç:** Klasik DNS trafiği ve Windows DNS yapılandırması için görünürlük sağlamak.

**Kapsam:**

- DNS query/response parser
- Transaction korelasyonu ve timeout
- DNS server değişikliği tespiti
- DNS history persistence
- DNS ekranı

**Çıkış ölçütü:** Desteklenen DNS paketleri güvenle parse edilir, işlemler korele edilir ve DNS sunucusu değişimleri kanıtla alert üretir.

**Tasklar:** NS-030–NS-034

## M7 — Broadcast Monitoring

**Durum:** ✅ Tamamlandı (NS-035–NS-038, 2026-09-26).

**Amaç:** Broadcast ve ARP yoğunluğunu bounded rolling window'larla ölçmek ve beklenmeyen artışları raporlamak.

**Kapsam:**

- Broadcast sınıflandırma
- Rolling sayaçlar ve baseline
- Threshold/rate detector ve alert deduplication
- Dashboard istatistikleri

**Çıkış ölçütü:** Burst ve sürekli yüksek trafik ayrıştırılır; bellek sınırlı kalır; kullanıcı ölçüm penceresi ve eşiği görebilir.

**Tasklar:** NS-035–NS-038

Sınıflandırma, bounded rolling oran/baseline ve açıklanabilir yoğunluk alert'i
mevcut pasif consumer'a bağlıdır. Dashboard portable metrikleri gösterir;
işaretli sentetik yük testi queue, kalite ve kapanma sınırlarını doğrular.

## M8 — Device Security

**Durum:** NS-039–NS-040 tamamlandı (2026-09-26); NS-041–NS-042 bekliyor.

**Amaç:** Bilinen cihaz profilleri ile gözlenen ağ kimliği arasındaki şüpheli değişimleri tespit etmek.

**Kapsam:**

- Device profile ve trust modeli
- MAC/IP kimlik değişimi kuralları
- Profil/trust yönetimi
- False-positive odaklı testler

**Çıkış ölçütü:** Kullanıcı cihazı adlandırıp beklenen kimlikleri doğrulayabilir; beklenmeyen değişiklikler açıklanabilir alert üretir.

**Tasklar:** NS-039–NS-042

## M9 — VLAN Monitoring

**Amaç:** Capture'da mevcut 802.1Q etiketlerini gözlemek ve ağ bağlamına göre şüpheli VLAN değişimlerini bildirmek.

**Kapsam:**

- 802.1Q parser
- VLAN baseline
- Yeni/beklenmeyen VLAN ve değişim detector'ı
- Özet persistence ve UI görünümü

**Çıkış ölçütü:** Tagged/untagged ve malformed fixture'lar doğru işlenir; NIC offload sınırlaması kullanıcıya gösterilir.

**Tasklar:** NS-043–NS-046

## M10 — Packaging, Hardening & Test

**Amaç:** Uygulamayı farklı Windows yetki/capture koşullarında güvenli, gözlemlenebilir ve dağıtılabilir hale getirmek.

**Kapsam:**

- Merkezi config/logging/diagnostics
- Capability ve permission onboarding
- Performans, backpressure ve dayanıklılık
- Windows paketleme ve temiz makine doğrulaması
- CI test matrisi ve release kontrol listesi

**Çıkış ölçütü:** Temiz Windows ortamında kurulum/çalıştırma doğrulanır; düşük yetki ve capture yokluğu anlaşılır biçimde degrade olur; kalite kapıları geçer.

**Tasklar:** NS-047–NS-051

## Sürümleme önerisi

- **0.1:** M1–M3, bağlantı görünürlüğü ve history
- **0.2:** M4–M5, cihaz görünürlüğü ve ARP/MITM sinyalleri
- **0.3:** M6–M9, DNS/broadcast/device/VLAN güvenlik modülleri
- **1.0:** M10 tamamlanmış, belgelenmiş ve Windows smoke testleri geçen sürüm

Bu sürüm hedefleri bağlayıcı tarih değil, kapsam kapılarıdır.

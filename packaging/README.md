# NS-050 Windows paket doğrulaması

NS-096 güncel installer build/policy: [Installer/upgrade/uninstall](../docs/INSTALLER_UPGRADE_UNINSTALL.md).
Inno Setup 6.7.3 ile mevcut PyInstaller onedir sarıldı; gerçek build/payload/PE/
SHA256 PASS. NS-096 COMPLETE: mevcut Windows VM'deki yeni standart profillerle
install/repair/installer-upgrade/uninstall/Unicode ve son kalite kapıları PASS.
Pristine OS snapshot yoktu; 0.1.1 fixture app payload'ı 0.1.0 kaldı. Host wizard
App Control 4551 ile blocked; kabul VM'de yapıldı. Portable ve installed
aynı `%LOCALAPPDATA%\NetSentinel` data policy kullanır. Aşağıdaki NS-050 VM kanıtı
tarihseldir; güncel NS-096 installer kanıtı olarak sayılmaz.

`TASKS.md` paketleyici/format belirtmez. Bu uygulama PyInstaller `onedir`
GUI klasörü ve aktarım için zip üretir. `packaging/build_windows.py`,
`src/netsentinel/version.py` sürümünü Windows exe metadata'sına işler,
üçüncü taraf lisans envanteri ile lisans dosyalarını pakete ekler ve zip için
SHA-256 üretir. `NetSentinel.spec` SQL migration 001–019'u açıkça dahil eder.
Windows manifest `asInvoker` düzeyindedir; otomatik UAC yükseltmesi yoktur.
Npcap/WinPcap sürücüsü ve kullanıcıya ait DB/config/log dosyaları pakette yoktur.

## Yerel artefact kontrolü

```powershell
uv sync --extra dev --extra packaging
.\.venv\Scripts\python.exe packaging\build_windows.py
.\.venv\Scripts\python.exe packaging\smoke_windows.py
```

İkinci komut zip SHA-256 değerini doğrular; paketi boş, boşluk ve Türkçe
karakter içeren bir yola çıkarır; farklı cwd ile GUI exe'nin sınırlı
`--self-test <report.json>` tanı modunu iki kez çalıştırır. Bu tanı modu
Qt platform eklentisini, gerçek SQLite bağlantısında 001–019'u, 018→019
yükseltmesini, ilk rehberin Finish ile kaydını, sonraki açılışta rehberin
gösterilmemesini ve düzenli kapanışı denetler. Temp `%LOCALAPPDATA%` kullanır,
gerçek kullanıcı verisini değiştirmez. Test yalnızca salt okunur capability
kontrollerini ve core connection monitor'ü başlatır; capture/aktif ağ eylemi
başlatmaz. Zaman aşımında child process sonlandırılır.

## Temiz Windows VM kontrol listesi

Bu manuel adımlar artefact tamamlanmadan önce Python, repo veya `.venv`
bulunmayan temiz Windows 10/11 x64 VM'de, standart kullanıcıyla yapılmalıdır:

1. Zip'i ve `.sha256` dosyasını VM'ye kopyalayın; `Get-FileHash -Algorithm SHA256`
   sonucu ile `.sha256` içindeki değeri karşılaştırın.
2. Zip'i boşluk/Türkçe karakter içeren bir klasöre açın. `NetSentinel.exe`yi
   farklı çalışma dizininden başlatın; ilk rehberi, pasif varsayılanı ve
   Diagnostics durumunu inceleyin. Npcap olmayan VM'de capture kısıtlı
   görünmeli ve pencere açılmalıdır; admin/UAC talebi çıkmamalıdır.
3. **Finish** ile ana pencereyi açın. `%LOCALAPPDATA%\NetSentinel` altında
   `config.json`, `netsentinel.sqlite3` ve bounded `netsentinel.log` konumunu
   kontrol edin. Paket klasörüne yazılmamalıdır. SQLite migration ledger'ı
   001–019 olmalıdır. Pencereyi kapatıp tekrar açın; rehber tekrarlanmamalı.
4. Bozuk config ile güvenli fallback/yeniden rehberi, mevcut 018 DB kopyasıyla
   019 yükseltmesini ve salt okunur kurulum diziniyle veri yolunu sınayın.
   Bu testleri gerçek kullanıcı profili yerine VM snapshot'ında yapın.
5. Paket klasörünü kaldırın. Kullanıcı verisi varsayılan olarak
   `%LOCALAPPDATA%\NetSentinel` altında **korunur**; silmek ya da yedeklemek
   kullanıcının açık kararıdır. Paket kaldırma otomatik veri silmez.

Artefact imzasızdır. SmartScreen uyarısı mümkündür; uyarı açılış çökmesi
değildir. Kod imzalama ve lisans uyumluluğu dağıtımdan önce ayrı incelenmelidir.

## NS-050 temiz Windows VM kabul sonucu (2026-09-28)

`NetSentinel-0.1.0-windows-x64.zip` VM içinde `.sha256` sidecar ile karşılaştırıldı;
SHA-256: `2e9492b6b0b6551931aa74c1edc16dd73822ef1d369dcf77395e89724175280e`.
VM `Get-ComputerInfo` çıktısı `Windows 10 Home`, `WindowsVersion 2009`, build
`26200` idi. Testten önce NetSentinel user data yoktu; Npcap/WinPcap servisleri,
`npcap.sys`, `wpcap.dll` ve `System32\Npcap` bulunmadı. `py` ve `git` komutları
bulunmadı; `python.exe` yalnız WindowsApps yolunda görüldü (gerçek bir Python
kurulumu ayrıca doğrulanmadı).

Zip normal kullanıcı Desktop'ında boşluk içeren, repo dışı bir klasöre açıldı.
Standart kullanıcıyla ve farklı cwd'den ilk açılışta onboarding göründü; UAC,
SmartScreen, DLL/Qt/SQLite hatası ya da crash olmadı. Packet capture
`Unavailable` (dependency/driver unavailable), Devices/DNS/Alerts `Degraded`,
Connections `Available` idi. Finish sonrası engine çalıştı, packet capture
`stopped` kaldı ve Connections sayfası açıldı. Devices'taki explicit Start
passive capture denemesi capture başlatmadı; mevcut sanitize edilmiş
unavailable mesajı korundu ve uygulama çalışmaya devam etti. Düğme aktif
kalıp tıklama sonrası ayrıca yeni bir bildirim göstermedi.

`%LOCALAPPDATA%\NetSentinel` altında `config.json`, `netsentinel.sqlite3` ve
boş `netsentinel.log` oluştu; `onboarding_completed=true` kaydedildi. Paket
klasörünün 174 dosyalık açılış öncesi/sonrası listeleri iki GUI oturumunda
aynıydı. Her iki normal kapanış 10 saniye içinde exit code 0 verdi ve arka
planda süreç bırakmadı. İkinci açılış doğrudan ana pencereyi, çalışan engine'i,
erişilebilir Connections'ı ve aynı degraded capability durumunu gösterdi.
Artifact'ın VM'de çalıştırılan `--self-test` raporu `ok=true`, 9 migration,
`schema_version=9`, `old_schema_version=8`, `upgraded_schema_version=9`, Qt ve
SQLite başarılı, `onboarding_visible=false`, `gui_exit=0` kaydetti. Bu migration
raporu tanı modunun geçici DB'sine aittir; normal ilk oturumun gerçek DB dosyası
ayrıca oluştu ve sonraki oturumda hatasız açıldı.

# NS-093 — Tray ve application lifecycle

## Kod öncesi policy freeze (2026-10-05)

Normal launch görünür MainWindow ile başlar: mevcut lifecycle.start(), sonra
window.show(), sonra Qt event loop. İlk kullanımda mevcut görünür onboarding
önce gelir; tamamlandığında monitoring ve MainWindow açılır. create_application
yalnız composition yapar, engine başlatmaz/pencere açmaz. Tray-only/minimized
startup, login autostart, Windows service, elevation ve yeni network action yoktur.

Typed shared `WindowCloseBehavior` ve `AppConfig.window_close_behavior`:
`quit_application` (QUIT_APPLICATION), `hide_to_tray` (HIDE_TO_TRAY).
Varsayılan/eksik/geçersiz değer QUIT_APPLICATION: eski X davranışını korur,
kullanıcıya habersiz background çalışma getirmez. Mevcut local config.json
(bootstrap.runtime_config_path) atomic Save kullanılır; SQLite 019 değişmez.
Settings → Application behavior → When I close the window: Save/Cancel.
Save en güncel config'i yükleyip yalnız bu alanı değiştirir; Cancel yazmaz.
Tray unavailable iken hide seçimi disabled, açıklama görünür; önceki tercih
otomatik silinmez. Etkin tercih capability ile ayrı hesaplanır.

| Stored preference | Tray | Quitting | X sonucu |
|---|---|---|---|
| HIDE_TO_TRAY | available | hayır | event ignore + window.hide; shutdown yok |
| HIDE_TO_TRAY | unavailable / init failed | hayır | QUIT_APPLICATION fallback |
| QUIT_APPLICATION | herhangi | hayır | explicit quit |
| herhangi | herhangi | evet | gerçek close kabul edilir |

PyQt6 QSystemTrayIcon adapter capability kontrolünü kapsüller; fake adapter aynı
availability/start/cleanup sınırını kullanır. Sabit Show NetSentinel, Hide
NetSentinel, Quit menüsü; Trigger/DoubleClick açar, Context menüyü açar.
App ömründe tek tray/menu; hide/show yeni worker veya icon oluşturmaz.
Tooltip yalnız NetSentinel. Bildirim/showMessage yok; NS-094 başlatılmaz.
Mevcut app icon kullanılır, eksikse Qt standard icon; init failure safe fallback.

Show minimize flag'ini kaldırır, diğer state/geometry'yi korur, raise/activate
yapar. Hide yalnız presentation değiştirir: engine, alert, risk, incident,
capture/DNS ve TI lifecycle etkilenmez. Tray unavailable iken hide reddedilir.
Tray kullanılabilirken quitOnLastWindowClosed=False (explicit tray Hide de
background kullanım sağlar); unavailable iken True. Explicit Quit her iki
durumda Qt quit yoluna ulaşır. Minimize normal taskbar davranışıdır.

Application controller explicit quitting flag kullanır. File → Quit ve tray
Quit aynı yolu kullanır; QApplication Quit event ve aboutToQuit aynı cleanup'a
bağlanır. ApplicationLifecycle shutdown idempotent sahibi kalır. Event loop
finally de controller cleanup/shutdown yapar. Quitting sırasında Show/Hide yok.

Mevcut shutdown sırası: TI lookup/timer, TI scheduler, incident list/detail/risk,
risk queries, preference, baseline, history, destination, signer, alerts, DNS,
device inventory/profile, capabilities, bridge detach, engine.stop.
Her mevcut worker kendi bounded stop sözleşmesine sahiptir (çoğu 2 s; engine
AppConfig.shutdown_timeout varsayılan 2 s, 0.05–60 s). Sıralı toplam bütçe bu
beklemelerin toplamıdır; global 2 s garantisi yoktur. Timeout/degraded sonuçları
korunur; blocking adapter zorla kesilmez, daemon worker dönünce temizlenir.
Forced process kill/crash altında cleanup garantisi yoktur.

Qt API kaynakları: [QSystemTrayIcon](https://doc.qt.io/qt-6/qsystemtrayicon.html),
[QApplication](https://doc.qt.io/qt-6/qapplication.html).

## Windows manual smoke

Native shell smoke otomatik/offscreen testten ayrı kaydedilir. Henüz çalıştırılmadı.

1. Standard user PowerShell: `.\.venv\Scripts\python.exe -m netsentinel --gui`.
2. Görünür onboarding/ana pencereyi ve tek tray icon'u doğrula.
3. Settings → Application behavior → Hide to system tray → Save.
4. X: pencere kaybolmalı, aynı process/tray kalmalı.
5. Normal yerel kullanımın connection observation'larının ilerlediğini doğrula;
   capture başlatma veya harici reputation lookup gerekmez.
6. Tray → Show ve tek/çift tıklama: aynı pencere/process geri gelmeli.
7. X/Show birkaç kez; duplicate icon, worker veya reset olmamalı.
8. Minimize/maximize sonrası Show'un state/geometry davranışını kontrol et.
9. Tray → Quit: process bounded sürede çıkmalı; icon kalkmalı. File → Quit de dene.
10. Relaunch: pencere görünür başlamalı, close tercihi korunmalı.
11. Quit NetSentinel seçeneğini Save et; X gerçek çıkış yapmalı.
12. Tray olmayan/failure session'da açıklama ve quit fallback'i doğrula (fake
    adapter offscreen bu dalı kapsar; native shell sonucu ayrıca kaydedilir).

Installer/packaging, notifications, retention/privacy ve NS-094+ kapsam dışıdır.

## Lifecycle kabul matrisi

Tabloda stop sayısı method invocation değil, shell başına gerçek engine.stop
çağrısıdır; guarded shutdown tekrarları aynı sonucu döndürür.

| Eylem | Window | Tray (available) | Monitoring | Engine stop | App |
|---|---|---|---|---|---|
| create_application | henüz görünmez | görünür | henüz başlamaz | 0 | composed |
| normal startup | görünür | görünür | mevcut lifecycle ile çalışır | 0 | running |
| Show / tray Show / Trigger / DoubleClick | görünür, minimize kaldırılır | görünür | yeniden start yok | 0 | running |
| Hide / tray Hide | gizli | görünür | çalışır | 0 | running |
| X + hide preference | gizli, destroy yok | görünür | çalışır | 0 | running |
| X + quit / unavailable | kapanır | temizlenir | bounded stop | 1 | quitting/exits |
| tray Quit / File Quit | gerçek close | temizlenir | bounded stop | 1 | quitting/exits |
| QApplication Quit | gerçek close | temizlenir | bounded stop | 1 | quitting/exits |
| aboutToQuit / loop finally | presentation tekrar açılmaz | temizlenir | idempotent | toplam 1 | stopped |
| tray capability loss | gizliyse yeniden görünür | temizlenir | çalışır | 0 | running |

## Otomatik doğrulama kanıtları

`tests/gui/test_tray_lifecycle.py` fake capability/start/show/hide/quit/activation,
partial init failure, runtime capability loss, 100 hide/show ve 100 close/restore,
native Qt adapter action/activation/resource/cleanup, minimized+maximized restore,
typed Settings Save/Cancel/restart/preserve-other-settings/failed-save ve dört
ayrı subprocess Qt event-loop exit yolunu kapsar. Subprocess tray de fake'dir;
Qt event loop/close/quit/exit gerçektir, native Windows shell kanıtı değildir.

Hidden integration iki ayrı gerçek sınırı doğrular:

- Production bootstrap MonitoringEngine + SQLiteHistoryWriter; fake collection ve
  process/context portlarıyla gizli window sırasında polling event'i durable history
  ve Connections model'e ulaşır. Fresh database schema_migrations MAX(version)=19.
- NS-092 gerçek baseline/risk worker → AlertService/assessment → explicit incident
  persistence hikâyesi gizliyken üretilir; Connections ve worker-owned Incidents
  read model'de görünür. Incident production hâlâ explicit API'dir; yeni subscriber yok.

Granted optional TI consent + real dormant scheduler/fake provider ile 100 hide/show
sıfır provider çağrısı üretir; socket/network access forbidden guard'ı vardır.
Bloke query 0.05 s configured join ve bloke real engine collector 0.05 s stop
sınırıyla <1 s içinde degraded sonuç döndürür; engine SHUTDOWN_TIMEOUT diagnostic'i
korunur. Release sonrası worker çıkar. Spy order testi tüm mevcut owner'ların
sırasını, bir timeout sonrası kalan stop'ların çalışmasını ve tek actual stop'u
doğrular. Fatal startup rollback/finally de bir stop üretir.

`tests/unit/shared/test_window_close_config.py` eksik/unknown/null/integer/list/object
değerlerin safe default'u, typed model rejection, exact JSON roundtrip ve field-only
Save doğrular. Eski NS-055 process detail, application shell/lifecycle, onboarding,
optional TI, Incidents, config ve engine testleri geniş regresyon grubundadır.

Tray diagnostic değişimi yalnız sabit session status:
available / unavailable / initialization_failed / cleanup_failed. Raw exception,
path, process/IP/domain yoktur; hide/show log spam'i veya yeni shared counters yok.
Settings label/buddy/accessibility ve standard QAction metinleri vardır.

Komutlar (repo root, explicit live marker'ları default suite dışında):

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/gui/test_tray_lifecycle.py tests/unit/shared/test_window_close_config.py
.\.venv\Scripts\python.exe -m pytest -q tests/gui/test_app_lifecycle.py tests/gui/test_application_shell.py tests/gui/test_tray_lifecycle.py tests/gui/test_process_context.py tests/gui/test_capabilities.py tests/gui/test_threat_intel_consent.py tests/gui/test_threat_intel_scheduler.py tests/gui/test_threat_intel_evidence.py tests/gui/test_incident_acceptance.py tests/unit/shared tests/unit/application/test_engine.py tests/integration/test_runtime_diagnostics.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m mypy src/netsentinel/presentation/tray.py src/netsentinel/presentation/widgets/application_behavior.py src/netsentinel/presentation/app.py
git diff --check
```

Yeni-only: **36 passed (7.68 s)**. Geniş hedefli grup son dört ek testten önce
**198 passed (31.73 s)**; final full suite sonucu aşağıda kaydedilir. Ruff temiz;
configured mypy 34 source ve direct mypy 3 source temiz. MainWindow'u da dahil eden
ek bir mypy denemesi mevcut snapshot-object/nullable-widget/Qt override annotation
borcunu gösterdi; yeni action binding'i assert ile daraltıldı, kapsam dışı mevcut
annotation'lar refactor edilmedi. Configured ve yeni lifecycle module kapıları geçer.

Final offline suite: **3401 passed, 8 deselected (235.24 s)**. Şema **019 → 019**;
schema dosyalarının hiçbiri değişmedi ve migration yoktur. NS-093 **COMPLETE**,
M17 **devam ediyor**. NS-094 ve sonraki tasklar başlatılmadı. Native Windows manual
smoke **çalıştırılmadı**; checklist yukarıdadır. Bu sonuç public-beta/native-shell
gate'in geçildiği iddiası değildir.

Eklenen dosyalar: `presentation/tray.py`, `presentation/widgets/application_behavior.py`,
`tests/gui/test_tray_lifecycle.py`, `tests/unit/shared/test_window_close_config.py`,
bu lifecycle belgesi. Değişen dosyalar: `presentation/app.py`,
`presentation/views/main_window.py`, `shared/config.py`, `docs/ARCHITECTURE.md`,
`docs/PRODUCT.md`, `docs/SECURITY.md`, `docs/ROADMAP.md`, `docs/TASKS.md`.
Üretim kaynaklarının tamamı `src/netsentinel/` altındadır. Mevcut test dosyaları
değiştirilmedi; 36 yeni case iki yeni test dosyasındadır. Git teslimi kullanıcı
isteğiyle `main` üzerinde `feat: add tray application lifecycle`; final commit
hash/push/working-tree sonucu teslim mesajında bildirilir.

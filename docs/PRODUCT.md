# Ürün tanımı

NS-105 (2026-10-09): yalnız localization foundation tamamlandı. Mevcut
application UI metinleri English canonical Qt source olarak işaretlendi;
English katalog olmadan çalışır. Dil seçimi/kaydı, production çeviriler ve yeni
guided tour eklenmedi. Runtime switching NO_GO; future seçimler bütün uygulamada
explicit restart gerektirir. Mevcut M17 guide ve tüm izin/response davranışı
korunur; schema020. NS-106–120 NOT STARTED. [Kabul](LOCALIZATION_ACCEPTANCE.md).

NS-103 (2026-10-09) adds Connections → Selected connection → Manual firewall
response: explicit single-profile/manual-lifetime review, Confirm/Cancel,
sanitized results, bounded local ownership/audit and separately confirmed Undo.
Evidence is not a malware verdict; shared-IP/all-instance/path-replacement
collateral and DNS/flow attribution limits remain visible. Normal desktop
composition retains the frozen **in-product writes NO_GO** boundary and reads
custody only; success/rollback use injected fake infrastructure acceptance.
No automatic response/elevation/process termination or NS-104 native/uninstall
work. Schema020 unchanged. [NS-103 behavior and acceptance](MANUAL_RESPONSE_UI_ACCEPTANCE.md).
Earlier task summaries below retain their historical scope.

NS-100 (2026-10-08): user **GO NS-100** accepted; contract implementation
**COMPLETE** (205 new tests; full offline4038/8 deselected, coverage91.17%,
Ruff/configured mypy37/direct3/whitespace/privacy PASS). Pure typed program+literal-IP+transport/port/single-profile
outbound BLOCK scope, explicit manual lifetime, preview/file/source binding and
read-only privilege review are added. In-product writes remain **NO_GO** until
the trusted privilege boundary and later ownership/native gates are resolved.
Desktop behavior, installer and schema019 are unchanged; **NS-101–104 NOT STARTED**,
tag/release **NONE**. [Contract and limits](RESPONSE_COMMAND_CONTRACT.md),
[acceptance](RESPONSE_COMMAND_ACCEPTANCE.md).
The following NS-099 and earlier summaries retain their historical scope.

NS-099 final environment closure (2026-10-08): **private native WireGuard VPN PASS**.
NS-099 **COMPLETE**, M17 **COMPLETE**; accepted8242868 runtime unchanged,
unsigned0.1.0 candidate SHA256 `39b14fe844c8aaa150a8b09229e0d63aaaf5ecc98b5bc8c54b419140be7749d9`,
37,559,481 bytes, schema019→019. Fresh installed1119 hashes/0 mismatches.
Real tunnel/HTTPS/scope/disconnect/restart and baseline/DB persistence PASS;
alerts/incidents0 throughout, notifications OFF/intents0, bounded app errors0.
Native S3 PASS, notification policy PASS and human UX8/8 retain their recorded scope.
Limited unsigned pilot **CONDITIONAL_GO** subject to NS-097 owner/distribution gates;
broad release **NO_GO** (unsigned/signing gates). M18 **GO FOR PLANNING ONLY**,
no explicit response implementation GO; NS-100 **NOT STARTED**; tag/release **NONE**.
[VPN measurements, limitations and cleanup](NS099_VPN_WIREGUARD_CLOSURE.md).

Earlier acceptance summaries below are historical; product/security rules remain in force.

NS-099 notification-policy closure (2026-10-07): **policy PASS**, actual Windows
global Notifications OFF/ON in the same Limited-token Session1; application
reports **UNKNOWN**, accepted submission is not visible-delivery proof.
Current unpublished unsigned0.1.0 source `8242868ba79c63ad743c005366ea715b238cf5d0`,
SHA256 `39b14fe844c8aaa150a8b09229e0d63aaaf5ecc98b5bc8c54b419140be7749d9`, 37,559,481 bytes, schema019→019.
Installed1119 hashes/0 mismatches;194 source-matching compiled modules.
Native popup/privacy/click/duplicates/restart PASS in the recorded policy scope.
Human UX remains PASS8/8, layout CLOSED in its evaluator scope. VPN and meaningful
native sleep NOT RUN; NS-099 INCOMPLETE, M17 IN PROGRESS, pilot/broad NO_GO,
M18 DEFER, NS-100 NOT STARTED; tag/release NONE.
[Policy model, native measurements and limitations](NS099_NOTIFICATION_POLICY_CLOSURE.md).

## Previous layout follow-up — historical candidate

NS-099 layout follow-up (2026-10-07): current runtime/source `bfe531d960aaabd6b61c1701cf7179f7214c5097`,
unsigned0.1.0 candidate SHA256 `74529e4cfa03d466ed365a4b0fe5c65c4399873acf150b0c3472496472bdf4c2`, 37,543,802 bytes, schema019→019.
Incidents/DNS/History layout fixed; fresh Windows11 native layout test-build
captures evaluated by the human. Focused layout recheck **PASS**; overall Human UX
**8 PASS / 0 FAIL**. The previous layout finding is closed. Prior functional/native measurements below keep
their original ae08d7e/14934a52 candidate scope. VPN NOT RUN, native sleep NOT RUN,
effective OS-disabled policy BLOCKED; NS-099 INCOMPLETE, M17 IN PROGRESS,
pilot/broad NO_GO, M18 DEFER, NS-100 NOT STARTED. [Layout record](NS099_LAYOUT_CLOSURE.md).

The earlier closure summary below retains its historical candidate scope.

NS-099 beta gate IN PROGRESS / INCOMPLETE: committed ae08d7e retention/Diagnostics
GUI düzeltmesinden 0.1.0 unsigned aday yeniden derlendi; source/hash/payload ve frozen benign FP/notification review
bütçeleri [kabul raporu](PUBLIC_BETA_ACCEPTANCE.md) ve
[protokolde](BETA_PROTOCOL.md). Yeni Windows 11 VM'de standard/Unicode install,
repair, browser/updater, restart, sanitized export ve KEEP uninstall tarihsel kapsamında doğrulandı.
Yeni aday native fixture toast/privacy/click/restart ve tray-context Quit PASS;
zorunlu VPN ve meaningful sleep NOT RUN, effective OS-policy BLOCKED ve insan layout kriteri FAIL.
Offline kanıt native PASS değildir. Limited unsigned pilot şimdilik NO_GO, broad public NO_GO;
M17 IN PROGRESS, M18 DEFER. [Kullanıcı desteği](BETA_SUPPORT.md),
[privacy özeti](BETA_PRIVACY.md). Aşağıdaki teslimat kayıtları tarihseldir.

NS-098 altı sayfalı sürümlü ilk açılış/Privacy rehberi, Help'ten yeniden açma,
eski kullanıcıya nonmodal bilgilendirme ve NS-095 motorunu kullanan Feedback &
Support görünümü ekler. Finish/Skip izin vermez; capture, AbuseIPDB ve notification
ayarları ayrı kalır. Feedback full sanitized preview sonrası yerel Save'dir;
proje sayfası yalnız explicit click ile açılır, ayrı feedback/security adresi
tanımlı değildir. [Davranış ve sınırlar](FIRST_RUN_FEEDBACK.md),
[0.1.0 pilot hazırlık notları](RELEASE_NOTES.md). NS-098 teslimat kaydı tarihseldir;
güncel M17 devam eder, NS-099 INCOMPLETE; M18 başlatılmaz.

NS-097 signing/update dağıtım spike'ı tamamlandı: sınırlı ve açıkça unsigned
pilot için conditional GO, broad public beta/production için public signer ve
kalan M17 kabul kapıları zorunludur. Tek canonical kanal GitHub Releases; ilk
beta manual update, sıfır automatic update-network request. Automatic updater,
certificate satın alma veya GUI/network/schema değişikliği yoktur. Mevcut 0.1.0
installer unsigned ve değişmedi; 0.1.1 lifecycle fixture release değildir.
[Frozen karar](SIGNING_UPDATE_DISTRIBUTION.md), [kanıt](SIGNING_UPDATE_ACCEPTANCE.md).
M17 IN PROGRESS; NS-098/099 başlamadı. Aşağıdaki teslimat kayıtları tarihseldir.

NS-096 installer kaynak implementasyonu mevcut portable PyInstaller paketini
offline, per-user kurulumla sarar. Program: `%LOCALAPPDATA%\Programs\NetSentinel`;
yerel veri: `%LOCALAPPDATA%\NetSentinel`. Uninstall varsayılan KEEP, DELETE ayrı
seçim ve destructive confirmation gerektirir; external export korunur, secure
erase garantisi yoktur. Capture/TI/notification/storage defaults değişmez;
Npcap, elevation, service/autostart, updater veya upload eklenmez. ISCC 6.7.3 ile
unsigned pilot installer artefact'ı derlendi ve doğrulandı; mevcut Windows VM'deki
yeni standart kullanıcı profilleriyle lifecycle/Unicode kabulü PASS: NS-096 COMPLETE.
Pristine OS snapshot yoktu; exact TASKS bu baseline'ı zorunlu tanımlamaz.
0.1.1 fixture installer lifecycle'ını sınadı; uygulama payload'ı 0.1.0 kaldı.
Host wizard smoke App Control 4551 ile blocked; kabul VM'de yapıldı. Son full
offline 3683 passed/8 deselected, Ruff/mypy/diff PASS. M17 devam ediyor; NS-097 başlamadı.
[Installer policy ve native checklist](INSTALLER_UPGRADE_UNINSTALL.md).
Aşağıdaki teslimat kayıtları tarihseldir.

NS-095 Settings → Storage & Privacy yerel store sayıları/approximate DB-WAL
boyutu, opt-in retention, scope önizlemeli/onaylı purge ve sanitized support JSON
önizleme/Save sağlar. Retention varsayılan kapalıdır; Save ile açılırsa ilk kontrol
60 saniye sonra, ardından saatte bir bounded worker'da çalışır. Aktif/current veri,
alert-linked explanation, cihaz profili/trust ve suppression/mark-normal korunur.
Kaynak silinse de retained incident/assessment snapshot ve expired/unavailable
açıklaması okunabilir. Support export raw history, IP/domain/path/MAC/hash/not,
provider response veya secret içermez; otomatik upload yoktur. SQLite 019 değişmez.
Silme secure erase veya anında dosya küçülmesi garantisi vermez; DB encryption
garantisi yoktur. [Store envanteri, politika ve sınırlar](STORAGE_PRIVACY.md).
M17 devam ediyor; NS-096 başlatılmadı. Aşağıdaki teslimat kayıtları tarihseldir.

NS-094 privacy-aware desktop notifications ve Settings → Desktop notifications
tamamlandı. Varsayılan kapalı, Enable/Save ile gelecekteki eligible alert'ler
için açılır. Preview yalnız genel LOW/MEDIUM/HIGH metnidir; OS başka kişilere veya
lock screen'e gösterebilir. Dedup/cooldown/hysteresis ve suppression popup yükünü
sınırlar. Click gizli/minimize pencereyi geri getirir ve exact alert detail açar;
submission OS display garantisi değildir. Restart/enable geçmişi replay etmez.
SQLite 019 değişmez; native Windows manual smoke çalıştırılmadı.
[Policy, platform sınırları ve smoke](DESKTOP_NOTIFICATIONS.md). M17 devam ediyor;
NS-095 başlatılmadı. Aşağıdaki önceki task teslimat kayıtları tarihseldir.

NS-093 günlük desktop kullanımına Qt tray ve Settings → Application behavior
close preference ekler. Normal launch görünür başlar; varsayılan X = Quit
NetSentinel. Kullanıcı Hide to system tray seçerse X yalnız pencereyi gizler,
monitoring devam eder. Tray yoksa/kurulamazsa X quit yapar; tray çalışma sırasında
kaybolursa gizli pencere geri gösterilir. File/tray Quit bounded ve idempotent
lifecycle shutdown kullanır. SQLite 019 değişmez. Windows service, autostart ve
desktop notification yoktur; NS-094 başlamadı. [Policy ve smoke checklist](TRAY_APPLICATION_LIFECYCLE.md).
Aşağıdaki önceki task teslimat kayıtları tarihseldir.

NS-092 offline acceptance/soak M16 çıkışını doğruladı: restart-safe incident
kimliği, dedup/reopen/source-expiry ve dürüst timeline sınırları korunur.
Sentetik connection/DNS/baseline/risk/fake TI ve offscreen GUI gerçek servis ve
repository sınırlarını geçer. DNS association process attribution değildir;
incident üretimi mevcut explicit API'de kalır. Yeni ürün davranışı veya dış ağ
işlemi eklenmedi. M16 COMPLETE; NS-093 başlatılmadı.
[Kabul hikâyesi ve ölçülen bütçeler](INCIDENT_ACCEPTANCE_SOAK.md).

NS-091 Incidents sayfası yerel kayıtlı incident listesi, detail ve bounded timeline
sunar. Gözlem, ilişki/inference, assessment ve lifecycle action zamanları açıkça
ayrıdır; kaynak kaybı veya unknown ilişki açıklaması saklanan minimum context ile
kalır. Process observed dili kullanılır; create-time yalnız instance identity
context'tir. Açmak/scroll/refresh veri veya lifecycle değiştirmez, TI isteği
başlatmaz. Bu explicit NS-090 boundary'deki mevcut kayıtları okur; yeni incident
üreten engine subscription eklenmediğinden boş liste geçerlidir. Timeline causal
veya forensic completeness iddiası yapmaz. [Sınırlar ve kabul raporu](INCIDENT_TIMELINE_ACCEPTANCE.md).

NS-090 yerel backend, correlated incident'i restart sonrası aynı kimlikle saklar;
ACK/RESOLVE/REOPEN ve evidence append alert lifecycle'ından bağımsızdır. Kaynak
history silinse de bounded canonical explanation ve expired/unavailable durumu
okunabilir. Explicit service API vardır; incident ekranı ve timeline NS-091 ile
uygulanmıştır. SQLite 019. [Incident persistence sınırları](INCIDENT_PERSISTENCE.md).

NS-088 Connections → External reputation içinde explicit **Check reputation**
eylemi ve Alerts/Connections ortak risk açıklamasında tarihi TI context sağlar.
AbuseIPDB public IPv4/IPv6, provider/type consent ve NS-087 bounded cache-first
scheduler kullanılır; varsayılan kapalıdır. HIT destekleyici context'tir, malware
hükmü değildir; NO_HIT güvenli olduğunu kanıtlamaz. Stale ve refresh hatası ayrı
görünür. Numeric policy v1 değişmez; revision occurrence/count/last_seen/ACK/RESOLVED
değiştirmez. Secret backend/key-entry yoktur; unavailable credential açık gösterilir,
local detection devam eder. Explicit composition mevcut secret portunu enjekte
edebilir. Startup/observation/alert/selection/detail/consent Save sıfır lookup;
history enumerate/upload edilmez. SQLite 018, migration yoktur.
[UI, tarihi provenance ve sınırlar](THREAT_INTELLIGENCE_EVIDENCE.md).

NS-086, AbuseIPDB IP-only CHECK adapter'ını explicit caller composition için
sağlar; NS-088 desktop lookup akışına bağlıdır. Domain/hash desteklenmez; abstraction
korunur. NO_HIT yalnız lookback içinde rapor bulunmadığını ifade eder, güvenli
olduğu anlamına gelmez. Scheduler NS-087 ile mevcut; risk/UI entegrasyonu NS-088'dir.
[Provider/terms/privacy kararı](THREAT_INTELLIGENCE_PROVIDER_ABUSEIPDB.md).

NS-084, M15'in yalnız provider-independent TI port ve consent policy adımını
uyguladı. Settings → Threat intelligence / reputation consent içinde provider ve
data type başına manual selected izin önizlemesi vardır; yeni seçimler varsayılan
kapalıdır. NS-087 registry yalnız AbuseIPDB IP capability'si sunar. Consent vermek
history tarama/gönderme veya lookup başlatma eylemi değildir.
[İzin, veri açıklaması ve sonuç semantiği](THREAT_INTELLIGENCE_CONSENT.md).

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

## Yeni fazın ürün yönü (M11–M16 tamamlandı; M17 devam ediyor)

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

**Mevcut ile planı ayırma:** M1–M10'da TCP/UDP polling görünürlüğü, erişilebilen PID/process adı/create-time, connection history, pasif LAN/DNS/VLAN gözlemleri, özel detector'lar, kanıtlı alert'ler, device trust ve portable Windows paketleme vardır. NS-052 ile executable path, NS-053 ile mevcut snapshot'ta erişilebilen best-effort parent context process metadata olarak okunur; NS-054 bu context'i connection history snapshot'ında yerel olarak saklar. NS-055 Connections ve History detaylarında bu alanları ve eksiklik nedenlerini gösterir; parent bilgisi yalnız gözlenen bağlamdır. NS-064 Connections ve History'de DNS association kanıtını kesin hostname iddiası olmadan, local ASN/country context'inden ayrı gösterir. NS-069–075 observed baseline ve detail/reset UI uygulanmıştır. NS-076–079 generic evidence, pure scoring, versioned assessment ve mevcut alert lifecycle entegrasyonu yerel backend olarak uygulanmıştır. Kesin domain–connection attribution ve firewall bugün uygulanmış değildir; desktop notification NS-094, per-user installer NS-096 ile eklenmiştir. Polling “opened/closed” gerçek TCP connect/FIN zamanını garanti etmez; per-flow upload/download yoktur.

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

Kullanıcı daha önce açılmış bağlantıları zaman, process veya endpoint üzerinden inceler. Uygulamanın yeniden başlatılmasından sonra geçmiş korunur; Settings → Storage & Privacy üzerinden kullanıcı opt-in scheduled retention ve onaylı scope purge seçebilir. Legacy manual retention API de korunur.

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

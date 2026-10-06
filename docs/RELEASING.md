# NS-051 — Release readiness checklist

## NS-097 signing/manual update gate (2026-10-06)

[Frozen decision, sources and commands](SIGNING_UPDATE_DISTRIBUTION.md),
[dry-run/tamper evidence](SIGNING_UPDATE_ACCEPTANCE.md). NS-097 spike COMPLETE;
M17 IN PROGRESS, NS-098/099 not started. This is not a release/tag approval.
Current 0.1.0 installer remains unsigned and unchanged; 0.1.1 is only NS-096 fixture.

- [x] Limited unsigned pilot policy, key ownership/custody/CI boundary,
  verification, cost/eligibility, network disclosure and rollback decisions frozen.
- [x] Canonical 0.1.0 hash/PE version and explicit UNSIGNED state observed;
  copy-only one-byte tamper, wrong hash/version, missing file/malformed manifest reject.
- [ ] Owner audience/license/channel availability and remaining M17 acceptance.
- [ ] Public signer legal identity/eligibility/custody/budget and actual signing run.
- [ ] Protected explicit release build/sign/publish with no PR/fork credentials;
  owned inner PE and generated Inno uninstaller/self-copy signatures verified.
- [ ] Mandatory SHA256/RFC3161 SHA256 timestamp/trust/revocation/publisher checks;
  final installer/portable hashes and small release manifest after signing.
- [ ] Canonical GitHub Releases prerelease/notes/final hashes assembled and approved;
  immutable assets/tag settings confirmed. No unsigned promotion to broad release.

Existing `build_installer.py` remains an unsigned developer/pilot builder; its
payload `.manifest.json` is not final release metadata. New offline
`packaging/verify_release.py` returns integrity only, signature NOT_CHECKED;
signed manifest assertions fail with AUTHENTICODE_REQUIRED. Built-in Windows
trust commands may have OS network retrieval; disclose explicitly. Manual
updates only, no application update requests. No automatic downgrade/schema/data
rollback; preserve closed backup and use only verified compatible recovery.

The NS-096 records below are historical and do not authorize a signed release.

## NS-096 installer gate (2026-10-06)

Task COMPLETE. Per-user Inno Setup 6.3+ compiler prerequisite; build:
`.\.venv\Scripts\python.exe packaging\build_installer.py --iscc <ISCC.exe>`.
Fresh PyInstaller payload/private-data/license/019 validation precedes compiler;
ignored `dist/NetSentinel-<version>-Setup.exe`, SHA256 and manifest outputs.
ISCC 6.7.3 build and actual payload/PE/SHA256 checks passed; unsigned pilot
`dist/NetSentinel-0.1.0-Setup.exe` produced. Local wizard blocked by Application
Control 4551; isolated portable smoke passed. Exact TASKS native gate passed in
fresh standard-user profiles on an existing Windows VM; no pristine OS snapshot.
0.1.1 installer fixture retains application payload 0.1.0. Final targeted 121,
installer-only 57, full offline 3683 passed/8 deselected; Ruff/mypy/diff PASS.
No signing/update distribution decision or release/tag/NS-097 work.

- [x] Compiler succeeds; actual compiler input/payload inventory, PE and sidecar hashes verified.
- [x] Exact TASKS VM lifecycle acceptance: standard user/no UAC, no Python/Npcap,
  fresh install/data separation, repair, two-version installer-fixture upgrade,
  single registration/path, KEEP/DELETE/reinstall/Cancel and Unicode install/delete.
- [x] Record native evidence separately from offline/source/offscreen tests.
- [x] Repair/upgrade preserves observed config/DB; app owns schema migrations.
- [x] Static source/payload confirms no driver/elevation/autostart/service/firewall/updater/upload hook.
- [ ] Broader unreported [checklist recipes](INSTALLER_WINDOWS_SMOKE.md), including
  silent flows, running/hidden tray wizard, failure/rollback, native schema
  fixtures, custom spaced/long paths and reparse/inventory-tamper scenarios.
  These are not claimed as native PASS or substituted into exact TASKS acceptance.

[Installer contract](INSTALLER_UPGRADE_UNINSTALL.md), [evidence report](INSTALLER_ACCEPTANCE.md).
The NS-051 records below are historical and do not pass the NS-096 gate.

Bu liste bir release veya tag oluşturmaz. NS-051 kabul ölçütleri geçti ve M10
tamamlandı. Mevcut uygulama sürümü `0.1.0`; ROADMAP'teki `1.0` belgeli kapsam
hedefidir, bu belgenin oluşturulması bir 1.0 yayını değildir.

## 1.0 kapsam karşılaştırması

- [ ] `docs/PRODUCT.md` içindeki bağlantılar, history, cihaz/ARP kimliği,
  DNS, broadcast, VLAN, alert ve PyQt6/SQLite/Diagnostics kapsamını M1–M10
  sonuçlarıyla karşılaştırın. `docs/ROADMAP.md` M10 çıkış ölçütünü denetleyin.
- [ ] Firewall/IPS, DPI, saldırı veya yetkisiz tarama, TLS interception,
  bulut/SIEM ve kusursuz process-packet eşlemesi gibi PRODUCT kapsam dışı
  maddelerini 1.0 özelliği gibi sunmayın.
- [ ] Sürüm, metadata ve kullanıcı belgeleri aynı release candidate'a ait olsun.

## PR kalite kapıları

- [ ] `.github/workflows/ci.yml` PR'da Windows 2022 ve 2025 işlerini
  başarıyla tamamlasın; `pull_request` sonucu görülmeden CI geçmiş sayılmasın.
- [ ] Kilitli bağımlılıklarla aşağıdaki komutları çalıştırın. Testler
  unit/integration/offscreen GUI'yi kapsar. `windows_live` ve `lab_live`
  varsayılan akışta dışarıdadır; `performance` offline fixture'ları dahildir.

```powershell
uv sync --locked --extra dev
.\.venv\Scripts\python.exe -m ruff check src tests packaging
.\.venv\Scripts\python.exe -m mypy
.\.venv\Scripts\python.exe -m pytest -m "not windows_live and not lab_live" --cov=netsentinel --cov-report=term-missing --cov-fail-under=85
uv audit --locked --python-version 3.12 --python-platform windows
```

- [ ] Coverage toplamı en az %85 olsun; rapordaki atlanan `windows_live` ve
  `lab_live` testlerini başarılmış test saymayın. Type gate şu anda domain,
  application portları ve shared portable sözleşmelerini kapsar; tam uygulama
  type temizliği iddia edilmez.
- [ ] Audit bulgularını ve araç/servis hatalarını başarısız kapı olarak ele
  alın. Bilinçli istisna gerekiyorsa gerekçeyi release kararına yazın.

## Güvenlik ve izin

- [ ] `docs/SECURITY.md` ile karşılaştırın: varsayılan pasif davranış,
  kullanıcı eylemi olmadan capture/aktif probe olmaması, otomatik elevation,
  Npcap kurulumu veya indirme olmaması, kullanıcıya gösterilen yetenek sınırı.
- [ ] Standart kullanıcıda Npcap yokken Connections'ın çalıştığını,
  capture'ın sanitized `Unavailable/Degraded` kaldığını ve explicit capture
  hatasının uygulamayı düşürmediğini clean Windows ortamında doğrulayın.
- [ ] Config/SQLite/log için `%LOCALAPPDATA%\NetSentinel` kullanımını,
  paket klasörüne runtime veri yazılmamasını, bounded log ve payload/credential/
  SQL/yol içermeyen tanı/log sözleşmesini gözden geçirin.
- [ ] Live/lab capture gerektiğinde yalnız yetkili ağda ve ayrı opt-in test
  olarak çalıştırın; PR kalite kapısına veya varsayılan release testine eklemeyin.

## Migration ve paket

- [ ] SQLite migration manifestinin ardışık ve append-only olduğunu kontrol
  edin. Mevcut manifest 001–019'dur; fresh DB ve 018→019 yükseltmesini aynı
  release candidate artifact'ının `--self-test`/smoke raporuyla doğrulayın.
- [ ] Windows x64 `onedir` artifact'ını üretin; farklı cwd, boşluk/Türkçe
  karakterli çıkarma yolu, Qt, SQLite, icon, onboarding ve kapanışı
  `packaging/smoke_windows.py` ile doğrulayın.
- [ ] ZIP ve `.sha256` dosyalarını eşleştirin; temiz Windows VM'ye yalnız
  artifact aktarın ve VM'de hash'i yeniden doğrulayın. Npcap olmayan standart
  kullanıcı oturumunda ilk/ikinci açılış, degraded mode, LocalAppData ve temiz
  kapanış sonuçlarını kaydedin. SmartScreen/App Control engelini uygulama
  çökmesinden ayrı raporlayın.
- [ ] `THIRD_PARTY_NOTICES.md` ve `licenses/` içeriğini, PyQt6/Scapy dağıtım
  koşullarını ve Npcap'in bundle edilmediğini inceleyin. Zip klasörü
  kaldırıldığında `%LOCALAPPDATA%\NetSentinel` verisi varsayılan olarak korunur;
  silme veya yedekleme kullanıcı kararıdır.

## NS-051 yerel dry-run kaydı (2026-09-28)

Bu kayıt 1.0 release onayı değildir. NS-050'nin hash'i doğrulanmış `0.1.0`
artifact'ı Npcap'siz temiz Windows VM'de geçti; ayrıntı
`packaging/README.md` içindedir.

- [x] `uv.lock` güncel; Ruff temel E/F kuralları ve portable mypy kapsamı geçti.
- [x] Varsayılan suite: 938 passed, 5 deselected. Offline performance: 6 passed.
- [x] CI ile aynı coverage komutu: 938 passed, 5 deselected; toplam %88,64,
  gerekli %85 tabanının üzerinde.
- [ ] Bir PowerShell değişkenine tüm test çıktısını toplayan ayrı coverage
  denemesinde 28 failure ve 3 error görüldü; aynı suite doğrudan stdout'a
  çalıştırılan iki koşuda 938 passed ile geçti. Bu ayrı çıktı yakalama
  denemesinin nedeni doğrulanmadı; gerçek PR matrisinin üç işi bu hatayı
  tekrarlamadan geçti. Başarısız deneme başarılı test olarak sayılmaz.
- [x] `uv audit --locked`: 28 pakette bilinen açık veya olumsuz proje durumu yok.
- [x] Bilinçli yanlış lint/type/test/coverage girdileri sıfır olmayan çıkış
  üretti. Workflow YAML ayrıştırıldı; PR tetikleyicisi ve Windows matrisi
  yapısal olarak doğrulandı.
- [x] PRODUCT kapsam ve kapsam dışı listesi ile ROADMAP 1.0 hedefi dry-run'da
  karşılaştırıldı; yeni ürün yeteneği veya release/tag eklenmedi.
- [x] [GitHub PR #1](https://github.com/ByteGambit/NetSentinel/pull/1)'de
  `CI / Lint, types, and dependency audit`, `CI / Offline
  tests and coverage (windows-2022)` ve `CI / Offline tests and coverage
  (windows-2025)` işleri geçti. Sentetik VLAN/DNS fixture'larının host interface
  bağımlılığı giderildikten sonra son işlevsel commit `999bd394b3b0601c1fec92213919c31aa019801d`
  üzerinde üç başarılı kontrol görüldü.
- [ ] Gelecekteki 1.0 release candidate'ı için artifact build ve clean VM smoke
  ayrıca tekrarlanmalıdır; NS-050'nin `0.1.0` artifact sonucu ona aktarılmaz.

Son yerel PR doğrulamasında DNS parser testleri 13 passed, varsayılan suite ve CI
coverage komutu 940 passed / 5 deselected; coverage %88,65, Ruff ve mypy geçti.
Bu kayıt NS-051 kabul kanıtıdır; gelecekteki bir 1.0 release candidate'ının
ayrı checklist onayı değildir.

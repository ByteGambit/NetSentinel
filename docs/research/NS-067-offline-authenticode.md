# NS-067 — Offline Authenticode spike

**Karar: GO — yalnız local, on-demand signer evidence için. Catalog desteği REQUIRED.**
Tarih: 2026-10-01. NS-068 conditional production adapter ayrı tasktır; bu spike
uygulama portu, UI, persistence veya production signer eklemez. GO, imzayı
malware/güvenlik hükmüne dönüştürme kararı değildir. Standard-user Windows
oturumunda embedded ve catalog imzaları, offline WinTrust policy ile yerel
örneklerde doğrulandı. Ağ çıkışının paket düzeyinde gözlenmesi, elevated oturum,
expired certificate fixture ve çoklu imza fixture'ı **NOT TESTED**. Bunlar
NS-068 kabulünde ayrıca sınanmalıdır.

## Soru, kapsam ve kanıt düzeyi

Soru: NetSentinel local executable file için standard-user ortamında güvenilir
signer/signature evidence çıkarabilir mi? **Evet, erişilebilir yerel dosyalar
için, ayrı embedded/catalog yolları ve cache-only trust policy ile.** Sonuç,
*diskte o anda incelenen dosya sürümüne* aittir; process'in yüklenmiş image'ı,
publisher'ın güvenilirliği, malware reputation veya kullanıcı tercihi değildir.
`0` WinVerifyTrust dönüşü yalnız seçilen action/policy altında trusted demektir;
başka nonzero kod başarı sayılamaz ([WinVerifyTrust]).

Burada **API-supported**, Microsoft belgesindeki imkân; **live-verified**,
bu hostta harness çıktısı; **unknown/not tested**, kanıtın eksik olduğu alan.
Testler Windows `10.0.26200.0`, x64, Python 3.12.14 ve **medium-integrity,
non-admin** token ile yapıldı. Dosyalar çalıştırılmadı veya DLL olarak
yüklenmedi. İnternetten fixture indirilmedi, online revocation çağrısı
yapılmadı. Sistem dosyasına yazılmadı.

## API stack ve offline policy

1. `WINTRUST_ACTION_GENERIC_VERIFY_V2` + `WINTRUST_FILE_INFO` embedded
   Authenticode yoludur. `WTD_UI_NONE`, noninteractive HWND,
   `WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE`,
   `WTD_STATEACTION_VERIFY` ve **her seferinde** `WTD_STATEACTION_CLOSE`
   kullanıldı. Microsoft özellikle code-signature doğrulamasında ağdan alma
   girişimini önlemek için `WTD_CACHE_ONLY_URL_RETRIEVAL` gerektiğini söyler;
   `WTD_REVOKE_NONE` tek başına yeterli değildir ([WINTRUST_DATA]).
2. Catalog yolu: `CryptCATAdminAcquireContext2` ile algoritma bağlamı,
   `CryptCATAdminCalcHashFromFileHandle2` ile Windows SIP/catalog üye hash'i,
   `CryptCATAdminEnumCatalogFromHash`, `CryptCATCatalogInfoFromContext`,
   `WINTRUST_CATALOG_INFO` + aynı offline WinTrust policy. Handle ve WinTrust
   state serbest bırakılır. Bu research harness her algoritma için **ilk**
   catalog'u doğrular; production tüm eşleşmeleri bounded enumerate etmeli.
   SHA-256 ve SHA-1 bağlamları burada lookup kapsaması için denendi; yeni
   SHA-1 imzalama önerisi değildir ([catalog acquisition], [catalog hash],
   [catalog enumeration], [catalog verification]).
3. `WTHelperProvDataFromStateData` → `WTHelperGetProvSignerFromChain` →
   `WTHelperGetProvCertFromChain` ile doğrulama state'indeki **signer**
   sertifikası seçildi; store'daki ilk sertifika signer varsayılmadı. Resmi
   helper'lar belgelenmiş olsa da gelecekte değişebilir uyarısı taşır. Sertifika
   subject/issuer display name `CertGetNameStringW`, SHA-256 certificate DER
   fingerprint ise salt kimlik kanıtıdır; chain policy kararı subject string'e
   dayanmaz ([provider data], [provider signer], [provider cert]).
4. `CryptQueryObject` embedded PKCS#7/store/message extraction için
   **API-supported, harness'te NOT TESTED**; Microsoft API'yi deprecated olarak
   işaretler. `CryptMsgGetParam` signer info'yu, `CertFindCertificateInStore`
   issuer/serial ile signer certificate'ı çözmek için olası yoldur. Salt
   extraction, imzanın dosyaya bağlı digest'ini veya chain trust'ı doğrulamaz
   ([CryptQueryObject], [CryptMsgGetParam]).

`Get-AuthenticodeSignature` catalog varsa catalog signature'ı tercih edebilir;
bu yüzden tek başına embedded yokluğunu açıklamak için oracle değildir.
PowerShell subprocess/text parsing production bağımlılığı önerilmez.
Karşılaştırma komutu **NOT TESTED**; offline retrieval politikasını onun için
sabitleyen bir argüman yoktu ([Get-AuthenticodeSignature]). `signtool.exe`
PATH üzerinde bulunmadı; SDK aracı production runtime koşulu olamaz
([time stamping / SignTool]).

### Ağ, chain ve revocation

İmza varlığı, dosya digest'inin kriptografik doğruluğu, o Windows trust
store/policy ile zincir kararı, timestamp zamanı, revocation, publisher adı,
raw file SHA-256, malware reputation ve user trust **ayrı alanlar** olmalı.
WinTrust offline `0` sonucu yerel/cache chain policy sonucudur; güncel online
revocation veya evrensel güven demek değildir. Revocation disabled olduğunda
durum `NOT_CHECKED`, **asla** `NOT_REVOKED` değildir. Gelecekte cache-only
revocation seçilirse cache yokluğu `UNKNOWN_OFFLINE` olarak korunmalıdır.
`CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL` chain AIA/CTL/root fetch'i,
`CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY` CRL/OCSP fetch'i ayrı sınırlar;
doğrudan `CertGetCertificateChain` kullanılırsa ikisi de değerlendirilmelidir
([CertGetCertificateChain]). AIA, CRL/OCSP, AuthRoot/CTL ve timestamp chain
retrieval normal online policy'de ağ etkinliği üretebilir. WinTrust
`WTD_CACHE_ONLY_URL_RETRIEVAL` kodda gerçekten set edildi ve canlı
doğrulamalar bunu kullandı; **paket/ETW düzeyinde sıfır network girişimi
ölçülmedi**. Host cryptsvc'nin bağımsız arka plan güncellemeleri de bu testin
kontrolünde değildi. NS-068 offline acceptance bunu izole VM'de ayrıca
ölçmelidir ([WINTRUST_DATA], [CertGetCertificateChain], [AIA retrieval]).

`CERT_E_REVOKED`, `CRYPT_E_REVOCATION_OFFLINE`,
`CRYPT_E_NO_REVOCATION_CHECK` gibi kodlar revocation kanıtına göre ayrılır;
bu fixture'larda **NOT TESTED**. `CERT_E_UNTRUSTEDROOT` veya
`CERT_E_EXPIRED` sonucu imzanın hiç bulunmadığı anlamına gelmez.
`TRUST_E_BAD_DIGEST` değişmiş embedded imzayı, `TRUST_E_NOSIGNATURE`
embedded yolda imza bulunmadığını, `TRUST_E_SUBJECT_FORM_UNKNOWN` bu
non-PE örneklerde desteklenmeyen formu gösterdi. Raw kodlar internal bounded
diagnostic olarak kalmalı; portable boundary typed status taşımalı
([trust return values]).

### Timestamp, multiple signatures, publisher

Microsoft, güvenilir timestamp'in signer certificate sonradan expire olsa da
imzayı doğrulanabilir tuttuğunu; timestamp yoksa expiration ile geçersiz
olacağını açıklar. `WTD_LIFETIME_SIGNING_FLAG` set edilirse imzanın ömrü
sertifika ömrüyle sınırlandırılır. Bu politika değişkeni ve legacy PKCS#7
countersignature/RFC 3161 ayrımı future result'ta kayıtlı olmalı. Yerel
örneklerde provider state `csCounterSigners=1`, `sftVerifyAsOf` ve ilk
countersigner error `0` verdi; expired+timestamped veya RFC 3161 fixture'ı
**NOT TESTED**. `sftVerifyAsOf` tek başına signed-at kanıtı gibi sunulmaz;
timestamp chain/policy validasyonu gerekir ([time stamping], [provider signer],
[WINTRUST_DATA]).

`WINTRUST_SIGNATURE_SETTINGS` secondary signature sayısını ve specific index
verification'ı destekler. Bu harness tek varsayılan imza yolunu ve provider
signer listesini en çok 8 ile okur; dual-signed fixture **NOT TESTED**.
NS-068 tek "signed by" string'i üretmeden önce secondary signature'ları
bounded enumerate edip her biri için ayrı verification/publisher/timestamp
state tutmalı. Display subject ve organization/issuer, certificate fingerprint
ve isteğe bağlı serial kimlik/teşhis kanıtıdır; CN eşleşmesi trust policy
değildir ([signature settings], [provider signer]).

## Canlı kontrollü sonuçlar

| Kategori | Embedded WinTrust | SHA-256 catalog | Signer ve sonuç |
|---|---|---|---|
| Windows uygulama, catalog-only (`notepad.exe`) | `0x800B0100` | found, `0` | Microsoft Windows; issuer Microsoft Windows Production PCA 2011; offline local trust |
| Windows uygulama, embedded + catalog (`explorer.exe`) | `0` | found, `0` | Microsoft Windows; iki doğrulama yolu |
| Windows sistem DLL, embedded + catalog (`kernel32.dll`) | `0` | found, `0` | Microsoft Windows; ayrı sertifika fingerprint'leri görülebildi |
| Windows konsol uygulaması, catalog-only (`conhost.exe`) | `0x800B0100` | found, `0` | catalog support olmadan yanlış unsigned |
| Python venv executable, tested paths'te unsigned | `0x800B0100` | no catalog | `no_signature_in_tested_paths`; tüm olası signature biçimleri için evrensel hüküm değil |
| Synthetic non-PE 5-byte data / README | `0x800B0003` | no catalog | unsupported subject form; unsigned ile birleştirilmedi |
| Signed catalog file'ın değiştirilmemiş temp kopyası | `0x800B0100` | found, `0` | path değişse de content/member eşleşmesi sürdü |
| Embedded signed DLL'nin **temp** kopyasında byte 200000 değiştirildi | `0x80096010` | no catalog | embedded signature invalid; signer certificate hâlâ extract edildi |
| Catalog-only EXE'nin **temp** kopyasında byte 200000 değiştirildi | `0x800B0100` | no catalog | eski catalog membership kayboldu; önceden imzalı olduğunu API'den geri çıkaramayız |
| Missing path / directory | preflight `file_not_found` / `not_regular_file` | çağrılmadı | ayrı availability sonuçları |
| Access denied | NOT TESTED | NOT TESTED | local ACL fixture yok |

Değişiklikler yalnız benzersiz temp dizinindeki kopyalarda yapıldı ve
`finally` temizlendi; orijinal dosyalar değişmedi. Catalog SHA-256 member
hash'i aynı dosyanın NS-066 tarzı **raw whole-file SHA-256** değeriyle eşit
çıkmadı (`equals_raw_sha256=false`): Windows SIP/catalog hash algoritması
kullanılmalı. NS-066 digest catalog lookup input'u olarak yeniden kullanılmaz.

Performans yalnız küçük yerel örnekler için fikir verir: aynı process'te
embedded+catalog `explorer.exe` üç turda embedded 148/52/54 ms, catalog
SHA-256 verification 17/23/16 ms; venv `python.exe` embedded 1.7/1.3/1.4 ms;
README unsupported 49/18/16 ms. Catalog-only copy farklı process'lerde
catalog verification 93/101/86 ms görüldü. Bunlar yalnız API elapsed
süreleridir; file hash, lookup ve process startup toplamı değildir.
P99, büyük dosya, soğuk store, domain policy, çoklu catalog ve yoğun queue
ölçülmedi. Tek background worker thread'inde catalog-only test `0` döndü;
COM init gereksinimi bu API dokümanlarında görülmedi, geniş concurrency/thread
safety iddiası **NOT TESTED**. API çağrısı synchronous, documented cancel
parametresi yok: cooperative cancellation çağrı *öncesi/sonrası* ve bounded
daemon worker shutdown ile sağlanmalı; içteki WinTrust call için hard timeout
iddiası yapılamaz.

## Capability matrisi

`SUPPORTED` API kabiliyeti, hostta doğrulandığı anlamına gelmez;
`PARTIAL` politika/ek API/fixture eksik; `UNKNOWN` kaynak ve test kararsız;
`NOT TESTED` bu spike'ta denenmedi. WinVerifyTrust/CryptoAPI sütunu embedded
yolu ve provider-state extraction'ı, Catalog APIs sütunu üye lookup +
WinTrust catalog yolunu ifade eder.

| Capability | WinVerifyTrust/CryptoAPI | Catalog APIs | PowerShell comparison |
|---|---|---|---|
| Embedded signature detection | SUPPORTED (live) | NOT SUPPORTED | PARTIAL (catalog preference) |
| Embedded signature verification | SUPPORTED (live) | NOT SUPPORTED | SUPPORTED (documented; not run) |
| Catalog signature detection | NOT SUPPORTED (file choice alone) | SUPPORTED (live) | SUPPORTED (documented; not run) |
| Catalog signature verification | NOT SUPPORTED (file choice alone) | SUPPORTED (live with WinTrust) | SUPPORTED (documented; not run) |
| Signer subject | SUPPORTED (provider state, live) | SUPPORTED (provider state, live) | SUPPORTED (documented; not run) |
| Issuer | SUPPORTED (live) | SUPPORTED (live) | SUPPORTED (documented; not run) |
| Certificate thumbprint/fingerprint | SUPPORTED (DER SHA-256, live) | SUPPORTED (DER SHA-256, live) | PARTIAL (object property; not run) |
| Timestamp presence | PARTIAL (counter signer count live) | PARTIAL (counter signer count live) | PARTIAL (not run) |
| Timestamp verification | PARTIAL (provider error observed; expired case untested) | PARTIAL (same) | NOT TESTED |
| Chain trust | SUPPORTED (offline WinTrust `0` live) | SUPPORTED (offline WinTrust `0` live) | PARTIAL (policy not controlled here) |
| Offline verification | SUPPORTED (flag documented and used) | SUPPORTED (same WinTrust flag used) | UNKNOWN (no controlled policy run) |
| Online revocation | NOT TESTED (excluded by task) | NOT TESTED | NOT TESTED |
| Revocation unknown | PARTIAL (typed future semantics needed) | PARTIAL | UNKNOWN |
| Unsigned distinction | PARTIAL (catalog must also be checked) | PARTIAL (lookup errors/algorithms) | PARTIAL (status conflation risk) |
| Invalid signature distinction | SUPPORTED (bad digest live) | PARTIAL (modified member disappears) | NOT TESTED |
| Modified signed file detection | SUPPORTED (embedded copy live) | PARTIAL (membership loss live) | NOT TESTED |
| Multi-signature | SUPPORTED (settings documented; fixture not run) | UNKNOWN (multi-catalog not tested) | NOT TESTED |
| IPv / N/A | NOT SUPPORTED (file verification; IP version N/A) | NOT SUPPORTED (N/A) | NOT SUPPORTED (N/A) |
| Standard user | SUPPORTED (live for accessible files) | SUPPORTED (live) | NOT TESTED |
| Admin requirement | NOT SUPPORTED (none observed; ACL may deny file) | NOT SUPPORTED (none observed) | UNKNOWN |
| No executable loading | SUPPORTED (data APIs; live code path) | SUPPORTED | UNKNOWN (implementation not instrumented) |
| Background-thread suitability | PARTIAL (one worker live) | PARTIAL (one worker live) | NOT TESTED |
| Cancellation | NOT SUPPORTED inside synchronous call | NOT SUPPORTED inside call | UNKNOWN |
| Performance | PARTIAL (small local samples) | PARTIAL (small local samples) | NOT TESTED |
| Production complexity | PARTIAL (FFI/state/error policy) | PARTIAL (SIP hash + multiple handles) | PARTIAL (subprocess/parse unacceptable) |
| Maintenance risk | PARTIAL (documented helper future-change warning) | PARTIAL (catalog API future-change warning) | PARTIAL (shell/runtime dependency) |

## NS-066 ilişkisi, TOCTOU ve NS-068 önerisi

NS-066 `LocalFileExecutableHasher` on-demand, 1 worker, 64 pending,
128 cache, 1 GiB/5 s cap, streaming reads ve before/opened/after metadata
kontrolü kullanır. Raw file SHA-256 bir fingerprint'tir; signer veya process
identity değildir. `ProcessIdentity(pid, create_time)` ve executable path
bir request correlation'dır, immutable file identity kanıtı değildir.
Hash snapshot A ile signer snapshot B farklıysa ortak UI evidence olarak
birleştirilmemeli. `WINTRUST_FILE_INFO.hFile` ve catalog
`WINTRUST_CATALOG_INFO.hMemberFile` documented optional read handle'larıdır;
catalog hash'i aynı açık handle'dan hesaplandı. Buna rağmen provider path veya
başka açılış yapabilir, dosya içerikleri aynı handle üzerinde yazılarak
değiştirilebilir ve metadata collision mümkündür. Perfect atomicity bu spike'ta
kanıtlanmadı. Future flow: local/non-UNC path ve reparse/symlink policy →
read handle ve file ID/device/size/mtime metadata → hash ve signer work →
metadata recheck; değişirse `FILE_CHANGED`, sonuç publish/cache edilmez.
Gerekirse handle sharing/lock stratejisi ve metadata collision için content
digest bağlama ayrı test edilir. Cache key **path-only olamaz**; file ID/device,
size, mtime ve mümkünse raw content digest + trust-store/policy version +
verification time/freshness gerekir. Catalog database veya trust store değişimi
cache sonucunu değiştirebilir; cache kısa TTL/explicit invalidation ister.

NS-068 için önerilen sınır: domain'de Windows'tan bağımsız typed evidence,
application'da on-demand bounded one-worker/dedup/cache ve current process/path
correlation, infrastructure'da yalnız documented WinTrust/catalog APIs,
presentation'da ayrı `signature present`, `integrity`, `local chain trust`,
`timestamp`, `revocation NOT_CHECKED/UNKNOWN`, `publisher display`, `source`
alanları. Önerilen sonuçlarda en az `UNSIGNED` (yalnız desteklenen yollar
eksiksiz sorgulandıysa), `SIGNED_VALID_TRUSTED_LOCAL`,
`SIGNED_VALID_UNTRUSTED`, `SIGNATURE_INVALID`, `CERTIFICATE_EXPIRED`,
`REVOCATION_UNKNOWN/NOT_CHECKED`, `VERIFICATION_UNAVAILABLE`,
`ACCESS_DENIED`, `FILE_NOT_FOUND`, `FILE_CHANGED`, `UNSUPPORTED` ayrılır;
WinTrust tek return code'dan kriptografik geçerlilik ile chain trust'ı
her zaman ayrı çıkaramadığı için `SIGNED_VALID_UNTRUSTED` yalnız yeterli
provider/chain evidence ile verilmelidir. Raw Windows code optional bounded
internal detail; path, subject ve fingerprint diagnostics/log'a dökülmez.
GUI/monitoring thread'i bloklanmaz, network/reputation lookup eklenmez,
auto elevation olmaz. Catalog REQUIRED; yalnız embedded adapter Windows
binary'lerinde sistematik false unsigned üretir.

## Doğrulama ve çalıştırma

Harness: `tools/research/ns067_wintrust_probe.py`; research-only, explicit
local absolute path, 16 path/32 MiB/5 repeat sınırı, target execute/LoadLibrary
yok. Örnek invocation:

```powershell
.\.venv\Scripts\python.exe tools/research/ns067_wintrust_probe.py "$env:WINDIR\System32\notepad.exe" "$env:WINDIR\explorer.exe"
.\.venv\Scripts\python.exe tools/research/ns067_wintrust_probe.py --repeat 3 "$env:WINDIR\explorer.exe" (Resolve-Path .\.venv\Scripts\python.exe).Path
.\.venv\Scripts\python.exe -m pytest -q tests/unit/research/test_ns067_wintrust_probe.py
```

Değiştirilmiş kopyalar benzersiz `%TEMP%\ns067-<GUID>` altında oluşturuldu,
byte 200000 terslendi, yalnız harness'e verildi, `finally` içinde exact
temp path doğrulanıp silindi. Live results üstte kayıtlıdır. Fake outcomes
catalog-only, bad digest, catalog API failure, unsupported non-PE ve
untrusted catalog'u sınıflandırır. Harness first-catalog-only ve 32 MiB cap
nedeniyle production implementation değildir. Ürün koduna import edilmez.

Kopya/mutation testinin kullanılan PowerShell akışı:

```powershell
$root=Join-Path $env:TEMP ('ns067-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$embedded=Join-Path $root 'kernel32-mutated.dll'
$catalog=Join-Path $root 'notepad-mutated.exe'
try {
    Copy-Item -LiteralPath "$env:WINDIR\System32\kernel32.dll" -Destination $embedded
    Copy-Item -LiteralPath "$env:WINDIR\System32\notepad.exe" -Destination $catalog
    foreach ($p in @($embedded,$catalog)) {
        $bytes=[IO.File]::ReadAllBytes($p)
        $bytes[200000]=$bytes[200000] -bxor 1
        [IO.File]::WriteAllBytes($p,$bytes)
    }
    .\.venv\Scripts\python.exe tools/research/ns067_wintrust_probe.py $embedded $catalog
} finally {
    $resolved=[IO.Path]::GetFullPath($root)
    $tempRoot=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
    if (-not $resolved.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Unsafe temporary path'
    }
    foreach ($p in @($embedded,$catalog)) {
        if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
    }
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root }
}
```

Validation (aynı Windows ortamı, offscreen Qt):

- `.venv\Scripts\python.exe -m pytest -q tests/unit/research/test_ns067_wintrust_probe.py tests/gui/test_engine_bridge.py`: **20 passed**.
- `.venv\Scripts\python.exe -m pytest -q`: iki ardışık koşuda **1099 passed, 5 deselected**. İlk iki tam koşu `test_real_sqlite_migration_repository_worker_and_three_pages` sırasında Qt access violation ile düşmüştü. Aynı ortamda önceki `802789d52dd23f0fe9cb80b7d49c4c6e96800d88` commit'inin tam koşusu da aynı testte çöktü; dolayısıyla NS-067 kaynaklı bir regression değildi. `QtEngineBridge.destroyed` üzerindeki geçici lambda yerine `state.detach` doğrudan bağlandı. Var olan QObject destruction testi ve iki tam koşu bu yaşam döngüsü düzeltmesinden sonra geçti.
- `.venv\Scripts\ruff.exe check src tests tools/research/ns067_wintrust_probe.py tools/research/ns067_pure_mypy.py`: **passed**.
- `.venv\Scripts\python.exe tools/research/ns067_pure_mypy.py`: **Success: no issues found in 16 source files**. Sürüm: **mypy 2.3.1 (compiled: no)**. Windows Application Control `librt.internal` DLL'ini engellediği için bu kaynak tabanlı launcher, mypy'nin kurulu Python kaynaklarını çalıştırır; yalnızca geçici/no-incremental cache için Python writer sağlar ve binary read çağrılarında hata verir. Güvenlik politikası veya engellenen DLL değiştirilmedi. Kasıtlı `str` → `int` assignment hatasıyla negatif kontrol exit 1 verdi.
- `git diff --check`: **passed**.

[WinVerifyTrust]: https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust
[WINTRUST_DATA]: https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data
[catalog acquisition]: https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadminacquirecontext2
[catalog hash]: https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadmincalchashfromfilehandle2
[catalog enumeration]: https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadminenumcatalogfromhash
[catalog verification]: https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_catalog_info
[provider data]: https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wthelperprovdatafromstatedata
[provider signer]: https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovsignerfromchain
[provider cert]: https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovcertfromchain
[CryptQueryObject]: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptqueryobject
[CryptMsgGetParam]: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetparam
[Get-AuthenticodeSignature]: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature?view=powershell-7.6
[CertGetCertificateChain]: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain
[AIA retrieval]: https://learn.microsoft.com/en-us/windows-server/security/authority-information-access-retrieval
[time stamping]: https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures
[trust return values]: https://learn.microsoft.com/en-us/windows/win32/seccrypto/certificate-and-trust-return-values
[signature settings]: https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_signature_settings

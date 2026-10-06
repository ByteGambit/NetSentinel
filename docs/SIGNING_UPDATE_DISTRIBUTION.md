# NS-097 — Signing/update distribution spike

Decision frozen 2026-10-06. This is a distribution/security design spike, not a
release authorization. The authoritative TASKS acceptance is **signed workflow
or explicit pilot policy; key ownership/network disclosure; explicit decision
and fail-closed tamper result**. Evidence is in
[SIGNING_UPDATE_ACCEPTANCE.md](SIGNING_UPDATE_ACCEPTANCE.md).

## Decision and current state

**Immediate recommendation: limited, explicitly unsigned pilot through the
project's GitHub Releases, with manual updates. Broad public beta/production:
NO-GO until a public signer and the remaining M17 gates are ready.** A limited
public pilot is CONDITIONAL GO only after the owner approves its audience,
licensing, channel access and the remaining beta acceptance. NS-097 does not
publish anything or override NS-098/099. Signed distribution remains the target.

Preferred production path: **Azure Artifact Signing Public Trust, if the actual
legal publisher qualifies; otherwise CA-issued OV with managed cloud/HSM
custody**. If there is no qualifying organization, evaluate a CA's individual
validated offering separately; do not pretend an individual has OV eligibility.
Until one of these paths is validated, stay at the limited unsigned pilot gate.
No certificate purchase, identity enrollment, resource provisioning or updater.

| Known locally | Unknown | Owner decision required before distribution |
|---|---|---|
| Remote `https://github.com/ByteGambit/NetSentinel.git`; GitHub Actions Windows 2022/2025 CI | Repository visibility, GitHub plan/protection settings | Make the canonical channel accessible to the intended audience; protect release authority |
| Version source `src/netsentinel/version.py` = `0.1.0`; schema 019 | Legal publisher/entity/country, validated identity, Azure tenant/subscription, CA account | Select truthful legal identity, budget and service; name human custodians |
| No production signing setup in packaging/CI | Existing certificates or resources outside this repository | Do not infer their existence or absence from the repo |
| No project license file tracked; third-party license inventory is generated | Public/open-source program eligibility and redistribution clearance | Resolve licensing before public pilot; no open-source discount assumed |

The existing NS-096 installer is **NotSigned**, 37,535,265 bytes, PE FileVersion
and ProductVersion `0.1.0`. SHA-256:
`f9c253eea2b605436fc685cdf2334c4d52233a3bb5ac01d6a358b633fae419a7`.
The 0.1.1 upgrade installer was a lifecycle fixture whose app payload remained
0.1.0; it is never a release candidate. No byte-reproducibility claim is made.

## Options, eligibility and cost

Prices below are USD reference prices accessed 2026-10-06, excluding tax,
exchange rates, runner costs and regional quotes. Recheck before any purchase.

| Option | Current facts and costs | NetSentinel decision |
|---|---|---|
| Unsigned pilot | No signing fee; GitHub access/CI costs depend on plan. HTTPS and SHA256 help provenance/integrity but do not authenticate a publisher against channel compromise | Limited pilot conditional; broad distribution NO-GO |
| Azure Artifact Signing (formerly Trusted Signing) | Basic $9.99/account/month, 5,000 signatures/month, excess $0.005/signature; Premium $99.99, 100,000, same excess. Basic annual base $119.88; includes managed certificate lifecycle, no separate token/certificate purchase [S1,S4] | Preferred production if eligible; no paid account created |
| Traditional OV | Example SSL.com $129 one-year, annualized $96.75–129 over advertised prepaid terms; multi-year purchase is not a multi-year certificate. Token +$379 on OV page. Other issuer GlobalSign: price not publicly fixed / quote required on reviewed page [S11,S14] | Conditional fallback after organization validation, regional issuance and custody quote |
| OV cloud custody | SSL.com eSigner page shows Tier 1 $15/month equivalent with 240 signings and annual/monthly selector; billing term must be confirmed. Illustrative $129 + 12×$15 = $309/year, not a purchase quote. Same site lists token $249 here versus $379 on OV page: conflicting product configurations, obtain final quote. BYO HSM attestation starts $500, plus infrastructure costs [S13] | Managed cloud preferred to attaching USB token to a developer's CI runner |
| EV | SSL.com one-year $349; discounted prepaid terms differ; compliant custody/subscription additional. Extended identity vetting may help specific enterprise procurement; no driver or contractual requirement here [S12] | NO-GO for current premium; no instant SmartScreen reputation |
| Microsoft Store | MSIX Store signing/hosting is provided by Microsoft. Existing unpackaged Win32 EXE/MSI listing requires publisher-paid signing and hosting [S9] | Defer; current Inno installer gets no free signing bypass |
| Self-signed | No public CA fee; manual trust deployment/cleanup risk | Dev/test only; public pilot/beta NO-GO; never ask users to install our root |

Public Trust Artifact Signing organizations must be in **US, Canada, EU, UK,
Australia, New Zealand, Japan, South Korea, Singapore, Switzerland, Norway or
Israel**; individuals must be in **US or Canada**. A service region is not a
publisher country. Türkiye is not in this eligibility list: if the publisher
is located there, this path is currently NO-GO. Timezone/workstation location
does not establish legal domicile. Private Trust's geographic exception does
not make it a public distribution alternative. Organization validation uses
legal entity/public records, website/domain emails/business documents and a
representative's identity; individual validation requires matching government
ID/address and an Individual-type billing account. [S2]

A **paid Azure subscription** is required; free/trial/sponsored subscriptions
are not accepted. CN/O reflects a validated legal name, not an invented
NetSentinel company. Identity validation expiry can stop signing and requires
renewal; budget includes continued service and identity administration. [S3]

Traditional CA issuance needs verified organization details and authorization;
issuers' countries, sanctions and document rules require confirmation. Current
CA/B rules require hardware-backed subscriber keys (at least FIPS 140-2 Level 2
or Common Criteria EAL4+), including non-EV since June 2023; issuance from
2026-03-01 has maximum 460-day certificate validity. Renew/reissue before expiry,
even under a prepaid multi-year commercial plan. Token signing adds secure
runner/PIN/device handling; cloud HSM adds provider authentication, availability,
quota and renewal integration. Ordinary exportable software PFX is not the
recommended production path. [S10,S11]

## Windows trust and Store caveats

Signing does **not** guarantee no SmartScreen warning. Microsoft describes
publisher/certificate and file-hash reputation; a new build/hash can still warn.
EV no longer starts with instant positive reputation. Signing lets a user
inspect authenticated publisher/integrity, not a malware verdict, a download
threshold or a guaranteed date when warnings disappear. Smart App Control may
supersede SmartScreen on Windows 11 and checks executable components too.
Enterprise Application Control still follows its own allow policy. [S5]

The NS-096 host really blocked the unsigned wizard with App Control event 4551;
the VM lifecycle pass does not establish allowance on other machines. No
disable-security, Defender exclusion, trusted-root installation or bypass guide.
If blocked, stop and use the organization's approved distribution route.

Store's specific Win32 rules take precedence over generic advice saying that
Store apps are re-signed: unpackaged installer **and its PE files** still need
publisher signatures chaining to the required trusted CA. [S8,S9] Listing also
requires an offline EXE/MSI, immutable versioned HTTPS installer URL, silent
installation/certification and appropriate metadata. MSIX would be a new
packaging/data/lifecycle validation task and brings OS-managed updates. Neither
route is implemented now. Artifact Signing's latest certificate-management
page distinguishes Windows Platform Trust List from the Trusted Root Program;
confirm current Store certification eligibility before using it there. [S6]

## Pilot channel and manual update contract

The sole canonical source is
**https://github.com/ByteGambit/NetSentinel/releases**. This is the selected
future channel, not evidence that a public release or publicly accessible repo
already exists. A website may link there; it must not maintain separate latest
metadata. Never use the 0.1.1 fixture or random file-share links as a release.

Numeric app/PE/installer version is X.Y.Z from `version.py`. Channels:
`pilot` = unsigned limited audience, `beta` = public signed prerelease,
`stable` = signed production after the relevant gates. Tag references are
`vX.Y.Z-pilot.1`, `vX.Y.Z-beta.1`, `vX.Y.Z` respectively; pilot/beta GitHub
releases are marked prerelease. Increment the app version for a changed payload;
never repurpose a version/tag or move a release tag. No nightly channel now.
The manifest verifier deliberately supports this small convention only.

Before a pilot, the owner records clean source SHA, audience and license review;
publishes installer, final SHA256 sidecar, small release manifest and release
notes together. Notes identify version, fixes, known limitations, schema impact,
backup/downgrade restrictions and **unsigned pilot** prominently. Licenses and
notices remain included in the payload; the existing generated dependency
inventory is not a standards-compliant SBOM. SBOM expansion is deferred.

User reads current version in About, manually opens the canonical channel in a
browser, checks notes/signature/hash/version, quits NetSentinel including the
hidden tray app and explicitly runs the installer. NS-096 handles compatible
repair/upgrade. No background check, download, updater daemon, scheduled update,
auto-install or self-restart. Manual update is sufficient for the M17 model;
it does not prove NS-099 beta readiness.

## Threat model and signing authority

Account/token compromise can replace unsigned downloads and their hashes
together. A SHA256 beside a compromised file does not prevent that attack;
HTTPS does not independently authenticate an unsigned publisher. Signed
installer + trusted publisher verification + canonical HTTPS channel + final
hash is the chosen first signed-manual-beta trust model. An independent manifest
signature/TUF/cryptographic anti-rollback framework is not justified now: it
would add key/bootstrap/rotation obligations without an automatic client.
Stale valid releases and maliciously signed code remain risks. Users must check
withdrawal notices and version; signing-key compromise needs incident response.

| Authority | Owner / allowed role |
|---|---|
| Legal signing identity | Project owner acting as the validated publisher; exact legal name unresolved |
| Account administration / enrollment / renewal | Named publisher custodian, MFA; separate from routine build identity |
| Release approval | Project owner or named release maintainer, explicit reviewed source/hash/notes |
| Signing | Dedicated release identity scoped to a single production profile; Artifact Signing Certificate Profile Signer role [S15] |
| Identity validation | Separate Artifact Signing Identity Verifier; never granted to PR/build runner [S15] |
| Publishing | Dedicated publish job, repository-scoped short-lived token after verification |
| Revocation / emergency recovery | Owner plus named backup custodian can disable access, contact provider/CA and recover account |

Artifact Signing holds keys in managed FIPS 140-3 Level 3 HSMs and provides
digest signing without uploading the file. [S7] The publisher owns identity and
authorization, not an exportable workstation key. For OV use compliant provider
HSM/token custody. No production PFX/P12/private PEM/key in Git, `.env`, installer,
ZIP, logs or plaintext/base64 CI secret. Cloud credentials still need restricted
access/rotation even when the private key is non-exportable.

Documentation caveat: S7/FAQ state FIPS 140-3 Level 3; S6 still describes
FIPS 140-2 Level 3 operated modules and explicitly disallows key/cert import or
export. Record this mismatch and confirm provider compliance evidence if needed;
both describe remote hardware custody, not a downloadable private PFX.

Current `.github/workflows/ci.yml` is credential-free `pull_request` and
`workflow_dispatch`, `contents: read`, pinned actions and no signing/publishing.
Keep it so. Future explicit release workflow uses reviewed clean main/source
SHA and protected version tag; **ordinary push never signs**. Quality/build,
sign and publish are separate jobs/identities. PR/fork artifacts and
`pull_request_target` code never get signer credentials. Use isolated ephemeral
Windows runners; sign an explicit owned-file allowlist, never arbitrary uploads
or recursive third-party PE globs. Review lockfile/compiler/actions and all
workflow changes before releasing.

Use a protected `release-signing` environment with selected main/release tags
and required approval; prevent self-review where a second maintainer exists.
GitHub required reviewers on Free/Pro/Team are public-repo-only: visibility/plan
must be checked; if unavailable, use a separately controlled manual signing
gate, never silently bypass approval. [S16] Prefer Azure OIDC federation and
`azure/login` followed by Microsoft's `Azure/artifact-signing-action`, pinned to
reviewed commits. Only sign job gets `id-token: write`; scope the Entra federated
subject to the actual repo/environment and audience, confirm its current `sub`
format (new/transferred repositories may use immutable IDs). Avoid reusable
static cloud/PAT secrets. Only publish gets `contents: write`, no signing role.
[S17,S18] Actual protection settings are not audited or changed by this spike.

Enable immutable releases before first publication if supported and confirmed;
GitHub protects associated assets/tags and supplies release attestations. [S19]
Assemble in draft, review all bytes/notes, then publish once. Immutability does
not stop an authorized compromised account creating a new bad release. Keep
separate archived hashes/audit; secure owner recovery/MFA and minimal tokens.
If immutability is unavailable, owner-enforced no replacement/tag rewrite plus
archived evidence is required; do not claim platform enforcement.

## Production signing order and timestamp policy

All steps below are a **future target**, not enabled by the current builder:

1. Clean reviewed commit → locked tests/quality → fresh PyInstaller payload.
2. Sign and timestamp `NetSentinel.exe`; verify before packaging. It is the
   only NetSentinel-owned payload EXE in the current inventory; the narrow data
   deletion helper is a mode of that EXE, not another helper binary. Future
   owned native helpers must join the explicit inventory. Preserve third-party
   DLL/PYD/EXE vendor signatures; do not sign them as NetSentinel-authored code.
3. Refresh owned-file checksums after inner signing; create portable ZIP only
   after signed inner bytes are final. Current `build_windows.py` creates its
   unsigned ZIP earlier, so that output cannot be promoted as signed production.
4. Compile Inno with an externally configured fixed signing wrapper and
   `SignedUninstaller=yes`: sign/timestamp generated uninstaller and temporary
   self-copies during compilation. Outer post-build signing alone misses these.
   Prefer Inno `SignTool=<controlled-name>` integration for these generated
   programs; `$f` is the quoted target. No arbitrary `$p` forwarding or secrets
   in `.iss`. Current `.iss` has no signing directives. [S20,S21]
5. Inno's configured tool also signs/timestamps final Setup.exe; verify outer
   installer and installed uninstaller in isolated smoke, plus all required
   owned inner PE files. No second signing pass or mutation after verification.
6. Hash **final signed and timestamped bytes**, produce sidecar/release manifest,
   reverify, owner approve, publish exact verified bytes. This invariant also
   applies to unsigned pilot (hash after final compile) and portable ZIP.

Authenticode baseline: SHA256 file digest, **RFC3161 SHA256 timestamp required**,
no SHA1-only flow. SDK SignTool is an explicit prerequisite, not silently
installed. `sign` may warn on timestamp failure; treat **all nonzero exit codes
including 2/warnings**, missing timestamp, wrong identity, trust/signature failure,
partial owned signing or hash/manifest failure as release failure. [S22]

Reviewed command/config dry-run, placeholders only; not executed:

```powershell
& '<SDK>\x64\signtool.exe' sign /fd SHA256 /tr 'http://timestamp.acs.microsoft.com' /td SHA256 /dlib '<client>\x64\Azure.CodeSigning.Dlib.dll' /dmdf '<metadata.json>' '<owned-file.exe>'
& '<SDK>\x64\signtool.exe' verify /pa /all /v /tw '<owned-file.exe>'
if ($LASTEXITCODE -ne 0) { throw 'Release verification failed' }
```

Metadata contains endpoint/account/profile/correlation ID, no secret; choose
region endpoint matching the account. Current client package name is
`Microsoft.ArtifactSigning.Client`, while DLL remains `Azure.CodeSigning.Dlib.dll`.
Use a reviewed supported SDK/client/.NET combination. [S23]

For Artifact Signing use Microsoft's recommended TSA
`http://timestamp.acs.microsoft.com`; retain this official HTTP endpoint rather
than invent an HTTPS replacement. RFC3161 token authentication/chain is mandatory;
network interference must fail signing, not permit unsigned fallback. For OV
freeze the selected CA's supported RFC3161 endpoint after issuer choice. TSA
and signing requests occur on release infrastructure, never in the app.
Timestamp proves chronology, not code safety. Artifact Signing certificates
renew daily and last 72 hours; timestamp validity can survive signer/TSA expiry
subject to trust/revocation. Expiration differs from revocation. Do not pin an
immutable leaf thumbprint; service profile EKU can identify a durable profile
but changes if recreated. Record approved publisher/profile transitions. [S6]

## Verification, manifest and user commands

Read the canonical versioned release and its warning/withdrawal/notes first.
Download named installer and published sidecar/manifest; compare the expected
hash from that release. Signing/renaming/version resource text alone is not
provenance. Pilot signature result must honestly be UNSIGNED; signed beta must
match the approved legal publisher and pass trust/timestamp verification.

```powershell
$installer = (Get-Item -LiteralPath '.\NetSentinel-0.1.0-Setup.exe').FullName
$expected = 'f9c253eea2b605436fc685cdf2334c4d52233a3bb5ac01d6a358b633fae419a7'
if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash -ine $expected) { throw 'Hash mismatch: stop' }
if ((Get-Item -LiteralPath $installer).VersionInfo.FileVersion.Trim() -ne '0.1.0') { throw 'Version mismatch: stop' }
$signature = Get-AuthenticodeSignature -LiteralPath $installer
$signature | Select-Object Status,SignerCertificate,TimeStamperCertificate
# Pilot: expected NotSigned; never call it trusted. Signed release: require Valid,
# approved publisher, mandatory timestamp, and the production SignTool checks above.
```

Hash/version operations are local. **Get-AuthenticodeSignature and SignTool are
explicit Windows trust checks; OS chain/AIA/root/revocation handling may contact
network services**. Do not advertise these as guaranteed offline. Release trust
checks should use a controlled online environment with current roots/revocation
data; missing trust/revocation information blocks a production approval. A
certificate merely present is insufficient, and Valid under custom local roots
alone does not establish the intended public publisher. Production audit records
digest algorithms/TSA chain and verified signing time, not only timestamp presence.

| Signature outcome (conceptual) | Treatment |
|---|---|
| SIGNED_TRUSTED | Valid chain/integrity for approved publisher and required timestamp; still not code-safety proof |
| SIGNED_UNTRUSTED | Chain/identity cannot meet policy (includes self-signed/unavailable trust); stop public release |
| SIGNED_INVALID | Bad digest/invalid or revoked signature; stop |
| UNSIGNED | Expected only under explicit limited pilot policy |
| VERIFICATION_ERROR / NOT_CHECKED | Unknown, tool failure or skipped check; cannot approve signed release |

Timestamp state is separate (required-valid / absent / invalid / not-checked).
No signature bool. Current packaging verifier is deliberately **offline integrity
only**, not a signing service or a substitute for public-trust verification:

```powershell
.\.venv\Scripts\python.exe packaging\verify_release.py .\dist\NetSentinel-0.1.0-Setup.exe --sha256 f9c253eea2b605436fc685cdf2334c4d52233a3bb5ac01d6a358b633fae419a7 --expected-version 0.1.0
# Optional --manifest <release.json>; this is NOT the NS-096 payload .manifest.json.
```

Output is fixed JSON with `signature_state=NOT_CHECKED`; exit 0 is
`INTEGRITY_OK`, never publisher trust/install permission. Hash streams in 1 MiB
chunks; 1 GiB/30s cooperative read budget, 64 KiB manifest, local paths only,
reparse ancestors refused, pre/post metadata comparison. Windows PE version
uses a static PowerShell FileVersionInfo command, target path via environment,
15s child timeout, no target execution or trust/network call. Supply a local disk
path; mapped network drives are not independently detected by this small tool.
Other platforms
can hash; required PE version check reports TOOL_UNAVAILABLE. Local filesystem
blocking reads and hostile metadata-preserving races are not hard deadlines or
atomic snapshot guarantees. Errors omit paths, command output and exceptions.

Exit codes: 0 INTEGRITY_OK; 1 HASH_MISMATCH; 2 INVALID_INPUT; 3 VERSION_MISMATCH;
4 IO_ERROR; 5 TOOL_UNAVAILABLE; 6 INVALID_MANIFEST; 7 SIZE_MISMATCH;
8 AUTHENTICODE_REQUIRED; 9 FILE_CHANGED; 10 LIMIT_EXCEEDED. A manifest claiming
signed status returns 8 even with correct hash/version: separate production
verification is still required. Manifest assertions never become trusted states.

Release manifest v1, **illustrative dry-run values; not a published release**:

```json
{
  "format_version": 1,
  "product": "NetSentinel",
  "version": "0.1.0",
  "channel": "pilot",
  "published_at": "2026-10-06T00:00:00Z",
  "filename": "NetSentinel-0.1.0-Setup.exe",
  "size_bytes": 37535265,
  "sha256": "f9c253eea2b605436fc685cdf2334c4d52233a3bb5ac01d6a358b633fae419a7",
  "signature_policy": "unsigned-pilot",
  "signing_state": "unsigned",
  "source_commit": "e22ad5ca6c1bea3b80acbabec018986c23e397cb",
  "release_url": "https://github.com/ByteGambit/NetSentinel/releases/tag/v0.1.0-pilot.1",
  "release_notes": "https://github.com/ByteGambit/NetSentinel/releases/tag/v0.1.0-pilot.1"
}
```

At real release use actual UTC publication time and clean release source SHA;
serialize sorted keys/UTF-8 consistently. No minimum_supported_version, freshness
enforcement, secrets or automatic updater semantics. For signed beta/stable use
`signing_state=signed`, `signature_policy=authenticode-sha256-rfc3161`.
The strict parser rejects duplicate/missing/extra fields, malformed types/time,
filename/hash/size/version/channel/policy inconsistencies and off-channel URLs.
It validates syntax/references, not remote existence or tag→SHA truth. Owners
check that relationship. NS-096's 176 KB payload manifest lists inner files and
is **not** this small final-installer release manifest. It must not be reused
as signed metadata after mutating binaries. Existing builder remains unsigned;
future release integration must generate the final manifest after signing.

## Network/privacy disclosure

| Actor | Current requests / exposure |
|---|---|
| Installer | No required network; no update/download/telemetry hook |
| NetSentinel manual updates | **Zero automatic update requests**; no version endpoint |
| User's browser | Explicit GitHub visit/download; GitHub/CDN sees source IP, timing, user-agent and any account/cookie context |
| Offline verifier | No network API/trust call; optional PE version subprocess reads local file only |
| Windows/browser security checks | May query reputation/certificate/revocation services independently of app; enterprise policy can block |
| Optional TI | Separate existing provider/type/selected-subject consent; never reused as update consent |
| Future release signing infrastructure | Entra/GitHub/OIDC, Azure region signing service, TSA and trust validation; release metadata/digests, not user history |

No future app check is authorized here. If separately approved, proposal is a
disclosed request to the canonical GitHub release metadata endpoint (e.g.
`https://api.github.com/repos/ByteGambit/NetSentinel/releases`), beta-aware explicit
selection, opt-in default disabled, manual trigger first; any periodic mode
would require disclosed interval (proposed at most daily) and an off switch.
Source IP/timing always leave device; app version/OS/channel/user-agent may if
encoded and must be specified before implementation. No device ID, process/path,
DNS/IP history, raw telemetry or file upload. Do not assume `/latest` returns
beta prereleases. This is design disclosure, not an endpoint/client change.

## Downgrade, rollback and incident response

| Action | Frozen beta policy |
|---|---|
| Automatic downgrade | NO; no update client exists |
| Manually install an older binary | Unsupported unless exact old binary/new DB schema compatibility was tested and documented |
| Schema downgrade | NO; existing future-schema safe refusal, never reset/delete newer DB |
| Release withdrawal | Mark bad release withdrawn in notes/canonical advisory, stop promoting/downloading it, preserve tag/hash/audit evidence |
| Application rollback | Only owner-documented compatible prior signed binary; otherwise forward fixed version |
| Data rollback | Never automatic; separate explicit restore of a known closed backup after compatibility checks; history since backup can be lost |

Before upgrade quit all writers and, if needed, copy the entire closed local
data root including relevant SQLite files/config. Sanitized support export is
not a database backup. Uninstall KEEP preserves data. Do not suggest DELETE to
solve incompatible schema. Inno file-copy rollback does not undo completed app
DB migrations. A bad release announcement includes affected versions, known-good
forward fix, compatibility/backup/manual steps and limitations; never overwrite
user DB blindly or silently downgrade. For immutable releases preserve assets
as evidence and warn prominently; if immediate download denial is required,
archive evidence before platform removal and document that immutability limits
selective asset deletion. No user notification daemon is added.

On credential compromise: freeze sign/publish, disable federated/service access,
contact Microsoft/CA to **revoke** affected certs, publish canonical incident
notice, assess all affected hashes/timestamps/runs, rotate access and recover
publisher account, review code/runner provenance, issue verified fixed releases.
Deleting an Artifact Signing profile stops future use but **does not revoke
old certificates** [S3]. Owner and backup custodian retain historical evidence;
do not erase logs/releases to hide impact. Renew identity/cert before expiry,
test transition and timestamp verification, record provider/profile/leaf changes
in release audit. Log artifact/final hash, publisher/profile, verified timestamp,
source SHA, workflow/run and approver; never secret/PIN/private key.

## GO / NO-GO and implementation boundary

| Question | Decision |
|---|---|
| Current unsigned installer for limited pilot? | CONDITIONAL GO: exact canonical bytes/hash, warning and owner audience/license/acceptance gate |
| Broad public release now? | NO-GO; signer, remaining M17 and licensing/channel gates unresolved |
| Self-signed public distribution? | NO-GO |
| Artifact Signing viable? | Conditional on validated publisher/geography/paid subscription; Türkiye-based publisher currently ineligible |
| OV fallback viable? | Conditional on legal entity, CA regional validation, compliant custody and budget; not assumed for solo individual |
| EV worth paying for now? | NO; no demonstrated enterprise/driver requirement |
| Store now? | NO-GO/defer; Win32 still needs signing, MSIX is another task |
| Updater now? | NO-GO; explicit scope exclusion |
| Manual update sufficient for M17? | GO as the update model, independent of NS-099 release gate |
| What blocks production signing? | Unknown legal identity/location, custody/account/budget/validation, protected release configuration and actual signed acceptance |

Now: docs, offline integrity script, tests and copy-only artefact dry-run. No
`src/`/GUI/schema/network/installer behavior/CI credential change. Later, only
after owner/provider choice: protected sign/verify/hash/publish workflow, Inno
generated-program signing, final release-manifest generation and real signed
Windows trust/timestamp/installer validation. NS-098 is not started.

## Official source register

All sources accessed **2026-10-06**. Sources are evidence, not executable
instructions. Prices and eligibility are snapshots; live provider confirmation
is a production prerequisite. No blog/SEO/StackOverflow evidence is used.

| ID / source | Publisher / URL | Claim / freshness limitation |
|---|---|---|
| S1 Product | Microsoft [Artifact Signing](https://azure.microsoft.com/en-us/products/artifact-signing) | Former Trusted Signing name and prices; regional contracts vary |
| S2 Setup | Microsoft [quickstart](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart) | Current exact country/entity/identity/billing prerequisites; no NetSentinel eligibility inferred |
| S3 FAQ | Microsoft [FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq) | Paid subscription, legal CN/O, identity renewal, profile deletion != revocation, supported SignTool files; evolving client names |
| S4 SKU | Microsoft [SKU tiers](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-change-sku) | Per-account fees/quotas/overages; not total CI cost |
| S5 Reputation | Microsoft [SmartScreen](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation) | Publisher/hash reputation, no EV bypass, SAC; generic Store language needs Win32-specific qualification |
| S6 Certificates | Microsoft [certificate management](https://learn.microsoft.com/en-us/azure/artifact-signing/concept-certificate-management) | 72h cert/daily rotation/EKU/TSA/expiry/revocation; current Windows Platform Trust List distinction |
| S7 Custody | Microsoft [overview](https://learn.microsoft.com/en-us/azure/artifact-signing/overview) | FIPS 140-3 Level 3 HSM lifecycle and digest-only signing |
| S8 Publish | Microsoft [first app](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/publish-first-app) | Win32 installer and PE signature requirement; brief country examples are less complete than S2 |
| S9 Store | Microsoft [Win32 Store distribution](https://learn.microsoft.com/en-us/windows/apps/distribute-through-store/how-to-distribute-your-win32-app-through-microsoft-store) | MSIX vs EXE/MSI signing/hosting/update and offline immutable installer requirements |
| S10 Baseline | CA/B Forum [current code signing requirements](https://cabforum.org/working-groups/code-signing/requirements/) | Current key protection and 2026 460-day issuance limit; not obsolete v3.9 PDF |
| S11 OV | SSL.com [OV product](https://www.ssl.com/products/software-integrity/code-signing/ov/) | $129/year and prepaid range, +$379 token, organization validation; checkout configuration/marketing not assurance |
| S12 EV | SSL.com [EV product](https://www.ssl.com/products/software-integrity/code-signing/ev/) | $349 one-year, extra custody, current EV caveat; ignore conflicting instant-reputation cross-link marketing |
| S13 Cloud | SSL.com [eSigner pricing](https://www.ssl.com/products/software-integrity/signing-service/) | Cloud fee/volume, token/HSM alternatives; selector-dependent fee and token-price disagreement require quote |
| S14 Other CA | GlobalSign [code signing](https://www.globalsign.com/en/code-signing-certificate) | Conceptual issuer alternative; reviewed page had no fixed dollar price |
| S15 Roles | Microsoft [assign roles](https://learn.microsoft.com/en-us/azure/artifact-signing/tutorial-assign-roles) | Separate identity verification and profile signing RBAC |
| S16 Approval | GitHub [environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments) | Branch/tag restrictions, approval, plan/public-repo caveats; settings not confirmed |
| S17 OIDC | GitHub [OIDC in Azure](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-azure) | Federation, job token permissions and newer immutable-subject caveat |
| S18 Integration | Microsoft [artifact-signing-action](https://github.com/Azure/artifact-signing-action) | Current GitHub action, OIDC recommendation, signer role, digest/TSA inputs; pin reviewed commit later |
| S19 Release protection | GitHub [immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) | Asset/tag immutability and attestation; enablement not assumed |
| S20 Inno signing | Inno Setup [SignTool](https://jrsoftware.org/ishelp/topic_setup_signtool.htm) | External compiler signing and substitution; old SHA1 examples not adopted |
| S21 Uninstaller | Inno Setup [SignedUninstaller](https://jrsoftware.org/ishelp/topic_setup_signeduninstaller.htm) | Generated uninstall/self-copy signing; outer signing alone insufficient |
| S22 SDK | Microsoft [SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool) | SHA256/RFC3161, /pa /all /tw, 0/1/2 returns; /tw absence is warning not automatic fatal |
| S23 Client | Microsoft [signing integrations](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations) | EXE/SignTool integration, current package/DLL names, official HTTP TSA command; not executed here |

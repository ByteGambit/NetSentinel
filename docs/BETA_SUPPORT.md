# NetSentinel pilot support

0.1.0 unsigned candidate, schema 019; **not a published release**. Current gate:
[PUBLIC_BETA_ACCEPTANCE.md](PUBLIC_BETA_ACCEPTANCE.md). Test protocol and manual
results: [BETA_PROTOCOL.md](BETA_PROTOCOL.md),
[PUBLIC_BETA_CHECKLIST.md](PUBLIC_BETA_CHECKLIST.md).

## Install and Windows scope

Packaging expects a Windows 10-or-later x64-compatible client. That minimum is
not evidence that every Windows 10/11 edition/build is tested or supported by
its OS vendor. Current native client: **Windows 11 Home x64, build 26200.9457**,
new VMware Workstation VM, fresh standard and Unicode profiles on an existing OS.
Install/repair/restart/export/KEEP checks passed in their recorded historical scope.
The closure candidate reinstall/payload identity, native fixture toast/click and
tray Quit passed; required VPN/meaningful sleep NOT RUN, effective OS-policy BLOCKED,
human layout criterion FAIL (seven other criteria PASS). No pristine OS claim.
Historical NS-096 VM used fresh standard-user and Unicode profiles on an existing
Windows OS, without Python/Npcap; OS build was not recorded. No universal support
claim. ARM64/native non-x64, server editions and other client builds are NOT TESTED.

Use only the owner's approved candidate/channel and independently compare the
candidate SHA256. Normal offline installation is per-user, without elevation or
Python. Program files are under LocalAppData/Programs/NetSentinel; sensitive local
data is under the separate LocalAppData/NetSentinel root. Installer does not add
autostart, services, Npcap, firewall rules or an updater. Start it manually.

Unsigned means there is no authenticated public publisher signature. SHA256
detects a changed file relative to the expected value; it does not authenticate
the owner if the channel/hash is compromised. Windows SmartScreen or Application
Control may warn or block. A prior host actually blocked the unsigned wizard
(4551). Stop if policy blocks it; use an organization-approved distribution route.
No Windows-security bypass is supported. Signing alone is not a safety verdict
or guarantee of no warnings. Broad public release remains NO_GO.

## What works without Npcap

Npcap is an optional external packet-capture driver; NetSentinel does not bundle,
download, install or manage it. Without accessible Npcap, core process/connection
polling and local saved views should work where OS access permits. Passive LAN,
classic DNS, ARP/broadcast/VLAN observation depends on capture. Diagnostics
reports unavailable/degraded states rather than claiming observation is active.
Capture starts only by the separate explicit Devices action; no automatic
capture or UAC. TI and notifications have their own default-OFF settings.

## Review alerts and limitations

Concern score and LOW/MEDIUM/HIGH identify review priority, not probability of
malware. Read contributors, quality, confidence, freshness and limitations;
novel destinations, VPN scope changes and CDN activity can be benign. Baseline
READY means adequate observed coverage, not a trusted application. Use narrow
mark-normal/suppression only after review; it preserves underlying evidence.

Polling can miss short-lived connections; process metadata is not an event log.
There are no per-flow byte totals. Classic DNS cannot universally see DoH/DoT;
many-to-many DNS/IP associations do not prove domain-to-process causality.
Hash/signature/country/reputation are context: signed != safe, unsigned != malicious,
TI HIT != malware and NO_HIT != safe. Incident grouping/order is not causality,
forensic completeness or a complete automatic incident stream: production incident
creation remains an explicit service boundary. No automatic blocking/response.
Desktop TI credential backend is unavailable; optional TI is not a beta requirement.

## Local data and support bundle

Settings -> Storage & Privacy shows local store counts/approximate sizes,
opt-in bounded retention and confirmed scoped purge. Protected/current/reference
and user preference/profile data are explained and may remain. Delete is not
secure erase or guaranteed immediate disk shrink. See [privacy summary](BETA_PRIVACY.md).

Help -> Feedback & Support -> generate full sanitized preview -> inspect ->
Save to a chosen local JSON file -> inspect the saved file. It includes bounded
aggregate/status metadata, not raw history, IP/domain/MAC/full executable paths,
notes, keys, provider responses or config. It is not anonymous or a DB backup.
**Saving does not upload anything.** Sharing is your separate manual action.
Never include real browsing screenshots, raw logs/history, secrets or private
vulnerability details in a public issue.

No dedicated feedback or private security address exists in the checkout. Before
recruiting pilot testers the owner must establish an agreed manual feedback/private
security contact. The UI's explicit Open project page button opens the actual
[project page](https://github.com/ByteGambit/NetSentinel) with no attachment/prefill;
it does not promise that an approved support channel is available there.
Report candidate hash, sanitized environment, scenario, expected/actual behavior,
aggregate metrics and severity through that agreed channel. See protocol blocker
definitions; stop a test after a privacy leak, corruption or policy block.

## Update and uninstall

Updates are manual, with the intended canonical
[project Releases channel](https://github.com/ByteGambit/NetSentinel/releases).
No release or candidate upload is created by NS-099. No automatic check/download
or downgrade is provided. Verify version/source/hash/unsigned policy before a
compatible installer over-install, and preserve a closed local backup if needed.
Do not reset/delete a newer database to force a downgrade. Browser downloads and
OS security verification may make their own network requests; TI consent is separate.

Quit NetSentinel, including a hidden tray session, before repair/uninstall.
Normal X defaults to Quit; opt-in Hide to tray continues monitoring; tray Show
restores, Quit exits. Windows uninstall defaults to **KEEP** local data (silent
uninstall also KEEP). **DELETE** is a separate choice plus destructive confirmation,
restricted to the owned data root. External exports and parent user folders are
preserved. Cancellation before deletion preserves data; partial I/O failure can
leave data. Reinstall after KEEP reuses compatible state; after DELETE starts fresh.

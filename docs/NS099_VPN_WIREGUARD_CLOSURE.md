# NS-099 — Native private WireGuard VPN closure

**VPN PASS (2026-10-08 local / 2026-10-07 UTC). NS-099 COMPLETE; M17 COMPLETE.**
The last required environment scenario was executed on the accepted candidate.
Earlier SoftEther BLOCKED/NOT RUN evidence remains historical; it was not retried.
No NetSentinel production change, installer rebuild, migration, tag or release.
NS-100 NOT STARTED. M18 recommendation: GO FOR PLANNING ONLY; implementation
still requires an explicit response GO and user authorization.

## Candidate and test environment

Starting repository HEAD == fetched origin/main:
`98b2b5a6e973ff5c289c614381ae9aaca3d3f051`; tracked tree clean.
Runtime source `8242868ba79c63ad743c005366ea715b238cf5d0`, unsigned 0.1.0,
`NetSentinel-0.1.0-Setup.exe`, **37,559,481 bytes**, SHA256
`39b14fe844c8aaa150a8b09229e0d63aaaf5ecc98b5bc8c54b419140be7749d9`.
Installed EXE SHA256
`bfa73e87509d6b2762336a9f0cff87026f31271580a188fa10e81005320a89d4`;
fresh VMware MCP payload verification: **1119 files, 0 mismatches**.
AppId `{62E3BFC6-ACAD-4FC3-94D8-46927D015096}`, schema **019→019**.

Client: configured **Windows 11** VMware VM, Home x64 build 26200.9457, Tools
running. NetSentinel runs in interactive Session 1 with a Limited token and a
new isolated LOCALAPPDATA profile. Existing development/history data untouched.
Notifications, scheduled retention, packet capture and reputation remain OFF.
No old Windows 11 x64 (2) VM used. No new pristine-image/other-build claim.

Topology: Windows VM → WireGuard → existing Kali VM → existing VMware NAT →
ordinary outbound HTTPS. Kali Rolling **2026.3**, kernel **7.1.5+kali-amd64**,
Tools **13.0.10**. Linux `wireguard-tools` **1.0.20260223-2**, reported
**v1.0.20260223**, installed through the official distro package manager.
The [official Windows MSI](https://download.wireguard.com/windows-client/)
**1.1.1** was Authenticode **Valid / WireGuard LLC** on host and guest,
3,293,184 bytes, SHA256
`7bfed60ad61b785c914b38b61555a975488e1d3ec472dbfb2fcdf498fca75242`.
MSI install exit 0; normal privileged
[tunnel service CLI](https://git.zx2c4.com/wireguard-windows/about/docs/enterprise.md)
succeeded. NetSentinel itself was not elevated.

Both endpoints use the existing private VMware NAT subnet. The Linux listener
accepts only the test client's private IPv4 source/destination; forwarding/NAT
is limited to the single tunnel client. No router/public inbound forwarding
was created; VMware NAT incoming TCP/UDP mappings were empty. Linux had no
global IPv6 address. Fresh keys and copied profiles were locally restricted;
no key/credential/raw process path is committed. User explicitly authorized
local image credential use for vmrun and this bounded setup/cleanup sudo scope.
Linux needed vmrun fallback because MCP had no configured Linux guest credentials;
Windows operations used VMware MCP. No security/power-policy bypass.

This is an **IPv4 VPN workload**. Client AllowedIPs also routes `::/0` into
the tunnel to avoid IPv6 escape, but no global IPv6 tunnel connectivity is
provided or claimed tested. Public egress IP need not change: both endpoints
ultimately use the same VMware NAT. Routing + handshake + peer transfer +
Linux forwarding/NAT counters establish the real tunnel.

## Actual measurements

All times below are UTC on 2026-10-07. Native monitoring stayed responsive;
same PID **12028**, one monitoring session throughout connect/disconnect.

| Phase / UTC | History rows | Edge rows | Alerts | Incidents | Baseline rows | Main DB bytes |
|---|---:|---:|---:|---:|---:|---:|
| No VPN, 23:20:16 | 388 | 31 | 0 | 0 | 11 | 2,838,528 |
| Connected, 23:24:16 | 442 | 32 | 0 | 0 | 13 | 2,838,528 |
| VPN browser sampling, 23:27:54 | 492 | 56 | 0 | 0 | 13 | 3,059,712 |
| Disconnected + browser, 23:30:16 | 552 | 72 | 0 | 0 | 13 | 3,317,760 |
| Clean Quit / closed DB, 23:36:08 | 597 | 82 | 0 | 0 | 13 | 3,747,840 |
| Restart, 23:37:11 | 663 | 93 | 0 | 0 | 13 | 3,747,840 |
| Restart + browser, 23:38:32 | 690 | 108 | 0 | 0 | 13 | 3,747,840 |

The sampling intervals include normal guest background traffic. History-row
increments are not packet counts or a deduplicated browser-connection count.
VPN sample versus baseline: **+104 history rows, +25 Edge rows**; **13 Edge
history rows** carry the VPN interface and exact local-address-match scope.
Final versus baseline: **+302 history rows, +77 Edge rows**.
Main DB growth **+909,312 bytes**. WAL: 4,161,232 baseline; 0 at clean Quit;
2,101,232 final live sample. WAL size is not logical data growth.

First observed handshake **23:23:46**; later handshake **23:27:52**.
Last endpoint transfer at cleanup: **240,656 bytes received / 2,819,880 sent**
(Linux perspective). Final forwarding counters before endpoint cleanup:
**1454 client-outbound packets / 2276 return packets**, **40 NAT matches**.
The interface existed with its assigned tunnel IPv4 address, IPv4 default
route through WireGuard and DNS **1.1.1.1**. These are real native OS values,
not a synthetic interface-metric change.

Benign browser fixture: fresh isolated InPrivate Edge with loopback-only CDP.
Before VPN, Example Domain completed; the initial launcher opened only one
tab, so no three-site pre-VPN claim. Corrected fixture explicitly opened
**example.org, python.org, wikipedia.org**. All three reached `complete` with
expected titles/URLs during VPN (23:28:16), after disconnect (23:29:45), and
after restart (23:38:11). No login, personal browsing, account consent or TLS
bypass. Native Edge rows independently corroborate monitoring; DOM navigation
alone is not the NetSentinel persistence proof.

## Scope, DNS, risk and burden

Ethernet interface index **9** alone before VPN; VPN index **24** appears
with a second fingerprint during VPN. Unique local-address matches are
`resolved` / `local_address_match`; wildcard/other unmatched observations
remain honestly `unknown`. Historical VPN scope remains readable after
disconnect; it is not falsely rewritten as the current physical Ethernet.
After uninstalling the temporary tunnel service, only Ethernet remained,
normal gateway/default route and original VMware DNS returned. Later benign
traffic and fresh session history continued without a tunnel interface.

Capture unavailable/stopped is represented honestly. DNS history **0** at
every phase; no observed DNS/domain correlation is invented from browser
metadata or OS DNS settings. IPv4 scope resolution is not proof of a physical
adapter, VPN priority, hostname identity or definitive process attribution.
Standard-user Windows process visibility limits still apply.

Alerts **0→0→0**, occurrences **0**, incidents **0→0→0**. Every alert severity
bucket is empty; useful/noise findings **0/0**. No severe benign FP, VPN-only
malware verdict, alert/incident storm or unexplained risk escalation observed.
Persisted assessment revisions at closed DB **377**, final **395**: max stored
score **0**, severity **unknown** for all, invalid JSON **0**. Unknown assessments
are not a safety verdict; enabled capture/reputation detectors are not tested.

Notifications remain OFF. Native expanded Diagnostics before restart showed
**intents 0 / eligible 0**; no new alert or historical alert exists to replay.
Observed unwanted popups **0** in bounded native screens; delivery confirmation
is **UNKNOWN / NOT MEASURED** because Qt supplies no OS delivery telemetry.
Do not reinterpret accepted submission as visible delivery. This OFF VPN
burden case supplements the earlier explicit ON/privacy/click/policy fixtures;
it does not replace their scoped visibility limitations.

Bounded NetSentinel ERROR/CRITICAL log lines **0**, log bytes **0**. Diagnostics:
standard user; monitoring engine **Running**; storage **Available**; history
writer **Running**, queue **0/2048** before restart. Capture unavailable,
DNS/devices/alerts degraded due passive capture limits; reputation/notifications/
retention disabled are optional states, not hidden worker failures. Post-restart
responsive GUI + growing native persisted history establish resumed monitoring;
post-restart internal queue counters were not independently reread.

Every SQLite quick_check **ok**, foreign-key violations **0**, schema **19**;
baseline invalid JSON **0**, capacity loss **0**. All **13 baseline identities
and payloads** survived the clean restart unchanged at the first sample;
last-observed timestamps did not regress. Longest history duration **2720.336295s**
fits the real session time; future-timestamp rows **0**, no fake giant duration.

## Restart, harness corrections and cleanup

The user selected ordinary **File > Quit** because host Computer Use clicks
did not take effect and MCP guest keystrokes returned invalid-parameter.
MCP watcher observed old PID absent and **0 remaining NetSentinel processes**
at **23:36:07.4585042**, then read a healthy checkpointed DB. Shutdown duration
**NOT MEASURED**: click time was not instrumented; watcher waiting time is not
shutdown latency. MCP restarted the same accepted EXE/profile at **23:37:05**,
new PID **8896**, one new expected session (two persisted sessions total).
Persisted counts/baselines remained readable, no alert replay or notification
source replay, and the browser generated new history. Replayed nonempty alert
fixtures retain their earlier policy-test scope.

Earlier during endpoint preparation the idle guest suspended in VMware; it
was resumed with the same PID. This is not new S3 acceptance evidence. A bounded
40-minute helper held temporary display/system execution-state requests, then
cleared them and exited; no permanent power settings changed. An early own
metrics helper timed out and stayed alive. Generic tool launches subsequently
returned DLL_INIT_FAILED; terminating only that known helper restored command
execution. No WireGuard denial appeared in the bounded CodeIntegrity query;
normal client launch then succeeded. Root cause beyond this correlation was
not proven; these harness errors are not counted as product crashes/errors.

Cleanup verified:

- Windows tunnel service **0**, tunnel interfaces **0**, temporary config absent.
- Linux interface/listener removed; test NAT/firewall chains/jumps removed.
- Original Linux rule set was empty. Empty loaded table metadata/default ACCEPT
  policies/counters remained; no added filtering/NAT rules remained. An initial
  bytewise comparison failed for this representation difference, then rule-level
  verification succeeded. No unrelated rule restoration/override was performed.
- Runtime IPv4 forwarding restored **1→0**, original value; no permanent sysctl.
- Endpoint/client keys and all transferred profile copies removed; host temporary
  sudo-input files **0**, guest credential directory removed by each bridge call.
- Owned scheduled tasks **0**, loopback CDP listeners **0**; own fixture browser
  closed normally. Keep-awake helper exit/stop receipt verified.
- Trusted installed WireGuard packages and reusable Linux VM remain. NetSentinel
  PID8896 remains intentionally running on its isolated acceptance profile.

Raw receipts, DB-derived process/scope/baseline records and screenshots stay in
ignored `build/ns099-wireguard-lab/`; only aggregate sanitized evidence is committed.

## Acceptance and release decisions

**PASS:** real private IPv4 tunnel, routed benign browser traffic, honest scope
and DNS limits, no crash/storm or VPN-alone malware/risk escalation, preserved
baseline/storage, normal disconnect recovery, clean restart and monitoring.
No requirement was waived. NS-099 exact TASKS acceptance combines this result
with accepted prior browser/updater/install/upgrade/uninstall/standard-user/
Npcap-missing/privacy/storage/tray cases, native host S3 PASS, notification policy
and ON fixtures, human UX8/8 and frozen-runtime offline quality checks. Prior
candidate/evaluator scopes and optional NOT RUN limitations remain explicit.

| Decision | Result |
|---|---|
| NS-099 / M17 | COMPLETE / COMPLETE |
| Limited unsigned pilot | CONDITIONAL_GO; owner audience/license/channel/contact and explicit distribution authorization still required under NS-097 |
| Broad public release | NO_GO; unsigned candidate, signer/protected signing/distribution gates unresolved |
| M18 | GO FOR PLANNING ONLY; no implementation/response authorization inferred |
| NS-100 / tag / release | NOT STARTED / NONE / NONE |

Docs-only delivery: no installer rebuild or full runtime rerun solely for this
evidence. Frozen runtime retains targeted123, full offline3833/8 deselected,
Ruff/configured mypy36/direct mypy6 PASS in their recorded scope. Final
diff/privacy and normal main commit/push are recorded in the delivery report.

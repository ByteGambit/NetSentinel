# NS-099 — VPN environment attempt (2026-10-07)

**VPN acceptance: NOT RUN. Environment provisioning: BLOCKED.** No tunnel was
established, so none of the VPN workload or recovery criteria is marked PASS.
NS-099 remains INCOMPLETE; M17 IN PROGRESS; limited pilot and broad release NO_GO;
M18 DEFER; NS-100 NOT STARTED. Native sleep was not attempted in this turn.
Human UX and notification-policy PASS keep their previously recorded scope.

## Candidate and environment

At the start and after a normal `git fetch origin main`, repository HEAD and
origin/main were `b14f74ed245e96104d7778c590ed6424e78c9d8b`; tracked working tree was
clean. Runtime source remains `8242868ba79c63ad743c005366ea715b238cf5d0`.
No NetSentinel production, test, packaging, dependency or schema files changed.
The current unpublished unsigned installer was not rebuilt unnecessarily:

| Field | Observed value |
|---|---|
| Installer | NetSentinel-0.1.0-Setup.exe, version 0.1.0 |
| Size / freshly checked SHA256 | 37,559,481 bytes / `39b14fe844c8aaa150a8b09229e0d63aaaf5ecc98b5bc8c54b419140be7749d9` |
| Installed EXE, freshly checked through VMware MCP | `bfa73e87509d6b2762336a9f0cff87026f31271580a188fa10e81005320a89d4` |
| AppId / schema | `{62E3BFC6-ACAD-4FC3-94D8-46927D015096}` / 019→019, no migration |
| Prior installed payload verification | 1119 files, 0 mismatches in notification-policy closure; full payload not rechecked here |
| Native client | Configured **Windows 11** VM, Windows 11 Home build 26200; VMware Tools running |
| Guest inventory | One up Ethernet adapter; 0 per-user and 0 all-user VPN profiles; no running NetSentinel process |
| Host inventory | Consumer Home edition, OS build 26200; private VMware VMnet1/VMnet8 adapters up; no detected WireGuard/OpenVPN installation; WSL not installed |
| Other endpoint | VMware MCP inventory reported only the configured Windows 11 VM; no ready second VPN endpoint was found |

The old Windows 11 x64 (2) VM was not used. MCP start returned a timeout, but
independent MCP status, Tools and actual guest commands established that the
correct VM was running and reachable; the timeout is not VPN or app evidence.
Raw local addresses and profile paths are kept out of committed evidence.

## Smallest attempted private tunnel

The intended topology was a temporary host user-mode SoftEther SSTP server on
the private VMware network, the guest's built-in Windows SSTP client, and
user-mode SecureNAT for benign HTTPS. No new guest VPN driver or host service
was needed for this proposed topology. This remained a proposal, not a working
or validated tunnel.

The [official user-mode manual](https://www.softether.org/4-docs/1-manual/3._SoftEther_VPN_Server_Manual/3.2_Operating_Modes)
and [official release assets](https://github.com/SoftEtherVPN/SoftEtherVPN/releases/expanded_assets/5.2.5188)
were consulted. The server package `softether-vpnserver_vpnbridge-5.02.5187.x64.exe`
from release 5.2.5188 was downloaded over HTTPS into an ignored local lab folder.
Its SHA256 exactly matched the release's
`df7f40d9fbdac5496ac214b5543f6e4742df55b69e1db848a1ce6c3cf36bbf81`.
The extracted server SHA256 was
`b800cfe7bffd8a004066025bc6a1bf6b32beaf7adade478e7e8b0e886ef5d1ff`;
Authenticode inspection reported NotSigned. Matching the download hash proves
integrity relative to that release listing, not that Windows policy permits it.

Files were extracted by reading DATAFILE resources and their documented source
compression format; the installer itself was never executed. The planned
bootstrap configuration contained only loopback IPv4 port 44443, with DDNS,
NAT traversal, IPv6 listeners, keep-connect, Azure relay, VPN-over-DNS/ICMP and
local bridging disabled. No listener on the private VMware address was launched.

An initial launch request was rejected by automatic approval review because
configuration loading/binding had not yet been established. No process ran.
Read-only checks of official
[Server.c](https://github.com/SoftEtherVPN/SoftEtherVPN/blob/5.2.5188/src/Cedar/Server.c)
and [FileIO.c](https://github.com/SoftEtherVPN/SoftEtherVPN/blob/5.2.5188/src/Mayaqua/FileIO.c)
established the adjacent `vpn_server.config` lookup; exact binary and restrictive
configuration were checked before the reviewed retry was allowed.

At **09:16:14 UTC**, Windows prevented process creation with:
`An Application Control policy has blocked this file. Malicious binary reputation.`
This is the OS refusal text, not an independent finding that the official package
is malware. The server never started. Application Control/Defender policy was
not changed; no exclusion, unblock, re-sign, alternate execution of the blocked
binary, TLS bypass or firewall relaxation was attempted.

The no-service/no-driver host route therefore could not proceed under current
policy. No ready alternative endpoint was found. Further options would require
provisioning a second server VM/OS or installing a different VPN implementation
and network drivers. Those are larger system changes than this bounded attempt;
their feasibility was not tested and they are not claimed impossible. Work stopped
at the user's explicit environment-limit condition rather than weakening security
or treating a synthetic interface as a real VPN.

## Acceptance measurements and cleanup

| VPN criterion / measurement | Result |
|---|---|
| Baseline/browser → connect → browser → disconnect/recovery | NOT RUN |
| Network scope / history / DNS/context / attribution | NOT RUN |
| Baseline integrity / crash / restart / persistence | NOT RUN |
| Alerts / incidents / notifications / application errors | **NOT MEASURED / NOT MEASURED / NOT MEASURED / NOT MEASURED** |
| Benign VPN FP / notification storm conclusion | NOT RUN; no zero-count inference |
| Environment failure | 1 OS-blocked server process-creation attempt; not a NetSentinel error count |
| Host verification at 09:17:09 UTC | 0 server processes, 0 SoftEther services, 0 lab port listeners, 0 lab-named firewall rules; existing RRAS stopped/RasMan running |
| Guest verification at 09:17:54 UTC | 0 server processes, 0 user/all-user VPN profiles, 0 NetSentinel processes; installed EXE hash unchanged |

No tunnel credentials, certificates, VPN profiles, routes, services, drivers or
firewall rules were created. No traffic/capture/alert injection or public service
was introduced. Downloaded files, configuration and fixed launch/cleanup receipts
remain in ignored `build/ns099-vpn-lab/`; these are inert and uncommitted. Only
preflight JSON receipts were written inside the VM. The VM remains running.

The exact TASKS acceptance wording is unchanged. This environment result closes
neither the VPN gate nor NS-099, and changes no release decision. Docs-only
consistency, diff and bounded privacy/secret checks accompany this record; earlier
full pytest/Ruff/mypy results remain historical and are not relabelled as new runs.
No tag or release was created.

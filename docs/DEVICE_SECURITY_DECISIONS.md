# NS-042 device identity decision table

This table describes the current NS-040 rules used by the NS-042 synthetic
scenario tests. It applies only to a selected network fingerprint and an
explicitly saved, active user profile. An observed device or binding is never
an expectation by itself. “Trusted” means designated by the user, not
authenticated or known safe. A signal is an identity discrepancy to review,
not proof of spoofing or compromise.

| Observation and saved context | Signal | Rule | Severity / confidence | Reason when silent or confidence basis |
|---|---|---|---|---|
| Unprofiled device at an IP with no unique expected owner | No | — | — | No user expectation to compare |
| Empty expected MAC list, including an observed member | No MAC signal | — | — | Empty MAC set is not a mismatch |
| Empty expected IP list with an expected MAC | No IP signal | — | — | Churn requires explicit expected IPs |
| Expected MAC and expected IP | No | — | — | Saved identity matches |
| One of several expected MACs, regardless of list order or case at input | No | — | — | Domain canonicalizes and sorts identities |
| Expected locally administered MAC | No | — | — | Explicit expectation matches |
| Expected MAC at one new DHCP IP | No | — | — | One unexpected IP is below the churn threshold |
| Expected MAC at two distinct unexpected IPs in five minutes | No | — | — | Fewer than three distinct IPs |
| Expected MAC at three distinct unexpected IPs in five minutes | Yes | `device_ip_churn` | low / moderate | Three distinct recent unexpected IPs |
| Duplicate observation of the same unexpected IP | No extra distinct IP | — | — | Binding identity and distinct-IP set are unchanged |
| Expected MAC at expected IP after unexpected IPs | No new churn | — | — | Current IP is expected |
| Profile member with unexpected MAC, expected or unexpected IP | Yes | `device_mac_identity_change` | low / low by default | Single passive discrepancy |
| Unexpected MAC at a uniquely expected IP, without membership | Yes | `device_mac_identity_change` | low / low by default | Saved IP identifies one profile |
| MAC discrepancy with an expected MAC binding at the same IP in the prior two minutes, on a trusted profile | Yes | `device_mac_identity_change` | medium / moderate | Recent expected binding corroborates discrepancy |
| Same corroborated discrepancy on unknown or untrusted profile | Yes | `device_mac_identity_change` | low / moderate | Trust is user state, not detector proof |
| New locally administered MAC, including corroborated trusted context | Yes if normal mismatch conditions hold | `device_mac_identity_change` | low / low or moderate | Local bit never raises severity; corroboration can raise confidence |
| Expected MAC appears at an IP uniquely expected by another profile on the same network | Yes | `device_identity_context_mismatch` | low / low | Context conflict; DHCP reassignment may explain it |
| Expected IP is shared by multiple profiles | No cross-profile signal from IP ownership alone | — | — | Ambiguous owner |
| Observation from another network fingerprint | No comparison with this profile | — | — | Network scopes are isolated |
| Observation older than snapshot time minus five minutes | No | — | — | Stale evidence; exact boundary is included |
| Registry device/binding has a newer `last_seen` than observation | No | — | — | Out-of-order packet cannot create a new signal |
| Observation at or before profile `updated_at` | No | — | — | An old packet cannot challenge a newer user edit |
| User adds the observed MAC to expectations, then snapshot refreshes | No subsequent MAC mismatch | — | — | Explicit user edit invalidates detector signal state |

For a signal, the SHA-256 fingerprint covers rule ID, network fingerprint,
profile UUID and the rule's unexpected identity: observed MAC for MAC mismatch,
MAC plus IP for context mismatch, and the constant `churn` for IP churn.
Timestamp, label, note, trust and occurrence number do not enter it. NS-028
maps this fingerprint to a deterministic alert UUID and owns deduplication,
acknowledgement, resolution and reopening. Duplicate or older timestamps do not
increase occurrence count or move `last_seen` backwards. A later observation
after restart can update the same row; a resolved alert reopens when the detector
emits the same issue again. Within one running detector instance, a successfully
persisted identity signal is suppressed until its state is invalidated or evicted.

The five-minute churn window includes its exact boundary. Only bindings of an
expected MAC at unexpected IPs, after the latest profile edit, count. The
repository supplies bounded recent bindings and the detector keeps at most
20 per profile plus 512 signal states. Profile, membership and binding reads
are bounded per refresh. These are heuristic limits, not a guarantee of full
network visibility.

The scenario matrix uses synthetic ARP frames, fake capture and clock, temporary
SQLite, and offscreen Qt. No live capture, Npcap, administrator rights, external
network, injected packet, raw ARP frame or payload storage is involved.

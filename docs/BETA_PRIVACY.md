# NetSentinel pilot privacy summary

**NetSentinel does not upload your network history by default.** Connection,
process/path, local network/DNS metadata, alerts, risk/baselines, preferences and
incidents stay in the user's local data root. Metadata can reveal activity;
local storage is not promised encrypted, anonymous, tamper-proof or forensically
complete. Raw packet payload is not retained as a default history feature.

Capture is separately and explicitly started, subject to Npcap/OS access. The
guide's Finish/Skip grants no capture, TI or notification permission. Optional
TI is default disabled; provider/type consent and explicit selected-public-IP
lookup are separate. A lookup can reveal that selected IP and your source IP/
timing to the provider; provider retention is not assumed safe. No bulk history,
files, executable paths, notes or API keys are sent. Desktop credential backend
is currently unavailable. A reputation response is supporting context, not a verdict.

Notifications are default OFF. Explicit enable permits generic severity-only
previews; OS may display them to others or on the lock screen. They omit IP/domain/
path/MAC/user/evidence. Submission does not prove OS display; click reads details
inside the running app. Restart and enable do not replay historical alerts.

Retention is opt-in, bounded and subject to active/reference/user-state protection.
Scoped purge requires confirmation; cancellation can occur between committed
chunks. Uninstall defaults KEEP; DELETE requires separate confirmation of the
owned root. Exported files outside that root remain yours to manage. SQLite/WAL
and filesystem remnants mean deletion is not secure erase or immediate shrink.

Help -> Feedback & Support uses **support-export-v1 / allowlist-v1**: full sanitized
preview before local Save, <=100 records and <=64KiB. Storage/retention aggregates
and limited alert/incident status summaries are included. Raw history, IP/domain/
MAC/hash/path, notes, credentials, config and provider response bodies are excluded.
Inspect the file before separately sharing; it is not anonymous or a backup.
There is no automatic support/crash upload or telemetry client. No dedicated
feedback/private-security endpoint exists; the owner must establish a manual route.

Updates are manual; app automatic update requests are zero. Explicit browser
navigation to the project/channel exposes ordinary browser/source-IP metadata
to GitHub/CDN; OS trust/security checks can separately contact their services.
No certificate/key acquisition, auto response, automatic elevation, driver
download or default external reputation request is introduced by NS-099.
See [support](BETA_SUPPORT.md), [security](SECURITY.md) and
[distribution policy](SIGNING_UPDATE_DISTRIBUTION.md).

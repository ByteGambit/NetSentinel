# NS-061 — Process/connection event-source spike

**Decision: NO-GO for a production event collector in the current NetSentinel product.**
**Recommended architecture now: POLLING ONLY.** Date: 2026-10-01. This is a
successful research result under the NS-061 acceptance criteria, not a claim
that Windows lacks these events. An elevated, separately authorized lab study
could revisit a **hybrid** design; it is not an implementation task or an
automatic consequence of this spike.

## 1. Question, scope, and evidence levels

Can process and connection ETW events improve lifecycle accuracy enough to
justify their privilege, loss, startup, privacy, and maintenance costs beside
the existing standard-user polling path? NS-056 is the dependency. This spike
does not add a service, command-line collection, persistence, production event
consumer, or domain contract. Here **schema-supported** means documented by
Microsoft, not observed on this host; **live-verified** means an actual local
test. A denied session start cannot verify the event payload or reliability.

## 2. Current polling architecture

`bootstrap.create_desktop_engine` composes `PsutilConnectionCollector`,
`ProcessMetadataEnricher(PsutilProcessMetadataResolver)`,
`ConnectionTrackingService`, `EventDispatcher`, and a bounded SQLite history
writer. The default interval is 1 second. The collector calls system-wide
`psutil.net_connections(kind="inet")`, normalizes TCP/UDP IPv4/IPv6 rows, and
reports malformed rows as `REDUCED`; collection failure is `FAILED`.
Per-PID metadata lookup adds name, executable path, create time, and a
best-effort parent snapshot. Access denied and exit races have typed partial
results. The tracker deduplicates a bounded 4096 active keys; keys include
`ProcessIdentity(pid, create_time)` when available. It gives each monitoring
run a session UUID and each observed lifecycle a separate UUID. The first
complete snapshot is `INITIAL`, not a real connect event. Later complete
snapshots can infer `OBSERVED` appearance and `NOT_OBSERVED` disappearance;
reduced/failed rounds do not invent closes. History checkpoints are bounded;
restart reconciliation marks gaps rather than fabricating close times. Health,
capability, config, and diagnostics are typed and sanitized; the synchronous
dispatcher is not a durable journal. Shutdown and writer drain are bounded.

This is strong for current socket state, accessible process create time,
startup coverage, low privilege, and repair after a missed sample. It misses
short processes/sockets and failed connection attempts; appearance and
disappearance times are poll times, not kernel start/FIN/RST times. UDP socket
rows have `NONE` state and are not per-peer transaction lifecycles. Parent
metadata is an observed snapshot, not historical lineage. No per-flow byte
claim is made (NS-059 NO-GO).

## 3. Candidate event sources and official references

| Source | Documented role | Decision-relevant limit |
|---|---|---|
| Classic kernel `Process` MOF, GUID `{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}` | Start/end/rundown with `EVENT_TRACE_FLAG_PROCESS` | System logger privilege; versioned MOF; no portable create-time field |
| `SystemProcessProviderGuid` `{151f55dc-467d-471f-83b5-5f889d46ff66}` | Newer `SYSTEM_PROCESS_KW_GENERAL` mapping to process flag | Requires system logger mode; generated events remain classic system-trace events |
| Classic kernel `TcpIp`, GUID `{9a280ac0-c8e0-11d1-84e2-00c04fb998a2}` | TCP v4/v6 connect, accept, disconnect, send/receive, retransmit, reconnect, fail | System logger privilege; no documented complete flow-state/recovery guarantee |
| Classic kernel `UdpIp`, GUID `{bf3a50c5-a9c9-4988-a005-2df0b7c80f80}` | UDP v4/v6 send/receive and fail | No documented UDP socket create/close events |
| `SystemIoProviderGuid` `{3d5c43e3-0f1c-4202-b817-174c0070dc79}` | `SYSTEM_IO_KW_NETWORK` maps to `EVENT_TRACE_FLAG_NETWORK_TCPIP` | System logger mode; keyword enablement is not proof of access |

Primary references: Microsoft [Process class](https://learn.microsoft.com/en-us/windows/win32/etw/process),
[Process v1 schema](https://learn.microsoft.com/en-us/windows/win32/etw/process-v1-typegroup1),
[Process v2 schema](https://learn.microsoft.com/en-us/windows/win32/etw/process-v2-typegroup1),
[Process v3 schema](https://learn.microsoft.com/en-us/windows/win32/etw/process-typegroup1),
[System Providers](https://learn.microsoft.com/en-us/windows/win32/etw/system-providers),
[TcpIp class](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip),
[TCP v4 connect/accept](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip-typegroup2),
[TCP v4 disconnect](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip-typegroup1),
[TCP v6 connect/accept](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip-typegroup4),
[TCP v6 disconnect](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip-typegroup3),
[TCP fail](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip-fail),
[UdpIp class](https://learn.microsoft.com/en-us/windows/win32/etw/udpip),
[UDP v4](https://learn.microsoft.com/en-us/windows/win32/etw/udpip-typegroup1),
[UDP v6](https://learn.microsoft.com/en-us/windows/win32/etw/udpip-typegroup2),
[StartTrace](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracea),
[system logger configuration](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session),
[session control](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session),
[loss counters](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties),
and [ETW overview](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing).
The `Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-Kernel-Network`,
and `Microsoft-Windows-TCPIP` provider names found by local `logman` are
separate enablement surfaces; their presence does not establish the classic
MOF events above are readable through a normal session.

## 4. Process ETW schema, start, end, and rundown

The classic process event **type values** are 1 Start, 2 End, 3 DCStart,
4 DCEnd; v2/v3 also list 39 Defunct. These are classic MOF type values,
not a universal manifest Event ID contract. The provider's event version and
MOF class must be matched when decoding; v1 lacks `UniqueProcessKey` and
command line, v2 adds those fields, and v3 has a different layout including
`DirectoryTableBase`. The common payload has `ProcessId`, `ParentId`,
`SessionId`, `ExitStatus`, and `ImageFileName`; image name is sensitive and
schema presence is not an availability guarantee for each event. `UserSID`
and command line are intentionally outside any proposed NetSentinel boundary.
The event header timestamp records trace event time; it is not a documented
process creation-time value. DCStart/DCEnd enumerate currently running
processes at session start/end, including idle/system, so their header time
must never become a process create time. `ExitStatus` exists in the schema,
but a consumer should use it only for a verified End and should not infer a
status from missing End. Microsoft warns that start events can be logged in
the parent's thread context; the **payload PID**, not header PID, identifies
the created process.

Rundown can cover pre-existing processes **if** the proper kernel session
starts and those events are delivered. It was not live-verified here. A
snapshot remains necessary for accessible create time/metadata and to repair
lost or missed rundown. Duplicate DCStart/Start/snapshot observations must be
merged on verified instance evidence; PID alone is inadequate. A lost
DCStart leaves existing processes unknown until snapshot. There is no safe
conclusion that a process remains alive merely because an End did not arrive:
session late start, application downtime, buffer loss, privilege failure,
consumer crash, and delayed delivery all defeat that inference. A process
crash can produce a kernel end event while collection is healthy, but this
host did not test it. PID reuse can occur before delayed End delivery.

## 5. Parent PID, process identity, and PID reuse

Start's `ParentId` is better historical evidence than a later `ppid()`
lookup, but **ParentId is not a verified `ParentProcessIdentity`**. Microsoft
explicitly says parent may have exited or the PID may already refer to a
different process. A future design may retain provenance such as
`OBSERVED_AT_PROCESS_START` with event timestamp; it may attach a parent
instance only if an earlier verified parent start/create time or a consistent
live resolver check exists. Otherwise parent identity remains unknown. The
existing `ProcessIdentity(pid, create_time)` and NS-053 conservative parent
status should remain intact.

The v2/v3 `UniqueProcessKey` is documented as a kernel process-object
**address**, not a globally permanent ID. It may help correlate Start/End
within one trace and disambiguate PID reuse while the object exists, but
pointer/address reuse and boot/session scope are not specified in the cited
schema. Never persist it as a portable UUID or replace `ProcessIdentity` with
it. A live resolver's create time should be checked against the event-time
candidate; if the process already exited, preserve an unverified instance.
ETW header timestamp may be retained as event provenance, not silently
substituted for psutil create time. Start/End with the same PID but conflicting
start evidence must be separate candidates; delayed old End must not close
the newer instance. Without a matching key/create time, the safe result is
ambiguous.

## 6. TCP/IP ETW schema and lifecycle

The classic TCP provider documents IPv4 type 12 Connect, 15 Accept, 13
Disconnect, 10 Send, 11 Receive, 14 Retransmit, 16 Reconnect, and 17 Fail;
IPv6 equivalents are 28 Connect, 31 Accept, 29 Disconnect, 26 Send, 27
Receive, 30 Retransmit, 32 Reconnect. The v2 connect/accept groups include
payload `PID`, source/destination address and port, TCP options/window data,
`seqnum`, and pointer-qualified `connid`; disconnect/receive/reconnect groups
include the same core endpoints/PID/connid. `size` is packet size, not a
NetSentinel per-flow byte contract. The provider documentation says to use
payload PID because network events may be logged by separate threads. These
MOF types do not document a TCP state field, a universal SYN-to-established
transition, a socket owner create time, or a complete close guarantee.

Connect vs Accept could improve outbound vs inbound provenance for events
actually observed, unlike current polling, which generally has no direction
field. It must not label a late-attached established snapshot as definitely
inbound/outbound. A disconnect is stronger evidence than `NOT_OBSERVED`, but
late/lost disconnect or process exit remains a gap. Both IPv4 and IPv6
schemas exist; this host did **not** verify live ETW loopback delivery,
address/port byte order, IPv6 scope handling, or connect/accept/disconnect
pairing. The generic Fail (17) schema contains only `Proto` address family
and `FailureCode` (resource/address conditions), with no PID, endpoint tuple,
or documented refused-connect status. Reconnect is described as retry after
a failed attempt, but alone does not establish every short failed `connect()`
attempt, its endpoint, and error code. A localhost `ECONNREFUSED` test is
therefore **not verified** as an ETW lifecycle event.

`connid` is documented as an event correlation identifier and has a pointer
qualifier. The cited pages do **not** specify lifetime uniqueness, boot-wide
uniqueness, reuse behavior, equality across v4/v6, or a durable mapping to
psutil rows. Candidate matching would need provider/version, address family,
endpoints, payload PID, verified process instance, time window, and
start/end evidence. It must never be copied directly into NS-056's
`ConnectionLifecycleId` UUID. Connect/disconnect pairing is schema-plausible
through `connid`, not live-verified here; collision/reuse must stay possible.

## 7. UDP and existing socket rows

The UDP provider documents v4 type 10 Send/11 Receive and v6 26 Send/27
Receive with payload PID, source/destination endpoint, size, sequence, and
`connid`; type 17 Fail is listed. It does **not** document UDP socket
open/close or a persistent peer lifecycle. A datagram event is a point
observation. A psutil UDP row is an observed local socket (possibly bound,
connected, or wildcard), not one datagram or guaranteed remote peer.
Several peers may share one socket. `connid` must not imply a durable UDP
conversation. Reconciliation may annotate a unique currently observed socket
with datagram evidence, but must not convert packet activity into a TCP-like
open/close or history lifecycle. No UDP event consumer was run.

## 8. Privilege and controlled local measurements

Host: Windows `10.0.26200.0`, `Berke\CodexSandboxOffline`, medium integrity
`S-1-16-8192`, no elevated/admin shell. `logman query providers` listed the
three provider names above. Each trial used a fresh `NS061-*` research name,
temporary `.etl`, 1 MB maximum file, 64 KB buffers, 2–4 buffers, and a
`finally` branch that would stop **only a session whose start returned
success**. All three `logman start` attempts returned signed
`-2147024891` (`0x80070005`, access denied). No session was created and no
ETL file remained. No automatic elevation or existing-session stop occurred.

| Source/session | Standard user on this host | Administrator / elevated admin | Service / kernel |
|---|---|---|---|
| Classic process system logger | NOT TESTED end-to-end; related `Kernel-Process` logman session denied | NOT EXECUTED; Microsoft documents privileged control, exact build/payload not measured | No service created; kernel system provider, not a user-mode driver requirement |
| Classic TCP/UDP system logger | NOT TESTED end-to-end; related `Kernel-Network` and `TCPIP` logman sessions denied | NOT EXECUTED; exact build/payload not measured | No service created; system logger mode required for system providers |
| NetSentinel psutil snapshot | Local own-process/socket control succeeded | NOT EXECUTED | No service/driver required |

Microsoft's `StartTrace` documentation allows session control for admins,
Performance Log Users, and certain built-in service accounts; NT Kernel
Logger control is narrower (admin/LocalSystem). A standard medium-integrity
token **alone** is not a universal ETW permission result: group membership,
session/provider ACL, logger mode, and the destination path matter. This
specific standard-user token could not start the attempted sessions. A
manifest-provider access test does not prove classic system logger access.
No admin result is claimed. NetSentinel must never auto-elevate or silently
modify groups/ACLs.

Controlled localhost/own-child polling probe (inline Python through the
repo venv, 2.37 s, no external traffic) observed: child parent PID and create
time available; child exit verified; a very short child exited; one own
`ESTABLISHED` row on IPv4 loopback and one on IPv6 loopback while sockets
were open; closed-port `connect_ex` failed in both families; UDP IPv4 one-byte
send/receive succeeded and its bound row was visible. These are **polling
controls**, not ETW event captures, direction proof, or reliability samples.
Provider event count, loss, CPU, memory, buffer pressure, decode time,
startup rundown, stale-session recovery, and shutdown latency are **NOT
TESTED**. A denied start cannot give a meaningful zero-loss or performance
result. There was no high-volume test or flood.

Live test matrix: process start/end, parent/child, very short child, TCP v4/v6
connect/accept/disconnect and failed localhost connect, UDP v4 send/receive
were executed only as own-process/psutil controls; **all corresponding ETW
event observations were NOT EXECUTED after session denial**. Existing-process
rundown, loss pressure, elevated/admin run, and a live successful ETW shutdown
were NOT EXECUTED. Failed-start cleanup was observed (no owned session/file).

The exact ETW start invocations were `logman start $name -ets -p
'Microsoft-Windows-Kernel-Process' 0x10 5 -o $file -max 1 -nb 2 4 -bs 64`,
then the same command with `Microsoft-Windows-Kernel-Network` and
`Microsoft-Windows-TCPIP`. In each trial `$name` was respectively prefixed
`NS061-Process-` or `NS061-Net-` plus a fresh research GUID, and `$file` was
`Join-Path $env:TEMP ($name + '.etl')`. The guarded cleanup was
`if ($started) { logman stop $name -ets }` followed by deletion of that
trial's own `$file` if present. `$started` was set only on start exit 0;
all three starts returned access denied, so **no stop command executed**.
The polling control ran as an inline, bounded Python stdin program through
`.\.venv\Scripts\python.exe -`; it used only own child processes and
`127.0.0.1`/`::1` temporary sockets, and printed aggregate booleans/counts.

## 9. Session ownership, startup race, shutdown, and loss

A future production design would need **one descriptive, deterministic
NetSentinel-owned session identity**, scoped enough to avoid another user or
installation's name, with a recorded owner/session GUID and start handle.
Microsoft discourages random names and accumulating parallel sessions.
`ERROR_ALREADY_EXISTS` is a collision, not ownership proof. On restart,
query identity/configuration and independently verify ownership before any
stop; if verification is unavailable, report degraded capability rather than
stopping another product's session. A crash can leave an active trace session
and provider enabled until stopped/reboot; do not adopt solely by name.
Never stop or reconfigure NT Kernel Logger or any existing system logger.
Use bounded buffers, limited keywords, loss queries, single owner, and a
bounded consumer queue; default collection should not start silently.

For a future hybrid, start the **owned** session and consumer first, then
capture a complete process/socket snapshot and process rundown while
buffering events with a fixed capacity. Record a startup watermark and
reconcile snapshot/rundown/events using verified instance evidence. A
snapshot-before-ETW sequence creates an unobserved gap; ETW-before-snapshot
creates duplicates but can be deduplicated. Neither eliminates lost events,
unknown create times, or an event emitted before the session actually became
effective. Treat the first complete snapshot as `INITIAL`; don't call a
DCStart a new process or a snapshot socket a TCP connect. If startup buffer
or rundown is incomplete, mark the interval reduced/unknown and run another
complete polling snapshot. Do not manufacture closes for pre-session flows.

Shutdown concept: stop accepting new application work, stop the producer
under verified ownership, drain consumer buffers/queue within a timeout,
query final loss counters, then close trace/owned session and report any
timeout or uncertain drain. Exact API ordering must account for ETW's note
to disable providers before stopping a session. The actual code must never
stop an unowned session. No successful ETW shutdown was tested here.

`EVENT_TRACE_PROPERTIES` exposes `EventsLost`, `LogBuffersLost`, and
`RealTimeBuffersLost`; `ControlTrace(QUERY)` can read running statistics.
Loss can arise from full buffers, a slow/missing real-time consumer, file
I/O, or oversized events. Counters show that *some* events were lost, not
which process/flow or precise missing interval. A generic per-flow sequence
number/replay service is not documented for these providers; `seqnum` in
TCP/UDP MOF is transport data, not an ETW delivery sequence. Consumer queue
drops must be counted separately. On loss, event-derived lifecycle evidence
becomes `LOSS_DETECTED`/unverified until a fresh complete polling snapshot;
even that snapshot cannot reconstruct a short flow that began and ended in
the gap. Process End absence is never liveness proof. Existing NS-056
`REDUCED`/`FAILED` round semantics and NS-058 monitoring gaps should remain
meaningful; do not relabel an incomplete ETW interval `COMPLETE` merely
because polling later repaired current state.

## 10. Ordering, reconciliation, quality, and privacy

`ProcessTrace` can deliver multiple trace streams in timestamp order, but
provider emission, buffer delivery, process metadata lookup, and application
dispatch are distinct moments. There is no cited causal guarantee that
process Start arrives before TCP Connect, or process End before/after TCP
Disconnect. A single logger clock choice improves timestamp comparison;
separate sessions or a wall-clock conversion need explicit clock metadata.
Arrival order must not be used as historical causality. Process exit can
precede delayed socket-close delivery; a PID can be reused meanwhile.
Keep event time, local receive time, source/version, and correlation status
separate; use bounded reordering and an unknown state when evidence conflicts.

Future conceptual boundary, **not implemented**: infrastructure owns native
session/TDH/MOF decoding and drops raw payload; an application port accepts
small typed `PROCESS_START`, `PROCESS_END`, `TCP_CONNECT`, `TCP_ACCEPT`,
`TCP_DISCONNECT`, `UDP_DATAGRAM`, `LOSS` evidence with source, event timestamp,
observed timestamp, process/flow candidate identity, and field availability.
`POLL_SNAPSHOT`, `ETW_EVENT`, `ETW_RUNDOWN`, `RECONCILED` provenance can be
tracked separately from NS-056's polling round quality. A candidate may be
`UNVERIFIED` until matching process create time/tuple/connid evidence is
unique. `COMPLETE`, `REDUCED`, `FAILED` remain round-level states;
`LOSS_DETECTED` is a source-health reason, not an invented replacement for
the existing enum. ETW OPEN evidence should not automatically emit an
NS-056 `ConnectionOpened` with a new lifecycle UUID; otherwise one socket
can be double-counted by event and poll. Polling remains authority for
current active state and recovery in any future hybrid; ETW supplies faster
time/direction evidence only where corroborated.

Image/path, parent relationship, endpoint, and event timing reveal personal
behavior. Command line may contain passwords, tokens, and secrets: it is
**out of scope for collection and persistence** even when a MOF version
lists it. Do not pass raw ETW payload, UserSID, process-object pointer,
raw path/name, or raw exception text into portable events/diagnostics.
Normalize, bound, and sanitize fields at the infrastructure boundary;
default telemetry remains local. No raw trace file was retained.

## 11. Capability matrix

`SUPPORTED` = documented schema/API or current polling behavior, **not live
ETW verification**. `PARTIAL` = incomplete semantic/coverage guarantee;
`UNKNOWN` = cited source does not settle it; `NOT SUPPORTED` = absent from
this source/contract; `NOT TESTED` = live measurement unavailable. TCP/IP ETW
column includes UDP IP events where indicated.

| Capability | psutil polling | Process ETW | TCP/IP ETW |
|---|---|---|---|
| Process start | NOT SUPPORTED (first seen only) | SUPPORTED (type 1) | NOT SUPPORTED |
| Process end | PARTIAL (later absence) | SUPPORTED (type 2, loss possible) | NOT SUPPORTED |
| Existing-process startup coverage | PARTIAL (only sockets' PIDs) | PARTIAL (DCStart; delivery untested) | NOT SUPPORTED |
| Parent PID | PARTIAL (later snapshot) | SUPPORTED (start payload) | NOT SUPPORTED |
| Verified process instance | PARTIAL (PID + create time) | PARTIAL (PID/key; create time absent) | NOT SUPPORTED |
| Executable/image name | PARTIAL (access/race) | PARTIAL (schema field, availability untested) | NOT SUPPORTED |
| Process create time | PARTIAL (psutil lookup) | NOT SUPPORTED (no exact payload field) | NOT SUPPORTED |
| PID reuse protection | PARTIAL (if create time known) | PARTIAL (key/timing, unverified scope) | PARTIAL (requires process join) |
| TCP connect | PARTIAL (later observed socket) | NOT SUPPORTED | PARTIAL (type 12/28; delivery untested) |
| TCP accept | PARTIAL (later observed socket) | NOT SUPPORTED | PARTIAL (type 15/31; delivery untested) |
| TCP disconnect | PARTIAL (later absence) | NOT SUPPORTED | PARTIAL (type 13/29; loss possible) |
| Failed connect | NOT SUPPORTED (no surviving row) | NOT SUPPORTED | UNKNOWN (Fail lacks tuple/PID; reconnect is retry) |
| UDP send/receive | NOT SUPPORTED | NOT SUPPORTED | PARTIAL (v4/v6 datagram events) |
| UDP socket lifecycle | PARTIAL (observed bound socket) | NOT SUPPORTED | NOT SUPPORTED (no open/close) |
| IPv4 | SUPPORTED | NOT SUPPORTED (process has no IP family) | PARTIAL (schema; live ETW untested) |
| IPv6 | SUPPORTED | NOT SUPPORTED (process has no IP family) | PARTIAL (schema; live ETW untested) |
| Loopback | SUPPORTED (own local control) | NOT SUPPORTED (not a network source) | NOT TESTED |
| Direction | NOT SUPPORTED as reliable field | NOT SUPPORTED | PARTIAL (connect/accept provenance) |
| Connection ID | PARTIAL (NetSentinel lifecycle UUID) | NOT SUPPORTED | PARTIAL (`connid`, scope/reuse unknown) |
| Event timestamp | PARTIAL (poll observation time) | PARTIAL (header emission time) | PARTIAL (header emission time) |
| Loss visibility | PARTIAL (reduced/failed rounds) | PARTIAL (ETW session counters) | PARTIAL (ETW session counters) |
| Startup reconciliation | SUPPORTED (first complete snapshot) | PARTIAL (rundown plus snapshot) | PARTIAL (no pre-session flow rundown) |
| Standard user | PARTIAL (own controls passed; system rows vary) | NOT TESTED classic; related start denied | NOT TESTED classic; related starts denied |
| Admin requirement | NOT SUPPORTED for ordinary polling | PARTIAL (system logger privileged; admin untested) | PARTIAL (system logger privileged; admin untested) |
| Bounded shutdown | SUPPORTED (current engine/writer) | NOT TESTED | NOT TESTED |
| Implementation complexity | PARTIAL (existing bounded adapters) | PARTIAL (native session/decoder/reconcile) | PARTIAL (native session/decoder/identity) |
| Maintenance risk | PARTIAL (psutil/Windows evolution) | PARTIAL (MOF version/ACL/loss) | PARTIAL (MOF version/flow semantics/rate) |

## 12. Offline sequences and decision

These are explicit **design sequences**, not a claim of an implemented ETW
decoder. Existing deterministic tests exercise the polling-side invariants:
`test_observation_quality.py`, `test_connection_tracking.py`,
`test_psutil_processes.py`, and `test_history_freshness.py`. They do not
simulate ETW payload parsing. Required future event-consumer fixtures are:

| Sequence | Safe expected handling |
|---|---|
| Start, duplicate Start, End | One process candidate; duplicate idempotent; close only matched instance |
| End before delayed Start; PID reused | Hold/mark ambiguous; old End never terminates new PID instance |
| Child Start with already exited/reused parent | Preserve reported parent PID and event time; parent instance unknown |
| TCP Connect before process metadata/Start delivery | Bounded candidate; later verify instance; no immediate false lineage |
| TCP Disconnect after process End | Match by verified flow evidence, not arrival order |
| Connect, Disconnect, same tuple reconnect | Separate lifecycle candidates; tuple or connid alone not a portable UUID |
| DCStart plus poll snapshot plus live Start | Deduplicate verified instance, keep initial-vs-observed meaning |
| Lost-event marker, later complete poll | Mark event interval reduced; repair current state, not historical short flows |
| Bounded queue overflow, shutdown timeout | Count own drops; degrade source; no infinite drain or false complete |
| UDP datagrams from multiple peers on one socket | Datagram evidence distinct from psutil local-socket lifecycle |

**Why NO-GO now:** this host's standard-user token cannot use the tested
ETW session surfaces; a successful classic system logger, rundown, loss
counter, process/flow payload, and bounded shutdown were not measured.
Schema-only advantages are real but insufficient to justify a production
collector or event-primary replacement. Process Start/End could materially
improve short-lived process visibility and parent-at-start evidence in an
authorized setting; TCP Connect/Accept/Disconnect might improve timing and
direction. Both need live privilege/schema/loss/identity verification, and
UDP still lacks a socket lifecycle. The hybrid approach is the only future
candidate worth testing: events as fast evidence, psutil as startup/current
state/recovery authority. Event-primary is not supported by this evidence.
Polling-only remains the recommended current architecture. No production
implementation is recommended now.

M11 exit check: NS-052–NS-060 were already marked complete; NS-061 is closed
by this documented decision. NS-056/058 identity, bounded quality/state,
restart-gap, and PID-reuse behavior were checked with 74 targeted offline
tests (`.\.venv\Scripts\python.exe -m pytest -q
tests/unit/application/test_observation_quality.py
tests/unit/application/test_connection_tracking.py
tests/unit/infrastructure/test_psutil_processes.py
tests/integration/sqlite/test_history_freshness.py`): **74 passed**.
Full `.\.venv\Scripts\python.exe -m pytest -q`: **1022 passed, 5
deselected**. `.\.venv\Scripts\python.exe -m ruff check src tests`: **all
checks passed**. `.\.venv\Scripts\python.exe -m mypy`: **no issues in 14
source files**. `git diff --check`: **passed**. These existing tests protect
polling invariants; they do not certify ETW event delivery.

**Explicit next action:** keep NS-056/058 polling contracts and close NS-061
as a documented NO-GO. If product priorities later justify elevated optional
telemetry, create a separate authorized task for an isolated Windows VM test
that captures actual classic process/TCP/UDP events under both standard and
elevated tokens, validates v4/v6/loopback/failure/rundown/ordering/loss and
owned stale-session recovery, and measures bounded CPU/memory/event rate and
shutdown. Do not start NS-062, create a service, or add production contracts
from this spike.

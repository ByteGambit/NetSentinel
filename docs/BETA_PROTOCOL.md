# NS-099 — Public beta acceptance protocol v1

Frozen 2026-10-06 **before NS-099 scenario results**. TASKS.md controls scope.
This evaluates a limited unsigned pilot, not broad distribution or response.
Runtime source: `1d053721733139ab66e0078737fbd19c38e4c679`; app version 0.1.0,
schema 019. Build identity is in [PUBLIC_BETA_ACCEPTANCE.md](PUBLIC_BETA_ACCEPTANCE.md).
Acceptance-only docs/tests may follow that commit without changing its payload.
The closure candidate subsequently uses committed runtime ae08d7e with the narrow
retention-Diagnostics presentation fix. Its complete source identity/hash and
affected retests are in the candidate record; earlier base/patch hashes are historical.
The thresholds below remain frozen and unchanged.
Any runtime/packaging change requires a new build/hash and affected native retest.
Never reuse the historical NS-096 hash for this candidate.

## Environments and evidence

Use the rebuilt installer in a real Windows x64 client VM, fresh standard-user
profile without NetSentinel state. Record Windows edition/version/build,
architecture, token/admin membership, Python (real runtime versus Store alias),
Npcap, network/VPN, resolution/scaling, snapshot/profile cleanliness and SHA256.
An existing OS with a fresh profile is not a pristine OS. Record Unicode profile
separately. Prior NS-096 results are historical, not current-candidate PASS.
Do not claim all Windows 10/11 versions from one VM. Tests/offscreen/source
fixtures are AUTOMATED PASS only, never native evidence.

Results: AUTOMATED PASS, NATIVE PASS, FAIL, NOT RUN, BLOCKED, NOT APPLICABLE.
No evidence is NOT RUN, never zero measurements. Required scenario pending
prevents a passed functional gate. Npcap-present and live TI are optional;
VPN absent leaves native VPN pending, with synthetic coverage recorded separately.

## Metrics and frozen thresholds

Severity policy has INFO/LOW/MEDIUM/HIGH, **no CRITICAL enum**. HIGH is the highest
available release check. Concern score is review priority, not malware probability.

Record benign browser/update/VPN/sleep/restart intervals and total active monitored
minutes, assessments, unique alerts, occurrence changes, INFO/LOW/MEDIUM/HIGH,
incidents, correlation reasons and timelines. Tester labels each reviewed alert
useful/actionable, benign/noise, or unresolved, with an explanation. This is
**beta tester benign/noise classification**, not scientific malware ground truth.
Report unknowns, not assumed benign labels. Burden = benign/noise alerts requiring
review / active monitored hours; count distinct alerts and repeated review demands.

Functional pilot thresholds, chosen as an operator review budget for this v1:

- Zero unexplained HIGH alerts caused solely by ordinary activity; unresolved
  HIGH explanations block. No unsupported malware certainty at any severity.
- At most 5 benign/noise review demands in a 30-minute monitored benign session
  (10/hour); also at most 2 in any individual scenario. Unresolved LOW/MEDIUM
  findings require review before exit. Do not move this budget after results.
- Identical persisted observations replayed without new evidence cause zero
  occurrence increments; no huge incident joined solely by repeated IP/domain.
- Sleep/restart/scope changes create no fabricated monitoring coverage,
  duration, high-confidence evidence or baseline corruption.

Notifications: default OFF yields **zero popups**. Enable separately for a
measured interval. Collect OS-delivered/observed popups, sink submissions,
unique notified alerts, duplicate/cooldown/coalesced/suppressed skips,
escalations, drops, failures, clicks and tester-dismissed/noisy popups.
Observed deliveries/hour and deliveries/unique actionable alert use actual
intervals; if actionable count is zero, ratio is N/A, not divide-by-zero.
Sink submission is **not OS delivery proof**.

- Zero identical duplicate deliveries, zero historical replay on enable/restart.
- Same subject/severity obeys NS-094 **120-second monotonic cooldown**;
  genuine escalation/reopen exceptions are reported separately.
- Benign activity at most 3 observed popups per 30 minutes (6/hour), with zero
  unexplained HIGH popups. Synthetic injected test alerts are a separate dataset,
  excluded from benign FP/burden, and must satisfy dedup/cooldown policy.
- Queue <=32, state <=512; native sink handles <=8/600s. No unexplained overflow
  or retry storm in normal use; OS suppression/unavailability is explicit.

## Scenario order

1. Verify candidate hash before transfer/run; record environment and defaults.
   Offline per-user install without UAC. No security-policy bypass if blocked.
2. Fresh guide at 1280x720 (or closest realistic resolution): all six pages,
   Next/Back/Skip/Finish, optional controls separate, risk/local-first understood.
   Help reopen, Diagnostics, Storage, notifications and Feedback accessible.
3. Npcap absent: core visibility/history where supported, capture/DNS honestly
   unavailable; no driver install/download, implicit capture, elevation or crash.
4. Start a bounded >=30-minute native session, including >=10 minutes ordinary
   HTTPS browsing of non-sensitive public sites and >=5 minutes a safe software
   update check. No risky OS update is required. Record helper/CDN behavior.
5. Safe available VPN baseline/connect/browse/disconnect; no network attack or
   VPN provisioning needed. If absent, mark NOT RUN and retain pending gate.
6. Sleep/wake, normal browsing afterward; record actual sleep duration,
   monitoring recovery, gaps, UI/tray/retention/alerts and notifications.
7. At least three app restarts if practical; one OS reboot if practical. Check
   config/guide/consent/history/baselines/incidents, no hidden capture/TI requests,
   no notification replay, no autostart. Reboot impracticality is explicit.
8. QUIT close, opt-in hide-to-tray, Show and Quit; continued hidden monitoring,
   bounded clean exit and no ghost process. Test notifications OFF then ON using
   only an accepted safe fixture/manual method, never external attack traffic.
   No production synthetic-alert insertion route exists: record this dependency
   honestly rather than directly altering the installed user's DB.
9. TI OFF: existing fake-provider/forbidden-network tests prove request policy;
   native request tracing/diagnostics must be labelled with its actual limits.
   Optional live lookup requires credential and separate explicit consent.
10. Storage loads/responsive, retention/purge protection; Feedback full sanitized
    preview -> local Save -> inspect exact file. Export is not a DB backup.
11. Review aggregate diagnostics/logs: errors, busy DB, worker failures, queue
    pressure, dropped telemetry, memory/startup/shutdown and DB/WAL growth.
    Quit/restart after soak; no corruption or replay. Record actual durations,
    poll cycles, counts, before/after sizes; no invented hard performance SLA.
12. Current-candidate repair and uninstall KEEP or confirmed DELETE; record data
    choice and preserved external files. Historical upgrade/Unicode evidence is
    separate; repeat current candidate Unicode install/launch when accessible.

## Findings, privacy and exit

BLOCKER: startup crash/install failure, corruption/destructive upgrade or KEEP
data loss, protected-state deletion, export/artefact secret or privacy leak,
default reputation request, automatic upload/response/elevation, deletion outside
owned root, misrepresented signature/capability/malware certainty, bypass needed,
unbounded notification storm, unexplained HIGH on benign activity, essential guide
controls inaccessible or impossible Quit/support export. Any unresolved blocker:
NO_GO. MAJOR: repeatable severe usability/capability failure; unresolved failure
of a required scenario blocks exit. MINOR: cosmetic explainable issue; list owner.
Missing required native evidence is an acceptance blocker, not a confirmed bug.

Commit only aggregate/synthetic evidence: no real browsing history, IP/domain/MAC,
username/path, keys, private certificates or native screenshots with telemetry.
Use the existing NS-098 synthetic screenshots. No automatic crash uploader.
Keep raw evidence locally; inspect even sanitized exports before manually sharing.

Exit requires all exact NS-099 mandatory scenarios evidenced and passing, offline
quality gates (full suite, >=85% coverage, Ruff/configured/direct mypy/diff), prior
M11–M16 gates preserved, support/privacy docs and an explicit decision. CI status
is separate from local checks; no inferred remote CI pass. Record dependency audit
failure/unavailability rather than silently carrying forward an old result.

Limited pilot GO or CONDITIONAL_GO requires functional exit; NS-097 owner
audience/licensing/manual channel conditions still apply. Broad public release
NO_GO until signing and protected release gates pass. Pending native acceptance
means limited pilot NO_GO for now; do not mark NS-099/M17 complete. Task evaluation
may conclude NO_GO after actual scenarios fail, but unperformed mandatory scenarios
are incomplete work. No tag, publication, upload, certificate purchase or updater.
M18 DEFER until burden/explainability/usability gates pass and later explicit
response GO is supplied; this protocol does not authorize NS-100.

Feedback: Help -> Feedback & Support -> sanitized preview -> Save locally ->
owner-agreed manual channel. Dedicated feedback/private-security endpoint remains
undefined; owner must establish the pilot contact before recruiting testers.
Never invent an address or post vulnerability details/raw telemetry publicly.

# NetSentinel 0.1.0 — pilot preparation notes

Prepared 2026-10-06 through NS-098. This is source/build preparation, not a tag,
published release, public beta acceptance or distribution authorization. M1–M16
are complete; M17 is IN PROGRESS; NS-099 is NOT STARTED. Existing NS-096 binaries
have not been rebuilt with NS-098. The 0.1.1 installer upgrade fixture still has
0.1.0 application payload and is never a release candidate.

- Process/connection metadata and retained local connection history provide
  visibility; selected process and destination context explains what is known.
- Local ASN/country and observed DNS associations show supporting context with
  ambiguity and freshness rather than a certain domain-to-process claim.
- Behavioral baseline and deterministic concern-score explanations separate
  severity, confidence, coverage, suppression and evidence limitations.
- Optional AbuseIPDB selected-public-IP reputation requires separate provider
  consent and manual lookup. Default requests are zero; the desktop credential
  backend remains unavailable. HIT/NO_HIT are supporting evidence, not verdicts.
- Incident timelines group retained related observations, inferences, assessments
  and actions, with source-expiry and incomplete-history states.
- Tray behavior is explicit; desktop notifications are opt-in and privacy-aware.
- Storage & Privacy offers bounded opt-in retention, confirmed local purge and
  allowlist support-export-v1 preview/atomic local Save, with no automatic upload.
- Per-user offline installer supports repair, compatible upgrade and KEEP-default
  uninstall; DELETE requires separate confirmation. Program and data roots differ.
- Six-page versioned guide can be skipped or reopened from Help without enabling
  optional features. Feedback & Support shows full sanitized preview and an
  explicit project-page route; no dedicated feedback/security contact is defined.

**NetSentinel does not upload your network history by default.** Local metadata
can still be sensitive. Capture is explicitly started and depends on Npcap/access;
there is no auto-install or elevation. Polling can miss short-lived connections;
process metadata is not event telemetry; per-flow byte totals are unavailable.
Classic DNS is not universal DoH/DoT visibility; domain associations are ambiguous.
Disk hash/signature/country/novelty/reputation are context, not proof of safety or
malware. Concern score is review priority, not probability. Incident ordering is
not causality or forensic completeness; retained source details can expire.
No automatic blocking or antivirus replacement is promised.

Distribution remains a limited, explicitly **unsigned pilot**, conditional on
owner audience/licensing/channel approval and remaining M17 gates. Windows may
warn or block these builds; never bypass security. Updates are **manual** through
the canonical project Releases channel; no automatic update request or client.
Broad public beta/production remains NO-GO without the signer and remaining gates.
See [distribution policy](SIGNING_UPDATE_DISTRIBUTION.md),
[installer acceptance](INSTALLER_ACCEPTANCE.md),
[guide/feedback policy](FIRST_RUN_FEEDBACK.md).

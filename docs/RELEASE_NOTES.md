# NetSentinel 0.1.0 — unpublished pilot candidate notes

NS-099 notification-policy closure (2026-10-07): **policy PASS**, actual Windows
global Notifications OFF/ON in the same Limited-token Session1; application
reports **UNKNOWN**, accepted submission is not visible-delivery proof.
Current unpublished unsigned0.1.0 source `8242868ba79c63ad743c005366ea715b238cf5d0`,
SHA256 `39b14fe844c8aaa150a8b09229e0d63aaaf5ecc98b5bc8c54b419140be7749d9`, 37,559,481 bytes, schema019→019.
Installed1119 hashes/0 mismatches;194 source-matching compiled modules.
Native popup/privacy/click/duplicates/restart PASS in the recorded policy scope.
Human UX remains PASS8/8, layout CLOSED in its evaluator scope. VPN and meaningful
native sleep NOT RUN; NS-099 INCOMPLETE, M17 IN PROGRESS, pilot/broad NO_GO,
M18 DEFER, NS-100 NOT STARTED; tag/release NONE.
[Policy model, native measurements and limitations](NS099_NOTIFICATION_POLICY_CLOSURE.md).

## Previous layout follow-up — historical candidate

NS-099 layout follow-up (2026-10-07): current runtime/source `bfe531d960aaabd6b61c1701cf7179f7214c5097`,
unsigned0.1.0 candidate SHA256 `74529e4cfa03d466ed365a4b0fe5c65c4399873acf150b0c3472496472bdf4c2`, 37,543,802 bytes, schema019→019.
Incidents/DNS/History layout fixed; fresh Windows11 native layout test-build
captures evaluated by the human. Focused layout recheck **PASS**; overall Human UX
**8 PASS / 0 FAIL**. The previous layout finding is closed. Prior functional/native measurements below keep
their original ae08d7e/14934a52 candidate scope. VPN NOT RUN, native sleep NOT RUN,
effective OS-disabled policy BLOCKED; NS-099 INCOMPLETE, M17 IN PROGRESS,
pilot/broad NO_GO, M18 DEFER, NS-100 NOT STARTED. [Layout record](NS099_LAYOUT_CLOSURE.md).

The earlier closure summary below retains its historical candidate scope.

Prepared 2026-10-06 through NS-099 acceptance, using clean committed runtime
`ae08d7ef1205f5bd4f0b9b0397075c1f6176f2c4`, including the narrow
retention-Diagnostics GUI fix. A new 0.1.0 unsigned installer
includes NS-098; [identity/hash](PUBLIC_BETA_CANDIDATE.json),
[current gate](PUBLIC_BETA_ACCEPTANCE.md). This is not a tag, published release,
passed native beta acceptance or distribution authorization. M1–M16 are complete;
M17 IN PROGRESS; NS-099 INCOMPLETE pending required VPN, full native sleep/gap,
effective OS-disabled policy and human layout FAIL. Other7 human UX criteria PASS. Closure native fixture
toast/privacy/click/restart and real tray context Quit passed in recorded scope.
Historical standard/Unicode install, repair,
browser/updater, restart, sanitized export and KEEP passed in the new Windows 11 VM.
The 0.1.1 installer upgrade
fixture still has 0.1.0 application payload and is never a release candidate.

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
- Diagnostics now reflects retention settings immediately after successful Save;
  the native-discovered stale display was fixed and OFF/ON retested in the final build.
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

Distribution policy remains a limited, explicitly **unsigned pilot**, conditional on
owner audience/licensing/channel approval and remaining M17 gates. Current NS-099
readiness decision is **NO_GO** until required native scenarios are evidenced.
Windows may
warn or block these builds; never bypass security. Updates are **manual** through
the canonical project Releases channel; no automatic update request or client.
Broad public beta/production remains NO-GO without the signer and remaining gates.
See [distribution policy](SIGNING_UPDATE_DISTRIBUTION.md),
[installer acceptance](INSTALLER_ACCEPTANCE.md),
[guide/feedback policy](FIRST_RUN_FEEDBACK.md), [pilot support](BETA_SUPPORT.md),
[privacy summary](BETA_PRIVACY.md). M18 is DEFERRED; NS-100 has not started.

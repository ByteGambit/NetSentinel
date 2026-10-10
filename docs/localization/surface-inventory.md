# NS-105 surface/source inventory

This inventory covers every current presentation module, the composition/Qt creation path,
and the six application services that already construct user-facing read/preview text.
The canonical TS lists the actual English sources and file locations; exact exclusions
are maintained in `literal-exceptions.json`. Domain/application imports stay Qt-free.

Metric definition: the two initial reviewed conversion passes routed **1,187 existing
presentation literal occurrences** (1,162 + 25) through Qt source calls. This is the
audited conversion-pass count, not a claim that each occurrence is a unique message.
Subsequent helper/display/descriptor work is reflected in the current call/site inventory
below. Target translations and enum display variants are not counted as converted literals.

## Product surfaces

| Surface | Inventory / boundary |
|---|---|
| Main window / navigation / menus | Stable PageId/action/object/role keys; translated captions, status bar, Settings and Help actions. |
| Dashboard | Aggregate metrics, health, VLAN/rate context, empty states, tooltip/a11y labels. Raw scope/evidence values remain exact. |
| Connections / History | Headers, filters, statuses, details, process/signer/destination/risk/baseline context and lookup failures; raw endpoints/IDs/ISO evidence preserved. |
| Devices / DNS | Profiles, trust, capture consent/status/interface failure, bindings, header/empty detail; protocol/record/evidence values preserved. |
| Alerts / Incidents | Lifecycle filters, severity/confidence, table/timeline/source status, read and command outcomes, bounded narratives; historical persisted titles/explanations remain verbatim. |
| Settings / privacy / TI | Application behavior, notification settings, Storage & Privacy, provider consent, preview/save/Cancel, retention/feedback captions and sanitized failures. |
| Response / preferences / audit | Reviewed targets/warnings/confirmations, lifecycle/permission displays, result labels; command IDs, ownership data and stored audit reason remain canonical. |
| M17 guide | All existing six pages, progress, action links, a11y/tooltips; original completion/consent contract. No v2 tour. |
| Tray / notification | Startup menu/tooltip and severity-derived title/body at submit; no replay hook or event rewrite. |
| Exports / CLI / installer / OS | Support-export JSON preview content, diagnostic receipts/logs/recovery manifests, installer policy and native OS chrome intentionally retain their canonical/OS formats. |

## Every presentation/source module

| File | Literal source calls | Contexts |
|---|---:|---|
| `src/netsentinel/presentation/__init__.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/alert_query.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/app.py` | 2 | App |
| `src/netsentinel/presentation/baseline_query.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/bridge.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/capability_query.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/destination_context.py` | 34 | DestinationContext |
| `src/netsentinel/presentation/destination_query.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/device_inventory.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/device_profile.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/dns_query.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/history_query.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/i18n/__init__.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/i18n/buttons.py` | 6 | StandardButtons |
| `src/netsentinel/presentation/i18n/manager.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/i18n/notifications.py` | 5 | Notifications |
| `src/netsentinel/presentation/i18n/text.py` | 1 | SourceText |
| `src/netsentinel/presentation/incident_query.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/models/__init__.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/models/alerts.py` | 33 | AlertsModel |
| `src/netsentinel/presentation/models/connection_filter.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/models/connections.py` | 7 | ConnectionsModel |
| `src/netsentinel/presentation/models/dashboard.py` | 47 | DashboardModel |
| `src/netsentinel/presentation/models/devices.py` | 5 | DevicesModel |
| `src/netsentinel/presentation/models/dns.py` | 16 | DnsModel |
| `src/netsentinel/presentation/models/history.py` | 15 | HistoryModel |
| `src/netsentinel/presentation/models/incidents.py` | 20 | IncidentsModel |
| `src/netsentinel/presentation/models/vlan.py` | 18 | VlanModel |
| `src/netsentinel/presentation/notifications.py` | 1 | Notifications |
| `src/netsentinel/presentation/preference_commands.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/process_context.py` | 31 | ProcessContext |
| `src/netsentinel/presentation/response_commands.py` | 1 | ResponseCommands |
| `src/netsentinel/presentation/risk_query.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/theme.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/tray.py` | 4 | Tray |
| `src/netsentinel/presentation/viewmodels.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/views/__init__.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/views/alerts.py` | 77 | Alerts |
| `src/netsentinel/presentation/views/connections.py` | 40 | Connections |
| `src/netsentinel/presentation/views/dashboard.py` | 45 | Dashboard |
| `src/netsentinel/presentation/views/devices.py` | 78 | Devices |
| `src/netsentinel/presentation/views/diagnostics.py` | 84 | Diagnostics |
| `src/netsentinel/presentation/views/dns.py` | 74 | Dns |
| `src/netsentinel/presentation/views/history.py` | 64 | History |
| `src/netsentinel/presentation/views/incidents.py` | 67 | Incidents |
| `src/netsentinel/presentation/views/main_window.py` | 25 | MainWindow |
| `src/netsentinel/presentation/views/placeholder.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/widgets/__init__.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/presentation/widgets/application_behavior.py` | 10 | ApplicationBehavior |
| `src/netsentinel/presentation/widgets/baseline_detail.py` | 27 | BaselineDetail |
| `src/netsentinel/presentation/widgets/connection_details.py` | 42 | ConnectionDetails |
| `src/netsentinel/presentation/widgets/device_profile.py` | 35 | DeviceProfile |
| `src/netsentinel/presentation/widgets/manual_response.py` | 45 | ManualResponse |
| `src/netsentinel/presentation/widgets/mark_normal.py` | 73 | MarkNormal |
| `src/netsentinel/presentation/widgets/notification_settings.py` | 17 | NotificationSettings |
| `src/netsentinel/presentation/widgets/onboarding.py` | 50 | Onboarding |
| `src/netsentinel/presentation/widgets/page_flow.py` | 1 | PageFlow |
| `src/netsentinel/presentation/widgets/risk_explanation.py` | 18 | RiskExplanation |
| `src/netsentinel/presentation/widgets/storage_privacy.py` | 53 | StoragePrivacy |
| `src/netsentinel/presentation/widgets/threat_intel_consent.py` | 19 | ThreatIntelConsent |
| `src/netsentinel/presentation/widgets/threat_intel_lookup.py` | 24 | ThreatIntelLookup |
| `src/netsentinel/shared/source_text.py` | 0 | No owned source literals; typed plumbing, technical values or caller-provided captions. |
| `src/netsentinel/shared/enum_sources.py` | 442 | AlertStatus.raw, AlertStatus.title, ApplicationIdentityQuality.human, ApplicationIdentityQuality.raw, AssessmentAvailability.human, AssessmentReadStatus.human, AssessmentSourceStatus.human, BaselineOrigin.raw, BaselineState.upper, BaselineStorageState.raw, BehaviorClassification.upper, BehaviorReason.words, CapabilityStatus.human, CapabilityStatus.raw, CaptureState.human, CaptureState.raw, ConnectionState.title, ContributorFamily.human, DatabaseStatus.human, DatabaseStatus.raw, DestinationNoveltyClassification.upper, DestinationNoveltyLimitation.words, DestinationNoveltyReason.words, DeviceTrust.raw, DeviceTrust.title, EngineState.human, EngineState.raw, EvidenceConfidence.human, EvidenceRole.human, EvidenceSource.human, Freshness.human, IncidentAction.raw, IncidentLimitation.words, IncidentOrigin.raw, IncidentState.raw, IncidentStatus.raw, LocalTrust.words, LookupState.words, MaintenanceStatus.raw, NetworkScopeStatus.human, NetworkScopeStatus.raw, NetworkScopeStatus.words, ObservationQuality.human, ObservationQuality.raw, PeriodicityClassification.upper, PeriodicityLimitation.words, PeriodicityReason.words, PersistenceState.raw, PreferenceEffect.human, PreferenceStatus.human, PreferenceStatus.upper, ResponseAction.raw, ResponseAction.upper, ResponseAuditEvent.raw, ResponseOperationStatus.raw, ResponseOutcome.raw, ResponseProfile.title, ResponseReason.raw, ResponseReconciliation.raw, ResponseRuleState.raw, ResponseSourceStatus.raw, RevocationStatus.words, RiskSeverity.raw, RiskSeverity.title, ScoringAdjustment.human, ScoringReason.human, SeverityCapReason.human, SignatureKind.raw, SignatureValidation.words, SignerAvailability.words, SubmissionState.words, SuppressionDisposition.human, SuppressionLimitation.human, ThreatIntelCacheFreshness.upper, ThreatIntelError.words, ThreatIntelEvidenceStatus.words, ThreatIntelResultStatus.upper, TimelineKind.raw |
| `src/netsentinel/application/services/baseline_detail.py` | 69 | BaselineDetail |
| `src/netsentinel/application/services/risk_explanation.py` | 158 | RiskExplanation |
| `src/netsentinel/application/services/incident_timeline.py` | 53 | IncidentTimeline |
| `src/netsentinel/application/services/response_ui.py` | 30 | ResponseUi |
| `src/netsentinel/application/services/threat_intel_evidence.py` | 21 | ThreatIntelEvidence |
| `src/netsentinel/application/services/mark_normal.py` | 27 | MarkNormal |

Current presentation literal source calls: **1214**. Extracted unique Qt keys: **1913**,
contexts: **119**, Qt numerus keys: **3**.

Enum mapping values are canonical extractable source descriptors, not production catalogs.
Technical exclusions include empty/reset/punctuation text, QSS, field/style/serialization
keys, diagnostic codes, addresses/ASN notation, ISO time syntax, raw record identity,
audit/history/user-entered strings and machine output. Unknown/dynamic prose newly
introduced outside the source set still requires manual review; the gate is bounded.

## Readiness / next acceptance

Logical leading/trailing alignment and symmetric navigation padding are in place. Qt
direction inheritance was tested LTR→RTL→LTR. Sidebar/card width limits, row sizing,
note/list/preview height limits, long menus/mnemonics and mixed-direction evidence require
NS-107/110 native review. No absolute widget placement, custom overlay or forced production
font family was found. OS/Qt glyph fallback, Arabic shaping and CJK fallback availability
have no native acceptance yet. No font files or licenses are added/redistributed.

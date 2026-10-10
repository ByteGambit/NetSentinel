# NS-105 changed files

75 changed/new review files against acceptance HEAD `6545832c31c0065a4afc44418b5d6c0d78642369`.
The precommit snapshot had no commit/push; the 2026-10-10 checkpoint authorizes
only the reviewed NS-105 commit/push to main. No tag or release.
Generated build/test/wheel/compiler outputs are ignored
and not part of this list. The only QM included for review is the test fixture.

| File | State |
|---|---|
| `.github/workflows/ci.yml` | Modified |
| `docs/ARCHITECTURE.md` | Modified |
| `docs/LOCALIZATION.md` | New |
| `docs/LOCALIZATION_ACCEPTANCE.md` | New |
| `docs/M19_M20_PLANNING.md` | Modified |
| `docs/PRODUCT.md` | Modified |
| `docs/ROADMAP.md` | Modified |
| `docs/SECURITY.md` | Modified |
| `docs/TASKS.md` | Modified |
| `docs/localization/acceptance-receipt.json` | New |
| `docs/localization/changed-files.md` | New |
| `docs/localization/literal-exceptions.json` | New |
| `docs/localization/surface-inventory.md` | New |
| `packaging/NetSentinel.spec` | Modified |
| `pyproject.toml` | Modified |
| `src/netsentinel/application/services/baseline_detail.py` | Modified |
| `src/netsentinel/application/services/incident_timeline.py` | Modified |
| `src/netsentinel/application/services/mark_normal.py` | Modified |
| `src/netsentinel/application/services/response_ui.py` | Modified |
| `src/netsentinel/application/services/risk_explanation.py` | Modified |
| `src/netsentinel/application/services/threat_intel_evidence.py` | Modified |
| `src/netsentinel/assets/i18n/manifest.json` | New |
| `src/netsentinel/presentation/app.py` | Modified |
| `src/netsentinel/presentation/destination_context.py` | Modified |
| `src/netsentinel/presentation/i18n/__init__.py` | New |
| `src/netsentinel/presentation/i18n/buttons.py` | New |
| `src/netsentinel/presentation/i18n/manager.py` | New |
| `src/netsentinel/presentation/i18n/notifications.py` | New |
| `src/netsentinel/presentation/i18n/text.py` | New |
| `src/netsentinel/presentation/models/alerts.py` | Modified |
| `src/netsentinel/presentation/models/connection_filter.py` | Modified |
| `src/netsentinel/presentation/models/connections.py` | Modified |
| `src/netsentinel/presentation/models/dashboard.py` | Modified |
| `src/netsentinel/presentation/models/devices.py` | Modified |
| `src/netsentinel/presentation/models/dns.py` | Modified |
| `src/netsentinel/presentation/models/history.py` | Modified |
| `src/netsentinel/presentation/models/incidents.py` | Modified |
| `src/netsentinel/presentation/models/vlan.py` | Modified |
| `src/netsentinel/presentation/notifications.py` | Modified |
| `src/netsentinel/presentation/process_context.py` | Modified |
| `src/netsentinel/presentation/response_commands.py` | Modified |
| `src/netsentinel/presentation/tray.py` | Modified |
| `src/netsentinel/presentation/viewmodels.py` | Modified |
| `src/netsentinel/presentation/views/alerts.py` | Modified |
| `src/netsentinel/presentation/views/connections.py` | Modified |
| `src/netsentinel/presentation/views/dashboard.py` | Modified |
| `src/netsentinel/presentation/views/devices.py` | Modified |
| `src/netsentinel/presentation/views/diagnostics.py` | Modified |
| `src/netsentinel/presentation/views/dns.py` | Modified |
| `src/netsentinel/presentation/views/history.py` | Modified |
| `src/netsentinel/presentation/views/incidents.py` | Modified |
| `src/netsentinel/presentation/views/main_window.py` | Modified |
| `src/netsentinel/presentation/views/placeholder.py` | Modified |
| `src/netsentinel/presentation/widgets/application_behavior.py` | Modified |
| `src/netsentinel/presentation/widgets/baseline_detail.py` | Modified |
| `src/netsentinel/presentation/widgets/connection_details.py` | Modified |
| `src/netsentinel/presentation/widgets/device_profile.py` | Modified |
| `src/netsentinel/presentation/widgets/manual_response.py` | Modified |
| `src/netsentinel/presentation/widgets/mark_normal.py` | Modified |
| `src/netsentinel/presentation/widgets/notification_settings.py` | Modified |
| `src/netsentinel/presentation/widgets/onboarding.py` | Modified |
| `src/netsentinel/presentation/widgets/page_flow.py` | Modified |
| `src/netsentinel/presentation/widgets/risk_explanation.py` | Modified |
| `src/netsentinel/presentation/widgets/storage_privacy.py` | Modified |
| `src/netsentinel/presentation/widgets/threat_intel_consent.py` | Modified |
| `src/netsentinel/presentation/widgets/threat_intel_lookup.py` | Modified |
| `src/netsentinel/shared/enum_sources.py` | New |
| `src/netsentinel/shared/source_text.py` | New |
| `tests/fixtures/i18n/pseudo.qm` | New |
| `tests/fixtures/i18n/pseudo.ts` | New |
| `tests/gui/test_localization.py` | New |
| `tests/unit/test_localization_tooling.py` | New |
| `tools/localization.py` | New |
| `translations/netsentinel_en.ts` | New |
| `uv.lock` | Modified |

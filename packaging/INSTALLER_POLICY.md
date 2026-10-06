# NetSentinel unsigned pilot distribution

Program files and local user data are separate. Default installation is per-user:
%LOCALAPPDATA%\Programs\NetSentinel. Development, portable and installed builds
store local data at %LOCALAPPDATA%\NetSentinel. SQLite, config/preferences,
monitoring history, alerts/incidents, profiles/trust, reputation cache and logs
stay local by default. First run preserves existing consent/onboarding defaults.

Uninstall defaults to KEEP local data. DELETE requires a separate choice and
destructive confirmation. NetSentinel cannot restore deleted local data; secure
erasure is not guaranteed. External user-selected exports are never removed.
Quit from File or the tray before repair/upgrade/uninstall, including hidden apps.
Unsafe paths or links refuse data deletion; choose KEEP or repair before retrying.

Rerunning the same installer repairs owned files and preserves local data.
An upgrade preserves data; application startup owns SQLite migrations. Downgrade
is not guaranteed. Copy closed local data before upgrade if a backup is needed.
Support export is sanitized metadata, not a full history/database backup.

No automatic elevation, Npcap bundling/download/install/removal, updater,
autostart, service, firewall rule, telemetry or automatic cloud upload.
Npcap absence leaves capture features degraded; supported connection monitoring
remains available. Installer operates offline. Third-party notices and licenses
are included; this policy is informational, not a new EULA.

This pilot installer is unsigned. SmartScreen/Application Control may block it
or runtime components. Do not disable or bypass Windows security. Native clean
Windows client acceptance and signing/distribution decisions remain separate.

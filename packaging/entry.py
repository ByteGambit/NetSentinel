"""Thin frozen entry point; GUI startup stays in the production composition root."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import sys
import tempfile


def _self_test(report: Path) -> int:
    """Documented, bounded offline diagnostic for an extracted Windows bundle."""

    result = {"migrations": 0, "sqlite": False, "qt": False, "gui_exit": None}
    try:
        from PyQt6.QtCore import QTimer
        from PyQt6.QtWidgets import QApplication

        from netsentinel.bootstrap import runtime_config_path
        from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
        from netsentinel.infrastructure.sqlite.migrations import MigrationRunner, builtin_migrations
        from netsentinel.presentation.app import run_application
        from netsentinel.presentation.widgets.onboarding import OnboardingDialog
        from netsentinel.shared.config import load_config_file
        from netsentinel.version import __version__

        result["version"] = __version__
        migrations = builtin_migrations()
        result["migrations"] = len(migrations)
        if [item.version for item in migrations] != list(range(1, 20)):
            raise RuntimeError("migration_manifest")
        with tempfile.TemporaryDirectory(prefix="netsentinel-db-") as directory:
            database = SQLiteDatabase(Path(directory) / "smoke.sqlite3")
            with database.connection() as connection:
                result["sqlite"] = connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal" and connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
                result["schema_version"] = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
            old = Path(directory) / "upgrade.sqlite3"
            with SQLiteDatabase(old, migration_runner=MigrationRunner(migrations[:18])).connection() as connection:
                result["old_schema_version"] = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
            with SQLiteDatabase(old).connection() as connection:
                result["upgraded_schema_version"] = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
        expected_onboarding = not load_config_file(runtime_config_path()).config.onboarding_completed
        app = QApplication.instance() or QApplication([])
        result["qt"] = bool(app.platformName())

        def inspect_ui() -> None:
            dialogs = [widget for widget in QApplication.topLevelWidgets() if isinstance(widget, OnboardingDialog) and widget.isVisible()]
            result["onboarding_visible"] = bool(dialogs)
            if dialogs:
                dialogs[0].finish_button.click()

        QTimer.singleShot(700, inspect_ui)
        QTimer.singleShot(2200, app.quit)
        result["gui_exit"] = run_application(argv=[])
        result["icon"] = not app.windowIcon().isNull()
        result["onboarding_saved"] = load_config_file(runtime_config_path()).config.onboarding_completed
        result["ok"] = all((result["sqlite"], result["qt"], result["icon"], result["schema_version"] == 19, result["old_schema_version"] == 18, result["upgraded_schema_version"] == 19, result.get("onboarding_visible") == expected_onboarding, result["onboarding_saved"], result["gui_exit"] == 0))
    except Exception:
        result["ok"] = False
        result["error"] = "self_test_failed"
    report.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
    return 0 if result["ok"] else 1


def main() -> int:
    if sys.argv[1:] == ["--uninstall-delete-local-data-confirmed"]:
        from netsentinel.infrastructure.uninstall_data import uninstall_local_data

        return uninstall_local_data()
    if len(sys.argv) > 1 and not (len(sys.argv) == 3 and sys.argv[1] == "--self-test"):
        return 2
    try:
        from netsentinel.infrastructure.windows_installer import mark_desktop_running

        mark_desktop_running()
    except Exception:
        return 1  # Fail closed before startup or any DB/config/log writer.
    if len(sys.argv) == 3 and sys.argv[1] == "--self-test":
        return _self_test(Path(sys.argv[2]))
    try:
        from netsentinel.presentation.app import run_application

        return run_application(argv=[])
    except Exception:
        # The windowed executable has no console. Record a fixed code only.
        try:
            from netsentinel.bootstrap import initialize_runtime
            from netsentinel.shared.logging import log_event, close_logging

            initialize_runtime()
            logger = logging.getLogger("netsentinel")
            log_event(logger, component="config", code="startup_failed", level=logging.ERROR)
            close_logging(logger)
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

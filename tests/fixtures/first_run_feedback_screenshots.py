"""Render actual Qt widgets with synthetic offline data; no live sensor claims.

Run from the repository with QT_QPA_PLATFORM=offscreen and the test dependencies:
python -m tests.fixtures.first_run_feedback_screenshots [output-directory]
"""

from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from time import monotonic

from PyQt6.QtGui import QFont, QFontDatabase
from PyQt6.QtWidgets import QApplication

from netsentinel.application.services.capabilities import CapabilityService
from netsentinel.application.services.storage_privacy import StoragePrivacyService
from netsentinel.application.services.storage_worker import StorageMaintenanceWorker
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.storage_maintenance import SQLiteStorageMaintenanceRepository
from netsentinel.presentation.app import create_application
from netsentinel.presentation.views.diagnostics import DiagnosticsView
from netsentinel.presentation.widgets.onboarding import OnboardingDialog
from netsentinel.presentation.widgets.storage_privacy import StoragePrivacyDialog
from netsentinel.shared.config import AppConfig
from netsentinel.shared.diagnostics import CaptureCapabilityReason
from tests.fixtures.storage_privacy import NOW, alert, connection, dns
from tests.gui.test_application_shell import FakeEngine
from tests.gui.test_capabilities import FakeCapture, FakeContexts, diagnostics


def main() -> None:
    destination = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs/images")
    destination.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication([])
    assert isinstance(app, QApplication)
    # The approved sandbox has no system font catalog; load for this renderer only.
    font_file = Path("C:/Windows/Fonts/segoeui.ttf")
    if font_file.is_file():
        QFontDatabase.addApplicationFont(str(font_file))
    app.setFont(QFont("Segoe UI", 10))
    capture = FakeCapture(CaptureCapabilityReason.DEPENDENCY_UNAVAILABLE)
    matrix = CapabilityService(FakeContexts(), capture, lambda: diagnostics(capture)).check()
    shell = create_application(FakeEngine(), config=AppConfig(onboarding_completed_version=1))

    def snapshot(widget, name):
        widget.show()
        app.processEvents()
        if not widget.grab().save(str(destination / f"ns098-{name}.png")):
            raise RuntimeError("snapshot_save_failed")

    guide = OnboardingDialog(None, lambda: True, skip=lambda: True, credential_available=False)
    guide.diagnostics.set_matrix(matrix)
    snapshot(guide, "guide-synthetic")
    guide._page(3)
    snapshot(guide, "limitations-synthetic")
    guide.reject()
    view = DiagnosticsView()
    view.resize(780, 520)
    view.set_preferences(AppConfig(), credential_available=False)
    view.set_matrix(matrix)
    snapshot(view, "diagnostics-synthetic")
    view.close()
    with TemporaryDirectory(prefix="netsentinel-ui-fixture-") as directory:
        database = SQLiteDatabase(Path(directory) / "synthetic.db")
        connection(database, 1, NOW)
        dns(database, 2, NOW)
        for number in range(1, 13):
            alert(database, number, NOW)
        worker = StorageMaintenanceWorker(lambda: StoragePrivacyService(
            SQLiteStorageMaintenanceRepository(database), clock=lambda: NOW))
        worker.start()
        dialogs = []
        try:
            for feedback, name in ((False, "storage-synthetic"), (True, "feedback-synthetic")):
                dialog = StoragePrivacyDialog(worker, feedback=feedback)
                dialogs.append(dialog)
                dialog.resize(940, 660)
                deadline = monotonic() + 5
                while dialog._future is not None and monotonic() < deadline:
                    dialog._poll()
                    app.processEvents()
                if dialog._future is not None:
                    raise RuntimeError("summary_timeout")
                if feedback:
                    dialog.export_preview.click()
                    deadline = monotonic() + 5
                    while dialog._future is not None and monotonic() < deadline:
                        dialog._poll()
                        app.processEvents()
                    if dialog._export is None:
                        raise RuntimeError("preview_unavailable")
                snapshot(dialog, name)
                dialog.reject()
        finally:
            for dialog in dialogs:
                dialog.reject()
            if not worker.stop():
                raise RuntimeError("worker_shutdown_failed")
    shell.lifecycle.shutdown()
    shell.window.close()
    assert capture.starts == 0


if __name__ == "__main__":
    main()

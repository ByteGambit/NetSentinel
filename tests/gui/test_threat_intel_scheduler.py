"""NS-087 offscreen main-thread responsiveness and optional lifecycle."""

from threading import Event

import pytest
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication

from netsentinel.application.services.threat_intel_scheduler import ThreatIntelLookupScheduler, LookupState as L
from netsentinel.application.services.threat_intelligence import ThreatIntelConsentService
from netsentinel.domain.connections import ConnectionOpened
from netsentinel.presentation.app import create_application
from netsentinel.presentation.widgets.threat_intel_consent import ThreatIntelConsentDialog
from netsentinel.presentation.views.main_window import PageId
from tests.fixtures.threat_intelligence import DESCRIPTORS, grant, query
from tests.gui.test_application_shell import FakeEngine
from tests.gui._ns013_support import snapshot
from tests.unit.application.test_threat_intel_scheduler import Provider, Cache


def test_gui_start_selection_consent_zero_calls_explicit_submit_nonblocking(qtbot):
    consent = grant()
    service = ThreatIntelConsentService(DESCRIPTORS, lambda: (consent,), lambda values: None)
    service.current()
    provider = Provider(block=True)
    scheduler = ThreatIntelLookupScheduler((provider,), service.snapshot, lambda: Cache())
    service.bind_scheduler_wakeup(scheduler.wakeup)
    engine = FakeEngine()
    shell = create_application(engine, argv=[], threat_intel_scheduler=scheduler,
                               threat_intel_consent_service=service)
    qtbot.addWidget(shell.window)
    assert shell.threat_intel_scheduler is scheduler
    try:
        shell.window.show()
        assert shell.lifecycle.start()
        assert not shell.lifecycle.start()
        engine.dispatcher.publish(ConnectionOpened(snapshot()))
        QApplication.processEvents()
        # Use the real row selection to exercise all existing detail coordinators.
        shell.window.page_widget(PageId.CONNECTIONS).table.selectRow(0)
        QApplication.processEvents()
        dialog = ThreatIntelConsentDialog(service, shell.window)
        qtbot.addWidget(dialog)
        dialog.show()
        QApplication.processEvents()
        assert provider.calls == []
        submitted, tick = Event(), Event()
        tickets = []

        def explicit():
            tickets.append(scheduler.submit(query(consent=consent)).ticket)
            submitted.set()

        QTimer.singleShot(0, explicit)
        qtbot.waitUntil(submitted.is_set)
        assert provider.entered.wait(3) and not provider.release.is_set()
        QTimer.singleShot(0, tick.set)
        qtbot.waitUntil(tick.is_set)
        assert scheduler.poll(tickets[0]).state is L.IN_FLIGHT
        provider.release.set()
        qtbot.waitUntil(lambda: scheduler.poll(tickets[0]).terminal)
        assert shell.lifecycle.shutdown()
        assert shell.lifecycle.shutdown()
        assert engine.start_calls == engine.stop_calls == 1
    finally:
        provider.release.set()
        shell.lifecycle.shutdown()
        assert scheduler.stop()


@pytest.mark.parametrize("failure", ["false", "raise"])
def test_optional_ti_start_failure_does_not_stop_local_engine(qtbot, failure):
    class BrokenScheduler:
        starts = stops = 0

        def start(self):
            self.starts += 1
            if failure == "raise":
                raise RuntimeError("private error")
            return False

        def stop(self):
            self.stops += 1
            return True

    scheduler = BrokenScheduler()
    engine = FakeEngine()
    shell = create_application(engine, argv=[], threat_intel_scheduler=scheduler)
    qtbot.addWidget(shell.window)
    assert shell.lifecycle.start()
    assert engine.running
    assert shell.lifecycle.shutdown() and shell.lifecycle.shutdown()
    assert scheduler.starts == scheduler.stops == engine.stop_calls == 1

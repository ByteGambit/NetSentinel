"""NS-029 offscreen alert browsing, lifecycle and thread boundary tests."""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, enumerate as threads

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication

from netsentinel.application.ports import AlertQuery
from netsentinel.application.services.alert_query import AlertQueryService
from netsentinel.application.services.alerts import AlertService
from netsentinel.domain.alerts import (AlertCandidate, AlertEvidence, AlertStatus,
    ArpScoreComponent, ArpScoreRule)
from netsentinel.domain.observations import MacAddress
from netsentinel.presentation.alert_query import AlertQueryCoordinator
from netsentinel.presentation.app import create_application
from netsentinel.presentation.models.alerts import AlertColumn, AlertsTableModel
from netsentinel.presentation.views.alerts import AlertsView
from netsentinel.presentation.views.main_window import MainWindow, PageId


T0 = datetime(2026, 9, 23, 12, 0, 0, 123456, tzinfo=UTC)


def candidate(n: int, *, network="a" * 64, rule="ip_mac_conflict", severity="low", confidence="low"):
    return AlertCandidate(f"{n:064x}", rule, network, f"{network}:192.0.2.{n % 200 + 1}",
                          severity, confidence,
                          AlertEvidence(T0 + timedelta(seconds=n), f"192.0.2.{n % 200 + 1}",
                                        MacAddress("00:11:22:33:44:66"), MacAddress("00:11:22:33:44:55"),
                                        T0 - timedelta(seconds=1), score=2,
                                        breakdown=(ArpScoreComponent(ArpScoreRule.IDENTITY_CONFLICT, 2),)))


class Repository:
    def __init__(self):
        self.rows = {}
        self.calls = []
        self.failure = False
        self.started = Event()
        self.release = None

    def record(self, candidate, now, rate_window):
        from netsentinel.domain.alerts import Alert, alert_id
        old = self.rows.get(candidate.fingerprint)
        if old is None:
            alert = Alert(alert_id(candidate.fingerprint), candidate.fingerprint, candidate.rule_id,
                          candidate.network_fingerprint, candidate.entity_id, candidate.severity,
                          candidate.confidence, AlertStatus.OPEN, candidate.evidence.observed_at,
                          candidate.evidence.observed_at, 1, (candidate.evidence,), now, now, now)
        else:
            from dataclasses import replace
            alert = replace(old, last_seen=candidate.evidence.observed_at,
                            occurrence_count=old.occurrence_count + 1,
                            evidence=(old.evidence + (candidate.evidence,))[-8:])
        self.rows[candidate.fingerprint] = alert
        return alert, True

    def query(self, query, *, is_cancelled=None):
        self.calls.append(query)
        self.started.set()
        if self.release is not None:
            self.release.wait(2)
        if self.failure:
            raise RuntimeError("sqlite /private/db.sqlite SELECT traceback secret")
        rows = sorted(self.rows.values(), key=lambda a: (a.last_seen, str(a.id)), reverse=True)
        for field in ("rule_id", "network_fingerprint", "severity", "confidence", "status"):
            value = getattr(query, field)
            if value is not None:
                rows = [row for row in rows if getattr(row, field) == value]
        return tuple(rows[query.offset:query.offset + query.limit])

    def set_status(self, alert_id, status, now):
        from dataclasses import replace
        for key, row in self.rows.items():
            if row.id == alert_id:
                updated = replace(row, status=status, updated_at=now)
                self.rows[key] = updated
                return updated
        return None

    def get(self, alert_id):
        return next((row for row in self.rows.values() if row.id == alert_id), None)


def setup(qtbot, repo=None):
    repo = Repository() if repo is None else repo
    coordinator = AlertQueryCoordinator(lambda: AlertQueryService(AlertService(repo, clock=lambda: T0 + timedelta(days=1))))
    view = AlertsView(coordinator=coordinator)
    qtbot.addWidget(view)
    assert coordinator.start()
    view.show()
    qtbot.waitUntil(lambda: not view._loading)
    return repo, coordinator, view


def test_placeholder_empty_single_multiple_details_and_no_duplicates(qtbot):
    repo, coordinator, view = setup(qtbot)
    try:
        assert not hasattr(view, "description")
        assert view.state_label.text() == "No alerts yet."
        first = AlertService(repo, clock=lambda: T0 + timedelta(days=1)).record(candidate(1))[0]
        second = AlertService(repo, clock=lambda: T0 + timedelta(days=1)).record(
            candidate(2, network="b" * 64, rule="gateway_mac_change", severity="medium", confidence="moderate"))[0]
        view.refresh()
        qtbot.waitUntil(lambda: not view._loading and view.model.rowCount() == 2)
        assert {row.id for row in view.model.alerts} == {first.id, second.id}
        view.refresh()
        qtbot.waitUntil(lambda: not view._loading)
        assert view.model.rowCount() == 2
        row = view.model.row_for_id(second.id)
        view.table.selectRow(row)
        assert view.selected_alert_id == second.id
        assert view.model.data(view.model.index(row, AlertColumn.SEVERITY)) == "medium"
        assert view.model.data(view.model.index(row, AlertColumn.CONFIDENCE)) == "moderate"
        assert view.details.values["expected"].text() == "00:11:22:33:44:55"
        assert view.details.values["observed"].text() == "00:11:22:33:44:66"
        assert "bbbbbbbb" in view.details.values["network"].text()
        assert "Identity conflict" in view.details.evidence.toPlainText()
        assert "2026" in view.details.values["first"].text()
        assert "+" in view.details.values["last"].text()
        assert "payload" not in view.details.evidence.toPlainText().lower()
        assert "compromised" not in view.details.explanation.text().lower()
        assert "interception" not in view.details.explanation.text().lower()
    finally:
        assert coordinator.stop()


def test_filters_page_boundary_selection_and_ack_restart(qtbot):
    repo = Repository()
    alerts = AlertService(repo, clock=lambda: T0 + timedelta(days=1))
    for n in range(53):
        alerts.record(candidate(n + 1, severity="info" if n < 2 else "low"))
    _, coordinator, view = setup(qtbot, repo)
    try:
        assert view.model.rowCount() == 50 and view.next_button.isEnabled()
        first_id = view.model.alert_at(0).id
        view.table.selectRow(0)
        view.refresh()
        qtbot.waitUntil(lambda: not view._loading)
        assert view.selected_alert_id == first_id
        view.next_page()
        qtbot.waitUntil(lambda: not view._loading)
        assert view.page_index == 1 and view.model.rowCount() == 3
        assert not view.next_button.isEnabled()
        view.previous_page()
        qtbot.waitUntil(lambda: not view._loading)
        assert view.model.rowCount() == 50
        view.severity_filter.setCurrentIndex(view.severity_filter.findData("info"))
        qtbot.waitUntil(lambda: not view._loading and view.model.rowCount() == 2)
        assert view.page_index == 0 and view.selected_alert_id is None
        assert not view.next_button.isEnabled()
        view.table.selectRow(0)
        selected = view.selected_alert_id
        view.acknowledge_button.click()
        qtbot.waitUntil(lambda: repo.get(selected).status is AlertStatus.ACKNOWLEDGED)
        qtbot.waitUntil(lambda: not view._loading and view.model.alert_at(0).status is AlertStatus.ACKNOWLEDGED)
        assert view.selected_alert_id == selected
        assert not view.acknowledge_button.isEnabled()
        assert AlertService(repo).get(selected).status is AlertStatus.ACKNOWLEDGED
        view.status_filter.setCurrentIndex(view.status_filter.findData(AlertStatus.OPEN))
        qtbot.waitUntil(lambda: not view._loading and view.model.rowCount() == 1)
        assert view.selected_alert_id is None
        view.status_filter.setCurrentIndex(view.status_filter.findData(AlertStatus.RESOLVED))
        qtbot.waitUntil(lambda: not view._loading and view.model.rowCount() == 0)
        assert view.state_label.text() == "No alerts match the current filters."
    finally:
        assert coordinator.stop()


def test_slow_query_stale_result_error_and_bounded_shutdown(qtbot):
    repo, coordinator, view = setup(qtbot)
    try:
        repo.release = Event()
        repo.started.clear()
        view.refresh()
        assert repo.started.wait(1)
        heartbeat = Event()
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(0, heartbeat.set)
        qtbot.waitUntil(heartbeat.is_set)
        view.severity_filter.setCurrentIndex(view.severity_filter.findData("medium"))
        assert view._loading
        repo.release.set()
        qtbot.waitUntil(lambda: not view._loading)
        assert repo.calls[-1].severity == "medium"
        repo.failure = True
        view.refresh()
        qtbot.waitUntil(lambda: not view._loading)
        assert view.state_label.text() == "Alerts are unavailable. Try Refresh."
        assert all(term not in view.state_label.text() for term in ("sqlite", "SELECT", "traceback", "/private"))
    finally:
        assert coordinator.stop()
        assert not coordinator.worker_alive
        assert not any(t.name == "netsentinel-alert-query" and t.is_alive() for t in threads())


def test_accessibility_navigation_keyboard_and_layer_imports(qtbot):
    window = MainWindow()
    qtbot.addWidget(window)
    window.show()
    window.navigate_to(PageId.ALERTS)
    view = window.page_widget(PageId.ALERTS)
    assert isinstance(view, AlertsView)
    controls = (window.navigation, view, view.status_filter, view.severity_filter,
                view.confidence_filter, view.rule_filter, view.refresh_button, view.table,
                view.previous_button, view.next_button, view.details,
                view.details.evidence, view.acknowledge_button)
    assert all(widget.accessibleName().strip() for widget in controls)
    window.navigation.setFocus()
    qtbot.waitUntil(lambda: QApplication.focusWidget() is window.navigation)
    for expected in controls[2:7]:
        qtbot.keyClick(QApplication.focusWidget(), Qt.Key.Key_Tab)
        assert QApplication.focusWidget() is expected
    for root, forbidden in ((Path("src/netsentinel/presentation"), {"sqlite3", "scapy"}),
                            (Path("src/netsentinel/application"), {"PyQt6"}),
                            (Path("src/netsentinel/domain"), {"PyQt6"})):
        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
            imports += [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
            assert not any(name.split(".")[0] in forbidden for name in imports), path
    window.close()


def test_composed_alert_worker_stops_with_application(qtbot):
    from tests.gui.test_application_shell import FakeEngine

    repo = Repository()
    shell = create_application(FakeEngine(), alert_service_factory=lambda: AlertQueryService(AlertService(repo)))
    qtbot.addWidget(shell.window)
    assert shell.lifecycle.start()
    shell.window.show()
    shell.window.navigate_to(PageId.ALERTS)
    view = shell.window.page_widget(PageId.ALERTS)
    qtbot.waitUntil(lambda: not view._loading)
    assert shell.alert_queries.worker_alive
    shell.window.close()
    assert shell.lifecycle.shutdown_requested
    assert not shell.alert_queries.worker_alive
    assert not any(t.name == "netsentinel-alert-query" and t.is_alive() for t in threads())

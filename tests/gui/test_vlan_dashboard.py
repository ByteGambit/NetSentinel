"""NS-046 selected-scope VLAN dashboard and alert evidence presentation."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from threading import Event

from netsentinel.application.services.device_inventory import DeviceInventorySnapshot
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.alert_query import AlertQueryService
from netsentinel.domain.alerts import AlertCandidate, AlertEvidence
from netsentinel.domain.vlan_summary import VlanBaselineState, VlanIdSummary, VlanSummarySnapshot
from netsentinel.presentation.models.vlan import vlan_dashboard_state
from netsentinel.presentation.views.dashboard import DashboardView
from netsentinel.presentation.views.alerts import AlertDetailsWidget
from netsentinel.presentation.alert_query import AlertQueryCoordinator
from netsentinel.presentation.views.alerts import AlertsView
from netsentinel.presentation.device_inventory import DeviceInventoryCoordinator
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from tests.unit.infrastructure.test_scapy_capture import context


def _snapshot(state=VlanBaselineState.LEARNING):
    ctx = context()
    at = ctx.observed_at
    summary = VlanSummarySnapshot(
        ctx.fingerprint, ctx.interface_id.casefold(), ctx.interface_index,
        at, at + timedelta(seconds=61), at, state,
        4, 5, 1, 2, 3, 0,
        (VlanIdSummary(10, 3, at, at + timedelta(seconds=60), True),
         VlanIdSummary(20, 2, at + timedelta(seconds=61), at + timedelta(seconds=61))),
        at + timedelta(seconds=62) if state is VlanBaselineState.VERIFIED else None,
    )
    return DeviceInventorySnapshot((ctx,), ctx.fingerprint, (), None, vlan_summary=summary)


def test_dashboard_shows_persisted_scope_categories_and_visibility(qtbot):
    view = DashboardView()
    qtbot.addWidget(view)
    empty = DeviceInventorySnapshot((context(),), context().fingerprint, (), None)
    view.set_vlan_snapshot(empty)
    assert "No VLAN observations saved" in view.vlan_labels["status"].text()
    for state in (VlanBaselineState.LEARNING, VlanBaselineState.LEARNED, VlanBaselineState.VERIFIED):
        view.set_vlan_snapshot(_snapshot(state))
        assert state.value.title() in view.vlan_labels["baseline"].text()
    assert "Accepted" in view.vlan_labels["baseline"].text()
    assert view.vlan_labels["observed"].text() == "10, 20"
    assert view.vlan_labels["reference"].text() == "10"
    assert "VID 20: 2 frame(s)" in view.vlan_rows.toPlainText()
    counts = view.vlan_labels["counts"].text()
    for text in ("Tagged 5", "Untagged observed 4", "VID 0 1", "VID 4095 2",
                 "Stacked VLAN tag observed 3", "Overflow 0"):
        assert text in counts
    assert "offload" in view.vlan_labels["visibility"].text()
    assert "not a complete VLAN inventory" in view.vlan_labels["visibility"].text()
    assert view.vlan_rows.accessibleName()


def test_scope_filter_and_saved_observation_wording():
    snapshot = _snapshot(VlanBaselineState.VERIFIED)
    state = vlan_dashboard_state(snapshot)
    assert "Saved observations" in state.status
    other = context(interface_id="other", interface_index=7)
    stale = replace(snapshot, contexts=(other,), selected_fingerprint=other.fingerprint)
    assert "No VLAN observations saved" in vlan_dashboard_state(stale).status
    unavailable = replace(snapshot, vlan_summary_unavailable=True)
    assert "unavailable. Try refreshing" in vlan_dashboard_state(unavailable).status


def test_persisted_vlan_alert_details_are_evidence_aligned(qtbot, tmp_path):
    ctx = context()
    service = AlertService(SQLiteAlertRepository(SQLiteDatabase(tmp_path / "gui_alert.sqlite3")),
                           clock=lambda: ctx.observed_at)
    candidate = AlertCandidate(
        "a" * 64, "vlan_previously_unobserved_vid", ctx.fingerprint, "b" * 64,
        "low", "low", AlertEvidence(ctx.observed_at, observation_count=2,
                                     details=(("interface", "wifi#12"), ("vid", "20"),
                                              ("baseline", "verified_observed"),
                                              ("visibility", "capture_filter_and_nic_offload_limited"))),
    )
    alert, _ = service.record(candidate)
    details = AlertDetailsWidget()
    qtbot.addWidget(details)
    details.set_alert(alert)
    assert "Previously unobserved VLAN ID" in details.values["type"].text()
    assert "VID 20" in details.evidence.toPlainText().replace("vid: 20", "VID 20")
    assert "switch configuration is not verified" in details.evidence.toPlainText()
    assert "offload" in details.evidence.toPlainText()
    assert "hopping" in details.explanation.text().lower()


def test_persisted_vlan_alert_is_browsable_in_alerts_view(qtbot, tmp_path):
    ctx = context()
    db = SQLiteDatabase(tmp_path / "vlan_alerts_view.sqlite3")
    candidate = AlertCandidate(
        "c" * 64, "vlan_previously_unobserved_vid", ctx.fingerprint, "d" * 64,
        "low", "low", AlertEvidence(ctx.observed_at, observation_count=2,
                                     details=(("interface", "wifi#12"), ("vid", "30"),
                                              ("baseline", "verified_observed"))),
    )
    AlertService(SQLiteAlertRepository(db), clock=lambda: ctx.observed_at).record(candidate)
    coordinator = AlertQueryCoordinator(
        lambda: AlertQueryService(AlertService(SQLiteAlertRepository(db), clock=lambda: ctx.observed_at))
    )
    view = AlertsView(coordinator=coordinator)
    qtbot.addWidget(view)
    assert coordinator.start()
    try:
        view.show()
        qtbot.waitUntil(lambda: view.model.rowCount() == 1)
        assert "Previously unobserved VLAN ID" in view.model.data(view.model.index(0, 4))
        view.table.selectRow(0)
        assert "vid: 30" in view.details.evidence.toPlainText()
    finally:
        assert coordinator.stop()


def test_inventory_worker_suppresses_old_scope_after_selection_change(qtbot):
    a = context()
    b = context(interface_id="other", interface_index=7)
    started = Event()
    release = Event()

    class Service:
        def refresh(self, *, select=None, start_capture=False, stop_capture=False):
            if select == a.fingerprint:
                started.set()
                release.wait(2)
            return DeviceInventorySnapshot((a, b), select, (), None)

        def close(self):
            return True

    coordinator = DeviceInventoryCoordinator(Service)
    seen = []
    coordinator.snapshot_ready.connect(lambda snapshot: seen.append(snapshot.selected_fingerprint))
    assert coordinator.start()
    try:
        assert coordinator.request("select", a.fingerprint)
        assert started.wait(2)
        assert coordinator.request("select", b.fingerprint)
        release.set()
        qtbot.waitUntil(lambda: b.fingerprint in seen)
        assert seen == [b.fingerprint]
    finally:
        release.set()
        assert coordinator.stop()

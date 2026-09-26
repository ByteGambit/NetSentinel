"""NS-046: fake capture callback through persisted summaries and alerts."""

from __future__ import annotations

from datetime import timedelta

from netsentinel.application.detectors.vlan_anomaly import DEVICE_SWITCH_RULE, NEW_VID_RULE
from netsentinel.application.ports import AlertQuery
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.device_inventory import DeviceInventoryProblem, DeviceInventoryService
from netsentinel.application.services.vlan import VlanSummaryService
from netsentinel.domain.alerts import AlertStatus
from netsentinel.domain.vlan_summary import VlanBaselineState
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceRepository
from netsentinel.infrastructure.sqlite.vlan_repository import SQLiteVlanSummaryRepository
from netsentinel.presentation.models.vlan import vlan_dashboard_state
from netsentinel.presentation.views.dashboard import DashboardView
from netsentinel.presentation.views.alerts import AlertsView
from netsentinel.presentation.alert_query import AlertQueryCoordinator
from netsentinel.application.services.alert_query import AlertQueryService
from tests.fixtures.packets.vlan import tagged
from tests.unit.infrastructure.test_scapy_capture import FakeContextProvider, context, worker_for
from tests.integration.test_traffic_metrics_pipeline import Capture


def test_fake_capture_parser_consumer_verify_alert_restart_and_dedup(tmp_path):
    ctx = context()
    db = SQLiteDatabase(tmp_path / "vlan_end_to_end.sqlite3")
    at = [ctx.observed_at]

    def build():
        worker, _, backend = worker_for(FakeContextProvider((ctx,)), queue_capacity=16,
                                        clock=lambda: at[0])
        summary = VlanSummaryService(SQLiteVlanSummaryRepository(db), clock=lambda: at[0],
                                     warmup=timedelta(0))
        alerts = AlertService(SQLiteAlertRepository(db), clock=lambda: at[0])
        inventory = DeviceInventoryService(FakeContextProvider((ctx,)), SQLiteDeviceRepository(db),
                                           worker, alerts=alerts, vlan_summary=summary)
        inventory.refresh(start_capture=True)
        return inventory, summary, alerts, backend

    def emit(inventory, backend, vid, second):
        at[0] = ctx.observed_at + timedelta(seconds=second)
        backend.handles[0].emit(tagged(vid))
        return inventory.refresh()

    inventory, summary, alerts, backend = build()
    try:
        first = emit(inventory, backend, 10, 0)
        assert first.vlan_summary.baseline_state is VlanBaselineState.LEARNING
        learned = emit(inventory, backend, 10, 1)
        assert learned.vlan_summary.baseline_state is VlanBaselineState.LEARNED
        assert alerts.query(AlertQuery(10)) == ()
        assert "not accepted by the user" in vlan_dashboard_state(learned).baseline
        assert summary.verify_baseline(ctx).baseline_state is VlanBaselineState.VERIFIED
        assert summary.get(ctx).verified_at is not None
        known = emit(inventory, backend, 10, 2)
        assert not known.vlan_alert_changed
        assert not emit(inventory, backend, 20, 3).vlan_alert_changed
        confirmed = emit(inventory, backend, 20, 4)
        assert confirmed.vlan_alert_changed
        assert confirmed.vlan_summary.learned_vlan_ids == (10,)
        state = vlan_dashboard_state(confirmed)
        assert state.observed == "10, 20" and state.reference == "10"
        rows = alerts.query(AlertQuery(10))
        assert len(rows) == 1 and rows[0].rule_id == NEW_VID_RULE
        assert dict(rows[0].evidence[0].details)["vid"] == "20"
        assert b"secret" not in repr(rows).encode()
        assert not emit(inventory, backend, 20, 5).vlan_alert_changed
        alerts.acknowledge(rows[0].id)
    finally:
        assert inventory.close()

    inventory, summary, alerts, backend = build()
    try:
        assert summary.get(ctx).baseline_state is VlanBaselineState.VERIFIED
        assert summary.get(ctx).verified_at is not None
        emit(inventory, backend, 20, 6)
        emit(inventory, backend, 20, 7)
        rows = alerts.query(AlertQuery(10))
        assert len(rows) == 1 and rows[0].status is AlertStatus.ACKNOWLEDGED
        assert summary.get(ctx).learned_vlan_ids == (10,)
    finally:
        assert inventory.close()


def test_failed_alert_write_keeps_summary_and_retries(tmp_path):
    ctx = context()
    db = SQLiteDatabase(tmp_path / "vlan_retry.sqlite3")
    at = [ctx.observed_at]
    worker, _, backend = worker_for(FakeContextProvider((ctx,)), queue_capacity=16,
                                    clock=lambda: at[0])
    summary = VlanSummaryService(SQLiteVlanSummaryRepository(db), clock=lambda: at[0],
                                 warmup=timedelta(0))
    actual = AlertService(SQLiteAlertRepository(db), clock=lambda: at[0])

    class FailOnce:
        calls = 0

        def record(self, candidate):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("private write path")
            return actual.record(candidate)

    inventory = DeviceInventoryService(FakeContextProvider((ctx,)), SQLiteDeviceRepository(db),
                                       worker, alerts=FailOnce(), vlan_summary=summary)
    try:
        inventory.refresh(start_capture=True)
        for second, vid in enumerate((10, 10)):
            at[0] = ctx.observed_at + timedelta(seconds=second)
            backend.handles[0].emit(tagged(vid))
            inventory.refresh()
        summary.verify_baseline(ctx)
        for second in (2, 3):
            at[0] = ctx.observed_at + timedelta(seconds=second)
            backend.handles[0].emit(tagged(20))
            failed = inventory.refresh()
        assert failed.problem is DeviceInventoryProblem.ALERT_UNAVAILABLE
        assert failed.vlan_alert_changed is False
        assert summary.get(ctx).tagged_count == 4
        assert summary.get(ctx).learned_vlan_ids == (10,)
        assert actual.query(AlertQuery(10)) == ()
        retried = inventory.refresh()
        assert retried.vlan_alert_changed
        assert len(actual.query(AlertQuery(10))) == 1
    finally:
        assert inventory.close()


def test_distinct_vids_and_live_source_mac_device_change_stay_separate(tmp_path):
    ctx = context()
    db = SQLiteDatabase(tmp_path / "vlan_identities.sqlite3")
    at = [ctx.observed_at]
    worker, _, backend = worker_for(FakeContextProvider((ctx,)), queue_capacity=16,
                                    clock=lambda: at[0])
    summary = VlanSummaryService(SQLiteVlanSummaryRepository(db), clock=lambda: at[0],
                                 warmup=timedelta(0))
    alerts = AlertService(SQLiteAlertRepository(db), clock=lambda: at[0])
    inventory = DeviceInventoryService(FakeContextProvider((ctx,)), SQLiteDeviceRepository(db),
                                       worker, alerts=alerts, vlan_summary=summary)

    def emit(vid, source, second):
        at[0] = ctx.observed_at + timedelta(seconds=second)
        frame = tagged(vid)
        frame.src = source
        backend.handles[0].emit(frame)
        return inventory.refresh()

    try:
        inventory.refresh(start_capture=True)
        own = "02:11:22:33:44:55"
        other = "02:aa:bb:cc:dd:ee"
        emit(10, own, 0)
        emit(10, own, 1)
        summary.verify_baseline(ctx)
        assert alerts.query(AlertQuery(10)) == ()
        emit(20, other, 2)
        assert alerts.query(AlertQuery(10)) == ()
        emit(20, own, 3)
        emit(20, own, 4)
        emit(30, other, 5)
        emit(30, other, 6)
        rows = alerts.query(AlertQuery(10))
        assert sum(row.rule_id == NEW_VID_RULE for row in rows) == 2
        assert sum(row.rule_id == DEVICE_SWITCH_RULE for row in rows) == 1
        assert len({row.fingerprint for row in rows}) == 3
        assert summary.get(ctx).learned_vlan_ids == (10,)
    finally:
        assert inventory.close()


def test_vlan_read_failure_does_not_hide_other_inventory_or_expose_error(tmp_path):
    ctx = context()

    class FailedSummary:
        def get(self, _context):
            raise RuntimeError("private SQLite path and query")

    inventory = DeviceInventoryService(
        FakeContextProvider((ctx,)),
        SQLiteDeviceRepository(SQLiteDatabase(tmp_path / "vlan_read_failure.sqlite3")),
        Capture((), ctx), vlan_summary=FailedSummary(),
    )
    try:
        snapshot = inventory.refresh()
        assert snapshot.vlan_summary_unavailable
        assert snapshot.entries == ()
        assert snapshot.problem is DeviceInventoryProblem.OBSERVATION_UNAVAILABLE
        assert "private SQLite" not in repr(snapshot)
        assert "unavailable" in vlan_dashboard_state(snapshot).status
    finally:
        assert inventory.close()


def test_offscreen_dashboard_to_persisted_alerts_from_fake_capture(qtbot, tmp_path):
    ctx = context()
    db = SQLiteDatabase(tmp_path / "vlan_gui_end_to_end.sqlite3")
    at = [ctx.observed_at]
    worker, _, backend = worker_for(FakeContextProvider((ctx,)), queue_capacity=16,
                                    clock=lambda: at[0])
    summary = VlanSummaryService(SQLiteVlanSummaryRepository(db), clock=lambda: at[0],
                                 warmup=timedelta(0))
    inventory = DeviceInventoryService(
        FakeContextProvider((ctx,)), SQLiteDeviceRepository(db), worker,
        alerts=AlertService(SQLiteAlertRepository(db), clock=lambda: at[0]),
        vlan_summary=summary,
    )
    dashboard = DashboardView()
    qtbot.addWidget(dashboard)
    coordinator = AlertQueryCoordinator(
        lambda: AlertQueryService(AlertService(SQLiteAlertRepository(db), clock=lambda: at[0]))
    )
    alerts_view = AlertsView(coordinator=coordinator)
    qtbot.addWidget(alerts_view)
    try:
        inventory.refresh(start_capture=True)
        for second, vid in enumerate((10, 10)):
            at[0] = ctx.observed_at + timedelta(seconds=second)
            backend.handles[0].emit(tagged(vid))
            inventory.refresh()
        summary.verify_baseline(ctx)
        for second in (2, 3):
            at[0] = ctx.observed_at + timedelta(seconds=second)
            backend.handles[0].emit(tagged(20))
            snapshot = inventory.refresh()
        dashboard.set_vlan_snapshot(snapshot)
        assert "Verified" in dashboard.vlan_labels["baseline"].text()
        assert dashboard.vlan_labels["observed"].text() == "10, 20"
        assert coordinator.start()
        alerts_view.show()
        qtbot.waitUntil(lambda: alerts_view.model.rowCount() == 1)
        alerts_view.table.selectRow(0)
        assert "vid: 20" in alerts_view.details.evidence.toPlainText()
    finally:
        assert coordinator.stop()
        assert inventory.close()

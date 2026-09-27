"""NS-032 Windows configuration snapshot to persisted alert, with no LAN."""

from datetime import UTC, datetime, timedelta

from netsentinel.application.ports import AlertQuery
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.baselines import DnsServerBaselineService
from netsentinel.application.services.dns_config import DnsConfigMonitoringService
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.windows_network import (
    WindowsIPv4Address, WindowsNetworkAdapterSnapshot, WindowsNetworkContextProvider,
)


def test_windows_snapshot_change_reaches_existing_alert_storage(tmp_path):
    tick = [0]
    servers = [("1.1.1.1",), ("1.1.1.1",),
               ("8.8.8.8", "1.1.1.1"), ("1.1.1.1", "8.8.8.8")]

    def snapshots():
        return (WindowsNetworkAdapterSnapshot(
            "{WIFI}", 7, "Wi-Fi", "Wireless", 71, True,
            (WindowsIPv4Address("192.168.4.20", 24),),
            ("192.168.4.1",), servers[tick[0]],
        ),)

    def observed():
        return datetime(2026, 9, 23, 12, tzinfo=UTC) + timedelta(seconds=tick[0])
    provider = WindowsNetworkContextProvider(snapshot_provider=snapshots, clock=observed)
    alerts = AlertService(SQLiteAlertRepository(SQLiteDatabase(tmp_path / "alerts.sqlite3")), clock=observed)
    service = DnsConfigMonitoringService(provider, alerts,
                                         baseline=DnsServerBaselineService(clock=lambda: float(tick[0])))
    for n in range(4):
        tick[0] = n
        result = service.poll()
        assert len(result) == (1 if n == 3 else 0)

    stored = alerts.query(AlertQuery(limit=10))
    assert len(stored) == 1
    assert stored[0].rule_id == "dns_server_set_change"
    assert stored[0].network_fingerprint == provider.get_contexts()[0].fingerprint
    details = dict(stored[0].evidence[0].details)
    assert details["previous_dns"] == "1.1.1.1"
    assert details["current_dns"] == "1.1.1.1,8.8.8.8"
    assert "payload" not in repr(stored[0]).lower()

"""NS-032 configuration changes use only synthetic Windows context metadata."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from netsentinel.application.detectors.dns_config import RULE_ID
from netsentinel.application.services.baselines import DnsServerBaselineService
from netsentinel.application.services.dns_config import DnsConfigMonitoringService, DnsConfigPollError
from netsentinel.domain.devices import NetworkContext, NetworkInterfaceKind


T0 = datetime(2026, 9, 23, 12, tzinfo=UTC)


def context(n: int, servers=("1.1.1.1",), *, interface="wifi", subnet="192.168.1.0/24",
            gateway="192.168.1.1", kind=NetworkInterfaceKind.WIFI):
    return NetworkContext(interface, 4, interface, kind, subnet.split("/")[0][:-1] + "2",
                          subnet, gateway, tuple(servers), T0 + timedelta(seconds=n))


class Clock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


class ContextSequence:
    def __init__(self):
        self.current = ()

    def get_contexts(self):
        if isinstance(self.current, Exception):
            raise self.current
        return self.current


class Alerts:
    def __init__(self):
        self.records = []
        self.fail = False

    def record(self, candidate):
        if self.fail:
            raise RuntimeError("private database failure")
        self.records.append(candidate)


def setup_service(**baseline_options):
    clock = Clock()
    source = ContextSequence()
    alerts = Alerts()
    baseline = DnsServerBaselineService(clock=clock, **baseline_options)
    service = DnsConfigMonitoringService(source, alerts, baseline=baseline)
    return clock, source, alerts, baseline, service


def poll(clock, source, service, n, servers=("1.1.1.1",), **options):
    clock.value = float(n)
    source.current = (context(n, servers, **options),)
    return service.poll()


def test_stable_reorder_and_single_transient_read_do_not_alert():
    clock, source, alerts, baseline, service = setup_service()
    assert poll(clock, source, service, 0, ("8.8.8.8", "1.1.1.1")) == ()
    assert poll(clock, source, service, 1, ("1.1.1.1", "8.8.8.8")) == ()
    assert poll(clock, source, service, 2, ("8.8.8.8", "1.1.1.1")) == ()
    assert poll(clock, source, service, 3, ("9.9.9.9",)) == ()
    assert poll(clock, source, service, 4, ("1.1.1.1", "8.8.8.8")) == ()
    assert alerts.records == []
    assert baseline.tracked_contexts == 1


def test_add_and_remove_are_confirmed_with_old_new_evidence():
    clock, source, alerts, _, service = setup_service()
    for n, servers in enumerate((("1.1.1.1",), ("1.1.1.1",),
                                  ("1.1.1.1", "8.8.8.8"), ("8.8.8.8", "1.1.1.1"))):
        result = poll(clock, source, service, n, servers)
    assert len(result) == 1
    event = result[0]
    assert event.rule_id == RULE_ID
    assert (event.severity, event.confidence) == ("low", "moderate")
    assert event.evidence.observation_count == 2
    assert dict(event.evidence.details)["previous_dns"] == "1.1.1.1"
    assert dict(event.evidence.details)["current_dns"] == "1.1.1.1,8.8.8.8"
    assert len(alerts.records) == 1
    assert poll(clock, source, service, 4, ("1.1.1.1", "8.8.8.8")) == ()
    assert poll(clock, source, service, 5, ("8.8.8.8",)) == ()
    removed = poll(clock, source, service, 6, ("8.8.8.8",))
    assert dict(removed[0].evidence.details)["previous_dns"] == "1.1.1.1,8.8.8.8"
    assert dict(removed[0].evidence.details)["current_dns"] == "8.8.8.8"


def test_vpn_switch_has_separate_baseline_and_return_preserves_wifi():
    clock, source, alerts, baseline, service = setup_service()
    poll(clock, source, service, 0)
    poll(clock, source, service, 1)
    assert poll(clock, source, service, 2, ("10.0.0.1",), interface="vpn",
                subnet="10.2.0.0/24", gateway="10.2.0.1", kind=NetworkInterfaceKind.VPN) == ()
    assert poll(clock, source, service, 3, ("10.0.0.1",), interface="vpn",
                subnet="10.2.0.0/24", gateway="10.2.0.1", kind=NetworkInterfaceKind.VPN) == ()
    assert poll(clock, source, service, 4) == ()
    assert baseline.tracked_contexts == 2
    assert alerts.records == []


def test_empty_read_failure_and_provisional_baseline_are_not_alerts():
    clock, source, alerts, _, service = setup_service()
    poll(clock, source, service, 0, ("9.9.9.9",))
    poll(clock, source, service, 1, ("1.1.1.1",))
    poll(clock, source, service, 2, ("1.1.1.1",))
    assert poll(clock, source, service, 3, ()) == ()
    poll(clock, source, service, 4, ("8.8.8.8",))
    source.current = OSError("private platform detail")
    with pytest.raises(DnsConfigPollError, match="read unavailable"):
        service.poll()
    assert poll(clock, source, service, 5, ("8.8.8.8",)) == ()
    assert len(poll(clock, source, service, 6, ("8.8.8.8",))) == 1
    assert len(alerts.records) == 1


def test_stale_timestamp_or_clock_rollback_cannot_confirm():
    clock, source, alerts, _, service = setup_service()
    poll(clock, source, service, 0)
    poll(clock, source, service, 1)
    poll(clock, source, service, 2, ("8.8.8.8",))
    clock.value = 1.0
    source.current = (context(3, ("8.8.8.8",)),)
    assert service.poll() == ()
    clock.value = 3.0
    source.current = (context(1, ("8.8.8.8",)),)
    assert service.poll() == ()
    assert alerts.records == []
    assert poll(clock, source, service, 4, ("8.8.8.8",))


def test_capacity_eviction_and_idle_expiry_are_bounded():
    clock, source, alerts, baseline, service = setup_service(max_contexts=2, idle_expiry=5)
    poll(clock, source, service, 0)
    poll(clock, source, service, 1)
    poll(clock, source, service, 2, interface="ethernet", subnet="10.1.0.0/24", gateway="10.1.0.1")
    poll(clock, source, service, 3, interface="vpn", subnet="10.2.0.0/24", gateway="10.2.0.1")
    assert baseline.tracked_contexts == 2
    assert poll(clock, source, service, 4, ("8.8.8.8",)) == ()
    assert poll(clock, source, service, 10, ("8.8.8.8",)) == ()
    assert baseline.tracked_contexts == 1
    assert alerts.records == []


def test_failed_alert_write_retries_without_losing_change():
    clock, source, alerts, _, service = setup_service()
    poll(clock, source, service, 0)
    poll(clock, source, service, 1)
    poll(clock, source, service, 2, ("8.8.8.8",))
    alerts.fail = True
    with pytest.raises(DnsConfigPollError, match="detection unavailable"):
        poll(clock, source, service, 3, ("8.8.8.8",))
    alerts.fail = False
    assert len(poll(clock, source, service, 4, ("8.8.8.8",))) == 1
    assert len(alerts.records) == 1


def test_absent_interface_breaks_pending_change_but_preserves_baseline():
    clock, source, alerts, baseline, service = setup_service()
    poll(clock, source, service, 0)
    poll(clock, source, service, 1)
    poll(clock, source, service, 2, ("8.8.8.8",))
    clock.value = 3.0
    source.current = ()
    assert service.poll() == ()
    assert baseline.tracked_contexts == 1
    assert poll(clock, source, service, 4, ("8.8.8.8",)) == ()
    assert len(poll(clock, source, service, 5, ("8.8.8.8",))) == 1
    assert len(alerts.records) == 1


def test_eight_ipv4_addresses_fit_bounded_alert_evidence():
    clock, source, alerts, _, service = setup_service()
    poll(clock, source, service, 0)
    poll(clock, source, service, 1)
    addresses = tuple(f"255.255.255.{n}" for n in range(10, 18))
    poll(clock, source, service, 2, addresses)
    result = poll(clock, source, service, 3, addresses)
    assert len(result) == 1
    assert len(dict(result[0].evidence.details)["current_dns"]) <= 128
    assert len(alerts.records) == 1


def test_invalid_window_limits_are_rejected():
    with pytest.raises(ValueError):
        DnsServerBaselineService(max_contexts=0)
    with pytest.raises(ValueError):
        DnsServerBaselineService(idle_expiry=0)

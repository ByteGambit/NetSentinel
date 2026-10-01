"""NS-064 offscreen destination evidence, scope and presentation contracts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from threading import Event, current_thread
from uuid import uuid4

from PyQt6.QtCore import QObject, Qt, pyqtSignal

from netsentinel.application.services.destination_evidence import (
    DestinationEvidenceRequest, DestinationEvidenceResult, DestinationEvidenceService,
)
from netsentinel.domain.connections import (
    ConnectionNetworkScope, NetworkAttributionMethod, NetworkScopeStatus,
    ConnectionOpened, ConnectionSnapshot, ConnectionState, Endpoint, ProcessInfo,
    TransportProtocol, ConnectionHistoryRecord,
)
from netsentinel.domain.destination_context import (
    DestinationAddressKind, DestinationContext, DestinationContextStatus,
    DestinationDatasetSource,
)
from netsentinel.domain.dns import (
    DnsAssociationLookup, DnsAssociationProvenance, DnsAssociationStatus,
    DnsEvidenceId, DnsEvidenceSourceStatus, DnsRecordType, DnsTransport,
    DomainAssociation,
)
from netsentinel.presentation.destination_context import (
    DestinationEvidenceWidget, present_destination,
)
from netsentinel.presentation.views.connections import ConnectionsView
from netsentinel.presentation.views.history import HistoryView
from netsentinel.presentation.destination_query import DestinationQueryCoordinator


AT = datetime(2026, 10, 1, 12, tzinfo=UTC)
SCOPE = ConnectionNetworkScope(NetworkScopeStatus.RESOLVED, "a" * 64, "adapter", 1,
                               NetworkAttributionMethod.LOCAL_ADDRESS_MATCH)
SOURCE = DestinationDatasetSource("<local dataset>", "2026-10", "sample", AT)


def candidate(name: str, *, provenance=DnsAssociationProvenance.DIRECT_ANSWER,
              at: datetime = AT) -> DomainAssociation:
    derived = provenance is DnsAssociationProvenance.CNAME_DERIVED
    return DomainAssociation(
        domain=name, ip="1.2.3.4", record_type=DnsRecordType.A,
        provenance=provenance, queried_domain=name,
        answer_name="edge.example" if derived else name,
        cname_chain=(name, "edge.example") if derived else (),
        observed_at=at, ttl=60, answer_ttl=60, retention_seconds=60,
        network_fingerprint="a" * 64, client_ip="192.0.2.10",
        server_ip="192.0.2.53", transport=DnsTransport.UDP,
        transaction_id=1, query_at=at - timedelta(milliseconds=1),
        evidence_id=DnsEvidenceId(uuid4()),
    )


def context(status=DestinationContextStatus.MATCHED) -> DestinationContext:
    if status is DestinationContextStatus.MATCHED:
        return DestinationContext("1.2.3.4", DestinationAddressKind.PUBLIC, status,
                                  13335, "<Cloudflare>", "US", SOURCE)
    return DestinationContext("1.2.3.4", DestinationAddressKind.PUBLIC, status,
                              source=SOURCE if status is DestinationContextStatus.UNKNOWN else None)


class Reader:
    def __init__(self, candidates=()):
        self.candidates = candidates
        self.calls = []

    def overlapping_by_ip(self, ip, **kwargs):
        self.calls.append((ip, kwargs))
        return self.candidates


class Resolver:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def resolve(self, ip):
        self.calls.append(ip)
        return self.result


def test_ambiguous_direct_cname_freshness_and_plain_text(qtbot) -> None:
    direct, derived = candidate("a.example"), candidate("b.example", provenance=DnsAssociationProvenance.CNAME_DERIVED)
    result = DestinationEvidenceResult(
        DnsAssociationLookup(DnsAssociationStatus.AMBIGUOUS, (direct, derived)),
        context(), NetworkScopeStatus.RESOLVED, as_of=AT + timedelta(seconds=10),
        source_statuses=(DnsEvidenceSourceStatus.AVAILABLE, DnsEvidenceSourceStatus.SOURCE_UNAVAILABLE),
    )
    widget = DestinationEvidenceWidget()
    qtbot.addWidget(widget)
    widget.set_result(result)
    assert "Ambiguous" in widget.dns_status.text()
    assert "a.example." in widget.dns_candidates.text()
    assert "b.example." in widget.dns_candidates.text()
    assert "Direct DNS answer" in widget.dns_candidates.text()
    assert "CNAME-derived" in widget.dns_candidates.text()
    assert "TTL 60s; fresh" in widget.dns_candidates.text()
    assert "source DNS evidence expired" in widget.dns_candidates.text()
    assert "AS13335" in widget.context_details.text()
    assert "Country (IP dataset context): US" in widget.context_details.text()
    assert "<local dataset> v2026-10" in widget.context_details.text()
    assert "<Cloudflare>" in widget.context_details.text()
    assert widget.dns_candidates.textFormat() is Qt.TextFormat.PlainText
    assert widget.context_details.textFormat() is Qt.TextFormat.PlainText
    assert widget.evidence_references == (direct.evidence_id, derived.evidence_id)
    assert widget.dataset_source == SOURCE
    assert widget.dataset_source.license == "sample"
    assert widget.dns_group.accessibleName() != widget.context_group.accessibleName()
    assert "risk" not in (widget.dns_status.text() + widget.context_status.text()).lower()
    assert "hostname:" not in widget.dns_status.text().lower()


def test_empty_legacy_and_context_states() -> None:
    item = candidate("legacy.example")
    legacy = DestinationEvidenceResult(
        DnsAssociationLookup(DnsAssociationStatus.CORRELATED, (item,)),
        context(), NetworkScopeStatus.RESOLVED, as_of=AT + timedelta(seconds=90),
        source_statuses=(DnsEvidenceSourceStatus.UNKNOWN_LEGACY,), historical=True,
    )
    presented = present_destination(legacy)
    assert "expired by selected time" in presented.candidates[0].text
    assert "canonical evidence reference unavailable" in presented.candidates[0].text
    assert "current local IP dataset" in presented.context_status
    assert "No DNS association observed" in present_destination(DestinationEvidenceResult(
        DnsAssociationLookup(DnsAssociationStatus.UNKNOWN, ()), context(),
        NetworkScopeStatus.RESOLVED)).dns_status
    for status, expected in (
        (DestinationContextStatus.UNKNOWN, "No match"),
        (DestinationContextStatus.NOT_CONFIGURED, "not configured"),
        (DestinationContextStatus.DATASET_UNAVAILABLE, "unavailable"),
    ):
        assert expected in present_destination(DestinationEvidenceResult(
            DnsAssociationLookup(DnsAssociationStatus.UNKNOWN, ()), context(status),
            NetworkScopeStatus.RESOLVED)).context_status
    private = DestinationContext("10.0.0.1", DestinationAddressKind.PRIVATE,
                                 DestinationContextStatus.NOT_APPLICABLE)
    assert "does not apply" in present_destination(DestinationEvidenceResult(
        DnsAssociationLookup(DnsAssociationStatus.UNKNOWN, ()), private,
        NetworkScopeStatus.RESOLVED)).context_status


def test_scope_client_and_no_remote_do_not_query_other_evidence() -> None:
    reader = Reader((candidate("a.example"),))
    resolver = Resolver(context())
    service = DestinationEvidenceService(reader, resolver)
    for scope in (ConnectionNetworkScope.unknown(), ConnectionNetworkScope.ambiguous()):
        result = service.lookup(DestinationEvidenceRequest("1.2.3.4", "192.0.2.10", scope, AT, AT))
        assert result.dns.candidates == ()
        assert "network scope" in present_destination(result).dns_status
    assert reader.calls == []
    result = service.lookup(DestinationEvidenceRequest(None, "192.0.2.10", SCOPE, AT, AT))
    assert result.context is None
    assert len(resolver.calls) == 2
    result = service.lookup(DestinationEvidenceRequest("1.2.3.4", "192.0.2.10", SCOPE, AT, AT))
    assert result.dns.status is DnsAssociationStatus.CORRELATED
    assert reader.calls[0][1]["client_ip"] == "192.0.2.10"
    assert reader.calls[0][1]["network_scope"] == SCOPE


def test_source_failure_is_distinct_from_no_evidence_and_rows_are_bounded() -> None:
    class BrokenReader:
        def overlapping_by_ip(self, ip, **kwargs):
            raise RuntimeError("local storage unavailable")

    failed = DestinationEvidenceService(BrokenReader(), Resolver(context())).lookup(
        DestinationEvidenceRequest("1.2.3.4", "192.0.2.10", SCOPE, AT, AT)
    )
    assert "source unavailable" in present_destination(failed).dns_status
    many = DestinationEvidenceResult(
        DnsAssociationLookup(DnsAssociationStatus.AMBIGUOUS,
                             tuple(candidate(f"d{index}.example") for index in range(40))),
        context(), NetworkScopeStatus.RESOLVED,
    )
    assert len(present_destination(many).candidates) == 32


def test_historical_legacy_indicator_is_not_collapsed_to_no_evidence() -> None:
    class LegacySource:
        def source_status(self, evidence_id):
            return DnsEvidenceSourceStatus.UNKNOWN_LEGACY

        def legacy_ip_observed(self, ip, **kwargs):
            assert kwargs["network_fingerprint"] == "a" * 64
            assert kwargs["client_ip"] == "192.0.2.10"
            return True

    result = DestinationEvidenceService(Reader(), Resolver(context()), LegacySource()).lookup(
        DestinationEvidenceRequest("1.2.3.4", "192.0.2.10", SCOPE, AT, AT,
                                   historical=True)
    )
    assert result.legacy_unknown
    assert "Legacy DNS observation" in present_destination(result).dns_status


class FakeCoordinator(QObject):
    result_ready = pyqtSignal(int, object)
    query_failed = pyqtSignal(int)

    def __init__(self):
        super().__init__()
        self.requests = []

    def request(self, request):
        self.requests.append(request)
        return len(self.requests)


def test_live_selection_discards_stale_result_and_keeps_remote_identity(qtbot) -> None:
    coordinator = FakeCoordinator()
    view = ConnectionsView(destination_queries=coordinator)
    qtbot.addWidget(view)
    view.show()
    for port, remote in ((41001, "1.2.3.4"), (41002, "8.8.8.8")):
        snapshot = ConnectionSnapshot(
            TransportProtocol.TCP, Endpoint("192.0.2.10", port), Endpoint(remote, 443),
            ConnectionState.ESTABLISHED, ProcessInfo.unavailable(), AT,
            network_scope=SCOPE,
        )
        view.source_model.handle_connection_opened(ConnectionOpened(snapshot))
    view.table.selectRow(0)
    first = coordinator.requests[-1]
    view.table.selectRow(1)
    second = coordinator.requests[-1]
    assert first.remote_ip != second.remote_ip
    old = DestinationEvidenceResult(DnsAssociationLookup(DnsAssociationStatus.CORRELATED,
                                    (candidate("old.example"),)), context(), NetworkScopeStatus.RESOLVED)
    coordinator.result_ready.emit(len(coordinator.requests) - 1, old)
    assert "old.example" not in view.details.destination.dns_candidates.text()
    current = DestinationEvidenceResult(DnsAssociationLookup(DnsAssociationStatus.UNKNOWN, ()),
                                        context(), NetworkScopeStatus.RESOLVED)
    coordinator.result_ready.emit(len(coordinator.requests), current)
    assert "No DNS association observed" in view.details.destination.dns_status.text()
    assert view.selected_row_id is not None
    assert second.remote_ip == view.selected_row_id.remote_address


def test_listener_has_clean_no_remote_state_without_lookup(qtbot) -> None:
    coordinator = FakeCoordinator()
    view = ConnectionsView(destination_queries=coordinator)
    qtbot.addWidget(view)
    snapshot = ConnectionSnapshot(
        TransportProtocol.TCP, Endpoint("0.0.0.0", 41000), None,
        ConnectionState.LISTEN, ProcessInfo.unavailable(), AT,
    )
    view.source_model.handle_connection_opened(ConnectionOpened(snapshot))
    view.table.selectRow(0)
    assert coordinator.requests == []
    assert view.details.destination.dns_status.text() == "No remote destination."


def test_history_selection_uses_record_interval_and_current_dataset_label(qtbot) -> None:
    coordinator = FakeCoordinator()
    view = HistoryView(destination_queries=coordinator)
    qtbot.addWidget(view)
    snapshot = ConnectionSnapshot(
        TransportProtocol.TCP, Endpoint("192.0.2.10", 41001), Endpoint("1.2.3.4", 443),
        ConnectionState.ESTABLISHED, ProcessInfo.unavailable(), AT + timedelta(seconds=5),
        network_scope=SCOPE,
    )
    view.model.replace_records((ConnectionHistoryRecord(uuid4(), AT, AT + timedelta(seconds=5), snapshot,
                                                       network_scope_since=AT),))
    view.table.selectRow(0)
    request = coordinator.requests[-1]
    assert request.historical
    assert request.first_seen == AT
    assert request.last_seen == AT + timedelta(seconds=5)
    assert request.client_ip == "192.0.2.10"
    assert request.network_scope == SCOPE
    coordinator.result_ready.emit(1, DestinationEvidenceResult(
        DnsAssociationLookup(DnsAssociationStatus.UNKNOWN, ()), context(),
        NetworkScopeStatus.RESOLVED, historical=True,
    ))
    assert "current local IP dataset" in view.details.destination.context_status.text()


def test_worker_discards_obsolete_request_without_gui_thread_lookup(qtbot) -> None:
    started, release = Event(), Event()
    called_on = []

    class BlockingService:
        def lookup(self, request):
            called_on.append(current_thread().name)
            if request.remote_ip == "1.2.3.4":
                started.set()
                assert release.wait(3)
            return DestinationEvidenceResult(
                DnsAssociationLookup(DnsAssociationStatus.UNKNOWN, ()), context(),
                NetworkScopeStatus.RESOLVED,
            )

    coordinator = DestinationQueryCoordinator(lambda: BlockingService())
    assert coordinator.start()
    first = DestinationEvidenceRequest("1.2.3.4", "192.0.2.10", SCOPE, AT, AT)
    second = DestinationEvidenceRequest("8.8.8.8", "192.0.2.10", SCOPE, AT, AT)
    coordinator.request(first)
    qtbot.waitUntil(started.is_set, timeout=3000)
    expected = coordinator.request(second)
    with qtbot.waitSignal(coordinator.result_ready, timeout=3000) as signal:
        release.set()
    assert signal.args[0] == expected
    assert called_on == ["netsentinel-destination-query", "netsentinel-destination-query"]
    assert coordinator.stop()

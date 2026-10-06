"""NS-099 inert native/offscreen layout probe; isolated synthetic data only.

Freeze this entrypoint with the candidate's production PYZ. No monitoring,
capture, reputation request or production-profile database is used.
"""

import json
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from PyQt6.QtCore import QPoint, QTimer
from PyQt6.QtWidgets import QApplication

from netsentinel.application.services.incident_timeline import IncidentTimelineQueryService, TimelinePage, TimelineRequest
from netsentinel.domain.connections import (
    ConnectionClosureReason, ConnectionHistoryRecord, ConnectionSnapshot,
    ConnectionState, Endpoint, NetworkScopeStatus, ProcessIdentity, ProcessInfo,
    ProcessInfoStatus, TransportProtocol,
)
from netsentinel.domain.dns import (
    DnsAnswer, DnsHistoryRecord, DnsQuestion, DnsRecordType, DnsTransaction,
    DnsTransactionStatus, DnsTransport,
)
from netsentinel.domain.incident_persistence import (
    IncidentAction, IncidentOrigin, IncidentRecord, IncidentResult, IncidentState,
    IncidentStatus, stable_incident_id,
)
from netsentinel.domain.incidents import (
    IncidentConnectionRef, IncidentDestination, IncidentDestinationKind,
    CorrelatedIncident, IncidentObservationKind, IncidentObservationRef, IncidentProcessRef,
    IncidentRelation, IncidentRelationReason,
)
from netsentinel.domain.risk_evidence import EvidenceScope, EvidenceScopeKind
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.incident_repository import SQLiteIncidentRepository
from netsentinel.infrastructure.sqlite.incident_timeline_repository import SQLiteIncidentTimelineRepository
from netsentinel.presentation.views.dns import DnsView
from netsentinel.presentation.views.history import HistoryView
from netsentinel.presentation.views.incidents import IncidentsView
from netsentinel.presentation.views.main_window import MainWindow, PageId


def synthetic_rows(root: Path) -> tuple[tuple[ConnectionHistoryRecord, ...], tuple[DnsHistoryRecord, ...], tuple[IncidentResult, ...], TimelinePage]:
    at = datetime(2026, 10, 7, 9, 12, 34, 123456, tzinfo=UTC)
    session = UUID(int=9900)
    identity = ProcessIdentity(9901, at - timedelta(hours=1))
    histories, dns_records = [], []
    for i in range(12):
        stamp = at + timedelta(seconds=i)
        process = ProcessInfo(ProcessInfoStatus.AVAILABLE, identity, "synthetic-long-process-name-for-layout.exe")
        snapshot = ConnectionSnapshot(TransportProtocol.TCP,
            Endpoint("2001:db8:1234:5678:90ab:cdef:1234:5678", 40000 + i),
            Endpoint("2001:db8:4321:8765:abcd:ef90:4321:8765", 443),
            ConnectionState.ESTABLISHED, process, stamp)
        histories.append(ConnectionHistoryRecord(UUID(int=100 + i), stamp - timedelta(seconds=5),
            stamp, snapshot, closed_at=stamp + timedelta(seconds=2), close_reason=ConnectionClosureReason.NOT_OBSERVED))
        transaction = DnsTransaction(status=DnsTransactionStatus.COMPLETED, network_fingerprint="a" * 64,
            transport=DnsTransport.UDP, client_ip="192.0.2.20", client_port=53000 + i,
            server_ip="198.51.100.53", server_port=53, transaction_id=i,
            questions=(DnsQuestion("long.synthetic-layout.example", 28),), query_at=stamp,
            response_at=stamp + timedelta(milliseconds=12), latency_seconds=.012,
            response_code=0, truncated=False,
            answers=tuple(DnsAnswer("long.synthetic-layout.example", DnsRecordType.AAAA,
                f"2001:db8::{j + 1}", 3600) for j in range(16)), retry_count=0)
        dns_records.append(DnsHistoryRecord(UUID(int=200 + i), transaction))
    db = SQLiteDatabase(root / "synthetic.sqlite3")
    repository = SQLiteIncidentRepository(db)
    policy = repository.policy.correlation
    connection = IncidentConnectionRef(session, UUID(int=1))
    observation = IncidentObservationRef(IncidentObservationKind.CONNECTION_OBSERVED, connection, at)
    # Use only existing production-PYZ modules; no extra correlator/writer service.
    correlated = CorrelatedIncident(UUID(int=300), policy.cohort(at), at, at,
        processes=(IncidentProcessRef(session, identity),), connections=(connection,),
        destinations=(IncidentDestination(IncidentDestinationKind.IPV4, "192.0.2.99", 443, TransportProtocol.TCP),),
        scopes=(EvidenceScope(EvidenceScopeKind.NETWORK, NetworkScopeStatus.RESOLVED, "a" * 64),),
        relations=(IncidentRelation(observation, IncidentRelationReason.FIRST_OBSERVATION),))
    correlated = replace(correlated, incident_id=stable_incident_id(correlated, policy))
    synthetic = IncidentRecord(correlated, 1, IncidentState.OPEN, at + timedelta(seconds=1),
        at + timedelta(seconds=1), IncidentAction.CREATED, IncidentOrigin.SYSTEM_CORRELATION, correlation_policy=policy)
    record = repository.update(correlated.incident_id, lambda current: current or synthetic).record
    assert record is not None
    incidents = tuple(IncidentResult(IncidentStatus.FOUND,
        record if i == 0 else replace(record, snapshot=replace(record.snapshot, incident_id=UUID(int=300 + i)))) for i in range(12))
    page = IncidentTimelineQueryService(SQLiteIncidentTimelineRepository(db)).lookup(TimelineRequest(record.incident_id))
    assert isinstance(page, TimelinePage)
    return tuple(histories), tuple(dns_records), incidents, page


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: layout probe <isolated NS099Layout directory>")
    root = Path(sys.argv[1])
    if root.name != "NS099Layout":
        raise SystemExit("Only the isolated NS099Layout directory is allowed")
    root.mkdir(parents=True, exist_ok=True)
    rows = synthetic_rows(root)
    app = QApplication([])
    window = MainWindow()
    window.setWindowTitle("NetSentinel — synthetic layout acceptance")
    window.show()

    def poll() -> None:
        request = root / "command.json"
        if not request.exists():
            return
        command = json.loads(request.read_text(encoding="utf-8-sig"))
        request.unlink()
        if command.get("quit"):
            window.close()
            app.quit()
            return
        window.resize(*command.get("size", [1280, 720]))
        page_id = PageId(command["page"])
        window.navigate_to(page_id)
        view = window.page_widget(page_id)
        populated, selected = command.get("populated", True), command.get("selected", True)
        if isinstance(view, IncidentsView):
            view.model.set_entries(rows[2] if populated else ())
            view.state.setText("12 synthetic incident display rows; no monitoring." if populated else "No incidents in this synthetic layout preview.")
            first_record = rows[2][0].record
            assert first_record is not None
            view.select_incident(first_record.incident_id if populated and selected else None)
            if populated and selected:
                view._detail_generation = 1
                view._detail_ready(1, rows[3])
        elif isinstance(view, DnsView):
            view.model.replace_records(rows[1] if populated else ())
            view.state_label.setText("12 synthetic DNS records; capture is not running." if populated else "No DNS history in this synthetic layout preview.")
            view.details.clear()
        elif isinstance(view, HistoryView):
            view.model.replace_records(rows[0] if populated else ())
            view.state_label.setText("12 synthetic connection records; no monitoring." if populated else "No history in this synthetic layout preview.")
            view.details.clear()
        else:
            raise ValueError("Only NS-099 affected pages are allowed")
        if populated and selected:
            view.table.selectRow(0)
        app.processEvents()
        if isinstance(view, DnsView) and command.get("detail_target") in ("questions", "answers"):
            view.details.detail_scroll.ensureWidgetVisible(getattr(view.details, command["detail_target"]))
        if isinstance(view, HistoryView) and command.get("right"):
            bar = view.table.horizontalScrollBar()
            assert bar is not None
            bar.setValue(bar.maximum())
        QTimer.singleShot(400, lambda: snapshot(command))

    def snapshot(command: dict) -> None:
        view = window.page_widget(window.current_page)
        assert isinstance(view, (DnsView, IncidentsView, HistoryView))
        table, vertical, viewport = view.table, view.table.verticalHeader(), view.table.viewport()
        model = table.model()
        assert vertical is not None and viewport is not None and model is not None
        window.grab().save(str(root / "window.png"))
        position = table.mapTo(window, QPoint())
        screen = app.primaryScreen()
        assert screen is not None
        result = {"fixture": "synthetic isolated native UI; exact candidate production PYZ",
            "page": window.current_page.value, "requested": command,
            "window": [window.width(), window.height()], "table": [table.width(), table.height()],
            "table_position": [position.x(), position.y()],
            "visible_rows": viewport.height() // vertical.defaultSectionSize(),
            "model_rows": model.rowCount(),
            "columns": [table.columnWidth(i) for i in range(model.columnCount())],
            "screen": [screen.size().width(), screen.size().height()],
            "logical_dpi": screen.logicalDotsPerInch(), "device_pixel_ratio": screen.devicePixelRatio()}
        (root / "result.json").write_text(json.dumps(result), encoding="utf-8")

    timer = QTimer()
    timer.setInterval(200)
    timer.timeout.connect(poll)
    timer.start()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

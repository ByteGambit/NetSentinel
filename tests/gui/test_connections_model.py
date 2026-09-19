"""Offscreen contract tests for the incremental connections table model."""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Thread

import pytest
from PyQt6.QtCore import QModelIndex, Qt
from PyQt6.QtTest import QAbstractItemModelTester

from netsentinel.domain.connections import (
    ConnectionClosed,
    ConnectionOpened,
    ConnectionSnapshot,
    ConnectionState,
    ConnectionUpdated,
    Endpoint,
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
    TransportProtocol,
)
from netsentinel.presentation.bridge import ConnectionEventBatch
from netsentinel.presentation.models.connections import (
    ConnectionColumn,
    ConnectionRole,
    ConnectionsTableModel,
    HEADERS,
)
from netsentinel.presentation.viewmodels import (
    ConnectionRowId,
    MISSING_VALUE,
    connection_row_from_snapshot,
)


BASE_TIME = datetime(2026, 9, 19, 8, 0, tzinfo=UTC)
CREATE_TIME = BASE_TIME - timedelta(minutes=5)


def _process(
    *,
    pid: int = 4242,
    name: str = "browser.exe",
    create_time: datetime = CREATE_TIME,
) -> ProcessInfo:
    return ProcessInfo(
        status=ProcessInfoStatus.AVAILABLE,
        identity=ProcessIdentity(pid=pid, create_time=create_time),
        name=name,
    )


def _snapshot(
    *,
    protocol: TransportProtocol = TransportProtocol.TCP,
    local_address: str = "192.168.1.15",
    local_port: int = 53124,
    remote_address: str | None = "93.184.216.34",
    remote_port: int | None = 443,
    state: ConnectionState = ConnectionState.ESTABLISHED,
    process: ProcessInfo | None = None,
    observed_at: datetime = BASE_TIME,
) -> ConnectionSnapshot:
    if remote_address is None:
        remote_endpoint = None
    else:
        assert remote_port is not None
        remote_endpoint = Endpoint(remote_address, remote_port)
    return ConnectionSnapshot(
        protocol=protocol,
        local_endpoint=Endpoint(local_address, local_port),
        remote_endpoint=remote_endpoint,
        state=state,
        process=_process() if process is None else process,
        observed_at=observed_at,
    )


def _display(
    model: ConnectionsTableModel,
    row: int,
    column: ConnectionColumn,
) -> object:
    return model.data(
        model.index(row, int(column)),
        int(Qt.ItemDataRole.DisplayRole),
    )


def _raw(
    model: ConnectionsTableModel,
    row: int,
    role: ConnectionRole,
) -> object:
    return model.data(model.index(row, 0), int(role))


def test_empty_shape_headers_and_model_contract(qtbot) -> None:
    model = ConnectionsTableModel()
    tester = QAbstractItemModelTester(
        model,
        QAbstractItemModelTester.FailureReportingMode.Warning,
        model,
    )

    assert tester.model() is model
    assert model.rowCount() == 0
    assert model.columnCount() == 7
    assert tuple(
        model.headerData(
            column,
            Qt.Orientation.Horizontal,
            int(Qt.ItemDataRole.DisplayRole),
        )
        for column in range(model.columnCount())
    ) == HEADERS


def test_open_inserts_display_and_raw_values_without_reset(qtbot) -> None:
    model = ConnectionsTableModel()
    inserted: list[tuple[int, int]] = []
    resets: list[bool] = []
    model.rowsInserted.connect(
        lambda _parent, first, last: inserted.append((first, last))
    )
    model.modelReset.connect(lambda: resets.append(True))

    model.handle_connection_opened(ConnectionOpened(_snapshot()))

    assert inserted == [(0, 0)]
    assert resets == []
    assert model.rowCount() == 1
    assert _display(model, 0, ConnectionColumn.PROCESS) == "browser.exe"
    assert _display(model, 0, ConnectionColumn.PID) == "4242"
    assert _display(model, 0, ConnectionColumn.PROTOCOL) == "TCP"
    assert _display(model, 0, ConnectionColumn.LOCAL_ENDPOINT) == (
        "192.168.1.15:53124"
    )
    assert _display(model, 0, ConnectionColumn.REMOTE_ENDPOINT) == (
        "93.184.216.34:443"
    )
    assert _display(model, 0, ConnectionColumn.STATE) == "Established"
    assert _display(model, 0, ConnectionColumn.DURATION) == "00:00:00"

    assert isinstance(_raw(model, 0, ConnectionRole.ROW_ID), ConnectionRowId)
    assert _raw(model, 0, ConnectionRole.RAW_PROTOCOL) == "tcp"
    assert _raw(model, 0, ConnectionRole.RAW_STATE) == "established"
    assert _raw(model, 0, ConnectionRole.RAW_PROCESS) == "browser.exe"
    assert _raw(model, 0, ConnectionRole.RAW_PID) == 4242
    assert _raw(model, 0, ConnectionRole.RAW_LOCAL_ADDRESS) == "192.168.1.15"
    assert _raw(model, 0, ConnectionRole.RAW_LOCAL_PORT) == 53124
    assert _raw(model, 0, ConnectionRole.RAW_REMOTE_ADDRESS) == "93.184.216.34"
    assert _raw(model, 0, ConnectionRole.RAW_REMOTE_PORT) == 443
    assert _raw(model, 0, ConnectionRole.DURATION) == 0.0


def test_two_open_events_create_distinct_rows_and_duplicate_is_noop(qtbot) -> None:
    model = ConnectionsTableModel()
    inserted: list[tuple[int, int]] = []
    changed: list[bool] = []
    model.rowsInserted.connect(
        lambda _parent, first, last: inserted.append((first, last))
    )
    model.dataChanged.connect(lambda *_args: changed.append(True))
    first = ConnectionOpened(_snapshot())
    second = ConnectionOpened(
        _snapshot(local_port=53125, remote_port=8443, process=_process(pid=4243))
    )

    model.handle_connection_opened(first)
    model.handle_connection_opened(second)
    model.handle_connection_opened(first)

    assert model.rowCount() == 2
    assert inserted == [(0, 0), (1, 1)]
    assert changed == []
    assert _raw(model, 0, ConnectionRole.RAW_LOCAL_PORT) == 53124
    assert _raw(model, 1, ConnectionRole.RAW_LOCAL_PORT) == 53125


def test_update_changes_correct_row_preserves_identity_and_order(qtbot) -> None:
    model = ConnectionsTableModel()
    first = _snapshot()
    other = _snapshot(local_port=60000, process=_process(pid=6000))
    current = _snapshot(
        process=_process(name="renamed.exe"),
        state=ConnectionState.CLOSE_WAIT,
        observed_at=BASE_TIME + timedelta(seconds=65),
    )
    model.handle_connection_opened(ConnectionOpened(first))
    model.handle_connection_opened(ConnectionOpened(other))
    first_id = _raw(model, 0, ConnectionRole.ROW_ID)
    other_id = _raw(model, 1, ConnectionRole.ROW_ID)
    changes: list[tuple[int, int, int, int, list[int]]] = []
    resets: list[bool] = []
    model.dataChanged.connect(
        lambda left, right, roles: changes.append(
            (left.row(), left.column(), right.row(), right.column(), roles)
        )
    )
    model.modelReset.connect(lambda: resets.append(True))

    model.handle_connection_updated(ConnectionUpdated(first, current))

    assert len(changes) == 1
    assert changes[0][:4] == (0, 0, 0, 6)
    assert int(Qt.ItemDataRole.DisplayRole) in changes[0][4]
    assert int(ConnectionRole.ROW_ID) in changes[0][4]
    assert resets == []
    assert _raw(model, 0, ConnectionRole.ROW_ID) == first_id
    assert _raw(model, 1, ConnectionRole.ROW_ID) == other_id
    assert _display(model, 0, ConnectionColumn.PROCESS) == "renamed.exe"
    assert _display(model, 0, ConnectionColumn.STATE) == "Close Wait"
    assert _display(model, 0, ConnectionColumn.DURATION) == "00:01:05"
    assert _raw(model, 0, ConnectionRole.DURATION) == 65.0


def test_close_removes_only_matching_row_and_repairs_lookup(qtbot) -> None:
    model = ConnectionsTableModel()
    first = _snapshot()
    second = _snapshot(local_port=53125, process=_process(pid=5252))
    third = _snapshot(local_port=53126, process=_process(pid=6262))
    for snapshot in (first, second, third):
        model.handle_connection_opened(ConnectionOpened(snapshot))
    removed: list[tuple[int, int]] = []
    resets: list[bool] = []
    model.rowsRemoved.connect(
        lambda _parent, first_row, last_row: removed.append(
            (first_row, last_row)
        )
    )
    model.modelReset.connect(lambda: resets.append(True))

    model.handle_connection_closed(
        ConnectionClosed(second, BASE_TIME + timedelta(seconds=1))
    )

    assert removed == [(1, 1)]
    assert resets == []
    assert model.rowCount() == 2
    assert _raw(model, 0, ConnectionRole.RAW_PID) == 4242
    assert _raw(model, 1, ConnectionRole.RAW_PID) == 6262

    model.handle_connection_closed(
        ConnectionClosed(third, BASE_TIME + timedelta(seconds=2))
    )
    assert model.rowCount() == 1
    assert removed[-1] == (1, 1)


def test_ipv6_udp_and_missing_remote_are_safely_formatted(qtbot) -> None:
    model = ConnectionsTableModel()
    snapshot = _snapshot(
        protocol=TransportProtocol.UDP,
        local_address="2001:db8::1",
        local_port=5353,
        remote_address=None,
        remote_port=None,
        state=ConnectionState.NONE,
    )

    model.handle_connection_opened(ConnectionOpened(snapshot))

    assert _display(model, 0, ConnectionColumn.PROTOCOL) == "UDP"
    assert _display(model, 0, ConnectionColumn.LOCAL_ENDPOINT) == (
        "[2001:db8::1]:5353"
    )
    assert _display(model, 0, ConnectionColumn.REMOTE_ENDPOINT) == MISSING_VALUE
    assert _display(model, 0, ConnectionColumn.STATE) == MISSING_VALUE
    assert _raw(model, 0, ConnectionRole.RAW_REMOTE_ADDRESS) is None
    assert _raw(model, 0, ConnectionRole.RAW_REMOTE_PORT) is None


@pytest.mark.parametrize(
    ("process", "expected_pid"),
    [
        (ProcessInfo.unavailable(), None),
        (
            ProcessInfo(
                status=ProcessInfoStatus.ACCESS_DENIED,
                identity=ProcessIdentity(777),
            ),
            777,
        ),
    ],
)
def test_missing_process_metadata_has_safe_placeholders(
    qtbot,
    process: ProcessInfo,
    expected_pid: int | None,
) -> None:
    model = ConnectionsTableModel()
    model.handle_connection_opened(ConnectionOpened(_snapshot(process=process)))

    assert _display(model, 0, ConnectionColumn.PROCESS) == MISSING_VALUE
    assert _display(model, 0, ConnectionColumn.PID) == (
        str(expected_pid) if expected_pid is not None else MISSING_VALUE
    )
    assert _raw(model, 0, ConnectionRole.RAW_PROCESS) is None
    assert _raw(model, 0, ConnectionRole.RAW_PID) == expected_pid


def test_duration_never_becomes_negative() -> None:
    snapshot = _snapshot()
    row = connection_row_from_snapshot(
        snapshot,
        first_seen=BASE_TIME + timedelta(minutes=1),
    )

    assert row.duration_seconds == 0.0
    assert row.duration_display == "00:00:00"


def test_pid_reuse_with_new_create_time_keeps_distinct_identity(qtbot) -> None:
    model = ConnectionsTableModel()
    old_process = _process(pid=99, create_time=CREATE_TIME)
    new_process = _process(
        pid=99,
        create_time=CREATE_TIME + timedelta(minutes=1),
    )

    model.handle_connection_opened(
        ConnectionOpened(_snapshot(process=old_process))
    )
    model.handle_connection_opened(
        ConnectionOpened(_snapshot(process=new_process))
    )

    assert model.rowCount() == 2
    assert _raw(model, 0, ConnectionRole.ROW_ID) != _raw(
        model,
        1,
        ConnectionRole.ROW_ID,
    )
    assert _raw(model, 0, ConnectionRole.RAW_PID) == 99
    assert _raw(model, 1, ConnectionRole.RAW_PID) == 99


def test_unknown_update_recovers_and_unknown_close_is_noop(qtbot) -> None:
    model = ConnectionsTableModel()
    previous = _snapshot()
    current = _snapshot(
        state=ConnectionState.TIME_WAIT,
        observed_at=BASE_TIME + timedelta(seconds=2),
    )
    inserted: list[tuple[int, int]] = []
    removed: list[bool] = []
    model.rowsInserted.connect(
        lambda _parent, first, last: inserted.append((first, last))
    )
    model.rowsRemoved.connect(lambda *_args: removed.append(True))

    model.handle_connection_updated(ConnectionUpdated(previous, current))
    model.handle_connection_closed(
        ConnectionClosed(
            _snapshot(local_port=9999, process=_process(pid=9999)),
            BASE_TIME + timedelta(seconds=3),
        )
    )

    assert model.rowCount() == 1
    assert inserted == [(0, 0)]
    assert removed == []
    assert _display(model, 0, ConnectionColumn.STATE) == "Time Wait"
    assert _raw(model, 0, ConnectionRole.DURATION) == 2.0


def test_ordered_batch_sequence_is_incremental_and_never_resets(qtbot) -> None:
    model = ConnectionsTableModel()
    tester = QAbstractItemModelTester(
        model,
        QAbstractItemModelTester.FailureReportingMode.Warning,
        model,
    )
    first = _snapshot()
    second = _snapshot(local_port=60000, process=_process(pid=6000))
    first_updated = _snapshot(
        state=ConnectionState.FIN_WAIT_1,
        observed_at=BASE_TIME + timedelta(seconds=3),
    )
    resets: list[bool] = []
    model.modelReset.connect(lambda: resets.append(True))

    model.handle_events(
        ConnectionEventBatch(
            (
                ConnectionOpened(first),
                ConnectionOpened(second),
                ConnectionUpdated(first, first_updated),
                ConnectionClosed(second, BASE_TIME + timedelta(seconds=4)),
            )
        )
    )

    assert model.rowCount() == 1
    assert _raw(model, 0, ConnectionRole.RAW_PID) == 4242
    assert _display(model, 0, ConnectionColumn.STATE) == "Fin Wait 1"
    assert resets == []
    assert tester.model() is model


def test_stale_close_does_not_remove_a_newer_same_identity_row(qtbot) -> None:
    model = ConnectionsTableModel()
    first = _snapshot()
    newer = _snapshot(observed_at=BASE_TIME + timedelta(seconds=5))
    model.handle_connection_opened(ConnectionOpened(first))
    model.handle_connection_opened(ConnectionOpened(newer))

    model.handle_connection_closed(
        ConnectionClosed(first, BASE_TIME + timedelta(seconds=1))
    )

    assert model.rowCount() == 1


def test_mutation_from_non_model_thread_is_rejected(qtbot) -> None:
    model = ConnectionsTableModel()
    errors: list[BaseException] = []

    def mutate() -> None:
        try:
            model.handle_connection_opened(ConnectionOpened(_snapshot()))
        except BaseException as error:
            errors.append(error)

    worker = Thread(target=mutate)
    worker.start()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], RuntimeError)
    assert model.rowCount() == 0


def test_invalid_indexes_and_role_names_are_safe(qtbot) -> None:
    model = ConnectionsTableModel()

    assert model.data(QModelIndex()) is None
    assert model.headerData(
        99,
        Qt.Orientation.Horizontal,
        int(Qt.ItemDataRole.DisplayRole),
    ) is None
    assert model.roleNames()[int(ConnectionRole.ROW_ID)] == b"rowId"
    assert model.roleNames()[int(ConnectionRole.DURATION)] == b"duration"


def test_presentation_model_does_not_import_infrastructure_or_io_libraries() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    paths = (
        repository_root
        / "src"
        / "netsentinel"
        / "presentation"
        / "models"
        / "connections.py",
        repository_root
        / "src"
        / "netsentinel"
        / "presentation"
        / "viewmodels.py",
    )

    imported: set[str] = set()
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        imported.update(
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )

    blocked_roots = {"psutil", "scapy", "sqlite3"}
    assert not any(name.split(".", 1)[0].lower() in blocked_roots for name in imported)
    assert not any(
        name == "netsentinel.infrastructure"
        or name.startswith("netsentinel.infrastructure.")
        for name in imported
    )


def test_domain_and_application_layers_do_not_import_pyqt6() -> None:
    repository_root = Path(__file__).resolve().parents[2]
    source_root = repository_root / "src" / "netsentinel"

    for layer in ("domain", "application"):
        for path in (source_root / layer).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imported = {
                alias.name
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            }
            imported.update(
                node.module
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            )
            assert not any(name == "PyQt6" or name.startswith("PyQt6.") for name in imported)

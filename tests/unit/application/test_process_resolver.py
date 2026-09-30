"""Unit tests for application-level process metadata enrichment."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import inspect

from netsentinel.application import ports
from netsentinel.application.ports import ProcessMetadataResolver
from netsentinel.application.services import processes
from netsentinel.application.services.processes import ProcessMetadataEnricher
from netsentinel.domain import connections
from netsentinel.domain.connections import (
    ConnectionSnapshot,
    ConnectionState,
    Endpoint,
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
    ParentProcessStatus,
    TransportProtocol,
)
from netsentinel.infrastructure.psutil_processes import PsutilProcessMetadataResolver


OBSERVED_AT = datetime(2026, 9, 18, 9, 30, tzinfo=UTC)
STARTED_AT = datetime(2026, 9, 18, 8, 0, tzinfo=UTC)


def snapshot(*, pid: int | None, port: int = 50_000) -> ConnectionSnapshot:
    process = ProcessInfo.unavailable()
    if pid is not None:
        process = ProcessInfo(
            status=ProcessInfoStatus.UNAVAILABLE,
            identity=ProcessIdentity(pid=pid),
        )
    return ConnectionSnapshot(
        protocol=TransportProtocol.TCP,
        local_endpoint=Endpoint("192.0.2.10", port),
        remote_endpoint=Endpoint("203.0.113.20", 443),
        state=ConnectionState.ESTABLISHED,
        process=process,
        observed_at=OBSERVED_AT,
    )


def available(pid: int, create_time: datetime = STARTED_AT) -> ProcessInfo:
    return ProcessInfo(
        status=ProcessInfoStatus.AVAILABLE,
        identity=ProcessIdentity(pid=pid, create_time=create_time),
        name=f"process-{pid}.exe",
    )


class FakeResolver:
    def __init__(self, results: dict[int, ProcessInfo | Exception]) -> None:
        self.results = results
        self.calls: list[int] = []

    def resolve(self, pid: int) -> ProcessInfo:
        self.calls.append(pid)
        result = self.results[pid]
        if isinstance(result, Exception):
            raise result
        return result


def test_enricher_accepts_port_and_enriches_process_name_and_identity() -> None:
    resolver: ProcessMetadataResolver = FakeResolver({42: available(42)})

    result = ProcessMetadataEnricher(resolver).enrich([snapshot(pid=42)])

    assert result[0].process == available(42)
    assert result[0].key.process_identity == ProcessIdentity(42, STARTED_AT)


def test_pass_local_cache_resolves_repeated_pid_only_once() -> None:
    resolver = FakeResolver({42: available(42)})
    source = [snapshot(pid=42), snapshot(pid=42, port=50_001)]

    result = ProcessMetadataEnricher(resolver).enrich(source)

    assert resolver.calls == [42]
    assert [item.process for item in result] == [available(42), available(42)]


def test_pass_local_cache_reads_executable_path_only_once() -> None:
    class CountingProcess:
        exe_calls = 0

        def create_time(self) -> float:
            return STARTED_AT.timestamp()

        def name(self) -> str:
            return "browser.exe"

        def exe(self) -> str:
            self.exe_calls += 1
            return "C:\\Apps\\browser.exe"

    process = CountingProcess()
    resolver = PsutilProcessMetadataResolver(process_factory=lambda pid: process)
    source = [snapshot(pid=42), snapshot(pid=42, port=50_001)]

    result = ProcessMetadataEnricher(resolver).enrich(source)

    assert process.exe_calls == 1
    assert all(
        item.process.executable_path == "C:\\Apps\\browser.exe" for item in result
    )


def test_pass_local_cache_resolves_parent_only_once_per_child() -> None:
    class CountingProcess:
        def __init__(self, pid: int) -> None:
            self.pid = pid

        def create_time(self) -> float:
            return (
                STARTED_AT - timedelta(hours=1) if self.pid == 7 else STARTED_AT
            ).timestamp()

        def name(self) -> str:
            return "parent.exe" if self.pid == 7 else "child.exe"

        def exe(self) -> str:
            return "C:\\Apps\\child.exe"

        def ppid(self) -> int:
            return 7 if self.pid == 42 else 0

    calls: list[int] = []

    def factory(pid: int) -> CountingProcess:
        calls.append(pid)
        return CountingProcess(pid)

    resolver = PsutilProcessMetadataResolver(
        process_factory=factory, clock=lambda: OBSERVED_AT
    )
    result = ProcessMetadataEnricher(resolver).enrich(
        [snapshot(pid=42), snapshot(pid=42, port=50_001)]
    )

    assert calls == [42, 7, 7]
    assert all(item.process.parent is not None for item in result)
    assert result[0].process.parent is result[1].process.parent
    assert result[0].process.parent.status is ParentProcessStatus.OBSERVED


def test_cache_does_not_cross_snapshot_passes_and_exposes_pid_reuse() -> None:
    second_start = STARTED_AT + timedelta(hours=1)

    class ReusedPidResolver:
        calls = 0

        def resolve(self, pid: int) -> ProcessInfo:
            self.calls += 1
            create_time = STARTED_AT if self.calls == 1 else second_start
            return available(pid, create_time)

    resolver = ReusedPidResolver()
    enricher = ProcessMetadataEnricher(resolver)

    first = enricher.enrich([snapshot(pid=42)])[0]
    second = enricher.enrich([snapshot(pid=42)])[0]

    assert resolver.calls == 2
    assert first.process.identity == ProcessIdentity(42, STARTED_AT)
    assert second.process.identity == ProcessIdentity(42, second_start)
    assert first.key != second.key


def test_snapshot_without_pid_is_unchanged_and_does_not_call_resolver() -> None:
    resolver = FakeResolver({})
    source = snapshot(pid=None)

    result = ProcessMetadataEnricher(resolver).enrich([source])

    assert result == (source,)
    assert resolver.calls == []


def test_resolver_failure_does_not_affect_other_records() -> None:
    resolver = FakeResolver(
        {
            10: RuntimeError("provider failed"),
            20: available(20),
        }
    )

    result = ProcessMetadataEnricher(resolver).enrich(
        [snapshot(pid=10), snapshot(pid=20, port=50_001)]
    )

    assert result[0].process == ProcessInfo(
        status=ProcessInfoStatus.UNAVAILABLE,
        identity=ProcessIdentity(10),
    )
    assert result[1].process == available(20)
    assert resolver.calls == [10, 20]


def test_invalid_resolver_result_is_isolated() -> None:
    resolver = FakeResolver({10: available(99)})

    result = ProcessMetadataEnricher(resolver).enrich([snapshot(pid=10)])

    assert result[0].process.status is ProcessInfoStatus.UNAVAILABLE
    assert result[0].process.identity == ProcessIdentity(10)


def test_domain_and_application_layers_do_not_import_psutil() -> None:
    for module in (connections, ports, processes):
        source = inspect.getsource(module)
        assert "import psutil" not in source
        assert "from psutil" not in source

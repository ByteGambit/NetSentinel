from __future__ import annotations

from datetime import UTC, datetime
from threading import Event

from netsentinel.application.services.executable_signer import ExecutableSignerService
from netsentinel.domain.connections import ProcessIdentity, ProcessInfo, ProcessInfoStatus
from netsentinel.domain.executable_signer import ExecutableSigner, SignerAvailability as Availability


class BlockingVerifier:
    def __init__(self) -> None:
        self.entered = Event()
        self.release = Event()
        self.calls = 0

    def verify(self, path: str, *, is_cancelled: object) -> ExecutableSigner:
        self.calls += 1
        self.entered.set()
        self.release.wait(1)
        return ExecutableSigner(Availability.UNAVAILABLE)


def process(pid: int, path: str) -> ProcessInfo:
    return ProcessInfo(status=ProcessInfoStatus.AVAILABLE,
                       identity=ProcessIdentity(pid, datetime(2026, 1, 1, tzinfo=UTC)),
                       name="sample",
                       executable_path=path, executable_path_status=ProcessInfoStatus.AVAILABLE)


def test_coalescing_saturation_and_bounded_shutdown() -> None:
    fake = BlockingVerifier()
    service = ExecutableSignerService(fake, queue_capacity=1)
    first = service.request(process(1, "C:\\one.exe"))
    assert fake.entered.wait(1)
    duplicate = service.request(process(2, "C:\\one.exe"))
    pending = service.request(process(3, "C:\\two.exe"))
    saturated = service.request(process(4, "C:\\three.exe"))
    assert first.future is duplicate.future and service.coalesced == 1
    assert saturated.future.result().availability is Availability.SATURATED
    assert service.stop(timeout=0.01) is False
    assert first.future.result().availability is Availability.CANCELLED
    assert pending.future.result().availability is Availability.CANCELLED
    fake.release.set()
    assert service.stop(timeout=1)
    assert fake.calls == 1
    assert service.request(process(5, "C:\\one.exe")).future.result().availability is Availability.CANCELLED

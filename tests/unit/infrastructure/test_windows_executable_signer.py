"""Offline adapter contracts without depending on host catalog/store state."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path

import pytest

from netsentinel.domain.executable_signer import (
    ExecutableSigner, LocalTrust, SignatureKind, SignatureValidation,
    SignerAvailability as Availability, SignerIdentity,
)
from netsentinel.infrastructure.windows_executable_signer import (
    CATALOG_INFO, NO_SIGNATURE, OFFLINE_FLAGS, FILE_INFO, TRUST_DATA,
    _WindowsTrust, WindowsExecutableSigner,
)


SIGNED = ExecutableSigner(Availability.AVAILABLE, SignatureKind.CATALOG,
                          SignatureValidation.VALID, LocalTrust.TRUSTED_LOCAL_POLICY,
                          signer=SignerIdentity("Publisher", "Issuer", "a" * 64))


class FakeNative:
    def __init__(self, result: ExecutableSigner = SIGNED) -> None:
        self.result = result
        self.calls = 0
        self.mutate: Path | None = None

    def inspect(self, path: str, handle: wintypes.HANDLE, *, cancelled: object) -> ExecutableSigner:
        assert handle.value
        self.calls += 1
        if self.mutate is not None:
            self.mutate.write_bytes(b"changed")
        return self.result


def test_snapshot_cache_and_file_change(tmp_path: Path) -> None:
    path = tmp_path / "sample.exe"
    path.write_bytes(b"one")
    fake = FakeNative()
    adapter = WindowsExecutableSigner(native=fake, cache_capacity=1)
    def run() -> ExecutableSigner:
        return adapter.verify(str(path), is_cancelled=lambda: False)
    assert run() == SIGNED
    assert run() == SIGNED
    assert fake.calls == 1
    path.write_bytes(b"more bytes")
    assert run() == SIGNED
    assert fake.calls == 2
    other = tmp_path / "second.exe"
    other.write_bytes(b"two")
    adapter.verify(str(other), is_cancelled=lambda: False)
    assert adapter.cache_size == 1
    fake.mutate = path
    path.write_bytes(b"three bytes")
    assert run().availability is Availability.FILE_CHANGED
    assert adapter.cache_size == 1


def test_preflight_and_denied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = WindowsExecutableSigner(native=FakeNative())
    def run(path: Path | str) -> ExecutableSigner:
        return adapter.verify(str(path), is_cancelled=lambda: False)
    assert run(tmp_path / "missing.exe").availability is Availability.NOT_FOUND
    assert run(tmp_path).availability is Availability.INVALID_PATH
    assert run(r"\\server\share\sample.exe").availability is Availability.REMOTE_PATH
    path = tmp_path / "file.exe"
    path.write_bytes(b"bytes")
    original_stat = os.stat
    def denied(candidate: object, **kwargs: object) -> os.stat_result:
        if str(candidate) == str(path):
            raise PermissionError()
        return original_stat(candidate, **kwargs)
    monkeypatch.setattr(os, "stat", denied)
    assert run(path).availability is Availability.ACCESS_DENIED


def test_offline_flags_model_and_native_state_cleanup() -> None:
    assert OFFLINE_FLAGS & 0x1000
    assert OFFLINE_FLAGS & 0x10
    assert SIGNED.revocation.value == "not_checked"
    assert not hasattr(SIGNED, "safe") and not hasattr(SIGNED, "risk_score")
    calls: list[int] = []
    trust = _WindowsTrust.__new__(_WindowsTrust)
    def verify(_hwnd: object, _action: object, data_ptr: object) -> int:
        data = ctypes.cast(data_ptr, ctypes.POINTER(TRUST_DATA)).contents
        calls.append(data.dwStateAction)
        return 0
    trust.verify = verify
    trust._identity = lambda _state: (None, None)  # type: ignore[method-assign]
    info = FILE_INFO(ctypes.sizeof(FILE_INFO), "C:\\sample.exe", None, None)
    code, result = trust._verify(info, 1, SignatureKind.EMBEDDED)
    assert code == 0 and result.local_trust is LocalTrust.TRUSTED_LOCAL_POLICY
    assert calls == [1, 2]
    trust._identity = lambda _state: (_ for _ in ()).throw(RuntimeError("provider failed"))  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        trust._verify(info, 1, SignatureKind.EMBEDDED)
    assert calls == [1, 2, 1, 2]


def test_catalog_admin_and_context_cleanup_on_success_and_failure() -> None:
    trust = _WindowsTrust.__new__(_WindowsTrust)
    released: list[str] = []
    trust._verify = lambda _info, choice, _kind: (  # type: ignore[method-assign]
        (NO_SIGNATURE, ExecutableSigner(Availability.AVAILABLE)) if choice == 1
        else (0, SIGNED)
    )
    def acquire(pointer: object, _subject: object, _algorithm: str, _reserved: object, _flags: int) -> int:
        ctypes.cast(pointer, ctypes.POINTER(wintypes.HANDLE)).contents.value = 7
        return 1
    def calc(_admin: object, _file: object, size: object, digest: object, _flags: int) -> int:
        ctypes.cast(size, ctypes.POINTER(wintypes.DWORD)).contents.value = 32
        return 1
    def info(_catalog: object, pointer: object, _flags: int) -> int:
        ctypes.cast(pointer, ctypes.POINTER(CATALOG_INFO)).contents.wszCatalogFile = "C:\\local.cat"
        return 1
    trust.acquire = acquire
    trust.calc = calc
    trust.enum = lambda *_args: 9
    trust.cat_info = info
    trust.release_cat = lambda *_args: released.append("catalog")
    trust.release_admin = lambda *_args: released.append("admin")
    assert trust.inspect("C:\\sample.exe", wintypes.HANDLE(5), cancelled=lambda: False) == SIGNED
    assert released == ["catalog", "admin"]
    released.clear()
    trust.cat_info = lambda *_args: 0
    result = trust.inspect("C:\\sample.exe", wintypes.HANDLE(5), cancelled=lambda: False)
    assert result.availability is Availability.UNAVAILABLE
    assert released == ["catalog", "admin", "admin"]

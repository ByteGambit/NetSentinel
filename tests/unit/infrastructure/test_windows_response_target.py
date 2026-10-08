"""NS-101 target guard tests; synthetic native handles, no local file access."""

from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
import sys

import pytest

from netsentinel.domain.response import ResponseReason
from netsentinel.infrastructure import windows_response_target as module
from netsentinel.infrastructure.windows_response_firewall import TargetValidationError, FirewallApiError
from netsentinel.domain.response import FirewallReadStatus
from tests.unit.domain.test_response import command


class Files:
    def __init__(self, c):
        self.command = c
        self.calls = []
        self.closed = []
        self.drive = 3
        self.attributes = {}
        self.final_paths = {}
        self.identity_change = False
        self.open_error = None

    def GetDriveType(self, root):
        self.calls.append(("drive", root))
        return self.drive

    def CreateFile(self, path, access, sharing, security, disposition, flags, template):
        self.calls.append(("open", path, access, sharing, disposition, flags))
        if self.open_error:
            raise self.open_error
        return SimpleNamespace(path=path, Close=lambda: self.closed.append(path))

    def GetFileInformationByHandle(self, handle):
        identity = self.command.file_identity
        attrs = 0 if handle.path == self.command.spec.program_path else 0x10
        attrs = self.attributes.get(handle.path, attrs)
        return (attrs, None, None, identity.modified_at, identity.volume_serial,
                identity.size_bytes >> 32, identity.size_bytes & 0xFFFFFFFF, 1,
                identity.file_id >> 32, (identity.file_id & 0xFFFFFFFF) + int(self.identity_change))

    def GetFinalPathNameByHandle(self, handle, flags):
        return self.final_paths.get(handle.path, "\\\\?\\" + handle.path)


def install(monkeypatch, c=None, classify=lambda path: True):
    c = command() if c is None else c
    api = Files(c)
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setattr(module.sys, "executable", r"C:\NetSentinel\netsentinel.exe")
    monkeypatch.setitem(sys.modules, "win32file", api)
    monkeypatch.setitem(sys.modules, "win32api", SimpleNamespace(GetWindowsDirectory=lambda: r"C:\Windows"))
    return api, module.WindowsExecutableTarget(classify), c


@pytest.mark.parametrize("path", [r"C:\Example\app.exe", r"C:\Program Files\Örnek 中 & $()\app.exe"])
def test_validated_identity_and_all_ancestors_are_held_through_dispatch(monkeypatch, path):
    c = replace(command(), spec=replace(command().spec, program_path=path))
    api, guard, c = install(monkeypatch, c)
    with guard(c):
        assert api.closed == []
        opens = [call for call in api.calls if call[0] == "open"]
        assert opens[-1][1] == path
        assert opens[-1][2:] == (0x80, 1, 3, 0x02200000)
        assert all(call[3] == 3 for call in opens[:-1])
    assert api.closed == list(reversed([call[1] for call in opens]))


@pytest.mark.parametrize("drive", [0, 1, 2, 4, 5, 6])
def test_no_network_or_nonfixed_drive_is_opened(monkeypatch, drive):
    api, guard, c = install(monkeypatch)
    api.drive = drive
    with pytest.raises(TargetValidationError):
        with guard(c):
            pytest.fail("entered")
    assert not any(call[0] == "open" for call in api.calls)


@pytest.mark.parametrize("path", [r"C:\Windows\app.exe", r"C:\NetSentinel\app.exe",
                                 r"C:\Program Files\WindowsApps\app.exe",
                                 r"C:\Example\svchost.exe", r"C:\Example\python.exe",
                                 r"C:\Example\NetSentinel.exe"])
def test_system_packaged_self_shared_host_targets_refused(monkeypatch, path):
    c = replace(command(), spec=replace(command().spec, program_path=path))
    api, guard, c = install(monkeypatch, c)
    with pytest.raises(TargetValidationError):
        with guard(c):
            pytest.fail("entered")
    assert not any(call[0] == "open" for call in api.calls)


@pytest.mark.parametrize("classifier", [lambda p: False, lambda p: None, lambda p: 1,
                                      lambda p: (_ for _ in ()).throw(RuntimeError("private"))])
def test_independent_desktop_classification_is_required_and_exact(monkeypatch, classifier):
    api, guard, c = install(monkeypatch, classify=classifier)
    with pytest.raises(TargetValidationError):
        with guard(c):
            pytest.fail("entered")
    assert len(api.closed) == 3


@pytest.mark.parametrize("path,attrs", [("C:\\", 0x410), (r"C:\Example", 0x410),
                                      (r"C:\Example\app.exe", 0x400),
                                      (r"C:\Example\app.exe", 0x10), (r"C:\Example", 0)])
def test_reparse_or_wrong_file_class_refuses_and_closes_all_handles(monkeypatch, path, attrs):
    api, guard, c = install(monkeypatch)
    api.attributes[path] = attrs
    with pytest.raises(TargetValidationError):
        with guard(c):
            pytest.fail("entered")
    assert set(api.closed) == {call[1] for call in api.calls if call[0] == "open"}


def test_file_drift_or_final_path_alias_requires_new_preview(monkeypatch):
    api, guard, c = install(monkeypatch)
    api.identity_change = True
    with pytest.raises(TargetValidationError) as exc:
        with guard(c):
            pytest.fail("entered")
    assert exc.value.reason is ResponseReason.REVALIDATION_REQUIRED
    api.identity_change = False
    api.final_paths[c.spec.program_path] = r"\\?\C:\Different\app.exe"
    with pytest.raises(TargetValidationError) as exc:
        with guard(c):
            pytest.fail("entered")
    assert exc.value.reason is ResponseReason.REVALIDATION_REQUIRED


@pytest.mark.parametrize("error,reason", [(PermissionError("private"), ResponseReason.ACCESS_DENIED),
                                      (FileNotFoundError("private"), ResponseReason.TARGET_UNAVAILABLE),
                                      (RuntimeError("private"), ResponseReason.TARGET_UNAVAILABLE)])
def test_file_errors_sanitized_and_handles_closed(monkeypatch, error, reason):
    api, guard, c = install(monkeypatch)
    api.open_error = error
    with pytest.raises(TargetValidationError) as exc:
        with guard(c):
            pytest.fail("entered")
    assert exc.value.reason is reason
    assert exc.value.__cause__ is None and "private" not in str(exc.value)


def test_api_exceptions_in_guard_body_keep_privilege_result(monkeypatch):
    api, guard, c = install(monkeypatch)
    error = FirewallApiError(FirewallReadStatus.ACCESS_DENIED, definite_failure=True)
    with pytest.raises(FirewallApiError) as exc:
        with guard(c):
            raise error
    assert exc.value is error
    assert len(api.closed) == 3


def test_classifier_never_reads_through_unverified_reparse_components(monkeypatch):
    calls = []
    api, guard, c = install(monkeypatch, classify=lambda p: calls.append(p) or True)
    api.attributes[r"C:\Example"] = 0x410
    with pytest.raises(TargetValidationError):
        with guard(c):
            pytest.fail("entered")
    assert calls == []


def test_backend_unavailable_is_not_a_validation_grant(monkeypatch):
    api, guard, c = install(monkeypatch)
    monkeypatch.setattr(module.sys, "platform", "linux")
    with pytest.raises(TargetValidationError):
        with guard(c):
            pytest.fail("entered")
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "win32file", None)
    with pytest.raises(TargetValidationError):
        with guard(c):
            pytest.fail("entered")
    assert api.calls == []


def test_metadata_recipe_binds_full_volume_file_id_size_and_time(monkeypatch):
    c = command()
    c = replace(c, file_identity=replace(c.file_identity, file_id=2**63 + 123,
                                        size_bytes=2**33 + 1, modified_at=c.file_identity.modified_at + timedelta(microseconds=123)))
    api, _, c = install(monkeypatch, c)
    assert module.file_identity(api.GetFileInformationByHandle(SimpleNamespace(path=c.spec.program_path))) == c.file_identity

"""NS-069 offline policy tests: process instance versus application scope."""

from datetime import UTC, datetime, timedelta

import pytest

from netsentinel.application.services.application_identity import (
    compare_application_scopes,
    resolve_application_scope,
)
from netsentinel.domain.application_identity import (
    ApplicationIdentityChange as IdentityChange,
    ApplicationIdentityEvidence as Evidence,
    ApplicationIdentityQuality as Quality,
    ApplicationRevisionChange as RevisionChange,
)
from netsentinel.domain.connections import ProcessIdentity, ProcessInfo, ProcessInfoStatus as Status
from netsentinel.domain.executable_hash import (
    ExecutableHash,
    ExecutableHashRequest,
    ExecutableHashStatus as HashStatus,
)


CREATED = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
PATH_A = "C:\\Program Files\\Foo\\worker.exe"
PATH_B = "C:\\Users\\Alice\\AppData\\Local\\Bar\\worker.exe"


def process(
    pid: int = 1200,
    *,
    created: datetime | None = CREATED,
    path: str | None = PATH_A,
    path_status: Status | None = None,
    name: str = "worker.exe",
) -> ProcessInfo:
    return ProcessInfo(
        status=Status.AVAILABLE,
        identity=ProcessIdentity(pid, created),
        name=name,
        executable_path=path,
        executable_path_status=path_status,
    )


def scope_with_hash(info: ProcessInfo, result: ExecutableHash):
    assert info.identity is not None and info.executable_path is not None
    return resolve_application_scope(
        info,
        hash_request=ExecutableHashRequest(info.identity, info.executable_path),
        hash_result=result,
    )


def test_same_path_restart_and_case_spelling_have_same_stable_key() -> None:
    first = resolve_application_scope(process())
    restart = resolve_application_scope(
        process(9000, created=CREATED + timedelta(days=1), path="c:/program files/foo/./FOO/../WORKER.EXE", name="renamed.exe")
    )
    assert first.identity.key == restart.identity.key
    assert first.identity == restart.identity
    assert first.identity.restart_stable
    assert first.identity.evidence is Evidence.EXECUTABLE_PATH
    assert first.identity.key == "winpath:v1:c:\\program files\\foo\\worker.exe"
    assert compare_application_scopes(first, restart).identity_change is IdentityChange.SAME_SCOPE


def test_same_name_different_path_and_same_hash_do_not_merge() -> None:
    first = process(path=PATH_A)
    other = process(9000, created=CREATED + timedelta(days=1), path=PATH_B)
    assert resolve_application_scope(first).identity.key != resolve_application_scope(other).identity.key
    digest = ExecutableHash(HashStatus.AVAILABLE, "a" * 64)
    comparison = compare_application_scopes(scope_with_hash(first, digest), scope_with_hash(other, digest))
    assert comparison.identity_change is IdentityChange.DIFFERENT_SCOPE
    assert not comparison.can_carry_baseline


@pytest.mark.parametrize("status", [Status.ACCESS_DENIED, Status.NOT_FOUND, Status.UNAVAILABLE])
def test_missing_path_is_instance_scoped_and_not_restart_stable(status: Status) -> None:
    first = resolve_application_scope(process(path=None, path_status=status))
    repeated = resolve_application_scope(process(path=None, path_status=status))
    restart = resolve_application_scope(process(9000, created=CREATED + timedelta(days=1), path=None, path_status=status))
    assert first.identity.quality is Quality.PROVISIONAL
    assert first.identity.evidence is Evidence.PROCESS_INSTANCE
    assert first.identity.key == repeated.identity.key
    assert first.identity.key != restart.identity.key
    assert not first.identity.restart_stable
    assert not compare_application_scopes(first, restart).can_carry_baseline


def test_pid_reuse_and_missing_create_time_are_conservative() -> None:
    first = resolve_application_scope(process(path=None))
    reused = resolve_application_scope(process(created=CREATED + timedelta(seconds=1), path=None))
    incomplete = resolve_application_scope(process(created=None, path=None))
    assert first.identity.key != reused.identity.key
    assert incomplete.identity.quality is Quality.UNKNOWN
    assert incomplete.identity.key is None
    assert resolve_application_scope(process(9, created=None, path=None)).identity.key is None


def test_path_upgrade_and_inconsistent_path_change_are_typed() -> None:
    unknown = resolve_application_scope(process(path=None))
    known = resolve_application_scope(process())
    changed = resolve_application_scope(process(path=PATH_B))
    upgrade = compare_application_scopes(unknown, known)
    assert upgrade.identity_change is IdentityChange.METADATA_UPGRADE
    assert not upgrade.can_carry_baseline
    assert compare_application_scopes(known, changed).identity_change is IdentityChange.PATH_CHANGED
    assert compare_application_scopes(known, unknown).identity_change is IdentityChange.METADATA_LOSS


def test_path_then_hash_upgrade_keeps_scope_but_does_not_migrate_unknown_data() -> None:
    unknown = resolve_application_scope(process(path=None))
    known = resolve_application_scope(process())
    hashed = scope_with_hash(process(), ExecutableHash(HashStatus.AVAILABLE, "a" * 64))
    assert compare_application_scopes(unknown, known).identity_change is IdentityChange.METADATA_UPGRADE
    assert compare_application_scopes(known, hashed).revision_change is RevisionChange.BECAME_KNOWN
    direct = compare_application_scopes(unknown, hashed)
    assert direct.identity_change is IdentityChange.METADATA_UPGRADE
    assert direct.revision_change is RevisionChange.BECAME_KNOWN
    assert not direct.can_carry_baseline


def test_hash_revision_changes_without_changing_application_identity() -> None:
    info = process()
    unknown = resolve_application_scope(info)
    a = scope_with_hash(info, ExecutableHash(HashStatus.AVAILABLE, "a" * 64))
    same = scope_with_hash(info, ExecutableHash(HashStatus.AVAILABLE, "a" * 64))
    b = scope_with_hash(info, ExecutableHash(HashStatus.AVAILABLE, "b" * 64))
    assert unknown.identity == a.identity == b.identity
    assert compare_application_scopes(unknown, a).revision_change is RevisionChange.BECAME_KNOWN
    assert not compare_application_scopes(unknown, a).can_carry_baseline
    assert compare_application_scopes(a, same).can_carry_baseline
    assert compare_application_scopes(a, b).revision_change is RevisionChange.CHANGED
    assert not compare_application_scopes(a, b).can_carry_baseline


@pytest.mark.parametrize("status", [
    HashStatus.ACCESS_DENIED, HashStatus.NOT_FOUND, HashStatus.CHANGED_DURING_READ,
    HashStatus.SATURATED, HashStatus.UNAVAILABLE,
])
def test_hash_failure_is_unknown_revision_not_artifact_change(status: HashStatus) -> None:
    info = process()
    known = scope_with_hash(info, ExecutableHash(HashStatus.AVAILABLE, "a" * 64))
    failed = scope_with_hash(info, ExecutableHash(status))
    comparison = compare_application_scopes(known, failed)
    assert failed.identity.restart_stable
    assert failed.revision.hash_status is status
    assert not failed.revision.known
    assert comparison.revision_change is RevisionChange.UNKNOWN
    assert not comparison.can_carry_baseline


def test_stale_hash_request_is_ignored_and_never_starts_io() -> None:
    info = process()
    other = process(path=PATH_B)
    assert info.identity is not None and info.executable_path is not None
    scope = resolve_application_scope(
        other,
        hash_request=ExecutableHashRequest(info.identity, info.executable_path),
        hash_result=ExecutableHash(HashStatus.AVAILABLE, "a" * 64),
    )
    assert scope.revision.digest is None
    assert scope.identity.restart_stable


def test_invalid_relative_path_has_no_stable_identity() -> None:
    relative = resolve_application_scope(process(path="worker.exe"))
    drive_relative = resolve_application_scope(process(path="C:worker.exe"))
    assert relative.identity.quality is Quality.PROVISIONAL
    assert drive_relative.identity.quality is Quality.PROVISIONAL


def test_observed_unc_path_can_identify_an_application_without_hashing() -> None:
    first = resolve_application_scope(process(path=r"\\server\share\Foo\worker.exe"))
    second = resolve_application_scope(process(path="//SERVER/share/foo/WORKER.EXE"))
    assert first.identity == second.identity
    assert first.identity.restart_stable
    assert not first.revision.known


def test_invalid_api_input_is_rejected() -> None:
    with pytest.raises(TypeError):
        resolve_application_scope(object())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        resolve_application_scope(process(), hash_result=ExecutableHash(HashStatus.UNAVAILABLE))
    with pytest.raises(TypeError):
        compare_application_scopes(object(), resolve_application_scope(process()))  # type: ignore[arg-type]

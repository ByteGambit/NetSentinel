"""Pure NS-069 policy for observed Windows application scopes."""

from __future__ import annotations

import ntpath
from datetime import UTC, datetime

from netsentinel.domain.application_identity import (
    ApplicationIdentity,
    ApplicationIdentityChange,
    ApplicationIdentityComparison,
    ApplicationIdentityEvidence,
    ApplicationIdentityQuality,
    ApplicationRevision,
    ApplicationRevisionChange,
    ApplicationScope,
)
from netsentinel.domain.connections import ProcessInfo, ProcessInfoStatus
from netsentinel.domain.executable_hash import ExecutableHash, ExecutableHashRequest


def resolve_application_scope(
    process: ProcessInfo,
    *,
    hash_request: ExecutableHashRequest | None = None,
    hash_result: ExecutableHash | None = None,
) -> ApplicationScope:
    """Resolve existing metadata without filesystem, hash, network or DB I/O.

    Hash evidence is accepted only with a matching on-demand request token.
    A path-backed identity does not wait for hashing, and a hash never merges
    different paths into one application.
    """
    if not isinstance(process, ProcessInfo):
        raise TypeError("process must be ProcessInfo")
    if (hash_request is None) != (hash_result is None):
        raise ValueError("hash_request and hash_result must be supplied together")
    if hash_request is not None and not isinstance(hash_request, ExecutableHashRequest):
        raise TypeError("hash_request must be ExecutableHashRequest")
    if hash_result is not None and not isinstance(hash_result, ExecutableHash):
        raise TypeError("hash_result must be ExecutableHash")

    path_status = process.executable_path_status
    assert path_status is not None  # ProcessInfo fills this status in __post_init__.
    canonical = (
        _canonical_windows_path(process.executable_path)
        if path_status is ProcessInfoStatus.AVAILABLE and process.executable_path is not None
        else None
    )
    if canonical is not None:
        identity = ApplicationIdentity(
            ApplicationIdentityQuality.STABLE,
            f"winpath:v1:{canonical}",
            ApplicationIdentityEvidence.EXECUTABLE_PATH,
            path_status,
        )
    elif process.identity is not None and process.identity.create_time is not None:
        instance = process.identity
        created_at = instance.create_time
        assert created_at is not None
        since_epoch = created_at - datetime(1970, 1, 1, tzinfo=UTC)
        micros = (since_epoch.days * 86_400 + since_epoch.seconds) * 1_000_000 + since_epoch.microseconds
        identity = ApplicationIdentity(
            ApplicationIdentityQuality.PROVISIONAL,
            f"instance:v1:{instance.pid}:{micros}",
            ApplicationIdentityEvidence.PROCESS_INSTANCE,
            path_status,
        )
    else:
        identity = ApplicationIdentity(
            ApplicationIdentityQuality.UNKNOWN,
            None,
            ApplicationIdentityEvidence.NONE,
            path_status,
        )

    usable_hash = (
        hash_request is not None
        and hash_result is not None
        and canonical is not None
        and hash_request.matches(process)
    )
    revision = (
        ApplicationRevision(hash_result.digest, hash_result.status)
        if usable_hash and hash_result is not None
        else ApplicationRevision(None)
    )
    return ApplicationScope(identity, revision, process.identity)


def compare_application_scopes(
    previous: ApplicationScope, current: ApplicationScope
) -> ApplicationIdentityComparison:
    """Explain scope transitions; never silently migrate learned observations."""
    if not isinstance(previous, ApplicationScope) or not isinstance(current, ApplicationScope):
        raise TypeError("both values must be ApplicationScope")
    old, new = previous.identity, current.identity
    same_instance = (
        previous.process_identity is not None
        and previous.process_identity.create_time is not None
        and previous.process_identity == current.process_identity
    )
    if old.restart_stable and new.restart_stable and old.key == new.key:
        identity_change = ApplicationIdentityChange.SAME_SCOPE
    elif same_instance and old.quality is ApplicationIdentityQuality.PROVISIONAL and new.restart_stable:
        identity_change = ApplicationIdentityChange.METADATA_UPGRADE
    elif same_instance and old.restart_stable and not new.restart_stable:
        identity_change = ApplicationIdentityChange.METADATA_LOSS
    elif same_instance and old.restart_stable and new.restart_stable:
        identity_change = ApplicationIdentityChange.PATH_CHANGED
    elif old.key is not None and old.key == new.key:
        identity_change = ApplicationIdentityChange.SAME_SCOPE
    elif old.key is None or new.key is None:
        identity_change = ApplicationIdentityChange.UNKNOWN
    else:
        identity_change = ApplicationIdentityChange.DIFFERENT_SCOPE

    old_hash, new_hash = previous.revision.digest, current.revision.digest
    if old_hash is None and new_hash is not None:
        revision_change = ApplicationRevisionChange.BECAME_KNOWN
    elif identity_change is ApplicationIdentityChange.SAME_SCOPE and old.restart_stable:
        if old_hash is not None and new_hash is not None:
            revision_change = (
                ApplicationRevisionChange.SAME if old_hash == new_hash
                else ApplicationRevisionChange.CHANGED
            )
        else:
            revision_change = ApplicationRevisionChange.UNKNOWN
    else:
        revision_change = ApplicationRevisionChange.UNKNOWN
    return ApplicationIdentityComparison(
        identity_change,
        revision_change,
        identity_change is ApplicationIdentityChange.SAME_SCOPE
        and old.restart_stable
        and revision_change is ApplicationRevisionChange.SAME,
    )


def _canonical_windows_path(path: str) -> str | None:
    """Normalize lexical Windows spelling only; never follow filesystem links."""
    normalized = ntpath.normcase(ntpath.normpath(path))
    drive, tail = ntpath.splitdrive(normalized)
    if not drive or not tail.startswith("\\"):
        return None
    return normalized

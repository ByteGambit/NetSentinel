"""NS-104 custody-only uninstall report. Never dispatch firewall operations.

The per-user installer cannot acquire a trusted privileged write boundary.
Preserve rules and custody; require explicit administrator-managed Undo before
DELETE. OS presence is deliberately UNKNOWN, never inferred from old receipts.
"""

from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
import sqlite3
from uuid import UUID

from netsentinel.domain.response import ResponseAction
from netsentinel.domain.response_lifecycle import MAX_RESPONSE_OPERATIONS, ResponseStorageError
from netsentinel.infrastructure.sqlite.response_repository import SQLiteResponseLifecycleRepository
from netsentinel.infrastructure.uninstall_data import UnsafeDataRoot, _reject_link
from netsentinel.shared.paths import user_data_paths


@dataclass(frozen=True)
class UninstallResponseReport:
    text: str = field(repr=False)
    remaining_count: int
    available: bool

    @property
    def permits_data_delete(self) -> bool:
        return self.available and self.remaining_count == 0


class _CustodyReader(SQLiteResponseLifecycleRepository):
    """Reuse NS-102's complete decoder on one consistent read-only transaction.

    No base constructor (which initializes/migrates custody), lock-file creation,
    save, reconciliation, expiry dispatch, native API or adoption is performed.
    """

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._readonly = connection
        row = connection.execute("SELECT store_id FROM response_store WHERE singleton=1").fetchone()
        if row is None:
            raise ResponseStorageError("Response custody unavailable.")
        self._store_id = UUID(row[0])
        if self._store_id.int == 0 or str(self._store_id) != row[0]:
            raise ResponseStorageError("Response custody unavailable.")

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        yield self._readonly


GUIDANCE = (
    "Firewall rules are PRESERVED. No firewall cleanup or elevation was attempted.\n"
    "Current Windows Firewall state is NOT CHECKED; recorded state is historical.\n"
    "Cleanup requires administrator permission and an explicit, separately confirmed Undo.\n"
    "Use the approved response backend with retained FINAL custody and fresh full equality,\n"
    "or inspect the exact rule in Windows Defender Firewall with Advanced Security.\n"
    "Modified, duplicate, pending or unverified rules require manual administrator review.\n"
    "Never remove rules by prefix/group. Missing rules are not successful cleanup.\n"
    "KEEP retains ownership/audit. DELETE is refused while rules may remain or custody is unknown.\n"
)


def inspect_response_custody(base: Path) -> UninstallResponseReport:
    """Bounded exact provenance list; no OS query, DB creation or migration."""
    try:
        paths = user_data_paths(local_app_data=base)
        expected = base / "NetSentinel"
        if not base.is_absolute() or paths.root != expected:
            raise UnsafeDataRoot("Noncanonical data root.")
        for path in (*reversed(expected.parents), expected, paths.database,
                     Path(str(paths.database) + "-wal"), Path(str(paths.database) + "-shm")):
            try:
                _reject_link(path)
            except FileNotFoundError:
                continue
        if not paths.database.exists():
            return UninstallResponseReport(GUIDANCE + "\nNo local response custody database. No ownership claim.\n", 0, True)
        with closing(sqlite3.connect(paths.database.as_uri() + "?mode=ro", uri=True, timeout=1)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            versions = [row[0] for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version LIMIT 22")]
            if not versions or versions != list(range(1, len(versions) + 1)) or versions[-1] > 20:
                raise ResponseStorageError("Unsupported schema.")
            if versions[-1] < 20:
                if connection.execute("SELECT count(*) FROM sqlite_master WHERE name LIKE 'response_%'").fetchone()[0]:
                    raise ResponseStorageError("Unexpected response custody.")
                return UninstallResponseReport(GUIDANCE + "\nPre-response schema; no response custody.\n", 0, True)
            count = connection.execute("SELECT count(*) FROM response_operations").fetchone()[0]
            if count > MAX_RESPONSE_OPERATIONS:
                raise ResponseStorageError("Custody exceeds capacity.")
            if count == 0:
                return UninstallResponseReport(GUIDANCE + "\nNo retained response operations. No ownership claim.\n", 0, True)
            reader = _CustodyReader(connection)
            reader._validate_custody()
            rows = []
            after = None
            for _ in range(MAX_RESPONSE_OPERATIONS // 64 + 1):
                page = reader.page(after=after)
                for operation in page:
                    if operation.command.action is not ResponseAction.CREATE:
                        continue
                    if reader.has_verified_removal(operation.command.rule_id):
                        continue
                    spec = operation.command.spec
                    rows.append(
                        f"Rule: {operation.command.rule_name}\n"
                        f"Executable: {spec.program_path}\nRemote: {spec.remote_ip}:{spec.remote_port} / {spec.transport.value}\n"
                        f"Profile: {spec.profile.value}; OUTBOUND BLOCK; until manually removed\n"
                        f"Custody: {'FINAL' if operation.manifest else 'PREPARED only (not ownership)'}\n"
                        f"Recorded lifecycle: {operation.status.value}; reconciliation: {operation.reconciliation.value}\n"
                        "Current presence: UNKNOWN; removal: NOT ATTEMPTED\n"
                    )
                if len(page) < 64:
                    break
                after = page[-1].operation_id
            return UninstallResponseReport(GUIDANCE + f"\nPotentially remaining recorded rules: {len(rows)}\n\n" + "\n".join(rows), len(rows), True)
    except (OSError, sqlite3.Error, ValueError, TypeError, UnsafeDataRoot, ResponseStorageError):
        return UninstallResponseReport(GUIDANCE + "\nUNKNOWN: custody could not be completely enumerated. KEEP data and repair/review before DELETE.\n", 0, False)


def write_uninstall_response_report() -> int:
    """Fixed known-folder output for interactive and silent uninstall, no CLI path."""
    from netsentinel.infrastructure.windows_installer import stopped_desktop, windows_local_app_data

    try:
        with stopped_desktop():
            base = windows_local_app_data()
            report = inspect_response_custody(base)
            root = base / "NetSentinel"
            # No history on a never-launched install: no persistent folder created.
            if not root.exists():
                return 0 if report.available else 1
            _reject_link(root)
            output = root / "firewall-uninstall-report.txt"
            if output.exists():
                _reject_link(output)
            output.write_text(report.text, encoding="utf-8-sig")
            return 0 if report.available else 1
    except Exception:
        return 1  # Fixed failure only; installer preserves data/rules.

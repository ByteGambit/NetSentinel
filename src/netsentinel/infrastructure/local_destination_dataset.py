"""Bounded, data-only TSV adapter for user-provided ASN/country prefixes."""

from __future__ import annotations

from datetime import UTC, datetime
import os
from os import fstat
from ipaddress import ip_address, ip_network
from pathlib import Path
from stat import S_ISREG
from threading import RLock

from netsentinel.domain.destination_context import (
    DestinationAddressKind, DestinationContext, DestinationContextStatus,
    DestinationDatasetSource,
)
from netsentinel.shared.diagnostics import DestinationDatasetDiagnostic, DestinationDatasetStatus


MAX_DATASET_BYTES = 16 * 1024 * 1024
MAX_DATASET_RECORDS = 100_000
MAX_DATASET_LINE_BYTES = 2048
DATASET_MAGIC = "netsentinel-destination-context"
DATASET_SCHEMA_VERSION = "1"

type _Record = tuple[int | None, str | None, str | None]
type _Index = dict[int, dict[int, dict[int, _Record]]]


class _InvalidDataset(ValueError):
    pass


class _UnsupportedVersion(ValueError):
    pass


class LocalDestinationDataset:
    """Explicit reload swaps immutable-by-convention indexes under a short lock."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._lock = RLock()
        self._index: _Index | None = None
        self._source: DestinationDatasetSource | None = None
        self._generation = 0
        self._diagnostic = DestinationDatasetDiagnostic(DestinationDatasetStatus.NOT_CONFIGURED)
        if path is not None:
            self.reload(path)

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    def diagnostic(self) -> DestinationDatasetDiagnostic:
        with self._lock:
            return self._diagnostic

    def reload(self, path: str | Path | None) -> DestinationDatasetDiagnostic:
        """Load off the GUI thread; a failed replacement retains the old snapshot."""
        if path is None:
            with self._lock:
                self._index = None
                self._source = None
                self._generation += 1
                self._diagnostic = DestinationDatasetDiagnostic(DestinationDatasetStatus.NOT_CONFIGURED)
                return self._diagnostic
        try:
            index, source, count = self._read(Path(path))
        except _UnsupportedVersion:
            failure = DestinationDatasetStatus.UNSUPPORTED_VERSION
        except (_InvalidDataset, UnicodeError, ValueError, TypeError):
            failure = DestinationDatasetStatus.INVALID_DATASET
        except OSError:
            failure = DestinationDatasetStatus.LOAD_FAILED
        else:
            with self._lock:
                self._index = index
                self._source = source
                self._generation += 1
                self._diagnostic = DestinationDatasetDiagnostic(
                    DestinationDatasetStatus.AVAILABLE, count, source.name, source.version,
                )
                return self._diagnostic
        with self._lock:
            if self._source is not None:
                self._diagnostic = DestinationDatasetDiagnostic(
                    DestinationDatasetStatus.AVAILABLE, self._diagnostic.record_count,
                    self._source.name, self._source.version, failure,
                )
            else:
                self._diagnostic = DestinationDatasetDiagnostic(failure)
            return self._diagnostic

    @staticmethod
    def _read(path: Path) -> tuple[_Index, DestinationDatasetSource, int]:
        # UNC paths and symlinks can silently turn a local enrichment into network I/O.
        if str(path).startswith("\\\\"):
            raise _InvalidDataset("nonlocal path")
        if os.name == "nt":
            from ctypes import windll

            anchor = path.absolute().anchor
            if windll.kernel32.GetDriveTypeW(anchor) == 4:  # DRIVE_REMOTE
                raise _InvalidDataset("remote drive")
        if any(part.is_symlink() or part.is_junction() for part in (path, *path.parents)):
            raise _InvalidDataset("linked path")
        with path.open("rb") as stream:
            before = stream.fileno()
            initial = fstat(before)
            if not S_ISREG(initial.st_mode) or initial.st_size > MAX_DATASET_BYTES:
                raise _InvalidDataset("invalid file type or size")

            def line() -> str:
                raw = stream.readline(MAX_DATASET_LINE_BYTES + 1)
                if len(raw) > MAX_DATASET_LINE_BYTES or stream.tell() > MAX_DATASET_BYTES:
                    raise _InvalidDataset("line too long")
                return raw.decode("utf-8").rstrip("\r\n")

            header = line().split("\t")
            if len(header) != 5 or header[0] != DATASET_MAGIC:
                raise _InvalidDataset("invalid header")
            if header[1] != DATASET_SCHEMA_VERSION:
                raise _UnsupportedVersion("unsupported schema")
            source = DestinationDatasetSource(header[2], header[3], header[4], datetime.now(UTC))
            index: _Index = {4: {}, 6: {}}
            count = 0
            while True:
                raw = line()
                if not raw and stream.tell() == initial.st_size:
                    break
                count += 1
                if count > MAX_DATASET_RECORDS:
                    raise _InvalidDataset("too many records")
                fields = raw.split("\t")
                if len(fields) != 4:
                    raise _InvalidDataset("invalid row")
                prefix, asn_text, as_name, country = fields
                network = ip_network(prefix, strict=True)
                asn = None
                if asn_text:
                    if not asn_text.isascii() or not asn_text.isdigit():
                        raise _InvalidDataset("invalid ASN")
                    asn = int(asn_text)
                record: _Record = (asn, as_name or None, country or None)
                # Central model validation is shared with every future local adapter.
                DestinationContext(str(network.network_address), DestinationAddressKind.PUBLIC,
                                   DestinationContextStatus.MATCHED, *record, source)
                bucket = index[network.version].setdefault(network.prefixlen, {})
                key = int(network.network_address) >> (network.max_prefixlen - network.prefixlen)
                if key in bucket:
                    raise _InvalidDataset("duplicate prefix")
                bucket[key] = record
            final = fstat(before)
            if (final.st_size != initial.st_size or final.st_mtime_ns != initial.st_mtime_ns
                    or final.st_size > MAX_DATASET_BYTES):
                raise _InvalidDataset("file changed during load")
            if count == 0:
                raise _InvalidDataset("empty dataset")
            return index, source, count

    def lookup(self, ip: str) -> DestinationContext:
        address = ip_address(ip)
        canonical = str(address)
        with self._lock:
            index, source, status = self._index, self._source, self._diagnostic.status
        if index is None or source is None:
            result_status = (DestinationContextStatus.NOT_CONFIGURED
                             if status is DestinationDatasetStatus.NOT_CONFIGURED
                             else DestinationContextStatus.DATASET_UNAVAILABLE)
            return DestinationContext(canonical, DestinationAddressKind.PUBLIC, result_status)
        bits = address.max_prefixlen
        integer = int(address)
        for length in sorted(index[address.version], reverse=True):
            record = index[address.version][length].get(integer >> (bits - length))
            if record is not None:
                return DestinationContext(canonical, DestinationAddressKind.PUBLIC,
                                          DestinationContextStatus.MATCHED, *record, source)
        return DestinationContext(canonical, DestinationAddressKind.PUBLIC,
                                  DestinationContextStatus.UNKNOWN, source=source)

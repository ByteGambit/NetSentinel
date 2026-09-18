"""Application service for enriching connection snapshots with process data."""

from __future__ import annotations

from dataclasses import replace
from typing import Iterable

from netsentinel.application.ports import ProcessMetadataResolver
from netsentinel.domain.connections import (
    ConnectionSnapshot,
    ProcessIdentity,
    ProcessInfo,
    ProcessInfoStatus,
)


class ProcessMetadataEnricher:
    """Enrich one snapshot pass while isolating per-process failures.

    The cache deliberately lives only for the duration of :meth:`enrich`.
    Re-resolving every later pass prevents stale metadata from hiding PID reuse.
    """

    def __init__(self, resolver: ProcessMetadataResolver) -> None:
        self._resolver = resolver

    def enrich(
        self, snapshots: Iterable[ConnectionSnapshot]
    ) -> tuple[ConnectionSnapshot, ...]:
        """Return snapshots with portable process metadata when available."""

        cache: dict[int, ProcessInfo] = {}
        enriched: list[ConnectionSnapshot] = []

        for snapshot in snapshots:
            identity = snapshot.process.identity
            if identity is None:
                enriched.append(snapshot)
                continue

            pid = identity.pid
            process = cache.get(pid)
            if process is None:
                process = self._resolve_safely(pid)
                cache[pid] = process

            enriched.append(replace(snapshot, process=process))

        return tuple(enriched)

    def _resolve_safely(self, pid: int) -> ProcessInfo:
        fallback = ProcessInfo(
            status=ProcessInfoStatus.UNAVAILABLE,
            identity=ProcessIdentity(pid=pid),
        )
        try:
            process = self._resolver.resolve(pid)
            if process.identity is None or process.identity.pid != pid:
                return fallback
        except Exception:
            return fallback
        return process


__all__ = ("ProcessMetadataEnricher",)

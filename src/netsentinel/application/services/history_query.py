"""Portable, bounded read service for connection history."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace

from netsentinel.application.ports import (
    MAX_HISTORY_QUERY_LIMIT,
    ConnectionHistoryQuery,
    ConnectionHistoryRepository,
)
from netsentinel.domain.connections import ConnectionHistoryRecord


@dataclass(frozen=True, slots=True)
class ConnectionHistoryPage:
    """One immutable page returned without loading the full history table."""

    records: tuple[ConnectionHistoryRecord, ...]
    offset: int
    page_size: int
    has_previous: bool
    has_next: bool


class ConnectionHistoryQueryService:
    """Apply look-ahead pagination through the repository port only."""

    def __init__(self, repository: ConnectionHistoryRepository) -> None:
        self._repository = repository

    def load_page(
        self,
        query: ConnectionHistoryQuery,
        *,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> ConnectionHistoryPage:
        if not isinstance(query, ConnectionHistoryQuery):
            raise TypeError("query must be a ConnectionHistoryQuery")
        if query.limit >= MAX_HISTORY_QUERY_LIMIT:
            raise ValueError("page size must leave room for one look-ahead row")

        bounded_query = replace(query, limit=query.limit + 1)
        if is_cancelled is None:
            rows = self._repository.query(bounded_query)
        else:
            rows = self._repository.query(
                bounded_query,
                is_cancelled=is_cancelled,
            )
        return ConnectionHistoryPage(
            records=rows[: query.limit],
            offset=query.offset,
            page_size=query.limit,
            has_previous=query.offset > 0,
            has_next=len(rows) > query.limit,
        )


__all__ = ("ConnectionHistoryPage", "ConnectionHistoryQueryService")

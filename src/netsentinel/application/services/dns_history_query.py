"""Bounded, portable DNS history pages."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace

from netsentinel.application.ports import (
    DnsHistoryQuery, DnsHistoryRepository, MAX_DNS_HISTORY_QUERY_LIMIT,
)
from netsentinel.domain.dns import DnsHistoryRecord


@dataclass(frozen=True, slots=True)
class DnsHistoryPage:
    records: tuple[DnsHistoryRecord, ...]
    offset: int
    page_size: int
    has_previous: bool
    has_next: bool


class DnsHistoryQueryService:
    def __init__(self, repository: DnsHistoryRepository) -> None:
        self._repository = repository

    def load_page(self, query: DnsHistoryQuery, *,
                  is_cancelled: Callable[[], bool] | None = None) -> DnsHistoryPage:
        if not isinstance(query, DnsHistoryQuery):
            raise TypeError("query must be a DnsHistoryQuery")
        if query.limit >= MAX_DNS_HISTORY_QUERY_LIMIT:
            raise ValueError("page size must leave room for look-ahead")
        rows = self._repository.query(replace(query, limit=query.limit + 1),
                                      is_cancelled=is_cancelled)
        return DnsHistoryPage(rows[:query.limit], query.offset, query.limit,
                              query.offset > 0, len(rows) > query.limit)

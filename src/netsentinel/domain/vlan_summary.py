"""Portable, bounded summaries of visible VLAN capture evidence (NS-044)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum


class VlanBaselineState(str, Enum):
    LEARNING = "learning"
    LEARNED = "learned"
    VERIFIED = "verified"


@dataclass(frozen=True, slots=True)
class VlanIdSummary:
    vlan_id: int
    count: int
    first_seen: datetime
    last_seen: datetime
    learned: bool = False

    def __post_init__(self) -> None:
        if type(self.vlan_id) is not int or not 1 <= self.vlan_id <= 4094:
            raise ValueError("summary VID must be 1..4094")
        if type(self.count) is not int or self.count < 1:
            raise ValueError("summary count must be positive")
        _times(self.first_seen, self.last_seen)
        if not isinstance(self.learned, bool):
            raise TypeError("learned must be bool")


@dataclass(frozen=True, slots=True)
class VlanSummarySnapshot:
    network_fingerprint: str
    interface_id: str
    interface_index: int
    first_seen: datetime
    last_seen: datetime
    learning_started_at: datetime
    baseline_state: VlanBaselineState
    untagged_count: int
    tagged_count: int
    priority_tagged_count: int
    reserved_count: int
    stacked_count: int
    overflow_count: int
    vlan_ids: tuple[VlanIdSummary, ...]
    verified_at: datetime | None = None

    def __post_init__(self) -> None:
        if (len(self.network_fingerprint) != 64 or
                any(c not in "0123456789abcdef" for c in self.network_fingerprint)):
            raise ValueError("invalid network fingerprint")
        if not self.interface_id or len(self.interface_id) > 512 or self.interface_id != self.interface_id.casefold():
            raise ValueError("interface ID must be normalized")
        if type(self.interface_index) is not int or self.interface_index < 0:
            raise ValueError("invalid interface index")
        _times(self.first_seen, self.last_seen)
        _times(self.learning_started_at, self.learning_started_at)
        if not isinstance(self.baseline_state, VlanBaselineState):
            raise TypeError("invalid baseline state")
        if self.baseline_state is VlanBaselineState.VERIFIED:
            if self.verified_at is None:
                raise ValueError("verified baseline requires an explicit verification time")
            _times(self.learning_started_at, self.verified_at)
        elif self.verified_at is not None:
            raise ValueError("unverified baseline cannot have a verification time")
        for name in ("untagged_count", "tagged_count", "priority_tagged_count",
                     "reserved_count", "stacked_count", "overflow_count"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"invalid {name}")
        if not isinstance(self.vlan_ids, tuple) or len(self.vlan_ids) > 128:
            raise ValueError("VLAN IDs must be a bounded tuple")
        if tuple(sorted(item.vlan_id for item in self.vlan_ids)) != tuple(item.vlan_id for item in self.vlan_ids):
            raise ValueError("VLAN IDs must be sorted and unique")
        if len({item.vlan_id for item in self.vlan_ids}) != len(self.vlan_ids):
            raise ValueError("duplicate VID")

    @property
    def total_count(self) -> int:
        return (self.untagged_count + self.tagged_count + self.priority_tagged_count
                + self.reserved_count + self.stacked_count)

    @property
    def learned_vlan_ids(self) -> tuple[int, ...]:
        return tuple(item.vlan_id for item in self.vlan_ids if item.learned)


def _times(first: datetime, last: datetime) -> None:
    for value in (first, last):
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("timestamps must be UTC-aware")
    if first > last:
        raise ValueError("first_seen cannot follow last_seen")


__all__ = ("VlanBaselineState", "VlanIdSummary", "VlanSummarySnapshot")

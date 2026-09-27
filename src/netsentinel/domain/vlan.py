"""Portable, payload-free 802.1Q header observation (NS-043)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class VlanTagKind(str, Enum):
    UNTAGGED = "untagged"
    PRIORITY_TAGGED = "priority_tagged"
    TAGGED = "tagged"
    RESERVED = "reserved"
    STACKED = "stacked"


@dataclass(frozen=True, slots=True)
class VlanObservation:
    """One visible outer tag; stacked inner tags are intentionally not parsed."""

    kind: VlanTagKind
    vlan_id: int | None = None
    pcp: int | None = None
    dei: bool | None = None
    encapsulated_protocol: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, VlanTagKind):
            raise TypeError("kind must be a VlanTagKind")
        fields = (self.vlan_id, self.pcp, self.dei, self.encapsulated_protocol)
        if self.kind is VlanTagKind.UNTAGGED:
            if any(field is not None for field in fields):
                raise ValueError("untagged observation cannot contain tag fields")
            return
        for name, value, maximum in (
            ("vlan_id", self.vlan_id, 4095),
            ("pcp", self.pcp, 7),
            ("encapsulated_protocol", self.encapsulated_protocol, 65535),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise ValueError(f"{name} is invalid")
        if not isinstance(self.dei, bool):
            raise TypeError("dei must be a bool")
        if self.kind is VlanTagKind.PRIORITY_TAGGED and self.vlan_id != 0:
            raise ValueError("priority tag requires VID 0")
        if self.kind is VlanTagKind.TAGGED and (self.vlan_id is None or not 1 <= self.vlan_id <= 4094):
            raise ValueError("tagged VID must be 1..4094")
        if self.kind is VlanTagKind.RESERVED and self.vlan_id != 4095:
            raise ValueError("reserved tag requires VID 4095")
        if self.kind is VlanTagKind.STACKED and self.encapsulated_protocol not in (0x8100, 0x88A8):
            raise ValueError("stacked tag requires an inner tag protocol")


__all__ = ("VlanObservation", "VlanTagKind")

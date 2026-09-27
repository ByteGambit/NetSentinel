"""Offline 802.1Q fixtures; no sockets or live network traffic."""

from __future__ import annotations

from scapy.layers.inet import IP
from scapy.layers.l2 import Dot1AD, Dot1Q, Ether
from scapy.packet import Raw


def _ether() -> Ether:
    return Ether(src="00:00:00:00:00:00", dst="ff:ff:ff:ff:ff:ff")


def tagged(vid: int = 42, *, pcp: int = 3, dei: int = 1) -> object:
    return Ether(bytes(_ether() / Dot1Q(vlan=vid, prio=pcp, dei=dei) / IP() / Raw(b"secret")))


def untagged() -> object:
    return Ether(bytes(_ether() / IP() / Raw(b"secret")))


def stacked(*, provider: bool = False, mixed: bool = False) -> object:
    outer = Dot1AD(vlan=11) if provider else Dot1Q(vlan=11)
    inner = Dot1AD(vlan=22) if mixed else Dot1Q(vlan=22)
    return Ether(bytes(_ether() / outer / inner / IP() / Raw(b"secret")))

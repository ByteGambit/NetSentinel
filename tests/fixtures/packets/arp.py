"""Synthetic Scapy ARP request/reply fixtures for NS-021."""

from __future__ import annotations

from scapy.layers.l2 import ARP, Ether


def arp_request() -> object:
    return Ether(
        src="AA:BB:CC:DD:EE:FF",
        dst="FF:FF:FF:FF:FF:FF",
    ) / ARP(
        op=1,
        hwsrc="AA:BB:CC:DD:EE:FF",
        psrc="192.168.1.20",
        hwdst="00:00:00:00:00:00",
        pdst="192.168.1.1",
    )


def arp_reply() -> object:
    return Ether(
        src="00:11:22:33:44:55",
        dst="AA:BB:CC:DD:EE:FF",
    ) / ARP(
        op=2,
        hwsrc="00:11:22:33:44:55",
        psrc="192.168.1.1",
        hwdst="AA:BB:CC:DD:EE:FF",
        pdst="192.168.1.20",
    )

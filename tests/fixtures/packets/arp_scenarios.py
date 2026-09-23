"""Anonymous, in-memory ARP packet scenarios for NS-029."""

from __future__ import annotations

from scapy.layers.l2 import ARP, Ether


def sender(mac: str, ip: str):
    """A passive packet fixture; no socket or packet transmission."""
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc=mac, psrc=ip, hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.10")


NORMAL = (("00:11:22:33:44:55", "192.168.1.1", 0),
          ("00:11:22:33:44:55", "192.168.1.20", 0),
          ("00:11:22:33:44:55", "192.168.1.1", 61),
          ("00:11:22:33:44:55", "192.168.1.20", 61),
          ("00:11:22:33:44:55", "192.168.1.21", 61))

SPOOF_LIKE = (("00:11:22:33:44:66", "192.168.1.1", 62),
              ("00:11:22:33:44:66", "192.168.1.20", 62),
              ("00:11:22:33:44:66", "192.168.1.1", 63))

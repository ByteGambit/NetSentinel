"""In-memory DNS packets for NS-030; these never open capture sockets."""

from __future__ import annotations

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, IPv6, TCP, UDP, raw


def dns_query(*, tcp: bool = False, mdns: bool = False, ipv6: bool = False) -> object:
    ip = IPv6(src="2001:db8::20", dst="ff02::fb" if mdns else "2001:db8::53") if ipv6 else IP(
        src="192.0.2.20", dst="224.0.0.251" if mdns else "198.51.100.53"
    )
    port = 5353 if mdns else 53
    transport = TCP(sport=53000, dport=port, flags="PA") if tcp else UDP(sport=53000, dport=port)
    packet = Ether() / ip / transport / DNS(id=42, qd=DNSQR(qname="Example.COM", qtype="A"))
    return Ether(raw(packet))


def dns_response(*, tcp: bool = False, truncated: bool = False) -> object:
    answers = [
        DNSRR(rrname="Example.COM", type="A", ttl=30, rdata="192.0.2.99"),
        DNSRR(rrname="Example.COM", type="AAAA", ttl=30, rdata="2001:db8::99"),
        DNSRR(rrname="Alias.Example.COM", type="CNAME", ttl=20, rdata="Example.COM"),
        DNSRR(rrname="99.2.0.192.in-addr.arpa", type="PTR", ttl=10, rdata="Host.Example.COM"),
        DNSRR(rrname="Example.COM", type="TXT", ttl=10, rdata="private payload"),
    ]
    transport = TCP(sport=53, dport=53000, flags="PA") if tcp else UDP(sport=53, dport=53000)
    packet = Ether() / IP(src="198.51.100.53", dst="192.0.2.20") / transport / DNS(
        id=42, qr=1, tc=int(truncated), qd=DNSQR(qname="Example.COM"), an=answers
    )
    return Ether(raw(packet))

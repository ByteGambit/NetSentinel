"""Decision cases shared by the NS-042 scenario matrix test."""

from dataclasses import dataclass


@dataclass(frozen=True)
class IdentityCase:
    name: str
    expected_macs: tuple[str, ...]
    expected_ips: tuple[str, ...]
    observed_mac: str
    observed_ip: str
    member: bool = True
    trust: str = "unknown"
    recent_expected: bool = False
    rule: str | None = None
    severity: str | None = None
    confidence: str | None = None


A = "00:11:22:33:44:55"
B = "00:11:22:33:44:66"
PRIVATE = "02:11:22:33:44:77"
IP = "192.168.1.10"
OTHER_IP = "192.168.1.20"

CASES = (
    IdentityCase("no profile", (), (), B, IP, member=False),
    IdentityCase("empty expectations", (), (), B, IP),
    IdentityCase("empty MAC expectation", (), (IP,), B, IP),
    IdentityCase("empty IP expectation", (A,), (), A, OTHER_IP),
    IdentityCase("expected MAC and IP", (A,), (IP,), A, IP),
    IdentityCase("one of several expected MACs", (A, B, PRIVATE), (IP,), B, IP),
    IdentityCase("expected locally administered MAC", (PRIVATE,), (IP,), PRIVATE, IP),
    IdentityCase("single DHCP renewal", (A,), (IP,), A, OTHER_IP),
    IdentityCase("unexpected MAC at expected IP", (A,), (IP,), B, IP,
                 rule="device_mac_identity_change", severity="low", confidence="low"),
    IdentityCase("trusted corroborated mismatch", (A,), (IP,), B, IP,
                 trust="trusted", recent_expected=True,
                 rule="device_mac_identity_change", severity="medium", confidence="moderate"),
    IdentityCase("untrusted corroborated mismatch", (A,), (IP,), B, IP,
                 trust="untrusted", recent_expected=True,
                 rule="device_mac_identity_change", severity="low", confidence="moderate"),
    IdentityCase("new private MAC remains low", (A,), (IP,), PRIVATE, IP,
                 trust="trusted", recent_expected=True,
                 rule="device_mac_identity_change", severity="low", confidence="moderate"),
    IdentityCase("member MAC changes and IP remains expected", (A,), (IP,), B, IP,
                 rule="device_mac_identity_change", severity="low", confidence="low"),
    IdentityCase("member MAC and IP both change", (A,), (IP,), B, OTHER_IP,
                 rule="device_mac_identity_change", severity="low", confidence="low"),
)

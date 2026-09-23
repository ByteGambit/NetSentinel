"""NS-032 Windows DNS server-set change detection over portable context data."""

from __future__ import annotations

from hashlib import sha256

from netsentinel.domain.alerts import AlertCandidate, AlertEvidence
from netsentinel.domain.dns_config import DnsServerChange


RULE_ID = "dns_server_set_change"


class DnsConfigChangeDetector:
    """Translate confirmed configuration evidence into a conservative alert."""

    def assess(self, change: DnsServerChange) -> AlertCandidate:
        if not isinstance(change, DnsServerChange):
            raise TypeError("change must be DnsServerChange")
        identity = "\0".join((RULE_ID, change.network_fingerprint,
                              ",".join(change.previous_servers),
                              ",".join(change.current_servers)))
        return AlertCandidate(
            fingerprint=sha256(identity.encode("ascii")).hexdigest(),
            rule_id=RULE_ID,
            network_fingerprint=change.network_fingerprint,
            entity_id=change.network_fingerprint,
            severity="low",
            confidence="moderate",
            evidence=AlertEvidence(
                observed_at=change.confirmed_at,
                observation_count=change.confirmation_count,
                details=(
                    ("previous_dns", ",".join(change.previous_servers)),
                    ("current_dns", ",".join(change.current_servers)),
                    ("first_seen_utc", change.first_observed_at.isoformat()),
                    ("interface_kind", change.interface_kind.value),
                    ("confirmation", "repeated_windows_config_read"),
                ),
            ),
        )


__all__ = ("DnsConfigChangeDetector", "RULE_ID")

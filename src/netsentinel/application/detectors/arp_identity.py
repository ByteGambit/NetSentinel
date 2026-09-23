"""NS-026 passive ARP identity discrepancies over persisted observations."""

from __future__ import annotations

from datetime import timedelta
from ipaddress import IPv4Address

from netsentinel.application.ports import DeviceRepository, NetworkContextProvider
from netsentinel.application.services.baselines import GatewayBaselineService, GatewayContextChanged
from netsentinel.domain.alerts import (
    ArpIdentityConflictDetected, ArpIdentityEvidence, ArpIdentityReason, ArpIdentityRule,
)
from netsentinel.domain.devices import GatewayBaselineStatus, NetworkContext
from netsentinel.domain.observations import MacAddress, PacketObservation


def _sender(context: NetworkContext, observation: PacketObservation) -> tuple[IPv4Address, MacAddress] | None:
    if not isinstance(context, NetworkContext) or not isinstance(observation, PacketObservation):
        raise TypeError("context and observation must be portable network models")
    if (observation.network_fingerprint != context.fingerprint
            or observation.interface_id.casefold() != context.interface_id.casefold()
            or observation.interface_index != context.interface_index
            or observation.observed_at < context.observed_at
            or observation.arp is None):
        return None
    arp = observation.arp
    ip = IPv4Address(arp.sender_ip)
    mac = arp.sender_mac
    if (mac.is_zero or mac.is_multicast or ip.is_unspecified or ip.is_loopback
            or ip.is_multicast or ip.is_reserved or ip == IPv4Address("255.255.255.255")):
        return None
    # Announcements (sender == target) commonly accompany legitimate failover,
    # DHCP, and router restart. NS-027 may later correlate them as weak signals.
    if arp.sender_ip == arp.target_ip:
        return None
    return ip, mac


class IpMacConflictDetector:
    """Compare one sender against the latest persisted sender of the same IP.

    Call before recording the incoming binding. The repository is the state
    source; no second learner, worker, cooldown map, or alert schema is needed.
    A long gap is treated as DHCP/reconfiguration rather than a live conflict.
    """

    def __init__(self, repository: DeviceRepository, contexts: NetworkContextProvider,
                 *, warmup: timedelta = timedelta(seconds=60),
                 conflict_window: timedelta = timedelta(seconds=120)) -> None:
        if warmup < timedelta(0) or conflict_window <= timedelta(0):
            raise ValueError("windows must be positive")
        self._repository = repository
        self._contexts = contexts
        self._warmup = warmup
        self._window = conflict_window

    def observe(self, context: NetworkContext, observation: PacketObservation) -> ArpIdentityConflictDetected | None:
        sender = _sender(context, observation)
        if sender is None:
            return None
        if not any(item.fingerprint == context.fingerprint
                   and item.interface_id.casefold() == context.interface_id.casefold()
                   and item.interface_index == context.interface_index
                   and item.gateway == context.gateway
                   for item in self._contexts.get_contexts()):
            return None
        ip, mac = sender
        # Gateway uses the more specific NS-025 expected identity and must not
        # be classified again from ordinary device binding history.
        if context.gateway == str(ip):
            return None
        previous = self._repository.latest_binding_for_ip(context.fingerprint, str(ip))
        if previous is None or previous.mac == mac:
            return None
        at = observation.observed_at
        if (at <= previous.last_seen or at - previous.last_seen > self._window
                or at - previous.first_seen < self._warmup):
            return None
        return ArpIdentityConflictDetected(
            ArpIdentityRule.IP_MAC_CONFLICT, ArpIdentityReason.RECENT_SENDER_CONFLICT,
            ArpIdentityEvidence(context.fingerprint, str(ip), previous.mac, mac,
                                previous.last_seen, at),
            "low", "low",
        )


class GatewayMacChangeDetector:
    """Compare the current gateway sender to NS-025's persisted expected MAC."""

    def __init__(self, baseline: GatewayBaselineService) -> None:
        self._baseline = baseline

    def observe(self, context: NetworkContext, observation: PacketObservation) -> ArpIdentityConflictDetected | None:
        sender = _sender(context, observation)
        if sender is None or context.gateway is None or str(sender[0]) != context.gateway:
            return None
        try:
            baseline = self._baseline.get(context)
        except GatewayContextChanged:
            return None
        if (baseline is None or baseline.status is GatewayBaselineStatus.LEARNING
                or baseline.gateway_ip != context.gateway):
            return None
        mac = sender[1]
        if mac == baseline.mac or observation.observed_at <= baseline.last_seen:
            return None
        if baseline.pending_seen_at is not None and observation.observed_at <= baseline.pending_seen_at:
            return None
        if baseline.pending_mac == mac and baseline.pending_seen_at is not None and baseline.pending_seen_at >= baseline.last_seen:
            return None
        verified = baseline.status is GatewayBaselineStatus.VERIFIED
        return ArpIdentityConflictDetected(
            ArpIdentityRule.GATEWAY_MAC_CHANGE,
            ArpIdentityReason.VERIFIED_GATEWAY_CONFLICT if verified else ArpIdentityReason.LEARNED_GATEWAY_CONFLICT,
            ArpIdentityEvidence(context.fingerprint, context.gateway, baseline.mac, mac,
                                baseline.last_seen, observation.observed_at, baseline.status),
            "medium" if verified and not mac.is_locally_administered else "low",
            "low",
        )


__all__ = ("GatewayMacChangeDetector", "IpMacConflictDetector")

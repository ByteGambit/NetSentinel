"""NS-025 passive, scoped gateway identity learning; no alert decisions."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from collections.abc import Callable

from netsentinel.application.ports import GatewayBaselineRepository, NetworkContextProvider
from netsentinel.domain.devices import (
    GatewayBaseline, GatewayBaselineChange, GatewayBaselineStatus, NetworkContext,
)
from netsentinel.domain.observations import MacAddress, PacketObservation


class GatewayContextChanged(ValueError):
    """The selected network is no longer current or observation is from another scope."""


class GatewayConfirmationUnavailable(ValueError):
    """There is no learned candidate to confirm."""


class GatewayBaselineService:
    """Synchronous service for the existing single ARP consumer.

    Passive observations can only move a conflict-free candidate from learning
    to learned after two observations and a 60-second window. Only an explicit
    user command can set or replace a verified expected MAC. An observed conflict
    is retained as a conservative learning veto, not interpreted as an attack.
    """

    def __init__(
        self,
        repository: GatewayBaselineRepository,
        context_provider: NetworkContextProvider,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        learning_window: timedelta = timedelta(seconds=60),
    ) -> None:
        if not isinstance(learning_window, timedelta):
            raise TypeError("learning_window must be a timedelta")
        if learning_window < timedelta(0):
            raise ValueError("learning_window cannot be negative")
        self._repository = repository
        self._context_provider = context_provider
        self._clock = clock
        self._learning_window = learning_window

    def get(self, context: NetworkContext) -> GatewayBaseline | None:
        self._require_current(context)
        return self._repository.get(context.fingerprint)

    def changes(self, context: NetworkContext) -> tuple[GatewayBaselineChange, ...]:
        self._require_current(context)
        return self._repository.changes(context.fingerprint)

    def observe(
        self, context: NetworkContext, observation: PacketObservation
    ) -> GatewayBaseline | None:
        self._require_current(context)
        if not isinstance(observation, PacketObservation):
            raise TypeError("observation must be a PacketObservation")
        if (
            observation.network_fingerprint != context.fingerprint
            or observation.interface_id.casefold() != context.interface_id.casefold()
            or observation.interface_index != context.interface_index
        ):
            raise GatewayContextChanged("Observation network context does not match.")
        if context.gateway is None or observation.arp is None:
            return None
        arp = observation.arp
        if arp.sender_ip != context.gateway:
            return None
        mac = arp.sender_mac
        ip = IPv4Address(arp.sender_ip)
        if mac.is_zero or mac.is_multicast or ip.is_unspecified or ip.is_multicast or ip.is_loopback:
            return None
        old = self._repository.get(context.fingerprint)
        at = observation.observed_at
        if at < context.observed_at:
            return old
        now = self._now()
        if old is None:
            baseline = GatewayBaseline(
                context.fingerprint, context.gateway, mac, GatewayBaselineStatus.LEARNING,
                at, at, now, 1,
            )
            change = GatewayBaselineChange(
                context.fingerprint, context.gateway, None, mac, at, "first_observation"
            )
            return self._repository.save(baseline, change)
        if old.gateway_ip != context.gateway:
            raise GatewayContextChanged("Stored gateway does not match context.")
        if at < old.last_seen or (at == old.last_seen and mac == old.mac):
            return old
        if mac != old.mac:
            if old.pending_seen_at is not None and at <= old.pending_seen_at:
                return old
            return self._repository.save(replace(
                old,
                conflicted=old.conflicted or old.status is GatewayBaselineStatus.LEARNING,
                pending_mac=mac, pending_seen_at=at,
            ))
        status = old.status
        count = min(old.observation_count + 1, 2_147_483_647)
        if (
            status is GatewayBaselineStatus.LEARNING
            and not old.conflicted
            and count >= 2
            and now >= old.learning_started_at + self._learning_window
        ):
            status = GatewayBaselineStatus.LEARNED
        return self._repository.save(
            replace(old, last_seen=at, observation_count=count, status=status)
        )

    def confirm(self, context: NetworkContext, mac: MacAddress) -> GatewayBaseline:
        """Explicit user confirmation of an observed gateway MAC."""

        self._require_current(context)
        if not isinstance(mac, MacAddress) or mac.is_zero or mac.is_multicast:
            raise ValueError("mac must be a nonzero unicast MacAddress")
        old = self._repository.get(context.fingerprint)
        if old is None:
            raise GatewayConfirmationUnavailable("No gateway candidate has been observed.")
        if old.gateway_ip != context.gateway:
            raise GatewayContextChanged("Stored gateway does not match context.")
        if mac != old.mac and mac != old.pending_mac:
            raise GatewayConfirmationUnavailable("Confirm the observed candidate only.")
        if old.status is GatewayBaselineStatus.VERIFIED and mac == old.mac:
            return old
        now = self._now()
        if now < max(old.learning_started_at, old.pending_seen_at or old.learning_started_at):
            raise ValueError("confirmation time cannot precede learning")
        verified = replace(
            old,
            mac=mac,
            status=GatewayBaselineStatus.VERIFIED,
            verified_at=now,
            last_seen=max(old.last_seen, old.pending_seen_at or old.last_seen),
            conflicted=False,
            pending_mac=None,
            pending_seen_at=None,
        )
        return self._repository.save(
            verified,
            GatewayBaselineChange(
                context.fingerprint, context.gateway, old.mac, mac,
                now, "user_confirmation",
            ),
        )

    def _require_current(self, context: NetworkContext) -> None:
        if not isinstance(context, NetworkContext):
            raise TypeError("context must be a NetworkContext")
        current = self._context_provider.get_contexts()
        if not any(
            item.fingerprint == context.fingerprint
            and item.interface_id.casefold() == context.interface_id.casefold()
            and item.interface_index == context.interface_index
            and item.gateway == context.gateway
            for item in current
        ):
            raise GatewayContextChanged("Selected network context is no longer current.")

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("clock must return a UTC-aware datetime")
        return value.astimezone(UTC)


__all__ = ("GatewayBaselineService", "GatewayConfirmationUnavailable", "GatewayContextChanged")

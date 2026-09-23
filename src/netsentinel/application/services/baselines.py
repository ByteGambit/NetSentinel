"""NS-025 passive, scoped gateway identity learning; no alert decisions."""

from __future__ import annotations

from dataclasses import replace
from dataclasses import dataclass
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from collections.abc import Callable
from time import monotonic
from math import isfinite

from netsentinel.application.ports import GatewayBaselineRepository, NetworkContextProvider
from netsentinel.domain.devices import (
    GatewayBaseline, GatewayBaselineChange, GatewayBaselineStatus, NetworkContext,
)
from netsentinel.domain.observations import MacAddress, PacketObservation
from netsentinel.domain.dns_config import DnsServerChange


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


@dataclass(slots=True)
class _DnsBaseline:
    servers: tuple[str, ...]
    last_observed_at: datetime
    last_tick: float
    confirmed: bool = False
    pending: tuple[str, ...] | None = None
    pending_since: datetime | None = None
    pending_count: int = 0


class DnsServerBaselineService:
    """Bounded, memory-only baseline of Windows DNS server sets per network.

    Empty or oversized reads cannot replace an established baseline. A new set
    must appear in two ordered polls before replacing it. Clock rollback and
    stale snapshots cannot advance confirmation. No DNS packet is involved.
    """

    def __init__(self, *, clock: Callable[[], float] = monotonic,
                 max_contexts: int = 256, idle_expiry: float = 86_400.0) -> None:
        if type(max_contexts) is not int or not 1 <= max_contexts <= 4_096:
            raise ValueError("max_contexts must be between 1 and 4096")
        if not isinstance(idle_expiry, (int, float)) or not isfinite(idle_expiry) or idle_expiry <= 0:
            raise ValueError("idle_expiry must be positive")
        self._clock = clock
        self._max_contexts = max_contexts
        self._idle_expiry = float(idle_expiry)
        self._state: OrderedDict[str, _DnsBaseline] = OrderedDict()

    @property
    def tracked_contexts(self) -> int:
        return len(self._state)

    def interrupt(self) -> None:
        """A failed whole read breaks confirmation continuity."""
        for key, state in tuple(self._state.items()):
            if not state.confirmed:
                del self._state[key]
                continue
            state.pending = None
            state.pending_since = None
            state.pending_count = 0

    def interrupt_absent(self, seen: set[str]) -> None:
        """A disappeared interface breaks a pending change, not its baseline."""
        for key, state in tuple(self._state.items()):
            if key not in seen:
                if not state.confirmed:
                    del self._state[key]
                else:
                    state.pending = None
                    state.pending_since = None
                    state.pending_count = 0

    def observe(self, context: NetworkContext) -> DnsServerChange | None:
        if not isinstance(context, NetworkContext):
            raise TypeError("context must be NetworkContext")
        tick = float(self._clock())
        if not isfinite(tick):
            raise ValueError("monotonic clock must be finite")
        for key, state in tuple(self._state.items()):
            if tick >= state.last_tick and tick - state.last_tick > self._idle_expiry:
                del self._state[key]
        servers = context.dns_servers
        old = self._state.get(context.fingerprint)
        if not servers or len(servers) > 8:
            if old is not None:
                old.pending = None
                old.pending_since = None
                old.pending_count = 0
            return None
        if old is None:
            if len(self._state) >= self._max_contexts:
                self._state.popitem(last=False)
            self._state[context.fingerprint] = _DnsBaseline(servers, context.observed_at, tick)
            return None
        if tick <= old.last_tick or context.observed_at <= old.last_observed_at:
            return None
        old.last_tick = tick
        old.last_observed_at = context.observed_at
        self._state.move_to_end(context.fingerprint)
        if not old.confirmed:
            if servers == old.servers:
                old.confirmed = True
            else:
                old.servers = servers
            return None
        if servers == old.servers:
            old.pending = None
            old.pending_since = None
            old.pending_count = 0
            return None
        if servers != old.pending:
            old.pending = servers
            old.pending_since = context.observed_at
            old.pending_count = 1
            return None
        old.pending_count = min(2, old.pending_count + 1)
        change = DnsServerChange(context.fingerprint, context.interface_kind,
                                 old.servers, servers, old.pending_since,
                                 context.observed_at, old.pending_count)
        return change

    def commit(self, change: DnsServerChange) -> None:
        """Advance the expected set only after the alert sink accepted evidence."""
        old = self._state.get(change.network_fingerprint)
        if old is None or old.servers != change.previous_servers or old.pending != change.current_servers:
            raise ValueError("DNS baseline no longer matches change")
        old.servers = change.current_servers
        old.pending = None
        old.pending_since = None
        old.pending_count = 0


__all__ = ("GatewayBaselineService", "GatewayConfirmationUnavailable", "GatewayContextChanged", "DnsServerBaselineService")

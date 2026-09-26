"""NS-044 observed VLAN aggregates and conservative passive learning."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from netsentinel.application.ports import VlanSummaryRepository
from netsentinel.domain.devices import NetworkContext
from netsentinel.domain.observations import PacketObservation
from netsentinel.domain.vlan import VlanTagKind
from netsentinel.domain.vlan_summary import VlanBaselineState, VlanIdSummary, VlanSummarySnapshot


MAX_VLAN_IDS = 128
MAX_COUNT = 9_223_372_036_854_775_807


class VlanContextChanged(ValueError):
    """The observation belongs to a different network or interface."""


class VlanBaselineNotReady(ValueError):
    """Explicit verification requires a complete learned passive reference."""


class VlanSummaryService:
    """Synchronous service owned by the existing passive capture consumer.

    Counts represent captured frames, including repeated equal observations.
    At least two normal-tag observations over 60 seconds establish a *learned*
    reference. Only VIDs observed twice enter it. Passive evidence never becomes
    user-verified configuration.
    Newly seen VIDs after learning remain visible but cannot silently enter
    the frozen learned set. VID 0, 4095, and stacked tags have distinct counts
    and are never learned as ordinary VLAN membership.
    """

    def __init__(self, repository: VlanSummaryRepository, *,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC),
                 warmup: timedelta = timedelta(seconds=60),
                 minimum_observations: int = 2) -> None:
        if not isinstance(warmup, timedelta) or warmup < timedelta(0):
            raise ValueError("warmup must be a nonnegative timedelta")
        if type(minimum_observations) is not int or not 2 <= minimum_observations <= 1000:
            raise ValueError("minimum observations must be 2..1000")
        self._repository = repository
        self._clock = clock
        self._warmup = warmup
        self._minimum = minimum_observations

    def get(self, context: NetworkContext) -> VlanSummarySnapshot | None:
        if not isinstance(context, NetworkContext):
            raise TypeError("context must be NetworkContext")
        return self._repository.get(context.fingerprint, context.interface_id.casefold(),
                                    context.interface_index)

    def verify_baseline(self, context: NetworkContext) -> VlanSummarySnapshot:
        """Explicitly accept the frozen observed VID set for this exact scope.

        Verification is a user-owned command contract, never an effect of a
        packet. It does not assert switch configuration or traffic visibility.
        """
        summary = self.get(context)
        if summary is None or summary.baseline_state is VlanBaselineState.LEARNING:
            raise VlanBaselineNotReady("VLAN baseline has not finished passive learning")
        if summary.overflow_count or not summary.learned_vlan_ids:
            raise VlanBaselineNotReady("VLAN baseline is incomplete")
        return self._repository.verify(summary.network_fingerprint, summary.interface_id,
                                       summary.interface_index, self._now())

    def observe(self, context: NetworkContext,
                observation: PacketObservation) -> VlanSummarySnapshot | None:
        if not isinstance(context, NetworkContext) or not isinstance(observation, PacketObservation):
            raise TypeError("context and observation must be portable models")
        if (observation.network_fingerprint != context.fingerprint or
                observation.interface_id.casefold() != context.interface_id.casefold() or
                observation.interface_index != context.interface_index):
            raise VlanContextChanged("VLAN observation scope does not match context")
        vlan = observation.vlan
        if vlan is None:
            return None
        now = self._now()
        old = self.get(context)
        at = observation.observed_at
        if old is None:
            old = VlanSummarySnapshot(
                context.fingerprint, context.interface_id.casefold(), context.interface_index,
                at, at, now, VlanBaselineState.LEARNING, 0, 0, 0, 0, 0, 0, (),
            )
        counts = {
            VlanTagKind.UNTAGGED: "untagged_count",
            VlanTagKind.TAGGED: "tagged_count",
            VlanTagKind.PRIORITY_TAGGED: "priority_tagged_count",
            VlanTagKind.RESERVED: "reserved_count",
            VlanTagKind.STACKED: "stacked_count",
        }
        field = counts[vlan.kind]
        entries = {item.vlan_id: item for item in old.vlan_ids}
        overflow = old.overflow_count
        if vlan.kind is VlanTagKind.TAGGED:
            vid = vlan.vlan_id
            assert vid is not None
            current = entries.get(vid)
            if current is not None:
                entries[vid] = replace(current, count=_increment(current.count),
                                       first_seen=min(current.first_seen, at),
                                       last_seen=max(current.last_seen, at))
            elif len(entries) < MAX_VLAN_IDS:
                entries[vid] = VlanIdSummary(vid, 1, at, at)
            else:
                overflow = _increment(overflow)
        values = {field: _increment(getattr(old, field))}
        state = old.baseline_state
        if (state is VlanBaselineState.LEARNING and
                now >= old.learning_started_at + self._warmup and
                old.tagged_count + (vlan.kind is VlanTagKind.TAGGED) >= self._minimum and
                any(item.count >= self._minimum for item in entries.values())):
            state = VlanBaselineState.LEARNED
            entries = {vid: replace(item, learned=item.count >= self._minimum)
                       for vid, item in entries.items()}
        summary = replace(old, **values, overflow_count=overflow,
                          first_seen=min(old.first_seen, at), last_seen=max(old.last_seen, at),
                          baseline_state=state,
                          vlan_ids=tuple(entries[vid] for vid in sorted(entries)))
        return self._repository.save(summary)

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ValueError("clock must return a UTC-aware datetime")
        return now.astimezone(UTC)


def _increment(value: int) -> int:
    return min(value + 1, MAX_COUNT)


__all__ = ("MAX_VLAN_IDS", "VlanBaselineNotReady", "VlanContextChanged", "VlanSummaryService")

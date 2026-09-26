"""NS-045 passive VLAN decisions from NS-044 summaries and portable observations.

The result is an AlertCandidate for a later consumer. This module does not write
alerts, learn a scope VLAN baseline, or inspect raw packets.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from math import isfinite
from time import monotonic
from uuid import UUID

from netsentinel.domain.alerts import AlertCandidate, AlertEvidence
from netsentinel.domain.devices import DeviceIdentity
from netsentinel.domain.observations import PacketObservation
from netsentinel.domain.vlan import VlanTagKind
from netsentinel.domain.vlan_summary import VlanBaselineState, VlanSummarySnapshot


NEW_VID_RULE = "vlan_previously_unobserved_vid"
DEVICE_SWITCH_RULE = "vlan_device_tag_change"
DIVERSITY_RULE = "vlan_unusual_diversity"
CONFIRMATION_COUNT = 2
CONFIRMATION_SECONDS = 120
DIVERSITY_SECONDS = 60
DIVERSITY_VIDS = 3
IDLE_EXPIRY_SECONDS = 600
MAX_STATES = 512

_Scope = tuple[str, str, int]
_Key = tuple[str, _Scope, str]
_DeviceKey = tuple[_Scope, UUID]


@dataclass(slots=True)
class _CandidateState:
    first_at: datetime
    last_at: datetime
    first_tick: float
    last_tick: float
    count: int = 1
    emitted: bool = False


@dataclass(slots=True)
class _DeviceState:
    current_vid: int
    last_at: datetime
    last_tick: float
    pending_vid: int | None = None
    pending_first_at: datetime | None = None
    pending_first_tick: float | None = None
    pending_count: int = 0


class VlanAnomalyDetector:
    """Evaluate visible normal VIDs against an explicitly accepted baseline.

    Source MAC is merely a passive observed-device identity. Device tag history
    is short-lived detector confirmation state, never a trusted VLAN baseline.
    """

    def __init__(self, *, clock: Callable[[], float] = monotonic,
                 max_states: int = MAX_STATES) -> None:
        if type(max_states) is not int or not 1 <= max_states <= MAX_STATES:
            raise ValueError("max_states must be 1..512")
        self._clock = clock
        self._max_states = max_states
        self._states: dict[_Key, _CandidateState] = {}
        self._devices: dict[_DeviceKey, _DeviceState] = {}
        self._last_tick: float | None = None

    @property
    def tracked_states(self) -> int:
        return len(self._states) + len(self._devices)

    def observe(self, summary: VlanSummarySnapshot,
                observation: PacketObservation) -> tuple[AlertCandidate, ...]:
        if not isinstance(summary, VlanSummarySnapshot) or not isinstance(observation, PacketObservation):
            raise TypeError("portable VLAN summary and packet observation required")
        scope = (summary.network_fingerprint, summary.interface_id, summary.interface_index)
        if scope != (observation.network_fingerprint, observation.interface_id.casefold(),
                     observation.interface_index):
            raise ValueError("VLAN summary and observation scopes differ")
        tick = self._now()
        self._expire(tick)
        vlan = observation.vlan
        # These classes are visible metadata, not ordinary VLAN membership.
        if vlan is None or vlan.kind is not VlanTagKind.TAGGED:
            return ()
        vid = vlan.vlan_id
        assert vid is not None
        if (summary.baseline_state is not VlanBaselineState.VERIFIED or
                summary.overflow_count or not summary.learned_vlan_ids):
            return ()
        entry = next((item for item in summary.vlan_ids if item.vlan_id == vid), None)
        if entry is None or not entry.first_seen <= observation.observed_at <= entry.last_seen:
            raise ValueError("current VID is absent from the NS-044 summary")
        at = observation.observed_at.astimezone(UTC)
        results: list[AlertCandidate] = []
        if vid not in summary.learned_vlan_ids:
            new_key = (NEW_VID_RULE, scope, str(vid))
            new_state, advanced = self._advance(new_key, at, tick)
            if advanced and new_state.count >= CONFIRMATION_COUNT and not new_state.emitted:
                results.append(self._candidate(NEW_VID_RULE, scope, str(vid), vid, summary,
                                               new_state, "low", "low", "repeated_passive_tag"))
                new_state.emitted = True
        source = observation.ethernet_source_mac
        if source is not None and not (source.is_zero or source.is_broadcast or source.is_multicast):
            device_id = DeviceIdentity(scope[0], source, at, at).device_id
            device_result = self._observe_device(scope, device_id, vid, at, tick, summary)
            if device_result is not None:
                results.append(device_result)
        # Diversity counts distinct confirmed unexpected VIDs in this short
        # processing-time window. A single frame for each VID cannot trigger it.
        confirmed = sorted((int(key[2]), state) for key, state in self._states.items()
                           if key[0] == NEW_VID_RULE and key[1] == scope
                           and state.count >= CONFIRMATION_COUNT
                           and tick - state.last_tick < DIVERSITY_SECONDS)
        if len(confirmed) >= DIVERSITY_VIDS:
            key = (DIVERSITY_RULE, scope, "multiple")
            state, _ = self._advance(key, at, tick)
            if not state.emitted:
                results.append(self._candidate(DIVERSITY_RULE, scope, "multiple", vid,
                                               summary, state, "medium", "low",
                                               "three_confirmed_unseen_vids",
                                               observed_vids=tuple(item[0] for item in confirmed)))
                state.emitted = True
        return tuple(results)

    def _observe_device(self, scope: _Scope, device_id: UUID, vid: int,
                        at: datetime, tick: float,
                        summary: VlanSummarySnapshot) -> AlertCandidate | None:
        key = (scope, device_id)
        state = self._devices.get(key)
        if state is None:
            self._make_room()
            self._devices[key] = _DeviceState(vid, at, tick)
            return None
        if at <= state.last_at:
            return None
        state.last_at = at
        state.last_tick = tick
        if vid == state.current_vid:
            state.pending_vid = None
            state.pending_first_at = None
            state.pending_first_tick = None
            state.pending_count = 0
            return None
        if (state.pending_vid != vid or state.pending_first_tick is None or
                tick - state.pending_first_tick >= CONFIRMATION_SECONDS):
            state.pending_vid = vid
            state.pending_first_at = at
            state.pending_first_tick = tick
            state.pending_count = 1
            return None
        state.pending_count += 1
        if state.pending_count < CONFIRMATION_COUNT:
            return None
        previous = state.current_vid
        first_at = state.pending_first_at
        first_tick = state.pending_first_tick
        assert first_at is not None and first_tick is not None
        evidence = _CandidateState(first_at, at, first_tick, tick, state.pending_count)
        state.current_vid = vid
        state.pending_vid = None
        state.pending_first_at = None
        state.pending_first_tick = None
        state.pending_count = 0
        return self._candidate(DEVICE_SWITCH_RULE, scope, f"{device_id}:{previous}:{vid}",
                               vid, summary, evidence, "low", "low",
                               f"previously_observed_vid:{previous}")

    def _advance(self, key: _Key, at: datetime, tick: float) -> tuple[_CandidateState, bool]:
        state = self._states.get(key)
        if state is not None and at <= state.last_at:
            return state, False
        if state is None or tick - state.last_tick >= CONFIRMATION_SECONDS:
            if state is None:
                self._make_room()
            state = _CandidateState(at, at, tick, tick)
            self._states[key] = state
        else:
            state.last_at = at
            state.last_tick = tick
            state.count = min(state.count + 1, CONFIRMATION_COUNT)
        return state, True

    def _candidate(self, rule: str, scope: _Scope, identity: str, vid: int,
                   summary: VlanSummarySnapshot, state: _CandidateState,
                   severity: str, confidence: str, basis: str,
                   observed_vids: tuple[int, ...] = ()) -> AlertCandidate:
        interface = f"{scope[1]}#{scope[2]}"
        if len(interface) > 128 or not interface.isascii() or not interface.isprintable():
            interface = sha256(interface.encode("utf-8")).hexdigest()
        learned = ",".join(map(str, summary.learned_vlan_ids[:12]))
        if len(summary.learned_vlan_ids) > 12:
            learned += f",+{len(summary.learned_vlan_ids) - 12}"
        entity = sha256("\0".join((scope[0], scope[1], str(scope[2]), identity)).encode()).hexdigest()
        fingerprint = sha256("\0".join((rule, *scope[:2], str(scope[2]), identity)).encode()).hexdigest()
        identity_detail = (("device_id", identity.split(":", 1)[0]) if rule == DEVICE_SWITCH_RULE
                           else ("learned_vids", learned))
        return AlertCandidate(
            fingerprint, rule, scope[0], entity, severity, confidence,
            AlertEvidence(state.last_at,
                          observation_count=len(observed_vids) if observed_vids else state.count,
                          details=(("interface", interface),
                                   ("vid", ",".join(map(str, observed_vids[:12])) if observed_vids else str(vid)),
                                   ("category", "tagged"), ("baseline", "verified_observed"),
                                   identity_detail, ("first_observed", state.first_at.isoformat()),
                                   ("confidence_basis", basis),
                                   ("visibility", "capture_filter_and_nic_offload_limited"))),
        )

    def _expire(self, tick: float) -> None:
        for key, state in tuple(self._states.items()):
            if tick - state.last_tick >= IDLE_EXPIRY_SECONDS:
                del self._states[key]
        for key, state in tuple(self._devices.items()):
            if tick - state.last_tick >= IDLE_EXPIRY_SECONDS:
                del self._devices[key]

    def _make_room(self) -> None:
        if self.tracked_states < self._max_states:
            return
        choices = ([(state.last_tick, "signal", str(key), key) for key, state in self._states.items()]
                   + [(state.last_tick, "device", str(key), key) for key, state in self._devices.items()])
        _, kind, _, key = min(choices)
        if kind == "signal":
            del self._states[key]
        else:
            del self._devices[key]

    def _now(self) -> float:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value):
            raise ValueError("monotonic clock must be finite")
        self._last_tick = float(value) if self._last_tick is None else max(self._last_tick, float(value))
        return self._last_tick


__all__ = ("VlanAnomalyDetector", "NEW_VID_RULE", "DEVICE_SWITCH_RULE", "DIVERSITY_RULE")

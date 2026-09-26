"""NS-040: conservative profile identity signals from passive device metadata."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from uuid import UUID

from netsentinel.domain.alerts import AlertCandidate, AlertEvidence
from netsentinel.domain.devices import DeviceIdentity, DeviceProfile, DeviceTrust, IdentityBinding, NetworkContext
from netsentinel.domain.observations import MacAddress


MAC_RULE = "device_mac_identity_change"
CONTEXT_RULE = "device_identity_context_mismatch"
IP_CHURN_RULE = "device_ip_churn"
HISTORY_WINDOW = timedelta(minutes=5)
RECENT_CONFLICT_WINDOW = timedelta(minutes=2)
MAX_STATES = 512


@dataclass(slots=True)
class _SignalState:
    profile_id: UUID
    last_seen: datetime
    persisted: bool = False


class DeviceIdentityChangeDetector:
    """Compare one network's explicit expectations with its passive observations.

    The profile snapshot is replaced once per inventory refresh. It is never a
    user-data writer or persistent source of truth. AlertService owns all alert
    state; a signal is marked delivered only after its write succeeds.
    """

    def __init__(self) -> None:
        self._profiles: dict[UUID, DeviceProfile] = {}
        self._members: dict[UUID, UUID] = {}
        self._expected_ips: dict[str, set[UUID]] = {}
        self._recent: dict[UUID, tuple[IdentityBinding, ...]] = {}
        self._states: dict[str, _SignalState] = {}
        self._network: str | None = None
        self._snapshot_at: datetime | None = None

    @property
    def tracked_states(self) -> int:
        return len(self._states)

    def replace_snapshot(
        self,
        network_fingerprint: str,
        rows: tuple[tuple[DeviceProfile, tuple[UUID, ...], tuple[IdentityBinding, ...]], ...],
        now: datetime,
    ) -> None:
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise ValueError("now must be UTC-aware")
        profiles: dict[UUID, DeviceProfile] = {}
        members: dict[UUID, UUID] = {}
        expected_ips: dict[str, set[UUID]] = {}
        recent: dict[UUID, tuple[IdentityBinding, ...]] = {}
        for profile, device_ids, bindings in rows:
            if profile.network_fingerprint != network_fingerprint or profile.merged_into is not None:
                raise ValueError("profile snapshot has an invalid network or merged alias")
            member_ids = set(device_ids)
            if any(binding.network_fingerprint != network_fingerprint or binding.device_id not in member_ids
                   for binding in bindings):
                raise ValueError("recent binding does not belong to profile scope")
            profiles[profile.profile_id] = profile
            recent[profile.profile_id] = bindings
            for device_id in device_ids:
                if device_id in members:
                    raise ValueError("device belongs to multiple profiles")
                members[device_id] = profile.profile_id
            for ip in profile.expected_ips:
                expected_ips.setdefault(ip, set()).add(profile.profile_id)
        # A user edit or merge invalidates old detector state before comparison.
        for fingerprint, state in tuple(self._states.items()):
            previous = self._profiles.get(state.profile_id)
            current = profiles.get(state.profile_id)
            if (current is None or previous is None or
                previous.expected_macs != current.expected_macs or
                previous.expected_ips != current.expected_ips or
                previous.trust != current.trust or
                now - state.last_seen >= HISTORY_WINDOW * 2):
                del self._states[fingerprint]
        self._network = network_fingerprint
        self._snapshot_at = now
        self._profiles = profiles
        self._members = members
        self._expected_ips = expected_ips
        self._recent = recent

    def observe(
        self, context: NetworkContext, device: DeviceIdentity, binding: IdentityBinding,
        observed_at: datetime,
    ) -> tuple[AlertCandidate, ...]:
        if (context.fingerprint != self._network or
            device.network_fingerprint != context.fingerprint or
            binding.network_fingerprint != context.fingerprint or
            device.device_id != binding.device_id or
            device.mac != binding.mac or
            observed_at.tzinfo is None or observed_at.utcoffset() != timedelta(0)):
            raise ValueError("device observation does not match current profile scope")
        if self._snapshot_at is None or observed_at < self._snapshot_at - HISTORY_WINDOW:
            return ()
        # Registry last_seen is monotonic; an older packet must not become a new signal.
        if device.last_seen > observed_at or binding.last_seen > observed_at:
            return ()
        owner_id = self._members.get(device.device_id)
        ip_owners = self._expected_ips.get(binding.ip_address, set())
        ip_owner_id = next(iter(ip_owners)) if len(ip_owners) == 1 else None
        candidates: list[AlertCandidate] = []
        if owner_id is not None:
            profile = self._profiles[owner_id]
            if observed_at <= profile.updated_at:
                return ()
            if profile.expected_macs and device.mac not in profile.expected_macs:
                candidates.append(self._candidate(MAC_RULE, profile, device, binding, observed_at,
                                                  "member_mac_outside_expected", str(device.mac)))
            elif profile.expected_macs and device.mac in profile.expected_macs:
                if ip_owner_id is not None and ip_owner_id != owner_id:
                    candidates.append(self._candidate(CONTEXT_RULE, profile, device, binding, observed_at,
                                                      "mac_at_other_profile_ip", f"{device.mac}:{binding.ip_address}"))
                elif profile.expected_ips and binding.ip_address not in profile.expected_ips:
                    ips = {binding.ip_address}
                    ips.update(
                        old.ip_address for old in self._recent.get(owner_id, ())
                        if old.mac in profile.expected_macs
                        and old.ip_address not in profile.expected_ips
                        and profile.updated_at <= old.last_seen <= observed_at
                        and observed_at - old.last_seen <= HISTORY_WINDOW
                    )
                    if len(ips) >= 3:
                        candidates.append(self._candidate(IP_CHURN_RULE, profile, device, binding, observed_at,
                                                          "three_unexpected_ips_in_300s", "churn"))
        elif ip_owner_id is not None:
            profile = self._profiles[ip_owner_id]
            if observed_at > profile.updated_at and profile.expected_macs and device.mac not in profile.expected_macs:
                candidates.append(self._candidate(MAC_RULE, profile, device, binding, observed_at,
                                                  "unexpected_mac_at_expected_ip", str(device.mac)))
        if owner_id is not None:
            self._remember(owner_id, binding)
        return tuple(candidate for candidate in candidates if self._admit(candidate, observed_at))

    def _remember(self, profile_id: UUID, binding: IdentityBinding) -> None:
        current = {item.binding_id: item for item in self._recent.get(profile_id, ())}
        previous = current.get(binding.binding_id)
        if previous is None or binding.last_seen > previous.last_seen:
            current[binding.binding_id] = binding
        self._recent[profile_id] = tuple(sorted(
            current.values(), key=lambda item: (item.last_seen, str(item.binding_id)), reverse=True
        )[:20])

    def mark_persisted(self, candidate: AlertCandidate) -> None:
        state = self._states.get(candidate.fingerprint)
        if state is not None:
            state.persisted = True

    def _admit(self, candidate: AlertCandidate, at: datetime) -> bool:
        state = self._states.get(candidate.fingerprint)
        if state is not None:
            if at < state.last_seen or state.persisted:
                return False
            state.last_seen = max(state.last_seen, at)
            return True  # retry a failed AlertService write, even for the same timestamp
        if len(self._states) >= MAX_STATES:
            victim = min(self._states, key=lambda key: (self._states[key].last_seen, key))
            del self._states[victim]
        self._states[candidate.fingerprint] = _SignalState(UUID(candidate.entity_id), at)
        return True

    def _candidate(
        self, rule: str, profile: DeviceProfile, device: DeviceIdentity,
        binding: IdentityBinding, at: datetime, reason: str, identity: str,
    ) -> AlertCandidate:
        recent_expected = [
            old for old in self._recent.get(profile.profile_id, ())
            if old.ip_address == binding.ip_address and old.mac in profile.expected_macs
            and old.last_seen < at and at - old.last_seen <= RECENT_CONFLICT_WINDOW
        ]
        corroborated = bool(recent_expected) and rule == MAC_RULE
        severity = ("medium" if corroborated and profile.trust is DeviceTrust.TRUSTED
                    and not device.mac.is_locally_administered else "low")
        confidence = "moderate" if corroborated or rule == IP_CHURN_RULE else "low"
        expected_mac = profile.expected_macs[0] if len(profile.expected_macs) == 1 else None
        details = (
            ("profile_id", str(profile.profile_id)),
            ("device_id", str(device.device_id)),
            ("label", profile.label[:128]),
            ("expected_macs", _brief(profile.expected_macs)),
            ("expected_ips", _brief(profile.expected_ips)),
            ("trust", profile.trust.value),
            ("reason", reason),
            ("confidence_basis", "recent_expected_binding" if corroborated else
             "three_distinct_recent_ips" if rule == IP_CHURN_RULE else "single_passive_observation"),
        )
        fingerprint = sha256("\0".join((rule, profile.network_fingerprint,
                                         str(profile.profile_id), identity)).encode("ascii")).hexdigest()
        return AlertCandidate(
            fingerprint, rule, profile.network_fingerprint, str(profile.profile_id),
            severity, confidence,
            AlertEvidence(at, binding.ip_address, device.mac, expected_mac,
                          max((old.last_seen for old in recent_expected), default=None),
                          observation_count=3 if rule == IP_CHURN_RULE else 1,
                          details=details),
        )


def _brief(values: tuple[MacAddress, ...] | tuple[str, ...]) -> str:
    rendered = ",".join(str(value) for value in values[:4])
    if len(values) > 4:
        rendered += f",+{len(values) - 4}"
    return rendered[:128]


__all__ = ("DeviceIdentityChangeDetector", "MAC_RULE", "CONTEXT_RULE", "IP_CHURN_RULE")

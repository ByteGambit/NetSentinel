"""Explicit user profile commands, independent of passive observations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from uuid import UUID, uuid4

from netsentinel.application.ports import DeviceProfileMergeConflict, DeviceProfileRepository
from netsentinel.domain.devices import DeviceProfile, DeviceTrust
from netsentinel.domain.observations import MacAddress


class ProfileInputError(ValueError):
    """A safe, actionable field validation message."""


@dataclass(frozen=True, slots=True)
class ProfileEdit:
    label: str
    note: str
    trust: DeviceTrust
    expected_macs: tuple[str, ...]
    expected_ips: tuple[str, ...]


def validate_edit(edit: ProfileEdit) -> tuple[str, str, tuple[MacAddress, ...], tuple[str, ...]]:
    if not isinstance(edit, ProfileEdit) or not isinstance(edit.trust, DeviceTrust):
        raise ProfileInputError("Choose a valid trust state.")
    label, note = edit.label.strip(), edit.note.strip()
    if len(label) > 128 or any(ord(char) < 32 for char in label):
        raise ProfileInputError("Label must be one line and at most 128 characters.")
    if len(note) > 1024 or any(ord(char) < 32 and char not in "\n\t" for char in note):
        raise ProfileInputError("Note must be at most 1024 characters and contain no control characters.")
    if len(edit.expected_macs) > 32:
        raise ProfileInputError("Keep at most 32 expected MAC addresses.")
    if len(edit.expected_ips) > 32:
        raise ProfileInputError("Keep at most 32 expected IPv4 addresses.")
    try:
        macs = tuple(MacAddress(value) for value in edit.expected_macs)
    except (TypeError, ValueError) as error:
        raise ProfileInputError("Enter a valid six-octet MAC address.") from error
    if any(mac.is_zero or mac.is_broadcast or mac.is_multicast for mac in macs):
        raise ProfileInputError("Expected MAC must be a nonzero unicast address.")
    if len(set(macs)) != len(macs):
        raise ProfileInputError("Remove duplicate expected MAC addresses.")
    try:
        ips = tuple(str(IPv4Address(value)) for value in edit.expected_ips)
    except (TypeError, ValueError) as error:
        raise ProfileInputError("Enter a valid IPv4 address.") from error
    if len(set(ips)) != len(ips):
        raise ProfileInputError("Remove duplicate expected IPv4 addresses.")
    return label, note, macs, ips


class DeviceProfileService:
    def __init__(self, repository: DeviceProfileRepository) -> None:
        self._repository = repository

    def load(self, device_id: UUID) -> DeviceProfile | None:
        return self._repository.get_for_device(device_id)

    def save(self, device_id: UUID, network_fingerprint: str,
             original: DeviceProfile | None, edit: ProfileEdit) -> DeviceProfile:
        label, note, macs, ips = validate_edit(edit)
        now = datetime.now(UTC)
        if original is None:
            profile = DeviceProfile(
                uuid4(), network_fingerprint, label, note, edit.trust, now, now,
                now if edit.trust is not DeviceTrust.UNKNOWN else None, macs, ips,
            )
            return self._repository.create(device_id, profile)
        if original.network_fingerprint != network_fingerprint:
            raise DeviceProfileMergeConflict("Profile network changed.")
        if now <= original.updated_at:
            now = original.updated_at + timedelta(microseconds=1)
        profile = DeviceProfile(
            original.profile_id, original.network_fingerprint, label, note, edit.trust,
            original.created_at, now,
            now if edit.trust is not original.trust else original.trust_changed_at,
            macs, ips,
        )
        return self._repository.update(profile, expected_updated_at=original.updated_at)


__all__ = ("DeviceProfileService", "ProfileEdit", "ProfileInputError", "validate_edit")

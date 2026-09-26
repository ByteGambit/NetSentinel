"""NS-041 profile command persists without rewriting observed inventory."""

from datetime import UTC, datetime, timedelta

import pytest

from netsentinel.application.ports import DeviceProfileMergeConflict
from netsentinel.application.services.device_profiles import DeviceProfileService, ProfileEdit, ProfileInputError, validate_edit
from netsentinel.domain.devices import DeviceIdentity, DeviceTrust, IdentityBinding
from netsentinel.domain.observations import MacAddress
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceProfileRepository, SQLiteDeviceRepository


def test_create_edit_restart_stale_and_observed_isolation(tmp_path):
    database = SQLiteDatabase(tmp_path / "profile_ui.sqlite3")
    devices = SQLiteDeviceRepository(database)
    profiles = SQLiteDeviceProfileRepository(database)
    service = DeviceProfileService(profiles)
    at = datetime(2026, 9, 26, tzinfo=UTC)
    fingerprint = "a" * 64
    mac = MacAddress("02:11:22:33:44:55")
    observed = DeviceIdentity(fingerprint, mac, at, at)
    binding = IdentityBinding(fingerprint, mac, "192.168.1.40", at, at)
    devices.record_binding(observed, binding)
    first = service.save(observed.device_id, fingerprint, None,
                         ProfileEdit("Laptop", "Private", DeviceTrust.UNKNOWN, (), ()))
    assert first.profile_id != observed.device_id
    assert first.trust_changed_at is None
    changed = service.save(observed.device_id, fingerprint, first,
                           ProfileEdit("Laptop 2", "Private", DeviceTrust.TRUSTED,
                                       (str(mac),), ("192.168.1.40",)))
    assert changed.profile_id == first.profile_id
    assert changed.trust_changed_at == changed.updated_at
    assert changed.trust_changed_at.tzinfo is not None
    with pytest.raises(DeviceProfileMergeConflict):
        service.save(observed.device_id, fingerprint, first,
                     ProfileEdit("Stale", "", DeviceTrust.UNKNOWN, (), ()))
    devices.record_binding(DeviceIdentity(fingerprint, mac, at + timedelta(minutes=1), at + timedelta(minutes=1)),
                           IdentityBinding(fingerprint, mac, "192.168.1.41", at + timedelta(minutes=1), at + timedelta(minutes=1)))
    reopened = DeviceProfileService(SQLiteDeviceProfileRepository(SQLiteDatabase(database.path)))
    assert reopened.load(observed.device_id) == changed
    assert len(devices.list_bindings(observed.device_id)) == 2
    same_trust = reopened.save(observed.device_id, fingerprint, changed,
                               ProfileEdit("Laptop 3", "Private", DeviceTrust.TRUSTED,
                                           (str(mac),), ("192.168.1.40",)))
    assert same_trust.trust_changed_at == changed.trust_changed_at


@pytest.mark.parametrize("edit,phrase", [
    (ProfileEdit("x" * 129, "", DeviceTrust.UNKNOWN, (), ()), "128"),
    (ProfileEdit("", "x" * 1025, DeviceTrust.UNKNOWN, (), ()), "1024"),
    (ProfileEdit("", "", DeviceTrust.UNKNOWN, ("bad",), ()), "MAC"),
    (ProfileEdit("", "", DeviceTrust.UNKNOWN, (), ("bad",)), "IPv4"),
    (ProfileEdit("", "", DeviceTrust.UNKNOWN, ("02:11:22:33:44:55",) * 2, ()), "duplicate"),
    (ProfileEdit("", "", DeviceTrust.UNKNOWN, (), ("192.168.1.1",) * 2), "duplicate"),
    (ProfileEdit("", "", DeviceTrust.UNKNOWN, ("02:11:22:33:44:55",) * 33, ()), "32"),
    (ProfileEdit("", "", DeviceTrust.UNKNOWN, (), ("192.168.1.1",) * 33), "32"),
])
def test_field_errors_are_actionable(edit, phrase):
    with pytest.raises(ProfileInputError, match=phrase):
        validate_edit(edit)

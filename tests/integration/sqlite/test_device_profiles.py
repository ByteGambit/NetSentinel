"""NS-039 user profiles remain separate from passive observed state."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import sqlite3
from uuid import uuid4

import pytest

from netsentinel.application.ports import DeviceProfileDataCorrupt, DeviceProfileMergeConflict, DeviceProfileRepositoryError
from netsentinel.application.services.devices import DeviceRegistryService
from netsentinel.domain.devices import DeviceIdentity, DeviceProfile, DeviceTrust, NetworkContext, NetworkInterfaceKind, IdentityBinding
from netsentinel.domain.observations import ArpObservation, ArpOpcode, LinkLayerProtocol, MacAddress, NetworkLayerProtocol, PacketObservation
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.migrations import MigrationRunner, builtin_migrations, default_migration_runner
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceProfileRepository, SQLiteDeviceRepository


T0 = datetime(2026, 9, 26, 10, tzinfo=UTC)
FP = "a" * 64
MAC_A = MacAddress("02:11:22:33:44:55")
MAC_B = MacAddress("02:11:22:33:44:66")


def observed(repo, mac=MAC_A, ip="192.168.1.20", at=T0, fingerprint=FP):
    return repo.record_binding(
        DeviceIdentity(fingerprint, mac, at, at),
        IdentityBinding(fingerprint, mac, ip, at, at),
    )[0]


def profile(*, fingerprint=FP, label="Laptop", note="Owner note", trust=DeviceTrust.TRUSTED,
            at=T0, macs=(MAC_A,), ips=("192.168.1.20",)):
    return DeviceProfile(uuid4(), fingerprint, label, note, trust, at, at,
                         at if trust is not DeviceTrust.UNKNOWN else None, macs, ips)


def repositories(tmp_path):
    db = SQLiteDatabase(tmp_path / "profiles.sqlite3")
    return db, SQLiteDeviceRepository(db), SQLiteDeviceProfileRepository(db)


def test_crud_roundtrip_trust_time_and_observation_isolation(tmp_path):
    db, observations, profiles = repositories(tmp_path)
    device = observed(observations)
    assert profiles.get_for_device(device.device_id) is None
    original = profile()
    assert profiles.create(device.device_id, original) == original
    reopened = SQLiteDeviceProfileRepository(SQLiteDatabase(db.path))
    assert reopened.get(original.profile_id) == original
    assert reopened.get_for_device(device.device_id) == original
    observed(observations, at=T0 + timedelta(seconds=30), ip="192.168.1.21")
    assert reopened.get_for_device(device.device_id) == original
    assert len(observations.list_bindings(device.device_id)) == 2
    changed = replace(original, trust=DeviceTrust.UNTRUSTED,
                      updated_at=T0 + timedelta(minutes=1), trust_changed_at=T0 + timedelta(minutes=1))
    assert reopened.update(changed) == changed
    text_only = replace(changed, label="Renamed", updated_at=T0 + timedelta(minutes=2))
    assert reopened.update(text_only).trust_changed_at == changed.trust_changed_at
    assert reopened.update(text_only) == text_only
    with pytest.raises(DeviceProfileMergeConflict):
        reopened.update(changed)
    assert reopened.delete(text_only.profile_id)
    assert not reopened.delete(text_only.profile_id)
    assert reopened.get_for_device(device.device_id) is None
    assert len(observations.list_bindings(device.device_id)) == 2


def test_validation_and_scope_are_bounded(tmp_path):
    _, observations, profiles = repositories(tmp_path)
    device = observed(observations)
    with pytest.raises(ValueError):
        replace(profile(), label="x" * 129)
    with pytest.raises(ValueError):
        replace(profile(), note="x" * 1025)
    with pytest.raises(ValueError):
        replace(profile(), expected_macs=(MAC_A,) * 33)
    with pytest.raises(ValueError):
        replace(profile(), expected_ips=("192.168.1.1",) * 33)
    with pytest.raises(ValueError):
        replace(profile(), created_at=T0.replace(tzinfo=None))
    with pytest.raises(ValueError):
        replace(profile(), trust_changed_at=T0.replace(tzinfo=None))
    with pytest.raises(DeviceProfileMergeConflict):
        profiles.create(device.device_id, profile(fingerprint="b" * 64))
    with pytest.raises(DeviceProfileMergeConflict):
        profiles.create(uuid4(), profile())
    assert profiles.get_for_device(device.device_id) is None


def test_existing_observations_upgrade_without_mutation_and_schema_is_metadata_only(tmp_path):
    db = SQLiteDatabase(tmp_path / "upgrade.sqlite3", migration_runner=MigrationRunner(builtin_migrations()[:6]))
    device = observed(SQLiteDeviceRepository(db))
    with db.connection() as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 6
    upgraded = SQLiteDatabase(db.path)
    repo = SQLiteDeviceProfileRepository(upgraded)
    assert repo.get_for_device(device.device_id) is None
    with upgraded.connection() as connection:
        assert default_migration_runner().current_version(connection) == 7
        assert connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM device_bindings").fetchone()[0] == 1
        columns = {row[1] for table in ("device_profiles", "device_profile_members")
                   for row in connection.execute(f"PRAGMA table_info({table})")}
        assert not columns.intersection({"payload", "packet", "raw_frame", "credentials"})


def test_concurrent_observation_updates_do_not_change_user_metadata(tmp_path):
    _, observations, profiles = repositories(tmp_path)
    device = observed(observations)
    original = profiles.create(device.device_id, profile())
    edited = replace(original, label="Edited", updated_at=T0 + timedelta(seconds=1))
    with ThreadPoolExecutor(max_workers=4) as executor:
        work = [executor.submit(observed, observations, at=T0 + timedelta(seconds=i)) for i in range(12)]
        work.append(executor.submit(profiles.update, edited))
        for item in work:
            item.result()
    assert profiles.get_for_device(device.device_id) == edited
    assert observations.list_devices(FP)[0].last_seen == T0 + timedelta(seconds=11)


def test_merge_links_devices_and_preserves_source_profile_and_bindings(tmp_path):
    db, observations, profiles = repositories(tmp_path)
    target_device = observed(observations)
    source_device = observed(observations, MAC_B, "192.168.1.30")
    target = profiles.create(target_device.device_id, profile(label="", note="target note", trust=DeviceTrust.UNKNOWN, macs=(MAC_A,), ips=()))
    source = profiles.create(source_device.device_id, profile(label="Router", note="", trust=DeviceTrust.TRUSTED, macs=(MAC_B,), ips=("192.168.1.30",)))
    merged = profiles.merge_devices(target_device.device_id, source_device.device_id, T0 + timedelta(minutes=1))
    assert merged.label == "Router" and merged.note == "target note"
    assert merged.trust is DeviceTrust.TRUSTED
    assert merged.trust_changed_at == T0 + timedelta(minutes=1)
    assert merged.expected_macs == (MAC_A, MAC_B)
    assert merged.expected_ips == ("192.168.1.30",)
    reopened = SQLiteDeviceProfileRepository(SQLiteDatabase(db.path))
    assert reopened.get_for_device(target_device.device_id) == merged
    assert reopened.get_for_device(source_device.device_id) == merged
    assert reopened.get(source.profile_id) == replace(source, merged_into=target.profile_id)
    assert reopened.merge_devices(target_device.device_id, source_device.device_id, T0 + timedelta(minutes=2)) == merged
    assert len(observations.list_bindings(target_device.device_id)) == 1
    assert len(observations.list_bindings(source_device.device_id)) == 1
    with pytest.raises(DeviceProfileMergeConflict):
        reopened.delete(target.profile_id)


def test_conflicting_or_cross_network_merge_is_atomic(tmp_path):
    _, observations, profiles = repositories(tmp_path)
    a = observed(observations)
    b = observed(observations, MAC_B)
    first = profiles.create(a.device_id, profile(label="A"))
    second = profiles.create(b.device_id, profile(label="B"))
    with pytest.raises(DeviceProfileMergeConflict):
        profiles.merge_devices(a.device_id, b.device_id, T0 + timedelta(seconds=1))
    assert profiles.get_for_device(a.device_id) == first
    assert profiles.get_for_device(b.device_id) == second
    other = observed(observations, MAC_B, fingerprint="b" * 64)
    with pytest.raises(DeviceProfileMergeConflict):
        profiles.merge_devices(a.device_id, other.device_id, T0 + timedelta(seconds=1))
    assert profiles.get_for_device(a.device_id) == first


def test_trust_conflict_and_stale_merge_time_are_rejected(tmp_path):
    _, observations, profiles = repositories(tmp_path)
    a = observed(observations)
    b = observed(observations, MAC_B)
    first = profiles.create(a.device_id, profile(label="same", note="", trust=DeviceTrust.TRUSTED))
    second = profiles.create(b.device_id, profile(label="same", note="", trust=DeviceTrust.UNTRUSTED))
    with pytest.raises(DeviceProfileMergeConflict):
        profiles.merge_devices(a.device_id, b.device_id, T0 + timedelta(seconds=1))
    assert profiles.get_for_device(a.device_id) == first
    assert profiles.get_for_device(b.device_id) == second
    compatible = replace(second, trust=DeviceTrust.TRUSTED,
                         updated_at=T0 + timedelta(seconds=3), trust_changed_at=T0 + timedelta(seconds=3))
    profiles.update(compatible)
    with pytest.raises(DeviceProfileMergeConflict):
        profiles.merge_devices(a.device_id, b.device_id, T0 + timedelta(seconds=2))


def test_repository_failure_is_sanitized(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    profiles = SQLiteDeviceProfileRepository(SQLiteDatabase(blocker / "database.sqlite3"))
    with pytest.raises(DeviceProfileRepositoryError) as captured:
        profiles.get(uuid4())
    assert "blocker" not in str(captured.value)


def test_profile_repository_closes_each_owned_connection(tmp_path):
    class TrackingDatabase(SQLiteDatabase):
        def __init__(self, path):
            super().__init__(path)
            self.seen = []

        @contextmanager
        def connection(self):
            with super().connection() as connection:
                self.seen.append(connection)
                yield connection

    db = TrackingDatabase(tmp_path / "tracked.sqlite3")
    device = observed(SQLiteDeviceRepository(db))
    profiles = SQLiteDeviceProfileRepository(db)
    saved = profiles.create(device.device_id, profile())
    assert profiles.get(saved.profile_id) == saved
    assert profiles.get_for_device(device.device_id) == saved
    assert profiles.delete(saved.profile_id)
    assert db.seen
    for connection in db.seen:
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")


def test_corrupt_profile_is_sanitized(tmp_path):
    db, observations, profiles = repositories(tmp_path)
    device = observed(observations)
    saved = profiles.create(device.device_id, profile())
    with db.connection() as connection:
        connection.execute("UPDATE device_profiles SET expected_macs_json = ? WHERE id = ?", ('["bad"]', str(saved.profile_id)))
    with pytest.raises(DeviceProfileDataCorrupt, match="Persisted device profile is invalid"):
        profiles.get(saved.profile_id)


def test_synthetic_observation_to_profile_integration(tmp_path):
    db, observations, profiles = repositories(tmp_path)
    context = NetworkContext("adapter-a", 7, "Adapter", NetworkInterfaceKind.WIFI,
                             "192.168.1.10", "192.168.1.0/24", "192.168.1.1", (), T0)
    arp = ArpObservation(ArpOpcode.REPLY, MAC_A, "192.168.1.20", MacAddress("ff:ff:ff:ff:ff:ff"), context.ipv4_address)
    packet = PacketObservation(context.interface_id, context.interface_index, context.fingerprint, T0, 42, 42,
                               LinkLayerProtocol.ETHERNET, NetworkLayerProtocol.ARP, arp=arp)
    registry = DeviceRegistryService(observations)
    device, _ = registry.observe(context, packet)
    saved = profiles.create(device.device_id, profile(fingerprint=context.fingerprint))
    registry.observe(context, replace(packet, observed_at=T0 + timedelta(seconds=2)))
    reopened = SQLiteDeviceProfileRepository(SQLiteDatabase(db.path))
    assert reopened.get_for_device(device.device_id) == saved
    assert registry.devices(context)[0].last_seen == T0 + timedelta(seconds=2)

"""NS-022 SQLite device and binding migration/round-trip coverage."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from netsentinel.application.ports import DeviceDataCorrupt
from netsentinel.domain.devices import DeviceIdentity, IdentityBinding
from netsentinel.domain.observations import MacAddress
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.infrastructure.sqlite.repositories import SQLiteDeviceRepository


T0 = datetime(2026, 9, 22, 10, 11, 12, 123456, tzinfo=UTC)
FINGERPRINT = "a" * 64
MAC = MacAddress("aa:bb:cc:dd:ee:ff")


def record(repo, *, fingerprint=FINGERPRINT, mac=MAC, ip="192.168.1.20", at=T0):
    return repo.record_binding(
        DeviceIdentity(fingerprint, mac, at, at),
        IdentityBinding(fingerprint, mac, ip, at, at),
    )


def test_migration_and_round_trip_across_repository_instances(tmp_path):
    db = SQLiteDatabase(tmp_path / "devices.sqlite3")
    repo = SQLiteDeviceRepository(db)
    assert repo.list_devices(FINGERPRINT) == ()
    first = record(repo)
    record(repo, at=T0 + timedelta(seconds=10))
    record(repo, at=T0 - timedelta(seconds=10))
    record(repo, ip="192.168.1.21", at=T0 + timedelta(seconds=3))
    record(repo, mac=MacAddress("02:11:22:33:44:55"))
    record(repo, fingerprint="b" * 64)
    reopened = SQLiteDeviceRepository(SQLiteDatabase(db.path))
    devices = reopened.list_devices(FINGERPRINT)
    assert len(devices) == 2
    device = next(d for d in devices if d.mac == MAC)
    assert device.device_id == first[0].device_id
    assert device.first_seen == T0
    assert device.last_seen == T0 + timedelta(seconds=10)
    bindings = reopened.list_bindings(device.device_id)
    assert [b.ip_address for b in bindings] == ["192.168.1.20", "192.168.1.21"]
    assert bindings[0].first_seen == T0
    assert bindings[0].last_seen == T0 + timedelta(seconds=10)
    assert len(reopened.list_devices("b" * 64)) == 1
    latest = reopened.latest_binding_for_ip(FINGERPRINT, "192.168.1.20")
    assert latest.mac == MAC and latest.last_seen == T0 + timedelta(seconds=10)
    assert reopened.latest_binding_for_ip("b" * 64, "192.168.1.21") is None
    with db.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 3
        assert connection.execute("SELECT COUNT(*) FROM device_bindings").fetchone()[0] == 4
        columns = {row[1] for row in connection.execute("PRAGMA table_info(device_bindings)")}
        assert "payload" not in columns and "packet" not in columns


def test_corrupt_persisted_device_is_sanitized(tmp_path):
    db = SQLiteDatabase(tmp_path / "devices.sqlite3")
    repo = SQLiteDeviceRepository(db)
    record(repo)
    with db.connection() as connection:
        connection.execute("UPDATE devices SET mac = '01:00:5e:00:00:01'")
    with pytest.raises(DeviceDataCorrupt, match="Persisted device data is invalid"):
        repo.list_devices(FINGERPRINT)


def test_concurrent_repository_calls_keep_one_device_and_binding(tmp_path):
    db = SQLiteDatabase(tmp_path / "devices.sqlite3")
    repo = SQLiteDeviceRepository(db)
    # Migrations are a startup operation; exercise concurrent upserts on a ready DB.
    with db.connection():
        pass
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(
            lambda offset: record(repo, at=T0 + timedelta(seconds=offset)),
            range(8),
        ))
    assert len({item[0].device_id for item in results}) == 1
    devices = repo.list_devices(FINGERPRINT)
    assert len(devices) == 1
    assert T0 <= devices[0].first_seen <= T0 + timedelta(seconds=7)
    assert devices[0].last_seen == T0 + timedelta(seconds=7)
    assert len(repo.list_bindings(devices[0].device_id)) == 1

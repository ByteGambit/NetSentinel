"""NS-095 fake clocks, worker admission, cancellation and config persistence."""

from dataclasses import replace
from datetime import timedelta, timezone
from threading import Event, get_ident

import pytest

from netsentinel.application.services.storage_privacy import StoragePrivacyService, PrivacyOperationError
from netsentinel.application.services.storage_worker import (
    MaintenanceOperation as Op, MaintenanceRequest, StorageMaintenanceWorker, StorageSettings,
)
from netsentinel.bootstrap import create_storage_maintenance_worker
from netsentinel.domain.storage_privacy import (
    MaintenanceStatus, StorageRetentionPolicy, StorageScope, Store,
    StorageSummary, utc_now,
)
from netsentinel.shared.config import (
    AppConfig, StorageMaintenanceConfig, load_config_values, load_config_file, save_config_file,
)
from tests.fixtures.storage_privacy import NOW


class MemoryRepository:
    def __init__(self):
        self.calls = []
        self.entered = Event()
        self.release = Event()
        self.block = False

    def summary(self, rules, now, stop):
        self.calls.append(('summary', get_ident()))
        self.entered.set()
        if self.block:
            assert self.release.wait(2)
        return StorageSummary((), 0, 0, 19)

    def cleanup_chunk(self, rule, now, limit, purge, stop):
        self.calls.append(('cleanup', get_ident()))
        self.entered.set()
        return 0

    def export_page(self, category, offset, limit, stop):
        self.calls.append(('export', get_ident()))
        return ()


@pytest.mark.parametrize('field,value', [
    ('storage_retention_enabled', 'yes'), ('storage_retention_enabled', 1),
    ('storage_history_days', 0), ('storage_history_days', True),
    ('storage_security_days', 366), ('storage_security_days', '90'),
])
def test_invalid_config_uses_safe_defaults(field, value):
    loaded = load_config_values({field: value})
    assert loaded.issues
    assert loaded.config == AppConfig()


@pytest.mark.parametrize('value', [0, 29, 366, True, float('nan'), '30'])
def test_policy_validation(value):
    with pytest.raises(ValueError):
        StorageRetentionPolicy(value, 90)


@pytest.mark.parametrize('changes', [
    {'max_chunks': 17}, {'max_deletes': 2049}, {'runtime_seconds': 3},
    {'export_bytes': 65537}, {'export_page_records': 26}, {'busy_timeout_ms': 101},
    {'interval_seconds': float('nan')}, {'startup_delay_seconds': True},
])
def test_hard_worker_bounds(changes):
    with pytest.raises(ValueError):
        StorageMaintenanceConfig(**changes)


def test_clock_utc_required_and_store_rules_deterministic():
    with pytest.raises(ValueError):
        utc_now(NOW.replace(tzinfo=None))
    with pytest.raises(ValueError):
        utc_now(NOW.astimezone(timezone(timedelta(hours=3))))
    rules = StorageRetentionPolicy().rules
    assert rules == StorageRetentionPolicy().rules
    assert rules[0].store is Store.CACHE
    assert len({r.store for r in rules}) == len(rules)


def test_time_budget_stops_before_adapter_call():
    ticks = iter((0.0, 3.0, 3.0, 3.0))
    repo = MemoryRepository()
    service = StoragePrivacyService(repo, timer=lambda: next(ticks), clock=lambda: NOW)
    result = service.run_retention()
    assert result.status is MaintenanceStatus.LIMITED and result.deleted_rows == 0
    assert repo.calls == []


def test_deferred_start_periodic_no_poll_subscription_and_restart():
    repo = MemoryRepository()
    current = [0.0]
    budgets = StorageMaintenanceConfig(startup_delay_seconds=60, interval_seconds=3600)
    settings = StorageSettings(True, StorageRetentionPolicy())
    def factory():
        return StoragePrivacyService(repo, clock=lambda: NOW)
    worker = StorageMaintenanceWorker(factory, settings=settings, budgets=budgets, timer=lambda: current[0])
    assert worker.start()
    assert worker.next_due_seconds == 60 and not repo.entered.is_set()
    current[0] = 60
    assert repo.entered.wait(2)
    assert worker.stop()
    restarted = StorageMaintenanceWorker(factory, settings=settings, budgets=budgets, timer=lambda: current[0])
    assert restarted.start() and restarted.next_due_seconds == 60
    assert restarted.stop()


def test_one_worker_off_caller_thread_conflict_and_bounded_stop():
    repo = MemoryRepository()
    repo.block = True
    worker = StorageMaintenanceWorker(lambda: StoragePrivacyService(repo, clock=lambda: NOW))
    worker.start()
    caller = get_ident()
    first = worker.submit(MaintenanceRequest(Op.SUMMARY))
    assert repo.entered.wait(2)
    second = worker.submit(MaintenanceRequest(Op.EXPORT_PREVIEW))
    with pytest.raises(PrivacyOperationError):
        second.result(2)
    assert not worker.stop(timeout=0.01)
    repo.release.set()
    first.result(2)
    assert worker.stop() and not worker.start()
    assert repo.calls[0][1] != caller and worker.rejected == 1


def test_worker_failure_sanitized_and_recovers_for_local_monitoring():
    def broken():
        raise OSError('192.0.2.1 private.example C:/private-user')
    worker = StorageMaintenanceWorker(broken)
    worker.start()
    try:
        for _ in range(2):
            with pytest.raises(PrivacyOperationError) as error:
                worker.submit(MaintenanceRequest(Op.SUMMARY)).result(2)
            assert 'private' not in str(error.value)
        assert worker.failures == 2
    finally:
        worker.stop()


def test_opt_in_settings_save_restart_and_other_settings_preserved(tmp_path):
    target = tmp_path / 'config.json'
    config = replace(AppConfig(), desktop_notifications_enabled=True, onboarding_completed=True)
    save_config_file(target, config)
    worker = create_storage_maintenance_worker(database_path=tmp_path / 'test.db', config=config, config_path=target)
    assert not (tmp_path / 'test.db').exists()
    worker.start()
    try:
        settings = StorageSettings(True, StorageRetentionPolicy(60, 120))
        result = worker.submit(MaintenanceRequest(Op.SETTINGS, settings=settings)).result(2)
        assert result == settings and worker.settings == settings
        loaded = load_config_file(target).config
        assert loaded.storage_history_days == 60 and loaded.storage_security_days == 120
        assert loaded.desktop_notifications_enabled and loaded.onboarding_completed
        assert loaded.threat_intel_consents == config.threat_intel_consents
        assert loaded.window_close_behavior == config.window_close_behavior
        assert worker.next_due_seconds <= 60
        assert not (tmp_path / 'test.db').exists()
    finally:
        worker.stop()


def test_unconfirmed_purge_rejected_without_calling_adapter():
    repo = MemoryRepository()
    worker = StorageMaintenanceWorker(lambda: StoragePrivacyService(repo, clock=lambda: NOW))
    worker.start()
    try:
        with pytest.raises(PrivacyOperationError):
            worker.submit(MaintenanceRequest(Op.PURGE, scope=StorageScope.ALL)).result(2)
        assert repo.calls == []
    finally:
        worker.stop()

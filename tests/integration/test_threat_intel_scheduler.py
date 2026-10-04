"""NS-087 real cache/bootstrap, fake transport, consent and schema regressions."""

from dataclasses import replace
from datetime import UTC, datetime
from threading import Event
import json

import pytest

from netsentinel.application.services.threat_intelligence import ThreatIntelConsentService
from netsentinel.bootstrap import (
    ABUSEIPDB_DESCRIPTOR, create_threat_intel_consent_service,
    create_threat_intel_scheduler, collect_diagnostics, create_monitoring_engine,
)
from netsentinel.domain.threat_intelligence import ThreatIntelError as E, ThreatIntelResultStatus as S
from netsentinel.domain.threat_intel_cache import ThreatIntelCacheFreshness as F, ThreatIntelCacheKey
from netsentinel.application.services.threat_intel_scheduler import LookupState as L, SubmissionState as U
from netsentinel.infrastructure.abuseipdb import AbuseIpDbAdapter
from netsentinel.infrastructure.sqlite import SQLiteDatabase
from netsentinel.infrastructure.sqlite.threat_intel_cache_repository import SQLiteThreatIntelCacheRepository
from netsentinel.infrastructure.threat_intel_http import HttpResponse
from tests.fixtures.threat_intelligence import DESCRIPTORS, grant, query
from tests.unit.application.test_threat_intel_scheduler import Provider, Cache, done, state


class Secrets:
    def __init__(self):
        self.calls = 0

    def get_secret(self, provider):
        self.calls += 1
        return "test-private-credential"


class Transport:
    def __init__(self, statuses=(200,)):
        self.statuses = statuses
        self.calls = []

    def send(self, request):
        self.calls.append(request)
        status = self.statuses[min(len(self.calls) - 1, len(self.statuses) - 1)]
        body = {"data": {"ipAddress": "8.8.8.8", "isPublic": True, "ipVersion": 4,
            "abuseConfidenceScore": 0, "totalReports": 0, "numDistinctUsers": 0,
            "lastReportedAt": None}} if status == 200 else {"errors": []}
        return HttpResponse(status, {"content-type": "application/json", "retry-after": "bad"},
            json.dumps(body).encode())


def test_abuseipdb_production_port_cache_write_restart_and_revoke(tmp_path):
    path, db_path = tmp_path / "config.json", tmp_path / "cache.sqlite3"
    consent = create_threat_intel_consent_service(config_path=path, descriptors=(ABUSEIPDB_DESCRIPTOR,))
    transport, secret = Transport(), Secrets()
    provider = AbuseIpDbAdapter(secret, transport)
    scheduler = create_threat_intel_scheduler(consent, database_path=db_path, providers=(provider,))
    assert not db_path.exists() and transport.calls == []
    granted = grant(ABUSEIPDB_DESCRIPTOR.provider)
    consent.save((granted,))
    request = replace(query(ABUSEIPDB_DESCRIPTOR.provider, consent=granted), queried_at=datetime.now(UTC))
    scheduler.start()
    try:
        first = done(scheduler, scheduler.submit(request).ticket)
        assert first.result.status is S.NO_HIT
        assert first.cache_write.status.value == "stored"
        assert len(transport.calls) == secret.calls == 1
        diagnostic = collect_diagnostics(create_monitoring_engine(), database_path=db_path, threat_intel=scheduler)
        assert diagnostic.threat_intel.provider_calls == 1
        assert request.subject.value not in repr(diagnostic.threat_intel)
        assert secret.get_secret(None) not in repr(first)
    finally:
        assert scheduler.stop()
    # Persistent fresh cache, runtime queue and retry state are not replayed.
    restarted = create_threat_intel_scheduler(consent, database_path=db_path, providers=(provider,))
    restarted.start()
    try:
        second = done(restarted, restarted.submit(request).ticket)
        assert second.state is L.FRESH_CACHE and second.cache.entry.result.status is S.NO_HIT
        assert len(transport.calls) == 1
        consent.save(())
        assert restarted.submit(request).state is U.REJECTED_POLICY
        cache = SQLiteThreatIntelCacheRepository(SQLiteDatabase(db_path))
        assert cache.get(ThreatIntelCacheKey.from_result(first.result), datetime.now(UTC)).freshness is F.FRESH
        with SQLiteDatabase(db_path).connection() as connection:
            assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 19
            assert connection.execute("SELECT COUNT(*) FROM threat_intel_cache").fetchone()[0] == 1
            assert not connection.execute("SELECT name FROM sqlite_master WHERE name LIKE '%job%'").fetchall()
        assert cache.get(replace(ThreatIntelCacheKey.from_result(first.result), result_version=3),
                         datetime.now(UTC)).freshness is F.UNSUPPORTED
    finally:
        assert restarted.stop()


def test_default_missing_secret_terminal_without_http(tmp_path):
    consent = create_threat_intel_consent_service(config_path=tmp_path / "config.json",
        descriptors=(ABUSEIPDB_DESCRIPTOR,))
    scheduler = create_threat_intel_scheduler(consent, database_path=tmp_path / "cache.sqlite3")
    granted = grant(ABUSEIPDB_DESCRIPTOR.provider)
    consent.save((granted,))
    scheduler.start()
    try:
        outcome = done(scheduler, scheduler.submit(query(ABUSEIPDB_DESCRIPTOR.provider, consent=granted)).ticket)
        assert outcome.result.error is E.CREDENTIAL_UNAVAILABLE and outcome.attempts == 1
    finally:
        assert scheduler.stop()


def test_factory_secret_injection_and_dormant_start(tmp_path):
    consent = create_threat_intel_consent_service(config_path=tmp_path / "config.json",
        descriptors=(ABUSEIPDB_DESCRIPTOR,))
    secret = Secrets()
    scheduler = create_threat_intel_scheduler(consent, database_path=tmp_path / "cache.sqlite3", secrets=secret)
    assert secret.calls == 0
    scheduler.start()
    try:
        assert secret.calls == 0 and scheduler.diagnostics().provider_calls == 0
        assert not (tmp_path / "cache.sqlite3").exists()
    finally:
        assert scheduler.stop()


@pytest.mark.parametrize("update", ["save", "reload", "invalid_read"])
def test_consent_snapshot_notification_pending_and_no_submit_io(tmp_path, update):
    grants = [grant()]
    reads = []

    def read():
        reads.append(1)
        if update == "invalid_read" and not grants:
            raise OSError("private subject or key must not escape")
        return tuple(grants)

    service = ThreatIntelConsentService(DESCRIPTORS, read, lambda value: None)
    p = Provider()
    scheduler = create_threat_intel_scheduler(service, database_path=tmp_path / "cache.sqlite3", providers=(p,))
    scheduler.set_network_available(False)
    scheduler.start()
    try:
        ticket = scheduler.submit(query(consent=grants[0])).ticket
        state(scheduler, ticket, L.OFFLINE_DEFERRED)
        assert len(reads) == 1  # admission/worker gates never read the settings file
        if update == "save":
            service.save(())
        else:
            grants.clear()
            service.current()
        assert done(scheduler, ticket).state is L.CANCELLED_CONSENT
        scheduler.set_network_available(True)
        assert p.calls == []
    finally:
        assert scheduler.stop()


def test_fake_transport_malformed_retry_after_uses_scheduler_backoff(tmp_path):
    from tests.unit.application.test_threat_intel_scheduler import Clock
    from netsentinel.application.services.threat_intel_scheduler import ThreatIntelLookupScheduler
    consent = grant(ABUSEIPDB_DESCRIPTOR.provider)
    transport = Transport((429, 200))
    provider = AbuseIpDbAdapter(Secrets(), transport, clock=lambda: query().queried_at)
    clock = Clock()
    scheduler = ThreatIntelLookupScheduler((provider,), lambda: (consent,), lambda: Cache(), clock=clock)
    scheduler.start()
    try:
        ticket = scheduler.submit(query(ABUSEIPDB_DESCRIPTOR.provider, consent=consent)).ticket
        outcome = state(scheduler, ticket, L.DELAYED)
        assert outcome.result.error is E.RATE_LIMITED
        assert outcome.result.rate_limit.retry_after_seconds is None
        assert scheduler._next_call[ABUSEIPDB_DESCRIPTOR.provider] == 1
        assert len(transport.calls) == 1
        clock.value = 1
        scheduler.wakeup()
        assert done(scheduler, ticket).result.status is S.NO_HIT
        assert len(transport.calls) == 2
    finally:
        assert scheduler.stop()


def test_engine_subscriber_submission_does_not_wait_for_provider():
    from tests.unit.application.test_engine import SequenceCollector, engine_for, snapshot
    from netsentinel.domain.connections import ConnectionOpened
    from netsentinel.application.events import EventDispatcher
    from netsentinel.application.services.threat_intel_scheduler import ThreatIntelLookupScheduler
    consent = grant()
    p = Provider(block=True)
    scheduler = ThreatIntelLookupScheduler((p,), lambda: (consent,), lambda: Cache())
    scheduler.start()
    dispatcher = EventDispatcher()
    returned = Event()

    def explicit_request(event):
        # Test-only explicit API caller on the engine thread; production has no hook.
        scheduler.submit(query(consent=consent))
        returned.set()

    dispatcher.subscribe(ConnectionOpened, explicit_request)
    collector = SequenceCollector(((snapshot(),),), reached=2)
    engine = engine_for(collector, dispatcher=dispatcher, interval=0.001)
    try:
        engine.start()
        assert returned.wait(3) and p.entered.wait(3)
        assert collector.ready.wait(3)  # second poll while provider is still blocked
        assert not p.release.is_set()
        assert all(name.startswith("netsentinel-ti-") for name in p.threads)
    finally:
        engine.stop()
        p.release.set()
        assert scheduler.stop()

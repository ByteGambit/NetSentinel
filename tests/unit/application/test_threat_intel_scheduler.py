"""NS-087 offline deterministic worker/budget/revocation acceptance."""

from dataclasses import replace
from datetime import timedelta
from threading import Event, Lock, current_thread
from time import monotonic
from uuid import uuid4

import pytest

from netsentinel.application.services.threat_intel_scheduler import (
    LookupState as L, SubmissionState as U, ThreatIntelLookupScheduler,
    ThreatIntelProviderBudget, ThreatIntelSchedulerPolicy, RETRYABLE_ERRORS,
)
from netsentinel.domain.threat_intel_cache import (
    ThreatIntelCacheFreshness as F, ThreatIntelCacheLookup, ThreatIntelCacheMutation,
    ThreatIntelCacheMutationStatus as M, ThreatIntelCacheEntry, ThreatIntelCacheKey,
    ThreatIntelCachedResult,
)
from netsentinel.domain.threat_intelligence import (
    ThreatIntelDenial, ThreatIntelError as E, ThreatIntelResult, ThreatIntelResultStatus as S,
    ThreatIntelRateLimit, ThreatIntelTrigger,
)
from tests.fixtures.threat_intelligence import A, B, NOW, DESCRIPTORS, grant, query


class Clock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


class Cache:
    def __init__(self, lookup=None, mutation=None):
        self.lookup = lookup or ThreatIntelCacheLookup(F.MISS)
        self.mutation = mutation or ThreatIntelCacheMutation(M.STORED, 1)
        self.reads = []
        self.writes = []
        self.threads = []
        self.block = None

    def get(self, key, now):
        self.reads.append(key)
        self.threads.append(current_thread().name)
        if self.block:
            self.block[0].set()
            assert self.block[1].wait(3)
        return self.lookup

    def put(self, result, now):
        self.writes.append(result)
        self.threads.append(current_thread().name)
        return self.mutation


class Provider:
    def __init__(self, provider=A, errors=(), status=S.HIT, hint=None, block=False):
        self.descriptor = DESCRIPTORS[(A, B).index(provider)]
        self.errors, self.status, self.hint = errors, status, hint
        self.calls, self.threads = [], []
        self.entered, self.release = Event(), Event()
        if not block:
            self.release.set()
        self.lock = Lock()
        self.active = self.maximum = 0

    def query(self, request):
        with self.lock:
            index = len(self.calls)
            self.calls.append(request)
            self.threads.append(current_thread().name)
            self.active += 1
            self.maximum = max(self.maximum, self.active)
        self.entered.set()
        assert self.release.wait(3)
        with self.lock:
            self.active -= 1
        error = self.errors[min(index, len(self.errors) - 1)] if self.errors else None
        return ThreatIntelResult(request, S.ERROR if error else self.status, NOW, error,
            rate_limit=ThreatIntelRateLimit(self.hint) if self.hint is not None else None)


def cached(request, status=S.HIT, freshness=F.FRESH):
    result = ThreatIntelResult(request, status, NOW)
    entry = ThreatIntelCacheEntry(ThreatIntelCacheKey.from_result(result),
        ThreatIntelCachedResult.from_result(result), NOW + timedelta(hours=1), NOW + timedelta(hours=2))
    return ThreatIntelCacheLookup(freshness, entry)


@pytest.fixture
def runtime():
    owned = []

    def make(*, providers=None, cache=None, policy=None, budgets=(), consents=None):
        ps = providers or (Provider(),)
        grants = consents if consents is not None else [grant(p.descriptor.provider) for p in ps]
        store = cache or Cache()
        clock = Clock()
        scheduler = ThreatIntelLookupScheduler(tuple(ps), lambda: tuple(grants), lambda: store,
            clock=clock, utc_clock=lambda: NOW, policy=policy, budgets=budgets)
        owned.append((scheduler, ps, store))
        scheduler.start()
        return scheduler, ps, store, clock, grants

    yield make
    for scheduler, providers, cache in owned:
        for provider in providers:
            provider.release.set()
        if cache.block:
            cache.block[1].set()
        assert scheduler.stop(2)


def wait(scheduler, predicate):
    # Condition notifications, never arbitrary sleep or wall-clock backoff.
    with scheduler._condition:
        assert scheduler._condition.wait_for(predicate, timeout=3), scheduler.diagnostics()


def state(scheduler, ticket, expected):
    wait(scheduler, lambda: scheduler.poll(ticket).state is expected)
    return scheduler.poll(ticket)


def done(scheduler, ticket):
    wait(scheduler, lambda: scheduler.poll(ticket).terminal)
    return scheduler.poll(ticket)


def test_construct_start_default_denied_and_invalid():
    p = Provider()
    scheduler = ThreatIntelLookupScheduler((p,), lambda: (), lambda: Cache())
    assert p.calls == []
    assert scheduler.submit(query(consent=grant())).state is U.STOPPED
    assert scheduler.start() and not scheduler.start()
    try:
        assert scheduler.submit(None).state is U.INVALID
        result = scheduler.submit(query(consent=grant()))
        assert result.state is U.REJECTED_POLICY and result.denial is ThreatIntelDenial.NO_CONSENT
        assert p.calls == [] and scheduler.diagnostics().outstanding == 0
    finally:
        assert scheduler.stop()
        assert scheduler.stop()


@pytest.mark.parametrize("case,denial", [
    ("unknown", ThreatIntelDenial.UNSUPPORTED_PROVIDER),
    ("local", ThreatIntelDenial.LOCAL_SUBJECT),
    ("auto", ThreatIntelDenial.TRIGGER_NOT_SUPPORTED),
    ("wrong_grant", ThreatIntelDenial.NO_CONSENT),
])
def test_policy_gate(runtime, case, denial):
    scheduler, ps, _, _, grants = runtime()
    request = query(consent=grants[0])
    request = {"unknown": replace(request, provider=B),
        "local": query(value="127.0.0.1", consent=grants[0]),
        "auto": replace(request, trigger=ThreatIntelTrigger.AUTOMATIC),
        "wrong_grant": replace(request, consent=grant())}[case]
    assert scheduler.submit(request).denial is denial
    assert ps[0].calls == []


def test_nonblocking_provider_and_inflight_duplicate_storm(runtime):
    p = Provider(block=True)
    scheduler, _, store, _, grants = runtime(providers=(p,))
    request = query(consent=grants[0])
    submitted = scheduler.submit(request)
    assert submitted.state is U.ACCEPTED
    assert p.entered.wait(3) and not p.release.is_set()
    for _ in range(10000):
        duplicate = scheduler.submit(replace(request, request_id=uuid4()))
        assert duplicate.state is U.COALESCED and duplicate.ticket == submitted.ticket
    assert scheduler.diagnostics().outstanding == 1
    assert len(scheduler._dedup) == 1 and len(p.calls) == 1
    p.release.set()
    outcome = done(scheduler, submitted.ticket)
    assert outcome.result.status is S.HIT and outcome.cache_write.status is M.STORED
    assert store.writes and all(t.startswith("netsentinel-ti-") for t in p.threads + store.threads)
    assert current_thread().name not in p.threads
    assert scheduler.diagnostics().coalesced == 10000


def test_pending_dedup_while_cache_blocks_and_caller_returns(runtime):
    store = Cache()
    entered, release = Event(), Event()
    store.block = entered, release
    scheduler, ps, _, _, grants = runtime(cache=store)
    request = query(consent=grants[0])
    ticket = scheduler.submit(request).ticket
    assert entered.wait(3)
    assert scheduler.submit(replace(request, request_id=uuid4())).ticket == ticket
    assert ps[0].calls == []
    release.set()
    assert done(scheduler, ticket).state is L.PROVIDER_RESULT


@pytest.mark.parametrize("status", [S.HIT, S.NO_HIT])
@pytest.mark.parametrize("online", [True, False])
def test_fresh_cache_zero_calls_even_offline(runtime, status, online):
    consent = grant()
    store = Cache(cached(query(consent=consent), status))
    scheduler, ps, _, _, _ = runtime(cache=store, consents=[consent])
    scheduler.set_network_available(online)
    for _ in range(2):
        outcome = done(scheduler, scheduler.submit(query(consent=consent)).ticket)
        assert outcome.state is L.FRESH_CACHE and outcome.cache.entry.result.status is status
        assert outcome.result is None
    assert ps[0].calls == [] and store.writes == []


@pytest.mark.parametrize("status", [S.HIT, S.NO_HIT])
@pytest.mark.parametrize("error", [None, E.INVALID_RESPONSE, E.TIMEOUT])
def test_stale_refresh_preserves_old_status_and_error(runtime, status, error):
    consent = grant()
    store = Cache(cached(query(consent=consent), status, F.STALE))
    p = Provider(errors=(error,) if error else (), status=status)
    scheduler, _, _, clock, _ = runtime(cache=store, providers=(p,), consents=[consent])
    ticket = scheduler.submit(query(consent=consent)).ticket
    if error is E.TIMEOUT:
        for count, delay in ((2, 1), (3, 2)):
            wait(scheduler, lambda: scheduler.poll(ticket).state is L.DELAYED
                 and scheduler.poll(ticket).attempts == count - 1)
            clock.value += delay
            scheduler.wakeup()
    outcome = done(scheduler, ticket)
    assert outcome.cache.freshness is F.STALE
    assert outcome.cache.entry.result.status is status
    assert outcome.result.status is (S.ERROR if error else status)
    assert len(store.writes) == (0 if error else 1)
    assert outcome.attempts == (3 if error is E.TIMEOUT else 1)


@pytest.mark.parametrize("freshness", [F.MISS, F.CORRUPT, F.UNAVAILABLE, F.UNSUPPORTED, F.EXPIRED, F.CLOCK_ANOMALY])
def test_cache_limitations_do_not_block_provider(runtime, freshness):
    scheduler, ps, _, _, grants = runtime(cache=Cache(ThreatIntelCacheLookup(freshness)))
    outcome = done(scheduler, scheduler.submit(query(consent=grants[0])).ticket)
    assert outcome.cache.freshness is freshness and outcome.result.status is S.HIT
    assert len(ps[0].calls) == 1


@pytest.mark.parametrize("status", [S.HIT, S.NO_HIT])
def test_cache_write_failure_keeps_provider_result(runtime, status):
    store = Cache(mutation=ThreatIntelCacheMutation(M.UNAVAILABLE))
    scheduler, _, _, _, grants = runtime(cache=store, providers=(Provider(status=status),))
    outcome = done(scheduler, scheduler.submit(query(consent=grants[0])).ticket)
    assert outcome.result.status is status and outcome.cache_write.status is M.UNAVAILABLE


@pytest.mark.parametrize("error", list(E))
def test_exact_retry_error_matrix_and_attempt_cap(runtime, error):
    p = Provider(errors=(error,))
    scheduler, _, store, clock, grants = runtime(providers=(p,))
    ticket = scheduler.submit(query(consent=grants[0])).ticket
    if error in RETRYABLE_ERRORS:
        for attempt, deadline in ((1, 1), (2, 3)):
            wait(scheduler, lambda: scheduler.poll(ticket).state is L.DELAYED
                 and scheduler.poll(ticket).attempts == attempt)
            assert len(p.calls) == attempt
            clock.value = deadline - 0.001
            scheduler.wakeup()
            assert len(p.calls) == attempt
            clock.value = deadline
            scheduler.wakeup()
    outcome = done(scheduler, ticket)
    assert outcome.state is L.PROVIDER_ERROR and outcome.result.error is error
    assert outcome.attempts == (3 if error in RETRYABLE_ERRORS else 1)
    assert store.writes == []


@pytest.mark.parametrize("hint,delay,clamped", [(None, 1, False), (0, 1, False), (12, 12, False), (86400, 300, True)])
def test_429_hint_backoff_and_provider_isolation(runtime, hint, delay, clamped):
    a, b = Provider(errors=(E.RATE_LIMITED,), hint=hint), Provider(B)
    scheduler, _, _, clock, grants = runtime(providers=(a, b))
    ticket = scheduler.submit(query(consent=grants[0])).ticket
    state(scheduler, ticket, L.DELAYED)
    other_a = scheduler.submit(query(value="1.1.1.1", consent=grants[0])).ticket
    other_b = scheduler.submit(query(B, consent=grants[1])).ticket
    assert done(scheduler, other_b).state is L.PROVIDER_RESULT
    state(scheduler, other_a, L.DELAYED)
    assert len(a.calls) == 1 and len(b.calls) == 1
    assert scheduler.poll(ticket).retry_after_clamped is clamped
    assert scheduler._next_call[A] == delay
    clock.value = delay
    scheduler.wakeup()
    wait(scheduler, lambda: len(a.calls) == 2)
    assert scheduler.diagnostics().rate_limited >= 1


def test_backoff_cap_is_deterministic(runtime):
    p = Provider(errors=(E.TIMEOUT,))
    policy = ThreatIntelSchedulerPolicy(max_attempts=5, initial_backoff=2, max_backoff=3)
    scheduler, _, _, clock, grants = runtime(providers=(p,), policy=policy)
    ticket = scheduler.submit(query(consent=grants[0])).ticket
    for attempt, deadline in ((1, 2), (2, 5), (3, 8), (4, 11)):
        wait(scheduler, lambda: scheduler.poll(ticket).state is L.DELAYED
             and scheduler.poll(ticket).attempts == attempt)
        assert scheduler._jobs[ticket.job_id].due == deadline
        clock.value = deadline
        scheduler.wakeup()
    assert done(scheduler, ticket).attempts == 5


def test_per_provider_and_global_capacity_storm(runtime):
    policy = ThreatIntelSchedulerPolicy(capacity=5, concurrency=2)
    budgets = ((A, ThreatIntelProviderBudget(capacity=3)), (B, ThreatIntelProviderBudget(capacity=3)))
    scheduler, ps, _, _, grants = runtime(providers=(Provider(), Provider(B)), policy=policy, budgets=budgets)
    scheduler.set_network_available(False)
    for index in range(3):
        assert scheduler.submit(query(value=f"8.8.8.{index + 1}", consent=grants[0])).state is U.ACCEPTED
    assert scheduler.submit(query(value="8.8.8.7", consent=grants[0])).state is U.CAPACITY_REACHED
    for index in range(2):
        assert scheduler.submit(query(B, value=f"1.1.1.{index + 1}", consent=grants[1])).state is U.ACCEPTED
    for index in range(1000):
        assert scheduler.submit(query(B, value=f"9.9.{index // 255}.{index % 255}", consent=grants[1])).state is U.CAPACITY_REACHED
    assert scheduler.diagnostics().outstanding == len(scheduler._dedup) == 5
    assert ps[0].calls == ps[1].calls == []


def test_provider_concurrency_and_local_rate_refill(runtime):
    a, b = Provider(block=True), Provider(B, block=True)
    scheduler, _, _, clock, grants = runtime(providers=(a, b))
    tickets = [scheduler.submit(query(value=f"8.8.8.{i + 1}", consent=grants[0])).ticket for i in range(3)]
    bt = scheduler.submit(query(B, consent=grants[1])).ticket
    assert a.entered.wait(3) and b.entered.wait(3)
    assert scheduler.diagnostics().active <= 4
    assert a.maximum == b.maximum == 1
    a.release.set()
    b.release.set()
    done(scheduler, bt)
    wait(scheduler, lambda: any(scheduler.poll(t).terminal for t in tickets))
    assert len(a.calls) == 1
    for stamp in (1, 2):
        clock.value = stamp
        scheduler.wakeup()
        wait(scheduler, lambda: sum(scheduler.poll(t).terminal for t in tickets) == stamp + 1)
    assert a.maximum == 1 and len(a.calls) == 3


@pytest.mark.parametrize("stage", ["offline", "retry", "inflight", "cache"])
def test_consent_revoke_and_regrant_never_resurrects(runtime, stage):
    p = Provider(errors=(E.TIMEOUT,) if stage in ("retry", "inflight") else (), block=stage == "inflight")
    store = Cache()
    if stage == "cache":
        store.block = Event(), Event()
    scheduler, _, _, clock, grants = runtime(providers=(p,), cache=store)
    consent = grants[0]
    scheduler.set_network_available(stage != "offline")
    ticket = scheduler.submit(query(consent=consent)).ticket
    if stage == "offline":
        state(scheduler, ticket, L.OFFLINE_DEFERRED)
    elif stage == "retry":
        state(scheduler, ticket, L.DELAYED)
    elif stage == "cache":
        assert store.block[0].wait(3)
    else:
        assert p.entered.wait(3)
    grants.clear()
    scheduler.wakeup()
    grants.append(consent)  # even identical grant cannot undo observed cancellation
    scheduler.wakeup()
    p.release.set()
    if store.block:
        store.block[1].set()
    outcome = done(scheduler, ticket)
    assert outcome.state is L.CANCELLED_CONSENT
    assert outcome.consent_revoked_during_flight is (stage == "inflight")
    clock.value = 300
    scheduler.set_network_available(True)
    scheduler.wakeup()
    assert len(p.calls) == (1 if stage in ("retry", "inflight") else 0)
    assert store.writes == []


@pytest.mark.parametrize("freshness", [F.MISS, F.STALE])
def test_offline_to_online_once_stale_visible(runtime, freshness):
    consent = grant()
    store = Cache(cached(query(consent=consent), S.NO_HIT, F.STALE) if freshness is F.STALE else None)
    scheduler, ps, _, _, _ = runtime(cache=store, consents=[consent])
    scheduler.set_network_available(False)
    ticket = scheduler.submit(query(consent=consent)).ticket
    outcome = state(scheduler, ticket, L.OFFLINE_DEFERRED)
    assert outcome.cache.freshness is freshness and ps[0].calls == []
    scheduler.set_network_available(True)
    assert done(scheduler, ticket).state is L.PROVIDER_RESULT
    scheduler.set_network_available(True)
    assert len(ps[0].calls) == 1


def test_shutdown_pending_retry_inflight_bounded_restart(runtime):
    p = Provider(block=True, errors=(E.TIMEOUT,))
    scheduler, _, _, _, grants = runtime(providers=(p,))
    first = scheduler.submit(query(consent=grants[0])).ticket
    assert p.entered.wait(3)
    pending = scheduler.submit(query(value="1.1.1.1", consent=grants[0])).ticket
    start = monotonic()
    assert not scheduler.stop(0)
    assert monotonic() - start < 0.5
    assert scheduler.poll(pending).state is L.CANCELLED_SHUTDOWN
    assert scheduler.submit(query(consent=grants[0])).state is U.STOPPED
    assert not scheduler.start()
    p.release.set()
    assert scheduler.stop(2)
    assert done(scheduler, first).state is L.CANCELLED_SHUTDOWN
    assert len(p.calls) == 1 and scheduler.diagnostics().outstanding == 0
    assert scheduler.start()
    assert scheduler.poll(first) is None and p.calls and not scheduler._jobs


def test_shutdown_delayed_retries(runtime):
    scheduler, ps, _, clock, grants = runtime(providers=(Provider(errors=(E.TIMEOUT,)),))
    ticket = scheduler.submit(query(consent=grants[0])).ticket
    state(scheduler, ticket, L.DELAYED)
    assert scheduler.stop()
    assert scheduler.poll(ticket).state is L.CANCELLED_SHUTDOWN
    clock.value = 1000
    scheduler.wakeup()
    assert len(ps[0].calls) == 1


def test_result_retention_cap_ttl_and_sanitized_diagnostics(runtime):
    consent = grant()
    policy = ThreatIntelSchedulerPolicy(result_capacity=2, result_ttl=10)
    scheduler, _, _, clock, _ = runtime(policy=policy, consents=[consent], cache=Cache(cached(query(consent=consent))))
    tickets = [scheduler.submit(query(consent=consent)).ticket]
    done(scheduler, tickets[0])
    for _ in range(3):
        ticket = scheduler.submit(query(consent=consent)).ticket
        tickets.append(ticket)
        done(scheduler, ticket)
    assert scheduler.poll(tickets[0]) is None
    diagnostic = scheduler.diagnostics()
    assert diagnostic.retained == 2 and diagnostic.completed == 4
    assert "8.8.8.8" not in repr(diagnostic) and str(consent.consent_id) not in repr(diagnostic)
    clock.value = 10
    assert scheduler.poll(tickets[-1]) is None and scheduler.diagnostics().retained == 0


@pytest.mark.parametrize("kwargs", [{"capacity": 0}, {"concurrency": 5}, {"max_attempts": 9},
    {"initial_backoff": 0}, {"max_backoff": float("inf")}, {"retry_after_cap": 301},
    {"shutdown_timeout": 3}, {"result_capacity": 65}, {"result_ttl": 0}, {"version": 2}])
def test_invalid_policy(kwargs):
    with pytest.raises(ValueError):
        ThreatIntelSchedulerPolicy(**kwargs)


@pytest.mark.parametrize("kwargs", [{"capacity": 65}, {"concurrency": 5}, {"minimum_interval": 0},
    {"minimum_interval": float("nan")}, {"capacity": True}])
def test_invalid_provider_budget(kwargs):
    with pytest.raises(ValueError):
        ThreatIntelProviderBudget(**kwargs)


def test_scheduler_has_no_history_risk_secret_or_callback_surface():
    import inspect
    from netsentinel.application.services import threat_intel_scheduler
    source = inspect.getsource(threat_intel_scheduler)
    for forbidden in ("RiskEvidence", "AlertService", "get_secret", "Future", "subscribe(", "submit_all", "sqlite3", "PyQt"):
        assert forbidden not in source
    assert ThreatIntelCacheKey(A, query().data_type, query().subject).result_version == 2


@pytest.mark.parametrize("failure", ["raise", "wrong_query", "untyped"])
def test_provider_boundary_sanitization_and_worker_survival(runtime, failure):
    class Broken(Provider):
        def query(self, request):
            super().query(request)
            if failure == "raise":
                raise RuntimeError("8.8.8.8 secret-private-exception")
            if failure == "untyped":
                return {"error": "secret-private-exception"}
            return ThreatIntelResult(replace(request, request_id=uuid4()), S.HIT, NOW)

    p = Broken()
    scheduler, _, _, clock, grants = runtime(providers=(p,), policy=ThreatIntelSchedulerPolicy(max_attempts=1))
    ticket = scheduler.submit(query(consent=grants[0])).ticket
    outcome = done(scheduler, ticket)
    assert outcome.result.error is (E.UNAVAILABLE if failure == "raise" else E.INVALID_RESPONSE)
    assert "secret-private-exception" not in repr(outcome)
    assert scheduler.diagnostics().running and scheduler.diagnostics().failed == 1
    clock.value = 1
    scheduler.wakeup()
    assert done(scheduler, scheduler.submit(query(value="1.1.1.1", consent=grants[0])).ticket).terminal


@pytest.mark.parametrize("failure", ["factory", "get", "put"])
def test_cache_exception_does_not_lose_provider_result(runtime, failure):
    class BrokenCache(Cache):
        def get(self, key, now):
            if failure == "get":
                raise OSError("private cache")
            return super().get(key, now)

        def put(self, result, now):
            if failure == "put":
                raise OSError("private cache")
            return super().put(result, now)

    scheduler, _, _, _, grants = runtime(cache=BrokenCache())
    if failure == "factory":
        def broken_factory():
            raise OSError("private factory")
        scheduler._cache_factory = broken_factory
    outcome = done(scheduler, scheduler.submit(query(consent=grants[0])).ticket)
    assert outcome.result.status is S.HIT
    assert "private" not in repr(outcome)
    if failure in ("factory", "get"):
        assert outcome.cache.freshness is F.UNAVAILABLE
    if failure in ("factory", "put"):
        assert outcome.cache_write.status is M.UNAVAILABLE


def test_network_error_is_not_global_offline(runtime):
    a, b = Provider(errors=(E.NETWORK_ERROR,)), Provider(B)
    scheduler, _, _, _, grants = runtime(providers=(a, b))
    ticket = scheduler.submit(query(consent=grants[0])).ticket
    state(scheduler, ticket, L.DELAYED)
    assert scheduler.diagnostics().online
    assert done(scheduler, scheduler.submit(query(B, consent=grants[1])).ticket).result.status is S.HIT


def test_round_robin_and_retry_yields_to_new_manual_job(runtime):
    a, b = Provider(errors=(E.TIMEOUT, None)), Provider(B)
    scheduler, _, _, clock, grants = runtime(providers=(a, b), policy=ThreatIntelSchedulerPolicy(concurrency=1))
    first = scheduler.submit(query(consent=grants[0])).ticket
    state(scheduler, first, L.DELAYED)
    fresh = scheduler.submit(query(value="1.1.1.1", consent=grants[0])).ticket
    other = scheduler.submit(query(B, consent=grants[1])).ticket
    assert done(scheduler, other).state is L.PROVIDER_RESULT
    state(scheduler, fresh, L.DELAYED)
    clock.value = 1
    scheduler.wakeup()
    assert done(scheduler, fresh).state is L.PROVIDER_RESULT
    assert a.calls[1].subject.value == "1.1.1.1"
    clock.value = 2
    scheduler.wakeup()
    assert done(scheduler, first).attempts == 2


def test_global_concurrency_and_custom_provider_concurrency(runtime):
    a, b = Provider(block=True), Provider(B, block=True)
    policy = ThreatIntelSchedulerPolicy(concurrency=2)
    budgets = ((A, ThreatIntelProviderBudget(concurrency=2)),)
    scheduler, _, _, clock, grants = runtime(providers=(a, b), policy=policy, budgets=budgets)
    a1 = scheduler.submit(query(consent=grants[0])).ticket
    assert a.entered.wait(3)
    a2 = scheduler.submit(query(value="1.1.1.1", consent=grants[0])).ticket
    state(scheduler, a2, L.DELAYED)
    clock.value = 1
    scheduler.wakeup()
    wait(scheduler, lambda: len(a.calls) == 2)
    assert a.maximum == scheduler.diagnostics().active == 2
    bt = scheduler.submit(query(B, consent=grants[1])).ticket
    assert b.calls == []  # all two global workers occupied
    a.release.set()
    done(scheduler, a1)
    done(scheduler, a2)
    assert b.entered.wait(3)
    b.release.set()
    assert done(scheduler, bt).terminal


def test_canonical_ipv6_dedup_and_separate_subject_type_provider(runtime):
    from netsentinel.domain.threat_intelligence import ThreatIntelDataType
    consents = [grant(), grant(B), grant(A, ThreatIntelDataType.DOMAIN_REPUTATION)]
    scheduler, _, _, _, _ = runtime(providers=(Provider(), Provider(B)), consents=consents)
    scheduler.set_network_available(False)
    first = scheduler.submit(query(value="2606:4700:4700::1111", consent=consents[0]))
    duplicate = scheduler.submit(query(value="2606:4700:4700:0:0:0:0:1111", consent=consents[0]))
    assert duplicate.state is U.COALESCED and duplicate.ticket == first.ticket
    assert scheduler.submit(query(B, value="2606:4700:4700::1111", consent=consents[1])).ticket != first.ticket
    assert scheduler.submit(query(A, ThreatIntelDataType.DOMAIN_REPUTATION, consent=consents[2])).ticket != first.ticket
    assert scheduler.diagnostics().outstanding == 3


def test_regrant_new_identity_can_submit_while_old_attempt_finishes(runtime):
    p = Provider(block=True)
    scheduler, _, _, clock, consents = runtime(providers=(p,))
    old = scheduler.submit(query(consent=consents[0])).ticket
    assert p.entered.wait(3)
    consents.clear()
    scheduler.wakeup()
    consents.append(grant())
    new = scheduler.submit(query(consent=consents[0]))
    assert new.state is U.ACCEPTED and new.ticket != old
    p.release.set()
    assert done(scheduler, old).state is L.CANCELLED_CONSENT
    clock.value = 1
    scheduler.wakeup()
    assert done(scheduler, new.ticket).state is L.PROVIDER_RESULT


def test_execution_rechecks_consent_without_proactive_notification(runtime):
    store = Cache()
    store.block = Event(), Event()
    scheduler, ps, _, _, consents = runtime(cache=store)
    ticket = scheduler.submit(query(consent=consents[0])).ticket
    assert store.block[0].wait(3)
    consents.clear()  # deliberately omit wakeup; execution gate must still deny
    store.block[1].set()
    assert done(scheduler, ticket).state is L.CANCELLED_CONSENT
    assert ps[0].calls == []


def test_provider_success_is_not_terminal_before_cache_write_finishes(runtime):
    entered, release = Event(), Event()

    class BlockingPut(Cache):
        def put(self, result, now):
            entered.set()
            assert release.wait(3)
            return super().put(result, now)

    scheduler, _, store, _, grants = runtime(cache=BlockingPut())
    ticket = scheduler.submit(query(consent=grants[0])).ticket
    try:
        assert entered.wait(3)
        assert scheduler.poll(ticket).result.status is S.HIT
        assert not scheduler.poll(ticket).terminal and store.writes == []
    finally:
        release.set()
    outcome = done(scheduler, ticket)
    assert outcome.cache_write.status is M.STORED and len(store.writes) == 1
    assert scheduler.diagnostics().completed == 1


def test_terminal_429_still_holds_provider_budget(runtime):
    a, b = Provider(errors=(E.RATE_LIMITED,), hint=10), Provider(B)
    scheduler, _, _, _, grants = runtime(providers=(a, b), policy=ThreatIntelSchedulerPolicy(max_attempts=1))
    first = done(scheduler, scheduler.submit(query(consent=grants[0])).ticket)
    assert first.result.error is E.RATE_LIMITED and first.terminal
    pending = scheduler.submit(query(value="1.1.1.1", consent=grants[0])).ticket
    assert done(scheduler, scheduler.submit(query(B, consent=grants[1])).ticket).terminal
    state(scheduler, pending, L.DELAYED)
    assert len(a.calls) == 1 and scheduler._next_call[A] == 10


def test_partial_worker_start_failure_can_be_cleanly_stopped(monkeypatch):
    import netsentinel.application.services.threat_intel_scheduler as module
    original = module.Thread.start
    starts = []

    def failing_start(thread):
        starts.append(thread)
        if len(starts) == 2:
            raise RuntimeError("private platform failure")
        original(thread)

    monkeypatch.setattr(module.Thread, "start", failing_start)
    scheduler = ThreatIntelLookupScheduler((Provider(),), lambda: (), lambda: Cache())
    with pytest.raises(RuntimeError, match="optional scheduler worker unavailable"):
        scheduler.start()
    assert not scheduler.diagnostics().running
    assert scheduler.submit(query()).state is U.STOPPED
    assert scheduler.stop() and not any(t.is_alive() for t in starts)


def test_ready_retry_not_starved_by_manual_storm(runtime):
    p = Provider(errors=(E.TIMEOUT, None))
    scheduler, _, _, clock, grants = runtime(providers=(p,), policy=ThreatIntelSchedulerPolicy(concurrency=1))
    original = query(consent=grants[0])
    ticket = scheduler.submit(original).ticket
    state(scheduler, ticket, L.DELAYED)
    fresh = [scheduler.submit(query(value=f"1.1.1.{i + 1}", consent=grants[0])).ticket for i in range(3)]
    for pending in fresh:
        state(scheduler, pending, L.DELAYED)
    clock.value = 1
    scheduler.wakeup()
    done(scheduler, fresh[0])
    clock.value = 2
    scheduler.wakeup()
    assert done(scheduler, ticket).attempts == 2
    assert p.calls[2] == original

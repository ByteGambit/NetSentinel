"""NS-087 bounded explicit lookup worker; no history/engine/GUI dependency.

submit and poll do memory-only work. Cache factories and provider ports run on
fixed workers. Coalesced callers share a pollable ticket, without subscribers.
Consent readers must be fast memory snapshots; call wakeup after changing them.
"""

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from math import isfinite
from threading import Condition, Thread, current_thread
from time import monotonic
from uuid import UUID, uuid4

from netsentinel.application.ports import ThreatIntelligenceProvider
from netsentinel.application.services.threat_intel_cache import ThreatIntelCacheService
from netsentinel.application.services.threat_intelligence import validate_descriptors
from netsentinel.domain.threat_intel_cache import (
    ThreatIntelCacheFreshness as F, ThreatIntelCacheKey, ThreatIntelCacheLookup,
    ThreatIntelCacheMutation, ThreatIntelCacheMutationStatus as M,
)
from netsentinel.domain.threat_intelligence import (
    ThreatIntelConsent, ThreatIntelDenial, ThreatIntelError as E,
    ThreatIntelProviderId, ThreatIntelQuery, ThreatIntelResult,
    ThreatIntelResultStatus as S, ThreatIntelTrigger, consent_denial,
)
from netsentinel.shared.diagnostics import ThreatIntelSchedulerDiagnostics


RETRYABLE_ERRORS = frozenset({E.TIMEOUT, E.NETWORK_ERROR, E.UNAVAILABLE, E.RATE_LIMITED})


def _integer(value: int, maximum: int) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("invalid scheduler capacity")


def _seconds(value: float, maximum: float, *, zero: bool = False) -> None:
    if isinstance(value, bool) or not isfinite(value) or not (0 <= value <= maximum):
        raise ValueError("invalid scheduler duration")
    if not zero and value == 0:
        raise ValueError("scheduler duration must be positive")


@dataclass(frozen=True, slots=True)
class ThreatIntelProviderBudget:
    capacity: int = 16  # includes cache work, delayed jobs and active attempts
    concurrency: int = 1
    minimum_interval: float = 1.0

    def __post_init__(self) -> None:
        _integer(self.capacity, 64)
        _integer(self.concurrency, 4)
        _seconds(self.minimum_interval, 300)
        if self.concurrency > self.capacity:
            raise ValueError("provider concurrency exceeds capacity")


@dataclass(frozen=True, slots=True)
class ThreatIntelSchedulerPolicy:
    version: int = 1
    capacity: int = 64  # outstanding jobs, so retries always retain their slot
    concurrency: int = 4
    max_attempts: int = 3  # initial + two retries
    initial_backoff: float = 1.0
    max_backoff: float = 30.0
    retry_after_cap: float = 300.0
    result_capacity: int = 64
    result_ttl: float = 300.0
    shutdown_timeout: float = 2.0
    fresh_dispatch_burst: int = 2

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != 1:
            raise ValueError("unsupported scheduler policy")
        for value, cap in ((self.capacity, 64), (self.concurrency, 4),
                           (self.max_attempts, 8), (self.result_capacity, 64),
                           (self.fresh_dispatch_burst, 8)):
            _integer(value, cap)
        for duration, bound in ((self.initial_backoff, 30), (self.max_backoff, 300),
                           (self.retry_after_cap, 300), (self.result_ttl, 3600)):
            _seconds(duration, bound)
        _seconds(self.shutdown_timeout, 2, zero=True)
        if self.initial_backoff > self.max_backoff or self.concurrency > self.capacity:
            raise ValueError("inconsistent scheduler bounds")


class SubmissionState(str, Enum):
    ACCEPTED = "accepted"
    COALESCED = "coalesced"
    REJECTED_POLICY = "rejected_policy"
    CAPACITY_REACHED = "capacity_reached"
    STOPPED = "stopped"
    INVALID = "invalid"


class LookupState(str, Enum):
    QUEUED = "queued"
    IN_FLIGHT = "in_flight"
    DELAYED = "delayed"
    OFFLINE_DEFERRED = "offline_deferred"
    FRESH_CACHE = "fresh_cache"
    PROVIDER_RESULT = "provider_result"
    PROVIDER_ERROR = "provider_error"
    CANCELLED_CONSENT = "cancelled_consent"
    CANCELLED_SHUTDOWN = "cancelled_shutdown"


@dataclass(frozen=True, slots=True)
class ThreatIntelLookupTicket:
    job_id: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.job_id, UUID):
            raise TypeError("ticket requires a UUID")


@dataclass(frozen=True, slots=True)
class ThreatIntelSubmission:
    state: SubmissionState
    ticket: ThreatIntelLookupTicket | None = None
    denial: ThreatIntelDenial | None = None


@dataclass(frozen=True, slots=True)
class ThreatIntelScheduledOutcome:
    ticket: ThreatIntelLookupTicket
    state: LookupState
    attempts: int = 0
    cache: ThreatIntelCacheLookup | None = field(default=None, repr=False)
    result: ThreatIntelResult | None = field(default=None, repr=False)
    cache_write: ThreatIntelCacheMutation | None = None
    retry_after_clamped: bool = False
    consent_revoked_during_flight: bool = False
    terminal: bool = False


@dataclass(slots=True)
class _Job:
    ticket: ThreatIntelLookupTicket
    query: ThreatIntelQuery
    key: tuple[ThreatIntelCacheKey, ThreatIntelTrigger, int, UUID]
    state: LookupState = LookupState.QUEUED
    cache: ThreatIntelCacheLookup | None = None
    result: ThreatIntelResult | None = None
    cache_write: ThreatIntelCacheMutation | None = None
    attempts: int = 0
    due: float = 0
    active: bool = False
    clamped: bool = False
    cancelled: bool = False


class ThreatIntelLookupScheduler:
    """Fair fresh/retry queues within round-robin providers; bounded local state.

    No general worker abstraction exists in the repo: RiskAlertWorker owns a
    different drain/SQL contract. This reuses its Condition/fixed daemon worker
    and bounded join pattern, adding fair delayed dispatch and provider budgets.
    """

    def __init__(self, providers: tuple[ThreatIntelligenceProvider, ...],
                 read_consents: Callable[[], tuple[ThreatIntelConsent, ...]],
                 cache_factory: Callable[[], ThreatIntelCacheService], *,
                 policy: ThreatIntelSchedulerPolicy | None = None,
                 budgets: tuple[tuple[ThreatIntelProviderId, ThreatIntelProviderBudget], ...] = (),
                 clock: Callable[[], float] = monotonic,
                 utc_clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        validate_descriptors(tuple(p.descriptor for p in providers))
        self.policy = policy or ThreatIntelSchedulerPolicy()
        self._providers = {p.descriptor.provider: p for p in providers}
        if (not isinstance(budgets, tuple) or len(budgets) > len(providers)
                or len(dict(budgets)) != len(budgets)
                or any(p not in self._providers or not isinstance(b, ThreatIntelProviderBudget)
                       for p, b in budgets)):
            raise ValueError("invalid provider budgets")
        overrides = dict(budgets)
        self._budgets = {p: overrides.get(p, ThreatIntelProviderBudget()) for p in self._providers}
        self._read_consents, self._cache_factory = read_consents, cache_factory
        self._clock, self._utc = clock, utc_clock
        self._condition = Condition()
        self._jobs: OrderedDict[UUID, _Job] = OrderedDict()
        self._dedup: dict[tuple[ThreatIntelCacheKey, ThreatIntelTrigger, int, UUID], UUID] = {}
        self._completed: OrderedDict[UUID, tuple[float, ThreatIntelScheduledOutcome]] = OrderedDict()
        self._threads: list[Thread] = []
        self._accepting = False
        self._online = True  # unknown connectivity: no probe; transport failures remain provider-local
        self._next_call = dict.fromkeys(self._providers, 0.0)
        self._in_flight = dict.fromkeys(self._providers, 0)
        self._new_streak = dict.fromkeys(self._providers, 0)
        self._turn = 0
        self._counts = dict.fromkeys(("accepted", "coalesced", "capacity_rejected", "provider_calls",
            "retries", "rate_limited", "consent_cancelled", "shutdown_cancelled", "completed",
            "failed", "cache_fresh", "cache_stale", "cache_misses"), 0)

    def start(self) -> bool:
        with self._condition:
            if self._accepting or any(t.is_alive() for t in self._threads):
                return False
            self._completed.clear()
            self._next_call = dict.fromkeys(self._providers, 0.0)
            self._new_streak = dict.fromkeys(self._providers, 0)
            self._accepting = True
            self._threads = [Thread(target=self._run, name=f"netsentinel-ti-{i}", daemon=True)
                             for i in range(self.policy.concurrency)]
            try:
                for thread in self._threads:
                    thread.start()
            except Exception:
                self._accepting = False
                self._condition.notify_all()
                raise RuntimeError("optional scheduler worker unavailable") from None
            return True

    def _denial(self, query: ThreatIntelQuery) -> ThreatIntelDenial | None:
        provider = self._providers.get(query.provider)
        try:
            return consent_denial(query, provider.descriptor if provider else None, self._read_consents())
        except Exception:
            return ThreatIntelDenial.NO_CONSENT

    def submit(self, query: ThreatIntelQuery) -> ThreatIntelSubmission:
        if not isinstance(query, ThreatIntelQuery):
            return ThreatIntelSubmission(SubmissionState.INVALID)
        with self._condition:
            if not self._accepting:
                return ThreatIntelSubmission(SubmissionState.STOPPED)
            denial = self._denial(query)
            if denial is not None:
                return ThreatIntelSubmission(SubmissionState.REJECTED_POLICY, denial=denial)
            self._cancel_revoked()
            assert query.consent is not None
            key = (ThreatIntelCacheKey(query.provider, query.data_type, query.subject),
                   query.trigger, query.policy_version, query.consent.consent_id)
            existing = self._dedup.get(key)
            if existing is not None:
                self._counts["coalesced"] += 1
                return ThreatIntelSubmission(SubmissionState.COALESCED, self._jobs[existing].ticket)
            count = sum(j.query.provider == query.provider for j in self._jobs.values())
            if len(self._jobs) >= self.policy.capacity or count >= self._budgets[query.provider].capacity:
                self._counts["capacity_rejected"] += 1
                return ThreatIntelSubmission(SubmissionState.CAPACITY_REACHED)
            ticket = ThreatIntelLookupTicket(uuid4())
            self._jobs[ticket.job_id] = _Job(ticket, query, key)
            self._dedup[key] = ticket.job_id
            self._counts["accepted"] += 1
            self._condition.notify_all()
            return ThreatIntelSubmission(SubmissionState.ACCEPTED, ticket)

    def _view(self, job: _Job, *, terminal: bool = False, revoked: bool = False) -> ThreatIntelScheduledOutcome:
        return ThreatIntelScheduledOutcome(job.ticket, job.state, job.attempts, job.cache,
            job.result, job.cache_write, job.clamped, revoked, terminal)

    def _prune(self) -> None:
        now = self._clock()
        while self._completed:
            stamp, _ = next(iter(self._completed.values()))
            if len(self._completed) <= self.policy.result_capacity and now - stamp < self.policy.result_ttl:
                break
            self._completed.popitem(last=False)

    def poll(self, ticket: ThreatIntelLookupTicket) -> ThreatIntelScheduledOutcome | None:
        """Nonblocking snapshot; None means expired/evicted/unknown ticket."""
        with self._condition:
            self._prune()
            job = self._jobs.get(ticket.job_id)
            if job is not None:
                return self._view(job)
            stored = self._completed.get(ticket.job_id)
            return stored[1] if stored else None

    def _finish(self, job: _Job, state: LookupState, *, revoked: bool = False) -> None:
        job.state = state
        self._jobs.pop(job.ticket.job_id, None)
        self._dedup.pop(job.key, None)
        self._completed[job.ticket.job_id] = (self._clock(), self._view(job, terminal=True, revoked=revoked))
        self._prune()
        self._counts["completed"] += 1
        self._counts["failed"] += int(state is LookupState.PROVIDER_ERROR)
        self._condition.notify_all()

    def _cancel_revoked(self) -> None:
        for job in tuple(self._jobs.values()):
            if self._denial(job.query) is not None:
                job.cancelled = True
                if not job.active:
                    self._counts["consent_cancelled"] += 1
                    self._finish(job, LookupState.CANCELLED_CONSENT)

    def wakeup(self) -> None:
        """Consent-change notification or fake-clock wakeup; performs no I/O."""
        with self._condition:
            self._cancel_revoked()
            self._condition.notify_all()

    def set_network_available(self, available: bool) -> None:
        if type(available) is not bool:
            raise TypeError("network availability must be boolean")
        with self._condition:
            self._online = available
            self._condition.notify_all()

    def diagnostics(self) -> ThreatIntelSchedulerDiagnostics:
        with self._condition:
            self._prune()
            return ThreatIntelSchedulerDiagnostics(
                running=self._accepting, online=self._online, outstanding=len(self._jobs),
                active=sum(j.active for j in self._jobs.values()),
                delayed=sum(j.state is LookupState.DELAYED for j in self._jobs.values()),
                offline_deferred=sum(j.state is LookupState.OFFLINE_DEFERRED for j in self._jobs.values()),
                retained=len(self._completed), **self._counts)

    def _pick(self) -> _Job | None:
        self._cancel_revoked()
        providers = tuple(self._providers)
        now = self._clock()
        for offset in range(len(providers)):
            index = (self._turn + offset) % len(providers)
            provider = providers[index]
            # Bounded fresh burst then a ready retry; stable order in each class.
            prefer_new = self._new_streak[provider] < self.policy.fresh_dispatch_burst
            for job in sorted(self._jobs.values(), key=lambda j: (j.attempts > 0) == prefer_new):
                if job.active or job.query.provider != provider or job.cancelled:
                    continue
                if job.cache is not None:
                    if not self._online:
                        changed = job.state is not LookupState.OFFLINE_DEFERRED
                        job.state = LookupState.OFFLINE_DEFERRED
                        if changed:
                            self._condition.notify_all()
                        continue
                    if (now < max(job.due, self._next_call[provider])
                            or self._in_flight[provider] >= self._budgets[provider].concurrency):
                        changed = job.state is not LookupState.DELAYED
                        job.state = LookupState.DELAYED
                        if changed:
                            self._condition.notify_all()
                        continue
                    # Reserve the budget under the same lock as selection.
                    self._in_flight[provider] += 1
                    self._next_call[provider] = now + self._budgets[provider].minimum_interval
                    self._new_streak[provider] = (0 if job.attempts else min(
                        self.policy.fresh_dispatch_burst, self._new_streak[provider] + 1))
                    job.attempts += 1
                job.active = True
                job.state = LookupState.IN_FLIGHT
                self._turn = (index + 1) % len(providers)
                self._condition.notify_all()
                return job
        return None

    def _wait_delay(self) -> float | None:
        if not self._online:
            return None
        now = self._clock()
        deadlines = [max(j.due, self._next_call[j.query.provider]) for j in self._jobs.values()
                     if not j.active and j.cache is not None
                     and self._in_flight[j.query.provider] < self._budgets[j.query.provider].concurrency]
        return max(0.001, min(deadlines) - now) if deadlines else None

    def _run(self) -> None:
        cache: ThreatIntelCacheService | None = None
        while True:
            with self._condition:
                if not self._accepting:
                    return
                job = self._pick()
                if job is None:
                    self._condition.wait(self._wait_delay())
                    continue
            if job.cache is None:
                try:
                    if cache is None:
                        cache = self._cache_factory()
                    lookup = cache.get(job.key[0], self._utc())
                    if not isinstance(lookup, ThreatIntelCacheLookup):
                        lookup = ThreatIntelCacheLookup(F.UNAVAILABLE)
                    elif lookup.entry is not None and lookup.entry.key != job.key[0]:
                        lookup = ThreatIntelCacheLookup(F.CORRUPT)
                except Exception:
                    lookup = ThreatIntelCacheLookup(F.UNAVAILABLE)
                with self._condition:
                    job.active = False
                    job.cache = lookup
                    if self._cancel_after_work(job):
                        continue
                    if lookup.freshness is F.FRESH:
                        self._counts["cache_fresh"] += 1
                        self._finish(job, LookupState.FRESH_CACHE)
                    else:
                        self._counts["cache_stale" if lookup.freshness is F.STALE else "cache_misses"] += 1
                        job.state = LookupState.QUEUED
                        self._condition.notify_all()
                continue
            # Final memory-only consent/network/lifecycle check immediately before dispatch.
            with self._condition:
                if self._cancel_after_work(job):
                    self._in_flight[job.query.provider] -= 1
                    job.active = False
                    continue
                if not self._online:
                    self._in_flight[job.query.provider] -= 1
                    job.attempts -= 1
                    job.active = False
                    job.state = LookupState.OFFLINE_DEFERRED
                    continue
                self._counts["provider_calls"] += 1
                if job.attempts > 1:
                    self._counts["retries"] += 1
            try:
                result = self._providers[job.query.provider].query(job.query)
            except Exception:
                result = ThreatIntelResult(job.query, S.ERROR, max(self._utc(), job.query.queried_at), E.UNAVAILABLE)
            if not isinstance(result, ThreatIntelResult) or result.query != job.query:
                result = ThreatIntelResult(job.query, S.ERROR, max(self._utc(), job.query.queried_at), E.INVALID_RESPONSE)
            with self._condition:
                job.result = result
                cancelled = job.cancelled or not self._accepting or self._denial(job.query) is not None
            if not cancelled and result.status is not S.ERROR:
                try:
                    # May have moved to a different worker after the cache stage.
                    if cache is None:
                        cache = self._cache_factory()
                    mutation = cache.put(result, self._utc())
                except Exception:
                    mutation = ThreatIntelCacheMutation(M.UNAVAILABLE)
                job.cache_write = mutation
            with self._condition:
                job.active = False
                self._in_flight[job.query.provider] -= 1
                if self._cancel_after_work(job, during_flight=True):
                    continue
                if result.status is not S.ERROR:
                    self._finish(job, LookupState.PROVIDER_RESULT)
                    continue
                delay = min(self.policy.max_backoff, self.policy.initial_backoff * 2 ** (job.attempts - 1))
                if result.error is E.RATE_LIMITED:
                    self._counts["rate_limited"] += 1
                    hint = result.rate_limit.retry_after_seconds if result.rate_limit else None
                    if hint is not None:
                        job.clamped |= hint > self.policy.retry_after_cap
                        delay = max(delay, min(hint, self.policy.retry_after_cap))
                    self._next_call[job.query.provider] = max(self._next_call[job.query.provider], self._clock() + delay)
                if result.error in RETRYABLE_ERRORS and job.attempts < self.policy.max_attempts:
                    job.due = self._clock() + delay
                    job.state = LookupState.DELAYED
                    # Rotate a retry behind newer explicit jobs within its provider.
                    self._jobs.move_to_end(job.ticket.job_id)
                    self._condition.notify_all()
                else:
                    self._finish(job, LookupState.PROVIDER_ERROR)

    def _cancel_after_work(self, job: _Job, *, during_flight: bool = False) -> bool:
        if not self._accepting:
            self._counts["shutdown_cancelled"] += 1
            self._finish(job, LookupState.CANCELLED_SHUTDOWN)
            return True
        if job.cancelled or self._denial(job.query) is not None:
            self._counts["consent_cancelled"] += 1
            self._finish(job, LookupState.CANCELLED_CONSENT, revoked=during_flight)
            return True
        return False

    def stop(self, timeout: float | None = None) -> bool:
        duration = self.policy.shutdown_timeout if timeout is None else timeout
        _seconds(duration, 2, zero=True)
        with self._condition:
            if current_thread() in self._threads:
                raise RuntimeError("scheduler cannot join itself")
            self._accepting = False
            for job in tuple(self._jobs.values()):
                if not job.active:
                    self._counts["shutdown_cancelled"] += 1
                    self._finish(job, LookupState.CANCELLED_SHUTDOWN)
            self._condition.notify_all()
            threads = tuple(t for t in self._threads if t.ident is not None)
        # Real monotonic bounds joins even when the scheduling clock is fake.
        deadline = monotonic() + duration
        for thread in threads:
            thread.join(max(0, deadline - monotonic()))
        return not any(t.is_alive() for t in threads)

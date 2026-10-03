"""NS-071 bounded learning lifecycle and asynchronous checkpoint orchestration."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from math import isfinite
from threading import Condition, RLock, Thread, current_thread
from time import monotonic

from netsentinel.application.ports import BaselineRepository
from netsentinel.application.services.behavior_features import BehaviorCapacity
from netsentinel.domain.behavior_baseline import (
    BaselineDiagnostics, BaselineLoad, BaselineOrigin, BaselineSnapshot,
    BaselineState, BaselineStorageState, BaselineSummary, FEATURE_POLICY_VERSION,
    MAX_BASELINE_COUNTER, validate_baseline_summary,
    validate_baseline_scope,
)
from netsentinel.domain.behavior_features import BehaviorFeatureSnapshot, BehaviorScopeKey, FeatureCount
from netsentinel.domain.connections import ObservationQuality
from netsentinel.shared.config import BehaviorBaselineConfig


def baseline_policy_key(capacity: BehaviorCapacity, polling_interval: float, config: BehaviorBaselineConfig) -> str:
    return ":".join(str(value) for value in (
        FEATURE_POLICY_VERSION, *tuple(getattr(capacity, name) for name in capacity.__slots__),
        float(polling_interval), config.minimum_samples, float(config.minimum_monitored_seconds),
        config.stale_days, config.retention_days,
    ))


def baseline_state(summary: BaselineSummary, now: datetime, config: BehaviorBaselineConfig) -> BaselineState:
    if now < summary.last_observed_at or now < summary.persisted_at:
        return BaselineState.CLOCK_ANOMALY
    age = (now - summary.last_observed_at).total_seconds()
    if age >= config.retention_days * 86_400:
        return BaselineState.EXPIRED
    if age >= config.stale_days * 86_400:
        return BaselineState.STALE
    f = summary.features
    if f.capacity_loss or f.reduced_appearances or f.unknown_destinations:
        return BaselineState.INSUFFICIENT_QUALITY
    if f.observed_appearances == 0 and f.monitored_seconds == 0:
        return BaselineState.LEARNING
    if f.observed_appearances < config.minimum_samples or f.monitored_seconds < config.minimum_monitored_seconds:
        return BaselineState.INSUFFICIENT_DATA
    return BaselineState.READY


def merge_learning(old: BehaviorFeatureSnapshot, delta: BehaviorFeatureSnapshot, capacity: BehaviorCapacity) -> BehaviorFeatureSnapshot:
    """Add contributions once, retaining bounded feature maps and loss markers."""
    if old.scope != delta.scope:
        raise ValueError("cannot merge different baseline scopes")
    if old.observed_appearances + delta.observed_appearances > MAX_BASELINE_COUNTER or old.monitored_seconds + delta.monitored_seconds > 1e12:
        return replace(old, capacity_loss=True, gap_seen=old.gap_seen or delta.gap_seen)
    maps: dict[str, tuple[FeatureCount, ...]] = {}
    others: dict[str, int] = {}
    loss = old.capacity_loss or delta.capacity_loss
    for name, cap in (("destinations", capacity.destinations), ("ports", capacity.ports), ("protocols", capacity.protocols)):
        retained = {item.value: item.observed_appearances for item in getattr(old, name)}
        overflow = getattr(old, "other_" + name) + getattr(delta, "other_" + name)
        for item in getattr(delta, name):
            if item.value not in retained and len(retained) >= cap:
                overflow += item.observed_appearances
                loss = True
            else:
                retained[item.value] = retained.get(item.value, 0) + item.observed_appearances
        maps[name] = tuple(FeatureCount(value, count) for value, count in sorted(retained.items(), key=lambda item: str(item[0])))
        others[name] = overflow
    return BehaviorFeatureSnapshot(
        old.scope, old.observed_appearances + delta.observed_appearances,
        old.reduced_appearances + delta.reduced_appearances,
        old.monitored_seconds + delta.monitored_seconds,
        maps["destinations"], maps["ports"], maps["protocols"],
        others["destinations"], others["ports"], others["protocols"],
        old.unknown_destinations + delta.unknown_destinations,
        len(maps["destinations"]), len(maps["ports"]), len(maps["protocols"]),
        old.gap_seen or delta.gap_seen, loss,
    )


@dataclass(frozen=True, slots=True)
class BaselineCommand:
    scope: BehaviorScopeKey
    summary: BaselineSummary | None
    sequence: int
    reset: bool = False


class BaselineWriter:
    """One component-specific owner, 128 coalesced pending scopes + one active.

    The service serializes checkpoint/reset submissions under its own lock.
    Reset is carried through coalescing, so the worker deletes before any newer
    summary. An older in-flight write completes before that reset, never after.
    """

    def __init__(self, repository_factory: Callable[[], AbstractContextManager[BaselineRepository]], *,
                 capacity: int = 128, shutdown_timeout: float = 2.0) -> None:
        if type(capacity) is not int or not 1 <= capacity <= 128:
            raise ValueError("invalid baseline queue capacity")
        if isinstance(shutdown_timeout, bool) or not isfinite(shutdown_timeout) or not 0 <= shutdown_timeout <= 60:
            raise ValueError("invalid baseline shutdown timeout")
        self._factory = repository_factory
        self.capacity = capacity
        self.shutdown_timeout = shutdown_timeout
        self._condition = Condition(RLock())
        self._pending: OrderedDict[BehaviorScopeKey, BaselineCommand] = OrderedDict()
        self._latest: OrderedDict[BehaviorScopeKey, int] = OrderedDict()
        self._worker: Thread | None = None
        self._accepting = False
        self._stopping = False
        self._abandon = False
        self.checkpoints = 0
        self.failures = 0
        self.rejected = 0
        self.cleanup_rows = 0
        self.on_load: Callable[[BaselineLoad | None], None] = lambda _: None
        self.on_write: Callable[[BaselineCommand, bool], None] = lambda _c, _s: None
        self.on_loss: Callable[[], None] = lambda: None
        self.load_limit = 128
        self.clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def start(self) -> bool:
        with self._condition:
            if self._worker is not None and self._worker.is_alive():
                return False
            self._stopping = self._abandon = False
            self._accepting = True
            self._worker = Thread(target=self._run, name="netsentinel-baseline-writer", daemon=True)
            self._worker.start()
            return True

    def submit(self, command: BaselineCommand) -> bool:
        with self._condition:
            if not self._accepting and not (current_thread() is self._worker and self._stopping and not self._abandon):
                self.rejected += 1
                return False
            prior_sequence = self._latest.get(command.scope, -1)
            if command.sequence < prior_sequence:
                self.rejected += 1
                return False
            prior = self._pending.get(command.scope)
            if prior is None and len(self._pending) >= self.capacity:
                self.rejected += 1
                return False
            if prior is not None:
                command = replace(command, reset=prior.reset or command.reset)
            self._pending[command.scope] = command
            self._latest[command.scope] = command.sequence
            self._latest.move_to_end(command.scope)
            while len(self._latest) > 128:
                self._latest.popitem(last=False)
            self._condition.notify()
            return True

    @property
    def pending_count(self) -> int:
        with self._condition:
            return len(self._pending)

    @property
    def stopping(self) -> bool:
        with self._condition:
            return self._stopping

    def stop(self, timeout: float | None = None) -> bool:
        duration = self.shutdown_timeout if timeout is None else timeout
        if isinstance(duration, bool) or not isfinite(duration) or not 0 <= duration <= 60:
            raise ValueError("invalid baseline stop timeout")
        with self._condition:
            worker = self._worker
            if worker is current_thread():
                raise RuntimeError("baseline worker cannot join itself")
            self._accepting = False
            self._stopping = True
            self._condition.notify()
        if worker is None:
            return True
        worker.join(duration)
        if worker.is_alive():
            with self._condition:
                self._abandon = True
                self._pending.clear()
                self._condition.notify()
            return False
        return True

    def _run(self) -> None:
        try:
            with self._factory() as repository:
                self.on_load(repository.load(self.load_limit))
                # Load first so expired/clock-anomalous data retains a typed origin.
                self._cleanup(repository)
                while True:
                    with self._condition:
                        ready = self._condition.wait_for(lambda: self._pending or self._stopping or self._abandon, timeout=30.0)
                        if self._abandon or (self._stopping and not self._pending):
                            return
                        command = self._pending.popitem(last=False)[1] if ready else None
                    if command is None:
                        self._cleanup(repository)
                        continue
                    success = False
                    try:
                        deleted = repository.write(command.summary, command.scope, reset=command.reset)
                        with self._condition:
                            self.checkpoints += 1
                            self.cleanup_rows += deleted
                        success = True
                        if deleted:
                            self.on_loss()
                    except Exception:
                        with self._condition:
                            self.failures += 1
                    self.on_write(command, success)
                    self._cleanup(repository)
        except Exception:
            with self._condition:
                self.failures += 1
            self.on_load(None)
        finally:
            with self._condition:
                self._accepting = False
                self._pending.clear()

    def _cleanup(self, repository: BaselineRepository) -> None:
        try:
            count = repository.cleanup(self.clock())
            with self._condition:
                self.cleanup_rows += count
            if count:
                self.on_loss()
        except Exception:
            with self._condition:
                self.failures += 1


@dataclass(slots=True)
class _Learning:
    summary: BaselineSummary | None
    origin: BaselineOrigin
    blocked: BaselineState | None = None
    sequence: int = 0
    reset: bool = False


class BehaviorBaselineService:
    """Memory-only producers and queries; all repository I/O goes to the owner."""

    def __init__(self, writer: BaselineWriter, *, capacity: BehaviorCapacity | None = None,
                 config: BehaviorBaselineConfig | None = None, polling_interval: float = 1.0,
                 monotonic_clock: Callable[[], float] = monotonic,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self.capacity = capacity or BehaviorCapacity()
        self.config = config or BehaviorBaselineConfig()
        if self.capacity.scopes > 128 or self.capacity.destinations > 64 or self.capacity.ports > 32 or self.capacity.protocols > 2:
            raise ValueError("baseline capacity exceeds persisted format")
        if not isfinite(polling_interval) or polling_interval <= 0:
            raise ValueError("invalid polling interval")
        self.policy_key = baseline_policy_key(self.capacity, polling_interval, self.config)
        self._writer = writer
        self._clock = clock
        self._monotonic = monotonic_clock
        self._lock = RLock()
        self._records: OrderedDict[BehaviorScopeKey, _Learning] = OrderedDict()
        self._dirty: set[BehaviorScopeKey] = set()
        self._storage = BaselineStorageState.LOADING
        self._loaded = False
        self._load_loss = False
        self._loaded_count = 0
        self._invalid = 0
        self._resets = 0
        self._sequence = 0
        self._due: float | None = None
        writer.on_load = self.restore
        writer.on_write = self._acknowledge
        writer.on_loss = self._note_loss
        writer.load_limit = min(self.config.load_limit, self.capacity.scopes)
        writer.clock = clock

    def start(self) -> bool:
        return self._writer.start()

    def restore(self, loaded: BaselineLoad | None) -> None:
        with self._lock:
            if loaded is None:
                self._storage = BaselineStorageState.UNAVAILABLE
                self._loaded = True
                self._load_loss = True
                return
            self._storage = BaselineStorageState.AVAILABLE
            if self._loaded:
                return  # Same-process stop/start must not add the checkpoint twice.
            self._loaded = True
            self._load_loss = loaded.capacity_loss
            for read in loaded.records:
                self._loaded_count += 1
                if read.scope is None:
                    self._invalid += 1
                    self._load_loss = True
                    continue
                live = self._records.get(read.scope)
                if live is not None and live.reset:
                    continue  # Reset accepted while startup I/O was in flight.
                state = read.state
                summary = read.summary
                if summary is not None:
                    if (len(summary.features.destinations) > self.capacity.destinations
                            or len(summary.features.ports) > self.capacity.ports
                            or len(summary.features.protocols) > self.capacity.protocols):
                        state = BaselineState.CORRUPT
                        summary = None
                    elif summary.policy_key != self.policy_key:
                        state = BaselineState.POLICY_MISMATCH
                        summary = None
                    else:
                        state = baseline_state(summary, self._now(), self.config)
                blocked = state if state in (
                    BaselineState.CORRUPT, BaselineState.UNSUPPORTED_VERSION,
                    BaselineState.POLICY_MISMATCH, BaselineState.STALE,
                    BaselineState.EXPIRED, BaselineState.CLOCK_ANOMALY,
                ) else None
                if blocked is not None:
                    self._invalid += int(blocked in (BaselineState.CORRUPT, BaselineState.UNSUPPORTED_VERSION, BaselineState.POLICY_MISMATCH))
                    self._install(read.scope, _Learning(summary, BaselineOrigin.PREVIOUS_UNAVAILABLE, blocked))
                    continue
                if summary is not None:
                    # A restart is known to break continuity, never to add coverage.
                    summary = replace(summary, features=replace(summary.features, gap_seen=True))
                    if live is not None and live.summary is not None:
                        summary = replace(summary, features=merge_learning(summary.features, live.summary.features, self.capacity), last_observed_at=live.summary.last_observed_at)
                    self._install(read.scope, _Learning(summary, BaselineOrigin.RESTORED, sequence=0 if live is None else live.sequence))
            for entry in self._records.values():
                if entry.origin is BaselineOrigin.PREVIOUS_UNAVAILABLE and entry.blocked is None:
                    if not self._load_loss:
                        entry.origin = BaselineOrigin.NEW
                    elif entry.summary is not None:
                        entry.summary = replace(entry.summary, features=replace(entry.summary.features, capacity_loss=True))
            if self._writer.stopping:
                self.checkpoint(force=True)

    def observe(self, contributions: tuple[BehaviorFeatureSnapshot, ...], observed_at: datetime,
                quality: ObservationQuality) -> None:
        with self._lock:
            if quality is not ObservationQuality.COMPLETE:
                for existing_scope, existing_entry in self._records.items():
                    if existing_entry.summary is not None and not existing_entry.summary.features.gap_seen:
                        existing_entry.summary = replace(existing_entry.summary, features=replace(existing_entry.summary.features, gap_seen=True))
                        self._touch(existing_scope, existing_entry)
            if quality is not ObservationQuality.FAILED:
                for contribution in contributions:
                    scope = contribution.scope
                    if scope.identity_restart_stable:
                        try:
                            validate_baseline_scope(scope)
                        except (ValueError, TypeError):
                            self._install(scope, _Learning(None, BaselineOrigin.PREVIOUS_UNAVAILABLE, BaselineState.UNAVAILABLE))
                            continue
                    entry = self._records.get(scope)
                    if entry is not None and entry.blocked is not None:
                        continue
                    if entry is not None and entry.summary is not None:
                        state = baseline_state(entry.summary, self._now(), self.config)
                        if observed_at < entry.summary.last_observed_at:
                            state = BaselineState.CLOCK_ANOMALY
                        if state in (BaselineState.STALE, BaselineState.EXPIRED, BaselineState.CLOCK_ANOMALY):
                            entry.blocked = state
                            continue
                        features = merge_learning(entry.summary.features, contribution, self.capacity)
                    else:
                        features = contribution
                        origin = BaselineOrigin.NEW if self._loaded and not self._load_loss else BaselineOrigin.PREVIOUS_UNAVAILABLE
                        if not scope.identity_restart_stable:
                            origin = BaselineOrigin.SESSION_ONLY
                        entry = entry or _Learning(None, origin)
                        self._install(scope, entry)
                    if self._load_loss and entry.origin in (BaselineOrigin.NEW, BaselineOrigin.PREVIOUS_UNAVAILABLE):
                        features = replace(features, capacity_loss=True)
                    summary = BaselineSummary(features, observed_at, self._now(), self.policy_key)
                    if scope.identity_restart_stable:
                        validate_baseline_summary(summary)
                    entry.summary = summary
                    self._records.move_to_end(scope)
                    self._touch(scope, entry)
            self.checkpoint()

    def _install(self, scope: BehaviorScopeKey, entry: _Learning) -> None:
        if scope in self._records:
            self._records[scope] = entry
            return
        same_app = [key for key in self._records if key.application_key == scope.application_key]
        applications = {key.application_key for key in self._records}
        victims: list[BehaviorScopeKey] = []
        if not same_app and len(applications) >= self.capacity.applications:
            oldest_app = next(iter(self._records)).application_key
            victims = [key for key in self._records if key.application_key == oldest_app]
        elif len(same_app) >= self.capacity.networks_per_application:
            victims = same_app[:1]
        elif len(self._records) >= self.capacity.scopes:
            victims = [next(iter(self._records))]
        for victim in victims:
            del self._records[victim]
            self._dirty.discard(victim)
            self._load_loss = True
        self._records[scope] = entry

    def _touch(self, scope: BehaviorScopeKey, entry: _Learning) -> None:
        self._sequence += 1
        entry.sequence = self._sequence
        if scope.identity_restart_stable:
            self._dirty.add(scope)

    def _note_loss(self) -> None:
        with self._lock:
            self._load_loss = True

    def checkpoint(self, *, force: bool = False) -> int:
        with self._lock:
            tick = self._monotonic()
            if not isfinite(tick):
                raise ValueError("invalid checkpoint monotonic clock")
            if self._due is None:
                self._due = tick + self.config.checkpoint_interval
            if not self._loaded or (not force and tick < self._due):
                return 0
            self._due = tick + self.config.checkpoint_interval
            submitted = 0
            for scope in sorted(self._dirty, key=lambda s: (s.application_key, s.revision_digest or "", s.network_token)):
                entry = self._records[scope]
                if entry.blocked is not None:
                    continue
                if entry.summary is not None:
                    state = baseline_state(entry.summary, self._now(), self.config)
                    if state in (BaselineState.STALE, BaselineState.EXPIRED, BaselineState.CLOCK_ANOMALY):
                        entry.blocked = state
                        continue
                summary = None if entry.summary is None else replace(entry.summary, persisted_at=self._now())
                if self._writer.submit(BaselineCommand(scope, summary, entry.sequence, entry.reset)):
                    submitted += 1
            return submitted

    def reset(self, scope: BehaviorScopeKey) -> bool:
        """Idempotent exact-scope reset; acceptance is not durable completion."""
        with self._lock:
            self._sequence += 1
            if scope.identity_restart_stable:
                validate_baseline_scope(scope)
                command = BaselineCommand(scope, None, self._sequence, True)
                if not self._writer.submit(command):
                    return False
            self._install(scope, _Learning(None, BaselineOrigin.RESET, sequence=self._sequence, reset=scope.identity_restart_stable))
            if scope.identity_restart_stable:
                self._dirty.add(scope)
            self._resets += 1
            return True

    def _acknowledge(self, command: BaselineCommand, success: bool) -> None:
        with self._lock:
            self._storage = BaselineStorageState.AVAILABLE if success else BaselineStorageState.UNAVAILABLE
            entry = self._records.get(command.scope)
            if entry is None or entry.sequence != command.sequence:
                return
            if success:
                self._dirty.discard(command.scope)
                entry.reset = False
                if entry.summary is not None and command.summary is not None:
                    entry.summary = replace(entry.summary, persisted_at=command.summary.persisted_at)
            else:
                self._dirty.add(command.scope)
                entry.reset |= command.reset

    def snapshot(self, scope: BehaviorScopeKey) -> BaselineSnapshot:
        with self._lock:
            entry = self._records.get(scope)
            if entry is None:
                state = BaselineState.UNAVAILABLE if self._load_loss or not self._loaded else BaselineState.LEARNING
                return BaselineSnapshot(scope, state, BaselineOrigin.PREVIOUS_UNAVAILABLE if state is BaselineState.UNAVAILABLE else BaselineOrigin.NEW, self._storage, None)
            state = entry.blocked or (BaselineState.LEARNING if entry.summary is None else baseline_state(entry.summary, self._now(), self.config))
            if state in (BaselineState.STALE, BaselineState.EXPIRED, BaselineState.CLOCK_ANOMALY):
                entry.blocked = state  # Forward/backward clock jumps cannot silently refresh.
            return BaselineSnapshot(scope, state, entry.origin, self._storage, entry.summary)

    def diagnostics(self) -> BaselineDiagnostics:
        with self._lock:
            return BaselineDiagnostics(self._storage, self._loaded_count, len(self._dirty),
                                       self._writer.pending_count, self._writer.checkpoints,
                                       self._writer.failures, self._writer.rejected, self._invalid,
                                       self._writer.cleanup_rows, self._resets, self._load_loss)

    def stop(self, timeout: float | None = None) -> bool:
        self.checkpoint(force=True)
        return self._writer.stop(timeout)

    def _now(self) -> datetime:
        stamp = self._clock()
        offset = stamp.utcoffset()
        if stamp.tzinfo is None or offset is None or offset.total_seconds() != 0:
            raise ValueError("baseline clock must be UTC")
        return stamp

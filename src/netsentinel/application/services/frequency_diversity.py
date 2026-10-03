"""NS-073 bounded session reference learning and evidence emission control."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field, replace
from math import isfinite
from threading import RLock
from uuid import UUID

from netsentinel.application.detectors.frequency_diversity import evaluate_frequency_diversity
from netsentinel.domain.behavior_baseline import BaselineSnapshot
from netsentinel.domain.behavior_features import BehaviorScopeKey
from netsentinel.domain.frequency_diversity import (
    BehaviorClassification as Classification, BehaviorDeviationEvidence,
    BehaviorRangeReference, BehaviorRangeSample, BehaviorReason as Reason,
    BehaviorRule, BehaviorWindow, FrequencyDiversityInput, FrequencyDiversityPolicy,
)


class BehaviorRangeLearner:
    """Explicit reference collection phase, never automatic anomaly adaptation.

    At most 128 scopes x eight aggregate samples. Accepted independent windows
    move to the end; eviction is oldest accepted scope. No raw events/IP lists,
    persistence or monotonic epochs survive a new learner instance. The owner
    freezes learning before evaluation and clears it on baseline reset.
    """

    def __init__(self, policy: FrequencyDiversityPolicy = FrequencyDiversityPolicy()) -> None:
        self.policy = policy
        self._references: OrderedDict[BehaviorScopeKey, BehaviorRangeReference] = OrderedDict()
        self._lock = RLock()

    @property
    def scope_count(self) -> int:
        with self._lock:
            return len(self._references)

    def snapshot(self, scope: BehaviorScopeKey) -> BehaviorRangeReference | None:
        with self._lock:
            return self._references.get(scope)

    def reset(self, scope: BehaviorScopeKey) -> None:
        with self._lock:
            self._references.pop(scope, None)

    def learn(self, window: BehaviorWindow, baseline: BaselineSnapshot) -> bool:
        checked = evaluate_frequency_diversity(FrequencyDiversityInput(window, baseline), self.policy)[0]
        if checked.classification not in (Classification.NORMAL, Classification.ELEVATED_UNCONFIRMED):
            return False
        assert baseline.summary is not None
        key = window.features.scope
        with self._lock:
            prior = self._references.get(key)
            if prior is not None and (prior.session_id != window.session_id or prior.baseline_policy_key != baseline.summary.policy_key):
                prior = None
            samples = () if prior is None else prior.samples
            if samples and window.started_monotonic < samples[-1].ended_monotonic:
                return False
            sample = BehaviorRangeSample(window.started_monotonic, window.ended_monotonic,
                                         window.features.monitored_seconds,
                                         window.features.observed_appearances,
                                         window.features.destination_diversity)
            self._references[key] = BehaviorRangeReference(key, window.session_id, self.policy,
                                                         (*samples, sample)[-8:], baseline.summary.policy_key)
            self._references.move_to_end(key)
            while len(self._references) > self.policy.maximum_scopes:
                self._references.popitem(last=False)
            return True


@dataclass(slots=True)
class _RuleState:
    last_ended: float | None = None
    confirmations: int = 0
    last_emission: float | None = None


@dataclass(slots=True)
class _ScopeState:
    session_id: UUID
    baseline_policy_key: str | None
    rules: dict[BehaviorRule, _RuleState] = field(default_factory=dict)


class FrequencyDiversityService:
    """Two rule states per scope, at most 128 scopes; all clocks explicit.

    Confirmation advances only for non-overlapping window envelopes. Repeated
    refreshes/overlapping rolling windows cannot confirm or emit again. Oldest
    independently evaluated scope is evicted; replacement starts unconfirmed.
    This controls evidence emission eligibility, not alert dedup or delivery.
    """

    def __init__(self, policy: FrequencyDiversityPolicy = FrequencyDiversityPolicy()) -> None:
        self.policy = policy
        self._states: OrderedDict[BehaviorScopeKey, _ScopeState] = OrderedDict()
        self._last_now: float | None = None
        self._lock = RLock()

    @property
    def scope_count(self) -> int:
        with self._lock:
            return len(self._states)

    def reset(self, scope: BehaviorScopeKey) -> None:
        with self._lock:
            self._states.pop(scope, None)

    def evaluate(self, observation: FrequencyDiversityInput, *, now_monotonic: float) -> tuple[BehaviorDeviationEvidence, BehaviorDeviationEvidence]:
        if isinstance(now_monotonic, bool) or not isinstance(now_monotonic, (int, float)) or not isfinite(now_monotonic) or not 0 <= now_monotonic <= 1e12:
            raise ValueError("invalid explicit monotonic time")
        calculated = evaluate_frequency_diversity(observation, self.policy)
        window = observation.window
        with self._lock:
            if now_monotonic < window.ended_monotonic or (self._last_now is not None and now_monotonic < self._last_now):
                return tuple_clock_anomaly(calculated)
            self._last_now = now_monotonic
            scope = window.features.scope
            entry = self._states.get(scope)
            summary = None if observation.baseline is None else observation.baseline.summary
            policy_key = None if summary is None else summary.policy_key
            if entry is not None and (entry.session_id != window.session_id or entry.baseline_policy_key != policy_key):
                del self._states[scope]
                entry = None
            evaluated = (Classification.NORMAL, Classification.ELEVATED_UNCONFIRMED)
            if entry is None and any(e.classification in evaluated for e in calculated):
                entry = _ScopeState(window.session_id, policy_key)
                self._states[scope] = entry
                while len(self._states) > self.policy.maximum_scopes:
                    self._states.popitem(last=False)
            if entry is None:
                return calculated
            advanced = False
            results = []
            for evidence in calculated:
                state = entry.rules.setdefault(evidence.rule_id, _RuleState())
                if evidence.classification not in evaluated:
                    state.confirmations = 0
                    results.append(evidence)
                    continue
                independent = state.last_ended is None or window.started_monotonic >= state.last_ended
                if not independent:
                    if evidence.classification is Classification.ELEVATED_UNCONFIRMED:
                        evidence = replace(evidence,
                            classification=Classification.ELEVATED_CONFIRMED if state.confirmations >= self.policy.confirmation_windows else Classification.ELEVATED_UNCONFIRMED,
                            confirmation_count=state.confirmations, reason=Reason.WINDOW_NOT_INDEPENDENT)
                    results.append(evidence)
                    continue
                if state.last_ended is not None and window.started_monotonic - state.last_ended > self.policy.maximum_confirmation_gap_seconds:
                    state.confirmations = 0
                state.last_ended = window.ended_monotonic
                advanced = True
                if evidence.classification is Classification.NORMAL:
                    state.confirmations = 0
                else:
                    state.confirmations = min(self.policy.confirmation_windows, state.confirmations + 1)
                    evidence = replace(evidence, confirmation_count=state.confirmations)
                    if state.confirmations >= self.policy.confirmation_windows:
                        cooldown = state.last_emission is not None and now_monotonic - state.last_emission < self.policy.cooldown_seconds
                        evidence = replace(evidence, classification=Classification.ELEVATED_CONFIRMED,
                                           emission_eligible=not cooldown,
                                           reason=Reason.COOLDOWN_ACTIVE if cooldown else evidence.reason)
                        if not cooldown:
                            state.last_emission = now_monotonic
                results.append(evidence)
            if advanced:
                self._states.move_to_end(scope)
            return results[0], results[1]


def tuple_clock_anomaly(results: tuple[BehaviorDeviationEvidence, BehaviorDeviationEvidence]) -> tuple[BehaviorDeviationEvidence, BehaviorDeviationEvidence]:
    def invalid(evidence: BehaviorDeviationEvidence) -> BehaviorDeviationEvidence:
        return replace(evidence, classification=Classification.NOT_EVALUATED,
                       reason=Reason.CLOCK_ANOMALY, emission_eligible=False)
    return invalid(results[0]), invalid(results[1])

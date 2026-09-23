"""Synchronous DNS configuration poller on the existing engine worker."""

from __future__ import annotations

from netsentinel.application.detectors.dns_config import DnsConfigChangeDetector
from netsentinel.application.ports import NetworkContextProvider
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.baselines import DnsServerBaselineService
from netsentinel.domain.alerts import AlertCandidate


class DnsConfigPollError(RuntimeError):
    """Sanitized local configuration read or alert storage failure."""


class DnsConfigMonitoringService:
    """Read local Windows contexts and persist only confirmed changes.

    This service owns no thread, socket, timer or capture resource. Its caller
    schedules ``poll``. Whole-read failures break pending confirmations.
    """

    def __init__(self, contexts: NetworkContextProvider, alerts: AlertService,
                 *, baseline: DnsServerBaselineService | None = None,
                 detector: DnsConfigChangeDetector | None = None) -> None:
        self._contexts = contexts
        self._alerts = alerts
        self._baseline = baseline or DnsServerBaselineService()
        self._detector = detector or DnsConfigChangeDetector()

    def poll(self) -> tuple[AlertCandidate, ...]:
        try:
            contexts = self._contexts.get_contexts()
        except Exception:
            self._baseline.interrupt()
            raise DnsConfigPollError("DNS configuration read unavailable") from None

        # Multiple IPv4 addresses can share a fingerprint. Conflicting values
        # in one OS snapshot are ambiguous, so neither value is evidence.
        by_fingerprint = {}
        ambiguous = set()
        for context in contexts:
            if context.is_loopback:
                continue
            existing = by_fingerprint.setdefault(context.fingerprint, context)
            if existing.dns_servers != context.dns_servers:
                ambiguous.add(context.fingerprint)
        self._baseline.interrupt_absent(set(by_fingerprint) - ambiguous)
        candidates: list[AlertCandidate] = []
        failed = False
        for fingerprint, context in by_fingerprint.items():
            if fingerprint in ambiguous:
                continue
            try:
                change = self._baseline.observe(context)
                if change is not None:
                    candidate = self._detector.assess(change)
                    self._alerts.record(candidate)
                    self._baseline.commit(change)
                    candidates.append(candidate)
            except Exception:
                failed = True
        if failed:
            raise DnsConfigPollError("DNS configuration detection unavailable")
        return tuple(candidates)


__all__ = ("DnsConfigMonitoringService", "DnsConfigPollError")

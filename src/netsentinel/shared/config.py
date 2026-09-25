"""Portable configuration values shared across application compositions."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite


DEFAULT_RETENTION_DAYS = 30
DEFAULT_MAX_HISTORY_ROWS = 100_000
DEFAULT_CLEANUP_CHUNK_SIZE = 500


def _require_positive_int(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} must be an integer")
    if value <= 0:
        raise ValueError(f"{field_name} must be greater than zero")


@dataclass(frozen=True, slots=True)
class HistoryRetentionConfig:
    """Portable connection-history retention policy.

    Both age and row policies are always enabled.  The row limit counts active
    and completed lifecycle records together, while cleanup may delete only
    completed records.  Each committed delete is bounded by ``cleanup_chunk_size``.
    """

    retention_days: int = DEFAULT_RETENTION_DAYS
    max_history_rows: int = DEFAULT_MAX_HISTORY_ROWS
    cleanup_chunk_size: int = DEFAULT_CLEANUP_CHUNK_SIZE

    def __post_init__(self) -> None:
        _require_positive_int(self.retention_days, "retention_days")
        _require_positive_int(self.max_history_rows, "max_history_rows")
        _require_positive_int(self.cleanup_chunk_size, "cleanup_chunk_size")


@dataclass(frozen=True, slots=True)
class TrafficRateConfig:
    """NS-037 conservative rates in packets/second, scoped per protocol."""

    broadcast_floor_pps: float = 5.0
    arp_floor_pps: float = 2.0
    baseline_multiplier: float = 3.0
    minimum_samples: int = 3
    recovery_fraction: float = 0.5
    recovery_samples: int = 2
    cooldown_seconds: float = 120.0
    idle_expiry_seconds: float = 600.0
    max_states: int = 128  # NS-036's 64 scopes times two protocols

    def __post_init__(self) -> None:
        for name in ("broadcast_floor_pps", "arp_floor_pps", "baseline_multiplier",
                     "recovery_fraction", "cooldown_seconds", "idle_expiry_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and positive")
        if self.baseline_multiplier <= 1 or not 0 < self.recovery_fraction < 1:
            raise ValueError("multiplier must exceed one and recovery fraction must be below one")
        for name in ("minimum_samples", "recovery_samples", "max_states"):
            _require_positive_int(getattr(self, name), name)
        if not 2 <= self.minimum_samples <= 32 or self.recovery_samples > 32 or self.max_states > 8192:
            raise ValueError("sample counts and max_states must be bounded")


__all__ = (
    "DEFAULT_CLEANUP_CHUNK_SIZE",
    "DEFAULT_MAX_HISTORY_ROWS",
    "DEFAULT_RETENTION_DAYS",
    "HistoryRetentionConfig",
    "TrafficRateConfig",
)

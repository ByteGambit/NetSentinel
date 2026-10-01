"""Portable configuration values shared across application compositions."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import asdict, replace
from math import isfinite
from collections.abc import Mapping
import json
import os
from pathlib import Path
import tempfile
from typing import Any


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


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Safe, bounded runtime knobs. Capture remains opt-in regardless of config."""

    polling_interval: float = 1.0
    shutdown_timeout: float = 2.0
    capture_queue_capacity: int = 1_024
    history_queue_capacity: int = 2_048
    history_batch_size: int = 64
    history_checkpoint_interval: float = 30.0
    dns_queue_capacity: int = 2_048
    dns_batch_size: int = 64
    log_max_bytes: int = 1_048_576
    log_backups: int = 3
    onboarding_completed: bool = False

    def __post_init__(self) -> None:
        if type(self.onboarding_completed) is not bool:
            raise ValueError("onboarding_completed must be a boolean")
        for name in ("polling_interval", "shutdown_timeout"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value) or not 0.05 <= value <= 60:
                raise ValueError(f"{name} must be finite and between 0.05 and 60")
        interval = self.history_checkpoint_interval
        if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not isfinite(interval) or not 1 <= interval <= 3600:
            raise ValueError("history_checkpoint_interval must be finite and between 1 and 3600")
        for name, ceiling in (
            ("capture_queue_capacity", 65_536), ("history_queue_capacity", 65_536),
            ("history_batch_size", 500), ("dns_queue_capacity", 65_536),
            ("dns_batch_size", 500),
            ("log_max_bytes", 16_777_216), ("log_backups", 10),
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError(f"{name} must be an integer between 1 and {ceiling}")
        if self.log_max_bytes < 256:
            raise ValueError("log_max_bytes must be at least 256")
        if self.history_batch_size > self.history_queue_capacity:
            raise ValueError("history_batch_size must not exceed history_queue_capacity")
        if self.dns_batch_size > self.dns_queue_capacity:
            raise ValueError("dns_batch_size must not exceed dns_queue_capacity")


@dataclass(frozen=True, slots=True)
class ConfigIssue:
    field: str
    code: str


@dataclass(frozen=True, slots=True)
class ConfigLoadResult:
    config: AppConfig
    issues: tuple[ConfigIssue, ...] = ()


def load_config_values(values: Mapping[str, Any]) -> ConfigLoadResult:
    """Validate each field independently; invalid fields use safe defaults."""

    if not isinstance(values, Mapping):
        return ConfigLoadResult(AppConfig(), (ConfigIssue("config", "invalid_root"),))
    defaults = AppConfig()
    accepted: dict[str, Any] = {}
    issues: list[ConfigIssue] = []
    fields = tuple(AppConfig.__dataclass_fields__)
    for name in sorted(values, key=lambda item: str(item)):
        if not isinstance(name, str) or name not in fields:
            issues.append(ConfigIssue("unknown", "unknown_field"))
    for name in fields:
        if name not in values:
            continue
        value = values[name]
        try:
            probe = {name: value}
            if name in ("history_queue_capacity", "dns_queue_capacity"):
                probe[name.replace("queue_capacity", "batch_size")] = 1
            AppConfig(**probe)
        except (TypeError, ValueError):
            issues.append(ConfigIssue(name, "invalid_value"))
        else:
            accepted[name] = value
    for prefix in ("history", "dns"):
        batch_name = prefix + "_batch_size"
        queue_name = prefix + "_queue_capacity"
        if accepted.get(batch_name, getattr(defaults, batch_name)) > accepted.get(queue_name, getattr(defaults, queue_name)):
            issues.append(ConfigIssue(batch_name, "exceeds_queue_capacity"))
            accepted.pop(batch_name, None)
            if getattr(defaults, batch_name) > accepted.get(queue_name, getattr(defaults, queue_name)):
                accepted.pop(queue_name, None)
                issues.append(ConfigIssue(queue_name, "below_default_batch_size"))
    return ConfigLoadResult(AppConfig(**accepted), tuple(issues))


def load_config_file(path: str | Path) -> ConfigLoadResult:
    """Read a small local JSON config; malformed/unreadable files fail closed."""

    try:
        target = Path(path)
        with target.open("r", encoding="utf-8") as source:
            content = source.read(16_385)
        if len(content) > 16_384:
            return ConfigLoadResult(AppConfig(), (ConfigIssue("config", "file_too_large"),))
        values = json.loads(content)
    except FileNotFoundError:
        return ConfigLoadResult(AppConfig())
    except (OSError, UnicodeError, json.JSONDecodeError):
        return ConfigLoadResult(AppConfig(), (ConfigIssue("config", "unreadable_or_malformed"),))
    return load_config_values(values)


def complete_onboarding(path: str | Path, config: AppConfig) -> AppConfig:
    """Atomically persist an explicit user completion with validated settings."""

    target = Path(path)
    completed = replace(config, onboarding_completed=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=target.parent,
            prefix=".config-", suffix=".tmp", delete=False,
        ) as stream:
            temporary = stream.name
            json.dump(asdict(completed), stream, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
    return completed


__all__ = (
    "DEFAULT_CLEANUP_CHUNK_SIZE",
    "DEFAULT_MAX_HISTORY_ROWS",
    "DEFAULT_RETENTION_DAYS",
    "HistoryRetentionConfig",
    "TrafficRateConfig",
    "AppConfig", "ConfigIssue", "ConfigLoadResult", "load_config_values", "load_config_file", "complete_onboarding",
)

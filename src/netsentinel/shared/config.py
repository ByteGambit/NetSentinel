"""Portable configuration values shared across application compositions."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import asdict, replace
from enum import Enum
from math import isfinite
from collections.abc import Mapping
import json
import os
from pathlib import Path
import tempfile
from typing import Any
from uuid import UUID

from netsentinel.domain.threat_intelligence import (
    MAX_TI_CONSENTS, ThreatIntelConsent, ThreatIntelDataType, ThreatIntelProviderId, ThreatIntelTrigger,
    validate_consents,
)


DEFAULT_RETENTION_DAYS = 30
DEFAULT_MAX_HISTORY_ROWS = 100_000
DEFAULT_CLEANUP_CHUNK_SIZE = 500
CURRENT_ONBOARDING_VERSION = 1


@dataclass(frozen=True, slots=True)
class StorageMaintenanceConfig:
    """Central NS-095 worker budgets, independent of engine polling."""

    interval_seconds: float = 3600.0
    startup_delay_seconds: float = 60.0
    runtime_seconds: float = 2.0
    max_chunks: int = 16
    max_deletes: int = 2048
    busy_timeout_ms: int = 100
    shutdown_seconds: float = 2.0
    export_category_records: int = 50
    export_page_records: int = 25
    preview_category_records: int = 10
    export_bytes: int = 65_536

    def __post_init__(self) -> None:
        for name, maximum in (("max_chunks", 16), ("max_deletes", 2048),
                              ("busy_timeout_ms", 100), ("export_category_records", 50),
                              ("export_page_records", 25), ("preview_category_records", 10),
                              ("export_bytes", 65_536)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("maintenance integer outside budget")
        for name, maximum in (("interval_seconds", 86_400), ("startup_delay_seconds", 3600),
                              ("runtime_seconds", 2), ("shutdown_seconds", 2)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value) or not 0.01 <= value <= maximum:
                raise ValueError("maintenance duration outside budget")
        if self.interval_seconds < self.startup_delay_seconds:
            raise ValueError("maintenance interval must exceed startup delay")


class WindowCloseBehavior(str, Enum):
    """NS-093 user preference, independent of session tray capability."""

    QUIT_APPLICATION = "quit_application"
    HIDE_TO_TRAY = "hide_to_tray"


@dataclass(frozen=True, slots=True)
class BehaviorBaselineConfig:
    """Explicit NS-071 local learning, storage and checkpoint budgets."""

    minimum_samples: int = 20
    minimum_monitored_seconds: float = 600.0
    stale_days: int = 30
    retention_days: int = 90
    checkpoint_interval: float = 30.0
    max_rows: int = 512
    load_limit: int = 128
    cleanup_chunk_size: int = 64

    def __post_init__(self) -> None:
        for name, ceiling in (("minimum_samples", 1_000_000), ("stale_days", 3650),
                              ("retention_days", 3650), ("max_rows", 512),
                              ("load_limit", 128), ("cleanup_chunk_size", 64)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError(f"{name} is outside its bounded policy")
        for name, ceiling in (("minimum_monitored_seconds", 86_400), ("checkpoint_interval", 3600)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value) or not 1 <= value <= ceiling:
                raise ValueError(f"{name} must be finite and bounded")
        if self.retention_days <= self.stale_days or self.load_limit > self.max_rows:
            raise ValueError("retention must exceed staleness; load must fit row quota")


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
    onboarding_completed_version: int = 0
    onboarding_dismissed_version: int = 0
    desktop_notifications_enabled: bool = False
    storage_retention_enabled: bool = False
    storage_history_days: int = 30
    storage_security_days: int = 90
    window_close_behavior: WindowCloseBehavior = WindowCloseBehavior.QUIT_APPLICATION
    destination_dataset_path: str | None = None
    threat_intel_consents: tuple[ThreatIntelConsent, ...] = ()

    def __post_init__(self) -> None:
        validate_consents(self.threat_intel_consents)
        if type(self.storage_retention_enabled) is not bool:
            raise ValueError("storage_retention_enabled must be a boolean")
        for value in (self.storage_history_days, self.storage_security_days):
            if type(value) is not int or not 30 <= value <= 365:
                raise ValueError("storage retention days must be between 30 and 365")
        if type(self.desktop_notifications_enabled) is not bool:
            raise ValueError("desktop_notifications_enabled must be a boolean")
        if not isinstance(self.window_close_behavior, WindowCloseBehavior):
            raise ValueError("window_close_behavior must be WindowCloseBehavior")
        if self.destination_dataset_path is not None:
            path = self.destination_dataset_path
            if (not isinstance(path, str) or not path or len(path) > 4096
                    or any(ord(char) < 32 for char in path) or path.startswith("\\\\")):
                raise ValueError("destination_dataset_path must be a bounded local path")
        if type(self.onboarding_completed) is not bool:
            raise ValueError("onboarding_completed must be a boolean")
        for value in (self.onboarding_completed_version, self.onboarding_dismissed_version):
            if type(value) is not int or not 0 <= value <= 10_000:
                raise ValueError("onboarding version must be between 0 and 10000")
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
            if name == "threat_intel_consents":
                value = _load_threat_intel_consents(value)
            if name == "window_close_behavior":
                value = WindowCloseBehavior(value)
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
    if issues and accepted.get("threat_intel_consents"):
        # A damaged config cannot silently preserve an outbound-data permission.
        accepted.pop("threat_intel_consents")
        issues.append(ConfigIssue("threat_intel_consents", "disabled_due_to_config_issue"))
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

    current = load_config_file(path).config if Path(path).exists() else config
    completed = replace(current, onboarding_completed=True,
                        onboarding_completed_version=max(current.onboarding_completed_version, CURRENT_ONBOARDING_VERSION))
    save_config_file(path, completed)
    return completed


def onboarding_pending(config: AppConfig) -> bool:
    """Legacy completion grants a nonmodal upgrade notice, never eternal hiding."""
    return max(config.onboarding_completed_version, config.onboarding_dismissed_version) < CURRENT_ONBOARDING_VERSION


def show_onboarding_at_startup(config: AppConfig) -> bool:
    return (onboarding_pending(config) and not config.onboarding_completed
            and config.onboarding_completed_version == 0 and config.onboarding_dismissed_version == 0)


def dismiss_onboarding(path: str | Path, config: AppConfig) -> AppConfig:
    """Skip acknowledges this guide version without completing or consenting."""
    current = load_config_file(path).config if Path(path).exists() else config
    dismissed = replace(current, onboarding_dismissed_version=max(current.onboarding_dismissed_version, CURRENT_ONBOARDING_VERSION))
    save_config_file(path, dismissed)
    return dismissed


def save_window_close_behavior(path: str | Path, behavior: WindowCloseBehavior) -> None:
    """Explicit settings Save preserves other settings changed this session."""

    current = load_config_file(path).config
    save_config_file(path, replace(current, window_close_behavior=behavior))


def save_notification_preference(path: str | Path, enabled: bool) -> None:
    current = load_config_file(path).config
    save_config_file(path, replace(current, desktop_notifications_enabled=enabled))


def save_storage_preferences(path: str | Path, enabled: bool, history_days: int, security_days: int) -> None:
    """Called by the maintenance worker after explicit Save; preserve other fields."""
    current = load_config_file(path).config
    save_config_file(path, replace(current, storage_retention_enabled=enabled,
                                   storage_history_days=history_days, storage_security_days=security_days))


def _load_threat_intel_consents(value: Any) -> tuple[ThreatIntelConsent, ...]:
    # Entire malformed TI section is disabled, not partially opted in.
    if not isinstance(value, list) or len(value) > MAX_TI_CONSENTS:
        raise ValueError("invalid consent section")
    consents = []
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {
            "consent_id", "provider", "data_type", "trigger", "policy_version",
        }:
            raise ValueError("invalid consent entry")
        if not isinstance(entry["provider"], dict) or set(entry["provider"]) != {"value"}:
            raise ValueError("invalid provider reference")
        if any(not isinstance(entry[field], str) for field in ("consent_id", "data_type", "trigger")):
            raise ValueError("invalid consent fields")
        consents.append(ThreatIntelConsent(
            UUID(entry["consent_id"]), ThreatIntelProviderId(entry["provider"]["value"]),
            ThreatIntelDataType(entry["data_type"]), ThreatIntelTrigger(entry["trigger"]),
            entry["policy_version"],
        ))
    result = tuple(consents)
    validate_consents(result)
    return result


def save_config_file(path: str | Path, config: AppConfig) -> None:
    """Atomically persist validated local config after explicit user action."""
    if not isinstance(config, AppConfig):
        raise TypeError("config must be AppConfig")
    values = asdict(config)
    for entry in values["threat_intel_consents"]:
        entry["consent_id"] = str(entry["consent_id"])
    content = json.dumps(values, separators=(",", ":"))
    if len(content) > 16_384:
        raise ValueError("serialized config exceeds loader bound")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=target.parent,
            prefix=".config-", suffix=".tmp", delete=False,
        ) as stream:
            temporary = stream.name
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)


__all__ = (
    "CURRENT_ONBOARDING_VERSION", "onboarding_pending", "show_onboarding_at_startup", "dismiss_onboarding",
    "DEFAULT_CLEANUP_CHUNK_SIZE",
    "DEFAULT_MAX_HISTORY_ROWS",
    "DEFAULT_RETENTION_DAYS",
    "HistoryRetentionConfig",
    "TrafficRateConfig",
    "StorageMaintenanceConfig", "save_storage_preferences",
    "AppConfig", "WindowCloseBehavior", "save_window_close_behavior", "ConfigIssue", "ConfigLoadResult", "load_config_values", "load_config_file", "complete_onboarding", "save_config_file",
)

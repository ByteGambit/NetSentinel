"""Bounded structured logs with an allowlist instead of free-form messages."""

from __future__ import annotations

from datetime import UTC, datetime
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import re

from netsentinel.shared.config import AppConfig
from netsentinel.shared.diagnostics import DiagnosticCode, DiagnosticComponent


_SAFE_TOKEN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_COMPONENTS = {item.value for item in DiagnosticComponent} | {"config"}
_CODES = {item.value for item in DiagnosticCode} | {
    "invalid_root", "unknown_field", "invalid_value", "exceeds_queue_capacity",
    "below_default_batch_size", "file_too_large", "unreadable_or_malformed",
    "startup_failed",
}


class SafeJsonFormatter(logging.Formatter):
    """Never serialize message, exception, extra payload, path, or stack."""

    def format(self, record: logging.LogRecord) -> str:
        def token(name: str, allowed: set[str]) -> str:
            value = getattr(record, name, None)
            return value if isinstance(value, str) and _SAFE_TOKEN.fullmatch(value) and value in allowed else "redacted"

        return json.dumps({
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname if record.levelname in {"INFO", "WARNING", "ERROR"} else "INFO",
            "component": token("safe_component", _COMPONENTS),
            "code": token("safe_code", _CODES),
        }, separators=(",", ":"), sort_keys=True)


class SafeRotatingFileHandler(RotatingFileHandler):
    def handleError(self, record: logging.LogRecord) -> None:
        # Logging must not leak a file path/exception to stderr or stop monitoring.
        return None


def configure_logging(path: str | Path, config: AppConfig) -> logging.Logger:
    """Configure the one application logger without touching the root logger."""

    if not isinstance(config, AppConfig):
        raise TypeError("config must be AppConfig")
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    handler = SafeRotatingFileHandler(target, maxBytes=config.log_max_bytes, backupCount=config.log_backups, encoding="utf-8")
    handler.setFormatter(SafeJsonFormatter())
    logger = logging.getLogger("netsentinel")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for previous in tuple(logger.handlers):
        logger.removeHandler(previous)
        previous.close()
    logger.addHandler(handler)
    return logger


def log_event(logger: logging.Logger, *, component: str, code: str, level: int = logging.INFO) -> None:
    """Callers provide only stable code identifiers, never observed values."""

    logger.log(level, "event", extra={"safe_component": component, "safe_code": code})


def close_logging(logger: logging.Logger) -> None:
    for handler in tuple(logger.handlers):
        logger.removeHandler(handler)
        handler.close()


__all__ = ("SafeJsonFormatter", "configure_logging", "log_event", "close_logging")

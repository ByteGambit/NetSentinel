"""PyQt6 application startup and MonitoringEngine lifecycle integration."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import sys
from typing import Protocol

from PyQt6.QtWidgets import QApplication

from netsentinel.presentation.views.main_window import MainWindow


class EngineLifecycle(Protocol):
    """Narrow lifecycle surface required by the desktop shell."""

    def start(self) -> bool: ...

    def stop(self, timeout: float | None = None) -> bool: ...


class ApplicationLifecycle:
    """Own the engine's start and single controlled shutdown request."""

    def __init__(self, engine: EngineLifecycle) -> None:
        self._engine = engine
        self._start_requested = False
        self._shutdown_requested = False
        self._shutdown_result: bool | None = None

    @property
    def shutdown_requested(self) -> bool:
        return self._shutdown_requested

    def start(self) -> bool:
        """Start the engine at most once for this application run."""

        if self._start_requested:
            return False
        self._start_requested = True
        return self._engine.start()

    def shutdown(self) -> bool:
        """Request the engine's bounded, idempotent stop exactly once."""

        if self._shutdown_requested:
            return bool(self._shutdown_result)
        self._shutdown_requested = True
        self._shutdown_result = self._engine.stop()
        return self._shutdown_result


@dataclass(frozen=True, slots=True)
class ApplicationShell:
    """Objects composing one desktop application run."""

    application: QApplication
    window: MainWindow
    lifecycle: ApplicationLifecycle


def create_application(
    engine: EngineLifecycle,
    argv: Sequence[str] | None = None,
) -> ApplicationShell:
    """Create, but do not show or run, the NetSentinel desktop shell."""

    existing = QApplication.instance()
    if existing is None:
        application = QApplication(list(argv) if argv is not None else [])
    elif isinstance(existing, QApplication):
        application = existing
    else:  # pragma: no cover - defensive guard for unusual embedding hosts
        raise RuntimeError("an incompatible Qt core application already exists")

    application.setApplicationName("NetSentinel")
    application.setOrganizationName("NetSentinel")

    lifecycle = ApplicationLifecycle(engine)
    window = MainWindow(on_close=lifecycle.shutdown)
    application.aboutToQuit.connect(lifecycle.shutdown)
    return ApplicationShell(application, window, lifecycle)


def run_application(
    argv: Sequence[str] | None = None,
    *,
    engine: EngineLifecycle | None = None,
) -> int:
    """Compose dependencies, start monitoring, and enter the Qt event loop."""

    if engine is None:
        # Importing the composition root lazily keeps widget modules free from
        # infrastructure dependencies and keeps GUI tests lightweight.
        from netsentinel.bootstrap import create_monitoring_engine

        engine = create_monitoring_engine()

    shell = create_application(
        engine,
        argv=sys.argv if argv is None else argv,
    )
    shell.lifecycle.start()
    shell.window.show()
    try:
        return shell.application.exec()
    finally:
        # closeEvent and aboutToQuit also use this path. The lifecycle guard
        # ensures the engine receives one bounded stop request only.
        shell.lifecycle.shutdown()


def main() -> int:
    """Run the standalone presentation entry point."""

    return run_application()


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = (
    "ApplicationLifecycle",
    "ApplicationShell",
    "EngineLifecycle",
    "create_application",
    "run_application",
)

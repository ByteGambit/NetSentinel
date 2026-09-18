"""PyQt6 application startup and MonitoringEngine lifecycle integration."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import sys
from typing import Protocol

from PyQt6.QtWidgets import QApplication

from netsentinel.presentation.bridge import EngineEventSource, QtEngineBridge
from netsentinel.presentation.views.main_window import MainWindow


class EngineLifecycle(Protocol):
    """Narrow lifecycle surface required by the desktop shell."""

    def start(self) -> bool: ...

    def stop(self, timeout: float | None = None) -> bool: ...


class DesktopEngine(EngineLifecycle, EngineEventSource, Protocol):
    """Combined engine surface required by the composed desktop application."""


class ApplicationLifecycle:
    """Own bridge attachment and the engine's controlled lifecycle."""

    def __init__(self, engine: EngineLifecycle, bridge: QtEngineBridge) -> None:
        self._engine = engine
        self._bridge = bridge
        self._start_requested = False
        self._shutdown_requested = False
        self._shutdown_result: bool | None = None

    @property
    def shutdown_requested(self) -> bool:
        return self._shutdown_requested

    def start(self) -> bool:
        """Attach the bridge before starting the engine, at most once."""

        if self._start_requested:
            return False
        self._start_requested = True
        self._bridge.start()
        try:
            return self._engine.start()
        except BaseException:
            self._bridge.stop()
            raise

    def shutdown(self) -> bool:
        """Detach GUI delivery, then request one bounded engine stop."""

        if self._shutdown_requested:
            return bool(self._shutdown_result)
        self._shutdown_requested = True
        self._bridge.stop()
        self._shutdown_result = self._engine.stop()
        return self._shutdown_result


@dataclass(frozen=True, slots=True)
class ApplicationShell:
    """Objects composing one desktop application run."""

    application: QApplication
    window: MainWindow
    bridge: QtEngineBridge
    lifecycle: ApplicationLifecycle


def create_application(
    engine: DesktopEngine,
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

    bridge = QtEngineBridge(engine)
    lifecycle = ApplicationLifecycle(engine, bridge)
    window = MainWindow(on_close=lifecycle.shutdown)
    bridge.setParent(window)
    application.aboutToQuit.connect(lifecycle.shutdown)
    return ApplicationShell(application, window, bridge, lifecycle)


def run_application(
    argv: Sequence[str] | None = None,
    *,
    engine: DesktopEngine | None = None,
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
    "DesktopEngine",
    "EngineLifecycle",
    "create_application",
    "run_application",
)

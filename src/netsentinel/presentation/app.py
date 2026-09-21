"""PyQt6 application startup and MonitoringEngine lifecycle integration."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import sys
from typing import Protocol

from PyQt6.QtWidgets import QApplication

from netsentinel.application.services.statistics import StatisticsService
from netsentinel.presentation.bridge import EngineEventSource, QtEngineBridge
from netsentinel.presentation.history_query import (
    HistoryQueryCoordinator,
    HistoryServiceFactory,
)
from netsentinel.presentation.views.main_window import MainWindow


class EngineLifecycle(Protocol):
    """Narrow lifecycle surface required by the desktop shell."""

    def start(self) -> bool: ...

    def stop(self, timeout: float | None = None) -> bool: ...


class DesktopEngine(EngineLifecycle, EngineEventSource, Protocol):
    """Combined engine surface required by the composed desktop application."""


class ApplicationLifecycle:
    """Own bridge attachment and the engine's controlled lifecycle."""

    def __init__(
        self,
        engine: EngineLifecycle,
        bridge: QtEngineBridge,
        history_queries: HistoryQueryCoordinator | None = None,
    ) -> None:
        self._engine = engine
        self._bridge = bridge
        self._history_queries = history_queries
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
        if self._history_queries is not None:
            self._history_queries.start()
        self._bridge.start()
        try:
            return self._engine.start()
        except BaseException:
            self._bridge.stop()
            if self._history_queries is not None:
                self._history_queries.stop()
            raise

    def shutdown(self) -> bool:
        """Detach GUI delivery, then request one bounded engine stop."""

        if self._shutdown_requested:
            return bool(self._shutdown_result)
        self._shutdown_requested = True
        history_stopped = (
            True
            if self._history_queries is None
            else self._history_queries.stop()
        )
        self._bridge.stop()
        self._shutdown_result = self._engine.stop() and history_stopped
        return self._shutdown_result


@dataclass(frozen=True, slots=True)
class ApplicationShell:
    """Objects composing one desktop application run."""

    application: QApplication
    window: MainWindow
    bridge: QtEngineBridge
    lifecycle: ApplicationLifecycle
    history_queries: HistoryQueryCoordinator | None = None


def create_application(
    engine: DesktopEngine,
    argv: Sequence[str] | None = None,
    *,
    history_service_factory: HistoryServiceFactory | None = None,
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
    history_queries = (
        HistoryQueryCoordinator(history_service_factory)
        if history_service_factory is not None
        else None
    )
    lifecycle = ApplicationLifecycle(engine, bridge, history_queries)
    window = MainWindow(
        on_close=lifecycle.shutdown,
        statistics=StatisticsService(),
        history_queries=history_queries,
    )
    bridge.setParent(window)
    if history_queries is not None:
        history_queries.setParent(window)
    window.bind_engine_bridge(bridge)
    application.aboutToQuit.connect(lifecycle.shutdown)
    return ApplicationShell(application, window, bridge, lifecycle, history_queries)


def run_application(
    argv: Sequence[str] | None = None,
    *,
    engine: DesktopEngine | None = None,
) -> int:
    """Compose dependencies, start monitoring, and enter the Qt event loop."""

    if engine is None:
        # Importing the composition root lazily keeps widget modules free from
        # infrastructure dependencies and keeps GUI tests lightweight.
        from netsentinel.bootstrap import (
            create_desktop_engine,
            create_history_query_service_factory,
        )

        engine = create_desktop_engine()
        history_service_factory = create_history_query_service_factory()
    else:
        history_service_factory = None

    shell = create_application(
        engine,
        argv=sys.argv if argv is None else argv,
        history_service_factory=history_service_factory,
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

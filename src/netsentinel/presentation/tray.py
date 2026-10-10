"""NS-093 Qt tray boundary and presentation-only application coordination."""

from __future__ import annotations

from netsentinel.presentation.i18n.text import translate

from collections.abc import Callable
from typing import Protocol
from weakref import ref

from PyQt6.QtCore import QEvent, QObject, QTimer, Qt
from PyQt6.QtWidgets import QApplication, QMainWindow, QMenu, QSystemTrayIcon

from netsentinel.presentation.widgets.application_behavior import ApplicationBehaviorDialog
from netsentinel.shared.config import WindowCloseBehavior


class ShutdownLifecycle(Protocol):
    @property
    def shutdown_requested(self) -> bool: ...

    def shutdown(self) -> bool: ...


class TrayAdapter(Protocol):
    """Fake seam: no engine ownership, network, or native shell in tests."""

    def start(self, show: Callable[[], None], hide: Callable[[], None],
              quit_application: Callable[[], None]) -> bool: ...

    def available(self) -> bool: ...

    def cleanup(self) -> None: ...


class QtTrayAdapter:
    def __init__(self, application: QApplication, window: QMainWindow) -> None:
        self._application = application
        self._window_ref = ref(window)
        self.icon: QSystemTrayIcon | None = None
        self.menu: QMenu | None = None

    def available(self) -> bool:
        return QSystemTrayIcon.isSystemTrayAvailable()

    def start(self, show: Callable[[], None], hide: Callable[[], None],
              quit_application: Callable[[], None]) -> bool:
        if not self.available():
            return False
        if self.icon is not None:
            return self.icon.isVisible()
        icon = self._application.windowIcon()
        if icon.isNull():
            return False
        window = self._window_ref()
        if window is None:
            return False
        self.icon = QSystemTrayIcon(icon, window)
        self.icon.setToolTip(translate('Tray', 'NetSentinel'))
        self.menu = QMenu(window)
        for title, callback in ((translate('Tray', 'Show NetSentinel'), show), (translate('Tray', 'Hide NetSentinel'), hide),
                                (translate('Tray', 'Quit'), quit_application)):
            action = self.menu.addAction(title)
            assert action is not None
            action.triggered.connect(callback)
        self.icon.setContextMenu(self.menu)

        def activate(reason: QSystemTrayIcon.ActivationReason) -> None:
            if reason in (QSystemTrayIcon.ActivationReason.Trigger,
                          QSystemTrayIcon.ActivationReason.DoubleClick):
                show()

        self.icon.activated.connect(activate)
        self.icon.show()
        return self.icon.isVisible()

    def cleanup(self) -> None:
        if self.icon is not None:
            self.icon.hide()
            self.icon.setContextMenu(None)
            self.icon.deleteLater()
            self.icon = None
        if self.menu is not None:
            self.menu.close()
            self.menu.deleteLater()
            self.menu = None


class ApplicationController(QObject):
    """Keep visibility separate from the existing bounded shutdown owner."""

    def __init__(
        self, application: QApplication, window: QMainWindow, lifecycle: ShutdownLifecycle,
        adapter: TrayAdapter, behavior: WindowCloseBehavior,
        save_preference: Callable[[WindowCloseBehavior], None] | None = None,
    ) -> None:
        super().__init__(window)
        self.application = application
        self._window_ref = ref(window)
        self.lifecycle = lifecycle
        self.adapter = adapter
        self.behavior = behavior
        self._save_preference = save_preference
        self._quitting = False
        self._cleaned = False
        self.settings_dialog: ApplicationBehaviorDialog | None = None
        # Sanitized fixed session status; no exception text or subject metadata.
        self.tray_status = "unavailable"
        try:
            self.tray_available = adapter.start(self.show_window, self.hide_window, self.request_quit)
        except Exception:
            self.tray_available = False
            self.tray_status = "initialization_failed"
        if self.tray_available:
            self.tray_status = "available"
        else:
            self._cleanup_adapter()
        application.setQuitOnLastWindowClosed(not self.tray_available)
        application.installEventFilter(self)
        application.aboutToQuit.connect(self.shutdown)
        self._capability_timer = QTimer(self)
        self._capability_timer.setInterval(1000)
        self._capability_timer.timeout.connect(self.refresh_capability)
        if self.tray_available:
            self._capability_timer.start()

    @property
    def window(self) -> QMainWindow:
        window = self._window_ref()
        if window is None:
            raise RuntimeError("application window no longer exists")
        return window

    @property
    def quitting(self) -> bool:
        return self._quitting or self.lifecycle.shutdown_requested

    @property
    def effective_close_behavior(self) -> WindowCloseBehavior:
        return self.behavior if self.tray_available else WindowCloseBehavior.QUIT_APPLICATION

    def refresh_capability(self) -> None:
        if not self.tray_available or self.quitting:
            return
        try:
            available = self.adapter.available()
        except Exception:
            available = False
        if not available:
            self.tray_available = False
            self.tray_status = "unavailable"
            self._capability_timer.stop()
            self._cleanup_adapter()
            self.application.setQuitOnLastWindowClosed(True)
            # Shell loss while hidden must leave a route back to the app.
            if not self.window.isVisible():
                self.show_window()

    def show_window(self) -> None:
        if self.quitting:
            return
        self.window.setWindowState(self.window.windowState() & ~Qt.WindowState.WindowMinimized)
        self.window.show()
        self.window.raise_()
        self.window.activateWindow()

    def hide_window(self) -> None:
        self.refresh_capability()
        if self.quitting or not self.tray_available:
            return
        self.window.hide()

    def close_requested(self) -> bool:
        """False means ignore the close event: the window survives hidden."""
        self.refresh_capability()
        if self.quitting:
            self.shutdown()
            return True
        if self.effective_close_behavior is WindowCloseBehavior.HIDE_TO_TRAY:
            self.hide_window()
            return False
        self.shutdown()
        # Avoid recursive Qt close delivery while handling this closeEvent.
        # A composed/offscreen shell without an event loop has nothing to quit;
        # do not leave a stale Quit queued for a later application run.
        thread = self.application.thread()
        if thread is not None and thread.loopLevel() > 0:
            QTimer.singleShot(0, self.application.quit)
        return True

    def request_quit(self) -> None:
        if self._quitting:
            return
        self.shutdown()
        self.application.quit()

    def _cleanup_adapter(self) -> None:
        try:
            self.adapter.cleanup()
        except Exception:
            self.tray_status = "cleanup_failed"

    def shutdown(self) -> bool:
        self._quitting = True
        if not self._cleaned:
            self._cleaned = True
            self.application.removeEventFilter(self)
            self._capability_timer.stop()
            self._cleanup_adapter()
            if self.settings_dialog is not None:
                self.settings_dialog.reject()
        return self.lifecycle.shutdown()

    def eventFilter(self, watched: QObject | None, event: QEvent | None) -> bool:  # noqa: N802
        # QApplication.quit delivers Quit before closing top-level windows.
        # Mark it here so external/platform quit cannot turn into close-to-tray.
        if watched is getattr(self, "application", None) and event is not None and event.type() == QEvent.Type.Quit:
            self.shutdown()
        return False

    def show_settings(self) -> None:
        if self.quitting:
            return
        self.refresh_capability()
        if self.settings_dialog is None:
            self.settings_dialog = ApplicationBehaviorDialog(
                self.behavior, self.tray_available, self.save_behavior, self.window,
            )
            self.settings_dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            self.settings_dialog.finished.connect(self._settings_finished)
        self.settings_dialog.show()
        self.settings_dialog.raise_()

    def _settings_finished(self, _result: int) -> None:
        self.settings_dialog = None

    def save_behavior(self, behavior: WindowCloseBehavior) -> None:
        if not isinstance(behavior, WindowCloseBehavior):
            raise ValueError("invalid window close behavior")
        if self.quitting:
            raise ValueError("application quitting")
        if self._save_preference is not None:
            self._save_preference(behavior)
        self.behavior = behavior

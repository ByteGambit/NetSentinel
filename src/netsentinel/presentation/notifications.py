"""NS-094 Qt sink and bounded timer handoff. No worker accesses Qt objects."""

from collections.abc import Callable
from time import monotonic
from uuid import UUID
from weakref import ref

from PyQt6.QtCore import QObject, QThread, QTimer
from PyQt6.QtWidgets import QApplication, QMainWindow, QSystemTrayIcon

from netsentinel.application.events import EventDispatcher
from netsentinel.application.services.notifications import (
    DesktopNotificationRequest, DesktopNotificationSink, NotificationDeliveryOutcome,
    NotificationDeliveryService, PersistedNotificationIntent,
    NotificationPlatformState,
)
from netsentinel.infrastructure.windows_notification_policy import windows_notification_policy
from netsentinel.domain.risk_scoring import RiskSeverity
from netsentinel.presentation.tray import ApplicationController
from netsentinel.presentation.views.alerts import AlertsView
from netsentinel.presentation.views.main_window import MainWindow, PageId
from netsentinel.presentation.views.diagnostics import DiagnosticsView
from netsentinel.presentation.widgets.notification_settings import NotificationSettingsDialog
from PyQt6.QtCore import Qt


class QtDesktopNotificationSink(QObject):
    """One immutable target per Qt message source; never reuse a source for B.

    Qt's messageClicked has no message token. A bounded set of temporary tray
    icons provides separate signal sources. At capacity reject; never redirect
    an old click to the newest alert. Handles expire after ten minutes.
    """

    CAPACITY = 8
    CLICK_LIFETIME = 600.0

    def __init__(self, application: QApplication, window: QMainWindow, *,
                 policy_query: Callable[[], NotificationPlatformState] | None = None) -> None:
        super().__init__(window)
        self._application = application
        self._handler: Callable[[UUID], None] | None = None
        self._closed = False
        self._handles: dict[QSystemTrayIcon, tuple[UUID, float]] = {}
        self._policy_query = policy_query or (windows_notification_policy if application.platformName() == "windows"
            else lambda: NotificationPlatformState.DELIVERY_UNKNOWN)
        self.submission_attempts = 0
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._expire)

    def set_click_handler(self, handler: Callable[[UUID], None]) -> None:
        self._handler = handler

    def policy_state(self) -> NotificationPlatformState:
        if QThread.currentThread() != self.thread():
            raise RuntimeError("notification policy query requires Qt thread")
        if self._closed or not QSystemTrayIcon.isSystemTrayAvailable() or not QSystemTrayIcon.supportsMessages():
            return NotificationPlatformState.UNAVAILABLE
        try:
            state = self._policy_query()
            return state if isinstance(state, NotificationPlatformState) else NotificationPlatformState.DELIVERY_UNKNOWN
        except Exception:
            return NotificationPlatformState.DELIVERY_UNKNOWN

    def submit(self, request: DesktopNotificationRequest) -> NotificationDeliveryOutcome:
        if QThread.currentThread() != self.thread():
            raise RuntimeError("notification sink requires Qt thread")
        state = self.policy_state()
        if state in (NotificationPlatformState.DISABLED_BY_OS, NotificationPlatformState.SESSION_RESTRICTED):
            return NotificationDeliveryOutcome.PLATFORM_RESTRICTED
        if state is NotificationPlatformState.UNAVAILABLE:
            return NotificationDeliveryOutcome.SINK_UNAVAILABLE
        self._expire()
        if len(self._handles) >= self.CAPACITY:
            return NotificationDeliveryOutcome.SINK_UNAVAILABLE
        icon = QSystemTrayIcon(self._application.windowIcon(), self)
        try:
            icon.setToolTip("NetSentinel notification")
            icon.messageClicked.connect(lambda: self._click(icon))
            self._handles[icon] = request.alert_id, monotonic() + self.CLICK_LIFETIME
            icon.show()
            message_icon = (QSystemTrayIcon.MessageIcon.Critical if request.severity is RiskSeverity.HIGH
                            else QSystemTrayIcon.MessageIcon.Warning)
            self.submission_attempts += 1
            icon.showMessage(request.title, request.body, message_icon, 10000)
            self._timer.start()
            return NotificationDeliveryOutcome.SUBMITTED_TO_SINK
        except Exception:
            self._remove(icon)
            return NotificationDeliveryOutcome.SINK_FAILED

    def _click(self, icon: QSystemTrayIcon) -> None:
        handle = self._handles.get(icon)
        if self._closed or handle is None or monotonic() >= handle[1]:
            return
        if self._handler is not None:
            self._handler(handle[0])

    def _remove(self, icon: QSystemTrayIcon) -> None:
        self._handles.pop(icon, None)
        try:
            icon.messageClicked.disconnect()
            icon.hide()
            icon.deleteLater()
        except RuntimeError:
            pass

    def _expire(self) -> None:
        now = monotonic()
        for icon, (_, expiry) in tuple(self._handles.items()):
            if now >= expiry:
                self._remove(icon)
        if not self._handles:
            self._timer.stop()

    def close(self) -> None:
        self._closed = True
        self._handler = None
        self._timer.stop()
        for icon in tuple(self._handles):
            self._remove(icon)


class DesktopNotificationController(QObject):
    def __init__(self, dispatcher: EventDispatcher, sink: DesktopNotificationSink,
                 controller: ApplicationController, window: MainWindow, *, enabled: bool,
                 save_preference: Callable[[bool], None] | None = None) -> None:
        super().__init__(window)
        self._dispatcher, self._controller, self._window_ref = dispatcher, controller, ref(window)
        self.service = NotificationDeliveryService(sink, enabled=enabled)
        self._subscription = dispatcher.subscribe(PersistedNotificationIntent, self._accept)
        self._closed = False
        self._save_preference = save_preference
        self.settings_dialog: NotificationSettingsDialog | None = None
        assert window.notification_settings_action is not None
        window.notification_settings_action.setEnabled(True)
        window.notification_settings_action.triggered.connect(self.show_settings)
        sink.set_click_handler(self._click)
        alerts = window.page_widget(PageId.ALERTS)
        assert isinstance(alerts, AlertsView)
        alerts.notification_navigation_finished.connect(self._navigation_finished)
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self.drain)
        self._timer.start()
        self._refresh_diagnostics()

    def _accept(self, intent: PersistedNotificationIntent) -> None:
        self.service.enqueue(intent)

    def drain(self) -> None:
        if self._closed or self._controller.quitting:
            return
        self.service.drain_one()
        self.service.refresh_policy()
        self._refresh_diagnostics()

    def _refresh_diagnostics(self) -> None:
        window = self._window_ref()
        if window is not None:
            diagnostics = window.page_widget(PageId.DIAGNOSTICS)
            assert isinstance(diagnostics, DiagnosticsView)
            diagnostics.set_notification_diagnostics(self.service.diagnostics(), enabled=self.service.enabled)
        if self.settings_dialog is not None:
            self.settings_dialog.refresh_delivery_state()

    def _click(self, alert_id: UUID) -> None:
        if self._closed or self._controller.quitting:
            return
        self.service.count("clicks")
        window = self._window_ref()
        if window is None:
            return
        self._controller.show_window()
        window.navigate_to(PageId.ALERTS)
        alerts = window.page_widget(PageId.ALERTS)
        assert isinstance(alerts, AlertsView)
        alerts.open_notification_alert(alert_id)

    def _navigation_finished(self, success: bool) -> None:
        if not self._closed:
            self.service.count("navigation_success" if success else "navigation_failure")
            self._refresh_diagnostics()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._timer.stop()
        if self.settings_dialog is not None:
            self.settings_dialog.reject()
        self._dispatcher.unsubscribe(self._subscription)
        self.service.close()

    def show_settings(self) -> None:
        if self._closed or self._controller.quitting:
            return
        if self.settings_dialog is None:
            window = self._window_ref()
            if window is None:
                return
            self.settings_dialog = NotificationSettingsDialog(self.service.enabled, self.save_enabled, window,
                policy_state=self.service.refresh_policy,
                submission_outcome=lambda: self.service.diagnostics().last_submission_outcome)
            self.settings_dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            self.settings_dialog.finished.connect(self._settings_finished)
        self.settings_dialog.show()
        self.settings_dialog.raise_()

    def _settings_finished(self, _result: int) -> None:
        self.settings_dialog = None

    def save_enabled(self, enabled: bool) -> None:
        if self._closed or self._controller.quitting:
            raise ValueError("application quitting")
        if self._save_preference is not None:
            self._save_preference(enabled)
        self.service.set_enabled(enabled)
        self.service.refresh_policy()
        self._refresh_diagnostics()

"""Isolated native fixture: exact final production PYZ, no live telemetry/DB edits."""
import json
import sys
from pathlib import Path
from datetime import UTC, datetime
from dataclasses import asdict
from hashlib import sha256
from PyQt6.QtCore import QTimer
from netsentinel.application.events import EventDispatcher
from netsentinel.application.services.alerts import AlertService
from netsentinel.application.services.alert_query import AlertQueryService
from netsentinel.application.services.notifications import PersistedNotificationIntent
from netsentinel.domain.alerts import Alert, AlertCandidate, AlertEvidence
from netsentinel.infrastructure.sqlite.alert_repository import SQLiteAlertRepository
from netsentinel.infrastructure.sqlite.database import SQLiteDatabase
from netsentinel.presentation.app import create_application
from netsentinel.presentation.views.main_window import PageId
from netsentinel.presentation.views.alerts import AlertsView
from netsentinel.shared.config import AppConfig, load_config_file, save_config_file
from netsentinel.shared.diagnostics import CapabilitySnapshot, CapabilityStatus, EngineCounters, EngineHealthSnapshot, EngineState


class FixtureEngine:
    def __init__(self) -> None:
        self.dispatcher = EventDispatcher()
        self.running = False

    def start(self) -> bool:
        self.running = True
        return True

    def stop(self, timeout: float | None = None) -> bool:
        self.running = False
        return True

    def health_snapshot(self) -> EngineHealthSnapshot:
        return EngineHealthSnapshot(state=EngineState.RUNNING if self.running else EngineState.STOPPED,
            capabilities=CapabilitySnapshot(connection_monitoring=CapabilityStatus.UNAVAILABLE,
                                            process_metadata=CapabilityStatus.UNAVAILABLE),
            counters=EngineCounters(), worker_alive=self.running)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: native probe <isolated NS099Toast directory>")
    root = Path(sys.argv[1])
    if root.name != "NS099Toast":
        raise SystemExit("Only the isolated NS099Toast fixture directory is allowed")
    root.mkdir(parents=True, exist_ok=True)
    cfg = root / "config.json"
    if not cfg.exists():
        save_config_file(cfg, AppConfig())
    engine = FixtureEngine()
    db = SQLiteDatabase(root / "synthetic.sqlite3")
    repo = SQLiteAlertRepository(db)
    alerts = AlertService(repo, dispatcher=engine.dispatcher)
    shell = create_application(engine, argv=[], config=load_config_file(cfg).config, config_path=cfg,
        alert_service_factory=lambda: AlertQueryService(AlertService(SQLiteAlertRepository(db))))
    shell.window.setWindowTitle("NetSentinel — synthetic notification acceptance")
    shell.lifecycle.start()
    shell.window.show()
    generated = 0
    target: Alert | None = None
    last_action = "startup-no-replay"
    history: list[dict[str, object]] = []


    def report() -> None:
        assert shell.notifications is not None
        view = shell.window.page_widget(PageId.ALERTS)
        assert isinstance(view, AlertsView)
        result = {"fixture": "isolated native production components; same candidate PYZ",
            "source_commit": "ae08d7ef1205f5bd4f0b9b0397075c1f6176f2c4",
            "generated_this_process": generated, "enabled": shell.notifications.service.enabled,
            "diagnostics": asdict(shell.notifications.service.diagnostics()),
            "selected_alert": str(view.selected_alert_id) if view.selected_alert_id else None,
            "target_alert": str(target.id) if target else None,
            "last_action": last_action, "action_history": history,
            "policy_note": "submitted_to_sink is not OS-delivered; OS observation recorded separately"}
        (root / "result.json").write_text(json.dumps(result), encoding="utf-8")


    def poll() -> None:
        nonlocal generated, target, last_action
        assert shell.notifications is not None and shell.controller is not None
        command = root / "command.json"
        if command.exists():
            action = json.loads(command.read_text(encoding="utf-8-sig"))["action"]
            command.unlink()
            last_action = action
            if action in ("off", "on", "policy"):
                if action == "on":
                    shell.notifications.save_enabled(True)
                now = datetime.now(UTC)
                c = AlertCandidate(sha256(action.encode()).hexdigest(), "ip_mac_conflict", "a" * 64,
                    "synthetic-private-user", "low", "low", AlertEvidence(now, "192.0.2.123",
                    details=(("path", "C:/synthetic/private/tool.exe"), ("domain", "synthetic.private.example"))))
                target, eligible = alerts.record(c)
                generated += int(eligible)
                shell.notifications.drain()
            elif action == "duplicate" and target:
                for _ in range(3):
                    shell.notifications.service.enqueue(PersistedNotificationIntent.from_alert(target, None, eligible=True))
                    generated += 1
                    shell.notifications.drain()
            elif action == "disable":
                shell.notifications.save_enabled(False)
            elif action == "quit":
                report()
                shell.controller.request_quit()
                return
            history.append({"action": action, "diagnostics": asdict(shell.notifications.service.diagnostics())})
        report()


    timer = QTimer()
    timer.setInterval(200)
    timer.timeout.connect(poll)
    timer.start()
    report()
    return shell.application.exec()


if __name__ == "__main__":
    raise SystemExit(main())

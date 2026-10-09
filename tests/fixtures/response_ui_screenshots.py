"""Deterministic synthetic NS-103 offscreen layout evidence; no native backend."""

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QWidget  # noqa: E402
from PyQt6.QtGui import QFont, QFontDatabase  # noqa: E402
from netsentinel.application.services.response_ui import (  # noqa: E402
    ResponseHistory, ResponseHistoryRow, ResponsePreview, WARNINGS, target_text, result_text,
)
from netsentinel.domain.response import ResponseOutcome, ResponseReason, ResponseResult  # noqa: E402
from netsentinel.presentation.widgets.manual_response import (  # noqa: E402
    ManualResponseWidget, ResponseConfirmationDialog,
)
from tests.fixtures.response_ui import selection  # noqa: E402
from tests.unit.domain.test_response import command  # noqa: E402


def render(output: Path) -> None:
    app = QApplication.instance() or QApplication([])
    # Renderer-only font catalog, following the NS-098 sandbox fixture.
    QFontDatabase.addApplicationFont("C:/Windows/Fonts/segoeui.ttf")
    app.setFont(QFont("Segoe UI", 10))
    output.mkdir(parents=True, exist_ok=True)
    c = command()
    preview = ResponsePreview(c, target_text(c) + "Preview UTC: 2026-10-08T12:00:00+00:00 (five-minute confirmation deadline)\n"
        + WARNINGS + "\nPermission: action-time validation required; no automatic elevation.")
    parent = QWidget()
    dialog = ResponseConfirmationDialog(preview, parent)
    dialog.show()
    app.processEvents()
    assert dialog.grab().save(str(output / "ns103-preview-synthetic.png"))
    dialog.close()
    widget = ManualResponseWidget()
    widget.resize(860, 1250)
    widget.select(selection())
    row = ResponseHistoryRow(c.command_id, c.rule_id, target_text(c) +
        "Requested UTC: 2026-10-08T12:00:00+00:00\nLifecycle: verified; current reconciliation: exact\n"
        "Historical SUCCESS: rule created and read back; traffic effect not measured.\n"
        "Fresh unique full equality is required for Undo.", True)
    widget._history = ResponseHistory((row,), ("1 | 2026-10-08T12:00:00+00:00 | create | verified_success | exact",))
    widget.records.addItem(f"{row.operation_id} — rule {row.rule_id}")
    widget.records.setCurrentRow(0)
    widget.undo.setEnabled(True)  # synthetic finalized read projection
    widget.audit.setPlainText("\n".join(widget._history.audit))
    widget.status.setText("Synthetic owned rule: last recorded state exact. Undo requires fresh equality and permission.")
    widget.show()
    app.processEvents()
    assert widget.grab().save(str(output / "ns103-owned-synthetic.png"))
    result = ResponseResult(c.command_id, c.action, ResponseOutcome.PARTIAL, ResponseReason.OS_DB_DISAGREEMENT)
    widget.status.setText(result_text(result))
    widget.undo.setEnabled(False)
    widget.record_text.setPlainText(target_text(c) + "Lifecycle: partial; ownership not finalized.\n" + result_text(result))
    widget.audit.setPlainText("1 | 2026-10-08T12:00:00+00:00 | create | prepared\n"
        "2 | 2026-10-08T12:00:00+00:00 | create | attempt\n"
        "3 | 2026-10-08T12:00:00+00:00 | create | unknown_partial | partial | pending_create")
    app.processEvents()
    assert widget.grab().save(str(output / "ns103-partial-synthetic.png"))
    widget.close()
    parent.close()


if __name__ == "__main__":
    render(Path("docs/images"))

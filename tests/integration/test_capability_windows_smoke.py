"""NS-048 opt-in read-only smoke for both standard and elevated Windows runs."""

from __future__ import annotations

import sys

import pytest

from netsentinel.bootstrap import (
    create_capability_service_factory, create_monitoring_engine,
)


@pytest.mark.windows_live
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only capability smoke")
def test_read_only_capability_check_in_current_privilege_context(tmp_path):
    engine = create_monitoring_engine()
    service = create_capability_service_factory(
        engine, database_path=tmp_path / "capability.sqlite3",
    )()
    matrix = service.check()
    assert matrix.is_elevated in (True, False)
    assert {feature.name for feature in matrix.features} == {
        "Connections", "Process details", "History", "Packet capture",
        "Devices", "DNS", "Alerts",
    }
    assert not engine.health_snapshot().worker_alive
    assert matrix.diagnostics.capture is not None
    assert not matrix.diagnostics.capture.worker_alive

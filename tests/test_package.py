"""Smoke tests for the initial package scaffold."""

from __future__ import annotations

from pytest import CaptureFixture
from pytest import MonkeyPatch

import netsentinel
from netsentinel.__main__ import main


def test_package_is_importable() -> None:
    assert netsentinel.__name__ == "netsentinel"


def test_entry_point_displays_help(capsys: CaptureFixture[str]) -> None:
    exit_code = main([])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "usage: netsentinel" in captured.out


def test_entry_point_can_delegate_to_gui_without_changing_help_smoke(
    monkeypatch: MonkeyPatch,
) -> None:
    from netsentinel.presentation import app

    received: list[object] = []

    def fake_run_application(argv: object) -> int:
        received.append(argv)
        return 23

    monkeypatch.setattr(app, "run_application", fake_run_application)

    assert main(["--gui"]) == 23
    assert received == [[]]

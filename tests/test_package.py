"""Smoke tests for the initial package scaffold."""

from __future__ import annotations

from pytest import CaptureFixture

import netsentinel
from netsentinel.__main__ import main


def test_package_is_importable() -> None:
    assert netsentinel.__name__ == "netsentinel"


def test_entry_point_displays_help(capsys: CaptureFixture[str]) -> None:
    exit_code = main([])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "usage: netsentinel" in captured.out

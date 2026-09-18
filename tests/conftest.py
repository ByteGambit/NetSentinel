"""Shared pytest configuration for NetSentinel tests."""

from __future__ import annotations

import os


# Keep Qt tests deterministic and independent of a physical display. Respect an
# explicit platform selected by a developer or CI environment.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

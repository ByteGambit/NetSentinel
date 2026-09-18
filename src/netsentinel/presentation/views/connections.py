"""Connections placeholder for the NS-008 application shell."""

from __future__ import annotations

from PyQt6.QtWidgets import QWidget

from netsentinel.presentation.views.placeholder import PlaceholderPage


class ConnectionsView(PlaceholderPage):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(
            title="Connections",
            description=(
                "Live connection data, filtering, and details will be added in "
                "NS-010 and NS-011."
            ),
            parent=parent,
        )


__all__ = ("ConnectionsView",)

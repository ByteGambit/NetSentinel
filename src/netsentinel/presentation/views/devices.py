"""Devices placeholder for the NS-008 application shell."""

from __future__ import annotations

from PyQt6.QtWidgets import QWidget

from netsentinel.presentation.views.placeholder import PlaceholderPage


class DevicesView(PlaceholderPage):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(
            title="Devices",
            description=(
                "Local network device visibility is planned for a future "
                "milestone."
            ),
            parent=parent,
        )


__all__ = ("DevicesView",)

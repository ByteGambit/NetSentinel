"""Dashboard placeholder for the NS-008 application shell."""

from __future__ import annotations

from PyQt6.QtWidgets import QWidget

from netsentinel.presentation.views.placeholder import PlaceholderPage


class DashboardView(PlaceholderPage):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(
            title="Dashboard",
            description=(
                "Connection activity and monitoring health summaries will be "
                "available in NS-012."
            ),
            parent=parent,
        )


__all__ = ("DashboardView",)

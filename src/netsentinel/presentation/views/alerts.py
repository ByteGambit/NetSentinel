"""Alerts placeholder for the NS-008 application shell."""

from __future__ import annotations

from PyQt6.QtWidgets import QWidget

from netsentinel.presentation.views.placeholder import PlaceholderPage


class AlertsView(PlaceholderPage):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(
            title="Alerts",
            description=(
                "Explainable security alerts and supporting evidence are "
                "planned for a future milestone."
            ),
            parent=parent,
        )


__all__ = ("AlertsView",)

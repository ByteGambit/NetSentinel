"""Shared layout for NS-008 placeholder pages."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget


class PlaceholderPage(QWidget):
    """Present a page heading and an honest description of planned work."""

    def __init__(
        self,
        *,
        title: str,
        description: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName(f"{title.lower()}Page")

        title_label = QLabel(title, self)
        title_label.setObjectName("pageTitle")
        title_label.setStyleSheet("font-size: 24px; font-weight: 600;")

        description_label = QLabel(description, self)
        description_label.setObjectName("pageDescription")
        description_label.setWordWrap(True)
        description_label.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
        )
        description_label.setStyleSheet("color: #52606d; font-size: 14px;")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(12)
        layout.addWidget(title_label)
        layout.addWidget(description_label)
        layout.addStretch(1)


__all__ = ("PlaceholderPage",)

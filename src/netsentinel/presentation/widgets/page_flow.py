"""Natural-height monitoring details and a row-sized table in one page flow."""

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QResizeEvent
from PyQt6.QtWidgets import (
    QFrame, QHeaderView, QLayout, QScrollArea, QSizePolicy, QTableView,
    QTabWidget, QTextEdit, QVBoxLayout, QWidget,
)


class EndpointTableView(QTableView):
    """Keep endpoints readable, sharing spare width without stretching short fields."""

    def configure_columns(self, widths: tuple[int, ...], compact: tuple[int, ...]) -> None:
        header = self.horizontalHeader()
        assert header is not None
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for column, characters in enumerate(widths):
            self.setColumnWidth(column, self.fontMetrics().averageCharWidth() * characters)
        for column in compact:
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)

    def resizeEvent(self, event: QResizeEvent | None) -> None:
        super().resizeEvent(event)
        # IPv4 plus port remains fully visible; IPv6 can use horizontal scrolling.
        endpoint_width = self.fontMetrics().horizontalAdvance("255.255.255.255:65535") + 24
        header = self.horizontalHeader()
        viewport = self.viewport()
        assert header is not None and viewport is not None
        other_width = sum(header.sectionSize(i) for i in range(header.count()) if i not in (3, 4))
        width = max(endpoint_width, (viewport.width() - other_width) // 2)
        for column in (3, 4):
            self.setColumnWidth(column, width)


class MonitoringPageScroll(QScrollArea):
    """One page scrollbar; table row scrolling remains local to its viewport."""

    def __init__(self, table: QTableView, parent: QWidget) -> None:
        super().__init__(parent)
        self.table = table
        self.setObjectName("monitoringPageScroll")
        self.setAccessibleName(parent.accessibleName() + " page content")
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content = QWidget(self)
        self.page_layout = QVBoxLayout(content)
        self.page_layout.setContentsMargins(28, 24, 28, 24)
        self.page_layout.setSpacing(10)
        self.page_layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)
        self.setWidget(content)
        outer = QVBoxLayout(parent)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self)

    def resizeEvent(self, event: QResizeEvent | None) -> None:
        super().resizeEvent(event)
        vertical_header = self.table.verticalHeader()
        horizontal_header = self.table.horizontalHeader()
        horizontal_scroll = self.table.horizontalScrollBar()
        viewport = self.viewport()
        assert vertical_header is not None and horizontal_header is not None
        assert horizontal_scroll is not None and viewport is not None
        row_height = max(28, self.table.fontMetrics().height() + 10)
        vertical_header.setDefaultSectionSize(row_height)
        rows = max(6, min(10, int(viewport.height() * 0.35) // row_height))
        chrome = horizontal_header.sizeHint().height() + 2 * self.table.frameWidth()
        chrome += horizontal_scroll.sizeHint().height()
        self.table.setFixedHeight(rows * row_height + chrome)


class FlowTabWidget(QTabWidget):
    """Size the active detail tab to its content, including wrapped text."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        policy = QSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        policy.setHeightForWidth(True)
        self.setSizePolicy(policy)
        self.currentChanged.connect(lambda _: self.updateGeometry())

    def heightForWidth(self, width: int) -> int:
        widget = self.currentWidget()
        height = 0
        if widget is not None:
            layout = widget.layout()
            inner_width = max(1, width - 8)
            height = (layout.totalHeightForWidth(inner_width) if layout is not None and layout.hasHeightForWidth()
                      else widget.sizeHint().height())
        tab_bar = self.tabBar()
        assert tab_bar is not None
        return max(0, height) + tab_bar.sizeHint().height() + 8

    def sizeHint(self) -> QSize:
        return QSize(super().sizeHint().width(), self.heightForWidth(max(1, self.width())))

    def minimumSizeHint(self) -> QSize:
        widget = self.currentWidget()
        height = widget.minimumSizeHint().height() if widget is not None else 0
        tab_bar = self.tabBar()
        assert tab_bar is not None
        return QSize(0, max(0, height) + tab_bar.sizeHint().height() + 8)


class FlowTextEdit(QTextEdit):
    """Read-only plain text whose full document participates in the page height."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        document = self.document()
        assert document is not None
        document_layout = document.documentLayout()
        assert document_layout is not None
        document_layout.documentSizeChanged.connect(self._fit_document)
        self._fit_document()

    def _fit_document(self) -> None:
        document = self.document()
        assert document is not None
        height = int(document.size().height()) + 2 * self.frameWidth() + 4
        self.setFixedHeight(max(self.fontMetrics().height() + 12, height))

    def resizeEvent(self, event: QResizeEvent | None) -> None:
        super().resizeEvent(event)
        self._fit_document()

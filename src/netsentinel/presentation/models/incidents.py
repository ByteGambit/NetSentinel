"""NS-091 bounded tables with textual, accessible timeline semantics."""

from typing import Generic, TypeVar

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt

from netsentinel.application.services.incident_timeline import TimelineEntry, TimelineKind, SOURCE_TEXT, MAX_LOADED_ROWS
from netsentinel.domain.incident_persistence import IncidentResult
from netsentinel.presentation.models.history import format_local_timestamp


T = TypeVar("T")


class TextTableModel(QAbstractTableModel, Generic[T]):
    HEADERS: tuple[str, ...] = ()
    MAXIMUM = 100

    def __init__(self, parent=None):
        super().__init__(parent)
        self.entries: tuple[T, ...] = ()

    def set_entries(self, entries):
        if len(entries) > self.MAXIMUM:
            raise ValueError("incident list display exceeds bound")
        self.beginResetModel()
        self.entries = tuple(entries)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.entries)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.HEADERS)

    def values(self, row) -> tuple[str, ...]:
        raise NotImplementedError

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < self.rowCount() or not 0 <= index.column() < self.columnCount():
            return None
        values = self.values(index.row())
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.AccessibleTextRole):
            return values[index.column()]
        if role in (Qt.ItemDataRole.ToolTipRole, Qt.ItemDataRole.AccessibleDescriptionRole):
            return "; ".join(values)
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole and 0 <= section < len(self.HEADERS):
            return self.HEADERS[section]
        return None


class IncidentTableModel(TextTableModel[IncidentResult]):
    HEADERS = ("Incident ID", "State", "First observed (local)", "Last observed (local)", "Incident revision", "References / limitations")

    def values(self, row):
        entry = self.entries[row]
        r = entry.record
        if r is None:
            return ("Unavailable incident", entry.status.value, "Unknown", "Unknown", "Unknown", "Stored incident could not be read.")
        s = r.snapshot
        counts = f"{len(s.relations)} observations; {len(s.evidence)} evidence; {len(s.assessments)} assessments; {len(s.limitations)} limitations"
        return (str(r.incident_id), r.state.value, format_local_timestamp(s.first_observed_at),
                format_local_timestamp(s.last_observed_at), str(r.revision), counts)

class TimelineTableModel(TextTableModel[TimelineEntry]):
    HEADERS = ("Time (local)", "Kind", "Title", "Explanation", "Current source state")

    MAXIMUM = MAX_LOADED_ROWS

    def values(self, row):
        e = self.entries[row]
        time = format_local_timestamp(e.primary_time)
        if e.kind is TimelineKind.ASSESSMENT and e.assessment_time is None:
            time = "Assessment time unknown; ordering anchor: " + time
        elif e.kind is TimelineKind.INFERENCE:
            time = "Observation anchor: " + time
        return (time + " — " + e.time_semantics,
                e.kind.value, e.title, e.explanation, SOURCE_TEXT[e.source_status])

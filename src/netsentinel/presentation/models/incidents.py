"""NS-091 bounded tables with textual, accessible timeline semantics."""

from netsentinel.presentation.i18n.text import TranslationSequence

from netsentinel.presentation.i18n.text import display_enum, format_text, render_join

from netsentinel.presentation.i18n.text import translate

from typing import Generic, TypeVar
from netsentinel.presentation.i18n.text import render_text

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
            return render_text(values[index.column()])
        if role in (Qt.ItemDataRole.ToolTipRole, Qt.ItemDataRole.AccessibleDescriptionRole):
            return render_join('; ', values)
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole and 0 <= section < len(self.HEADERS):
            return self.HEADERS[section]
        return None


class IncidentTableModel(TextTableModel[IncidentResult]):
    HEADERS = TranslationSequence(lambda: (translate('IncidentsModel', 'Incident ID'), translate('IncidentsModel', 'State'), translate('IncidentsModel', 'First observed (local)'), translate('IncidentsModel', 'Last observed (local)'), translate('IncidentsModel', 'Incident revision'), translate('IncidentsModel', 'References / limitations')))

    def values(self, row):
        entry = self.entries[row]
        r = entry.record
        if r is None:
            return (translate('IncidentsModel', 'Unavailable incident'), display_enum(entry.status), translate('IncidentsModel', 'Unknown'), translate('IncidentsModel', 'Unknown'), translate('IncidentsModel', 'Unknown'), translate('IncidentsModel', 'Stored incident could not be read.'))
        s = r.snapshot
        counts = format_text(translate('IncidentsModel', '{value1} observations; {value2} evidence; {value3} assessments; {value4} limitations'), value1=len(s.relations), value2=len(s.evidence), value3=len(s.assessments), value4=len(s.limitations))
        return (str(r.incident_id), display_enum(r.state), format_local_timestamp(s.first_observed_at),
                format_local_timestamp(s.last_observed_at), str(r.revision), counts)

class TimelineTableModel(TextTableModel[TimelineEntry]):
    HEADERS = TranslationSequence(lambda: (translate('IncidentsModel', 'Time (local)'), translate('IncidentsModel', 'Kind'), translate('IncidentsModel', 'Title'), translate('IncidentsModel', 'Explanation'), translate('IncidentsModel', 'Current source state')))

    MAXIMUM = MAX_LOADED_ROWS

    def values(self, row):
        e = self.entries[row]
        time = format_local_timestamp(e.primary_time)
        if e.kind is TimelineKind.ASSESSMENT and e.assessment_time is None:
            time = translate('IncidentsModel', 'Assessment time unknown; ordering anchor: ') + time
        elif e.kind is TimelineKind.INFERENCE:
            time = translate('IncidentsModel', 'Observation anchor: ') + time
        return (format_text(translate('IncidentsModel', '{time} — {semantics}'), time=time, semantics=e.time_semantics),
                display_enum(e.kind), e.title, e.explanation, SOURCE_TEXT[e.source_status])

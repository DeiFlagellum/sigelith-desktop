"""
Model tabeli historii (Qt Model/View) z filtrowaniem i sortowaniem.

Poprzednik nie pokazywal historii w ogole — istniala wyłącznie jako plik JSON
i przycisk "Eksportuj do CSV". Żeby sprawdzić, czy cos już bylo stemplowane,
trzeba bylo otworzyć plik w edytorze.

Model/View zamiast recznego wypelniania `QTableWidget` jest tu wyborem
wydajnosciowym: przy kilku tysiacach wpisów Qt rysuje tylko widoczne wiersze,
a filtrowanie i sortowanie idzie przez `QSortFilterProxyModel` bez
przebudowywania tabeli.
"""
from __future__ import annotations

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
)
from PySide6.QtGui import QColor, QFont

from .. import beatcore
from ..history import SOURCE_TVS_LEGACY, Entry
from ..hashing import human_size
from ..i18n import _
from ..proof import Level
from . import theme
from .widgets import plain_tooltip

COL_WHEN, COL_BEAT, COL_FILE, COL_DIGEST, COL_LEVEL, COL_ANCHOR, COL_NOTE = range(7)

#: Liczba kolumn. Sama lista naglowkow jest FUNKCJA (`headers`): policzona
#: w czasie importu zamrozilaby jezyk na tym sprzed wczytania ustawien.
COLUMN_COUNT = 7


def headers() -> list[tuple[str, str]]:
    """(naglowek, podpowiedz) dla kazdej kolumny — w jezyku interfejsu."""
    return [
        (_('Local time'), _('When the stamp was created, in your time zone')),
        ('@beat', _('The same moment in @beat time — without time zones')),
        (_('File'), _('Document name. It was never sent to the server')),
        ('SHA-256', _('Document digest — the only information that reached the '
                      'register')),
        (_('Level'), _('How far the proof has matured: recorded -> signed -> '
                       'anchored')),
        (_('Anchor'), _('Where the week root was preserved outside BeatTime')),
        (_('Note'), _('Your own description. It stays on this computer')),
    ]

# Rola koloru, nie konkretna barwa — wartosc bierzemy z motywu przy kazdym
# rysowaniu, zeby ciemny motyw dostal swoja (jasniejsza) zielen i zolc.
_LEVEL_ROLE = {
    Level.ANCHORED.value: 'ok',
    Level.SIGNED.value: 'ok',
    Level.RECORDED.value: 'warn',
}


class HistoryModel(QAbstractTableModel):
    """Wpisy historii jako tabela. Najnowsze na gorze."""

    def __init__(self, entries: list[Entry] | None = None, parent=None):
        super().__init__(parent)
        self._entries: list[Entry] = list(reversed(entries or []))

    # --- Kontrakt modelu ---

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._entries)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else COLUMN_COUNT

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation != Qt.Horizontal or not 0 <= section < COLUMN_COUNT:
            return None
        if role == Qt.DisplayRole:
            return headers()[section][0]
        if role == Qt.ToolTipRole:
            return headers()[section][1]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        entry = self._entries[index.row()]
        column = index.column()

        if role == Qt.DisplayRole:
            return self._display(entry, column)
        if role == Qt.ToolTipRole:
            # Notatka, nazwa pliku, nazwa banku i czas pochodza z historii —
            # takze z automatycznie importowanego history.json starego TVS.
            return plain_tooltip(self._tooltip(entry, column))
        if role == Qt.UserRole:
            return entry
        if role == Qt.FontRole and column == COL_DIGEST:
            font = QFont('Cascadia Mono')
            font.setStyleHint(QFont.Monospace)
            font.setPointSize(9)
            return font
        if role == Qt.ForegroundRole and column == COL_LEVEL:
            key = _LEVEL_ROLE.get(entry.level)
            return QColor(theme.current()[key]) if key else None
        if role == Qt.TextAlignmentRole and column == COL_BEAT:
            return int(Qt.AlignRight | Qt.AlignVCenter)
        # Klucz sortowania: tekst "12.09.2026" sortowalby sie alfabetycznie,
        # czyli blednie. Sortujemy po wartosciach porownywalnych.
        if role == Qt.InitialSortOrderRole:
            return self._sort_key(entry, column)
        return None

    def _display(self, entry: Entry, column: int) -> str:
        if column == COL_WHEN:
            return entry.when_local
        if column == COL_BEAT:
            return entry.beat or '—'
        if column == COL_FILE:
            return entry.file_name or '—'
        if column == COL_DIGEST:
            return entry.short_digest
        if column == COL_LEVEL:
            if entry.source == SOURCE_TVS_LEGACY:
                return _('TVS archive')
            try:
                return Level(entry.level).label
            except ValueError:
                return entry.level
        if column == COL_ANCHOR:
            return _anchor_text(entry)
        if column == COL_NOTE:
            return entry.note or ''
        return ''

    def _tooltip(self, entry: Entry, column: int) -> str:
        if column == COL_DIGEST:
            return entry.digest + '\n\n' + _('Right-click to copy.')
        if column == COL_FILE:
            return entry.file_path or entry.file_name or '—'
        if column == COL_LEVEL:
            if entry.source == SOURCE_TVS_LEGACY:
                return _('Entry carried over from the old TVS client. Its '
                         '"signature" is a concatenation of a time and a digest '
                         'that cannot be verified.\n\n'
                         'Stamp this file again to get a proof that\n'
                         'can be checked independently.')
            if entry.signed_by_retired_key:
                return _('The week root was signed with a BeatTime key that '
                         'has been\nretired — such a signature is no longer a '
                         'proof, so the level\nstays "Recorded".\n\n'
                         'Refresh statuses (F5) to fetch a signature made with '
                         'the current key.')
            if entry.root_signature and not entry.verified_ok:
                return _('The root signature was not accepted at the last '
                         'check:\na key outside the built-in list, or '
                         'inconsistent proof data.\n\n'
                         'Refresh statuses (F5) to check the proof again.')
            try:
                return Level(entry.level).description
            except ValueError:
                return ''
        if column == COL_WHEN:
            return 'UTC: ' + (entry.utc or '—')
        if column == COL_ANCHOR:
            return _anchor_tooltip(entry)
        if column == COL_NOTE:
            return entry.note or _('No note')
        return ''

    @staticmethod
    def _sort_key(entry: Entry, column: int):
        if column == COL_WHEN:
            dt = entry.utc_dt
            return dt.timestamp() if dt else 0.0
        if column == COL_BEAT:
            try:
                return float((entry.beat or '@0').lstrip('@'))
            except ValueError:
                return 0.0
        if column == COL_LEVEL:
            try:
                return Level(entry.level).order
            except ValueError:
                return 0
        return ''

    # --- Operacje ---

    def set_entries(self, entries: list[Entry]) -> None:
        self.beginResetModel()
        self._entries = list(reversed(entries or []))
        self.endResetModel()

    def entry_at(self, row: int) -> Entry | None:
        return self._entries[row] if 0 <= row < len(self._entries) else None


def _anchor_text(entry: Entry) -> str:
    if entry.ots_status == 'bitcoin':
        return f'Bitcoin #{entry.ots_height}' if entry.ots_height else 'Bitcoin'
    if entry.ots_status == 'pending':
        return 'OpenTimestamps…'
    for anchor in entry.anchors:
        if isinstance(anchor, dict) and anchor.get('bank'):
            return str(anchor['bank'])[:28]
    return '—'


def _anchor_tooltip(entry: Entry) -> str:
    lines = []
    if entry.week:
        state = _('closed') if entry.week_closed else _('open')
        lines.append(_('Week %(week)s (%(state)s)') % {'week': entry.week,
                                                       'state': state})
    if entry.week_root:
        lines.append(_('Merkle root: %(root)s') % {'root': entry.week_root})
    if entry.ots_status == 'bitcoin':
        lines.append(_('OpenTimestamps: confirmed in block %(height)s')
                     % {'height': entry.ots_height})
    elif entry.ots_status == 'pending':
        lines.append(_('OpenTimestamps: submitted, waiting for a Bitcoin block'))
    for anchor in entry.anchors:
        if not isinstance(anchor, dict):
            continue
        parts = [str(anchor.get('bank') or ''), str(anchor.get('date') or '')[:10]]
        ref = str(anchor.get('bank_reference') or '')
        if ref:
            parts.append(_('no. %(ref)s') % {'ref': ref})
        lines.append(_('Bank anchor: %(details)s')
                     % {'details': ' · '.join(p for p in parts if p)})
    return '\n'.join(lines) or _('No anchor — the week is still running.')


class HistoryFilter(QSortFilterProxyModel):
    """Filtr tekstowy po wszystkich kolumnach + filtr poziomu dowodu."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._text = ''
        self._level = ''            # pusty = wszystkie
        self.setSortRole(Qt.InitialSortOrderRole)

    def set_text(self, text: str) -> None:
        self._text = (text or '').strip().lower()
        self.invalidateFilter()

    def set_level(self, level: str) -> None:
        self._level = level or ''
        self.invalidateFilter()

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        model = self.sourceModel()
        entry = model.entry_at(row) if isinstance(model, HistoryModel) else None
        if entry is None:
            return False
        if self._level and entry.level != self._level:
            return False
        if not self._text:
            return True
        # Szukamy takze w PELNYM skrocie, nie tylko w skroconej formie
        # widocznej w tabeli — inaczej wklejenie calego hasha nic nie znajduje.
        haystack = ' '.join((
            entry.file_name, entry.digest, entry.note, entry.beat,
            entry.week, entry.utc, beatcore.local_str(entry.utc_dt),
            human_size(entry.file_size) if entry.file_size else '',
        )).lower()
        return self._text in haystack

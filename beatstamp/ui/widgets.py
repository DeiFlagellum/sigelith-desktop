"""
Elementy interfejsu wielokrotnego uzytku.

Poprzednia wersja miala tu jedna `QLabel` z `installEventFilter` i recznym
przechwytywaniem `DragEnter`/`Drop`. Nie obslugiwala `DragMove` (na czesci
konfiguracji Windows upuszczenie w ogole nie dochodzilo do skutku), brala
tylko `urls[0]` (reszta plików ginela bez slowa), nie reagowala na klikniecie
ani na klawiature, i nie odrozniala pliku od katalogu.
"""
from __future__ import annotations

import html
import time
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent, QFont
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from .. import beatcore
from ..config import CLOCK_DRIFT_WARN_SECONDS
from ..i18n import _


def plain_tooltip(text: str) -> str:
    """Podpowiedz z tekstu zwyklego, ktorej Qt NIE zinterpretuje jako HTML.

    Qt sam zgaduje format podpowiedzi (`Qt::mightBeRichText`): napis, ktory
    wyglada na znacznik, trafia do parsera tekstu wzbogaconego, a ten laduje
    `<img src=...>` — takze ze sciezki sieciowej UNC. Podpowiedzi niosa dane
    z sieci, z pliku `.beatproof` i z historii (nazwy plikow, notatki, nazwy
    bankow), wiec zamiast zgadywania wymuszamy tekst wzbogacony (`<qt>`)
    z KAZDA wartoscia escapowana. Podzialy wierszy zostaja zachowane.
    """
    if not text:
        return ''
    return '<qt>' + html.escape(text).replace('\n', '<br>') + '</qt>'


def card(*, muted: bool = False) -> QFrame:
    """Ramka-karta — podstawowy blok ukladu."""
    frame = QFrame()
    frame.setObjectName('cardMuted' if muted else 'card')
    return frame


def label(text: str, *, role: str = '', tooltip: str = '',
          wrap: bool = False, selectable: bool = False) -> QLabel:
    lbl = QLabel(text)
    if role:
        lbl.setObjectName(role)
    if tooltip:
        lbl.setToolTip(tooltip)
    lbl.setWordWrap(wrap)
    if selectable:
        lbl.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
    return lbl


class DropZone(QFrame):
    """Obszar upuszczania plików — mysz, klawiatura i klikniecie.

    Przyjmuje WIELE plików naraz i rozwija upuszczone katalogi. Wyraznie
    sygnalizuje stan (spoczynek / najechanie / praca), bo bez tego uzytkownik
    nie wie, czy upuszczenie w ogole zostalo przyjete.
    """

    filesDropped = Signal(list)          # list[Path]
    browseRequested = Signal()

    def __init__(self, title: str, hint: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(150)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._active = False
        self._busy = False

        self._icon = QLabel('⬇')
        font = QFont()
        font.setPointSize(26)
        self._icon.setFont(font)
        self._icon.setAlignment(Qt.AlignCenter)

        self._title = QLabel(title)
        self._title.setObjectName('h2')
        self._title.setAlignment(Qt.AlignCenter)

        self._hint = QLabel(hint)
        self._hint.setObjectName('hint')
        self._hint.setAlignment(Qt.AlignCenter)
        self._hint.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 22, 20, 22)
        layout.setSpacing(6)
        layout.addStretch(1)
        layout.addWidget(self._icon)
        layout.addWidget(self._title)
        layout.addWidget(self._hint)
        layout.addStretch(1)

        self.setToolTip(_(
            'Drag files here, or click to pick them from disk.\n'
            'You can drop several files at once — a whole folder too.\n\n'
            'Files are NOT sent anywhere: only their 64-character\n'
            'SHA-256 digest, computed on this computer, goes to the network.'
        ))
        self._restyle()

    # --- Stan ---

    def set_busy(self, busy: bool) -> None:
        """W trakcie pracy strefa nie przyjmuje nowych plików."""
        self._busy = busy
        self.setAcceptDrops(not busy)
        self.setCursor(Qt.ArrowCursor if busy else Qt.PointingHandCursor)
        self._restyle()

    def set_texts(self, title: str, hint: str) -> None:
        self._title.setText(title)
        self._hint.setText(hint)

    def _restyle(self) -> None:
        app = QApplication.instance()
        accent = '#ff5c39'
        palette = self.palette()
        border = palette.color(self.foregroundRole())
        border.setAlpha(90)
        if self._busy:
            style = f'border: 2px solid rgba(255,92,57,0.35); background: transparent;'
        elif self._active:
            style = f'border: 2px solid {accent}; background: rgba(255,92,57,0.10);'
        else:
            style = (f'border: 2px dashed rgba({border.red()},{border.green()},'
                     f'{border.blue()},0.45); background: transparent;')
        self.setStyleSheet(f'DropZone {{ {style} border-radius: 12px; }}')
        _unused = app          # NIE `_`: ta nazwa nalezy do gettext

    # --- Przeciaganie ---

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if not self._busy and event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._active = True
            self._restyle()

    def dragMoveEvent(self, event) -> None:
        # Bez tego czesc srodowisk Windows nie dopuszcza upuszczenia — brak
        # tej obslugi byl przyczyna "przeciagam, a nic sie nie dzieje".
        if not self._busy and event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragLeaveEvent(self, event) -> None:
        self._active = False
        self._restyle()
        super().dragLeaveEvent(event)

    def dropEvent(self, event: QDropEvent) -> None:
        self._active = False
        self._restyle()
        if self._busy:
            return
        paths = collect_paths(url.toLocalFile() for url in event.mimeData().urls())
        if paths:
            event.acceptProposedAction()
            self.filesDropped.emit(paths)

    # --- Mysz i klawiatura ---

    def mouseReleaseEvent(self, event) -> None:
        if not self._busy and event.button() == Qt.LeftButton:
            self.browseRequested.emit()
        super().mouseReleaseEvent(event)

    def keyPressEvent(self, event) -> None:
        # Dostepnosc: strefe da sie obsluzyc bez myszy.
        if event.key() in (Qt.Key_Return, Qt.Key_Enter, Qt.Key_Space) and not self._busy:
            self.browseRequested.emit()
            return
        super().keyPressEvent(event)


# Sufit liczby plikow z jednego upuszczenia. Upuszczenie katalogu `C:\` bez
# tego limitu wciagneloby setki tysiecy sciezek i zamrozilo aplikacje jeszcze
# przed pierwszym skrotem.
MAX_DROPPED_FILES = 500


def collect_paths(raw_paths) -> list[Path]:
    """Zamienia upuszczone ścieżki na liste Plików (katalogi rozwija).

    Pomija dowiazania symboliczne do katalogow: petla dowiazan
    (`a -> b -> a`) zapetlilaby przechodzenie drzewa w nieskonczonosc.
    """
    files: list[Path] = []
    seen: set[str] = set()

    def add(path: Path) -> bool:
        key = str(path).lower()
        if key in seen:
            return True
        seen.add(key)
        files.append(path)
        return len(files) < MAX_DROPPED_FILES

    for raw in raw_paths:
        if not raw:
            continue
        path = Path(raw)
        try:
            if path.is_file():
                if not add(path):
                    return files
            elif path.is_dir() and not path.is_symlink():
                for child in sorted(path.rglob('*')):
                    try:
                        if child.is_file() and not child.is_symlink():
                            if not add(child):
                                return files
                    except OSError:
                        continue
        except OSError:
            continue
    return files


class BeatClock(QWidget):
    """Zegar @beat liczony LOKALNIE, z korekta dryfu zegara systemowego.

    Poprzednik przy każdym pliku szedl po czas do `google.com` i
    `worldtimeapi.org` — dwa synchroniczne zapytania HTTP w watku GUI, przy
    czym drugi serwis już nie istnieje. Tutaj serwer jest odpytywany RAZ
    (model SNTP z `/api/sync/`), a zegar tyka u nas. Działa offline, nie
    obciaza serwera i nie blokuje niczego.

    Gdy dryf przekroczy prog, mowimy o tym wprost: uzytkownik ze zle
    ustawionym zegarem widzialby inny beat niż reszta swiata i nie mialby jak
    się o tym dowiedziec.
    """

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._offset = 0.0               # sekundy: serwer - my
        self._synced = False

        self._value = QLabel('@---.--')
        self._value.setObjectName('beatClock')
        self._value.setToolTip(_(
            '@beat time: the day split into 1000 beats (1 beat = 86.4 s),\n'
            'anchored in UTC. @000 is UTC midnight, @500 — UTC noon.\n'
            'No time zones: @523 means the same all over the world.'
        ))
        self._utc = QLabel('—')
        self._utc.setObjectName('faint')

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._value, alignment=Qt.AlignRight)
        layout.addWidget(self._utc, alignment=Qt.AlignRight)

        self._timer = QTimer(self)
        self._timer.setInterval(200)     # ~0,002 beatu — plynnie, bez kosztu
        self._timer.timeout.connect(self._tick)
        self._timer.start()
        self._tick()

    def apply_sync(self, offset_seconds: float) -> None:
        self._offset = float(offset_seconds)
        self._synced = True
        self._tick()

    @property
    def drift_seconds(self) -> float:
        return self._offset

    @property
    def drift_warning(self) -> str:
        if not self._synced or abs(self._offset) < CLOCK_DRIFT_WARN_SECONDS:
            return ''
        direction = _('behind') if self._offset > 0 else _('ahead of')
        return _('This computer\'s clock is %(direction)s the BeatTime server '
                 'time by %(seconds)s s. Timestamps are issued by the server, '
                 'so the proof is correct — but the clock shown next to it may '
                 'differ from the real @beat.') % {
                     'direction': direction,
                     'seconds': f'{abs(self._offset):.1f}'}

    def _tick(self) -> None:
        now = datetime.fromtimestamp(time.time() + self._offset, tz=timezone.utc)
        beats = beatcore.beats_from_utc(now)
        self._value.setText(beatcore.format_beat(beats, decimals=2))
        suffix = '' if self._synced else _(' (not synchronised)')
        self._utc.setText(now.strftime('%H:%M:%S UTC') + suffix)


class CopyField(QWidget):
    """Pole tylko do odczytu z przyciskiem kopiowania.

    Powstalo z konkretnej niewygody: w starej wersji skrót i adres
    weryfikacji byly wypisywane do wspolnego `QTextEdit`, więc skopiowanie
    samego skrótu wymagalo recznego zaznaczania 64 znakow myszka.
    """

    def __init__(self, placeholder: str = '', *, monospace: bool = True,
                 tooltip: str = '', parent: QWidget | None = None):
        super().__init__(parent)
        self._field = QLineEdit()
        self._field.setReadOnly(True)
        self._field.setPlaceholderText(placeholder)
        if monospace:
            self._field.setObjectName('mono')
        if tooltip:
            self._field.setToolTip(tooltip)

        self._button = QPushButton(_('Copy'))
        self._button.setToolTip(_('Copies the contents to the clipboard'))
        # Stala szerokosc trzyma przyciski Kopiuj w jednej linii pionowej
        # w calym oknie — ale 84 px wystarcza tylko na „Copy" i „Kopiuj".
        # Niemieckie „Kopieren" potrzebuje 110 px i bylo przycinane. Tekst
        # jest ten sam we wszystkich polach, wiec wynik nadal jest wspolny
        # dla calego okna; 84 zostaje dolna granica, zeby wyglad w polskim
        # i angielskim sie nie zmienil.
        self._button.setFixedWidth(max(84, self._button.sizeHint().width()))
        self._button.clicked.connect(self._copy)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addWidget(self._field, 1)
        layout.addWidget(self._button)

    def set_value(self, value: str) -> None:
        self._field.setText(value or '')
        self._field.setCursorPosition(0)
        self._button.setEnabled(bool(value))

    def value(self) -> str:
        return self._field.text()

    def _copy(self) -> None:
        text = self._field.text()
        if not text:
            return
        QApplication.clipboard().setText(text)
        original = self._button.text()
        self._button.setText(_('Copied'))
        QTimer.singleShot(1400, lambda: self._button.setText(original))


class StatusBadge(QLabel):
    """Kolorowy znacznik stanu: OK / ostrzezenie / błąd / informacja."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.hide()

    def show_state(self, kind: str, text: str, tooltip: str = '') -> None:
        self.setObjectName({'ok': 'badgeOk', 'warn': 'badgeWarn',
                            'error': 'badgeError'}.get(kind, 'badgeInfo'))
        self.setText(text)
        # Podpowiedz niesie ostrzezenia i zastrzezenia z weryfikacji, w ktore
        # moga trafic wartosci z pliku albo z sieci — nigdy jako HTML.
        self.setToolTip(plain_tooltip(tooltip))
        # Zmiana objectName wymaga przeliczenia stylu — bez tego widget
        # zachowuje wyglad poprzedniego stanu.
        self.style().unpolish(self)
        self.style().polish(self)
        self.show()

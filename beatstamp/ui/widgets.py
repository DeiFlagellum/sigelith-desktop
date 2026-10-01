"""
Elementy interfejsu wielokrotnego uzytku.

Czesc z nich jest RYSOWANA recznie (`paintEvent`), a nie skladana z etykiet
i arkusza stylow. Powod jest praktyczny, nie estetyczny: plakietka stanu
zrobiona z `QLabel` z wypelnieniem w arkuszu stylow liczyla swoj rozmiar
PRZED nalozeniem stylu po zmianie `objectName`, wiec pierwsza i ostatnia
litera dotykaly krawedzi. Widget, ktory sam mierzy tekst i sam rysuje tlo,
nie ma tego problemu w zadnym jezyku i przy zadnej skali ekranu.
"""
from __future__ import annotations

import html
import math
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import (
    QEasingCurve,
    QPointF,
    QPropertyAnimation,
    QRectF,
    QSize,
    Qt,
    QTimer,
    Property,
    Signal,
)
from PySide6.QtGui import (
    QColor,
    QDragEnterEvent,
    QDropEvent,
    QFont,
    QFontMetrics,
    QPainter,
    QPainterPath,
    QPen,
)
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .. import beatcore
from ..config import CLOCK_DRIFT_WARN_SECONDS
from ..i18n import _
from . import icons, theme


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
    if wrap:
        # Etykieta z zawijaniem musi ROSNAC w pionie, a nie sciskac sie pod
        # sasiadem — bez tego przy malym oknie napis „Uwaga: ..." wchodzil
        # pod pole skrotu SHA-256.
        lbl.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
    if selectable:
        lbl.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
    return lbl


def fit_to_screen(window: QWidget, width: int, height: int) -> None:
    """Rozmiar okna — ale nie wiekszy niz wolny obszar ekranu.

    Wolny obszar = ekran bez paska zadan; od wysokosci odejmujemy tez pasek
    tytulu (ramke rysuje system i `resize` jej nie liczy). Przy 1366x768 oraz
    1920x1080 ze skala 150% (1280x720 logicznie) okno 1100x780 wychodzilo
    poza ekran, a przyciski okien dialogowych chowaly sie pod paskiem zadan
    (audyt 2026-09-27).
    """
    from PySide6.QtGui import QGuiApplication
    screen = None
    for candidate in (window.parentWidget(), window):
        if candidate is not None and candidate.screen() is not None:
            screen = candidate.screen()
            break
    screen = screen or QGuiApplication.primaryScreen()
    if screen is None:
        window.resize(width, height)
        return
    area = screen.availableGeometry()
    frame = 40
    w = max(window.minimumWidth(), min(int(width), area.width() - 16))
    h = max(window.minimumHeight(), min(int(height), area.height() - frame))
    window.resize(w, h)


class ElidedLabel(QLabel):
    """Etykieta, ktora przy braku miejsca skraca tekst wielokropkiem.

    Zwykla `QLabel` bez zawijania ma minimalna szerokosc rowna tekstowi.
    Gdy okno jest wezsze niz suma takich minimow, Qt obcina widgety na
    slepo — w naglowku uciekal wtedy poczatek napisu i koncowka zegara.
    Ta etykieta mowi ukladowi „moge byc waska" i sama skraca tekst; pelny
    tekst zostaje w podpowiedzi.
    """

    MIN_WIDTH = 40

    def __init__(self, text: str = '', parent: QWidget | None = None):
        super().__init__(parent)
        self._full = ''
        self._tip = ''
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.setText(text)

    def setText(self, text: str) -> None:  # noqa: N802 — nazwa z Qt
        self._full = text or ''
        self._elide()
        self.updateGeometry()

    def full_text(self) -> str:
        return self._full

    def sizeHint(self) -> QSize:
        metrics = QFontMetrics(self.font())
        return QSize(metrics.horizontalAdvance(self._full) + 4, super().sizeHint().height())

    def minimumSizeHint(self) -> QSize:
        return QSize(self.MIN_WIDTH, super().minimumSizeHint().height())

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._elide()

    def _elide(self) -> None:
        metrics = QFontMetrics(self.font())
        shown = metrics.elidedText(self._full, Qt.ElideRight, max(0, self.width() - 2))
        QLabel.setText(self, shown)
        QLabel.setToolTip(self, plain_tooltip(self._full) if shown != self._full
                          else self._tip)

    def set_hint(self, text: str) -> None:
        """Podpowiedz pokazywana, gdy tekst NIE jest skrocony."""
        self._tip = text
        self._elide()


class ElidedButton(QPushButton):
    """Przycisk, ktory przy braku miejsca skraca tekst wielokropkiem."""

    MIN_WIDTH = 72

    def __init__(self, text: str = '', parent: QWidget | None = None,
                 elide: Qt.TextElideMode = Qt.ElideRight):
        super().__init__(parent)
        self._full = ''
        self._tip = ''
        self._mode = elide
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.setText(text)

    def setText(self, text: str) -> None:  # noqa: N802
        self._full = text or ''
        self._elide()
        self.updateGeometry()

    def full_text(self) -> str:
        return self._full

    def set_hint(self, text: str) -> None:
        self._tip = text
        self._elide()

    def _chrome(self) -> int:
        icon = self.iconSize().width() if not self.icon().isNull() else 0
        return icon + 34

    def sizeHint(self) -> QSize:
        metrics = QFontMetrics(self.font())
        base = super().sizeHint()
        return QSize(metrics.horizontalAdvance(self._full) + self._chrome(), base.height())

    def minimumSizeHint(self) -> QSize:
        return QSize(self.MIN_WIDTH, super().minimumSizeHint().height())

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._elide()

    def _elide(self) -> None:
        metrics = QFontMetrics(self.font())
        room = max(0, self.width() - self._chrome()) if self.width() > 0 else 10_000
        shown = metrics.elidedText(self._full, self._mode, room)
        QPushButton.setText(self, shown)
        tip = self._tip or ''
        if shown != self._full:
            tip = self._full + (f'\n\n{tip}' if tip else '')
        QPushButton.setToolTip(self, plain_tooltip(tip) if tip else '')


def section_label(text: str) -> QLabel:
    """Naglowek sekcji: male wersaliki z rozstrzelonymi literami."""
    lbl = QLabel(text.upper())
    lbl.setObjectName('section')
    font = lbl.font()
    font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1.2)
    lbl.setFont(font)
    return lbl


def divider() -> QFrame:
    line = QFrame()
    line.setObjectName('divider')
    line.setFrameShape(QFrame.NoFrame)
    return line


# --- Plakietka stanu ------------------------------------------------------------

_BADGE_ROLES = {'ok': ('ok', 'ok_soft'), 'warn': ('warn', 'warn_soft'),
                'error': ('error', 'error_soft'), 'info': ('accent_ink', 'accent_soft'),
                'signal': ('signal', 'signal_soft'),
                'muted': ('text_muted', 'surface_hi')}


class StatusBadge(QLabel):
    """Kolorowa plakietka stanu: kropka + tekst w zaokraglonej pastylce.

    Nadal jest `QLabel` (tekst, podpowiedz, dostepnosc), ale rozmiar liczy
    i tlo rysuje sama — patrz naglowek modulu.
    """

    PAD_X = 12
    PAD_Y = 4
    DOT = 7

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._kind = 'info'
        font = self.font()
        font.setPointSizeF(9)
        font.setWeight(QFont.Weight.DemiBold)
        self.setFont(font)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.hide()

    def show_state(self, kind: str, text: str, tooltip: str = '') -> None:
        self._kind = kind if kind in _BADGE_ROLES else 'info'
        self.setObjectName({'ok': 'badgeOk', 'warn': 'badgeWarn',
                            'error': 'badgeError'}.get(kind, 'badgeInfo'))
        self.setText(text)
        # Podpowiedz niesie ostrzezenia i zastrzezenia z weryfikacji, w ktore
        # moga trafic wartosci z pliku albo z sieci — nigdy jako HTML.
        self.setToolTip(plain_tooltip(tooltip))
        self.updateGeometry()
        self.update()
        self.show()

    @property
    def kind(self) -> str:
        return self._kind

    def sizeHint(self) -> QSize:
        metrics = QFontMetrics(self.font())
        width = metrics.horizontalAdvance(self.text()) + 2 * self.PAD_X + self.DOT + 7
        return QSize(width, metrics.height() + 2 * self.PAD_Y)

    def minimumSizeHint(self) -> QSize:
        return self.sizeHint()

    def paintEvent(self, _event) -> None:
        fg_role, bg_role = _BADGE_ROLES.get(self._kind, _BADGE_ROLES['info'])
        fg = theme.color(fg_role)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        radius = rect.height() / 2
        painter.setPen(QPen(theme.color(fg_role, 150), 1))
        painter.setBrush(theme.color(bg_role))
        painter.drawRoundedRect(rect, radius, radius)
        cy = rect.center().y()
        painter.setPen(Qt.NoPen)
        painter.setBrush(fg)
        # Kropka stoi na POCZATKU tekstu — po arabsku z prawej strony.
        lead = self.PAD_X + self.DOT + 7
        if self.isRightToLeft():
            dot_x = rect.right() - self.PAD_X - self.DOT / 2
            text_rect = rect.adjusted(self.PAD_X, 0, -lead, 0)
        else:
            dot_x = rect.left() + self.PAD_X + self.DOT / 2
            text_rect = rect.adjusted(lead, 0, -self.PAD_X, 0)
        painter.drawEllipse(QPointF(dot_x, cy), self.DOT / 2, self.DOT / 2)
        painter.setPen(fg)
        painter.setFont(self.font())
        painter.drawText(text_rect, Qt.AlignVCenter | Qt.AlignHCenter, self.text())


# --- Droga dowodu ------------------------------------------------------------------

STEP_DONE = 'done'
STEP_ACTIVE = 'active'
STEP_PENDING = 'pending'
STEP_FAIL = 'fail'


@dataclass
class JourneyStep:
    title: str
    state: str = STEP_PENDING
    caption: str = ''            # druga linijka pod tytulem (data, numer)
    tooltip: str = ''


class ProofJourney(QWidget):
    """Os etapow dowodu: od zapisu w rejestrze do kopii u osob trzecich.

    Dowod DOJRZEWA w czasie i ta os pokazuje to wprost: co juz jest
    (wypelnione kolo), co trwa (pulsujacy pierscien) i co przyjdzie samo
    (puste kolo). Tekst podpowiedzi kazdego etapu mowi, skad wiadomo.
    """

    NODE = 12

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._steps: list[JourneyStep] = []
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(60)
        self._timer.timeout.connect(self._tick)
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMinimumHeight(66)

    def set_steps(self, steps: list[JourneyStep]) -> None:
        self._steps = list(steps)
        if any(s.state == STEP_ACTIVE for s in self._steps):
            self._timer.start()
        else:
            self._timer.stop()
        self.setToolTip(plain_tooltip('\n'.join(
            f'{self._mark(s.state)} {s.title}' + (f' — {s.caption}' if s.caption else '')
            + (f'\n    {s.tooltip}' if s.tooltip else '') for s in self._steps)))
        self.update()

    @staticmethod
    def _mark(state: str) -> str:
        return {STEP_DONE: '✓', STEP_ACTIVE: '•', STEP_FAIL: '✗'}.get(state, '○')

    def steps(self) -> list[JourneyStep]:
        return list(self._steps)

    def sizeHint(self) -> QSize:
        return QSize(600, 70)

    def _tick(self) -> None:
        self._phase = (self._phase + 0.05) % 1.0
        self.update()

    def hideEvent(self, event) -> None:
        self._timer.stop()
        super().hideEvent(event)

    def showEvent(self, event) -> None:
        if any(s.state == STEP_ACTIVE for s in self._steps):
            self._timer.start()
        super().showEvent(event)

    def paintEvent(self, _event) -> None:
        if not self._steps:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        count = len(self._steps)
        width = self.width()
        margin = max(40.0, width / count / 2)
        span = (width - 2 * margin) / max(1, count - 1) if count > 1 else 0
        cy = 18.0
        xs = [margin + i * span for i in range(count)] if count > 1 else [width / 2]
        # Os czyta sie w kierunku pisma: po arabsku pierwszy etap stoi z prawej.
        step = 1.0
        if self.isRightToLeft():
            xs = [width - x for x in xs]
            step = -1.0

        done_color = theme.color('ok')
        active_color = theme.color('signal')
        fail_color = theme.color('error')
        idle = theme.color('border_strong')

        # Linie miedzy etapami: pelne do ostatniego ukonczonego, dalej przerywane.
        for i in range(count - 1):
            left, right = self._steps[i], self._steps[i + 1]
            finished = left.state == STEP_DONE and right.state in (STEP_DONE, STEP_ACTIVE)
            pen = QPen(done_color if finished else idle, 2)
            if not finished:
                pen.setStyle(Qt.DashLine)
            painter.setPen(pen)
            gap = step * (self.NODE / 2 + 3)
            painter.drawLine(QPointF(xs[i] + gap, cy), QPointF(xs[i + 1] - gap, cy))

        title_font = QFont(self.font())
        title_font.setPointSizeF(8.6)
        title_font.setWeight(QFont.Weight.DemiBold)
        caption_font = QFont(self.font())
        caption_font.setPointSizeF(8)
        column = max(60.0, span if count > 1 else width) - 6

        for i, step in enumerate(self._steps):
            x = xs[i]
            r = self.NODE / 2
            if step.state == STEP_DONE:
                painter.setPen(Qt.NoPen)
                painter.setBrush(done_color)
                painter.drawEllipse(QPointF(x, cy), r, r)
                painter.setPen(QPen(QColor('#ffffff'), 1.8, Qt.SolidLine, Qt.RoundCap))
                painter.drawLine(QPointF(x - 3, cy), QPointF(x - 0.8, cy + 2.4))
                painter.drawLine(QPointF(x - 0.8, cy + 2.4), QPointF(x + 3.4, cy - 2.6))
            elif step.state == STEP_ACTIVE:
                glow = QColor(active_color)
                glow.setAlpha(int(110 * (1 - self._phase)))
                painter.setPen(Qt.NoPen)
                painter.setBrush(glow)
                painter.drawEllipse(QPointF(x, cy), r + 6 * self._phase, r + 6 * self._phase)
                painter.setBrush(theme.color('surface'))
                painter.setPen(QPen(active_color, 2.2))
                painter.drawEllipse(QPointF(x, cy), r, r)
                painter.setPen(Qt.NoPen)
                painter.setBrush(active_color)
                painter.drawEllipse(QPointF(x, cy), 2.6, 2.6)
            elif step.state == STEP_FAIL:
                painter.setPen(Qt.NoPen)
                painter.setBrush(fail_color)
                painter.drawEllipse(QPointF(x, cy), r, r)
                painter.setPen(QPen(QColor('#ffffff'), 1.8, Qt.SolidLine, Qt.RoundCap))
                painter.drawLine(QPointF(x - 2.6, cy - 2.6), QPointF(x + 2.6, cy + 2.6))
                painter.drawLine(QPointF(x + 2.6, cy - 2.6), QPointF(x - 2.6, cy + 2.6))
            else:
                painter.setBrush(theme.color('surface'))
                painter.setPen(QPen(idle, 1.6))
                painter.drawEllipse(QPointF(x, cy), r, r)

            color = (theme.color('text') if step.state in (STEP_DONE, STEP_ACTIVE)
                     else theme.color('text_muted'))
            painter.setPen(color)
            painter.setFont(title_font)
            box = QRectF(x - column / 2, cy + r + 6, column, 16)
            metrics = QFontMetrics(title_font)
            painter.drawText(box, Qt.AlignHCenter | Qt.AlignTop,
                             metrics.elidedText(step.title, Qt.ElideRight, int(column)))
            if step.caption:
                painter.setPen(theme.color('text_faint'))
                painter.setFont(caption_font)
                cm = QFontMetrics(caption_font)
                caption = step.caption
                if self.isRightToLeft():
                    # Podpis to zwykle data, tydzien albo numer: izolacja
                    # z kierunkiem pierwszej mocnej litery (FSI) — „الكتلة 966892"
                    # zostaje arabskie, „2026-W37" czyta sie od lewej.
                    caption = f'\u2068{caption}\u2069'
                painter.drawText(QRectF(box.left(), box.bottom() + 1, column, 15),
                                 Qt.AlignHCenter | Qt.AlignTop,
                                 cm.elidedText(caption, Qt.ElideRight, int(column)))


# --- Wskaznik pracy --------------------------------------------------------------------

class Spinner(QWidget):
    """Obracajacy sie luk w kolorach marki — widoczny znak, ze cos trwa."""

    def __init__(self, size: int = 44, parent: QWidget | None = None):
        super().__init__(parent)
        self._angle = 0.0
        self._size = size
        self._timer = QTimer(self)
        self._timer.setInterval(16)
        self._timer.timeout.connect(self._tick)
        self.setFixedSize(size, size)

    def start(self) -> None:
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    def _tick(self) -> None:
        self._angle = (self._angle + 6) % 360
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        pad = 4
        rect = QRectF(pad, pad, self._size - 2 * pad, self._size - 2 * pad)
        painter.setPen(QPen(theme.color('border_strong'), 3.5))
        painter.drawEllipse(rect)
        pen = QPen(theme.color('accent'), 3.5, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(pen)
        painter.drawArc(rect, int(-self._angle * 16), int(100 * 16))
        pen.setColor(theme.color('signal'))
        painter.setPen(pen)
        painter.drawArc(rect, int((-self._angle + 180) * 16), int(55 * 16))


class BusyOverlay(QWidget):
    """Nakladka na okno z wirujacym wskaznikiem i opisem czynnosci.

    Dla czynnosci, ktore uzytkownik URUCHOMIL i na ktorych wynik czeka —
    synchronizacja zegara, stan uslugi, reczne sprawdzenie swiadkow. Maly
    napis na pasku stanu byl tu za slaby: uzytkownik klikal, niczego nie
    widzial i klikal znowu. Nakladka trwa co najmniej `MIN_MS`, a na koniec
    pokazuje wynik — wtedy widac, ze czynnosc naprawde sie wydarzyla.
    """

    MIN_MS = 1100
    RESULT_MS = 1600

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setAttribute(Qt.WA_StyledBackground, False)
        self.hide()
        self._started = 0.0
        self._pending: tuple[str, str, bool] | None = None

        self.spinner = Spinner(52)
        self.title = QLabel()
        self.title.setObjectName('h2')
        self.title.setAlignment(Qt.AlignCenter)
        # Zwykly tekst: w nakladce laduje m.in. blad polaczenia, czyli czasem
        # tresc od serwera.
        self.title.setTextFormat(Qt.PlainText)
        self.detail = QLabel()
        self.detail.setTextFormat(Qt.PlainText)
        self.detail.setObjectName('hint')
        self.detail.setAlignment(Qt.AlignCenter)
        self.detail.setWordWrap(True)
        self.result = QLabel()
        self.result.setAlignment(Qt.AlignCenter)
        self.result.hide()

        box = QFrame(self)
        box.setObjectName('card')
        # STALA szerokosc: z wyrownaniem AlignHCenter uklad liczyl wysokosc
        # zawijanego opisu dla innej szerokosci niz faktyczna i trzy linie
        # dostawaly miejsce na dwie (tytul nachodzil na spinner).
        box.setFixedWidth(440)
        inner = QVBoxLayout(box)
        inner.setContentsMargins(28, 24, 28, 22)
        inner.setSpacing(10)
        inner.addWidget(self.spinner, 0, Qt.AlignHCenter)
        inner.addWidget(self.result, 0, Qt.AlignHCenter)
        inner.addWidget(self.title)
        inner.addWidget(self.detail)
        self._box = box

        layout = QVBoxLayout(self)
        layout.addStretch(1)
        layout.addWidget(box, 0, Qt.AlignHCenter)
        layout.addStretch(1)

        self._opacity = QGraphicsOpacityEffect(self)
        self._opacity.setOpacity(1.0)
        self.setGraphicsEffect(self._opacity)
        self._fade = QPropertyAnimation(self._opacity, b'opacity', self)
        self._fade.setDuration(220)
        self._fade.finished.connect(self._after_fade)

    # --- Sterowanie ----------------------------------------------------------

    def begin(self, title: str, detail: str = '') -> None:
        self._pending = None
        self.title.setText(title)
        self.detail.setText(detail)
        self.result.hide()
        self.spinner.show()
        self.spinner.start()
        self._started = time.monotonic()
        self._cover()
        self._fade.stop()
        self._opacity.setOpacity(1.0)
        self.show()
        self.raise_()

    def finish(self, title: str, detail: str = '', ok: bool = True) -> None:
        """Pokazuje wynik — nie wczesniej niz po `MIN_MS` od poczatku."""
        if not self.isVisible():
            return
        elapsed = (time.monotonic() - self._started) * 1000
        wait = max(0, int(self.MIN_MS - elapsed))
        self._pending = (title, detail, ok)
        QTimer.singleShot(wait, self._show_result)

    @property
    def active(self) -> bool:
        return self.isVisible()

    def _show_result(self) -> None:
        if self._pending is None or not self.isVisible():
            return
        title, detail, ok = self._pending
        self._pending = None
        self.spinner.stop()
        self.spinner.hide()
        self.result.setPixmap(icons.pixmap(
            'check-circle-fill' if ok else 'exclamation-triangle-fill',
            'ok' if ok else 'warn', 44))
        self.result.show()
        self.title.setText(title)
        self.detail.setText(detail)
        QTimer.singleShot(self.RESULT_MS, self._fade_out)

    def _fade_out(self) -> None:
        if not self.isVisible() or self._pending is not None:
            return
        self._fade.setStartValue(1.0)
        self._fade.setEndValue(0.0)
        self._fade.start()

    def _after_fade(self) -> None:
        if self._opacity.opacity() <= 0.01:
            self.hide()
            self.spinner.stop()
            self._opacity.setOpacity(1.0)

    def mousePressEvent(self, event) -> None:
        # Klikniecie w nakladke po wyniku zamyka ja od razu.
        if not self.spinner.isVisible():
            self.hide()
        event.accept()

    # --- Geometria -----------------------------------------------------------

    def _cover(self) -> None:
        parent = self.parentWidget()
        if parent is not None:
            self.setGeometry(parent.rect())

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        veil = theme.color('bg', 190)
        painter.fillRect(self.rect(), veil)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)

    def eventFilter(self, obj, event) -> bool:
        return False


class PulseDot(QWidget):
    """Kropka „na zywo": pulsuje, gdy cos sie dzieje, stoi, gdy czeka."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._role = 'text_faint'
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(50)
        self._timer.timeout.connect(self._tick)
        self.setFixedSize(16, 16)

    def set_state(self, role: str, pulsing: bool) -> None:
        self._role = role
        if pulsing:
            self._timer.start()
        else:
            self._timer.stop()
            self._phase = 0.0
        self.update()

    def _tick(self) -> None:
        self._phase = (self._phase + 0.04) % 1.0
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        c = QPointF(8, 8)
        color = theme.color(self._role)
        if self._timer.isActive():
            halo = QColor(color)
            halo.setAlpha(int(140 * (1 - self._phase)))
            painter.setPen(Qt.NoPen)
            painter.setBrush(halo)
            painter.drawEllipse(c, 3.5 + 4.5 * self._phase, 3.5 + 4.5 * self._phase)
        painter.setPen(Qt.NoPen)
        painter.setBrush(color)
        painter.drawEllipse(c, 3.6, 3.6)


# --- Strefa upuszczania ------------------------------------------------------------------

class DropZone(QFrame):
    """Obszar upuszczania plikow — mysz, klawiatura i klikniecie.

    Przyjmuje WIELE plikow naraz i rozwija upuszczone katalogi. Wyraznie
    sygnalizuje stan (spoczynek / najechanie / praca): ramka przy najechaniu
    zaczyna sie przesuwac, a tlo rozswietla — bez tego uzytkownik nie wie,
    czy upuszczenie w ogole zostalo przyjete.
    """

    filesDropped = Signal(list)          # list[Path]
    browseRequested = Signal()

    def __init__(self, title: str, hint: str, parent: QWidget | None = None,
                 icon_name: str = 'fingerprint'):
        super().__init__(parent)
        self._icon_name = icon_name
        self.setObjectName('dropZone')
        self.setAcceptDrops(True)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(150)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._active = False
        self._busy = False
        self._hover = False
        self._dash = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(40)
        self._timer.timeout.connect(self._tick)

        self._icon = QLabel()
        self._icon.setFixedSize(58, 58)
        self._icon.setAttribute(Qt.WA_TransparentForMouseEvents)

        self._title = QLabel(title)
        self._title.setObjectName('h2')
        self._title.setAlignment(Qt.AlignCenter)
        self._title.setAttribute(Qt.WA_TransparentForMouseEvents)

        self._hint = QLabel(hint)
        self._hint.setObjectName('hint')
        self._hint.setAlignment(Qt.AlignCenter)
        self._hint.setWordWrap(True)
        self._hint.setAttribute(Qt.WA_TransparentForMouseEvents)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(6)
        layout.addStretch(1)
        layout.addWidget(self._icon, 0, Qt.AlignHCenter)
        layout.addSpacing(4)
        layout.addWidget(self._title)
        layout.addWidget(self._hint)
        layout.addStretch(1)

        self.setToolTip(_(
            'Drag files here, or click to pick them from disk.\n'
            'You can drop several files at once — a whole folder too.\n\n'
            'Files are NOT sent anywhere: only their 64-character\n'
            'SHA-256 digest, computed on this computer, goes to the network.'
        ))

    # --- Stan ---

    def set_busy(self, busy: bool) -> None:
        """W trakcie pracy strefa nie przyjmuje nowych plikow."""
        self._busy = busy
        self.setAcceptDrops(not busy)
        self.setCursor(Qt.ArrowCursor if busy else Qt.PointingHandCursor)
        self._sync_timer()
        self.update()

    def set_texts(self, title: str, hint: str) -> None:
        self._title.setText(title)
        self._hint.setText(hint)

    def _sync_timer(self) -> None:
        if (self._active or self._busy) and self.isVisible():
            self._timer.start()
        else:
            self._timer.stop()

    def _tick(self) -> None:
        self._dash = (self._dash + (1.2 if self._busy else 0.6)) % 24
        self.update()

    def enterEvent(self, event) -> None:
        self._hover = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._hover = False
        self.update()
        super().leaveEvent(event)

    def hideEvent(self, event) -> None:
        self._timer.stop()
        super().hideEvent(event)

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(self.rect()).adjusted(1.5, 1.5, -1.5, -1.5)
        radius = 16.0
        lit = self._active or (self._hover and not self._busy)
        base = theme.color('surface_alt' if lit else 'surface')
        painter.setPen(Qt.NoPen)
        painter.setBrush(base)
        painter.drawRoundedRect(rect, radius, radius)
        if self._active:
            painter.setBrush(theme.color('accent', 26))
            painter.drawRoundedRect(rect, radius, radius)

        border_role = 'accent' if (self._active or self._busy) else (
            'accent' if self._hover else 'border_strong')
        pen = QPen(theme.color(border_role, 230 if lit or self._busy else 200), 1.8)
        pen.setStyle(Qt.CustomDashLine)
        pen.setDashPattern([6, 6])
        pen.setDashOffset(-self._dash)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawRoundedRect(rect, radius, radius)

        # Ikona: kolo z gradientem i strzalka w dol do „tacy".
        icon = self._icon.geometry()
        center = QPointF(icon.center().x() + 0.5, icon.center().y() + 0.5)
        ring = theme.color('accent' if lit or self._busy else 'border_strong')
        painter.setPen(QPen(ring, 1.6))
        painter.setBrush(theme.color('accent_soft' if lit else 'surface_hi'))
        painter.drawEllipse(center, 26, 26)
        # Odcisk palca (stemplowanie) albo tarcza (weryfikacja): plik nie
        # wychodzi z komputera — do sieci idzie tylko jego „odcisk", skrot.
        shift = math.sin(self._dash / 24 * 2 * math.pi) * 1.5 if (self._active or self._busy) else 0
        glyph = icons.pixmap(self._icon_name,
                             'accent' if lit or self._busy else 'text_muted', 26)
        painter.drawPixmap(QPointF(center.x() - 13, center.y() - 13 + shift), glyph)

    # --- Przeciaganie ---

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if not self._busy and event.mimeData().hasUrls():
            event.acceptProposedAction()
            self._active = True
            self._sync_timer()
            self.update()

    def dragMoveEvent(self, event) -> None:
        # Bez tego czesc srodowisk Windows nie dopuszcza upuszczenia — brak
        # tej obslugi byl przyczyna "przeciagam, a nic sie nie dzieje".
        if not self._busy and event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragLeaveEvent(self, event) -> None:
        self._active = False
        self._sync_timer()
        self.update()
        super().dragLeaveEvent(event)

    def dropEvent(self, event: QDropEvent) -> None:
        self._active = False
        self._sync_timer()
        self.update()
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
    """Zamienia upuszczone sciezki na liste plikow (katalogi rozwija).

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


# --- Zegar -----------------------------------------------------------------------------

class BeatClock(QWidget):
    """Zegar @beat liczony LOKALNIE, z korekta dryfu zegara systemowego.

    Pokazuje trzy zapisy tej samej chwili: @beat (wspolny dla calego
    swiata), czas UZYTKOWNIKA z jego strefa i czas UTC. Do 2.1 obok @beat
    stal wylacznie czas UTC, wiec w Polsce zegar „spoznial sie" o dwie
    godziny — dokladnie tak wyglada czas UTC, ale nie tego czlowiek szuka
    na swoim zegarze.

    Serwer jest odpytywany RAZ (model SNTP z `/api/sync/`), a zegar tyka
    u nas. Gdy dryf przekroczy prog, mowimy o tym wprost.
    """

    syncRequested = Signal()

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
        self._local = QLabel('—')
        self._local.setObjectName('clockLocal')
        self._local.setToolTip(_('Your local time, with the time zone of this '
                                 'computer'))
        self._utc = QLabel('—')
        self._utc.setObjectName('clockUtc')
        self._utc.setToolTip(_('Coordinated Universal Time — the time the '
                               'register counts in'))

        self._dot = PulseDot()
        self._dot.setToolTip(_('Not synchronised with the Sigelith server yet'))
        self.sync_button = QToolButton()
        icons.apply(self.sync_button, 'arrow-clockwise', 'text_muted', 17)
        self.sync_button.setCursor(Qt.PointingHandCursor)
        self.sync_button.setToolTip(_('Synchronise the clock with the Sigelith '
                                      'server (F6)'))
        self.sync_button.clicked.connect(self.syncRequested)

        times = QVBoxLayout()
        times.setSpacing(0)
        times.addWidget(self._local, 0, Qt.AlignRight)
        times.addWidget(self._utc, 0, Qt.AlignRight)

        beat_row = QHBoxLayout()
        beat_row.setSpacing(6)
        beat_row.addWidget(self._dot, 0, Qt.AlignVCenter)
        beat_row.addWidget(self._value, 0, Qt.AlignVCenter)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)
        layout.addLayout(times)
        layout.addLayout(beat_row)
        layout.addWidget(self.sync_button, 0, Qt.AlignVCenter)

        self._timer = QTimer(self)
        self._timer.setInterval(200)     # ~0,002 beatu — plynnie, bez kosztu
        self._timer.timeout.connect(self._tick)
        self._timer.start()
        self._tick()

    def apply_sync(self, offset_seconds: float) -> None:
        self._offset = float(offset_seconds)
        self._synced = True
        warning = self.drift_warning
        self._dot.set_state('warn' if warning else 'signal', False)
        self._dot.setToolTip(warning or (
            _('Synchronised with the Sigelith server — difference %(offset)s s')
            % {'offset': f'{self._offset:+.2f}'}))
        self._tick()

    def set_syncing(self, active: bool) -> None:
        self._dot.set_state('signal' if active else ('signal' if self._synced else 'text_faint'),
                            active)
        self.sync_button.setEnabled(not active)

    @property
    def drift_seconds(self) -> float:
        return self._offset

    @property
    def synced(self) -> bool:
        return self._synced

    @property
    def drift_warning(self) -> str:
        if not self._synced or abs(self._offset) < CLOCK_DRIFT_WARN_SECONDS:
            return ''
        direction = _('behind') if self._offset > 0 else _('ahead of')
        return _('This computer\'s clock is %(direction)s the Sigelith server '
                 'time by %(seconds)s s. Timestamps are issued by the server, '
                 'so the proof is correct — but the clock shown next to it may '
                 'differ from the real @beat.') % {
                     'direction': direction,
                     'seconds': f'{abs(self._offset):.1f}'}

    def _tick(self) -> None:
        now = datetime.fromtimestamp(time.time() + self._offset, tz=timezone.utc)
        beats = beatcore.beats_from_utc(now)
        self._value.setText(beatcore.format_beat(beats, decimals=2))
        self._local.setText(now.astimezone().strftime('%H:%M:%S')
                            + '  ' + beatcore.utc_offset_label(now))
        suffix = '' if self._synced else _(' (not synchronised)')
        self._utc.setText(now.strftime('%H:%M:%S UTC') + suffix)

    def local_text(self) -> str:
        return self._local.text()

    def utc_text(self) -> str:
        return self._utc.text()


# --- Pole z kopiowaniem ---------------------------------------------------------------------

class CopyField(QWidget):
    """Pole tylko do odczytu z przyciskiem kopiowania."""

    def __init__(self, placeholder: str = '', *, monospace: bool = True,
                 tooltip: str = '', parent: QWidget | None = None):
        super().__init__(parent)
        self._field = QLineEdit()
        self._field.setReadOnly(True)
        self._field.setPlaceholderText(placeholder)
        if monospace:
            self._field.setObjectName('mono')
            # Skroty, klucze i adresy czyta sie od lewej takze w oknie RTL.
            self._field.setLayoutDirection(Qt.LeftToRight)
        if tooltip:
            self._field.setToolTip(tooltip)

        self._button = QPushButton(_('Copy'))
        icons.apply(self._button, 'copy')
        self._button.setToolTip(_('Copies the contents to the clipboard'))
        # Stala szerokosc trzyma przyciski Kopiuj w jednej linii pionowej.
        # Mierzymy OBA napisy: „Skopiowano" (1,4 s po kliknieciu) jest w wielu
        # jezykach dluzsze niz „Kopiuj" i nie miescilo sie w przycisku.
        widths = [100]
        for text in (_('Copied'), _('Copy')):
            self._button.setText(text)
            widths.append(self._button.sizeHint().width())
        self._button.setFixedWidth(max(widths))
        self._button.clicked.connect(self._copy)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
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


def action_row(buttons: list[QPushButton], *, stretch_at_end: bool = True) -> QHBoxLayout:
    """Rzad przyciskow z JEDNAKOWYM odstepem w calym programie.

    Do 2.1 przyciski pod wynikiem stemplowania i weryfikacji stykaly sie
    bokami (uklad zagniezdzony w siatce bez wlasnego odstepu), a w historii
    mialy odstep — trzy zakladki, trzy wyglady.
    """
    row = QHBoxLayout()
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(10)
    for button in buttons:
        row.addWidget(button)
    if stretch_at_end:
        row.addStretch(1)
    return row

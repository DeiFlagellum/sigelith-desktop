"""
Ikony — Bootstrap Icons 1.13.1 (MIT), rysowane z SVG w kolorach motywu.

Dlaczego SVG, a nie znaki Unicode. Do 2.1 ikony byly znakami (⟳, 🔒, ✔),
ktorych czcionka interfejsu nie ma — na czesci komputerow rysowaly sie jako
puste prostokaty. Ikona SVG wyglada tak samo wszedzie, jest ostra przy kazdej
skali ekranu i bierze kolor z motywu.

Jak to dziala. Bootstrap Icons rysuja w kolorze `currentColor`. Przed
wczytaniem podmieniamy go na kolor roli z biezacego motywu (`theme.current`)
i renderujemy przez `QImageReader` w DOCELOWYM rozmiarze (razy skala ekranu)
— nie skalujemy bitmapy 16x16. Wtyczka SVG Qt (`imageformats/qsvg.dll`) jest
w paczce, wiec nie potrzeba modulu `PySide6.QtSvg`.

Zmiana motywu w trakcie dzialania: kazda ikona nadana przez `apply*` jest
zapamietana (slabo — widget moze zniknac) i `refresh()` rysuje je od nowa.
"""
from __future__ import annotations

import logging
import weakref

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QSize, Qt
from PySide6.QtGui import QGuiApplication, QIcon, QImageReader, QPainter, QPixmap

from ..config import resource_path
from . import theme

log = logging.getLogger(__name__)

#: Kolor ikon na przyciskach glownych (bialy tekst na akcencie).
ON_ACCENT = '#ffffff'

_cache: dict[tuple, QPixmap] = {}
_registry: list[tuple] = []


def _color(role: str) -> str:
    if role.startswith('#'):
        return role
    return theme.current().get(role, theme.current().get('text_muted', '#888888'))


def _svg(name: str) -> bytes:
    path = resource_path(f'icons/{name}.svg')
    try:
        return path.read_bytes()
    except OSError:
        log.warning('brak ikony %s (%s)', name, path)
        return b''


def _scale() -> float:
    screen = QGuiApplication.primaryScreen()
    ratio = screen.devicePixelRatio() if screen is not None else 1.0
    # Co najmniej 2x: ikona narysowana raz jest ostra takze po przeniesieniu
    # okna na monitor o wiekszej skali.
    return max(2.0, float(ratio))


def pixmap(name: str, role: str = 'text_muted', size: int = 16) -> QPixmap:
    color = _color(role)
    scale = _scale()
    key = (name, color, size, scale)
    cached = _cache.get(key)
    if cached is not None:
        return cached
    data = _svg(name).replace(b'currentColor', color.encode('ascii'))
    result = QPixmap()
    if data:
        buffer = QBuffer()
        buffer.setData(QByteArray(data))
        buffer.open(QIODevice.ReadOnly)
        reader = QImageReader(buffer, b'svg')
        edge = int(round(size * scale))
        reader.setScaledSize(QSize(edge, edge))
        image = reader.read()
        if not image.isNull():
            result = QPixmap.fromImage(image)
            result.setDevicePixelRatio(scale)
    _cache[key] = result
    return result


#: Odstep miedzy ikona a tekstem na przycisku. Styl Fusion stawia tekst
#: tuz przy ikonie; odstep jest wiec czescia obrazka (przezroczysty margines).
BUTTON_GAP = 7


def _padded(source: QPixmap, gap: int) -> QPixmap:
    if source.isNull() or gap <= 0:
        return source
    scale = source.devicePixelRatio()
    width = source.width() / scale
    canvas = QPixmap(int(round((width + gap) * scale)), source.height())
    canvas.setDevicePixelRatio(scale)
    canvas.fill(Qt.transparent)
    painter = QPainter(canvas)
    # Odstep ma lezec MIEDZY ikona a tekstem. Po arabsku ikona stoi po prawej
    # stronie tekstu, wiec margines idzie na jej lewa strone.
    from PySide6.QtGui import QGuiApplication
    x = gap if QGuiApplication.isRightToLeft() else 0
    painter.drawPixmap(QPointF(x, 0), source)
    painter.end()
    return canvas


def icon(name: str, role: str = 'text_muted', size: int = 16, gap: int = 0) -> QIcon:
    """Ikona z odmiana „wylaczona" w kolorze przygaszonym."""
    value = QIcon()
    value.addPixmap(_padded(pixmap(name, role, size), gap), QIcon.Normal)
    value.addPixmap(_padded(pixmap(name, 'text_faint', size), gap), QIcon.Disabled)
    value.addPixmap(_padded(pixmap(name, role if role.startswith('#') else 'text', size),
                            gap), QIcon.Active)
    return value


def _remember(kind: str, target, name: str, role: str, size: int, extra=None) -> None:
    try:
        ref = weakref.ref(target)
    except TypeError:
        return
    _registry.append((kind, ref, name, role, size, extra))


def _gap_for(widget) -> int:
    from PySide6.QtWidgets import QPushButton
    return BUTTON_GAP if isinstance(widget, QPushButton) and widget.text() else 0


def apply(widget, name: str, role: str = 'text_muted', size: int = 16) -> None:
    """`setIcon` na przycisku / akcji — i zapamietanie do `refresh()`."""
    gap = _gap_for(widget)
    widget.setIcon(icon(name, role, size, gap))
    if hasattr(widget, 'setIconSize'):
        widget.setIconSize(QSize(size + gap, size))
    _remember('icon', widget, name, role, size, gap)


def apply_label(label, name: str, role: str = 'text_muted', size: int = 16) -> None:
    """Ikona jako obraz etykiety."""
    label.setPixmap(pixmap(name, role, size))
    label.setFixedSize(size, size)
    _remember('label', label, name, role, size)


def apply_tab(tabs, index: int, name: str, role: str = 'text_muted', size: int = 16) -> None:
    tabs.setTabIcon(index, icon(name, role, size))
    tabs.setIconSize(QSize(size, size))
    _remember('tab', tabs, name, role, size, index)


def refresh() -> int:
    """Rysuje zapamietane ikony od nowa w kolorach biezacego motywu."""
    _cache.clear()
    alive = []
    for kind, ref, name, role, size, extra in _registry:
        target = ref()
        if target is None:
            continue
        try:
            if kind == 'icon':
                target.setIcon(icon(name, role, size, extra or 0))
            elif kind == 'label':
                target.setPixmap(pixmap(name, role, size))
            elif kind == 'tab':
                target.setTabIcon(extra, icon(name, role, size))
        except RuntimeError:            # obiekt C++ juz zniszczony
            continue
        alive.append((kind, ref, name, role, size, extra))
    _registry[:] = alive
    return len(alive)


def available(name: str) -> bool:
    return resource_path(f'icons/{name}.svg').is_file()

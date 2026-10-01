"""
Motyw graficzny — jasny i ciemny, z jednego zestawu zmiennych.

Kierunek od 2.2: narzedzie z przyszlosci, ale powazne. Ciemne, glebokie tlo
(granat przechodzacy w grafit), karty z delikatnym gradientem i cienka
ramka, jeden akcent marki (`#ff5c39`, ten sam co certyfikat i strona serwisu)
i drugi, chlodny kolor sygnalu (cyjan) zarezerwowany dla rzeczy, ktore
dzieja sie NA ZYWO: swiadkowie, weryfikacja, zegar. Typografia: Inter do
tekstu, JetBrains Mono do skrotow i zegara — obie w paczce (`fonts.py`),
wiec program wyglada tak samo na kazdym komputerze.

Kolory sa nazwane rolami, a arkusz stylow sklada sie z nich szablonem.
Dodanie trzeciego motywu to nowy slownik, nie nowy arkusz. Wszystkie wartosci
to `#rrggbb` — test kontrastu (WCAG) liczy je wprost.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication

from .. import fonts

ACCENT = '#ff5c39'

# Szarosc do tekstu wzbogaconego (HTML) wstawianego wprost w etykiety.
# Qt nie obsluguje w nim `opacity`, a napis jest skladany raz — kolor musi
# byc jedna wartoscia dla obu motywow. `#8a93a1` ma kontrast >= 3:1 na
# bialym i na ciemnym tle.
MUTED_INK = '#8a93a1'

LIGHT = {
    'bg': '#f2f4f8',
    'bg_edge': '#e6ebf3',
    'surface': '#ffffff',
    'surface_alt': '#f6f8fb',
    'surface_hi': '#eef2f8',
    'card_top': '#ffffff',
    'card_bottom': '#fafbfd',
    'border': '#dde3ec',
    'border_strong': '#c2cbd9',
    'text': '#0f1624',
    'text_muted': '#53607a',
    'text_faint': '#717e95',
    'accent': ACCENT,
    'accent_hover': '#ff7654',
    'accent_press': '#e64a28',
    'accent_soft': '#fff0ea',
    'accent_ink': '#c43d1c',
    'signal': '#0b87a8',
    'signal_soft': '#e2f5fa',
    'ok': '#12805a',
    'ok_soft': '#e5f5ee',
    'warn': '#a05a00',
    'warn_soft': '#fdf2e1',
    'error': '#c62828',
    'error_soft': '#fdecec',
    'selection': '#ffe6dc',
    'glow': '#ffd4c6',
}

DARK = {
    'bg': '#090d14',
    'bg_edge': '#0e1522',
    'surface': '#101724',
    'surface_alt': '#141d2d',
    'surface_hi': '#1a2539',
    'card_top': '#131c2c',
    'card_bottom': '#0f1623',
    'border': '#212d43',
    'border_strong': '#33425d',
    'text': '#e8edf5',
    'text_muted': '#9aa7bc',
    'text_faint': '#6f7d95',
    'accent': ACCENT,
    'accent_hover': '#ff7a5c',
    'accent_press': '#e5482a',
    'accent_soft': '#2a1611',
    'accent_ink': '#ff8a6c',
    'signal': '#3ccfff',
    'signal_soft': '#0d2533',
    'ok': '#3ddc97',
    'ok_soft': '#0f261d',
    'warn': '#f4b94d',
    'warn_soft': '#2a2112',
    'error': '#ff6b6b',
    'error_soft': '#2f1618',
    'selection': '#2b1f2a',
    'glow': '#5a2416',
}


def resolve(mode: str) -> dict:
    """Zestaw kolorow dla 'light', 'dark' albo 'auto' (jak system)."""
    if mode == 'light':
        return LIGHT
    if mode == 'dark':
        return DARK
    return DARK if system_prefers_dark() else LIGHT


def system_prefers_dark() -> bool:
    app = QApplication.instance()
    if app is None:
        return False
    hints = app.styleHints()
    scheme = getattr(hints, 'colorScheme', None)
    if callable(scheme):
        try:
            return scheme() == Qt.ColorScheme.Dark
        except (AttributeError, TypeError):
            pass
    window = app.palette().color(QPalette.ColorRole.Window)
    return window.lightness() < 128


# Kolory aktualnie obowiazujacego motywu — dla miejsc, gdzie barwe podaje
# KOD, a nie arkusz stylow (model tabeli, widgety rysowane recznie).
_CURRENT: dict = dict(LIGHT)


def current() -> dict:
    """Kolory motywu obowiazujacego w tej chwili."""
    return _CURRENT


def is_dark() -> bool:
    return _CURRENT.get('bg') == DARK['bg']


def color(role: str, alpha: int | None = None) -> QColor:
    """`QColor` roli z biezacego motywu, opcjonalnie z przezroczystoscia 0-255."""
    value = QColor(_CURRENT.get(role, '#ff00ff'))
    if alpha is not None:
        value.setAlpha(alpha)
    return value


#: Czcionki systemowe Windows dla pism, ktorych Inter nie ma. Stoja ZA
#: Interem: lacinka (skroty, @beat, nazwy wlasne) zostaje w Interze, a
#: dopiero znaki spoza niego biora nastepna rodzine z listy. Bez tego Qt
#: wybiera zastepcze pismo sam i bywa, ze japonski tekst dostaje chinskie
#: ksztalty ideogramow (ta sama pozycja Unicode, inny rysunek).
SCRIPT_FAMILIES = {
    'ja': ('Yu Gothic UI', 'Meiryo UI', 'Meiryo'),
    'ko': ('Malgun Gothic',),
    'zh': ('Microsoft YaHei UI', 'Microsoft YaHei'),
    'ar': ('Segoe UI',),
}


def script_families(language: str | None = None) -> tuple[str, ...]:
    """Rodziny zastepcze dla jezyka interfejsu (puste dla lacinki i cyrylicy)."""
    from ..i18n import current_language
    return SCRIPT_FAMILIES.get(language or current_language(), ())


def _css_families(first: str, *rest: str) -> str:
    names = [first, *script_families(), *rest]
    seen: list[str] = []
    for name in names:
        if name not in seen:
            seen.append(name)
    return ', '.join(f'"{n}"' for n in seen)


def ui_font(point_size: float = 10.0, weight: int = QFont.Weight.Normal) -> QFont:
    font = QFont(fonts.UI_FAMILY)
    font.setFamilies([fonts.UI_FAMILY, *script_families(), 'Segoe UI'])
    font.setPointSizeF(point_size)
    font.setWeight(QFont.Weight(weight))
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    return font


def mono_font(point_size: float = 9.5, weight: int = QFont.Weight.Normal) -> QFont:
    font = QFont(fonts.MONO_FAMILY)
    font.setFamilies([fonts.MONO_FAMILY, *script_families(), 'Consolas'])
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setPointSizeF(point_size)
    font.setWeight(QFont.Weight(weight))
    return font


def apply_theme(app: QApplication, mode: str) -> dict:
    """Ustawia czcionki, palete i arkusz stylow. Zwraca uzyty zestaw kolorow."""
    global _CURRENT
    fonts.register_qt_fonts()
    colors = resolve(mode)
    _CURRENT = colors
    app.setStyle('Fusion')       # jedyny styl Qt wygladajacy tak samo wszedzie
    app.setFont(ui_font(10))
    app.setPalette(_palette(colors))
    app.setStyleSheet(stylesheet(colors))
    return colors


def _palette(c: dict) -> QPalette:
    """Paleta Qt — dla widgetow, ktore nie czytaja arkusza stylow."""
    p = QPalette()
    def col(key): return QColor(c[key])
    p.setColor(QPalette.ColorRole.Window, col('bg'))
    p.setColor(QPalette.ColorRole.WindowText, col('text'))
    p.setColor(QPalette.ColorRole.Base, col('surface'))
    p.setColor(QPalette.ColorRole.AlternateBase, col('surface_alt'))
    p.setColor(QPalette.ColorRole.Text, col('text'))
    p.setColor(QPalette.ColorRole.Button, col('surface_alt'))
    p.setColor(QPalette.ColorRole.ButtonText, col('text'))
    p.setColor(QPalette.ColorRole.Highlight, col('accent'))
    p.setColor(QPalette.ColorRole.HighlightedText, QColor('#ffffff'))
    p.setColor(QPalette.ColorRole.ToolTipBase, col('surface_hi'))
    p.setColor(QPalette.ColorRole.ToolTipText, col('text'))
    p.setColor(QPalette.ColorRole.PlaceholderText, col('text_faint'))
    p.setColor(QPalette.ColorRole.Link, col('accent'))
    p.setColor(QPalette.ColorRole.Mid, col('border'))
    disabled = QPalette.ColorGroup.Disabled
    p.setColor(disabled, QPalette.ColorRole.Text, col('text_faint'))
    p.setColor(disabled, QPalette.ColorRole.ButtonText, col('text_faint'))
    p.setColor(disabled, QPalette.ColorRole.WindowText, col('text_faint'))
    return p


def _tinted_icon(name: str, color: str) -> str:
    """Ikona Bootstrap w danym kolorze jako PLIK SVG w katalogu tymczasowym.

    Arkusz stylow Qt przyjmuje obraz tylko jako SCIEZKE, a ikony Bootstrap
    rysuja w `currentColor`. Kopia w kolorze powstaje raz i jest uzywana
    dalej (nazwa pliku niesie kolor, wiec zmiana motywu daje nowy plik).
    """
    import tempfile
    from pathlib import Path
    from ..config import resource_path
    safe = color.lstrip('#').lower()
    target = Path(tempfile.gettempdir()) / 'beatstamp-ui' / f'{name}-{safe}.svg'
    try:
        if not target.is_file():
            data = resource_path(f'icons/{name}.svg').read_bytes()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data.replace(b'currentColor', color.encode('ascii')))
    except OSError:
        return ''
    return target.as_posix()


def _check_mark() -> str:
    """Bialy znaczek ✓ do pola wyboru."""
    return _tinted_icon('check2', '#ffffff')


def stylesheet(c: dict) -> str:
    """Arkusz stylow aplikacji."""
    ui = fonts.UI_FAMILY
    mono = fonts.MONO_FAMILY
    ui_stack = _css_families(ui, 'Segoe UI')
    return f"""
    QWidget {{
        color: {c['text']};
        font-family: {ui_stack}, sans-serif;
        font-size: 10pt;
    }}
    QMainWindow, QDialog {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                    stop:0 {c['bg_edge']}, stop:0.35 {c['bg']}, stop:1 {c['bg']});
    }}
    QScrollArea, QScrollArea > QWidget > QWidget#scrollBody {{ background: transparent; border: none; }}
    QWidget#page {{ background: transparent; }}

    /* --- Naglowek okna --- */
    QFrame#header {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                    stop:0 {c['card_top']}, stop:1 {c['surface_alt']});
        border: 1px solid {c['border']};
        border-radius: 16px;
    }}

    /* --- Karty --- */
    QFrame#card {{
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                    stop:0 {c['card_top']}, stop:1 {c['card_bottom']});
        border: 1px solid {c['border']};
        border-radius: 14px;
    }}
    QFrame#cardMuted {{
        background: {c['surface_alt']};
        border: 1px solid {c['border']};
        border-radius: 12px;
    }}
    QFrame#cardAlarm {{
        background: {c['error_soft']};
        border: 1px solid {c['error']};
        border-radius: 14px;
    }}
    QFrame#divider {{ background: {c['border']}; border: none; max-height: 1px; min-height: 1px; }}

    /* --- Typografia --- */
    QLabel#h1 {{ font-size: 17pt; font-weight: 700; }}
    QLabel#h2 {{ font-size: 12.5pt; font-weight: 600; }}
    QLabel#h3 {{ font-size: 10.5pt; font-weight: 600; }}
    QLabel#brand {{ font-size: 15pt; font-weight: 700; color: {c['accent']}; }}
    QLabel#section {{ color: {c['text_faint']}; font-size: 8pt; font-weight: 700; }}
    QLabel#hint {{ color: {c['text_muted']}; font-size: 9.2pt; }}
    QLabel#faint {{ color: {c['text_faint']}; font-size: 8.8pt; }}
    QLabel#value {{ font-size: 10pt; }}
    QLabel#signal {{ color: {c['signal']}; font-weight: 600; }}
    QLabel#okText {{ color: {c['ok']}; font-weight: 600; }}
    QLabel#warnText {{ color: {c['warn']}; font-weight: 600; }}
    QLabel#errorText {{ color: {c['error']}; font-weight: 600; }}
    QLabel#beatClock {{
        font-family: "{mono}", "Consolas", monospace; font-size: 21pt; font-weight: 700;
        color: {c['accent']};
    }}
    QLabel#clockLocal {{ font-family: "{mono}", "Consolas", monospace; font-size: 10.5pt;
                         font-weight: 500; }}
    QLabel#clockUtc {{ font-family: "{mono}", "Consolas", monospace; font-size: 8.8pt;
                       color: {c['text_faint']}; }}
    QLabel#badgeOk, QLabel#badgeWarn, QLabel#badgeError, QLabel#badgeInfo {{
        font-size: 9pt; font-weight: 600; background: transparent; border: none;
    }}
    QLabel#bigNumber {{ font-family: "{mono}", "Consolas", monospace; font-size: 18pt;
                        font-weight: 700; }}
    QLabel#mono, QLineEdit#mono, QPlainTextEdit#mono {{
        font-family: "{mono}", "Cascadia Mono", "Consolas", monospace;
        font-size: 9pt;
    }}

    /* --- Przyciski --- */
    QPushButton {{
        background: {c['surface_alt']};
        border: 1px solid {c['border_strong']};
        border-radius: 9px;
        padding: 8px 16px;
        min-height: 18px;
        font-weight: 500;
    }}
    QPushButton:hover  {{ border-color: {c['accent']}; background: {c['surface_hi']}; }}
    QPushButton:pressed {{ background: {c['surface']}; }}
    QPushButton:disabled {{ color: {c['text_faint']}; border-color: {c['border']};
                            background: {c['surface']}; }}
    QPushButton#primary {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                    stop:0 {c['accent_hover']}, stop:1 {c['accent']});
        color: #ffffff; border: 1px solid {c['accent']}; font-weight: 700;
        padding: 9px 20px;
    }}
    QPushButton#primary:hover {{
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                    stop:0 #ff8a6c, stop:1 {c['accent_hover']});
        border-color: {c['accent_hover']};
    }}
    QPushButton#primary:pressed {{ background: {c['accent_press']}; }}
    QPushButton#primary:disabled {{
        background: {c['surface_hi']}; border-color: {c['border']}; color: {c['text_faint']};
    }}
    QPushButton#compact {{ padding: 8px 9px; }}
    QPushButton#ghost {{
        background: transparent; border: 1px solid transparent; color: {c['text_muted']};
        padding: 6px 10px;
    }}
    QPushButton#ghost:hover {{ color: {c['text']}; border-color: {c['border_strong']}; }}
    QPushButton#link {{
        background: transparent; border: none; color: {c['accent']};
        padding: 2px 4px; text-decoration: underline; text-align: left;
    }}
    QToolButton {{ background: transparent; border: none; color: {c['text_muted']};
                   padding: 4px 6px; border-radius: 7px; }}
    QToolButton:hover {{ background: {c['surface_hi']}; color: {c['text']}; }}

    /* --- Pola --- */
    QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
        background: {c['surface_alt']};
        border: 1px solid {c['border_strong']};
        border-radius: 9px;
        padding: 7px 10px;
        selection-background-color: {c['selection']};
        selection-color: {c['text']};
    }}
    QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus,
    QSpinBox:focus, QDoubleSpinBox:focus {{ border: 1px solid {c['accent']}; }}
    QLineEdit:read-only {{ background: {c['surface']}; }}
    QLineEdit:disabled, QComboBox:disabled {{ background: {c['surface']}; color: {c['text_faint']}; }}
    /* Strzalki: sam `::drop-down` bez `::down-arrow` (i pola liczbowe
       z samym `padding`) dawaly listy bez strzalki i przyciski +/- bez
       strzalek — styl Fusion nie rysuje ich, gdy podelement ma wlasny styl
       (audyt 2026-09-27). */
    QComboBox {{ padding-right: 30px; }}
    QComboBox::drop-down {{
        subcontrol-origin: padding; subcontrol-position: center right;
        border: none; width: 28px;
    }}
    QComboBox::down-arrow {{ image: url("{_tinted_icon('chevron-down', c['text_muted'])}");
                             width: 12px; height: 12px; }}
    QComboBox::down-arrow:disabled {{ image: url("{_tinted_icon('chevron-down', c['text_faint'])}"); }}
    QSpinBox, QDoubleSpinBox {{ padding-right: 28px; }}
    QSpinBox::up-button, QDoubleSpinBox::up-button {{
        subcontrol-origin: border; subcontrol-position: top right;
        width: 24px; border: none; border-left: 1px solid {c['border']};
        border-top-right-radius: 9px;
    }}
    QSpinBox::down-button, QDoubleSpinBox::down-button {{
        subcontrol-origin: border; subcontrol-position: bottom right;
        width: 24px; border: none; border-left: 1px solid {c['border']};
        border-bottom-right-radius: 9px;
    }}
    QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover,
    QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {{
        background: {c['surface_hi']};
    }}
    QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {{
        image: url("{_tinted_icon('chevron-up', c['text_muted'])}"); width: 10px; height: 10px;
    }}
    QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {{
        image: url("{_tinted_icon('chevron-down', c['text_muted'])}"); width: 10px; height: 10px;
    }}
    QComboBox QAbstractItemView {{
        background: {c['surface_hi']}; border: 1px solid {c['border_strong']};
        selection-background-color: {c['accent']}; selection-color: #ffffff;
        outline: none; padding: 4px;
    }}

    /* --- Zakladki: pastylki zamiast kart --- */
    QTabWidget::pane {{ border: none; background: transparent; top: 8px; }}
    QTabWidget::tab-bar {{ left: 2px; }}
    QTabBar::tab {{
        background: transparent; color: {c['text_muted']};
        padding: 8px 18px; margin-right: 6px;
        border: 1px solid transparent; border-radius: 17px;
        font-weight: 600;
    }}
    QTabBar::tab:hover {{ color: {c['text']}; background: {c['surface_alt']}; }}
    QTabBar::tab:selected {{
        background: {c['surface_hi']}; color: {c['text']};
        border: 1px solid {c['border_strong']};
    }}
    QDialog QTabWidget::pane {{ border: 1px solid {c['border']}; border-radius: 12px;
                               background: {c['surface']}; top: 6px; }}

    /* --- Tabela historii --- */
    QTableView {{
        background: {c['surface']};
        alternate-background-color: {c['surface_alt']};
        border: 1px solid {c['border']}; border-radius: 12px;
        gridline-color: transparent;
        selection-background-color: {c['selection']};
        selection-color: {c['text']};
        outline: none;
    }}
    QTableView::item {{ padding: 6px 8px; border: none; }}
    QHeaderView {{ background: transparent; }}
    QHeaderView::section {{
        background: {c['surface_alt']}; color: {c['text_faint']};
        padding: 8px 8px; border: none;
        border-bottom: 1px solid {c['border']};
        font-weight: 700; font-size: 8.5pt;
    }}
    QListWidget {{ background: {c['surface']}; border: 1px solid {c['border']};
                   border-radius: 10px; padding: 4px; outline: none; }}
    QListWidget::item {{ padding: 6px 8px; border-radius: 6px; }}
    QListWidget::item:selected {{ background: {c['selection']}; color: {c['text']}; }}

    /* --- Pasek postepu --- */
    QProgressBar {{
        background: {c['surface_alt']}; border: 1px solid {c['border']};
        border-radius: 8px; height: 16px; text-align: center;
        color: {c['text_muted']}; font-size: 8.5pt;
    }}
    QProgressBar::chunk {{
        border-radius: 7px;
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                    stop:0 {c['accent']}, stop:1 {c['signal']});
    }}

    /* --- Pozostale --- */
    QToolTip {{
        background: {c['surface_hi']}; color: {c['text']};
        border: 1px solid {c['border_strong']}; border-radius: 8px;
        padding: 7px 10px;
    }}
    QStatusBar {{ background: transparent; color: {c['text_muted']};
                  border-top: 1px solid {c['border']}; }}
    QStatusBar::item {{ border: none; }}
    QMenuBar {{ background: transparent; padding: 2px 4px; }}
    QMenuBar::item {{ padding: 5px 10px; border-radius: 6px; background: transparent; }}
    QMenuBar::item:selected {{ background: {c['surface_hi']}; color: {c['text']}; }}
    QMenu {{ background: {c['surface_hi']}; border: 1px solid {c['border_strong']};
             border-radius: 10px; padding: 6px; }}
    QMenu::item {{ padding: 7px 28px 7px 16px; border-radius: 6px; }}
    QMenu::item:selected {{ background: {c['accent']}; color: #ffffff; }}
    QMenu::separator {{ height: 1px; background: {c['border']}; margin: 5px 8px; }}
    QGroupBox {{ border: 1px solid {c['border']}; border-radius: 10px; margin-top: 14px;
                 padding: 12px 10px 10px 10px; font-weight: 600; }}
    QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 4px;
                        color: {c['text_muted']}; }}
    QCheckBox, QRadioButton {{ spacing: 9px; }}
    QCheckBox::indicator {{ width: 16px; height: 16px; }}
    QRadioButton::indicator {{ width: 14px; height: 14px; }}
    QCheckBox::indicator:unchecked {{
        border: 1px solid {c['border_strong']}; border-radius: 5px; background: {c['surface_alt']};
    }}
    QCheckBox::indicator:checked {{
        border: 1px solid {c['accent']}; border-radius: 5px; background: {c['accent']};
        image: url("{_check_mark()}");
    }}
    QRadioButton::indicator:unchecked {{
        border: 1px solid {c['border_strong']}; border-radius: 8px; background: {c['surface_alt']};
    }}
    QRadioButton::indicator:checked {{
        width: 6px; height: 6px;
        border: 5px solid {c['accent']}; border-radius: 8px; background: #ffffff;
    }}
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 3px; }}
    QScrollBar::handle:vertical {{ background: {c['border_strong']}; border-radius: 4px; min-height: 28px; }}
    QScrollBar::handle:vertical:hover {{ background: {c['text_faint']}; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 3px; }}
    QScrollBar::handle:horizontal {{ background: {c['border_strong']}; border-radius: 4px; min-width: 28px; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
    QSplitter::handle {{ background: {c['border']}; }}
    """

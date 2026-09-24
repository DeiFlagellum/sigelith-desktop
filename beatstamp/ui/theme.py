"""
Motyw graficzny — jasny i ciemny, z jednego zestawu zmiennych.

Poprzednik nie mial motywu w ogole: bylo jedno `setStyleSheet` na etykiecie
upuszczania, twarde `#888` i reszta domyslna. Przy ciemnym motywie Windows
dawalo to ciemny tekst na ciemnym tle — i nie dalo sie tego zmienic.

Tutaj kolory sa nazwane rolami (tlo, powierzchnia, tekst, akcent, obramowanie),
a arkusz stylow sklada sie z nich szablonem. Dodanie trzeciego motywu to nowy
slownik, nie nowy arkusz.

Akcent `#ff5c39` jest kolorem marki BeatTime — tym samym, ktorym operuje
certyfikat PDF (`apps/tsa/cert.py`) i strona beattime.live.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

ACCENT = '#ff5c39'

# Szarosc do tekstu wzbogaconego (HTML) wstawianego wprost w etykiety.
#
# Qt nie obsluguje w nim `opacity`, wiec pierwsza wersja tego kodu — `<span
# style="opacity:.7">` — nie przygaszala niczego: napis zostawal w pelnej
# czerni. Kolor musi byc jedna wartoscia dla obu motywow, bo napis jest
# skladany raz i nie przeliczamy go przy zmianie motywu. `#8a93a1` lezy
# posrodku: ma kontrast >= 3:1 na bialym tle i na ciemnym (#1c2128), czyli
# spelnia WCAG dla tekstu drugorzednego w kazdym z nich.
MUTED_INK = '#8a93a1'

LIGHT = {
    'bg': '#f4f5f7',
    'surface': '#ffffff',
    'surface_alt': '#f9fafb',
    'border': '#d9dee6',
    'border_strong': '#b9c1cd',
    'text': '#11151c',
    'text_muted': '#5b6472',
    'text_faint': '#8a93a1',
    'accent': ACCENT,
    'accent_hover': '#ff7554',
    'accent_press': '#e64a28',
    'accent_soft': '#fff1ec',
    'ok': '#1f8a4c',
    'ok_soft': '#e8f6ee',
    'warn': '#b26a00',
    'warn_soft': '#fdf3e3',
    'error': '#c62828',
    'error_soft': '#fdecec',
    'selection': '#ffe3d9',
}

DARK = {
    'bg': '#15181d',
    'surface': '#1c2128',
    'surface_alt': '#22272f',
    'border': '#30363f',
    'border_strong': '#454d59',
    'text': '#e6e9ee',
    'text_muted': '#a0a8b4',
    'text_faint': '#7b838f',
    'accent': ACCENT,
    'accent_hover': '#ff7554',
    'accent_press': '#e64a28',
    'accent_soft': '#3a221b',
    'ok': '#4cc38a',
    'ok_soft': '#16281f',
    'warn': '#e0a33a',
    'warn_soft': '#2b2318',
    'error': '#f2726f',
    'error_soft': '#2e1b1b',
    'selection': '#4a2a1e',
}


def resolve(mode: str) -> dict:
    """Zwraca zestaw kolorow dla 'light', 'dark' albo 'auto'.

    'auto' idzie za ustawieniem systemu. Qt 6.5+ udostepnia to przez
    `styleHints().colorScheme()`; na starszych wersjach rozpoznajemy motyw po
    jasnosci domyslnego tla okna — dziala wszedzie i nie wymaga wyjatkow.
    """
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


# Kolory aktualnie obowiazujacego motywu. Potrzebne tam, gdzie barwe podaje
# KOD, a nie arkusz stylow — w modelu tabeli (`Qt.ForegroundRole`) arkusz nie
# siega, bo kolor komorki zwraca model. Bez tego poziomy dowodu rysowaly sie
# zawsze barwami motywu jasnego: ciemna zielen `#1f8a4c` na ciemnym tle
# (a zwlaszcza na tle zaznaczenia `#4a2a1e`) byla praktycznie nieczytelna.
_CURRENT: dict = dict(LIGHT)


def current() -> dict:
    """Kolory motywu obowiazujacego w tej chwili."""
    return _CURRENT


def apply_theme(app: QApplication, mode: str) -> dict:
    """Ustawia palete i arkusz stylow. Zwraca uzyty zestaw kolorow."""
    global _CURRENT
    colors = resolve(mode)
    _CURRENT = colors
    app.setStyle('Fusion')       # jedyny styl Qt wygladajacy tak samo wszedzie
    app.setPalette(_palette(colors))
    app.setStyleSheet(stylesheet(colors))
    return colors


def _palette(c: dict) -> QPalette:
    """Paleta Qt — dla widgetow, ktore nie czytaja arkusza stylow.

    Sam arkusz nie wystarcza: okna dialogowe systemowe, podpowiedzi i
    zaznaczenie tekstu w polach edycji biora kolory z palety. Bez tego w
    ciemnym motywie zdarzal sie czarny tekst na czarnym tle.
    """
    p = QPalette()
    def col(key): return QColor(c[key])
    p.setColor(QPalette.ColorRole.Window, col('bg'))
    p.setColor(QPalette.ColorRole.WindowText, col('text'))
    p.setColor(QPalette.ColorRole.Base, col('surface'))
    p.setColor(QPalette.ColorRole.AlternateBase, col('surface_alt'))
    p.setColor(QPalette.ColorRole.Text, col('text'))
    p.setColor(QPalette.ColorRole.Button, col('surface'))
    p.setColor(QPalette.ColorRole.ButtonText, col('text'))
    p.setColor(QPalette.ColorRole.Highlight, col('accent'))
    p.setColor(QPalette.ColorRole.HighlightedText, QColor('#ffffff'))
    p.setColor(QPalette.ColorRole.ToolTipBase, col('surface'))
    p.setColor(QPalette.ColorRole.ToolTipText, col('text'))
    p.setColor(QPalette.ColorRole.PlaceholderText, col('text_faint'))
    p.setColor(QPalette.ColorRole.Link, col('accent'))
    disabled = QPalette.ColorGroup.Disabled
    p.setColor(disabled, QPalette.ColorRole.Text, col('text_faint'))
    p.setColor(disabled, QPalette.ColorRole.ButtonText, col('text_faint'))
    p.setColor(disabled, QPalette.ColorRole.WindowText, col('text_faint'))
    return p


def stylesheet(c: dict) -> str:
    """Arkusz stylow aplikacji."""
    return f"""
    QWidget {{
        color: {c['text']};
        font-size: 10pt;
    }}
    QMainWindow, QDialog {{ background: {c['bg']}; }}

    /* --- Karty: podstawowy blok ukladu --- */
    QFrame#card {{
        background: {c['surface']};
        border: 1px solid {c['border']};
        border-radius: 10px;
    }}
    QFrame#cardMuted {{
        background: {c['surface_alt']};
        border: 1px solid {c['border']};
        border-radius: 10px;
    }}

    /* --- Typografia --- */
    QLabel#h1 {{ font-size: 16pt; font-weight: 600; }}
    QLabel#h2 {{ font-size: 12pt; font-weight: 600; }}
    QLabel#hint {{ color: {c['text_muted']}; font-size: 9pt; }}
    QLabel#faint {{ color: {c['text_faint']}; font-size: 9pt; }}
    QLabel#mono, QLineEdit#mono, QPlainTextEdit#mono {{
        font-family: "Cascadia Mono", "Consolas", "DejaVu Sans Mono", monospace;
        font-size: 9pt;
    }}
    QLabel#beatClock {{
        font-family: "Cascadia Mono", "Consolas", monospace;
        font-size: 15pt; font-weight: 600; color: {c['accent']};
    }}

    /* --- Znaczniki stanu --- */
    QLabel#badgeOk    {{ background: {c['ok_soft']};    color: {c['ok']};
                         border: 1px solid {c['ok']};    border-radius: 9px;
                         padding: 3px 10px; font-weight: 600; font-size: 9pt; }}
    QLabel#badgeWarn  {{ background: {c['warn_soft']};  color: {c['warn']};
                         border: 1px solid {c['warn']};  border-radius: 9px;
                         padding: 3px 10px; font-weight: 600; font-size: 9pt; }}
    QLabel#badgeError {{ background: {c['error_soft']}; color: {c['error']};
                         border: 1px solid {c['error']}; border-radius: 9px;
                         padding: 3px 10px; font-weight: 600; font-size: 9pt; }}
    QLabel#badgeInfo  {{ background: {c['accent_soft']}; color: {c['accent_press']};
                         border: 1px solid {c['accent']}; border-radius: 9px;
                         padding: 3px 10px; font-weight: 600; font-size: 9pt; }}

    /* --- Przyciski --- */
    QPushButton {{
        background: {c['surface']};
        border: 1px solid {c['border_strong']};
        border-radius: 7px;
        padding: 7px 14px;
        min-height: 18px;
    }}
    QPushButton:hover  {{ border-color: {c['accent']}; }}
    QPushButton:pressed {{ background: {c['surface_alt']}; }}
    QPushButton:disabled {{ color: {c['text_faint']}; border-color: {c['border']}; }}
    QPushButton#primary {{
        background: {c['accent']}; color: #ffffff;
        border: 1px solid {c['accent']}; font-weight: 600;
        padding: 9px 20px;
    }}
    QPushButton#primary:hover   {{ background: {c['accent_hover']}; border-color: {c['accent_hover']}; }}
    QPushButton#primary:pressed {{ background: {c['accent_press']}; }}
    QPushButton#primary:disabled {{
        background: {c['border']}; border-color: {c['border']}; color: {c['text_faint']};
    }}
    QPushButton#link {{
        background: transparent; border: none; color: {c['accent']};
        padding: 2px 4px; text-decoration: underline;
    }}

    /* --- Pola --- */
    QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
        background: {c['surface']};
        border: 1px solid {c['border_strong']};
        border-radius: 7px;
        padding: 6px 9px;
        selection-background-color: {c['selection']};
        selection-color: {c['text']};
    }}
    QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus,
    QSpinBox:focus, QDoubleSpinBox:focus {{ border: 1px solid {c['accent']}; }}
    QLineEdit:disabled, QComboBox:disabled {{ background: {c['surface_alt']}; color: {c['text_faint']}; }}
    QComboBox::drop-down {{ border: none; width: 22px; }}
    QComboBox QAbstractItemView {{
        background: {c['surface']}; border: 1px solid {c['border_strong']};
        selection-background-color: {c['accent']}; selection-color: #ffffff;
        outline: none;
    }}

    /* --- Zakladki --- */
    QTabWidget::pane {{
        border: 1px solid {c['border']}; border-radius: 10px;
        background: {c['surface']}; top: -1px;
    }}
    QTabBar::tab {{
        background: transparent; color: {c['text_muted']};
        padding: 9px 20px; margin-right: 3px;
        border: 1px solid transparent;
        border-top-left-radius: 9px; border-top-right-radius: 9px;
    }}
    QTabBar::tab:hover {{ color: {c['text']}; }}
    QTabBar::tab:selected {{
        background: {c['surface']}; color: {c['text']}; font-weight: 600;
        border: 1px solid {c['border']}; border-bottom-color: {c['surface']};
    }}

    /* --- Tabela historii --- */
    QTableView {{
        background: {c['surface']};
        alternate-background-color: {c['surface_alt']};
        border: 1px solid {c['border']}; border-radius: 8px;
        gridline-color: {c['border']};
        selection-background-color: {c['selection']};
        selection-color: {c['text']};
    }}
    QTableView::item {{ padding: 4px 6px; }}
    QHeaderView::section {{
        background: {c['surface_alt']}; color: {c['text_muted']};
        padding: 7px 8px; border: none;
        border-bottom: 1px solid {c['border']}; border-right: 1px solid {c['border']};
        font-weight: 600;
    }}

    /* --- Pasek postepu --- */
    QProgressBar {{
        background: {c['surface_alt']}; border: 1px solid {c['border']};
        border-radius: 7px; height: 16px; text-align: center;
        color: {c['text_muted']}; font-size: 8.5pt;
    }}
    QProgressBar::chunk {{ background: {c['accent']}; border-radius: 6px; }}

    /* --- Pozostale --- */
    QToolTip {{
        background: {c['surface']}; color: {c['text']};
        border: 1px solid {c['border_strong']}; border-radius: 6px;
        padding: 6px 9px;
    }}
    QStatusBar {{ background: {c['bg']}; color: {c['text_muted']}; }}
    QStatusBar::item {{ border: none; }}
    QMenuBar {{ background: {c['bg']}; }}
    QMenuBar::item:selected {{ background: {c['accent_soft']}; color: {c['accent_press']}; }}
    QMenu {{ background: {c['surface']}; border: 1px solid {c['border_strong']};
             border-radius: 8px; padding: 5px; }}
    QMenu::item {{ padding: 6px 26px 6px 18px; border-radius: 5px; }}
    QMenu::item:selected {{ background: {c['accent']}; color: #ffffff; }}
    QMenu::separator {{ height: 1px; background: {c['border']}; margin: 5px 8px; }}
    QCheckBox, QRadioButton {{ spacing: 8px; }}
    QCheckBox::indicator, QRadioButton::indicator {{ width: 17px; height: 17px; }}
    QCheckBox::indicator:unchecked {{
        border: 1px solid {c['border_strong']}; border-radius: 4px; background: {c['surface']};
    }}
    QCheckBox::indicator:checked {{
        border: 1px solid {c['accent']}; border-radius: 4px; background: {c['accent']};
    }}
    QScrollBar:vertical {{ background: transparent; width: 11px; margin: 2px; }}
    QScrollBar::handle:vertical {{ background: {c['border_strong']}; border-radius: 5px; min-height: 28px; }}
    QScrollBar::handle:vertical:hover {{ background: {c['text_faint']}; }}
    QScrollBar:horizontal {{ background: transparent; height: 11px; margin: 2px; }}
    QScrollBar::handle:horizontal {{ background: {c['border_strong']}; border-radius: 5px; min-width: 28px; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
    QSplitter::handle {{ background: {c['border']}; }}
    """

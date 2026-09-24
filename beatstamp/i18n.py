"""
Warstwa tlumaczen BeatStamp — gettext, katalogi `.po`/`.mo`.

DLACZEGO GETTEXT, A NIE `QObject.tr()`

`tr()` jest metoda `QObject`. Tymczasem 30% napisow tej aplikacji lezy
w modulach swiadomie wolnych od Qt: `certificate.py`, `api.py`, `proof.py`,
`bundle.py`, `hashing.py`, `plural.py`. Oznaczenie ich przez
`QCoreApplication.translate(...)` wciagneloby PySide6 do warstwy, ktora
z zalozenia dziala bez niego — a `keys.py` jest wrecz ladowany ze sciezki
pliku w srodowisku Django, gdzie PySide6 nie jest zainstalowane
(`apps/tsa/tests.py: DesktopKeyMirrorTests`).

Drugi powod jest praktyczny: reszta monorepo BeatTime uzywa `.po`/`.mo`
(`locale/<lang>/LC_MESSAGES/django.po`, dziesiec jezykow), wiec narzedzia,
nawyki i format plikow sa te same.

JEZYK ZRODLOWY = ANGIELSKI

`msgid` sa po angielsku, bo tak wyglada kazdy katalog gettext i tak
oczekuje tego kazde narzedzie tlumaczeniowe. Brak katalogu degraduje sie
wiec do angielskiego, a nie do polskiego — to wazne dla wersji ze Sklepu,
gdzie paczka moze trafic do kogos, kto polskiego nie zna.

WYKRYWANIE JEZYKA SYSTEMU

Na Windows NIE wolno uzyc `QLocale.system()` ani `locale.getlocale()`.
Oba zwracaja FORMAT REGIONALNY (daty, waluta), a nie jezyk interfejsu.
Na maszynie z polskim interfejsem i niemieckim formatem regionalnym daja
`de_DE` — aplikacja uruchomilaby sie po niemiecku u polskiego uzytkownika,
i nikt nie zauwazylby tego w testach. Jedyne miarodajne zrodlo to
`kernel32.GetUserPreferredUILanguages(MUI_LANGUAGE_NAME)`, ktore zwraca
uporzadkowana liste jezykow INTERFEJSU.
"""
from __future__ import annotations

import gettext as _gettext
import logging
import os
import sys
from pathlib import Path

log = logging.getLogger(__name__)

#: Nazwa domeny gettext = nazwa pliku katalogu (`beatstamp.mo`).
DOMAIN = 'beatstamp'

#: Jezyk, w ktorym napisane sa `msgid` w kodzie. Nie ma wlasnego katalogu:
#: brak tlumaczenia oznacza po prostu zwrocenie `msgid`.
SOURCE_LANGUAGE = 'en'

#: Jezyki, ktore aplikacja deklaruje. Kolejnosc = kolejnosc na liscie
#: w Ustawieniach (pierwszy jest jezykiem domyslnym katalogu).
SUPPORTED = ('pl', 'en', 'de')

#: Wartosc ustawienia „jak w systemie".
AUTO = 'auto'

#: Wymuszenie jezyka z zewnatrz — uzywaja go testy i `tools/verify_exe.py`.
#: Ma pierwszenstwo przed systemem, ale nie przed jawnym `set_language`.
LANGUAGE_ENV = 'BEATSTAMP_LANG'

#: Nazwy jezykow w NICH SAMYCH. Lista jezykow po polsku bylaby bezuzyteczna
#: dokladnie dla tego, kto jej potrzebuje: kogos, kto polskiego nie czyta.
LANGUAGE_NAMES = {
    'pl': 'Polski',
    'en': 'English',
    'de': 'Deutsch',
}

# Formaty daty i liczby. ZADEN katalog komunikatow tego nie rozwiazuje:
# `%d.%m.%Y` nie jest napisem do tlumaczenia, tylko regula zapisu, a
# separator dziesietny w ogole nie wystepuje w tekscie. Tabela jest krotka,
# jawna i testowalna — i dlatego lepsza niz `QLocale`, ktore na Windows
# bierze format regionalny niezalezny od wybranego jezyka interfejsu.
_FORMATS = {
    'en': {
        'decimal': '.',
        'date': '%Y-%m-%d',
        # Zapis ISO nie ma sensownej formy „bez roku": „06-15–2026-06-21"
        # wyglada jak dwa rozne formaty w jednym zakresie. Dla angielskiego
        # obie granice zakresu sa wiec pelne.
        'date_short': '%Y-%m-%d',
        'datetime': '%Y-%m-%d, %H:%M:%S',
    },
    'pl': {
        'decimal': ',',
        'date': '%d.%m.%Y',
        'date_short': '%d.%m',
        'datetime': '%d.%m.%Y, %H:%M:%S',
    },
    'de': {
        'decimal': ',',
        'date': '%d.%m.%Y',
        'date_short': '%d.%m.',
        'datetime': '%d.%m.%Y, %H:%M:%S',
    },
}

_translation: _gettext.NullTranslations = _gettext.NullTranslations()
_current: str = SOURCE_LANGUAGE
_initialised = False


# --- Katalogi ---------------------------------------------------------------

def locale_dir() -> Path:
    """Katalog z katalogami tlumaczen (`locale/<lang>/LC_MESSAGES/`).

    `config` importujemy DOPIERO TUTAJ, a nie na poziomie modulu: `config`
    sam tlumaczy komunikaty przeprowadzki danych, wiec import na gorze
    zamknalby cykl `config -> i18n -> config`.
    """
    from .config import resource_path
    return resource_path('locale')


def available_languages() -> tuple[str, ...]:
    """Jezyki, dla ktorych naprawde jest co wczytac.

    Jezyk zrodlowy jest na liscie zawsze — `msgid` sa w kodzie, wiec nie
    potrzebuje pliku.
    """
    root = locale_dir()
    found = [SOURCE_LANGUAGE]
    for code in SUPPORTED:
        if code == SOURCE_LANGUAGE:
            continue
        if (root / code / 'LC_MESSAGES' / f'{DOMAIN}.mo').is_file():
            found.append(code)
    return tuple(code for code in SUPPORTED if code in found)


# --- Jezyk systemu ----------------------------------------------------------

def _windows_ui_languages() -> list[str]:
    """Jezyki INTERFEJSU Windows, w kolejnosci preferencji uzytkownika.

    `GetUserPreferredUILanguages` z flaga `MUI_LANGUAGE_NAME` (0x8) wypelnia
    bufor nazwami w rodzaju `pl-PL\\0en-US\\0\\0`. To jedyne zrodlo, ktore
    mowi o jezyku INTERFEJSU; `QLocale.system()` i `locale.getlocale()`
    zwracaja format regionalny i potrafia sie z nim rozjechac.
    """
    try:
        import ctypes
        from ctypes import wintypes

        MUI_LANGUAGE_NAME = 0x8
        count = wintypes.ULONG()
        size = wintypes.ULONG()
        kernel32 = ctypes.windll.kernel32
        if not kernel32.GetUserPreferredUILanguages(
                MUI_LANGUAGE_NAME, ctypes.byref(count), None, ctypes.byref(size)):
            return []
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel32.GetUserPreferredUILanguages(
                MUI_LANGUAGE_NAME, ctypes.byref(count), buffer, ctypes.byref(size)):
            return []
        raw = buffer[:size.value]
    except (AttributeError, OSError, ValueError) as e:      # noqa: BLE001
        log.info('nie udalo sie odczytac jezykow interfejsu Windows: %s', e)
        return []
    return [part for part in raw.split('\x00') if part]


def _posix_languages() -> list[str]:
    """Kolejnosc konwencjonalna dla gettext poza Windows."""
    for name in ('LANGUAGE', 'LC_ALL', 'LC_MESSAGES', 'LANG'):
        value = (os.environ.get(name) or '').strip()
        if value and value not in ('C', 'POSIX'):
            return [part for part in value.replace(':', ' ').split() if part]
    return []


def system_languages() -> list[str]:
    """Jezyki systemu jako gole kody (`['pl', 'en']`), bez powtorzen."""
    raw = _windows_ui_languages() if sys.platform == 'win32' else _posix_languages()
    codes: list[str] = []
    for item in raw:
        code = str(item).replace('_', '-').split('.')[0].split('-')[0].lower()
        if code and code not in codes:
            codes.append(code)
    return codes


def resolve(code: str) -> str:
    """Zamienia ustawienie (`auto`/`pl`/`en`/`de`) na konkretny jezyk."""
    wanted = str(code or '').strip().lower()
    available = available_languages()
    if wanted and wanted != AUTO:
        return wanted if wanted in available else SOURCE_LANGUAGE
    forced = (os.environ.get(LANGUAGE_ENV) or '').strip().lower()
    if forced and forced in available:
        return forced
    for candidate in system_languages():
        if candidate in available:
            return candidate
    return SOURCE_LANGUAGE


# --- Przelaczanie -----------------------------------------------------------

def set_language(code: str = AUTO) -> str:
    """Ustawia jezyk interfejsu. Zwraca kod, ktory faktycznie obowiazuje.

    Wywolanie jest tanie i bezpieczne w kazdym momencie: `gettext` i
    `ngettext` siegaja po AKTUALNY katalog przy kazdym wywolaniu, wiec
    napisy skladane po tej zmianie sa juz w nowym jezyku. Napisy wstrzykniete
    wczesniej w konstruktory widgetow zostaja stare — dlatego Ustawienia
    mowia wprost, ze pelna zmiana wymaga ponownego uruchomienia.
    """
    global _translation, _current, _initialised
    language = resolve(code)
    if language == SOURCE_LANGUAGE:
        _translation = _gettext.NullTranslations()
    else:
        try:
            _translation = _gettext.translation(
                DOMAIN, localedir=str(locale_dir()), languages=[language])
        except (OSError, ValueError) as e:       # noqa: BLE001
            log.warning('brak katalogu tlumaczen dla %s: %s', language, e)
            _translation = _gettext.NullTranslations()
            language = SOURCE_LANGUAGE
    _current = language
    _initialised = True
    _apply_formats(language)
    return language


def _apply_formats(language: str) -> None:
    """Przekazuje format daty do `beatcore`.

    `beatcore` jest lustrem `apps/beat/core.py` i NIE IMPORTUJE niczego
    z pakietu — dlatego format wstawiamy tu, z zewnatrz, zamiast dokladac
    tam import, ktory rozjechalby oba pliki.
    """
    from . import beatcore
    beatcore.DATETIME_FORMAT = datetime_format(language)


def current_language() -> str:
    """Kod jezyka, ktory obowiazuje teraz."""
    if not _initialised:
        set_language(AUTO)
    return _current


def language_choices() -> list[tuple[str, str]]:
    """Pary (wartosc ustawienia, etykieta) do listy w Ustawieniach."""
    choices = [(AUTO, gettext('Same as system'))]
    choices += [(code, LANGUAGE_NAMES.get(code, code))
                for code in available_languages()]
    return choices


# --- Tlumaczenie ------------------------------------------------------------

def gettext(message: str) -> str:
    """Tlumaczy napis. Brak tlumaczenia = zwraca `msgid` (angielski)."""
    if not _initialised:
        set_language(AUTO)
    return _translation.gettext(message)              # i18n: skip


def ngettext(singular: str, plural: str, n: int) -> str:
    """Forma liczebnikowa wedlug regul JEZYKA, nie wedlug angielskich dwoch.

    Polski ma trzy formy (one/few/many) i wybiera je regula z naglowka
    `Plural-Forms` katalogu — identyczna z CLDR. Bez katalogu obowiazuje
    regula angielska (`n == 1`), co dla angielskiego jest poprawne.
    """
    if not _initialised:
        set_language(AUTO)
    return _translation.ngettext(singular, plural, n)  # i18n: skip


def mark(message: str) -> str:
    """Oznacza napis do wyciagniecia BEZ tlumaczenia go teraz.

    Uzywane tam, gdzie napis powstaje w czasie importu, a przetlumaczony
    ma byc dopiero przy uzyciu (odpowiednik `N_` w konwencji gettext).
    """
    return message


#: Skrot przyjety w calym kodzie — tak samo jak w Django i w GNU gettext.
_ = gettext
N_ = mark


# --- Formaty daty i liczby --------------------------------------------------

def _formats(language: str | None = None) -> dict[str, str]:
    code = language or current_language()
    return _FORMATS.get(code, _FORMATS[SOURCE_LANGUAGE])


def decimal_separator(language: str | None = None) -> str:
    """Separator dziesietny: przecinek po polsku i niemiecku, kropka po angielsku."""
    return _formats(language)['decimal']


def date_format(language: str | None = None) -> str:
    return _formats(language)['date']


def short_date_format(language: str | None = None) -> str:
    """Dzien i miesiac, bez roku — do zakresu tygodnia."""
    return _formats(language)['date_short']


def datetime_format(language: str | None = None) -> str:
    return _formats(language)['datetime']


def format_iso_date(iso_day: object) -> str:
    """'2026-09-21' -> zapis daty w jezyku interfejsu.

    Warstwa prezentacji dla dat z `keys.py`. Sam `keys.py` zostaje czystym
    Pythonem bez importow z pakietu — jest ladowany ze sciezki pliku przez
    serwer i przez `apps/tsa/tests.py`, gdzie PySide6 ani reszta pakietu nie
    istnieja.
    """
    parts = str(iso_day or '').split('-')
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return str(iso_day or '')
    from datetime import date
    try:
        day = date(int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return str(iso_day or '')
    return day.strftime(date_format())

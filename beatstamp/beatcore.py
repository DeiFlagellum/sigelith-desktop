"""
Rdzen czasu @beat — konwersja UTC <-> beat. Zero I/O, zero sieci.

Port `apps/beat/core.py` (sciezka od katalogu glownego monorepo BeatTime;
wzgledem tego pliku: `../../apps/beat/core.py`). Trzymany
znak w znak zgodnie z serwerem, bo od tego zalezy, czy zegar w aplikacji
pokazuje to samo co beattime.live. Kazda rozbieznosc tutaj była by widoczna
dla uzytkownika jako "aplikacja klamie". Zgodnosc obu implementacji pilnuje
tests/test_server_parity.py (BeatCoreParityTests).

Model: doba = 1000 beatów, 1 beat = 86.4 s, kotwica w UTC (@000 = północ UTC,
@500 = południe UTC). Bez stref czasowych — @523 znaczy to samo wszedzie.
"""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

SECONDS_PER_DAY = 86_400
BEATS_PER_DAY = 1_000
SECONDS_PER_BEAT = SECONDS_PER_DAY / BEATS_PER_DAY  # 86.4 s

# Beat liczymy z CALKOWITYCH mikrosekund doby / 86_400_000, a nie przez
# dzielenie / 86.4 — 86.4 nie jest przedstawialne binarnie w double, wiec przy
# floor centibeat spadalby o jeden na granicach (00:21:36 to dokladnie @015.00,
# a /86.4 dawalo 14.99).
MICROSECONDS_PER_BEAT = 86_400_000


def _as_utc(dt: datetime) -> datetime:
    """Zwraca dt jako aware-UTC. Naive traktujemy jako UTC (kontrakt API)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def beats_from_utc(dt: datetime) -> float:
    """Dokladny czas beat w [0, 1000) dla podanej chwili."""
    dt = _as_utc(dt)
    us_of_day = (
        (dt.hour * 3600 + dt.minute * 60 + dt.second) * 1_000_000 + dt.microsecond
    )
    return (us_of_day / MICROSECONDS_PER_BEAT) % BEATS_PER_DAY


def beats_from_unix(unix_seconds: float) -> float:
    """Czas beat z uniksowego znacznika (sekundy, moga mieć ulamek)."""
    us_of_day = round((unix_seconds % SECONDS_PER_DAY) * 1_000_000)
    return (us_of_day / MICROSECONDS_PER_BEAT) % BEATS_PER_DAY


def format_beat(beats: float, *, decimals: int = 0) -> str:
    """
    Formatuje do '@NNN' (decimals=0) lub '@NNN.dd' (centibeaty, decimals=2).

    Ucinamy (floor), NIE zaokraglamy: zaokraglenie 999.6 daloby '@1000', co
    jest nieprawidlowe (powinno owinac do @000).
    """
    if decimals < 0:
        # Komunikat znak w znak jak w `apps/beat/core.py` — to jest blad
        # programisty (zla wartosc argumentu), nigdy tekst dla uzytkownika,
        # wiec NIE idzie przez katalog tlumaczen.
        raise ValueError('decimals musi byc >= 0')
    beats = beats % BEATS_PER_DAY
    factor = 10 ** decimals
    truncated = math.floor(beats * factor) / factor
    width = 3 + (decimals + 1 if decimals else 0)
    return f'@{truncated:0{width}.{decimals}f}'


def beat_to_seconds_of_day(beats: float) -> float:
    """Odwrotnosc: ile sekund po polnocy UTC odpowiada danemu beatowi."""
    return (beats % BEATS_PER_DAY) * SECONDS_PER_BEAT


def beat_to_utc(beats: float, day: datetime) -> datetime:
    """Dla danego beatu i daty zwraca konkretna chwilę UTC tego dnia."""
    day = _as_utc(day)
    midnight = day.replace(hour=0, minute=0, second=0, microsecond=0)
    us = round((beats % BEATS_PER_DAY) * MICROSECONDS_PER_BEAT)
    return midnight + timedelta(microseconds=us)


# --- Warstwa prezentacji ----------------------------------------------------
#
# Ten modul jest lustrem `apps/beat/core.py` i CELOWO nie importuje niczego
# z pakietu (`tests/test_server_parity.py` laduje go obok kodu serwera).
# Dlatego format daty nie jest tu czytany z `i18n`, tylko USTAWIANY z zewnatrz:
# `i18n.set_language` podmienia `DATETIME_FORMAT` przy kazdej zmianie jezyka.
# Wartosc domyslna odpowiada zapisowi polskiemu i niemieckiemu.

#: Zapis czasu lokalnego. Podmieniane przez `i18n._apply_formats`.
DATETIME_FORMAT = '%d.%m.%Y, %H:%M:%S'


def parse_iso_utc(value: str) -> datetime | None:
    """Parsuje znacznik z API ('...Z' albo '...+00:00'). None gdy się nie da.

    `datetime.fromisoformat` przyjmuje 'Z' dopiero od Pythona 3.11; podmiana
    jest i tak potrzebna, bo serwer wysyla oba warianty zamiennie.
    """
    if not value:
        return None
    try:
        return _as_utc(datetime.fromisoformat(str(value).replace('Z', '+00:00')))
    except (TypeError, ValueError):
        return None


def local_str(dt: datetime | None, fmt: str | None = None) -> str:
    """Czas lokalny uzytkownika, po ludzku: '12.09.2026, 09:10:42'."""
    if dt is None:
        return '—'
    try:
        return _as_utc(dt).astimezone().strftime(fmt or DATETIME_FORMAT)
    except (OSError, OverflowError, ValueError):
        # Windows nie przelicza na czas lokalny dat sprzed 1970 i bardzo
        # odleglych (OSError 22). Z pliku albo z serwera moze przyjsc kazda —
        # pokazujemy wtedy UTC zamiast okna bledu przy kazdym odswiezeniu.
        return _as_utc(dt).strftime(fmt or DATETIME_FORMAT) + ' UTC'


def utc_offset_label(dt: datetime | None = None) -> str:
    """Przesuniecie czasu lokalnego wzgledem UTC: 'UTC+2', 'UTC-3:30', 'UTC'.

    Liczone dla KONKRETNEJ chwili, bo czas letni zmienia je dwa razy w roku:
    stempel z lipca ma w Polsce UTC+2, a z grudnia UTC+1.
    """
    moment = _as_utc(dt) if dt is not None else datetime.now(timezone.utc)
    offset = moment.astimezone().utcoffset() or timedelta(0)
    minutes = int(offset.total_seconds() // 60)
    if minutes == 0:
        return 'UTC'
    sign = '+' if minutes > 0 else '-'
    hours, rest = divmod(abs(minutes), 60)
    return f'UTC{sign}{hours}' + (f':{rest:02d}' if rest else '')


def zone_suffix(dt: datetime | None) -> str:
    """' (UTC+2)' do dopisania za czasem lokalnym; '' gdy brak chwili."""
    return f' ({utc_offset_label(dt)})' if dt is not None else ''


def utc_str(dt: datetime | None) -> str:
    """Czas UTC w formie kanonicznej, sekundowej."""
    if dt is None:
        return '—'
    return _as_utc(dt).isoformat(timespec='seconds').replace('+00:00', 'Z')

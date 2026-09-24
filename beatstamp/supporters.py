"""
Lista podziekowan: pobranie z beattime.live, walidacja i pamiec podreczna.

Kontrakt endpointu `GET /api/supporters/thanks` pilnuje po stronie serwera
`apps/support/tests_desktop_contract.py`:

    {"v": 1, "updated": "<ISO 8601>" | null, "names": ["…", …]}

Trzy zasady, ktore ten modul egzekwuje po stronie aplikacji.

**Odpowiedz serwera to DANE NIEZAUFANE.** BeatStamp jest zainstalowany
u ludzi i nie aktualizuje sie razem z serwerem, wiec musi przezyc kazda
odpowiedz: obca (DNS, proxy, firma z inspekcja TLS), zepsuta (blad wdrozenia)
i zlosliwa. Sprawdzamy wiec KSZTALT (typy pol, wersje kontraktu), tniemy
LICZBE nazw i DLUGOSC kazdej, i usuwamy znaki, ktore w wierszu listy nie
reprezentuja zadnej litery (sterujace, zero-width, przestawiajace kierunek
tekstu, Zalgo). Nazwa idzie potem do widgetu tekstu ZWYKLEGO, a kazda
podpowiedz przez `widgets.plain_tooltip` — nic z sieci nie ma prawa trafic
do parsera tekstu wzbogaconego Qt.

**Usuniecie nazwy na stronie musi zniknac takze w aplikacji.** Zgoda ze
strony (`apps/support/consent.py`: APP_THANKS) obiecuje „moge wycofac
zgode w kazdej chwili". Gdyby aplikacja trzymala liste w nieskonczonosc,
obietnica bylaby nieprawdziwa dokladnie u tych osob, ktore juz sie wypisaly.
Dlatego pamiec podreczna ma TWARDY termin waznosci (`CACHE_MAX_AGE_SECONDS`
= doba): starsza NIE JEST POKAZYWANA — nawet bez sieci. Odswiezenie
proponujemy po godzinie, czyli po `Cache-Control: max-age=3600` endpointu.

**Nazw nie ma w instalatorze.** Zadna nazwa nie jest wbudowana w program ani
w paczke MSIX; jedynym miejscem, gdzie lezy kopia, jest plik w katalogu
danych uzytkownika, ktory sam sie przeterminowuje.
"""
from __future__ import annotations

import json
import logging
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .api import ApiError
from .config import app_data_dir, write_atomic
from .i18n import _

log = logging.getLogger(__name__)

#: Wersja kontraktu, ktora ta wersja programu umie przeczytac. Dopisanie pol
#: jest wstecznie zgodne (serwer nie podbija `v`); zmiana typu albo znikniecie
#: pola — nie, i wtedy `v` rosnie, a my mowimy o tym wprost zamiast zgadywac.
CONTRACT_VERSION = 1

#: Sufit liczby nazw. Lista jest krotka z natury; tysiac wierszy w oknie to
#: albo blad serwera, albo cudza odpowiedz — w obu przypadkach nie ma powodu
#: budowac z niej widgetu.
MAX_NAMES = 500

#: Sufit dlugosci jednej nazwy. Tyle samo dopuszcza serwer
#: (`apps/support/names.py: MAX_LEN`); dluzsza nazwa nie pochodzi z formularza.
MAX_NAME_LENGTH = 40

#: Sufit znakow laczacych na JEDEN znak bazowy — ten sam, co w `names.py`.
#: Bez niego nazwa zlozona z dziesiatek znakow laczacych (Zalgo) rozpycha
#: wiersz listy w pionie.
MAX_MARKS = 3

#: Kategorie Unicode, ktore nie reprezentuja zadnej widocznej litery:
#: sterujace, formatujace (zero-width, znaczniki kierunku tekstu), surogaty,
#: prywatne i nieprzypisane.
_INVISIBLE_CATEGORIES = frozenset({'Cc', 'Cf', 'Cs', 'Co', 'Cn'})
_MARK_CATEGORIES = frozenset({'Mn', 'Me'})

#: Plik z kopia listy w katalogu danych uzytkownika.
CACHE_NAME = 'supporters.json'
CACHE_VERSION = 1

#: Kopia starsza niz doba nie jest pokazywana (patrz naglowek modulu).
CACHE_MAX_AGE_SECONDS = 24 * 3600

#: Po tym czasie proponujemy odswiezenie — tyle, ile `Cache-Control` endpointu.
CACHE_FRESH_SECONDS = 3600

#: Zapas na przestawiony zegar. Kopia „z przyszlosci" (zegar cofniety po
#: zapisie) nie moze zyc wiecznie tylko dlatego, ze jej wiek wychodzi ujemny.
CLOCK_SKEW_TOLERANCE_SECONDS = 300


@dataclass(frozen=True)
class ThanksList:
    """Zwalidowana lista podziekowan razem z chwila jej pobrania."""

    names: tuple[str, ...] = ()
    #: `updated` z serwera (ISO 8601) albo '' — pole informacyjne, nigdy
    #: warunek czegokolwiek. Pusta lista nie ma `updated` w ogole.
    updated: str = ''
    #: Czas lokalny (unix) pobrania. Sluzy TYLKO terminowi waznosci kopii.
    fetched_at: float = 0.0
    #: Czy serwer przyslal wiecej nazw, niz pokazujemy.
    truncated: bool = False

    @property
    def age_seconds(self) -> float:
        return time.time() - self.fetched_at

    @property
    def expired(self) -> bool:
        """Czy kopii NIE WOLNO juz pokazac (doba albo zegar z przyszlosci)."""
        age = self.age_seconds
        return age >= CACHE_MAX_AGE_SECONDS or age < -CLOCK_SKEW_TOLERANCE_SECONDS

    @property
    def stale(self) -> bool:
        """Czy wypada odpytac serwer (godzina `Cache-Control` albo wiecej)."""
        return self.expired or self.age_seconds >= CACHE_FRESH_SECONDS


# --- Walidacja --------------------------------------------------------------

def clean_name(raw: object) -> str:
    """Nazwa gotowa do pokazania albo '' (gdy nic sensownego nie zostalo).

    Kolejnosc ma znaczenie: najpierw znikaja znaki niewidoczne (inaczej
    nabijalyby dlugosc i pozwalaly przemycic 40 znakow „pustej" nazwy),
    potem nadmiarowe znaki laczace, na koncu biale znaki i sufit dlugosci.
    """
    if not isinstance(raw, str):
        return ''
    visible: list[str] = []
    marks = 0
    for char in raw:
        category = unicodedata.category(char)
        if category in _INVISIBLE_CATEGORIES:
            # Podzial wiersza i tabulacja to tez znaki sterujace, ale niosa
            # odstep — bez tego „Anna\nMaria" skleilo by sie w „AnnaMaria".
            if char.isspace():
                visible.append(' ')
            continue
        if category in _MARK_CATEGORIES:
            marks += 1
            if marks > MAX_MARKS:
                continue
        else:
            marks = 0
        visible.append(char)
    text = ' '.join(''.join(visible).split())
    if len(text) > MAX_NAME_LENGTH:
        text = text[:MAX_NAME_LENGTH].rstrip() + '…'
    return text


def _clean_names(raw: object) -> tuple[tuple[str, ...], bool]:
    """(nazwy, czy_obcieto). Wpis, ktory nie jest napisem, po prostu znika."""
    if not isinstance(raw, (list, tuple)):
        raise ApiError(_('The list of supporters came back in an unexpected '
                         'format.'))
    names: list[str] = []
    truncated = False
    dropped = 0
    for item in raw:
        if len(names) >= MAX_NAMES:
            truncated = True
            break
        name = clean_name(item)
        if name:
            names.append(name)
        else:
            dropped += 1
    if dropped:
        log.warning('lista podziekowan: pominieto %s nazw bez tresci', dropped)
    if truncated:
        log.warning('lista podziekowan: serwer przyslal wiecej niz %s nazw',
                    MAX_NAMES)
    return tuple(names), truncated


def _clean_updated(raw: object) -> str:
    """Znacznik `updated` albo '' — pole informacyjne nie psuje calej listy."""
    if not isinstance(raw, str) or not raw.strip():
        return ''
    text = raw.strip()[:40]
    try:
        datetime.fromisoformat(text.replace('Z', '+00:00'))
    except ValueError:
        log.info('lista podziekowan: nieczytelna data zmiany — pomijam')
        return ''
    return text


def parse(payload: object, *, fetched_at: float | None = None) -> ThanksList:
    """Zamienia odpowiedz serwera na `ThanksList`. Kazdy blad to `ApiError`.

    Pusta lista jest POPRAWNA odpowiedzia, a nie bledem: dopoki wlasciciel
    nie wlaczy flagi `SUPPORT_APP_THANKS_ENABLED`, endpoint oddaje
    `{"v": 1, "updated": null, "names": []}` — i dokladnie to okno ma pokazac.
    """
    if not isinstance(payload, dict):
        raise ApiError(_('The list of supporters came back in an unexpected '
                         'format.'))
    version = payload.get('v')
    if isinstance(version, bool) or not isinstance(version, int):
        raise ApiError(_('The list of supporters came back in an unexpected '
                         'format.'))
    if version != CONTRACT_VERSION:
        raise ApiError(_(
            'This version of BeatStamp cannot read the list of supporters '
            '(the server speaks version %(version)s). A newer version of the '
            'application can.') % {'version': version})
    names, truncated = _clean_names(payload.get('names'))
    return ThanksList(
        names=names,
        updated=_clean_updated(payload.get('updated')),
        fetched_at=time.time() if fetched_at is None else float(fetched_at),
        truncated=truncated,
    )


# --- Pamiec podreczna -------------------------------------------------------

def cache_path() -> Path:
    return app_data_dir() / CACHE_NAME


def save_cache(data: ThanksList) -> None:
    """Zapisuje kopie listy. Niepowodzenie nie jest bledem uzytkownika.

    Kopia to wygoda (okno pokazuje cos od razu), a nie dane, bez ktorych
    program nie dziala — dlatego brak prawa zapisu konczy sie wierszem
    w dzienniku, a nie komunikatem.
    """
    payload = {
        'v': CACHE_VERSION,
        'fetched_at': float(data.fetched_at),
        'updated': data.updated,
        'names': list(data.names),
    }
    try:
        write_atomic(cache_path(),
                     json.dumps(payload, indent=2,
                                ensure_ascii=False).encode('utf-8'))
    except OSError as e:
        log.info('lista podziekowan — nie udalo sie zapisac kopii: %s', e)


def load_cache() -> ThanksList | None:
    """Kopia listy albo `None`, gdy jej nie ma, jest zepsuta albo przeterminowana.

    Plik lezy w katalogu uzytkownika, wiec przechodzi PRZEZ TA SAMA walidacje
    co odpowiedz serwera. Uszkodzonej kopii nie odkladamy na bok jak historii
    (`history._quarantine`) — to dane do odtworzenia jednym zapytaniem, a nie
    jedyny slad po pracy uzytkownika.
    """
    path = cache_path()
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        log.info('lista podziekowan — kopia nieczytelna: %s', e)
        return None
    if not isinstance(raw, dict) or raw.get('v') != CACHE_VERSION:
        return None
    try:
        fetched_at = float(raw.get('fetched_at') or 0.0)
    except (TypeError, ValueError):
        return None
    try:
        names, truncated = _clean_names(raw.get('names'))
    except ApiError:
        log.info('lista podziekowan — kopia ma zly ksztalt, pomijam')
        return None
    data = ThanksList(names=names, updated=_clean_updated(raw.get('updated')),
                      fetched_at=fetched_at, truncated=truncated)
    if data.expired:
        log.info('lista podziekowan — kopia starsza niz doba, nie pokazuje jej')
        return None
    return data


def forget_cache() -> None:
    """Usuwa kopie listy (np. przy czyszczeniu danych). Bez wyjatkow."""
    try:
        cache_path().unlink(missing_ok=True)
    except OSError as e:
        log.info('lista podziekowan — nie udalo sie usunac kopii: %s', e)

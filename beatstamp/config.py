"""
Ścieżki i ustawienia aplikacji.

Naprawia bezposrednio dwie wady poprzednika:

1. `HISTORY_FILE = "history.json"` bylo ścieżka WZGLEDNA. W wersji exe katalog
   roboczy to miejsce, z którego uzytkownik akurat uruchomil program — historia
   rozsypywala się po dysku, a w `C:\\Program Files` zapis po prostu nie
   przechodzil (brak prawa zapisu) i ginal w cichym `except`.
2. Historia trafiala do repozytorium razem ze skrotami plików uzytkownika.

3. Dane w `%LOCALAPPDATA%` NIE PRZEZYWAJA odinstalowania paczki MSIX.
   Windows wirtualizuje kazdy NOWO utworzony plik w `AppData` do prywatnego,
   per-paczkowego magazynu i kasuje go razem z paczka. `write_atomic` tworzy
   nowy plik przy KAZDYM zapisie (mkstemp + os.replace), wiec historia stempli
   znikalaby przy odinstalowaniu ze Sklepu — bez ostrzezenia i bez sladu.

4. Katalog „Dokumenty" — pierwsza proba ucieczki z `AppData` — jest po stronie
   Windows folderem CHRONIONYM. „Kontrolowany dostep do folderow" (ochrona
   przed ransomware) blokuje w nim zapis kazdej aplikacji, ktorej Defender
   nie zna z rozpowszechnienia i reputacji; swiezo zbudowany plik `.exe` jest
   z definicji nieznany, a podpis ani obecnosc w Sklepie nic tu nie zmieniaja.
   Domyslna lista folderow chronionych jest przy tym NIEMODYFIKOWALNA
   (Dokumenty, Obrazy, Wideo, Muzyka, Ulubione i ich odpowiedniki w
   `C:\\Users\\Public`). Blokada nie zglasza sie jako odmowa dostepu:
   `tempfile.mkstemp` w `write_atomic` przewraca sie na `FileNotFoundError`,
   mimo ze katalog nadrzedny istnieje — patrz `looks_protected`.

Dane uzytkownika ida wiec POZA `AppData` i POZA katalogi chronione: na
Windows do `%USERPROFILE%\\Sigelith` (patrz `_default_data_dir`; do 2.2.0,
jeszcze jako BeatStamp, byl to `%USERPROFILE%\\BeatStamp` — dane stamtad
kopiuje jednorazowo `migrate_legacy_data`). Ta sama lokalizacja obowiazuje
w wersji ze Sklepu, w zwyklym `.exe` i w uruchomieniu ze zrodel: dzieki temu
instalacja ze Sklepu na maszynie, gdzie wczesniej chodzil zwykly `.exe`,
widzi te sama historie.

Obietnica z punktu 2 zostaje w mocy: skróty dokumentow nie moga same wedrowac
miedzy maszynami. Korzen profilu nie jest objety ani OneDrive Known Folder
Move (obejmuje Pulpit, Dokumenty, Obrazy), ani Kopia zapasowa Windows — o tej
drugiej stronie medalu (brak kopii w chmurze) interfejs mowi wprost.

ZADNA lokalizacja nie jest jednak gwarantowana na zawsze: uzytkownik albo
administrator moze dodac DOWOLNY folder do listy chronionej. Dlatego katalog
danych jest tu nie tylko wyliczany, ale i SPRAWDZANY (`probe_write`), a wybor
innego miejsca zapamietuje `remember_data_dir`.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from . import keys
from .i18n import _
from .onion import is_v3_url

log = logging.getLogger(__name__)

# --- Katalogi ---------------------------------------------------------------

#: Nazwa katalogu danych (`%USERPROFILE%\Sigelith`) i katalogu aplikacji
#: w `%LOCALAPPDATA%` — od 3.0.0, czyli od zmiany nazwy programu na Sigelith
#: Desktop (2026-09-27). Celowo krotka i BEZ „Desktop": to katalog danych
#: uzytkownika, ktory przezywa program i jego kolejne nazwy.
DATA_DIR_NAME = 'Sigelith'

#: Nazwa katalogow z czasow BeatStampa (do 2.2.0). Sluzy WYLACZNIE do
#: odnalezienia starych danych i starego wskaznika — program nic tam nie
#: zapisuje poza notatka `PRZENIESIONO.txt` i nigdy niczego stamtad nie kasuje.
LEGACY_DIR_NAME = 'BeatStamp'

#: Zmienna srodowiskowa wskazujaca katalog danych WPROST — pelna sciezka do
#: samego katalogu, nie do jego rodzica. Ma pierwszenstwo przed wszystkim.
#: Uzywaja jej: testy, `tools/verify_exe.py` i kazdy, kto chce trzymac dane
#: obok programu (wersja przenosna na pendrive).
DATA_DIR_ENV = 'SIGELITH_DATA_DIR'

#: Ta sama zmienna pod nazwa z czasow BeatStampa. Honorowana dalej — skrypt
#: albo skrot z wersja przenosna, ktory ja ustawia, nie moze po aktualizacji
#: po cichu zaczac pisac gdzie indziej. Nowa nazwa ma pierwszenstwo.
LEGACY_DATA_DIR_ENV = 'BEATSTAMP_DATA_DIR'

#: Kolejnosc sprawdzania: pierwsza NIEPUSTA zmienna rozstrzyga.
DATA_DIR_ENVS = (DATA_DIR_ENV, LEGACY_DATA_DIR_ENV)

#: Plik ze SCIEZKA do katalogu danych wybranego przez uzytkownika (Ustawienia
#: -> „Katalog danych" albo okno po zablokowanym zapisie). Nie moze lezec
#: w katalogu danych — jest wskaznikiem NA ten katalog i musi dac sie odczytac,
#: zanim wiadomo, gdzie on jest. Nie moze tez lezec w `settings.json` z tego
#: samego powodu: `settings.json` jest wewnatrz katalogu danych.
#:
#: Miejsce: `%LOCALAPPDATA%\Sigelith` (`app_local_dir`) — jedyny katalog,
#: ktory na Windows jest jednoczesnie wlasny dla aplikacji i POZA domyslna
#: lista folderow chronionych przez ochrone przed ransomware, czyli zapisywalny
#: dokladnie wtedy, gdy katalog danych zapisywalny nie jest. Paczka MSIX go
#: wirtualizuje i skasuje przy odinstalowaniu — to akceptowalna strata:
#: znika sam WSKAZNIK, a nie dane, i przy nastepnym starcie obowiazuje
#: lokalizacja domyslna (albo `SIGELITH_DATA_DIR`).
#:
#: Wybor zapisany przez BeatStampa lezy w `%LOCALAPPDATA%\BeatStamp`
#: (`legacy_location_file`) i jest dalej CZYTANY, dopoki nowego wskaznika nie
#: ma — uzytkownik, ktory przeniosl dane na inny dysk, nie wraca po
#: aktualizacji do pustej lokalizacji domyslnej.
LOCATION_FILE = 'katalog-danych.json'

#: Nazwa pliku probnego, ktorym sprawdzamy, czy w katalogu da sie ZAPISAC.
#: Kropka na poczatku: plik jest ukryty i nie miesza sie uzytkownikowi
#: z historia ani z ustawieniami.
PROBE_NAME = '.proba-zapisu'

#: Zwracane przez `GetCurrentPackageFullName`, gdy proces NIE dziala z paczki.
_APPMODEL_ERROR_NO_PACKAGE = 15700

#: `FOLDERID_Documents` — identyfikator katalogu „Dokumenty" w API Windows.
_FOLDERID_DOCUMENTS = '{FDD39AD0-238F-46AF-ADB4-6C85480369C7}'


def is_frozen() -> bool:
    """Czy kod dziala z pliku zbudowanego PyInstallerem (`.exe`)."""
    return getattr(sys, 'frozen', False)


def is_packaged() -> bool:
    """Czy proces dziala z paczki MSIX (wersja ze Sklepu).

    Dwa niezalezne sposoby, w kolejnosci wiarygodnosci:

    1. `GetCurrentPackageFullName` z `kernel32` — jedyna miarodajna odpowiedz.
       Poza paczka zwraca `APPMODEL_ERROR_NO_PACKAGE` (15700); w paczce
       zwraca `ERROR_INSUFFICIENT_BUFFER`, bo pytamy z pustym buforem.
    2. Zapasowo sciezka procesu: aplikacje z paczki leza w
       `C:\\Program Files\\WindowsApps\\<paczka>\\`. Potrzebne tam, gdzie
       pierwsza droga nie istnieje albo zawiodla.

    Sama lokalizacja danych od tego NIE zalezy — jest jedna dla obu trybow
    (patrz `app_data_dir`). Ta funkcja sluzy diagnostyce: wiersz w dzienniku
    „spakowany: True" natychmiast odrozni zgloszenie z wersji ze Sklepu od
    zgloszenia ze zwyklego `.exe`, a to dwa rozne swiaty uprawnien.
    """
    if sys.platform != 'win32':
        return False
    try:
        import ctypes
        length = ctypes.c_uint32(0)
        rc = ctypes.windll.kernel32.GetCurrentPackageFullName(ctypes.byref(length), None)
    except (AttributeError, OSError, ValueError):
        rc = None
    if rc is not None:
        return rc != _APPMODEL_ERROR_NO_PACKAGE
    try:
        parts = {part.lower() for part in Path(sys.executable).resolve().parts}
    except OSError:
        return False
    return 'windowsapps' in parts


def _windows_documents_dir() -> Path | None:
    """Katalog „Dokumenty" tak, jak widzi go system.

    Dzis sluzy WYLACZNIE do ODNALEZIENIA starych danych
    (`legacy_documents_data_dir`) — jako lokalizacja docelowa „Dokumenty"
    odpadly, bo sa folderem chronionym przez ochrone przed ransomware.

    Swiadomie NIE `Path.home() / 'Documents'`: ten katalog bywa przekierowany
    (zasady grupy, udzial sieciowy, przeniesienie na inny dysk, OneDrive
    Known Folder Move), a przy nieangielskim systemie ma inna nazwe.
    Zgadywanie po nazwie wskazuje wtedy miejsce, w ktorym niczego nie ma —
    i przeprowadzka po cichu nie znalazlaby danych uzytkownika.
    """
    try:
        import ctypes
        from ctypes import wintypes

        class _GUID(ctypes.Structure):
            _fields_ = [('Data1', wintypes.DWORD), ('Data2', wintypes.WORD),
                        ('Data3', wintypes.WORD), ('Data4', ctypes.c_ubyte * 8)]

        guid = _GUID()
        ctypes.oledll.ole32.CLSIDFromString(_FOLDERID_DOCUMENTS, ctypes.byref(guid))
        buffer = ctypes.c_wchar_p()
        ctypes.oledll.shell32.SHGetKnownFolderPath(
            ctypes.byref(guid), 0, None, ctypes.byref(buffer))
        try:
            value = buffer.value
        finally:
            ctypes.windll.ole32.CoTaskMemFree(buffer)
    except (AttributeError, OSError, ValueError):
        return None
    return Path(value) if value else None


def _onedrive_roots() -> list[Path]:
    """Korzenie OneDrive znane srodowisku (osobisty i firmowy)."""
    roots = []
    for name in ('OneDrive', 'OneDriveConsumer', 'OneDriveCommercial'):
        value = (os.environ.get(name) or '').strip()
        if value:
            roots.append(Path(value))
    return roots


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def is_inside_onedrive(path: Path) -> bool:
    """Czy sciezka lezy w jakims katalogu OneDrive tego uzytkownika.

    Nie decyduje juz o lokalizacji domyslnej (korzen profilu jest poza
    zasiegiem Known Folder Move), ale OSTRZEGA, gdy uzytkownik SAM wskaze
    katalog w chmurze. Historia to lista skrotow dokumentow razem z ich
    nazwami; znacznik czasu zestawiony z podejrzewanym plikiem POTWIERDZA, ze
    to wlasnie ten plik byl stemplowany i kiedy. Takie dane moga wedrowac
    miedzy maszynami tylko z decyzji uzytkownika — swiadomej, nie domyslnej.
    """
    return any(_is_inside(path, root) for root in _onedrive_roots())


def forced_data_dir() -> tuple[str, str]:
    """(nazwa zmiennej, wartosc) katalogu narzuconego z zewnatrz albo ('', '').

    Rozstrzyga pierwsza NIEPUSTA zmienna z `DATA_DIR_ENVS` — `SIGELITH_DATA_DIR`
    przed `BEATSTAMP_DATA_DIR`. Wartosc jest zwracana surowa (takze wzgledna):
    o jej przyjeciu decyduje `resolved_data_dir`, a o pominieciu przeprowadzki
    `migrate_legacy_data` — tak samo jak dotad dla jednej zmiennej.
    """
    for name in DATA_DIR_ENVS:
        value = (os.environ.get(name) or '').strip()
        if value:
            return name, value
    return '', ''


def _local_base() -> Path:
    """Katalog aplikacji lokalnych systemu (`%LOCALAPPDATA%` i odpowiedniki)."""
    if sys.platform == 'win32':
        base = os.environ.get('LOCALAPPDATA') or os.path.expanduser('~')
    elif sys.platform == 'darwin':
        base = os.path.expanduser('~/Library/Application Support')
    else:
        base = os.environ.get('XDG_DATA_HOME') or os.path.expanduser('~/.local/share')
    return Path(base)


def app_local_dir() -> Path:
    """`%LOCALAPPDATA%\\Sigelith` — miejsce wskaznika `LOCATION_FILE`.

    Na macOS i Linuksie jest to zarazem lokalizacja domyslna danych
    (`_default_data_dir`). Katalogu NIE tworzymy przy samym pytaniu o sciezke.
    """
    return _local_base() / DATA_DIR_NAME


def _default_data_dir() -> Path:
    """Domyslna lokalizacja danych — bez tworzenia czegokolwiek.

    Windows: `%USERPROFILE%\\Sigelith`, czyli `C:\\Users\\<kto>\\Sigelith`
    (do 2.2.0: `%USERPROFILE%\\BeatStamp` — ta sama logika, inna nazwa).
    Cztery warunki naraz, ktorych nie spelnia zadne inne miejsce:

    * **Poza lista folderow chronionych.** Ochrona przed ransomware
      („Kontrolowany dostep do folderow") chroni Dokumenty, Obrazy, Wideo,
      Muzyke i Ulubione — nie korzen profilu. W Dokumentach zapis konczyl sie
      u wlasciciela bledem przy KAZDYM stemplu.
    * **Poza `AppData`.** Paczka MSIX wirtualizuje nowe pliki w `AppData` do
      prywatnego magazynu paczki i kasuje je przy odinstalowaniu; tutaj nie,
      bo pelnozaufana aplikacja z paczki pisze w pozostalych czesciach
      `%USERPROFILE%` bez wirtualizacji i bez dodatkowych uprawnien.
    * **Widoczne.** Uzytkownik wchodzi do swojego profilu i widzi folder
      `Sigelith` — dowody da sie skopiowac na inny komputer w calosci,
      bez szukania.
    * **Poza chmura.** OneDrive Known Folder Move obejmuje Pulpit, Dokumenty
      i Obrazy; korzen profilu zostawia w spokoju.

    Korzen profilu jest w swiecie Windows sprawdzonym miejscem dla danych,
    ktore maja przetrwac: `.ssh`, `.gnupg`, `.gitconfig`, `.aws`. Nazwa jest
    celowo BEZ kropki na poczatku — folder ma byc widoczny, bo to jedyny
    sposob, zeby uzytkownik sam znalazl swoje dowody.

    macOS i Linux zostaja w katalogu aplikacji systemu (`app_local_dir`):
    MSIX tam nie istnieje, ochrony przed ransomware tez nie ma, wiec nie ma
    czego naprawiac. Zmienila sie tylko NAZWA katalogu (3.0.0) — dane
    z `.../BeatStamp` kopiuje jednorazowo `migrate_legacy_data`.
    """
    if sys.platform == 'win32':
        profile = os.environ.get('USERPROFILE') or os.path.expanduser('~')
        return Path(profile) / DATA_DIR_NAME
    return app_local_dir()


def location_file() -> Path:
    """Plik ze sciezka wybrana przez uzytkownika. Patrz `LOCATION_FILE`."""
    return app_local_dir() / LOCATION_FILE


def legacy_location_file() -> Path:
    """Wskaznik zapisany przez BeatStampa (do 2.2.0) — tylko do odczytu."""
    return legacy_app_data_dir() / LOCATION_FILE


def stored_data_dir() -> Path | None:
    """Katalog danych zapamietany po wyborze uzytkownika albo `None`.

    Kazdy blad — brak pliku, uszkodzony JSON, sciezka wzgledna, pusty napis —
    znaczy „nie ma wyboru" i sprowadza program do lokalizacji domyslnej.
    Wskaznik nie moze byc powodem, dla ktorego program sie nie uruchamia.

    Gdy nowego wskaznika NIE MA, czytamy wybor zapisany przez BeatStampa
    (`legacy_location_file`). Nowy wskaznik — takze pusty, zapisany przy
    powrocie do lokalizacji domyslnej — ma zawsze pierwszenstwo; starego
    pliku nie zmieniamy nigdy.
    """
    path = location_file()
    try:
        exists = path.is_file()
    except OSError:
        exists = False
    if not exists:
        path = legacy_location_file()
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    value = raw.get('katalog') if isinstance(raw, dict) else None
    if not isinstance(value, str) or not value.strip():
        return None
    chosen = Path(value.strip()).expanduser()
    if not chosen.is_absolute():
        log.warning('zapamietany katalog danych %r nie jest sciezka bezwzgledna '
                    '— pomijam', value)
        return None
    return chosen


def remember_data_dir(path: Path | None) -> bool:
    """Zapamietuje wybor uzytkownika (`None` = powrot do domyslnego).

    Zwraca, czy sie udalo. Niepowodzenie NIE jest bledem krytycznym: wybrany
    katalog dziala do konca sesji, tyle ze nastepny start wroci do
    domyslnego — i o tym interfejs mowi wprost.
    """
    target = location_file()
    try:
        if path is None:
            target.unlink(missing_ok=True)
            # Wybor BeatStampa w starym miejscu wrocilby przy nastepnym
            # odczycie (`stored_data_dir`). Starego pliku nie ruszamy —
            # przyslaniamy go jawnie pustym wyborem.
            if legacy_location_file().is_file():
                write_atomic(target, json.dumps({
                    'katalog': '',
                    'zapisano_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                }, indent=2, ensure_ascii=False).encode('utf-8'))
            return True
        write_atomic(target, json.dumps({
            'katalog': str(path),
            'zapisano_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        }, indent=2, ensure_ascii=False).encode('utf-8'))
    except OSError as e:
        log.warning('nie udalo sie zapamietac katalogu danych w %s: %s', target, e)
        return False
    return True


def resolved_data_dir() -> Path:
    """Katalog danych — sama sciezka, BEZ tworzenia katalogu.

    Kolejnosc: zmienna `SIGELITH_DATA_DIR` albo — zapasowo — dawna
    `BEATSTAMP_DATA_DIR` (wskazuje katalog wprost, `forced_data_dir`), potem
    wybor zapamietany przez uzytkownika (`LOCATION_FILE`), potem lokalizacja
    domyslna dla systemu.

    Zmienna srodowiskowa jest PRZED wyborem uzytkownika celowo: uzywaja jej
    testy, `tools/verify_exe.py` i wersja przenosna z pendrive'a, czyli
    sytuacje, w ktorych katalog ma byc narzucony z zewnatrz na jedno
    uruchomienie i nie ma prawa zalezec od tego, co ktos kiedys kliknal.

    Sciezka WZGLEDNA w tej zmiennej jest odrzucana. To dokladnie wada numer 1
    z naglowka modulu: katalog roboczy to miejsce, z ktorego uzytkownik akurat
    uruchomil program, wiec historia rozsypywalaby sie po dysku. Przyjecie
    takiej wartosci przywrocilby usterke, ktora ten plik naprawia.
    """
    name, override = forced_data_dir()
    if override:
        path = Path(override).expanduser()
        if path.is_absolute():
            return path
        log.warning('%s musi byc sciezka bezwzgledna — pomijam wartosc %r',
                    name, override)
    chosen = stored_data_dir()
    if chosen is not None:
        return chosen
    return _default_data_dir()


def legacy_app_data_dir() -> Path:
    """PIERWSZA stara lokalizacja danych (`%LOCALAPPDATA%\\BeatStamp`).

    Zrodlo przeprowadzki (`migrate_legacy_data`) i miejsce STAREGO wskaznika
    (`legacy_location_file`). Katalogu celowo NIE tworzymy przy samym
    pytaniu o sciezke: sprawdzenie „czy jest co przenosic" nie ma prawa
    zostawic po sobie pustego katalogu w miejscu, ktore wlasnie opuszczamy.

    Na macOS i Linuksie byla to lokalizacja domyslna BeatStampa — tam jest
    jedynym zrodlem przeprowadzki do `.../Sigelith`.
    """
    return _local_base() / LEGACY_DIR_NAME


def legacy_profile_data_dir() -> Path | None:
    """TRZECIA stara lokalizacja (`%USERPROFILE%\\BeatStamp`) albo `None`.

    Domyslna lokalizacja BeatStampa 2.2.0 — ta sama logika co dzisiejszy
    `%USERPROFILE%\\Sigelith`, tylko pod stara nazwa programu. U kazdego,
    kto uzywal wersji 2.2, leza tu PRAWDZIWE dane (historia, ustawienia,
    stan swiadka), wiec to pelnoprawne, NAJSWIEZSZE zrodlo przeprowadzki.
    Poza Windows nie istniala (tam domyslny byl `legacy_app_data_dir`).
    """
    if sys.platform != 'win32':
        return None
    profile = os.environ.get('USERPROFILE') or os.path.expanduser('~')
    return Path(profile) / LEGACY_DIR_NAME


def legacy_documents_data_dir() -> Path | None:
    """DRUGA stara lokalizacja danych (`Dokumenty\\BeatStamp`) albo `None`.

    Krotki, ale prawdziwy epizod w historii tego programu: dane wyprowadzono
    z `AppData` wlasnie tutaj, zeby przetrwaly odinstalowanie paczki MSIX —
    i dopiero na maszynie z wlaczona ochrona przed ransomware okazalo sie, ze
    w Dokumentach nie da sie zapisywac. Na dyskach uzytkownikow, ktorzy zdazyli
    ostemplowac cokolwiek w tym okresie, leza tam PRAWDZIWE dane, wiec to
    pelnoprawne zrodlo przeprowadzki, a nie sprzatanie po sobie.

    Katalog czytamy nawet wtedy, gdy ochrona jest wlaczona: „Kontrolowany
    dostep do folderow" blokuje ZAPIS i USUWANIE, nie odczyt.
    """
    if sys.platform != 'win32':
        return None
    documents = _windows_documents_dir()
    return None if documents is None else documents / LEGACY_DIR_NAME


def data_dir_for_choice(chosen: Path) -> Path:
    """Folder wskazany w oknie wyboru -> katalog danych aplikacji.

    Uzytkownik wskazuje MIEJSCE (na przyklad `D:\\Dane`), a nie katalog
    aplikacji. Wysypanie `history.json`, `settings.json` i dziennika wprost
    do wskazanego folderu byloby niegrzeczne w katalogu z wlasnymi plikami
    i szkodliwe w korzeniu dysku, wiec dokladamy podkatalog `Sigelith` —
    chyba ze uzytkownik wskazal juz katalog danych (`Sigelith` albo dawny
    `BeatStamp`, czyli najczesciej poprzedni katalog przeniesiony recznie).
    """
    chosen = Path(chosen)
    if chosen.name in (DATA_DIR_NAME, LEGACY_DIR_NAME):
        return chosen
    return chosen / DATA_DIR_NAME


def _reject_constant(name: str):
    raise ValueError(f'non-finite number in JSON: {name}')


def _finite_float(text: str) -> float:
    value = float(text)
    if value != value or value in (float('inf'), float('-inf')):
        raise ValueError(f'non-finite number in JSON: {text[:20]}')
    return value


def json_loads(text):
    """`json.loads` bez NaN/Infinity i bez przepelnienia stosu — wszystko jako ValueError.

    `Infinity` albo `1e999` w polu liczbowym dawaly OverflowError przy `int()`,
    a gleboko zagniezdzona tablica — RecursionError. Oba spoza (OSError,
    ValueError), ktore lapia loadery, wiec jeden zepsuty plik (ustawienia,
    historia, stan swiadka, .beatproof) albo odpowiedz serwera wywracaly
    program zamiast skonczyc sie komunikatem (fuzzing 2026-09-27).
    """
    try:
        return json.loads(text, parse_constant=_reject_constant, parse_float=_finite_float)
    except RecursionError as e:
        raise ValueError('JSON nested too deeply') from e


def app_data_dir() -> Path:
    """Katalog na dane uzytkownika. Tworzony przy pierwszym uzyciu.

    Nigdy nie rzuca wyjatku: brak prawa zapisu albo niedostepny udzial
    sieciowy konczy sie wpisem w dzienniku i zwroceniem sciezki mimo wszystko.
    Program dziala dalej (historia i ustawienia wracaja do wartosci
    domyslnych), zamiast gasnac przy starcie — a zapis, ktory naprawde ma
    znaczenie, zglosi blad sam.

    Sciezka NIE jest zapamietywana miedzy wywolaniami: testy podmieniaja
    zmienne srodowiskowe juz po zaimportowaniu modulu.
    """
    path = resolved_data_dir()
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        log.error('katalog danych %s jest niedostepny: %s', path, e)
    return path


def resource_path(relative: str) -> Path:
    """Ścieżka do zasobu — działa tak samo ze zrodel i z jednoplikowego exe.

    PyInstaller w trybie onefile rozpakowuje zasoby do katalogu tymczasowego
    i podaje go w `sys._MEIPASS`.
    """
    base = getattr(sys, '_MEIPASS', None)
    return Path(base) / relative if base else Path(__file__).resolve().parent.parent / relative


def history_path() -> Path:
    return app_data_dir() / 'history.json'


def settings_path() -> Path:
    return app_data_dir() / 'settings.json'


def handover_dir() -> Path:
    """Stan Sigelith Handover: karty, kontakty, przesylki (handover_app/store.py)."""
    return app_data_dir() / 'handover'


def default_handover_downloads() -> Path:
    """Pliki z otwartych przesylek, gdy uzytkownik nie wybral innego folderu."""
    return Path.home() / 'Downloads' / 'Sigelith'


#: Dziennik zdarzen w katalogu danych. Do 2.2.0 `beatstamp.log` — dziennika
#: przeprowadzka nie przenosi (`MIGRATED_NAMES`), wiec stara nazwa nie ma tu
#: czego szukac; stary plik zostaje w starym katalogu.
LOG_NAME = 'sigelith.log'
#: Zrzut awaryjny `faulthandler` (`__main__.enable_crash_dump`) obok dziennika.
CRASH_LOG_NAME = 'sigelith-crash.log'


def log_path() -> Path:
    return app_data_dir() / LOG_NAME


# --- Zapis atomowy ----------------------------------------------------------


def write_atomic(path: Path, data: bytes) -> None:
    """Zapis "wszystko albo nic": plik tymczasowy obok + zamiana nazwy.

    Poprzednik pisal historie przez zwykly `open(..., 'w')`, który najpierw
    OBCINA plik do zera. Przerwanie w tym momencie (zanik zasilania, zabicie
    procesu, pełny dysk) zostawialo plik pusty albo urwany w polowie — a przy
    nastepnym starcie `except: pass` uznawal go za brak historii i nadpisywal
    JEDNYM wpisem. Cala historia znikala bez sladu.

    `os.replace` jest na Windows i POSIX operacja atomowa w obrebie wolumenu:
    albo widac stara zawartość, albo cala nowa. Nigdy nic posrodku.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + '.', suffix='.tmp')
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())  # bajty na talerzu, nie tylko w cache OS
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


# --- Zablokowany zapis ------------------------------------------------------


def looks_protected(directory: Path, error: OSError) -> bool:
    """Czy ten blad zapisu wyglada na blokade systemowa, a nie na brak dysku.

    PULAPKA, dla ktorej ta funkcja istnieje: „Kontrolowany dostep do folderow"
    NIE zglasza sie jako `PermissionError`. `tempfile.mkstemp` w
    `write_atomic` przewraca sie na `FileNotFoundError` — „No such file or
    directory" dla pliku tymczasowego w katalogu, ktory ISTNIEJE i ktory widac
    w Eksploratorze. Kod lapiacy sam `PermissionError` nie wykryje wiec
    niczego, a uzytkownik zobaczy slad wyjatku mowiacy o brakujacym pliku,
    ktorego nigdy nie bylo.

    Regula jest wiec dwuczlonowa:

    * `PermissionError` — odmowa wprost (uprawnienia NTFS, plik zajety,
      czesc blokad antywirusowych);
    * `FileNotFoundError` MIMO ISTNIEJACEGO katalogu nadrzednego — podpis
      ochrony przed ransomware. Gdy katalogu naprawde nie ma (odlaczony dysk
      wymienny, zniknal udzial sieciowy), warunek nie zachodzi i komunikat
      mowi o czym innym.
    """
    if isinstance(error, PermissionError):
        return True
    if isinstance(error, FileNotFoundError):
        try:
            return directory.is_dir()
        except OSError:
            return False
    return False


@dataclass(frozen=True)
class WriteProblem:
    """Nieudany zapis do katalogu danych, opisany po ludzku.

    Powstaje w jednym miejscu (`describe_write_problem`), zeby ten sam
    komunikat obowiazywal przy starcie, przy stemplowaniu i przy zapisie
    ustawien — i zeby dalo sie go sprawdzic testem bez uruchamiania okna.
    """

    directory: Path
    reason: str                  # opis od systemu, do wiersza „szczegoly"
    protected: bool              # blokada (ransomware/uprawnienia), nie brak miejsca

    @property
    def title(self) -> str:
        return _('Sigelith Desktop cannot save data')

    @property
    def message(self) -> str:
        """Co sie stalo, dlaczego i jakie sa wyjscia — bez zargonu."""
        if self.protected:
            return _(
                'Windows is blocking writes to this folder:\n'
                '%(path)s\n\n'
                'This is almost always ransomware protection in Windows '
                'Security ("Controlled folder access"). It lets only '
                'applications it already knows write to folders such as '
                'Documents, Pictures or Videos — a newly installed program is '
                'not one of them yet.\n\n'
                'There are two ways out: allow Sigelith Desktop in the Windows '
                'ransomware protection settings, or pick another folder for '
                'the data. Nothing is deleted either way — whatever is already '
                'in the old folder stays there.') % {'path': self.directory}
        return _(
            'The data folder does not accept writes:\n'
            '%(path)s\n\n'
            'What the system reports: %(reason)s\n\n'
            'Pick another folder for the data — nothing is deleted, whatever '
            'is already in the old folder stays there.') % {
                'path': self.directory, 'reason': self.reason}


def describe_write_problem(directory: Path, error: OSError) -> WriteProblem:
    """Zamienia wyjatek na opis dla czlowieka. Nic nie wyswietla."""
    reason = getattr(error, 'strerror', '') or str(error)
    problem = WriteProblem(directory=Path(directory), reason=str(reason),
                           protected=looks_protected(Path(directory), error))
    log.warning('zapis do %s nie przeszedl (%s: %s); blokada: %s',
                directory, type(error).__name__, error, problem.protected)
    return problem


def probe_write(directory: Path | None = None) -> WriteProblem | None:
    """Sprawdza plikiem probnym, czy w katalogu da sie ZAPISAC. `None` = da sie.

    Po co przed praca, a nie dopiero przy zapisie: skrot duzego pliku liczy
    sie minutami, a stempel jest nieodwracalny — wpis idzie do publicznego
    rejestru. Uzytkownik, ktory dowiaduje sie o blokadzie dopiero po tej
    drodze, traci czas, a swiezy dowod przepada razem z nieudanym zapisem
    historii. Lepiej powiedziec o tym przy starcie.

    Plik probny idzie przez `write_atomic`, czyli przez DOKLADNIE te sciezke
    kodu, ktora zapisuje historie (`mkstemp` + `os.replace`). Sprawdzanie
    prostym `open(..., 'w')` przepusciloby blokade, ktora dotyczy tworzenia
    pliku tymczasowego.
    """
    directory = Path(directory) if directory is not None else resolved_data_dir()
    probe = directory / PROBE_NAME
    try:
        directory.mkdir(parents=True, exist_ok=True)
        write_atomic(probe, b'ok')
    except OSError as e:
        return describe_write_problem(directory, e)
    finally:
        try:
            probe.unlink(missing_ok=True)
        except OSError as e:
            # Ochrona przed ransomware blokuje takze USUWANIE. Zapis przeszedl,
            # wiec katalog dziala — zostawiony plik probny nie jest problemem.
            log.info('nie udalo sie usunac pliku probnego %s: %s', probe, e)
    return None


# --- Przeprowadzka ze starych lokalizacji -----------------------------------

#: Znaczniki w NOWYM katalogu: „przeprowadzka Z TEGO zrodla zakonczona bez
#: bledu". Zapisywane DOPIERO po przejsciu calej petli — przerwanie w polowie
#: znaczy, ze przy nastepnym starcie zaczynamy to zrodlo od poczatku.
#:
#: KAZDE zrodlo ma WLASNY znacznik. Wspolny znacznik zamknalby droge danym
#: z drugiego miejsca: `Dokumenty\BeatStamp` na maszynie wlasciciela zawiera
#: juz `.przeniesiono-z-appdata` (bo bylo CELEM poprzedniej przeprowadzki),
#: wiec przy jednym znaczniku przeprowadzka z Dokumentow uznalaby sie za
#: wykonana, zanim cokolwiek skopiowala.
MIGRATION_MARKER = '.przeniesiono-z-appdata'
DOCUMENTS_MARKER = '.przeniesiono-z-dokumentow'
#: Przeprowadzka `%USERPROFILE%\BeatStamp` -> `%USERPROFILE%\Sigelith` (3.0.0).
BEATSTAMP_MARKER = '.przeniesiono-z-beatstamp'

#: Wszystkie znaczniki przeprowadzek — do przeniesienia razem z danymi
#: (`_carry_over_markers`).
MARKERS = (MIGRATION_MARKER, DOCUMENTS_MARKER, BEATSTAMP_MARKER)

#: Sufiks nazwy dla pliku, ktory NIE nadpisal istniejacego (`_unique_aside`).
#: Tez wlasny dla kazdego zrodla — nazwa `history.json.z-appdata-…` przy pliku
#: przyniesionym z Dokumentow klamalaby o pochodzeniu danych, a przy scalaniu
#: dwoch historii to jedyna informacja, ktora pozwala je rozroznic.
ASIDE_APPDATA = 'z-appdata'
ASIDE_DOCUMENTS = 'z-dokumentow'
ASIDE_BEATSTAMP = 'z-beatstamp'
ASIDE_PREVIOUS = 'z-poprzedniego'

#: Pliki przenoszone ze starej lokalizacji. Dziennika NIE przenosimy: nowy
#: powstaje juz na miejscu, a stary nie jest danymi uzytkownika.
MIGRATED_NAMES = ('history.json', 'settings.json', '.tvs-zaimportowano')

#: Kopie ratunkowe uszkodzonej historii (`history._quarantine`). To jedyny
#: slad po danych, ktorych nie dalo sie wczytac — zostawienie ich w katalogu
#: kasowanym razem z paczka byloby strata bez odwolania.
MIGRATED_GLOBS = ('historia.uszkodzona-*.json',)

#: Podkatalog przenoszony CALY (od 3.0.0): stan swiadka, sprawdzone pliki
#: checkpointow, kopia dziennika i — przede wszystkim — `witness/evidence/`,
#: czyli material dowodowy po alarmie, ktorego nie wolno zgubic z oczu.
#: Bez niego swiadek w nowym katalogu zaczynalby od zera: bez przypietej
#: historii checkpointow i bez alarmow wykrytych przez BeatStampa.
#: Pliki tymczasowe zapisu atomowego (`*.tmp`) zostaja.
#: `handover/` (od 3.0): moje karty i kontakty oraz przesylki w toku. Sekrety
#: sa tam jako bloby DPAPI — przeniesione na INNE konto Windows nie otworza
#: sie, ale przesylki i kontakty zostaja widoczne, a nie znikaja.
MIGRATED_TREES = ('witness', 'handover')

#: Informacja zostawiana w starym katalogu — dla kogos, kto tam zajrzy.
FORWARDING_NOTE = 'PRZENIESIONO.txt'


@dataclass
class MigrationReport:
    """Wynik przeprowadzki. Sluzy dziennikowi i jednej linii na pasku stanu.

    Jeden raport obejmuje WSZYSTKIE zrodla (`legacy_locations`), bo dla
    uzytkownika to jedna czynnosc: „dane sa teraz tutaj". Dziennik dostaje
    pelna liste zrodel, zeby dalo sie odtworzyc, skad co przyszlo.
    """

    target: Path
    sources: list[Path] = field(default_factory=list)
    copied: list[str] = field(default_factory=list)
    kept_aside: list[str] = field(default_factory=list)
    already_there: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    done: bool = False                 # znaczniki zapisane = nie wrocimy tu wiecej

    @property
    def source(self) -> Path | None:
        """Pierwsze zrodlo, w ktorym cokolwiek bylo (albo `None`)."""
        return self.sources[0] if self.sources else None

    @property
    def changed(self) -> bool:
        """Czy uzytkownik ma sie o czym dowiedziec."""
        return bool(self.copied or self.kept_aside)

    @property
    def message(self) -> str:
        """Jedno zdanie na pasek stanu. Puste = nie ma o czym mowic."""
        if not self.changed:
            return ''
        # Kazde zrodlo przeprowadzki to dane z czasow BeatStampa, wiec zdanie
        # mowi od razu o zmianie nazwy — uzytkownik po aktualizacji widzi
        # nowy program i nowy folder, a nie wie, ze to ten sam.
        parts = [(_('BeatStamp is now Sigelith Desktop — your data has been '
                    'moved to: %(path)s')
                  if self.copied else _('Data folder: %(path)s'))
                 % {'path': self.target}]
        if self.kept_aside:
            parts.append(
                _('A file of that name was already there, so the version from '
                  'the old location was saved next to it as: %(names)s')
                % {'names': ', '.join(self.kept_aside)})
        return ' '.join(parts)


def _unique_aside(target: Path, name: str, tag: str) -> Path:
    """Nazwa `<plik>.<tag>-<czas>`, wolna nawet przy kolizji co do sekundy."""
    stamp = time.strftime('%Y%m%d-%H%M%S')
    candidate = target / f'{name}.{tag}-{stamp}'
    counter = 1
    while candidate.exists():
        candidate = target / f'{name}.{tag}-{stamp}-{counter}'
        counter += 1
    return candidate


def _migration_sources(source: Path) -> list[str]:
    """Sciezki WZGLEDNE (`/`) plikow do skopiowania ze zrodla."""
    names = list(MIGRATED_NAMES)
    for pattern in MIGRATED_GLOBS:
        try:
            names.extend(sorted(p.name for p in source.glob(pattern) if p.is_file()))
        except OSError as e:
            log.warning('przeprowadzka — nie udało się przejrzeć %s: %s', source, e)
    for tree in MIGRATED_TREES:
        try:
            root = source / tree
            if root.is_dir():
                names.extend(sorted(p.relative_to(source).as_posix()
                                    for p in root.rglob('*')
                                    if p.is_file() and p.suffix != '.tmp'))
        except OSError as e:
            log.warning('przeprowadzka — nie udało się przejrzeć %s: %s',
                        source / tree, e)
    return list(dict.fromkeys(names))          # bez powtorzen, kolejnosc zachowana


def _write_forwarding_note(source: Path, target: Path) -> None:
    note = source / FORWARDING_NOTE
    if note.exists():
        return
    try:
        note.write_text(
            _('Sigelith Desktop (formerly BeatStamp) has moved its data (stamp '
              'history, settings) to:\n\n'
              '    %(path)s\n\n'
              'This folder is no longer in use. The files were kept here as a '
              'copy — you can delete them once you are sure everything is in '
              'the new place.\n') % {'path': target},
            encoding='utf-8')
    except OSError as e:
        log.info('przeprowadzka — nie udało się zostawić notatki w %s: %s', source, e)


def _carry_over_markers(source: Path, target: Path, own: str | None) -> None:
    """Przenosi znaczniki INNYCH przeprowadzek razem z danymi.

    Bez tego kroku lancuch `AppData -> Dokumenty -> profil\\BeatStamp ->
    profil\\Sigelith` produkowalby duplikaty: dane z `AppData` sa juz scalone
    w `Dokumenty\\BeatStamp` (swiadczy o tym lezacy tam znacznik), wiec po
    skopiowaniu ich dalej przeprowadzka z `AppData` powinna od razu uznac sie
    za wykonana. Gdyby znacznik nie powedrowal, STARSZA historia z `AppData`
    wrocilaby obok nowszej jako `history.json.z-appdata-<czas>` — bez straty
    danych, ale z falszywym wrazeniem, ze cos sie rozdwoilo.

    Kazde niepowodzenie jest tu nieszkodliwe: brak znacznika oznacza co
    najwyzej jedno zbedne przejscie przy nastepnym starcie.
    """
    for name in MARKERS:
        if name == own:
            continue
        try:
            src = source / name
            dst = target / name
            if src.is_file() and not dst.exists():
                write_atomic(dst, src.read_bytes())
        except OSError as e:
            log.info('przeprowadzka — nie udalo sie przeniesc znacznika %s: %s',
                     name, e)


def _copy_data(source: Path, target: Path, tag: str,
               report: MigrationReport) -> bool:
    """Kopiuje komplet plikow danych. Zwraca, czy obeszlo sie bez bledu."""
    ok = True
    for name in _migration_sources(source):
        src = source / name
        try:
            if not src.is_file():
                continue
            data = src.read_bytes()
        except OSError as e:
            log.warning('przeprowadzka — nie udało się odczytać %s: %s', src, e)
            report.failed.append(name)
            ok = False
            continue
        dst = target / name
        try:
            if dst.exists():
                if dst.is_file() and dst.read_bytes() == data:
                    report.already_there.append(name)
                    continue
                aside = _unique_aside(target, name, tag)
                write_atomic(aside, data)
                report.kept_aside.append(aside.name)
                log.warning('przeprowadzka — %s już istniał na nowym miejscu; '
                            'wersję ze starej lokalizacji zapisano jako %s',
                            name, aside.name)
                continue
            write_atomic(dst, data)
            report.copied.append(name)
        except OSError as e:
            log.warning('przeprowadzka — nie udało się zapisać %s: %s', dst, e)
            report.failed.append(name)
            ok = False
    return ok


def _same_dir(first: Path, second: Path) -> bool:
    try:
        return first.resolve() == second.resolve()
    except OSError:
        return first == second


def _migrate_one(source: Path, target: Path, marker_name: str, tag: str,
                 report: MigrationReport, *, skip: bool = False) -> bool:
    """Przeprowadzka z JEDNEGO zrodla. Zwraca, czy jest zamknieta znacznikiem.

    `skip` = zrodlo nie dotyczy tego katalogu docelowego: zapisujemy sam
    znacznik („nie ma stad czego brac") i niczego nie kopiujemy.
    """
    if _same_dir(target, source):
        return True

    marker = target / marker_name
    try:
        if marker.exists():
            return True
    except OSError:
        pass

    try:
        has_source = source.is_dir()
    except OSError:
        has_source = False
    if not has_source or skip:
        # Swieza instalacja: nie ma czego przenosic. Znacznik i tak zapisujemy,
        # zeby kolejne starty nie szukaly tego katalogu bez potrzeby.
        return _mark_migrated(marker, source)

    report.sources.append(source)
    if not _copy_data(source, target, tag, report):
        return False
    _carry_over_markers(source, target, marker_name)
    done = _mark_migrated(marker, source)
    _write_forwarding_note(source, target)
    return done


def legacy_locations() -> list[tuple[Path, str, str]]:
    """Stare lokalizacje danych: (katalog, znacznik, sufiks kolizji).

    Kolejnosc jest znaczaca i idzie od NAJSWIEZSZEJ. Przy scalaniu wygrywa
    ten plik, ktory trafi na miejsce pierwszy (drugi laduje obok, bo
    `_copy_data` niczego nie nadpisuje) — a najswiezsza historia jest tam,
    gdzie program pisal ostatnio: `%USERPROFILE%\\BeatStamp` (2.2.0), przed
    nim Dokumenty, na koncu `AppData`.

    Zrodlo `%USERPROFILE%\\BeatStamp` idzie pierwsze takze z drugiego powodu:
    lezace tam znaczniki poprzednich przeprowadzek wedruja razem z danymi
    (`_carry_over_markers`), wiec Dokumenty i `AppData`, juz raz scalone
    w wersji 2.2, nie sa czytane drugi raz.
    """
    locations: list[tuple[Path, str, str]] = []
    profile = legacy_profile_data_dir()
    if profile is not None:
        locations.append((profile, BEATSTAMP_MARKER, ASIDE_BEATSTAMP))
    documents = legacy_documents_data_dir()
    if documents is not None:
        locations.append((documents, DOCUMENTS_MARKER, ASIDE_DOCUMENTS))
    locations.append((legacy_app_data_dir(), MIGRATION_MARKER, ASIDE_APPDATA))
    return locations


def copy_data_to(target: Path) -> MigrationReport:
    """Kopiuje dane z BIEZACEGO katalogu do wskazanego — zmiana w Ustawieniach.

    Ta sama maszyneria co przy przeprowadzce ze starych lokalizacji, z jedna
    roznica: nie ma znacznika „juz zrobione". Zmiana katalogu jest decyzja
    uzytkownika podejmowana wielokrotnie, a nie jednorazowym zdarzeniem
    w historii instalacji.

    Znaczniki przeprowadzek ida razem z danymi, zeby nowy katalog nie zaczal
    sciagac po raz drugi tego, co zostalo juz scalone w poprzednim.
    """
    source = resolved_data_dir()
    target = Path(target)
    report = MigrationReport(target=target)
    if _same_dir(target, source):
        report.done = True
        return report
    try:
        has_source = source.is_dir()
    except OSError:
        has_source = False
    if not has_source:
        report.done = True
        return report

    report.sources.append(source)
    report.done = _copy_data(source, target, ASIDE_PREVIOUS, report)
    if report.done:
        _carry_over_markers(source, target, None)
        _write_forwarding_note(source, target)
    return report


def migrate_legacy_data() -> MigrationReport:
    """Jednorazowo kopiuje dane ze STARYCH lokalizacji do biezacej.

    Zrodla sa trzy (`legacy_locations`), bo trzy razy byly lokalizacja
    domyslna: `%LOCALAPPDATA%\\BeatStamp` (kasowany przy odinstalowaniu paczki
    MSIX), `Dokumenty\\BeatStamp` (blokowany przez ochrone przed ransomware)
    i `%USERPROFILE%\\BeatStamp` (BeatStamp 2.2.0 — przed zmiana nazwy
    programu na Sigelith Desktop). Uzytkownik moze miec dane w kazdym z nich
    — i musi zobaczyc je razem, w jednym komplecie.

    `%USERPROFILE%\\BeatStamp` dotyczy WYLACZNIE lokalizacji domyslnej. Katalog
    wybrany przez uzytkownika (wskaznik `LOCATION_FILE`, takze zapisany przez
    BeatStampa) dostal swoje dane wlasnie stamtad — przy zmianie katalogu
    w wersji 2.2 (`copy_data_to`) — a potem juz tylko tam pisal. Ponowne
    kopiowanie przynioslo by same starsze wersje „obok"; zapisujemy wiec sam
    znacznik, ktory przy kolejnej zmianie katalogu wedruje razem z danymi.

    Zasady, ktorych ta funkcja pilnuje:

    * **Kopiuje, nigdy nie przenosi.** Zrodlo zostaje nietkniete — przerwanie
      w dowolnym momencie zostawia w starym katalogu pelny komplet oryginalow.
    * **Nie nadpisuje.** Plik, ktory juz jest na nowym miejscu i rozni sie
      zawartoscia, zostaje; wersja ze starej lokalizacji laduje obok jako
      `<nazwa>.<sufiks-zrodla>-<czas>` i trafia do raportu. Zaden wariant tej
      funkcji nie kasuje danych uzytkownika.
    * **Jest idempotentna.** Znacznik zrodla zapisujemy DOPIERO po bezbledowym
      przejsciu calej jego petli. Powtorka po przerwaniu rozpoznaje wlasne,
      wczesniej skopiowane pliki po IDENTYCZNEJ zawartosci i pomija je po
      cichu — bez tego warunku kazdy kolejny start produkowalby nowe kopie
      `*.z-appdata-*`.
    * **Kopiuje bajty, nie tresc.** Plik uszkodzony przenosi sie tak samo jak
      poprawny; o tym, co z nim zrobic, decyduje `History.load` juz na nowym
      miejscu (kwarantanna) — tu nie ma zadnego parsowania, wiec nie ma czego
      zgubic.
    * **Idzie przez `write_atomic`**, czyli plik tymczasowy powstaje w
      katalogu DOCELOWYM. Stare lokalizacje bywaja na innym wolumenie albo na
      udziale sieciowym; `os.rename`/`shutil.move` przewrocilyby sie tam na
      „Invalid cross-device link".
    """
    target = app_data_dir()
    report = MigrationReport(target=target)

    # Katalog narzucony z zewnatrz = katalog IZOLOWANY. `SIGELITH_DATA_DIR`
    # (i dawna `BEATSTAMP_DATA_DIR`) uzywaja wersja przenosna z pendrive'a,
    # testy i `tools/verify_exe.py`, a w kazdym z tych przypadkow „wciagnij
    # tu historie z tej maszyny" jest dokladnym przeciwienstwem tego, o co
    # chodzilo: pendrive zabralby cudze dane, a weryfikacja wydania
    # mieszalaby swoj stempel probny z prawdziwa historia osoby skladajacej
    # paczke. Wybor uzytkownika zapisany we wskazniku (`LOCATION_FILE`)
    # takiego skutku nie ma — tam przeprowadzka jest wlasnie tym, czego
    # uzytkownik oczekuje.
    name, forced = forced_data_dir()
    if forced:
        log.info('przeprowadzka pominieta: katalog danych narzucony przez %s', name)
        report.done = True
        return report

    at_default = _same_dir(target, _default_data_dir())
    done = True
    for source, marker_name, tag in legacy_locations():
        skip = marker_name == BEATSTAMP_MARKER and not at_default
        done = _migrate_one(source, target, marker_name, tag, report,
                            skip=skip) and done
    report.done = done
    return report


def _mark_migrated(marker: Path, source: Path) -> bool:
    try:
        write_atomic(marker, json.dumps({
            'przeniesiono_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'zrodlo': str(source),
        }, indent=2, ensure_ascii=False).encode('utf-8'))
    except OSError as e:
        log.warning('przeprowadzka — nie udało się zapisać znacznika %s: %s', marker, e)
        return False
    return True


# --- Ustawienia -------------------------------------------------------------

#: Adres API Sigelith. sigelith.org i beattime.live obsluguje TA SAMA
#: instancja (jedna baza, jeden dziennik, jeden klucz Ed25519), a kazda
#: sciezka API jest pod obiema domenami taka sama — beattime.live dziala
#: dalej na zawsze, ale od 3.0.0 program mowi do sigelith.org.
DEFAULT_BASE_URL = 'https://sigelith.org'

#: Domyslne adresy API z poprzednich wersji. `settings.json` zapisuje KAZDE
#: pole, takze domyslne, wiec u kazdego uzytkownika BeatStampa lezy tam
#: `"base_url": "https://beattime.live"` — nie jako wybor, tylko jako
#: utrwalona wartosc domyslna. `Settings.load` zamienia ja na biezaca
#: (tak samo jak stary klucz fabryczny w `pinned_public_key`); kazdy INNY
#: adres, np. wlasna instancja, zostaje nietkniety.
LEGACY_DEFAULT_BASE_URLS = frozenset({'https://beattime.live'})

#: Usluga ukryta Tor — adres WBUDOWANY, awaryjny. Biezacy program pobiera
#: sam z `/api/onion/` i zapamietuje w `Settings.onion_url` (onion.py), wiec
#: zmiana adresu .onion nie wymaga nowego wydania. Ten prowadzi do tej samej
#: instancji co sigelith.org i beattime.live i zostaje wlaczony na stale.
ONION_BASE_URL = 'http://beattimep6dfropwazgaluos7xsxxmyjeat2ddb73dxxvvbsejmp4hqd.onion'
DEFAULT_TOR_PROXY = 'socks5h://127.0.0.1:9050'

# Dokumenty prawne wydawcy. § 5 DDG (dawniej TMG) wymaga, zeby impressum bylo
# „leicht erkennbar, unmittelbar erreichbar und standig verfugbar" — przyjeta
# miara jest najwyzej DWA klikniecia. W aplikacji sa to: Pomoc -> Impressum
# i Pomoc -> Ochrona danych (`ui/main_window._build_menu`), a dodatkowo oba
# adresy powtarza okno „O programie".
#
# Dwie rzeczy, ktore tu sa celowo:
#
# * **Staly adres, nie `Settings.base_url`.** Obowiazek dotyczy wydawcy tej
#   aplikacji. Gdyby adres szedl z ustawien, wpisanie wlasnego serwera (pole
#   dla testow i dla wersji rozwojowej) podmienialoby impressum na cudze —
#   albo prowadzilo donikad.
# * **Staly prefiks `/de/`.** Oryginaly istnieja WYLACZNIE po niemiecku
#   (`apps/web/views._german_only`), bo to niemiecki obowiazek prawny;
#   podstawienie prefiksu jezyka interfejsu dawaloby 404. Jedyny inny adres
#   to angielskie tlumaczenie polityki (`/privacy/`, bez prefiksu jezyka) —
#   `privacy_policy_url` nizej.
#
# Od 3.0.0 pod sigelith.org — te same sciezki, ta sama instancja i ten sam
# wydawca (Adam Koch, Hagen) co pod beattime.live.
IMPRESSUM_URL = 'https://sigelith.org/de/impressum/'
PRIVACY_POLICY_URL = 'https://sigelith.org/de/datenschutz/'
PRIVACY_POLICY_URL_EN = 'https://sigelith.org/privacy/'


def privacy_policy_url(language: str = 'en') -> str:
    """Polityka prywatnosci w wersji, ktora uzytkownik przeczyta.

    Interfejs niemiecki dostaje oryginal, kazdy inny — tlumaczenie angielskie
    (od 2026-09-27): wersji polskiej czy japonskiej nie ma, a angielska jest
    dla wiekszosci czytelnikow blizsza niz niemiecka. Na jej poczatku stoi,
    ze wiazacy jest oryginal, z odnosnikiem do niego.
    """
    return PRIVACY_POLICY_URL if (language or '').lower() == 'de' else PRIVACY_POLICY_URL_EN

# Strony serwisu, ktore istnieja w wersjach jezykowych (`config/urls.py`
# serwera: `i18n_patterns`, angielski BEZ prefiksu). Pozostale — `/spec/`,
# `/checkpoints/`, `/open-source/`, `/docs/` — sa jednojezyczne i maja jeden
# adres; prefiks jezyka dawalby tam 404. Od 3.0.0 pod sigelith.org: ta sama
# instancja co beattime.live, wiec kazda sciezka dziala pod obiema domenami.
SITE_BASE = 'https://sigelith.org'
LOCALIZED_PAGES = frozenset({'', 'apps', 'proof', 'evidence', 'quickstart',
                             'swatch-internet-time', 'capsule', 'manifesto'})
#: Strony, ktorych oryginal jest w jednym jezyku, a reszta to tlumaczenie
#: albo przekierowanie. Manifest: oryginal PL, tlumaczenie EN; `/de/manifesto/`
#: przekierowuje na EN.
PAGE_LANGUAGES = {'manifesto': frozenset({'pl', 'en'})}
#: Kod jezyka aplikacji -> prefiks jezyka na stronie (gdy sie roznia).
SITE_LANGUAGE_PREFIX = {'zh': 'zh-hans'}


def site_url(path: str, language: str = 'en') -> str:
    """Adres strony serwisu w jezyku interfejsu, jesli taka wersja jest.

    `path` bez ukosnikow na brzegach, z opcjonalnym zapytaniem:
    `site_url('proof?h=...', 'pl')` -> `https://sigelith.org/pl/proof/?h=...`.
    """
    page, _sep, query = str(path or '').strip('/').partition('?')
    page = page.strip('/')
    first = page.split('/', 1)[0]
    language = (language or 'en').lower()
    # Katalog aplikacji to `zh`; strona ma chinski uproszczony pod `/zh-hans/`.
    language = SITE_LANGUAGE_PREFIX.get(language, language)
    allowed = PAGE_LANGUAGES.get(first)
    prefix = ''
    if first in LOCALIZED_PAGES and language != 'en' and (
            allowed is None or language in allowed):
        prefix = f'/{language}'
    url = f'{SITE_BASE}{prefix}/{page}/' if page else f'{SITE_BASE}{prefix}/'
    return f'{url}?{query}' if query else url


#: Publiczna strona weryfikacji skrotu — JEDYNE miejsce, w ktorym zapisany jest
#: jej adres. Z niego biora: kod QR i tekst certyfikatu PDF
#: (`certificate.py`), odnosnik wpisu historii (`history.Entry.verify_url`)
#: i przycisk „Sprawdz w przegladarce" (`verify_url(..., language)`).
#:
#: OSTATECZNA sciezka (decyzja wlasciciela 2026-09-27): `/proof/?h=<skrot>`
#: pod sigelith.org. Te sama sciezke drukuje od 2026-09-27 certyfikat PDF
#: serwera (apps/tsa/cert.py), wiec i tak musi dzialac zawsze — kod QR na
#: wydrukowanym certyfikacie ma dzialac latami. Nie zmieniac.
VERIFY_URL = 'https://sigelith.org/proof/?h='


def verify_url(digest: str, language: str = '') -> str:
    """Adres weryfikacji skrotu na stronie Sigelith.

    Bez `language` — adres KANONICZNY, bez prefiksu jezyka: trafia do kodu
    QR i na certyfikat, ktory czyta kazdy, w dowolnym jezyku. Z `language` —
    ta sama strona w jezyku interfejsu (`site_url`), dla przycisku w oknie.
    """
    digest = str(digest or '')
    if not language:
        return VERIFY_URL + digest
    page, _sep, query = VERIFY_URL.partition('?')
    page = page.split('://', 1)[-1].partition('/')[2]
    return site_url(f'{page.strip("/")}?{query}{digest}', language)

# Zrodla bibliotek, z ktorych korzystamy na LGPLv3 (Qt i PySide6). Paragraf 4
# tej licencji wymaga czterech rzeczy naraz i kazda z nich jest w oknie
# „O programie": (a) widocznej informacji, ze program uzywa tych bibliotek,
# (b) noty o ich prawach autorskich, (c) DOSTARCZENIA kopii tekstow GNU GPL
# i LGPL razem z programem — stad katalog `licenses/` w paczce, a nie sam
# odnosnik — i (d) udostepnienia zrodel SAMYCH BIBLIOTEK, czyli tych adresow.
#
# Adresy prowadza do DOKLADNIE tej wersji, ktora jest w paczce. Odnosnik do
# „najnowszego Qt" nie spelnia tego wymogu: za rok wskazywalby na cos innego
# niz to, z czym program zostal skompilowany. Trwala pisemna oferte wydania
# tych zrodel niesie plik `NOTICE` (tez w paczce) — adres moze kiedys zniknac,
# oferta nie. Wersje sa tu wpisane wprost, bo zmiana wersji Qt MUSI byc
# widoczna jako zmiana w tym pliku; zgodnosci z `tools/licenses.py` (skad
# bierze je generator not) pilnuje `tests/test_licensing.py`.
QT_SOURCE_URL = ('https://download.qt.io/archive/qt/6.11/6.11.2/single/'
                 'qt-everywhere-src-6.11.2.tar.xz')
PYSIDE_SOURCE_URL = ('https://download.qt.io/official_releases/QtForPython/'
                     'pyside6/PySide6-6.11.2-src/'
                     'pyside-setup-everywhere-src-6.11.2.tar.xz')

# Adresy, pod ktorymi moze nasluchiwac LOKALNY Tor.
LOOPBACK_HOSTS = frozenset({'127.0.0.1', 'localhost', '::1', '[::1]'})

# Powyzej tej wartosci dryf zegara systemowego jest pokazywany jako
# ostrzezenie. 2 s to ~0.023 beatu — ponizej progu widocznosci w @NNN,
# a powyzej zaczyna byc widoczne w centibeatach.
CLOCK_DRIFT_WARN_SECONDS = 2.0


@dataclass
class Settings:
    """Ustawienia uzytkownika. Kazde pole ma bezpieczna wartość domyślna."""

    # --- Polaczenie ---
    base_url: str = DEFAULT_BASE_URL
    use_tor: bool = False
    tor_proxy: str = DEFAULT_TOR_PROXY
    # Adres .onion pobrany z /api/onion/ (onion.py) i chwila ostatniego
    # UDANEGO sprawdzenia (ISO 8601 UTC). Puste = wbudowany ONION_BASE_URL.
    onion_url: str = ''
    onion_checked: str = ''
    timeout_seconds: float = 15.0

    # --- Zaufanie ---
    # OPCJONALNY wlasny klucz (zaawansowane). Pusty = wbudowana historia
    # kluczy Sigelith z keys.py — i to jest ustawienie zalecane. Wlasny klucz
    # jest uznawany OBOK listy (np. gdy Sigelith ogłosi rotacje, zanim wyjdzie
    # nowa wersja programu) i jest stale widoczny na pasku stanu. Wylaczyc
    # sprawdzanie klucza sie nie da. Nazwa pola zostaje dla zgodnosci
    # z istniejacymi plikami settings.json.
    pinned_public_key: str = ''

    # --- Swiadkowie (2.2) ---
    # 'private' — kopia calego dziennika, serwer nie wie, ktore wpisy sa
    # nasze; 'fast' — pytanie o kazdy skrot osobno (witness.py).
    verification_mode: str = 'private'
    # Sprawdzanie dziennika i dojrzewania dowodow, gdy okno jest otwarte.
    background_checks: bool = True
    # Kopie u osob trzecich (GitHub, Internet Archive, Zenodo) i blok
    # Bitcoina u niezaleznego eksploratora.
    third_party_checks: bool = True

    # --- Zachowanie ---
    auto_verify_after_stamp: bool = True
    # Czesci nazwy zapisywanego certyfikatu i dowodu (`naming.py`). Pierwsze
    # pole ma stara nazwe, zeby ustawienie z 2.1 dzialalo dalej.
    name_cert_after_source: bool = True
    cert_name_moment: bool = True
    cert_name_beat: bool = True
    confirm_overwrite: bool = True
    theme: str = 'auto'              # auto | light | dark
    # Jezyk interfejsu: 'auto' (jak system) albo kod z `i18n.SUPPORTED`.
    # Wartosc spoza listy degraduje sie do jezyka zrodlowego, wiec recznie
    # zepsuty settings.json nie wywraca startu programu.
    language: str = 'auto'           # auto | pl | en | de
    last_directory: str = ''
    history_limit: int = 5000        # gorny sufit wpisow; 0 = bez limitu

    # --- Sigelith Handover (3.0) ---
    # Folder wymiany (OneDrive, Dropbox, Syncthing...): paczki i odpowiedzi
    # zapieczetowane do adresata, odbierane automatycznie. Pusty = pliki
    # zapisuje i otwiera uzytkownik (HANDOVER_SPEC.md §10.3).
    handover_exchange_dir: str = ''
    # Folder na pliki z otwartych przesylek. Pusty = Pobrane\Sigelith.
    handover_downloads_dir: str = ''
    # Atestacja TPM karty w pliku karty i w dowodzie (§3.6). Mozna wylaczyc.
    handover_attestation: bool = True

    # --- Okno ---
    window_geometry: str = ''        # base64 z QByteArray

    @classmethod
    def load(cls) -> 'Settings':
        """Czyta ustawienia; każdy błąd konczy się wartosciami domyslnymi.

        Nieznane klucze sa ignorowane, a pola o zlym typie wracaja do
        domyslnych — plik edytowany recznie nie może wywrocic startu programu.
        """
        path = settings_path()
        if not path.exists():
            return cls()
        try:
            raw = json_loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return cls()
        if not isinstance(raw, dict):
            return cls()
        known = {f.name: f for f in fields(cls)}
        kwargs = {}
        for key, value in raw.items():
            f = known.get(key)
            if f is None:
                continue
            try:
                if f.type in ('bool', bool):
                    kwargs[key] = bool(value)
                elif f.type in ('int', int):
                    kwargs[key] = int(value)
                elif f.type in ('float', float):
                    kwargs[key] = float(value)
                else:
                    kwargs[key] = str(value)
            except (TypeError, ValueError, OverflowError):
                continue
        # Migracja z wersji, w ktorej to pole bylo JEDYNYM przypietym kluczem
        # z wartoscia fabryczna. Stary klucz fabryczny i klucze wycofane nie
        # sa wyborem uzytkownika — zostawione, blokowalyby aktualny klucz
        # (kazdy swiezy dowod wygladalby na podpisany obcym kluczem).
        # Przy nastepnym zapisie trafi tu juz ''.
        # Wartosc, ktora nie jest kluczem Ed25519 w kanonicznym base64 (null,
        # liczba, smieci z recznej edycji), tez zamienia sie na '' — inaczej
        # zostawalaby na stale jako „wlasny klucz" z ostrzezeniem na pasku
        # stanu i blokowala zapis Ustawien.
        if 'pinned_public_key' in kwargs:
            raw_key = raw.get('pinned_public_key')
            kwargs['pinned_public_key'] = keys.normalize_override(raw_key)
            quiet = {'', keys.LEGACY_DEFAULT_PINNED_KEY,
                     *keys.retired_public_keys(), *keys.current_public_keys()}
            if not kwargs['pinned_public_key'] and (
                    not isinstance(raw_key, str) or raw_key.strip() not in quiet):
                log.warning('ustawienia: pominięto nieprawidłowy klucz publiczny '
                            'w settings.json (pole pinned_public_key)')
        # Utrwalona wartosc domyslna z BeatStampa (beattime.live) to nie wybor
        # uzytkownika — patrz `LEGACY_DEFAULT_BASE_URLS`. Przy nastepnym
        # zapisie trafi tu juz sigelith.org.
        if 'base_url' in kwargs and kwargs['base_url'].strip().rstrip('/').lower() \
                in LEGACY_DEFAULT_BASE_URLS:
            kwargs['base_url'] = DEFAULT_BASE_URL
        return cls(**kwargs)

    @property
    def witness_mode(self) -> str:
        """Tryb sprawdzania: 'private' albo 'fast' (zla wartosc = prywatny)."""
        return self.verification_mode if self.verification_mode in (
            'private', 'fast') else 'private'

    @property
    def key_override(self) -> str:
        """Wlasny klucz do weryfikacji albo '' (= tylko wbudowana lista)."""
        return keys.normalize_override(self.pinned_public_key)

    def save(self) -> None:
        """Zapisuje ustawienia. `OSError` leci dalej — lapie go interfejs.

        Katalog danych bywa zablokowany (ochrona przed ransomware, pelny dysk,
        niedostepny udzial sieciowy). Polkniecie bledu tutaj znaczyloby, ze
        program potwierdza zapis, ktorego nie bylo; `ui/main_window._store`
        umie zamiast tego pokazac przyczyne i zaproponowac inny katalog.

        Sciezki NIE zapamietujemy w polu: `settings_path()` liczymy przy
        kazdym zapisie, wiec po zmianie katalogu plik trafia juz w nowe
        miejsce.
        """
        write_atomic(
            settings_path(),
            json.dumps(asdict(self), indent=2, ensure_ascii=False).encode('utf-8'),
        )

    # --- Pochodne ---

    @property
    def onion_base_url(self) -> str:
        """Adres uslugi .onion: pobrany z serwisu, a bez niego wbudowany.

        Zapamietany adres przyjmujemy tylko jako poprawny adres v3 — plik
        ustawien recznie popsuty albo z innej wersji nie przestawi ruchu Tor
        w nieznane miejsce.
        """
        return self.onion_url if is_v3_url(self.onion_url) else ONION_BASE_URL

    @property
    def effective_base_url(self) -> str:
        """Adres, pod który faktycznie ida zapytania."""
        return self.onion_base_url if self.use_tor else self.base_url.rstrip('/')

    @property
    def tor_proxy_is_local(self) -> bool:
        """Czy proxy Tor wskazuje na TEN komputer.

        Ma znaczenie, bo w trybie Tor ruch idzie zwykłym HTTP-em (adres
        `.onion` nie ma certyfikatu CA — tożsamość usługi niesie sam adres,
        a szyfrowanie zapewnia Tor od końca do końca). Ten argument trzyma
        się jednak WYŁĄCZNIE wtedy, gdy po drugiej stronie naprawdę jest Tor.
        Proxy pod cudzym adresem oznacza ruch jawnym tekstem do maszyny,
        która nie jest siecią Tor — czyli dokładne przeciwieństwo tego, co
        przełącznik obiecuje. Interfejs sygnalizuje to wprost, zamiast dalej
        wyświetlać zapewnienie o prywatności.
        """
        from urllib.parse import urlparse
        try:
            host = urlparse(self.tor_proxy).hostname or ''
        except ValueError:
            return False
        return host.lower() in LOOPBACK_HOSTS

    @property
    def proxies(self) -> dict[str, str] | None:
        """Proxy dla requests. SOCKS5h = DNS rozwiązuje Tor, nie my.

        To nie jest kosmetyka: przy zwyklym `socks5://` nazwa `.onion` poszlaby
        do lokalnego resolvera DNS, który jej nie zna — i przy okazji wyciekla
        by do dostawcy internetu. Litera `h` przenosi rozwiazywanie nazwy do
        sieci Tor.
        """
        if not self.use_tor:
            return None
        return {'http': self.tor_proxy, 'https': self.tor_proxy}

    @property
    def verify_tls(self) -> str | bool:
        """Magazyn CA do weryfikacji TLS albo False dla .onion.

        Zwracamy Ścieżkę do `certifi`, nie samo `True`. W wersji exe magazyn
        CA jest rozpakowywany do katalogu tymczasowego i wskazanie go wprost
        zdejmuje zaleznosc od tego, czy `requests` sam go odnajdzie w
        zamrozonym srodowisku — cicha awaria tego wyszukiwania konczy się
        błędem TLS na każdym zapytaniu.

        Adres `.onion` nie ma certyfikatu CA i nie potrzebuje go: tożsamość
        usługi jest wbudowana w sam adres (klucz Ed25519), a ruch szyfruje Tor
        od konca do konca. Warstwa TLS tam po prostu nie wystepuje — nie jest
        "wylaczona".
        """
        if self.use_tor:
            return False
        import certifi
        return certifi.where()

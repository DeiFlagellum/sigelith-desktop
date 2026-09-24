"""
Historia kluczy publicznych BeatTime — jedyne zrodlo zaufania aplikacji.

BeatTime podpisuje tygodniowe korzenie Merkle kluczem Ed25519. Serwer przysyla
klucz razem z podpisem, ale sam podpis dowodzi tylko tego, ze ktos mial JAKIS
klucz. O tym, czy podpis pochodzi od BeatTime, decyduje WYLACZNIE ta lista,
wbudowana w program — nigdy odpowiedz serwera.

Dwie kategorie:

* CURRENT_KEYS — klucze, ktorymi BeatTime podpisuje teraz. Podpis takim
  kluczem (plus poprawna sciezka inkluzji) daje poziom PODPISANY/ZAKOTWICZONY.
* RETIRED_KEYS — klucze wycofane. Podpis wycofanym kluczem NIE jest uznawany:
  poziom dowodu zostaje „Zarejestrowany", a interfejs prosi o odswiezenie
  dowodu online (serwer ma kazdy opublikowany korzen podpisany ponownie
  aktualnym kluczem). Powod jest konkretny: klucz z 2026-06..09 podpisal tez
  inne, testowe korzenie dla tygodni 2026-W25 i 2026-W30, wiec sam jego podpis
  nie rozstrzyga, ktory korzen jest prawdziwy.

LUSTRO SERWERA. `RETIRED_KEYS` to kopia `apps/tsa/signing.py: RETIRED_KEYS`
(bez pola `reason`). Zgodnosc pilnuja dwa testy, po jednym z kazdej strony:

* desktop/tests/test_server_parity.py — parsuje signing.py modulem `ast`
  (bez Django),
* apps/tsa/tests.py: DesktopKeyMirrorTests — laduje TEN plik przez importlib.

Aktualny klucz nie lezy w repozytorium serwera (serwer wyprowadza go z env),
wiec CURRENT_KEYS sprawdza opcjonalny test na zywo (BEATSTAMP_LIVE=1) na
https://beattime.live/api/proof/root/latest.

Przy rotacji: nowy klucz dopisz do CURRENT_KEYS, stary przenies do
RETIRED_KEYS z data wycofania — tutaj i w signing.py jednoczesnie. Zadnego
wpisu sie nie usuwa.

Klucze porownujemy w POSTACI KANONICZNEJ (`canonical`), nie jako napisy.
Ostatni znak base64 przed `=` niesie dwa nieuzywane bity, wiec np. `...yN0=`
i `...yN1=` dekoduja sie do tych samych 32 bajtow — porownanie napisow
przepuszczaloby taki alias klucza wycofanego jako „inny" klucz.

Modul jest czystym Pythonem: bez Qt, bez sieci, bez importow z pakietu —
serwer laduje go wprost ze sciezki pliku.
"""
from __future__ import annotations

import base64
import binascii

# Klucze, ktorymi BeatTime podpisuje teraz. Kolejnosc chronologiczna;
# ostatni to klucz podstawowy (pokazywany w instrukcji weryfikacji).
CURRENT_KEYS: tuple[dict, ...] = (
    {
        'public_key': 'e7y9THJIUKvNKOZHmdBjJ8E0bOKyBFVxxMpAJ8w574Y=',
        'active_from': '2026-09-21',
    },
)

# Klucze wycofane — lustro apps/tsa/signing.py: RETIRED_KEYS. Kolejnosc
# chronologiczna. `retired_on` to dzien, od ktorego podpis tym kluczem nie
# jest juz wiazacy.
RETIRED_KEYS: tuple[dict, ...] = (
    {
        'public_key': 'YNVYXDyg3hQGM3F+/ec+ZNmeN1JI/hZX+CxLqyJdyN0=',
        'active_from': '2026-06-15',
        'retired_on': '2026-09-21',
    },
)

# Domyslna wartosc `Settings.pinned_public_key` w BeatStampie do wersji 2.0.0
# wlacznie (od 2.1.0 pole jest domyslnie puste).
# Zapisana w %LOCALAPPDATA%\BeatStamp\settings.json nie jest wyborem
# uzytkownika, tylko starym ustawieniem fabrycznym — migracja ja czysci.
LEGACY_DEFAULT_PINNED_KEY = 'YNVYXDyg3hQGM3F+/ec+ZNmeN1JI/hZX+CxLqyJdyN0='

# Stan podpisujacego klucza (VerificationResult.signer_status).
SIGNER_CURRENT = 'current'      # klucz z CURRENT_KEYS
SIGNER_OVERRIDE = 'override'    # klucz wpisany recznie w Ustawieniach
SIGNER_RETIRED = 'retired'      # klucz z RETIRED_KEYS — nie uznajemy
SIGNER_UNKNOWN = 'unknown'      # obcy albo brak klucza — nie uznajemy
TRUSTED_STATUSES = frozenset({SIGNER_CURRENT, SIGNER_OVERRIDE})


def current_public_keys() -> tuple[str, ...]:
    return tuple(k['public_key'] for k in CURRENT_KEYS)


def retired_public_keys() -> tuple[str, ...]:
    return tuple(k['public_key'] for k in RETIRED_KEYS)


def primary_key() -> str:
    """Najnowszy aktualny klucz — do instrukcji i komunikatow."""
    return CURRENT_KEYS[-1]['public_key']


def canonical(pub: object) -> str:
    """Klucz Ed25519 w kanonicznym base64 albo '' (= nie jest kluczem).

    Przyjmujemy wylacznie zapis, ktory po zdekodowaniu do 32 bajtow i
    ponownym zakodowaniu daje DOKLADNIE ten sam napis (bialy znak na brzegach
    nie przeszkadza). Wszystko inne — zly base64, inna dlugosc, niezerowe
    bity dopelnienia (alias tego samego klucza) — to ''. Dzieki temu kazde
    porownanie w tym module jest porownaniem bajtow klucza.
    """
    text = str(pub or '').strip()
    if not text:
        return ''
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return ''
    if len(raw) != 32 or base64.b64encode(raw).decode('ascii') != text:
        return ''
    return text


def is_retired(pub: object) -> bool:
    pub = canonical(pub)
    return bool(pub) and pub in retired_public_keys()


def is_trusted(pub: object, override: object = '') -> bool:
    """Czy podpis tym kluczem wolno uznac za podpis BeatTime.

    Wycofany klucz NIE jest zaufany nawet wtedy, gdy ktos wpisal go jako
    wlasny klucz w ustawieniach — nadpisanie nie moze przywrocic klucza,
    ktory BeatTime sam wycofal.
    """
    return classify(pub, override) in TRUSTED_STATUSES


def retired_info(pub: object) -> dict | None:
    """Wpis z RETIRED_KEYS dla klucza (kopia) albo None."""
    pub = canonical(pub)
    for k in RETIRED_KEYS:
        if pub and k['public_key'] == pub:
            return dict(k)
    return None


def classify(pub: object, override: object = '') -> str:
    """Jeden z SIGNER_*: jak traktowac podpis zlozony kluczem `pub`.

    Kolejnosc sprawdzen ma znaczenie: lista wycofanych wygrywa ze wszystkim,
    wiec zaden wpis w ustawieniach nie przywroci wycofanego klucza. Zapis
    niekanoniczny (takze alias klucza z listy) to SIGNER_UNKNOWN.
    """
    pub = canonical(pub)
    if not pub:
        return SIGNER_UNKNOWN
    if pub in retired_public_keys():
        return SIGNER_RETIRED
    if pub in current_public_keys():
        return SIGNER_CURRENT
    if pub == normalize_override(override):
        return SIGNER_OVERRIDE
    return SIGNER_UNKNOWN


def normalize_override(value: object) -> str:
    """Wlasny klucz z ustawien albo '' (= wbudowana lista kluczy).

    Puste pole, stara wartosc fabryczna, klucz wycofany, klucz, ktory i tak
    jest na liscie aktualnych, oraz wszystko, co nie jest kluczem Ed25519
    w kanonicznym base64 (np. `null` albo smieci z recznie edytowanego
    settings.json), niczego nie nadpisuja — zamieniamy je na ''. Dzieki temu
    ostrzezenie „wlasny klucz" pojawia sie tylko wtedy, gdy uzytkownik
    naprawde wpisal poprawny klucz spoza listy.
    """
    text = canonical(value)
    if (not text or text == LEGACY_DEFAULT_PINNED_KEY
            or text in retired_public_keys() or text in current_public_keys()):
        return ''
    return text


def format_date(iso_day: str) -> str:
    """'2026-09-21' -> '21.09.2026' (zapis dat w interfejsie)."""
    parts = str(iso_day or '').split('-')
    if len(parts) == 3 and all(p.isdigit() for p in parts):
        return f'{parts[2]}.{parts[1]}.{parts[0]}'
    return str(iso_day or '')

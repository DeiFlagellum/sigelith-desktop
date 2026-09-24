"""
Samokontrola SPAKOWANEJ aplikacji — `BeatStamp.exe --selftest`.

Po co to istnieje. Testy jednostkowe dzialaja na kodzie ZRODLOWYM, wiec cala
klasa usterek pakowania jest dla nich niewidoczna z definicji: wykluczony
modul, niedolaczony zasob, magazyn CA, ktorego `certifi` nie znajduje
w paczce. `tools/verify_exe.py` przechodzi glowna sciezke uzytkownika
(skrot -> HTTPS -> stempel -> weryfikacja -> zapis), ale trzy rzeczy zostaja
poza jej zasiegiem, bo wymagaja klikniecia w interfejsie:

* **certyfikat PDF** — `reportlab` laduje czesc wlasnych modulow przez `exec`,
  wiec analiza statyczna PyInstallera ich nie widzi. Tak wlasnie wygladala
  druga nieudana kompilacja tego projektu: program startowal i stemplowal,
  a przewracal sie dopiero przy „Zapisz certyfikat";
* **okno podziekowan** — osobne zapytanie do innego zasobu API;
* **katalogi tlumaczen** — `verify_exe` sprawdza jeden jezyk (polski),
  a paczka ze Sklepu deklaruje trzy.

Tego nie da sie sprawdzic z zewnatrz — sprawdzenie musi biec WEWNATRZ
zbudowanej aplikacji, bo pytanie brzmi „czy TA paczka ma wszystko". Dlatego
jest to przelacznik samego programu, a nie osobne narzedzie.

Wyniki ida do dziennika (`beatstamp.log` w katalogu danych) i do kodu wyjscia:
0 — komplet, 1 — cokolwiek nie przeszlo. Wersja skompilowana jest programem
okienkowym i nie ma dokad pisac na konsoli, wiec dziennik jest jedynym
kanalem, ktory dziala tak samo ze zrodel i z paczki.

    BeatStamp.exe --selftest             # pelna, z siecia
    BeatStamp.exe --selftest --offline   # tylko to, co lokalne

NAZWY FLAG

Glowne nazwy sa ANGIELSKIE, bo flaga wiersza polecen jest interfejsem
publicznym: po otwarciu kodu i po wydaniu ze Sklepu wpisuja ja ludzie,
ktorzy polskiego nie znaja, i cytuja ja skrypty, ktorych nie widzimy.
Dotychczasowe `--samokontrola` i `--bez-sieci` zostaja jako ROWNOPRAWNE
aliasy na zawsze: flaga, ktora kiedys dzialala, a po aktualizacji przestaje,
psuje cudza automatyzacje bez ostrzezenia — a koszt utrzymania aliasu to
jeden wpis w krotce.
"""
from __future__ import annotations

import logging
import sys
import time

#: Glowna nazwa flagi (ta, ktora pokazujemy w dokumentacji).
FLAG = '--selftest'
OFFLINE_FLAG = '--offline'

#: Wszystkie przyjmowane nazwy — glowna i aliasy. Kolejnosc: glowna pierwsza.
FLAGS = (FLAG, '--samokontrola')
OFFLINE_FLAGS = (OFFLINE_FLAG, '--bez-sieci')

log = logging.getLogger('beatstamp.samokontrola')

#: Napis uzywany jako probka tlumaczenia. Musi istniec w KAZDYM katalogu —
#: pilnuje tego `tests/test_i18n.py: EveryLanguageIsCompleteTests`, wiec
#: jego zniknieciu towarzyszy czerwony test, a nie cicha awaria tutaj.
PROBE = 'Settings…'


class Failure(Exception):
    """Kontrola nie przeszla. Tresc trafia do dziennika."""


def _check_resources() -> str:
    """Zasoby, ktore musi zawierac paczka: magazyn CA i ikona."""
    import os

    import certifi

    from .config import resource_path

    bundle = certifi.where()
    if not os.path.exists(bundle):
        raise Failure(f'certifi wskazuje na nieistniejacy magazyn CA: {bundle}')
    icon = resource_path('beatstamp.ico')
    if not icon.is_file():
        raise Failure(f'brak ikony aplikacji: {icon}')
    return f'magazyn CA {os.path.getsize(bundle) // 1024} kB, ikona na miejscu'


def _check_languages() -> str:
    """Wszystkie trzy jezyki paczki — nie tylko ten, z ktorym akurat wystartowano.

    Angielski jest jezykiem ZRODLOWYM: `msgid` sa po angielsku, wiec nie ma
    wlasnego katalogu i poprawnym wynikiem jest napis NIEZMIENIONY. Polski
    i niemiecki musza dac cos innego — katalog, ktory nie trafil do paczki,
    degraduje sie po cichu do angielskiego i to jest dokladnie ta awaria,
    ktorej szukamy.
    """
    from . import i18n

    results = []
    previous = i18n.current_language()
    try:
        for code in ('en', 'pl', 'de'):
            active = i18n.set_language(code)
            if active != code:
                raise Failure(f'jezyk {code}: katalogu nie da sie wczytac '
                              f'(obowiazuje {active})')
            # `i18n: skip` — ekstraktor slusznie pilnuje, zeby argument
            # `gettext()` byl stalym napisem (inaczej nie da sie go
            # wyciagnac do katalogu). Tu napis jest PROBKA, nie tekstem
            # dla czlowieka: do katalogu trafia z miejsca, w ktorym go
            # naprawde widac, czyli z okna glownego.
            translated = i18n.gettext(PROBE)   # i18n: skip
            if code == i18n.SOURCE_LANGUAGE:
                if translated != PROBE:
                    raise Failure(f'jezyk zrodlowy {code} zmienil napis na {translated!r}')
            elif translated == PROBE:
                raise Failure(f'jezyk {code}: katalog nie tlumaczy — '
                              f'{PROBE!r} zostalo bez zmiany')
            results.append(f'{code}={translated!r}')
    finally:
        i18n.set_language(previous)
    return ', '.join(results)


def _check_data_dir() -> str:
    """Katalog danych istnieje i da sie w nim zapisac.

    W paczce MSIX to nie jest oczywiste: Windows wirtualizuje zapisy do
    `AppData`, a zapis do katalogu instalacyjnego jest zabroniony. Drugi
    powod jest nowszy: ochrona przed ransomware potrafi zablokowac zapis
    w KAZDYM katalogu, ktory uzytkownik doda do listy chronionej — i zglasza
    to jako „nie ma takiego pliku", nie jako odmowe dostepu.

    Sprawdzenie idzie przez `config.probe_write`, czyli DOKLADNIE ten sam kod,
    ktorego uzywa program przy starcie. Wlasna, rownolegla wersja tej proby
    rozjechalaby sie z nia przy pierwszej zmianie.
    """
    from .config import app_data_dir, probe_write

    directory = app_data_dir()
    problem = probe_write(directory)
    if problem is not None:
        raise Failure(f'katalog danych {directory} nie przyjmuje zapisu '
                      f'({"blokada systemowa" if problem.protected else "blad"}): '
                      f'{problem.reason}')
    return str(directory)


def _sample_entry():
    """Wpis historii z kompletem pol — material dla certyfikatu.

    Dane sa oczywiscie zmyslone. Certyfikat wystawiony z nich nie jest
    dowodem niczego i nigdzie nie trafia; chodzi wylacznie o to, zeby
    `reportlab` musial narysowac WSZYSTKIE elementy strony, razem z kodem QR
    i sciezka inkluzji — czyli dokladnie te czesci, ktorych brak w paczce
    wychodzi dopiero przy zapisie certyfikatu.
    """
    from .history import Entry

    return Entry(
        digest='0' * 64,
        file_name='samokontrola.txt',
        file_size=1234,
        beat='@000.00',
        utc='2026-01-01T00:00:00Z',
        seq=1,
        week='2026-W01',
        week_root='1' * 64,
        week_closed=True,
        chain_hash='2' * 64,
        root_signature='3' * 128,
        public_key='4' * 64,
        inclusion_proof=[{'position': 'left', 'hash': '5' * 64}],
        verified_ok=True,
    )


def _check_certificate() -> str:
    """Certyfikat PDF — cala sciezka `reportlab` razem z kodem QR."""
    from .certificate import build_certificate

    data = build_certificate(_sample_entry())
    if not data.startswith(b'%PDF'):
        raise Failure('wynik nie jest plikiem PDF (brak naglowka %PDF)')
    if len(data) < 5_000:
        raise Failure(f'PDF ma tylko {len(data)} B — strona nie zostala narysowana')
    return f'{len(data) // 1024} kB'


def _check_thanks() -> str:
    """Okno podziekowan: pobranie listy z produkcji i jej kontrola."""
    from . import supporters
    from .api import BeatTimeClient
    from .config import Settings

    payload = BeatTimeClient(Settings()).supporters_thanks()
    data = supporters.parse(payload)
    return f'{len(data.names)} nazw, zaktualizowano {data.updated or "(brak daty)"}'


#: Kolejnosc ma znaczenie: najpierw to, co lokalne i tanie, na koncu to, co
#: wymaga sieci. Awaria pakowania ma byc widoczna takze wtedy, gdy maszyna
#: skladajaca wydanie nie ma akurat polaczenia.
LOCAL_CHECKS = (
    ('zasoby paczki', _check_resources),
    ('katalogi tlumaczen', _check_languages),
    ('katalog danych', _check_data_dir),
    ('certyfikat PDF', _check_certificate),
)
NETWORK_CHECKS = (
    ('lista podziekowan', _check_thanks),
)


def run(*, offline: bool = False) -> int:
    """Wykonuje komplet kontroli. Zwraca kod wyjscia (0 = wszystko przeszlo)."""
    checks = list(LOCAL_CHECKS)
    if offline:
        log.info('samokontrola: tryb bez sieci — pomijam %s',
                 ', '.join(name for name, _f in NETWORK_CHECKS))
    else:
        checks += list(NETWORK_CHECKS)

    failures = 0
    for name, check in checks:
        started = time.monotonic()
        try:
            detail = check()
        except Failure as e:
            failures += 1
            log.error('samokontrola [NIE] %s: %s', name, e)
        except Exception as e:                        # noqa: BLE001
            # Wyjatek spoza `Failure` to najczesciej wlasnie brakujacy modul —
            # czyli to, czego szukamy. Typ wyjatku jest tu istotna informacja.
            failures += 1
            log.error('samokontrola [NIE] %s: %s: %s',
                      name, type(e).__name__, e, exc_info=True)
        else:
            log.info('samokontrola [OK] %s: %s (%.2f s)',
                     name, detail, time.monotonic() - started)

    if failures:
        log.error('SAMOKONTROLA NIE PRZESZLA: %s z %s kontroli', failures, len(checks))
        return 1
    log.info('SAMOKONTROLA: komplet %s kontroli przeszedl', len(checks))
    return 0


def requested(argv: list[str]) -> bool:
    """Czy w argumentach jest prosba o samokontrole (dowolna z nazw)."""
    return any(flag in argv for flag in FLAGS)


def offline_requested(argv: list[str]) -> bool:
    """Czy samokontrola ma pominac to, co wymaga sieci."""
    return any(flag in argv for flag in OFFLINE_FLAGS)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    return run(offline=offline_requested(argv))

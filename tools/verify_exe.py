"""
Sprawdza GOTOWĄ, ZBUDOWANĄ aplikację — nie kod, z którego powstała.

Powód istnienia tego skryptu jest konkretny. Pierwsza kompilacja programu (wtedy BeatStamp)
wyglądała na udaną (PyInstaller zakończył się kodem 0, plik miał poprawny
rozmiar, ikonę i metadane wersji), a mimo to **nie uruchamiała się wcale**:
w `beatstamp.spec` wykluczony był moduł `PIL`, który `reportlab.lib.utils`
importuje bezwarunkowo. Ze źródeł wszystko działało, bo Pillow siedzi
w środowisku — błąd istniał wyłącznie w paczce.

Cała klasa takich usterek — brakujący moduł, niedołączony zasób, magazyn CA,
którego `certifi` nie znajduje w `sys._MEIPASS` — jest **niewidoczna dla
testów jednostkowych z definicji**. Jedyny sposób, żeby ją złapać, to
uruchomić zbudowany program i sprawdzić, czy naprawdę wykonał swoją pracę.

Build jest KATALOGOWY (`dist/SigelithDesktop/SigelithDesktop.exe` plus
`_internal/`), więc skrypt przyjmuje zarówno ścieżkę do pliku .exe, jak i do
samego katalogu, i mierzy rozmiar CAŁEJ paczki — to ona jedzie do Sklepu,
nie sam program rozruchowy, który waży niecały megabajt.

Test przechodzi całą ścieżkę użytkownika: start → skrót SHA-256 → HTTPS
(czyli i magazyn CA) → rejestracja w Sigelith → weryfikacja lokalna → zapis
historii. Uruchamiany jest w ŚWIEŻYM katalogu danych (`SIGELITH_DATA_DIR`)
przy PUSTEJ starej lokalizacji (`%LOCALAPPDATA%`), więc sprawdza też
zachowanie przy pierwszym uruchomieniu na nowym komputerze — razem
z przeprowadzką danych, która przy pustym źródle ma tylko zapisać znacznik
i nie tworzyć starego katalogu.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

# Nazwa flagi samokontroli idzie Z KODU APLIKACJI, a nie z napisu tutaj:
# to jest interfejs publiczny, ktory wlasnie dostal angielska nazwe glowna
# i polskie aliasy. Wpisana recznie rozjechalaby sie przy nastepnej zmianie
# i to w narzedziu, ktore ma pilnowac wlasnie takich rozjazdow.
# `beatstamp/__init__.py` i `beatstamp/selftest.py` nie importuja PySide6,
# wiec ten import jest tani i dziala takze bez zainstalowanego Qt.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from beatstamp import config, selftest  # noqa: E402  (sciezka ustawiona wyzej)

TIMEOUT_SECONDS = 45
POLL_SECONDS = 0.5


def fail(message: str) -> None:
    print(f'  [BŁĄD] {message}')
    raise SystemExit(1)


def ok(message: str) -> None:
    print(f'  [OK]   {message}')


def main() -> int:
    # Konsola Windows bywa w cp1252: linia samokontroli z nazwami jezykow
    # (cyrylica, CJK, arabski) wywracala weryfikacje DOBREJ paczki.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors='replace')
        except (AttributeError, ValueError):
            pass
    exe = _resolve_exe(sys.argv[1] if len(sys.argv) > 1 else 'dist/SigelithDesktop')
    print(f'Weryfikacja: {exe}')
    if not exe.is_file():
        fail('plik nie istnieje — kompilacja się nie powiodła')
    package = exe.parent
    total = sum(f.stat().st_size for f in package.rglob('*') if f.is_file())
    ok(f'katalog programu istnieje ({total / 1024 / 1024:.1f} MB, '
       f'{sum(1 for f in package.rglob("*") if f.is_file())} plikow)')

    # Zasoby sprawdzamy PRZED uruchomieniem, bo inaczej ich brak objawi sie
    # dopiero jako skutek: interfejs uparcie po angielsku albo kazde
    # polaczenie HTTPS odrzucone. Tu widac przyczyne i z nazwy.
    internal = package / '_internal'
    # Jezyki bierzemy ze ZRODEL (`locale/<jezyk>/.../beatstamp.po`): kazdy
    # katalog w repozytorium musi miec swoj `.mo` w paczce.
    source_locale = Path(__file__).resolve().parent.parent / 'locale'
    languages = sorted(p.parent.parent.name
                       for p in source_locale.glob('*/LC_MESSAGES/beatstamp.po'))
    required = [('certifi/cacert.pem', 'magazyn CA (certifi)'),
                ('beatstamp.ico', 'ikona aplikacji')]
    required += [(f'locale/{code}/LC_MESSAGES/beatstamp.mo', f'katalog tlumaczen: {code}')
                 for code in languages]
    for relative, label in required:
        if not (internal / relative).is_file():
            fail(f'w paczce brakuje zasobu: {label} (_internal/{relative})')
    ok(f'zasoby na miejscu: magazyn CA, tlumaczenia ({" ".join(languages)}), ikona')

    workspace = Path(tempfile.mkdtemp(prefix='sigelith-verify-'))
    # Katalog danych wskazujemy WPROST. Bez tego trafilby do prawdziwego
    # katalogu danych osoby uruchamiającej test (`%USERPROFILE%\Sigelith`),
    # a stemple weryfikacyjne mieszałyby się z jej historią. Ta sama zmienna
    # wyłącza przeprowadzkę ze starych lokalizacji (`config.migrate_legacy_data`)
    # — katalog ma być PUSTY, żeby jedyny wpis, który w nim powstanie,
    # pochodził z tego uruchomienia.
    data_dir = workspace / 'dane'
    app_data = workspace / 'AppData'
    app_data.mkdir()

    # Dokument z losową treścią — musi dać skrót, którego nikt wcześniej nie
    # stemplował. Bez tego serwer zwróciłby HTTP 200 (stempel już istnieje)
    # i test przeszedłby, nie sprawdziwszy ścieżki zapisu.
    document = workspace / 'dokument testowy.txt'
    document.write_text(f'Sigelith Desktop weryfikacja {uuid.uuid4()}', encoding='utf-8')
    expected = hashlib.sha256(document.read_bytes()).hexdigest()

    env = dict(os.environ)
    env[config.DATA_DIR_ENV] = str(data_dir)
    env['LOCALAPPDATA'] = str(app_data)     # pusta STARA lokalizacja
    # Jezyk wymuszony, zeby test nie zalezal od ustawien maszyny, na ktorej
    # akurat sklada sie wydanie. Przy okazji sprawdza, ze katalogi tlumaczen
    # NAPRAWDE trafily do paczki: gdyby ich zabraklo, wpis w dzienniku
    # pokazalby „jezyk interfejsu (ustawienia 'pl'): en".
    env['SIGELITH_LANG'] = 'pl'
    env.pop('QT_QPA_PLATFORM', None)        # ma działać na prawdziwym pulpicie

    # --- Samokontrola paczki -------------------------------------------
    # Osobne uruchomienie, bo sprawdza to, czego nie da sie zobaczyc
    # z zewnatrz: komplet katalogow tlumaczen, zapis do katalogu danych,
    # wygenerowanie certyfikatu PDF (dynamiczne importy `reportlab` — tak
    # wygladala druga nieudana kompilacja tego projektu), obieg Sigelith
    # Handover (kryptografia z rozszerzen w Rust, DPAPI i webauthn.dll przez
    # ctypes) i pobranie listy podziekowan. Program konczy sie sam, przed
    # stworzeniem okna.
    selftest_dir = workspace / 'samokontrola'
    selftest_env = dict(env)
    selftest_env[config.DATA_DIR_ENV] = str(selftest_dir)
    print('  uruchamiam samokontrole paczki')
    try:
        code = subprocess.run([str(exe), selftest.FLAG], env=selftest_env,
                              cwd=str(workspace), timeout=TIMEOUT_SECONDS * 2).returncode
    except subprocess.TimeoutExpired:
        fail('samokontrola nie skonczyla sie w wyznaczonym czasie')
        return 1                      # nieosiagalne: `fail` rzuca SystemExit
    selftest_log = selftest_dir / config.LOG_NAME
    for line in _selftest_lines(selftest_log):
        print(f'         {line}')
    if code != 0:
        fail(f'samokontrola paczki NIE przeszla (kod {code})' + _log_tail(selftest_log))
    if not any('SAMOKONTROLA: komplet' in line for line in _selftest_lines(selftest_log)):
        fail('samokontrola nie zostawila wyniku w dzienniku' + _log_tail(selftest_log))
    # Handover jawnie: kontrola wypadnieta z listy dalaby „komplet" bez niej.
    if not any('[OK] Sigelith Handover' in line for line in _selftest_lines(selftest_log)):
        fail('samokontrola nie sprawdzila Sigelith Handover' + _log_tail(selftest_log))
    ok('samokontrola paczki przeszla (zasoby, wszystkie jezyki, PDF, Handover, podziekowania)')

    # --- Sciezka uzytkownika -------------------------------------------
    print(f'  uruchamiam z argumentem: {document.name}')
    process = subprocess.Popen([str(exe), str(document)], env=env, cwd=str(workspace))

    history = data_dir / 'history.json'
    log = data_dir / config.LOG_NAME
    deadline = time.time() + TIMEOUT_SECONDS
    entries = None
    while time.time() < deadline:
        if process.poll() is not None and not history.exists():
            fail(f'program zakończył się przedwcześnie (kod {process.returncode})'
                 + _log_tail(log))
        if history.exists():
            try:
                entries = json.loads(history.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                time.sleep(POLL_SECONDS)      # zapis może trwać
                continue
            if entries:
                break
        time.sleep(POLL_SECONDS)

    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
    except OSError:
        pass

    if not log.exists():
        fail('nie powstał dziennik zdarzeń — program nie wystartował'
             + _log_tail(log))
    ok('program wystartował i założył katalog danych')

    text = log.read_text(encoding='utf-8', errors='replace')
    if 'magazyn CA NIEDOSTEPNY' in text or 'magazyn CA NIEDOSTĘPNY' in text:
        fail('certifi nie odnalazł magazynu CA w paczce — HTTPS nie zadziała')
    if 'istnieje: True' not in text:
        fail('magazyn CA nie został dołączony do paczki' + _log_tail(log))
    ok('magazyn CA (certifi) jest w paczce i odnaleziony')

    if not entries:
        fail(f'w ciągu {TIMEOUT_SECONDS} s nie powstał żaden wpis historii'
             + _log_tail(log))

    entry = entries[0]
    if entry.get('digest') != expected:
        fail(f'skrót niezgodny: {entry.get("digest")} != {expected}')
    ok(f'skrót zgodny z policzonym niezależnie ({expected[:16]}…)')

    for field, label in (('beat', 'czas @beat'), ('utc', 'czas UTC'),
                         ('week', 'tydzień'), ('seq', 'numer w rejestrze')):
        if not entry.get(field):
            fail(f'brak pola „{label}" — odpowiedź serwera nie została zapisana')
    ok(f'stempel nadany: {entry["beat"]} · {entry["utc"]} · wpis #{entry["seq"]}')

    if not entry.get('verified_ok'):
        fail('weryfikacja lokalna odpowiedzi NIE wypadła pomyślnie')
    ok('weryfikacja lokalna (Merkle + klucz) przeszła')

    if entry.get('file_name') != document.name:
        fail('nazwa pliku nie trafiła do historii')
    ok(f'historia zapisana poprawnie w {data_dir}')

    # Stary katalog ma pozostać nietknięty: przy pustym źródle przeprowadzka
    # nie ma prawa go utworzyć, a dane pod żadnym pozorem nie mogą tam trafić.
    if (app_data / config.LEGACY_DIR_NAME).exists():
        fail('program dotknął starej lokalizacji %LOCALAPPDATA%\\BeatStamp')
    ok('stara lokalizacja %LOCALAPPDATA%\\BeatStamp nietknięta')

    for phrase in ('Traceback', 'nieprzechwycony', 'CRITICAL'):
        if phrase in text:
            fail(f'dziennik zawiera ślad awarii („{phrase}")' + _log_tail(log))
    ok('dziennik bez śladów awarii')

    print('\nWERYFIKACJA PLIKU .EXE: WSZYSTKO PRZESZŁO')
    return 0


def _selftest_lines(log: Path) -> list[str]:
    """Wiersze samokontroli z dziennika — bez znacznika czasu i nazwy modulu."""
    if not log.exists():
        return []
    return [line.split(': ', 1)[-1]
            for line in log.read_text(encoding='utf-8', errors='replace').splitlines()
            if 'beatstamp.samokontrola: ' in line]


def _resolve_exe(argument: str) -> Path:
    """Sciezka do pliku .exe — z katalogu programu albo wprost do pliku.

    Build jest katalogowy, wiec naturalne „wskaz co zbudowales" to katalog.
    Przyjmujemy jedno i drugie, zeby wywolanie z `build.ps1` (plik) i reczne
    (katalog) dzialaly tak samo.
    """
    path = Path(argument).resolve()
    if path.is_dir():
        return path / 'SigelithDesktop.exe'
    return path


def _log_tail(log: Path) -> str:
    if not log.exists():
        return '\n  (dziennik nie powstał)'
    tail = log.read_text(encoding='utf-8', errors='replace').splitlines()[-15:]
    return '\n  dziennik:\n    ' + '\n    '.join(tail)


if __name__ == '__main__':
    sys.exit(main())

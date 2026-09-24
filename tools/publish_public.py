"""Publikacja katalogu `desktop/` do publicznego repozytorium (migawka wydania).

Model: monorepo jest ZRODLEM PRAWDY, publiczne repozytorium jest lustrem —
jeden commit na wydanie, bez historii monorepo. Rotacja klucza podpisujacego
musi zmienic `apps/tsa/signing.py` i `desktop/beatstamp/keys.py` w JEDNYM
commicie pod kontrola dwoch lustrzanych testow; gdyby publiczne repozytorium
bylo zrodlem, trzeba by publicznie wypchnac nowy klucz, zanim serwer zacznie
nim podpisywac.

Dlaczego przez `git archive`, a nie kopiowanie katalogu
-------------------------------------------------------
Kopiowanie NIE respektuje `.gitignore`. W katalogu roboczym leza `dist/`,
`build/` i `packaging/_local/` z testowym certyfikatem zawierajacym KLUCZ
PRYWATNY, a takze zbudowane paczki z bibliotekami Qt, ktorych licencja
wyklucza publikacje. `git archive` bierze wylacznie pliki SLEDZONE i honoruje
`export-ignore` z `.gitattributes` — czyli publikujemy dokladnie to, co jest
w repozytorium, a nie to, co akurat lezy na dysku.

Uruchomienie:
    python desktop/tools/publish_public.py --repo DeiFlagellum/beatstamp
    python desktop/tools/publish_public.py --repo ... --dry-run   (tylko kontrola)
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

KORZEN = Path(__file__).resolve().parents[2]
PODKATALOG = 'desktop'

# Czego w migawce byc NIE MOZE. Lista jest celowo szersza niz to, co `git
# archive` moze w ogole wypuscic: kontrola ma wylapac takze blad w
# .gitignore/.gitattributes, a nie tylko blad tego skryptu.
ZAKAZANE_ROZSZERZENIA = {'.pfx', '.p12', '.pem', '.key', '.jks', '.keystore',
                         '.snk', '.cer', '.crt', '.env'}
ZAKAZANE_KATALOGI = {'dist', 'build', '_local', 'secrets', '__pycache__', '.venv'}
# Moduly Qt dostepne wylacznie komercyjnie albo na GPLv3.
ZAKAZANE_NAZWY = {'qt6virtualkeyboard.dll', 'qtvirtualkeyboardplugin.dll'}
# Wzorce, ktore wygladaja na material klucza albo sekret w tresci pliku.
#
# Skladane ze SKLEJENIA, a nie wpisane w calosci: kontrola czyta takze ten
# plik, wiec wzorzec zapisany doslownie zglaszalby sam siebie. Wyjecie tego
# pliku spod kontroli byloby prostsze, ale zrobiloby slepa plame dokladnie
# tam, gdzie najlatwiej o pomylke.
ZAKAZANE_WZORCE = [
    re.compile(b'-----BEGIN ' + rb'[A-Z ]*' + b'PRIVATE KEY-----'),
    re.compile(b'TS_ED25519_' + b'PRIVKEY' + rb'\s*='),
    re.compile(b'STRIPE_SECRET' + b'_KEY' + rb'\s*=\s*["\']?sk_'),
    re.compile(b'X-Internal' + b'-Secret:' + rb'\s*\S'),
]
TEKSTOWE = {'.py', '.md', '.txt', '.ps1', '.spec', '.xml', '.po', '.pot',
            '.json', '.cfg', '.toml', '.yml', '.yaml', '.gitattributes'}


def uruchom(polecenie: list[str], cwd: Path | None = None, cicho: bool = False) -> str:
    wynik = subprocess.run(polecenie, cwd=cwd or KORZEN, capture_output=True, text=True)
    if wynik.returncode != 0:
        raise SystemExit(f'polecenie nie powiodlo sie: {" ".join(polecenie)}\n'
                         f'{wynik.stdout}\n{wynik.stderr}')
    if not cicho and wynik.stdout.strip():
        print(wynik.stdout.strip())
    return wynik.stdout


def wersja() -> str:
    tresc = (KORZEN / PODKATALOG / 'beatstamp' / '__init__.py').read_text(encoding='utf-8')
    m = re.search(r"__version__\s*=\s*'([^']+)'", tresc)
    if not m:
        raise SystemExit('nie znalazlem __version__ w beatstamp/__init__.py')
    return m.group(1)


def drzewo_czyste() -> None:
    """Publikujemy ze ZRODLA PRAWDY, a nie z niezapisanych zmian."""
    brudne = subprocess.run(['git', 'status', '--porcelain', '--', PODKATALOG],
                            cwd=KORZEN, capture_output=True, text=True).stdout.strip()
    if brudne:
        raise SystemExit('desktop/ ma niezacommitowane zmiany — najpierw commit:\n' + brudne)


def migawka(cel: Path) -> None:
    """Pliki SLEDZONE z HEAD:desktop, z honorowaniem export-ignore."""
    with tempfile.NamedTemporaryFile(suffix='.tar', delete=False) as plik:
        tar_sciezka = Path(plik.name)
    try:
        with open(tar_sciezka, 'wb') as out:
            wynik = subprocess.run(['git', 'archive', '--format=tar', f'HEAD:{PODKATALOG}'],
                                   cwd=KORZEN, stdout=out, stderr=subprocess.PIPE, text=False)
        if wynik.returncode != 0:
            raise SystemExit('git archive nie powiodlo sie: ' + wynik.stderr.decode('utf-8', 'replace'))
        with tarfile.open(tar_sciezka) as tar:
            tar.extractall(cel, filter='data')
    finally:
        tar_sciezka.unlink(missing_ok=True)


def skontroluj(katalog: Path) -> list[str]:
    zarzuty = []
    for sciezka in sorted(katalog.rglob('*')):
        if sciezka.is_dir():
            if sciezka.name.lower() in ZAKAZANE_KATALOGI:
                zarzuty.append(f'katalog, ktorego tu byc nie moze: {sciezka.relative_to(katalog)}')
            continue
        wzgledna = sciezka.relative_to(katalog)
        if sciezka.suffix.lower() in ZAKAZANE_ROZSZERZENIA:
            zarzuty.append(f'plik z materialem klucza/konfiguracji: {wzgledna}')
        if sciezka.name.lower() in ZAKAZANE_NAZWY:
            zarzuty.append(f'modul Qt tylko-GPL: {wzgledna}')
        if any(czesc.lower() in ZAKAZANE_KATALOGI for czesc in wzgledna.parts[:-1]):
            zarzuty.append(f'plik w zakazanym katalogu: {wzgledna}')
        if sciezka.suffix.lower() in TEKSTOWE or sciezka.name == '.gitattributes':
            dane = sciezka.read_bytes()
            for wzorzec in ZAKAZANE_WZORCE:
                if wzorzec.search(dane):
                    zarzuty.append(f'sekret w tresci ({wzorzec.pattern.decode()}): {wzgledna}')
    for wymagany in ('LICENSE', 'NOTICE', 'README.md'):
        if not (katalog / wymagany).is_file():
            zarzuty.append(f'brak pliku wymaganego przy publikacji: {wymagany}')
    if (katalog / 'ROZWOJ.md').exists():
        zarzuty.append('ROZWOJ.md trafil do migawki — sprawdz export-ignore w .gitattributes')
    return zarzuty


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', required=True, help='np. DeiFlagellum/beatstamp')
    p.add_argument('--dry-run', action='store_true', help='tylko zbuduj i skontroluj migawke')
    p.add_argument('--message', default='', help='tresc commita (domyslnie: BeatStamp <wersja>)')
    args = p.parse_args()

    drzewo_czyste()
    v = wersja()
    print(f'BeatStamp {v} — migawka z HEAD:{PODKATALOG}')

    with tempfile.TemporaryDirectory() as tmp:
        snap = Path(tmp) / 'snapshot'
        snap.mkdir()
        migawka(snap)
        pliki = [s for s in snap.rglob('*') if s.is_file()]
        print(f'plikow w migawce: {len(pliki)}')

        zarzuty = skontroluj(snap)
        if zarzuty:
            print('\nKONTROLA NIE PRZESZLA:')
            for z in zarzuty:
                print('  -', z)
            return 1
        print('kontrola: czysto (brak kluczy, paczek, modulow tylko-GPL)')

        if args.dry_run:
            print('\n--dry-run: nic nie wyslano')
            return 0

        praca = Path(tmp) / 'repo'
        uruchom(['git', 'clone', '--depth', '1', f'https://github.com/{args.repo}.git',
                 str(praca)], cwd=KORZEN)
        # Pierwsza publikacja: swieze repozytorium nie ma jeszcze HEAD, a
        # domyslna galaz gita bywa `master`. Nazwe ustalamy sami, zeby
        # pierwszy commit nie wyladowal na galezi, ktorej nikt nie oczekuje.
        puste = subprocess.run(['git', 'rev-parse', '--verify', 'HEAD'], cwd=praca,
                               capture_output=True, text=True).returncode != 0
        if puste:
            uruchom(['git', 'checkout', '-b', 'main'], cwd=praca, cicho=True)
        for element in praca.iterdir():
            if element.name == '.git':
                continue
            shutil.rmtree(element) if element.is_dir() else element.unlink()
        for element in snap.iterdir():
            cel = praca / element.name
            shutil.copytree(element, cel) if element.is_dir() else shutil.copy2(element, cel)

        uruchom(['git', 'add', '-A'], cwd=praca)
        stan = subprocess.run(['git', 'status', '--porcelain'], cwd=praca,
                              capture_output=True, text=True).stdout.strip()
        if not stan:
            print('publiczne repozytorium jest juz aktualne — nic do wyslania')
            return 0
        uruchom(['git', 'commit', '-m', args.message or f'BeatStamp {v}'], cwd=praca)
        uruchom(['git', 'push', 'origin', 'HEAD'], cwd=praca)
        print(f'\nwyslano do https://github.com/{args.repo}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

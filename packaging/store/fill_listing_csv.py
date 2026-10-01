"""Wypelnia plik CSV karty ze Sklepu (Partner Center → Store listings → Export
listing) tekstami z `listing.json` i zrzutami — wszystkie jezyki naraz.

Partner Center przyjmuje z powrotem tylko CSV z WLASNEGO eksportu (kolumny
Field / ID / Type musza zostac nietkniete), dlatego nie generujemy go od
zera: najpierw eksport, potem ten skrypt, na koncu „Import listings →
Import folder" z katalogiem wynikowym.

    python desktop/packaging/store/fill_listing_csv.py eksport.csv robocze/desktop_shots/store wynik

Wynik: `wynik/listing.csv` (UTF-8), `wynik/screens/<jezyk>/*.png` i ikona karty
`wynik/logo/tile-300.png`; sciezki plikow w CSV zaczynaja sie od nazwy
katalogu (tak wymaga import folderu). Pola, ktorych nie ma w eksporcie, skrypt
wypisuje — nazwy pol w Partner Center bywaja zmieniane, a my wolimy o tym
wiedziec niz zgadywac.

LOGO KARTY: dla aplikacji (nie gier) Sklep bierze „1:1 App tile icon"
300 x 300 (`StoreLogo300x300`), a bez niej — male logo z paczki. Plakat 2:3
i okladka 1:1 (`StoreLogo720x1080`, `StoreLogo1080x1080`) sa wg dokumentacji
Microsoftu dla gier i Xboksa — zostaja puste.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LISTING = HERE / 'listing.json'
#: wzorzec ikony programu (make_icon.py) — ta sama ikona co w paczce MSIX
ICON = HERE.parent / 'beatstamp-icon.png'
TILE_SIZE = 300
TILE = 'logo/tile-300.png'
#: limity pola Keywords w Partner Center
MAX_TERMS, MAX_TERM_CHARS, MAX_TERM_WORDS = 7, 40, 21
#: katalog zrzutow generatora (robocze/desktop_shots.py) dla kolumny jezyka
SHOT_DIRS = {'en-us': 'en', 'pl-pl': 'pl', 'de-de': 'de', 'es-es': 'es', 'fr-fr': 'fr',
             'ru-ru': 'ru', 'tr-tr': 'tr', 'ja-jp': 'ja', 'ko-kr': 'ko', 'zh-cn': 'zh',
             'ar-sa': 'ar'}


def cells(item: dict, prefix: str, tile: str) -> dict[str, str]:
    """Pole CSV -> wartosc dla jednego jezyka."""
    out = {'Description': item['description'], 'ReleaseNotes': item['whats_new'],
           'ShortDescription': item['short_description'],
           'CopyrightTrademarkInformation': item['copyright'], 'StoreLogo300x300': tile}
    for n, feature in enumerate(item['features'], 1):
        out[f'Feature{n}'] = feature
    for n, (shot, caption) in enumerate(zip(item['screenshots'], item['captions']), 1):
        out[f'DesktopScreenshot{n}'] = f'{prefix}/{shot}'
        out[f'DesktopScreenshotCaption{n}'] = caption
    for n, requirement in enumerate(item['recommended_hardware'], 1):
        out[f'RecommendedHardwareReq{n}'] = requirement
    for n, term in enumerate(item['search_terms'], 1):
        out[f'SearchTerm{n}'] = term
    return out


def check_search_terms(terms: list[str]) -> None:
    """Limity Keywords: do 7 hasel, kazde do 40 znakow, razem do 21 roznych slow."""
    words = {word.lower() for term in terms for word in term.split()}
    if (len(terms) > MAX_TERMS or any(len(t) > MAX_TERM_CHARS for t in terms)
            or len(words) > MAX_TERM_WORDS):
        raise SystemExit(f'slowa kluczowe ponad limit Partner Center: {terms}')


def write_tile(target: Path) -> None:
    """Ikona karty 300 x 300 pomniejszona z wzorca 2048 px (bez powiekszania)."""
    from PIL import Image                               # tylko tutaj potrzebny

    with Image.open(ICON) as master:
        tile = master.convert('RGBA').resize((TILE_SIZE, TILE_SIZE), Image.LANCZOS)
    target.parent.mkdir(parents=True, exist_ok=True)
    tile.save(target, format='PNG', optimize=True)


def fill(exported: Path, shots: Path, out_dir: Path) -> list[str]:
    """Zwraca liste pol z listing.json, ktorych nie bylo w eksporcie."""
    listing = json.loads(LISTING.read_text(encoding='utf-8'))
    raw = exported.read_bytes()
    bom = raw.startswith(b'\xef\xbb\xbf')
    # io.StringIO, nie splitlines(): opis w komorce ma wiele wierszy.
    rows = list(csv.reader(io.StringIO(raw.decode('utf-8-sig'), newline='')))
    header, body = rows[0], rows[1:]
    if header[:1] != ['Field']:
        raise SystemExit('to nie jest eksport kart ze Sklepu (pierwsza kolumna: Field)')
    by_field = {row[0]: row for row in body if row}
    for locale in listing:
        if locale not in [h.lower() for h in header]:
            header.append(locale)
    width = len(header)
    for row in body:
        row.extend([''] * (width - len(row)))

    missing: set[str] = set()
    out_dir.mkdir(parents=True, exist_ok=True)
    write_tile(out_dir / TILE)
    for locale, item in listing.items():
        check_search_terms(item['search_terms'])
        column = [h.lower() for h in header].index(locale)
        source = shots / SHOT_DIRS[locale]
        target = out_dir / 'screens' / SHOT_DIRS[locale]
        target.mkdir(parents=True, exist_ok=True)
        for shot in item['screenshots']:
            shutil.copyfile(source / shot, target / shot)
        prefix = f'{out_dir.name}/screens/{SHOT_DIRS[locale]}'
        # Ten sam plik ikony we wszystkich jezykach: Sklep i tak wymaga
        # obrazow osobno dla kazdej karty.
        for field, value in cells(item, prefix, f'{out_dir.name}/{TILE}').items():
            row = by_field.get(field)
            if row is None:
                missing.add(field)
                continue
            row[column] = value

    with open(out_dir / 'listing.csv', 'w', encoding='utf-8-sig' if bom else 'utf-8',
              newline='') as f:
        csv.writer(f).writerows([header, *body])
    return sorted(missing)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('exported', type=Path, help='CSV z Partner Center (Export listing)')
    parser.add_argument('shots', type=Path, help='katalog zrzutow: <jezyk>/01-stamp.png ...')
    parser.add_argument('out', type=Path, help='katalog wynikowy do „Import folder"')
    args = parser.parse_args()
    missing = fill(args.exported, args.shots, args.out)
    print(f'{args.out / "listing.csv"}: {len(json.loads(LISTING.read_text(encoding="utf-8")))} '
          'jezykow')
    if missing:
        print('Pol nie ma w eksporcie (sprawdz nazwy w Partner Center): ' + ', '.join(missing))
    return 0


if __name__ == '__main__':
    sys.exit(main())
